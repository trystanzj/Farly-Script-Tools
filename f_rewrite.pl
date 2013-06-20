#!/usr/bin/perl -w

# f_rewrite.pl - Farly Script Tools - Interactive firewall rule rewrite
# Copyright (C) 2012  Trystan Johnson
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

use strict;
use warnings;
use Getopt::Long;
use Pod::Usage;
use Farly;
use Farly::Rule::Expander;
use Farly::Object::Aggregate qw(NEXTVAL);
use Farly::ASA::ProtocolFormatter;
use Farly::ASA::PortFormatter;
use Farly::ASA::ProtocolFormatter;
use Farly::ASA::ICMPFormatter;
use Farly::Template::Cisco;

my %opts;

GetOptions( \%opts, 'file=s', 'id=s', 'groupby=s', 'output=s', 'help', 'man' )
  or pod2usage(2);

pod2usage(1) if ( defined $opts{'help'} );

pod2usage( -verbose => 2 ) if ( defined $opts{'man'} );

if ( !defined $opts{'file'} ) {
    pod2usage("Please specify a configuration file");
}

if ( !-f $opts{'file'} ) {
    pod2usage("--file $opts{'file'} not found");
}

if ( !defined $opts{'id'} ) {
    pod2usage("Please specify an access-list ID");
}

if ( !defined $opts{'groupby'} ) {
    pod2usage("Please specify a --groupby property");
}

if ( $opts{'groupby'} !~ /^DST_PORT$|^SRC_IP$|^DST_IP$|^SRC_PORT$/ ) {
    pod2usage("Invalid --groupby property $opts{'groupby'}" );
}

if ( !defined $opts{'output'} ) {
    pod2usage("Please specify an output file name");
}

my $property = $opts{'groupby'};
my $output   = $opts{'output'};

my $ANY = Farly::IPv4::Network->new('0.0.0.0 0.0.0.0');

print "\nimporting... ", $opts{'file'}, "\n";

my $importer = Farly->new();

my $container = $importer->process( "ASA", $opts{'file'} );

my $search = Farly::Object->new();
$search->set( "ID", Farly::Value::String->new( $opts{'id'} ) );

my $search_result = Farly::Object::List->new();

$container->matches( $search, $search_result );

my $rules = filter_comments($search_result);

set_defaults($rules);

if ( $property eq 'SRC_PORT' || $property eq 'DST_PORT' ) {
    $rules = filter_layer4($rules);
}

if ( $rules->size == 0 ) {
    die "\n", $opts{'id'}, " is not a valid access-list id\n";
}

print "grouping rules...\n";

my %properties = (
    'ID'       => 1,
    'ACTION'   => 1,
    'PROTOCOL' => 1,
    'SRC_IP'   => 1,
    'SRC_PORT' => 1,
    'DST_IP'   => 1,
    'DST_PORT' => 1,
);

delete $properties{$property};

# group the rules which have common identity
my $agg = Farly::Object::Aggregate->new($rules);
$agg->groupby( keys %properties );

# track pre-existing and new groups
# %groups = { <ID string> => { $group_set<Farly::Object::Set> } }
my %groups;
existings_groups( $container, \%groups );

#new rules to add
my @keep;    # [ $object<Farly::Object> ]

#old rules to remove
my @remove;    # [ $list<Farly::Object::List> ] (the grouped rules)

my $it = $agg->list_iterator();

my $size = scalar( $agg->iter() );
my $count = 1;

while ( my $list = NEXTVAL($it) ) {

    if ( $list->size == 1 ) {
        print  "\n$count of $size doesn't need to be grouped\n";
        $count++;
        next; 
    };

    if ( $list->[0]->get($property)->equals($ANY) ) {
        print "\n$count of $size $property is IP 0.0.0.0/0\n";
        $count++;
        next;         
    }

    # create a group for the specified property from the $list of rules
    my $group_set = create_group( $list, $property );

    # if this group already has an ID the ID is returned
    my $id = current_group_id( $group_set, \%groups );

    if ( !defined($id) ) {

        print "\n$count of $size\n";
        # the group doesn't have an ID display the first rule
        print "hint :   ";
        display_object( $list->[0] );

        # get a new group ID from the user
        $id = name_new_group( $group_set, \%groups );
    }

    die "ERROR : id not defined\n" unless defined($id);

    # create a group reference object using the new ID 
    my $group_ref = group_ref($id);

    # create a new rule which using the new group reference object
    my $cloned_rule = $list->[0]->clone();
    $cloned_rule->set( $property, $group_ref );
    $cloned_rule->delete_key('LINE');

    # keep the new rule
    push @keep, $cloned_rule;

    # remove the rest of the old none grouped rules
    push @remove, $list;

    $count++;
}

print "\nprinting configuration to $output...\n";

open STDOUT, ">$output" or die "failed to open $output file";

foreach my $id ( keys %groups ) {

    my $group_set = $groups{$id};

    foreach my $object ( $group_set->iter ) {

        last if ( $object->has_defined('EXISTS') );

        $object->set( 'ID', Farly::Value::String->new($id) );

        display_object($object);
    }
}

#print the new rules
foreach my $rule (@keep) {

    display_object($rule);
}

#remove the rules which are now grouped
foreach my $list (@remove) {

    remove($list);
}

close STDOUT;

sub filter_layer4 {
    my ($list) = @_;

    my $TCP = Farly::Transport::Protocol->new("6");
    my $UDP = Farly::Transport::Protocol->new("17");

    my $rules = Farly::Object::List->new();

    foreach my $rule ( $list->iter ) {

        next if ( $rule->has_defined('COMMENT') );

        if ( $rule->get('PROTOCOL')->equals($TCP) || $rule->get('PROTOCOL')->equals($UDP) )
        {
            $rules->add($rule);
        }
    }

    return $rules;
}

sub filter_comments {
    my ($list) = @_;

    my $rules = Farly::Object::List->new();

    foreach my $rule ( $list->iter ) {

        if ( $rule->has_defined('COMMENT') ) {
            next;
        }
        else {
            $rules->add($rule);
        }
    }

    return $rules;
}

sub set_defaults {
    my ($list) = @_;

    foreach my $rule ( $list->iter ) {
        if ( !$rule->has_defined('SRC_PORT') ) {
            $rule->set( 'SRC_PORT', Farly::Transport::PortRange->new( 1, 65535 ) );
        }
        if ( !$rule->has_defined('DST_PORT') ) {
            $rule->set( 'DST_PORT', Farly::Transport::PortRange->new( 1, 65535 ) );
        }
    }
}

sub existings_groups {
    my ( $container, $groups ) = @_;

    my $GROUP = Farly::Object->new();
    $GROUP->set( 'ENTRY', Farly::Value::String->new('GROUP') );
    my $OBJECT = Farly::Object->new();
    $OBJECT->set( 'ENTRY', Farly::Value::String->new('OBJECT') );

    foreach my $obj ( $container->iter() ) {

        if ( $obj->matches($GROUP) || $obj->matches($OBJECT) ) {

            $obj->set( 'EXISTS', Farly::Value::String->new('TRUE') );

            my $id = $obj->get('ID')->as_string();

            # if this ID has not been seen create a new ::Set for this group
            if ( !defined $groups->{$id} ) {
                $groups->{$id} = Farly::Object::Set->new();
            }

            $groups->{$id}->add($obj);
        }
    }
}

# create a service group
sub service_group {
    my ( $object, $protocol ) = @_;

    my $group_protocol = Farly::ASA::ProtocolFormatter->new()->as_string($protocol);

    $object->set( 'ENTRY',       Farly::Value::String->new('GROUP') );
    $object->set( 'GROUP_TYPE',  Farly::Value::String->new('service') );
    $object->set( 'OBJECT_TYPE', Farly::Value::String->new('PORT') );
    $object->set( 'GROUP_PROTOCOL', Farly::Value::String->new($group_protocol) );
}

# create a network group
sub network_group {
    my ($object) = @_;

    $object->set( 'ENTRY',       Farly::Value::String->new('GROUP') );
    $object->set( 'GROUP_TYPE',  Farly::Value::String->new('network') );
    $object->set( 'OBJECT_TYPE', Farly::Value::String->new('NETWORK') );
}

# create a group reference
sub group_ref {
    my ($id) = @_;

    my $group_ref = Farly::Object::Ref->new();
    $group_ref->set( 'ENTRY', Farly::Value::String->new('GROUP') );
    $group_ref->set( 'ID',    Farly::Value::String->new($id) );

    return $group_ref;
}

# given a set of rules, return a group for the given property
sub create_group {
    my ( $list, $property ) = @_;

    #the new group
    my $group = Farly::Object::Set->new();

    foreach my $rule ( $list->iter() ) {

        # skip COMMENTS
        next if $rule->has_defined('COMMENT');

        # the new group member
        my $object = Farly::Object->new();

        # set the new group member to the specified "group by property"
        $object->set( "OBJECT", $rule->get($property) );

        # populate the rest of the properties for the group members
        if ( $property eq 'SRC_PORT' || $property eq 'DST_PORT' ) {

            service_group( $object, $rule->get('PROTOCOL')->as_string() );
        }
        elsif ( $property eq 'SRC_IP' || $property eq 'DST_IP' ) {

            network_group($object);
        }

        # add this group member to the group if its not already there
        if ( !$group->includes($object) ) {
            $group->add($object);
        }
    }

    return $group;
}

sub get_group_id {
    my $input = '';

    while ( $input !~ /\S+/ ) {

        print "Enter new group ID : ";
        $input = <STDIN>;
    }

    return $input;
}

# print the new group and prompt the user for a group name
# make sure the new group name is not already used
sub name_new_group {
    my ( $group_set, $groups ) = @_;

    print "group members :\n";

    foreach my $object ( $group_set->iter() ) {

        if ( $object->has_defined('GROUP_PROTOCOL') ) {

            print " ", $object->get('GROUP_PROTOCOL')->as_string(), " ";
        }

        print " ", $object->get('OBJECT')->as_string() . "\n";
    }

    my $input = get_group_id();

    while ( defined( $groups->{$input} ) ) {

        print "\n  that group ID is already used\n\n";
        $input = get_group_id();
    }

    $groups->{$input} = $group_set;

    print "OK\n";

    return $input;
}

# check if the given group already has a group ID
sub current_group_id {
    my ( $group_set, $groups ) = @_;

    foreach my $id ( keys %$groups ) {
        if ( $groups->{$id}->includes($group_set) ) {
            return $id;
        }
    }

    return undef;
}

# process rules to remove
sub remove {
    my ($list) = @_;

    foreach my $rule ( $list->iter ) {

        my $clone = $rule->clone;
        $clone->set( 'REMOVE', Farly::Value::String->new('RULE') );
        $clone->delete_key('LINE');

        display_object($clone);
    }
}

sub display_object {
    my ($object) = @_;

    my $template = Farly::Template::Cisco->new('ASA');

    my $f = {
        'port_formatter'     => Farly::ASA::PortFormatter->new(),
        'protocol_formatter' => Farly::ASA::ProtocolFormatter->new(),
        'icmp_formatter'     => Farly::ASA::ICMPFormatter->new(),
    };

    $template->use_text(1);
    $template->set_formatters($f);

    $template->as_string($object);
    print "\n";
}

__END__

=head1 NAME

f_rewrite.pl  -  Interactively re-write an access-list using user specified group ID's.

=head1 SYNOPSIS

f_rewrite.pl --file FILE --id ID --groupby PROPERTY --output OUTPUT_FILE

=head1 DESCRIPTION

B<f_rewrite.pl> is used to interactively rewrite a firewall configuration in order to
create accurate and logically named groups.

By running B<f_rewrite.pl> repeatedly an expanded firewall configuration can be shrunk
to a minimal number of configuration lines.

B<f_rewrite.pl> will use existing group ID's.

=head1 OPTIONS

=over 8

=item B<--file FILE>

B<Required> firewall configuration FILE. 

=item B<--id ID>

Run for the specified rule ID.

=item B<--groupby PROPERTY>

Must be one of DST_PORT, SRC_IP, DST_IP or SRC_PORT.

=item B<--output OUTPUT_FILE>

Write the group by commands to this file.

=item B<--help>

Prints a brief help message and exits.

=item B<--man>

Prints the manual page and exits.

=back

=head1 EXAMPLES

Run a full firewall rewrite. The cfg.txt "outside-in" rules are expanded and optimized. 
The --output commands are applied to the firewall before running the next f_rewrite.pl
command.

Create new expanded optimized firewall rules:

  f_analyze.pl --file cfg.txt --id outside-in --new outside-in-new >new_cfg.txt

Create new destination port groups:

  f_rewrite.pl --file new_cfg.txt --id outside-in-new --groupby DST_PORT --output new_dst_port_groups.txt

Create new client source IP address groups:

  f_rewrite.pl --file cfg_with_dport_groups.txt --id outside-in-new --groupby SRC_IP --output new_src_groups.txt

Create new server destination IP address groups:

  f_rewrite.pl --file cfg_with_dport_src_groups.txt --id outside-in --groupby DST_IP --output new_dst_groups.txt

=cut
