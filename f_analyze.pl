#!/usr/bin/perl -w

# f_analyze.pl  -  Farly Script Tools - Duplicate and shadowed
#                  firewall rule analysis
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
use Farly::Rule::Optimizer;
use Farly::Remove::Rule;
use Farly::Template::Cisco;
use Farly::ASA::PortFormatter;
use Farly::ASA::ProtocolFormatter;
use Farly::ASA::ICMPFormatter;

my %opts;
my $search = Farly::Object->new();

GetOptions( \%opts, 'file=s', 'id=s', 'verbose', 'new', 'remove', 'help', 'man' ) or pod2usage(2);

pod2usage(1) if ( defined $opts{'help'} );

pod2usage( -verbose => 2 ) if ( defined $opts{'man'} );

if ( !defined $opts{'file'} ) {
    pod2usage("Please specify a valid configuration file");
}

if ( !-f $opts{'file'} ) {
    pod2usage("Please specify a valid configuration file");
}

if ( !defined $opts{'id'} ) {
    pod2usage("Please specify an access-list ID");
}

if ( defined $opts{'new'} && defined $opts{'remove'} ) {
    pod2usage("Please specify either new or remove");
}

if ( !defined $opts{'verbose'} && !defined $opts{'new'} && !defined $opts{'remove'} ) {
    pod2usage("Please specify an analysis option");
}

eval {
    $search->set( 'ENTRY' => Farly::Value::String->new('RULE') );
    $search->set( 'ID'    => Farly::Value::String->new( $opts{'id'} ) );
};
if ($@) {
    pod2usage($@);
}

print "\n! analyzing...\n\n";

my $importer = Farly->new();

my $container = $importer->process( "ASA", $opts{'file'} );

my $rule_expander = Farly::Rule::Expander->new($container);

my $expanded_rules = $rule_expander->expand_all();

my $rules = Farly::Object::List->new();

$expanded_rules->matches( $search, $rules );

if ( $rules->size == 0 ) {
    die "\n", $opts{'id'}, " is not a valid access-list id\n";
}

my $l4_optimizer = Farly::Rule::Optimizer->new($rules);
$l4_optimizer->verbose( $opts{'verbose'} );
$l4_optimizer->run();

my $icmp_optimizer = Farly::Rule::Optimizer->new( $l4_optimizer->optimized() );
$icmp_optimizer->verbose( $opts{'verbose'} );
$icmp_optimizer->set_icmp();
$icmp_optimizer->run();

my $l3_optimizer = Farly::Rule::Optimizer->new( $icmp_optimizer->optimized() );
$l3_optimizer->verbose( $opts{'verbose'} );
$l3_optimizer->set_l3();
$l3_optimizer->run();

if ( defined $opts{'new'} ) {

    print "\n! new\n\n";
    display( $l3_optimizer->optimized() );

}
elsif ( defined $opts{'remove'} ) {

    my $config = Farly::Object::List->new();
    $container->matches( $search, $config );

    # create the rule remover object for this firewall
    my $remover = Farly::Remove::Rule->new($config);

    print "\n! remove\n\n";
    $remover->remove($rules);

    # does the configuration need to be modified?
    if ( $remover->result()->size() > 0 ) {
        display( $remover->result(), \%opts );
    }

}

sub display {
    my ( $list, $opts ) = @_;

    my $template = Farly::Template::Cisco->new('ASA');

    my $f = {
        'port_formatter'     => Farly::ASA::PortFormatter->new(),
        'protocol_formatter' => Farly::ASA::ProtocolFormatter->new(),
        'icmp_formatter'     => Farly::ASA::ICMPFormatter->new(),
    };

    $template->use_text(1);
    $template->set_formatters($f);

    foreach my $rule_object ( $list->iter() ) {
        if ( !defined $opts{'remove'} ) {
            $rule_object->delete_key('LINE');
        }
        $template->as_string($rule_object);
        print "\n";
    }
}

__END__

=head1 NAME

f_analyze.pl - Find duplicate and shadowed firewall rules

=head1 SYNOPSIS

f_analyze.pl --file FILE --id ID [--verbose] --new|--remove

=head1 DESCRIPTION

B<f_analyze.pl> finds duplicate and shadowed firewall rules. A specific 
firewall configuration and access-list ID must be specified.

=head1 OPTIONS

=over 8

=item B<--file FILE>

B<Required> firewall configuration FILE. 

=item B<--id ID>

Run for the specified rule ID.

=item B<--verbose>

Displays a detailed report showing all duplicate or shadowed rules.

=item B<--new>

Returns an optimised rule set in expanded format.

=item B<--remove>

Returns all expanded rules which are errors.

=item B<--help>

Prints a brief help message and exits.

=item B<--man>

Prints the manual page and exits.

=back

=head1 EXAMPLES

Print a detailed analysis and new rule set.

    f_analyze.pl --file fw_config.txt --id outside-in --verbose --new
    
=cut
