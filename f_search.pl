#!/usr/bin/perl -w

# f_search.pl - Farly Script Tools - Firewall configuration search
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

# Version = 0.20

use strict;
use warnings;
use Getopt::Long;
use Pod::Usage;
use Farly;
use Farly::Rule::Expander;
use Farly::Template::Cisco;
use Farly::ASA::PortFormatter;
use Farly::ASA::ProtocolFormatter;
use Farly::ASA::ICMPFormatter;
use Farly::Opts::Search;
use Farly::Remove::Rule;

my %opts;

GetOptions(
	\%opts,          'file=s',        'id=s',     'action=s',
	'p=s',           's=s',           'sport=s',  'd=s',
	'dport=s',       'matches',       'contains', 'remove',
	'exclude-src=s', 'exclude-dst=s', 'help',     'man'
  )
  or pod2usage(2);

pod2usage(1) if ( defined $opts{'help'} );

pod2usage( -verbose => 2 ) if ( defined $opts{'man'} );

if ( !defined $opts{'file'} ) {
	pod2usage("Please specify a configuration file");
}

if ( !-f $opts{'file'} ) {
	pod2usage("Please specify a valid configuration file");
}

if ( defined $opts{'matches'} && defined $opts{'contains'} ) {
	pod2usage("Either 'matches' or 'contains' can be specified. Not both.");
}

my $search_method = 'search';

if ( defined $opts{'matches'} ) {
	$search_method = 'matches';
}
elsif ( defined $opts{'contains'} ) {
	$search_method = 'contains';
}

if ( defined $opts{'remove'} ) {
	$search_method = 'contained_by';
}

my $search_parser;
my $search;

eval {
	$search_parser = Farly::Opts::Search->new( \%opts );
	$search        = $search_parser->search();
};
if ($@) {
	pod2usage($@);
}

print "!searching...\n\n";

my $importer = Farly->new();

my $container = $importer->process( "ASA", $opts{'file'} );

my $rule_expander = Farly::Rule::Expander->new($container);

my $expanded_rules = $rule_expander->expand_all();

my $search_result = Farly::Object::List->new();

$expanded_rules->$search_method( $search, $search_result );

if ( $search_parser->filter->size > 0 ) {
	$search_result = filter( $search_result, $search_parser->filter() );
}

if ( defined $opts{'remove'} ) {
	$search_result = remove( $container, $search_result );
}

display( $search_result, \%opts );

# END MAIN

sub filter {
	my ( $search_result, $filter ) = @_;

	my $filtered_rule_set = Farly::Object::List->new();

	foreach my $rule_object ( $search_result->iter() ) {

		my $excluded;

		foreach my $exclude_object ( $filter->iter() ) {
			if ( $rule_object->contained_by($exclude_object) ) {
				$excluded = 1;
				last;
			}
		}

		if ( !$excluded ) {
			$filtered_rule_set->add($rule_object);
		}
	}

	return $filtered_rule_set;
}

sub remove {
	my ( $fw, $search_result ) = @_;

	my $remover = Farly::Remove::Rule->new($fw);
	$remover->remove($search_result);

	return $remover->result();
}

sub display {
	my ( $search_result, $opts ) = @_;

	my $template = Farly::Template::Cisco->new('ASA');

	foreach my $rule_object ( $search_result->iter() ) {

		if ( !defined $opts{'remove'} ) {

			my $f = {
				'port_formatter'     => Farly::ASA::PortFormatter->new(),
				'protocol_formatter' => Farly::ASA::ProtocolFormatter->new(),
				'icmp_formatter'     => Farly::ASA::ICMPFormatter->new(),
			};

			$template->use_text(1);
			$template->set_formatters($f);

			$rule_object->delete_key('LINE');
		}

		$template->as_string($rule_object);

		print "\n";
	}
}

__END__

=head1 NAME

f_search.pl - Search firewall configurations for all references to the
              specified host, subnet, ports or protocols.

=head1 SYNOPSIS

f_search.pl --file FILE --option [VALUE]

=head1 DESCRIPTION

B<f_search.pl> searches firewall configurations by source IP, source port, 
destination IP, destination port or any combination of the above. 

The configurable search options are "matches" and "contains." The default option 
is "search" which returns every rule that could possibly match the given Layer 3 or
Layer 4 options. This means a search IP range larger than ranges on the firewall will
still return results.

f_search.pl can be used for day to day firewall troubleshooting or automated
verification of organization specific firewall security policies.

=head1 OPTIONS

=over 8

=item B<--file FILE>

B<Required> firewall configuration FILE. 

=item B<--id ID>

Run the search for the specified rule ID.

=item B<--action permit|deny>

Specify the firewall rule action to match.

=item B<-p PROTOCOL>

Search for rules using the specified protocol. Can be a text ID such as tcp or udp, or a protocol number.

=item B<-s ADDRESS>

Source IP Address, Network or FQDN

B<Important: Usage of subnet mask format requires quotes>, for example -s "192.168.1.0 255.255.255.0"

=item B<--sport PORT>

Source Port Name or Number

=item B<-d ADDRESS>

Destination IP Address, Network or FQDN

B<Important: Usage of subnet mask format requires quotes>, for example -d "192.168.1.0 255.255.255.0"

=item B<--dport PORT>

Destination Port Name or Number

=item B<--matches>

Will match the given search options exactly.

=item B<--contains>

Will find rules which the firewall would match.

=item B<--remove>

The remove option can be used to generate the commands needed to remove the search result from the firewalls.

=item B<--exclude-src FILE>

Specify a FILE with a list of source IPv4 networks to exclude from the search results.
The typical use case for this option would be to audit connectivity to important locations in the network.

=item B<--exclude-dst FILE>

Specify a FILE with a list of destination IPv4 networks to exclude from the search results.

=item B<--help>

Prints a brief help message and exits.

=item B<--man>

Prints the manual page and exits.

=back

=head1 EXAMPLES

Display all rules which permit connectivity to 192.168.2.1:

    f_search.pl --file config.txt -d 192.168.2.1

Display all rules which permit connectivity to 192.168.2.1 tcp/80:

    f_search.pl --file config.txt -d 192.168.2.1 --dport www

Display all permit rules with a source IP address of "any":

    f_search.pl --file config.txt --matches --action permit -s "0.0.0.0 0.0.0.0"

Display all rules permitting telnet:

    f_search.pl --file config.txt --matches --dport telnet

Report external connectivity to subnet 192.168.3.0/24, port 1433, from external locations:

    f_search.pl --file config.txt -d 192.168.3.0/24 --dport 1433 --exclude-src internal_networks.txt

=cut
