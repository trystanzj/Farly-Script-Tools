#!/usr/bin/perl -w

# f_search.pl - Farly Script Tools - List open ports
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
use Farly::Opts::Search;
use Farly::Rule::Expander;

my %opts;
my $search_parser;
my $search;

GetOptions( \%opts, 'file=s', 'id=s', 'action=s', 'p=s', 's=s', 'd=s', 'help', 'man' ) or pod2usage(2);

pod2usage(1) if ( defined $opts{'help'} );

pod2usage( -verbose => 2 ) if ( defined $opts{'man'} );

if ( !defined $opts{'file'} ) {
	pod2usage("Please specify a configuration file");
}

if ( !-f $opts{'file'} ) {
	pod2usage("Please specify a valid configuration file");
}

eval {
	$search_parser = Farly::Opts::Search->new( \%opts );
	$search        = $search_parser->search();
};
if ($@) {
	pod2usage($@);
}

print "searching...\n\n";

my $importer = Farly->new();

my $container = $importer->process( "ASA", $opts{'file'} );

my $rule_expander = Farly::Rule::Expander->new($container);

my $expanded_rules = $rule_expander->expand_all();

my $search_result = Farly::Object::List->new();

$expanded_rules->contained_by( $search, $search_result );

my %ports;

foreach my $rule_object ( $search_result->iter() ) {

	if ( $rule_object->has_defined('DST_PORT') ) {
		$ports{ $rule_object->get('DST_PORT')->as_string() }++;
	}

}

foreach my $port ( sort keys %ports ) {
	print "$port\n";
}

__END__

=head1 NAME

f_list_ports.pl - List all unique destination ports associated with the
                  specified rules, hosts, subnets, or protocols.

=head1 SYNOPSIS

f_list_ports.pl --file FILE --option VALUE

=head1 DESCRIPTION

B<f_list_ports.pl> lists all unique destination ports associated with the specified
rules, hosts, subnets, or protocols. Output of this script may be used for firewall
security audits or configuration of other network security tools.

=head1 OPTIONS

=over 8

=item B<--file FILE>

B<Required> firewall configuration FILE. 

=item B<--id ID>

Run the search for the specified rule ID. Is required.

=item B<--action permit|deny>

Specify the firewall rule action to match.

=item B<-p PROTOCOL> 

Search for rules using the specified protocol. Can be a text ID such as tcp or udp, or a protocol number.

Not required, but is recommended or no distinction will be made between TCP and UDP.

=item B<-s ADDRESS>

Source IP Address, Network or FQDN

B<Important: Usage of subnet mask format requires quotes>, for example -d "192.168.1.0 255.255.255.0"

=item B<-d ADDRESS>

Destination IP Address, Network or FQDN

B<Important: Usage of subnet mask format requires quotes>, for example -d "192.168.1.0 255.255.255.0"

=item B<--help>

Prints a brief help message and exits.

=item B<--man>

Prints the manual page and exits.

=back

=head1 EXAMPLES

List all outside TCP ports open between 10.0.0.0/8 and 192.168.1.0/24

    f_search.pl --file fw_config.txt --id outside-in --action permit -p tcp -s 10.0.0.0/8 -d 192.168.1.0/24

=cut