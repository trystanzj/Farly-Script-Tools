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

use strict;
use warnings;
use Getopt::Long;
use Farly;
use Farly::Opts::Search;
use Farly::Rule::Expander;

my %opts;
my $search_parser;
my $search;
my $search_method = 'search';

if ( GetOptions( \%opts, 'file=s', 'id=s', 'action=s', 'p=s', 's=s', 'd=s', 'help|?' ) )
{
	if ( defined $opts{'help'} || defined $opts{'?'} ) {
		usage();
	}

	if ( !defined $opts{'file'} ) {
		usage("Please specify a configuration file");
	}

	if ( !-f $opts{'file'} ) {
		usage("Please specify a valid configuration file");
	}

	eval {
		$search_parser = Farly::Opts::Search->new( \%opts );
		$search        = $search_parser->search();
	};
	if ($@) {
		usage($@);
	}

}
else {
	usage();
}

print "\nsearching...\n\n";

my $importer = Farly->new();

my $container = $importer->process( "ASA", $opts{'file'} );

my $rule_expander = Farly::Rule::Expander->new($container);

my $expanded_rules = $rule_expander->expand_all();

my $search_result = Object::KVC::List->new();

$expanded_rules->contained_by( $search, $search_result );

my %ports;

foreach my $rule_object ( $search_result->iter() ) {

	if ( $rule_object->has_defined('DST_PORT') ) {
		$ports{ $rule_object->get('DST_PORT')->as_string() }++;
	}

}

foreach my $port ( keys %ports ) {
	print "$port\n";
}

sub usage {
	my ($err) = @_;

	print qq{

  f_list_ports.pl  -  List all unique destination ports associated with the
                      specified rules, hosts, subnets, or protocols.

Usage:

  f_list_ports.pl [option] [value]

Help:

  f_list_ports.pl --help|-?

Mandatory configuration file:

  --file <file name>  The firewall configuration file

Layer 3 and 4 search options:

  -p <protocol>       Protocol
  -s <ip address>     Source IP Address or Network
  -d <ip>             Destination IP Address or Network

  Usage of subnet mask format requires quotes, for
  example -d "192.168.1.0 255.255.255.0"

Configure the search:

  --id <string>            Specify an access-list ID
  --action <permit|deny>   Limit results to rules of the specified action
};

	if ( defined $err ) {
		print "Error:\n\n";
		print "$err\n";
	}
	exit;
}
