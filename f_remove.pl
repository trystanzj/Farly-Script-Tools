#!/usr/bin/perl -w

# f_remove.pl - Farly Script Tools - Retired address removal
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
use Farly::Remove::Address;
use Farly::Template::Cisco;

my %opts;
my $ip;

GetOptions( \%opts, 'file=s', 'host=s', 'net=s', 'help', 'man' ) or pod2usage(2);

pod2usage(1) if ( defined $opts{'help'} );

pod2usage( -verbose => 2 ) if ( defined $opts{'man'} );

if ( ! defined $opts{'file'} ) {
	pod2usage("Please specify a configuration file");
}
	
if ( !-f $opts{'file'} ) {
	pod2usage("Please specify a valid configuration file");
}

if ( ! defined $opts{'host'} &&  ! defined $opts{'net'} ) {
	pod2usage("Please specify a host or address to remove");	
}

eval {
	if ( $opts{'host'} ) {
		$ip = Farly::IPv4::Address->new( $opts{'host'} );
	}
	elsif ( $opts{'net'} ) {
		$ip = Farly::IPv4::Network->new( $opts{'net'} );
	}
};
if ($@) {
	pod2usage($@);
}

print "! remove\n\n";

my $fw;
eval {
	my $importer = Farly->new();
	$fw = $importer->process( "ASA", $opts{'file'} );
};
if ($@) {
	pod2usage($@);
}

my $remover = Farly::Remove::Address->new($fw);

$remover->remove($ip);

my $template = Farly::Template::Cisco->new('ASA');

foreach my $rule_object ( $remover->result()->iter() ) {
	$template->as_string($rule_object);
	print "\n";
}


__END__

=head1 NAME

f_remove.pl - Generates firewall configurations needed to remove
              all references to the specified host or subnet.

=head1 SYNOPSIS

f_remove.pl --file FILE [ --host IP | --net NETWORK ]

=head1 DESCRIPTION

B<f_remove.pl> removes all references to the specified IP address or network. It takes groups and group dependencies into account.
i.e. A rule referencing a group with only one entry will be removed before the group is removed.

=head1 OPTIONS

=over 8

=item B <--file FILE>

B<Required> firewall configuration FILE. 

=item B <--host IP>

Host IPv4 address.

=item B <--net NETWORK>

IPv4 Network in CIDR or dotted decimal mask format.  

B<Important: Usage of subnet mask format requires quotes>, for example -d "192.168.1.0 255.255.255.0"

=back

=cut
