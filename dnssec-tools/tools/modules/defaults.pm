#
# Copyright 2006 SPARTA, Inc.  All rights reserved.  See the COPYING
# file distributed with this software for details
#
# DNSSEC Tools
#
#	DNSSEC-Tools default values.
#
#	This module maintains a set of default values used by DNSSEC-Tools
#	programs.  This allows these defaults to be centralized in a single
#	place and prevents them from being spread around multiple programs.
#

package Net::DNS::SEC::Tools::defaults;

require Exporter;
use strict;

our @ISA = qw(Exporter);
our @EXPORT = qw(dnssec_tools_defaults);

our $CONFFILE = "/usr/local/etc/dnssec/dnssec-tools.conf"; # Configuration file.
our $VERSION = "0.01";

my %defaults =
(
	"checkzone"	=> "named-checkzone",
	"keygen"	=> "dnssec-keygen",
	"signzone"	=> "dnssec-signzone",

	"algorithm"	=> "rsasha1",		# Encryption algorithm.
	"enddate"	=> "+2592000",		# Zone life, in seconds.
	"ksklength"	=> 2048,		# Length of KSK key.
	"ksklife"	=> 15768000,		# Lifetime of KSK key.
	"random"	=> "/dev/urandom",	# Random no. generator device.
	"zsklength"	=> 1024,		# Length of ZSK key.
	"zsklife"	=> 604800,		# Lifetime of ZSK key.

);


#--------------------------------------------------------------------------
#
# Routine:	dnssec_tools_defaults()
#
# Purpose:	Read a configuration file and parse it into pieces.  The
#		lines are tokenized and then stored in the config hash table.
#
sub dnssec_tools_defaults
{
	my $defvar = shift;			# Default field to be returned.
	my $defval;				# Default field's value.

	$defval = $defaults{$defvar};
	return($defval);
}

1;

#############################################################################

=pod

=head1 NAME

Net::DNS::SEC::Tools::defaults - DNSSEC-Tools default values.

=head1 SYNOPSIS

  use Net::DNS::SEC::Tools::defaults;

  $defalg = dnssec_tools_defaults("algorithm");

  $cz_path = dnssec_tools_defaults("checkzone");

  $ksklife = dnssec_tools_defaults("ksklife");

=head1 DESCRIPTION

This module maintains a set of default values used by DNSSEC-Tools
programs.  This allows these defaults to be centralized in a single
place and prevents them from being spread around multiple programs.

I<dnssec_tools_defaults(default)> is the only interface in this module.
It is passed I<default>, which is the name of a default to look up, and
it returns the value of that default.

=head1 DEFAULT FIELDS

There are several types of defaults defined for DNSSEC-Tools.  These types,
however, are only implicit and are not distinguished from one another.
The I<dnssec_tools_defaults()> interface handles everything in exactly the
same fashion.

=head2 BIND Programs

=over 4

=item B<checkzone>

This default holds the path to the I<named-checkzone> BIND program.

=item B<keygen>

This default holds the path to the I<dnssec-keygen> BIND program.

=item B<signzone>

This default holds the path to the I<dnssec-signzone> BIND program.

=back

=head2 DNSSEC-Tools Fields

=over 4

=item B<algorithm>

This default holds the default encryption algorithm.

=item B<enddate>

This default holds the default zone life, in seconds.

=item B<ksklength>

This default holds the default length of the KSK key.

=item B<ksklife>

This default holds the default lifetime of the KSK key.  This is only used
for determining when to roll-over the KSK key.  Keys otherwise have no
concept of a lifetime.  This is measured in seconds.

=item B<random>

This default holds the default random number generator device.

=item B<zsklength>

This default holds the default length of the ZSK key.

=item B<zsklife>

This default holds the default lifetime of the ZSK key.  This is only used
for determining when to roll-over the ZSK key.  Keys otherwise have no
concept of a lifetime.  This is measured in seconds.

=back

=head1 COPYRIGHT

Copyright 2006 SPARTA, Inc.  All rights reserved.
See the COPYING file included with the DNSSEC-Tools package for details.

=head1 AUTHOR

Wayne Morrison, tewok@users.sourceforge.net

=head1 SEE ALSO

B<genkrf(8)>,
B<zonesigner(8)>

=cut
