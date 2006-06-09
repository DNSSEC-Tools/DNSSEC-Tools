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
our @EXPORT = qw(dnssec_tools_defaults dnssec_tools_defnames);

our $CONFFILE = "/usr/local/etc/dnssec/dnssec-tools.conf"; # Configuration file.
our $VERSION = "0.01";

my %defaults =
(
	"bind_checkzone" => "/usr/local/sbin/named-checkzone",
	"bind_keygen"	 => "/usr/local/sbin/dnssec-keygen",
	"bind_signzone"	 => "/usr/local/sbin/dnssec-signzone",

	"viewimage"	 => "/usr/X11R6/bin/viewimage",

	"algorithm"	 => "rsasha1",		# Encryption algorithm.
	"enddate"	 => "+2592000",		# Zone life, in seconds.
	"ksklength"	 => 2048,		# Length of KSK key.
	"ksklife"	 => 15768000,		# Lifespan of KSK key.
	"random"	 => "/dev/urandom",	# Random no. generator device.
	"zsklength"	 => 1024,		# Length of ZSK key.
	"zsklife"	 => 604800,		# Lifespan of ZSK key.

	"entropy_msg"	 => 1,			# Display entropy message flag.
        "savekeys"	 => 1,			# Save/delete old keys flag.
	"usegui"	 => 0,			# Use GUI for option entry flag.

        "tanamedconffile"  => "/usr/local/etc/named/named.conf",
        "tadnsvalconffile" => "/usr/local/etc/dnssec/dnsval.conf",
        "tasleeptime"      => 3600,
);

my @defnames =
(
	"algorithm",
	"bind_checkzone",
	"bind_keygen",
	"bind_signzone",
	"enddate",
	"entropy_msg",
	"ksklength",
	"ksklife",
	"random",
	"savekeys",
	"usegui",
	"viewimage",
	"zsklength",
	"zsklife",
        "tanamedconffile",
        "tadnsvalconffile",
        "tacontact",
        "tasmtpserver",
        "tasleeptime",
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

#--------------------------------------------------------------------------
#
# Routine:	dnssec_tools_defnames()
#
# Purpose:	Return the names of the default values.
#
sub dnssec_tools_defnames
{
	return(@defnames);
}

1;

#############################################################################

=pod

=head1 NAME

Net::DNS::SEC::Tools::defaults - DNSSEC-Tools default values.

=head1 SYNOPSIS

  use Net::DNS::SEC::Tools::defaults;

  $defalg = dnssec_tools_defaults("algorithm");

  $cz_path = dnssec_tools_defaults("bind_checkzone");

  $ksklife = dnssec_tools_defaults("ksklife");

  @default_names = dnssec_tools_defnames();

=head1 DESCRIPTION

This module maintains a set of default values used by DNSSEC-Tools
programs.  This allows these defaults to be centralized in a single
place and prevents them from being spread around multiple programs.

=head1 INTERFACES

=over 4

=item I<dnssec_tools_defaults(default)>

This interface returns the value of a DNSSEC-Tools default.  The interface
is passed I<default>, which is the name of a default to look up.  The value
of this default is returned to the caller.

=item I<dnssec_tools_defnames()>

This interface returns the names of all the DNSSEC-Tools defaults.
No default values are returned, but the default names returned by
I<dnssec_tools_defnames()> may then be passed to I<dnssec_tools_defaults()>.

=back

=head1 DEFAULT FIELDS

The following are the defaults defined for DNSSEC-Tools.

=over 4

=item B<algorithm>

This default holds the default encryption algorithm.

=item B<bind_checkzone>

This default holds the path to the I<named-checkzone> BIND program.

=item B<bind_keygen>

This default holds the path to the I<dnssec-keygen> BIND program.

=item B<bind_signzone>

This default holds the path to the I<dnssec-signzone> BIND program.

=item B<enddate>

This default holds the default zone life, in seconds.

=item B<entropy_msg>

This default indicates whether or not I<zonesigner> should display an entropy
message.

=item B<ksklength>

This default holds the default length of the KSK key.

=item B<ksklife>

This default holds the default lifespan of the KSK key.  This is only used
for determining when to roll-over the KSK key.  Keys otherwise have no
concept of a lifespan.  This is measured in seconds.

=item B<random>

This default holds the default random number generator device.

=item B<savekeys>

This default indicates whether or not keys should be deleted when they are no
longer in use.

=item B<usegui>

This default indicates whether or not the DNSSEC-Tools GUI should be used for
option entry.

=item B<viewimage>

This default holds the default image viewer.

=item B<zsklength>

This default holds the default length of the ZSK key.

=item B<zsklife>

This default holds the default lifespan of the ZSK key.  This is only used
for determining when to roll-over the ZSK key.  Keys otherwise have no
concept of a lifespan.  This is measured in seconds.

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
