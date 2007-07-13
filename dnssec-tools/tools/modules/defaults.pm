#
# Copyright 2006-2007 SPARTA, Inc.  All rights reserved.  See the COPYING
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

use Net::DNS::SEC::Tools::conf;

our @ISA = qw(Exporter);
our @EXPORT = qw(
		   dnssec_tools_alldefaults
		   dnssec_tools_default
		   dnssec_tools_defnames
		);

our $VERSION = "1.0";

my %defaults =
(
	"admin-email"	   => "root",		# Admin's email address.
	"algorithm"	   => "rsasha1",	# Encryption algorithm.
	"enddate"	   => "+2592000",	# Zone life, in seconds.
	"entropy_msg"	   => 1,		# Display entropy message flag.
	"keyarch"	   => "/usr/bin/keyarch",	# Key-archiving program.
	"keygen"	   => getprefixdir() . "/sbin/dnssec-keygen",
	"keygen-opts"	   => "",		# Options for key generator.
	"kskcount"	   => 1,		# Number of KSK keys.
	"ksklength"	   => 2048,		# Length of KSK key.
	"ksklife"	   => 15768000,		# Lifespan of KSK key.
	"lifespan-max"	   => 94608000,		# Max lifespan (two years.)
	"lifespan-min"	   => 3600,		# Min lifespan (one hour.)
	"random"	   => "/dev/urandom",	# Random no. generator device.
	"rndc"		   => getprefixdir() . "/sbin/rndc",
	"roll_logfile"	   => getlocalstatedir() . "/log.rollerd",
	"roll_loglevel"	   => "phase",		# Rollerd's logging level.
	"roll_sleeptime"   => 3600,		# Rollerd's sleep time.
	"savekeys"	   => 1,		# Save/delete old keys flag.
	"tacontact" 	   => "",
	"tadnsvalconffile" => getconfdir() . "/dnsval.conf",
	"tanamedconffile"  => "/usr/local/etc/named/named.conf",
	"tasleeptime"      => 3600,
	"tasmtpserver"     => "",
	"usegui"	   => 0,		# Use GUI for option entry flag.
	"viewimage"	   => "/usr/X11R6/bin/viewimage",
	"zonecheck"	   => getprefixdir() . "/sbin/named-checkzone",
	"zonecheck-opts"   => "",		# Options for zone checker.
	"zonesign"	   => getprefixdir() . "/sbin/dnssec-signzone",
	"zonesign-opts"	   => "",		# Options for zone signer.
	"zonesigner"	   => "/usr/bin/zonesigner",	# Zonesigner program.
	"zskcount"	   => 1,		# Number of Current ZSK keys.
	"zsklength"	   => 1024,		# Length of ZSK key.
	"zsklife"	   => 604800,		# Lifespan of ZSK key.
);

#--------------------------------------------------------------------------
#
# Routine:	dnssec_tools_alldefaults()
#
# Purpose:	Return a copy of the DNSSEC-Tools defaults.
#
sub dnssec_tools_alldefaults
{
	my %defcopy;					# Copy of default hash.

	%defcopy = %defaults;
	return(%defcopy);
}

#--------------------------------------------------------------------------
#
# Routine:	dnssec_tools_default()
#
# Purpose:	Look up a DNSSEC-Tools default and return its value.
#
sub dnssec_tools_default
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
	my @defnames = sort(keys(%defaults));

	return(@defnames);
}

1;

#############################################################################

=pod

=head1 NAME

Net::DNS::SEC::Tools::defaults - DNSSEC-Tools default values.

=head1 SYNOPSIS

  use Net::DNS::SEC::Tools::defaults;

  %defs = dnssec_tools_alldefaults();

  $defalg = dnssec_tools_default("algorithm");

  $cz_path = dnssec_tools_default("zonecheck");

  $ksklife = dnssec_tools_default("ksklife");

  @default_names = dnssec_tools_defnames();

=head1 DESCRIPTION

This module maintains a set of default values used by DNSSEC-Tools
programs.  This allows these defaults to be centralized in a single
place and prevents them from being spread around multiple programs.

=head1 INTERFACES

=over 4

=item I<dnssec_tools_alldefaults()>

This interface returns a copy of all the DNSSEC-Tools defaults in a hash table.

=item I<dnssec_tools_default(default)>

This interface returns the value of a DNSSEC-Tools default.  The interface
is passed I<default>, which is the name of a default to look up.  The value
of this default is returned to the caller.

=item I<dnssec_tools_defnames()>

This interface returns the names of all the DNSSEC-Tools defaults.
No default values are returned, but the default names returned by
I<dnssec_tools_defnames()> may then be passed to I<dnssec_tools_default()>.

=back

=head1 DEFAULT FIELDS

The following are the defaults defined for DNSSEC-Tools.

=over 4

=item B<admin-email>

This default holds the default email address for the DNSSEC-Tools
administrator.

=item B<algorithm>

This default holds the default encryption algorithm.

=item B<enddate>

This default holds the default zone life, in seconds.

=item B<entropy_msg>

This default indicates whether or not I<zonesigner> should display an entropy
message.

=item B<keyarch>

This default holds the path to the key-archiving program.

=item B<keygen>

This default holds the path to the key-generation program.

=item B<kskcount>

This default holds the default number of KSK keys to generate for a zone.

=item B<ksklength>

This default holds the default length of a KSK key.

=item B<ksklife>

This default holds the default lifespan of a KSK key.  This is only used
for determining when to rollover the KSK key.  Keys otherwise have no
concept of a lifespan.  This is measured in seconds.

=item B<lifespan-max>

This default is the maximum lifespan of a key.

=item B<lifespan-min>

This default is the minimum lifespan of a key.

=item B<random>

This default holds the default random number generator device.

=item B<rndc>

This default is the default path of the BIND B<rndc> program.

=item B<roll_logfile>

This default is the path to B<rollerd>'s log file.

=item B<roll_loglevel>

This default is the default logging level for B<rollerd>.

=item B<roll_sleeptime>

This default holds the default sleep time used by the B<rollerd> rollover
daemon.

=item B<savekeys>

This default indicates whether or not keys should be deleted when they are no
longer in use.

=item B<tanamedconffile>

This default specifies the name of the named configuration file.

=item B<tadnsvalconffile>

This default specifies the name of the dnsval configuration file.

=item B<tasleeptime>

This default holds the default value for how long the daemon should sleep.

=item B<tacontact>

This is merely a placeholder for the contact information. There is no useful
default value for this.

=item B<tasmtpserver>

This is merely a placeholder for the name of the smtpserver. There is no useful
default value for this.

=item B<usegui>

This default indicates whether or not the DNSSEC-Tools GUI should be used for
option entry.

=item B<viewimage>

This default holds the default image viewer.

=item B<zonecheck>

This default holds the path to the zone-verification program.

=item B<zonesign>

This default holds the path to the zone-signing program.

=item B<zonesigner>

This default is the path to the B<zonesigner> program.

=item B<zskcount>

This default holds the default number of ZSK keys to generate for a zone.

=item B<zsklength>

This default holds the default length of the ZSK key.

=item B<zsklife>

This default holds the default lifespan of the ZSK key.  This is only used
for determining when to rollover the ZSK key.  Keys otherwise have no
concept of a lifespan.  This is measured in seconds.

=back

=head1 COPYRIGHT

Copyright 2006-2007 SPARTA, Inc.  All rights reserved.
See the COPYING file included with the DNSSEC-Tools package for details.

=head1 AUTHOR

Wayne Morrison, tewok@users.sourceforge.net

=cut
