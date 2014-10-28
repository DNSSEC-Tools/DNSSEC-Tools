#
# Copyright 2006-2014 SPARTA, Inc.  All rights reserved.  See the COPYING
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

our $VERSION = "2.1";
our $MODULE_VERSION = "2.1.0";

my $installdir = getprefixdir() . "/bin"; # DNSSEC-Tools installation directory.

my %defaults =
(
	'admin-email'	   => "root",		# Admin's email address.
	'archivedir'	   => getprefixdir() . "/var/key-archive",
	'algorithm'	   => "rsasha1",	# Encryption algorithm.
	'autosign'	   => 1,		# Auto-sign zone files flag.
	'enddate'	   => "+2764800",	# Zone life, in seconds.
	'entropy_msg'	   => 1,		# Display entropy message flag.
	'keygen'	   => getprefixdir() . "/sbin/dnssec-keygen",
	'keygen-opts'	   => "",		# Options for key generator.
	'kskcount'	   => 1,		# Number of KSK keys.
	'ksklength'	   => 2048,		# Length of KSK key.
	'ksklife'	   => 31536000,		# Lifespan of KSK key.
	'revperiod'	   => 3888000,		# Revocation period.
	'lifespan-max'	   => 94608000,		# Max lifespan (two years.)
	'lifespan-min'	   => 3600,		# Min lifespan (one hour.)
	'prog-ksk1'	   => 'default',	# Program for KSK phase 1.
	'prog-ksk2'	   => 'default',	# Program for KSK phase 2.
	'prog-ksk3'	   => 'default',	# Program for KSK phase 3.
	'prog-ksk4'	   => 'default',	# Program for KSK phase 4.
	'prog-ksk5'	   => 'default',	# Program for KSK phase 5.
	'prog-ksk6'	   => 'default',	# Program for KSK phase 6.
	'prog-ksk7'	   => 'default',	# Program for KSK phase 7.
	'prog-normal'	   => 'default',	# Program for non-rollover.
	'prog-zsk1'	   => 'default',	# Program for ZSK phase 1.
	'prog-zsk2'	   => 'default',	# Program for ZSK phase 2.
	'prog-zsk3'	   => 'default',	# Program for ZSK phase 3.
	'prog-zsk4'	   => 'default',	# Program for ZSK phase 4.
	'random'	   => "/dev/urandom",	# Random no. generator device.
	'rndc'		   => getprefixdir() . "/sbin/rndc",
	'rndc-opts'	   => '',		# Options for rndc.
	'roll_loadzone'	   => 1,		# Zone-reloading flag.
	'roll_logfile'	   => makelocalstatedir() . "/log.rollerd",
	'roll_loglevel'	   => "phase",		# Rollerd's logging level.
	'roll_phasemsg'	   => "long",		# Rollerd's phase logmsg length.
	'roll_sleeptime'   => 3600,		# Rollerd's sleep time.
	'log_tz'	   => "gmt",		# Log message timezone.
	'savekeys'	   => 1,		# Save/delete old keys flag.
	'mailer-server'    => "localhost",	# Mail server.
	'mailer-type'      => "smtp",		# Mail type.
	'tacontact' 	   => "",
	'tatmpdir' 	   => "/tmp/dnssec-tools/trustman",
	'tadnsvalconffile' => getconfdir() . "/dnsval.conf",
	'tanamedconffile'  => getconfdir() . "/named/named.conf",
	'tasleeptime'      => 3600,
	'tasmtpserver'     => "localhost",	# Trustman's SMTP server.
	'taresolvconf'	   => "/etc/resolv.conf",	# resolv.conf file.
	'usegui'	   => 0,		# Use GUI for option entry flag.
	'zone_errors'	   => 5,
	'zonecheck'	   => getprefixdir() . "/sbin/named-checkzone",
	'zonecheck-opts'   => "-i local",	# Options for zone checker.
	'zonefile-parser'  => 'Net::DNS::ZoneFile',
	'zonesign'	   => getprefixdir() . "/sbin/dnssec-signzone",
	'zonesign-opts'	   => "",		# Options for zone signer.
	'zskcount'	   => 1,		# Number of Current ZSK keys.
	'zsklength'	   => 1024,		# Length of ZSK key.
	'zsklife'	   => 7884000,		# Lifespan of ZSK key.
	'usensec3'         => "no",             # Use NSEC3 by default
	'nsec3iter'	   => 100,              # default NSEC3 iterations
	'nsec3salt'	   => "random:64",      # default NSEC3 salt
	'nsec3optout'	   => "no",             # NSEC3 opt-out default
	'blinkenlights'	   => "$installdir/blinkenlights",
	'cleanarch'	   => "$installdir/cleanarch",
	'cleankrf'	   => "$installdir/cleankrf",
	'dtconf'	   => "$installdir/dtconf",
	'dtconfchk'	   => "$installdir/dtconfchk",
	'dtdefs'	   => "$installdir/dtdefs",
	'dtinitconf'	   => "$installdir/dtinitconf",
	'dtrealms'	   => "$installdir/dtrealms",
	'expchk'	   => "$installdir/expchk",
	'fixkrf'	   => "$installdir/fixkrf",
	'genkrf'	   => "$installdir/genkrf",
	'getdnskeys'	   => "$installdir/getdnskeys",
	'grandvizier'	   => "$installdir/grandvizier",
	'keyarch'	   => "$installdir/keyarch",
	'krfcheck'	   => "$installdir/krfcheck",
	'lsdnssec'	   => "$installdir/lsdnssec",
	'lskrf'		   => "$installdir/lskrf",
	'lsrealm'	   => "$installdir/lsrealm",
	'lsroll'	   => "$installdir/lsroll",
	'realmchk'	   => "$installdir/realmchk",
	'realmctl'	   => "$installdir/realmctl",
	'realminit'	   => "$installdir/realminit",
	'rollchk'	   => "$installdir/rollchk",
	'rollctl'	   => "$installdir/rollctl",
	'rollerd'	   => "$installdir/rollerd",
	'rollinit'	   => "$installdir/rollinit",
	'rolllog'	   => "$installdir/rolllog",
	'rollrec-editor'   => "$installdir/rollrec-editor",
	'rollset'	   => "$installdir/rollset",
	'signset-editor'   => "$installdir/signset-editor",
	'tachk'		   => "$installdir/tachk",
	'timetrans'	   => "$installdir/timetrans",
	'trustman'	   => "$installdir/trustman",
	'zonesigner'	   => "$installdir/zonesigner",
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

=item B<archivedir>

This default holds the default directory in which keys will be archived.

=item B<algorithm>

This default holds the default encryption algorithm.

=item B<enddate>

This default holds the default zone life, in seconds.

=item B<entropy_msg>

This default indicates whether or not I<zonesigner> should display an entropy
message.

=item B<keygen>

This default holds the path to the key-generation program.

=item B<keygen-opts>

This default hold a set of options for the key-generation program.

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

=item B<log_tz>

This default is the timezone to be used in log-message timestamps.

=item B<mailer-server>

The mail server that will be contacted by I<dt_adminmail()>.  This is
passed to I<Mail::Send>.

=item B<mailer-type>

The type of mailer that will be contacted by I<dt_adminmail()>.  This is
passed to I<Mail::Mailer> (by way of I<Mail::Send>.)  Any values recognized
by I<Mail::Mailer> may be used here.

=item B<prog_ksk1> ... B<prog_ksk7>

These defaults hold the default phase commands to be executed by B<rollerd>
for each phase of KSK rollover.  The I<default> keyword indicates that the
normal phase processing should be performed.  Multiple commands may be given,
but they must be separated by bangs.  The I<default> keyword may be
combined with other commands.

=item B<prog_normal>

These defaults hold the default phase commands to be executed by B<rollerd>
when a zone is not in a rollover state.  The I<default> keyword indicates that
the normal phase processing should be performed.  Multiple commands may be
given, but they must be separated by bangs.  The I<default> keyword may
be combined with other commands.

=item B<prog_zsk1> ... B<prog_zsk7>

These defaults hold the default phase commands to be executed by B<rollerd>
for each phase of ZSK rollover.  The I<default> keyword indicates that the
normal phase processing should be performed.  Multiple commands may be given,
but they must be separated by bangs.  The I<default> keyword may be
combined with other commands.

=item B<random>

This default holds the default random number generator device.

=item B<revperiod>

This default holds the default revocation period of a KSK key. This is
the minimum period of time a revoked KSK is required to remain in the
signing set so that it is properly observed by resolvers.  This is
measured in seconds.

=item B<rndc>

This default is the default path of the BIND B<rndc> program.

=item B<roll_loadzone>

This default is flag indicates if B<rollerd> should have the DNS daemon
reload its zones.

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

=item B<tacontact>

This is merely a placeholder for the contact information. There is no useful
default value for this.

=item B<tadnsvalconffile>

This default specifies the path of the B<dnsval> configuration file.

=item B<tanamedconffile>

This default specifies the path of the B<named> configuration file.

=item B<taresolvconf>

This default specifies the path to the DNS B<resolv.conf> file.

=item B<tasleeptime>

This default holds the default value for how long the daemon should sleep.

=item B<tasmtpserver>

This default specifies the name of the SMTP server.

=item B<tatmpdir>

This default specifies the location of B<trustman>'s temporary directory.

=item B<usegui>

This default indicates whether or not the DNSSEC-Tools GUI should be used for
option entry.

=item B<zone_errors>

This default holds the maximum number of consecutive errors a particular zone
may have before it is changed to be a I<skip> zone.

=item B<zonecheck>

This default holds the path to the zone-verification program.

=item B<zonecheck-opts>

This default hold a set of options for the zone-verification program.

This default is set to "-i local".  This value has been found to greatly
improve the amount of time it takes B<named-checkzone> to run.

=item B<zonefile-parser>

This default specifies the parser that will be used to parse zone files.
The default value is to use the B<Net::DNS::ZoneFile> module.

=item B<zonesign>

This default holds the path to the zone-signing program.

=item B<zonesign-opts>

This default hold a set of options for the zone-signing program.

=item B<zskcount>

This default holds the default number of ZSK keys to generate for a zone.

=item B<zsklength>

This default holds the default length of the ZSK key.

=item B<zsklife>

This default holds the default lifespan of the ZSK key.  This is only used
for determining when to rollover the ZSK key.  Keys otherwise have no
concept of a lifespan.  This is measured in seconds.

=back

=head1 DNSSEC-TOOLS PROGRAM FIELDS

The following are the defaults holding the paths to the DNSSEC-Tools
programs.

=over 4

=item B<blinkenlights>

This default holds the path to the DNSSEC-Tools B<blinkenlights> program.

=item B<cleanarch>

This default holds the path to the DNSSEC-Tools B<cleanarch> program.

=item B<cleankrf>

This default holds the path to the DNSSEC-Tools B<cleankrf> program.

=item B<dtconf>

This default holds the path to the DNSSEC-Tools B<dtconf> program.

=item B<dtconfchk>

This default holds the path to the DNSSEC-Tools B<dtconfchk> program.

=item B<dtdefs>

This default holds the path to the DNSSEC-Tools B<dtdefs> program.

=item B<dtinitconf>

This default holds the path to the DNSSEC-Tools B<dtinitconf> program.

=item B<expchk>

This default holds the path to the DNSSEC-Tools B<expchk> program.

=item B<fixkrf>

This default holds the path to the DNSSEC-Tools B<fixkrf> program.

=item B<genkrf>

This default holds the path to the DNSSEC-Tools B<genkrf> program.

=item B<getdnskeys>

This default holds the path to the DNSSEC-Tools B<getdnskeys> program.

=item B<keyarch>

This default holds the path to the DNSSEC-Tools B<keyarch> program.

=item B<krfcheck>

This default holds the path to the DNSSEC-Tools B<krfcheck> program.

=item B<lskrf>

This default holds the path to the DNSSEC-Tools B<lskrf> program.

=item B<lsroll>

This default holds the path to the DNSSEC-Tools B<lsroll> program.

=item B<rollchk>

This default holds the path to the DNSSEC-Tools B<rollchk> program.

=item B<rollctl>

This default holds the path to the DNSSEC-Tools B<rollctl> program.

=item B<rollerd>

This default holds the path to the DNSSEC-Tools B<rollerd> program.

=item B<rollinit>

This default holds the path to the DNSSEC-Tools B<rollinit> program.

=item B<rolllog>

This default holds the path to the DNSSEC-Tools B<rolllog> program.

=item B<rollrec-editor>

This default holds the path to the DNSSEC-Tools B<rollrec-editor> program.

=item B<rollset>

This default holds the path to the DNSSEC-Tools B<rollset> program.

=item B<signset-editor>

This default holds the path to the DNSSEC-Tools B<signset-editor> program.

=item B<tachk>

This default holds the path to the DNSSEC-Tools B<tachk> program.

=item B<timetrans>

This default holds the path to the DNSSEC-Tools B<timetrans> program.

=item B<trustman>

This default holds the path to the DNSSEC-Tools B<trustman> program.

=item B<zonesigner>

This default holds the path to the DNSSEC-Tools B<zonesigner> program.

=back

=head1 COPYRIGHT

Copyright 2006-2014 SPARTA, Inc.  All rights reserved.
See the COPYING file included with the DNSSEC-Tools package for details.

=head1 AUTHOR

Wayne Morrison, tewok@tislabs.com

=cut
