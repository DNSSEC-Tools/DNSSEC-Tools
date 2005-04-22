#!/usr/bin/perl
#
# Copyright 2004 Sparta, inc.  All rights reserved.  See the COPYING
# file distributed with this software for details
#
# dnssec-tools
#
#	Option routines.
#
#	The routine in this module manipulates option lists for the
#	dnssec-tools.  After building an option list from three sources
#	(system config file, keyrec file, command-line options), a hash
#	table of options is passed back to the caller.  The caller must
#	use the options as required.
#
#

package Net::DNS::SEC::Tools::tooloptions;

require Exporter;
use strict;

use Net::DNS::SEC::Tools::conf;
use Net::DNS::SEC::Tools::keyrec;

use Getopt::Long;

our $VERSION = "0.01";

our @ISA = qw(Exporter);

our @EXPORT = qw(tooloptions tooloptions opts_krfile opts_getkeys
	         opts_keykr opts_zonekr opts_createkrf opts_reset
	         opts_suspend opts_restore opts_drop);

#
# Standard options accepted by all tools in the dnssec-tools suite.
#
my @stdopts =
(
	"algorithm=s",			# Encryption algorithm
	"endtime=s",			# End-time for signed zone.
	"gends",			# Generate DS records.
	"help",				# Give a usage message and exit.
	"keyrec=s",			# Keyrec name.
	"kgopts=s",			# Additional options for dnssec-keygen.
	"krfile=s",			# Keyrec file.
	"ksdir=s",			# Directory for keyset files.
	"kskdirectory=s",		# Directory for KSK keys.
	"kskkey=s",			# KSK key.
	"ksklength=i",			# Length of KSK.
	"kskpath=s",			# Path to KSK.
	"nokrfile",			# Don't use a keyrec file.
	"random=s",			# Random number generator.
	"reuseksk",			# Reuse KSK.
	"reusezsk",			# Reuse ZSK.
	"szopts=s",			# Additional dnssec-signzone options.
	"verbose+",			# Verbose flag.
	"zone=s",			# Zone name.
	"zdata=s",			# Zone data filename.
	"zfile=s",			# Zone filename.
	"zskdirectory=s",		# Directory for ZSK keys.
	"zskkey=s",			# ZSK key.
	"zsklength=i",			# Length of ZSK.
	"zskpath=s",			# Path to ZSK.
);

my $firstcall		= 1;		# First-call flag.
my $create_krfile	= 0;		# Create non-existent keyrec file flag.

my %cmdopts	= ();			# Options from command line.
my %saveopts	= ();			# Save-area for command-line options.

##############################################################################
#
# Routine:	tooloptions()
#
#
sub tooloptions
{
	my $krfile;				# Keyrec file to parse.
	my $krname;				# Keyrec name to snarf.
	my @csopts;				# Command-specific options.

	my $cslen;				# Length of @csopts.

	my %dnssec_opts;			# Options from config file.
	my $fullkr;				# Reference to krname's keyrec.
	my %keyrec;				# krname's keyrec.

	my @opts;				# Copy of standard options.
	my %configopts;				# Combined options.

	#
	# Get the arguments.  If the keyrec file arg is an empty string, then
	# we know there won't be a keyrec name.
	#
	$krfile = shift;
	if($krfile ne "")
	{
		$krname = shift;
	}
	@csopts = @_;
	$cslen = @csopts;

	#
	# Get the config file and copy the file contents.
	#
	%dnssec_opts = parseconfig();
	%configopts  = %dnssec_opts;

	#
	# If this is the first time we've been called, get the command
	# line options and save them in a module-local variable for use
	# in subsequent calls.
	#
	if($firstcall)
	{
		#
		# Copy the standard options and append any command-specific
		# options that have been given.
		#
		@opts = @stdopts;
		if($cslen > 0)
		{
			push(@opts,@csopts);
		}

		GetOptions(\%cmdopts,@opts);
		$firstcall = 0;
	}

	#
	# Read the keyrec file and pull out the specified keyrec.  If the
	# caller didn't specify a keyrec file, we'll skip this step.
	#
	if($krfile ne "")
	{

		#
		# If the caller wants to create a non-existent keyrec
		# file, we'll g'head and create it now.
		#
		if($create_krfile)
		{
			#
			# If the specified keyrec file doesn't exist,
			# create it.
			#
			if(! -e $krfile)
			{
				my $ret;		# open() return code.

				$ret = open(NEWKRF,"> $krfile");
				if(!defined($ret))
				{
					print STDERR "unable to create keyrec file \"$krfile\"\n";
					return(undef);
				}

				close(NEWKRF);
			}

			#
			# Turn off keyrec file creation.
			#
			$create_krfile = 0;
		}

		#
		# Read the keyrec file.
		#
		keyrec_read($krfile);
		$fullkr = keyrec_fullrec($krname);
		if($fullkr == undef)
		{
			return(undef);
		}
		%keyrec = %$fullkr;

		#
		# Shmoosh the config file and the keyrec together,
		# starting with the config file.
		#
		foreach my $k (sort(keys(%keyrec)))
		{
			$configopts{$k} = $keyrec{$k};
		}

		#
		# Save the name of the keyrec file.
		#
		$configopts{'krfile'} = $krfile;
	}

	#
	# Mix in the options with the config data and the keyrec.
	#
	foreach my $k (sort(keys(%cmdopts)))
	{
		$configopts{$k} = $cmdopts{$k};
	}

	#
	# Return the whole swirling mess back to the user.
	#
	return(\%configopts);
}

##############################################################################
#
# Routine:	opts_krfile()
#
# Purpose:	This routine looks up the keyrec file and keyrec name and
#		then uses those fields to help build an options hash.
#		References to the keyrec file name, keyrec name, and hash
#		table are returned to the caller.
#
#		The keyrec file and name arguments are required parameters.
#		They may be given as empty strings, but they must be given.
#		An array of command-specific options may be given as a third
#		argument.
#
#		If either the keyrec file or keyrec name are given as empty
#		strings, their values will be taken from the -krfile and
#		-keyrec command line options.
#
#		If the keyrec file and keyrec name are both specified by
#		the caller, then this routine will have the same effect as
#		directly calling tooloptions().
#
sub opts_krfile
{
	my $arglen = @_;		# Number of arguments passed.

	my $krf	   = shift;		# Keyrec file to parse.
	my $krname = shift;		# Keyrec name to find in $krf.
	my @csopts = @_;		# Command-specific options.

	my $ret;			# Return value from tooloptions().
	my $ropts;			# Reference to %opts.
	my %opts;			# Options hash.

	#
	# Start setting up the options using the system config file
	# and the command-line options.
	#
	$ropts = tooloptions("");
	%opts = %$ropts;

	#
	# We *must* have been given a keyrec file and a keyrec name at a
	# minimum, even if they were merely nullish placeholders.
	#
	if($arglen < 2)
	{
		return(undef);
	}

	#
	# If an empty keyrec file was given, we'll get it from the
	# -krfile command line option.
	#
	if($krf eq "")
	{
		$krf = $opts{'krfile'};
		if($krf eq "")
		{
			return(undef);
		}
	}

	#
	# If an empty keyrec file was given, we'll get it from the -keyrec
	# or -zone command line options.  Preference is given to -keyrec.
	#
	if($krname eq "")
	{
		$krname = $opts{'keyrec'};
		if($krname eq "")
		{
			$krname = $opts{'zone'};
			if($krname eq "")
			{
				return(undef);
			}
		}
	}

	#
	# Get the options once more, but this time we'll also get info
	# from the keyrec.
	# 
	$ret = tooloptions($krf,$krname,@csopts);
	return($krf,$krname,$ret);
}

##############################################################################
#
# Routine:	opts_getkeys()
#
# Purpose:	This routine returns references to the KSK and ZSK records
#		associated with a given keyrec entry.
#
#		The keyrec file and keyrec name may be specified either by
#		the caller directly (names given as parameters) or by taking
#		them from the command line arguments (names given as empty
#		strings.)  
#
sub opts_getkeys
{
	my $arglen = @_;		# Number of arguments passed.

	my $krf;			# Keyrec file to parse.
	my $krname;			# Keyrec name to find.
	my @csopts;			# Command-specific options.

	my $kskkey;			# KSK key.
	my $kskhash;			# Reference for KSK hash table.
	my %kskrec;

	my $zskkey;			# ZSK key.
	my $zskhash;			# Reference for ZSK hash table.
	my %zskrec;

	my $ropts;			# Reference to %opts.
	my %opts;			# Options hash.

	#
	# Get the keyrec for a specified krfile/krname pair.
	#
	if($arglen == 0)
	{
		($krf,$krname,$ropts) = opts_krfile("","");
	}
	else
	{
		($krf,$krname,$ropts) = opts_krfile(@_);
	}
	if($ropts == undef)
	{
		return(undef);
	}
	%opts = %$ropts;

	#
	# Get the options specifying the KSK key and the ZSK key.
	#
	$kskkey = $opts{'kskkey'};
	$zskkey = $opts{'zskkey'};

	#
	# Dig the KSK record out of the keyrec file.
	#
	$kskhash = tooloptions($krf,$kskkey,@csopts);
	if($kskhash == undef)
	{
		return(undef);
	}
	%kskrec = %$kskhash;

	#
	# Dig the ZSK record out of the keyrec file.
	#
	$zskhash = tooloptions($krf,$zskkey,@csopts);
	if($zskhash == undef)
	{
		return(undef);
	}
	%zskrec = %$zskhash;

	#
	# Return the KSK and ZSK records to our caller.
	#
	return(\%kskrec,\%zskrec);
}

##############################################################################
#
# Routine:	opts_keykr()
#
# Purpose:	This routine returns a reference to a key's keyrec.  It
#		also ensures that the keyrec belongs to a key and not a zone.
#
#		The keyrec file and keyrec name may be specified either by
#		the caller directly (names given as parameters) or by taking
#		them from the command line arguments (names given as empty
#		strings.)  
#
sub opts_keykr
{
	my $arglen = @_;		# Number of arguments passed.

	my $krf;			# Keyrec file to parse.
	my $krname;			# Keyrec name to find.
	my @csopts;			# Command-specific options.

	my $ropts;			# Reference to %keyrec.
	my %keyrec;			# Keyrec hash.

	#
	# Get the keyrec for a specified krfile/krname pair.
	#
	if($arglen == 0)
	{
		($krf,$krname,$ropts) = opts_krfile("","");
	}
	else
	{
		($krf,$krname,$ropts) = opts_krfile(@_);
	}

	#
	# If no hash file was returned (unknown zone or keyrec name, most
	# likely) then we'll return an undefined value.
	#
	if($ropts == undef)
	{
		return(undef);
	}
	%keyrec = %$ropts;

	#
	# Ensure this keyrec is for a key.
	#
	if(($keyrec{'keyrec_type'} ne "key")	&&
	   ($keyrec{'keyrec_type'} ne "ksk")	&&
	   ($keyrec{'keyrec_type'} ne "zsk"))
	{
		return(undef);
	}

	#
	# Return the key keyrec to our caller.
	#
	return(\%keyrec);
}

##############################################################################
#
# Routine:	opts_zonekr()
#
# Purpose:	This routine returns a reference to a zone's keyrec, with
#		the config file and command line options mixed in.  It also
#		ensures that the keyrec belongs to a zone and not a key.
#
#		The keyrec file and keyrec name may be specified either by
#		the caller directly (names given as parameters) or by taking
#		them from the command line arguments (names given as empty
#		strings.)  
#
sub opts_zonekr
{
	my $arglen = @_;		# Number of arguments passed.

	my $krf;			# Keyrec file to parse.
	my $krname;			# Keyrec name to find.
	my @csopts;			# Command-specific options.

	my $ropts;			# Reference to %keyrec.
	my %keyrec;			# Keyrec hash.

	my $keyname;			# Name of zone's keys.
	my $khref;			# Key hash reference.
	my %keyhash;			# Hash for zone's keys' keyrecs.

	#
	# Get the keyrec for a specified krfile/krname pair.
	#
	if($arglen == 0)
	{
		($krf,$krname,$ropts) = opts_krfile("","");
	}
	else
	{
		($krf,$krname,$ropts) = opts_krfile(@_);
	}

	#
	# If no hash file was returned (unknown zone or keyrec name, most
	# likely) then we'll return an undefined value.
	#
	if($ropts == undef)
	{
		return(undef);
	}
	%keyrec = %$ropts;

	#
	# Ensure this keyrec is for a zone.
	#
	if($keyrec{'keyrec_type'} ne "zone")
	{
		return(undef);
	}

	#
	# Dig the KSK record out of the keyrec file and add it to the options.
	#
	$keyname = $keyrec{'kskkey'};
	$khref = tooloptions($krf,$keyname,@csopts);
	if(defined($khref))
	{
		%keyhash = %$khref;
		foreach my $k (keys(%keyhash))
		{
			if($k !~ /^keyrec_/)
			{
				$keyrec{$k} = $keyhash{$k};
			}
		}
	}

	#
	# Add the ZSK record to the options.
	#
	$keyname = $keyrec{'zskkey'};
	$khref = tooloptions($krf,$keyname,@csopts);
	if(defined($khref))
	{
		%keyhash = %$khref;
		foreach my $k (keys(%keyhash))
		{
			if($k !~ /^keyrec_/)
			{
				$keyrec{$k} = $keyhash{$k};
			}
		}
	}

	#
	# Return the zone keyrec to our caller.
	#
	return(\%keyrec);
}

##############################################################################
#
# Routine:	opts_createkrf()
#
# Purpose:	Turn on creation of non-existent keyrec files.
#		This flag is only used by tooloptions().
#
sub opts_createkrf
{
	$create_krfile = 1;
}

##############################################################################
#
# Routine:	opts_suspend()
#
# Purpose:	Suspend use of the command-line options.  While suspended,
#		tooloptions() will not add them to the final hash table.
#
sub opts_suspend
{
	%saveopts = %cmdopts;
	%cmdopts  = ();
}

##############################################################################
#
# Routine:	opts_restore()
#
# Purpose:	Restore use of the command-line options.  This will allow
#		tooloptions() to add them to the final hash table.
#
sub opts_restore
{
	%cmdopts  = %saveopts;
	%saveopts = ();
}

##############################################################################
#
# Routine:	opts_drop()
#
# Purpose:	Irrevocably disable use of the command-line options.
#		tooloptions() will no longer add them to the final hash table.
#
#
sub opts_drop
{
	%cmdopts  = ();
	%saveopts = ();
}

##############################################################################
#
# Routine:	opts_reset()
#
# Purpose:	Reset the first-call flag so we can look at our command-
#		line arguments once more.
#
sub opts_reset
{
	$firstcall = 1;
	opts_drop();
}

1;

#############################################################################

=pod

=head1 NAME

Net::DNS::SEC::Tools::tooloptions - dnssec-tools option routines.

=head1 SYNOPSIS

  use Net::DNS::SEC::Tools::tooloptions;

  $keyrec_file = "portrigh.keyrec";
  $keyrec_name = "Kportrigh.com.+005+10988";
  @specopts = ("propagate+", "waittime=i");

  $optsref = tooloptions($keyrec_file,$keyrec_name);
  %options = %$optsref;

  $optsref = tooloptions($keyrec_file,$keyrec_name,@specopts);
  %options = %$optsref;

  $optsref = tooloptions("",@specopts);
  %options = %$optsref;

  ($krfile,$krname,$optsref) = opts_krfile($keyrec_file,"");
  %options = %$optsref;

  ($krfile,$krname,$optsref) = opts_krfile("",$keyrec_name,@specopts);
  %options = %$optsref;

  ($krfile,$krname,$optsref) = opts_krfile("","");
  %options = %$optsref;

  $key_ref = opts_keykr();
  %key_kr  = %$key_ref;

  $optsref = opts_keykr($keyrec_file,$keyrec_name);
  %options = %$optsref;

  $zoneref = opts_zonekr();
  %zone_kr = %$zoneref;

  $zoneref = opts_zonekr($keyrec_file,$keyrec_name);
  %zone_kr = %$zoneref;

  opts_createkrf();

  opts_suspend();

  opts_restore();

  opts_drop();

  opts_reset();


=head1 DESCRIPTION

The dnssec-tools support a set of options common to all the tools in the
suite.  These options may have defaults set in the
B</usr/local/etc/dnssec/dnssec-tools.conf> configuration file, in a I<keyrec>
file, from command-line options, or from any combination of the three.  In
order to enforce a common sequence of option interpretation, all dnssec-tools
should use the I<Net::DNS::SEC::Tools::tooloptions()> routine to initialize
its options.

The I<keyrec_file> argument specifies a I<keyrec> file that will be consulted.
The I<keyrec> named by the I<keyrec_name> argument will be loaded.  If no
I<keyrec> file should be used, then I<keyrec_file> should be an empty string
and the I<keyrec_name> parameter not included.  The I<@specopts> array
contains command-specific arguments; the arguments must be in the format
prescribed by the I<Getopt::Long> Perl module.

I<tooloptions()> combines data from these three option sources into a hash
table.  The hash table is returned to the caller, which will then use the
options as needed.

The command-line options are saved between calls, so a command may call
I<tooloptions()> multiple times and still have the command-line options
included in the final hash table.  This is useful for examining multiple
I<keyrec>s in a single command.  Inclusion of command-line options may be
suspended and restored using the I<opts_suspend()> and I<opts_restore()> calls.
Options may be discarded entirely by calling I<opts_drop()>; once dropped,
command-line options may never be restored.  Suspension, restoration, and
dropping of command-line options are only effective after the initial
I<tooloptions()> call. 

The options sources are combined in this manner:

=over 4

=item 1.  B</usr/local/etc/dnssec/dnssec-tools.conf>

The system-wide configuration file is read and these option values are used
as the defaults.  These options are put into a hash table, with the option
names as the hash key.

=item 2. I<Keyrec> File

If a I<keyrec> file was specified, then the I<keyrec> named by I<keyrec_name>
will be retrieved.  The I<keyrec>'s fields are added to the hash table.  Any
field whose keyword matches an existing hash key will override the existing
value.

=item 3. Command-line Options

The command-line options, specified in I<@specopts>, are parsed using
I<Getoptions()> from the I<Getopt::Long> Perl module.  These options are
folded into the hash table; again possibly overriding existing hash values.
The options given in I<@specopts> must be in the format required by
I<Getoptions()>.

=back

A reference to the hash table created in these three steps is returned to the
caller.


=head1 EXAMPLE

B</usr/local/etc/dnssec/dnssec-tools.conf> has these entries:

=over 4

ksklength      1024

zsklength      512

=back

portrigh.keyrec has this entry:

=over 4

key	"Kportrigh.com.+005+10988"

zsklength	"1024"

=back

B<zonesigner> is executed with this command line:

=over 4

zonesigner -ksklength 512 -zsklength 4096 -wait 600 ...  portrigh.com

=back

I<tooloptions("portrigh.keyrec","Kportrigh.com.+005+10988",("wait=i"))>
will read each option source in turn, ending up with:
    I<ksklength> 	 512
    I<zsklength> 	 4096
    I<wait> 		 600


=head1 TOOL OPTION ARGUMENTS

Many of the dnssec-tools option interfaces take the same set of arguments:
I<$keyrec_file>, I<$keyrec_name>, and I<@csopts>.  These arguments are used
similarly by all the interfaces; differences are noted in the interface
descriptions in the next section.

=over 4

=item I<$keyrec_file>

Name of the I<keyrec> file to be searched.

=item I<$keyrec_name>

Name of the I<keyrec> that is being sought

=item I<@csopts>

Command-specific options.

=back

The I<keyrec> named in I<$keyrec_name> is selected from the I<keyrec> file
given in I<$keyrec_file>.  If either I<$keyrec_file> or I<$keyrec_name> are
given as empty strings, their values will be taken from the I<-krfile> and
I<-keyrec> command line options.

A set of command-specific options may be specified in I<@csopts>.  These
options are in the format required by the I<Getopt::Long> Perl module.  If
I<@csopts> is left off the call, then no command-specific options will be
included in the final option hash.


=head1 TOOL OPTION INTERFACES

=over 4

=item I<tooloptions($keyrec_file,$keyrec_name,@csopts)>

This I<tooloptions()> call builds an option hash from the system configuration
file, a I<keyrec>, and a set of command-specific options.  A reference to
this option hash is returned to the caller.

If I<$keyrec_file> is given as an empty string, then no I<keyrec> file will
be consulted.  In this case, it is assumed that I<$keyrec_name> will be left
out altogether.

If a non-existent I<$keyrec_file> is given and I<opts_createkrf()> has been
called, then the named I<keyrec> file will be created.  I<opts_createkrf()>
must be called for each I<keyrec> file that must be created, as the
I<tooloptions> I<keyrec>-creation state is reset after I<tooloptions()> has
completed.

=item I<opts_krfile($keyrec_file,$keyrec_name,@csopts)>

The I<opts_krfile()> routine looks up the I<keyrec> file and I<keyrec> name
and uses those fields to help build an options hash.  References to the
I<keyrec> file name, I<keyrec> name, and the option hash table are returned
to the caller.

The I<$keyrec_file> and I<$keyrec_name> arguments are required parameters.
They may be given as empty strings, but they B<must> be given.

If the I<$keyrec_file> file and I<$keyrec_name> name are both specified by
the caller, then this routine will have the same effect as directly calling
I<tooloptions()>.


=item I<opts_getkeys($keyrec_file,$keyrec_name,@csopts)>

This routine returns references to the KSK and ZSK I<keyrec>s associated with
a specified I<keyrec> entry.  This gives an easy way to get a zone's I<keyrec>
entries in a single step.

This routine acts as a front-end to the I<opts_krfile()> routine.
I<opts_getkeys()>' arguments conform to those of I<opts_krfile()>.

If I<opts_getkeys()> isn't passed any arguments, it will act as if both
I<$keyrec_file> and I<$keyrec_name> were given as empty strings.  In this
case, their values will be taken from the I<-krfile> and I<-keyrec> command
line options.


=item I<opts_keykr($keyrec_file,$keyrec_name,@csopts)>

This routine returns a reference to a key I<keyrec>.  It ensures that the
named I<keyrec> is a key I<keyrec>; if it isn't, I<undef> is returned.

This routine acts as a front-end to the I<opts_krfile()> routine.
I<opts_keykr()>'s arguments conform to those of I<opts_krfile()>.

If I<opts_keykr()> isn't passed any arguments, it will act as if both
I<$keyrec_file> and I<$keyrec_name> were given as empty strings.  In this
case, their values will be taken from the I<-krfile> and I<-keyrec> command
line options.


=item I<opts_zonekr($keyrec_file,$keyrec_name,@csopts)>

This routine returns a reference to a zone I<keyrec>.  The I<keyrec> fields
from the zone's KSK and ZSK are folded in as well, but the key's I<keyrec_>
fields are excluded.  This call ensures that the named I<keyrec> is a zone
I<keyrec>; if it isn't, I<undef> is returned.

This routine acts as a front-end to the I<opts_krfile()> routine.
I<opts_zonekr()>'s arguments conform to those of I<opts_krfile()>.

If I<opts_zonekr()> isn't passed any arguments, it will act as if both
I<$keyrec_file> and I<$keyrec_name> were given as empty strings.  In this
case, their values will be taken from the I<-krfile> and I<-keyrec> command
line options.

=item I<opts_createkrf()>

Force creation of an empty I<keyrec> file if the specified file does not
exist.  This may happen on calls to I<tooloptions()>, I<opts_getkeys()>,
I<opts_krfile()>, and I<opts_zonekr()>.

=item I<opts_suspend()>

Suspend inclusion of the command-line options in building the final hash
table of responses.

=item I<opts_restore()>

Restore inclusion of the command-line options in building the final hash
table of responses.

=item I<opts_drop()>

Discard the command-line options.  They will no longer be available for
inclusion in building the final hash table of responses for this execution
of the command.

=item I<opts_reset()>

Reset an internal flag so that the command-line arguments may be
re-examined.  This is usually only useful if the arguments have been
modified by the calling program itself.

=back


=head1 AUTHOR

Wayne Morrison, tewok@users.sourceforge.net


=head1 SEE ALSO

zonesigner(1)

Net::DNS::SEC::Tools::conf(3), Net::DNS::SEC::Tools::keyrec(3), Getopt::Long(3)

Net::DNS::SEC::Tools::keyrec(5)


=head1 TODO

=cut
