#!/usr/bin/perl
#
# Copyright 2005-2006 SPARTA, Inc.  All rights reserved.  See the COPYING
# file distributed with this software for details.
#
# DNSSEC-Tools
#
#	Option routines.
#
#	The routine in this module manipulates option lists for the
#	DNSSEC-Tools.  After building an option list from three sources
#	(system config file, keyrec file, command-line options), a hash
#	table of options is passed back to the caller.  The caller must
#	use the options as required.
#
#

package Net::DNS::SEC::Tools::tooloptions;

use Net::DNS::SEC::Tools::QWPrimitives;
require Exporter;
use strict;

use Net::DNS::SEC::Tools::conf;
use Net::DNS::SEC::Tools::keyrec;

our $VERSION = "0.01";

our @ISA = qw(Exporter);

our @EXPORT = qw(tooloptions tooloptions opts_krfile opts_getkeys
	         opts_keykr opts_zonekr opts_createkrf opts_setcsopts
	         opts_reset opts_suspend opts_restore opts_drop);

############################################################################
#
# Standard options accepted by all tools in the DNSSEC-Tools suite.
#
# These are in Getopt::GUI::Long format.
#
my @stdopts =
(
	['GUI:separator',	'Cryptography Options:'],
		["algorithm=s",		"Cryptographic HASH algorithm",
		 question => {
				type	=> 'menu',
				values	=> [qw(RSA RSAMD5 DH DSA RSASHA1 HMAC-MD5)],
				default	=> 'RSAMD5'
			     }
		],
		["random=s",		"Random number generator device"],
		["endtime=s",		"End-time for signed zone"],
		["gends",		"Generate DS records"],

	'',

	['GUI:separator',	'Configuration Options:'],
		["keyrec=s",		"Keyrec name",
		  helpdesc => 'test'
		],
		["krfile=s",		"Keyrec file"],
		["nokrfile",		"Do not use a Keyrec file"],
		["genkeys",		"Generate KSK and ZSK"],
		["savekeys",		"Save old keys in archive directory"],
		["archivedir=s",	"Key archive directory"],

	'',

	['GUI:separator',	'Key-signing Key Options:'],
		["genksk",		"Generate KSK"],
		["kskkey=s",		"KSK key"],
		["kskdirectory=s",	"Directory for KSK keys"],
		["ksklength=i",		"Length of KSK"],
		["ksklife=i",		"Life-span of KSK"],
		["kskpath=s",		"Path to KSK"],
		["ksdir=s",		"Directory for keyset files"],

	'',

	['GUI:separator',	'Zone-signing Key Options:'],
		["genzsk",		"Generate ZSK"],
		["signset=s",		"Signing Set"],
		["zskkey=s",		"ZSK key"],
		["zskcount=i",		"Number of Current ZSKs to generate"],
		["zskdirectory=s",	"Directory for ZSK keys"],
		["zsklength=i",		"Length of ZSK"],
		["zsklife=i",		"Life-span of ZSK"],
		["zskpath=s",		"Path to ZSK"],

	'',

	['GUI:separator',	'Zone Options:'],
		["zone=s",		"Zone name",	required => 1],
		["zdata=s",		"Zone data filename"],
		["zfile=s",		"Zone filename"],

		'',

		["kgopts=s",		"Additional options for dnssec-keygen"],
		["szopts=s",		"Additional dnssec-signzone options"],

	'',

	['GUI:separator',	'Roll-over Options:'],
		["roll_logfile=s",	"Roll-over manager's log filename"],
		["roll_loglevel=s",	"Roll-over manager's logging level"],
		["roll_sleeptime=i",	"Sleep-time for Roll-over manager"],

	'',

	['GUI:separator',		'Control Options:'],
		["verbose+",		"Verbose mode"],
		["Version",		"Display version number"],
		["help",		'Show command line help',
		 question => {
				values	=> 'Display Help',
				type	=> 'button'
			     }
		],

	#
	# Getopt::Long::GUI-specific argument specifications.  Ignored if !GUI.
	#

	#
	# Don't show the "other arguments" dialog box.
	#
	['GUI:nootherargs',1],

	#
	# Prompt for zone input and output file names.
	#
	['GUI:guionly',
		{
			type		=> 'fileupload',
			name		=> 'zonein',
			check_values	=> \&qw_required_field,
			text		=> 'Input Zone File:'
		},
	 	{
			type		=> 'fileupload',
			name		=> 'zoneout',
			check_values	=> \&qw_required_field,
			text		=> 'Output Zone File'
		}
	],

	#
	# Map to other args variable.
	#
	['GUI:hook_finished',
		sub
		{
			@main::saveargs = @ARGV;
		}
	],

	['GUI:actions',
		sub
		{
			require QWizard;
			import QWizard;
			qwparam('__otherargs', qwparam('zonein') . " " . 
			      qwparam('zoneout'));
			$Getopt::Long::GUI::verbose = 1;
			return('OK');
		}
	],
);

############################################################################
#

my $firstcall		= 1;		# First-call flag.
my $create_krfile	= 0;		# Create non-existent keyrec file flag.

my $gui			= 0;		# GUI-usage flag.

my %cmdopts	= ();			# Options from command line.
my %saveopts	= ();			# Save-area for command-line options.

my @cspecopts	= ();			# Caller-saved command-specific options.

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

	my %dnssec_opts;			# Options from the config file.
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

	#
	# Set up the command-specific options array.  We'll start with
	# whatever's left in the argument list.  If the caller has saved
	# a set of options already, we'll plop those onto the end of
	# this list.
	#
	@csopts = @_;
	if(scalar(@cspecopts) >= 0)
	{
		push @csopts,@cspecopts;
	}
	$cslen = @csopts;

	#
	# Get the config file and copy the file contents.
	#
	%dnssec_opts = parseconfig();
	%configopts  = %dnssec_opts;

	#
	# Set the GUI-usage flag according to the config file.
	#
	$gui = $configopts{'usegui'};

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

		localgetoptions(\%cmdopts,@opts);
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
# Routine:	opts_setcsopts()
#
# Purpose:	Save a copy of the caller-specified, caller-specific options.
#
#
sub opts_setcsopts
{
	my @csopts = @_;			# Command-specific options.
	@cspecopts = @csopts;
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

##############################################################################
#
# Routine:	opts_gui()
#
# Purpose:	Set the GUI flag to allow GUI usage.
#
sub opts_gui
{
	$gui = 1;
}

##############################################################################
#
# Routine:	opts_nogui()
#
# Purpose:	Set the GUI flag to disallow GUI usage.
#
sub opts_nogui
{
	$gui = 0;
}

##############################################################################
#
# Routine:	localgetoptions()
#
# Purpose:	A wrapper to determine if options should be specified through
#		a GUI or not.  If the $gui flag isn't set, then the GUI won't
#		be used.  If $gui is set and the Getopt::Long::GUI routine is
#		available, then we'll use the GUI.  Otherwise, we'll just
#		call Getopt::Long.
#
#		localgetoptions() and localoptionsmap() are only needed to
#		support "not-requiring" Getopt::Long::GUI.
#
#		Code pulled from the Getopt::Long::GUI documentation and can
#		be updated to newer versions in the future, if need be.
#
sub localgetoptions
{
	my @args = @_;		# Force copy since we're called multiple times.

	if($gui)
	{
		if(($#ARGV == -1) && (eval {require Getopt::GUI::Long;}))
		{
			import Getopt::GUI::Long;
			return(GetOptions(@args));
		}
	}

	require Getopt::Long;
	import Getopt::Long;

	GetOptions(localoptionsmap(@args));
}

##############################################################################
#
# Routine:	localoptionsmap()
#
# Purpose:	Maps Getopt::Long::GUI arguments to Getopt::Long arguments.
#
#		Code pulled from the Getopt::Long::GUI documentation and can
#		be updated to newer versions in the future, if need be.
#
sub localoptionsmap
{
	my ($st, $cb, @opts) = ((ref($_[0]) eq 'HASH') ? (1, 1, $_[0]) : (0,2));

	for(my $i = $st; $i <= $#_; $i += $cb)
	{
		if($_[$i])
		{
			next if((ref($_[$i]) eq 'ARRAY') && ($_[$i][0] =~ /^GUI:/));

			push @opts, ((ref($_[$i]) eq 'ARRAY') ? $_[$i][0] : $_[$i]);
			push @opts, $_[$i+1] if($cb == 2);
		}
	}

	return(@opts);
}

1;

#############################################################################

=pod

=head1 NAME

Net::DNS::SEC::Tools::tooloptions - DNSSEC-Tools option routines.

=head1 SYNOPSIS

  use Net::DNS::SEC::Tools::tooloptions;

  $keyrec_file = "example.keyrec";
  $keyrec_name = "Kexample.com.+005+10988";
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

  opts_setcsopts(@specopts);

  opts_createkrf();

  opts_suspend();

  opts_restore();

  opts_drop();

  opts_reset();

  opts_gui();

  opts_nogui();

=head1 DESCRIPTION

DNSSEC-Tools supports a set of options common to all the tools in the suite.
These options may have defaults set in the B<dnssec-tools.conf> configuration
file, in a I<keyrec> file, from command-line options, or from any combination
of the three.  In order to enforce a common sequence of option interpretation,
all DNSSEC-Tools should use the B<tooloptions()> routine to initialize its
options.

The I<keyrec_file> argument specifies a I<keyrec> file that will be consulted.
The I<keyrec> named by the I<keyrec_name> argument will be loaded.  If no
I<keyrec> file should be used, then I<keyrec_file> should be an empty string
and the I<keyrec_name> parameter not included.  The I<@specopts> array
contains command-specific arguments; the arguments must be in the format
prescribed by the B<Getopt::Long> Perl module.

B<tooloptions()> combines data from these three option sources into a hash
table.  The hash table is returned to the caller, which will then use the
options as needed.

The command-line options are saved between calls, so a command may call
B<tooloptions()> multiple times and still have the command-line options
included in the final hash table.  This is useful for examining multiple
I<keyrec>s in a single command.  Inclusion of command-line options may be
suspended and restored using the B<opts_suspend()> and B<opts_restore()> calls.
Options may be discarded entirely by calling B<opts_drop()>; once dropped,
command-line options may never be restored.  Suspension, restoration, and
dropping of command-line options are only effective after the initial
B<tooloptions()> call. 

The options sources are combined in this manner:

=over 4

=item 1.  B<dnssec-tools.conf>

The system-wide configuration file is read and these option values are used
as the defaults.  These options are put into a hash table, with the option
names as the hash key.

=item 2. I<keyrec> File

If a I<keyrec> file was specified, then the I<keyrec> named by I<keyrec_name>
will be retrieved.  The I<keyrec>'s fields are added to the hash table.  Any
field whose keyword matches an existing hash key will override the existing
value.

=item 3. Command-line Options

The command-line options, specified in I<@specopts>, are parsed using
B<Getoptions()> from the B<Getopt::Long> Perl module.  These options are
folded into the hash table; again possibly overriding existing hash values.
The options given in I<@specopts> must be in the format required by
B<Getoptions()>.

=back

A reference to the hash table created in these three steps is returned to the
caller.


=head1 EXAMPLE

B<dnssec-tools.conf> has these entries:

    ksklength      1024
    zsklength      512

B<example.keyrec> has this entry:

    key         "Kexample.com.+005+10988"
            zsklength        "1024"

I<zonesigner> is executed with this command line:

    zonesigner -ksklength 512 -zsklength 4096 -wait 600 ...  example.com

B<tooloptions("example.keyrec","Kexample.com.+005+10988",("wait=i"))>
will read each option source in turn, ending up with:
    I<ksklength>           512
    I<zsklength>          4096
    I<wait>                600


=head1 TOOLOPTION ARGUMENTS

Many of the DNSSEC-Tools option interfaces take the same set of arguments:
I<$keyrec_file>, I<$keyrec_name>, and I<@csopts>.  These arguments are used
similarly by most of the interfaces; differences are noted in the interface
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
options are in the format required by the B<Getopt::Long> Perl module.  If
I<@csopts> is left off the call, then no command-specific options will be
included in the final option hash.  The I<@csopts> array may be passed
directly to several interfaces or it may be saved in a call to
B<opts_setcsopts()>.

=head1 TOOLOPTION INTERFACES

=over 4

=item B<tooloptions($keyrec_file,$keyrec_name,@csopts)>

This B<tooloptions()> call builds an option hash from the system configuration
file, a I<keyrec>, and a set of command-specific options.  A reference to
this option hash is returned to the caller.

If I<$keyrec_file> is given as an empty string, then no I<keyrec> file will
be consulted.  In this case, it is assumed that I<$keyrec_name> will be left
out altogether.

If a non-existent I<$keyrec_file> is given and B<opts_createkrf()> has been
called, then the named I<keyrec> file will be created.  B<opts_createkrf()>
must be called for each I<keyrec> file that must be created, as the
B<tooloptions> I<keyrec>-creation state is reset after B<tooloptions()> has
completed.

=item B<opts_krfile($keyrec_file,$keyrec_name,@csopts)>

The B<opts_krfile()> routine looks up the I<keyrec> file and I<keyrec> name
and uses those fields to help build an options hash.  References to the
I<keyrec> file name, I<keyrec> name, and the option hash table are returned
to the caller.

The I<$keyrec_file> and I<$keyrec_name> arguments are required parameters.
They may be given as empty strings, but they B<must> be given.

If the I<$keyrec_file> file and I<$keyrec_name> name are both specified by
the caller, then this routine will have the same effect as directly calling
B<tooloptions()>.

=item B<opts_getkeys($keyrec_file,$keyrec_name,@csopts)>

This routine returns references to the KSK and ZSK I<keyrec>s associated with
a specified I<keyrec> entry.  This gives an easy way to get a zone's I<keyrec>
entries in a single step.

This routine acts as a front-end to the B<opts_krfile()> routine.
Arguments to B<opts_getkeys()> conform to those of B<opts_krfile()>.

If B<opts_getkeys()> isn't passed any arguments, it will act as if both
I<$keyrec_file> and I<$keyrec_name> were given as empty strings.  In this
case, their values will be taken from the I<-krfile> and I<-keyrec> command
line options.

=item B<opts_keykr($keyrec_file,$keyrec_name,@csopts)>

This routine returns a reference to the key I<keyrec> named by
I<$keyrec_name>.  It ensures that the named I<keyrec> is a key I<keyrec>;
if it isn't, I<undef> is returned.

This routine acts as a front-end to the B<opts_krfile()> routine.
B<opts_keykr()>'s arguments conform to those of B<opts_krfile()>.

If B<opts_keykr()> isn't passed any arguments, it will act as if both
I<$keyrec_file> and I<$keyrec_name> were given as empty strings.  In this
case, their values will be taken from the I<-krfile> and I<-keyrec> command
line options.

=item B<opts_zonekr($keyrec_file,$keyrec_name,@csopts)>

This routine returns a reference to the zone I<keyrec> named by
I<$keyrec_name>.  The I<keyrec> fields from the zone's KSK and ZSK are
folded in as well, but the key's I<keyrec_> fields are excluded.  This
call ensures that the named I<keyrec> is a zone I<keyrec>; if it isn't,
I<undef> is returned.

This routine acts as a front-end to the B<opts_krfile()> routine.
B<opts_zonekr()>'s arguments conform to those of B<opts_krfile()>.

If B<opts_zonekr()> isn't passed any arguments, it will act as if both
I<$keyrec_file> and I<$keyrec_name> were given as empty strings.  In this
case, their values will be taken from the I<-krfile> and I<-keyrec> command
line options.

=item B<opts_setcsopts(@csopts)>

This routine saves a copy of the command-specific options given in I<@csopts>.
This collection of options is added to the I<@csopts> array that may be passed
to B<tooloptions()>.

=item B<opts_createkrf()>

Force creation of an empty I<keyrec> file if the specified file does not
exist.  This may happen on calls to B<tooloptions()>, B<opts_getkeys()>,
B<opts_krfile()>, and B<opts_zonekr()>.

=item B<opts_suspend()>

Suspend inclusion of the command-line options in building the final hash
table of responses.

=item B<opts_restore()>

Restore inclusion of the command-line options in building the final hash
table of responses.

=item B<opts_drop()>

Discard the command-line options.  They will no longer be available for
inclusion in building the final hash table of responses for this execution
of the command.

=item B<opts_reset()>

Reset an internal flag so that the command-line arguments may be
re-examined.  This is usually only useful if the arguments have been
modified by the calling program itself.

=item B<opts_gui()>

Set an internal flag so that command arguments may be specified with a GUI.
GUI usage requires that Getopt::Long::GUI is available.  If it isn't, then 
Getopt::Long will be used.

=item B<opts_nogui()>

Set an internal flag so that the GUI will not be used for specifying
command arguments.

=back

=head1 COPYRIGHT

Copyright 2004-2006 SPARTA, Inc.  All rights reserved.
See the COPYING file included with the DNSSEC-Tools package for details.

=head1 AUTHOR

Wayne Morrison, tewok@users.sourceforge.net

=head1 SEE ALSO

B<zonesigner(8)>

B<Getopt::Long(3)>

B<Net::DNS::SEC::Tools::conf(3)>, B<Net::DNS::SEC::Tools::keyrec(3)>,

B<Net::DNS::SEC::Tools::keyrec(5)>

=cut
