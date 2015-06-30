#!/usr/bin/perl
#
# Copyright 2005-2014 SPARTA, Inc.  All rights reserved.  See the COPYING
# file distributed with this software for details.
#
# DNSSEC-Tools
#
#	Option routines.
#
#	This module manipulates option lists for the DNSSEC-Tools.  After
#	building an option list from a number of sources (DNSSEC-Tools
#	defaults, DNSSEC-Tools config file, keyrec file, command-specific
#	options, and command-line options), a hash table of options is
#	passed back to the caller.  The caller uses the options as required.
#

package Net::DNS::SEC::Tools::tooloptions;

use Net::DNS::SEC::Tools::QWPrimitives;
use Net::DNS::SEC::Tools::defaults;

require Exporter;
use strict;

use Net::DNS::SEC::Tools::conf;
use Net::DNS::SEC::Tools::keyrec;

our $VERSION = "2.1";
our $MODULE_VERSION = "2.1.0";

our @ISA = qw(Exporter);

our @EXPORT = qw(
			opts_cmdline
			opts_cmdopts
			opts_createkrf
			opts_drop
			opts_gui
			opts_nogui
			opts_onerr
			opts_reset
			opts_restore
			opts_setcsopts
			opts_suspend
			opts_zonekr
		);

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
		["nogends",		"Don't generate DS records"],

	'',

	['GUI:separator',	'Configuration Options:'],
		["dtconfig=s",		"DNSSEC-Tools configuration file"],
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
		["kskcount=i",		"Number of KSKs to generate"],
		["kskdirectory=s",	"Directory for KSK keys"],
		["ksklength=i",		"Length of KSK"],
		["ksklife=i",		"Life-span of KSK"],
		["revperiod=i",		"Revocation period"],
		["dsdir=s",		"Directory for dsset files"],
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

		["kgopts=s",		"Additional key-generation options"],
		["szopts=s",		"Additional zone-signing options"],
		["zcopts=s",		"Additional zone-checking options"],

	'',

	['GUI:separator',	'Roll-over Options:'],
		["roll_logfile=s",	"Roll-over manager's log filename"],
		["roll_loglevel=s",	"Roll-over manager's logging level"],
		["logtz=s",		"Roll-over manager's logging timezone"],
		["roll_sleeptime=i",	"Sleep-time for Roll-over manager"],
		["zone_errors=i",	"Maximum consecutive errors for a zone"],

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

my $errexit		= 0;		# On-error flag.
my $gui			= 0;		# GUI-usage flag.

my %cmdopts	= ();			# Options from command line.
my %saveopts	= ();			# Save-area for command-line options.

my @cspecopts	= ();			# Caller-saved command-specific options.

##############################################################################
# Routine:	opts_cmdopts()
#
# Purpose:	This call builds an option hash from data taken from several
#		places.  The data are read and saved in this order:
#
#			- DNSSEC-Tools defaults
#			- DNSSEC-Tools configuration file
#			- a set of command-specific options
#			- command line options
#
#		Since there may be overlapping hash keys, the input becomes
#		more and more specific to a particular command invocation.
#
#		A reference to the final option hash is returned to the caller.
#
sub opts_cmdopts
{
	my @csopts = @_;			# Command-specific options.

	my %optionset = ();			# The combined options set.
	my %subopts   = ();			# Options subset.
	my %cmdopts    = ();			# Command line options.

# print "opts_cmdopts:  down in\n";

	#
	# Get the DNSSEC-Tools defaults.
	#
	%optionset = dnssec_tools_alldefaults();

	#
	# Get the config file and mix the file contents in with the defaults.
	#
	#
	%subopts = parseconfig();
	foreach my $k (sort(keys(%subopts)))
	{
		$optionset{$k} = $subopts{$k};
	}

	#
	# Set the GUI-usage flag according to the config file.  This must be
	# done right here so that the proper GUI/non-GUI behavior takes place.
	#
	$gui = $optionset{'usegui'};

	#
	# Mix in the command-line options with all the others.
	#
	%cmdopts = opts_int_cmdline(@csopts);
	foreach my $k (sort(keys(%cmdopts)))
	{
		$optionset{$k} = $cmdopts{$k};
	}

	#
	# Return the whole swirling mess back to the user.
	#
	return(\%optionset);
}

##############################################################################
# Routine:	opts_zonekr()
#
# Purpose:	This call builds an option hash from data taken from several
#		places.  The data are read and saved in this order:
#
#			- DNSSEC-Tools defaults
#			- DNSSEC-Tools configuration file
#			- a given keyrec file
#			- a set of command-specific options
#			- command line options
#
#		Since there may be overlapping hash keys, the input becomes
#		more and more specific to a particular command invocation.
#
#		A reference to the final option hash is returned to the caller.
#
sub opts_zonekr
{
	my $krfile = shift;			# Keyrec file to parse.
	my $krname = shift;			# Keyrec name to snarf.
	my @csopts = @_;			# Command-specific options.

	my %optionset = ();			# The combined options set.
	my %subopts   = ();			# Options subset.
	my %cmdopts   = ();			# Command line options.

# print "opts_zonekr:  down in\n";

	#
	# Get the DNSSEC-Tools defaults.
	#
	%optionset = dnssec_tools_alldefaults();

	#
	# Get the config file contents.
	#
	%subopts = parseconfig();

	#
	# Set the GUI-usage flag according to the config file.  This must be
	# done right here so that the proper GUI/non-GUI behavior takes place.
	#
	$gui = $optionset{'usegui'};

	#
	# Get the command-line options.
	#
	%cmdopts = opts_int_cmdline(@csopts);

	#
	# If the user specified a different config file, we'll parse it.
	#
	if(defined($cmdopts{'dtconfig'}))
	{
		setconffile($cmdopts{'dtconfig'});
		%subopts = parseconfig();
	}

	#
	# Mix the config file contents in with the defaults.
	#
	foreach my $k (sort(keys(%subopts)))
	{
		$optionset{$k} = $subopts{$k};
	}

	#
	# Get the keyrec file (from command line options) and keyrec name
	# (from command line args) values if the caller didn't give them.
	#
	$krfile = $cmdopts{'krfile'}	if($krfile eq "");
	$krname = $ARGV[0]		if($krname eq "");
	$krname = $cmdopts{'zone'}	if(defined($cmdopts{'zone'}));

	#
	# Initialize (maybe) and read the keyrec file and the specified zone,
	# putting the data into a hash table.
	#
	$optionset{'krfile'} = $krfile;
	if($krfile ne "")
	{
		if(opts_int_newkrf($krfile) == 1)
		{
			%subopts = opts_int_zonecopy($krfile,$krname);
		}
	}

	#
	# Mix in the keyrec's options with the config and command options.
	#
	foreach my $k (sort(keys(%subopts)))
	{
		$optionset{$k} = $subopts{$k};
	}

	#
	# Mix in the command-line options with all the others.
	#
	foreach my $k (sort(keys(%cmdopts)))
	{
		$optionset{$k} = $cmdopts{$k};
	}

	#
	# Return the whole swirling mess back to the user.
	#
	return(\%optionset);
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
# Routine:	opts_onerr()
#
# Purpose:	Set new on-error flag and return the old flag.
#
sub opts_onerr
{
	my $newaction = shift;				# New on-error flag.
	my $oldaction = $errexit;			# Old on-error flag.

	$errexit = $newaction;
	return($oldaction);
}

##############################################################################
# Routine:	opts_int_newkrf()
#
# Purpose:	Roughly speaking, this routine creates a new keyrec file.
#		(It actually just creates a new file, but it's a file intended
#		for use as a keyrec file.)
#
#		Operation is influenced by $create_krfile.  If that var is
#		set on and the specified file doesn't already exist, then
#		the keyrec file is created.
#
#		If the keyrec file was created, then $create_krfile will be
#		turned off.
#
#		Negative values are returned on failure; non-negative values
#		are returned on success.
#
#		Return Values:
#
#			 1	The keyrec file already exists.
#			 0	The keyrec file was created.
#			-1	No keyrec file was specified.
#			-2	$create_krfile was not turned on.
#			-3	Unable to create the keyrec file.
#
sub opts_int_newkrf
{
	my $krfile = shift;				# Keyrec file.
	my $ret;					# open() return code.

# print "opts_int_newkrf:  down in\n";

	#
	# If the caller didn't specify a keyrec file, return an error.
	#
	return(-1) if($krfile eq "");

	#
	# If the keyrec file exists, return success.
	# (By which we mean that the file exists.)
	#
	return(1) if(-e $krfile);

	#
	# If the caller wants to create a non-existent keyrec file, we'll
	# create it now.
	# If the caller doesn't want to create a new keyrec, we'll assume
	# it already exists and read it.
	#

	#
	# If the specified keyrec file doesn't exist, create it.
	#
	return(-2) if(!$create_krfile);

	#
	# Create the specified keyrec file.
	#
	$ret = open(NEWKRF,"> $krfile");
	return(-3) if(!defined($ret));
	close(NEWKRF);

	#
	# Turn off keyrec file creation.
	#
	$create_krfile = 0;
	return(0);
}

##############################################################################
#
sub opts_int_zonecopy
{
	my $krfile = shift;			# Name of keyrec file.
	my $krname = undef;			# Keyrec name we're examining.
	my $krtype;				# Keyrec type.

	my $found = 0;				# Found flag.

	my $krec;				# Keyrec reference.
	my %keyrec;				# Keyrec.

	my %fields = ();			# Fields from keyrec.

	#
	# Read the keyrec file.
	#
	keyrec_close();
	keyrec_read($krfile);

# print "\nopts_int_zonecopy:  down in\n";

	#
	# If we were given any arguments, we'll grab the zone keyrec's
	# name.  If the name is empty, we'll mark it as undefined.
	#
	if(@_)
	{
		$krname = shift;
		$krname = undef if($krname eq "");
	}

	#
	# If the zone keyrec is undefined, we'll use the alphabetically
	# first zone keyrec we find.
	# If the zone keyrec was given, we'll pull out that zone's keyrec.
	#
	if($krname eq undef)
	{
		my @krnames;				# Keyrec names.

		#
		# Find the first zone keyrec in the keyrec file.
		#
		@krnames = keyrec_names();
		foreach my $krn (sort(@krnames))
		{
			$krtype = keyrec_recval($krn,'keyrec_type');

			#
			# If this is a zone keyrec, we'll save the name and
			# drop out of the loop.
			#
			if($krtype eq "zone")
			{
				$krname = $krn;
				$found = 1;
				last;
			}
		}
	}
	else
	{
		$krtype = keyrec_recval($krname,'keyrec_type');
		$found = 1 if($krtype eq "zone");
	}

	#
	# Return failure if there's no zone keyrec.
	#
	if(!$found)
	{
		keyrec_close();
		return(undef);
	}

	#
	# Get the zone's keyrec values.
	#
	$krec = keyrec_fullrec($krname);
	return(undef) if($krec == undef);
	%keyrec = %$krec;

	#
	# Copy the zone keyrec.
	#
	foreach my $k (sort(keys(%keyrec)))
	{
		$fields{$k} = $keyrec{$k} if($k !~ /^keyrec_/);
	}

	#
	# Copy the data from the Current KSK and Current ZSK keyrecs.
	#
#	foreach my $ktype ('kskcur', 'zskcur')
	foreach my $ktype ('kskcur', 'zskcur', 'kskpub', 'zskpub', 'zsknew')
	{
		my $setname;			# Name of the signing set.
		my $setkeys;			# Keys in the signing set.

		#
		# Get the keys in this signing set.
		#
		$setname = keyrec_recval($krname,$ktype);
		$setkeys = keyrec_recval($setname,'keys');

		#
		# Add the data from each key's keyrec.
		#
		foreach my $keyname (split / /,$setkeys)
		{
			#
			# Get the key's keyrec values.
			#
			$krec = keyrec_fullrec($keyname);
			next if($krec eq '');
			%keyrec = %$krec;

			#
			# Copy the key keyrec.
			#
			foreach my $k (keys(%keyrec))
			{
				$fields{$k} = $keyrec{$k} if($k !~ /^keyrec_/);
			}
		}
	}

	#
	# Return the collected zone and key data.
	#
	return(%fields);
}

##############################################################################
# Routine:	opts_cmdline()
#
# Purpose:	Parse a command line looking for the arguments in the standard
#		set of options and the caller's set.  If the first argument is
#		true, the program-wide @ARGV is restored after parsing.  If the
#		caller provides other arguments, they're added as additional
#		options.  The parsed options are returned to the caller.
#
sub opts_cmdline
{
	my $saveargv = shift;			# Flag for saving @ARGV.
	my @csopts = @_;			# Command-specific options.

	my @args;				# Copy of @ARGV.
	my @opts;				# Copy of standard options.
	my %parsedopts;				# Parsed options.

	my $curgui = $gui;			# Saved $gui value.
	my $curfc = $firstcall;			# Saved $firstcall value.

	#
	# Save the argument vector.
	#
	@args = @ARGV;

	#
	# Add the standard options to the caller's options.
	#
	@opts = @stdopts;
	push @opts, @csopts if(@csopts > 0);

	#
	# Force some flags we need.
	#
	$gui = 0;
	$firstcall = 0;

	#
	# Extract the command line options.
	#
	localgetoptions(\%parsedopts,@opts);

	#
	# Restore the forced flags.
	#
	$gui = $curgui;
	$firstcall = $curfc;

	#
	# Restore the saved argument vector.
	#
	@ARGV = @args if($saveargv);

	return(%parsedopts);
}

##############################################################################
#
sub opts_int_cmdline
{
	my @csopts = @_;			# Command-specific options.
	my $cslen;				# Length of @csopts.

	my @opts;				# Copy of standard options.
	my %subopts = ();			# Options subset.

	#
	# Don't do anything if this isn't the first time we were called.
	#
	return if(!$firstcall);

	#
	# We'll start with whatever's left in the argument list.  If the
	# caller has saved a set of options already, we'll plop those onto
	# the end of this list.
	#
	push @csopts,@cspecopts if(scalar(@cspecopts) >= 0);
	$cslen = @csopts;

	#
	# Copy the standard options and append any command-specific
	# options that have been given.
	#
	@opts = @stdopts;
	push(@opts,@csopts) if($cslen > 0);

	#
	# Extract the command line options and set a flag indicating that
	# we've handled the options already.
	#
	localgetoptions(\%subopts,@opts);
	$firstcall = 0;

	return(%subopts);
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
	my $ret;		# Return code from GetOptions().

	if($gui)
	{
		if(($#ARGV == -1) && (eval {require Getopt::GUI::Long;}))
		{
			import Getopt::GUI::Long;
			return(GetOptions(@args));
		}
	}

	require Getopt::Long;
	import Getopt::Long qw(:config no_ignore_case_always);

	#
	# Parse the command line for options.
	#
	$ret = GetOptions(localoptionsmap(@args));

	#
	# If there was an option problem and we should exit, we'll do so.
	# If there's a usage() in the main module, we'll call that first.
	#
	if(!$ret && $errexit)
	{
		main::usage() if(main->can('usage'));
		exit(1);
	}

	#
	# Return the GetOptions() return code to our caller.
	#
	return($ret);
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

  @specopts = ("propagate+", "waittime=i");

  %opts = opts_cmdline($restoreargv,@calleropts);

  $optsref = opts_cmdopts(@specopts);
  %options = %$optsref;

  $zoneref = opts_zonekr($keyrec_file,$keyrec_name,@specopts);
  %zone_kr = %$zoneref;

  opts_setcsopts(@specopts);

  opts_createkrf();

  opts_suspend();

  opts_restore();

  opts_drop();

  opts_reset();

  opts_gui();

  opts_nogui();

  $oldaction = opts_onerr(1);
  opts_onerr(0);

=head1 DESCRIPTION

DNSSEC-Tools supports a set of options common to all the tools in the suite.
These options may be set from DNSSEC-Tools defaults, values set in the
B<dnssec-tools.conf> configuration file, in a I<keyrec> file, from
command-specific options, from command-line options, or from any combination
of the five.  In order to enforce a common sequence of option interpretation,
all DNSSEC-Tools should use the B<tooloptions.pm> routines to initialize their
options.

B<tooloptions.pm> routines combine data from the aforementioned option sources
into a hash table.  The hash table is returned to the caller, which will then
use the options as needed.

The command-line options are saved between calls, so a command may call
B<tooloptions.pm> routines multiple times and still have the command-line
options included in the final hash table.  This is useful for examining
multiple I<keyrec>s in a single command.  Inclusion of command-line options
may be suspended and restored using the I<opts_suspend()> and
I<opts_restore()> calls.  Options may be discarded entirely by calling
I<opts_drop()>; once dropped, command-line options may never be restored.
Suspension, restoration, and dropping of command-line options are only
effective after the initial B<tooloptions.pm> call.

The options sources are combined in this order:

=over 4

=item 1.  DNSSEC-Tools Defaults

The DNSSEC-Tools defaults, as defined in B<conf.pm> are put into a hash table,
with the option names as the hash key.

=item 2.  DNSSEC-Tools Configuration File

The system-wide DNSSEC-Tools configuration file is read and these option
values are added to the option collection.  Again, the option names are used
as the hash key.

=item 3. I<keyrec> File

If a I<keyrec> file was specified, then the I<keyrec> named by I<keyrec_name>
will be retrieved.  The I<keyrec>'s fields are added to the hash table.  Any
field whose keyword matches an existing hash key will override any existing
values.

=item 4. Command-Specific Options

Options specific to the invoking commands may be specified in I<@specopts>.
This array is parsed by I<Getoptions()> from the B<Getopt::Long> Perl module.
These options are folded into the hash table; possibly overriding existing
hash values.  The options given in I<@specopts> must be in the format required
by I<Getoptions()>.

=item 5. Command-Line Options

The command-line options are parsed using I<Getoptions()> from the
B<Getopt::Long> Perl module.  These options are folded into the hash table;
again, possibly overriding existing hash values.  The options given in
I<@specopts> must be in the format required by I<Getoptions()>.

=back

A reference to the hash table created in these steps is returned to the caller.

=head1 EXAMPLE

B<dnssec-tools.conf> has these entries:

    ksklength      2048
    zsklength      1024

B<example.keyrec> has this entry:

    key         "Kexample.com.+005+12345"
            zsklength        "2048"

B<zonesigner> is executed with this command line:

    zonesigner -zsklength 4096 -wait 3600 ...  example.com

I<opts_zonekr("example.keyrec","Kexample.com.+005+12345",("wait=i"))>
will read each option source in turn, ending up with:
    I<ksklength>          1024
    I<zsklength>          4096
    I<wait>                600

=head1 TOOLOPTIONS INTERFACES

=over 4

=item I<opts_cmdline($restoreargv,@calleropts)>

This routine parses a command line looking for the arguments in the standard
set of options and an optional set of options specified by the caller.  If the
first argument is true, the program-wide @ARGV is restored after parsing.  If
the caller provides other arguments, they're added as additional options.  The
parsed options are returned to the caller in a hash.

=item I<opts_cmdopts(@csopts)>

The I<opts_cmdopts()> call builds an option hash from the system configuration
file, a I<keyrec>, and a set of command-specific options.  A reference to
this option hash is returned to the caller.

If I<$keyrec_file> is given as an empty string, then no I<keyrec> file will
be consulted.  In this case, it is assumed that I<$keyrec_name> will be left
out altogether.

If a non-existent I<$keyrec_file> is given and I<opts_createkrf()> has been
called, then the named I<keyrec> file will be created.  I<opts_createkrf()>
must be called for each I<keyrec> file that must be created, as the
B<tooloptions> I<keyrec>-creation state is reset after B<tooloptions()> has
completed.

=item I<opts_zonekr($keyrec_file,$keyrec_name,@csopts)>

This routine returns a reference to options gathered from the basic option
sources and from the zone I<keyrec> named by I<$keyrec_name>, which is found
in I<$keyrec_file>.  The I<keyrec> fields from the zone's KSK and ZSK are
folded in as well, but the key's I<keyrec_> fields are excluded.  This
call ensures that the named I<keyrec> is a zone I<keyrec>; if it isn't,
I<undef> is returned.

The I<keyrec> file is read with I<keyrec_read()>.  To ensure it is properly
read, I<keyrec_close()> is called first.

The I<$keyrec_file> argument specifies a I<keyrec> file that will be
consulted.  The I<keyrec> named by the I<$keyrec_name> argument will be
loaded.  If a I<keyrec> file is found and I<opts_createkrf()> has been
previously called, then the I<keyrec> file will be created if it doesn't
exist.

If I<$keyrec_file> is given as "", then the command-line options are searched
for a I<-krfile> option.  If I<$keyrec_name> is given as "", then the name is
taken from I<$ARGV[0]>.

The I<@specopts> array contains command-specific arguments; the arguments must
be in the format prescribed by the B<Getopt::Long> Perl module.

If the command line contains the I<-dtconfig> option, then I<opts_zonekr>()
sets that option to be the configuration file.  It then parses that file and
uses it as the source for configuration file data.

=item I<opts_setcsopts(@csopts)>

This routine saves a copy of the command-specific options given in I<@csopts>.
This collection of options is added to the I<@csopts> array that may be passed
to B<tooloptions.pm> routines.

=item I<opts_createkrf()>

Force creation of an empty I<keyrec> file if the specified file does not
exist.  This may happen on calls to I<opts_zonekr()>.

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

=item I<opts_gui()>

Set an internal flag so that command arguments may be specified with a GUI.
GUI usage requires that B<Getopt::GUI::Long> is available.  If it isn't, then
B<Getopt::Long> will be used.

=item I<opts_nogui()>

Set an internal flag so that the GUI will not be used for specifying
command arguments.

=item I<opts_onerr(exitflag)>

Set an internal flag indicating what should happen if an invalid option is
specified on the command line.  If I<exitflag> is non-zero, then the process
will exit on an invalid option; if it is zero, then the process will not
exit.  The default action is to report an error without exiting.

The old exit action is returned.

=back

=head1 COPYRIGHT

Copyright 2005-2014 SPARTA, Inc.  All rights reserved.
See the COPYING file included with the DNSSEC-Tools package for details.

=head1 AUTHOR

Wayne Morrison, tewok@tislabs.com

=head1 SEE ALSO

B<zonesigner(8)>

B<Getopt::Long(3)>

B<Net::DNS::SEC::Tools::conf(3)>,
B<Net::DNS::SEC::Tools::defaults(3)>,
B<Net::DNS::SEC::Tools::keyrec(3)>

B<Net::DNS::SEC::Tools::keyrec(5)>

=cut
