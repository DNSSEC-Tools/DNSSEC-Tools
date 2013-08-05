#!/usr/bin/perl
#
# Copyright 2006-2013 SPARTA, Inc.  All rights reserved.  See the COPYING
# file distributed with this software for details.
#
# DNSSEC Tools
#
#	Rollrec file routines.
#
#	The routines in this module manipulate a rollrec file for the DNSSEC-
#	Tools.  The rollrec file contains information about key rollover
#	status.
#
#	Entries in the configuration file are of the "key value" format, with
#	the value enclosed in quotes.  Comments may be included by prefacing
#	them with the '#' or ';' comment characters.
#
#	These entries are grouped by the zone whose key(s) are being rolled
#	over.
#
#	An example rollrec file follows:
#
#	    roll "example.com"
#		zonename	"example.com"
#		zonefile	"/usr/etc/dnssec-tools/zones/db.example.com"
#		keyrec		"/usr/etc/dnssec-tools/keyrec/example.keyrec"
#		zskphase	"2"
#		kskphase	"0"
#		maxttl		"86400"
#		curerrors	"0"
#		display		"0"
#		phasestart	"Wed Mar 09 21:49:22 2005"
#
#	    roll "example2.com"
#		zonename	"example2.com"
#		zonefile	"/usr/etc/dnssec-tools/zone/db.example2.com"
#		keyrec		"/usr/etc/dnssec-tools/keyrec/example2.keyrec"
#		kskphase	"1"
#		zskphase	"0"
#		maxttl		"100000"
#		display		"1"
#		loglevel	"info"
#		curerrors	"0"
#		maxerrors	"5"
#		phasestart	"Sun Jan 01 16:00:00 2005"
#
#	    roll "example2.com"
#		version		"2"
#
#
#	The current implementation assumes that only one rollrec file will
#	be open at a time.  If module use proves this to be a naive assumption
#	this module will have to be rewritten to account for it.
#
#	The directory rollrec field was an excellent suggestion made by
#	Otmar Lendl <ol@bofh.priv.at>.  Several changes here, in rollerd,
#	and in other scripts are a result of this suggestion.
#

package Net::DNS::SEC::Tools::rollrec;

require Exporter;
use strict;

use Fcntl qw(:DEFAULT :flock);

use Net::DNS::SEC::Tools::conf;
use Net::DNS::SEC::Tools::rollmgr;

our $VERSION = "2.0";
our $MODULE_VERSION = "2.0.1";

our @ISA = qw(Exporter);

#--------------------------------------------------------------------------
#
# Exported commands.
#

our @EXPORT = qw(
			rollrec_add
			rollrec_close
			rollrec_current
			rollrec_default
			rollrec_del
			rollrec_delfield
			rollrec_discard
			rollrec_dump_array
			rollrec_dump_hash
			rollrec_exists
			rollrec_fields
			rollrec_fullrec
			rollrec_init
			rollrec_info
			rollrec_lock
			rollrec_merge
			rollrec_names
			rollrec_read
			rollrec_readfiles
			rollrec_rectype
			rollrec_recval
			rollrec_rename
			rollrec_settime
			rollrec_setval
			rollrec_split
			rollrec_unlock
			rollrec_version
			rollrec_write
			rollrec_zonegroup
			rollrec_zonegroups
			rollrec_zonegroup_cmds
		);

#--------------------------------------------------------------------------
#
# Zonegroup commands.
#
my %zg_commands =
	(
		'rollcmd_dspub'		=>	1,
		'rollcmd_rollksk'	=>	1,
		'rollcmd_rollzone'	=>	1,
		'rollcmd_rollzsk'	=>	1,
		'rollcmd_skipzone'	=>	1,
	);

#--------------------------------------------------------------------------
#
# Default file names.
#
my $DEFAULT_DNSSECTOOLS_DIR = getconfdir();
my $DEFAULT_ROLLREC = "dnssec-tools.rollrec";
my $LOCKNAME = "rollrec.lock";

#
# Valid fields in a non-informational rollrec.
#
my @ROLLFIELDS = (
			'zonename',
			'zonefile',
			'keyrec',
			'zonegroup',
			'maxttl',
			'administrator',
			'directory',
			'phasestart',
			'display',
			'loglevel',
			'kskphase',
			'zskphase',
			'zsargs',
			'curerrors',
			'maxerrors',
			'rndc-opts',
			'ksk_rollsecs',
			'ksk_rolldate',
			'zsk_rollsecs',
			'zsk_rolldate',
		  );

#
# Valid fields in an informational rollrec.
#
my @ROLLINFOFIELDS = (
			'version',
		  );

our $ROLLREC_INFO = 'info rollrec';		# Name of info rollrec.
our $ROLLREC_CURRENT_VERSION = 2;		# Current version of rollrecs.

#--------------------------------------------------------------------------

my @rollreclines;		# Rollrec lines.
my $rollreclen;			# Number of rollrec lines.

my %rollrecs;			# Rollrec hash table.
my %rollrecindex;		# Maps rollrec names to @rollreclines indices.

my %zonegroups;			# Zone group hash table.

my $modified;			# File-modified flag.

#--------------------------------------------------------------------------
# Routine:	rollrec_lock()
#
# Purpose:	Lock rollrec processing so that only one process reads a
#		rollrec file at a time.
#
#		The actual rollrec file is not locked; rather, a synch-
#		ronization file is locked.  We lock in this manner due to
#		the way the rollrec module's functionality is spread over
#		a set of routines.
#
sub rollrec_lock
{
	my $lockdir;			# Configuration file directory.
	my $lockfile;			# Name of the lock file.

# print "rollrec_lock:  down in\n";

	#
	# Get the DNSSEC-Tools config directory.
	#
	$lockdir = makelocalstatedir("/dnssec-tools") || $DEFAULT_DNSSECTOOLS_DIR;

	#
	# Build our lock file.
	#
	$lockfile = "$lockdir/$LOCKNAME";

	#
	# Open (and create?) our lock file.
	#
	if(!sysopen(RRLOCK,$lockfile,O_RDONLY|O_CREAT))
	{
#		err("unable to open lock file \"$lockfile\"; not locking...\n",-1);
		return(0);
	}

	#
	# Lock the lock file.
	#
	return(flock(RRLOCK,LOCK_EX));
}

#--------------------------------------------------------------------------
# Routine:	rollrec_unlock()
#
# Purpose:	Unlock rollrec processing so that other processes may read
#		a rollrec file.
#
sub rollrec_unlock
{
# print "rollrec_unlock:  down in\n";

	#
	# Unlock the lock file.
	#
	return(flock(RRLOCK,LOCK_UN));
}

#--------------------------------------------------------------------------
# Routine:	rollrec_read()
#
# Purpose:	Read a DNSSEC-Tools rollrec file.  The contents are read into
#		the @rollreclines array and the rollrecs are broken out into
#		the %rollrecs hash table.
#
sub rollrec_read
{
	my $rrf = shift;			# Rollover file.
	my $rrcnt;				# Number of rollrecs we found.
	my @sbuf;				# Buffer for stat().

# print "rollrec_read:  down in\n";

	#
	# Use the default rollrec file, unless the caller specified
	# a different file.
	#
	$rrf = rollrec_default() if($rrf eq '');

	#
	# Make sure the rollrec file exists.
	#
	if(! -e $rrf)
	{
		err("rollrec file $rrf does not exist\n",-1);
		return(-1);
	}

	#
	# If a rollrec file is already open, we'll flush our buffers and
	# save the file.
	#
	@sbuf = stat(ROLLREC);
	rollrec_close() if(@sbuf != 0);

	#
	# Open up the rollrec file.  If we can't open it for reading and
	# writing, we'll try to open it just for reading.
	#
	if(open(ROLLREC,"+< $rrf") == 0)
	{
		if(open(ROLLREC,"< $rrf") == 0)
		{
			err("unable to open $rrf\n",-1);
			return(-2);
		}
	}

	#
	# Initialize some data.
	#
	rollrec_init();

	#
	# Read the contents of the specified rollrec file.
	#
	rollrec_readfile(*ROLLREC,0);

	#
	# Return the number of rollrecs we found.
	#
	$rrcnt = keys(%rollrecs);
	return($rrcnt);
}

#--------------------------------------------------------------------------
# Routine:	rollrec_merge()
#
# Purpose:	Merge a set of DNSSEC-Tools rollrec files.  The contents are
#		read into the @rollreclines array and the rollrecs are broken
#		out into the %rollrecs hash table.
#
sub rollrec_merge
{
	my $firstrrf = shift;		# First rollrec file in list.
	my @rrflist = @_;		# Set of rollrec files.

	my %allrrfs = ();		# All rollrec filenames to be merged.
	my $errs = 0;			# Count of non-fatal errors.
	my $rrcnt;			# Number of rollrecs we found.

# print "rollrec_merge:  down in\n";

	#
	# Make sure a set of rollrec files was specified.
	#
	if((! defined($firstrrf)) || (@rrflist == 0))
	{
		err("no rollrec files given to merge\n",1);
		return(-1);
	}

	#
	# Build a hash of the rollrec file names and the number of times
	# each is specified.
	#
	foreach my $fn ($firstrrf, @rrflist)
	{
		$allrrfs{$fn}++;
	}

	#
	# Bump the error count if a file was listed multiple times.
	#
	foreach my $fn (keys(%allrrfs))
	{
		$errs++ if($allrrfs{$fn} > 1);
	}

	#
	# If any file was listed multiple times, given an error and return.
	#
	if($errs)
	{
		err("unable to merge rollrec files since some rollrec files were given multiple times\n",1);
		return(-5);
	}

	#
	# Create a target file if the first rollrec file doesn't exist or
	# if the file is empty.  A bare-bones rollrec will be created that
	# only has an info rollrec.
	#
	if((! -e $firstrrf) || (-z $firstrrf))
	{
		if(open(TMP,"> $firstrrf") == 0)
		{
			err("rollrec_merge:  unable to create target rollrec file \"$firstrrf\"\n",1);
			return(-2);
		}

		#
		# Write the new info rollrec.
		#
		print TMP "\n";
		print TMP "skip \"$ROLLREC_INFO\"\n";
		print TMP "	version		\"$ROLLREC_CURRENT_VERSION\"\n";
		print TMP "\n";

		close(TMP);
	}

	#
	# Read the first rollrec file.  This will also zap all our current
	# internal data.
	#
	$allrrfs{$firstrrf}++;
	if(rollrec_read($firstrrf) < 0)
	{
		return(-3);
	}

	#
	# Read each remaining rollrec file and add it to our internal
	# rollrec collection.
	#
	foreach my $rrf (@rrflist)
	{
		#
		# Make sure the rollrec file exists.
		#
		if(! -e $rrf)
		{
			err("rollrec file \"$rrf\" does not exist\n",1);
			$errs++;
			next;
		}

		#
		# Close the needed file handle.
		#
		close(ROLLREC_MERGE);

		#
		# Open up the rollrec file.
		#
		if(open(ROLLREC_MERGE,"< $rrf") == 0)
		{
			err("unable to open $rrf\n",1);
			$errs++;
			next;
		}

		#
		# Read the contents of the specified rollrec file.
		#
		if(rollrec_readfile(*ROLLREC_MERGE,1) < 0)
		{
			$errs++;
		}
	}

	#
	# Close the file handle.
	#
	close(ROLLREC_MERGE);

	#
	# If we encountered errors while merging the files, we'll give
	# an error and reset ourself.
	#
	if($errs)
	{
		err("unable to merge rollrec files due to errors\n",1);
		rollrec_init();
		return(-4);
	}

	#
	# Write the new rollrec file.
	#
	$modified = 1;
	rollrec_write();

	#
	# Return the number of rollrecs we found.
	#
	$rrcnt = keys(%rollrecs);
	return($rrcnt);
}

#--------------------------------------------------------------------------
# Routine:	rollrec_split()
#
# Purpose:	Split a rollrec file in two.  A list of rollrec entries will
#		be removed from the current rollrec file and appended to
#		another file.  The rollrec entries will be removed from
#		@rollreclines and %rollrecs.
#
#		Things get interesting with the target rollrec file and the
#		info rollrec.  If the target file doesn't exist, the source's
#		info rollrec is copied to it.  If it does exist but doesn't
#		have an info rollrec, then the source's info rollrec is copied
#		to the target.  If the target file exists and has an info
#		rollrec, then the two files must have matching version numbers.
#
#		The rollrecs will be appended to the destination file.
#
sub rollrec_split
{
	my $newrrf = shift;		# New rollrec file.
	my @rrlist = @_;		# Set of rollrec names.

	my $valid = 0;			# Count of valid names.
	my @badnames = ();		# List of invalid names.
	my $rrcnt = 0;			# Number of rollrecs we split.
	my $verscopy = 0;		# Flag for copying info rollrec.

# print "rollrec_split:  down in\n";

	#
	# Make sure a set of rollrec files was specified.
	#
	if((! defined($newrrf)) || ($newrrf eq ''))
	{
		err("no target rollrec file given for split\n",1);
		return(-1);
	}

	#
	# Make sure a set of rollrec files was specified.
	#
	if(@rrlist == 0)
	{
		err("no rollrec names given for split\n",1);
		return(-2);
	}

	#
	# Count the valid rollrec names in the name list.
	#
	foreach my $rrn (@rrlist)
	{
		next if($rrn eq $ROLLREC_INFO);
		$valid++ if(defined($rollrecs{$rrn}));
	}

	#
	# Ensure that at least one of the rollrec names in the name list
	# is valid.
	#
	if($valid == 0)
	{
		err("no rollrec names given for split are existing rollrecs\n",1);
		return(-3);
	}

	#
	# If the new rollrec file already exists, make sure it's at the same
	# version as the old file.
	#
	# This code is ugly.  We'll fix it when we objectify the module a bit
	# further so it can handle multiple open rollrecs.  Having time to do
	# that will come RSN.
	#
	if(-e $newrrf)
	{
		my @nlines;				# Lines in new rollrec.
		my $keyword;				# Keyword from the line.
		my $value;				# Keyword's value.
		my $newvers = -1;			# Rollrec's version.

		if(open(TMP,"< $newrrf") == 0)
		{
			err("rollrec_split:  unable to read target rollrec file \"$newrrf\"\n",1);
			return(-20);
		}

		@nlines = <TMP>;
		close(TMP);

		#
		# Find the start of the info rollrec.
		#
		for(my $ind=0; $ind < @nlines; $ind++)
		{
			my $line = $nlines[$ind];

			#
			# Skip comment lines and empty lines.
			#
			if(($line =~ /^\s*$/) || ($line =~ /^\s*[;#]/))
			{
				next;
			}

			#
			# Grab the keyword and value from the line.
			#
			$line =~ /^\s*([a-zA-Z_]+)\s+"([a-zA-Z0-9\/\-+_.,: \@\t]*)"/;
			$keyword = $1;
			$value = $2;

			#
			# Look for a keyword of "roll" or "skip" and the
			# info rollrec.
			#
			next if(($keyword !~ /^roll$/i)		&&
				($keyword !~ /^skip$/i));
			next if($value ne $ROLLREC_INFO);

			#
			# Okeedokee, we've got the info rollrec now.
			# Lop off the first chunk o' file.
			#
			splice @nlines, 0, $ind;
			last;
		}

		#
		# Find the end of the info rollrec.
		#
		for(my $ind=1; $ind < @nlines; $ind++)
		{
			my $line = $nlines[$ind];

			#
			# Skip comment lines and empty lines.
			#
			if(($line =~ /^\s*$/) || ($line =~ /^\s*[;#]/))
			{
				next;
			}

			#
			# Grab the keyword and value from the line.
			#
			$line =~ /^\s*([a-zA-Z_]+)\s+"([a-zA-Z0-9\/\-+_.,: \@\t]*)"/;
			$keyword = $1;

			next if(($keyword !~ /^roll$/i)		&&
				($keyword !~ /^skip$/i));

			#
			# Get rid of everything from here to the end.
			#
			splice @nlines, $ind, @nlines; 
		}

		#
		# We now have the info rollrec -- if there is one.
		#
		if(@nlines)
		{
			my %newinfo = ();	# New file's info rollrec.
			my $inforecs = 0;	# Info records we found.

			for(my $ind=0; $ind < @nlines; $ind++)
			{
				my $line = $nlines[$ind];

				#
				# Skip comment lines and empty lines.
				#
				if(($line =~ /^\s*$/) || ($line =~ /^\s*[;#]/))
				{
					next;
				}

				#
				# Save this line's keyword/value pair.
				#
				$line =~ /^\s*([a-zA-Z_]+)\s+"([a-zA-Z0-9\/\-+_.,: \@\t]*)"/;
				$keyword = $1;
				$value	 = $2;
				$newinfo{$1} = $2;
				$inforecs++;
			}

			#
			# If we found any actual info records, we'll check
			# the version.
			#
			if($inforecs)
			{
				if(defined($newinfo{'version'}))
				{
					$newvers = $newinfo{'version'};
				}
				else
				{
					$newvers = undef;
				}
			}
		}

		#
		# Figure out what to do with the version based on
		# value of $newvers:
		#	< 0	There's no info rollrec.  We'll copy the
		#		current rollrec's info rollrec to the file.
		#
		#	< 2	There's an info rollrec with a pre-info
		#		rollrec version.  We'll return an error.
		#
		#	If it's neither of the above and it doesn't match
		#	the current rollrec's version, then there's a fatal
		#	version mismatch.  We'll return an error.
		#
		if(! defined($newvers))
		{
			return(-8);
		}
		elsif($newvers < 0)
		{
			$verscopy = 1;
		}
		elsif($newvers < 2)
		{
			return(-6);
		}
		elsif($rollrecs{$ROLLREC_INFO}{'version'} != $newvers)
		{
			return(-7);
		}

	}
	else
	{
		#
		# If this is a new target rollrec file, we'll copy the
		# info rollrec from the original file.
		#
		$verscopy = 1;
	}

	#
	# Open the target rollrec file for appending.
	#
	if(open(ROLLREC_SPLIT,">> $newrrf") == 0)
	{
		err("unable to open \"$newrrf\" for split\n",1);
		return(-4);
	}

	#
	# Add the info rollrec if we've found we should copy it.
	#
	unshift @rrlist, $ROLLREC_INFO if($verscopy);

	#
	# Read each remaining rollrec file and add it to our internal
	# rollrec collection.
	#
	foreach my $rrn (@rrlist)
	{
		my $rrind;			# Index to rollrec's first line.

		#
		# Skip the info rollrec if it was named and we shouldn't
		# copy it.
		#
		next if(!$verscopy && ($rrn eq $ROLLREC_INFO));

		#
		# If this name isn't the name of an existing rollrec, we'll
		# save the name and go to the next.
		#
		if(! exists($rollrecs{$rrn}))
		{
			push @badnames,$rrn;
			next;
		}

		#
		# Find the index for this rollrec in @rollreclines.
		#
		$rrind = rrindex($rrn);

		#
		# Bump our count of split rollrecs.
		#
		$rrcnt++;

		#
		# Find the specified field's entry in the rollrec's lines in
		# @rollreclines.  We'll skip over lines that don't have a
		# keyword and dquotes-enclosed value.
		#
		print ROLLREC_SPLIT "$rollreclines[$rrind]";
		for($rrind++; $rrind<$rollreclen; $rrind++)
		{
			my $ln = $rollreclines[$rrind];	# Line in rollrec file.
			my $lkw;			# Line's keyword.

			#
			# Get the line's keyword and value.
			#
			$ln =~ /^\s*([a-z_]+)\s+"([a-z0-9\/\-+_.,: \t]*)"/i;
			$lkw = $1;

			#
			# If we hit the beginning of the next rollrec or a
			# blank line, we'll write a blank line and, drop out.
			#
			if(($lkw =~ /^(roll|skip)$/i) || ($ln eq "\n"))
			{
				print ROLLREC_SPLIT "\n";
				last;
			}

			print ROLLREC_SPLIT "$ln";
		}

		#
		# If we hit the beginning of the next rollrec or a
		# blank line, we'll write a blank line and, drop out.
		#
		if($rrind == $rollreclen)
		{
			print ROLLREC_SPLIT "\n";
		}

		#
		# Delete the named rollrec.
		#
		rollrec_del($rrn);
	}

	#
	# Close the file handle.
	#
	close(ROLLREC_SPLIT);

	#
	# If we found some names that aren't in the original rollrec file,
	# we'll give an error and return the list of bad names.
	#
	if(@badnames > 0)
	{
		err("invalid rollrec names (@badnames) in split\n",1);
		return(-5, @badnames);
	}

	#
	# Write the updated rollrec file.
	#
	$modified = 1;
	rollrec_write();

	#
	# Return the number of rollrecs we split into a new rollrec file.
	#
	return($rrcnt);
}

#--------------------------------------------------------------------------
# Routine:	rollrec_readfile()
#
# Purpose:	Read the specified rollrec file.  The contents are read into
#		the @rollreclines array and the rollrecs are broken out into
#		the %rollrecs hash table.
#
sub rollrec_readfile
{
	my $rfh = shift;			# File handle for rollrec file.
	my $merger = shift;			# Merge-rollrec flag.
	my $name;				# Name of the rollrec entry.
	my $havecmdsalready = 0;		# Commands-read flag.
	my $prevline = 'dummy';			# Previous line.

	my $mir_start	 = -1;			# Start of merged rollrec.
	my $mir_found	 =  0;			# Found-info-rollrec flag.
	my $mir_ir_start = -1;			# Start of merged info rollrec.
	my $mir_version	 = -1;			# Merged rollrec's version.

	#
	# If we already have commands loaded, don't reload them.
	#
	my @currentcmds = rollmgr_getallqueuedcmds();
	$havecmdsalready = 1 if ($#currentcmds > -1);

	#
	# If we're starting a rollrec merge, we'll save the beginning
	# of the new rollrec.
	#
	$mir_start = $rollreclen if($merger);

	#
	# Grab the lines and pop 'em into the rollreclines array.  We'll also
	# save each rollrec into a hash table for easy reference.
	#
	while(<$rfh>)
	{
		my $line;		# Line from the rollrec file.
		my $keyword = "";	# Keyword from the line.
		my $value = "";		# Keyword's value.

		$line = $_;

		#
		# Collapse consecutive blank lines to a single blank.
		#
		# This isn't strictly necessary, but it keeps rollrec files
		# from getting filled with lots of blank lines.
		#
		next if(($prevline =~ /^\s*$/) && ($line =~ /^\s*$/));
		$prevline = $line;

		#
		# Save the line in our array of rollrec lines.
		#
		$rollreclines[$rollreclen] = $line;
		$rollreclen++;

		#
		# Skip comment lines and empty lines.
		#
		if(($line =~ /^\s*$/) || ($line =~ /^\s*[;#]/))
		{
			next;
		}

		#
		# Grab the keyword and value from the line.  The keyword
		# must be alphabetic.  The value can contain alphanumerics,
		# and a number of punctuation characters.  The value *must*
		# be enclosed in double quotes.
		#
		$line =~ /^\s*([a-zA-Z_]+)\s+"([a-zA-Z0-9\/\-+_.,: \@\t]*)"/;
		$keyword = $1;
		$value = $2;
#		print "rollrec_readfile:  keyword <$keyword>\t\t<$value>\n";

		#
		# If the keyword is "roll" or "skip" and we aren't merging
		# rollrecs, then we're starting a new record.  We'll save
		# the name of the rollrec, and then proceed on to the next
		# line.  
		#
		if(($keyword =~ /^roll$/i) || ($keyword =~ /^skip$/i))
		{
			if($merger)
			{
				#
				# If we've found the start of the info rollrec,
				# we'll save the position and set a flag that
				# we've found it.
				# If we've found the start of the next rollrec
				# after the info rollrec, then we'll remove
				# info rollrec from @rollreclines.
				#
				if($value eq $ROLLREC_INFO)
				{
					$mir_ir_start = $rollreclen - 1;
					$mir_found = 1;
					next;
				}
				elsif($mir_ir_start > -1)
				{
					splice @rollreclines, $mir_ir_start, -1;

					$mir_ir_start = -1;
				}
			}

			$name = $value;

			#
			# If this name has already been used for a rollrec,
			# we'll whinge, clean up, and return.  No rollrecs
			# will be retained.
			#
			if(exists($rollrecs{$name}))
			{
				rollrec_discard();
				err("rollrec_readfile:  duplicate record name; aborting...\n",-1);
				return(-1);
			}
			rollrec_newrec($keyword,$name,$rollreclen - 1);
			next;
		}

		elsif($keyword =~ /^cmd$/i)
		{
			#
			# The line is used to issue a specific command to run.
			# We queue it for later processing.
			#
# print STDERR "rollrec_readfile:  processing command: $value / $havecmdsalready\n";

			next if($havecmdsalready);

			my $cmdtoload = $value;
			my ($cmd, $arg) = ($cmdtoload =~ /^\s*(\w+)\s*(.*)$/);
			$cmd = "rollcmd_" . $cmd if($cmd !~ /^rollcmd_/);
 

			if(rollmgr_verifycmd($cmd) == 0)
			{
				err("rollrec_readfile: invalid command $cmdtoload\n", -1);
				next;
			}

			#
			# Save the command in our queue to process.
			#
			rollmgr_queuecmd($cmd, $arg);

			#
			# Remove the line from the file to write back out.
			#
			pop @rollreclines;
			next;
		}

		#
		# If we're merging rollrecs and we've found the rollrec
		# version in the info rollrec, save the version.
		# Also, we won't be adding anything from the additional
		# file's info rollrec to the existing info rollrec.
		#
		if($merger && ($mir_ir_start > -1) && ($keyword =~ /version/i))
		{
			$mir_version = $value;

			if($rollrecs{$ROLLREC_INFO}{'version'} < $mir_version)
			{
				err("rollrec_readfile:  merging rollrecs, version mismatch  - $rollrecs{$ROLLREC_INFO}{'version'}, $mir_version\n");
				return(-2);
			}

			next;
		}

		#
		# Save this zone's zonegroup.
		#
		if($keyword =~ /^zonegroup$/i)
		{
			$zonegroups{$value}++;
		}


		#
		# Save this subfield into the rollrec's collection.
		#
		$rollrecs{$name}{$keyword} = $value;
	}

	#
	# Make sure the last line is a blank line.
	#
	if($mir_found && ($mir_version == -1))
	{
		err("rollrec_readfile:  info rollrec found, but it contains no version field\n");
		return(-3);
	}

	#
	# Make sure the last line is a blank line.
	#
	if($rollreclines[-1] !~ /^\s*$/)
	{
		push @rollreclines, "\n";
		$rollreclen = @rollreclines;
	}

	#
	# If the rollrec doesn't have an info rollrec, we'll prepend a
	# new one.  The hash entries will be added to %rollrecs; the
	# file lines will be prepended to @rollreclines.
	#
	if(!defined($rollrecs{$ROLLREC_INFO}))
	{
		my @newinfo = ();			# New info rollrec.

		#
		# Build the new info rollrec.
		#
		$newinfo[0] = "\n";
		$newinfo[1] = "skip \"$ROLLREC_INFO\"\n";
		$newinfo[2] = "	version		\"$ROLLREC_CURRENT_VERSION\"\n";
		$newinfo[3] = "\n";

		#
		# Add the new info rollrec to our file contents and the
		# hash of rollrec entries.
		#
		unshift @rollreclines, @newinfo;

		$rollrecs{$ROLLREC_INFO}{'rollrec_type'} = 'skip';
		$rollrecs{$ROLLREC_INFO}{'version'} = $ROLLREC_CURRENT_VERSION;

		#
		# Set the file-modified flag and we're good to go.
		#
		$modified = 1;
	}

	#
	# Build our index of rollrec indices.
	#
	buildrrindex();

	return(0);
}

#--------------------------------------------------------------------------
# Routine:	rollrec_current()
#
# Purpose:	Return a boolean indicating if this rollrec is current.
#		Versions 0, 1, and 2 are considered equivalent.
#
#		If this rollrec file's version matches the current rollrec
#		version, we'll return a true value.
#		If the file's version is less than the current rollrec
#		version, we'll return a false value.
#		If the file's version is greater than the current rollrec
#		version, we'll return a false value and print an error message.
#		If the file's version is not in the proper format, we'll
#		return a false value and print an error message.
#
#		Since the last two conditions shouldn't ever happen, it could
#		be argued that a failure value should be returned.  However,
#		an easy two-value boolean function was wanted, not a three-
#		value function.
#
sub rollrec_current
{
	my $rrvers;					# Rollrec's version.

# print "rollrec_current:  down in ($name)\n";

	#
	# If the rollrec doesn't have a defined version, or there isn't
	# an info rollrec, then we'll force an out-of-date version.
	#
	if(!defined($rollrecs{$ROLLREC_INFO}) ||
	   !defined($rollrecs{$ROLLREC_INFO}{'version'}))
	{
		return(0);
	}

	#
	# Ensure the rollrec's version has the appropriate format.
	#
	$rrvers = $rollrecs{$ROLLREC_INFO}{'version'};

	if($rrvers !~ /^[0-9]+\.?[0-9]*$/)
	{
		print STDERR "invalid format for rollrec version - \"$rrvers\"\n";
		return(0);
	}

	#
	# Return an appropriate boolean for the rollrec file's currency.
	#
	if(($rrvers == 0)	||
	   ($rrvers == 1)	||
	   ($rrvers == $ROLLREC_CURRENT_VERSION))
	{
		return(1);
	}
	else
	{
		if($rrvers > $ROLLREC_CURRENT_VERSION)
		{
			print STDERR "invalid rollrec version - \"$rrvers\"; current version is \"$ROLLREC_CURRENT_VERSION\"\n";
		}
		return(0);
	}

}

#--------------------------------------------------------------------------
# Routine:	rollrec_info()
#
# Purpose:	Return the informational rollrec.
#
sub rollrec_info
{
	my $nrec = $rollrecs{$ROLLREC_INFO};

# print "rollrec_info:  down in ($name)\n";

	return($nrec);
}

#--------------------------------------------------------------------------
# Routine:	rollrec_version()
#
# Purpose:	Return the rollrec's version.  If the version is 0, then
#		we'll bump the number up to 1.
#
sub rollrec_version
{
	my $rrv = $rollrecs{$ROLLREC_INFO}{'version'};

# print "rollrec_version:  down in\n";

	$rrv = 1 if($rrv == 0);

	return($rrv);
}

#--------------------------------------------------------------------------
# Routine:	rollrec_names()
#
# Purpose:	Smoosh the rollrec names into an array and return the array.
#		The name of the informational rollrec willnot be returned.
#
sub rollrec_names
{
	my $rrn;				# Rollrec name index.
	my @names = ();				# Array for rollrec names.

# print "rollrec_names:  down in\n";

	foreach $rrn (sort(keys(%rollrecs)))
	{
		next if($rrn eq $ROLLREC_INFO);
		push @names, $rrn;
	}

	return(@names);
}

#--------------------------------------------------------------------------
# Routine:	rollrec_zonegroups()
#
# Purpose:	Return the zonegroups hash.
#
sub rollrec_zonegroups
{
# print "rollrec_zonegroups:  down in\n";

	return(%zonegroups);
}

#--------------------------------------------------------------------------
# Routine:	rollrec_zonegroup()
#
# Purpose:	Return the zones (rollrec names) in a given zonegroup.
#
sub rollrec_zonegroup
{
	my $zgname = shift;				# Zonegroup to look up.
	my @zglist = ();				# Zones in zonegroup.

# print "rollrec_zonegroup:  down in\n";

	#
	# Return null if the name isn't defined.
	#
	return if(! defined($zgname));

	#
	# Build a list of the zones in this zonegroup.
	#
	foreach my $rrn (sort(keys(%rollrecs)))
	{
		#
		# Skip the info rollrec.  It shouldn't have a zonegroup, anyway.
		#
		next if($rrn eq $ROLLREC_INFO);

		if($rollrecs{$rrn}{'zonegroup'} eq $zgname)
		{
			push @zglist, $rrn;
		}
	}

	#
	# Return the list.
	#
	return(@zglist);
}

#--------------------------------------------------------------------------
# Routine:	rollrec_zonegroup_cmds()
#
# Purpose:	Return the list of commands relevant to zonegroups.
#
sub rollrec_zonegroup_cmds
{
# print "rollrec_zonegroup_cmds:  down in\n";

	return(%zg_commands);
}

#--------------------------------------------------------------------------
# Routine:	rollrec_exists()
#
# Purpose:	Return a flag indicating if the given rollrec exists.
#
sub rollrec_exists
{
	my $name = shift;

# print "rollrec_exists:  down in ($name)\n";

	#
	# Skip the info rollrec.
	#
	return if($name eq $ROLLREC_INFO);

	return(exists($rollrecs{$name}));
}

#--------------------------------------------------------------------------
# Routine:	rollrec_fullrec()
#
# Purpose:	Return all entries in a given rollrec.
#
sub rollrec_fullrec
{
	my $name = shift;
	my $nrec = $rollrecs{$name};

# print "rollrec_fullrec:  down in ($name)\n";

	#
	# Skip the info rollrec.
	#
	return if($name eq $ROLLREC_INFO);

	return($nrec);
}

#--------------------------------------------------------------------------
# Routine:	rollrec_recval()
#
# Purpose:	Return the value of a name/subfield pair.
#
sub rollrec_recval
{
	my $name = shift;
	my $field = shift;
	my $val = $rollrecs{$name}{$field};

# print "rollrec_recval:  down in ($name) ($field) ($val)\n";

	#
	# Skip the info rollrec.
	#
	return if($name eq $ROLLREC_INFO);

	return($val);
}

#--------------------------------------------------------------------------
# Routine:	rollrec_rectype()
#
# Purpose:	Change the value of a rollrec.  The new value may only be
#		"roll" or "skip".
#
# Return Values:
#		1 - success
#		0 - failure (invalid record type or rollrec not found)
#
sub rollrec_rectype
{
	my $name    = shift;		# Name of rollrec we're modifying.
	my $rectype = shift;		# Rollrec's new type.
	my $rrind;			# Rollrec's index.

# print STDERR "rollrec_rectype:  <$name> <$rectype>\n";

	#
	# Skip the info rollrec.
	#
	return(0) if($name eq $ROLLREC_INFO);

	#
	# Make sure we've got a valid record type.
	#
	return(0) if(($rectype ne "roll") && ($rectype ne "skip"));

	#
	# Ensure this is a valid rollrec.
	#
	return(0) if(!defined($rollrecindex{$name}));

	#
	# Get the rollrec's index.
	#
	$rrind = rrindex($name);

	#
	# Change the rollrec's type.
	#
	$rollreclines[$rrind] =~ s/^(\s*)(roll|skip)(\s+)/$1$rectype$3/i;
	$rollrecs{$name}{'rollrec_type'} = $rectype;

	#
	# Set the modified flag and return success.
	#
	$modified = 1;
	return(1);
}

#--------------------------------------------------------------------------
# Routine:	rollrec_setval()
#
# Purpose:	Set the value of a name/subfield pair.  The value is saved
#		in both %rollrecs and in @rollreclines.  The $modified file-
#		modified flag is updated, along with the length $rollreclen.
#
sub rollrec_setval
{
	my $name   = shift;		# Name of rollrec we're modifying.
	my $field  = shift;		# Rollrec's subfield to be changed.
	my $val	   = shift;		# New value for the rollrec's subfield.

	my $found = 0;			# Rollrec-found flag.
	my $fldind;			# Loop index.
	my $rrind;			# Loop index for finding rollrec.
	my $lastfld = 0;		# Last found field in @rollreclines.

# print "rollrec_setval:  down in\n";

	#
	# Skip the info rollrec.
	#
	return(0) if($name eq $ROLLREC_INFO);

	#
	# If a rollrec of the specified name doesn't exist, we'll create a
	# new one.  We'll add it to @rollreclines and %rollrecs.
	#
	# We'll also assume it's a "roll" type rollrec.
	#
	if(!exists($rollrecs{$name}))
	{
		#
		# Add the rollrec to the %rollrecs hash.
		#
		rollrec_newrec("roll",$name,$rollreclen + 1);

		#
		# Start the new rollrec in @rollreclines.
		#
		$rollreclines[$rollreclen] = "\n";
		$rollreclen++;
		$rollreclines[$rollreclen] = "roll\t\"$name\"\n";
		$rollrecindex{$name} = $rollreclen;
		$rollreclen++;
	}

	#
	# Set the new value for the name/field in %rollrecs.
	#
	$rollrecs{$name}{$field} = $val;

	#
	# Get the index of the rollrec in @rollreclines.
	#
	$rrind = rrindex($name);

	#
	# Find the specified field's entry in the rollrec's lines in
	# @rollreclines.  We'll skip over lines that don't have a keyword
	# and dquotes-enclosed value.  If we hit the next rollrec then we'll
	# stop looking and add a new entry at the end of the rollrec's fields.
	#
	for($fldind=$rrind+1;$fldind<$rollreclen;$fldind++)
	{
		my $line = $rollreclines[$fldind];	# Line in rollrec file.
		my $lkw;				# Line's keyword.
		my $lval;				# Line's value.

		#
		# Get the line's keyword and value.
		#
		$line =~ /^\s*([a-zA-Z_]+)\s+"([a-zA-Z0-9\/\-+_.,: \t]*)"/;
		$lkw = $1;
		$lval = $2;

		#
		# Skip lines that don't match the expected field/value pattern.
		#
		next if($lkw eq "");

		#
		# If we hit the beginning of the next rollrec without
		# finding the field, drop out and insert it.
		#
		last if((lc($lkw) eq "roll") || (lc($lkw) eq "skip"));

		#
		# Save the index of the last field we've looked at that
		# belongs to the rollrec.
		#
		$lastfld = $fldind;

		#
		# If we found the field, set the found flag, drop out and
		# modify it.
		#
		if(lc($lkw) eq lc($field))
		{
			$found = 1;
			last;
		}
	}

	#
	# If we found the entry, we'll modify it in place.
	# If we didn't find the entry, we'll insert a new line into the array.
	#
	if($found)
	{
		$rollreclines[$fldind] =~ s/"([a-zA-Z0-9\/\-+_.,: \t]*)"/"$val"/;
	}
	else
	{
		my $newline = "\t$field\t\t\"$val\"\n";

		#
		# If the keyword is longer than 7 characters, we'll lop out one
		# of the tabs between the keyword and the value.  This is to do
		# some rough, simple formatting to keep the rollrec file some-
		# what orderly.  This assumes eight-character tabstops.
		#
		if(length($field) > 7)
		{
			$newline =~ s/\t\t/\t/;
		}

		#
		# If the starting rollrec line is the last line in the file,
		# we'll just push the new line at the end.  If it's somewhere
		# in the middle, we'll do the magic to insert it at the start
		# of the rollrec.
		#
		my @endarr = splice(@rollreclines,$rrind+1);
		push(@rollreclines,$newline);
		push(@rollreclines,@endarr);

		#
		# Bump the array length counter.
		#
		$rollreclen++;

		#
		# Rebuild our table of rollrec indices.
		#
		buildrrindex();
	}

	#
	# Tell the world (or at least the module) that the file has
	# been modified.
	#
	$modified = 1;
	return(0);
}

#--------------------------------------------------------------------------
# Routine:	rollrec_delfield()
#
# Purpose:	Delete a name/subfield pair.  The value is deleted from
#		both %rollrecs and @rollreclines.  The $modified file-
#		modified flag is updated, along with the length $rollreclen.
#
sub rollrec_delfield
{
	my $name   = shift;		# Name of rollrec we're modifying.
	my $field  = shift;		# Rollrec's subfield to be deleted.

	my $found = 0;			# Rollrec-found flag.
	my $fldind;			# Loop index.
	my $rrind;			# Loop index for finding rollrec.
	my $lastfld = 0;		# Last found field in @rollreclines.

# print "rollrec_delfield:  down in\n";

	#
	# Skip the info rollrec.
	#
	return(0) if($name eq $ROLLREC_INFO);

	#
	# Return if a rollrec of the specified name doesn't exist.
	#
	return(0) if(!exists($rollrecs{$name}));

	#
	# Return if a rollrec of the specified name doesn't have the
	# specified field.
	#
	return(0) if(!exists($rollrecs{$name}{$field}));

	#
	# Delete the field from %rollrecs.
	#
	delete($rollrecs{$name}{$field});

	#
	# Get the index for the rollrec.
	#
	$rrind = rrindex($name);

	#
	# Find the specified field's entry in the rollrec's lines in
	# @rollreclines.  We'll skip over lines that don't have a keyword
	# and dquotes-enclosed value.
	#
	for($fldind=$rrind+1;$fldind<$rollreclen;$fldind++)
	{
		my $line = $rollreclines[$fldind];	# Line in rollrec file.
		my $lkw;				# Line's keyword.
		my $lval;				# Line's value.

		#
		# Get the line's keyword and value.
		#
		$line =~ /^\s*([a-zA-Z_]+)\s+"([a-zA-Z0-9\/\-+_.,: \t]*)"/;
		$lkw = $1;
		$lval = $2;

		#
		# Go to the next line if this one doesn't match the
		# field/value pattern.
		#
		next if($lkw eq "");

		#
		# If we hit the beginning of the next rollrec without
		# finding the field, drop out.
		#
		last if((lc($lkw) eq "roll") || (lc($lkw) eq "skip"));

		#
		# Save the index of the last field we've looked at that
		# belongs to the rollrec.
		#
		$lastfld = $fldind;

		#
		# If we found the field, set the found flag, drop out and
		# modify it.
		#
		if(lc($lkw) eq lc($field))
		{
			$found = 1;
			last;
		}
	}

	#
	# If we found the entry, we'll delete it and rebuild the
	# rollrec index table.
	#
	if($found)
	{
		splice @rollreclines, $fldind, 1;
		buildrrindex();
	}

	#
	# Tell the world (or at least the module) that the file has
	# been modified.
	#
	$modified = 1;
	return(1);
}

#--------------------------------------------------------------------------
# Routine:	rollrec_add()
#
# Purpose:	Adds a new rollrec and fields to %rollrecs and $rollreclines.
#
sub rollrec_add
{
	my $rrtype = shift;		# Rollrec type.
	my $rrname = shift;		# Name of rollrec we're creating.
	my $flds   = shift;		# Reference to rollrec fields.

	my $chronosecs;			# Current time in seconds.
	my $chronostr;			# Current time string.


	my %fields;			# Rollrec fields.

# print "rollrec_add:  down in\n";

	#
	# Skip the info rollrec.
	#
	return if($rrname eq $ROLLREC_INFO);

	#
	# Get the timestamp.
	#
	$chronosecs = time();
	$chronostr  = gmtime($chronosecs);

	#
	# Create the basic rollrec info.
	#
	rollrec_newrec($rrtype,$rrname,$rollreclen + 1);

	#
	# Add the new rollrec's first line to the end of the rollrec table.
	# and add an entry to the rollrec index.
	#
	$rollreclines[$rollreclen] = "\n";
	$rollreclen++;
	$rollreclines[$rollreclen] = "roll\t\"$rrname\"\n";
	$rollrecindex{$rrname} = $rollreclen;
	$rollreclen++;

	#
	# Fill the new rollrec with the caller's hash fields and add it to
	# the end of the rollrec table.
	#
	if(defined($flds))
	{
		%fields = %$flds;
		foreach my $fn (@ROLLFIELDS)
		{
			my $spacing = "\t\t";	# Spacing string.

			#
			# Only add the timestamp at the end, and only
			# add the timestamp we're going to put in.
			#
			if(($fn eq 'rollrec_rollsecs') || ($fn eq 'rollrec_rolldate'))
			{
				next;
			}

			#
			# If this field isn't defined for the rollrec,
			# don't add it in.
			#
			if(!defined($fields{$fn}))
			{
				next;
			}

			#
			# Drop back to a single tab between key and value
			# if the key name is long.
			#
			$spacing = "\t"    if(length($fn) > 7);

			#
			# Add the field to the hash table and to the rollrec
			# file contents array.
			#
			$rollrecs{$rrname}{$fn} = $fields{$fn};
			$rollreclines[$rollreclen] = "\t$fn$spacing\"$fields{$fn}\"\n";
			$rollreclen++;
		}
	}

	#
	# Set a timestamp for this entry.
	#
	$rollrecs{$rrname}{'rollrec_rollsecs'} = $chronosecs;
	$rollrecs{$rrname}{'rollrec_rolldate'} = $chronostr;
	$rollreclines[$rollreclen] = "\trollrec_rollsecs\t\"$chronosecs\"\n";
	$rollreclen++;
	$rollreclines[$rollreclen] = "\trollrec_rolldate\t\"$chronostr\"\n";
	$rollreclen++;

	#
	# Put a blank line after the final line of the rollrec.
	#
	$rollreclines[$rollreclen] = "\n";
	$rollreclen++;

	#
	# Mark the rollrec file as having been modified.
	#
	$modified = 1;
	return(0);
}

#--------------------------------------------------------------------------
# Routine:	rollrec_del()
#
# Purpose:	Deletes a rollrec and fields from %rollrecs and $rollreclines.
#
sub rollrec_del
{
	my $rrname = shift;		# Name of rollrec we're deleting.

	my %rollrec;			# Rollrec to be deleted.
	my $rrr;			# Rollrec reference.

	my $ind;			# Index into rollreclines.
	my $rrind;			# Index to rollrec's first line.
	my $line;			# Rollrec line from @rollreclines.
	my $lkey;			# Rollrec line's key.
	my $lval;			# Rollrec line's value.
	my $len;			# Length of array slice to delete.

# print "rollrec_del:  down in\n";

	#
	# Skip the info rollrec.
	#
	return(-1) if($rrname eq $ROLLREC_INFO);

	#
	# Don't allow empty rollrec names or non-existent rollrecs.
	#
	return(-1) if($rrname eq '');
	return(-1) if(!defined($rollrecindex{$rrname}));

	#
	# Get a copy of the rollrec from the rollrec hash and then delete
	# the original.
	#
	$rrr = $rollrecs{$rrname};
	%rollrec = %$rrr;
	delete $rollrecs{$rrname};

	#
	# Get the index for this rollrec.
	#
	$rrind = rrindex($rrname);

	#
	# Find the beginning of the next rollrec.
	#
	for($ind = $rrind+1; $ind < $rollreclen; $ind++)
	{
		$line = $rollreclines[$ind];

		$line =~ /^\s*(roll|skip)\s+"([a-zA-Z0-9\/\-+_.,: \t]+)"/i;
		$lkey = $1;
		$lval = $2;

		last if(($lkey eq "roll") || ($lkey eq "skip"));
	}

	$ind--;

	#
	# Find the end of the previous rollrec (the one to be deleted.)
	#
	while($ind > $rrind)
	{
		last if($rollreclines[$ind] ne "\n");
		$ind--;
	}

	#
	# Delete the rollrec from @rollreclines.
	#
	$len = $ind - $rrind + 1;
	splice(@rollreclines,$rrind,$len);
	$rollreclen -= $len;

	#
	# Fold two consecutive blank lines into one.
	#
	if(($rollreclines[$rrind-1] eq "\n") && ($rollreclines[$rrind] eq "\n"))
	{
		splice(@rollreclines,$rrind,1);
	}

	#
	# Rebuild our table of rollrec indices.
	#
	buildrrindex();

	#
	# Mark that the file has been modified.
	#
	$modified = 1;
	return(0);
}

#--------------------------------------------------------------------------
# Routine:	rollrec_rename()
#
# Purpose:	Renames a rollrec.
#
sub rollrec_rename
{
	my $oldname = shift;		# Name of rollrec we're renaming.
	my $newname = shift;		# New name of rollrec.

	my %rollrec;			# Rollrec to be deleted.
	my $rrr;			# Rollrec reference.

	my $ind;			# Index into rollreclines.
	my $rrind;			# Index to rollrec's first line.
	my $line;			# Rollrec line from @rollreclines.
	my $lkey;			# Rollrec line's key.
	my $lval;			# Rollrec line's value.
	my $len;			# Length of array slice to delete.

# print "rollrec_rename:  down in\n";

	#
	# Skip the info rollrec.
	#
	return(-6) if($oldname eq $ROLLREC_INFO);
	return(-7) if($newname eq $ROLLREC_INFO);

	#
	# Don't allow empty rollrec names.
	#
	return(-1) if($oldname eq '');
	return(-2) if($newname eq '');

	#
	# The old rollrec must exist.
	#
	return(-3) if(! exists($rollrecs{$oldname}));

	#
	# Don't allow renames to existing rollrec names.
	#
	return(-4) if(exists($rollrecs{$newname}));

	#
	# Get a copy of the old rollrec.
	#
	$rollrecs{$newname} = $rollrecs{$oldname};

	#
	# Change the name field in the new rollrec.
	#
	$rollrecs{$newname}{'rollrec_name'} = $newname;
	$rrr = $rollrecs{$newname};
	%rollrec = %$rrr;

	#
	# If we didn't find a rollrec with this name, return failure.
	#
	return(-5) if(!defined($rollrecindex{name}));

	#
	# Get the index of this rollrec.
	#
	$rrind = rrindex($oldname);

	#
	# Find the beginning of the next rollrec.
	#
	$rollreclen = @rollreclines;
	for($ind = $rrind+1;$ind < $rollreclen; $ind++)
	{
		$line = $rollreclines[$ind];

		$line =~ /^\s*([a-zA-Z_]+)\s+"([a-zA-Z0-9\/\-+_.,: \@\t]*)"/;
		$lkey = $1;
		$lval = $2;

		last if($lkey eq "roll");
	}
	$ind--;

	#
	# Find the end of the previous rollrec (the one to be deleted.)
	#
	while($ind > $rrind)
	{
		last if($rollreclines[$ind] ne "\n");
		$ind--;
	}

	#
	# Find the rollrec's roll or skip line and change the name.
	#
	for(my $i=$rrind; $i <= $ind; $i++)
	{
		my $chunk;			# Key and spacing from line.

		$rollreclines[$i] =~ /^(\s*([a-zA-Z_]+)\s+)"([a-zA-Z0-9\/\-+_.,: \@\t]*)"/;
		$chunk = $1;
		$lkey = $2;

		if(($lkey eq 'roll') || ($lkey eq 'skip'))
		{
			$rollreclines[$i] = "$chunk\"$newname\"\n";
			last;
		}
	}

	#
	# Delete the old rollrec and the old name's entry in the index hash.
	#
	delete $rollrecs{$oldname};
	$rollrecindex{$newname} = $rollrecindex{$oldname};
	delete $rollrecindex{$oldname};

	#
	# Mark that the file has been modified.
	#
	$modified = 1;
	return(0);
}

#--------------------------------------------------------------------------
# Routine:	rollrec_settime()
#
# Purpose:	Sets the phase-start time in the rollrec.
#
sub rollrec_settime
{
	my $cnt	 = @_;			# Number of arguments.
	my $name = shift;		# Name of rollrec we're creating.
	my $val  = shift;		# Optional argument.

	my $chronos;			# Timestamp for the record.

# print "rollrec_settime:  down in\n";

	#
	# Skip the info rollrec.
	#
	return if($name eq $ROLLREC_INFO);

	if(($cnt == 2) && ($val == 0))
	{
		$chronos = '';
	}
	else
	{
		$chronos = gmtime();
		$chronos =~ s/\n$//;
	}

	rollrec_setval($name,"phasestart",$chronos);
}

#--------------------------------------------------------------------------
# Routine:	rollrec_newrec()
#
# Purpose:	Creates a rollrec in %rollrecs.  The name and type fields
#		are set.
#
#		This routine is NOT rebuilding the index.  Doing this here
#		has the potential for slowing down file reads and such.
#		The index is dealt with in those module routines which call
#		rollrec_newrec(); since it isn't exported, there should be
#		no outside callers to worry about.
#
sub rollrec_newrec
{
	my $type = shift;		# Type of rollrec we're creating.
	my $name = shift;		# Name of rollrec we're creating.
	my $line = shift;		# Line number of this rollrec.

# print "rollrec_newrec:  down in\n";

	return if(($type ne "roll") && ($type ne "skip"));

	$rollrecs{$name}{"rollrec_name"} = $name;
	$rollrecs{$name}{"rollrec_type"} = $type;

	$rollrecindex{$name} = $line;
}

#--------------------------------------------------------------------------
# Routine:	rollrec_fields()
#
# Purpose:	Return the list of rollrec fields.
#
sub rollrec_fields
{
# print "rollrec_fields:  down in\n";

	return(@ROLLFIELDS);
}

#--------------------------------------------------------------------------
# Routine:	rollrec_default()
#
# Purpose:	Return the default rollrec file.
#
sub rollrec_default
{
	my $confdir;				# Configuration directory.
	my $defrr;				# Default rollrec name.

# print "rollrec_default:  down in\n";

	#
	# Get the DNSSEC-Tools config directory.
	#
	$confdir = getconfdir() || $DEFAULT_DNSSECTOOLS_DIR;

	#
	# Build our lock file.
	#
	$defrr = "$confdir/$DEFAULT_ROLLREC";

	return($defrr);
}


#--------------------------------------------------------------------------
# Routine:	rollrec_init()
#
# Purpose:	Initialize the internal data.
#
sub rollrec_init
{
# print "rollrec_init:  down in\n";

	%rollrecs     = ();
	%zonegroups   = ();
	%rollrecindex = ();
	@rollreclines = ();
	$rollreclen   = 0;
	$modified     = 0;
}

#--------------------------------------------------------------------------
# Routine:	rollrec_discard()
#
# Purpose:	Discard the current rollrec file -- don't save the contents,
#		don't delete the file, reset all internal fields.
#
sub rollrec_discard
{
# print "rollrec_discard:  down in\n";

	close(ROLLREC);
	rollrec_init();
}

#--------------------------------------------------------------------------
# Routine:	rollrec_close()
#
# Purpose:	Save the roll record file and close the descriptor.
#
sub rollrec_close
{
# print "rollrec_close:  down in\n";

	rollrec_write();
	close(ROLLREC);
}

#--------------------------------------------------------------------------
# Routine:	rollrec_write()
#
# Purpose:	Save the roll record file and leave the file handle open.
#		We'll get an exclusive lock on the rollrec file in order
#		to (try to) ensure we're the only ones writing the file.
#
#		We'll make a (hopefully atomic) copy of the in-core rollrec
#		lines prior to trying to write.  This is an attempt to
#		keep the data from being mucked with while we're using it.
#
sub rollrec_write
{
	my $writecmds = shift;	# Boolean for saving unexecuted commands.
	my $rrc = "";		# Concatenated rollrec file contents.
	my $ofh;		# Old file handle.

	my @rrlines = @rollreclines;	# Copy of The Rollrec.
	my $rrlen;			# Number of lines in The Rollrec.

# print STDERR "rollrec_write:  down in\n";

	my @currentcmds = rollmgr_getallqueuedcmds();

	#
	# If the file hasn't changed, we'll skip writing.
	#
	return if(!$modified && ($#currentcmds == -1));

	#
	# Make sure we've got the correct count of rollrec lines.
	#
	$rrlen = @rrlines;

	#
	# Loop through the array of rollrec lines and concatenate them all.
	#
	for(my $ind = 0; $ind < $rrlen; $ind++)
	{
		$rrc .= $rrlines[$ind];
	}

	#
	# Remember any unprocessed queue commands.
	#
	if($writecmds)
	{
		foreach my $cmdandvalue (rollmgr_getallqueuedcmds())
		{
			my ($cmd, $value) = @$cmdandvalue;
			$cmd =~ s/^rollcmd_//;
			$rrc .= "cmd \"$cmd $value\"\n";
		}
	}

	#
	# Lock the rollrec file.
	#
	flock(ROLLREC,LOCK_EX);

	#
	# Force immediate writes of ROLLREC.
	#
	$ofh = select ROLLREC;
	$| = 1;

	#
	# Zap the rollrec file and write out the new one.
	#
	seek(ROLLREC,0,0);
	truncate(ROLLREC,0);
	print ROLLREC $rrc;

	#
	# Reset ROLLREC buffering to original state.
	#
	select $ofh;

	#
	# Unlock the rollrec file.
	#
	return(flock(ROLLREC,LOCK_UN));
}

#--------------------------------------------------------------------------
# Routine:	buildrrindex()
#
# Purpose:	This routine builds a name->index hash table for the defined
#		rollrecs.  The name is the name of a rollrec.  The index is
#		that rollrec's index in the @rollreclines array.  This hash
#		table drastically speeds up the reference time over the old
#		method of searching the whole table.
#
sub buildrrindex
{
# print "buildrrindex:  down in\n";

	#
	# Zap the current rollrec index.
	#
	%rollrecindex = ();

	#
	# Traipse through @rollreclines, and save the line index for the
	# start of each rollrec.
	#
	for(my $rrind=0;$rrind<$rollreclen;$rrind++)
	{
		my $line = $rollreclines[$rrind];	# Line in rollrec file.
		my $rrname;				# Rollrec name.

		#
		# Dig out the line's keyword and value.
		#
		$line =~ /^\s*(roll|skip)\s+"([a-zA-Z0-9\/\-+_.,: \t]+)"/i;
		$rrname = $2;

		#
		# If this is a roll or skip line, save the line index for
		# this rollrec entry.
		#
		if($rrname ne '')
		{
			$rollrecindex{$rrname} = $rrind;
		}
	}
}

#--------------------------------------------------------------------------
# Routine:	rrindex()
#
# Purpose:	Get the index for the named rollrec entry.  We'll first
#		consult the name's existing index to @rollreclines.  If the
#		name matches, all's well.  If it doesn't, then we'll rebuild
#		the index hash and then get the table index.
#
#		Callers MUST have already checked that the rollrec name
#		exists.  Arguably, this should be done here, but it isn't.
#
sub rrindex
{
	my $name = shift;			# Rollrec to look up.
	my $rrind;				# Rollrec's index.
	my $line;				# Supposed start of rollrec.
	my $lname;				# Name from line.

	#
	# Find the index for this rollrec in @rollreclines.
	#
	$rrind = $rollrecindex{$name};

	#
	# Get the line we're expecting this rollrec to start with.
	#
	$line = $rollreclines[$rrind];

	#
	# Dig out the rollrec name from this line.
	#
	$line =~ /^\s*(roll|skip)\s+"([a-zA-Z0-9\/\-+_.,: \t]+)"/i;
	$lname = $2;

	#
	# If this name doesn't match the requested name, we'll rebuild
	# the index and call ourself to find the index.
	#
	# This should never fail, as long as the caller already ensured
	# the rollrec name is valid.
	#
	if($lname ne $name)
	{
		buildrrindex();
		$rrind = rrindex($name);
	}

	#
	# Give the rollrec's index back to our caller.
	#
	return($rrind);
}

#--------------------------------------------------------------------------
# Routine:	rollrec_dump_hash()
#
# Purpose:	Dump the parsed rollrec entries.
#
sub rollrec_dump_hash
{
# print "rollrec_dump_hash:  down in\n";

	#
	# Loop through the hash of rollrecs and print the rollrec names,
	# subfields, and values.
	#
	foreach my $k (sort(keys(%rollrecs)))
	{
		print "rollrec - $k\n";
		my $subp = $rollrecs{$k};
		my %subrecs = %$subp;
		foreach my $sk (sort(keys(%subrecs)))
		{
			print "\t$sk\t\t$subrecs{$sk}\n";
		}
		print "\n";
	}
}

#--------------------------------------------------------------------------
# Routine:	rollrec_dump_array()
#
# Purpose:	Display the contents of @rollreclines.
#
sub rollrec_dump_array
{
# print "rollrec_dump_array:  down in\n";

	#
	# Loop through the array of rollrec lines and print them all.
	#
	for(my $ind=0;$ind<$rollreclen;$ind++)
	{
		print $rollreclines[$ind];
	}
}

1;

#############################################################################

=pod

=head1 NAME

Net::DNS::SEC::Tools::rollrec - Manipulate a DNSSEC-Tools rollrec file.

=head1 SYNOPSIS

  use Net::DNS::SEC::Tools::rollrec;

  rollrec_lock();
  rollrec_read("localhost.rollrec");

  $valid = rollrec_current();
  $rrinfo = rollrec_info();

  @rrnames = rollrec_names();

  $flag = rollrec_exists("example.com");

  $rrec = rollrec_fullrec("example.com");
  %rrhash = %$rrec;
  $zname = $rrhash{"maxttl"};

  $val = rollrec_recval("example.com","zonefile");

  rollrec_add("roll","example.com",\%rollfields);
  rollrec_add("skip","example.com",\%rollfields);

  rollrec_del("example.com");

  rollrec_rename("example.com","subdom.example.com");

  rollrec_type("example.com","roll");
  rollrec_type("example.com","skip");

  rollrec_setval("example.com","zonefile","db.example.com");

  rollrec_delfield("example.com","directory");

  rollrec_settime("example.com");
  rollrec_settime("example.com",0);

  @rollrecfields = rollrec_fields();

  $default_file = rollrec_default();

  $count = rollrec_merge("primary.rrf", "new0.rrf", "new1.rrf");
  @retvals = rollrec_split("new-rollrec.rrf", @rollrec_list);

  %zgroups = rollrec_zonegroups();
  @zgroup = rollrec_zonegroup($zonegroupname);
  @zgcmds = rollrec_zonegroup_cmds();

  rollrec_write();
  rollrec_close();
  rollrec_discard();

  rollrec_unlock();

=head1 DESCRIPTION

The B<Net::DNS::SEC::Tools::rollrec> module manipulates the contents of a
DNSSEC-Tools I<rollrec> file.  I<rollrec> files describe the status of a
zone rollover process, as performed by the DNSSEC-Tools programs.  Module
interfaces exist for looking up I<rollrec> records, creating new records,
and modifying existing records.

A I<rollrec> file is organized in sets of I<rollrec> records.  I<rollrec>s
describe the state of a rollover operation.  A I<rollrec> consists of a set
of keyword/value entries.  The following is an example of a I<rollrec>:

    roll "example"
	zonename		"example.com"
	zonefile		"/etc/dnssec-tools/zones/db.example.com"
	keyrec			"/etc/dnssec-tools/keyrec/example.keyrec"
	zonegroup		"example zones"
	directory		"/etc/dnssec-tools/dir-example.com"
	kskphase		"0"
	zskphase		"2"
	maxttl			"86400"
	administrator		"bob@bobhost.example.com"
	phasestart		"Wed Mar 09 21:49:22 2005"
	display			"0"
	loglevel		"info"
	rollrec_rollsecs	"1115923362"
	rollrec_rolldate	"Tue Mar 09 19:12:54 2005"
	curerrors		0
	maxerrors		5
        # optional records:
        istrustanchor           "yes"
        holddowntime            "8W"

Additionally, commands to be acted upon at start-up can be defined using the
"cmd" token as shown in the following example.

    cmd "rollzsk example.com"

Use this feature with caution and only if you understand the internals of
B<rollerd> and I<exactly> what will be done by the specified command.

The first step in using this module must be to read the I<rollrec> file.  The
I<rollrec_read()> interface reads the file and parses it into an internal
format.  The file's records are copied into a hash table (for easy reference
by the B<rollrec.pm> routines) and in an array (for
preserving formatting and comments.)

After the file has been read, the contents are referenced using
I<rollrec_fullrec()> and I<rollrec_recval()>.  The I<rollrec_add()>,
I<rollrec_setval()>, and I<rollrec_settime()> interfaces are used
to modify the contents of a I<rollrec> record.

If the I<rollrec> file has been modified, it must be explicitly written or
the changes will not saved.  I<rollrec_write()> saves the new contents to disk.
I<rollrec_close()> saves the file and close the Perl file handle to the
I<rollrec> file.  If a I<rollrec> file is no longer wanted to be open, yet
the contents should not be saved, I<rollrec_discard()> gets rid of the data
closes and the file handle B<without> saving any modified data.

On reading a I<rollrec> file, consecutive blank lines are collapsed into a
single blank line.  As I<rollrec> entries are added and deleted, files merged
and files split, it is possible for blocks of consecutive blanks lines to
grow.  This blank-line collapsing will prevent these blocks from growing
excessively.

There is a special I<rollrec> called the I<info rollrec>.  It contains
information about the I<rollrec> file, such as the version of I<rollrec>s
stored within the file.  It is only accessible through the I<rollrec_info()>
interface, and the I<rollrec_current()> interface will indicate if the file's
version number is current.

=head1 ROLLREC LOCKING

This module includes interfaces for synchronizing access to the I<rollrec>
files.  This synchronization is very simple and relies upon locking and
unlocking a single lock file for all I<rollrec> files.

I<rollrec> locking is not required before using this module, but it is
recommended.  The expected use of these facilities follows:

    rollrec_lock() || die "unable to lock rollrec file\n";
    rollrec_read();
    ... perform other rollrec operations ...
    rollrec_close();
    rollrec_unlock();

Synchronization is performed in this manner due to the way the module's
functionality is implemented, as well as providing flexibility to users
of the module.  It also provides a clear delineation in callers' code as
to where and when I<rollrec> locking is performed.

This synchronization method has the disadvantage of having a single lockfile
as a bottleneck to all I<rollrec> file access.  However, it reduces complexity
in the locking interfaces and cuts back on the potential number of required
lockfiles.

Using a single synchronization file may not be practical in large
installations.  If that is found to be the case, then this will be reworked.

=head1 ROLLREC INTERFACES

The interfaces to the B<rollrec.pm> module are given below.

=over 4

=item I<rollrec_add(rollrec_type,rollrec_name,fields)>

This routine adds a new I<rollrec> to the I<rollrec> file and the internal
representation of the file contents.  The I<rollrec> is added to both the
I<%rollrecs> hash table and the I<@rollreclines> array.  Entries are only
added if they are defined for I<rollrec>s.

I<rollrec_type> is the type of the I<rollrec>.  This must be either "roll"
or "skip".  I<rollrec_name> is the name of the I<rollrec>.  I<fields> is a
reference to a hash table that contains the name/value I<rollrec> fields.  The
keys of the hash table are always converted to lowercase, but the entry values
are left as given.

Timestamp fields are added at the end of the I<rollrec>.  These fields have
the key values I<rollrec_gensecs> and I<rollrec_gendate>.

A blank line is added after the final line of the new I<rollrec>.
The I<rollrec> file is not written after I<rollrec_add()>, though
it is internally marked as having been modified.

=item I<rollrec_close()>

This interface saves the internal version of the I<rollrec> file (opened with
I<rollrec_read()>) and closes the file handle. 

=item I<rollrec_current()>

This routine returns a boolean indicating if this open rollrec is current,
as defined by the version number in the I<info rollrec>.
Versions 0, 1, and 2 are considered to be equivalent.

Return values are:

    1 rollrec is current
    0 rollrec is obsolete
    0 rollrec has an invalid version

The last condition shouldn't ever happen and it could be argued that a
failure value should be returned.  However, an easy two-value boolean
function was wanted, not a three-value function.

=item I<rollrec_del(rollrec_name)>

This routine deletes a I<rollrec> from the set of I<rollrec>s loaded into
memory by the B<rollrec.pm> module.  The I<rollrec> is deleted from both
the I<%rollrecs> hash table and the I<@rollreclines> array.

The I<rollrec> file is not written after I<rollrec_del()>, though the
collection of I<rollrec>s is internally marked as having been modified.

Only the I<rollrec> itself is deleted.  Any associated comments and blank
lines surrounding it are left intact.

Return values are:

     0 successful rollrec deletion
    -1 unknown name

=item I<rollrec_delfield(rollrec_name,field)>

Deletes the given field from the specified I<rollrec>.  The file is
B<not> written after updating the value, but the internal file-modified flag
is set.  The value is saved in both I<%rollrecs> and in I<@rollreclines>.

Return values:

    0 - failure (rollrec not found or rollrec does not
	contain the field)
    1 - success

=item I<rollrec_discard()>

This routine removes a I<rollrec> file from use by a program.  The internally
stored data are deleted and the I<rollrec> file handle is closed.  However,
modified data are not saved prior to closing the file handle.  Thus, modified
and new data will be lost.

=item I<rollrec_exists(rollrec_name)>

This routine returns a boolean flag indicating if the I<rollrec> named in
I<rollrec_name> exists.

=item I<rollrec_fullrec(rollrec_name)>

I<rollrec_fullrec()> returns a reference to the I<rollrec> specified in
I<rollrec_name>.

=item I<rollrec_info()>

I<rollrec_info()> returns a reference to the I<info rollrec> given in the
current file.  This interface is the only way for a calling program to
retrieve this information.

=item I<rollrec_lock()>

I<rollrec_lock()> locks the I<rollrec> lockfile.  An exclusive lock is
requested, so the execution will suspend until the lock is available.  If the
I<rollrec> synchronization file does not exist, it will be created.  If the
process can't create the synchronization file, an error will be returned.
Success or failure is returned.

=item I<rollrec_merge(target_rollrec_file, rollrec_file1, ... rollrec_fileN)>

This interface merges the specified I<rollrec> files.  It reads each file
and parses them into a I<rollrec> hash table and a file-contents array.  The
resulting merge is written to the file named by I<target_rollrec_file>.
If another I<rollrec> is already open, it is saved and closed prior to
opening the new I<rollrec>.

If I<target_rollrec_file> is an existing I<rollrec> file, its contents will
be merged with the other files passed to I<rollrec_merge()>.  If the file
does not exist, I<rollrec_merge()> will create it and merge the remaining
files into it.

The I<info rollrec> can affect how the merging will work.  If the
I<target_rollrec_file> is doesn't exist or is empty, then a simple I<info
rollrec> will be added to the file.  No part of the I<info rollrec>s will be
merged into that of the I<target_rollrec_file>.

If the file does exist but doesn't have an I<info rollrec> B<rollrec>, then
then the source's I<info rollrec> is copied to the target.  The
files' I<info rollrec>s must either have the same version or the versions
must all be less than the version of the I<target_rollrec_file>.

Upon success, I<rollrec_merge()> returns the number of I<rollrec>s read from
the file.

Failure return values:

    -1 no rollrec files were given to rollrec_merge
    -2 unable to create target rollrec file
    -3 unable to read first rollrec file
    -4 an error occurred while reading the rollrec names
    -5 rollrec files were duplicated in the list of rollrec files

=item I<rollrec_names()>

This routine returns a list of the I<rollrec> names from the file.
The name of the I<info rollrec> is not included in this list.

=item I<rollrec_read(rollrec_file)>

This interface reads the specified I<rollrec> file and parses it into a
I<rollrec> hash table and a file-contents array.  I<rollrec_read()> B<must> be
called prior to any of the other B<rollrec.pm> calls.  If another I<rollrec>
is already open, it is saved and closed prior to opening the new I<rollrec>.

I<rollrec_read()> attempts to open the I<rollrec> file for reading and
writing.  If this fails, then it attempts to open the file for reading only.

I<rollrec_read()> is a front-end for I<rollrec_readfile()>.  It sets up the
module's saved data in preparation for reading a new I<rollrec> file.  These
house-keeping actions are not performed by I<rollrec_readfile()>.

Upon success, I<rollrec_read()> returns the number of I<rollrec>s read from
the file.

Failure return values:

    -1 specified rollrec file doesn't exit
    -2 unable to open rollrec file
    -3 duplicate rollrec names in file

=item I<rollrec_readfile(rollrec_file_handle,mergeflag)>

This interface reads the specified file handle to a I<rollrec> file and
parses the file contents into a I<rollrec> hash table and a file-contents
array.  The hash table and file-contents array are B<not> cleared prior
to adding data to them.

The I<mergeflag> argument indicates whether the call will be merging a
I<rollrec> file with a previously read I<rollrec> or if it will be reading
a fresh I<rollrec> file.

Upon success, I<rollrec_read()> returns zero.

Failure return values:

    -1 duplicate rollrec names in file

=item I<rollrec_rectype(rollrec_name,rectype)>

Set the type of the specified I<rollrec> record.  The file is
B<not> written after updating the value, but the internal file-modified flag
is set.  The value is saved in both I<%rollrecs> and in I<@rollreclines>.

I<rollrec_name> is the name of the I<rollrec> that will be modified.
I<rectype> is the new type of the I<rollrec>, which must be either "roll"
or "skip".

Return values:

    0 - failure (invalid record type or rollrec not found)
    1 - success

=item I<rollrec_recval(rollrec_name,rollrec_field)>

This routine returns the value of a specified field in a given I<rollrec>.
I<rollrec_name> is the name of the particular I<rollrec> to consult.
I<rollrec_field> is the field name within that I<rollrec>.

For example, the current I<rollrec> file contains the following I<rollrec>.

    roll	"example.com"
                zonefile        "db.example.com"

The call:

    rollrec_recval("example.com","zonefile")

will return the value "db.example.com".

=item I<rollrec_rename(old_rollrec_name,new_rollrec_name)>

This routine renames the I<rollrec> named by I<old_rollrec_name> to
I<new_rollrec_name>.  The actual effect is to change the name in the I<roll>
or I<skip> line to I<new_rollrec_name>.  The name is changed in the internal
version of the the I<rollrec> file only.  The file itself is not changed, but
must be saved by calling either I<rollrec_write()>, I<rollrec_save()>, or
I<rollrec_saveas()>.

I<old_rollrec_name> must be the name of an existing I<rollrec>.  Conversely,
I<new_rollrec_name> must not name an existing I<rollrec>.

Return values:

     0 - success
    -1 - old_rollrec_name was null or empty
    -2 - new_rollrec_name was null or empty
    -3 - old_rollrec_name is not an existing rollrec
    -4 - new_rollrec_name is already a rollrec
    -5 - internal error that should never happen

=item I<rollrec_settime(rollrec_name,val)>

Set the phase-start timestamp in the I<rollrec> specified by I<rollrec_name>
to the current time.  If the optional I<val> parameter is given and it is
zero, then the phase-start timestamp is set to a null value.

The file is B<not> written after updating the value.

=item I<rollrec_setval(rollrec_name,field,value)>

Set the value of a name/field pair in a specified I<rollrec>.  The file is
B<not> written after updating the value, but the internal file-modified flag
is set.  The value is saved in both I<%rollrecs> and in I<@rollreclines>.

I<rollrec_name> is the name of the I<rollrec> that will be modified.  If the
named I<rollrec> does not exist, it will be created as a "roll"-type
I<rollrec>.
I<field> is the I<rollrec> field which will be modified.
I<value> is the new value for the field.

=item I<rollrec_split(new_rollrec_file,rollrec_names)>

Move a set of I<rollrec> entries from the current I<rollrec> file to a new
file.  The moved I<rollrec> entries are removed both from the current file
and from the internal module data representing that file.

The I<new_rollrec_file> parameter holds the name of the new I<rollrec> file.
If this file doesn't exist, it will be created.  If it does exist, the
I<rollrec> entries will be appended to that file.

I<rollrec_names> is a list of I<rollrec> entries that will be moved from the
current file to the file named in I<new_rollrec_file>.  If some of the given
I<rollrec> names are invalid, the valid names will be moved to the new file
and the invalid names will be returned in a list to the caller.

Only the I<rollrec> entries themselves will be moved to the new I<rollrec>
file.  Any associated comments will be left in the current I<rollrec> file.

I<rollrec>-splitting gets interesting with the addition of the I<info
rollrec>.  If the I<new_rollrec_file> file doesn't exist, the source
B<rollrec> file's I<info rollrec> is copied to the target file.  If the file
does exist but doesn't have an I<info rollrec>, then then the source's I<info
rollrec> is copied to the target.  If the target file exists and has an I<info
rollrec>, then the two files must have matching version numbers.

On success, the count of moved I<rollrec> entries is returned.  Error returns
are given below.

Failure return values:
    -1 - no target rollrec file given in new_rollrec_file
    -2 - no rollrec names given in rollrec_names
    -3 - none of the rollrec names given are existing rollrecs
    -4 - unable to open new_rollrec_file
    -5 - invalid rollrec names were specified in rollrec_names,
         followed by the list of bad names
    -6 - target's info rollrec has previous version than current
    -7 - target's info rollrec has (undefined) later version
         than current
    -8 - target's info rollrec exists without version number

=item I<rollrec_unlock()>

I<rollrec_unlock()> unlocks the I<rollrec> synchronization file.

=item I<rollrec_write()>

This interface saves the internal version of the I<rollrec> file (opened with
I<rollrec_read()>).  It does not close the file handle.  As an efficiency
measure, an internal modification flag is checked prior to writing the file.
If the program has not modified the contents of the I<rollrec> file, it is not
rewritten.

I<rollrec_write()> gets an exclusive lock on the I<rollrec> file while writing.

=item I<rollrec_zonegroup($zonegroupname)>

This interface returns a list of the zones in the zonegroup (named by
I<$zonegroupname>) defined in the current I<rollrec> file.  Null is returned
if there are no zones in the zonegroup.

While this is using the term "zone", it is actually referring to the name of
the rollrec entries.  For a particular rollrec entry, the rollrec name is
usually the same as the zone name, but this is not a requirement.

=item I<rollrec_zonegroup_cmds()>

This interface returns a list of the rollctl commands whose behavior changes
when they are used with the I<-group> option.

=item I<rollrec_zonegroups()>

This interface returns a hash table of the zonegroups defined in the current
I<rollrec> file.  The hash key is the name of the zonegroup; the hash value
is the number of zones in the zonegroup.  Null is returned if there are no
zonegroups in the I<rollrec> file.

While this is using the term "zone", it is actually referring to the name of
the rollrec entries.  For a particular rollrec entry, the rollrec name is
usually the same as the zone name, but this is not a requirement.

=back

=head1 ROLLREC INTERNAL INTERFACES

The interfaces described in this section are intended for internal use by the
B<rollrec.pm> module.  However, there are situations where external entities
may have need of them.  Use with caution, as misuse may result in damaged or
lost I<rollrec> files.

=over 4

=item I<rollrec_init()>

This routine initializes the internal I<rollrec> data.  Pending changes will
be lost.  An open I<rollrec> file handle will remain open, though the data are
no longer held internally.  A new I<rollrec> file must be read in order to use
the B<rollrec.pm> interfaces again.

=item I<rollrec_default()>

This routine returns the name of the default I<rollrec> file.

=back

=head1 ROLLREC DEBUGGING INTERFACES

The following interfaces display information about the currently parsed
I<rollrec> file.  They are intended to be used for debugging and testing, but
may be useful at other times.

=over 4

=item I<rollrec_dump_hash()>

This routine prints the I<rollrec> file as it is stored internally in a hash
table.  The I<rollrec>s are printed in alphabetical order, with the fields
alphabetized for each I<rollrec>.  New I<rollrec>s and I<rollrec> fields are
alphabetized along with current I<rollrec>s and fields.  Comments from the
I<rollrec> file are not included with the hash table.

=item I<rollrec_dump_array()>

This routine prints the I<rollrec> file as it is stored internally in an
array.  The I<rollrec>s are printed in the order given in the file, with the
fields ordered in the same manner.  New I<rollrec>s are appended to the end
of the array.  I<rollrec> fields added to existing I<rollrec>s are added at
the beginning of the I<rollrec> entry.  Comments and vertical whitespace are
preserved as given in the I<rollrec> file.

=back

=head1 COPYRIGHT

Copyright 2006-2013 SPARTA, Inc.  All rights reserved.
See the COPYING file included with the DNSSEC-Tools package for details.

=head1 AUTHOR

Wayne Morrison, tewok@tislabs.com

=head1 SEE ALSO

B<lsroll(1)>,
B<rollchk(8)>,
B<rollinit(8)>

B<Net::DNS::SEC::Tools::keyrec(3)>,
B<Net::DNS::SEC::Tools::keyrec(5)>

=cut
