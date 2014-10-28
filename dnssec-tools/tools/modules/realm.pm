#!/usr/bin/perl
#
# Copyright 2012-2014 SPARTA, Inc.  All rights reserved.  See the COPYING
# file distributed with this software for details.
#
# DNSSEC Tools
#
#	Realmrec file routines.
#
#	The routines in this module manipulate a realm file for DNSSEC-Tools.
#	The realm file contains information about separate rollover
#	instantiations.
#
#	Entries in the realm file are of the key/value format, with the value
#	enclosed in quotes.  Comments may be included by prefacing them with
#	the '#' or ';' comment characters.
#
#	An example realm file follows:
#
#	    realm "production"
#		state		"active"
#		realmdir	"/usr/etc/dnssec-tools/realms/production"
#		configdir	"/usr/local/realms/production"
#		statedir	"/usr/local/realms/production"
#		rollrec		"production.rollrec"
#		administrator	"sysfolks@example.com"
#		display		"1"
#		args		"-loglevel phase -logfile log.prod -display"
#		user		"prodmgr"
#
#	    realm "testing"
#		state		"inactive"
#		realmdir	"/usr/etc/dnssec-tools/realms/testing"
#		configdir	"/usr/local/realms/production"
#		rollrec		"testing.rollrec"
#		manager		"rollerd-test"
#		args		"-sleep 16 -loglevel tmi -logfile log.test"
#		user		"realmtester"
#

package Net::DNS::SEC::Tools::realm;

require Exporter;
use strict;

use Fcntl qw(:DEFAULT :flock);

use Net::DNS::SEC::Tools::conf;
# use Net::DNS::SEC::Tools::rollmgr;

our $VERSION = "2.0";
our $MODULE_VERSION = "2.0.0";

our @ISA = qw(Exporter);

#--------------------------------------------------------------------------

#
# Exported commands.
#

our @EXPORT = qw(
			realm_add
			realm_close
			realm_default
			realm_del
			realm_delfield
			realm_discard
			realm_dump_array
			realm_dump_hash
			realm_exists
			realm_fields
			realm_fullrec
			realm_init
			realm_lock
			realm_merge
			realm_names
			realm_read
			realm_readfiles
			realm_rectype
			realm_recval
			realm_rename
			realm_setval
			realm_split
			realm_unlock
			realm_write
		);

#--------------------------------------------------------------------------

#
# Default file names.
#
my $DEFAULT_DNSSECTOOLS_DIR = getconfdir();
my $DEFAULT_REALMFILE = "dnssec-tools.realm";
my $LOCKNAME = "realm.lock";

#
# Valid fields in a realm.
#
my @REALMFIELDS = (
			'state',
			'realmdir',
			'configdir',
			'statedir',
			'rollrec',
			'administrator',
			'display',
			'user',
			'manager',
			'args',
			'hoard',		# only used by buildrealms
		  );

#--------------------------------------------------------------------------

my @realmlines;			# Realm lines.
my $realmlen;			# Number of realm lines.

my %realms;			# Realm hash table.
my %realmindex;			# Maps realm names to @realmlines indices.

my $modified;			# File-modified flag.

#--------------------------------------------------------------------------
# Routine:	realm_lock()
#
# Purpose:	Lock realm processing so that only one process reads a
#		realm file at a time.
#
#		The actual realm file is not locked; rather, a synch-
#		ronization file is locked.  We lock in this manner due to
#		the way the realm module's functionality is spread over
#		a set of routines.
#
sub realm_lock
{
	my $lockdir;			# Configuration file directory.
	my $lockfile;			# Name of the lock file.

# print "realm_lock:  down in\n";

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
# Routine:	realm_unlock()
#
# Purpose:	Unlock realm processing so that other processes may read
#		a realm file.
#
sub realm_unlock
{
# print "realm_unlock:  down in\n";

	#
	# Unlock the lock file.
	#
	return(flock(RRLOCK,LOCK_UN));
}

#--------------------------------------------------------------------------
# Routine:	realm_read()
#
# Purpose:	Read a DNSSEC-Tools realm file.  The contents are read into
#		the @realmlines array and the realms are broken out into
#		the %realms hash table.
#
sub realm_read
{
	my $rlmf = shift;		# Realm record file.
	my $rlmcnt;			# Number of realms we found.
	my @sbuf;			# Buffer for stat().

# print "realm_read:  down in\n";

	#
	# Use the default realm file, unless the caller specified
	# a different file.
	#
	$rlmf = realm_default() if($rlmf eq "");

	#
	# Make sure the realm file exists.
	#
	if(! -e $rlmf)
	{
		err("realm file $rlmf does not exist\n",-1);
		return(-1);
	}

	#
	# If a realm file is already open, we'll flush our buffers and
	# save the file.
	#
	@sbuf = stat(REALM);
	realm_close() if(@sbuf != 0);

	#
	# Open up the realm file.  If we can't open it for reading and
	# writing, we'll try to open it just for reading.
	#
	if(open(REALM,"+< $rlmf") == 0)
	{
		if(open(REALM,"< $rlmf") == 0)
		{
			err("unable to open $rlmf\n",-1);
			return(-2);
		}
	}

	#
	# Initialize some data.
	#
	realm_init();

	#
	# Read the contents of the specified realm file.
	#
	realm_readfile(*REALM);

	#
	# Return the number of realms we found.
	#
	$rlmcnt = keys(%realms);
	return($rlmcnt);
}

#--------------------------------------------------------------------------
# Routine:	realm_merge()
#
# Purpose:	Merge a set of DNSSEC-Tools realm files.  The contents are
#		read into the @realmlines array and the realms are broken
#		out into the %realms hash table.
#
sub realm_merge
{
	my $firstrlm = shift;		# First realm file in list.
	my @rlmlist = @_;		# Set of realm files.

	my %allrlms = ();		# All realm filenames to be merged.
	my $errs = 0;			# Count of non-fatal errors.
	my $rrcnt;			# Number of realms we found.

# print "realm_merge:  down in\n";

	#
	# Make sure a set of realm files was specified.
	#
	if((! defined($firstrlm)) || (@rlmlist == 0))
	{
		err("no realm files given to merge\n",1);
		return(-1);
	}

	#
	# Build a hash of the realm file names and the number of times
	# each is specified.
	#
	foreach my $fn ($firstrlm, @rlmlist)
	{
		$allrlms{$fn}++;
	}

	#
	# Bump the error count if a file was listed multiple times.
	#
	foreach my $fn (keys(%allrlms))
	{
		$errs++ if($allrlms{$fn} > 1);
	}

	#
	# If any file was listed multiple times, given an error and return.
	#
	if($errs)
	{
		err("unable to merge realm files since some realm files were given multiple times\n",1);
		return(-5);
	}

	#
	# Create a target file if the first realm file doesn't exist.
	#
	if(! -e $firstrlm)
	{
		if(open(TMP,"> $firstrlm") == 0)
		{
			err("realm_merge:  unable to create target realm file \"$firstrlm\"\n",1);
			return(-2);
		}
		close(TMP);
	}

	#
	# Read the first realm file.  This will also zap all our current
	# internal data.
	#
	$allrlms{$firstrlm}++;
	if(realm_read($firstrlm) < 0)
	{
		return(-3);
	}

	#
	# Read each remaining realm file and add it to our internal
	# realm collection.
	#
	foreach my $rrf (@rlmlist)
	{
		#
		# Make sure the realm file exists.
		#
		if(! -e $rrf)
		{
			err("realm file \"$rrf\" does not exist\n",1);
			$errs++;
			next;
		}

		#
		# Close the needed file handle.
		#
		close(REALM_MERGE);

		#
		# Open up the realm file.
		#
		if(open(REALM_MERGE,"< $rrf") == 0)
		{
			err("unable to open $rrf\n",1);
			$errs++;
			next;
		}

		#
		# Read the contents of the specified realm file.
		#
		if(realm_readfile(*REALM_MERGE) < 0)
		{
			$errs++;
		}
	}

	#
	# Close the file handle.
	#
	close(REALM_MERGE);

	#
	# If we encountered errors while merging the files, we'll give
	# an error and reset ourself.
	#
	if($errs)
	{
		err("unable to merge realm files due to errors\n",1);
		realm_init();
		return(-4);
	}

	#
	# Write the new realm file.
	#
	$modified = 1;
	realm_write();

	#
	# Return the number of realm we found.
	#
	$rrcnt = keys(%realms);
	return($rrcnt);
}

#--------------------------------------------------------------------------
# Routine:	realm_split()
#
# Purpose:	Split a realm file in two.  A list of realm entries will
#		be removed from the current realm file and appended to
#		another file.  The realm entries will be removed from
#		@realmlines and %realms.
#
#		The realms will be appended to the destination file.
#
sub realm_split
{
	my $newrrf = shift;		# New realm file.
	my @rrlist = @_;		# Set of realm names.

	my $valid = 0;			# Count of valid names.
	my @badnames = ();		# List of invalid names.
	my $rrcnt = 0;			# Number of realms we split.

# print "realm_split:  down in\n";

	#
	# Make sure a set of realm files was specified.
	#
	if((! defined($newrrf)) || ($newrrf eq ''))
	{
		err("no target realm file given for split\n",1);
		return(-1);
	}

	#
	# Make sure a set of realm files was specified.
	#
	if(@rrlist == 0)
	{
		err("no realm names given for split\n",1);
		return(-2);
	}

	#
	# Count the valid realm names in the name list.
	#
	foreach my $rrn (@rrlist)
	{
		$valid++ if(defined($realms{$rrn}));
	}

	#
	# Ensure that at least one of the realm names in the name list
	# is valid.
	#
	if($valid == 0)
	{
		err("no realm names given for split are existing realms\n",1);
		return(-3);
	}

	#
	# Open the target realm file for appending.
	#
	if(open(REALM_SPLIT,">> $newrrf") == 0)
	{
		err("unable to open \"$newrrf\" for split\n",1);
		return(-4);
	}

	#
	# Read each remaining realm file and add it to our internal
	# realm collection.
	#
	foreach my $rrn (@rrlist)
	{
		my $rlmind;			# Index to realm's first line.

		#
		# If this name isn't the name of an existing realm, we'll
		# save the name and go to the next.
		#
		if(! exists($realms{$rrn}))
		{
			push @badnames,$rrn;
			next;
		}

		#
		# Find the index for this realm in @realmlines.
		#
		$rlmind = rlmindex($rrn);

		#
		# Bump our count of split realms.
		#
		$rrcnt++;

		#
		# Find the specified field's entry in the realm's lines in
		# @realmlines.  We'll skip over lines that don't have a
		# keyword and dquotes-enclosed value.
		#
		print REALM_SPLIT "$realmlines[$rlmind]";
		for($rlmind++; $rlmind<$realmlen; $rlmind++)
		{
			my $ln = $realmlines[$rlmind];	# Line in realm file.
			my $lkw;			# Line's keyword.

			#
			# Get the line's keyword and value.
			#
			$ln =~ /^\s*([a-z_]+)\s+"([a-z0-9\/\-+_.,: \t]*)"/i;
			$lkw = $1;

			#
			# If we hit the beginning of the next realm or a
			# blank line, we'll write a blank line and, drop out.
			#
			if(($lkw =~ /^realm$/i) || ($ln eq "\n"))
			{
				print REALM_SPLIT "\n";
				last;
			}

			print REALM_SPLIT "$ln";
		}

		#
		# If we hit the beginning of the next realm or a
		# blank line, we'll write a blank line and, drop out.
		#
		if($rlmind == $realmlen)
		{
			print REALM_SPLIT "\n";
		}

		#
		# Delete the named realm.
		#
		realm_del($rrn);
	}

	#
	# Close the file handle.
	#
	close(REALM_SPLIT);

	#
	# If we found some names that aren't in the original realm file,
	# we'll give an error and return the list of bad names.
	#
	if(@badnames > 0)
	{
		err("invalid realm names (@badnames) in split\n",1);
		return(-5, @badnames);
	}

	#
	# Write the updated realm file.
	#
	$modified = 1;
	realm_write();

	#
	# Return the number of realms we split into a new realm file.
	#
	return($rrcnt);
}

#--------------------------------------------------------------------------
# Routine:	realm_readfile()
#
# Purpose:	Read the specified realm file.  The contents are read into
#		the @realmlines array and the realms are broken out into
#		the %realms hash table.
#
sub realm_readfile
{
	my $rfh = shift;			# File handle for realm file.
	my $name;				# Name of the realm entry.
	my $havecmdsalready = 0;		# Commands-read flag.
	my $prevline = 'dummy';			# Previous line.

	#
	# Grab the lines and pop 'em into the realmlines array.  We'll also
	# save each realm into a hash table for easy reference.
	#
	while(<$rfh>)
	{
		my $line;		# Line from the realm file.
		my $keyword = "";	# Keyword from the line.
		my $value = "";		# Keyword's value.

		$line = $_;

		#
		# Collapse consecutive blank lines to a single blank.
		#
		# This isn't strictly necessary, but it keeps realm files
		# from getting filled with lots of blank lines.
		#
		next if(($prevline =~ /^\s*$/) && ($line =~ /^\s*$/));
		$prevline = $line;

		#
		# Save the line in our array of realm lines.
		#
		$realmlines[$realmlen] = $line;
		$realmlen++;

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
#		print "realm_readfile:  keyword <$keyword>\t\t<$value>\n";

		#
		# If the keyword is "realm", then we're starting a new record.
		# We'll save the name of the realm, and then proceed on to
		# the next line.  
		#
		if($keyword =~ /^realm$/i)
		{
			$name = $value;

			#
			# If this name has already been used for a realm,
			# we'll whinge, clean up, and return.  No realms
			# will be retained.
			#
			if(exists($realms{$name}))
			{
				realm_discard();
				err("realm_readfile:  duplicate record name; aborting...\n",-1);
				return(-1);
			}
			realm_newrec($keyword,$name,$realmlen - 1);
			next;
		}

		#
		# Save this subfield into the realm's collection.
		#
		$realms{$name}{$keyword} = $value;
	}

	#
	# Make sure the last line is a blank line.
	#
	if($realmlines[-1] !~ /^\s*$/)
	{
		push @realmlines, "\n";
		$realmlen = @realmlines;
	}

	#
	# Build our index of realm indices.
	#
	buildrealmindex();

	return(0);
}

#--------------------------------------------------------------------------
# Routine:	realm_names()
#
# Purpose:	Smoosh the realm names into an array and return the array.
#
sub realm_names
{
	my $rrn;				# Realm name index.
	my @names = ();				# Array for realm names.

# print "realm_names:  down in\n";

	foreach $rrn (sort(keys(%realms)))
	{
		push @names, $rrn;
	}

	return(@names);
}

#--------------------------------------------------------------------------
# Routine:	realm_exists()
#
# Purpose:	Return a flag indicating if the given realm exists.
#
sub realm_exists
{
	my $name = shift;

# print "realm_exists:  down in ($name)\n";

	return(exists($realms{$name}));
}

#--------------------------------------------------------------------------
# Routine:	realm_fullrec()
#
# Purpose:	Return all entries in a given realm.
#
sub realm_fullrec
{
	my $name = shift;
	my $nrec = $realms{$name};

# print "realm_fullrec:  down in ($name)\n";

	return($nrec);
}

#--------------------------------------------------------------------------
# Routine:	realm_recval()
#
# Purpose:	Return the value of a name/subfield pair.
#
sub realm_recval
{
	my $name = shift;
	my $field = shift;
	my $val = $realms{$name}{$field};

# print "realm_recval:  down in ($name) ($field) ($val)\n";

	return($val);
}

#--------------------------------------------------------------------------
# Routine:	realm_rectype()
#
# Purpose:	Change the value of a realm.  The new value may only be
#		"realm".
#
# Return Values:
#		1 - success
#		0 - failure (invalid record type or realm not found)
#
sub realm_rectype
{
	my $name    = shift;		# Name of realm we're modifying.
	my $rectype = shift;		# Realm's new type.
	my $rlmind;			# Realm's index.

# print STDERR "realm_rectype:  <$name> <$rectype>\n";

	#
	# Make sure we've got a valid record type.
	#
	return(0) if($rectype ne "realm");

	#
	# Ensure this is a valid realm.
	#
	return(0) if(!defined($realmindex{$name}));

	#
	# Get the realm's index.
	#
	$rlmind = rlmindex($name);

	#
	# Change the realm's type.
	#
	$realmlines[$rlmind] =~ s/^(\s*)realm(\s+)/$1$rectype$2/i;
	$realms{$name}{'realm_type'} = $rectype;

	#
	# Set the modified flag and return success.
	#
	$modified = 1;
	return(1);
}

#--------------------------------------------------------------------------
# Routine:	realm_setval()
#
# Purpose:	Set the value of a name/subfield pair.  The value is saved
#		in both %realms and in @realmlines.  The file-modified flag
#		is updated, along with the length $realmlen.
#
sub realm_setval
{
	my $name   = shift;		# Name of realm we're modifying.
	my $field  = shift;		# Realm's subfield to be changed.
	my $val	   = shift;		# New value for the realm's subfield.

	my $found = 0;			# Realm-found flag.
	my $fldind;			# Loop index.
	my $rlmind;			# Loop index for finding realm.
	my $lastfld = 0;		# Last found field in @realmlines.

# print "realm_setval:  down in\n";

	#
	# If a realm of the specified name doesn't exist, we'll create a
	# new one.  We'll add it to @realmlines and %realms.
	#
	# We'll also assume it's a "realm" type realm.
	#
	if(!exists($realms{$name}))
	{
		#
		# Add the realm to the %realms hash.
		#
		realm_newrec("realm",$name,$realmlen + 1);

		#
		# Start the new realm in @realmlines.
		#
		$realmlines[$realmlen] = "\n";
		$realmlen++;
		$realmlines[$realmlen] = "realm\t\"$name\"\n";
		$realmindex{$name} = $realmlen;
		$realmlen++;
	}

	#
	# Set the new value for the name/field in %realms.
	#
	$realms{$name}{$field} = $val;

	#
	# Get the index of the realm in @realmlines.
	#
	$rlmind = rlmindex($name);

	#
	# Find the specified field's entry in the realm's lines in
	# @realmlines.  We'll skip over lines that don't have a keyword
	# and dquotes-enclosed value.  If we hit the next realm then we'll
	# stop looking and add a new entry at the end of the realm's fields.
	#
	for($fldind=$rlmind+1;$fldind<$realmlen;$fldind++)
	{
		my $line = $realmlines[$fldind];	# Line in realm file.
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
		# If we hit the beginning of the next realm without
		# finding the field, drop out and insert it.
		#
		last if(lc($lkw) eq "realm");

		#
		# Save the index of the last field we've looked at that
		# belongs to the realm.
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
		$realmlines[$fldind] =~ s/"([a-zA-Z0-9\/\-+_.,: \t]*)"/"$val"/;
	}
	else
	{
		my $newline = "\t$field\t\t\"$val\"\n";

		#
		# If the keyword is longer than 7 characters, we'll lop out one
		# of the tabs between the keyword and the value.  This is to do
		# some rough, simple formatting to keep the realm file some-
		# what orderly.  This assumes eight-character tabstops.
		#
		if(length($field) > 7)
		{
			$newline =~ s/\t\t/\t/;
		}

		#
		# If the starting realm line is the last line in the file,
		# we'll just push the new line at the end.  If it's somewhere
		# in the middle, we'll do the magic to insert it at the start
		# of the realm.
		#
		my @endarr = splice(@realmlines,$rlmind+1);
		push(@realmlines,$newline);
		push(@realmlines,@endarr);

		#
		# Bump the array length counter.
		#
		$realmlen++;

		#
		# Rebuild our table of realm indices.
		#
		buildrealmindex();
	}

	#
	# Tell the world (or at least the module) that the file has
	# been modified.
	#
	$modified = 1;
	return(0);
}

#--------------------------------------------------------------------------
# Routine:	realm_delfield()
#
# Purpose:	Delete a name/subfield pair.  The value is deleted from
#		both %realms and @realmlines.  The $modified file-
#		modified flag is updated, along with the length $realmlen.
#
sub realm_delfield
{
	my $name   = shift;		# Name of realm we're modifying.
	my $field  = shift;		# Realm's subfield to be deleted.

	my $found = 0;			# Realm-found flag.
	my $fldind;			# Loop index.
	my $rlmind;			# Loop index for finding realm.
	my $lastfld = 0;		# Last found field in @realmlines.

# print "realm_delfield:  down in\n";

	#
	# Return if a realm of the specified name doesn't exist.
	#
	return(0) if(!exists($realms{$name}));

	#
	# Return if a realm of the specified name doesn't have the
	# specified field.
	#
	return(0) if(!exists($realms{$name}{$field}));

	#
	# Delete the field from %realms.
	#
	delete($realms{$name}{$field});

	#
	# Get the index for the realm.
	#
	$rlmind = rlmindex($name);

	#
	# Find the specified field's entry in the realm's lines in
	# @realmlines.  We'll skip over lines that don't have a keyword
	# and dquotes-enclosed value.
	#
	for($fldind=$rlmind+1;$fldind<$realmlen;$fldind++)
	{
		my $line = $realmlines[$fldind];	# Line in realm file.
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
		# If we hit the beginning of the next realm without
		# finding the field, drop out.
		#
		last if(lc($lkw) eq "realm");

		#
		# Save the index of the last field we've looked at that
		# belongs to the realm.
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
	# realm index table.
	#
	if($found)
	{
		splice @realmlines, $fldind, 1;
		buildrealmindex();
	}

	#
	# Tell the world (or at least the module) that the file has
	# been modified.
	#
	$modified = 1;
	return(1);
}

#--------------------------------------------------------------------------
# Routine:	realm_add()
#
# Purpose:	Adds a new realm and fields to %realms and $realmlines.
#
sub realm_add
{
	my $rlmtype = shift;		# Realm type.
	my $rlmname = shift;		# Name of realm we're creating.
	my $flds   = shift;		# Reference to realm fields.

	my $chronosecs;			# Current time in seconds.
	my $chronostr;			# Current time string.


	my %fields;			# Realm fields.

# print "realm_add:  down in\n";

	#
	# Get the timestamp.
	#
	$chronosecs = time();
	$chronostr  = gmtime($chronosecs);

	#
	# Create the basic realm info.
	#
	realm_newrec($rlmtype,$rlmname,$realmlen + 1);

	#
	# Add the new realm's first line to the end of the realm table.
	# and add an entry to the realm index.
	#
	$realmlines[$realmlen] = "\n";
	$realmlen++;
	$realmlines[$realmlen] = "realm\t\"$rlmname\"\n";
	$realmindex{$rlmname} = $realmlen;
	$realmlen++;

	#
	# Fill the new realm with the caller's hash fields and add it to
	# the end of the realm table.
	#
	if(defined($flds))
	{
		%fields = %$flds;
		foreach my $fn (@REALMFIELDS)
		{
			my $spacing = "\t\t";	# Spacing string.

			#
			# If this field isn't defined for the realm,
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
			# Add the field to the hash table and to the realm
			# file contents array.
			#
			$realms{$rlmname}{$fn} = $fields{$fn};
			$realmlines[$realmlen] = "\t$fn$spacing\"$fields{$fn}\"\n";
			$realmlen++;
		}
	}

	#
	# Put a blank line after the final line of the realm.
	#
	$realmlines[$realmlen] = "\n";
	$realmlen++;

	#
	# Mark the realm file as having been modified.
	#
	$modified = 1;
	return(0);
}

#--------------------------------------------------------------------------
# Routine:	realm_del()
#
# Purpose:	Deletes a realm and fields from %realms and $realmlines.
#
sub realm_del
{
	my $rlmname = shift;		# Name of realm we're deleting.

	my %realm;			# Realm to be deleted.
	my $rrr;			# Realm reference.

	my $ind;			# Index into realmlines.
	my $rlmind;			# Index to realm's first line.
	my $line;			# Realm line from @realmlines.
	my $lkey;			# Realm line's key.
	my $lval;			# Realm line's value.
	my $len;			# Length of array slice to delete.

# print "realm_del:  down in\n";

	#
	# Don't allow empty realm names or non-existent realms.
	#
	return(-1) if($rlmname eq "");
	return(-1) if(!defined($realmindex{$rlmname}));

	#
	# Get a copy of the realm from the realm hash and then delete
	# the original.
	#
	$rrr = $realms{$rlmname};
	%realm = %$rrr;
	delete $realms{$rlmname};

	#
	# Get the index for this realm.
	#
	$rlmind = rlmindex($rlmname);

	#
	# Find the beginning of the next realm.
	#
	for($ind = $rlmind+1; $ind < $realmlen; $ind++)
	{
		$line = $realmlines[$ind];

		$line =~ /^\s*(realm)\s+"([a-zA-Z0-9\/\-+_.,: \t]+)"/i;
		$lkey = $1;
		$lval = $2;

		last if($lkey eq "realm");
	}

	$ind--;

	#
	# Find the end of the previous realm (the one to be deleted.)
	#
	while($ind > $rlmind)
	{
		last if($realmlines[$ind] ne "\n");
		$ind--;
	}

	#
	# Delete the realm from @realmlines.
	#
	$len = $ind - $rlmind + 1;
	splice(@realmlines,$rlmind,$len);
	$realmlen -= $len;

	#
	# Fold two consecutive blank lines into one.
	#
	if(($realmlines[$rlmind-1] eq "\n") && ($realmlines[$rlmind] eq "\n"))
	{
		splice(@realmlines,$rlmind,1);
	}

	#
	# Rebuild our table of realm indices.
	#
	buildrealmindex();

	#
	# Mark that the file has been modified.
	#
	$modified = 1;
	return(0);
}

#--------------------------------------------------------------------------
# Routine:	realm_rename()
#
# Purpose:	Renames a realm.
#
sub realm_rename
{
	my $oldname = shift;		# Name of realm we're renaming.
	my $newname = shift;		# New name of realm.

	my %realm;			# Realm to be deleted.
	my $rrr;			# Realm reference.

	my $ind;			# Index into realmlines.
	my $rlmind;			# Index to realm's first line.
	my $line;			# Realm line from @realmlines.
	my $lkey;			# Realm line's key.
	my $lval;			# Realm line's value.
	my $len;			# Length of array slice to delete.

# print "realm_rename:  down in\n";

	#
	# Don't allow empty realm names.
	#
	return(-1) if($oldname eq '');
	return(-2) if($newname eq '');

	#
	# The old realm must exist.
	#
	return(-3) if(! exists($realms{$oldname}));

	#
	# Don't allow renames to existing realm names.
	#
	return(-4) if(exists($realms{$newname}));

	#
	# Get a copy of the old realm.
	#
	$realms{$newname} = $realms{$oldname};

	#
	# Change the name field in the new realm.
	#
	$realms{$newname}{'realm_name'} = $newname;
	$rrr = $realms{$newname};
	%realm = %$rrr;

	#
	# If we didn't find a realm with this name, return failure.
	#
	return(-5) if(!defined($realmindex{name}));

	#
	# Get the index of this realm.
	#
	$rlmind = rlmindex($oldname);

	#
	# Find the beginning of the next realm.
	#
	$realmlen = @realmlines;
	for($ind = $rlmind+1;$ind < $realmlen; $ind++)
	{
		$line = $realmlines[$ind];

		$line =~ /^\s*([a-zA-Z_]+)\s+"([a-zA-Z0-9\/\-+_.,: \@\t]*)"/;
		$lkey = $1;
		$lval = $2;

		last if($lkey eq "realm");
	}
	$ind--;

	#
	# Find the end of the previous realm (the one to be deleted.)
	#
	while($ind > $rlmind)
	{
		last if($realmlines[$ind] ne "\n");
		$ind--;
	}

	#
	# Find the realm's realm line and change the name.
	#
	for(my $i=$rlmind; $i <= $ind; $i++)
	{
		my $chunk;			# Key and spacing from line.

		$realmlines[$i] =~ /^(\s*([a-zA-Z_]+)\s+)"([a-zA-Z0-9\/\-+_.,: \@\t]*)"/;
		$chunk = $1;
		$lkey = $2;

		if($lkey eq 'realm')
		{
			$realmlines[$i] = "$chunk\"$newname\"\n";
			last;
		}
	}

	#
	# Delete the old realm and the old name's entry in the index hash.
	#
	delete $realms{$oldname};
	$realmindex{$newname} = $realmindex{$oldname};
	delete $realmindex{$oldname};

	#
	# Mark that the file has been modified.
	#
	$modified = 1;
	return(0);
}

#--------------------------------------------------------------------------
# Routine:	realm_newrec()
#
# Purpose:	Creates a realm in %realms.  The name and type fields
#		are set.
#
#		This routine is NOT rebuilding the index.  Doing this here
#		has the potential for slowing down file reads and such.
#		The index is dealt with in those module routines which call
#		realm_newrec(); since it isn't exported, there should be
#		no outside callers to worry about.
#
sub realm_newrec
{
	my $type = shift;		# Type of realm we're creating.
	my $name = shift;		# Name of realm we're creating.
	my $line = shift;		# Line number of this realm.

# print "realm_newrec:  down in\n";

	return if($type ne "realm");

	$realms{$name}{"realm_name"} = $name;
	$realms{$name}{"realm_type"} = $type;

	$realmindex{$name} = $line;
}

#--------------------------------------------------------------------------
# Routine:	realm_fields()
#
# Purpose:	Return the list of realm fields.
#
sub realm_fields
{
# print "realm_fields:  down in\n";

	return(@REALMFIELDS);
}

#--------------------------------------------------------------------------
# Routine:	realm_default()
#
# Purpose:	Return the default realm file.
#
sub realm_default
{
	my $confdir;				# Configuration directory.
	my $defrr;				# Default realm name.

# print "realm_default:  down in\n";

	#
	# Get the DNSSEC-Tools config directory.
	#
	$confdir = getconfdir() || $DEFAULT_DNSSECTOOLS_DIR;

	#
	# Build our lock file.
	#
	$defrr = "$confdir/$DEFAULT_REALMFILE";

	return($defrr);
}


#--------------------------------------------------------------------------
# Routine:	realm_init()
#
# Purpose:	Initialize the internal data.
#
sub realm_init
{
# print "realm_init:  down in\n";

	%realms     = ();
	%realmindex = ();
	@realmlines = ();
	$realmlen   = 0;
	$modified     = 0;
}

#--------------------------------------------------------------------------
# Routine:	realm_discard()
#
# Purpose:	Discard the current realm file -- don't save the contents,
#		don't delete the file, reset all internal fields.
#
sub realm_discard
{
# print "realm_discard:  down in\n";

	close(REALM);
	realm_init();
}

#--------------------------------------------------------------------------
# Routine:	realm_close()
#
# Purpose:	Save the realm file and close the descriptor.
#
sub realm_close
{
# print "realm_close:  down in\n";

	realm_write();
	close(REALM);
}

#--------------------------------------------------------------------------
# Routine:	realm_write()
#
# Purpose:	Save the realm file and leave the file handle open.
#		We'll get an exclusive lock on the realm file in order
#		to (try to) ensure we're the only ones writing the file.
#
#		We'll make a (hopefully atomic) copy of the in-core realm
#		lines prior to trying to write.  This is an attempt to
#		keep the data from being mucked with while we're using it.
#
sub realm_write
{
	my $writecmds = shift;	# Boolean for saving unexecuted commands.
	my $rfc = "";		# Concatenated realm file contents.
	my $ofh;		# Old file handle.

	my @rrlines = @realmlines;	# Copy of The Realm.
	my $rrlen;			# Number of lines in The Realm.

# print STDERR "realm_write:  down in\n";

	#
	# If the file hasn't changed, we'll skip writing.
	#
	return if(!$modified);

	#
	# Make sure we've got the correct count of realm lines.
	#
	$rrlen = @rrlines;

	#
	# Loop through the array of realm lines and concatenate them all.
	#
	for(my $ind = 0; $ind < $rrlen; $ind++)
	{
		$rfc .= $rrlines[$ind];
	}

	#
	# Lock the realm file.
	#
	flock(REALM,LOCK_EX);

	#
	# Force immediate writes of REALM.
	#
	$ofh = select REALM;
	$| = 1;

	#
	# Zap the realm file and write out the new one.
	#
	seek(REALM,0,0);
	truncate(REALM,0);
	print REALM $rfc;

	#
	# Reset REALM buffering to original state.
	#
	select $ofh;

	#
	# Unlock the realm file.
	#
	return(flock(REALM,LOCK_UN));
}

#--------------------------------------------------------------------------
# Routine:	buildrealmindex()
#
# Purpose:	This routine builds a name->index hash table for the defined
#		realms.  The name is the name of a realm.  The index is
#		that realm's index in the @realmlines array.
#
sub buildrealmindex
{

	#
	# Zap the current realm index.
	#
	%realmindex = ();

	#
	# Traipse through @realmlines, and save the line index for the
	# start of each realm.
	#
	for(my $rlmind=0;$rlmind<$realmlen;$rlmind++)
	{
		my $line = $realmlines[$rlmind];	# Line in realm file.
		my $rlmname;				# Realm name.

		#
		# Dig out the line's keyword and value.
		#
		$line =~ /^\s*realm\s+"([a-zA-Z0-9\/\-+_.,: \t]+)"/i;
		$rlmname = $1;

		#
		# If this is a realm line, save the line index for
		# this realm entry.
		#
		if($rlmname ne '')
		{
			$realmindex{$rlmname} = $rlmind;
		}
	}
}

#--------------------------------------------------------------------------
# Routine:	rlmindex()
#
# Purpose:	Get the index for the named realm entry.  We'll first
#		consult the name's existing index to @realmlines.  If the
#		name matches, all's well.  If it doesn't, then we'll rebuild
#		the index hash and then get the table index.
#
#		Callers MUST have already checked that the realm name
#		exists.  Arguably, this should be done here, but it isn't.
#
sub rlmindex
{
	my $name = shift;			# Realm to look up.
	my $rlmind;				# Realm's index.
	my $line;				# Supposed start of realm.
	my $lname;				# Name from line.

	#
	# Find the index for this realm in @realmlines.
	#
	$rlmind = $realmindex{$name};

	#
	# Get the line we're expecting this realm to start with.
	#
	$line = $realmlines[$rlmind];

	#
	# Dig out the realm name from this line.
	#
	$line =~ /^\s*(realm)\s+"([a-zA-Z0-9\/\-+_.,: \t]+)"/i;
	$lname = $2;

	#
	# If this name doesn't match the requested name, we'll rebuild
	# the index and call ourself to find the index.
	#
	# This should never fail, as long as the caller already ensured
	# the realm name is valid.
	#
	if($lname ne $name)
	{
		buildrealmindex();
		$rlmind = rlmindex($name);
	}

	#
	# Give the realm's index back to our caller.
	#
	return($rlmind);
}

#--------------------------------------------------------------------------
# Routine:	realm_dump_hash()
#
# Purpose:	Dump the parsed realm entries.
#
sub realm_dump_hash
{
# print "realm_dump_hash:  down in\n";

	#
	# Loop through the hash of realms and print the realm names,
	# subfields, and values.
	#
	foreach my $k (sort(keys(%realms)))
	{
		print "realm - $k\n";
		my $subp = $realms{$k};
		my %subrecs = %$subp;
		foreach my $sk (sort(keys(%subrecs)))
		{
			print "\t$sk\t\t$subrecs{$sk}\n";
		}
		print "\n";
	}
}

#--------------------------------------------------------------------------
# Routine:	realm_dump_array()
#
# Purpose:	Display the contents of @realmlines.
#
sub realm_dump_array
{
# print "realm_dump_array:  down in\n";

	#
	# Loop through the array of realm lines and print them all.
	#
	for(my $ind=0;$ind<$realmlen;$ind++)
	{
		print $realmlines[$ind];
	}
}

1;

#############################################################################

=pod

=head1 NAME

Net::DNS::SEC::Tools::realm - Manipulate a DNSSEC-Tools realm file.

=head1 SYNOPSIS

  use Net::DNS::SEC::Tools::realm;

  realm_lock();
  realm_read("localhost.realm");

  @rlmnames = realm_names();

  $flag = realm_exists("example");

  $rrec = realm_fullrec("example");
  %rrhash = %$rrec;
  $zname = $rrhash{"maxttl"};

  $val = realm_recval("example","state");

  realm_add("realm","example",\%realmfields);

  realm_del("example");

  realm_rename("example","test-realm");

  realm_setval("example","rollrec","example.rrf");

  realm_delfield("example","user");

  @realmfields = realm_fields();

  $count = realmrec_merge("primary.realm", "new0.realm", "new1.realm");
  @retvals = realmrec_split("new-realm.rrf", @list_of_realms);


  $default_file = realm_default();

  realm_write();
  realm_close();
  realm_discard();

  realm_unlock();

=head1 DESCRIPTION

The B<Net::DNS::SEC::Tools::realm> module manipulates the contents of a
DNSSEC-Tools I<realm> file.  I<realm> files describe the status of a
zone rollover environment, as managed by the DNSSEC-Tools programs.  Module
interfaces exist for looking up I<realm> records, creating new records,
and modifying existing records.

A I<realm> file is organized in sets of I<realm> records.  I<realm>s
describe the state of a rollover environment.  A I<realm> consists of a set
of keyword/value entries.  The following is an example of a I<realm>:

	realm "production"
		state		"active"
		realmdir	"/usr/etc/dnssec-tools/realms/production"
		configdir	"/usr/etc/dnssec-tools/configs/production"
		rollrec		"production.rollrec"
		administrator	"sysfolks@example.com"
		display		"1"
		args		"-loglevel phase -logfile log.prod -display"
		user		"prodmgr"

The first step in using this module must be to read the I<realm> file.  The
I<realm_read()> interface reads the file and parses it into an internal
format.  The file's records are copied into a hash table (for easy reference
by the B<realm.pm> routines) and in an array (for preserving formatting and
comments.)

After the file has been read, the contents are referenced using
I<realm_fullrec()> and I<realm_recval()>.  The I<realm_add()> and
I<realm_setval()> interfaces are used to modify the contents of a I<realm>
record.

If the I<realm> file has been modified, it must be explicitly written or the
changes will not saved.  I<realm_write()> saves the new contents to disk.
I<realm_close()> saves the file and close the Perl file handle to the I<realm>
file.  If a I<realm> file is no longer wanted to be open, yet the contents
should not be saved, I<realm_discard()> gets rid of the data closes and the
file handle B<without> saving any modified data.

On reading a I<realm> file, consecutive blank lines are collapsed into a
single blank line.  As I<realm> entries are added and deleted, files merged
and files split, it is possible for blocks of consecutive blanks lines to
grow.  This will prevent these blocks from growing excessively.

=head1 REALM LOCKING

This module includes interfaces for synchronizing access to the I<realm>
files.  This synchronization is very simple and relies upon locking and
unlocking a single lock file for all I<realm> files.

I<realm> locking is not required before using this module, but it is
recommended.  The expected use of these facilities follows:

    realm_lock() || die "unable to lock realm file\n";
    realm_read();
    ... perform other realm operations ...
    realm_close();
    realm_unlock();

Synchronization is performed in this manner due to the way the module's
functionality is implemented, as well as providing flexibility to users
of the module.  It also provides a clear delineation in callers' code as
to where and when I<realm> locking is performed.

This synchronization method has the disadvantage of having a single lockfile
as a bottleneck to all I<realm> file access.  However, it reduces complexity
in the locking interfaces and cuts back on the potential number of required
lockfiles.

Using a single synchronization file may not be practical in large
installations.  If that is found to be the case, then this will be reworked.

=head1 REALM INTERFACES

The interfaces to the B<realm.pm> module are given below.

=over 4

=item I<realm_add(realm_type,realm_name,fields)>

This routine adds a new I<realm> to the I<realm> file and the internal
representation of the file contents.  The I<realm> is added to both the
I<%realms> hash table and the I<@realmlines> array.  Entries are only
added if they are defined for I<realm>s.

I<realm_type> is the type of the I<realm>.  This must be "realm".
I<realm_name> is the name of the I<realm>.  I<fields> is a reference to a
hash table that contains the name/value I<realm> fields.  The keys of the
hash table are always converted to lowercase, but the entry values are
left as given.

A blank line is added after the final line of the new I<realm>.  The I<realm>
file is not written after I<realm_add()>, though it is internally marked as
having been modified.

=item I<realm_del(realm_name)>

This routine deletes a I<realm> from the I<realm> file and the internal
representation of the file contents.  The I<realm> is deleted from both
the I<%realms> hash table and the I<@realmlines> array.

Only the I<realm> itself is deleted from the file.  Any associated comments
and blank lines surrounding it are left intact.  The I<realm> file is not
written after I<realm_del()>, though it is internally marked as having been
modified.

Return values are:

     0 successful realm deletion
    -1 unknown name

=item I<realm_close()>

This interface saves the internal version of the I<realm> file (opened with
I<realm_read()>) and closes the file handle. 

=item I<realm_delfield(realm_name,field)>

Deletes the given field from the specified I<realm>.  The file is
B<not> written after updating the value, but the internal file-modified flag
is set.  The value is saved in both I<%realms> and in I<@realmlines>.

Return values:

    0 - failure (realm not found or realm does not
	contain the field)
    1 - success

=item I<realm_discard()>

This routine removes a I<realm> file from use by a program.  The internally
stored data are deleted and the I<realm> file handle is closed.  However,
modified data are not saved prior to closing the file handle.  Thus, modified
and new data will be lost.

=item I<realm_exists(realm_name)>

This routine returns a boolean flag indicating if the I<realm> named in
I<realm_name> exists.

=item I<realm_fullrec(realm_name)>

I<realm_fullrec()> returns a reference to the I<realm> specified in
I<realm_name>.

=item I<realm_lock()>

I<realm_lock()> locks the I<realm> lockfile.  An exclusive lock is
requested, so the execution will suspend until the lock is available.  If the
I<realm> synchronization file does not exist, it will be created.  If the
process can't create the synchronization file, an error will be returned.

Success or failure is returned.

=item I<realm_merge(target_realm_file, realm_file1, ... realm_fileN)>

This interface merges the specified I<realm> files.  It reads each file
and parses them into a I<realm> hash table and a file-contents array.
The resulting merge is written to the file named by I<target_realm_file>.
If another I<realm> is already open, it is saved and closed prior to
opening the new I<realm>.

If I<target_realm_file> is an existing I<realm> file, its contents will
be merged with the other files passed to I<realm_merge()>.  If the file
does not exist, I<realm_merge()> will create it and merge the remaining
files into it.

Upon success, I<realm_read()> returns the number of I<realm>s read from
the file.

Failure return values:

    -1 no realm files were given to realm_merge
    -2 unable to create target realm file
    -3 unable to read first realm file
    -4 an error occurred while reading the realm names
    -5 realm files were duplicated in the list of realm files

=item I<realm_names()>

This routine returns a list of the I<realm> names from the file.

=item I<realm_read(realm_file)>

This interface reads the specified I<realm> file and parses it into a
I<realm> hash table and a file-contents array.  I<realm_read()> B<must> be
called prior to any of the other B<realm.pm> calls.  If another I<realm>
is already open, it is saved and closed prior to opening the new I<realm>.

I<realm_read()> attempts to open the I<realm> file for reading and
writing.  If this fails, then it attempts to open the file for reading only.

I<realm_read()> is a front-end for I<realm_readfile()>.  It sets up the
module's saved data in preparation for reading a new I<realm> file.  These
house-keeping actions are not performed by I<realm_readfile()>.

Upon success, I<realm_read()> returns the number of I<realm>s read from
the file.

Failure return values:

    -1 specified realm file doesn't exit
    -2 unable to open realm file
    -3 duplicate realm names in file

=item I<realm_readfile(realm_file_handle)>

This interface reads the specified file handle to a I<realm> file and
parses the file contents into a I<realm> hash table and a file-contents
array.  The hash table and file-contents array are B<not> cleared prior
to adding data to them.

Upon success, I<realm_read()> returns zero.

Failure return values:

    -1 duplicate realm names in file

=item I<realm_rectype(realm_name,rectype)>

Set the type of the specified I<realm> record.  The file is
B<not> written after updating the value, but the internal file-modified flag
is set.  The value is saved in both I<%realms> and in I<@realmlines>.

I<realm_name> is the name of the I<realm> that will be modified.
I<rectype> is the new type of the I<realm>, which must be "realm".

Return values:

    0 - failure (invalid record type or realm not found)
    1 - success

=item I<realm_recval(realm_name,realm_field)>

This routine returns the value of a specified field in a given I<realm>.
I<realm_name> is the name of the particular I<realm> to consult.
I<realm_field> is the field name within that I<realm>.

For example, the current I<realm> file contains the following I<realm>.

    realm	"example"
                rollrec        "example.rrf"

The call:

    realm_recval("example","rollrec")

will return the value "example.rrf".

=item I<realm_rename(old_realm_name,new_realm_name)>

This routine renames the I<realm> named by I<old_realm_name> to
I<new_realm_name>.  The actual effect is to change the name in the I<realm>
line to I<new_realm_name>.  The name is changed in the internal version of the
the I<realm> file only.  The file itself is not changed, but must be saved by
calling either I<realm_write()>, I<realm_save()>, or I<realm_saveas()>.

I<old_realm_name> must be the name of an existing I<realm>.  Conversely,
I<new_realm_name> must not name an existing I<realm>.

Return values:

     0 - success
    -1 - old_realm_name was null or empty
    -2 - new_realm_name was null or empty
    -3 - old_realm_name is not an existing realm
    -4 - new_realm_name is already a realm
    -5 - internal error that should never happen

=item I<realm_setval(realm_name,field,value)>

Set the value of a name/field pair in a specified I<realm>.  The file is
B<not> written after updating the value, but the internal file-modified flag
is set.  The value is saved in both I<%realms> and in I<@realmlines>.

I<realm_name> is the name of the I<realm> that will be modified.  If the
named I<realm> does not exist, it will be created as a "realm"-type
I<realm>.
I<field> is the I<realm> field which will be modified.
I<value> is the new value for the field.

=item I<realm_split(new_realm_file,realm_names)>

Move a set of I<realm> entries from the current I<realm> file to a new
file.  The moved I<realm> entries are removed both from the current file
and from the internal module data representing that file.

The I<new_realm_file> parameter holds the name of the new I<realm> file.
If this file doesn't exist, it will be created.  If it does exist, the
I<realm> entries will be appended to that file.

I<realm_names> is a list of I<realm> entries that will be moved from the
current file to the file named in I<new_realm_file>.  If some of the given
I<realm> names are invalid, the valid names will be moved to the new file
and the invalid names will be returned in a list to the caller.

Only the I<realm> entries themselves will be moved to the new I<realm>
file.  Any associated comments will be left in the current I<realm> file.

On success, the count of moved I<realm> entries is returned.  Error returns
are given below.

Failure return values:
    -1 - no target realm file given in new_realm_file
    -2 - no realm names given in realm_names
    -3 - none of the realm names given are existing realms
    -4 - unable to open new_realm_file
    -5 - invalid realm names were specified in realm_names,
         followed by the list of bad names.

=item I<realm_unlock()>

I<realm_unlock()> unlocks the I<realm> synchronization file.

=item I<realm_write()>

This interface saves the internal version of the I<realm> file (opened with
I<realm_read()>).  It does not close the file handle.  As an efficiency
measure, an internal modification flag is checked prior to writing the file.
If the program has not modified the contents of the I<realm> file, it is not
rewritten.

I<realm_write()> gets an exclusive lock on the I<realm> file while writing.

=back

=head1 REALM INTERNAL INTERFACES

The interfaces described in this section are intended for internal use by the
B<realm.pm> module.  However, there are situations where external entities
may have need of them.  Use with caution, as misuse may result in damaged or
lost I<realm> files.

=over 4

=item I<realm_init()>

This routine initializes the internal I<realm> data.  Pending changes will
be lost.  A new I<realm> file must be read in order to use the B<realm.pm>
interfaces again.

=item I<realm_default()>

This routine returns the name of the default I<realm> file.

=back

=head1 REALM DEBUGGING INTERFACES

The following interfaces display information about the currently parsed
I<realm> file.  They are intended to be used for debugging and testing, but
may be useful at other times.

=over 4

=item I<realm_dump_hash()>

This routine prints the I<realm> file as it is stored internally in a hash
table.  The I<realm>s are printed in alphabetical order, with the fields
alphabetized for each I<realm>.  New I<realm>s and I<realm> fields are
alphabetized along with current I<realm>s and fields.  Comments from the
I<realm> file are not included with the hash table.

=item I<realm_dump_array()>

This routine prints the I<realm> file as it is stored internally in an
array.  The I<realm>s are printed in the order given in the file, with the
fields ordered in the same manner.  New I<realm>s are appended to the end
of the array.  I<realm> fields added to existing I<realm>s are added at
the beginning of the I<realm> entry.  Comments and vertical whitespace are
preserved as given in the I<realm> file.

=back

=head1 COPYRIGHT

Copyright 2012-2014 SPARTA, Inc.  All rights reserved.
See the COPYING file included with the DNSSEC-Tools package for details.

=head1 AUTHOR

Wayne Morrison, tewok@tislabs.com

=head1 SEE ALSO

B<lsrealm(1)>,
B<realmchk(8)>,
B<realminit(8)>

B<Net::DNS::SEC::Tools::realm(3)>,

=cut
