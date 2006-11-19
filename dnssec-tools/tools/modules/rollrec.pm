#!/usr/bin/perl
#
# Copyright 2006 SPARTA, Inc.  All rights reserved.  See the COPYING
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
#	The format and contents of a rollrec file are *very* preliminary.
#	These entries are grouped by the zone whose key(s) are being rolled
#	over.
#
#	An example rollrec file follows:
#
#	    roll "example.com"
#		zonefile	"/usr/etc/dnssec/zones/db.example.com"
#		keyrec		"/usr/etc/dnssec/keyrec/example.keyrec"
#		curphase	"2"
#		maxttl		"86400"
#		display		"0"
#		phasestart	"Wed Mar 09 21:49:22 2005"
#
#	    roll "triharpskel.com"
#		zonefile	"/usr/etc/dnssec/zone/db.triharpskel.com"
#		keyrec		"/usr/etc/dnssec/keyrec/triharpskel.keyrec"
#		curphase	"1"
#		maxttl		"100000"
#		display		"1"
#		phasestart	"Sun Jan 01 16:00:00 2005"
#
#
#
#	The current implementation assumes that only one rollrec file will
#	be open at a time.  If module use proves this to be a naive assumption
#	this module will have to be rewritten to account for it.
#

package Net::DNS::SEC::Tools::rollrec;

require Exporter;
use strict;

use Fcntl qw(:DEFAULT :flock);

use Net::DNS::SEC::Tools::conf;

our $VERSION = "0.01";

our @ISA = qw(Exporter);

our @EXPORT = qw(
			rollrec_add
			rollrec_close
			rollrec_default
			rollrec_del
			rollrec_discard
			rollrec_dump_array
			rollrec_dump_hash
			rollrec_fields
			rollrec_fullrec
			rollrec_init
			rollrec_lock
			rollrec_names
			rollrec_newrec
			rollrec_read
			rollrec_rectype
			rollrec_recval
			rollrec_settime
			rollrec_setval
			rollrec_unlock
			rollrec_write
		);

#--------------------------------------------------------------------------

#
# Default file names.
#
my $DEFAULT_DNSSECTOOLS_DIR = "/usr/local/etc/dnssec";
my $DEFAULT_ROLLREC = "dnssec-tools.rollrec";
my $LOCKNAME = "rollrec.lock";

#
# Valid fields in a rollrec.
#
my @ROLLFIELDS = (
			'zonefile',
			'keyrec',
			'curphase',
			'maxttl',
			'phasestart',
			'display',
			'rollrec_signdate',
			'rollrec_signsecs',
		  );

#--------------------------------------------------------------------------

my @rollreclines;			# Rollrec lines.
my $rollreclen;				# Number of rollrec lines.

my %rollrecs;				# Rollrec hash table (keywords/values.)

my $modified;				# File-modified flag.

#--------------------------------------------------------------------------
#
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
	my $confdir;			# Configuration file directory.
	my $lockfile;			# Name of the lock file.

# print "rollrec_lock:  down in\n";

	#
	# Get the DNSSEC-Tools config directory.
	#
	$confdir = getconffile() || $DEFAULT_DNSSECTOOLS_DIR;
	$confdir =~ /^(.*)\/.*$/;
	$confdir = $1;

	#
	# Build our lock file.
	#
	$lockfile = "$confdir/$LOCKNAME";

	#
	# Open (and create?) our lock file.
	#
	if(!sysopen(RRLOCK,$lockfile,O_RDONLY|O_CREAT))
	{
#		print STDERR "unable to open lock file \"$lockfile\"; not locking...\n";
		return(0);
	}

	#
	# Lock the lock file.
	#
	return(flock(RRLOCK,LOCK_EX));
}

#--------------------------------------------------------------------------
#
# Routine:	rollrec_unlock()
#
# Purpose:	Unlock rollrec processing so that other processes may read
#		a rollrec file.
#
sub rollrec_unlock
{
# print "rollrec_unlock:  down in\n";

	#
	# Lock the lock file.
	#
	return(flock(RRLOCK,LOCK_UN));
}

#--------------------------------------------------------------------------
#
# Routine:	rollrec_read()
#
# Purpose:	Read a DNSSEC-Tools rollrec file.  The contents are read into the
#		@rollreclines array and the rollrecs are broken out into the
#		%rollrecs hash table.
#
sub rollrec_read
{
	my $rrf = shift;		# Rollover record file.
	my $name;			# Name of the rollrec.
	my $rrcnt;			# Number of rollrecs we found.
	my @sbuf;			# Buffer for stat().

# print "rollrec_read:  down in\n";

	#
	# Use the default rollrec file, unless the caller specified
	# a different file.
	#
	$rrf = rollrec_default() if($rrf eq "");

	#
	# Make sure the rollrec file exists.
	#
	if(! -e $rrf)
	{
		print STDERR "$rrf does not exist\n";
		return(-1);
	}

	#
	# If a rollrec file is already open, we'll flush our buffers and
	# save the file.
	#
	@sbuf = stat(ROLLREC);
	rollrec_close() if(@sbuf != 0);

	#
	# Open up the rollrec file.
	#
	if(open(ROLLREC,"+< $rrf") == 0)
	{
		print STDERR "unable to open $rrf\n";
		return(-2);
	}

	#
	# Initialize some data.
	#
	rollrec_init();

	#
	# Grab the lines and pop 'em into the rollreclines array.  We'll also
	# save each rollrec into a hash table for easy reference.
	#
	while(<ROLLREC>)
	{
		my $line;		# Line from the rollrec file.
		my $keyword = "";	# Keyword from the line.
		my $value = "";		# Keyword's value.

		$line = $_;

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
		$line =~ /^\s*([a-zA-Z_]+)\s+"([a-zA-Z0-9\/\-+_.,: \t]+)"/;
		$keyword = $1;
		$value = $2;
#		print "rollrec_read:  keyword <$keyword>\t\t<$value>\n";

		#
		# If the keyword is "roll", then we're starting a new record.
		# We'll save the name of the rollrec, and then proceed on to
		# the next line.  
		#
		if(($keyword =~ /^roll$/i) || ($keyword =~ /^skip$/i))
		{
			$name = $value;

			#
			# If this name has already been used for a rollrec,
			# we'll whinge, clean up, and return.  No rollrecs
			# will be retained.
			#
			if(exists($rollrecs{$name}))
			{
				print STDERR "rollrec_read:  duplicate record name; aborting...\n";

				rollrec_discard();
				return(-3);
			}
			rollrec_newrec($keyword,$name);
			next;
		}

		#
		# Save this subfield into the rollrec's collection.
		#
		$rollrecs{$name}{$keyword} = $value;
	}

	#
	# Return the number of rollrecs we found.
	#
	$rrcnt = keys(%rollrecs);
	return($rrcnt);
}

#--------------------------------------------------------------------------
#
# Routine:	rollrec_names()
#
# Purpose:	Smoosh the rollrec names into an array and return the array.
#
sub rollrec_names
{
	my $rrn;				# Rollrec name index.
	my @names = ();				# Array for rollrec names.

# print "rollrec_names:  down in\n";

	foreach $rrn (sort(keys(%rollrecs)))
	{
		push @names, $rrn;
	}

	return(@names);
}

#--------------------------------------------------------------------------
#
# Routine:	rollrec_fullrec()
#
# Purpose:	Return all entries in a given rollrec.
#
sub rollrec_fullrec
{
	my $name = shift;
	my $nrec = $rollrecs{$name};

# print "rollrec_fullrec:  down in ($name)\n";

	return($nrec);
}

#--------------------------------------------------------------------------
#
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

	return($val);
}

#--------------------------------------------------------------------------
#
# Routine:	rollrec_rectype()
#
# Purpose:	Change the value of a rollrec.  The new value may only be
#		"roll" or "skip".
#
# Return Values:
#
#		1 - success
#		0 - failure (invalid record type or rollrec not found)
#
sub rollrec_rectype
{
	my $name    = shift;		# Name of rollrec we're modifying.
	my $rectype = shift;		# Rollrec's new type.

	#
	# Make sure we've got a valid record type.
	#
	return(0) if(($rectype ne "roll") && ($rectype ne "skip"));

	#
	# Find the appropriate entry to modify in @rollreclines.  If the
	# given field isn't set in $name's rollrec, we'll insert this as
	# a new field at the end of that rollrec.
	#
	for(my $rrind=0;$rrind<$rollreclen;$rrind++)
	{
		my $line = $rollreclines[$rrind];	# Line in rollrec file.
		my $rtype;				# Rollrec type.
		my $rrname;				# Rollrec name.

		#
		# Dig out the line's keyword and value.
		#
		$line =~ /^\s*(roll|skip)\s+"([a-zA-Z0-9\/\-+_.,: \t]+)"/i;
		$rtype = $1;
		$rrname = $2;

		#
		# If this line has the rollrec's name and is the start of a
		# new rollrec, then we've found our man.  We'll change the
		# record type and return success.
		#
		if(lc($rrname) eq lc($name))
		{
			$rollrecs{$name}{'rollrec_type'} = $rectype;

			$line =~ s/$rtype/$rectype/;
			$rollreclines[$rrind] = $line;
			$modified = 1;
			return(1);
		}
	}

	#
	# We didn't find the line, so we'll return failure.
	#
	return(0);
}

#--------------------------------------------------------------------------
#
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
		rollrec_newrec("roll",$name);

		#
		# Start the new rollrec in @rollreclines.
		#
		$rollreclines[$rollreclen] = "\n";
		$rollreclen++;
		$rollreclines[$rollreclen] = "roll\t\"$name\"\n";
		$rollreclen++;
	}

	#
	# Set the new value for the name/field in %rollrecs.
	#
	$rollrecs{$name}{$field} = $val;

	#
	# Find the appropriate entry to modify in @rollreclines.  If the
	# given field isn't set in $name's rollrec, we'll insert this as
	# a new field at the end of that rollrec.
	#
	for($rrind=0;$rrind<$rollreclen;$rrind++)
	{
		my $line = $rollreclines[$rrind];	# Line in rollrec file.
		my $rrname;				# Rollrec name.

		#
		# Dig out the line's keyword and value.
		#
		$line =~ /^\s*roll\s+"([a-zA-Z0-9\/\-+_.,: \t]+)"/i;
		$rrname = $1;

		#
		# If this line has the rollrec's name and is the start of a
		# new rollrec, then we've found our man.
		#
		# IMPORTANT NOTE:  We will *always* find the rollrec we're
		#		   looking for.  The exists() check above
		#		   ensures that there will be a rollrec with
		#		   the name we want.
		#
		last if(lc($rrname) eq lc($name));
	}

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
		$line =~ /^\s*([a-zA-Z_]+)\s+"([a-zA-Z0-9\/\-+_.,: \t]+)"/;
		$lkw = $1;
		$lval = $2;

		#
		# If we hit the beginning of the next rollrec without
		# finding the field, drop out and insert it.
		#
		next if($lkw eq "");

		#
		# If we hit the beginning of the next rollrec without
		# finding the field, drop out and insert it.
		#
		last if(lc($lkw) eq "roll");

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
		$rollreclines[$fldind] =~ s/"([a-zA-Z0-9\/\-+_.,: \t]+)"/"$val"/;
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
	}

	#
	# Tell the world (or at least the module) that the file has
	# been modified.
	#
	$modified = 1;
	return(0);
}

#--------------------------------------------------------------------------
#
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
	# Get the timestamp.
	#
	$chronosecs = time();
	$chronostr  = gmtime($chronosecs);

	#
	# Create the basic rollrec info.
	#
	rollrec_newrec($rrtype,$rrname);

	#
	# Add the new rollrec's first line to the end of the rollrec table.
	#
	$rollreclines[$rollreclen] = "\n";
	$rollreclen++;
	$rollreclines[$rollreclen] = "roll\t\"$rrname\"\n";
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
	# Sync the rollrec file.
	#
	$modified = 1;
	rollrec_write();
	return(0);
}

#--------------------------------------------------------------------------
#
# Routine:	rollrec_del()
#
# Purpose:	Deletes a rollrec and fields from %rollrecs and $rollreclines.
#
sub rollrec_del
{
	my $rrname = shift;		# Name of rollrec we're creating.

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
	# Don't allow empty rollrec names.
	#
	return(-1) if($rrname eq "");

	#
	# Get a copy of the rollrec from the rollrec hash and then delete
	# the original.
	#
	$rrr = $rollrecs{$rrname};
	%rollrec = %$rrr;
	delete $rollrecs{$rrname};

	#
	# Find the index of the first line for this rollrec in the
	# list of file lines.
	#
	for($ind = 0;$ind < $rollreclen; $ind++)
	{
		$line = $rollreclines[$ind];

		$line =~ /\s*(\S+)\s+(\S+)/;
		$lkey = $1;
		$lval = $2;

		$lval =~ s/"//g;

		last if($lval eq $rrname);
	}
	$rrind = $ind;

	#
	# If we didn't find a rollrec with this name, return failure.
	#
	return(-1) if($ind == $rollreclen);

	#
	# Find the beginning of the next rollrec.
	#
	for($ind = $rrind+1;$ind < $rollreclen; $ind++)
	{
		$line = $rollreclines[$ind];

		$line =~ /\s*(\S+)\s+(\S+)/;
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
	# Delete the rollrec from @rollreclines.
	#
	$len = $ind - $rrind + 1;
	splice(@rollreclines,$rrind,$len);
	$rollreclen -= $len;

	#
	# Tell the world (or at least the module) that the file has
	# been modified.
	#
	$modified = 1;
	rollrec_write();
	return(0);
}

#--------------------------------------------------------------------------
#
# Routine:	rollrec_settime()
#
# Purpose:	Sets the phase-start time in the rollrec.
#
sub rollrec_settime
{
	my $name = shift;		# Name of rollrec we're creating.
	my $chronos;			# Timestamp for the record.

# print "rollrec_settime:  down in\n";

	$chronos = gmtime();
	$chronos =~ s/\n$//;

	rollrec_setval($name,"phasestart",$chronos);
}

#--------------------------------------------------------------------------
#
# Routine:	rollrec_newrec()
#
# Purpose:	Creates a rollrec in %rollrecs.  The name field of is set.
#
sub rollrec_newrec
{
	my $type = shift;		# Type of rollrec we're creating.
	my $name = shift;		# Name of rollrec we're creating.

# print "rollrec_newrec:  down in\n";

	return if(($type ne "roll") && ($type ne "skip"));

	$rollrecs{$name}{"rollrec_name"} = $name;
	$rollrecs{$name}{"rollrec_type"} = $type;
}

#--------------------------------------------------------------------------
#
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
#
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
	$confdir = getconffile() || $DEFAULT_DNSSECTOOLS_DIR;
	$confdir =~ /^(.*)\/.*$/;
	$confdir = $1;

	#
	# Build our lock file.
	#
	$defrr = "$confdir/$DEFAULT_ROLLREC";

	return($defrr);
}


#--------------------------------------------------------------------------
#
# Routine:	rollrec_init()
#
# Purpose:	Initialize the internal data.
#
sub rollrec_init
{
# print "rollrec_init:  down in\n";

	%rollrecs     = ();
	@rollreclines = ();
	$rollreclen   = 0;
	$modified     = 0;
}

#--------------------------------------------------------------------------
#
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
#
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
#
# Routine:	rollrec_write()
#
# Purpose:	Save the roll record file and leave the file handle open.
#
sub rollrec_write
{
	my $rrc = "";		# Concatenated rollrec file contents.
	my $ofh;		# Old file handle.

# print "rollrec_write:  down in\n";

	#
	# If the file hasn't changed, we'll skip writing.
	#
	return if(!$modified);

	#
	# Loop through the array of rollrec lines and concatenate them all.
	#
	for(my $ind=0;$ind<$rollreclen;$ind++)
	{
		$rrc .= $rollreclines[$ind];
	}

	#
	# Zap the rollrec file and write out the new one.
	#
	seek(ROLLREC,0,0);
	truncate(ROLLREC,0);
	print ROLLREC $rrc;

	#
	# Flush the ROLLREC buffer.
	#
	$ofh = select ROLLREC;
	$| = 1;
	select $ofh;
}

#--------------------------------------------------------------------------
#
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
#
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

  @rrnames = rollrec_names();

  $rrec = rollrec_fullrec("example.com");
  %rrhash = %$rrec;
  $zname = $rrhash{"maxttl"};

  $val = rollrec_recval("example.com","zonefile");

  rollrec_add("roll","example.com",\%rollfields);
  rollrec_add("skip","example.com",\%rollfields);

  rollrec_del("example.com");

  rollrec_type("example.com","skip");
  rollrec_type("example.com","roll");

  rollrec_setval("example.com","zonefile","db.example.com");

  rollrec_settime("example.com");

  @rollrecfields = rollrec_fields();

  $default_file = rollrec_default();

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

    roll "example.com"
	zonefile		"/usr/etc/dnssec/zones/db.example.com"
	keyrec			"/usr/etc/dnssec/keyrec/example.keyrec"
	curphase		"2"
	maxttl			"86400"
	phasestart		"Wed Mar 09 21:49:22 2005"
	display			"0"
	rollrec_rollsecs	"1115923362"
	rollrec_rolldate	"Tue Mar 09 19:12:54 2005"

The first step in using this module must be to read the I<rollrec> file.  The
I<rollrec_read()> interface reads the file and parses it into an internal
format.  The file's records are copied into a hash table (for easy reference
by the B<Net::DNS::SEC::Tools::rollrec> routines) and in an array (for
preserving formatting and comments.)

After the file has been read, the contents are referenced using
I<rollrec_fullrec()> and I<rollrec_recval()>.  The contents are
modified using I<rollrec_add()>, I<rollrec_setval()>, and
I<rollrec_settime()>.

If the I<rollrec> file has been modified, it must be explicitly written or
the changes will not saved.  I<rollrec_write()> saves the new contents to disk.
I<rollrec_close()> saves the file and close the Perl file handle to the
I<rollrec> file.  If a I<rollrec> file is no longer wanted to be open, yet
the contents should not be saved, I<rollrec_discard()> gets rid of the data
closes and the file handle B<without> saving any modified data.

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

The interfaces to the B<Net::DNS::SEC::Tools::rollrec> module are given below.

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

A blank line is added after the final line of the new I<rollrec>.  After adding
all new I<rollrec> entries, the I<rollrec> file is written but it is not closed.

=item I<rollrec_del(rollrec_name)>

This routine deletes a I<rollrec> from the I<rollrec> file and the internal
representation of the file contents.  The I<rollrec> is deleted from both
the I<%rollrecs> hash table and the I<@rollreclines> array.

Only the I<rollrec> itself is deleted from the file.  Any associated comments
and blank lines surrounding it are left intact.

Return values are:

    0 successful rollrec deletion

    -1 unknown name

=item I<rollrec_close()>

This interface saves the internal version of the I<rollrec> file (opened with
I<rollrec_read()>) and closes the file handle. 

=item I<rollrec_discard()>

This routine removes a I<rollrec> file from use by a program.  The internally
stored data are deleted and the I<rollrec> file handle is closed.  However,
modified data are not saved prior to closing the file handle.  Thus, modified
and new data will be lost.

=item I<rollrec_fullrec(rollrec_name)>

I<rollrec_fullrec()> returns a reference to the I<rollrec> specified in
I<rollrec_name>.

=item I<rollrec_lock()>

I<rollrec_lock()> locks the I<rollrec> lockfile.  An exclusive lock is
requested, so the execution will suspend until the lock is available.  If the
I<rollrec> synchronization file does not exist, it will be created.  If the
process can't create the synchronization file, an error will be returned.
Success or failure is returned.

=item I<rollrec_names()>

This routine returns a list of the I<rollrec> names from the file.

=item I<rollrec_read(rollrec_file)>

This interface reads the specified I<rollrec> file and parses it into a
I<rollrec> hash table and a file contents array.  I<rollrec_read()>
B<must> be called prior to any of the other
B<Net::DNS::SEC::Tools::rollrec> calls.  If another I<rollrec> is
already open, then it is saved and closed prior to opening the new
I<rollrec>.

Upon success, I<rollrec_read()> returns the number of I<rollrec>s read from the
file.

Failure return values:

    -1 specified rollrec file doesn't exit

    -2 unable to open rollrec file

    -3 duplicate rollrec names in file

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

=item I<rollrec_setval(rollrec_name,field,value)>

Set the value of a name/field pair in a specified I<rollrec>.  The file is
B<not> written after updating the value, but the internal file-modified flag
is set.  The value is saved in both I<%rollrecs> and in I<@rollreclines>.

I<rollrec_name> is the name of the I<rollrec> that will be modified.  If the
named I<rollrec> does not exist, it will be created as a "roll"-type
I<rollrec>.
I<field> is the I<rollrec> field which will be modified.
I<value> is the new value for the field.

=item I<rollrec_settime(rollrec_name)>

Set the timestamp in the I<rollrec> specified by I<rollrec_name>.
The file is B<not> written after updating the value.

=item I<rollrec_unlock()>

I<rollrec_unlock()> unlocks the I<rollrec> synchronization file.

=item I<rollrec_write()>

This interface saves the internal version of the I<rollrec> file (opened with
I<rollrec_read()>).  It does not close the file handle.  As an efficiency
measure, an internal modification flag is checked prior to writing the file.
If the program has not modified the contents of the I<rollrec> file, it is not
rewritten.

=back

=head1 ROLLREC INTERNAL INTERFACES

=over 4

The interfaces described in this section are intended for internal use by the
B<Net::DNS::SEC::Tools::rollrec> module.  However, there are situations where
external entities may have need of them.  Use with caution, as misuse may
result in damaged or lost I<rollrec> files.

=item I<rollrec_init()>

This routine initializes the internal I<rollrec> data.  Pending changes will
be lost.  An open I<rollrec> file handle will remain open, though the data are
no longer held internally.  A new I<rollrec> file must be read in order to use
the B<Net::DNS::SEC::Tools::rollrec> interfaces again.

=item I<rollrec_newrec(type,name)>

This interface creates a new I<rollrec>.  The I<rollrec_name> field in the
I<rollrec> is set to the values of the I<name> parameter.  The I<type>
parameter must be either "roll" or "skip".

=item I<rollrec_default()>

This routine returns the name of the default I<rollrec> file.

=back

=head1 ROLLREC DEBUGGING INTERFACES

=over 4

The following interfaces display information about the currently parsed
I<rollrec> file.  They are intended to be used for debugging and testing, but
may be useful at other times.

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

Copyright 2004-2006 SPARTA, Inc.  All rights reserved.
See the COPYING file included with the DNSSEC-Tools package for details.

=head1 AUTHOR

Wayne Morrison, tewok@users.sourceforge.net

=head1 SEE ALSO

B<lsroll(1)>,
B<rollchk(8)>,
B<rollinit(8)>

B<Net::DNS::SEC::Tools::keyrec(3)>,
B<Net::DNS::SEC::Tools::keyrec(5)>

=cut
