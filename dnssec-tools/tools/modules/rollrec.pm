#!/usr/bin/perl
#
# Copyright 2005 SPARTA, Inc.  All rights reserved.  See the COPYING
# file distributed with this software for details.
#
# DNSSEC Tools
#
#	Rollrec file routines.
#
#	The routines in this module manipulate a rollrec file for the DNSSEC
#	tools.  The rollrec file contains information about key roll-over
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
#		phasestart	"Wed Mar 09 21:49:22 2005"
#
#	    roll "triharpskel.com"
#		zonefile	"/usr/etc/dnssec/zone/db.triharpskel.com"
#		keyrec		"/usr/etc/dnssec/keyrec/triharpskel.keyrec"
#		curphase	"1"
#		maxttl		"100000"
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

our $VERSION = "0.01";

our @ISA = qw(Exporter);

our @EXPORT = qw(rollrec_read rollrec_names rollrec_fullrec rollrec_recval
		 rollrec_setval rollrec_add rollrec_del rollrec_newrec
		 rollrec_fields rollrec_init rollrec_default
		 rollrec_discard rollrec_close rollrec_write
		 rollrec_dump_hash rollrec_dump_array);

my $DEFAULT_ROLLREC = "/usr/local/etc/dnssec/dnssec-tools.rollrec";

#
# Valid fields in a rollrec.
#
my @ROLLFIELDS = (
			'zonefile',
			'keyrec',
			'curphase',
			'maxttl',
			'phasestart',
			'rollrec_signdate',
			'rollrec_signsecs',
		  );

my @rollreclines;			# Rollrec lines.
my $rollreclen;				# Number of rollrec lines.

my %rollrecs;				# Rollrec hash table (keywords/values.)

my $modified;				# File-modified flag.


#--------------------------------------------------------------------------
#
# Routine:	rollrec_read()
#
# Purpose:	Read a DNSSEC rollrec file.  The contents are read into the
#		@rollreclines array and the rollrecs are broken out into the
#		%rollrecs hash table.
#
sub rollrec_read
{
	my $rrf = shift;		# Roll-over record file.
	my $name;			# Name of the rollrec.
	my $rrcnt;			# Number of rollrecs we found.
	my @sbuf;			# Buffer for stat().

	#
	# Use the default rollrec file, unless the caller specified
	# a different file.
	#
	if($rrf eq "")
	{
		$rrf = $DEFAULT_ROLLREC;
	}

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
	if(@sbuf != 0)
	{
		rollrec_close();
	}

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
		if($keyword =~ /^roll$/i)
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
			rollrec_newrec($name);
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

	return($val);
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

	#
	# If a rollrec of the specified name doesn't exist, we'll create a
	# new one.  We'll add it to @rollreclines and %rollrecs.
	#
	if(!exists($rollrecs{$name}))
	{
		#
		# Add the rollrec to the %rollrecs hash.
		#
		rollrec_newrec($name);

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
		if(lc($rrname) eq lc($name))
		{
			last;
		}
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
		if($lkw eq "")
		{
			next;
		}

		#
		# If we hit the beginning of the next rollrec without
		# finding the field, drop out and insert it.
		#
		if(lc($lkw) eq "roll")
		{
			last;
		}

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
	my $rrname = shift;		# Name of rollrec we're creating.
	my $flds   = shift;		# Reference to rollrec fields.

	my $chronosecs;			# Current time in seconds.
	my $chronostr;			# Current time string.

	my %fields;			# Rollrec fields.

	#
	# Get the timestamp.
	#
	$chronosecs = time();
	$chronostr  = gmtime($chronosecs);

	#
	# Create the basic rollrec info.
	#
	rollrec_newrec($rrname);

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
# Routine:	rollrec_newrec()
#
# Purpose:	Creates a rollrec in %rollrecs.  The name field of is set.
#
sub rollrec_newrec
{
	my $name = shift;		# Name of rollrec we're creating.

	$rollrecs{$name}{"rollrec_name"} = $name;
}

#--------------------------------------------------------------------------
#
# Routine:	rollrec_fields()
#
# Purpose:	Return the list of rollrec fields.
#
sub rollrec_fields
{
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
	return($DEFAULT_ROLLREC);
}


#--------------------------------------------------------------------------
#
# Routine:	rollrec_init()
#
# Purpose:	Initialize the internal data.
#
sub rollrec_init
{
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

	#
	# If the file hasn't changed, we'll skip writing.
	#
	if(!$modified)
	{
		return;
	}

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
}

#--------------------------------------------------------------------------
#
# Routine:	rollrec_dump_hash()
#
# Purpose:	Dump the parsed rollrec entries.
#
sub rollrec_dump_hash
{
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

Net::DNS::SEC::Tools::rollrec - Manipulate a dnssec-tools rollrec file.

=head1 SYNOPSIS

  use Net::DNS::SEC::Tools::rollrec;

  rollrec_read("localhost.rollrec");

  @rrnames = rollrec_names();

  $rrec = rollrec_fullrec("example.com");
  %rrhash = %$rrec;
  $zname = $rrhash{"maxttl"};

  $val = rollrec_recval("example.com","zonefile");

  rollrec_add("example.com",\%rollfields);

  rollrec_del("example.com");

  rollrec_setval("example.com","zonefile","db.example.com");

  @rollrecfields = rollrec_fields();

  $default_file = rollrec_default();

  rollrec_write();
  rollrec_close();
  rollrec_discard();

=head1 DESCRIPTION

The I<Net::DNS::SEC::Tools::rollrec> module manipulates the contents of a
dnssec-tools I<rollrec> file.  I<rollrec> files describe the status of a
zone roll-over process, as performed by the dnssec-tools programs.  Module
interfaces exist for looking up I<rollrec> records, creating new records,
and modifying existing records.

A I<rollrec> file is organized in sets of I<rollrec> records.  I<rollrec>s
describe the state of a roll-over operation.  A I<rollrec> consists of a set
of keyword/value entries.  The following is an example of a I<rollrec>:

    roll "example.com"
	zonefile		"/usr/etc/dnssec/zones/db.example.com"
	keyrec			"/usr/etc/dnssec/keyrec/example.keyrec"
	curphase		"2"
	maxttl			"86400"
	phasestart		"Wed Mar 09 21:49:22 2005"
	rollrec_rollsecs	"1115923362"
	rollrec_rolldate	"Tue Mar 09 19:12:54 2005"

The first step in using this module must be to read the I<rollrec> file.  The
I<rollrec_read()> interface reads the file and parses it into an internal
format.  The file's records are copied into a hash table (for easy reference
by the I<Net::DNS::SEC::Tools::rollrec> routines) and in an array (for
preserving formatting and comments.)

After the file has been read, the contents are referenced using
I<rollrec_fullrec()> and I<rollrec_recval()>.  The contents are
modified using I<rollrec_add()> and I<rollrec_setval()>.

If the I<rollrec> file has been modified, it must be explicitly written or
the changes are not saved.  I<rollrec_write()> saves the new contents to disk.
I<rollrec_close()> saves the file and close the Perl file handle to the
I<rollrec> file.  If a I<rollrec> file is no longer wanted to be open, yet
the contents should not be saved, I<rollrec_discard()> gets rid of the data
closes and the file handle B<without> saving any modified data.

=head1 ROLLREC INTERFACES

The interfaces to the I<Net::DNS::SEC::Tools::rollrec> module are given below.

=head2 I<rollrec_add(rollrec_name,fields)>

This routine adds a new I<rollrec> to the I<rollrec> file and the internal
representation of the file contents.  The I<rollrec> is added to both the
I<%rollrecs> hash table and the I<@rollreclines> array.  Entries are only
added if they are defined for I<rollrec>s.

I<rollrec_name> is the name of the I<rollrec>.  I<fields> is a reference to a
hash table that contains the name/value I<rollrec> fields.  The keys of the
hash table are always converted to lowercase, but the entry values are left
as given.

Timestamp fields are added at the end of the I<rollrec>.  These fields have
the key values I<rollrec_gensecs> and I<rollrec_gendate>.

A blank line is added after the final line of the new I<rollrec>.  After adding
all new I<rollrec> entries, the I<rollrec> file is written but is not closed.

=head2 I<rollrec_del(rollrec_name)>

This routine deletes a I<rollrec> from the I<rollrec> file and the internal
representation of the file contents.  The I<rollrec> is deleted from both
the I<%rollrecs> hash table and the I<@rollreclines> array.

Only the I<rollrec> itself is deleted from the file.  Any associated comments
and blank lines surrounding it are left intact.

Return values are:

    0 successful I<rollrec> deletion

    -1 unknown name

=head2 I<rollrec_close()>

This interface saves the internal version of the I<rollrec> file (opened with
I<rollrec_read()>) and closes the file handle. 

=head2 I<rollrec_discard()>

This routine removes a I<rollrec> file from use by a program.  The internally
stored data are deleted and the I<rollrec> file handle is closed.  However,
modified data are not saved prior to closing the file handle.  Thus, modified
and new data will be lost.

=head2 I<rollrec_fullrec(rollrec_name)>

I<rollrec_fullrec()> returns a reference to the I<rollrec> specified in
I<rollrec_name>.

=head2 I<rollrec_names()>

This routine returns a list of the I<rollrec> names from the file.

=head2 I<rollrec_read(rollrec_file)>

This interface reads the specified I<rollrec> file and parses it into a
I<rollrec> hash table and a file contents array.  I<rollrec_read()>
B<must> be called prior to any of the other
I<Net::DNS::SEC::Tools::rollrec> calls.  If another I<rollrec> is
already open, then it is saved and closed prior to opening the new
I<rollrec>.

Upon success, I<rollrec_read()> returns the number of I<rollrec>s read from the
file.

Failure return values:

    -1 specified I<rollrec> file doesn't exit

    -2 unable to open I<rollrec> file

    -3 duplicate I<rollrec> names in file

=head2 I<rollrec_recval(rollrec_name,rollrec_field)>

This routine returns the value of a specified field in a given I<rollrec>.
I<rollrec_name> is the name of the particular I<rollrec> to consult.
I<rollrec_field> is the field name within that I<rollrec>.

For example, the current I<rollrec> file contains the following I<rollrec>.

    roll	"example.com"
                zonefile        "db.example.com"

The call:

    rollrec_recval("example.com","zonefile")

will return the value "db.example.com".

=head2 I<rollrec_setval(rollrec_name,field,value)>

Set the value of a name/field pair in a specified I<rollrec>.  The file is
B<not> written after updating the value, but the internal file-modified flag
is set.  The value is saved in both I<%rollrecs> and in I<@rollreclines>.

I<rollrec_name> is the name of the I<rollrec> that will be modified.
I<field> is the I<rollrec> field which will be modified.
I<value> is the new value for the field.

=head2 I<rollrec_write()>

This interface saves the internal version of the I<rollrec> file (opened with
I<rollrec_read()>).  It does not close the file handle.  As an efficiency
measure, an internal modification flag is checked prior to writing the file.
If the program has not modified the contents of the I<rollrec> file, it is not
rewritten.

=head1 ROLLREC INTERNAL INTERFACES

The interfaces described in this section are intended for internal use by the
I<Net::DNS::SEC::Tools::rollrec> module.  However, there are situations where
external entities may have need of them.  Use with caution, as misuse may
result in damaged or lost I<rollrec> files.

=head2 I<rollrec_init()>

This routine initializes the internal I<rollrec> data.  Pending changes will
be lost.  An open I<rollrec> file handle will remain open, though the data are
no longer held internally.  A new I<rollrec> file must be read in order to use
the I<Net::DNS::SEC::Tools::rollrec> interfaces again.

=head2 I<rollrec_newrec(name)>

This interface creates a new I<rollrec>.  The I<rollrec_name> field in the
I<rollrec> is set to the values of the I<name> parameter.

=head2 I<rollrec_default()>

This routine returns the name of the default I<rollrec> file.

=head1 ROLLREC DEBUGGING INTERFACES

The following interfaces display information about the currently parsed
I<rollrec> file.  They are intended to be used for debugging and testing, but
may be useful at other times.

=head2 I<rollrec_dump_hash()>

This routine prints the I<rollrec> file as it is stored internally in a hash
table.  The I<rollrec>s are printed in alphabetical order, with the fields
alphabetized for each I<rollrec>.  New I<rollrec>s and I<rollrec> fields are
alphabetized along with current I<rollrec>s and fields.  Comments from the
I<rollrec> file are not included with the hash table.

=head2 I<rollrec_dump_array()>

This routine prints the I<rollrec> file as it is stored internally in an
array.  The I<rollrec>s are printed in the order given in the file, with the
fields ordered in the same manner.  New I<rollrec>s are appended to the end
of the array.  I<rollrec> fields added to existing I<rollrec>s are added at
the beginning of the I<rollrec> entry.  Comments and vertical whitespace are
preserved as given in the I<rollrec> file.

=head1 COPYRIGHT

Copyright 2004-2005 SPARTA, Inc.  All rights reserved.
See the COPYING file included with the dnssec-tools package for details.

=head1 AUTHOR

Wayne Morrison, tewok@users.sourceforge.net

=head1 SEE ALSO

Net::DNS::SEC::Tools::keyrec(3)

Net::DNS::SEC::Tools::keyrec(5)

=cut
