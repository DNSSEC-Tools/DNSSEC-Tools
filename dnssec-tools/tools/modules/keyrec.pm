#
# Copyright 2004 Sparta, inc.  All rights reserved.  See the COPYING
# file distributed with this software for details
#
# DNSSEC Tools
#
#	Keyrec file routines.
#
#	The routines in this module manipulate a keyrec file for the DNSSEC
#	tools.  The keyrec file contains information about the values used
#	to generate a key or to sign a zone.
#
#	Entries in the configuration file are of the "key value" format, with
#	the value enclosed in quotes.  Comments may be included by prefacing
#	them with the '#' or ';' comment characters.
#
#	The format and contents of a keyrec file are *very* preliminary.
#	It is assumed that there entries will be grouped into one of two
#	types of records.  A zone record contains data used to sign a zone.
#	A key record contains data used to generate an encryption key.  Each
#	record type has several subfields.
#
#	An example configuration file follows:
#
#		zone "portrigh.com"
#			zonefile	"db.portrigh.com"
#			kskpath		"Kportrigh.com.+005+26000"
#			zskpath		"Kportrigh.com.+005+52000"
#			endtime		"+2592000"   # Zone expires in 30 days.
#
#		key "Kportrigh.com.+005+26000"
#			zonename	"portrigh.com"
#			keyrec_type	"ksk"
#			algorithm	"rsasha1"
#			length		"1024"
#			random		"-r /dev/urandom"
#
#	The current implementation assumes that only one keyrec file will
#	be open at a time.  If module use proves this to be a naive assumption
#	this module will have to be rewritten to account for it.
#

package Net::DNS::SEC::Tools::keyrec;

require Exporter;
use strict;

our $VERSION = "0.01";

our @ISA = qw(Exporter);

our @EXPORT = qw(keyrec_read keyrec_names keyrec_fullrec keyrec_recval
		 keyrec_setval keyrec_add keyrec_newkeyrec
		 keyrec_keyfields keyrec_zonefields keyrec_init
		 keyrec_discard keyrec_close keyrec_write
		 keyrec_dump_hash keyrec_dump_array);

#
# Fields in a key keyrec.
#
my @KEYFIELDS = (
			'keyrec_type',
			'algorithm',
			'random',
			'kskdirectory',
			'ksklength',
			'zskdirectory',
			'zsklength',
			'keyrec_gensec',
			'keyrec_gendate',
		 );

#
# Fields in a zone keyrec.
#
my @ZONEFIELDS = (
			'zonefile',
			'kskkey',
			'kskpath',
			'zskkey',
			'zskpath',
			'endtime',
			'keyrec_signsecs',
			'keyrec_signdate',
		  );

my @keyreclines;			# Keyrec lines.
my $keyreclen;				# Number of keyrec lines.

my %keyrecs;				# Keyrec hash table (keywords/values.)

my $modified;				# File-modified flag.


#--------------------------------------------------------------------------
#
# Routine:	keyrec_read()
#
# Purpose:	Read a DNSSEC keyrec file.  The contents are read into the
#		@keyreclines array and the keyrecs are broken out into the
#		%keyrecs hash table.
#
sub keyrec_read
{
	my $krf = shift;		# Key record file.
	my $name;			# Name of the keyrec (zone or key.)
	my $krcnt;			# Number of keyrecs we found.
	my @sbuf;			# Buffer for stat().

	#
	# Make sure the keyrec file exists.
	#
	if(! -e $krf)
	{
		print STDERR "$krf does not exist\n";
		return(-1);
	}

	#
	# If a keyrec file is already open, we'll flush our buffers and
	# save the file.
	#
	@sbuf = stat(KEYREC);
	if(@sbuf != 0)
	{
		keyrec_close();
	}

	#
	# Open up the keyrec file.
	#
	if(open(KEYREC,"+< $krf") == 0)
	{
		print STDERR "unable to open $krf\n";
		return(-2);
	}

	#
	# Initialize some data.
	#
	keyrec_init();

	#
	# Grab the lines and pop 'em into the keyreclines array.  We'll also
	# save each keyrec into a hash table for easy reference.
	#
	while(<KEYREC>)
	{
		my $line;		# Line from the keyrec file.
		my $keyword = "";	# Keyword from the line.
		my $value = "";		# Keyword's value.

		$line = $_;

		#
		# Save the line in our array of keyrec lines.
		#
		$keyreclines[$keyreclen] = $line;
		$keyreclen++;

		#
		# Skip comment lines and empty lines.
		#
		if(($line =~ /^[ \t]*$/) || ($line =~ /^[ \t]*[;#]/))
		{
			next;
		}

		#
		# Grab the keyword and value from the line.  The keyword
		# must be alphabetic.  The value can contain alphanumerics,
		# and a number of punctuation characters.  The value *must*
		# be enclosed in double quotes.
		#
		$line =~ /^[ \t]*([a-zA-Z_]+)[ \t]+"([a-zA-Z0-9\/\-+_.,: \t]+)"/;
		$keyword = $1;
		$value = $2;
#		print "keyrec_read:  keyword <$keyword>\t\t<$value>\n";

		#
		# If the keyword is "key" or "zone", then we're starting a
		# new record.  We'll save the name of the keyrec, as well
		# as the record type, and then proceed on to the next line.  
		#
		if(($keyword =~ /^key$/i) || ($keyword =~ /^zone$/i))
		{
			$name = $value;

			#
			# If this name has already been used for a keyrec,
			# we'll whinge, clean up, and return.  No keyrecs
			# will be retained.
			#
			if(exists($keyrecs{$name}))
			{
				print STDERR "keyrec_read:  duplicate record name; aborting...\n";

				keyrec_discard();
				return(-3);
			}
			keyrec_newkeyrec($name,$keyword);
			next;
		}

		#
		# Save this subfield into the keyrec's collection.
		#
		$keyrecs{$name}{$keyword} = $value;
	}

	#
	# Return the number of keyrecs we found.
	#
	$krcnt = keys(%keyrecs);
	return($krcnt);
}

#--------------------------------------------------------------------------
#
# Routine:	keyrec_names()
#
# Purpose:	Smoosh the keyrec names into an array and return the array.
#
sub keyrec_names
{
	my $krn;				# Keyrec name index.
	my @names = ();				# Array for keyrec names.

	foreach $krn (sort(keys(%keyrecs)))
	{
		push @names, $krn;
	}

	return(@names);
}

#--------------------------------------------------------------------------
#
# Routine:	keyrec_fullrec()
#
# Purpose:	Return all entries in a given keyrec.
#
sub keyrec_fullrec
{
	my $name = shift;
	my $krec = $keyrecs{$name};

	return($krec);
}

#--------------------------------------------------------------------------
#
# Routine:	keyrec_recval()
#
# Purpose:	Return the value of a name/subfield pair.
#
sub keyrec_recval
{
	my $name = shift;
	my $field = shift;
	my $val = $keyrecs{$name}{$field};

	return($val);
}

#--------------------------------------------------------------------------
#
# Routine:	keyrec_setval()
#
# Purpose:	Set the value of a name/subfield pair.  The value is saved
#		in both %keyrecs and in @keyreclines.  The $modified file-
#		modified flag is updated, along with the length $keyreclen.
#
sub keyrec_setval
{
	my $krtype = shift;		# Type of keyrec (for new keyrecs.)
	my $name   = shift;		# Name of keyrec we're modifying.
	my $field  = shift;		# Keyrec's subfield to be changed.
	my $val	   = shift;		# New value for the keyrec's subfield.

	my $found = 0;			# Keyrec-found flag.
	my $fldind;			# Loop index.
	my $krind;			# Loop index for finding keyrec.
	my $lastfld = 0;		# Last found field in @keyreclines.

	#
	# If a keyrec of the specified name doesn't exist, we'll create a
	# new one.  If the field is "keyrec_type", then we're creating a new
	# keyrec.  We'll add it to @keyreclines and %keyrecs.
	#
	if(!exists($keyrecs{$name}))
	{
		#
		# Add the keyrec to the %keyrecs hash.
		#
		if(keyrec_newkeyrec($name,$krtype) < 0)
		{
			return(-1);
		}

		#
		# Start the new keyrec in @keyreclines.
		#
		$keyreclines[$keyreclen] = "\n";
		$keyreclen++;
		$keyreclines[$keyreclen] = "$krtype\t\"$name\"\n";
		$keyreclen++;
	}

	#
	# Set the new value for the name/field in %keyrecs.
	#
	$keyrecs{$name}{$field} = $val;

	#
	# Find the appropriate entry to modify in @keyreclines.  If the
	# given field isn't set in $name's keyrec, we'll insert this as
	# a new field at the end of that keyrec.
	#
	for($krind=0;$krind<$keyreclen;$krind++)
	{
		my $line = $keyreclines[$krind];	# Line in keyrec file.
		my $krtype;				# Keyrec type.
		my $krname;				# Keyrec name.

		#
		# Dig out the line's keyword and value.
		#
		$line =~ /^[ \t]*([a-zA-Z_]+)[ \t]+"([a-zA-Z0-9\/\-+_.,: \t]+)"/;
		$krtype = $1;
		$krname = $2;

		#
		# If this line has the keyrec's name and is the start of a
		# new keyrec, then we've found our man.
		#
		# IMPORTANT NOTE:  We will *always* find the keyrec we're
		#		   looking for.  The exists() check above
		#		   ensures that there will be a keyrec with
		#		   the name we want.
		#
		if((lc($krname) eq lc($name)) &&
		   ((lc($krtype) eq "zone") || (lc($krtype) eq "key")))
		{
			last;
		}
	}

	#
	# Find the specified field's entry in the keyrec's lines in
	# @keyreclines.  We'll skip over lines that don't have a keyword
	# and dquotes-enclosed value.  If we hit the next keyrec (marked
	# by a zone or key line) then we'll stop looking and add a new
	# entry at the end of the keyrec's fields.
	#
	for($fldind=$krind+1;$fldind<$keyreclen;$fldind++)
	{
		my $line = $keyreclines[$fldind];	# Line in keyrec file.
		my $lkw;				# Line's keyword.
		my $lval;				# Line's value.

		#
		# Get the line's keyword and value.
		#
		$line =~ /^[ \t]*([a-zA-Z_]+)[ \t]+"([a-zA-Z0-9\/\-+_.,: \t]+)"/;
		$lkw = $1;
		$lval = $2;

		#
		# If we hit the beginning of the next keyrec without
		# finding the field, drop out and insert it.
		#
		if($lkw eq "")
		{
			next;
		}

		#
		# If we hit the beginning of the next keyrec without
		# finding the field, drop out and insert it.
		#
		if((lc($lkw) eq "zone") || (lc($lkw) eq "key"))
		{
			last;
		}

		#
		# Save the index of the last field we've looked at that
		# belongs to the keyrec.
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
		$keyreclines[$fldind] =~ s/"([a-zA-Z0-9\/\-+_.,: \t]+)"/"$val"/;
	}
	else
	{
		my $newline = "\t$field\t\t\"$val\"\n";

		#
		# If the keyword is longer than 7 characters, we'll lop out one
		# of the tabs between the keyword and the value.  This is to do
		# some rough, simple formatting to keep the keyrec file somewhat
		# orderly.  This assumes eight-character tabstops.
		#
		if(length($field) > 7)
		{
			$newline =~ s/\t\t/\t/;
		}

		#
		# If the starting keyrec line is the last line in the file,
		# we'll just push the new line at the end.  If it's somewhere
		# in the middle, we'll do the magic to insert it at the start
		# of the keyrec.
		#
		my @endarr = splice(@keyreclines,$krind+1);
		push(@keyreclines,$newline);
		push(@keyreclines,@endarr);

		#
		# Bump the array length counter.
		#
		$keyreclen++;
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
# Routine:	keyrec_add()
#
# Purpose:	Adds a new keyrec and fields to %keyrecs and $keyreclines.
#
sub keyrec_add
{
	my $krtype = shift;		# Type of keyrec we're creating.
	my $krname = shift;		# Name of keyrec we're creating.
	my $flds   = shift;		# Reference to keyrec fields.

	my $chronosecs;			# Current time in seconds.
	my $chronostr;			# Current time string.
	my $secsstr;			# Hash key for time in seconds.
	my $datestr;			# Hash key for time string.

	my %fields;			# Keyrec fields.
	my @getfields;			# Hash fields to retrieve.

	#
	# Get the timestamp.
	#
	$chronosecs = time();
	$chronostr  = gmtime($chronosecs);

	#
	# Create the basic keyrec info.
	#
	if(keyrec_newkeyrec($krname,$krtype) < 0)
	{
		return(-1);
	}

	#
	# Set the fields, by type, that we'll grab from the caller's hash.
	#
	if($krtype eq "key")
	{
		@getfields = @KEYFIELDS;

		$secsstr = 'keyrec_gensecs';
		$datestr = 'keyrec_gendate';
	}
	elsif($krtype eq "zone")
	{
		@getfields = @ZONEFIELDS;

		$secsstr = 'keyrec_signsecs';
		$datestr = 'keyrec_signdate';
	}

	#
	# Add the new keyrec's first line to the end of the keyrec table.
	#
	$keyreclines[$keyreclen] = "\n";
	$keyreclen++;
	$keyreclines[$keyreclen] = "$krtype\t\"$krname\"\n";
	$keyreclen++;

	#
	# Fill the new keyrec with the caller's hash fields and add it to
	# the end of the keyrec table.
	#
	if(defined($flds))
	{
		%fields = %$flds;
		foreach my $fn (@getfields)
		{
			my $spacing = "\t\t";	# Spacing string.

			#
			# Only add the timestamp at the end, and only
			# add the timestamp we're going to put in.
			#
			if(($fn eq $secsstr) || ($fn eq $datestr))
			{
				next;
			}

			#
			# If this field isn't defined for the keyrec,
			# don't add it in.
			#
			if(!defined($fields{$fn}))
			{
				next;
			}

			#
			# Special case for keys:  Only give the key length
			# for the key's type.
			#
			if((($fields{'keyrec_type'} eq 'zsk') &&
			    ($fn eq 'ksklength'))		||
			   (($fields{'keyrec_type'} eq 'ksk') &&
			    ($fn eq 'zsklength')))
			{
				next;
			}

			#
			# Drop back to a single tab between key and value
			# if the key name is long.
			#
			$spacing = "\t"    if(length($fn) > 7);

			#
			# Add the field to the hash table and to the keyrec
			# file contents array.
			#
			$keyrecs{$krname}{$fn} = $fields{$fn};
			$keyreclines[$keyreclen] = "\t$fn$spacing\"$fields{$fn}\"\n";
			$keyreclen++;
		}
	}

	#
	# Set a timestamp for this entry.
	#
	$keyrecs{$krname}{$secsstr} = $chronosecs;
	$keyrecs{$krname}{$datestr} = $chronostr;
	$keyreclines[$keyreclen] = "\t$secsstr\t\"$chronosecs\"\n";
	$keyreclen++;
	$keyreclines[$keyreclen] = "\t$datestr\t\"$chronostr\"\n";
	$keyreclen++;

	#
	# Put a blank line after the final line of the keyrec.
	#
	$keyreclines[$keyreclen] = "\n";
	$keyreclen++;

	#
	# Sync the keyrec file.
	#
	$modified = 1;
	keyrec_write();
	return(0);
}

#--------------------------------------------------------------------------
#
# Routine:	keyrec_newkeyrec()
#
# Purpose:	Creates a keyrec in %keyrecs.  The name and type fields of
#		the keyrec are set.
#
sub keyrec_newkeyrec
{
	my $name = shift;		# Name of keyrec we're creating.
	my $type  = shift;		# Type of keyrec we're creating.

	#
	# Ensure we're only getting a valid type.
	#
	if(($type ne "key") && ($type ne "zone"))
	{
		return(-1);
	}

	$keyrecs{$name}{"keyrec_name"} = $name;
	$keyrecs{$name}{"keyrec_type"} = $type;
	return(0);
}

#--------------------------------------------------------------------------
#
# Routine:	keyrec_keyfields()
#
# Purpose:	Return the list of key fields.
#
sub keyrec_keyfields
{
	return(@KEYFIELDS);
}

#--------------------------------------------------------------------------
#
# Routine:	keyrec_zonefields()
#
# Purpose:	Return the list of zone fields.
#
sub keyrec_zonefields
{
	return(@ZONEFIELDS);
}

#--------------------------------------------------------------------------
#
# Routine:	keyrec_init()
#
# Purpose:	Initialize the internal data.
#
sub keyrec_init
{
	%keyrecs     = ();
	@keyreclines = ();
	$keyreclen   = 0;
	$modified    = 0;
}

#--------------------------------------------------------------------------
#
# Routine:	keyrec_discard()
#
# Purpose:	Discard the current keyrec file -- don't save the contents,
#		don't delete the file, reset all internal fields.
#
sub keyrec_discard
{
	close(KEYREC);
	keyrec_init();
}

#--------------------------------------------------------------------------
#
# Routine:	keyrec_close()
#
# Purpose:	Save the key record file and close the descriptor.
#
sub keyrec_close
{
	keyrec_write();
	close(KEYREC);
}

#--------------------------------------------------------------------------
#
# Routine:	keyrec_write()
#
# Purpose:	Save the key record file and leave the file handle open.
#
sub keyrec_write
{
	my $krc = "";		# Concatenated keyrec file contents.

	#
	# If the file hasn't changed, we'll skip writing.
	#
	if(!$modified)
	{
		return;
	}

	#
	# Loop through the array of keyrec lines and concatenate them all.
	#
	for(my $ind=0;$ind<$keyreclen;$ind++)
	{
		$krc .= $keyreclines[$ind];
	}

	#
	# Zap the keyrec file and write out the new one.
	#
	seek(KEYREC,0,0);
	truncate(KEYREC,0);
	print KEYREC $krc;
}

#--------------------------------------------------------------------------
#
# Routine:	keyrec_dump_hash()
#
# Purpose:	Dump the parsed keyrec entries.
#
sub keyrec_dump_hash
{
	#
	# Loop through the hash of keyrecs and print the keyrec names,
	# subfields, and values.
	#
	foreach my $k (sort(keys(%keyrecs)))
	{
		print "keyrec - $k\n";
		my $subp = $keyrecs{$k};
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
# Routine:	keyrec_dump_array()
#
# Purpose:	Display the contents of @keyreclines.
#
sub keyrec_dump_array
{
	#
	# Loop through the array of keyrec lines and print them all.
	#
	for(my $ind=0;$ind<$keyreclen;$ind++)
	{
		print $keyreclines[$ind];
	}
}

1;

#############################################################################

=pod

=head1 NAME

Net::DNS::SEC::Tools::keyrec - Squoodge around with a dnssec-tools keyrec file.

=head1 SYNOPSIS

  use Net::DNS::SEC::Tools::keyrec;

  keyrec_read("localzone.keyrec");

  @krnames = keyrec_names();

  $krec = keyrec_fullrec("portrigh.com");
  %keyhash = %$krec;
  $zname = $keyhash{"algorithm"};

  $val = keyrec_recval("portrigh.com","zonefile");

  keyrec_add("zone","portrigh.com",\%zone_krfields);
  keyrec_add("key","Kportrigh.com.+005+12345",\%keydata);

  keyrec_setval("zone","portrigh.com","zonefile","db.portrigh.com");

  @keyfields = keyrec_keyfields();
  @zonefields = keyrec_zonefields();

  keyrec_write();
  keyrec_close();
  keyrec_discard();

=head1 DESCRIPTION

The I<Net::DNS::SEC::Tools::keyrec> module manipulates the contents of
a dnssec-tools I<keyrec> file.  I<keyrec> files contain data about
zones signed by and keys generated by the dnssec-tools.  Module
interfaces exist for looking up I<keyrec> records, creating new
records, and modifying existing records.

A I<keyrec> file is organized in sets of I<keyrec> records.  Each I<keyrec>
must be either of key type or zone type.  Key I<keyrec>s describe how
encryption keys were generated, zone I<keyrec>s describe how zones were
signed.  A I<keyrec> consists of a set of keyword/value entries.  The
following is an example of a key I<keyrec>:

    key     "Kportrigh.com.+005+30485"
          zonename        "portrigh.com"
          keyrec_type     "zsk"
          algorithm       "rsasha1"
          random          "/dev/urandom"
          zsklength       "512"
          keyrec_gensecs  "1101183727"
          keyrec_gendate  "Tue Nov 23 04:22:07 2004"

The first step in using this module B<must> be to read the I<keyrec>
file.  The I<keyrec_read()> interface reads the file and parses it
into an internal format.  The file's records are copied into a hash
table (for easy reference by the I<Net::DNS::SEC::Tools::keyrec>
routines> and in an array (for preserving formatting and comments.)

After the file has been read, the contents are referenced using
I<keyrec_fullrec()> and I<keyrec_recval()>.  The contents are modified
using I<keyrec_add()> and I<keyrec_setval()>.

If the I<keyrec> file has been modified, it must be explicitly written or the
changes are not saved.  I<keyrec_write()> saves the new contents to disk.
I<keyrec_close()> saves the file and close the Perl file handle to the
I<keyrec> file.  If a I<keyrec> file is no longer wanted to be open, yet the
contents should not be saved, I<keyrec_discard()> gets rid of the data closes
the file handle B<without> saving any modified data.

=head1 KEYREC INTERFACES

The following are the user interfaces to the
I<Net::DNS::SEC::Tools::keyrec> module.

=head2 I<keyrec_add(keyrec_type,keyrec_name,fields)>

This routine adds a new I<keyrec> to the I<keyrec> file and the internal
representation of the file contents.  The I<keyrec> is added to both the
I<%keyrecs> hash table and the I<@keyreclines> array.

I<keyrec_type> specifies the type of the I<keyrec> -- "key" or "zone".
I<keyrec_name> is the name of the I<keyrec>.  I<fields> is a reference to a
hash table that contains the name/value I<keyrec> fields.  The keys of the
hash table are always converted to lowercase, but the entry values are left
as given.

The I<ksklength> entry is only added if I<keyrec_type> is "ksk".

The I<zsklength> entry is only added if I<keyrec_type> is "zsk".

Timestamp fields are added at the end of the keyrec.  For key I<keyrec>s, the
I<keyrec_gensecs> and I<keyrec_gendate> timestamp fields are added.  For zone
I<keyrec>s, the I<keyrec_signsecs> and I<keyrec_signdate> timestamp fields
are added.

If a specified field isn't defined for the I<keyrec> type, the entry isn't
added.  This prevents zone I<keyrec> data from getting mingled with key
I<keyrec> data.

A blank line is added after the final line of the new I<keyrec>.  After adding
all new I<keyrec> entries, the I<keyrec> file is written but is not closed.

Return values are:

    0 success

    -1 invalid krtype

=head2 I<keyrec_close()>

This interface saves the internal version of the I<keyrec> file (opened with
I<keyrec_read()>) and closes the file handle. 

=head2 I<keyrec_discard()>

This routine removes a I<keyrec> file from use by a program.  The internally
stored data are deleted and the I<keyrec> file handle is closed.  However,
modified data are not saved prior to closing the file handle.  Thus, modified
and new data will be lost.

=head2 I<keyrec_fullrec(keyrec_name)>

I<keyrec_fullrec()> returns a reference to the I<keyrec> specified in
I<keyrec_name>.

=head2 I<keyrec_keyfields()>

This routine returns a list of the recognized fields for a key I<keyrec>.

=head2 I<keyrec_names()>

This routine returns a list of the I<keyrec> names from the file.

=head2 I<keyrec_read(keyrec_file)>

This interface reads the specified I<keyrec> file and parses it into a
I<keyrec> hash table and a file contents array.  I<keyrec_read()>
B<must> be called prior to any of the other
I<Net::DNS::SEC::Tools::keyrec> calls.  If another I<keyrec> is
already open, then it is saved and closed prior to opening the new
I<keyrec>.

Upon success, I<keyrec_read()> returns the number of I<keyrec>s read from the
file.

Failure return values:

    -1 specified I<keyrec> file doesn't exit

    -2 unable to open I<keyrec> file

    -3 duplicate I<keyrec> names in file

=head2 I<keyrec_recval(keyrec_name,keyrec_field)>

This routine returns the value of a specified field in a given I<keyrec>.
I<keyrec_name> is the name of the particular I<keyrec> to consult.
I<keyrec_field> is the field name within that I<keyrec>.

For example, the current I<keyrec> file contains the following I<keyrec>.

    zone	"portrigh.com"
                zonefile        "db.portrigh.com"

The call:

    keyrec_recval("portrigh.com","zonefile")

will return the value "db.portrigh.com".

=head2 I<keyrec_setval(keyrec_type,keyrec_name,field,value)>

Set the value of a name/field pair in a specified I<keyrec>.  The file is
B<not> written after updating the value.  The value is saved in both
I<%keyrecs> and in I<@keyreclines>, and the file-modified flag is set.

I<keyrec_type> specifies the type of the I<keyrec>.  This is only used if a
new I<keyrec> is being created by this call.
I<keyrec_name> is the name of the I<keyrec> that will be modified.
I<field> is the I<keyrec> field which will be modified.
I<value> is the new value for the field.

Return values are:

    0 if the creation succeeded

    -1 invalid type was given

=head2 I<keyrec_write()>

This interface saves the internal version of the I<keyrec> file (opened with
I<keyrec_read()>).  It does not close the file handle.  As an efficiency
measure, an internal modification flag is checked prior to writing the file.
If the program has not modified the contents of the I<keyrec> file, it is not
rewritten.

=head2 I<keyrec_zonefields()>

This routine returns a list of the recognized fields for a zone I<keyrec>.

=head1 KEYREC INTERNAL INTERFACES

The interfaces described in this section are intended for internal use by the
I<Net::DNS::SEC::Tools::keyrec> module.  However, there are situations where external
entities may have need of them.  Use with caution, as misuse may result in
damaged or lost I<keyrec> files.

=head2 I<keyrec_init()>

This routine initializes the internal I<keyrec> data.  Pending changes will
be lost.  An open I<keyrec> file handle will remain open, though the data are
no longer held internally.  A new I<keyrec> file must be read in order to use
the I<Net::DNS::SEC::Tools::keyrec> interfaces again.

=head2 I<keyrec_newkeyrec(kr_name,kr_type)>

This interface creates a new I<keyrec>.  The I<keyrec_name> and I<keyrec_hash>
fields in the I<keyrec> are set to the values of the I<kr_name> and I<kr_type>
parameters.  I<kr_type> must be either "key" or "zone".

Return values are:

    0 if the creation succeeded

    -1 if an invalid I<keyrec> type was given

=head1 KEYREC DEBUGGING INTERFACES

The following interfaces display information about the currently parsed
I<keyrec> file.  They are intended to be used for debugging and testing, but
may be useful at other times.

=head2 I<keyrec_dump_hash()>

This routine prints the I<keyrec> file as it is stored internally in a hash
table.  The I<keyrec>s are printed in alphabetical order, with the fields
alphabetized for each I<keyrec>.  New I<keyrec>s and I<keyrec> fields are
alphabetized along with current I<keyrec>s and fields.  Comments from the
I<keyrec> file are not included with the hash table.

=head2 I<keyrec_dump_array()>

This routine prints the I<keyrec> file as it is stored internally in
an array.  The I<keyrec>s are printed in the order given in the file,
with the fields ordered in the same manner.  New I<keyrec>s are
appended to the end of the array.  I<keyrec> fields added to existing
I<keyrec>s are added at the beginning of the I<keyrec> entry.
Comments and vertical whitespace are preserved as given in the
I<keyrec> file.

=head1 AUTHOR

Wayne Morrison, tewok@users.sourceforge.net

=head1 SEE ALSO

Net::DNS::SEC::Tools::keyrec(5)

=cut
