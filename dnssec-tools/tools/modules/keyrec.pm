#
# Copyright 2005-2008 SPARTA, Inc.  All rights reserved.  See the COPYING
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
#	These entries are grouped into one of three types of records:
#
#		zone records - contains data used to sign a zone
#		set records  - contains data on the keys in a zone 
#		key records  - contains data used to generate an encryption key
#
#	Each record type has several subfields.
#
#	A truncated example configuration file follows:
#
#		zone "example.com"
#			zonefile	"db.example.com"
#			zskcur		"signing-set-42"
#			zskpub		"signing-set-43"
#			endtime		"+2592000"   # Zone expires in 30 days.
#
#		set "signing-set-42"
#			zonename	"example.com"
#			keys		"Kexample.com.+005+87654 Kexample.com.+005+55555
#
#		key "Kexample.com.+005+26000"
#			zonename	"example.com"
#			keyrec_type	"kskcur"
#			algorithm	"rsasha1"
#			length		"1024"
#			ksklife		"15768000"
#			random		"-r /dev/urandom"
#
#	The current implementation assumes that only one keyrec file will be
#	open at a time.  If module use proves this to be a naive assumption,
#	this module will have to be rewritten to account for it.
#

package Net::DNS::SEC::Tools::keyrec;

require Exporter;

use strict;
use Net::DNS::SEC::Tools::conf;

our $VERSION = "1.4";

our @ISA = qw(Exporter);

our @EXPORT = qw(keyrec_creat keyrec_open keyrec_read keyrec_fmtchk keyrec_names
		 keyrec_fullrec keyrec_recval keyrec_setval keyrec_settime
		 keyrec_add keyrec_del keyrec_newkeyrec keyrec_exists
		 keyrec_zonefields keyrec_setfields keyrec_keyfields
		 keyrec_init keyrec_discard keyrec_close
		 keyrec_write keyrec_saveas keyrec_keypaths
		 keyrec_defkrf keyrec_dump_hash keyrec_dump_array
		 keyrec_signset_newname keyrec_signset_new
		 keyrec_signset_addkey keyrec_signset_delkey
		 keyrec_signset_haskey keyrec_signset_clear keyrec_signsets );

#
# Fields in a zone keyrec.
#
my @ZONEFIELDS = (
			'zonefile',
			'keyrec_type',		# Internal only.  Usually.
			'endtime',
			'zskdirectory',
			'kskdirectory',
			'archivedir',
			'ksdir',
			'kskcount',
			'kskcur',
			'kskpub',
			'signedzone',
			'zskcount',
			'zskcur',
			'zskpub',
			'zsknew',
			'serial',
			'lastset',
			'gends',
			'szopts',
			'keyrec_signsecs',
			'keyrec_signdate',
		  );

#
# Fields in a set keyrec.
#
my @SETFIELDS = (
			'keyrec_type',		# Internal only.  Usually.
			'keys',
		        'zonename',
			'keyrec_setsecs',
			'keyrec_setdate',
		 );

#
# Fields in a key keyrec.
#
my @KEYFIELDS = (
			'keyrec_type',
			'algorithm',
			'random',
			'keypath',		# Only set for obsolete ZSKs.
			'ksklength',
			'ksklife',
			'zsklength',
			'zsklife',
			'kgopts',
			'keyrec_gensec',
			'keyrec_gendate',
		        'zonename',
		 );


my @keyreclines;			# Keyrec lines.
my $keyreclen;				# Number of keyrec lines.

my %keyrecs;				# Keyrec hash table (keywords/values.)

my $modified;				# File-modified flag.


#--------------------------------------------------------------------------
#
# Routine:      keyrec_creat()
#
# Purpose:      Create a DNSSEC keyrec file, if it does not exist.  If
#               the file already exists, this function truncates the file.
#
#		Returns 1 if the file was created successfully and 0 if
#               there was an error in file creation.  Upon successful return,
#               this function leaves the file in an 'open' read-write state.
#
sub keyrec_creat
{
	my $krf = shift;		# Key record file.

	#
	# Create a new keyrec file, or truncate existing one
	#
	open(KEYREC,"+> $krf") || return 0;

	return 1;
}

#--------------------------------------------------------------------------
#
# Routine:      keyrec_open()
#
# Purpose:      Opens an existing DNSSEC keyrec file.  If the file can't
#		be opened for reading and writing, an attempt is made to
#		open it read-only.
#
#		Returns 1 if the file was opened successfully and 0 if
#               there was an error in opening file (for example, if the
#               file did not exist).  Upon successful return, this function
#               leaves the file in an 'open' read-write or read-only state.
#
sub keyrec_open
{
	my $krf = shift;		# Key record file.

	#
	# Open an existing keyrec file
	#
	if(open(KEYREC,"+< $krf") == 0)
	{
		open(KEYREC,"< $krf") || return(0);
	}

	return(1);
}

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
	# Make sure a keyrec file was specified.
	#
	if($krf eq "")
	{
		err("no keyrec file specified\n",-1);
		return(-1);
	}

	#
	# Make sure the keyrec file exists.
	#
	if(! -e $krf)
	{
		err("keyrec file $krf does not exist\n",-1);
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
	if(keyrec_open($krf) == 0)
	{
		err("unable to open $krf\n",-1);
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
#		$line =~ /^[ \t]*([a-zA-Z_]+)[ \t]+"([a-zA-Z0-9\/\-+_.,: \t]+)"/;
		$line =~ /^[ \t]*([a-zA-Z_]+)[ \t]+"([a-zA-Z0-9\/\-+_.,: \t]*)"/;
		$keyword = $1;
		$value = $2;
#		print "keyrec_read:  keyword <$keyword>\t\t<$value>\n";

		#
		# If the keyword is "key" or "zone", then we're starting a
		# new record.  We'll save the name of the keyrec, as well
		# as the record type, and then proceed on to the next line.  
		#
		if(($keyword =~ /^zone$/i)	||
		   ($keyword =~ /^set$/i)	||
		   ($keyword =~ /^key$/i))
		{
			$name = $value;

			#
			# If this name has already been used for a keyrec,
			# we'll whinge, clean up, and return.  No keyrecs
			# will be retained.
			#
			if(exists($keyrecs{$name}))
			{
				keyrec_discard();
				err("keyrec_read:  duplicate record name \"$name\"; aborting...\n",-1);
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
	# Ensure the keyrec file is in the current format.
	#
	keyrec_fmtchk($krf);

	#
	# Return the number of keyrecs we found.
	#
	$krcnt = keys(%keyrecs);
	return($krcnt);
}

#--------------------------------------------------------------------------
#
# Routine:	keyrec_fmtchk()
#
# Purpose:	Ensure the keyrec file is in the current format.
#
#			zone keyrecs:
#				- kskkey:
#					Delete the entry if a kskcur entry
#					exists.  If a kskcur entry doesn't
#					exist, the kskkey key will be moved
#					into a new kskcur entry.
#				- keys:
#					Ensure that each key in the zone is
#					really pointing to a signing set.  if
#					not, a new set is created and the key
#					inserted in it.
#
#			set keyrecs:
#				Nothing.
#
#			key keyrecs:
#				- ksk:
#					Change to a kskcur, kskpub, or kskobs.
#
sub keyrec_fmtchk()
{
	my $krf = shift;			# Name of keyrec file.
	my $krn;				# Name of keyrec.
	my $krec;				# Ref to the keyrec's hash.
	my %krec;				# The keyrec's hash.

	my $changes = 0;			# Count of changes made.

# print "keyrec_fmtchk:  down in\n";

	#
	# Check zone keyrecs for problems:
	#	- existence of kskkey fields
	#	- key fields that don't point to set keyrecs
	#
	foreach $krn (keyrec_names())
	{
		#
		# Get the keyrec hash.
		#
		$krec = $keyrecs{$krn};
		%krec = %$krec;

		#
		# Only look at zones right now.
		#
		next if($krec{'keyrec_type'} ne 'zone');

		#
		# Check for the old 'kskkey' keyrec field.  If we find
		# one, we'll make it the new 'kskcur' field if there's
		# no 'kskcur'.  In either case, we'll delete the field.
		#
		if(exists($krec{'kskkey'}))
		{
			#
			# Create a signing set for the new kskcur.
			#
			if(!exists($krec{'kskcur'}))
			{
				my $set;	# Signing set name.

				$set = keyrec_signset_newname($krn);
				keyrec_setval('zone',$krn,'kskcur',$set);
				keyrec_signset_addkey($set,$krec{'kskkey'});
			}

			#
			# Delete the old kskkey keyrec.
			#
			keyrec_delval($krn,'kskkey');
			$changes++;
		}

		#
		# Ensure that each of the valid key types is actually
		# pointing to a signing set.  If not, create a new
		# set and move the key there.
		#
		foreach my $key (qw /kskcur kskpub zskcur zskpub zsknew/)
		{
			my $keyname;		# Key's name.
			my $set;		# Signing set name.
			my $skr;		# Sub-keyrec.

			#
			# Skip the key if it isn't in the keyrec.
			#
			next if(!exists($krec{$key}));

			#
			# Get the keyrec type of this key's keyrec.
			#
			$keyname = $krec{$key};
			$skr = $keyrecs{$keyname}{'keyrec_type'};

			#
			# Skip the key if it's already a signing set.
			#
			next if($skr eq 'set');

			#
			# Skip the key if it's empty.
			#
			next if($krec{$key} eq '');

			#
			# Make a new signing set for this key.
			#
			$set = keyrec_signset_newname($krn);
			keyrec_setval('zone',$krn,$key,$set);
			keyrec_signset_addkey($set,$keyname);
			$changes++;
		}
	}

	#
	# Check set keyrecs for problems:
	#
	#	- Nothing to check in set keyrecs.
	#
	foreach $krn (keyrec_names())
	{
		#
		# Get the keyrec hash.
		#
		$krec = $keyrecs{$krn};
		%krec = %$krec;

		#
		# Only look at sets right now...
		#
		next if($krec{'keyrec_type'} ne 'set');

		#
		# ... but we have nothing in sets to update.
		#
	}

	#
	# Check key keyrecs for problems:
	#	- Change ksk type keyrecs to kskcur, kskpub, or kskobs.
	#
	foreach $krn (keyrec_names())
	{
		my $zone;			# Key's owner zone.
		my $krt;			# Keyrec's type.

		#
		# Get the keyrec hash.
		#
		$krec = $keyrecs{$krn};
		%krec = %$krec;

		#
		# Only look at keys right now.
		#
		next if(($krec{'keyrec_type'} eq 'zone')	||
			($krec{'keyrec_type'} eq 'set'));

		#
		# Get the keyrec's type.
		#
		$krt = $krec{'keyrec_type'};

		#
		# Convert a ksk keyrec into either a kskcur, kskpub,
		# or kskobs keyrec.
		#
		if($krt eq 'ksk')
		{
			my $key;		# Key type.
			my $set;		# Key's signing set.
			my $found = "";		# Found-key flag.

			#
			# Check the key's zone to find if it's used in
			# any of the zone's key sets.
			#
			$zone = $krec{'zonename'};
			foreach my $key (qw /kskcur kskpub/)
			{
				$set = $keyrecs{$zone}{$key};
				if(keyrec_signset_haskey($set,$krn))
				{
					$found = $key;
					last;
				}
			}

			#
			# If this key is used in the zone, we'll set its
			# type appropriately.  If not, we'll set it to
			# being an obsolete key.
			#
			if($found ne "")
			{
				keyrec_setval('key',$krn,'keyrec_type',$found);
			}
			else
			{
				keyrec_setval('key',$krn,'keyrec_type','kskobs');
			}
			$changes++;
		}
	}

	#
	# If any problems were found and fixed, write and re-read the file.
	#
	if($changes)
	{
		keyrec_write();
		keyrec_close();
		keyrec_read($krf);
	}
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
# Routine:	keyrec_keypaths()
#
# Purpose:	Return an array of the paths of a zone keyrec's keys.
#		The type of key is specified by the caller.
#
sub keyrec_keypaths
{
	my $krn = shift;			# Keyrec name.
	my $krt = shift;			# Keyrec type.

	my $sset;				# Signing set name.
	my $keylist;				# List of keys.
	my @paths = ();				# Array for keyrec names.

	#
	# Ensure this is a zone keyrec.
	#
	return(@paths) if($keyrecs{$krn}{'keyrec_type'} ne "zone");

	#
	# Ensure the keyrec type is valid.
	#
	if(($krt ne "kskcur") && ($krt ne "kskpub") && ($krt ne "ksknew") &&
	   ($krt ne "zskcur") && ($krt ne "zskpub"))
	{
		return(@paths);
	}

	#
	# Get and verify the name of the appropriate signing set.
	#
	return(@paths) if(!defined($keyrecs{$krn}{$krt}));
	$sset = $keyrecs{$krn}{$krt};

	#
	# Get and verify the key list.
	#
	return(@paths) if(!defined($keyrecs{$sset}{'keys'}));
	$keylist = $keyrecs{$sset}{'keys'};

	#
	# Get the key's paths and add 'em to the path array.
	#
	foreach my $kn (split /[\s,]/, $keylist)
	{
		#
		# Verify that this key exists and is the right type.
		#
		next if(!defined($keyrecs{$kn}));
		next if($keyrecs{$kn}{'keyrec_type'} ne $krt);

		#
		# Push the key's path onto the path list.
		#
		push @paths, $keyrecs{$kn}{'keypath'};
	}

	#
	# Return the path list.
	#
	return(sort(@paths));
}

#--------------------------------------------------------------------------
#
# Routine:	keyrec_exists()
#
# Purpose:	Smoosh the keyrec names into an array and return the array.
#
sub keyrec_exists
{
	my $name = shift;			# The name to check.

	return(1) if(exists($keyrecs{$name}));
	return(0);
}

#--------------------------------------------------------------------------
#
# Routine:	keyrec_fullrec()
#
# Purpose:	Return all entries in a given keyrec.
#
sub keyrec_fullrec
{
	my $name = shift;			# The record to retrieve.
	my $krec = $keyrecs{$name};		# The retrieved record.

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
	my $name = shift;			# The record to retrieve.
	my $field = shift;			# The field to retrieve.
	my $val = $keyrecs{$name}{$field};	# The retrieved field.

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
#		$line =~ /^[ \t]*([a-zA-Z_]+)[ \t]+"([a-zA-Z0-9\/\-+_.,: \t]+)"/;
		$line =~ /^[ \t]*([a-zA-Z_]+)[ \t]+"([a-zA-Z0-9\/\-+_.,: \t]*)"/;
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
		   ((lc($krtype) eq "zone")	||
		    (lc($krtype) eq "set")	||
		    (lc($krtype) eq "key")))
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
#		$line =~ /^[ \t]*([a-zA-Z_]+)[ \t]+"([a-zA-Z0-9\/\-+_.,: \t]+)"/;
		$line =~ /^[ \t]*([a-zA-Z_]+)[ \t]+"([a-zA-Z0-9\/\-+_.,: \t]*)"/;
		$lkw = $1;
		$lval = $2;

		#
		# Skip empty lines.
		#
		if($lkw eq "")
		{
			next;
		}

		#
		# If we hit the beginning of the next keyrec without
		# finding the field, drop out and insert it.
		#
		if((lc($lkw) eq "zone")	||
		   (lc($lkw) eq "set")	||
		   (lc($lkw) eq "key"))
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
#		$keyreclines[$fldind] =~ s/"([a-zA-Z0-9\/\-+_.,: \t]+)"/"$val"/;
		$keyreclines[$fldind] =~ s/"([a-zA-Z0-9\/\-+_.,: \t]*)"/"$val"/;
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
# Routine:	keyrec_delval()
#
# Purpose:	Delete a name/subfield pair from a keyrec.  The value is
#		removed from both %keyrecs and in @keyreclines.  The $modified
#		file-modified flag is updated, along with the length $keyreclen.
#
sub keyrec_delval
{
	my $name   = shift;		# Name of keyrec we're modifying.
	my $field  = shift;		# Keyrec's subfield to be changed.

	my $fldind;			# Loop index.
	my $krind;			# Loop index for finding keyrec.
	my $lastfld = 0;		# Last found field in @keyreclines.

	#
	# Return if a keyrec of the specified name doesn't exist.
	#
	return(1) if(!exists($keyrecs{$name}));

	#
	# Find the appropriate entry to delete from @keyreclines.  If
	# the given field isn't set in $name's keyrec, we'll return.
	#
	for($krind=0;$krind<$keyreclen;$krind++)
	{
		my $line = $keyreclines[$krind];	# Line in keyrec file.
		my $krtype;				# Keyrec type.
		my $krname;				# Keyrec name.

		#
		# Dig out the line's keyword and value.
		#
		$line =~ /^[ \t]*([a-zA-Z_]+)[ \t]+"([a-zA-Z0-9\/\-+_.,: \t]*)"/;
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
		   ((lc($krtype) eq "zone")	||
		    (lc($krtype) eq "set")	||
		    (lc($krtype) eq "key")))
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
		$line =~ /^[ \t]*([a-zA-Z_]+)[ \t]+"([a-zA-Z0-9\/\-+_.,: \t]*)"/;
		$lkw = $1;
		$lval = $2;

		#
		# Skip empty lines.
		#
		next if($lkw eq "");

		#
		# If we hit the beginning of the next keyrec without
		# finding the field, drop out and insert it.
		#
		if((lc($lkw) eq "zone")	||
		   (lc($lkw) eq "set")	||
		   (lc($lkw) eq "key"))
		{
			last;
		}

		#
		# Save the index of the last field we've looked at that
		# belongs to the keyrec.
		#
		$lastfld = $fldind;

		#
		# If we found the field, set the found flag, delete it and
		# tell the world (or at least the module) that the file has
		# been modified.
		#
		if(lc($lkw) eq lc($field))
		{
			#
			# Delete the field from %keyrecs and @keyreclines.
			#
			delete $keyrecs{$name}{$field};
			splice @keyreclines, $fldind, 1;

			$modified = 1;
			return(1);
		}
	}

	#
	# We didn't find the entry.
	#
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
	if($krtype eq "zone")
	{
		@getfields = @ZONEFIELDS;

		$secsstr = 'keyrec_signsecs';
		$datestr = 'keyrec_signdate';
	}
	elsif($krtype eq "set")
	{
		@getfields = @SETFIELDS;

		$secsstr = 'keyrec_setsecs';
		$datestr = 'keyrec_setdate';
	}
	elsif($krtype eq "key")
	{
		@getfields = @KEYFIELDS;

		$secsstr = 'keyrec_gensecs';
		$datestr = 'keyrec_gendate';
	}

	#
	# Add the new keyrec's first line to the end of the keyrec table.
	#
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
			# Only add fields defined for the keyrec's type.
			#
			next if(!defined($fields{$fn}));

			#
			# Handle KSK-specific fields.
			#
			if($fields{'keyrec_type'} !~ /^ksk/)
			{
				if(($fn eq 'ksklength')		||
				   ($fn eq 'ksklife'))
				{
					next;
				}
			}

			#
			# Handle ZSK-specific key fields.
			#
			if($fields{'keyrec_type'} !~ /^zsk/)
			{
				if(($fn eq 'zsklength')		||
				   ($fn eq 'zsklife'))
				{
					next;
				}
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
	return(0);
}

#--------------------------------------------------------------------------
#
# Routine:	keyrec_del()
#
# Purpose:	Deletes a keyrec and fields from %keyrecs and $keyreclines.
#
sub keyrec_del
{
	my $krname = shift;		# Name of keyrec we're creating.

	my %keyrec;			# Keyrec to be deleted.
	my $krr;			# Keyrec reference.
	my $krtype;			# Keyrec's type.

	my $ind;			# Index into keyreclines.
	my $krind;			# Index to keyrec's first line.
	my $line;			# Keyrec line from @keyreclines.
	my $lkey;			# Keyrec line's key.
	my $lval;			# Keyrec line's value.
	my $len;			# Length of array slice to delete.

	#
	# Don't allow empty keyrec names.
	#
	return(-1) if($krname eq "");

	#
	# Get a copy of the keyrec from the keyrec hash and then delete
	# the original.
	#
	$krr = $keyrecs{$krname};
	%keyrec = %$krr;
	delete $keyrecs{$krname};

	#
	# Get the keyrec's type.
	#
	if($keyrec{'keyrec_type'} eq "zone")
	{
		$krtype = "zone";
	}
	elsif($keyrec{'keyrec_type'} eq "set")
	{
		$krtype = "set";
	}
	else
	{
		$krtype = "key";
	}

	#
	# Find the index of the first line for this keyrec in the
	# list of file lines.
	#
	for($ind = 0;$ind < $keyreclen; $ind++)
	{
		$line = $keyreclines[$ind];

		$line =~ /\s*(\S+)\s+(\S+)/;
		$lkey = $1;
		$lval = $2;

		$lval =~ s/"//g;

		last if(($lkey eq $krtype) && ($lval eq $krname));
	}
	$krind = $ind;

	#
	# If we didn't find a keyrec with this name, return failure.
	#
	return(-1) if($ind == $keyreclen);

	#
	# Find the beginning of the next keyrec.
	#
	for($ind = $krind+1;$ind < $keyreclen; $ind++)
	{
		$line = $keyreclines[$ind];

		$line =~ /\s*(\S+)\s+(\S+)/;
		$lkey = $1;
		$lval = $2;

		last if(($lkey eq "zone") ||
			($lkey eq "set")  ||
			($lkey eq "key"));
	}
	$ind--;

	#
	# Find the end of the previous keyrec (the one to be deleted.)
	#
	while($ind > $krind)
	{
		last if($keyreclines[$ind] ne "\n");
		$ind--;
	}

	#
	# Delete the keyrec from @keyreclines.
	#
	$len = $ind - $krind + 1;
	splice(@keyreclines,$krind,$len);
	$keyreclen -= $len;

	#
	# Tell the world (or at least the module) that the file has
	# been modified.
	#
	$modified = 1;
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
	if(($type ne "zone") && ($type ne "set") && ($type ne "key"))
	{
		return(-1);
	}

	$keyrecs{$name}{"keyrec_name"} = $name;
	$keyrecs{$name}{"keyrec_type"} = $type;

	return(0);
}

#--------------------------------------------------------------------------
#
# Routine:	keyrec_settime()
#
# Purpose:	Set the time value of a keyrec to the current time.  If
#		the keyrec (identified by name and type) doesn't exist,
#		a new one will be created.
#
sub keyrec_settime
{
	my $krtype = shift;		# Type of keyrec (for new keyrecs.)
	my $name   = shift;		# Name of keyrec we're modifying.

	my $chronosecs;			# Seconds since epoch.
	my $chronostr;			# String version of now.

	#
	# Get the timestamp.
	#
	$chronosecs = time();
	$chronostr  = gmtime($chronosecs);

	#
	# Set the timestamp in the entry, with the fields set depending
	# on the keyrec type.
	#
	if($krtype eq "zone")
	{
		keyrec_setval($krtype,$name,'keyrec_signsecs',$chronosecs);
		keyrec_setval($krtype,$name,'keyrec_signdate',$chronostr);
	}
	elsif($krtype eq "set")
	{
		keyrec_setval($krtype,$name,'keyrec_setsecs',$chronosecs);
		keyrec_setval($krtype,$name,'keyrec_setdate',$chronostr);
	}
	elsif($krtype eq "key")
	{
		keyrec_setval($krtype,$name,'keyrec_gensecs',$chronosecs);
		keyrec_setval($krtype,$name,'keyrec_gendate',$chronostr);
	}
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
# Routine:	keyrec_setfields()
#
# Purpose:	Return the list of set fields.
#
sub keyrec_setfields
{
	return(@SETFIELDS);
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

#----------------------------------------------------------------------
# Routine:	keyrec_signset_newname()
#
# Purpose:	Create a new signing set name based on the last name
#		used for the zone.
#
sub keyrec_signset_newname
{
	my $zone = shift;			# Zone for lastset.
	my $setname;				# Name of zone's last set.
	my $oldind;				# Old index of zone's last set.
	my $newind;				# New index of zone's last set.

	my $setprefix = '-signset-';

# print "keyrec_signset_newname($zone):  down in\n";

	#
	# Get the zone's last signing set.
	#
	$setname = $keyrecs{$zone}{'lastset'};
	$setname = "$zone-signset-0" if(!defined($keyrecs{$zone}{'lastset'}));

	#
	# Get the first number in the set name.  If there isn't a number
	# in the set name, we'll append a zero.
	#
	$setname =~ /$setprefix(\d+)/;
	$oldind = $1;
	
	if($oldind eq '')
	{
		$setname = $setname . "0";
		$oldind = 0;
	}

	#
	# We'll increment the old index and use that as our new index.
	# The set name in our pile o' options will be changed to the new name.
	#
	$newind = int($oldind) + 1;
	$setname =~ s/$setprefix$oldind/$setprefix$newind/;
#	$keyrecs{$zone}{'lastset'} = $setname;
	keyrec_setval('zone',$zone,'lastset',$setname);

	#
	# Return the generated signing set name.
	#
	return($setname);
}


#--------------------------------------------------------------------------
#
# Routine:	keyrec_signset_new()
#
# Purpose:	Add a new signing set keyrec.   If the signing set keyrec
#		hasn't yet been added with keyrec_add(), then we'll add it
#		now.  The second through Nth arguments are concatenated
#		into a space-separated string and then that string is saved
#		in both %keyrecs and in @keyreclines.  The $modified file-
#		modified flag is updated, along with the length $keyreclen.
#
sub keyrec_signset_new
{
	my $zone  = shift;		# Signing Set's zone.
	my $name  = shift;		# Signing Set name we're creating.

	my $val;			# New value for the keyrec's subfield.
	my $ret;			# Return code from keyrec_setval().

	#
	# Create a new keyrec for the given name if it doesn't exist.
	#
	if(!exists($keyrecs{$name}))
	{
		return(-1) if(keyrec_add('set',$name) < 0);
	}

	#
	# Bloodge together the remaining arguments into a single string.
	# We'll use this for the signing set's set of keys.
	#
	$val = join ' ', sort @_;
	$val =~ s/^ //g;

	#
	# Add the set of keys and away we go!
	#
	$ret = keyrec_setval('set',$name,'zonename',$zone);
	return($ret) if($ret != 0);
	$ret = keyrec_setval('set',$name,'keys',$val);
	return($ret);
}

#--------------------------------------------------------------------------
#
# Routine:	keyrec_signset_addkey()
#
# Purpose:	Add a key to a Signing Set for the specified keyrec.
#
sub keyrec_signset_addkey
{
	my $name = shift;		# Keyrec to modify.

	my $keys;			# Keyrec's signing set.
	my @keys;			# Keyrec's signing set array.
	my $newkeys;			# New keys to add.
	my $ret;			# Return code from keyrec_setval().

	#
	# Return failure if the named keyrec doesn't exist.
	#
	if(!exists($keyrecs{$name}))
	{
		return(0) if(keyrec_add('set',$name) < 0);
	}

	#
	# Return failure if it isn't a Signing Set keyrec.
	#
	if($keyrecs{$name}{'keyrec_type'} ne 'set')
	{
		return(0) if(keyrec_add('set',$name) < 0);
	}

	#
	# Get the keyrec's signing set and add the new key.
	#
	$newkeys = join ' ', @_;

	#
	# Get the keyrec's signing set and add the new keys.
	#
	$keys = $keyrecs{$name}{'keys'};
	$keys = "$keys $newkeys";

	#
	# Format the keys string a bit.
	#
	$keys =~ s/^[ ]*//;
	$keys =~ s/[ ]+/ /g;

	#
	# Sort the keyrecs names.
	# (This isn't essential, but makes things nice and tidy.)
	#
	@keys = split / /, $keys;
	$keys = join ' ',  sort(@keys);

	#
	# Add the set of keys and away we go!
	#
	$ret = keyrec_setval('set',$name,'keys',$keys);
	keyrec_settime('set',$name);
	return($ret);
}

#--------------------------------------------------------------------------
#
# Routine:	keyrec_signset_delkey()
#
# Purpose:	Delete an entry from a Signing Set for the specified keyrec.
#
sub keyrec_signset_delkey
{
	my $name = shift;		# Keyrec to modify.
	my $key = shift;		# Signing Set name to delete.

	my $keys;			# Keyrec's signing set as a string.
	my @keys;			# Keyrec's signing set as an array.
	my $ret;			# Return code from keyrec_setval().

	#
	# Return failure if the named keyrec doesn't exist.
	#
	if(!exists($keyrecs{$name}))
	{
		return(0) if(keyrec_add('set',$name) < 0);
	}

	#
	# Return failure if it isn't a Signing Set keyrec.
	#
	if($keyrecs{$name}{'keyrec_type'} ne 'set')
	{
		return(0) if(keyrec_add('set',$name) < 0);
	}

	#
	# Get the keyrec's Signing Set into an array of names.
	#
	$keys = $keyrecs{$name}{'keys'};
	@keys = split / /, $keys;

	#
	# Remove the specified name from the signing-set array.
	#
	for(my $ind = 0;$ind < @keys; $ind++)
	{
		if($keys[$ind] eq $key)
		{
			splice @keys, $ind, 1;
		}
	}

	#
	# Build and format the keys string a bit.
	#
	$keys = join(' ', @keys);
	$keys =~ s/^[ ]*//;
	$keys =~ s/[ ]+/ /g;

	#
	# Delete the key.
	#
	$ret = keyrec_setval('set',$name,'keys',$keys);
	keyrec_settime('set',$name);
	return($ret);
}

#--------------------------------------------------------------------------
#
# Routine:	keyrec_signset_haskey()
#
# Purpose:	Check if a Signing Set contains the specified keyrec.
#
#		Returns 1 if the set holds the key.
#		Returns 0 if the set doesn't hold the key.
#
sub keyrec_signset_haskey
{
	my $name = shift;		# Keyrec to check.
	my $key = shift;		# Signing Set name to delete.

	my $keys;			# Keyrec's signing set as a string.
	my @keys;			# Keyrec's signing set as an array.
	my $ret;			# Return code from keyrec_setval().

	#
	# Return failure if the named keyrec doesn't exist.
	#
	return(0) if(!exists($keyrecs{$name}));

	#
	# Return failure if it isn't a Signing Set keyrec.
	#
	if($keyrecs{$name}{'keyrec_type'} ne 'set')
	{
		return(0);
	}

	#
	# Get the keyrec's Signing Set into an array of names.
	#
	$keys = $keyrecs{$name}{'keys'};
	@keys = split / /, $keys;

	#
	# Return success if the specified name is in the signing-set array.
	#
	for(my $ind = 0;$ind < @keys; $ind++)
	{
		return(1) if($keys[$ind] eq $key);
	}

	return(0);
}

#--------------------------------------------------------------------------
#
# Routine:	keyrec_signset_clear()
#
# Purpose:	Delete all keys for the specified Signing Set.
#
sub keyrec_signset_clear
{
	my $name = shift;		# Keyrec to modify.

	my $ret;			# Return code from keyrec_setval().

	#
	# Return failure if the named keyrec doesn't exist.
	#
	if(!exists($keyrecs{$name}))
	{
		return(0) if(keyrec_add('set',$name) < 0);
	}

	#
	# Return failure if it isn't a Signing Set keyrec.
	#
	if($keyrecs{$name}{'keyrec_type'} ne 'set')
	{
		return(0) if(keyrec_add('set',$name) < 0);
	}

	#
	# Clear the set of keys.
	#
	$ret = keyrec_setval('set',$name,'keys','');
	return($ret);
}

#--------------------------------------------------------------------------
#
# Routine:	keyrec_signsets()
#
# Purpose:	Return the names of the Signing Sets in the keyrec file.
#
sub keyrec_signsets
{
	my @signset = ();		# Signing set.

	my $ret;			# Return code from keyrec_setval().

	#
	# Build a list of signing set names.
	#
	foreach my $kr (keys(%keyrecs))
	{
		push @signset, $kr if($keyrecs{$kr}{'keyrec_type'} eq 'set');
	}

	#
	# Return the signing set names.
	#
	return(@signset);
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
# Routine:	keyrec_defkrf()
#
# Purpose:	Get the default keyrec file defined in the DNSSEC-Tools
#		configuration file.
#
sub keyrec_defkrf
{
	my %dtconf;				# Configuration info.
	my $krf;				# Keyrec file name.

	#
	# Get the configuration info.
	#
	%dtconf = parseconfig();

	#
	# Check the config file for a default keyrec filename.
	#
	$krf = $dtconf{'default_keyrec'};

	return($krf);
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
	my $krc = "";			# Concatenated keyrec file contents.
	my $ofh;			# Old file handle.

	#
	# If the file hasn't changed, we'll skip writing.
	#
	return if(!$modified);

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

	#
	# Flush the KEYREC buffer.
	#
	$ofh = select KEYREC;
	$| = 1;
	select $ofh;
}

#--------------------------------------------------------------------------
#
# Routine:	keyrec_saveas()
#
# Purpose:	Save the key record file into a user-specified file.  A new
#		file handle is used and it is closed after writing.
#
sub keyrec_saveas
{
	my $newname = shift;		# Name of new file.
	my $krc = "";			# Concatenated keyrec file contents.

	#
	# Loop through the array of keyrec lines and concatenate them all.
	#
	for(my $ind=0;$ind<$keyreclen;$ind++)
	{
		$krc .= $keyreclines[$ind];
	}

	#
	# Open the new file.
	#
	open(NEWKEYREC,">$newname") || return(0);
	print NEWKEYREC $krc;
	close(NEWKEYREC);

	#
	# Return success.
	#
	return(1);
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

Net::DNS::SEC::Tools::keyrec - DNSSEC-Tools I<keyrec> file operations

=head1 SYNOPSIS

  use Net::DNS::SEC::Tools::keyrec;

  keyrec_creat("localzone.keyrec");
  keyrec_open("localzone.keyrec");
  keyrec_read("localzone.keyrec");

  @krnames = keyrec_names();

  $krec = keyrec_fullrec("example.com");
  %keyhash = %$krec;
  $zname = $keyhash{"algorithm"};

  $val = keyrec_recval("example.com","zonefile");

  $exists = keyrec_exists("example.com");

  keyrec_add("zone","example.com",\%zone_krfields);
  keyrec_add("key","Kexample.com.+005+12345",\%keydata);

  keyrec_del("example.com");
  keyrec_del("Kexample.com.+005+12345");

  keyrec_setval("zone","example.com","zonefile","db.example.com");

  @kskpaths = keyrec_keypaths("example.com","kskcur");

  $setname = keyrec_signset_newname("example.com");

  keyrec_signset_new("zone","example-keys");

  keyrec_signset_addkey("example-keys","Kexample.com+005+12345",
 					 "Kexample.com+005+54321");
  keyrec_signset_addkey("example-keys",@keylist);

  keyrec_signset_delkey("example-keys","Kexample.com+005+12345");

  $flag = keyrec_signset_haskey("example-keys","Kexample.com+005+12345");

  keyrec_signset_clear("example-keys","Kexample.com+005+12345");

  @signset = keyrec_signsets();

  keyrec_settime("zone","example.com");
  keyrec_settime("set","signing-set-42");
  keyrec_settime("key","Kexample.com.+005+76543");

  @keyfields = keyrec_keyfields();
  @zonefields = keyrec_zonefields();

  keyrec_write();
  keyrec_saveas("filecopy.krf);
  keyrec_close();
  keyrec_discard();

  $default_krf = keyrec_defkrf();

=head1 DESCRIPTION

The B<Net::DNS::SEC::Tools::keyrec> module manipulates the contents of
a DNSSEC-Tools I<keyrec> file.  I<keyrec> files contain data about
zones signed by and keys generated by the DNSSEC-Tools programs.  Module
interfaces exist for looking up I<keyrec> records, creating new
records, and modifying existing records.

A I<keyrec> file is organized in sets of I<keyrec> records.  Each I<keyrec>
must be either of I<key> type or I<zone> type.  Key I<keyrec>s describe how
encryption keys were generated, zone I<keyrec>s describe how zones were
signed.  A I<keyrec> consists of a set of keyword/value entries.  The
following is an example of a key I<keyrec>:

    key     "Kexample.com.+005+30485"
          zonename        "example.com"
          keyrec_type     "kskcur"
          algorithm       "rsasha1"
          random          "/dev/urandom"
          ksklength       "512"
	  ksklife	  "15768000"
          keyrec_gensecs  "1101183727"
          keyrec_gendate  "Tue Nov 23 04:22:07 2004"

The first step in using this module B<must> be to create a new I<keyrec>
file or open and read an existing one.  The I<keyrec_creat()> interface creates
a I<keyrec> file if it does not exist and opens it.  The I<keyrec_open()>
interface opens an existing I<keyrec> file.  The I<keyrec_read()> interface
reads the file and parses it into an internal format. The file's
records are copied into a hash table (for easy reference by the
B<Net::DNS::SEC::Tools::keyrec> routines) and in an array (for
preserving formatting and comments.)

After the file has been read, the contents are referenced using
I<keyrec_fullrec()> and I<keyrec_recval()>.  The I<keyrec> contents are
modified using I<keyrec_add()>, and I<keyrec_setval()>.  I<keyrec_settime()>
will update a I<keyrec>'s timestamp to the current time.  I<keyrec>s may be
deleted with the I<keyrec_del()> interface.

If the I<keyrec> file has been modified, it must be explicitly written or the
changes are not saved.  I<keyrec_write()> saves the new contents to disk.
I<keyrec_saveas()> saves the in-memory I<keyrec> contents to the specified
file name, without affecting the original file.

I<keyrec_close()> saves the file and close the Perl file handle to the
I<keyrec> file.  If a I<keyrec> file is no longer wanted to be open, yet the
contents should not be saved, I<keyrec_discard()> gets rid of the data, and
closes the file handle B<without> saving any modified data.

=head1 KEYREC INTERFACES

The interfaces to the B<Net::DNS::SEC::Tools::keyrec> module are given below.

=over 4

=item I<keyrec_add(keyrec_type,keyrec_name,fields)>

This routine adds a new I<keyrec> to the I<keyrec> file and the internal
representation of the file contents.  The I<keyrec> is added to both the
I<%keyrecs> hash table and the I<@keyreclines> array.

I<keyrec_type> specifies the type of the I<keyrec> -- "key" or "zone".
I<keyrec_name> is the name of the I<keyrec>.  I<fields> is a reference to a
hash table that contains the name/value I<keyrec> fields.  The keys of the
hash table are always converted to lowercase, but the entry values are left
as given.

The I<ksklength> entry is only added if the value of the I<keyrec_type>
field is "kskcur".

The I<zsklength> entry is only added if the value of the I<keyrec_type>
field is "zsk", "zskcur", "zskpub", or "zsknew".

Timestamp fields are added at the end of the I<keyrec>.  For key I<keyrec>s,
the I<keyrec_gensecs> and I<keyrec_gendate> timestamp fields are added.  For
zone I<keyrec>s, the I<keyrec_signsecs> and I<keyrec_signdate> timestamp
fields are added.

If a specified field isn't defined for the I<keyrec> type, the entry isn't
added.  This prevents zone I<keyrec> data from getting mingled with key
I<keyrec> data.

A blank line is added after the final line of the new I<keyrec>.  After adding
all new I<keyrec> entries, the I<keyrec> file is written but is not closed.

Return values are:

    0 success
    -1 invalid I<krtype>

=item I<keyrec_close()>

This interface saves the internal version of the I<keyrec> file (opened with
I<keyrec_creat()>, I<keyrec_open()> or I<keyrec_read()>) and closes the file
handle.

=item I<keyrec_creat(keyrec_file)>

This interface creates a I<keyrec> file if it does not exist, and truncates
the file if it already exists.  It leaves the file in the open state.

I<keyrec_creat()> returns 1 if the file was created successfully.
It returns 0 if there was an error in creating the file.

=item I<keyrec_defkrf()>

This routine returns the default I<keyrec> filename from the DNSSEC-Tools
configuration file.

=item I<keyrec_del(keyrec_name)>

This routine deletes a I<keyrec> from the I<keyrec> file and the internal
representation of the file contents.  The I<keyrec> is deleted from both
the I<%keyrecs> hash table and the I<@keyreclines> array.

Only the I<keyrec> itself is deleted from the file.  Any associated comments
and blank lines surrounding it are left intact.

Return values are:

    0 successful I<keyrec> deletion
    -1 invalid I<krtype> (empty string or unknown name)

=item I<keyrec_discard()>

This routine removes a I<keyrec> file from use by a program.  The internally
stored data are deleted and the I<keyrec> file handle is closed.  However,
modified data are not saved prior to closing the file handle.  Thus, modified
and new data will be lost.

=item I<keyrec_exists(keyrec_name)>

I<keyrec_exists()> returns a boolean indicating if a I<keyrec> exists that
has the specified I<keyrec_name>.

=item I<keyrec_fullrec(keyrec_name)>

I<keyrec_fullrec()> returns a reference to the I<keyrec> specified in
I<keyrec_name>.

=item I<keyrec_keyfields()>

This routine returns a list of the recognized fields for a key I<keyrec>.

=item I<keyrec_names()>

This routine returns a list of the I<keyrec> names from the file.

=item I<keyrec_open(keyrec_file)>

This interface opens an existing I<keyrec> file.  It first attempts to open
the I<keyrec> file for reading and writing.  If this fails, then it attempts
to open it read-only.

I<keyrec_open()> returns 1 if the file was opened successfully.  It returns 0
if the file does not exists or if there was an error in opening the file.

=item I<keyrec_read(keyrec_file)>

This interface reads the specified I<keyrec> file and parses it into a
I<keyrec> hash table and a file contents array.  I<keyrec_read()> B<must> be
called prior to any of the other B<Net::DNS::SEC::Tools::keyrec> calls.  If
another I<keyrec> is already open, then it is saved and closed prior to
opening the new I<keyrec>.

Upon success, I<keyrec_read()> returns the number of I<keyrec>s read from the
file.

Failure return values:

    -1 specified I<keyrec> file doesn't exit
    -2 unable to open I<keyrec> file
    -3 duplicate I<keyrec> names in file

=item I<keyrec_recval(keyrec_name,keyrec_field)>

This routine returns the value of a specified field in a given I<keyrec>.
I<keyrec_name> is the name of the particular I<keyrec> to consult.
I<keyrec_field> is the field name within that I<keyrec>.

For example, the current I<keyrec> file contains the following I<keyrec>:

    zone	"example.com"
                zonefile        "db.example.com"

The call:

    keyrec_recval("example.com","zonefile")

will return the value "db.example.com".

=item I<keyrec_saveas(keyrec_file_copy)>

This interface saves the internal version of the I<keyrec> file (opened with
I<keyrec_creat()>, I<keyrec_open()> or I<keyrec_read()>) to the file named in
the I<keyrec_file_copy> parameter.  The new file's file handle is closed, 
but the original file and the file handle to the original file are not
affected.

=item I<keyrec_setval(keyrec_type,keyrec_name,field,value)>

Set the value of a I<name/field> pair in a specified I<keyrec>.  The file is
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


=item I<keyrec_keypaths(zonename,keytype)>

I<keyrec_keypaths()> returns a list of paths to a set of key files for a
given zone.  The zone is specified in I<zonename> and the type of key is
given in I<keytype>.

I<keytype> must be one of the following:  "kskcur", "kskpub", "ksknew",
"zskcur", or "zskpub".

If the given key type is not defined in the given zone's zone I<keyrec>, then
a null set is returned.

=item I<keyrec_settime(keyrec_type,keyrec_name)>

Set the timestamp of a specified I<keyrec>.  The file is B<not> written
after updating the value.  The value is saved in both I<%keyrecs> and in
I<@keyreclines>, and the file-modified flag is set.  The I<keyrec>'s
I<keyrec_signdate> and I<keyrec_signsecs> fields are modified.

=item I<keyrec_write()>

This interface saves the internal version of the I<keyrec> file (opened with
I<keyrec_creat()>, I<keyrec_open()> or I<keyrec_read()>).  It does not close
the file handle.  As an efficiency measure, an internal modification flag is
checked prior to writing the file.  If the program has not modified the
contents of the I<keyrec> file, it is not rewritten.

=item I<keyrec_zonefields()>

This routine returns a list of the recognized fields for a zone I<keyrec>.

=back

=head1 KEYREC SIGNING-SET INTERFACES

Signing Sets are collections of encryption keys, defined by inclusion in a
particular "set" I<keyrec>.  The names of the keys are in the I<keyrec>'s
I<keys> record, which contains the names of the key I<keyrec>s.  Due to the
way key names are handled, the names in a Signing Set must not contain spaces.

The Signing-Set-specific interfaces are given below.

=over 4

=item I<keyrec_signset_newname(zone_name)>

I<keyrec_signset_newname()> creates a name for a new Signing Set.  The name
will be generated by referencing the I<lastset> field in the I<keyrec> for
zone I<zone_name>, if the I<keyrec> has such a field.  The set index number
(described below) will be incremented and the I<lastset> with the new index
number will be returned as the new Signing Set name.  If the zone I<keyrec>
does not have a I<lastset> field, then the default set name of
I<signing-set-0> will be used.

The set index number is the first number found in the I<lastset> field.  It
doesn't matter where in the field it is found, the first number will be
considered to be the Signing Set index.  The examples below show how this is
determined:

    lastset field		index
    -------------		-----
    signing-set-0		   0
    signing-0-set		   0
    1-signing-0-set		   1
    signing-88-set-1		  88
    signingset4321		4321

=item I<keyrec_signset_new(signing_set_name)>

I<keyrec_signset_new()> creates the Signing Set named by I<signing_set_name>.
It returns 1 if the call is successful; 0 if it is not.

=item I<keyrec_signset_addkey(signing_set_name,key_list)>

I<keyrec_signset_addkey()> adds the keys listed in I<key_list> to the Signing
Set named by I<signing_set_name>.  I<key_list> may either be an array or a set
or arguments to the routine.  The I<keyrec> is created if it does not already
exist.
It returns 1 if the call is successful; 0 if it is not.

=item I<keyrec_signset_delkey(signing_set_name,key_name)>

I<keyrec_signset_delkey()> deletes the key given in I<key_name> to the
Signing Set named by I<signing_set_name>.
It returns 1 if the call is successful; 0 if it is not.

=item I<keyrec_signset_haskey(signing_set_name,key_name)>

I<keyrec_signset_haskey()> returns a flag indicating if the key specified
in I<key_name> is one of the keys in the Signing Set named by
I<signing_set_name>.
It returns 1 if the signing set has the key; 0 if it does not.

=item I<keyrec_signset_clear(keyrec_name)>

I<keyrec_signset_clear()> clears the entire signing set from the I<keyrec>
named by I<keyrec_name>.
It returns 1 if the call is successful; 0 if it is not.

=item I<keyrec_signsets()>

I<keyrec_signsets()> returns the names of the signing sets in the I<keyrec>
file.  These names are returned in an array.

=back

=head1 KEYREC INTERNAL INTERFACES

The interfaces described in this section are intended for internal use by the
B<keyrec.pm> module.  However, there are situations where external entities
may have need of them.  Use with caution, as misuse may result in damaged or
lost I<keyrec> files.

=over 4

=item I<keyrec_init()>

This routine initializes the internal I<keyrec> data.  Pending changes will
be lost.  An open I<keyrec> file handle will remain open, though the data are
no longer held internally.  A new I<keyrec> file must be read in order to use
the B<keyrec.pm> interfaces again.

=item I<keyrec_newkeyrec(kr_name,kr_type)>

This interface creates a new I<keyrec>.  The I<keyrec_name> and I<keyrec_hash>
fields in the I<keyrec> are set to the values of the I<kr_name> and I<kr_type>
parameters.  I<kr_type> must be either "key" or "zone".

Return values are:

    0 if the creation succeeded
    -1 if an invalid I<keyrec> type was given

=back

=head1 KEYREC DEBUGGING INTERFACES

The following interfaces display information about the currently parsed
I<keyrec> file.  They are intended to be used for debugging and testing, but
may be useful at other times.

=over 4

=item I<keyrec_dump_hash()>

This routine prints the I<keyrec> file as it is stored internally in a hash
table.  The I<keyrec>s are printed in alphabetical order, with the fields
alphabetized for each I<keyrec>.  New I<keyrec>s and I<keyrec> fields are
alphabetized along with current I<keyrec>s and fields.  Comments from the
I<keyrec> file are not included with the hash table.

=item I<keyrec_dump_array()>

This routine prints the I<keyrec> file as it is stored internally in
an array.  The I<keyrec>s are printed in the order given in the file,
with the fields ordered in the same manner.  New I<keyrec>s are
appended to the end of the array.  I<keyrec> fields added to existing
I<keyrec>s are added at the beginning of the I<keyrec> entry.
Comments and vertical whitespace are preserved as given in the
I<keyrec> file.

=back

=head1 COPYRIGHT

Copyright 2005-2008 SPARTA, Inc.  All rights reserved.
See the COPYING file included with the DNSSEC-Tools package for details.

=head1 AUTHOR

Wayne Morrison, tewok@users.sourceforge.net

=head1 SEE ALSO

B<Net::DNS::SEC::Tools::conf(5)>,
B<Net::DNS::SEC::Tools::keyrec(5)>

=cut
