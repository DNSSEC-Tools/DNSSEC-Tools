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
#	record type has several sub-fields.
#
#	An example configuration file follows:
#
#		zone "isles.netsec.tislabs.com"
#			zonefile	"db.isles.netsec.tislabs.com"
#			kskpath		"Kisles.netsec.tislabs.com.+005+26000"
#			zskpath		"Kisles.netsec.tislabs.com.+005+52000"
#			endtime		"+2592000"   # Zone expires in 30 days.
#
#		key "Kisles.netsec.tislabs.com.+005+26000"
#			zonename	"isles.netsec.tislabs.com"
#			type		"ksk"
#			algorithm	"rsasha1"
#			length		"1024"
#			random		"-r /dev/urandom"
#

use strict;

my @keyreclines;			# Keyrec lines.
my $keyreclen;				# Number of keyrec lines.

my %primaries = ();


#--------------------------------------------------------------------------
#
# Routine:	keyrec_read()
#
# Purpose:	Read a DNSSEC keyrec file and read the file into an array.
#
sub keyrec_read
{
	my $krf = shift;		# Key record file.
	my $primary;			# Primary element (zone or key.)

	#
	# Open up the keyrec file.
	#
	if(! -e $krf)
	{
		print STDERR "$krf does not exist\n";
		return(-1);
	}

	#
	# Open up the keyrec file.
	#
	if(open(KEYREC,"+< $krf") == 0)
	{
		print STDERR "unable to open $krf\n";
		return(-1);
	}

	#
	# Initialize some data.
	#
	@keyreclines = ();
	$keyreclen   = 0;

	#
	# Grab the lines and pop 'em into the keyreclines array.
	#
	while(<KEYREC>)
	{
		my $line;		# Line from the keyrec file.
		my $keyword = "";	# Keyword from the line.
		my $value = "";		# Keyword's value.

		$line = $_;

		$keyreclines[$keyreclen] = $line;
		$keyreclen++;

		if(($line =~ /^[ \t]*$/) || ($line =~ /^[ \t]*#/))
		{
			next;
		}

		$line =~ /^[ \t]*([a-zA-Z]+)[ \t]+"([a-zA-Z0-9\/\-+_., ]+)"/;
		$keyword = $1;
		$value = $2;

		if(($keyword =~ /^key$/i) || ($keyword =~ /^zone$/i))
		{
			$primary = $value;
			next;
		}

		$primaries{$primary}{$keyword} = $value;

#		print "keyrec_read:  keyword <$keyword>\t\t<$value>\n";
	}

#	print "\n";

	return($keyreclen);
}

#--------------------------------------------------------------------------
#
# Routine:	keyrec_save()
#
# Purpose:	Save the key record file and close the descriptor.
#
sub keyrec_save
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
# Routine:	keyrec_recval()
#
# Purpose:	Return the value of a primary/subprimary pair.
#
sub keyrec_recval
{
	my $primeval = shift;
	my $subprime = shift;
	my $val = $primaries{$primeval}{$subprime};

	return($val);
}

#--------------------------------------------------------------------------
#
# Routine:	keyrec_dump()
#
# Purpose:	Dump the parsed key record entries.
#
sub keyrec_dump
{
	#
	# Loop through the hash of keyrec primaries and print the primaries,
	# subprimaries, and values.
	#
	foreach my $k (sort(keys(%primaries)))
	{
		print "keyrec - $k\n";
		my $subp = $primaries{$k};
		my %subprimaries = %$subp;
		foreach my $sk (sort(keys(%subprimaries)))
		{
			print "\t$sk\t\t$subprimaries{$sk}\n";
		}
		print "\n";
	}
}

#--------------------------------------------------------------------------
#
# Routine:	keyrec_list()
#
# Purpose:	Display the key record file contents.
#
sub keyrec_list
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
