#
# DNSSEC Tools
#
#	Configuration file routines.
#
#	The routines in this module access the configuration file for
#	the DNSSEC tools.
#
#	Entries in the configuration file are of the "key value" format.
#	Comments may be included by prefacing them with the '#' or ';'
#	comment characters.
#
#	An example configuration file follows:
#
#		# Sample configuration entries.
#		algorithm	rsasha1		# Encryption algorithm.
#		ksk_length	1024		; KSK key length.
#


use strict;

our $CONFFILE = "/etc/dnssec/tools.conf";	# Configuration file.


#--------------------------------------------------------------------------
#
# Routine:	parseconfig()
#
# Purpose:	Read a configuration file and parse it into pieces.  The
#		lines are tokenized and then stored in the config hash table.
#
#		Config entries are of the "variable value" form.  The first
#		non-blank token is taken as the name of the configuration
#		parameter and is the hash key into %dnssec_conf.  Anything
#		after that token is put into a space-separated tokenized form
#		and added to the %dnssec_conf.  If a line contains a comment
#		character (a '#' or a ';') then anything from that character
#		to the end of the line is ignored.  Empty lines and lines
#		starting with a comment character are entirely ignored.
#
sub parseconfig
{
	my %dnssec_conf = ();

	#
	# Open up the config file.
	#
	if(open(CONF,"< $CONFFILE") == 0)
	{
		print STDERR "unable to open $CONFFILE\n";
		return;
	}

	#
	# Read each line from the file, tokenize the line, and add it
	# to the config hash table.
	#
	while(<CONF>)
	{
		my $arrlen;	# Length of the token array.
		my $val = "";	# Concatenated value tokens.
		my $var;	# Variable token.
		my @arr;	# Array of tokens from the config line.

		#
		# Split the line into a pile of tokens.
		#
		chop;
		@arr = split(/[ \t]/);
		$arrlen = @arr;
		$var = shift @arr;

		#
		# Skip any comments.
		#
		if(($var =~ /^[;#]/) || ($var eq ""))
		{
			next;
		}

		#
		# Concatenate the remaining tokens, separated by a single
		# space.  If we hit a comment character, we'll stop there.
		#
		for(my $ind=0;$ind<$arrlen;$ind++)
		{
			if($arr[$ind] =~ /^[#;]/)
			{
				last;
			}
			$val .= $arr[$ind] . " ";
		}

		#
		# Get rid of any leading or trailing spaces.
		#
		$val =~ s/^[ \t]*//;
		$val =~ s/[ \t]*$//;

		#
		# Add this variable/value pair to the configuration hash table.
		#
		$dnssec_conf{$var} = $val;
	}

	#
	# Close the configuration file and return the config hash.
	#
	close(CONF);
	return(%dnssec_conf);
}

1;
