#
#
# Copyright 2004-2005 SPARTA, Inc.  All rights reserved.  See the COPYING
# file distributed with this software for details
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

package Net::DNS::SEC::Tools::conf;

require Exporter;
use strict;

our @ISA = qw(Exporter);
our @EXPORT = qw(parseconfig);

our $CONFFILE = "/usr/local/etc/dnssec/dnssec-tools.conf"; # Configuration file.
our $VERSION = "0.01";

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
	my $conffile = $CONFFILE;
	my $numargs  = @_;
	my %dnssec_conf = ();

	#
	# Find the right configuration file to open.
	#
	if($numargs != 0)
	{
		$conffile = shift;
	}

	#
	# Make sure the config file actually exists.  If not,
	# we'll quietly return.
	#
	return if(! -e $conffile);

	#
	# Open up the config file.
	#
	if(open(CONF,"< $conffile") == 0)
	{
		print STDERR "unable to open $conffile\n";
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
		# We could use join() instead of an explicit loop, but this
		# way we get to have mid-line comments.
		#
		for(my $ind=0;$ind<$arrlen;$ind++)
		{
			my $newval = $arr[$ind];	# New value chunk.

			last if($newval =~ /^[#;]/);
			next if(($newval eq "") || ($newval =~ /[ \t]+/));

			$newval =~ s/^[ \t]+//;
			$newval =~ s/[ \t]+$//;
			$val .= $newval . " ";
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

#############################################################################

=pod

=head1 NAME

Net::DNS::SEC::Tools::conf - DNSSEC tools configuration file routines.

=head1 SYNOPSIS

  use Net::DNS::SEC::Tools::conf;

  %dtconf = parseconfig();

  %dtconf = parseconfig("localzone.keyrec");

=head1 DESCRIPTION

The DNSSEC tools have a configuration file for commonly used values.
These values are the defaults for a variety of things, such as
encryption algorithm and encryption key length.

B</usr/local/etc/dnssec/dnssec-tools.conf> is the path for the DNSSEC tools
configuration file.  The B<Net::DNS::SEC::Tools::conf> module provides
methods for accessing the configuration data in this file.

The DNSSEC tools configuration file consists of a set of configuration
value entries, with only one entry per line.  Each entry has the
"keyword value" format.  During parsing, the line is broken into
tokens, with tokens being separated by spaces and tabs.  The first
token in a line is taken to be the keyword.  All other tokens in that
line are concatenated into a single string, with a space separating
each token.  The untokenized string is added to a hash table, with the
keyword as the value's key.

Comments may be included by prefacing them with the '#' or ';'
comment characters.  These comments can encompass an entire line or may
follow a configuration entry.  If a comment shares a line with an entry,
value tokenization stops just prior to the comment character.

An example configuration file follows:

    # Sample configuration entries.

    algorithm       rsasha1     # Encryption algorithm.
    ksk_length      1024        ; KSK key length.

=head1 CONFIGURATION INTERFACES

=over 4

=item I<parseconfig()>

This routine reads and parses the system's DNSSEC tools configuration file.
The parsed contents are put into a hash table, which is returned to the caller.

=item I<parseconfig(conffile)>

This routine reads and parses a caller-specified DNSSEC tools configuration
file.  The parsed contents are put into a hash table, which is returned to
the caller.  The routine quietly returns if the configuration file does not
exist. 

=back

=head1 COPYRIGHT

Copyright 2004-2005 SPARTA, Inc.  All rights reserved.
See the COPYING file included with the DNSSEC-Tools package for details.

=head1 AUTHOR

Wayne Morrison, tewok@users.sourceforge.net

=head1 SEE ALSO

I<zonesigner(8)>

B<Net::DNS::SEC::Tools::keyrec(3)>

B<dnssec-tools.conf(5)>

=cut
