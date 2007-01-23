#
# Copyright 2004-2007 SPARTA, Inc.  All rights reserved.  See the COPYING
# file distributed with this software for details
#
# DNSSEC Tools
#
#	DNSSEC-Tools configuration routines.
#
#	The routines in this module perform configuration operations.
#	Some routines access the DNSSEC-Tools configuration file, while
#	others validate the execution environment.
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
our @EXPORT = qw(
			cmdcheck
			getconfdir
			getconffile
			parseconfig

			erraction
			err
			ERR_EXIT
			ERR_MSG 
			ERR_SILENT
		);

our @COMMANDS = qw(zonecheck keygen zonesign);

our $CONFFILE = "/usr/local/etc/dnssec/dnssec-tools.conf"; # Configuration file.
our $VERSION = "0.9";

###############################################################################
#
# Error actions this is intended for use by DNSSEC-Tools library routines.
#
my $ERR_SILENT	= 1;				# Don't do anything on error.
my $ERR_MSG	= 2;				# Print a message on error.
my $ERR_EXIT	= 3;				# Print a message and exit.

my $erraction = $ERR_SILENT;			# Action to take on errors.

sub ERR_EXIT	{ return($ERR_EXIT);	};
sub ERR_MSG 	{ return($ERR_MSG);	};
sub ERR_SILENT 	{ return($ERR_SILENT);	};

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
		err("unable to open $conffile\n",-1);
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

#######################################################################
#
# Routine:	cmdcheck()
#
# Purpose:	Ensure that the needed commands are available and executable.
#		If any of the commands either don't exist or aren't executable,
#		then an error message will be given and the process will exit.
#		If all is well, everything will proceed quietly onwards.
#
#		Things that make you go "hmmm....":
#			Is it *really* a good idea for a library routine
#			to exit on error, rather than just giving an
#			error return?
#
sub cmdcheck
{
	my $ropts = shift;			# Options hash reference.
	my %opts = %$ropts;			# Options hash.
	my $cmd;				# Command path.

	#
	# Check each of these commands for existence and executability.
	#
	foreach my $bcmd (@COMMANDS)
	{
		#
		# Only check the defined commands.
		#
		next if(!exists($opts{$bcmd}));
		$cmd = $opts{$bcmd};

		#
		# Check command name's existence.
		#
		if($cmd eq "")
		{
			err("command \"$bcmd\" does not exist; please install BIND (9.3.1 or later)\n",3);
			return(0);
		}

		#
		# Check command's existence.
		#
		if(! -e $cmd)
		{
			err("BIND command \"$cmd\" does not exist; please install BIND (9.3.1 or later)\n",3);
			return(0);
		}

		#
		# Check command's executability.
		#
		if(! -x $cmd)
		{
			err("$cmd not executable\n",3);
			return(0);
		}
	}

	return(1);
}

#######################################################################
#
# Routine:	getconfdir()
#
# Purpose:	Return the configuration directory name.
#
sub getconfdir
{
	my $dir;			# DNSSEC-Tools configuration directory.

	$CONFFILE =~ /^(.*)\/.*$/;
	$dir = $1;

	return($dir);
}

#######################################################################
#
# Routine:	getconffile()
#
# Purpose:	Return the configuration file name.
#
sub getconffile
{
	return($CONFFILE);
}


#######################################################################
#
# Routine:	erraction()
#
# Purpose:	Set the action to take on error.
#
sub erraction
{
	my $newact = shift;			# Action to take on error.
	my $curact;				# Current error action.

	#
	# Save the current error action.
	#
	$curact = $erraction;

	#
	# If this is a valid error action, we'll set the action.
	#
	if(($newact == $ERR_SILENT)	||
	   ($newact == $ERR_MSG)	||
	   ($newact == $ERR_EXIT))
	{
		$erraction = $newact;
	}

	#
	# Return the saved action.
	#
	return($curact);
}

#######################################################################
#
# Routine:	err()
#
# Purpose:	Report an error.  Maybe.
#
sub err
{
	my $errstr = shift;			# Error message.
	my $errret = shift;			# Error return code.

	return if($erraction == $ERR_SILENT);

	print STDERR "$errstr";

	exit($errret) if(($erraction == $ERR_EXIT) && ($errret >= 0));
}

1;

#############################################################################

=pod

=head1 NAME

Net::DNS::SEC::Tools::conf - DNSSEC-Tools configuration routines.

=head1 SYNOPSIS

  use Net::DNS::SEC::Tools::conf;

  %dtconf = parseconfig();

  %dtconf = parseconfig("localzone.keyrec");

  cmdcheck(\%options_hashref);

  $confdir = getconfdir();

  $conffile = getconffile();

  erraction(ERR_MSG);
  err("unable to open keyrec file",1);

=head1 DESCRIPTION

The routines in this module perform configuration operations.
Some routines access the DNSSEC-Tools configuration file, while others
validate the execution environment.

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

Another aspect of DNSSEC-Tools configuration is the error action used by the
DNSSEC-Tools Perl modules.  The action dictates whether an error condition
will only give an error return, print an error message to STDERR, or print an
error message and exit.  The I<erraction()> and I<err()> interfaces are used
for these operations.

=head1 INTERFACES

=over 4

=item B<parseconfig()>

This routine reads and parses the system's DNSSEC tools configuration file.
The parsed contents are put into a hash table, which is returned to the caller.

=item B<parseconfig(conffile)>

This routine reads and parses a caller-specified DNSSEC tools configuration
file.  The parsed contents are put into a hash table, which is returned to
the caller.  The routine quietly returns if the configuration file does not
exist. 

=item B<cmdcheck(\%options_hashref)>

This routine ensures that the needed commands are available and
executable.  If any of the commands either don't exist or aren't executable,
then an error message will be given and the process will exit.  If all is
well, everything will proceed quietly onwards.

The commands keys currently checked are I<zonecheck>, I<keygen>, and
I<zonesign>.  The pathnames for these commands are found in the given options
hash referenced by I<%options_hashref>.  If the hash doesn't contain an entry
for one of those commands, it is not checked.

=item B<getconfdir()>

This routine returns the name of the DNSSEC-Tools configuration directory.

=item B<getconffile()>

This routine returns the name of the DNSSEC-Tools configuration file.

=item B<erraction(error_action)>

This interface sets the error action for DNSSEC-Tools Perl modules.
The valid actions are:

    ERR_SILENT		Do not print an error message, do not exit.
    ERR_MSG		Print an error message, do not exit.
    ERR_EXIT		Print an error message, exit.

ERR_SILENT is the default action.

The previously set error action is returned.

=item B<err("error message",exit_code>

The B<err()> interface is used by the DNSSEC-Tools Perl modules to report
an error and exit, depending on the error action.

The first argument is an error message to print -- if the error action allows
error messages to be printed.

The second argument is an exit code -- if the error action requires that the
process exit.

=back

=head1 COPYRIGHT

Copyright 2004-2007 SPARTA, Inc.  All rights reserved.
See the COPYING file included with the DNSSEC-Tools package for details.

=head1 AUTHOR

Wayne Morrison, tewok@users.sourceforge.net

=head1 SEE ALSO

B<dnssec-tools.conf(5)>

=cut
