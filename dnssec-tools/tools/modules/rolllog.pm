#
# Copyright 2005-2014 SPARTA, Inc.  All rights reserved.  See the COPYING
# file distributed with this software for details
#
# DNSSEC Tools
#
# rolllog.pm -	Rollover logging functions.
#
#	The routines in this module provide a logging mechanism.
#

package Net::DNS::SEC::Tools::rolllog;

require Exporter;
use strict;

use Fcntl ':flock';
use Socket;

use Net::DNS::SEC::Tools::conf;
use Net::DNS::SEC::Tools::defaults;

our $VERSION = "2.1";
our $MODULE_VERSION = "2.1.0";

our @ISA = qw(Exporter);

our @EXPORT = qw(

		 rolllog_log
		 rolllog_file
		 rolllog_validlevel
		 rolllog_level
		 rolllog_levels
		 rolllog_num
		 rolllog_gettz
		 rolllog_settz
		 rolllog_str
			 LOG_NEVER
			 LOG_TMI
			 LOG_EXPIRE
			 LOG_INFO
			 LOG_PHASE
			 LOG_ERR
			 LOG_FATAL
			 LOG_ALWAYS
			 LOG_DEFAULT

		);

##############################################################################
#
# Log levels.  The first and last aren't selectable by a user.
#
my $LOG_NEVER	 =  0;			# Do not log this message.
my $LOG_TMI	 =  1;			# Overly verbose informational message.
my $LOG_EXPIRE	 =  3;			# Time-to-expiration given.
my $LOG_INFO	 =  4;			# Informational message.
my $LOG_PHASE	 =  6;			# Give current state of zone.
my $LOG_ERR	 =  8;			# Non-fatal error message.
my $LOG_FATAL	 =  9;			# Fatal error.
my $LOG_ALWAYS	 = 10;			# Messages that should always be given.

my $LOG_MIN	 =  $LOG_NEVER;		# Minimum log level.
my $LOG_MAX	 =  $LOG_ALWAYS;	# Maximum log level.

my $DEFAULT_LOGLEVEL = $LOG_INFO;	# Default log level.

sub LOG_NEVER		{ return($LOG_NEVER); };
sub LOG_TMI		{ return($LOG_TMI); };
sub LOG_EXPIRE		{ return($LOG_EXPIRE); };
sub LOG_INFO		{ return($LOG_INFO); };
sub LOG_PHASE		{ return($LOG_PHASE); };
sub LOG_ERR		{ return($LOG_ERR); };
sub LOG_FATAL		{ return($LOG_FATAL); };
sub LOG_ALWAYS		{ return($LOG_ALWAYS); };

sub LOG_DEFAULT		{ return($DEFAULT_LOGLEVEL); };

my $loglevel = $DEFAULT_LOGLEVEL;		# Rollerd's logging level.
my @logstrs =					# Valid strings for levels.
(
	"never",
	"tmi",
		undef,
	"expire",
	"info",
		undef,
	"phase",
		undef,
	"err",
	"fatal",
	"always"
);

my $logfile;					# rollerd's log file.

my $DEFAULT_LOGTZ = 'gmt';			# Default timezone.
my $usetz = $DEFAULT_LOGTZ;			# Timezone selector to use.



##############################################################################
#
# Routine:	rolllog_validlevel()
#
# Purpose:	Check if the given logging level is valid.  A boolean is
#		returned indicating if it is.
#
sub rolllog_validlevel
{
	my $level = shift;			# Logging level to check.
	my $ret;				# Return code.

	#
	# Do the Right Thing, depending on if the level is numeric or textual.
	#
	if($level =~ /^[\d]+$/)
	{
		$ret = rolllog_num($level);
		return(0) if($ret == -1);
	}
	else
	{
		$ret = rolllog_str($level);
		return(0) if(!defined($ret));
	}

	#
	# We're here, so *everything* is okay.
	#
	return(1);
}

##############################################################################
#
# Routine:	rolllog_level()
#
# Purpose:	Get/set the logging level.  If no arguments are given, then
#		the current logging level is returned.  If a valid new level
#		is given, that will become the new level.
#
#		If a problem occurs (invalid log level), then -1 will be
#		returned, unless a non-zero argument was passed for the
#		second argument.  In this case, a usage message is given and
#		the process exits.
#
sub rolllog_level
{
	my $newlevel = shift;			# New logging level.
	my $useflag  = shift;			# Usage-on-error flag.

	my $oldlevel = $loglevel;		# Current logging level.
	my $err = 0;				# Error flag.

	#
	# Return the current log level if that's all they want.
	#
	return($loglevel) if(!defined($newlevel));

	#
	# Translate the logging level to its numeric form.
	#
	$loglevel = rolllog_num($newlevel);

	#
	# If there was a problem, give usage messages and exit.
	#
	if($loglevel == -1)
	{
		if(!$useflag)
		{
			$loglevel = $oldlevel;
			return(-1);
		}

		err("unknown logging level \"$newlevel\"\n"		.
		    "valid logging levels (text and numeric forms):\n"	.
			"\ttmi		 1\n"				.
			"\texpire		 3\n"			.
			"\tinfo		 4\n"				.
			"\tphase	 6\n"				.
			"\terr		 8\n"				.
			"\tfatal		 9\n",-1);
		return(-1);
	}

	#
	# Return the old logging level.
	#
	return($oldlevel);
}

##############################################################################
#
# Routine:	rolllog_levels()
#
# Purpose:	Return the text forms of the valid log levels.  The levels
#		are returned in order, from most verbose to least.
#
sub rolllog_levels
{
	my @levels = ();				# Valid log levels.

	#
	# Create an array holding only the user-settable logging levels.
	#
	for(my $ind = ($LOG_NEVER+1); $ind < $LOG_ALWAYS; $ind++)
	{
		next if($logstrs[$ind] eq '');
		push @levels, $logstrs[$ind];
	}
	
	return(@levels);
}

##############################################################################
#
# Routine:	rolllog_gettz()
#
# Purpose:	Return the timezone function used for timestamps in log
#		messages.  'local' and 'gmt' are the acceptable values.
#
sub rolllog_gettz
{
	#
	# If the logging timezone hasn't been set yet, we'll set it to
	# the default value
	#
	if($usetz eq '')
	{
		$usetz = $DEFAULT_LOGTZ;
	}

	return($usetz);
}

##############################################################################
#
# Routine:	rolllog_settz()
#
# Purpose:	Set the timezone selector to use for timestamps in log
#		messages.  'local' and 'gmt' are the acceptable values.
#
sub rolllog_settz
{
	my $newtz = shift;				# New timezone.
	my $oldtz = $usetz;				# Old timezone.

	#
	# Ensure a valid timezone selector was given.  If no selector
	# was given, then we'll use the default.
	#
	if($newtz ne '')
	{
		return('') if(($newtz !~ /^gmt$/i) && ($newtz !~ /^local$/i));
	}
	else
	{
		$newtz = dnssec_tools_default('log_tz');
	}

	#
	# Set the timezone selector and return the old selector.
	#
	$usetz = lc $newtz;
	return($oldtz);
}

##############################################################################
#
# Routine:	rolllog_str()
#
# Purpose:	Return the text form of the specified log level.
#		undef is returned for bad levels.
#
sub rolllog_str
{
	my $level = shift;				# New logging level.

	#
	# Ensure a level was given.
	#
	return(undef) if(!defined($level));

	#
	# If log level isn't a numeric, we'll ensure that it's a valid
	# level string.
	#
	if($level =~ /[a-zA-Z]/)
	{
		my $lclev;				# Lowercase level.

		#
		# Convert the logging level to lowercase (for efficiency.)
		#
		$lclev = lc($level);

		foreach my $lstr (@logstrs)
		{
			return($lstr) if(lc($lstr) eq lc($lclev));
		}
		return(undef);
	}

	#
	# Check for out-of-bounds levels and return the text string.
	#
	return(undef) if(($level < $LOG_NEVER) || ($level > $LOG_ALWAYS));
	return($logstrs[$level]);
}

##############################################################################
#
# Routine:	rolllog_num()
#
# Purpose:	Translate a logging level to its numeric form.  The level
#		is also validated along the way.
#
sub rolllog_num
{
	my $newlevel = shift;				# New logging level.
	my $llev = -1;					# Level to return.

	#
	# If a non-numeric log level was given, translate it into the
	# appropriate numeric value.
	#
	if($newlevel !~ /^[0-9]+$/)
	{
		if($newlevel =~ /^tmi$/i)
		{
			$llev = LOG_TMI;
		}
		elsif($newlevel =~ /^expire$/i)
		{
			$llev = LOG_EXPIRE;
		}
		elsif($newlevel =~ /^info$/i)
		{
			$llev = LOG_INFO;
		}
		elsif($newlevel =~ /^phase$/i)
		{
			$llev = LOG_PHASE;
		}
		elsif($newlevel =~ /^err$/i)
		{
			$llev = LOG_ERR;
		}
		elsif($newlevel =~ /^fatal$/i)
		{
			$llev = LOG_FATAL;
		}
	}
	else
	{
		#
		# If a valid log level was given, make it the current level.
		#
		if(($newlevel >= $LOG_MIN) &&
		   ($newlevel <= $LOG_MAX) &&
		   defined($logstrs[$newlevel]))
		{
			$llev = $newlevel;
		}
	}

	#
	# Return the translated logging level.  Or an error.
	#
	return($llev);
}

##############################################################################
#
# Routine:	rolllog_file()
#
# Purpose:	Get/set the log file.  If no arguments are given, then
#		the current log file is returned.  If a valid new file
#		is given, that will become the new log file.
#
#		If a problem occurs (invalid log file), then -1 will be
#		returned, unless a non-zero argument was passed for the
#		second argument.  In this case, a usage message is given
#		and the process exits.
#
sub rolllog_file
{
	my $newlogfile = shift;				# Name of new logfile.
	my $useflag    = shift;				# Usage-on-error flag.

	my $oldlogfile = $logfile;			# Current logfile.

	#
	# Return the current log file if a log file wasn't given.
	#
	return($logfile) if(!defined($newlogfile));

	#
	# Allow "-" to represent stdout.
	#
	if($newlogfile eq "-")
	{
		$newlogfile = "/dev/stdout";
		if(! -e $newlogfile)
		{
			err("logfile \"$newlogfile\" does not exist\n",-1) if($useflag);
			return("");
		}
	}

	#
	# If a log file was specified, ensure it's a writable regular file.
	# If it isn't a regular file, ensure that it's one of the standard
	# process-output files.
	#
	if(-e $newlogfile)
	{
		if((! -f $newlogfile)			&&
		   (($newlogfile ne "/dev/stdout")	&&
		    ($newlogfile ne "/dev/tty")))
		{
			err("logfile \"$newlogfile\" is not a regular file\n",-1) if($useflag);
			return("");
		}
		if(! -w $newlogfile)
		{
			err("logfile \"$newlogfile\" is not writable\n",-1) if($useflag);
			return("");
		}
	}

	#
	# Open up the log file (after closing any open logs.)
	#
	$logfile = $newlogfile;
	close(LOG);
	open(LOG,">> $logfile") || die "unable to open \"$logfile\"\n";
	select(LOG);
	$| = 1;

	return($oldlogfile);
}

##############################################################################
#
# Routine:	rolllog_log()
#
sub rolllog_log
{
	my $lvl = shift;				# Message log level.
	my $fld = shift;				# Message field.
	my $msg = shift;				# Message to log.

	my $kronos;					# Current time.
	my $outstr;					# Output string.

	#
	# Don't give the message unless it's at or above the log level.
	#
	return if($lvl < $loglevel);

	#
	# Add an administrative field specifier if the field wasn't given.
	#
	$fld = "$fld: " if($fld ne "");

	#
	# Get the timestamp.
	#
	if($usetz eq 'local')
	{
		$kronos = localtime();
	}
	else
	{
		$kronos = gmtime();
	}
	$kronos =~ s/^....//;

	#
	# Build the output string.
	#
	chomp $msg;
	$outstr = "$kronos: $fld$msg";

	#
	# Write the message. 
	# 
	print LOG "$outstr\n";
}


1;

#############################################################################

=pod

=head1 NAME

Net::DNS::SEC::Tools::rolllog - DNSSEC-Tools rollover logging interfaces.

=head1 SYNOPSIS

  use Net::DNS::SEC::Tools::rolllog;

  @levels = rolllog_levels();

  $curlevel = rolllog_level();
  $oldlevel = rolllog_level("info");
  $oldlevel = rolllog_level(LOG_ERR,1);

  $curlogfile = rolllog_file();
  $oldlogfile = rolllog_file("-");
  $oldlogfile = rolllog_file("/var/log/roll.log",1);

  $loglevelstr = rolllog_str(8)
  $loglevelstr = rolllog_str("info")

  $ret = rolllog_num("info");

  $bool = rolllog_validlevel($newlevel);
  $bool = rolllog_validlevel(8);

  $curtz = rolllog_gettz();
  $oldtz = rolllog_settz('local');

  rolllog_log(LOG_INFO,"example.com","zone is valid");

=head1 DESCRIPTION

The B<Net::DNS::SEC::Tools::rolllog> module provides logging interfaces for
the rollover programs.  The logging interfaces allow log messages to be
recorded.  B<rollerd> must be running, as it is responsible for updating  
the log file.

Each log message is assigned a particular logging level.  The valid logging
levels are:

    text       numeric  meaning
    ----       -------  -------
    tmi           1     The highest level -- all log messages
			are saved.
    expire        3     A verbose countdown of zone expiration
			is given.
    info          4     Many informational messages are recorded.
    phase         6     Each zone's current rollover phase
			is given.
    err        	  8     Errors are recorded.
    fatal         9     Fatal errors are saved.

The levels include all numerically higher levels.  For example, if the log
level is set to B<phase>, then B<err> and B<fatal> messages will also be
recorded.

=head1 LOGGING INTERFACES

=over 4

=item I<rolllog_file(newfile,useflag)>

This routine sets and retrieves the log file for B<rollerd>.
The I<newfile> argument specifies the new log file to be set.  If I<newfile>
exists, it must be a regular file.

The I<useflag> argument is a boolean that indicates whether or not to give a
descriptive message if an invalid log file is given.  If I<useflag> is
true, the message is given and the process exits; if false, no message is
given.  For any error condition, an empty string is returned.

=item I<rolllog_gettz()>

This routine returns the timezone selector currently in use.  This value may
be either 'gmt' (for Greenwich Mean Time) or 'local' (for the host's local
time.)

=item I<rolllog_level(newlevel,useflag)>

This routine sets and retrieves the logging level for B<rollerd>.
The I<newlevel> argument specifies the new logging level to be set.
I<newlevel> may be given in either text or numeric form.

The I<useflag> argument is a boolean that indicates whether or not to give a
descriptive message and exit if an invalid logging level is given.  If
I<useflag> is true, the message is given and the process exits; if false, -1
is returned.

If given with no arguments, the current logging level is returned.  In fact,
the current level is always returned unless an error is found.  -1 is returned
on error.

=item I<rolllog_levels()>

This routine returns an array holding the text forms of the user-settable
logging levels.  The levels are returned in order, from most verbose to least.

=item I<rolllog_log(level,group,message)>

The I<rolllog_log()> interface writes a message to the log file.  Log
messages have this format:

	timestamp: group: message

The I<level> argument is the message's logging level.  It will only be written
to the log file if the current log level is numerically equal to or less than
I<level>.

I<group> allows messages to be associated together.  It is currently used by
B<rollerd> to group messages by the zone to which the message applies.

The I<message> argument is the log message itself.  Trailing newlines are
removed.

=item I<rolllog_num(loglevel)>

This routine translates a text log level (given in I<loglevel>) into the
associated numeric log level.  The numeric log level is returned to the caller.

If I<loglevel> is an invalid log level, -1 is returned.

=item I<rolllog_settz(tzsel)>

This routine sets the timezone to be used for timestamps in messages written
to the log.  This I<tzsel> value may be either 'gmt' (Greenwich Mean Time)
or 'local' (for the host's local time.)  I<tzsel> may be uppercase or
lowercase; the value will be converted to lowercase.  If no value is passed,
then the default will be used.

The current timezone selector is returned.  If an invalid selector is given,
then an undefined value is returned.

=item I<rolllog_str(loglevel)>

This routine translates a log level (given in I<loglevel>) into the associated
text log level.  The text log level is returned to the caller.

If I<loglevel> is a text string, it is checked to ensure it is a valid log
level.  Case is irrelevant when checking I<loglevel>.

If I<loglevel> is numeric, it is must be in the valid range of log levels.
I<undef> is returned if I<loglevel> is invalid.

=item I<rolllog_validlevel(level)>

This interface returns a boolean value indicating if the given logging level
is valid.

The I<level> argument is the logging level to be validated.  It may be a
numeric or textual value.

=back

=head1 COPYRIGHT

Copyright 2005-2014 SPARTA, Inc.  All rights reserved.
See the COPYING file included with the DNSSEC-Tools package for details.

=head1 AUTHOR

Wayne Morrison, tewok@tislabs.com

=head1 SEE ALSO

B<rollctl(1)>

B<rollerd(8)>

B<Net::DNS::SEC::Tools::rollmgr.pm(3)>

=cut
