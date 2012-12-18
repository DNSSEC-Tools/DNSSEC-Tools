#!/usr/bin/perl
#
# Copyright 2012 SPARTA, Inc.  All rights reserved.  See the COPYING
# file distributed with this software for details.
#
# owlutils.pm						Owl Monitoring System
#
#       This module contains routines used by the Owl sensor scripts.
#
# Revision History:
#	1.0	121201	Initial version.
#

package owlutils;

use strict;
require Exporter;

use POSIX;
use Log::Dispatch;
use Log::Dispatch::FileRotate;

#
# Version information.
#
my $NAME   = 'owlutils.pm';
my $VERS   = "$NAME version: 1.0";

our @ISA = qw(Exporter);


#------------------------------------------------------------------------
# Exported interfaces.
#

our @EXPORT = qw(
			owl_setup
			owl_chkdir
			owl_getpid
			owl_halt
			owl_printdefs
			owl_readconfig
			owl_running
			owl_setlog
			owl_singleton
			owl_writepid
		);


#------------------------------------------------------------------------
# Defaults and some constants.

my $NSBASE = 'root-servers.net';		# Base name for root servers.

our $DEF_ARCHDIR = "$FindBin::Bin/../old.data";	# Default archive directory.
our $DEF_CONFDIR = "$FindBin::Bin/../conf";	# Default config directory.
our $DEF_DATADIR = "$FindBin::Bin/../data";	# Default data directory.
our $DEF_LOGDIR	 = "$FindBin::Bin/../log";	# Default log directory.

our $DEF_CONFIG   = "owl.conf";			# Default config file.

#------------------------------------------------------------------------
#
# Constants for configuration data.
#

my $DEF_INTERVAL = 60;		# Default interval between transfers.
my $MIN_INTERVAL = 60;		# Minimum interval between transfers.

my $MININT	= 10;		# Minimum query interval.
my $DEF_QUINT	= 60;		# Default query interval.
				# Default query timeout is half query interval.

my $MINTO	= 5;		# Minimum query timeout.

#
# Amount of time between rolling the data files.
#
# my $DEF_ROLLINT = 60 * 60;		# Roll once per hour.
# my $DEF_ROLLINT = 60 * 30;		# Roll once every 30 minutes.
# my $DEF_ROLLINT = 60 * 20;		# Roll once every 20 minutes.
# my $DEF_ROLLINT = 60 * 15;		# Roll once every 15 minutes.

my $DEF_ROLLINT = 60 * 30;	#  XXX - testing

my $MIN_ROLLINT = 60 * 10;		#  Minimum file rollover interval.

#
# The default and valid DNS queries.
#
my $DEF_QUERYTYPE = 'A';
my %dnsqueries =
(
	'A'		=> 1,
	'AAAA'		=> 1,
	'ANY'		=> 1,
	'ANYCAST'	=> 1,
	'CNAME'		=> 1,
	'DNSKEY'	=> 1,
	'DS'		=> 1,
	'MX'		=> 1,
	'NS'		=> 1,
	'NSEC3'		=> 1,
	'RRSIG'		=> 1,
	'SOA'		=> 1,
	'TSIG'		=> 1,
	'TXT'		=> 1,
);

#------------------------------------------------------------------------
# Data.
#

my $progname;					# Program we're part of.
my $sensorlog;					# Sensor's log object.

my %owldaemons =				# Owl daemons.
(
	'owl-dnstimer'	=> 1,
	'owl-sensord'	=> 1,
	'owl-transfer'	=> 1,
);

#------------------------------------------------------------------------
# Shared data.
#

our $archdir = $DEF_ARCHDIR;		# Archive directory.
our $confdir = $DEF_CONFDIR;		# Configuration directory.
our $conffile;				# Configuration file.
our $datadir = $DEF_DATADIR;		# Data directory.
our $logdir  = $DEF_LOGDIR;		# Log directory.

our $transfer_interval = $DEF_INTERVAL;	# Actual transfer interval.

our @heartbeaturls = ();		# URLs for heartbeat to managers.
our $pidfile = '';			# Filename of process-id file.
our $sensorname = '';			# Name of this sensor.
our @sshusers = ();			# Users on managers that receive data.

our $dnstimerargs;			# Arguments for the owl-dnstimer daemon.
our $transferargs;			# Arguments for owl-transfer daemon.
our $admins = 'root';			# Administrator email.

our $hesitation;			# Sleep time between executions.
our $hibernation;			# Sleep time for minion xtn problems.
our $quickcount;			# Consecutive quick xtns before pausing.
our $quickseconds;			# Seconds that make a quick execution.

#----------------------------------------------------
# Exported fields from the Owl configuration file.
#

our @cf_targets	  = ();				# List of targets.
our @cf_servers	  = ();				# List of nameservers.
our @cf_qtypes	  = ();				# List of DNS query types.
our @cf_intervals = ();				# List of query intervals.
our @cf_timeouts  = ();				# List of query timeouts.
our @cf_rollints  = ();				# Datafile rollover interval.
our @cf_states	  = ();				# State of targets.

#----------------------------------------------------

our %loginfo = ();			# Logging information.

#===============================================================================
#
# Exported routines.
#

#------------------------------------------------------------------------
# Routine:	owl_setup()
#
# Purpose:	Initializes a few variables used by the rest of the module.
#
sub owl_setup
{
	my $pname = shift;			# Our program.
	my $cdir = shift;			# Configuration directory.
	my $ddir = shift;			# Data directory.
	my $ldir = shift;			# Log directory.

	#
	# Set the name of our program.
	#
	$progname = $pname;

	#
	# Set the directories as requested.
	#
	$confdir = $cdir if(defined($cdir) || ($cdir ne ''));
	$datadir = $ddir if(defined($ddir) || ($ddir ne ''));
	$logdir	 = $ldir if(defined($ldir) || ($ldir ne ''));

	#
	# Set the name of the pidfile we'll be using.
	#
	$pidfile = "$confdir/$progname.pid";
}

#------------------------------------------------------------------------
# Routine:	owl_halt()
#
# Purpose:	This routine will halt other instances of a given Owl sensor
#		program running.  The current process will not be HUP'd.
#
# Return Values
#		On error, zero is returned.
#		On success, the number of processes that were successfully
#		sent a SIGHUP is returned.
#
sub owl_halt
{
	my $target = shift;		# Program to kill.
	my $moi = $$;			# Our process id.
	my $cnt = 0;			# Count of halted processes.
	my $prevcnt = 0;		# Previous count of halted processes.

	#
	# Ensure we're only zapping our known programs.
	#
	return(0) if(!defined($owldaemons{$target}));

	#
	# Go through the list of running processes and send SIGHUP to any
	# with $target in the process list.
	#
	foreach my $sig (SIGHUP, SIGKILL)
	{
		my @psout;			# Output from ps.

		#
		# Get the running processes.
		#
		open(PS,"/bin/ps wax |");
		@psout = <PS>;
		close(PS);

		foreach my $psline (@psout)
		{
			my $pid;		# Process id from ps line.
			my $cmd;		# Command line from ps line.

			#
			# Get the process id and command line from the
			# ps output line.
			#
			$psline =~ /^\s*(\d+)\s+\S+\s+\S+\s+\S+\s+(.+)$/;
			$pid = $1;
			$cmd = $2;

			#
			# Skip this line if it doesn't contain the caller's
			# target.
			#
			next if($cmd !~ /$target/);

			#
			# Skip this line if it's our own process.
			#
			next if($pid == $moi);

			#
			# Send SIGHUP to the process and increment our count
			# of hup'd processes.
			#
			if(kill($sig,$pid) > 0)
			{
				$cnt++;
			}
		}

		#
		# Drop out if we there isn't anything else to signal.
		#
		last if($cnt == $prevcnt);
		$prevcnt = $cnt;

		#
		# Give things a moment to deal with the signal.
		#
		sleep(1);
	}

	#
	# Return the number of processes we successfully signaled.
	#
	return($cnt);
}

#------------------------------------------------------------------------
# Routine:	owl_printdefs()
#
# Purpose:	Print query defaults and exit.
#
sub owl_printdefs
{
	print "default archive directory             $DEF_ARCHDIR\n";
	print "default config directory              $DEF_CONFDIR\n";
	print "default data directory                $DEF_DATADIR\n";
	print "default log directory                 $DEF_LOGDIR\n";
	print "default config file                   $DEF_CONFIG\n";
	print "\n";
	print "default query interval                $DEF_QUINT\n";
	print "minimum query interval                $MININT\n";
	print "minimum query timeout                 $MINTO\n";
	print "default query type                    $DEF_QUERYTYPE\n";
	print "default datafile rollover interval    $DEF_ROLLINT\n";
	print "minimum datafile rollover interval    $MIN_ROLLINT\n";
	print "default interval between transfers    $DEF_INTERVAL\n";
	print "minimum interval between transfers    $MIN_INTERVAL\n";

	exit(0);
}

#------------------------------------------------------------------------
# Routine:	owl_readconfig()
#
# Purpose:	Parse an Owl sensor configuration file, building a set of
#		variables along the way.
#
sub owl_readconfig
{
	my $config = shift;			# Configuration file.
	my $ddir   = shift;			# Data directory.
	my $ldir   = shift;			# Log directory.

	my $errs   = 0;				# Error count.

	#
	# Ensure the config file exists.
	#
	$conffile = $config;
	if(! -e $config)
	{
		print STDERR "owl_readconfig:  config file \"$config\" does not exist\n";
		return(1);
	}

	#
	# Ensure the config file exists.
	#
	if(open(CONF,"< $config") == 0)
	{
		print STDERR "owl_readconfig:  unable to open config file \"$config\"\n";
		return(1);
	}

	#
	# Go through each line of the config file.
	#
	while(<CONF>)
	{
		my $line = $_;			# Config line.
		my @atoms;			# Pieces of config line.

		#
		# Massage the line a little.  Get rid of the trailing newline,
		# any leading spaces, and collapse whitespace to a single space.
		#
		chomp $line;
		$line =~ s/^\s+//g;
		$line =~ s/\s+/ /g;

		#
		# Skip comment and blank lines.
		#
		next if(($line =~ /^\#/) || ($line eq ''));

		#
		# Split the line into its pieces.
		#
		@atoms = split / /, $line;

		#
		# Look at the line's keyword to figure out what it's for.
		#	data    - parameter for data storage
		#	log     - parameter for logging
		#	manager - data about the managers
		#	sensor  - data about the sensor
		#	target  - defines a field for a target/nameserver pair
		#
		if($atoms[0] =~ /^query$/)
		{
			$errs += conf_queryline(@atoms);
		}
		elsif($atoms[0] =~ /^data$/i)
		{
			$errs += conf_dataline($ddir,@atoms);
		}
		elsif($atoms[0] =~ /^log$/i)
		{
			$errs += conf_logline($ldir,@atoms);
		}
		elsif($atoms[0] =~ /^manager$/i)
		{
			$errs += conf_mgrline(@atoms);
		}
		elsif($atoms[0] =~ /^sensor$/i)
		{
			$errs += conf_sensorline(@atoms);
		}
		else
		{
			print STDERR "owl_readconfig:  unrecognized config line: \"$line\"\n";
		}
	}

	close(CONF);

	#
	# Check the configuration values to make sure they're okay.
	#
	for(my $ind=0; $ind < @cf_targets; $ind++)
	{
		my $eid;			# Entry's identifier.
		my $interval;			# Root's query interval.
		my $rollint;			# Root's rollover interval.
		my $timeout;			# Root's query timeout.

		#
		# Get shortcuts for the values.
		#
		$eid = "$cf_targets[$ind]/$cf_servers[$ind]";
		$interval = $cf_intervals[$ind];
		$rollint  = $cf_rollints[$ind];
		$timeout  = $cf_timeouts[$ind];

		#
		# Get the query interval and ensure it's okay.
		#
		if($interval < $MININT)
		{
			print STDERR "$eid:  invalid query interval \"$interval\"; it must be $MININT or greater\n";
			$errs++;
			$cf_states[$ind] = 0;
		}

		#
		# Get the query timeout and ensure it's okay.
		#
		if($timeout < $MINTO)
		{
			print STDERR "$eid:  invalid query timeout \"$timeout\"; it must be $MINTO or greater\n";
			$errs++;
			$cf_states[$ind] = 0;
		}
		if($timeout >= $interval)
		{
			print STDERR "$eid:  invalid query timeout \"$timeout\"; it must be less than the interval ($interval)\n";
			$errs++;
			$cf_states[$ind] = 0;
		}

		#
		# Get the rollover interval and ensure it's okay.
		#
		if($rollint < $MIN_ROLLINT)
		{
			print STDERR "$eid:  invalid rollover interval \"$rollint\"; it must be $MIN_ROLLINT or greater\n";
			$errs++;
			$cf_states[$ind] = 0;
		}

	}

	#
	# Command-line values take precedence over config-file values.
	#
	$datadir = $DEF_DATADIR if(!defined($datadir));
	$datadir = $ddir if(defined($ddir));
	$logdir  = $DEF_LOGDIR if(!defined($logdir));
	$logdir  = $ldir if(defined($ldir));

	#
	# Bail on errors.
	#
	if($errs)
	{
		print STDERR "configuration errors:  $errs found\n";
	}

	return($errs);
}

#------------------------------------------------------------------------
# Routine:	owl_running()
#
# Purpose:	This routine returns a boolean indicating if the named
#		Owl sensor program is running.
#
sub owl_running
{
	my $prog  = shift;			# Owl program to check.
	my $curpf;				# Current pid file.

	$curpf = "$confdir/$prog.pid";
	return(running($curpf));
}

#------------------------------------------------------------------------
# Routine:	owl_setlog()
#
# Purpose:	This routine initializes logging for an Owl sensor program.
#
sub owl_setlog
{
	my $pname = shift;			# Program's hostname.
	my $newlogdir = shift;			# New log directory (optional.)
	my $hostname = `hostname`;		# Sensor's hostname.
	my @chron;				# Current times.
	my $tstmp;				# Timestamp for logname.

	#
	# Get the sensor's hostname.
	#
	$hostname = `hostname`;
	chomp $hostname;

	#
	# Build the timestamp to be added to the log's name.
	#
	@chron = gmtime();
	$tstmp = sprintf("%02d%02d%02d", $chron[5] % 100,
					 $chron[4] + 1,
					 $chron[3]);

	#
	# Get the (optional) new logging directory.
	#
	$logdir = $newlogdir if(defined($newlogdir));

	#
	# Set up the logging directory and file.
	#
	$loginfo{logdir} = $logdir;
	$loginfo{logfile} ||= "$progname-$tstmp.log";

	#
	# Set up the log handler...
	#
	$sensorlog = new Log::Dispatch(
		callbacks => sub
		     {
				my %h = @_;
				my $msg;

				$msg = Date::Format::time2str('%B %e %T', time);
				$msg .= " $hostname $progname: $h{message}\n";

				return($msg);
		     }
	);

	#
	# Build the name of the log file we'll be using.
	#
	$loginfo{filename} = File::Spec->catfile($loginfo{logdir},$loginfo{logfile});

	#
	# ... and make sure the log will rotate periodically.
	#
	$sensorlog->add(Log::Dispatch::FileRotate->new(
					name      => "$pname logfile",
					min_level => 'debug',
					mode      => 'append',
					filename  => "$loginfo{filename}",
					size      => 2000000,
					max	  => 60)
		       );

	#
	# Let the caller use our log.
	#
	return($sensorlog);
}

#------------------------------------------------------------------------
# Routine:	owl_singleton()
#
# Purpose:	This routine will ensure that there's only one instance
#		of a given Owl sensor program running.  If the argument
#		is non-zero, we'll exit if another instance is running.
#
sub owl_singleton
{
	my $exitflag  = shift;			# Exit-on-multiples flag.

	#
	# Make sure we have no doppelganger.
	#
	if((my $pid = running()) > 0)
	{
		exit(2) if($exitflag);
		return(0);
	}

	#
	# Let the log know we're starting.
	#
	if($sensorlog)
	{
		$sensorlog->warning("-" x 36);
		$sensorlog->warning("$progname starting");
	}

	#
	# Our caller might also want to know we're starting.
	#
	return(1);
}

#------------------------------------------------------------------------
# Routine:	owl_getpid()
#
# Purpose:	Return the contents of the pidfile.
#
sub owl_getpid
{
	my $pid;				# Process' id.

	if(open(PIDFILE,"< $pidfile") == 0)
	{
		print STDERR "$NAME:  unable to open $pidfile - $!\n";
		return(-1);
	}

	$pid = <PIDFILE>;
	close(PIDFILE);

	chomp $pid;
	return($pid);
}

#------------------------------------------------------------------------
# Routine:	owl_writepid()
#
# Purpose:	Write the pidfile.  Complain if we can't write it.
#
sub owl_writepid
{
	my $pid = $$;				# Process id.

	if(open(PIDFILE,"> $pidfile") == 0)
	{
		print STDERR "$NAME:  unable to create $pidfile - $!\n";
		return(1);
	}

	print PIDFILE "$pid\n";
	close(PIDFILE);

	return(0);
}

#------------------------------------------------------------------------
# Routine:	owl_chkdir()
#
# Purpose:	Ensure a specified directory exists.
#
sub owl_chkdir
{
	my $dirtype = shift;				# Type of directory.
	my $dir = shift;				# Directory to check.

	if($dir eq '')
	{
		return(0);
	}

	#
	# Make the directory if it doesn't exist.
	# If it does, make sure we can use it.
	#
	if(! -e $dir)
	{
		if(mkdir($dir) == 0)
		{
			print STDERR "unable to create $dirtype directory \"$dir\"\n";
			return(1)
		}
	}
	elsif((! -w $dir) ||
	      (! -x $dir) ||
	      (! -d $dir))
	{
		print STDERR "bad $dirtype directory \"$dir\"\n";
		return(1);
	}

	return(0);
}

#===============================================================================
#
# Un-exported routines.
#

#------------------------------------------------------------------------
# Routine:	conf_dataline()
#
# Purpose:	Handle a "data" line from the config file.
#
#		Type data config values:
#			0 - "data" (keyword)
#			1 - field keyword
#			2 - value
#
#
sub conf_dataline
{
	my $ddir  = shift;		# Directory maybe from command line.
	my @atoms = @_;			# Components of the data config line.
	my $atoms = @atoms;		# Count of line's atoms.

	#
	# Ensure we've got enough fields.
	#
	if($atoms < 2)
	{
		print STDERR "no values given for \"data\" line\n";
		return(1);
	}

	#
	# Get the data directory value and ensure it exists and is usable.
	# We'll only pick this up if it wasn't specified on the command line.
	#
	if($atoms[1] =~ /^dir$/)
	{
		#
		# Command-line options override the config file.
		#
		return(0) if(defined($ddir));

		$datadir = $atoms[2];
	}
	if($atoms[1] =~ /^archive$/)
	{
		$archdir = $atoms[2];
	}
	elsif($atoms[1] =~ /^interval$/)
	{
		$transfer_interval = $atoms[2];
		if($transfer_interval < $MIN_INTERVAL)
		{
			print STDERR "data transfer interval ($transfer_interval) is less than minimum allowed ($MIN_INTERVAL)\n";
			return(1)
		}
	}

	return(0);
}

#------------------------------------------------------------------------
# Routine:	conf_logline()
#
# Purpose:	Handle a "log" line from the config file.
#
#		Type log config values:
#			0 - "log" (keyword)
#			1 - field keyword
#			2 - value
#
#
sub conf_logline
{
	my $ldir  = shift;		# Directory maybe from command line.
	my @atoms = @_;			# Components of the log config line.
	my $atoms = @atoms;		# Count of line's atoms.

	#
	# Ensure we've got enough fields.
	#
	if($atoms < 2)
	{
		print STDERR "no values given for \"log\" line\n";
		return(1);
	}

	#
	# Get the log directory value and ensure it exists and is usable.
	# We'll only pick this up if it wasn't specified on the command line.
	#
	if($atoms[1] =~ /^dir$/i)
	{
		#
		# Command-line options override the config file.
		#
		return(0) if(defined($ldir));

		$logdir = $atoms[2];
	}

	return(0);
}

#------------------------------------------------------------------------
# Routine:	conf_mgrline()
#
# Purpose:	Handle a "manager" line from the config file.
#
#		Type manager config values:
#			0 - "manager" (keyword)
#			1 - field keyword
#			2 - value
#
#
sub conf_mgrline
{
	my @atoms = @_;			# Components of the manager config line.
	my $atoms = @atoms;		# Count of line's atoms.
	my $keyword;			# Line's field keyword.

	#
	# Ensure we've got enough fields.
	#
	if($atoms < 2)
	{
		print STDERR "no values given for \"manager\" line\n";
		return(1);
	}

	#
	# We don't need the line keyword, but we do need the field keyword.
	#
	shift @atoms;
	$keyword = shift @atoms;

	#
	# Pull out the value.
	#
	if($keyword =~ /^heartbeat$/i)
	{
		push @heartbeaturls, $atoms[0];
	}
	elsif($keyword =~ /^ssh-user$/i)
	{
		push @sshusers, join(' ', @atoms);
	}
	else
	{
		print STDERR "invalid keyword given for \"manager\" line\n";
		return(1);
	}

	return(0);
}

#------------------------------------------------------------------------
# Routine:	conf_sensorline()
#
# Purpose:	Handle a "sensor" line from the config file.
#
#		Type sensor config values:
#			0 - "sensor" (keyword)
#			1 - field keyword
#			2 - value
#
#
sub conf_sensorline
{
	my @atoms = @_;			# Components of the sensor config line.
	my $atoms = @atoms;		# Count of line's atoms.
	my $keyword;			# Line's field keyword.

	#
	# Ensure we've got enough fields.
	#
	if($atoms < 2)
	{
		print STDERR "no values given for \"sensor\" line\n";
		return(1);
	}

	#
	# We don't need the line keyword, but we do need the field keyword.
	#
	shift @atoms;
	$keyword = shift @atoms;

	#
	# Pick up one of the three sensor configuration values.
	#
	if($keyword =~ /^name$/i)
	{
		$sensorname = $atoms[0];
	}
	elsif($keyword =~ /^dnstimerargs$/i)
	{
		$dnstimerargs = join(' ', @atoms);
	}
	elsif($keyword =~ /^transferargs$/i)
	{
		$transferargs = join(' ', @atoms);
	}
	elsif($keyword =~ /^admin$/i)
	{
		$admins = join(' ', @atoms);
	}
	elsif($keyword =~ /^hesitation$/i)
	{
		$hesitation = $atoms[0];
	}
	elsif($keyword =~ /^hibernation$/i)
	{
		$hibernation = $atoms[0];
	}
	elsif($keyword =~ /^quickcount$/i)
	{
		$quickcount = $atoms[0];
	}
	elsif($keyword =~ /^quickseconds$/i)
	{
		$quickseconds = $atoms[0];
	}
	else
	{
		print STDERR "unknown keyword given for \"sensor\" line:  $keyword\n";
		return(1);
	}

	return(0);
}

#------------------------------------------------------------------------
# Routine:	conf_queryline()
#
# Purpose:	Handle a "query" line from the config file.
#
#		Type target config values:
#			0 - "query" (keyword)
#			1 - hostname of target
#			2 - nameserver to query for target
#			3 - type of query (optional)
#			4 - keyword (optional)
#			5 - value (optional)
#
sub conf_queryline
{
	my @atoms = @_;			# Components of the log config line.
	my $atoms = @atoms;		# Count of line's atoms.

	my $target;			# Target name.
	my $nsname;			# Nameserver's name.
	my $qtype;			# Query type.
	my $interval;			# Entry's query interval.
	my $timeout;			# Entry's query timeout.
	my $rollint;			# Datafile rollover interval.

	#
	# Ensure we've got at least target and nameserver names for this entry.
	#
	if($atoms < 2)
	{
		print STDERR "owl_readconfig:  no target or nameserver given for \"target\" line\n";
		return(1);
	}
	elsif($atoms < 3)
	{
		print STDERR "owl_readconfig:  no nameserver name given for \"target\" line\n";
		return(1);
	}

	#
	# Get the target.
	#
	shift @atoms;
	$target = shift @atoms;

	#
	# Get the nameserver and ensure it's okay.
	#
	$nsname = shift @atoms;
	$nsname = "$nsname.$NSBASE" if($nsname =~ /^[a-m]$/i);

	#
	# Get the query type and ensure it's okay.
	#
	if(@atoms > 0)
	{
		$qtype = shift @atoms;
		$qtype = uc($qtype);
		if(! defined($dnsqueries{$qtype}))
		{
			print STDERR "owl_readconfig:  invalid query type \"$qtype\" for $target:$nsname target\n";
			return(1);
		}
	}

	#
	# Pick up the rest of the arguments.
	#
	$interval = shift @atoms if(@atoms > 0);
	$timeout  = shift @atoms if(@atoms > 0);
	$rollint  = shift @atoms if(@atoms > 0);

	#
	# Account for default query type and missing query type.
	#
	if(($qtype eq '') || ($qtype eq '-'))
	{
		$qtype = $DEF_QUERYTYPE;
	}

	#
	# Account for default interval and missing interval.
	#
	if(($interval eq '') || ($interval eq '-'))
	{
		$interval = $DEF_QUINT;
	}

	#
	# Account for default timeout and missing timeout.
	#
	if(($timeout eq '') || ($timeout eq '-'))
	{
		$timeout  = $interval / 2;
	}

	#
	# Account for default rollover interval and missing rollover interval.
	#
	if(($rollint eq '') || ($rollint eq '-'))
	{
		$rollint  = $DEF_ROLLINT;
	}
	else
	{
		$rollint *= 60;
	}

	#
	# Save the data for this entry.
	#
	push @cf_targets, $target;
	push @cf_servers, $nsname;
	push @cf_qtypes,  $qtype;
	push @cf_intervals, $interval;
	push @cf_timeouts,  $timeout;
	push @cf_rollints,  $rollint;
	push @cf_states, 1;

	return(0);
}

#------------------------------------------------------------------------
# Routine:	running()
#
# Purpose:	Check if another instance of a program is running.  If so,
#		we'll return the pid of that instance.  If not, return zero.
#		We check the running status by sending it signal 0.
#
# Return Values:
#		-1	pidfile is not readable
#		0	program isn't running    (pidfile doesn't exist OR
#						  pidfile contains stale pid)
#		pid	program is running
#
sub running
{
	my $pf = shift;				# Pid file to check.
	my $opid;				# Process id in file.

	#
	# Get the pidfile to check.  If we weren't passed one, we'll use
	# the currently defined pidfile; otherwise, we'll use what we were
	# given.
	#
	$pf = $pidfile if(! defined($pf));

	#
	# If the pidfile doesn't exist, we'll assume we aren't running already.
	#
	return(0) if(! -e $pf);

	#
	# Ensure the pidfile is readable.
	#
	if(! -r $pf)
	{
		print STDERR "$progname:  pidfile $pf is not readable\n";
		return(-1);
	}

	#
	# Get the pid from the pidfile.
	#
	$opid = `cat $pf`;
	chomp $opid;

	#
	# If the pidfile exists, we'll check try to send it a signal to
	# see if it's still alive.  If the pid is an active process, we'll
	# return the process' id.  Otherwise, we'll return 0.
	#
	return($opid) if(kill(0,$opid) == 1);
	return(0);
}

1;

#--------------------------------------------------------------------------

=pod

=head1 NAME

owlutils - Utility routines for Owl sensor programs.

=head1 SYNOPSIS

  use owlutils;

  owl_setup('owl-dnstimer', 'conf', 'data-2011', 'logfiles');

  owl_readconfig('owl.conf',undef,'log-data');

  owl_running('owl-sensord');

  owl_singleton($exitflag);

  owl_chkdir('archive','oldfiles');

  owl_setlog('owl-dnstimer');

  owl_getpid();

  owl_writepid();

  owl_halt('owl-dnstimer');

  owl_printdefs();

=head1 DESCRIPTION

The B<owlutils.pm> module provides a set of common routines for the Owl sensor
programs.  These routines provide for a variety of things, such as program
initialization, ensuring only one instance of a particular program is running,
manipulation of process-id files.

=head1 DEFAULTS

The B<owlutils.pm> module contains definitions for several defaults used by
the Owl sensor programs.  There are externally available defaults and
internal-only defaults.

=head2 External Defaults

Externally available defaults may be referenced in this manner:

    $owlutils::DEF_DATADIR

The default directories are relative to the B<bin> directory from which the Owl
programs are executed.  The B<FindBin.pm> Perl module is used to locate this
starting-point directory.

  DEF_ARCHDIR   "$FindBin::Bin/../old.data"  Default archive directory.
  DEF_CONFDIR   "$FindBin::Bin/../conf"      Default config directory.
  DEF_DATADIR   "$FindBin::Bin/../data"      Default data directory.
  DEF_LOGDIR    "$FindBin::Bin/../log"       Default log directory.

  DEF_CONFIG    "owl.conf"                   Default config file.


=head2 Internal Defaults

Internal-only defaults are used by B<owlutils.pm> for such cases as providing
default values for configuration entries.  As the name implies, these are
not available outside B<owlutils.pm>.

  Default interval between transfers       60 seconds
  Minimum interval between transfers       60 seconds

  Default query interval                   60 seconds
  Minimum query interval                   10 seconds

  Default query timeout is half the query interval.
  Minimum query timeout                    60 seconds

  Minimum file rollover interval           10 minutes

  Default DNS query type                   A records

=head1 CONFIGURATION FILE DATA

The data from the parsed Owl configuration file may be referenced externally
to B<owlutils.pm>.  Most of the fields are independent, but several arrays are
tied together.

Most of these configuration data may be referenced in this manner:

    $owlutils::confdir
    @owlutils::heartbeaturls

=head2 Associated Arrays

The associated arrays of Owl configuration data hold the contents of the
I<query> lines from the configuration file.  They are associated in that
a particular I<query> line has its data distributed across the arrays all
at the same index.  Therefore, I<$cf_servers[4]> holds a datum for the same
I<query> line as I<$cf_targets[4]> and I<$cf_qtypes[4]>.  If a I<query>
line does not contain data fields for each array, then a default value
will be used.  

Data set from a I<query> line:

    @cf_targets	             List of targets.
    @cf_servers	             List of nameservers.
    @cf_qtypes	             List of DNS query types.
    @cf_intervals            List of query intervals.
    @cf_timeouts             List of query timeouts.
    @cf_rollints             Datafile rollover interval.

Data set according to the validity of the associated I<query> line:

    @cf_states	             State of targets.

=head2 Independent Data

The independent configuration data are, roughly speaking, unrelated to each
other.

Data specified by calling programs or built by B<owlutils.pm>:

    $archdir                 Archive directory.
    $confdir                 Configuration directory.
    $conffile                Configuration file.
    $datadir                 Data directory.
    $logdir                  Log directory.
    $pidfile                 Filename of process-id file.

    $hesitation              Sleep time between executions.
    $hibernation             Sleep time for minion execution problems.
    $quickcount              Consecutive quick executions before pausing.
    $quickseconds            Seconds that make a quick execution.

Data specified on a I<sensor> line:

    $admins                  Administrator email addresses.
    $dnstimerargs            Arguments for the owl-dnstimer daemon.
    $sensorname              Name of this sensor.
    $transferargs            Arguments for owl-transfer daemon.

Data specified on a I<data> line:

    $datadir                 Data directory.
    $transfer_interval       Actual transfer interval.

Data specified on a I<log> line:

    $logdir                  Log directory.

Data specified on a I<manager> line:

    @heartbeaturls           URLs for heartbeat to managers.
    @sshusers                Users on managers that receive data.

=head1 INTERFACES

=over 4

=item I<owl_chkdir(dirtype,dir)>

I<owl_chkdir()> will ensure that the specified directory I<dir> exists.  If
it doesn't exist, I<owl_chkdir()> will attempt to create the directory.  If
it does exist, I<owl_chkdir()> will ensure that it is a writable, searchable
directory.

The I<dirtype> parameter gives a little information about the named directory
and is only used in error messages.

Return Values:

    0 - The directory is a writable, searchable directory.
	This return value is also given if no directory name
	is specified.
    1 - The directory could not be created.  This is also given
	if the directory name was not a directory, was not
	searchable, or was not writable.

=item I<owl_getpid()>

I<owl_getpid()> will return the process id stored in the process-id file
for the running Owl program.  If it couldn't open the file, then -1 will
be returned.

=item I<owl_halt(progname)>

I<owl_halt()> will halt all instances of the named Owl sensor program.  It
tries to send SIGHUP to the program and reports the success or failure of
the attempt.

This assumes that SIGHUP will (soon) cause the named program to stop execution.

Return Values:

    0 - Unable to halt the specified program.  This is also used
        if a non-Owl program is named.
    >0 - Program halted; the count of halted programs is returned.

=item I<owl_printdefs()>

This routine prints the default values used by this module, then it exits.

=item I<owl_readconfig(config,datadir,logdir)>

I<owl_readconfig()> reads an Owl configuration file and parses its contents.
Several classes of configuration data are available.

Data constructed at program compile-time:

    $owlutils::confdir  - Owl configuration directory
    $owlutils::conffile - Owl configuration file
    $owlutils::logdir   - log directory
    $owlutils::pidfile  - program's process-id file
    %owlutils::loginfo  - log file information

Data from "sensor" lines:

    $owlutils::admins       - email addresses for Owl administrators
    $owlutils::dnstimerargs - arguments for the owl-dnstimer daemon
    $owlutils::hesitation   - time between Owl daemon executions
    $owlutils::hibernation  - sleep time upon execution problems
    $owlutils::quickcount   - count of quick executions before
			      pausing
    $owlutils::quickseconds - seconds count that makes a quick
			      execution
    $owlutils::sensorname   - name of this sensor
    $owlutils::transferargs - arguments for the owl-transfer daemon

Data from "data" lines:

    $owlutils::datadir           - data directory
    $owlutils::transfer_interval - transfer interval

Data from "manager" lines:

    @owlutils::heartbeaturls - URLs  for sending heartbeats to
			       managers
    @owlutils::sshusers      - contact info for transferring data
			       to managers

Data from "query" lines:

    @owlutils::cf_intervals - query intervals from "query" lines
    @owlutils::cf_qtypes    - DNS query types from "query" lines
    @owlutils::cf_rollints  - interval from "query" lines
    @owlutils::cf_servers   - nameservers from "query" lines
    @owlutils::cf_states    - targets from "query" lines
    @owlutils::cf_targets   - targets from "query" lines
    @owlutils::cf_timeouts  - query timeouts from "query" lines

See B<owl-config(5)> for a definition of the configuration file's format.

I<config> is the name of the configuration file to read.

The I<datadir> parameter is assumed to be the data directory given as a
command-line option.  If none was given, this should be undefined.  If a data
directory wasn't specified on the command line nor in the configuration file,
then a default value is used.

The I<logdir> parameter is assumed to be the log directory given as a
command-line option.  If none was given, this should be undefined.  If a log
directory wasn't specified on the command line nor in the configuration file,
then a default value is used.

Blank lines and lines starting with a pound sign are ignored.

The return value is the number of errors encountered when reading and parsing
the configuration file.  Calling programs should not trust an Owl sensor
configuration data if any errors were encountered while reading the
configuration file.

=item I<owl_running(progname)>

This interface returns a boolean value indicating if the Owl sensor program
named I<progname> is executing.  This is determined by checking for a
process-id file in the configuration directory and then checking if the
program is running.  Signal 0 is sent to the process id to determine if the
program is running.

Return Values:

    0 - The program does not have a process-id file.
	Signal 0 could not be sent to the program.
    1 - Signal 0 was successfully sent to the process id.

=item I<owl_setlog(progname)>

This routine initializes logging for an Owl sensor program.  The log file will
be rotated when it reaches a size of 2MB, and a maximum of 60 files will be
kept.  The %loginfo hash is given values for the log file name and location.

The name of the log file has this format:

    <logdir>/<progname>-YYMMDD.log

The Log::Dispatch object used to manage the log file is returned.

=item I<owl_setup(progname, configdir, datadir, logdir)>

This routine initializes a few variables used by the rest of this module.
It should be called prior to any of the other routines.

The variable naming the program's process-id file will be built, following
this format:

        <configdir>/<progname>.pid

I<progname> is the name of the program calling I<owl_setup()>.

I<configdir> is the name of the configuration directory.  If this is
undefined, then the default value will be used.

I<datadir> is the name of the data directory.  If this is undefined, then the
default value will be used.

I<logdir> is the name of the log directory.  If this is undefined, then the
default value will be used.

=item I<owl_singleton(exitflag)>

I<owl_singleton()> ensures that there's only one instance of the calling Owl
sensor program is running.  (The program name is taken from the I<progname>
argument passed to a prior invocation of I<owl_setup()>.)  If the argument is
non-zero the calling program will exit if another instance is running.

Return Values:

    0 - Another Owl sensor program with the same name is running.
    1 - Another Owl sensor program with the same name is not running.

=item I<owl_writepid()>

This routine creates a new process-id file for the calling program and writes
the process id to the file.

Return Values:

    0 - The process-id file was created and the process id written
	to the file.
    1 - The process-id file could not be created.

=back

=head1 SEE ALSO

B<owl-dnstimer(1)>,
B<owl-sensord(1)>

B<FindBin(3pm)>

B<owl-config(5)>,
B<owl-data(5)>

=head1 COPYRIGHT

Copyright 2012 SPARTA, Inc.  All rights reserved.

=head1 AUTHOR

Wayne Morrison, tewok@tislabs.com

=cut

