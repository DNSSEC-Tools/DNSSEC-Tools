#
# Copyright 2005-2006 SPARTA, Inc.  All rights reserved.  See the COPYING
# file distributed with this software for details
#
# DNSSEC Tools
#
# rollmgr.pm -	Roll-over manager functions.
#
#	The routines in this module provide a means to communicate with
#	rollerd.
#
#
#	Introduction
#		This module provides interfaces for communicating with the
#		DNSSEC-Tools' roll-over manager.  The top-level interfaces
#		are independent of the host Operating System, but the actual
#		operations are dependent upon the host O/S.
#
#		To allow similar O/Ses to share switch functions, thus
#		minimizing the size of the module, the rollmgr_prepdep()
#		routine determines which operating system class an operating
#		system falls into.  This determination is based upon the O/S
#		name, as taken from $^O.
#
#		This module has been ported to:
#
#			O/S name	O/S class
#			FreeBSD		Unix
#
#		When extending the interface or porting this module to another
#		O/S, the following entities must be modified as described
#		below.  The Unix switches may be used as a model.
#		
#
#	Port architecture hash
#		This hash table associates an operating-system class with
#		a switch hash.  The class (determined in rollmgr_prepdep())
#		is the hash key, with its associated switch hash as the
#		hash value.
#		The port architecture hash need not be updated when the
#		interface is extended.
#		The port architecture hash must be updated when the module
#		is ported to a new operating system.
#
#	Switch hashes
#		The switch hashes contain references to the different
#		platforms supported by this module.
#		Each switch hash must be updated when the interface
#		is extended.
#		The existing switch hashes need not be updated when
#		the module is ported to a new operating system.
#
#	Uninitialized switch functions
#		These interfaces are called when the switch table has not
#		yet been initialized.
#		These switch functions must be updated when the interface
#		is extended.
#		These switch functions need not be updated when the module
#		is ported to a new operating system.
#
#	Unknown switch functions
#		These interfaces are called when rollmgr.pm has not been
#		ported to the host operating system.  Unrecognized operating
#		systems will cause the module's calling process to exit.
#		These switch functions must be updated when the interface
#		is extended.
#		These switch functions need not be updated when the module
#		is ported to a new operating system.
#
#	Top-level interfaces
#		The top-level interfaces are O/S-independent front-ends to
#		the O/S-dependent routines.  These interfaces perform
#		these functions:
#			- look up their name in the switch table (%switchtab)
#			- call their associated O/S-dependent routine
#			- return the O/S-dependent routine's results
#		These switch functions must be updated when the interface
#		is extended.
#		These switch functions need not be updated when the module
#		is ported to a new operating system.
#
#

package Net::DNS::SEC::Tools::rollmgr;

require Exporter;
use strict;

use Fcntl ':flock';
use Socket;

our $VERSION = "0.01";

our @ISA = qw(Exporter);

our @EXPORT = qw(
		 rollmgr_cmdint
		 rollmgr_dir
		 rollmgr_dropid
		 rollmgr_getid
		 rollmgr_halt
		 rollmgr_idfile
		 rollmgr_loadzone
		 rollmgr_rmid
		 rollmgr_saveid

		 rollmgr_log
		 rollmgr_logfile
		 rollmgr_loglevel
			 LOG_NEVER
			 LOG_TMI
			 LOG_EXPIRE
			 LOG_INFO
			 LOG_CURPHASE
			 LOG_ERR
			 LOG_FATAL
			 LOG_ALWAYS
			 LOG_DEFAULT

		 rollmgr_channel
		 rollmgr_sendcmd
		 rollmgr_getcmd
		 rollmgr_verifycmd
			 ROLLCMD_LOGFILE
			 ROLLCMD_LOGLEVEL
			 ROLLCMD_ROLLALL
			 ROLLCMD_ROLLREC
			 ROLLCMD_ROLLZONE
			 ROLLCMD_RUNQUEUE
			 ROLLCMD_SHUTDOWN
			 ROLLCMD_SLEEPTIME
			 ROLLCMD_STATUS
		);

my $rollmgrid;				# Rollerd's process id.

##############################################################################
#
# Log levels.  The first and last aren't selectable by a user.
#
my $LOG_NEVER	 =  0;			# Do not log this message.
my $LOG_TMI	 =  1;			# Overly verbose informational message.
my $LOG_EXPIRE	 =  3;			# Time-to-expiration given.
my $LOG_INFO	 =  4;			# Informational message.
my $LOG_CURPHASE =  6;			# Give current state of zone.
my $LOG_ERR	 =  8;			# Non-fatal error message.
my $LOG_FATAL	 =  9;			# Fatal error.
my $LOG_ALWAYS	 = 10;			# Messages that should always be given.

my $DEFAULT_LOGLEVEL = $LOG_INFO;	# Default log level.

sub LOG_NEVER		{ return($LOG_NEVER); };
sub LOG_TMI		{ return($LOG_TMI); };
sub LOG_EXPIRE		{ return($LOG_EXPIRE); };
sub LOG_INFO		{ return($LOG_INFO); };
sub LOG_CURPHASE	{ return($LOG_CURPHASE); };
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
	"curphase",
		undef,
	"err",
	"fatal",
	"always"
);

my $logfile;					# rollerd's log file.

##############################################################################
#
# These "constants" are used by rollerd's command interfaces.
# 

my $ADDR	= INADDR_ANY;			# rollerd's server address.
my $CMDPORT	= 880109;			# rollerd's server port.
my $EOL		= "\015\012";			# Net-standard end-of-line.

my $ROLLCMD_LOGFILE	= "rollcmd_logfile";
my $ROLLCMD_LOGLEVEL	= "rollcmd_loglevel";
my $ROLLCMD_ROLLALL	= "rollcmd_rollall";
my $ROLLCMD_ROLLREC	= "rollcmd_rollrec";
my $ROLLCMD_ROLLZONE	= "rollcmd_rollzone";
my $ROLLCMD_RUNQUEUE	= "rollcmd_runqueue";
my $ROLLCMD_SHUTDOWN	= "rollcmd_shutdown";
my $ROLLCMD_SLEEPTIME	= "rollcmd_sleeptime";
my $ROLLCMD_STATUS	= "rollcmd_status";

sub ROLLCMD_LOGFILE		{ return($ROLLCMD_LOGFILE); };
sub ROLLCMD_LOGLEVEL		{ return($ROLLCMD_LOGLEVEL); };
sub ROLLCMD_ROLLALL		{ return($ROLLCMD_ROLLALL); };
sub ROLLCMD_ROLLREC		{ return($ROLLCMD_ROLLREC); };
sub ROLLCMD_ROLLZONE		{ return($ROLLCMD_ROLLZONE); };
sub ROLLCMD_RUNQUEUE		{ return($ROLLCMD_RUNQUEUE); };
sub ROLLCMD_SHUTDOWN		{ return($ROLLCMD_SHUTDOWN); };
sub ROLLCMD_SLEEPTIME		{ return($ROLLCMD_SLEEPTIME); };
sub ROLLCMD_STATUS		{ return($ROLLCMD_STATUS); };

my %roll_commands =
(
	rollcmd_logfile		=> 1,
	rollcmd_loglevel	=> 1,
	rollcmd_rollall		=> 1,
	rollcmd_rollrec		=> 1,
	rollcmd_rollzone	=> 1,
	rollcmd_runqueue	=> 1,
	rollcmd_shutdown	=> 1,
	rollcmd_sleeptime	=> 1,
	rollcmd_status		=> 1,
);

##############################################################################
#
# These "constants" are the names of rollerd's interfaces.
# 
my $CMDINT	= "cmdint";
my $DROPID	= "dropid";
my $GETDIR	= "getdir";
my $GETID	= "getid";
my $HALT	= "halt";
my $IDFILE	= "idfile";
my $LOADZONE	= "loadzone";
my $RMID	= "rmid";
my $SAVEID	= "saveid";

##############################################################################
#
# These are the switch hashes that determine what routine will be called
# for what O/S classes.
# 
my %switch_uninit =
(
	$CMDINT	  =>	\&uninit_cmdint,
	$DROPID	  =>	\&uninit_dropid,
	$GETDIR	  =>	\&uninit_dir,
	$GETID	  =>	\&uninit_getid,
	$HALT	  =>	\&uninit_halt,
	$IDFILE	  =>	\&uninit_idfile,
	$LOADZONE =>	\&uninit_loadzone,
	$RMID	  =>	\&uninit_rmid,
	$SAVEID	  =>	\&uninit_saveid,
);

my %switch_unknown =
(
	$CMDINT	  =>	\&unknown_cmdint,
	$DROPID	  =>	\&unknown_dropid,
	$GETDIR	  =>	\&unknown_dir,
	$GETID	  =>	\&unknown_getid,
	$HALT	  =>	\&unknown_halt,
	$IDFILE	  =>	\&unknown_idfile,
	$LOADZONE =>	\&unknown_loadzone,
	$RMID	  =>	\&unknown_rmid,
	$SAVEID	  =>	\&unknown_saveid,
);

my %switch_unix =
(
	$CMDINT	  =>	\&unix_cmdint,
	$DROPID	  =>	\&unix_dropid,
	$GETDIR	  =>	\&unix_dir,
	$GETID	  =>	\&unix_getid,
	$HALT	  =>	\&unix_halt,
	$IDFILE	  =>	\&unix_idfile,
	$LOADZONE =>	\&unix_loadzone,
	$RMID	  =>	\&unix_rmid,
	$SAVEID	  =>	\&unix_saveid,
);


##############################################################################
#
# This is the port architecture hash that associates O/S names with their
# switch tables.
# 

my %port_archs =
(
	"uninitialized"	=>	\%switch_uninit,
	"unknown"	=>	\%switch_unknown,
	"unix"		=>	\%switch_unix,
);


##############################################################################
#
# Unix-related constants.
# 

my $UNIX_ROLLMGR_DIR	    = "/usr/local/etc/dnssec/";
my $UNIX_ROLLMGR_PIDFILE = ($UNIX_ROLLMGR_DIR . "rollmgr.pid");

##############################################################################
#
# These fields are the O/S class and switch table used for interface calls.
# 

my $osclass   = "uninitialized";
my %switchtab = %{$port_archs{$osclass}};


##############################################################################
##############################################################################
##############################################################################
#
# Top-level Interfaces
#
#	These interfaces are the module interfaces called by external
#	routines. 
#

#--------------------------------------------------------------------------
#
# Routine:      rollmgr_prepdep()
#
# Purpose:	This routine prepares for device-dependent calls.  A global
#		switch table is set, based on the short-form of the operating
#		system's name.
#
#		This *must* be updated whenever this module is ported to
#		a new operating system.
#
sub rollmgr_prepdep
{
	my $swtab;				# Switch-table reference.
	my $osname = $^O;			# Operating system name.

	#
	# Set up the default operating system class.
	#
	$osclass = "unknown";

	#
	# Figure out which operating system class we're running on.
	#
	if(($osname eq "freebsd")	||
	   ($osname eq "linux")		||
	   ($osname eq "darwin"))
	{
		$osclass = "unix";
	}

	#
	# Get the appropriate switch table for this O/S class and save
	# it for later reference.
	#
	my $swtab = $port_archs{$osclass};
	%switchtab = %$swtab;
}

#--------------------------------------------------------------------------
#
# Routine:      rollmgr_dir()
#
# Purpose:	Front-end to the O/S-specific "get rollerd's
#		directory" function.
#
sub rollmgr_dir
{
	my @args = shift;			# Routine arguments.
	my $func;				# Actual function.

# print "rollmgr_dir\n";

	$func = $switchtab{$GETDIR};
	return(&$func(@args));
}

#--------------------------------------------------------------------------
#
# Routine:      rollmgr_dropid()
#
# Purpose:	Front-end to the O/S-specific "save rollerd's
#		process id" function.
#
sub rollmgr_dropid
{
	my @args = shift;			# Routine arguments.
	my $func;				# Actual function.

# print "rollmgr_dropid\n";

	$func = $switchtab{$DROPID};
	return(&$func(@args));
}

#--------------------------------------------------------------------------
#
# Routine:      rollmgr_getid()
#
# Purpose:	Front-end to the O/S-specific "get rollerd's
#		identity" function.
#
sub rollmgr_getid
{
	my @args = shift;			# Routine arguments.
	my $func;				# Actual function.

# print "rollmgr_getid\n";

	$func = $switchtab{$GETID};
	return(&$func(@args));
}

#--------------------------------------------------------------------------
#
# Routine:      rollmgr_halt()
#
# Purpose:	Front-end to the O/S-specific "halt rollerd"
#		function.
#
sub rollmgr_halt
{
	my @args = shift;			# Routine arguments.
	my $func;				# Actual function.

# print "rollmgr_halt\n";

	$func = $switchtab{$HALT};
	return(&$func(@args));
}

#--------------------------------------------------------------------------
#
# Routine:      rollmgr_idfile()
#
# Purpose:	Front-end to the O/S-specific "get rollerd's
#		identity filename" function.
#
sub rollmgr_idfile
{
	my @args = shift;			# Routine arguments.
	my $func;				# Actual function.

# print "rollmgr_idfile\n";

	$func = $switchtab{$IDFILE};
	return(&$func(@args));
}

#--------------------------------------------------------------------------
#
# Routine:      rollmgr_loadzone()
#
# Purpose:	Front-end to the O/S-specific "load the zone" function.
#
sub rollmgr_loadzone
{
	my @args = shift;			# Routine arguments.
	my $func;				# Actual function.

# print "rollmgr_loadzone\n";

	$func = $switchtab{$LOADZONE};
	return(&$func(@args));
}

#--------------------------------------------------------------------------
#
# Routine:      rollmgr_cmdint()
#
# Purpose:	Front-end to the O/S-specific "rollerd has a
#		command" function.
#
sub rollmgr_cmdint
{
	my @args = shift;			# Routine arguments.
	my $func;				# Actual function.

# print "rollmgr_cmdint\n";

	$func = $switchtab{$CMDINT};
	return(&$func(@args));
}

#--------------------------------------------------------------------------
#
# Routine:      rollmgr_rmid()
#
# Purpose:	Front-end to the O/S-specific "remove rollerd's
#		identity file" function.
#
sub rollmgr_rmid
{
	my @args = shift;			# Routine arguments.
	my $func;				# Actual function.

# print "rollmgr_rmid\n";

	$func = $switchtab{$RMID};
	return(&$func(@args));
}

#--------------------------------------------------------------------------
#
# Routine:      rollmgr_saveid()
#
# Purpose:	Front-end to the O/S-specific "save rollerd's
#		identity" function.
#
sub rollmgr_saveid
{
	my @args = shift;			# Routine arguments.
	my $func;				# Actual function.

# print "rollmgr_saveid\n";

	$func = $switchtab{$SAVEID};
	return(&$func(@args));
}


##############################################################################
##############################################################################
##############################################################################
#
# Uninitialized switch functions
#
#	These interfaces are called when the switch table has not yet been
#	initialized.  Each interface calls rollmgr_prepdep() to set up the
#	operating-system-dependent switch table, then calls that O/S's
#	version of the interface.  The O/S-specific results are returned
#	to the caller.  Any subsequent calls to rollmgr_ interfaces will
#	call the proper O/S-dependent interface.

#--------------------------------------------------------------------------
#
# Routine:      uninit_dir()
#
# Purpose:	Switch for uninitialized "get dir" command.
#
sub uninit_dir
{
	my @args = shift;			# Routine arguments.

# print "uninit_dir\n";

	rollmgr_prepdep();
	return(rollmgr_dir(@args));
}

#--------------------------------------------------------------------------
#
# Routine:      uninit_dropid()
#
# Purpose:	Switch for uninitialized "drop id" command.
#
sub uninit_dropid
{
	my @args = shift;			# Routine arguments.

# print "uninit_dropid\n";

	rollmgr_prepdep();
	return(rollmgr_dropid(@args));
}

#--------------------------------------------------------------------------
#
# Routine:      uninit_getid()
#
# Purpose:	Switch for uninitialized "get id" command.
#
sub uninit_getid
{
	my @args = shift;			# Routine arguments.

# print "uninit_getid\n";

	rollmgr_prepdep();
	return(rollmgr_getid(@args));
}

#--------------------------------------------------------------------------
#
# Routine:      uninit_halt()
#
# Purpose:	Switch for uninitialized "halt" command.
#
sub uninit_halt
{
	my @args = shift;			# Routine arguments.

# print "uninit_halt\n";

	rollmgr_prepdep();
	return(rollmgr_halt(@args));
}

#--------------------------------------------------------------------------
#
# Routine:      uninit_idfile()
#
# Purpose:	Switch for uninitialized "get id file" command.
#
sub uninit_idfile
{
	my @args = shift;			# Routine arguments.

# print "uninit_idfile\n";

	rollmgr_prepdep();
	return(rollmgr_idfile(@args));
}

#--------------------------------------------------------------------------
#
# Routine:      uninit_loadzone()
#
# Purpose:	Switch for uninitialized "load the zone" command.
#
sub uninit_loadzone
{
	my @args = shift;			# Routine arguments.

# print "uninit_loadzone\n";

	rollmgr_prepdep();
	return(rollmgr_loadzone(@args));
}

#--------------------------------------------------------------------------
#
# Routine:      uninit_cmdint()
#
# Purpose:	Switch for uninitialized "force queue" command.
#
sub uninit_cmdint
{
	my @args = shift;			# Routine arguments.

# print "uninit_cmdint\n";

	rollmgr_prepdep();
	return(rollmgr_cmdint(@args));
}

#--------------------------------------------------------------------------
#
# Routine:      uninit_rmid()
#
# Purpose:	Switch for uninitialized "remove id file" command.
#
sub uninit_rmid
{
	my @args = shift;			# Routine arguments.

# print "uninit_rmid\n";

	rollmgr_prepdep();
	return(rollmgr_rmid(@args));
}

#--------------------------------------------------------------------------
#
# Routine:      uninit_saveid()
#
# Purpose:	Switch for uninitialized "save id file" command.
#
sub uninit_saveid
{
	my @args = shift;			# Routine arguments.

# print "uninit_saveid\n";

	rollmgr_prepdep();
	return(rollmgr_saveid(@args));
}


##############################################################################
##############################################################################
##############################################################################
#
# Unknown switch functions
#
#	These interfaces are called when the operating system was not
#	recognized by rollmgr_prepdep().  In all cases, the routine
#	prints an error message and exits.
#

#--------------------------------------------------------------------------
#
# Routine:      unknown_action()
#
sub unknown_action
{
	print STDERR "rollmgr.pm has not been ported to your system yet; cannot continue until this has been done.\n";
	exit(42);
}

#--------------------------------------------------------------------------
#
# Routine:      unknown_dir()
#
sub unknown_dir
{
	unknown_action();
}

#--------------------------------------------------------------------------
#
# Routine:      unknown_getid()
#
sub unknown_getid
{
	unknown_action();
}

#--------------------------------------------------------------------------
#
# Routine:      unknown_halt()
#
sub unknown_halt
{
	unknown_action();
}

#--------------------------------------------------------------------------
#
# Routine:      unknown_idfile()
#
sub unknown_idfile
{
	unknown_action();
}

#--------------------------------------------------------------------------
#
# Routine:      unknown_loadzone()
#
sub unknown_loadzone
{
	unknown_action();
}

#--------------------------------------------------------------------------
#
# Routine:      unknown_cmdint()
#
sub unknown_cmdint
{
	unknown_action();
}

#--------------------------------------------------------------------------
#
# Routine:      unknown_rmid()
#
sub unknown_rmid
{
	unknown_action();
}

#--------------------------------------------------------------------------
#
# Routine:      unknown_saveid()
#
sub unknown_saveid
{
	unknown_action();
}


##############################################################################
##############################################################################
##############################################################################
#
# Unix switch functions
#
#	These interfaces are called when the O/S has been determined to
#	be a Unix-class O/S.
#

#--------------------------------------------------------------------------
#
# Routine:      unix_dir()
#
sub unix_dir
{
	return($UNIX_ROLLMGR_DIR);
}

#--------------------------------------------------------------------------
#
# Routine:	unix_idfile()
#
# Purpose:	Return rollerd's id file.
#
sub unix_idfile
{
	return($UNIX_ROLLMGR_PIDFILE);
}

#--------------------------------------------------------------------------
#
# Routine:	unix_loadzone()
#
# Purpose:	Kick the name server so it'll load the given zone.
#
sub unix_loadzone
{
	my $rndc = shift;				# Nameserver controller.
	my $zone = shift;                               # Zone to reload.
	my $ret;                                        # Execution return code.

# print "unix_loadzone\n";

	#
	# Get the path to the name server control program.
	#
	$rndc = dnssec_tools_defaults("bind_signzone") if($rndc eq "");
	return(0) if($rndc eq "");

	#
	# Reload the zone.
	#
	`$rndc reload $zone >/dev/null 2>&1`;
	$ret = $? >> 8;

	return($ret);
}

#--------------------------------------------------------------------------
#
# Routine:	unix_dropid()
#
# Purpose:	Ensures that another instance of rollerd is running and then
#		creates a pid file for future reference.
#
# Return Values:
#		 1 - The pidfile was initialized for this process.
#		 0 - Another process (not this one) is already acting as
#		     rollerd.
#
sub unix_dropid
{
	my $ego = $$;				# My identity.
	my $rdpid;				# Pid read from the pidfile.

# print "unix_dropid:  down in\n";

	#
	# Get the pid from rollerd's pidfile.
	#
	$rdpid = unix_getpid(0);

	#
	# Create the file if it doesn't exist.
	# If it does exist, we'll make sure the listed process isn't running.
	#
	if($rdpid < 0)
	{
# print "unix_dropid:  opening $UNIX_ROLLMGR_PIDFILE\n";
		unlink("$UNIX_ROLLMGR_PIDFILE");
		open(PIDFILE,"> $UNIX_ROLLMGR_PIDFILE") || warn "DROPID UNABLE TO OPEN \"$UNIX_ROLLMGR_PIDFILE\"\n";
		flock(PIDFILE,LOCK_EX);
	}
	else
	{
		my $pid;			# Pid from ps output.
		my $pscmd;			# ps command to execute.
		my $psline;			# Output line from ps.
		my $openrc;			# Return code from open().

# print "unix_dropid:  $UNIX_ROLLMGR_PIDFILE exists\n";
		flock(PIDFILE,LOCK_EX);

		#
		# Get the process status of the process having the pid
		# we found in the pidfile.
		#
		#	We shouldn't have to do this this way.
		#	We should be able to do "ps -p $rdpid" and
		#	skip the search loop.
		#	However, the $rdpid seems to be dropped
		#	when using that method.
		#
		$pscmd = "/bin/ps -ax";
		$openrc = open(PSOUT,"$pscmd |");
		$psline = <PSOUT>;
		while(<PSOUT>)
		{
			my $lpid;		# Pid from ps output.
			my $lcmd;		# Command from ps output.

			#
			# Get the pid and command from the ps line.
			#
			$psline = $_;
			$psline =~ /\s*(\S*)\s*(\S*)\s*(\S*)\s*(\S*)\s*(.*$)/;
			$lpid = $1;
			$psline = "$5";

			#
			# Drop out if the pid matches the file's pid.
			#
			last if($lpid == $rdpid);

			#
			# Reset the saved command and go to the next line.
			#
			$psline = "";
#			next;
		}
		close(PSOUT);

		#
		# Check if the pidfile's process is still running.
		# Return success if the current manager is us.
		# Return failure if the current manager isn't us.
		#
		if($psline =~ /rollerd/)
		{
			flock(PIDFILE,LOCK_UN);

			return(1) if($rdpid == $ego);
			return(0);
		}
	}

	#
	# Zap the file contents.
	#
	truncate($UNIX_ROLLMGR_PIDFILE,0);

	#
	# Save our pid as THE rollerd's pid.
	#
	seek(PIDFILE,0,0);
	print PIDFILE "$ego\n";
	flock(PIDFILE,LOCK_UN);
	close(PIDFILE);

	#
	# Save our pid as the internal version of the manager's pid and
	# return success.
	#
	$rollmgrid = $ego;
	return(1);
}

#--------------------------------------------------------------------------
#
# Routine:	unix_rmid()
#
# Purpose:	Delete rollerd's pidfile.  This is done when
#		as part of the manager's clean-up process.
#
# Return Values:
#		 1 - The pidfile was deleted.
#		 0 - No pidfile exists.
#		-1 - The calling process is not rollerd.
#		-2 - Unable to delete the pidfile.
#
sub unix_rmid
{
	my $ego = $$;				# My identity.
	my $flret;				# flock() return code.
	my $rdpid;				# Pid read from the pidfile.

# print "unix_rmid:  down in\n";

	#
	# Get the pid from rollerd's pidfile.
	#
	$rdpid = unix_getpid(0);
	flock(PIDFILE,LOCK_EX);

	#
	# Complain and return if there is not pidfile.
	#
	if($rdpid == -1)
	{
# print "unix_rmid:  rollerd's pidfile does not exist\n";
		return(0);
	}

	#
	# Ensure that this process is the One True Roll-over Manager.
	#
	if($rdpid != $ego)
	{
# print "unix_rmid:  we are not rollerd\n";
		return(-1);
	}

	#
	# Get rid of the pidfile.
	#
	if(unlink($UNIX_ROLLMGR_PIDFILE) != 1)
	{
# print "unix_rmid:  unable to delete pidfile\n";
		return(-2);
	}

	#
	# Close and unlock the pidfile.
	#
	flock(PIDFILE,LOCK_UN);
	close(PIDFILE);
	return(1);
}

#--------------------------------------------------------------------------
#
# Routine:	unix_getpid()
#
# Purpose:	Return rollerd, as recorded in its pidfile.
#		If the caller wants the file closed upon return, a non-zero
#		value should be passed as an argument.
#
# Return Values:
#		-1 is returned if the pidfile does not exist.
#		The first blob o' file contents is returned if it does exist.
#
# WARNINGS:
#		- This attempts to exclusively lock the pidfile.
#		  Set a timer if this matters to you.
#
#		- There's a nice little race condition here.  We need to lock
#		  the file and we can't do so without it being open.  So,
#		  we've got that little window we hope nothing sneaks through.
#
sub unix_getpid
{
	my $closeflag = shift;			# Close-flag for pidfile.
	my $pid;				# Pid from pidfile.

	#
	# Return an error if the file doesn't exist.
	#
	return(-1) if(stat($UNIX_ROLLMGR_PIDFILE) == 0);

	#
	# Open and lock the pidfile.
	#
	close(PIDFILE);
	if(open(PIDFILE,"+< $UNIX_ROLLMGR_PIDFILE") == 0)
	{
#		print STDERR "unix_getpid:  unable to open \"$UNIX_ROLLMGR_PIDFILE\"\n";
		return(-1);
	}
	flock(PIDFILE,LOCK_EX);

	#
	# Get the pid from the pidfile.
	#
	$pid = <PIDFILE>;
	flock(PIDFILE,LOCK_UN);

	#
	# Close and unlock the file if the caller only wants the pid.
	#
	close(PIDFILE) if($closeflag);

	#
	# Lop off any trailing newlines and return.
	#
#	$pid =~ s/\n//g;
	$pid =~ /([0-9]+)/;
	$pid = $1;

	return($pid);
}

#--------------------------------------------------------------------------
#
# Routine:	unix_cmdint()
#
# Purpose:	Kick rollerd to let it know it should re-read the rollrec
#		file and process its queue again.
#
sub unix_cmdint
{
	my $pid;				# Rollerd's pid.
	my $ret;				# Return code from kill().

# print "unix_cmdint:  down in\n";

	#
	# Get rollerd's process id.  Return an error if we couldn't get it
	# or if what we got is below some low arbitrary limit.
	#
	$pid = unix_getpid(1);
	return(-1) if(!defined($pid) ||  ($pid < 10));

	#
	# Send HUP to rollerd.
	#
	$ret = kill("HUP", $pid);
	return($ret);
}

#--------------------------------------------------------------------------
#
# Routine:	unix_halt()
#
# Purpose:	Tell rollerd to shut down.
#
sub unix_halt
{
	my $pid;				# Rollerd's pid.
	my $ret;				# Return code from kill().

# print "unix_halt:  down in\n";

	#
	# Get rollerd's process id.  Return an error if we couldn't get it
	# or if what we got is below some low arbitrary limit.
	#
	$pid = unix_getpid(1);
	return(-1) if(!defined($pid) ||  ($pid < 10));

	#
	# Send INT to rollerd.
	#
	$ret = kill('INT',$pid);
	return($ret);
}

#############################################################################
#############################################################################
#############################################################################

#-----------------------------------------------------------------------------
#
# Routine:	rollmgr_loglevel()
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
sub rollmgr_loglevel
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
	# If a non-numeric log level was given, translate it into the
	# appropriate numeric value.
	#
	if($newlevel !~ /^[0-9]+$/)
	{
		if($newlevel =~ /tmi/i)
		{
			$loglevel = LOG_TMI;
		}
		elsif($newlevel =~ /expire/i)
		{
			$loglevel = LOG_EXPIRE;
		}
		elsif($newlevel =~ /info/i)
		{
			$loglevel = LOG_INFO;
		}
		elsif($newlevel =~ /curphase/i)
		{
			$loglevel = LOG_CURPHASE;
		}
		elsif($newlevel =~ /err/i)
		{
			$loglevel = LOG_ERR;
		}
		elsif($newlevel =~ /fatal/i)
		{
			$loglevel = LOG_FATAL;
		}
		else
		{
			$err = 1;
		}

	}
	else
	{
		#
		# If a valid log level was given, make it the current level.
		#
		if(($newlevel < 0) || !defined($logstrs[$newlevel]))
		{
			$err = 1;
		}
		else
		{
			$loglevel = $newlevel;
		}
	}

	#
	# If there was a problem, give usage messages and exit.
	#
	if($err)
	{
		return(-1) if(!$useflag);

		print STDERR "unknown logging level \"$newlevel\"\n";
		print STDERR "valid logging levels (text and numeric forms):\n";
		print STDERR "\ttmi		 1\n";
		print STDERR "\texpire		 3\n";
		print STDERR "\tinfo		 4\n";
		print STDERR "\tcurphase	 6\n";
		print STDERR "\terr		 8\n";
		print STDERR "\tfatal		 9\n";
		exit(1);
	}

	#
	# Return the old logging level.
	#
	return($oldlevel);
}

#-----------------------------------------------------------------------------
#
# Routine:	rollmgr_logfile()
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
sub rollmgr_logfile
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
			print STDERR "logfile \"$newlogfile\" does not exist\n" if($useflag);
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
			print STDERR "logfile \"$newlogfile\" is not a regular file\n" if($useflag);
			return("");
		}
		if(! -w $newlogfile)
		{
			print STDERR "logfile \"$newlogfile\" is not writable\n" if($useflag);
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

#-----------------------------------------------------------------------------
#
# Routine:	rollmgr_log()
#
sub rollmgr_log
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
	$kronos = gmtime();
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

#############################################################################
#############################################################################
#############################################################################

#-----------------------------------------------------------------------------
#
# Routine:	rollmgr_channel()
#
# Purpose:	This routine initializes a socket to use for rollerd
#		communications.  It is called by both rollerd and rollerd
#		clients.
#
#		Currently, we're only setting up to connect to a rollerd
#		running on our own host.  In time, we may allow remote
#		connections.
#
sub rollmgr_channel
{
	my $server = shift;				# Server/client flag.

	my $proto;					# Protocol to use.
	my $remote = "localhost";			# Server's hostname.
	my $serveraddr;					# Server's address.
	my $conaddr;					# Address in connect().

# print "rollmgr_channel($server):  down in\n";

	#
	# Get the protocol and create a socket.
	#
	$proto	= getprotobyname("tcp");
	socket(SOCK,PF_INET,SOCK_STREAM,$proto);

	#
	# For the server, we'll set the socket's address and mark it as
	# connectable.
	# For the client, we'll get the address of the server and connect
	# to it.  (Right now, we're only talking to localhost.)
	#
	if($server)
	{
		setsockopt(SOCK,SOL_SOCKET,SO_REUSEADDR,pack("l",1));
		bind(SOCK,sockaddr_in($CMDPORT,$ADDR));
		listen(SOCK,SOMAXCONN);
	}
	else
	{

		$remote = "localhost";

		$serveraddr = inet_aton($remote);
		$conaddr = sockaddr_in($CMDPORT,$serveraddr);

		connect(SOCK,$conaddr);
	}
}

#-----------------------------------------------------------------------------
#
# Routine:	rollmgr_getcmd()
#
# Purpose:	This routine is called by the server to fetch a command and
#		its data from the command socket.  rollmgr_channel() is
#		assumed to have been called to initialize the command socket.
#
sub rollmgr_getcmd
{
	my $waiter = shift || 5;		# Time to wait for connect.

	my $cmd;				# Client's command.
	my $data;				# Command's data.
	my $user;				# ID info of sender.

	my $raddr;				# Client's address.
	my $rmtaddr;				# Client's address.
	my $rmtname;				# Client's name.
	my $rport;				# Remote port.

	my $oldhandler = $SIG{ALRM};		# Old alarm handler.

# print "rollmgr_getcmd:  down in\n";

	#
	# Set a time limit on how long we'll wait for the connection.
	# Our alarm handler is a dummy, only intended to keep us from
	# waiting forever.
	#
	$SIG{ALRM} = sub { my $foo = 42 };
	alarm($waiter);

	#
	# Accept the waiting connection.
	#
	$rmtaddr = accept(RMTSOCK,SOCK);
	return if(!defined($rmtaddr));

	#
	# Convert the client's address into a hostname.
	#
	($rport,$raddr) = sockaddr_in($rmtaddr);
	$rmtname = gethostbyaddr($raddr,AF_INET);
# print "rollmgr_getcmd:  connection from <$rmtname>\n";
	return("bad host","$rmtname","") if($rmtname ne "localhost");

	#
	# Get the command and data, and lop off the trailing goo.
	#
	$cmd  = <RMTSOCK>;
	$data = <RMTSOCK>;
	$user = <RMTSOCK>;
	$cmd  =~ s/ $EOL$//;
	$data =~ s/ $EOL$//;
	$user =~ s/ $EOL$//;

	#
	# Turn off the alarm and reset the alarm handler.
	#
	alarm(0);
	$SIG{ALRM} = $oldhandler;

	#
	# Close the remote socket and return the client's data.
	#
	close(RMTSOCK);
	return($cmd,$data,$user);
}

#-----------------------------------------------------------------------------
#
# Routine:	rollmgr_sendcmd()
#
# Purpose:	This routine allows a client to send a message to the server.
#		No other routines need be called to initialize anything.
#
sub rollmgr_sendcmd
{
	my $cmd	 = shift;				# Command to send.
	my $data = shift;				# Data for command.
	my $user = `id`;				# User info.

# print "rollmgr_sendcmd:  down in\n";

	return(0) if(rollmgr_verifycmd($cmd) == 0);

	chomp $user;

	rollmgr_channel(0);

	print SOCK "$cmd $EOL";
	print SOCK "$data $EOL";
	print SOCK "$user $EOL";

	close(SOCK);

	return(1);
}

#-----------------------------------------------------------------------------
#
# Routine:	rollmgr_verifycmd()
#
# Purpose:	This routine returns a boolean indicating if the specified
#		command is a valid command for for the roll-over daemon.
#
sub rollmgr_verifycmd
{
	my $cmd	 = shift;				# Command to check.
	my $hval;					# Command hash value.

# print "rollmgr_verifycmd:  down in\n";

	$hval = $roll_commands{$cmd};
# print "rollmgr_verifycmd:  <$cmd>\t\t<$hval>\n";

	return(0) if(!defined($hval));
	return(1);
}

1;

#############################################################################

=pod

=head1 NAME

Net::DNS::SEC::Tools::rollmgr - Communicate with the DNSSEC-Tools roll-over
manager.

=head1 SYNOPSIS

  use Net::DNS::SEC::Tools::rollmgr;

  $dir = rollmgr_dir();

  $idfile = rollmgr_idfile();

  $id = rollmgr_getid();

  rollmgr_dropid();

  rollmgr_rmid();

  rollmgr_cmdint();

  rollmgr_halt();

  $curlevel = rollmgr_loglevel();
  $oldlevel = rollmgr_loglevel("info");
  $oldlevel = rollmgr_loglevel(LOG_ERR,1);

  $curlogfile = rollmgr_logfile();
  $oldlogfile = rollmgr_logfile("-");
  $oldlogfile = rollmgr_logfile("/var/log/roll.log",1);

  rollmgr_log(LOG_INFO,"example.com","zone is valid");

  rollmgr_channel(1);
  ($cmd,$data) = rollmgr_getcmd();
  $ret = rollmgr_verifycmd($cmd);

  rollmgr_sendcmd(ROLLCMD_ROLLZONE,"example.com");

=head1 DESCRIPTION

The B<Net::DNS::SEC::Tools::rollmgr> module provides standard,
platform-independent methods for a program to communicate with DNSSEC-Tools'
I<rollerd> roll-over manager.  There are three interface classes described
here:  general interfaces, logging interfaces, and communications interfaces.

=head1 GENERAL INTERFACES

The interfaces to the B<Net::DNS::SEC::Tools::rollmgr> module are given below.

=head2 B<rollmgr_dir()>

This routine returns I<rollerd>'s directory.

=head2 B<rollmgr_idfile()>

This routine returns I<rollerd>'s id file.

=head2 B<rollmgr_getid()>

This routine returns I<rollerd>'s process id.  If a non-zero value
is passed as an argument, the id file will be left open and accessible through
the PIDFILE file handle.  See the WARNINGS section below.

Return Values:

    On success, the first portion of the file contents (up to 80
        characters) is returned.
    -1 is returned if the id file does not exist.

=head2 B<rollmgr_dropid()>

This interface ensures that another instance of I<rollerd> is not
running and then creates a id file for future reference.

Return Values:

    1 - the id file was successfully created for this process
    0 - another process is already acting as rollerd

=head2 B<rollmgr_rmid()>

This interface deletes I<rollerd>'s id file.

Return Values:

     1 - the id file was successfully deleted
     0 - no id file exists
    -1 - the calling process is not rollerd
    -2 - unable to delete the id file

=head2 B<rollmgr_cmdint()>

This routine informs I<rollerd> that a command has been sent via
I<rollmgr_sendcmd()>.

Return Values:

    -1 - an invalid process id was found for rollerd
    Anything else indicates the number of processes that were signaled.
    (This should only ever be 1.)

=head2 B<rollmgr_halt()>

This routine informs I<rollerd> to shut down.

In the current implementation, the return code from the B<kill()> command is
returned.

    -1 - an invalid process id was found for rollerd
    Anything else indicates the number of processes that were signaled.
    (This should only ever be 1.)

=head1 LOGGING INTERFACES

=head2 B<rollmgr_loglevel(newlevel,useflag)>

This routine sets and retrieves the logging level for I<rollerd>.
The I<newlevel> argument specifies the new logging level to be set.  The
valid levels are:

    text       numeric  meaning
    ----       -------  -------
    tmi           1     The highest level -- all log messages are saved.
    expire        3     A verbose countdown of zone expiration is given.
    info          4     Many informational messages are recorded.
    curphase      6     Each zone's current roll-over phase is given.
    err        	  8     Errors are recorded.
    fatal         9     Fatal errors are saved.

I<newlevel> may be given in either text or numeric form.  The levels include
all numerically higher levels.  For example, if the log level is set to
B<curphase>, then B<err> and B<fatal> messages will also be recorded.

The I<useflag> argument is a boolean that indicates whether or not to give a
descriptive message and exit if an invalid logging level is given.  If
I<useflag> is true, the message is given and the process exits; if false, -1
is returned.

If given with no arguments, the current logging level is returned.  In fact,
the current level is always returned unless an error is found.  -1 is returned
on error.

=head2 B<rollmgr_logfile(newfile,useflag)>

This routine sets and retrieves the log file for I<rollerd>.
The I<newfile> argument specifies the new log file to be set.  If I<newfile>
exists, it must be a regular file.

The I<useflag> argument is a boolean that indicates whether or not to give a
descriptive message if an invalid logging level is given.  If I<useflag> is
true, the message is given and the process exits; if false, no message is
given.  For any error condition, an empty string is returned.

=head2 B<rollmgr_log(level,group,message)>

The I<rollmgr_log()> interface writes a message to the log file.  Log
messages have this format:

	timestamp: group: message

The I<level> argument is the message's logging level.  It will only be written
to the log file if the current log level is numerically equal to or less than
I<level>.

I<group> allows messages to be associated together.  It is currently used by
I<rollerd> to group messages by the zone to which the message applies.

The I<message> argument is the log message itself.  Trailing newlines are
removed.

=head1 ROLLERD COMMUNICATIONS INTERFACES

=head2 B<rollmgr_channel(serverflag)>

This interface sets up a persistent channel for communications with I<rollerd>.
If I<serverflag> is true, then the server's side of the channel is created.
If I<serverflag> is false, then the client's side of the channel is created.

Currently, the connection may only be made to the localhost.  This may be
changed to allow remote connections, if this is found to be needed.

=head2 B<rollmgr_getcmd()>

I<rollmgr_getcmd()> retrieves a command sent over I<rollerd>'s communications
channel by a client program.  The command, the command's data, and some user
information are sent in each message.

The command, the command's data, and a set of sending-user information are
returned.  No verification of these data are performed by I<rollmgr_getcmd()>.

The sending-user information is the output of the I<id> command.  There is no
trusted path available in the current networking system, so this information
is informational and B<cannot> be trusted to be accurate.

=head2 B<rollmgr_sendcmd(cmd,data)>

I<rollmgr_sendcmd()> sends a command to I<rollerd>.  The command must be one
of the commands from the table below.  This interface creates a communications
channel to I<rollerd>, sends the message, and closes the channel.

The available commands and their required data are:

   command		data		purpose
   -------		----		-------
   ROLLCMD_LOGFILE	log-file	set rollerd's log filename
   ROLLCMD_LOGLEVEL	log-level	set rollerd's logging level
   ROLLCMD_ROLLALL	none		force all zones to start roll-over
   ROLLCMD_ROLLREC	rollrec-name	change rollerd's rollrec file
   ROLLCMD_ROLLZONE	zone-name	force a zone to start roll-over
   ROLLCMD_RUNQUEUE	none		rollerd runs through its queue
   ROLLCMD_SHUTDOWN	none		stop rollerd
   ROLLCMD_SLEEPTIME	seconds-count	set rollerd's sleep time
   ROLLCMD_STATUS	none		get rollerd's status

The data aren't checked for validity by I<rollmgr_sendcmd()>; validity
checking is a responsibility of I<rollerd>.

On success, 1 is returned.  If an invalid command is given, 0 is returned.

=head2 B<rollmgr_verifycmd(cmd)>

I<rollmgr_verifycmd()> verifies that I<cmd> is a valid command for I<rollerd>.
1 is returned for a valid command; 0 is returned for an invalid command.

=head1 WARNINGS

1.  B<rollmgr_getid()> attempts to exclusively lock the id file.
Set a timer if this matters to you.

2.  B<rollmgr_getid()> has a nice little race condition.  We should lock
the file prior to opening it, but we can't do so without it being open.

=head1 COPYRIGHT

Copyright 2005-2006 SPARTA, Inc.  All rights reserved.
See the COPYING file included with the DNSSEC-Tools package for details.

=head1 AUTHOR

Wayne Morrison, tewok@users.sourceforge.net

=head1 SEE ALSO

B<rollctl(1)>

B<Net::DNS::SEC::Tools::keyrec.pm(3)>
B<Net::DNS::SEC::Tools::rollrec.pm(3)>

B<rollerd(8)>

=cut
