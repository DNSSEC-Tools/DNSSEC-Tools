#
# Copyright 2012-2014 SPARTA, Inc.  All rights reserved.  See the COPYING
# file distributed with this software for details
#
# DNSSEC Tools
#
# realmmgr.pm -	Realm manager functions.
#
#	The routines in this module provide a means to communicate with
#	dtrealms.  The module is based on rollmgr.pm.
#
#
#	Introduction
#		This module provides interfaces for communicating with the
#		DNSSEC-Tools' realms manager.  The top-level interfaces are
#		independent of the host operating system, but the actual
#		operations are dependent upon the host O/S.
#
#		To allow similar O/Ses to share switch functions, thus
#		minimizing the size of the module, the realmmgr_prepdep()
#		routine determines which operating system class an operating
#		system falls into.  This determination is based upon the O/S
#		name, as taken from $^O.
#
#		This module has been ported to:
#
#			O/S name	O/S class
#			--------	---------
#			FreeBSD		Unix
#			Mac OSX		Unix
#			Solaris		Solaris/Unix
#
#		When extending the interface or porting this module to another
#		O/S, the following entities must be modified as described
#		below.  The Unix switches may be used as a model.
#		
#
#	Port architecture hash
#		This hash table associates an operating-system class with
#		a switch hash.  The class (determined in realmmgr_prepdep())
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
#		These interfaces are called when realmmgr.pm has not been
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

package Net::DNS::SEC::Tools::realmmgr;

require Exporter;
use strict;

use Fcntl ':flock';
use Socket;

use Net::DNS::SEC::Tools::conf;
use Net::DNS::SEC::Tools::defaults;
use Net::DNS::SEC::Tools::rolllog;

our $VERSION = "2.0";
our $MODULE_VERSION = "2.0.0";

our @ISA = qw(Exporter);

our @EXPORT = qw(
		 realmmgr_cmdint
		 realmmgr_dir
		 realmmgr_dropid
		 realmmgr_getid
		 realmmgr_halt
		 realmmgr_idfile
		 realmmgr_set_idfile
		 realmmgr_rmid
		 realmmgr_running
		 realmmgr_saveid

		 realmmgr_channel
		 realmmgr_closechan
		 realmmgr_getcmd
		 realmmgr_getresp
		 realmmgr_sendcmd
		 realmmgr_queuecmd
		 realmmgr_getqueueitem
		 realmmgr_getallqueuedcmds
		 realmmgr_sendresp
		 realmmgr_verifycmd

			 REALMCMD_COMMAND
			 REALMCMD_DISPLAY
			 REALMCMD_GETSTATUS
			 REALMCMD_LOGFILE
			 REALMCMD_LOGLEVEL
			 REALMCMD_LOGMSG
			 REALMCMD_LOGTZ
			 REALMCMD_REALMSTATUS
			 REALMCMD_SHUTDOWN
			 REALMCMD_STARTALL
			 REALMCMD_STARTREALM
			 REALMCMD_STATUS
			 REALMCMD_STOPALL
			 REALMCMD_STOPREALM

			 REALMCMD_RC_OKAY
			 REALMCMD_RC_BADEVENT
			 REALMCMD_RC_BADFILE
			 REALMCMD_RC_BADLEVEL
			 REALMCMD_RC_BADSLEEP
			 REALMCMD_RC_BADTZ
			 REALMCMD_RC_BADREALM
			 REALMCMD_RC_BADREALMDATA
			 REALMCMD_RC_DISPLAY
			 REALMCMD_RC_NOARGS
			 REALMCMD_RC_NOREALMS
			 REALMCMD_RC_REALMOPEN

			 CHANNEL_WAIT
			 CHANNEL_CLOSE
		);

my $realmmgrid;				# dtrealms's process id.

##############################################################################
#
# These "constants" are used by dtrealms' command interfaces.
# 

my $ADDR	= INADDR_ANY;			# dtrealms' server address.
my $CMDPORT	= 660903;			# dtrealms' server port.
my $EOL		= "\015\012";			# Net-standard end-of-line.

my $CHANNEL_TYPE = PF_UNIX;			# Type of channel we're using.
my $UNIXSOCK	 = "/realmmgr.socket";		# Unix socket name.
my $REALMMGR_PID = "/realmmgr.pid";		# Pid node name.

#
# Maximum lengths of Unix socket names for various systems.  These are used
# in rollmgr_channel().
#
my $FREEBSD_MAXSOCKNAME	= 103;
my $MACOSX_MAXSOCKNAME	= 103;
my $LINUX_MAXSOCKNAME	= 107;
my $UNKNOWN_MAXSOCKNAME = $MACOSX_MAXSOCKNAME;		# Use the shortest.
my $maxsockname		= $UNKNOWN_MAXSOCKNAME;

#
# The CHANNEL_ entities are used for specifying whether realmmgr_sendcmd()
# should or should not wait for a response from dtrealms.
#
my $CHANNEL_WAIT	= 0;
my $CHANNEL_CLOSE	= 1;
sub CHANNEL_WAIT		{ return($CHANNEL_WAIT);	};
sub CHANNEL_CLOSE		{ return($CHANNEL_CLOSE);	};
my @queuedcmds;

#
# The REALMCMD_RC_ entities are return codes sent from dtrealms and received
# by client programs from realmmgr_getresp().
#
my $REALMCMD_RC_OKAY		= 0;
my $REALMCMD_RC_BADLEVEL	= 1;
my $REALMCMD_RC_BADFILE		= 2;
my $REALMCMD_RC_BADSLEEP 	= 3;
my $REALMCMD_RC_BADREALM	= 4;
my $REALMCMD_RC_BADTZ		= 5;
my $REALMCMD_RC_REALMOPEN	= 6;
my $REALMCMD_RC_NOREALMS	= 7;
my $REALMCMD_RC_BADREALMDATA	= 8;
my $REALMCMD_RC_DISPLAY		= 9;
my $REALMCMD_RC_NOARGS		= 10;
my $REALMCMD_RC_BADEVENT	= 11;

sub REALMCMD_RC_OKAY		{ return($REALMCMD_RC_OKAY);		};
sub REALMCMD_RC_BADEVENT	{ return($REALMCMD_RC_BADEVENT);	};
sub REALMCMD_RC_BADFILE		{ return($REALMCMD_RC_BADFILE);		};
sub REALMCMD_RC_BADLEVEL	{ return($REALMCMD_RC_BADLEVEL);	};
sub REALMCMD_RC_BADRREALM	{ return($REALMCMD_RC_BADREALM);	};
sub REALMCMD_RC_BADREALMDATA	{ return($REALMCMD_RC_BADREALMDATA);	};
sub REALMCMD_RC_BADSLEEP	{ return($REALMCMD_RC_BADSLEEP);	};
sub REALMCMD_RC_BADTZ		{ return($REALMCMD_RC_BADTZ);		};
sub REALMCMD_RC_DISPLAY		{ return($REALMCMD_RC_DISPLAY);		};
sub REALMCMD_RC_NOARGS		{ return($REALMCMD_RC_NOARGS);		};
sub REALMCMD_RC_NOREALMS	{ return($REALMCMD_RC_NOREALMS);	};
sub REALMCMD_RC_REALMOPEN	{ return($REALMCMD_RC_REALMOPEN);	};

#
# The remaining REALMCMD_ entities are the realmmgr_sendcmd() commands
# recognized by dtrealms.  %realm_commands is a hash table of valid commands.
#
my $REALMCMD_COMMAND		= "realmcmd_command";
my $REALMCMD_DISPLAY		= "realmcmd_display";
my $REALMCMD_GETSTATUS		= "realmcmd_getstatus";
my $REALMCMD_LOGFILE		= "realmcmd_logfile";
my $REALMCMD_LOGLEVEL		= "realmcmd_loglevel";
my $REALMCMD_LOGMSG		= "realmcmd_logmsg";
my $REALMCMD_LOGTZ		= "realmcmd_logtz";
my $REALMCMD_REALMSTATUS	= "realmcmd_realmstatus";
my $REALMCMD_SHUTDOWN		= "realmcmd_shutdown";
my $REALMCMD_STARTALL		= "realmcmd_startall";
my $REALMCMD_STARTREALM		= "realmcmd_startrealm";
my $REALMCMD_STATUS		= "realmcmd_status";
my $REALMCMD_STOPALL		= "realmcmd_stopall";
my $REALMCMD_STOPREALM		= "realmcmd_stoprealm";

sub REALMCMD_COMMAND		{ return($REALMCMD_COMMAND);		};
sub REALMCMD_DISPLAY		{ return($REALMCMD_DISPLAY);		};
sub REALMCMD_GETSTATUS		{ return($REALMCMD_GETSTATUS);		};
sub REALMCMD_LOGFILE		{ return($REALMCMD_LOGFILE);		};
sub REALMCMD_LOGLEVEL		{ return($REALMCMD_LOGLEVEL);		};
sub REALMCMD_LOGMSG		{ return($REALMCMD_LOGMSG);		};
sub REALMCMD_LOGTZ		{ return($REALMCMD_LOGTZ);		};
sub REALMCMD_REALMSTATUS	{ return($REALMCMD_REALMSTATUS);	};
sub REALMCMD_SHUTDOWN		{ return($REALMCMD_SHUTDOWN);		};
sub REALMCMD_STARTALL		{ return($REALMCMD_STARTALL);		};
sub REALMCMD_STARTREALM		{ return($REALMCMD_STARTREALM);		};
sub REALMCMD_STATUS		{ return($REALMCMD_STATUS);		};
sub REALMCMD_STOPALL		{ return($REALMCMD_STOPALL);		};
sub REALMCMD_STOPREALM		{ return($REALMCMD_STOPREALM);		};

my %realm_commands =
(
	realmcmd_command	=> 1,
	realmcmd_display	=> 1,
	realmcmd_getstatus	=> 1,
	realmcmd_logfile	=> 1,
	realmcmd_loglevel	=> 1,
	realmcmd_logmsg		=> 1,
	realmcmd_logtz		=> 1,
	realmcmd_nodisplay	=> 1,
	realmcmd_realmstatus	=> 1,
	realmcmd_shutdown	=> 1,
	realmcmd_startall	=> 1,
	realmcmd_startrealm	=> 1,
	realmcmd_status		=> 1,
	realmcmd_stopall	=> 1,
	realmcmd_stoprealm	=> 1,
);

##############################################################################
#
# These "constants" are the names of dtrealms' interfaces.
# 
my $CMDINT	= "cmdint";
my $DROPID	= "dropid";
my $GETDIR	= "getdir";
my $GETID	= "getid";
my $HALT	= "halt";
my $IDFILE	= "idfile";
my $SETIDFILE	= "setidfile";
my $RMID	= "rmid";
my $RUNNING	= "running";
my $SAVEID	= "saveid";

##############################################################################
#
# These are the switch hashes that determine what routine will be called
# for what O/S classes.
# 
my %switch_uninit =
(
	$CMDINT	   =>	\&uninit_cmdint,
	$DROPID	   =>	\&uninit_dropid,
	$GETDIR	   =>	\&uninit_dir,
	$GETID	   =>	\&uninit_getid,
	$HALT	   =>	\&uninit_halt,
	$IDFILE	   =>	\&uninit_idfile,
	$SETIDFILE =>	\&uninit_set_idfile,
	$RMID	   =>	\&uninit_rmid,
	$RUNNING   =>	\&uninit_running,
	$SAVEID	   =>	\&uninit_saveid,
);

my %switch_unknown =
(
	$CMDINT	   =>	\&unknown_cmdint,
	$DROPID	   =>	\&unknown_dropid,
	$GETDIR	   =>	\&unknown_dir,
	$GETID	   =>	\&unknown_getid,
	$HALT	   =>	\&unknown_halt,
	$IDFILE	   =>	\&unknown_idfile,
	$SETIDFILE =>	\&unknown_set_idfile,
	$RMID	   =>	\&unknown_rmid,
	$RUNNING   =>	\&unknown_running,
	$SAVEID	   =>	\&unknown_saveid,
);

my %switch_unix =
(
	$CMDINT	   =>	\&unix_cmdint,
	$DROPID	   =>	\&unix_dropid,
	$GETDIR	   =>	\&unix_dir,
	$GETID	   =>	\&unix_getpid,
	$HALT	   =>	\&unix_halt,
	$IDFILE	   =>	\&unix_idfile,
	$SETIDFILE =>	\&unix_set_idfile,
	$RMID	   =>	\&unix_rmid,
	$RUNNING   =>	\&unix_running,
	$SAVEID	   =>	\&unix_saveid,
);

my %switch_sysv =
(
	$CMDINT	   =>	\&unix_cmdint,
	$DROPID	   =>	\&unix_psef_dropid,
	$GETDIR	   =>	\&unix_dir,
	$GETID	   =>	\&unix_getpid,
	$HALT	   =>	\&unix_halt,
	$IDFILE	   =>	\&unix_idfile,
	$SETIDFILE =>	\&unix_set_idfile,
	$RMID	   =>	\&unix_rmid,
	$RUNNING   =>	\&unix_running,
	$SAVEID	   =>	\&unix_saveid,
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
	"sysv"	 	=>	\%switch_sysv,
);


##############################################################################
#
# Unix-related constants.
# 

my $UNIX_REALMMGR_DIR	  = makelocalstatedir("run");
our $UNIX_REALMMGR_PIDFILE = ($UNIX_REALMMGR_DIR . $REALMMGR_PID);

my $PS = "/bin/ps";

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
# Routine:      realmmgr_prepdep()
#
# Purpose:	This routine prepares for device-dependent calls.  A global
#		switch table is set, based on the short-form of the operating
#		system's name.
#
#		This *must* be updated whenever this module is ported to
#		a new operating system.
#
sub realmmgr_prepdep
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
	# Figure out which operating system class we're running on.
	#
	if(($osname eq "solaris"))
	{
		$osclass = "sysv";
	}

	#
	# Set the maximum socket-name length depending on which operating
	# system class we're running on.
	#
	if($osname eq "darwin")
	{
		$maxsockname = $MACOSX_MAXSOCKNAME;
	}
	elsif($osname eq "freebsd")
	{
		$maxsockname = $FREEBSD_MAXSOCKNAME;
	}
	elsif($osname eq "linux")
	{
		$maxsockname = $LINUX_MAXSOCKNAME;
	}

	#
	# Get the appropriate switch table for this O/S class and save
	# it for later reference.
	#
	$swtab = $port_archs{$osclass};
	%switchtab = %$swtab;
}

#--------------------------------------------------------------------------
# Routine:      realmmgr_dir()
#
# Purpose:	Front-end to the O/S-specific "get dtrealms'
#		directory" function.
#
sub realmmgr_dir
{
	my @args = @_;				# Routine arguments.
	my $func;				# Actual function.

# print "realmmgr_dir\n";

	$func = $switchtab{$GETDIR};
	return(&$func(@args));
}

#--------------------------------------------------------------------------
# Routine:      realmmgr_dropid()
#
# Purpose:	Front-end to the O/S-specific "save dtrealms'
#		process id" function.
#
sub realmmgr_dropid
{
	my @args = @_;				# Routine arguments.
	my $func;				# Actual function.

# print "realmmgr_dropid\n";

	$func = $switchtab{$DROPID};
	return(&$func(@args));
}

#--------------------------------------------------------------------------
# Routine:      realmmgr_getid()
#
# Purpose:	Front-end to the O/S-specific "get dtrealms'
#		identity" function.
#
sub realmmgr_getid
{
	my @args = @_;				# Routine arguments.
	my $func;				# Actual function.

# print "realmmgr_getid\n";

	$func = $switchtab{$GETID};
	return(&$func(@args));
}

#--------------------------------------------------------------------------
# Routine:      realmmgr_halt()
#
# Purpose:	Front-end to the O/S-specific "halt dtrealms"
#		function.
#
sub realmmgr_halt
{
	my @args = @_;				# Routine arguments.
	my $func;				# Actual function.

# print "realmmgr_halt\n";

	$func = $switchtab{$HALT};
	return(&$func(@args));
}

#--------------------------------------------------------------------------
# Routine:      realmmgr_idfile()
#
# Purpose:	Front-end to the O/S-specific "get dtrealms'
#		identity filename" function.
#
sub realmmgr_idfile
{
	my @args = @_;				# Routine arguments.
	my $func;				# Actual function.

# print "realmmgr_idfile\n";

	$func = $switchtab{$IDFILE};
	return(&$func(@args));
}

#--------------------------------------------------------------------------
# Routine:      realmmgr_set_idfile()
#
# Purpose:	Front-end to the O/S-specific "set dtrealms'
#		identity filename" function.
#
sub realmmgr_set_idfile
{
	my @args = @_;				# Routine arguments.
	my $func;				# Actual function.

# print "realmmgr_set_idfile\n";

	$func = $switchtab{$SETIDFILE};
	return(&$func(@args));
}

#--------------------------------------------------------------------------
# Routine:      realmmgr_cmdint()
#
# Purpose:	Front-end to the O/S-specific "dtrealms has a
#		command" function.
#
sub realmmgr_cmdint
{
	my @args = @_;				# Routine arguments.
	my $func;				# Actual function.

# print "realmmgr_cmdint\n";

	$func = $switchtab{$CMDINT};
	return(&$func(@args));
}

#--------------------------------------------------------------------------
# Routine:      realmmgr_rmid()
#
# Purpose:	Front-end to the O/S-specific "remove dtrealms'
#		identity file" function.
#
sub realmmgr_rmid
{
	my @args = @_;				# Routine arguments.
	my $func;				# Actual function.

# print "realmmgr_rmid\n";

	$func = $switchtab{$RMID};
	return(&$func(@args));
}

#--------------------------------------------------------------------------
# Routine:      realmmgr_running()
#
# Purpose:	Front-end to the O/S-specific "is dtrealms running?" function.
#
sub realmmgr_running
{
	my @args = @_;				# Routine arguments.
	my $func;				# Actual function.

# print "realmmgr_running\n";

	$func = $switchtab{$RUNNING};
	return(&$func(@args));
}

#--------------------------------------------------------------------------
# Routine:      realmmgr_saveid()
#
# Purpose:	Front-end to the O/S-specific "save dtrealms'
#		identity" function.
#
sub realmmgr_saveid
{
	my @args = @_;				# Routine arguments.
	my $func;				# Actual function.

# print "realmmgr_saveid\n";

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
#	initialized.  Each interface calls realmmgr_prepdep() to set up the
#	operating-system-dependent switch table, then calls that O/S's
#	version of the interface.  The O/S-specific results are returned
#	to the caller.  Any subsequent calls to realmmgr_ interfaces will
#	call the proper O/S-dependent interface.

#--------------------------------------------------------------------------
# Routine:      uninit_dir()
#
# Purpose:	Switch for uninitialized "get dir" command.
#
sub uninit_dir
{
	my @args = @_;				# Routine arguments.

# print "uninit_dir\n";

	realmmgr_prepdep();
	return(realmmgr_dir(@args));
}

#--------------------------------------------------------------------------
# Routine:      uninit_dropid()
#
# Purpose:	Switch for uninitialized "drop id" command.
#
sub uninit_dropid
{
	my @args = @_;				# Routine arguments.

# print "uninit_dropid\n";

	realmmgr_prepdep();
	return(realmmgr_dropid(@args));
}

#--------------------------------------------------------------------------
# Routine:      uninit_getid()
#
# Purpose:	Switch for uninitialized "get id" command.
#
sub uninit_getid
{
	my @args = @_;				# Routine arguments.

# print "uninit_getid\n";

	realmmgr_prepdep();
	return(realmmgr_getid(@args));
}

#--------------------------------------------------------------------------
# Routine:      uninit_halt()
#
# Purpose:	Switch for uninitialized "halt" command.
#
sub uninit_halt
{
	my @args = @_;				# Routine arguments.

# print "uninit_halt\n";

	realmmgr_prepdep();
	return(realmmgr_halt(@args));
}

#--------------------------------------------------------------------------
# Routine:      uninit_idfile()
#
# Purpose:	Switch for uninitialized "get id file" command.
#
sub uninit_idfile
{
	my @args = @_;				# Routine arguments.

# print "uninit_idfile\n";

	realmmgr_prepdep();
	return(realmmgr_idfile(@args));
}

#--------------------------------------------------------------------------
# Routine:      uninit_idfile()
#
# Purpose:	Switch for uninitialized "get id file" command.
#
sub uninit_set_idfile
{
	my @args = @_;				# Routine arguments.

# print "uninit_set_idfile\n";

	realmmgr_prepdep();
	return(realmmgr_set_idfile(@args));
}

#--------------------------------------------------------------------------
# Routine:      uninit_cmdint()
#
# Purpose:	Switch for uninitialized "force queue" command.
#
sub uninit_cmdint
{
	my @args = @_;				# Routine arguments.

# print "uninit_cmdint\n";

	realmmgr_prepdep();
	return(realmmgr_cmdint(@args));
}

#--------------------------------------------------------------------------
# Routine:      uninit_rmid()
#
# Purpose:	Switch for uninitialized "remove id file" command.
#
sub uninit_rmid
{
	my @args = @_;				# Routine arguments.

# print "uninit_rmid\n";

	realmmgr_prepdep();
	return(realmmgr_rmid(@args));
}

#--------------------------------------------------------------------------
# Routine:      uninit_running()
#
# Purpose:	Switch for uninitialized "is dtrealms running?" command.
#
sub uninit_running
{
	my @args = @_;				# Routine arguments.

# print "uninit_running\n";

	realmmgr_prepdep();
	return(realmmgr_running(@args));
}

#--------------------------------------------------------------------------
# Routine:      uninit_saveid()
#
# Purpose:	Switch for uninitialized "save id file" command.
#
sub uninit_saveid
{
	my @args = @_;				# Routine arguments.

# print "uninit_saveid\n";

	realmmgr_prepdep();
	return(realmmgr_saveid(@args));
}


##############################################################################
##############################################################################
##############################################################################
#
# Unknown switch functions
#
#	These interfaces are called when the operating system was not
#	recognized by realmmgr_prepdep().  In all cases, the routine
#	prints an error message and exits.
#

#--------------------------------------------------------------------------
# Routine:      unknown_action()
#
sub unknown_action
{
	err("realmmgr.pm has not been ported to your system yet; cannot continue until this has been done.\n",42);
}

#--------------------------------------------------------------------------
# Routine:      unknown_dir()
#
sub unknown_dir
{
	unknown_action();
}

#--------------------------------------------------------------------------
# Routine:      unknown_getid()
#
sub unknown_getid
{
	unknown_action();
}

#--------------------------------------------------------------------------
# Routine:      unknown_halt()
#
sub unknown_halt
{
	unknown_action();
}

#--------------------------------------------------------------------------
# Routine:      unknown_idfile()
#
sub unknown_idfile
{
	unknown_action();
}

#--------------------------------------------------------------------------
# Routine:      unknown_set_idfile()
#
sub unknown_set_idfile
{
	unknown_action();
}

#--------------------------------------------------------------------------
# Routine:      unknown_cmdint()
#
sub unknown_cmdint
{
	unknown_action();
}

#--------------------------------------------------------------------------
# Routine:      unknown_rmid()
#
sub unknown_rmid
{
	unknown_action();
}

#--------------------------------------------------------------------------
# Routine:      unknown_running()
#
sub unknown_running
{
	unknown_action();
}

#--------------------------------------------------------------------------
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
# Routine:      unix_dir()
#
sub unix_dir
{
	return($UNIX_REALMMGR_DIR);
}

#--------------------------------------------------------------------------
# Routine:	unix_idfile()
#
# Purpose:	Return dtrealms' id file.
#
sub unix_idfile
{
	return($UNIX_REALMMGR_PIDFILE);
}

#--------------------------------------------------------------------------
# Routine:	unix_set_idfile()
#
# Purpose:	Sets dtrealms' id file to a particular value
#
sub unix_set_idfile
{
	$UNIX_REALMMGR_PIDFILE = $_[0];
}

#--------------------------------------------------------------------------
# Routine:	unix_psef_dropid()
#
# Purpose:      Replaces unix_dropid on ps -ef based systems
#
sub unix_psef_dropid
{
	return unix_dropid('-ps', '-ef', 1, @_);
}

#--------------------------------------------------------------------------
# Routine:	unix_dropid()
#
# Purpose:	Ensures that another instance of dtrealms is not running and
#		then creates a pid file for future reference.
#
# Options:      [-ps FLAGS PIDPOSITION]
#
# Return Values:
#		 1 - The pidfile was initialized for this process.
#		 0 - Another process (not this one) is already acting as
#		     dtrealms.
#		-1 - An error was encountered.
#
sub unix_dropid
{
	my $ego = $$;					# My identity.
	my $pfpid;					# Pid from the pidfile.
	my $pspid = -1;					# Pid from ps execution.
	my $psflags = "wax";
	my $pidposition = 0;

	if ($_[0] eq '-ps')
	{
		shift @_;
		$psflags = shift @_;
		$pidposition = shift @_;
	}

# print "unix_dropid:  down in\n";

	#
	# Get the pid from dtrealms' pidfile.
	#
	$pfpid = unix_getpid(0);

	#
	# Create the file if it doesn't exist.
	# If it does exist, we'll make sure the listed process isn't running.
	# If we can't create it, we'll complain and return a failure code.
	#
	if($pfpid < 0)
	{
# print "unix_dropid:  opening $UNIX_REALMMGR_PIDFILE\n";

		unlink("$UNIX_REALMMGR_PIDFILE");
		if(open(PIDFILE,"> $UNIX_REALMMGR_PIDFILE") == 0)
		{
			warn "DROPID UNABLE TO OPEN \"$UNIX_REALMMGR_PIDFILE\"\n";
			return(-1);
		}

		flock(PIDFILE,LOCK_EX);
	}
	else
	{
		my $pid;			# Pid from ps output.
		my $pscmd;			# ps command to execute.
		my $psline;			# Output line from ps.
		my $openrc;			# Return code from open().

# print "unix_dropid:  $UNIX_REALMMGR_PIDFILE exists\n";
		flock(PIDFILE,LOCK_EX);

		#
		# Get the process status of the process having the pid
		# we found in the pidfile.
		#
		#	We shouldn't have to do this this way.
		#	We should be able to do "ps -p $pfpid" and
		#	skip the search loop.
		#	However, the $pfpid seems to be dropped
		#	when using that method.
		#
		$pscmd = "$PS $psflags";
		$openrc = open(PSOUT,"$pscmd |");
		$psline = <PSOUT>;
		while(<PSOUT>)
		{
			my @psout;		# ps line array.

			#
			# Skip this line if it isn't a dtrealms line.
			#
			next if(! /dtrealms/);

			#
			# Get the pid from the line and drop out.
			#
			s/^[ ]*//;
			@psout = split / +/;
			$pspid = $psout[$pidposition];
			last;
		}
		close(PSOUT);

		#
		# Check if the pidfile's process is still running.
		# Return success if the current, executing manager is us.
		# Return failure if the current manager isn't us.
		#
		if($pfpid == $pspid)
		{
			flock(PIDFILE,LOCK_UN);

			return(1) if($pspid == $ego);
			return(0);
		}
	}

	#
	# Zap the file contents.
	#
	truncate($UNIX_REALMMGR_PIDFILE,0);

	#
	# Save our pid as THE dtrealms' pid.
	#
	seek(PIDFILE,0,0);
	print PIDFILE "$ego\n";
	flock(PIDFILE,LOCK_UN);
	close(PIDFILE);

	#
	# Save our pid as the internal version of the manager's pid and
	# return success.
	#
	$realmmgrid = $ego;
	return(1);
}


#--------------------------------------------------------------------------
# Routine:	unix_rmid()
#
# Purpose:	Delete dtrealms' pidfile.  This is done as part of the
#		manager's clean-up process.
#
# Return Values:
#		 1 - The pidfile was deleted.
#		 0 - No pidfile exists.
#		-1 - The calling process is not dtrealms.
#		-2 - Unable to delete the pidfile.
#
sub unix_rmid
{
	my $ego = $$;				# My identity.
	my $flret;				# flock() return code.
	my $rdpid;				# Pid read from the pidfile.

# print "unix_rmid:  down in\n";

	#
	# Get the pid from dtrealms' pidfile.
	#
	$rdpid = unix_getpid(0);
	flock(PIDFILE,LOCK_EX);

	#
	# Complain and return if there is not pidfile.
	#
	if($rdpid == -1)
	{
# print "unix_rmid:  dtrealms' pidfile does not exist\n";
		return(0);
	}

	#
	# Ensure that this process is the One True Realms Manager.
	#
	if($rdpid != $ego)
	{
# print "unix_rmid:  we are not dtrealms\n";
		return(-1);
	}

	#
	# Get rid of the pidfile.
	#
	if(unlink($UNIX_REALMMGR_PIDFILE) != 1)
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
# Routine:	unix_running()
#
# Purpose:	Determine if dtrealms is running and return a boolean
#		indicating the status.
#
# Return Values:
#		 1 - The pidfile's process is running.
#		 0 - The pidfile's process is not running.
#		-1 - Unable to read the pidfile.
#
sub unix_running
{
	my $ret;				# kill() return code.
	my $rdpid;				# dtrealms' pid (from pidfile.)

# print "unix_running:  down in\n";

	#
	# Get the pid from dtrealms' pidfile.
	#
	$rdpid = unix_getpid(1);

	#
	# Complain and return if there is not pidfile.
	#
	if($rdpid == -1)
	{
		return(-1);
	}

	#
	# Find out if dtrealms is alive.  If it isn't, return 0.
	#
	$ret = kill 0, $rdpid;
	return(0) if($ret == 0);

	#
	# Check if the pid's procname is dtrealms, returning an indicator.
	#
	$ret = `$PS -p $rdpid`;
	return(0) if($ret !~ /(dtrealms|perl)/);
	return(1);
}

#--------------------------------------------------------------------------
# Routine:	unix_getpid()
#
# Purpose:	Return dtrealms, as recorded in its pidfile.
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

# print "unix_getpid:  down in\n";

	#
	# Return an error if the file doesn't exist.
	#
	return(-1) if(stat($UNIX_REALMMGR_PIDFILE) == 0);

	#
	# Open and lock the pidfile.
	#
	close(PIDFILE);
	if(open(PIDFILE,"+< $UNIX_REALMMGR_PIDFILE") == 0)
	{
#		err("unix_getpid:  unable to open \"$UNIX_REALMMGR_PIDFILE\"\n",-1);
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
# Routine:	unix_cmdint()
#
# Purpose:	Kick dtrealms to let it know it should re-read the realms
#		file and process its queue again.
#
sub unix_cmdint
{
	my $pid;				# dtrealms's pid.
	my $ret;				# Return code from kill().

# print "unix_cmdint:  down in\n";

	#
	# Get dtrealms' process id.  Return an error if we couldn't get it
	# or if what we got is below some low arbitrary limit.
	#
	$pid = unix_getpid(1);
	return(-1) if(!defined($pid) ||  ($pid < 10));

	#
	# Send HUP to dtrealms.
	#
	$ret = kill("HUP", $pid);
	return($ret);
}

#--------------------------------------------------------------------------
# Routine:	unix_halt()
#
# Purpose:	Tell dtrealms to shut down.
#
sub unix_halt
{
	my $pid;				# dtrealms's pid.
	my $ret;				# Return code from kill().

# print "unix_halt:  down in\n";

	#
	# Get dtrealms' process id.  Return an error if we couldn't get it
	# or if what we got is below some low arbitrary limit.
	#
	$pid = unix_getpid(1);
	return(-1) if(!defined($pid) ||  ($pid < 10));

	#
	# Send INT to dtrealms.
	#
	$ret = kill('INT',$pid);
	return($ret);
}

#############################################################################
#############################################################################
#############################################################################

#-----------------------------------------------------------------------------
# Routine:	realmmgr_channel()
#
# Purpose:	This routine initializes a socket to use for dtrealms
#		communications.  It is called by both dtrealms and dtrealms
#		clients.
#
#		Currently, we're only setting up to connect to a dtrealms
#		running on our own host.  In time, we may allow remote
#		connections.
#
sub realmmgr_channel
{
	my $server = shift;				# Server/client flag.

# print "realmmgr_channel($server):  down in\n";

	#
	# Close any previously opened sockets.
	#
	close(CLNTSOCK);
	close(SOCK);

	if($CHANNEL_TYPE == PF_INET)
	{

		my $remote = "localhost";		# Server's hostname.
		my $serveraddr;				# Server's address.
		my $conaddr;				# Address in connect().
		my $proto = getprotobyname("tcp");	# Protocol to use.

		#
		# Create a socket.
		#
		socket(SOCK,PF_INET,SOCK_STREAM,$proto);

		#
		# For the server, we'll set the socket's address and mark
		# it as connectable.
		# For the client, we'll get the address of the server and
		# connect to it.  (Right now, we're only talking to localhost.)
		#
		if($server)
		{
			setsockopt(SOCK,SOL_SOCKET,SO_REUSEADDR,pack("l",1));
			bind(SOCK,sockaddr_in($CMDPORT,$ADDR)) || return(-2);
			listen(SOCK,SOMAXCONN) || return(-4);
		}
		else
		{
			$remote = "localhost";

			$serveraddr = inet_aton($remote);
			$conaddr = sockaddr_in($CMDPORT,$serveraddr);

			connect(SOCK,$conaddr) || return(0);
		}
	}
	elsif($CHANNEL_TYPE == PF_UNIX)
	{
		my $sockdata;				# Path for socket.
		my $unixsock;				# Unix socket file.

		#
		# Build the socket name and construct the socket data.
		#
		$unixsock = makelocalstatedir("/dnssec-tools") . $UNIXSOCK;
# print STDERR "realmmgr_channel:  unixsock - <$unixsock>\n";

		#
		# Ensure the socket name isn't too long.  This is a result
		# of a hardcode maximum length for socket names.  This is
		# in the kernel and isn't 
		#
		return(-5) if(length($unixsock) > $maxsockname);

		$sockdata = sockaddr_un($unixsock);

		#
		# For the server, we'll create the socket's file and bind it.
		# For the client, we'll get the connect to the server's socket.
		#
		if($server)
		{
			#
			# Create a Unix domain socket.
			#
			socket(SOCK,PF_UNIX,SOCK_STREAM,0) || return(-1);

			unlink($unixsock);
			bind(SOCK,$sockdata)	|| return(-2);
			chmod 0600, $unixsock	|| return(-3);
			listen(SOCK,SOMAXCONN)	|| return(-4);
		}
		else
		{
			#
			# Create and connect to a Unix domain socket.
			#
			socket(CLNTSOCK,PF_UNIX,SOCK_STREAM,0)	|| return(-1);
			connect(CLNTSOCK,$sockdata)		|| return(0);

		}
	}

	return(1);
}

#-----------------------------------------------------------------------------
# Routine:	realmmgr_closechan()
#
# Purpose:	This routine closes down the communications channel to
#		dtrealms.  It is called by both dtrealms and dtrealms clients.
#
sub realmmgr_closechan
{
# print "realmmgr_closechan:  down in\n";
	close(CLNTSOCK);
}

#-----------------------------------------------------------------------------
# Routine:	realmmgr_queuecmd()
#
# Purpose:	This routine can be called internally to queue a command
#		for later processing via calls to realmmgr_getcmd().
#		It is useful when doing initial start-up before full
#		processing is to commence.  Commands queued by this
#		process take precedence over commands received via the
#		command interface (ie, via realmmgr_sendcmd()).
#
sub realmmgr_queuecmd
{
	my ($cmd, $value) = @_;

	return(0) if (realmmgr_verifycmd($cmd) == 0);
	push @queuedcmds, [$cmd, $value];
}

#-----------------------------------------------------------------------------
# Routine:	realmmgr_getqueueitem()
#
# Purpose:	This routine can be called pull a command from the queue
#		This is intended to process the item, so it is removed
#		from the queue.
#
sub realmmgr_getqueueitem
{
	if($#queuedcmds > -1)
	{
		my $cmd = shift @queuedcmds;
		return($cmd);
	}
}

#-----------------------------------------------------------------------------
# Routine:	realmmgr_getallqueuedcmds()
#
# Purpose:	This routine returns all the queued commands in the stack
#		The items are left in place unless a truthful argument
#		(e.g. "1") is passed in.
#
sub realmmgr_getallqueuedcmds
{
	my $removefromqueue = shift;
	my @results = @queuedcmds;

	@queuedcmds = () if ($removefromqueue);
	return(@queuedcmds);
}

#-----------------------------------------------------------------------------
# Routine:	realmmgr_getcmd()
#
# Purpose:	This routine is called by the server to fetch a command and
#		its data from the command socket.  realmmgr_channel() is
#		assumed to have been called to initialize the command socket.
#
sub realmmgr_getcmd
{
	my $waiter = shift || 5;		# Time to wait for connect.

	my $cmd;				# Client's command.
	my $data;				# Command's data.

	my $accresp;				# Response from accept().

	my $oldhandler = $SIG{ALRM};		# Old alarm handler.

# print "realmmgr_getcmd:  down in\n";

	#
	# if we have anything queued up, process those first.
	#
	my $cmdandvalue = realmmgr_getqueueitem();
	return(@$cmdandvalue)
	    if(defined($cmdandvalue) && (ref($cmdandvalue) eq 'ARRAY'));

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
	$accresp = accept(CLNTSOCK,SOCK);
	return if(!defined($accresp));

	#
	# Do any required domain-specific checks.
	#
	if($CHANNEL_TYPE == PF_INET)
	{
		my $raddr;				# Client's address.
		my $clntname;				# Client's name.
		my $rport;				# Remote port.

		#
		# Convert the client's address into a hostname.
		#
		($rport,$raddr) = sockaddr_in($accresp);
		$clntname = gethostbyaddr($raddr,AF_INET);
# print "realmmgr_getcmd:  connection from <$clntname>\n";

		#
		# Ensure we're coming from the localhost.
		#
		return("bad host","$clntname","") if($clntname ne "localhost");
	}
	elsif($CHANNEL_TYPE == PF_UNIX)
	{
		#
		# Nothing to do now for Unix-domain sockets.
		#
	}

	#
	# Get the command and data, and lop off the trailing goo.
	#
	$cmd  = <CLNTSOCK>;
	$data = <CLNTSOCK>;
	$cmd  =~ s/ $EOL$//;
	$data =~ s/ $EOL$//;

	#
	# Turn off the alarm and reset the alarm handler.
	#
	alarm(0);
	$SIG{ALRM} = $oldhandler;

	#
	# Close the remote socket and return the client's data.
	#
	return($cmd,$data);
}

#-----------------------------------------------------------------------------
# Routine:	realmmgr_sendcmd()
#
# Purpose:	This routine allows a client to send a message to the server.
#		No other routines need be called to initialize anything.
#
sub realmmgr_sendcmd
{
	my $close = shift;				# Close flag.
	my $cmd	  = shift;				# Command to send.
	my $data  = shift;				# Data for command.

	my $oldsel;					# Currently selected fh.
	my $resp;					# Response.
	my $ret	 = 1;					# Return code.

# print "realmmgr_sendcmd:  down in\n";

	return(0) if(realmmgr_verifycmd($cmd) == 0);

	#
	# Create the communications channel to dtrealms and send the message.
	#
	return(0) if(realmmgr_channel(0) != 1);

	#
	# Make CLNTSOCK autoflush its output.
	#
	$oldsel = select(CLNTSOCK);
	$| = 1;

	#
	# Send the command and data.
	#
	print CLNTSOCK "$cmd $EOL";
	print CLNTSOCK "$data $EOL";

	#
	# Select the previous file handle once more.
	#
	select($oldsel);

	#
	# Close the socket if the client doesn't want a response.
	#
	close(CLNTSOCK) if($close);

	#
	# Let dtrealms know there's a command waiting.
	#
	realmmgr_cmdint();

	return(1);
}

#-----------------------------------------------------------------------------
# Routine:	realmmgr_sendresp()
#
# Purpose:	This routine allows dtrealms to send a message to a client.
#
sub realmmgr_sendresp
{
	my $retcode = shift;				# Return code.
	my $respmsg = shift;				# Response message.

	my $oldsel;					# Currently selected fh.

# print STDERR "realmmgr_sendresp:  down in\n";

	#
	# Make CLNTSOCK autoflush its output.
	#
	$oldsel = select(CLNTSOCK);
	$| = 1;

	#
	# Send the return code and response message.
	#
	print CLNTSOCK "$retcode $EOL";
	print CLNTSOCK "$respmsg $EOL";

	#
	# Select the previous file handle once more.
	#
	select($oldsel);
}

#-----------------------------------------------------------------------------
# Routine:	realmmgr_getresp()
#
# Purpose:	This routine allows a client to wait for a message response
#		from the server.  It will keep reading response lines until
#		either the socket closes or the timer expires.
#
sub realmmgr_getresp
{
	my $retcode = -1;				# Return code.
	my $respbuf;					# Response buffer.

	my $oldhandler = $SIG{ALRM};			# Old alarm handler.
	my $waiter = 5;					# Wait-time for resp.

# print "realmmgr_getresp:  down in\n";

	#
	# Set a time limit on how long we'll wait for the response.
	# Our alarm handler is a dummy, only intended to keep us from
	# waiting forever.
	#
	$SIG{ALRM} = sub { my $foo = 42 };
	alarm($waiter);

	#
	# Get the response code and message from dtrealms.
	#
	$retcode = <CLNTSOCK>;
	while(<CLNTSOCK>)
	{
		$respbuf .= $_;
	}
	$retcode =~ s/ $EOL$//;
	$respbuf =~ s/ $EOL$//;

	#
	# Reset the alarm handler and return the response buffer.
	#
	alarm(0);
	$SIG{ALRM} = $oldhandler;
	return($retcode,$respbuf);
}

#-----------------------------------------------------------------------------
# Routine:	realmmgr_verifycmd()
#
# Purpose:	This routine returns a boolean indicating if the specified
#		command is a valid command for the realms daemon.
#
sub realmmgr_verifycmd
{
	my $cmd	 = shift;				# Command to check.
	my $hval;					# Command hash value.

# print "realmmgr_verifycmd:  down in\n";

	$hval = $realm_commands{$cmd};
# print "realmmgr_verifycmd:  <$cmd>\t\t<$hval>\n";

	#
	# Success!
	#
	return(1);
}

1;

#############################################################################

=pod

=head1 NAME

Net::DNS::SEC::Tools::realmmgr - Communicate with the DNSSEC-Tools realms
manager.

=head1 SYNOPSIS

  use Net::DNS::SEC::Tools::realmmgr;

  $dir = realmmgr_dir();

  $idfile = realmmgr_idfile();

  $id = realmmgr_getid();

  realmmgr_dropid();

  realmmgr_rmid();

  realmmgr_cmdint();

  $runflag = realmmgr_running();

  realmmgr_halt();

  realmmgr_channel(1);
  ($cmd,$data) = realmmgr_getcmd();
  $ret = realmmgr_verifycmd($cmd);

  realmmgr_sendcmd(CHANNEL_CLOSE,REALMCMD_STARTREALM,"example-realm");

  realmmgr_sendcmd(CHANNEL_WAIT,REALMCMD_STARTREALM,"example-realm");
  ($retcode, $respmsg) = realmmgr_getresp();

=head1 DESCRIPTION

The B<Net::DNS::SEC::Tools::realmmgr> module provides standard,
platform-independent methods for a program to communicate with DNSSEC-Tools'
B<dtrealms> realms manager.  There are two interface classes described
here:  general interfaces and communications interfaces.

=head1 GENERAL INTERFACES

The interfaces to the B<Net::DNS::SEC::Tools::realmmgr> module are given below.

=over 4

=item I<realmmgr_dir()>

This routine returns B<dtrealms>'s directory.

=item I<realmmgr_idfile()>

This routine returns B<dtrealms>'s id file.

=item I<realmmgr_getid()>

This routine returns B<dtrealms>'s process id.  If a non-zero value
is passed as an argument, the id file will be left open and accessible through
the PIDFILE file handle.  See the WARNINGS section below.

Return Values:

    On success, the first portion of the file contents
	(up to 80 characters) is returned.
    -1 is returned if the id file does not exist.

=item I<realmmgr_dropid()>

This interface ensures that another instance of B<dtrealms> is not
running and then creates a id file for future reference.

Return Values:

    1 - the id file was successfully created for this process
    0 - another process is already acting as dtrealms
   -1 - unable to create the id file

=item I<realmmgr_rmid()>

This interface deletes B<dtrealms>'s id file.

Return Values:

     1 - the id file was successfully deleted
     0 - no id file exists
    -1 - the calling process is not dtrealms
    -2 - unable to delete the id file

=item I<realmmgr_cmdint()>

This routine informs B<dtrealms> that a command has been sent via
I<realmmgr_sendcmd()>.

Return Values:

    -1 - an invalid process id was found for dtrealms
    Anything else indicates the number of processes that were
    signaled.
    (This should only ever be 1.)

=item I<realmmgr_running()>

This routine determines if dtrealms is running and returns a value indicating
the status.

Return Values:

     1 - dtrealms is running.
     0 - The process listed in the dtrealms process id file
	 is not running.
    -1 - Unable to get the dtrealms process id.

=item I<realmmgr_halt()>

This routine informs B<dtrealms> to shut down.

In the current implementation, the return code from the B<kill()> command is
returned.

    -1 - an invalid process id was found for dtrealms
    Anything else indicates the number of processes that were
    signaled.
    (This should only ever be 1.)

=back

=head1 DTREALMS COMMUNICATIONS INTERFACES

=over 4

=item I<realmmgr_channel(serverflag)>

This interface sets up a persistent channel for communications with B<dtrealms>.
If I<serverflag> is true, then the server's side of the channel is created.
If I<serverflag> is false, then the client's side of the channel is created.

Currently, the connection may only be made to the localhost.  This may be
changed to allow remote connections, if this is found to be needed.

Return Values:

      1 - Communications channel successfully established.
      0 - Unable to connect to the server.
     -1 - Unable to create a Unix socket.
     -2 - Unable to bind to the Unix socket. (server only)
     -3 - Unable to change the permissions on the Unix socket. (server only)
     -4 - Unable to listen on the Unix socket. (server only)
     -5 - The socket name was longer than allowed for a Unix socket.

=item I<realmmgr_queuecmd(cmdname, value)>

This interface internally remembers a command and it's optional value
for later processing.  See the I<realmmgr_getcmd()> next for further
details.

=item I<realmmgr_getcmd()>

I<realmmgr_getcmd()> processes commands that need to be dealt with.  If
there are any internally stored commands queued via the
I<realmmgr_queuecmd()> function, they are dealt with first.  After that it
retrieves a command sent over B<dtrealms>'s communications channel by a
client program.  The command and the command's data are sent in each
message.

The command and the command's data are returned to the caller.

=item I<realmmgr_sendcmd(closeflag,cmd,data)>

I<realmmgr_sendcmd()> sends a command to B<dtrealms>.  The command must be one
of the commands from the table below.  This interface creates a communications
channel to B<dtrealms> and sends the message.  The channel is not closed, in
case the caller wants to receive a response from B<dtrealms>.

The available commands and their required data are:

   command		data		purpose
   -------		----		-------
   REALMCMD_COMMAND     realm, command	run command in a realm
   REALMCMD_DISPLAY	1/0		start/stop dtrealms'
					graphical display
   REALMCMD_GETSTATUS	none		currently unused
   REALMCMD_LOGFILE	log filename	change the log file
   REALMCMD_LOGLEVEL	log level	set a new logging level
   REALMCMD_LOGMSG	log message	add a message to the log
   REALMCMD_LOGTZ	timezone	set timezone for log messages
   REALMCMD_NODISPLAY	0		stop dtrealms' graphical display
   REALMCMD_REALMSTATUS	none		get status of the realms
   REALMCMD_SHUTDOWN	none		stop dtrealms and its realms
   REALMCMD_STARTALL	none		start all stopped realms
   REALMCMD_STOPALL	none		stop all running realms
   REALMCMD_STARTREALM	realm name	restart a suspended realm
   REALMCMD_STOPREALM	realm name	stop realm
   REALMCMD_STATUS	none		get status of dtrealms

The data aren't checked for validity by I<realmmgr_sendcmd()>; validity
checking is a responsibility of B<dtrealms>.

If the caller does not need a response from B<dtrealms>, then I<closeflag>
should be set to B<CHANNEL_CLOSE>; if a response is required then
I<closeflag> should be B<CHANNEL_WAIT>.  These values are boolean values,
and the constants aren't required.

On success, 1 is returned.  If an invalid command is given, 0 is returned.

=item I<realmmgr_getresp()>

After executing a client command sent via I<realmmgr_sendcmd()>, B<dtrealms>
will send a response to the client.  I<realmmgr_getresp()> allows
the client to retrieve the response.

A return code and a response string are returned, in that order.  Both are
specific to the command sent.

=item I<realmmgr_verifycmd(cmd)>

I<realmmgr_verifycmd()> verifies that I<cmd> is a valid command for B<dtrealms>.
1 is returned for a valid command; 0 is returned for an invalid command.

1 is returned for a valid command; 0 is returned for an invalid command.

=back

=head1 WARNINGS

1.  I<realmmgr_getid()> attempts to exclusively lock the id file.
Set a timer if this matters to you.

2.  I<realmmgr_getid()> has a nice little race condition.  We should lock
the file prior to opening it, but we can't do so without it being open.

=head1 COPYRIGHT

Copyright 2012-2014 SPARTA, Inc.  All rights reserved.
See the COPYING file included with the DNSSEC-Tools package for details.

=head1 AUTHOR

Wayne Morrison, tewok@tislabs.com

=head1 SEE ALSO

B<realmctl(1)>

B<dtrealms(8)>

B<Net::DNS::SEC::Tools::realm.pm(3)>,
B<Net::DNS::SEC::Tools::rolllog.pm(3)>,
B<Net::DNS::SEC::Tools::rollmgr.pm(3)>

=cut

