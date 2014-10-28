#
# Copyright 2005-2014 SPARTA, Inc.  All rights reserved.  See the COPYING
# file distributed with this software for details
#
# DNSSEC Tools
#
# rollmgr.pm -	Rollover manager functions.
#
#	The routines in this module provide a means to communicate with
#	rollerd.
#
#
#	Introduction
#		This module provides interfaces for communicating with the
#		DNSSEC-Tools' rollover manager.  The top-level interfaces
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

use Net::DNS::SEC::Tools::conf;
use Net::DNS::SEC::Tools::defaults;
use Net::DNS::SEC::Tools::rolllog;

our $VERSION = "2.0";
our $MODULE_VERSION = "2.0.0";

our @ISA = qw(Exporter);

our @EXPORT = qw(
		 rollmgr_cmdint
		 rollmgr_dir
		 rollmgr_dropid
		 rollmgr_getid
		 rollmgr_halt
		 rollmgr_idfile
		 rollmgr_set_idfile
		 rollmgr_loadzone
		 rollmgr_phasemsg
		 rollmgr_rmid
		 rollmgr_running
		 rollmgr_saveid

		 rollmgr_channel
		 rollmgr_closechan
		 rollmgr_getcmd
		 rollmgr_getresp
		 rollmgr_sendcmd
		 rollmgr_queuecmd
		 rollmgr_getqueueitem
		 rollmgr_getallqueuedcmds
		 rollmgr_sendresp
		 rollmgr_verifycmd
		 rollmgr_get_phase

			 ROLLCMD_DISPLAY
			 ROLLCMD_DSPUB
			 ROLLCMD_DSPUBALL
			 ROLLCMD_GETSTATUS
			 ROLLCMD_LOGFILE
			 ROLLCMD_LOGLEVEL
			 ROLLCMD_LOGMSG
			 ROLLCMD_LOGTZ
			 ROLLCMD_MERGERRFS
			 ROLLCMD_PHASEMSG
			 ROLLCMD_ROLLALL
			 ROLLCMD_ROLLALLKSKS
			 ROLLCMD_ROLLALLZSKS
			 ROLLCMD_ROLLKSK
			 ROLLCMD_ROLLREC
			 ROLLCMD_ROLLZONE
			 ROLLCMD_ROLLZSK
			 ROLLCMD_RUNQUEUE
			 ROLLCMD_QUEUELIST
			 ROLLCMD_QUEUESTATUS
			 ROLLCMD_SHUTDOWN
			 ROLLCMD_SIGNZONE
			 ROLLCMD_SIGNZONES
			 ROLLCMD_SKIPALL
			 ROLLCMD_SKIPZONE
			 ROLLCMD_SLEEPTIME
			 ROLLCMD_SPLITRRF
			 ROLLCMD_STATUS
			 ROLLCMD_ZONELOG
			 ROLLCMD_ZONEGROUP
			 ROLLCMD_ZONESTATUS
			 ROLLCMD_ZSARGS

			 ROLLMGR_GROUP

			 ROLLCMD_RC_BADEVENT
			 ROLLCMD_RC_BADFILE
			 ROLLCMD_RC_BADLEVEL
			 ROLLCMD_RC_BADROLLREC
			 ROLLCMD_RC_BADSLEEP
			 ROLLCMD_RC_BADTZ
			 ROLLCMD_RC_BADZONE
			 ROLLCMD_RC_BADZONEDATA
			 ROLLCMD_RC_BADZONEGROUP
			 ROLLCMD_RC_DISPLAY
			 ROLLCMD_RC_KSKROLL
			 ROLLCMD_RC_NOARGS
			 ROLLCMD_RC_NOZONES
			 ROLLCMD_RC_OKAY
			 ROLLCMD_RC_RRFOPEN
			 ROLLCMD_RC_ZSKROLL

			 CHANNEL_WAIT
			 CHANNEL_CLOSE
		);

my $rollmgrid;				# Rollerd's process id.

##############################################################################
#
# These "constants" are used by rollerd's command interfaces.
# 

my $ADDR	= INADDR_ANY;			# rollerd's server address.
my $CMDPORT	= 880109;			# rollerd's server port.
my $EOL		= "\015\012";			# Net-standard end-of-line.

my $CHANNEL_TYPE = PF_UNIX;			# Type of channel we're using.
my $UNIXSOCK	= "/rollmgr.socket";		# Unix socket name.

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
# The CHANNEL_ entities are used for specifying whether rollmgr_sendcmd()
# should or should not wait for a response from rollerd.
#
my $CHANNEL_WAIT	= 0;
my $CHANNEL_CLOSE	= 1;
sub CHANNEL_WAIT		{ return($CHANNEL_WAIT);	};
sub CHANNEL_CLOSE		{ return($CHANNEL_CLOSE);	};
my @queuedcmds;

#
# The ROLLCMD_RC_ entities are return codes sent from rollerd and received
# by client programs from rollmgr_getresp().
#
my $ROLLCMD_RC_OKAY		= 0;
my $ROLLCMD_RC_BADLEVEL		= 1;
my $ROLLCMD_RC_BADFILE		= 2;
my $ROLLCMD_RC_BADSLEEP	 	= 3;
my $ROLLCMD_RC_BADROLLREC	= 4;
my $ROLLCMD_RC_BADTZ		= 5;
my $ROLLCMD_RC_RRFOPEN		= 6;
my $ROLLCMD_RC_NOZONES		= 7;
my $ROLLCMD_RC_BADZONE		= 8;
my $ROLLCMD_RC_BADZONEDATA	= 9;
my $ROLLCMD_RC_DISPLAY		= 10;
my $ROLLCMD_RC_KSKROLL		= 11;
my $ROLLCMD_RC_ZSKROLL		= 12;
my $ROLLCMD_RC_NOARGS		= 13;
my $ROLLCMD_RC_BADEVENT		= 14;
my $ROLLCMD_RC_BADZONEGROUP	= 15;

sub ROLLCMD_RC_OKAY		{ return($ROLLCMD_RC_OKAY);		};
sub ROLLCMD_RC_BADEVENT		{ return($ROLLCMD_RC_BADEVENT);		};
sub ROLLCMD_RC_BADFILE		{ return($ROLLCMD_RC_BADFILE);		};
sub ROLLCMD_RC_BADLEVEL		{ return($ROLLCMD_RC_BADLEVEL);		};
sub ROLLCMD_RC_BADROLLREC	{ return($ROLLCMD_RC_BADROLLREC);	};
sub ROLLCMD_RC_BADSLEEP		{ return($ROLLCMD_RC_BADSLEEP);		};
sub ROLLCMD_RC_BADTZ		{ return($ROLLCMD_RC_BADTZ);		};
sub ROLLCMD_RC_BADZONE		{ return($ROLLCMD_RC_BADZONE);		};
sub ROLLCMD_RC_BADZONEDATA	{ return($ROLLCMD_RC_BADZONEDATA);	};
sub ROLLCMD_RC_BADZONEGROUP	{ return($ROLLCMD_RC_BADZONEGROUP);	};
sub ROLLCMD_RC_DISPLAY		{ return($ROLLCMD_RC_DISPLAY);		};
sub ROLLCMD_RC_KSKROLL		{ return($ROLLCMD_RC_KSKROLL);		};
sub ROLLCMD_RC_NOARGS		{ return($ROLLCMD_RC_NOARGS);		};
sub ROLLCMD_RC_NOZONES		{ return($ROLLCMD_RC_NOZONES);		};
sub ROLLCMD_RC_RRFOPEN		{ return($ROLLCMD_RC_RRFOPEN);		};
sub ROLLCMD_RC_ZSKROLL		{ return($ROLLCMD_RC_ZSKROLL);		};

#
# The remaining ROLLCMD_ entities are the rollmgr_sendcmd() commands
# recognized by rollerd.  %roll_commands is a hash table of valid commands.
#
my $ROLLCMD_DISPLAY	 = "rollcmd_display";
my $ROLLCMD_DSPUB	 = "rollcmd_dspub";
my $ROLLCMD_DSPUBALL	 = "rollcmd_dspuball";
my $ROLLCMD_GETSTATUS	 = "rollcmd_getstatus";
my $ROLLCMD_LOGFILE	 = "rollcmd_logfile";
my $ROLLCMD_LOGLEVEL	 = "rollcmd_loglevel";
my $ROLLCMD_LOGMSG	 = "rollcmd_logmsg";
my $ROLLCMD_LOGTZ	 = "rollcmd_logtz";
my $ROLLCMD_MERGERRFS	 = "rollcmd_mergerrfs";
my $ROLLCMD_PHASEMSG	 = "rollcmd_phasemsg";
my $ROLLCMD_ROLLALL	 = "rollcmd_rollall";
my $ROLLCMD_ROLLALLKSKS	 = "rollcmd_rollallksks";
my $ROLLCMD_ROLLALLZSKS	 = "rollcmd_rollallzsks";
my $ROLLCMD_ROLLKSK	 = "rollcmd_rollksk";
my $ROLLCMD_ROLLREC	 = "rollcmd_rollrec";
my $ROLLCMD_ROLLZONE	 = "rollcmd_rollzone";
my $ROLLCMD_ROLLZSK	 = "rollcmd_rollzsk";
my $ROLLCMD_RUNQUEUE	 = "rollcmd_runqueue";
my $ROLLCMD_QUEUELIST	 = "rollcmd_queuelist";
my $ROLLCMD_QUEUESTATUS	 = "rollcmd_queuestatus";
my $ROLLCMD_SHUTDOWN	 = "rollcmd_shutdown";
my $ROLLCMD_SIGNZONE	 = "rollcmd_signzone";
my $ROLLCMD_SIGNZONES	 = "rollcmd_signzones";
my $ROLLCMD_SKIPALL	 = "rollcmd_skipall";
my $ROLLCMD_SKIPZONE	 = "rollcmd_skipzone";
my $ROLLCMD_SLEEPTIME	 = "rollcmd_sleeptime";
my $ROLLCMD_SPLITRRF	 = "rollcmd_splitrrf";
my $ROLLCMD_STATUS	 = "rollcmd_status";
my $ROLLCMD_ZONEGROUP	 = "rollcmd_zonegroup";
my $ROLLCMD_ZONELOG	 = "rollcmd_zonelog";
my $ROLLCMD_ZONESTATUS	 = "rollcmd_zonestatus";
my $ROLLCMD_ZSARGS	 = "rollcmd_zsargs";

sub ROLLCMD_DISPLAY		{ return($ROLLCMD_DISPLAY);	 };
sub ROLLCMD_DSPUB		{ return($ROLLCMD_DSPUB);	 };
sub ROLLCMD_DSPUBALL		{ return($ROLLCMD_DSPUBALL);	 };
sub ROLLCMD_GETSTATUS		{ return($ROLLCMD_GETSTATUS);	 };
sub ROLLCMD_LOGFILE		{ return($ROLLCMD_LOGFILE);	 };
sub ROLLCMD_LOGLEVEL		{ return($ROLLCMD_LOGLEVEL);	 };
sub ROLLCMD_LOGMSG		{ return($ROLLCMD_LOGMSG);	 };
sub ROLLCMD_LOGTZ		{ return($ROLLCMD_LOGTZ);	 };
sub ROLLCMD_MERGERRFS		{ return($ROLLCMD_MERGERRFS);	 };
sub ROLLCMD_PHASEMSG		{ return($ROLLCMD_PHASEMSG);	 };
sub ROLLCMD_ROLLALL		{ return($ROLLCMD_ROLLALL);	 };
sub ROLLCMD_ROLLALLKSKS		{ return($ROLLCMD_ROLLALLKSKS);	 };
sub ROLLCMD_ROLLALLZSKS		{ return($ROLLCMD_ROLLALLZSKS);	 };
sub ROLLCMD_ROLLKSK		{ return($ROLLCMD_ROLLKSK);	 };
sub ROLLCMD_ROLLREC		{ return($ROLLCMD_ROLLREC);	 };
sub ROLLCMD_ROLLZONE		{ return($ROLLCMD_ROLLZONE);	 };
sub ROLLCMD_ROLLZSK		{ return($ROLLCMD_ROLLZSK);	 };
sub ROLLCMD_RUNQUEUE		{ return($ROLLCMD_RUNQUEUE);	 };
sub ROLLCMD_QUEUELIST		{ return($ROLLCMD_QUEUELIST);	 };
sub ROLLCMD_QUEUESTATUS		{ return($ROLLCMD_QUEUESTATUS);	 };
sub ROLLCMD_SHUTDOWN		{ return($ROLLCMD_SHUTDOWN);	 };
sub ROLLCMD_SIGNZONE		{ return($ROLLCMD_SIGNZONE);	 };
sub ROLLCMD_SIGNZONES		{ return($ROLLCMD_SIGNZONES);	 };
sub ROLLCMD_SKIPALL		{ return($ROLLCMD_SKIPALL);	 };
sub ROLLCMD_SKIPZONE		{ return($ROLLCMD_SKIPZONE);	 };
sub ROLLCMD_SLEEPTIME		{ return($ROLLCMD_SLEEPTIME);	 };
sub ROLLCMD_SPLITRRF		{ return($ROLLCMD_SPLITRRF);	 };
sub ROLLCMD_STATUS		{ return($ROLLCMD_STATUS);	 };
sub ROLLCMD_ZONEGROUP		{ return($ROLLCMD_ZONEGROUP);	 };
sub ROLLCMD_ZONELOG		{ return($ROLLCMD_ZONELOG);	 };
sub ROLLCMD_ZONESTATUS		{ return($ROLLCMD_ZONESTATUS);	 };
sub ROLLCMD_ZSARGS		{ return($ROLLCMD_ZSARGS);	 };

my $ROLLMGR_GROUP	= "g-";
sub ROLLMGR_GROUP		{ return($ROLLMGR_GROUP);	};

my %roll_commands =
(
	rollcmd_display		=> 1,
	rollcmd_dspub		=> 1,
	rollcmd_dspuball	=> 1,
	rollcmd_getstatus	=> 1,
	rollcmd_logfile		=> 1,
	rollcmd_loglevel	=> 1,
	rollcmd_logmsg		=> 1,
	rollcmd_logtz		=> 1,
	rollcmd_mergerrfs	=> 1,
	rollcmd_nodisplay	=> 1,
	rollcmd_phasemsg	=> 1,
	rollcmd_rollall		=> 1,
	rollcmd_rollallksks	=> 1,
	rollcmd_rollallzsks	=> 1,
	rollcmd_rollksk		=> 1,
	rollcmd_rollrec		=> 1,
	rollcmd_rollzone	=> 1,
	rollcmd_rollzsk		=> 1,
	rollcmd_runqueue	=> 1,
	rollcmd_queuelist	=> 1,
	rollcmd_queuestatus	=> 1,
	rollcmd_shutdown	=> 1,
	rollcmd_signzones	=> 1,
	rollcmd_signzone	=> 1,
	rollcmd_skipall		=> 1,
	rollcmd_skipzone	=> 1,
	rollcmd_sleeptime	=> 1,
	rollcmd_splitrrf	=> 1,
	rollcmd_status		=> 1,
	rollcmd_zonegroup	=> 1,
	rollcmd_zonelog		=> 1,
	rollcmd_zonestatus	=> 1,
	rollcmd_zsargs		=> 1,
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
my $SETIDFILE	= "setidfile";
my $LOADZONE	= "loadzone";
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
	$LOADZONE  =>	\&uninit_loadzone,
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
	$LOADZONE  =>	\&unknown_loadzone,
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
	$LOADZONE  =>	\&unix_loadzone,
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
	$LOADZONE  =>	\&unix_loadzone,
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

my $UNIX_ROLLMGR_DIR	  = makelocalstatedir("run");
our $UNIX_ROLLMGR_PIDFILE = ($UNIX_ROLLMGR_DIR . "/rollmgr.pid");

my $PS = "/bin/ps";

##############################################################################
#
# These fields are the O/S class and switch table used for interface calls.
# 

my $osclass   = "uninitialized";
my %switchtab = %{$port_archs{$osclass}};

##############################################################################
#
# These are textual descriptions of the rolling phases.
# 
my @zsk_roll_phases =
(
	'Not Rolling',
	'Waiting for old zone data to expire from caches',
	'Signing zone with KSK and Published ZSK',
	'Waiting for old zone data to expire from caches',
	'Adjusting keys in keyrec and signing zone with New ZSK',
);

my @ksk_roll_phases =
(
	'Not Rolling',
	'Waiting for old zone data to expire from caches',
	'Generating new Published KSK',
	'Waiting for cache or holddown timer expiration',
	'Rolling the KSK(s)',
	'Transfer New KSK keyset to parent',
	'Waiting for parent to publish new DS record',
	'Reloading the zone',
);

my $MAXKSK = 7;					# Maximum KSK phase number.
my $MAXZSK = 4;					# Maximum ZSK phase number.

my %key_phases = 
(
	'KSK' => \@ksk_roll_phases,
	'ZSK' => \@zsk_roll_phases
);

#
# Description-length values for rollmgr_get_phase().
#	NOTE:  These should be dealt with as configuration values.
#	       However, logging will be changing RSN, and we'll wait a bit.
#
my $PHASELONG	= 1;				# Use long descriptions.
my $PHASESHORT	= 0;				# Use short descriptions.
# my $longorshort = $PHASELONG;			# Description length to use.
my $longorshort = $PHASESHORT;			# Description length to use.

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
# Routine:      rollmgr_dir()
#
# Purpose:	Front-end to the O/S-specific "get rollerd's
#		directory" function.
#
sub rollmgr_dir
{
	my @args = @_;				# Routine arguments.
	my $func;				# Actual function.

# print "rollmgr_dir\n";

	$func = $switchtab{$GETDIR};
	return(&$func(@args));
}

#--------------------------------------------------------------------------
# Routine:      rollmgr_dropid()
#
# Purpose:	Front-end to the O/S-specific "save rollerd's
#		process id" function.
#
sub rollmgr_dropid
{
	my @args = @_;				# Routine arguments.
	my $func;				# Actual function.

# print "rollmgr_dropid\n";

	$func = $switchtab{$DROPID};
	return(&$func(@args));
}

#--------------------------------------------------------------------------
# Routine:      rollmgr_getid()
#
# Purpose:	Front-end to the O/S-specific "get rollerd's
#		identity" function.
#
sub rollmgr_getid
{
	my @args = @_;				# Routine arguments.
	my $func;				# Actual function.

# print "rollmgr_getid\n";

	$func = $switchtab{$GETID};
	return(&$func(@args));
}

#--------------------------------------------------------------------------
# Routine:      rollmgr_halt()
#
# Purpose:	Front-end to the O/S-specific "halt rollerd"
#		function.
#
sub rollmgr_halt
{
	my @args = @_;				# Routine arguments.
	my $func;				# Actual function.

# print "rollmgr_halt\n";

	$func = $switchtab{$HALT};
	return(&$func(@args));
}

#--------------------------------------------------------------------------
# Routine:      rollmgr_idfile()
#
# Purpose:	Front-end to the O/S-specific "get rollerd's
#		identity filename" function.
#
sub rollmgr_idfile
{
	my @args = @_;				# Routine arguments.
	my $func;				# Actual function.

# print "rollmgr_idfile\n";

	$func = $switchtab{$IDFILE};
	return(&$func(@args));
}

#--------------------------------------------------------------------------
# Routine:      rollmgr_set_idfile()
#
# Purpose:	Front-end to the O/S-specific "set rollerd's
#		identity filename" function.
#
sub rollmgr_set_idfile
{
	my @args = @_;				# Routine arguments.
	my $func;				# Actual function.

# print "rollmgr_set_idfile\n";

	$func = $switchtab{$SETIDFILE};
	return(&$func(@args));
}

#--------------------------------------------------------------------------
# Routine:      rollmgr_loadzone()
#
# Purpose:	Front-end to the O/S-specific "load the zone" function.
#
sub rollmgr_loadzone
{
	my @args = @_;				# Routine arguments.
	my $func;				# Actual function.

# print "rollmgr_loadzone\n";

	$func = $switchtab{$LOADZONE};
	return(&$func(@args));
}

#--------------------------------------------------------------------------
# Routine:      rollmgr_phasemsg()
#
# Purpose:	Set the phase-message length.  Valid values are "long" 
#		and "short".
#		This is generic and not O/S-specific.
#
sub rollmgr_phasemsg
{
	my $pval = shift;			# The new message length.

# print "rollmgr_phasemsg\n";

	if($pval =~ /long/i)
	{
		$longorshort = $PHASELONG; 
		return(1);
	}
	elsif($pval =~ /short/i)
	{
		$longorshort = $PHASESHORT; 
		return(1);
	}

	return(0);
}

#--------------------------------------------------------------------------
# Routine:      rollmgr_cmdint()
#
# Purpose:	Front-end to the O/S-specific "rollerd has a
#		command" function.
#
sub rollmgr_cmdint
{
	my @args = @_;				# Routine arguments.
	my $func;				# Actual function.

# print "rollmgr_cmdint\n";

	$func = $switchtab{$CMDINT};
	return(&$func(@args));
}

#--------------------------------------------------------------------------
# Routine:      rollmgr_rmid()
#
# Purpose:	Front-end to the O/S-specific "remove rollerd's
#		identity file" function.
#
sub rollmgr_rmid
{
	my @args = @_;				# Routine arguments.
	my $func;				# Actual function.

# print "rollmgr_rmid\n";

	$func = $switchtab{$RMID};
	return(&$func(@args));
}

#--------------------------------------------------------------------------
# Routine:      rollmgr_running()
#
# Purpose:	Front-end to the O/S-specific "is rollerd running?" function.
#
sub rollmgr_running
{
	my @args = @_;				# Routine arguments.
	my $func;				# Actual function.

# print "rollmgr_running\n";

	$func = $switchtab{$RUNNING};
	return(&$func(@args));
}

#--------------------------------------------------------------------------
# Routine:      rollmgr_saveid()
#
# Purpose:	Front-end to the O/S-specific "save rollerd's
#		identity" function.
#
sub rollmgr_saveid
{
	my @args = @_;				# Routine arguments.
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
# Routine:      uninit_dir()
#
# Purpose:	Switch for uninitialized "get dir" command.
#
sub uninit_dir
{
	my @args = @_;				# Routine arguments.

# print "uninit_dir\n";

	rollmgr_prepdep();
	return(rollmgr_dir(@args));
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

	rollmgr_prepdep();
	return(rollmgr_dropid(@args));
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

	rollmgr_prepdep();
	return(rollmgr_getid(@args));
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

	rollmgr_prepdep();
	return(rollmgr_halt(@args));
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

	rollmgr_prepdep();
	return(rollmgr_idfile(@args));
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

	rollmgr_prepdep();
	return(rollmgr_set_idfile(@args));
}

#--------------------------------------------------------------------------
# Routine:      uninit_loadzone()
#
# Purpose:	Switch for uninitialized "load the zone" command.
#
sub uninit_loadzone
{
	my @args = @_;				# Routine arguments.

# print "uninit_loadzone\n";

	rollmgr_prepdep();
	return(rollmgr_loadzone(@args));
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

	rollmgr_prepdep();
	return(rollmgr_cmdint(@args));
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

	rollmgr_prepdep();
	return(rollmgr_rmid(@args));
}

#--------------------------------------------------------------------------
# Routine:      uninit_running()
#
# Purpose:	Switch for uninitialized "is rollerd running?" command.
#
sub uninit_running
{
	my @args = @_;				# Routine arguments.

# print "uninit_running\n";

	rollmgr_prepdep();
	return(rollmgr_running(@args));
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
# Routine:      unknown_action()
#
sub unknown_action
{
	err("rollmgr.pm has not been ported to your system yet; cannot continue until this has been done.\n",42);
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
# Routine:      unknown_loadzone()
#
sub unknown_loadzone
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
	return($UNIX_ROLLMGR_DIR);
}

#--------------------------------------------------------------------------
# Routine:	unix_idfile()
#
# Purpose:	Return rollerd's id file.
#
sub unix_idfile
{
	return($UNIX_ROLLMGR_PIDFILE);
}

#--------------------------------------------------------------------------
# Routine:	unix_set_idfile()
#
# Purpose:	Sets rollerd's id file to a particular value
#
sub unix_set_idfile
{
	$UNIX_ROLLMGR_PIDFILE = $_[0];
}

#--------------------------------------------------------------------------
# Routine:	unix_loadzone()
#
# Purpose:	Kick the name server so it'll load the given zone.
#
sub unix_loadzone
{
	my $rndc = shift;				# Nameserver controller.
	my $opts = shift;				# Options for cntlr.
	my $zone = shift;				# Zone to reload.
	my $ret;					# Execution return code.

# print "unix_loadzone\n";

	#
	# Get the path to the name server control program.
	#
	$rndc = dnssec_tools_default('rndc') if($rndc eq '');
	return(0) if($rndc eq '');

	#
	# Reload the zone.
	#
	`$rndc $opts reload $zone >/dev/null 2>&1`;
	$ret = $? >> 8;

	return($ret);
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
# Purpose:	Ensures that another instance of rollerd is not running and
#		then creates a pid file for future reference.
#
# Options:      [-ps FLAGS PIDPOSITION]
#
# Return Values:
#		 1 - The pidfile was initialized for this process.
#		 0 - Another process (not this one) is already acting as
#		     rollerd.
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
	# Get the pid from rollerd's pidfile.
	#
	$pfpid = unix_getpid(0);

	#
	# Create the file if it doesn't exist.
	# If it does exist, we'll make sure the listed process isn't running.
	# If we can't create it, we'll complain and return a failure code.
	#
	if($pfpid < 0)
	{
# print "unix_dropid:  opening $UNIX_ROLLMGR_PIDFILE\n";

		unlink("$UNIX_ROLLMGR_PIDFILE");
		if(open(PIDFILE,"> $UNIX_ROLLMGR_PIDFILE") == 0)
		{
			warn "DROPID UNABLE TO OPEN \"$UNIX_ROLLMGR_PIDFILE\"\n";
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

# print "unix_dropid:  $UNIX_ROLLMGR_PIDFILE exists\n";
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
			# Skip this line if it isn't a rollerd line.
			#
			next if(! /rollerd/);

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
# Routine:	unix_rmid()
#
# Purpose:	Delete rollerd's pidfile.  This is done as part of the
#		manager's clean-up process.
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
	# Ensure that this process is the One True Rollover Manager.
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
# Routine:	unix_running()
#
# Purpose:	Determine if rollerd is running and return a boolean
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
	my $rdpid;				# rollerd's pid (from pidfile.)

# print "unix_running:  down in\n";

	#
	# Get the pid from rollerd's pidfile.
	#
	$rdpid = unix_getpid(1);

	#
	# Complain and return if there is not pidfile.
	#
	if($rdpid == -1)
	{
# print "unix_running:  rollerd's pidfile does not exist\n";
		return(-1);
	}

	#
	# Find out if rollerd is alive.  If it isn't, return 0.
	#
	$ret = kill 0, $rdpid;
	return(0) if($ret == 0);

	#
	# Check if the pid's procname is rollerd, returning an indicator.
	#
	$ret = `$PS -p $rdpid`;
	return(0) if($ret !~ /(rollerd|perl)/);
	return(1);

}

#--------------------------------------------------------------------------
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

# print "unix_getpid:  down in\n";

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
#		err("unix_getpid:  unable to open \"$UNIX_ROLLMGR_PIDFILE\"\n",-1);
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

# print "rollmgr_channel($server):  down in\n";

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
# print STDERR "rollmgr_channel:  unixsock - <$unixsock>\n";

		#
		# Ensure the socket name isn't too long.  This is a result
		# of a hardcode maximum length for socket names.  This is
		# in the kernel and isn't 
		#
		return(-5) if(length($unixsock) > $maxsockname);

		#
		# Create the socket.
		#
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
# Routine:	rollmgr_closechan()
#
# Purpose:	This routine closes down the communications channel to
#		rollerd.  It is called by both rollerd and rollerd clients.
#
sub rollmgr_closechan
{
# print "rollmgr_closechan:  down in\n";
	close(CLNTSOCK);
}

#-----------------------------------------------------------------------------
# Routine:	rollmgr_queuecmd()
#
# Purpose:	This routine can be called internally to queue a command
#		for later processing via calls to rollmgr_getcmd().
#		It is useful when doing initial start-up before full
#		processing is to commence.  Commands queued by this
#		process take precedence over commands received via the
#		command interface (ie, via rollmgr_sendcmd()).
#
sub rollmgr_queuecmd
{
	my ($cmd, $value) = @_;

	return(0) if (rollmgr_verifycmd($cmd) == 0);
	push @queuedcmds, [$cmd, $value];
}

#-----------------------------------------------------------------------------
# Routine:	rollmgr_getqueueitem()
#
# Purpose:	This routine can be called pull a command from the queue
#		This is intended to process the item, so it is removed
#		from the queue.
#
sub rollmgr_getqueueitem
{
	if($#queuedcmds > -1)
	{
		my $cmd = shift @queuedcmds;
		return($cmd);
	}
}

#-----------------------------------------------------------------------------
# Routine:	rollmgr_getallqueuedcmds()
#
# Purpose:	This routine returns all the queued commands in the stack
#		The items are left in place unless a truthful argument
#		(e.g. "1") is passed in.
#
sub rollmgr_getallqueuedcmds
{
	my $removefromqueue = shift;
	my @results = @queuedcmds;

	@queuedcmds = () if ($removefromqueue);
	return(@queuedcmds);
}

#-----------------------------------------------------------------------------
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

	my $accresp;				# Response from accept().

	my $oldhandler = $SIG{ALRM};		# Old alarm handler.

# print "rollmgr_getcmd:  down in\n";

	#
	# if we have anything queued up, process those first.
	#
	my $cmdandvalue = rollmgr_getqueueitem();
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
# print "rollmgr_getcmd:  connection from <$clntname>\n";

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
# Routine:	rollmgr_sendcmd()
#
# Purpose:	This routine allows a client to send a message to the server.
#		No other routines need be called to initialize anything.
#
sub rollmgr_sendcmd
{
	my $close = shift;				# Close flag.
	my $cmd	  = shift;				# Command to send.
	my $data  = shift;				# Data for command.

	my $oldsel;					# Currently selected fh.
	my $resp;					# Response.
	my $ret	 = 1;					# Return code.

# print "rollmgr_sendcmd:  down in\n";

	return(0) if(rollmgr_verifycmd($cmd) == 0);

	#
	# Create the communications channel to rollerd and send the message.
	#
	return(0) if(rollmgr_channel(0) != 1);

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
	# Let rollerd know there's a command waiting.
	#
	rollmgr_cmdint();

	return(1);
}

#-----------------------------------------------------------------------------
# Routine:	rollmgr_sendresp()
#
# Purpose:	This routine allows rollerd to send a message to a client.
#
sub rollmgr_sendresp
{
	my $retcode = shift;				# Return code.
	my $respmsg = shift;				# Response message.

	my $oldsel;					# Currently selected fh.

# print STDERR "rollmgr_sendresp:  down in\n";

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
# Routine:	rollmgr_getresp()
#
# Purpose:	This routine allows a client to wait for a message response
#		from the server.  It will keep reading response lines until
#		either the socket closes or the timer expires.
#
sub rollmgr_getresp
{
	my $retcode = -1;				# Return code.
	my $respbuf;					# Response buffer.

	my $oldhandler = $SIG{ALRM};			# Old alarm handler.
	my $waiter = 5;					# Wait-time for resp.

# print "rollmgr_getresp:  down in\n";

	#
	# Set a time limit on how long we'll wait for the response.
	# Our alarm handler is a dummy, only intended to keep us from
	# waiting forever.
	#
	$SIG{ALRM} = sub { my $foo = 42 };
	alarm($waiter);

	#
	# Get the response code and message from rollerd.
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
# Routine:	rollmgr_verifycmd()
#
# Purpose:	This routine returns a boolean indicating if the specified
#		command is a valid command for the rollover daemon.
#
sub rollmgr_verifycmd
{
	my $cmd	 = shift;				# Command to check.
	my $hval;					# Command hash value.

# print "rollmgr_verifycmd:  down in\n";

	$hval = $roll_commands{$cmd};
# print "rollmgr_verifycmd:  <$cmd>\t\t<$hval>\n";

	#
	# If the command is undefined, we'll check if it's a group
	# command.  If so, we'll strip the group indicator and try again.
	#
	if(!defined($hval))
	{
		my $gstr = ROLLMGR_GROUP;	# Group command indicator.
		if($cmd =~ /^$gstr/)
		{
			$cmd =~ s/^$gstr//;
			return(rollmgr_verifycmd($cmd));
		}
		else
		{
			return(0);
		}
	}

	#
	# Success!
	#
	return(1);
}

#-----------------------------------------------------------------------------
# Routine:	rollmgr_get_phase()
#
# Purpose:	This routine translates the numerical phases of rolling
#		keys into textual strings that are better descriptions
#		for human consumption.
#
sub rollmgr_get_phase
{
	my ($keytype, $keyphase) = @_;
	my $maxphase = -1;				# Maximum phase value.

	#
	# Don't return anything if the installer doesn't want long descriptions.
	#	NOTE:  This really should be a config value.
	#
	if($longorshort != $PHASELONG)
	{
		return('');
	}

	#
	# Figure out the maximum phase for this key type.
	#
	$maxphase = $MAXKSK if($keytype eq 'KSK');
	$maxphase = $MAXZSK if($keytype eq 'ZSK');

	#
	# Ensure the phase is within range and is a single digit.
	#
	if(($keyphase < 0) || ($keyphase > $maxphase) || ($keyphase !~ /^\d$/))
	{
		return('');
	}

	#
	# Return the phase description.
	#
	return($key_phases{uc($keytype)}[$keyphase]);
}

1;

#############################################################################

=pod

=head1 NAME

Net::DNS::SEC::Tools::rollmgr - Communicate with the DNSSEC-Tools rollover
manager.

=head1 SYNOPSIS

  use Net::DNS::SEC::Tools::rollmgr;

  $dir = rollmgr_dir();

  $idfile = rollmgr_idfile();

  $id = rollmgr_getid();

  rollmgr_dropid();

  rollmgr_rmid();

  rollmgr_cmdint();

  $runflag = rollmgr_running();

  rollmgr_halt();

  rollmgr_phasemsg('long');

  rollmgr_channel(1);
  ($cmd,$data) = rollmgr_getcmd();
  $ret = rollmgr_verifycmd($cmd);

  rollmgr_sendcmd(CHANNEL_CLOSE,ROLLCMD_ROLLZSK,"example.com");

  rollmgr_sendcmd(CHANNEL_WAIT,ROLLCMD_ROLLZSK,"example.com");
  ($retcode, $respmsg) = rollmgr_getresp();

  $descr = rollmgr_get_phase('KSK', $phasecnt);

=head1 DESCRIPTION

The B<Net::DNS::SEC::Tools::rollmgr> module provides standard,
platform-independent methods for a program to communicate with DNSSEC-Tools'
B<rollerd> rollover manager.  There are two interface classes described
here:  general interfaces and communications interfaces.

=head1 GENERAL INTERFACES

The interfaces to the B<Net::DNS::SEC::Tools::rollmgr> module are given below.

=over 4

=item I<rollmgr_dir()>

This routine returns B<rollerd>'s directory.

=item I<rollmgr_idfile()>

This routine returns B<rollerd>'s id file.

=item I<rollmgr_getid()>

This routine returns B<rollerd>'s process id.  If a non-zero value
is passed as an argument, the id file will be left open and accessible through
the PIDFILE file handle.  See the WARNINGS section below.

Return Values:

    On success, the first portion of the file contents
	(up to 80 characters) is returned.
    -1 is returned if the id file does not exist.

=item I<rollmgr_dropid()>

This interface ensures that another instance of B<rollerd> is not
running and then creates a id file for future reference.

Return Values:

    1 - the id file was successfully created for this process
    0 - another process is already acting as rollerd
   -1 - unable to create the id file

=item I<rollmgr_rmid()>

This interface deletes B<rollerd>'s id file.

Return Values:

     1 - the id file was successfully deleted
     0 - no id file exists
    -1 - the calling process is not rollerd
    -2 - unable to delete the id file

=item I<rollmgr_cmdint()>

This routine informs B<rollerd> that a command has been sent via
I<rollmgr_sendcmd()>.

Return Values:

    -1 - an invalid process id was found for rollerd
    Anything else indicates the number of processes that were
    signaled.
    (This should only ever be 1.)

=item I<rollmgr_running()>

This routine determines if rollerd is running and returns a value indicating
the status.

Return Values:

     1 - rollerd is running.
     0 - The process listed in the rollerd process id file
	 is not running.
    -1 - Unable to get the rollerd process id.

=item I<rollmgr_halt()>

This routine informs B<rollerd> to shut down.

In the current implementation, the return code from the B<kill()> command is
returned.

    -1 - an invalid process id was found for rollerd
    Anything else indicates the number of processes that were
    signaled.
    (This should only ever be 1.)

=item I<rollmgr_loadzone(ctlprog,opts,zone)>

This routine informs a name server to reload a zone's zone file.  The
I<$ctlprog> argument is the command that will be run to control the name
server.  If this is an empty string, then the default value for DNSSEC-Tools
will be used.  The I<$opts> argument is a set of options to be passed to
I<ctlprog>.  The I<$zone> argument is the name of the zone to be reloaded.

The command line to be run is built in this format:

    <$zone> <$opts> reload <$zone>

This format assumes that the B<rndc> command will be used for signalling
the name server.

The return value will be the return code from running I<$ctlprog>.

=item I<rollmgr_phasemsg()>

This routine sets the phase-message length.  of phase-related log messages
used by B<rollerd>.  The valid levels are "long" and "short", with "long"
being the default value.

The long message length means that a phase description will be included with
some log messages.  For example, the long form of a message about ZSK rollover
phase 3 will look like this:  "ZSK phase 3 (Waiting for old zone data to
expire from caches)".

The short message length means that a phase description will not be included
with some log messages.  For example, the short form of a message about ZSK
rollover phase 3 will look like this:  "ZSK phase 3".

Return Values:

     1 - the phase-message length was set
     0 - an invalid phase-message length was specified

=back

=head1 ROLLERD COMMUNICATIONS INTERFACES

=over 4

=item I<rollmgr_channel(serverflag)>

This interface sets up a persistent channel for communications with B<rollerd>.
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

=item I<rollmgr_queuecmd(cmdname, value)>

This interface internally remembers a command and it's optional value
for later processing.  See the I<rollmgr_getcmd()> next for further
details.

=item I<rollmgr_getcmd()>

I<rollmgr_getcmd()> processes commands that need to be dealt with.  If
there are any internally stored commands queued via the
I<rollmgr_queuecmd()> function, they are dealt with first.  After that it
retrieves a command sent over B<rollerd>'s communications channel by a
client program.  The command and the command's data are sent in each
message.

The command and the command's data are returned to the caller.

=item I<rollmgr_sendcmd(closeflag,cmd,data)>

I<rollmgr_sendcmd()> sends a command to B<rollerd>.  The command must be one
of the commands from the table below.  This interface creates a communications
channel to B<rollerd> and sends the message.  The channel is not closed, in
case the caller wants to receive a response from B<rollerd>.

The available commands and their required data are:

   command		data		purpose
   -------		----		-------
   ROLLCMD_DISPLAY	1/0		start/stop rollerd's
					graphical display
   ROLLCMD_DSPUB	zone-name	a DS record has been
					published
   ROLLCMD_DSPUBALL	none		DS records published for all
					zones in KSK rollover phase 5
   ROLLCMD_GETSTATUS	none		currently unused
   ROLLCMD_LOGFILE	log filename	change the log file
   ROLLCMD_LOGLEVEL	log level	set a new logging level
   ROLLCMD_LOGMSG	log message	add a message to the log
   ROLLCMD_LOGTZ	timezone	set timezone for log messages
   ROLLCMD_MERGERRFS	rollrec files	merge rollrec files with the
					current rollrec file
   ROLLCMD_PHASEMSG	long/short	set long or short phase
					messages
   ROLLCMD_QUEUELIST	none		returns the names and next
					event time of zones in the
					"soon queue
					(experimental)
   ROLLCMD_QUEUESTATUS	none		returns information about
  					the state of soon-queue
  					processing
					(experimental)
   ROLLCMD_ROLLALL	none		resume rollover for all
					suspended zones
   ROLLCMD_ROLLALLZSKS	none		force all zones to start
					ZSK rollover
   ROLLCMD_ROLLKSK	zone-name	force a zone to start
					KSK rollover
   ROLLCMD_ROLLREC	rollrec-name	change rollerd's rollrec file
   ROLLCMD_ROLLZONE	zone name	restart rollover for a
					suspended zone
   ROLLCMD_ROLLZSK	zone-name	force a zone to start
					ZSK rollover
   ROLLCMD_RUNQUEUE	none		rollerd runs through
					its queue
   ROLLCMD_SHUTDOWN	none		stop rollerd
   ROLLCMD_SIGNZONE	zone		sign a zone (no rollover)
   ROLLCMD_SIGNZONEs	all or active	sign all or active zones
   ROLLCMD_SKIPALL	none		suspend all rollovers
   ROLLCMD_SKIPZONE	zone name	suspend rollover for a
					rolling zone
   ROLLCMD_SLEEPTIME	seconds-count	set rollerd's sleep time
   ROLLCMD_SPLITRRF	rollrec-name,	move a set of zones from the
			zone names	current rollrec file into a
					new rollrec file
   ROLLCMD_STATUS	none		get status of rollerd
   ROLLCMD_ZONEGROUP	zonegroup name	get info on all zonegroups
					or a particular zonegroup
   ROLLCMD_ZONELOG	zone name	set the logging level for
			logging level	a particular zone
   ROLLCMD_ZONESTATUS	none		get status of the zones
   ROLLCMD_ZSARGS	zonesigner args	add a (probably temporary)
			zone list	set of options to the signing
					of a set of zones
	
The data aren't checked for validity by I<rollmgr_sendcmd()>; validity
checking is a responsibility of B<rollerd>.

If the caller does not need a response from B<rollerd>, then I<closeflag>
should be set to B<CHANNEL_CLOSE>; if a response is required then
I<closeflag> should be B<CHANNEL_WAIT>.  These values are boolean values,
and the constants aren't required.

On success, 1 is returned.  If an invalid command is given, 0 is returned.

=item I<rollmgr_getresp()>

After executing a client command sent via I<rollmgr_sendcmd()>, B<rollerd>
will send a response to the client.  I<rollmgr_getresp()> allows
the client to retrieve the response.

A return code and a response string are returned, in that order.  Both are
specific to the command sent.

=item I<rollmgr_verifycmd(cmd)>

I<rollmgr_verifycmd()> verifies that I<cmd> is a valid command for B<rollerd>.
1 is returned for a valid command; 0 is returned for an invalid command.

1 is returned for a valid command; 0 is returned for an invalid command.

=item I<rollmgr_get_phase(phasetype, phasenum)>

I<rollmgr_get_phase()> returns a description of a particular phase for a
particular type of rollover.  I<phasetype> specifies the type of rollover,
and may be "KSK" or "ZSK".  I<phasenum> specifies the phase number whose
description is desired.  This must be an integer between 0 and 7 (KSK) or 0
and 4 (ZSK).  If an invalid phase type or phase number is specified, an empty
string is returned. 

=back

=head1 WARNINGS

1.  I<rollmgr_getid()> attempts to exclusively lock the id file.
Set a timer if this matters to you.

2.  I<rollmgr_getid()> has a nice little race condition.  We should lock
the file prior to opening it, but we can't do so without it being open.

=head1 COPYRIGHT

Copyright 2005-2014 SPARTA, Inc.  All rights reserved.
See the COPYING file included with the DNSSEC-Tools package for details.

=head1 AUTHOR

Wayne Morrison, tewok@tislabs.com

=head1 SEE ALSO

B<rollctl(1)>

B<Net::DNS::SEC::Tools::keyrec.pm(3)>
B<Net::DNS::SEC::Tools::rolllog.pm(3)>
B<Net::DNS::SEC::Tools::rollrec.pm(3)>

B<rndc(8)>,
B<rollerd(8)>

=cut
