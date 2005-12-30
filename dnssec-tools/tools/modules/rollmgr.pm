#
# Copyright 2005 SPARTA, Inc.  All rights reserved.  See the COPYING
# file distributed with this software for details
#
# DNSSEC Tools
#
# rollmgr.pm -	Roll-over manager functions.
#
#	The routines in this module provide a means to communicate with
#	the roll-over manager.
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

our $VERSION = "0.01";

our @ISA = qw(Exporter);

our @EXPORT = qw(
		 rollmgr_dir
		 rollmgr_dropid
		 rollmgr_getid
		 rollmgr_halt
		 rollmgr_idfile
		 rollmgr_qproc
		 rollmgr_rmid
		 rollmgr_saveid
		);

my $rollmgrid;				# Roll-over manager's process id.

##############################################################################
#
# These "constants" are the names of the roll-over manager's interfaces.
# 
my $DROPID	= "dropid";
my $GETDIR	= "getdir";
my $GETID	= "getid";
my $HALT	= "halt";
my $IDFILE	= "idfile";
my $QPROC	= "qproc";
my $RMID	= "rmid";
my $SAVEID	= "saveid";

##############################################################################
#
# These are the switch hashes that determine what routine will be called
# for what O/S classes.
# 
my %switch_uninit =
(
	$DROPID	=>	\&uninit_dropid,
	$GETDIR	=>	\&uninit_dir,
	$GETID	=>	\&uninit_getid,
	$HALT	=>	\&uninit_halt,
	$IDFILE	=>	\&uninit_idfile,
	$QPROC	=>	\&uninit_qproc,
	$RMID	=>	\&uninit_rmid,
	$SAVEID	=>	\&uninit_saveid,
);

my %switch_unknown =
(
	$DROPID	=>	\&unknown_dropid,
	$GETDIR	=>	\&unknown_dir,
	$GETID	=>	\&unknown_getid,
	$HALT	=>	\&unknown_halt,
	$IDFILE	=>	\&unknown_idfile,
	$QPROC	=>	\&unknown_qproc,
	$RMID	=>	\&unknown_rmid,
	$SAVEID	=>	\&unknown_saveid,
);

my %switch_unix =
(
	$DROPID	=>	\&unix_dropid,
	$GETDIR	=>	\&unix_dir,
	$GETID	=>	\&unix_getid,
	$HALT	=>	\&unix_halt,
	$IDFILE	=>	\&unix_idfile,
	$QPROC	=>	\&unix_qproc,
	$RMID	=>	\&unix_rmid,
	$SAVEID	=>	\&unix_saveid,
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

my $UNIX_CMD_QPROC	= "HUP";		# Signal for qproc command.
my $UNIX_CMD_HALT	= "INT";		# Signal for halt command.

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
# Purpose:	Front-end to the O/S-specific "get roll-over manager's
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
# Purpose:	Front-end to the O/S-specific "save roll-over manager's
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
# Purpose:	Front-end to the O/S-specific "get roll-over manager's
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
# Purpose:	Front-end to the O/S-specific "halt roll-over manager"
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
# Purpose:	Front-end to the O/S-specific "get roll-over manager's
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
# Routine:      rollmgr_qproc()
#
# Purpose:	Front-end to the O/S-specific "run roll-over manager's
#		queue" function.
#
sub rollmgr_qproc
{
	my @args = shift;			# Routine arguments.
	my $func;				# Actual function.

# print "rollmgr_qproc\n";

	$func = $switchtab{$QPROC};
	return(&$func(@args));
}

#--------------------------------------------------------------------------
#
# Routine:      rollmgr_rmid()
#
# Purpose:	Front-end to the O/S-specific "remove roll-over manager's
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
# Purpose:	Front-end to the O/S-specific "save roll-over manager's
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
# Routine:      uninit_qproc()
#
# Purpose:	Switch for uninitialized "force queue" command.
#
sub uninit_qproc
{
	my @args = shift;			# Routine arguments.

# print "uninit_qproc\n";

	rollmgr_prepdep();
	return(rollmgr_qproc(@args));
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
# Routine:      unknown_qproc()
#
sub unknown_qproc
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
# Purpose:	Return the roll-over manager's id file.
#
sub unix_idfile
{
	return($UNIX_ROLLMGR_PIDFILE);
}


#--------------------------------------------------------------------------
#
# Routine:	unix_dropid()
#
# Purpose:	Ensures that another instance of the roll-over manager is
#		running and then creates a pid file for future reference.
#
# Return Values:
#		 1 - The pidfile was initialized for this process.
#		 0 - Another process (not this one) is already acting as
#		     the roll-over manager.
#
sub unix_dropid
{
	my $ego = $$;				# My identity.
	my $rdpid;				# Pid read from the pidfile.

# print "unix_droppid:  down in\n";

	#
	# Get the pid from the roll-over manager's pidfile.
	#
	$rdpid = unix_getpid(0);

	#
	# Create the file if it doesn't exist.
	# If it does exist, we'll make sure the listed process isn't running.
	#
	if($rdpid < 0)
	{
# print "unix_dropid:  opening $UNIX_ROLLMGR_PIDFILE\n";
		open(PIDFILE,"> $UNIX_ROLLMGR_PIDFILE") || warn "DROPPID UNABLE TO OPEN <$UNIX_ROLLMGR_PIDFILE>\n";
		flock(PIDFILE,LOCK_EX);
	}
	else
	{
		my $pid;			# Pid from ps output.
		my $pscmd;			# ps command to execute.
		my $psline;			# Output line from ps.
		my $openrc;			# Return code from open().

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
			next;
		}
		close(PSOUT);

		#
		# Check if the pidfile's process is still running.
		# Return success if the current manager is us.
		# Return failure if the current manager  isn't us.
		#
		if($psline =~ /rollover-manager/)
		{
			flock(PIDFILE,LOCK_UN);

			return(1) if($rdpid == $ego);
			return(0);
		}

		#
		# Zap the file contents.
		#
		truncate($UNIX_ROLLMGR_PIDFILE,0);
	}

	#
	# Save our pid as THE roll-over manager's pid.
	#
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
# Purpose:	Delete the roll-over manager's pidfile.  This is done when
#		as part of the manager's clean-up process.
#
# Return Values:
#		 1 - The pidfile was deleted.
#		 0 - No pidfile exists.
#		-1 - The calling process is not the roll-over manager.
#		-2 - Unable to delete the pidfile.
#
sub unix_rmid
{
	my $ego = $$;				# My identity.
	my $flret;				# flock() return code.
	my $rdpid;				# Pid read from the pidfile.

# print "unix_rmid:  down in\n";

	#
	# Get the pid from the roll-over manager's pidfile.
	#
	$rdpid = unix_getpid(0);
	flock(PIDFILE,LOCK_EX);

	#
	# Complain and return if there is not pidfile.
	#
	if($rdpid == -1)
	{
# print "unix_rmid:  roll-over manager's pidfile does not exist\n";
		return(0);
	}

	#
	# Ensure that this process is the One True Roll-over Manager.
	#
	if($rdpid != $ego)
	{
# print "unix_rmid:  we are not the roll-over manager\n";
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
# Purpose:	Return the roll-over manager, as recorded in its pidfile.
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
		print STDERR "unix_getpid:  unable to open \"$UNIX_ROLLMGR_PIDFILE\"\n";
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
	if($closeflag)
	{
		close(PIDFILE);
	}

	#
	# Lop off any trailing newlines and return.
	#
	$pid =~ s/\n//g;
	return($pid);
}

#--------------------------------------------------------------------------
#
# Routine:	unix_qproc()
#
# Purpose:	Kick the roll-over manager to let it know it should
#		re-read the rollrec file and process its queue again.
#
sub unix_qproc
{
	my $pid;				# Roll-over manager's pid.
	my $ret;				# Return code from kill().

print "unix_qproc:  down in\n";
	$pid = unix_getpid(1);

print "unix_qproc:  sending - kill($UNIX_CMD_QPROC,$pid)\n";
	$ret = kill($UNIX_CMD_QPROC,$pid);

print "unix_qproc:  kill($UNIX_CMD_QPROC,$pid) returned - $ret";

	return($ret);
}

#--------------------------------------------------------------------------
#
# Routine:	unix_halt()
#
# Purpose:	Tell the roll-over manager to shut down.
#
sub unix_halt
{
	my $pid;				# Roll-over manager's pid.
	my $ret;				# Return code from kill().

# print "unix_halt:  down in\n";
	$pid = unix_getpid(1);

	$ret = kill($UNIX_CMD_HALT,$pid);

# print "unix_halt:  kill($UNIX_CMD_HALT,$pid) returned - $ret";

	return($ret);
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

  rollmgr_qproc();

  rollmgr_halt();

=head1 DESCRIPTION

The B<Net::DNS::SEC::Tools::rollmgr> module provides standard,
platform-independent  methods for a program to communicate with
the roll-over manager.

=head1 ROLLMGR INTERFACES

The interfaces to the B<Net::DNS::SEC::Tools::rollmgr> module are given below.

=head2 B<rollmgr_dir()>

This routine returns the roll-over manager's directory.

=head2 B<rollmgr_idfile()>

This routine returns the roll-over manager's id file.

=head2 B<rollmgr_getid()>

This routine returns the roll-over manager's process id.  If a non-zero value
is passed as an argument, the id file will be left open and accessible through
the PIDFILE file handle.  See the WARNINGS section below.

Return Values:

    On success, the first portion of the file contents (up to 80
        characters) is returned.
    -1 is returned if the id file does not exist.

=head2 B<rollmgr_dropid()>

This interface ensures that another instance of the roll-over manager is not
running and then creates a id file for future reference.

Return Values:

    1 - the id file was successfully created for this process
    0 - another process is already acting as the roll-over manager

=head2 B<rollmgr_rmid()>

This interface deletes the roll-over manager's id file.

Return Values:

     1 - the id file was successfully deleted
     0 - no id file exists
    -1 - the calling process is not the roll-over manager
    -2 - unable to delete the id file

=head2 B<rollmgr_qproc()>

This routine informs the roll-over manager that it should re-read the
I<rollrec> file and process its queue again.

In the current implementation, the return code from the B<kill()> command is
returned.

=head2 B<rollmgr_halt()>

This routine informs the roll-over manager to shut down.

In the current implementation, the return code from the B<kill()> command is
returned.

=head1 WARNINGS

1.  B<rollmgr_getid()> attempts to exclusively lock the id file.
Set a timer if this matters to you.

2.  B<rollmgr_getid()> has a nice little race condition.  We should lock
the file prior to opening it, but we can't do so without it being open.

=head1 COPYRIGHT

Copyright 2004-2005 SPARTA, Inc.  All rights reserved.
See the COPYING file included with the DNSSEC-Tools package for details.

=head1 AUTHOR

Wayne Morrison, tewok@users.sourceforge.net

=head1 SEE ALSO

B<Net::DNS::SEC::Tools::rollctl(1)>

B<Net::DNS::SEC::Tools::rollrec(3)>

B<Net::DNS::SEC::Tools::rollmgr(8)>

=cut
