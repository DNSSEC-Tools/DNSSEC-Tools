#
# Copyright 2005 Sparta, inc.  All rights reserved.  See the COPYING
# file distributed with this software for details
#
# DNSSEC Tools
#
#	Roll-over manager functions.
#
#	The routines in this module provide a means to communicate with
#	the roll-over manager.
#

package Net::DNS::SEC::Tools::rollmgr;

require Exporter;
use strict;

use Fcntl ':flock';

our $VERSION = "0.01";

our @ISA = qw(Exporter);

our @EXPORT = qw(
		 rollmgr_dir
		 rollmgr_pidfile
		 rollmgr_getpid
		 rollmgr_droppid
		 rollmgr_rmpid
		 rollmgr_qproc
		 rollmgr_halt
		);

my $ROLLMGR_DIR	    = "/usr/local/etc/dnssec";
my $ROLLMGR_PIDFILE = ($ROLLMGR_DIR . "/dnssec-tools.rollmgr.pid");

my $rollmgrpid;				# Roll-over manager's process id.

#--------------------------------------------------------------------------
#
# Routine:	rollmgr_dir()
#
# Purpose:	Return the roll-over manager's directory.
#
sub rollmgr_dir
{
	return($ROLLMGR_DIR);
}

#--------------------------------------------------------------------------
#
# Routine:	rollmgr_pidfile()
#
# Purpose:	Return the roll-over manager's pid file.
#
sub rollmgr_pidfile
{
	return($ROLLMGR_PIDFILE);
}


#--------------------------------------------------------------------------
#
# Routine:	rollmgr_droppid()
#
# Purpose:	Ensures that another instance of the roll-over manager is
#		running and then creates a pid file for future reference.
#
# Return Values:
#		 1 - The pidfile was initialized for this process.
#		 0 - Another process (not this one) is already acting as
#		     the roll-over manager.
#
sub rollmgr_droppid
{
	my $ego = $$;				# My identity.
	my $rdpid;				# Pid read from the pidfile.

# print "rollmgr_droppid:  down in\n";

	#
	# Get the pid from the roll-over manager's pidfile.
	#
	$rdpid = rollmgr_getpid(0);
# print "\t\t\t\t---> rollmgr_getpid() return - $rdpid\n";

	#
	# Create the file if it doesn't exist.
	# If it does exist, we'll make sure the listed process isn't running.
	#
	if($rdpid < 0)
	{
# print "\t\t\t\t---> pid file does not exist\n";
# print "rollmgr_droppid:  opening $ROLLMGR_PIDFILE\n";
		open(PIDFILE,"> $ROLLMGR_PIDFILE") || warn "DROPPID UNABLE TO OPEN <$ROLLMGR_PIDFILE>\n";
# print "\t\t\t\t---> errno - < $! >\n";
# print "rollmgr_droppid:  locking $ROLLMGR_PIDFILE\n";
		flock(PIDFILE,LOCK_EX);
	}
	else
	{
# print "\t\t\t\t---> pid file exists\n";
		my $kcnt;			# Count of processes signaled.

		flock(PIDFILE,LOCK_EX);

		#
		# If the pidfile's process is still running, we'll return to
		# our caller.  If the current manager is us, we'll quietly
		# return success.  If it isn't, we'll whine and then return
		# an error.
		#
		$kcnt = kill(0,$rdpid);
		if($kcnt > 0)
		{
# print "\t\t\t\t---> process $rdpid exists\n";
			flock(PIDFILE,LOCK_UN);

			return(1) if($rdpid == $ego);

# print "rollmgr_droppid:  another roll-over manager (pid $rdpid) is already running\n";
			return(0);
		}

		#
		# Zap the file contents.
		#
		truncate($ROLLMGR_PIDFILE,0);
	}

	#
	# Save our pid as THE roll-over manager's pid.
	#
# print "\t\t\t\t---> writing our pid $ego into pidfile\n";
	print PIDFILE "$ego\n";
	flock(PIDFILE,LOCK_UN);
	close(PIDFILE);

	#
	# Save our pid as the internal version of the manager's pid and
	# return success.
	#
	$rollmgrpid = $ego;
	return(1);
}

#--------------------------------------------------------------------------
#
# Routine:	rollmgr_rmpid()
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
sub rollmgr_rmpid
{
	my $ego = $$;				# My identity.
	my $flret;				# flock() return code.
	my $rdpid;				# Pid read from the pidfile.

# print "rollmgr_rmpid:  down in\n";

	#
	# Get the pid from the roll-over manager's pidfile.
	#
	$rdpid = rollmgr_getpid(0);
	flock(PIDFILE,LOCK_EX);

	#
	# Complain and return if there is not pidfile.
	#
	if($rdpid == -1)
	{
# print "rollmgr_rmpid:  roll-over manager's pidfile does not exist\n";
		return(0);
	}

	#
	# Ensure that this process is the One True Roll-over Manager.
	#
	if($rdpid != $ego)
	{
# print "rollmgr_rmpid:  we are not the roll-over manager\n";
		return(-1);
	}

	#
	# Get rid of the pidfile.
	#
	if(unlink($ROLLMGR_PIDFILE) != 1)
	{
# print "rollmgr_rmpid:  unable to delete pidfile\n";
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
# Routine:	rollmgr_getpid()
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
sub rollmgr_getpid
{
	my $closeflag = shift;			# Close-flag for pidfile.
	my $pid;				# Pid from pidfile.

	#
	# Return an error if the file doesn't exist.
	#
	return(-1) if(stat($ROLLMGR_PIDFILE) == 0);

	#
	# Open and lock the pidfile.
	#
# print "rollmgr_getpid:  opening and locking $ROLLMGR_PIDFILE\n";
	open(PIDFILE,"+< $ROLLMGR_PIDFILE") || warn "UNABLE TO OPEN <$ROLLMGR_PIDFILE>\n";
	flock(PIDFILE,LOCK_EX);

	#
	# Get the pid from the pidfile.
	#
# print "rollmgr_getpid:  reading $ROLLMGR_PIDFILE\n";
	read(PIDFILE,$pid,80);
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
# print "rollmgr_getpid:  returning pid <$pid>>\n";
	return($pid);
}

#--------------------------------------------------------------------------
#
# Routine:	rollmgr_qproc()
#
# Purpose:	Kick the roll-over manager to let it know it should
#		re-read the rollrec file and process its queue again.
#
sub rollmgr_qproc
{
	my $pid;				# Roll-over manager's pid.
	my $ret;				# Return code from kill().

# print "rollmgr_qproc:  down in\n";
	$pid = rollmgr_getpid(1);

	$ret = kill('HUP',$pid);

# print "rollmgr_qproc:  kill(HUP,$pid) returned - $ret";

	return($ret);
}

#--------------------------------------------------------------------------
#
# Routine:	rollmgr_halt()
#
# Purpose:	Tell the roll-over manager to shut down.
#
sub rollmgr_halt
{
	print "rollmgr_halt:  down in\n";
}

1;

#############################################################################

=pod

=head1 NAME

Net::DNS::SEC::Tools::rollmgr - Communicate with the dnssec-tools roll-over
manager.

=head1 SYNOPSIS

  use Net::DNS::SEC::Tools::rollmgr;

  rollmgr_dir();

  rollmgr_pidfile();

  rollmgr_droppid();

  rollmgr_qproc();

  rollmgr_halt();

=head1 DESCRIPTION

The I<Net::DNS::SEC::Tools::rollmgr> module provides standard methods for a
program to communicate with the roll-over manager.

=head1 ROLLMGR INTERFACES

The interfaces to the I<Net::DNS::SEC::Tools::rollmgr> module are given below.

=head2 I<rollmgr_dir()>

This routine returns the roll-over manager's directory.

=head2 I<rollmgr_pidfile()>

This routine returns the roll-over manager's pid file.

=head2 I<rollmgr_droppid()>

This interface ensures that another instance of the roll-over manager is
running and then creates a pid file for future reference.

=head2 I<rollmgr_qproc()>

This routine informs the roll-over manager that it should re-read the
I<rollrec> file and process its queue again.

=head2 I<rollmgr_halt()>

This routine informs the roll-over manager to shut down.

=head1 AUTHOR

Wayne Morrison, tewok@users.sourceforge.net

=head1 SEE ALSO

Net::DNS::SEC::Tools::rollctl(1)

Net::DNS::SEC::Tools::rollrec(3)

Net::DNS::SEC::Tools::rollmgr(8)

=cut
