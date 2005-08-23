#!/usr/bin/perl
#
# Copyright 2005 SPARTA, Inc.  All rights reserved.  See the COPYING
# file distributed with this software for details
#
# DNSSEC Tools
#
# timetrans
#
#       This module contains an interface to convert an integer seconds count
#	into the equivalent number of weeks, days, hours, and minutes.
#

use strict;

#######################################################################
#
# Time-related constants.

my $MINUTE = 60;
my $HOUR   = (60 * $MINUTE);
my $DAY	   = (24 * $HOUR);
my $WEEK   = (7  * $DAY);

#---------------------------------------------------------------------------
#
# Routine:	timetrans()
#
# Purpose:	This routine converts an integer seconds count into the
#		equivalent number of weeks, days, hours, and minutes.
#
sub timetrans
{
	my $seconds = shift;			# The seconds to be translated.
	my $minutes;				# Minutes in seconds.
	my $hours;				# Hours in seconds.
	my $days;				# Days in seconds.
	my $weeks;				# Weeks in seconds.

	my $tstr;				# Time string.
	my $sstr;				# Seconds string.
	my $mstr;				# Minutes string.
	my $hstr;				# Hours string.
	my $dstr;				# Days string.

	#
	# Ensure we were given a valid seconds count.
	#
	if($seconds < 0)
	{
		print "bad value - <$seconds>\n";
		return("");
	}

	#
	# Handle the less-than-a-minute case.
	#
	if($seconds < $MINUTE)
	{
		$tstr = "$seconds second";
		$tstr = $tstr . "s" if($seconds != 1);

		return("") if($seconds == 0);
		return($tstr);
	}

	#
	# Handle the less-than-an-hour case.
	#
	if($seconds < $HOUR)
	{
		$minutes = $seconds / $MINUTE;
		$seconds = $seconds % $MINUTE;

		$sstr = timetrans($seconds);
		if($sstr ne "")
		{
			$tstr = sprintf("%d minutes, $sstr",$minutes);
		}
		else
		{
			$tstr = sprintf("%d minutes",$minutes);
		}

		$tstr =~ s/minutes/minute/ if($tstr =~ /^1 /);

		return("") if($minutes == 0);
		return($tstr);
	}

	#
	# Handle the less-than-a-day case.
	#
	if($seconds < $DAY)
	{
		$hours = $seconds / $HOUR;
		$minutes = $seconds % $HOUR;

		$mstr = timetrans($minutes);
		if($mstr ne "")
		{
			$tstr = sprintf("%d hours, $mstr",$hours);
		}
		else
		{
			$tstr = sprintf("%d hours",$hours);
		}

		$tstr =~ s/hours/hour/ if($tstr =~ /^1 /);

		return("") if($hours == 0);
		return($tstr);
	}

	#
	# Handle the less-than-a-week case.
	#
	if($seconds < $WEEK)
	{
		$days = $seconds / $DAY;
		$hours = $seconds % $DAY;

		$hstr = timetrans($hours);
		if($hstr ne "")
		{
			$tstr = sprintf("%d days, $hstr",$days);
		}
		else
		{
			$tstr = sprintf("%d days",$days);
		}

		$tstr =~ s/days/day/ if($tstr =~ /^1 /);

		return("") if($days == 0);
		return($tstr);
	}


	#
	# The rest of the cases all fall into weeks.  Months get a bit
	# sticky, so we're going to ignore them.
	#
	$weeks  = $seconds / $WEEK;
	$days	= $seconds % $WEEK;

	$dstr = timetrans($days);
	if($dstr ne "")
	{
		$tstr = sprintf("%d weeks, $dstr",$weeks);
	}
	else
	{
		$tstr = sprintf("%d weeks",$weeks);
	}

	$tstr =~ s/weeks/week/ if($tstr =~ /^1 /);

	return($tstr);
}

1;

#############################################################################

=pod

=head1 NAME

Net::DNS::SEC::Tools::timetrans - Convert an integer seconds count into text units.

=head1 SYNOPSIS

  use Net::DNS::SEC::Tools::timetrans;

  $timestring = timetrans(86488);

=head1 DESCRIPTION

The I<timetrans>() interface in the B<Net::DNS::SEC::Tools::timetrans>
converts an integer seconds count into the equivalent number of weeks,
days, hours, and minutes.  The time converted is a relative time, B<not>
an absolute time.  The returned time is given in terms of weeks, days, hours,
minutes, and seconds, as required to express the seconds count appropriately.

=head1 EXAMPLES

I<timetrans(400)> returns I<6 minutes, 40 seconds>

I<timetrans(420)> returns I<7 minutes>

I<timetrans(888)> returns I<14 minutes, 48 seconds>

I<timetrans(86400)> returns I<1 day>

I<timetrans(86488)> returns I<1 day, 28 seconds>

I<timetrans(715000)> returns I<1 week, 1 day, 6 hours, 36 minutes, 40 second>

I<timetrans(720000)> returns I<1 week, 1 day, 8 hours>

=head1 INTERFACES

The interfaces to the B<Net::DNS::SEC::Tools::timetrans> module are given
below.

=head2 I<timetrans()>

This routine converts an integer seconds count into the equivalent number of
weeks, days, hours, and minutes.  This converted seconds count is returned
as a text string.  The seconds count must be greater than zero or an error
will be returned.

Return Values:

    If a valid seconds count was given, the count converted into the
	appropriate text string will be returned.

    An empty string is returned if the no seconds count was given or if
	the seconds count is less than one.

=head1 COPYRIGHT

Copyright 2004-2005 SPARTA, Inc.  All rights reserved.
See the COPYING file included with the DNSSEC-Tools package for details.

=head1 AUTHOR

Wayne Morrison, tewok@users.sourceforge.net

=head1 SEE ALSO

I<timetrans(1)>

=cut

