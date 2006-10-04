#!/usr/bin/perl
#
# Copyright 2005-2006 SPARTA, Inc.  All rights reserved.  See the COPYING
# file distributed with this software for details
#
# DNSSEC Tools
#
# timetrans
#
#       This module contains an interface to convert an integer seconds count
#	into the equivalent number of weeks, days, hours, and minutes.
#

package Net::DNS::SEC::Tools::timetrans;

use strict;

require Exporter;

our @ISA = qw(Exporter);

our @EXPORT = qw(timetrans fuzzytimetrans);

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
	return("") if($seconds < 0);

	#
	# Check for zero seconds.
	#
	return("0 seconds") if($seconds == 0);

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

#---------------------------------------------------------------------------
#
# Routine:	fuzzytimetrans()
#
# Purpose:	This routine converts an integer seconds count into the
#		equivalent number of weeks *or* days *or* hours *or* minutes.
#
sub fuzzytimetrans
{
	my $seconds = shift;				# Seconds to translate.

	my $div;					# Divisor.
	my $unit;					# Time unit.

	my $remnant;					# Calculated time.
	my $timestr;					# Translated time.

	#
	# Ensure we were given a valid seconds count.
	#
	return("") if($seconds < 0);

	#
	# Check for zero seconds.
	#
	return("0 seconds") if($seconds == 0);

	#
	# Set the divisor and textual units we'll be using, based on
	# how many seconds we were given.
	#
	if($seconds < $MINUTE)
	{
		$div  = 1;		$unit = "second";
	}
	elsif($seconds < $HOUR)
	{
		$div  = $MINUTE;	$unit = "minute";
	}
	elsif($seconds < $DAY)
	{
		$div  = $HOUR;		$unit = "hour";
	}
	elsif($seconds < $WEEK)
	{
		$div  = $DAY;		$unit = "day";
	}
	else
	{
		$div  = $WEEK;		$unit = "week";
	}

	#
	# Calculate the number of units we have and translate it into
	# an "N.M" floating format.
	#
	$remnant = $seconds / $div;
	$timestr = sprintf("%.1f",$remnant);

	#
	# Pluralize the units if needed and build our return value.
	#
	$unit = $unit . "s" if($timestr != 1);
	$timestr = "$timestr $unit";

	return($timestr);
}

1;

#############################################################################

=pod

=head1 NAME

Net::DNS::SEC::Tools::timetrans - Convert an integer seconds count into text units.

=head1 SYNOPSIS

  use Net::DNS::SEC::Tools::timetrans;

  $timestring = timetrans(86488);

  $timestring = fuzzytimetrans(86488);

=head1 DESCRIPTION

The I<timetrans>() interface in B<Net::DNS::SEC::Tools::timetrans>
converts an integer seconds count into the equivalent number of weeks,
days, hours, and minutes.  The time converted is a relative time, B<not>
an absolute time.  The returned time is given in terms of weeks, days, hours,
minutes, and seconds, as required to express the seconds count appropriately.

The I<fuzzytimetrans>() interface converts an integer seconds count into the
equivalent number of weeks B<or> days B<or> hours B<or> minutes.  The unit
chosen is that which is most natural for the seconds count.  One decimal
place of precision is included in the result.

=head1 INTERFACES

The interfaces to the B<Net::DNS::SEC::Tools::timetrans> module are given
below.

=head2 B<timetrans()>

This routine converts an integer seconds count into the equivalent number of
weeks, days, hours, and minutes.  This converted seconds count is returned
as a text string.  The seconds count must be greater than zero or an error
will be returned.

Return Values:

    If a valid seconds count was given, the count converted into the
	appropriate text string will be returned.

    An empty string is returned if no seconds count was given or if
	the seconds count is less than one.

=head2 B<fuzzytimetrans()>

This routine converts an integer seconds count into the equivalent number of
weeks, days, hours, or minutes.  This converted seconds count is returned
as a text string.  The seconds count must be greater than zero or an error
will be returned.

Return Values:

    If a valid seconds count was given, the count converted into the
	appropriate text string will be returned.

    An empty string is returned if no seconds count was given or if
	the seconds count is less than one.

=head1 EXAMPLES

B<timetrans(400)> returns I<6 minutes, 40 seconds>

B<timetrans(420)> returns I<7 minutes>

B<timetrans(888)> returns I<14 minutes, 48 seconds>

B<timetrans(86400)> returns I<1 day>

B<timetrans(86488)> returns I<1 day, 28 seconds>

B<timetrans(715000)> returns I<1 week, 1 day, 6 hours, 36 minutes, 40 second>

B<timetrans(720000)> returns I<1 week, 1 day, 8 hours>

B<fuzzytimetrans(400)> returns I<6.7 minutes>

B<fuzzytimetrans(420)> returns I<7.0 minutes>

B<fuzzytimetrans(888)> returns I<14.8 minutes>

B<fuzzytimetrans(86400)> returns I<1.0 day>

B<fuzzytimetrans(86488)> returns I<1.0 day>

B<fuzzytimetrans(715000)> returns I<1.2 weeks>

B<fuzzytimetrans(720000)> returns I<1.2 weeks>

=head1 COPYRIGHT

Copyright 2004-2006 SPARTA, Inc.  All rights reserved.
See the COPYING file included with the DNSSEC-Tools package for details.

=head1 AUTHOR

Wayne Morrison, tewok@users.sourceforge.net

=head1 SEE ALSO

B<timetrans(1)>

=cut

