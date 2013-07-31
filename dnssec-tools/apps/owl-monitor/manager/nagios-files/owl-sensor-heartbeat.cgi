#!/usr/bin/perl
#
# Copyright 2012-2013 SPARTA, Inc.  All rights reserved.  See the COPYING
# file distributed with this software for details.
#
# owl-sensor-heartbeat.cgi				Owl Monitoring System
#
#       This CGI script records "heartbeats" from the Owl Monitoring Systems'
#	sensor nodes.  It will record web contacts from Owl sensor nodes,
#	with the record intended for use by Nagios or some other management
#	system as a means of tracking sensor availability.
#
# Revision History:
#       1.0     Initial version.				121201
#
#	2.0	Released as part of DNSSEC-Tools 2.0.		130301
#

use strict;

#------------------------------------------------------------------------
# Version information.
#
my $NAME   = 'owl-sensor-heartbeat.cgi';
my $VERS   = "$NAME version: 2.0.0";
my $DTVERS = "DNSSEC-Tools version: 2.0";

#------------------------------------------------------------------------
# Defaults and some constants.
#
#	$DIR must be adjusted for each site.
#

my $sensor = '<whoami?>';			# Sensor's name.

my $hbfile = '';				# Constructed heartbeat file.

my $DIR = '/owl/data';				# Heartbeat directory.
my $HBFILE = 'heartbeat';			# Heartbeat file.

#------------------------------------------------------------------------

main();
exit(0);

#----------------------------------------------------------------------------
# Routine:	sensorize()
#
# Purpose:	Run the whole shebang.
#
sub main
{
	sensorize();
	reply("Thanks for reporting, $sensor!");
}

#----------------------------------------------------------------------------
# Routine:	reply()
#
# Purpose:	Send a generic reply to the sensor.
#
sub reply
{
	my $msg = shift;			# Message to send sensor.

	print "Content-type: text/plain\n\n";

	print "\n\n$msg\n\n";
}

#----------------------------------------------------------------------------
# Routine:	sensorize()
#
# Purpose:	Add a line to the sensor's heartbeat file.
#
sub sensorize
{
	my $url = $ENV{'REQUEST_URI'};			# URL that started us.
	my $chronos;					# Timestamp.

	#
	# Get the sensor's name.
	#
	$url =~ /\?sensor=(.*)$/;
	$sensor = $1;
	$sensor = $ENV{'REMOTE_ADDR'} if($sensor eq '');

	#
	# Get the timestamp.
	#
	$chronos = time;

	#
	# Build the name of the heartbeat file.
	#
	gethbfile();

	#
	# Write our record.
	#
	open(SHB,"> $hbfile");
	print SHB "$chronos $sensor\n";
	close(SHB);
}

#----------------------------------------------------------------------------
# Routine:	gethbfile()
#
# Purpose:	Build the name of the heartbeat file.
#
sub gethbfile
{
	#
	# Ensure we recognize the sensor.  We don't want to be recording
	# heartbeats from just anyone.
	#
	if(! -e "$DIR/$sensor")
	{
		reply("unrecognized sensor - \"$sensor\"");
		exit(1);
	}

	#
	# And now build the filename.
	#
	$hbfile = "$DIR/$sensor/$HBFILE";
}

#----------------------------------------------------------------------------

=pod

=head1 NAME

owl-sensor-heartbeat.cgi - Records heartbeat contacts from Owl sensor nodes

=head1 SYNOPSIS

  http://owl.example.com/cgi-bin/owl-sensor-heartbeat.cgi?sensor=<sensorname>

=head1 DESCRIPTION

B<owl-sensor-heartbeat.cgi> records "heartbeats" from Owl sensor nodes.
This is a simple heartbeat, as only the most recent will be saved for a
particular sensor.  An historical record is not maintained.

B<owl-sensor-heartbeat.cgi> will record web contacts from Owl sensor nodes,
with the record intended for use by Nagios or some other management system as
a means of tracking sensor availability.  This is only intended to be called
as a result of a web access; it is not intended for direct use by users.

The sensor name is taken from the REQUEST_URI environment variable.
If that is not set, then the sensor host's IP address (as given in the
REMOTE_ADDR environment variable) will be used instead.

Only valid sensors will have their heartbeats recorded.  A valid sensor, in
this case, is one that has a sensor directory in the Owl data directory.

=head1 SEE ALSO

owl-dnstimer(1),
owl-heartbeat(1),
owl-sensord(1),
owl-stethoscope(1)

=head1 COPYRIGHT

Copyright 2012-2013 SPARTA, Inc.  All rights reserved.

=head1 AUTHOR

Wayne Morrison, tewok@tislabs.com

=cut

