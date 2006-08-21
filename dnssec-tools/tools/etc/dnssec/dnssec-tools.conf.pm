#!/usr/bin/perl
#
# Copyright 2005-2006 SPARTA, Inc.  All rights reserved.  See the COPYING
# file distributed with this software for details
#
#
# dnssec-tools.conf.pm
#
#	This script does nothing but provide a container for documentation
#	on the dnssec-tools.conf file.
#

1;

##############################################################################
#

=pod

=head1 NAME

dnssec-tools.conf - Configuration file for the DNSSEC-Tools programs.

=head1 DESCRIPTION

This file contains configuration information for the DNSSEC-Tools programs.
These configuration data are used if nothing else has been specified for a
particular program.  The B<conf.pm> module is used to parse this configuration
file.

A line in the configuration file contains either a comment or a configuration
entry.  Comment lines start with either a '#' character or a ';' character.
Comment lines and blank lines are ignored by the DNSSEC-Tools programs.

Configuration entries are in a I<keyword/value> format.  The keyword is a
character string that contains no whitespace.  The value is a tokenized list
of the remaining character groups, with each token separated by a single space.

True/false flags must be given a B<1> (true) or B<0> (false) value.

=head1 Configuration Records

The following records are recognized by the DNSSEC-Tools programs.
Not every DNSSEC-Tools program requires each of these records.

=over 4

=item algorithm

The default encryption algorithm to be passed to I<dnssec-keygen>.

=item archivedir

The pathname to the archived-key directory.

=item checkzone

The path to the I<named-checkzone> command.

=item default_keyrec

The default I<keyrec> filename to be used by the B<keyrec.pm> module.

=item endtime

The zone default expiration time to be passed to I<dnssec-signzone>.

=item entropy_msg

A true/false flag indicating if the I<zonesigner> command should display
a message about entropy generation.  This is primarily dependent on the
implementation of a system's random number generation.

=item keygen

The path to the I<dnssec-keygen> command.

=item ksklength

The default KSK key length to be passed to I<dnssec-keygen>.

=item ksklife

The default length of time between KSK roll-overs.  This is measured in
seconds.

This value is B<only> used for key roll-over.  Keys do not have a life-time
in any other sense.

=item lifespan-max

The maximum length of time a key should be in use before it is rolled over.
This is measured in seconds.

=item lifespan-min

The minimum length of time a key should be in use before it is rolled over.
This is measured in seconds.

=item random

The random device generator to be passed to I<dnssec-keygen>.

=item savekeys

A true/false flag indicating if old keys should be moved to the
archive directory.

=item signzone

The path to the I<dnssec-signzone> command.

=item usegui

Flag to allow/disallow usage of the GUI for specifying command options.

=item zonesigner

The path to the I<zonesigner> command.

=item zskcount

The default number of ZSK keys that will be generated for each zone.

=item zsklength

The default ZSK key length to be passed to I<dnssec-keygen>.

=item zsklife

The default length of time between ZSK roll-overs.  This is measured in
seconds.

This value is B<only> used for key roll-over.  Keys do not have a life-time
in any other sense.

=back

=head1 Sample Times

Several configuration fields measure various times.  This section is a
convenient reference for several common times, as measured in seconds.

    3600	- hour
    86400	- day
    604800	- week
    2592000	- 30-day month
    15768000	- half-year
    31536000	- year

=head1 Example File

The following is an example B<dnssec-tools.conf> configuration file.

    #
    # Paths to required programs.  These may need adjusting for
    # individual hosts.
    #
    checkzone       /usr/local/sbin/named-checkzone
    keygen          /usr/local/sbin/dnssec-keygen
    rndc            /usr/local/sbin/rndc
    signzone        /usr/local/sbin/dnssec-signzone
    viewimage       /usr/X11R6/bin/xview

    rollrec-chk     /usr/bin/rollrec-check
    zonesigner      /usr/bin/zonesigner

    #
    # Settings for dnssec-keygen.
    #
    algorithm	rsasha1
    ksklength	2048
    zsklength	1024
    random	/dev/urandom
    
    
    #
    # Settings for dnssec-signzone.
    #
    endtime		+2592000	# RRSIGs good for 30 days.
    
    # Life-times for keys.  These defauluts indicate how long a key has
    # between roll-overs.  The values are measured in seconds.
    # 
    ksklife         15768000		# Half-year.
    zsklife         604800 		# One week.
    lifespan-max    94608000		# Two years.
    lifespan-min    3600		# One hour.

    
    #
    # Settings that will be noticed by zonesigner.
    #
    archivedir          /usr/local/etc/dnssec/KEY-SAFE
    default_keyrec	default.krf
    entropy_msg		0
    savekeys            1
    zskcount            1

    #
    # Settings for rollover-manager.
    #
    roll_logfile    /usr/local/etc/dnssec/rollerd
    roll_loglevel   info
    roll_sleeptime  60


    #
    # GUI-usage flag.
    #
    usegui		0

=head1 COPYRIGHT

Copyright 2005-2006 SPARTA, Inc.  All rights reserved.
See the COPYING file included with the DNSSEC-Tools package for details.

=head1 AUTHOR

Wayne Morrison, tewok@users.sourceforge.net

=head1 SEE ALSO

B<dtinitconf(8)>,
B<dtconfchk(8)>,
B<rollerd(8)>,
B<zonesigner(8)>

B<Net::DNS::SEC::Tools::conf.pm(3)>,
B<Net::DNS::SEC::Tools::keyrec.pm(3)>

=cut
