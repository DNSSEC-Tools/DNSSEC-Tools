#!/usr/bin/perl
#
# Copyright 2005 SPARTA, Inc.  All rights reserved.  See the COPYING
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

=item random

The random device generator to be passed to I<dnssec-keygen>.

=item savekeys

A true/false flag indicating if old keys should be moved to the
archive directory.

=item signzone

The path to the I<dnssec-signzone> command.

=item zsklength

The default ZSK key length to be passed to I<dnssec-keygen>.

=back

=head1 Example File

The following is an example B<dnssec-tools.conf> configuration file.

    #
    # Paths to required programs.  These may need adjusting for
    # individual hosts.
    #
    checkzone       /usr/local/sbin/named-checkzone
    keygen          /usr/local/sbin/dnssec-keygen
    signzone        /usr/local/sbin/dnssec-signzone
    
    
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
    
    
    #
    # Settings that will be noticed by zonesigner.
    #
    default_keyrec	default.krf
    entropy_msg		0

    savekeys            1
    archivedir          /usr/local/etc/dnssec/KEY-SAFE

=head1 COPYRIGHT

Copyright 2004-2005 SPARTA, Inc.  All rights reserved.
See the COPYING file included with the DNSSEC-Tools package for details.

=head1 AUTHOR

Wayne Morrison, tewok@users.sourceforge.net

=head1 SEE ALSO

B<zonesigner(8)>

B<Net::DNS::SEC::Tools::conf.pm(3)>,
B<Net::DNS::SEC::Tools::keyrec.pm(3)>

=cut
