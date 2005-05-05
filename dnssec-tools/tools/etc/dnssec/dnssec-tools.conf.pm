#!/usr/bin/perl
#
# Copyright 2005 Sparta, Inc.  All rights reserved.  See the COPYING
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

dnssec-tools.conf - Configuration file for the B<dnssec-tools> programs.

=head1 DESCRIPTION

This file contains configuration information for the B<dnssec-tools> programs.
These configuration data are used if nothing else has been specified for a
particular program.

A line in the configuration file contains either a comment or a configuration
entry.  Comment lines start with a '#' character.  Comment lines and blank
lines are ignored by the B<dnssec-tools> programs.

Configuration entries are in a I<keyword/value> format.  The keyword is a
character string that contains no whitespace.  The value is a tokenized list
of the remaining character groups, with each token separated by a single space.

=head1 Configuration Records

The following records are recognized by the B<dnssec-tools> programs.
Not every B<dnssec-tools> program requires each of these records.

=over 4

=item algorithm

This entry contains the default encryption algorithm to be passed to
B<dnssec-keygen>.

=item checkzone

This entry contains the path to the B<named-checkzone> command.

=item endtime

This entry contains the zone default expiration date to be passed to
B<dnssec-signzone>.

=item keygen

This entry contains the path to the B<dnssec-keygen> command.

=item ksklength

This entry contains the default KSK key length to be passed to
B<dnssec-keygen>.

=item signzone

This entry contains the path to the B<dnssec-signzone> command.

=item zsklength

This entry contains the default ZSK key length to be passed to
B<dnssec-keygen>.

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
    ksklength	1024
    zsklength	512
    
    
    #
    # Settings for dnssec-signzone.
    #
    endtime		+259200		# RRSIGs good for three days.

=head1 AUTHOR

Wayne Morrison, tewok@users.sourceforge.net

=head1 SEE ALSO

Net::DNS::SEC::Tools::conf.pm(3)

=cut
