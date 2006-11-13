#
# Copyright 2006 SPARTA, Inc.  All rights reserved.  See the COPYING
# file distributed with this software for details
#
# DNSSEC Tools
#
#	Rollrec file format.
#

1;

#############################################################################

=pod

=head1 NAME

B<rollrec> - Rollover-related zone data used by DNSSEC-Tools programs.

=head1 DESCRIPTION

I<rollrec> files contain data used by the DNSSEC-Tools to manage key rollover.
A I<rollrec> file is organized in sets of I<rollrec> records.  Each I<rollrec>
describes the rollover state of a single zone and must be either of I<roll>
type or I<skip> type.  Zone I<rollrec>s record information about currently
rolling zones.  Skip I<rollrec>s record information about zones that are not
being rolled.  A I<rollrec> consists of a set of keyword/value entries.

The DNSSEC-Tools B<rollrec> module manipulates the contents of a I<rollrec>
file.  Module interfaces exist for looking up I<rollrec> records, creating
new records, and modifying existing records.

The following is an example of a roll I<rollrec>:

    roll "example.com"
	    zonefile	"example.com.signed"
	    keyrec	"example.com.krf"
	    curphase	"1"
	    maxttl	"60"
	    display	"1"
	    phasestart	"Mon Nov 13 19:31:26 2006"

The following is an example of a skip I<rollrec>:

    skip "test.com"
	    zonefile	"test.com.signed"
	    keyrec	"test.com.krf"
	    curphase	"0"
	    maxttl	"60"
	    display	"1"
	    phasestart	"Mon Nov 13 19:31:50 2006"

=head1 FIELDS

The fields in a I<rollrec> record are:


 * curphase	"0"

The zone's current rollover phase.  A value of zero indicates that the zone
is not in rollover, but is in normal operation.  A value of 1, 2, 3, 4
indicates that the zone is in that rollover phase.

 * display	"1"

This boolean field indicates whether or not the zone should be displayed by
the B<blinkenlights> program.

 * keyrec	"test.com.krf"

The zone's I<keyrec> file.

 * maxttl	"60"

The maximum time-to-live for the zone.  This is measured in seconds.

 * phasestart	"Mon Nov 13 19:31:50 2006"

The time-stamp of the beginning of the zone's current phase.

 * zonefile	"test.com.signed"

The zone's zone file.

=head1 COPYRIGHT
                 
Copyright 2006 SPARTA, Inc.  All rights reserved.
See the COPYING file included with the DNSSEC-Tools package for details.

=head1 AUTHOR

Wayne Morrison, tewok@users.sourceforge.net

=head1 SEE ALSO

B<blinkenlights(8)>,
B<lsroll(1)>,
B<rollerd(8)>,
B<zonesigner(8)>

B<Net::DNS::SEC::Tools::keyrec(3)>,
B<Net::DNS::SEC::Tools::rollrec(3)>

B<Net::DNS::SEC::Tools::file-keyrec(5)>

=cut
