#!/usr/bin/perl
#
# Copyright 2006 SPARTA, Inc.  All rights reserved.  See the COPYING
# file distributed with this software for details
#
#
# blinkenlights.conf.pm
#
#	This script does nothing but provide a container for documentation
#	on the blinkenlights.conf file.
#

1;

##############################################################################
#

=pod

=head1 NAME

blinkenlights.conf - Configuration file for the DNSSEC-Tools B<blinkenlights>
program.

=head1 DESCRIPTION

This file contains configuration information for the DNSSEC-Tools
B<blinkenlights> program.  These configuration data are used as default
values The B<conf.pm> module is used to parse this configuration file.

A line in this file contains either a comment or a configuration
entry.  Comment lines start with either a '#' character or a ';' character.
Comment lines and blank lines are ignored by the DNSSEC-Tools programs.

Configuration entries are in a I<keyword/value> format.  The keyword is a
character string that contains no whitespace.  The value is a tokenized list
of the remaining character groups, with each token separated by a single space.

True/false flags must be given a true or false value.
True values are:  1, "yes", "on".
False values are:  0, "no", "off".

=head1 Configuration Records

The following records are recognized by B<blinkenlights>.

=over 4

=item colors

Toggle indicating whether or not to use different background colors for
B<blinkenlights> zone stripes.
If on, different colors will be used.
If off, the I<skipcolor> value will be used.

=item fontsize

The font size used to display information in the B<blinkenlights> window.
If this is not specified, the default font size is 18.

=item modify

Toggle indicating whether or not to allow access to B<blinkenlights>'
zone-modification commands.  These commands are the GUI's front-end to
some of B<rollerd>'s commands.
If on, the commands are enabled.
If off, the commands are disabled.

=item shading

Toggle indicating whether or not to use color shading in B<blinkenlights>'
status column.
If on, shading is enabled.
If off, shading is disabled.

=item showskip

Toggle indicating whether or not to display skipped zones in B<blinkenlights>'
window.
If on, skipped zones are displayed.
If off, skipped zones are not displayed.

=item skipcolor

The background color to use in displaying skipped zones.
If this is not specified, the default color is grey.

=back

=head1 Example File

The following is an example B<blinkenlights.conf> configuration file.

    #
    # DNSSEC-Tools configuration file for blinkenlights
    #
    #	Recognized values:
    #		colors		use different colors for stripes (toggle)
    #		fontsize	size of demo output font
    #		modify		allow modification commands (toggle)
    #		shading		shade the status columns (toggle)
    #		showskip	show skipped zones (toggle)
    #		skipcolor	color to use for skip records

    fontsize		24
    modify		no

    colors		on
    skipcolor		orange
    showskip		1
    shading		yes

=head1 COPYRIGHT

Copyright 2006 SPARTA, Inc.  All rights reserved.
See the COPYING file included with the DNSSEC-Tools package for details.

=head1 AUTHOR

Wayne Morrison, tewok@users.sourceforge.net

=head1 SEE ALSO

B<blinkenlights(8)>,
B<rollerd(8)>

B<Net::DNS::SEC::Tools::conf.pm(3)>

=cut
