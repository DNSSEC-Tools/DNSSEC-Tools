#
#
# Copyright 2006 SPARTA, Inc.  All rights reserved.  See the COPYING
# file distributed with this software for details
#
#
package Net::DNS::SEC::Tools::BootStrap;

use strict;
require Exporter;

our $VERSION = "0.01";

our @ISA = qw(Exporter);

our @EXPORT = qw(dnssec_tools_load_mods);

our $gui_file_slots = 5;

our %extra_help_text = (GraphViz => 
  "Note:
  You also need the graphviz base libraries and tools as well.  For
  this, please see:

    http://www.graphviz.org/
");


sub dnssec_tools_load_mods {
    my %modules = @_;
    my $oops = 0;

    foreach my $k (keys(%modules)) {
	my $haveit = eval "require $k;";
	if (!$haveit) {
	    if ($modules{'$k'} ne 'noerror') {
		print STDERR "
SETUP ERROR:
--------------------------------------------------

I could not find an installation of the '$k' perl module, which this
tool needs in order to operate.

Please obtain and install this module.  You may be able do this using
the CPAN ( http://www.cpan.org/ ) system as follows:

   perl -MCPAN -e 'install \"$k\"'

The above command should install the '$k' module if it is available
within the CPAN archives.
$extra_help_text{$k}$modules{$k}
";
	    }
	    $oops = 1;
	} else {
	    package main;
	    import $k;
	    package Net::DNS::SEC::Tools::BootStrap;
	}
    }
    exit if ($oops);
}


1;

#############################################################################

=pod

=head1 NAME

Net::DNS::SEC::Tools::BootStrap - Optional loading of Perl modules

=head1 SYNOPSIS

  use Net::DNS::SEC::Tools::BootStrap;

  dnssec_tools_load_mods(
     PerlModule => 'Additional help/error text'
  );


=head1 DESCRIPTION

The DNSSEC-Tools package requires a number of Perl modules that are only
needed by some of the tools.  This module helps determine at run-time, rather
than at installation time, if the right tools are available on the system.
If any module fails to load, I<dnssec_tools_load_mods()> will display an
error message and calls I<exit()>.  The error message describes how to
install a module via CPAN.

The arguments to I<dnssec_tools_load_mods()> are given in pairs.  Each pair is
a module to try to load (and import) and an supplemental error message.  If
the module fails to load, the supplemental error message will be displayed
along with the installation-via-CPAN message.  If the error   message consists
of the string "noerror", then no error message will be displayed before the
function exits.

=head1 CAVEATS

The module will try to import any exported subroutines from the
module into the I<main> namespace.  This means that the I<BootStrap.pm>
module is likely not useful for importing symbols into other modules.
Work-arounds for this are:

=over

=item - import the symbols by hand into

  dnssec_tools_load_mods(
     PerlModule => 'Additional help/error text'
  );

  import PerlModule qw(func1 func2);

  func1(arg1, arg2);

=item - call the fully qualified function names instead

  dnssec_tools_load_mods(
     PerlModule => 'Additional help/error text'
  );

  PerlModule::func1(arg1, arg2);

=back

=head1 COPYRIGHT

Copyright 2006 SPARTA, Inc.  All rights reserved.
See the COPYING file included with the DNSSEC-Tools package for details.

=head1 AUTHOR

Wes Hardaker <hardaker@users.sourceforge.net>

=head1 SEE ALSO

http://www.dnssec-tools.org/

=cut

