#
#
# Copyright 2005-2014 SPARTA, Inc.  All rights reserved.  See the COPYING
# file distributed with this software for details
#
#

package Net::DNS::SEC::Tools::QWPrimitives;

use strict;
require Exporter;

use Net::DNS::SEC::Tools::conf;


our $VERSION = "1.9";
our $MODULE_VERSION = "1.9.0";

our @ISA = qw(Exporter);

our @EXPORT = qw(dnssec_tools_get_qwprimitives DTGetOptions);

our $gui_file_slots = 5;

#######################################################################
# Getopt::GUI::Long safe calling in case it doesn't exist on the system
#
sub DTGetOptions {
    my $configfile;
    my $usegui = 0;
    my $extraopts = [];

    # A special calling case is allowed: --dtconf configfile
    if ($ARGV[0] eq '--dtconf') {
	$configfile = $ARGV[1];
	@ARGV = () if ($#ARGV == 1); # call the GUI or help if only option
    }

    # read in the default config file
    my %config = parseconfig($configfile);

    # see if we CAN even do a gui
    my $have_gui = eval {require Getopt::GUI::Long;};

    # special config; is this used anywhere?
    if ($_[0] eq 'config') {
	shift @_;
	$extraopts = shift @_;
    }

    # if the default config says not to use a GUI, mark it not to load.
    # (boolconvert defaults nothing=false and we want nothing = true)
    if (exists($config{'usegui'})) {
	$usegui = boolconvert($config{'usegui'});
    }

    # allow the environmental override
    if (exists($ENV{'DT_GUI'})) {
	$usegui = boolconvert($ENV{'DT_GUI'});
    }

    # XXX: support --dtconf foo.conf --gui

    # then do the right thing based on if we have the Getopt::GUI::Long package
    # and whether we should use it or not by default.
    if ($have_gui) {
	require Getopt::Long;
	import Getopt::GUI::Long;
	Getopt::GUI::Long::Configure(qw(display_help no_ignore_case));

	if (!$usegui &&
	    $Getopt::GUI::Long::VERSION >= 0.9) {
	    # we *can perform* a GUI at this point, but the default is off.
	    # the user can still override using --gui
	    Getopt::GUI::Long::Configure(qw(no_gui), @$extraopts);
	}

	return GetOptions(@_);
    }

    # fall back to the normal Getopt::Long support
    require Getopt::Long;
    import Getopt::Long;

    # set up for -h / --help output warning
    my $hashref = 0;
    my $optionref;
    if (ref($_[0]) eq 'HASH') {
	# hash reference options were passed
	$optionref = $_[0];
	$hashref = 1;
	push @_, ["h|help|help-full"];
    } else {
	# variable reference options were passed
	push @_, ["h|help|help-full"], \$optionref;
    }

    # actually run getoptions
    Getopt::Long::Configure(qw(auto_help no_ignore_case));
    my $ret = GetOptions(LocalOptionsMap(@_));

    # check to see if they specified -h or --help
    if (($optionref && $optionref->{'h'}) ||
	(!$hashref && $$optionref)) {
	print
	  "\nPlease install perl's Getopt::GUI::Long module for help output\n\n";
	exit 1;
    }

    return $ret;
}

sub LocalOptionsMap {
    my ($st, $cb, @opts) = ((ref($_[0]) eq 'HASH') 
			    ? (1, 1, $_[0]) : (0, 2));
    for (my $i = $st; $i <= $#_; $i += $cb) {
	if ($_[$i]) {
	    next if (ref($_[$i]) eq 'ARRAY' && $_[$i][0] =~ /^GUI:/);
	    push @opts, ((ref($_[$i]) eq 'ARRAY') ? $_[$i][0] : $_[$i]);
	    push @opts, $_[$i+1] if ($cb == 2);
	}
    }
    return @opts;
}

sub dnssec_tools_get_qwprimitives {
    my %qwp =
      (
       # defining our own follow-on screens here
       'getzonefiles' =>
       {title => 'Which files',
	introduction => 'Which DNS zone files do you want to operate on?.',
	questions => [{type => 'dynamic',
		       values => sub {
			   my @qs;
			   for (my $i = 1; $i <= $gui_file_slots; $i++) {
			       push @qs,
				 {type => 'fileupload',
				  text => 'Zone File ' . $i,
				  name => 'file' . $i};
			       push @qs,
				 {type => 'hidden',
				  text => '',
				  name => 'tmp_name' . $i,
				  values => ''};
			   }
			   return \@qs;
		       }},
		     ],
	post_answers => 
	[sub {
	     require QWizard;
	     import QWizard;
	     my $rstr;
	     for (my $i = 1; $i <=5; $i++) {
		 if (qwparam('file'.$i)) {
		     my $fn =
		       $Getopt::GUI::Long::GUI_qw->qw_upload_file('file'.$i);
		     $fn =~ s/.*qwHTML//;
		     qwparam('tmp_name' . $i, $fn);
		 }
	     }
	 }],
       },

       'getzonenames' =>
       {title => 'Zone Names',
	introduction => 'For each of the DNS zone files you selected, please indicate what their zone names are.',
	post_answers => 
	[sub {
	     require QWizard;
	     import QWizard;
	     my $rstr;
	     for (my $i = 1; $i <=5; $i++) {
		 if (qwparam('file'.$i) &&
		     qwparam('zonename'.$i)) {
		     if (ref($_[0]->{'generator'}) =~ /HTML/) {
			 # don't allow web users to specify other file names
			 my $fn = qwparam('tmp_name'.$i);
			 if ($fn =~ /^[^\.\/]{6}\.tmp$/) {
			     $fn = "/tmp/qwHTML$fn";
			     next if (! -f $fn);
			     if (qwparam('dnssec_zone_names_first')) {
				 push @main::guiargs,
				   qwparam('zonename'.$i), $fn;
			     } else {
				 push @main::guiargs,
				   $fn, qwparam('zonename'.$i);
			     }
			 }
		     } else {
			 $rstr .= qwparam('file' . $i) . " " .
			   qwparam('zonename'.$i);
			 push @main::guiargs,
			   qwparam('file' . $i), qwparam('zonename'.$i);
		     }
		 }
	     }
	 }],
	questions => [{type => 'dynamic',
		       values => sub {
			   my @qs;
			   require QWizard;
			   import QWizard;
			   for (my $i = 1; $i <=5; $i++) {
			       if (qwparam('file'.$i)) {
				   my $def = qwparam('file'.$i);
				   $def =~ s/^.*\///;
				   $def =~ s/^db\.//;
				   $def =~ s/\.signed$//;
				   $def =~ s/\.zs$//;
				   push @qs,
				     {type => 'text',
				      name => 'zonename' . $i,
				      default => $def,
				      text => qwparam('file'.$i)};
			       }
			   }
			   return \@qs;
		       }}]
       },
       @_,
      );
    return %qwp;
}

1;

#############################################################################

=pod

=head1 NAME

Net::DNS::SEC::Tools::QWPrimitives - QWizard primitives for DNSSEC-Tools

=head1 SYNOPSIS

  use Net::DNS::SEC::Tools::QWPrimitives;
  use Getopt::Long::GUI;

  our @guiargs;

  DTGetOptions(  ...,
	         ['GUI:nootherargs',1],
                 ['GUI:otherprimaries',dnssec_tools_get_qwprimitives()],
  	         ['GUI:submodules','getzonefiles','getzonenames'],
              );

=head1 DESCRIPTION

B<QWizard> is a dynamic GUI-construction kit.  It displays a series of
questions, then retrieves and acts upon the answers.  This module
provides access to B<QWizard> for DNSSEC-Tools software.

In particular, the I<dnssec_tools_get_qwprimitives()> returns a set of
primary screens for requesting a set of zone files followed by a set
of domain names for those zone files.  These are then pushed into the
@guiargs which should be treated as the final ARGV array to process.

=head1 COPYRIGHT

Copyright 2005-2014 SPARTA, Inc.  All rights reserved.
See the COPYING file included with the DNSSEC-Tools package for details.

=head1 AUTHOR

Wes Hardaker <hardaker@users.sourceforge.net>

=head1 SEE ALSO

B<Getopt::GUI::Long(3)>,
B<Net::DNS(3)>,
B<QWizard(3)>

http://www.dnssec-tools.org

=cut

