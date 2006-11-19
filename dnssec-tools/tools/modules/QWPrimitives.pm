#
#
# Copyright 2005-2006 SPARTA, Inc.  All rights reserved.  See the COPYING
# file distributed with this software for details
#
#
package Net::DNS::SEC::Tools::QWPrimitives;

use strict;
require Exporter;

our $VERSION = "0.01";

our @ISA = qw(Exporter);

our @EXPORT = qw(dnssec_tools_get_qwprimitives);

our $gui_file_slots = 5;

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
				  name => 'file' . $i},
			       push @qs,
				 {type => 'hidden',
				  text => '',
				  name => 'tmp_name' . $i,
				  values => ''},
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
				 $rstr .= qwparam('zonename'.$i) . " $fn ";
			     } else {
				 $rstr .= "$fn " . qwparam('zonename'.$i);
			     }
			 }
		     } else {
			 $rstr .= qwparam('file' . $i) . " " .
			   qwparam('zonename'.$i);
		     }
		 }
	     }
	     qwparam('__otherargs',$rstr);
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

  GetOptions(  ...,
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
I<__otherargs> I<qwparam> variable, which is used by B<Getopt::GUI::Long>
to generate the I<@ARGV> list.

=head1 COPYRIGHT

Copyright 2005-2006 SPARTA, Inc.  All rights reserved.
See the COPYING file included with the DNSSEC-Tools package for details.

=head1 AUTHOR

Wes Hardaker <hardaker@users.sourceforge.net>

=head1 SEE ALSO

B<Getopt::GUI::Long(3)>,
B<Net::DNS(3)>,
B<QWizard(3)>

http://www.dnssec-tools.org

=cut

