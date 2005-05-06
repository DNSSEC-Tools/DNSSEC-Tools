#
#
# Copyright 2005 Sparta, inc.  All rights reserved.  See the COPYING
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
			      }
			   return \@qs;
		       }},
		     ],
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
		     if (qwparam('dnssec_zone_names_first')) {
			 $rstr .= qwparam('zonename'.$i) . " " .
			   qwparam('file'.$i) . " ";
		     } else {
			 $rstr .= qwparam('file'.$i) . " " .
			   qwparam('zonename'.$i) . " ";
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

  GetOptions(...,
             ['GUI:otherprimaries',dnssec_tools_get_qwprimitives()]);

=head1 DESCRIPTION

  TBD

=head1 COPYRIGHT

Copyright 2005 Sparta, Inc.  All rights reserved.
See the COPYING file included with the dnssec-tools package for details.

=head1 AUTHOR

Wes Hardaker <hardaker@users.sourceforge.net>

=head1 SEE ALSO

Net::DNS

http://www.dnssec-tools.org/

=cut

