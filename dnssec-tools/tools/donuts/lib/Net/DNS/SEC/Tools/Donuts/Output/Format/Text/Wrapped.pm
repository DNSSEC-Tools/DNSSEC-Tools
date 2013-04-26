#
# Copyright 2013-2013 Parsons.  All rights reserved.
# See the COPYING file included with the DNSSEC-Tools package for details.
#

package Net::DNS::SEC::Tools::Donuts::Output::Format::Wrapped;

use strict;
use Net::DNS::SEC::Tools::Donuts::Output::Format::Text;
use Text::Wrap;

our @ISA = qw(Net::DNS::SEC::Tools::Donuts::Output::Format::Text);

# the only thing this class does differently form the Text class is
# wrap output

sub Output {
    my ($self, $tag, $message) = @_;

    my $output_string;
    my $format = $self->output_format();

    my $tagwidth = 12;
    $tag .= ":";

    my $leader = " " x $self->{'section_depth'};
    print Text::Wrap::wrap($leader . sprintf("\%-${tagwidth}s ", $tag),
			   $leader . " " x ($tagwidth+1), $message) . "\n";
}

1;
