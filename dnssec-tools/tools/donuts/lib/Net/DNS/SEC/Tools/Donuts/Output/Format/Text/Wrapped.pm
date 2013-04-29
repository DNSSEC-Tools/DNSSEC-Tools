#
# Copyright 2013-2013 Parsons.  All rights reserved.
# See the COPYING file included with the DNSSEC-Tools package for details.
#

package Net::DNS::SEC::Tools::Donuts::Output::Format::Text::Wrapped;

use strict;
use Net::DNS::SEC::Tools::Donuts::Output::Format::Text;
use Text::Wrap;

our @ISA = qw(Net::DNS::SEC::Tools::Donuts::Output::Format::Text);

# the only thing this class does differently form the Text class is
# wrap output

sub Output {
    my ($self, $tag, $message) = @_;

    my $output_string;

    my $tagwidth = 12;
    $tag .= ":";

    my $leader = " " x $self->{'section_depth'};
    return Text::Wrap::wrap($leader . sprintf("\%-${tagwidth}s ", $tag),
			    $leader . " " x ($tagwidth+1), $message) . "\n";
}

sub Comment {
    my ($self, $comment) = @_;
    return Text::Wrap::wrap(" " x ($self->{'section_depth'}) . "# ",
			    " " x ($self->{'section_depth'}) . "# ",
			    $comment, ) . "\n";
}


1;
