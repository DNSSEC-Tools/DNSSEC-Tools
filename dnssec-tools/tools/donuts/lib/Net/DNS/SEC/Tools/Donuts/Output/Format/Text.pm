#
# Copyright 2013-2013 Parsons.  All rights reserved.
# See the COPYING file included with the DNSSEC-Tools package for details.
#

package Net::DNS::SEC::Tools::Donuts::Output::Format::Text;

use strict;
use Net::DNS::SEC::Tools::Donuts::Output::Format;

our @ISA = qw(Net::DNS::SEC::Tools::Donuts::Output::Format);

sub Output {
    my ($self, $tag, $message) = @_;

    my $output_string;

    my $tagwidth = 12;
    $tag .= ":";

    my $leader = " " x $self->{'section_depth'};
    sprintf("%s\%-${tagwidth}s %s\n", $leader, $tag, $message);
}

sub Separator {
    my ($self) = @_;

    return "\n";
}

sub StartSection {
    my ($self, $tag, $name) = @_;

    $self->{'section_depth'} += 2;

    return " " x ($self->{'section_depth'}-2) . "$tag: $name\n";
}

sub EndSection {
    my ($self) = @_;
    $self->{'section_depth'} -= 2;
    $self->{'section_depth'} = 0 if ($self->{'section_depth'} < 0);
}

sub Comment {
    my ($self, $comment) = @_;
    return " " x ($self->{'section_depth'}) . "# $comment\n";
}

1;
