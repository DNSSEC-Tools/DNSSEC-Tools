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
    printf("%s\%-${tagwidth}s %s\n", $leader, $tag, $message);
}

sub Separator {
    my ($self) = @_;

    print "\n";
}

sub StartSection {
    my ($self, $name) = @_;

    print " " x $self->{'section_depth'} . "$name:\n";

    $self->{'section_depth'} += 2;
}

sub EndSection {
    my ($self) = @_;
    $self->{'section_depth'} -= 2;
    $self->{'section_depth'} = 0 if ($self->{'section_depth'} < 0);
}

1;
