#
# Copyright 2013-2013 Parsons.  All rights reserved.
# See the COPYING file included with the DNSSEC-Tools package for details.
#

package Net::DNS::SEC::Tools::Donuts::Output::Format::XML;

use strict;
use Net::DNS::SEC::Tools::Donuts::Output::Format;

our @ISA = qw(Net::DNS::SEC::Tools::Donuts::Output::Format);

sub escape_html {
    return $_[0]; # XXX
}

sub simplify_tag {
    return $_[0]; # XXX
}

sub Output {
    my ($self, $tag, $message) = @_;

    my $tagwidth = 12;
    $tag = simplify_tag($tag);

    my $leader = " " x $self->{'section_depth'};
    sprintf("%s<%s>%s</%s>\n", $leader, $tag, escape_html($message), $tag);
}

sub Separator {
    my ($self) = @_;

    return "\n";
}

sub StartSection {
    my ($self, $tag, $name) = @_;

    $tag = simplify_tag($tag);
    $name = escape_html($name);

    $self->{'section_depth'} += 2;
    push @{$self->{'tags'}}, $tag;

    return " " x ($self->{'section_depth'}-2) . 
	sprintf("<%s name=\"%s\">\n", $tag, $name);
}

sub EndSection {
    my ($self) = @_;
    $self->{'section_depth'} -= 2;
    $self->{'section_depth'} = 0 if ($self->{'section_depth'} < 0);

    my $name = pop @{$self->{'tags'}};

    return " " x ($self->{'section_depth'}) . 
	sprintf("</%s>\n", $name);
}

sub Comment {
    my ($self, $comment) = @_;
    return "<!-- " . escape_html($comment) . " -->\n";
}

1;
