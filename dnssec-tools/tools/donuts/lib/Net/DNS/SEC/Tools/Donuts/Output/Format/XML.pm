#
# Copyright 2013-2013 Parsons.  All rights reserved.
# See the COPYING file included with the DNSSEC-Tools package for details.
#

package Net::DNS::SEC::Tools::Donuts::Output::Format::XML;

use strict;
use Net::DNS::SEC::Tools::Donuts::Output::Format;
use HTML::Entities;

our @ISA = qw(Net::DNS::SEC::Tools::Donuts::Output::Format);

sub simplify_tag {
    my ($tag) = @_;
    $tag =~ s/ /-/g;
    $tag =~ s/[^-a-zA-Z0-9]//g;
    return $tag;
}

sub Output {
    my ($self, $tag, $message) = @_;

    my $tagwidth = 12;
    $tag = simplify_tag($tag);

    my $leader = " " x $self->{'section_depth'};
    sprintf("%s<%s>%s</%s>\n", $leader, $tag, encode_entities($message), $tag);
}

sub Separator {
    my ($self) = @_;

#    return "\n";
}

sub StartSection {
    my ($self, $tag, $name) = @_;

    $tag = simplify_tag($tag);
    $name = encode_entities($name) if ($name);

    $self->{'section_depth'} += 2;
    push @{$self->{'tags'}}, $tag;

    if ($name) {
	return " " x ($self->{'section_depth'}-2) . 
	    sprintf("<%s name=\"%s\">\n", $tag, $name);
    }
    return " " x ($self->{'section_depth'}-2) . 
	sprintf("<%s>\n", $tag);
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
    return if (! $self->config('allow-comments', 1));
    return "<!-- " . encode_entities($comment) . " -->\n";
}

sub StartOutput {
    my ($self) = @_;
    return "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n<donuts>\n";
}

sub EndOutput {
    my ($self) = @_;
    return "</donuts>\n";
}

1;
