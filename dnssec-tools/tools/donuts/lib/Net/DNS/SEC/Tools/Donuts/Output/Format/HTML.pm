#
# Copyright 2013-2013 Parsons.  All rights reserved.
# See the COPYING file included with the DNSSEC-Tools package for details.
#

package Net::DNS::SEC::Tools::Donuts::Output::Format::HTML;

use strict;
use Net::DNS::SEC::Tools::Donuts::Output::Format;
use HTML::Entities;

our @ISA = qw(Net::DNS::SEC::Tools::Donuts::Output::Format);

my %markups = (
    'Donuts-Results' => 'b'
    );

sub simplify_tag {
    my ($tag) = @_;
    $tag =~ s/ /-/g;
    $tag =~ s/[^-a-zA-Z0-9]//g;
    return $tag;
}

sub markup {
    my ($self, $tag, $message) = @_;

    if (exists($markups{$tag})) {
	return
	    sprintf("<%s>%s:</%s> %s", $markups{$tag},
		    encode_entities($tag), $markups{$tag},
		    encode_entities($message));
    } else {
	return
	    sprintf("%s: %s", encode_entities($tag),
		    encode_entities($message));
    }

}

sub Output {
    my ($self, $tag, $message) = @_;

    my $tagwidth = 12;
    $tag = simplify_tag($tag);

    my $leader = " " x $self->{'section_depth'};
    return "$leader<li>" . $self->markup($tag . ":", $message) . "</li>\n";
}

sub Separator {
    my ($self) = @_;

    return "<br />\n";
}

sub StartSection {
    my ($self, $tag, $name) = @_;

    $tag = simplify_tag($tag);
    $name = encode_entities($name) if ($name);

    $self->{'section_depth'} += 2;
    push @{$self->{'tags'}}, $tag;

    my $leader = " " x ($self->{'section_depth'}-2);
    if ($name) {
	return "$leader<li> " . $self->markup($tag, $name) .
	    "</li>\n$leader<ul>\n";
    }
    return "$leader<li>$tag:</li>\n$leader<ul>\n";
}

sub EndSection {
    my ($self) = @_;
    $self->{'section_depth'} -= 2;
    $self->{'section_depth'} = 0 if ($self->{'section_depth'} < 0);

    return " " x ($self->{'section_depth'}) . "</ul>";
}

sub Comment {
    my ($self, $comment) = @_;
    return if (! $self->config('allow-comments', 1));
#    return "<!-- " . encode_entities($comment) . " -->\n";
    return;
}

sub StartOutput {
    my ($self) = @_;
#    return "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n<donuts>\n";
    return;
}

sub EndOutput {
    my ($self) = @_;
#    return "</donuts>\n";
    return;
}

1;
