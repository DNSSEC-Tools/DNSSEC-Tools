#
# Copyright 2013-2013 Parsons.  All rights reserved.
# See the COPYING file included with the DNSSEC-Tools package for details.
#

package Net::DNS::SEC::Tools::Donuts::Output::Format::JSON;

use strict;
use Net::DNS::SEC::Tools::Donuts::Output::Format;
use CGI qw(escapeHTML);

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

    my $output = $self->get_comma_leader();

    my $leader = " " x $self->{'section_depth'};
    sprintf("%s%s\"%s\": \"%s\"", $output, $leader, $tag, escapeHTML($message));
}

sub Separator {
    my ($self) = @_;

    return "\n";
}

sub is_section_first {
    my ($self) = @_;
    return 1 if ($#{$self->{'section_firsts'}} == -1);
    my $ans = $self->{'section_firsts'}[$#{$self->{'section_firsts'}}];
    $self->{'section_firsts'}[$#{$self->{'section_firsts'}}] = 0;
    return $ans;
}

sub is_in_array {
    my ($self) = @_;
    return 0 if (!exists($self->{'in_array'}) || $#{$self->{'in_array'}} == -1);
    return $self->{'in_array'}[$#{$self->{'in_array'}}];
}

sub get_comma_leader {
    my ($self) = @_;
    my $output = "";
    $output = ",\n" if (!$self->is_section_first());
    return $output;
}

sub StartBlock {
    my ($self, $tag, $name, $startchar) = @_;

    $tag = simplify_tag($tag);
    $name = escapeHTML($name) if ($name);

    $self->{'section_depth'} += 2;

    my $output = $self->get_comma_leader();
    $output .= " " x ($self->{'section_depth'}-2);

    if ($self->is_in_array()) {
	$output .= $startchar . "\n";
    } else {
	$output .= sprintf("\"%s\": %s\n", $tag, $startchar);
    }

    push @{$self->{'section_firsts'}}, 1;
    push @{$self->{'in_array'}}, ($startchar eq '[') ? 1 : 0;

    if ($name) {
	$output .= " " x ($self->{'section_depth'}) . 
	    sprintf("\"name\": \"%s\",\n", $name);
    }

    return $output;
}

sub EndBlock {
    my ($self, $tag, $name, $closechar) = @_;
    $self->{'section_depth'} -= 2;
    $self->{'section_depth'} = 0 if ($self->{'section_depth'} < 0);
    pop @{$self->{'section_firsts'}};
    pop @{$self->{'in_array'}};

    return "\n" . " " x ($self->{'section_depth'}) . $closechar;
}

sub StartSection {
    my ($self, $tag, $name) = @_;

    return $self->StartBlock($tag, $name, "{");
}

sub EndSection {
    my ($self, $tag, $name) = @_;

    return $self->EndBlock($tag, $name, "}");
}

sub StartArray {
    my ($self, $tag, $name) = @_;

    return $self->StartBlock($tag, $name, "[");
}

sub EndArray {
    my ($self, $tag, $name) = @_;

    return $self->EndBlock($tag, $name, "]");
}

sub ArrayObject {
}

sub Comment {
    my ($self, $comment) = @_;
    return " " x ($self->{'section_depth'}) . "// " . escapeHTML($comment) . "\n";
}

sub StartOutput {
    my ($self) = @_;
    return "{\n";
}

sub EndOutput {
    my ($self) = @_;
    return "}\n";
}

sub Separator {
    return;
}

1;
