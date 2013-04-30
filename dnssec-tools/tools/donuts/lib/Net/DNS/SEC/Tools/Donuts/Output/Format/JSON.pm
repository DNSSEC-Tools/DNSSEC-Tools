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

sub get_comma_leader {
    my ($self) = @_;
    my $output = "";
    $output = ",\n" if (!$self->is_section_first());
    return $output;
}

sub StartSection {
    my ($self, $tag, $name) = @_;

    $tag = simplify_tag($tag);
    $name = escapeHTML($name) if ($name);

    $self->{'section_depth'} += 2;

    my $output = $self->get_comma_leader();
    $output .= " " x ($self->{'section_depth'}-2) . 
	sprintf("\"%s\": {\n", $tag);


    push @{$self->{'section_firsts'}}, 1;

    if ($name) {
	$output .= " " x ($self->{'section_depth'}) . 
	    sprintf("\"name\": \"%s\",\n", $name);
    }
    return $output;
}

sub EndSection {
    my ($self) = @_;
    $self->{'section_depth'} -= 2;
    $self->{'section_depth'} = 0 if ($self->{'section_depth'} < 0);
    pop @{$self->{'section_firsts'}};

    return "\n" . " " x ($self->{'section_depth'}) . "}";
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
