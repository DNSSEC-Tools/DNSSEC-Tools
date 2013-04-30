#
# Copyright 2013-2013 Parsons.  All rights reserved.
# See the COPYING file included with the DNSSEC-Tools package for details.
#

package Net::DNS::SEC::Tools::Donuts::Output::Format::Perl;

use strict;
use Net::DNS::SEC::Tools::Donuts::Output::Format;
use CGI qw(escapeHTML);

our @ISA = qw(Net::DNS::SEC::Tools::Donuts::Output::Format);

sub add_to_current {
    my ($self, $tag, $message) = @_;
    if (ref($self->{'currentvar'}) eq 'ARRAY') {
	push @{$self->{'currentvar'}}, $message;
    } elsif (ref($self->{'currentvar'}) eq 'HASH') {
	$self->{'currentvar'}{$tag} = $message;
    } else {
	die;
    }
    return;
}

sub push_down_stack {
    my ($self, $newvar) = @_;
    push @{$self->{'objectstack'}}, $newvar;
    $self->{'currentvar'} = $newvar;
    return;
}

sub pop_up_stack {
    my ($self) = @_;
    pop @{$self->{'objectstack'}};
    $self->{'currentvar'} = ${$self->{'objectstack'}}[$#{$self->{'objectstack'}}];
    return;
}

sub Output {
    my ($self, $tag, $message) = @_;

    $self->add_to_current($tag, $message);
}

sub StartSection {
    my ($self, $tag, $name) = @_;

    my $newblock = {};
    $self->add_to_current($tag, $newblock);
    $self->push_down_stack($newblock);
    $self->add_to_current("name", $name);
}

sub EndSection {
    my ($self, $tag, $name) = @_;

    $self->pop_up_stack();
}

sub StartArray {
    my ($self, $tag, $name) = @_;

    my $newblock = [];
    $self->add_to_current($tag, $newblock);
    $self->push_down_stack($newblock);
}

sub EndArray {
    my ($self, $tag, $name) = @_;

    $self->pop_up_stack();
}

sub Comment {
    return;
}

sub storage_ref {
    my ($self) = @_;
    $self->{'outputvar'} = {} if (!exists($self->{'outputvar'}));
    return $self->{'outputvar'};
}

sub StartOutput {
    my ($self) = @_;
    $self->{'currentvar'} = $self->storage_ref();
    $self->{'objectstack'} = [$self->{'currentvar'}];
    return;
}

sub EndOutput {
    my ($self) = @_;
    return;
}

sub Separator {
    return;
}

1;
