#
# Copyright 2013-2013 Parsons.  All rights reserved.
# See the COPYING file included with the DNSSEC-Tools package for details.
#

package Net::DNS::SEC::Tools::Donuts::Output::Format;

use strict;

sub new {
    my $type = shift;
    my ($class) = ref($type) || $type;
    my $self = {};
    %$self = @_;
    $self->{'section_depth'} ||= 0;
    bless($self, $class);
}

sub Error {
    my ($self, $message, $tag) = @_;
    return $message;
}

sub Warning {
    my ($self, $message, $tag) = @_;
    return $message;
}

sub StartOutput {
}

sub EndOutput {
}

sub StartArray {
    my $self = shift @_;
    $self->StartSection(@_);
}

sub EndArray {
    my $self = shift @_;
    $self->EndSection(@_);
}

sub ArrayObject {
    my $self = shift @_;
    $self->Output(@_);
}

sub config {
    my ($self, $what, $default) = @_;
    return $default if (!exists($self->{'config'}{$what}));
    return $self->{'config'}{$what};
}

sub set_config {
    my ($self, $what, $value) = @_;
    return $self->{'config'}{$what};
}

1;
