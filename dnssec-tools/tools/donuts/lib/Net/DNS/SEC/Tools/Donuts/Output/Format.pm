#
# Copyright 2013-2013 Parsons.  All rights reserved.
# See the COPYING file included with the DNSSEC-Tools package for details.
#

package Net::DNS::SEC::Tools::Donuts::Output::Format;

use strict;

my $have_textwrap = eval { require Text::Wrap };

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
    print STDERR $message;
}

sub Warning {
    my ($self, $message, $tag) = @_;
    print STDERR $message;
}

1;
