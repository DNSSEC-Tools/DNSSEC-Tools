#
# Copyright 2013-2013 Parsons.  All rights reserved.
# See the COPYING file included with the DNSSEC-Tools package for details.
#

package Net::DNS::SEC::Tools::Donuts::Output;

use IO::Handle;
use IO::File;

use strict;

use Net::DNS::SEC::Tools::Donuts::Output::Format::Text;
use Net::DNS::SEC::Tools::Donuts::Output::Format::XML;
use Net::DNS::SEC::Tools::Donuts::Output::Format::JSON;

my $have_textwrap = eval { require Net::DNS::SEC::Tools::Donuts::Output::Format::Text::Wrapped; };

sub new {
    my $type = shift;
    my ($class) = ref($type) || $type;
    my $self = {};
    %$self = @_;
    $self->{'section_depth'} ||= 0;
    bless($self, $class);

    $self->set_format() if (!$self->{'formatter'});
    $self->set_location() if (!$self->{'location'});
    return $self;
}

sub set_format {
    my ($self, $format) = @_;

    if (ref($format) ne '') {
	# a class was directly passed
	$self->{'formatter'} = $format;
	return;
    }

    $format = defined($format) ? lc($format) : "wrapped";
    $format = "text" if ($format eq 'wrapped' && !$have_textwrap);

    $self->{'output_format'} = $format;

    if ($format eq 'wrapped') {
	Net::DNS::SEC::Tools::Donuts::Output::Format::Text::Wrapped->import();
	$self->{'formatter'} = new Net::DNS::SEC::Tools::Donuts::Output::Format::Text::Wrapped();
    } elsif ($format eq 'text') {
	$self->{'formatter'} = new Net::DNS::SEC::Tools::Donuts::Output::Format::Text();
    } elsif ($format eq 'xml') {
	$self->{'formatter'} = new Net::DNS::SEC::Tools::Donuts::Output::Format::XML();
    } elsif ($format eq 'json') {
	$self->{'formatter'} = new Net::DNS::SEC::Tools::Donuts::Output::Format::JSON();
    } else {
	die "unknown output-format directive: '$format'";
    }
}

sub format {
    my ($self) = @_;
    return $self->{'output_format'};
}

sub formatter {
    my ($self) = @_;
    $self->set_output_format() if (!defined($self->{'output_format'}));
    return $self->{'formatter'};
}

sub set_location {
    my ($self, $location) = @_;

    if (ref($location) ne '') {
	# a class was directly passed
	$self->{'location'} = $location;
	return;
    }

    $location = defined($location) ? $location : "stdout";

    if ($location eq 'stdout') {
	$self->{'location'} = new IO::Handle;
	$self->{'location'}->fdopen(fileno(STDOUT),"w");
    } elsif ($location eq 'stderr') {
	$self->{'location'} = new IO::Handle;
	$self->{'location'}->fdopen(fileno(STDERR),"w");
    } elsif ($location =~ /^file:(.*)/) {
	my $path = $1;
	$self->{'location'} = new IO::File;
	$self->{'location'}->open("> $path");
    } else {
	die "unknown location directive: '$location'";
    }
    
}

# why yes, these could be done with an autoload...

sub Output {
    my ($self, $tag, $message) = @_;

    $self->{'location'}->print(
	$self->{'formatter'}->Output($tag, $message));
}

sub Separator {
    my ($self, $tag, $message) = @_;

    $self->{'location'}->print(
	$self->{'formatter'}->Separator($tag, $message));
}

sub StartSection {
    my ($self, $tag, $message) = @_;

    $self->{'location'}->print(
	$self->{'formatter'}->StartSection($tag, $message));
}

sub EndSection {
    my ($self, $tag, $message) = @_;

    $self->{'location'}->print(
	$self->{'formatter'}->EndSection($tag, $message));
}

sub StartArray {
    my ($self, $tag, $message) = @_;

    $self->{'location'}->print(
	$self->{'formatter'}->StartArray($tag, $message));
}

sub EndArray {
    my ($self, $tag, $message) = @_;

    $self->{'location'}->print(
	$self->{'formatter'}->EndArray($tag, $message));
}

sub ArrayObject {
    my ($self, $tag, $message) = @_;

    $self->{'location'}->print(
	$self->{'formatter'}->ArrayObject($tag, $message));
}

sub Error {
    my ($self, $tag, $message) = @_;

    $self->{'location'}->print(
	$self->{'formatter'}->Erorr($tag, $message));
}

sub Warning {
    my ($self, $tag, $message) = @_;

    $self->{'location'}->print(
	$self->{'formatter'}->Warning($tag, $message));
}

sub Comment {
    my ($self, $tag, $message) = @_;

    $self->{'location'}->print(
	$self->{'formatter'}->Comment($tag, $message));
}

sub StartOutput {
    my ($self, $tag, $message) = @_;

    if (!exists($self->{'OutputStarted'}) ||
	$self->{'OutputStarted'} == 0) {
	$self->{'location'}->print(
	    $self->{'formatter'}->StartOutput($tag, $message));
    }
    $self->{'OutputStarted'}++;
}

sub EndOutput {
    my ($self, $tag, $message) = @_;

    $self->{'OutputStarted'}--;

    if ($self->{'OutputStarted'} == 0) {
	$self->{'location'}->print(
	    $self->{'formatter'}->EndOutput($tag, $message));
    }
}


1;
