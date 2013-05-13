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
use Net::DNS::SEC::Tools::Donuts::Output::Format::Perl;
use Net::DNS::SEC::Tools::Donuts::Output::Format::HTML;

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
    my ($self, $outputformat) = @_;

    if (ref($outputformat) ne '') {
	# a class was directly passed
	$self->{'formatter'} = $outputformat;
	return;
    }

    $outputformat ||= "wrapped";

    my ($format, $arguments) = ($outputformat =~ /^(\w+)(:.*|)$/);
    die "unknown output format: $outputformat" if (!$format);
    $arguments =~ s/^:// if ($arguments);

    $format = lc($format);
    $format = "text" if ($format eq 'wrapped' && !$have_textwrap);

    $self->{'output_format'} = $format;
    $self->{'output_format_arguments'} = $arguments;

    my %config;
    foreach my $config_item (split(/,\s*/,$arguments)) {
	my ($left, $right) = ($config_item =~ /(.*)=(.*)/);
	if (!defined($right)) {
	    $config{$config_item} = 1;
	} else {
	    $config{$left} = $right;
	}
    }

    if ($format eq 'wrapped') {
	Net::DNS::SEC::Tools::Donuts::Output::Format::Text::Wrapped->import();
	$self->{'formatter'} = new Net::DNS::SEC::Tools::Donuts::Output::Format::Text::Wrapped();
    } elsif ($format eq 'text') {
	$self->{'formatter'} = new Net::DNS::SEC::Tools::Donuts::Output::Format::Text();
    } elsif ($format eq 'html') {
	$self->{'formatter'} = new Net::DNS::SEC::Tools::Donuts::Output::Format::HTML();
    } elsif ($format eq 'xml') {
	$self->{'formatter'} = new Net::DNS::SEC::Tools::Donuts::Output::Format::XML();
    } elsif ($format eq 'json') {
	$self->{'formatter'} = new Net::DNS::SEC::Tools::Donuts::Output::Format::JSON();
    } elsif ($format eq 'perl') {
	$self->{'formatter'} = new Net::DNS::SEC::Tools::Donuts::Output::Format::Perl();
	if (exists($self->{'perllocation'})) {
	    # bind them together
	    ${$self->{'perllocation'}} = $self->{'formatter'}->storage_ref();
	    delete $self->{'perllocation'};
	}
    } else {
	# try and see if we can load something dynamically
	$format =~ s/(.)(.*)/uc($1) . lc($2)/e;
	my $success = eval "require Net::DNS::SEC::Tools::Donuts::Output::Format::$format;";
	if (!$success) {
	    die "unknown output-format directive: '$format'";
	}
	
	# now create an instance
	$self->{'formatter'} = eval "new Net::DNS::SEC::Tools::Donuts::Output::Format::${format} ()";
	if (ref($self->{'formatter'}) ne "Net::DNS::SEC::Tools::Donuts::Output::Format::${format}") {
	    die "failed to create a $format object: $@";
	}
    }

    $self->{'formatter'}{'config'} = \%config;
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
    my ($self, $location, $output) = @_;

    if (ref($location) ne '') {
	# a class was directly passed
	$self->{'location'} = $location;
	return;
    }

    $location = defined($location) ? $location : "stdout";

    if ($location eq 'stdout') {
	$self->{'location'} = new IO::Handle;
	$self->{'location'}->fdopen(fileno(STDOUT),"w");
	$output = $self->{'location'};
    } elsif ($location eq 'stderr') {
	$self->{'location'} = new IO::Handle;
	$self->{'location'}->fdopen(fileno(STDERR),"w");
	$output = $self->{'location'};
    } elsif ($location =~ /^file:(.*)/) {
	my $path = $1;
	$self->{'location'} = new IO::File;
	$self->{'location'}->open("> $path");
	$output = $self->{'location'};
    } elsif ($location eq 'string') {
	if (! eval 'require IO::String;') {
	    die "IO::String is required for exporting to a string";
	}
	import IO::String;

	$self->{'location'} = IO::String->new();
	$$output = $self->{'location'}->string_ref();
    } elsif ($location eq 'perl') {
	if (ref($self->{'formatter'}) eq 'Net::DNS::SEC::Tools::Donuts::Output::Format::Perl') {
	    # they've already set the correct formatter
	    # extract it's already set storage ref
	    $$output = $self->{'formatter'}->storage_ref();;
	} else {
	    # they haven't yet; store it for a later binding
	    $self->{'perllocation'} = $output;
	}
    } else {
	die "unknown location directive: '$location'";
    }
    
}

# config

sub allow_comments {
    my ($self, $yesno) = @_;
    $self->{'allow_comments'} = $yesno;
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
	$self->{'formatter'}->Error($tag, $message));
}

sub Warning {
    my ($self, $tag, $message) = @_;

    $self->{'location'}->print(
	$self->{'formatter'}->Warning($tag, $message));
}

sub Comment {
    my ($self, $tag, $message) = @_;

    return if (exists($self->{'allow_comments'}) &&
	       ! $self->{'allow_comments'});
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
