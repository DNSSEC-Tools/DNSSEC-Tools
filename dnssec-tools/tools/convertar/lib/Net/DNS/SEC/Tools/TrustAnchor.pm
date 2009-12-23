package Net::DNS::SEC::Tools::TrustAnchor;

=pod

=head1 NAME

Net::DNS::SEC::Tools::TrustAnchor

=head1 SYNOPSIS

This is a base class for multiple types of trustanchor repositories
that know how to read, write, and modify trust anchor repositories.

This package serves as both a API wrapper around a set of trust
anchors as well as a base class for packages that need to read/write
trust anchor sets into different formats.

Trust Anchors may be either DNSKEY records or DS references.

XXX: more documentation needed

=head1 API

Usage API defined by this module or sub-modules.

Note that:

  use Net::DNS::SEC::Tools::TrustAnchor;

is assumed to have imported some of the API routines mentioned below.

=over 4

=cut

use Exporter;
use IO::File;
use strict;

our @ISA = qw(Exporter);
our @EXPORT = qw(load_module parse_component);

=pod

=item $tar = new Net::DNS::SEC::Tools::TrustAnchor();

Initializes a new collection of trust anchors.

=cut

# note: this new clause is used by most sub-modules too, altering it
# will alter them.
sub new {
    my $type = shift;
    my ($class) = ref($type) || $type;
    my $self = {};
    %$self = @_;
    bless($self, $class);
    $self->init_extras();
    return $self;
}

sub parse_options {
    my ($self, $options) = @_;
    return if (!defined($options));

    # format: opt1=value/opt2=value
    my @options = split(/\/\s*/, $options);
    foreach my $option (@options) {
	my ($left, $right) = ($option =~ /([^=]+)=*(.*)/);
	$self->set_option($left, $right);
    }
    return $self;
}

sub set_option {
    my ($self, $option, $value) = @_;
    $self->{'options'}{$option} = $value;
}

# sub function for child classes to override at init time
sub init_extras {
}

=pod

=item $module = load_module("type");

Dynamically attemps to load a TrustAnchor reader/writer sub-class of
Net::DNS::SEC::Tools::TrustAnchor named "Type" and return an instance of it.

All sub-classes are assumed to contain a single letter upper-case
class name followed by all lower case.  Any modules otherwise named
will fail to load using this routine.

=cut

sub load_module {
    my ($intype) = @_;

    # parse trailing options off
    # type/option1=value,option2=value2
    my ($type, $options) = ($intype =~ /([^\/]+)\/*(.*)/);

    # XXX: decide what to do about upper/lower casing
    $type =~ s/(.)(.*)/uc($1) . lc($2)/e;
    if (! eval "require Net::DNS::SEC::Tools::TrustAnchor::$type") {
	print STDERR "Failed to load TrustAnchor type: $type\n";
	print STDERR "  $@\n";
	return;
    }
    my $obj = eval "new Net::DNS::SEC::Tools::TrustAnchor::$type()";
    if (!$obj) {
	print "failed to create a new $type object:\n  $@\n";
    }
    $obj->parse_options($options);
    return $obj;
}

=pod

=item $module = parse_component("type:file");

This parses a type and file specification consisting of type separated
by a colon (':') followed by a file-name path.  It will then load the
type module using the I<load_module()> rotine and return the type, the
file and extra options.

XXX: option parsing support not yet complete and will likely change
the type:file format specification; I.E. the type:file formatting
specification will likely change in the future and should be
considered alpha-level support.

=cut

sub parse_component {
    my ($file) = @_;

    # no extra options
    if ($file !~ /:/) {
	if ($file =~ /\.([^\.]+)$/) {
	    # if this fails, it'll have to handle it
	    return parse_component($1 . ":" . $file);
	}
    }

    # type:file
    if ($file =~ /^([^:]+):([^:]*)$/) {
	my ($type, $file) = ($1, $2);
	my $object = load_module($type);
	$object->set_file($file);
	return ($object, $file, {});
    }
}

sub set_file {
    my ($self, $file) = @_;
    $self->{'file'} = $file;
}

=pod

=item $tar = $module->read($location, $options);

Reads in a given TAR from a $location reference and returns a blessed
copy of the Net::DNS::SEC::Tools::TrustAnchor object containing all
the data.

This function may be over-ridden by a sub-class.

=cut

sub read {
    my ($self, $location, $options) = @_;
    my $hashedcontent = $self->read_content($location, $options);
    return if (!$hashedcontent);
    bless $hashedcontent, 'Net::DNS::SEC::Tools::TrustAnchor';
    return $hashedcontent;
}

=pod

=item $tar = $module->read($location, $options);

Reads in a given TAR from a $location reference and returns an
unblessed hash the contents.  The read() function merely wraps around
this and blesses it after being returned.

Sub-modules must over-ride this function (and/or the read() function)
if they expect the module to support loading.

=cut

sub read_content {
    my ($self, $location, $options) = @_;
    print STDERR "The TrustAnchor module " . ref($self) . " does not support reading\n";
    return 1;
}

sub get_extra_info {
    return {};
}

sub write_extra_info {
    my ($self, $fh, $data) = @_;
    #
    # save extra parameters as a comment at the top
    #
    print $fh
      $self->create_extra_info_string($data, $self->get_extra_info(),
				      $self->{'commentprefix'} || "#"),"\n";
}

=pod

=item $tar->merge(@others)

Merges the I<@other> array of trust anchors into the $tar object's own
trust anchor list.

=cut
sub merge {
    my ($self, @others) = @_;
    foreach my $other (@others) {
	# for each delegation in the other record
	foreach my $delegation (keys(%{$other->{'delegation'}})) {
	    # each delegation contains one or more trust anchor types
	    foreach my $type (keys(%{$other->{'delegation'}{$delegation}})) {
		# each type may have multiple content entries
		foreach my $entry
		  (@{$other->{'delegation'}{$delegation}{$type}}) {
		      # XXX: check for duplicates
		      # (ie, the current TAR may already contain an exact match)
		      push @{$self->{'delegation'}{$delegation}{$type}},
			$entry;
		  }
	    }
	}
    }
    return $self;
}


######################################################################
# blank prototypes
sub write_header {
    my ($self, $fh, $options, $data) = @_;
    $fh->print($self->{'header'}) if (exists($self->{'header'}));
}

sub write_trailer {
    my ($self, $fh, $options, $data) = @_;
    $fh->print($self->{'trailer'}) if (exists($self->{'trailer'}));
}

sub write {
    my ($self, $data, $location, $options) = @_;

    my $status;

    if (!$self->can('write_ds') || !$self->can('write_dnskey')) {
	print STDERR "The TrustAnchor module " . ref($self) . " does not support writing\n";
	return 1;
    }

    my $fh = new IO::File;
    $fh->open(">$location");
    if (!defined($fh)) {
	print STDERR "failed to open $location for writing\n";
	return 1;
    }

    #
    # save extra parameters as a comment at the top
    #
    $self->write_extra_info($fh, $data);

    $self->write_header($fh, $options, $data);

    #
    # save the data itself
    #
    foreach my $key (keys(%{$data->{'delegation'}})) {
	if (exists($data->{'delegation'}{$key}{'ds'})) {
	    foreach my $record (@{$data->{'delegation'}{$key}{'ds'}}) {
		$self->write_ds($fh, $key, $record);
	    }
	}
	if (exists($data->{'delegation'}{$key}{'dnskey'})) {
	    foreach my $record (@{$data->{'delegation'}{$key}{'dnskey'}}) {
		$self->write_dnskey($fh, $key, $record);
	    }
	}
    }
    $self->write_trailer($fh, $options, $data);
    $fh->close();
    return 0;
}

sub modify {
    my ($self, $location, $options) = @_;
    print STDERR "The TrustAnchor module " . ref($self) . " does not support inline-modification\n";
    return 1;
}

#
# these two routines save and read a commonly formated comment-style tag
# for including extra info that doesn't fit into normal syntax structures, like
# data version numbers etc.
#
my $EIVER=1;
sub create_extra_info_string {
    my ($self, $data, $moduleinfo, $prefix) = @_;
    #
    # save extra parameters as a comment at the top
    #
    $prefix ||= "";
    my $topstring = $prefix . " " . "EIVER=$EIVER";

    # datainfo
    foreach my $keyword (qw(serial name)) {
	$topstring .= " $keyword=$data->{$keyword}";
    }

    # mid-string break between datatypes
    $topstring .= " /";

    # module specific info
    if ($moduleinfo) {
	foreach my $keyword (keys(%$moduleinfo)) {
	    $topstring .= " $keyword=$moduleinfo->{$keyword}";
	}
    }

    return $topstring;
}

sub parse_extra_info_string {
    my ($self, $line, $data, $prefix) = @_;
    my $localinfo = {};

    if ($line !~ s/$prefix EIVER=1//) {
	die("unknown extra info version in data; can't recover\n");
    }

    while ($line =~ s/^\s*([^=]+)=(\S+)\s*//) {
	$data->{$1} = $2;
	last if ($line =~ s/^\s*\/\s*//);
    }

    while ($line =~ s/^\s*([^=]+)=(\S+)\s*//) {
	$localinfo->{$1} = $2;
    }
    return $localinfo;
}

#
# A remote URL fetching utility wrapper
#
sub fetch_url {
    my ($self, $url) = @_;

    # ensure we have the LWP::UserAgent module
    my $have_lwp = eval "require LWP::UserAgent;";
    if (! $have_lwp) {
	print STDERR "failed to load the LWP::UserAgent module.\n";
	print STDERR "The LWP::UserAgent is required for pulling trust anchors over-the-network.\n";
	return;
    }

    my $ua = LWP::UserAgent->new;
    my $response = $ua->get($url);
    if (! $response->is_success) {
	print STDERR "Failed to fetch $url\n";
	print STDERR $response->status_line;
	return;
    }

    return $response->decoded_content;
}

=back

=head1 AUTHOR

Wes Hardaker <hardaker ATTA users.sourceforge DOTTTY net>

=head1 SEE ALSO

convertar(1)

=cut

