package Net::DNS::SEC::Tools::TrustAnchor;

use Exporter;
use IO::File;

our @ISA = qw(Exporter);
our @EXPORT = qw(load_module parse_component);

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

# sub function for child classes to override at init time
sub init_extras {
}

sub load_module {
    my ($type) = @_;

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
    return $obj;
}

sub parse_component {
    my ($file) = @_;

    # no extra options
    if ($file !~ /:/) {
	# XXX: try file extension
	print STDERR "Could not determine TAR type for: $file\n";
	return;
    }

    # type:file
    if ($file =~ /^([^:]+):([^:]+)$/) {
	my ($type, $file) = ($1, $2);
	print "mod: $type, file: $file\n";
	my $object = load_module($type);
	$object->set_file($file);
	$object->set_options({});
	return ($object, $file, {});
    }

    print STDERR "foo: $file\n";
}

sub set_file {
    my ($self, $file) = @_;
    $self->{'file'} = $file;
}

sub set_options {
    my ($self, $opts) = @_;
    $self->{'options'} = $opts;
}

sub read {
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

# blank prototypes
sub write_header {
    my ($self, $fh) = @_;
    $fh->print($self->{'header'}) if (exists($self->{'header'}));
}

sub write_trailer {
    my ($self, $fh) = @_;
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

    $self->write_header($fh, $options);

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
    $self->write_trailer($fh, $options);
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

=pod

=head1 NAME

Net::DNS::SEC::Tools::TrustAnchor

=head1 SYNOPSIS

This is a base class for multiple types of trustanchor repositories
that know how to read, write and modify trust anchor repositories.

=head1 AUTHOR

Wes Hardaker <hardaker ATTA users.sourceforge DOTTTY net>

