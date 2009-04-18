package Net::DNS::SEC::Tools::TrustAnchor;

use Exporter;

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
    $self->init_global($self->{'dbh'}) if ($self->{'dbh'});
    return $self;
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

sub write {
    my ($self, $location, $options) = @_;
    print STDERR "The TrustAnchor module " . ref($self) . " does not support writing\n";
    return 1;
}

sub modify {
    my ($self, $location, $options) = @_;
    print STDERR "The TrustAnchor module " . ref($self) . " does not support inline-modification\n";
    return 1;
}

=pod

=head1 NAME

Net::DNS::SEC::Tools::TrustAnchor

=head1 SYNOPSIS

This is a base class for multiple types of trustanchor repositories
that know how to read, write and modify trust anchor repositories.

=head1 AUTHOR

Wes Hardaker <hardaker ATTA users.sourceforge DOTTTY net>

