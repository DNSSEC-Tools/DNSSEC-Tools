package Net::DNS::SEC::Tools::TrustAnchor::Itar;

use Net::DNS::SEC::Tools::TrustAnchor;

our @ISA = qw(Net::DNS::SEC::Tools::TrustAnchor);
our $VERSION = '0.1';

use XML::Simple;

sub read {
    my ($self, $location, $options) = @_;

    $location ||= $self->{'file'};
    $options ||= $self->{'options'};

    my $doc;

    if ($location =~ /^(http|ftp)/) {
	# pull from net
    } else {
	# read from file
	$doc = XMLin($location, ForceArray => 'ds');
    }

    # perform mapping from keys

    return $doc;
}

sub write {
    my ($self, $data, $location, $options) = @_;
    open(O, ">", $location);
    XMLout($data, OutputFile => $location, RootName => 'zone');
    close(O);
    return 0;
}

=pod
