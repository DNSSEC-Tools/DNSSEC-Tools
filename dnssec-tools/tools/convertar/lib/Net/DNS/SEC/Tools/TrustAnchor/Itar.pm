package Net::DNS::SEC::Tools::TrustAnchor::Itar;

use strict;
use Net::DNS::SEC::Tools::TrustAnchor;

our @ISA = qw(Net::DNS::SEC::Tools::TrustAnchor);
our $VERSION = '0.1';

use XML::Simple;

sub read_content {
    my ($self, $location, $options) = @_;

    $location ||= $self->{'file'};
    $options ||= $self->{'options'};

    if ($location eq '') {
	$location = 'https://itar.iana.org/anchors/anchors.xml';
    }

    my $doc;

    if ($location =~ /^(http|ftp)/) {
	# pull from net
	my $have_lwp = eval "require LWP::UserAgent;";
	if (! $have_lwp) {
	    print STDERR "failed to load the LWP::UserAgent module.\n";
	    print STDERR "The LWP::UserAgent is required for pulling trust anchors over-the-network.\n";
	    return;
	}

	my $ua = LWP::UserAgent->new;
	my $response = $ua->get($location);
	if (! $response->is_success) {
	    print STDERR "Failed to fetch $location\n";
	    print STDERR $response->status_line;
	    return;
	}

	$doc = XMLin($response->decoded_content, ForceArray => 'ds');
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

=cut

