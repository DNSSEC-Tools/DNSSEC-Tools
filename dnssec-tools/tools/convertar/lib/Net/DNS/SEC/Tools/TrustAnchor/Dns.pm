package Net::DNS::SEC::Tools::TrustAnchor::Dns;

use strict;
use Net::DNS::SEC::Tools::TrustAnchor;
use Net::DNS;
use Net::DNS::RR::DS;

our @ISA = qw(Net::DNS::SEC::Tools::TrustAnchor);
our $VERSION = '0.1';

use XML::Simple;

sub read_content {
    my ($self, $location, $options) = @_;

    $location ||= $self->{'file'};
    $options ||= $self->{'options'};

    # extract the lookup type and zone name
    my ($type, $zone) = ($location =~ /^(ds\/|dnskey\/|)(.*)/);
    $type ||= 'dnskey'; # default to a DNSKEY type
    $type =~ s/\///;

    my $doc = { delegation => {}};

    my $resolver = Net::DNS::Resolver->new;
    my $results = $resolver->query($zone, $type);

    if (!$results) {
	print STDERR "failed to read from $location (type=$type, zone=$zone): ",
	  $resolver->errorstring, "\n";
	return;
    }

    foreach my $rr ($results->answer) {
#	$rr->print;
	if ($type eq 'ds') {
	    push @{$doc->{'delegation'}{$zone}{$type}},
	      {
	       keytag => $rr->keytag,
	       algorithm => $rr->algorithm,
	       digesttype => $rr->digtype,
	       content => $rr->digest,
	      };
	} else {
	    next if (!($rr->flags & 1)); # XXX: ignore non KSK should be option

	    if ($self->{'options'}{'tods'}) {
		my $ds = create Net::DNS::RR::DS($rr, digtype => 'SHA256');
		push @{$doc->{'delegation'}{$zone}{'ds'}},
		  {
		   keytag => $ds->keytag,
		   algorithm => $ds->algorithm,
		   digesttype => $ds->digtype,
		   content => $ds->digest,
		  };
	    } else {
		push @{$doc->{'delegation'}{$zone}{$type}},
		  {
		   flags => $rr->flags,
		   algorithm => $rr->algorithm,
		   content => $rr->key,
		   digesttype => $rr->protocol,
		  };
	    }
	}
    }

    return $doc;
}

=pod

=cut

