package Net::DNS::SEC::Tools::TrustAnchor::Libval;

use strict;
use Net::DNS::SEC::Tools::TrustAnchor;

our @ISA = qw(Net::DNS::SEC::Tools::TrustAnchor);
our $VERSION = '0.1';

use XML::Simple;

sub read {
    my ($self, $location, $options) = @_;

    $location ||= $self->{'file'};
    $options ||= $self->{'options'};

    my $doc = { delegation => {}};

    my $intrustanchor = 0;
    open(I, "<", $location);
    while (<I>) {
	if (/^\s*# EIVER/) {
	    my $localinfo =
	      $self->parse_extra_info_string($_, $doc, "#");
	}

	next if (/^#/);

	if (/^(\S+)\s+trust-anchor/) {
	    $intrustanchor = 1;
	} elsif ($intrustanchor && /^\s*(\S+)\s+(DNSKEY|)\s*"([^"]+)"/) {
	    my $name = $1;
	    my $data = $3;
	    my ($flags, $alg, $digesttype, $content) =
	      ($data =~ /^(\d+)\s+(\d+)\s+(\d+)\s+(.*)/);
	    $content =~ s/ //g;
	    push @{$doc->{'delegation'}{$name}{'dnskey'}},
	      {
	       flags => $flags,
	       algorithm => $alg,
	       digesttype => $digesttype,
	       content => $content,
	      };
	    $intrustanchor = 0 if (/;/);
	} elsif ($intrustanchor && /^\s*(\S+)\s+DS\s+"([^"]+)"/) {
	    my $name = $1;
	    my $data = $2;
	    my ($keytag, $alg, $digesttype, $content) =
	      ($data =~ /^(\d+)\s+(\d+)\s+(\d+)\s+(.*)/);
	    $content =~ s/ //g;
	    push @{$doc->{'delegation'}{$name}{'ds'}},
	      {
	       keytag => $keytag,
	       algorithm => $alg,
	       digesttype => $digesttype,
	       content => $content,
	      };
	    $intrustanchor = 0 if (/;/);
	} elsif (/;/) {
	    $intrustanchor = 0;
	}
    }

    return $doc;
}

sub write {
    my ($self, $data, $location, $options) = @_;
    open(O, ">", $location);
    print O "# saved by Net::DNS::SEC::Tools::TrustAnchor::Libval\n";
    print O $self->create_extra_info_string($data, {}, "#"),"\n";
    print O ($options->{'contextname'} || ":") . " trust-anchor\n";
    foreach my $key (keys(%{$data->{'delegation'}})) {
	if (exists($data->{'delegation'}{$key}{'ds'})) {
	    foreach my $record (@{$data->{'delegation'}{$key}{'ds'}}) {
		printf O "\t%15s DS \"$record->{keytag} $record->{algorithm} $record->{digesttype} $record->{content}\"\n", $key;
	    }
	}
	if (exists($data->{'delegation'}{$key}{'dnskey'})) {
	    foreach my $record (@{$data->{'delegation'}{$key}{'dnskey'}}) {
		printf O "\t%15s \"$record->{flags} $record->{algorithm} $record->{digesttype} $record->{content}\"\n", $key;
	    }
	}
    }
    close(O);
    return 0;
}

=pod
