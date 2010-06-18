package Net::DNS::SEC::Tools::TrustAnchor::Libval;

use strict;
use Net::DNS::SEC::Tools::TrustAnchor;

our @ISA = qw(Net::DNS::SEC::Tools::TrustAnchor);
our $VERSION = '0.1';

use XML::Simple;

sub init_extras {
    my $self = shift;
    # XXX: allow for other contexts besides :
    $self->{'header'} = ": trust-anchor\n";
    $self->{'trailer'} = ";\n";
}

sub read_content {
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

	next if (/^\s*#/);

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

sub write_ds {
    my ($self, $fh, $name, $record) = @_;
    my $status;
    $fh->printf("\t%15s DS \"$record->{keytag} $record->{algorithm} $record->{digesttype} $record->{content}\"\n", $name);
}

sub write_dnskey {
    my ($self, $fh, $name, $record) = @_;
    my $status;
    $fh->printf("\t%15s \"$record->{flags} $record->{algorithm} $record->{digesttype} $record->{content}\"\n", $name);
}

sub write_trailer {
    my ($self, $fh, $options, $data) = @_;
    if ($self->{'options'}{'write_expectations'}) {
	$fh->printf(";\n\n");
	$fh->printf(": zone-security-expectation\n");
	$fh->printf("    %-50.50s ignore\n", ".");
	foreach my $zone (keys(%{$data->{'delegation'}})) {
	    $fh->printf("    %-50.50s validate\n", $zone);
	}
	$fh->printf(";\n");
    }
}

=pod

=cut

