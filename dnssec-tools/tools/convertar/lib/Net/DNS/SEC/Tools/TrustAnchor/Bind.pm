package Net::DNS::SEC::Tools::TrustAnchor::Bind;

use strict;
use Net::DNS::SEC::Tools::TrustAnchor;

our @ISA = qw(Net::DNS::SEC::Tools::TrustAnchor);
our $VERSION = '0.1';
use IO::File;

use XML::Simple;

sub init_extras {
    my $self = shift;
    $self->{'header'} = "trusted-keys {\n";
    $self->{'trailer'} = "}\n";
}


sub read_content {
    my ($self, $location, $options) = @_;

    $location ||= $self->{'file'};
    $options ||= $self->{'options'};

    my $doc = { delegation => {}};

    my $intrustanchor = 0;
    my $fileh = $location;
    if (!ref($fileh)) {
	# it's a string location to a file, so open it
	$fileh = new IO::File;
	$fileh->open($location);
	if (!$fileh) {
	    print STDERR "failed to open $location\n";
	    return;
	}
    }

    while (<$fileh>) {
	if (/^\s*# EIVER/) {
	    my $localinfo =
	      $self->parse_extra_info_string($_, $doc, "#");
	}

	# skip comments
	next if (/^\s*[#;]/);
	next if (/^\s*\/\//);

	if (/trusted-keys\s*{*/) {
	    $intrustanchor = 1;
	} elsif ($intrustanchor &&
		 /^\s*(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+\"([^"]*)\"\s*;/) {
	    next if (/{/); # allow for "trust-anchor\n {"
	    my ($name, $flags, $alg, $digesttype, $content) =
	      ($1, $2, $3, $4, $5);
	    $content =~ s/ //g;
	    $name =~ s/\"//g;
	    push @{$doc->{'delegation'}{$name}{'dnskey'}},
	      {
	       flags => $flags,
	       algorithm => $alg,
	       digesttype => $digesttype,
	       content => $content,
	      };
	    $intrustanchor = 0 if (/}/);
	} elsif (/}/) {
	    $intrustanchor = 0;
	}
	
	# XXX
    }

    return $doc;
}

sub write_ds {
    my ($self, $fh, $name, $record) = @_;
    my $status;
    $fh->printf("# unsupported DS record type for $name\n");
}

sub write_dnskey {
    my ($self, $fh, $name, $record) = @_;
    my $status;
    my $keytag = "";
    $keytag = " # $record->{keytag}" if (exists($record->{keytag}));
    $fh->printf("\t%15s $record->{flags} $record->{algorithm} $record->{digesttype} \"$record->{content}\";$keytag\n", $name);
}

sub write_trailer {
    my ($self, $fh, $options, $data) = @_;
    if ($self->{'options'}{'write_expectations'}) {
	$fh->printf("};\n\n");
	$fh->printf("options {\n");
	$fh->printf("    dnssec-validation yes;\n");
	$fh->printf("    dnssec-enable yes;\n");
	foreach my $zone (keys(%{$data->{'delegation'}})) {
	    $fh->printf("    dnssec-must-be-secure %-45.45s yes;\n",
			"\"$zone\"");
	}
	$fh->printf("};\n");
    }
}

=pod

=cut

