package Net::DNS::SEC::Tools::TrustAnchor::Bind;

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

	if (/trusted-keys\s+{/) {
	    $intrustanchor = 1;
	} elsif ($intrustanchor &&
		 /^\s*(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+\"([^"]*)\"\s*;/) {
	    my ($name, $flags, $alg, $digesttype, $content) =
	      ($1, $2, $3, $4, $5);
	    $content =~ s/ //g;
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

sub write {
    my ($self, $data, $location, $options) = @_;
    open(O, ">", $location);
    print O "# saved by Net::DNS::SEC::Tools::TrustAnchor::Bind\n";
    print O $self->create_extra_info_string($data, {}, "#"),"\n";
    print O "trusted-keys {\n";
    foreach my $key (keys(%{$data->{'delegation'}})) {
	if (exists($data->{'delegation'}{$key}{'ds'})) {
	    foreach my $record (@{$data->{'delegation'}{$key}{'ds'}}) {
		print O "# unsupported DS record type for $key\n";
	    }
	}
	if (exists($data->{'delegation'}{$key}{'dnskey'})) {
	    foreach my $record (@{$data->{'delegation'}{$key}{'dnskey'}}) {
		my $keytag = "";
		$keytag = " # $record->{keytag}" if (exists($record->{keytag}));
		printf O "\t%15s $record->{flags} $record->{algorithm} $record->{digesttype} \"$record->{content}\";$keytag\n", $key;
	    }
	}
    }
    print O "}\n";
    close(O);
    return 0;
}

=pod
