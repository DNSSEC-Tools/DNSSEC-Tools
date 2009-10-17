package Net::DNS::SEC::Tools::TrustAnchor::Secspider;

use strict;
use Net::DNS::SEC::Tools::TrustAnchor::Bind;
use IO::String;

# we're really just a special form of the Bind module
our @ISA = qw(Net::DNS::SEC::Tools::TrustAnchor::Bind);
our $VERSION = '0.1';

sub read_content {
    my ($self, $location, $options) = @_;

    # if we have any sort of locational argument, just read from it instead.
    if ($location) {
	return $self->SUPER::read_content($location, $options);
    }

    # fetch the TA list from the secspider server
    my $text =
      $self->fetch_url("http://secspider.cs.ucla.edu/trust-anchors.conf");
    return if (!$text);

    # turn it into a file handle
    my $ioh = IO::String->new($text);

    # call the normal bind module to process it
    return $self->SUPER::read_content($ioh, $options);
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

=pod

=cut

