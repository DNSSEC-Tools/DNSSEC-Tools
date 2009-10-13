package Net::DNS::SEC::Tools::TrustAnchor::Dump;

# XXX: fails for some reason if included; probably in the eval
#use strict;
use Net::DNS::SEC::Tools::TrustAnchor;

our @ISA = qw(Net::DNS::SEC::Tools::TrustAnchor);
our $VERSION = '0.1';

use Data::Dumper;

use XML::Simple;

sub read_content {
    my ($self, $location, $options) = @_;

    $location ||= $self->{'file'};
    $options ||= $self->{'options'};

    open(I, "$location");
    my $data;
    read(I, $data, 2**16);
    return eval "$data";
}

sub write {
    my ($self, $data, $location, $options) = @_;
    open(O, ">$location");
    print O Dumper($data);
    close(O);
    return 0;
}

=pod

=cut

