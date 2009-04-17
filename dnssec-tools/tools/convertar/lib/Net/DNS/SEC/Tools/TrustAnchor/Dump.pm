package Net::DNS::SEC::Tools::TrustAnchor::Dump;

use Net::DNS::SEC::Tools::TrustAnchor;

our @ISA = qw(Net::DNS::SEC::Tools::TrustAnchor);
our $VERSION = '0.1';

use Data::Dumper;

use XML::Simple;

sub write {
    my ($self, $data, $location, $options) = @_;
    open(O, ">$location");
    print O Dumper($data);
    close(O);
    return 0;
}

=pod
