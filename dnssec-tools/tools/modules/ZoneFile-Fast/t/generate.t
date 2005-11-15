# This is -*- perl -*-

use Net::DNS::ZoneFile::Fast;

use Test::More tests => 7 ;

my $data = q{
$GENERATE 1-5 $.1.1.1.in-addr.arpa. IN PTR host-$.acme.com.
};

my @rr = (
	[ Net::DNS::RR->new("1.1.1.1.in-addr.arpa. IN PTR host-1.acme.com.")->string, "First RR of a \$GENERATE" ],
	[ Net::DNS::RR->new("2.1.1.1.in-addr.arpa. IN PTR host-2.acme.com.")->string, "Second RR of a \$GENERATE" ],
	[ Net::DNS::RR->new("3.1.1.1.in-addr.arpa. IN PTR host-3.acme.com.")->string, "Third RR of a \$GENERATE" ],
	[ Net::DNS::RR->new("4.1.1.1.in-addr.arpa. IN PTR host-4.acme.com.")->string, "Fourth RR of a \$GENERATE" ],
	[ Net::DNS::RR->new("5.1.1.1.in-addr.arpa. IN PTR host-5.acme.com.")->string, "Last RR of a \$GENERATE" ],
);

my $rrset = Net::DNS::ZoneFile::Fast::parse($data);

ok(defined $rrset, "Parsing of a \$GENERATE statement");

is(scalar @$rrset, scalar @rr, "Number of parsed RRs");

for my $rr (@rr) {
    my $rrt = shift @$rrset;
    is($rrt->string, $rr->[0], $rr->[1]);
}







