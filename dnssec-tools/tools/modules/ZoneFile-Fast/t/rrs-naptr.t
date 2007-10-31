# This is -*- perl -*-

use Net::DNS::ZoneFile::Fast;

BEGIN {
    @test = 
	(
         q{2.1.2.1.5.5.5.0.7.7.1.e164.arpa. IN NAPTR 100 10 "u" "E2U+sip"  "!^.*$!sip:information@pbx.example.com!i" .},
         q{2.1.2.1.5.5.5.0.7.7.1.e164.arpa. IN NAPTR 102 10 "u" "E2U+email" "!^.*$!mailto:information@example.com!i"  .},
	 );
}

use Test::More tests => 2 * scalar @test;

for my $rrdata (@test) {
    my $rrset = Net::DNS::ZoneFile::Fast::parse($rrdata);
    ok(defined $rrset, "Parsing $rrdata");

    my $rr = new Net::DNS::RR $rrdata;
    (my $rrcorrect = $rr->string) =~ s/\s+/ /g;
    (my $rrtxt = $rrset->[0]->string) =~ s/\s+/ /g;
    is($rrtxt, $rrcorrect, "RR comparison for $rrdata");
}
