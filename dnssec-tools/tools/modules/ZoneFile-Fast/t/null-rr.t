# This is -*- perl -*-

use Net::DNS::RR;
use Net::DNS::ZoneFile::Fast;
use Test::More tests => 4;

my $zone = q{
$ORIGIN choicecarecard.com.
dddwww		IN	A	199.93.70.72
		IN	A	199.93.70.210
};

my $rrset = Net::DNS::ZoneFile::Fast::parse($zone);

ok(defined $rrset, "Parsing of the zone file");
ok(@$rrset == 2, "Correct number of records");
ok($rrset->[0]->string 
   eq Net::DNS::RR->new("dddwww.choicecarecard.com. 0 IN A 199.93.70.72")->string,
   "First dummy RR is ok");

ok($rrset->[1]->string 
   eq Net::DNS::RR->new("dddwww.choicecarecard.com. 0 IN A 199.93.70.210")->string,
   "Second dummy RR is ok");


