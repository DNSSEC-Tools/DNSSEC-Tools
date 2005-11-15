# This is -*- perl -*-

use Net::DNS::ZoneFile::Fast;
use Test::More tests => 6;

$zone = q{
$ORIGIN acme.com.
		  
www	926 IN A 10.10.10.10
        925 IN A 11.11.11.11
};

$crr = Net::DNS::RR->new("www.acme.com 925 IN A 11.11.11.11")->string;

my $rrset = Net::DNS::ZoneFile::Fast::parse($zone);

is (scalar @$rrset, 2, "Correct number of RRs in zone");
is ($rrset->[1]->string, $crr, "Correct (empty) RR parsed");

$zone = q{
$ORIGIN acme.com.
		  
www	926 IN A 10.10.10.10
www     925 IN A 11.11.11.11
};

$crr = Net::DNS::RR->new("www.acme.com 925 IN A 11.11.11.11")->string;

$rrset = Net::DNS::ZoneFile::Fast::parse($zone);

is (scalar @$rrset, 2, "Correct number of RRs in zone");
is ($rrset->[1]->string, $crr, "Correct (partial) RR parsed");

$zone = q{
$ORIGIN acme.com.
		  
www	926 IN A 10.10.10.10
www.acme.com.     925 IN A 11.11.11.11
};

$crr = Net::DNS::RR->new("www.acme.com 925 IN A 11.11.11.11")->string;

$rrset = Net::DNS::ZoneFile::Fast::parse($zone);

is (scalar @$rrset, 2, "Correct number of RRs in zone");
is ($rrset->[1]->string, $crr, "Correct (fqdn) RR parsed");






