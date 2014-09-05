# This is -*- perl -*-

#
# Test for allowing slashes in SOA zonenames.
# This file was copied from zone.t.
#

use Net::DNS;
use Net::DNS::ZoneFile::Fast;

my $zone = <<'EOF';
$ORIGIN 2.1.in-addr.arpa.
$TTL 600
3 IN SOA dns1.acme.com.	host\.master.acme.com. ( 
	1000	; The serial number
	 180	; The refresh interval
	  60	; The retry interval
	1800	; The expire interval
	1000	; The minimum TTL
)

	IN NS dns1.acme.com.
	IN NS dns2.acme.com.

1.3	600 IN PTR		host1.acme.com.
2.3	100 IN PTR	host2.acme.com.
3.3	50 PTR		host3.acme.com.
4.3	PTR		dns1.acme.com.
5.3	1800 IN PTR	dns2.acme.com.

$ORIGIN acme.com.
@ IN SOA dns1.acme.com.  host\.master.acme.com. (
	1000	; The serial number
	 180	; The refresh interval
	  60	; The retry interval
	1800	; The expire interval
	1000	; The minimum TTL
)
	3600 IN NS dns1.acme.com.
	IN NS dns2.acme.com.
	NS dns3.acme.com.

        IN MX 10 mail1.acme.com.
        3600 MX 20 mail2.acme.com.
        MX 30 coyote.acme.com.
        RP postmaster @

dns1		1000 IN A	1.2.3.4
dns2.acme.com.	1000 IN A	1.2.3.5
@		10 IN CNAME	host1.acme.com.
.		IN A		1.2.3.1
host1		IN A		1.2.3.1
		IN TXT		"This is the first host"
        RP tobez.tobez.org. host1

coyote		IN CNAME	@

    ; some comments to make life interesting
EOF

BEGIN {
    @rr = 
    (
     [ Net::DNS::RR->new("3.2.1.in-addr.arpa. 600 IN SOA dns1.acme.com. host\\.master.acme.com. 1000 180 60 1800 1000")->string,
       "IN-ADDR.ARPA SOA", 3 ],
     );
};

use Test::More tests => (1 + 2*@rr);

my $rrset = Net::DNS::ZoneFile::Fast::parse($zone);

ok(defined $rrset, "Parsing zone file");

for my $rr (@rr) {
    my $trr = shift @$rrset;
    is($trr->string, $rr->[0], $rr->[1]);
    is($trr->Line, $rr->[2], "$rr->[1] - line number");
}
