# This is -*- perl -*-

use Net::DNS::RR;
use Net::DNS::ZoneFile::Fast;

my $zone = <<'EOF';
$ORIGIN 2.1.in-addr.arpa.
$TTL 600
3 IN SOA dns1.acme.com.	hostmaster.acme.com. ( ; The host that should give auth answers ; The one who cares when it doesn't
; this comment is a pain...
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
@ IN SOA dns1.acme.com.  hostmaster.acme.com. ( ; The host that should give auth answers ; The one who cares when it doesn't
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
     [ Net::DNS::RR->new("3.2.1.in-addr.arpa. 600 IN SOA dns1.acme.com. hostmaster.acme.com. 1000 180 60 1800 1000")->string,
       "IN-ADDR.ARPA SOA", 3 ],
     [ Net::DNS::RR->new("3.2.1.in-addr.arpa. 600 IN NS dns1.acme.com.")->string,
       "First NS RR", 12 ],
     [ Net::DNS::RR->new("3.2.1.in-addr.arpa. 600 IN NS dns2.acme.com.")->string,
       "Second NS RR", 13 ],
     [ Net::DNS::RR->new("1.3.2.1.in-addr.arpa. 600 IN PTR host1.acme.com.")->string,
       "PTR RR with default TTL", 15 ],
     [ Net::DNS::RR->new("2.3.2.1.in-addr.arpa. 100 IN PTR host2.acme.com.")->string,
       "PTR RR with explicit TTL", 16 ],
     [ Net::DNS::RR->new("3.3.2.1.in-addr.arpa. 50 PTR host3.acme.com.")->string,
       "PTR RR with no class", 17 ],
     [ Net::DNS::RR->new("4.3.2.1.in-addr.arpa. 600 PTR dns1.acme.com.")->string,
       "PTR RR with no class and default TTL", 18 ],
     [ Net::DNS::RR->new("5.3.2.1.in-addr.arpa. 1800 IN PTR dns2.acme.com.")->string,
       "Plan PTR RR", 19 ],
     [ Net::DNS::RR->new("acme.com. 600 IN SOA dns1.acme.com. hostmaster.acme.com. 1000 180 60 1800 1000")->string,
       "acme.com. SOA", 22 ],
     [ Net::DNS::RR->new("acme.com. 3600 IN NS dns1.acme.com.")->string,
       "First NS RR", 29 ],
     [ Net::DNS::RR->new("acme.com. 600 IN NS dns2.acme.com.")->string,
       "Second NS RR", 30 ],
     [ Net::DNS::RR->new("acme.com. 600 IN NS dns3.acme.com.")->string,
       "Third NS RR", 31 ],
     [ Net::DNS::RR->new("acme.com. 600 IN MX 10 mail1.acme.com.")->string,
       "Innocent MX", 33 ],
     [ Net::DNS::RR->new("acme.com. 3600 IN MX 20 mail2.acme.com.")->string,
       "MX with TTL", 34 ],
     [ Net::DNS::RR->new("acme.com. 600 IN MX 30 coyote.acme.com.")->string,
       "Compact MX", 35 ],
     [ Net::DNS::RR->new("acme.com. 600 IN RP postmaster.acme.com. acme.com.")->string,
       "RP with implicit mbox and \@-txtdname", 36 ],
     [ Net::DNS::RR->new("dns1.acme.com. 1000 IN A 1.2.3.4")->string,
       "Simple A RR", 38 ],
     [ Net::DNS::RR->new("dns2.acme.com. 1000 IN A 1.2.3.5")->string,
       "FQDN A RR", 39 ],
     [ Net::DNS::RR->new("acme.com. 10 IN CNAME host1.acme.com.")->string,
       "\@ CNAME", 40 ],
     [ Net::DNS::RR->new(". 600 IN A 1.2.3.1")->string,
       "A RR for the root domain (invalid anyway)", 41 ],
     [ Net::DNS::RR->new("host1.acme.com. 600 IN A 1.2.3.1")->string,
       "Simple A RR", 42 ],
     [ Net::DNS::RR->new("host1.acme.com. 600 IN TXT \"This is the first host\"")->string,
       "dangling TXT RR", 43 ],
     [ Net::DNS::RR->new("host1.acme.com. 600 IN RP tobez.tobez.org. host1.acme.com.")->string,
       "RP with implicit txtdname", 44 ],
     [ Net::DNS::RR->new("coyote.acme.com. 600 IN CNAME acme.com.")->string,
       "@ on the RHS", 46 ],

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
