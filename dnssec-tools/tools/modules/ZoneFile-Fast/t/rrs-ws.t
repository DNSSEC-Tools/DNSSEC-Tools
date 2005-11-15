# This is -*- perl -*-

use Net::DNS::ZoneFile::Fast;

BEGIN {
    @test = 
	(
	 q{. 300 IN A 127.0.0.1},
	 q{localhost. 300 IN A 127.0.0.1},
	 q{localhost IN A 127.0.0.1},
	 q{localhost.acme IN A 127.0.0.1},
	 q{localhost A 127.0.0.1},
	 q{localhost. 300 A 127.0.0.1},
	 q{10.10.10.10.in-addr.arpa 300 IN PTR www.acme.com.},
	 q{10.10.10.10.in-addr.arpa. 300 IN PTR www.acme.com.},
	 q{10.10.10.10.in-addr.arpa. 300 PTR www.acme.com.},
	 q{10.10.10.10.in-addr.arpa. IN PTR www.acme.com.},
	 q{10.10.10.10.in-addr.arpa PTR www.acme.com.},
	 q{. 3600 IN NS dns1.acme.com.},
	 q{acme.com. 3600 IN NS dns1.acme.com.},
	 q{@ 3600 IN NS dns1.acme.com.},
	 q{acme.com. 100 IN CNAME www.acme.com.},
	 q{acme.com 100 IN CNAME www.acme.com.},
	 q{text.acme.com. 100 IN TXT "This is a quite long text"},
	 q{text.acme.com IN TXT "This is another piece"},
	 q{text.acme.com TXT "This is another piece"},
	 q{* 100 IN MX 10 mailhost.acme.com.},
	 q{* IN A 1.2.3.4},
	 q{* 10 IN A 1.2.3.4},
#	 q{* IN 10 A 1.2.3.4},   XXX newer Net::DNS does not like this syntax
	 q{acme.com. 200 IN MX 10 mailhost.acme.com.},
	 q{acme.com. IN MX 10 mailhost.acme.com.},
	 q{acme.com. MX 10 mailhost.acme.com.},
	 q{acme.com 200 IN MX 10 mailhost.acme.com.},
	 q{acme.com IN MX 10 mailhost.acme.com.},
	 q{acme.com MX 10 mailhost.acme.com.},
	 q{acme.com. IN SOA dns1.acme.com. me.acme.com. ( 1 2 3 4 5 )},
	 q{. IN SOA dns1.acme.com. hostmaster.acme.com. ( 1 1 1 1 1 )},
	 q{@ IN SOA dns1.acme.com. hostmaster.acme.com. ( 1 1 1 1 1 )},
	 q{. IN SOA dns1.acme.com. hostmaster.acme.com. ( 1 1 1 1 1 )},
	 q{acme.com. IN AAAA 2001:688:0:102::1:2},
	 q{acme.com. IN AAAA 2001:688:0:102::3},
	 q{acme.com. IN RP abuse.acme.com. acme.com.},
	 );
}

use Test::More tests => 2 * scalar @test;

for my $rrdata (@test) {
    my $test = "\n   \n" . $rrdata . "\n\n\n \n";
    my $rrset = Net::DNS::ZoneFile::Fast::parse($test);
    (my $adata = $rrdata) =~ s/@/./;
    $adata =~ s/(IN SOA .* (\d+)) \)/ $2 $1/;
    my $rr = new Net::DNS::RR $adata;
    (my $rrcorrect = $rr->string) =~ s/\s+/ /g;
    ok(defined $rrset, "Parsing $rrdata");
    (my $rrtxt = $rrset->[0]->string) =~ s/\s+/ /g;
    is($rrtxt, $rrcorrect, "RR comparison for $rrdata + whitespace");
}
