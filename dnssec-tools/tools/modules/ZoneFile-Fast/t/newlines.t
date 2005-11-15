# This is -*- perl -*-

use Net::DNS::ZoneFile::Fast;
use Test::More tests => 18;

ok(!defined Net::DNS::ZoneFile::Fast::parse(text => "\$ORIGIN\nmicrosoft.com.", quiet => 1, soft_errors => 1),
   '$ORIGIN clause spanning multiple lines');

ok(!defined Net::DNS::ZoneFile::Fast::parse(text => "\$TTL\n30", quiet => 1, soft_errors => 1),
   '$TTL clause spanning multiple lines');

ok(!defined Net::DNS::ZoneFile::Fast::parse(text => "\$GENERATE\n1-5 \$.1.1.1.in-addr.arpa. IN PTR host-\$.acme.com.", quiet => 1, soft_errors => 1),
   '$GENERATE clause spanning multiple lines');

ok(!defined Net::DNS::ZoneFile::Fast::parse(text => "a.com. 30 IN SOA dns1.a.com. hostmaster.a.com.\n(1 1 1 1 1)", quiet => 1, soft_errors => 1),
   'SOA record spanning multiple lines in a wrong way 1');

ok(!defined Net::DNS::ZoneFile::Fast::parse(text => "a.com.\n30 IN SOA dns1.a.com. hostmaster.a.com. (1 1 1 1 1)", quiet => 1, soft_errors => 1),
   'SOA record spanning multiple lines in a wrong way 2');

ok(!defined Net::DNS::ZoneFile::Fast::parse(text => "a.com. 30\nIN SOA dns1.a.com. hostmaster.a.com. (1 1 1 1 1)", quiet => 1, soft_errors => 1),
   'SOA record spanning multiple lines in a wrong way 3');

ok(!defined Net::DNS::ZoneFile::Fast::parse(text => "a.com. 30 IN\nSOA dns1.a.com. hostmaster.a.com. (1 1 1 1 1)", quiet => 1, soft_errors => 1),
   'SOA record spanning multiple lines in a wrong way 4');

ok(!defined Net::DNS::ZoneFile::Fast::parse(text => "a.com. 30 IN SOA\ndns1.a.com. hostmaster.a.com. (1 1 1 1 1)", quiet => 1, soft_errors => 1),
   'SOA record spanning multiple lines in a wrong way 5');

ok(!defined Net::DNS::ZoneFile::Fast::parse(text => "a.com. 30 IN SOA dns1.a.com.\nhostmaster.a.com. (1 1 1 1 1)", quiet => 1, soft_errors => 1),
   'SOA record spanning multiple lines in a wrong way 6');

ok(!defined Net::DNS::ZoneFile::Fast::parse(text => "4.3.2.1.in-addr.arpa. PTR\nbla.com.", quiet => 1, soft_errors => 1),
   'PTR record spanning multiple lines');

ok(!defined Net::DNS::ZoneFile::Fast::parse(text => "a.com. NS\nns.a.com.", quiet => 1, soft_errors => 1),
   'NS record spanning multiple lines');

ok(!defined Net::DNS::ZoneFile::Fast::parse(text => "a.com. CNAME\nb.com.", quiet => 1, soft_errors => 1),
   'CNAME record spanning multiple lines');

ok(!defined Net::DNS::ZoneFile::Fast::parse(text => "a.com. MX 0\nmail.a.com.", quiet => 1, soft_errors => 1),
   'MX record spanning multiple lines');

ok(!defined Net::DNS::ZoneFile::Fast::parse(text => "a.com. TXT\n\"hello, world\"", quiet => 1, soft_errors => 1),
   'TXT record spanning multiple lines');

ok(!defined Net::DNS::ZoneFile::Fast::parse(text => "a.com. HINFO Small-Laptop\nFreeBSD", quiet => 1, soft_errors => 1),
   'HINFO record spanning multiple lines');

ok(defined Net::DNS::ZoneFile::Fast::parse("a.com. AAAA 3ffe:8050:201:1860:42::1"),
   'normal AAAA record');

ok(!defined Net::DNS::ZoneFile::Fast::parse(text => "a.com. AAAA\n3ffe:8050:201:1860:42::1", quiet => 1, soft_errors => 1),
   'AAAA record spanning multiple lines');

ok(!defined Net::DNS::ZoneFile::Fast::parse(text => "a.com. A\n1.2.3.4", quiet => 1, soft_errors => 1),
   'A record spanning multiple lines');

