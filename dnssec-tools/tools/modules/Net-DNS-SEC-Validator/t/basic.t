#!./perl

BEGIN {
    unless(grep /blib/, @INC) {
        chdir 't' if -d 't';
        @INC = '../lib' if -d '../lib';
    }
}

use Test;

BEGIN { $n = 24; plan tests => $n }

use Net::DNS::SEC::Validator;
use Net::DNS::Packet;
use Net::hostent;
use Net::addrinfo;
use Socket qw(:all);

ok(Net::DNS::SEC::Validator::VAL_SUCCESS);

ok(Net::DNS::SEC::Validator::VAL_AC_VERIFIED);

ok(Net::DNS::SEC::Validator::SR_NOANSWER);

ok(Net::DNS::SEC::Validator::SR_NXDOMAIN);

use Net::DNS::SEC::Validator qw( !/VAL_/ !/SR_/ );

ok(VAL_SUCCESS);

ok(VAL_AC_VERIFIED);

ok(SR_NOANSWER);

ok(SR_NXDOMAIN);

$validator = new Net::DNS::SEC::Validator(policy => ":");
ok(defined($validator));

$r = $validator->policy(":");
ok($r);

$r = $validator->policy("validate_tools:");
ok($r);

@r = $validator->getaddrinfo("good-A.test.dnssec-tools.org");
ok(@r);
ok(ref($r[0]) eq 'Net::addrinfo');

$r = $validator->res_query("good-AAAA.test.dnssec-tools.org", "IN", "AAAA");
ok($r);

($pkt, $err) = new Net::DNS::Packet(\$r);
ok(not $err);

$r = $validator->res_query("good-A.test.dnssec-tools.org", "IN", "A");
ok($r);

($pkt, $err) = new Net::DNS::Packet(\$r);
ok(not $err);

$r = $validator->res_query("good-A.good-ns.test.dnssec-tools.org", "IN", "A");
ok($r);

($pkt, $err) = new Net::DNS::Packet(\$r);
ok(not $err);

$r = $validator->gethostbyname("good-A.good-ns.test.dnssec-tools.org");
ok(ref $r eq 'Net::hostent');

$r = $validator->gethostbyname("good-AAAA.test.dnssec-tools.org");
ok(not defined $r);

$r = $validator->gethostbyname("good-AAAA.test.dnssec-tools.org", AF_INET6);
print STDERR "$validator->{errorStr}:$validator->{valStatusStr}\n",
ok(ref $r eq 'Net::hostent');

$r = $validator->gethostbyname("good-A.test.dnssec-tools.org");
ok(ref $r eq 'Net::hostent');

$r = $validator->gethostbyname("www.marzot.net");
ok(ref $r eq 'Net::hostent');






