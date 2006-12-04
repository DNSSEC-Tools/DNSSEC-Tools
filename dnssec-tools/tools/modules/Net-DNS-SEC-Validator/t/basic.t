#!./perl

BEGIN {
    unless(grep /blib/, @INC) {
        chdir 't' if -d 't';
        @INC = '../lib' if -d '../lib';
    }
}

use Test;

BEGIN { $n = 46; plan tests => $n }

use Net::DNS::SEC::Validator;
use Net::DNS::Packet;
use Net::hostent;
use Net::addrinfo;
use Socket qw(:all);

sub isnum {
    my $n = shift;
    return $n =~ /^\d+$/;
}

ok(isnum(Net::DNS::SEC::Validator::VAL_SUCCESS));

ok(isnum(Net::DNS::SEC::Validator::VAL_AC_VERIFIED));

ok(isnum(Net::DNS::SEC::Validator::SR_DNS_GENERIC_ERROR));

ok(isnum(Net::DNS::SEC::Validator::SR_NXDOMAIN));

ok(isnum(VAL_SUCCESS));

ok(isnum(VAL_AC_VERIFIED));

ok(isnum(SR_DNS_GENERIC_ERROR));

ok(isnum(SR_NXDOMAIN));

$validator = new Net::DNS::SEC::Validator(policy => ":");
ok(defined($validator));

$r = $validator->policy(":");
ok($r);

$r = $validator->policy("validate_tools:");
ok($r);

@r = $validator->getaddrinfo("good-A.test.dnssec-tools.org");
ok(@r);
ok(defined $r[0] and ref($r[0]) eq 'Net::addrinfo');
# there are 3 of these
foreach $a (@r) {
    ok($validator->istrusted($a->val_status));
}

$r =$validator->getaddrinfo("pastdate-AAAA.pastdate-ds.test.dnssec-tools.org");
ok(not $validator->istrusted($r->val_status));

$r = $validator->getaddrinfo("nosig-A.futuredate-ds.test.dnssec-tools.org");
ok(not $validator->istrusted($r->val_status));

$r = $validator->getaddrinfo("pastdate-A.futuredate-ds.test.dnssec-tools.org");
ok(not $validator->istrusted($r->val_status));

$r = $validator->getaddrinfo("good-A.pastdate-ds.test.dnssec-tools.org");
ok(not $validator->istrusted($r->val_status));

@r = $validator->getaddrinfo("good-cname-to-good-A.test.dnssec-tools.org");
ok(@r);
foreach $a (@r) {
    ok($validator->istrusted($a->val_status));
}

@r = $validator->getaddrinfo("good-cname-to-badsign-A.test.dnssec-tools.org");
ok(@r);
ok($r[0]->val_status == VAL_BOGUS_PROVABLE);


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

$r = $validator->res_query("good-A.test.dnssec-tools.org", "IN", "AAAA");
ok(not defined $r);
ok($validator->{error});
ok($validator->{errorStr});
ok($validator->{valStatus});
ok($validator->{valStatusStr});

$r = $validator->gethostbyname("good-A.good-ns.test.dnssec-tools.org");
ok(ref $r eq 'Net::hostent');

$r = $validator->gethostbyname("good-AAAA.test.dnssec-tools.org");
ok(not defined $r);

$r = $validator->gethostbyname("good-AAAA.test.dnssec-tools.org", AF_INET6);
ok(ref $r eq 'Net::hostent');

$r = $validator->gethostbyname("good-A.test.dnssec-tools.org");
ok(ref $r eq 'Net::hostent');

$r = $validator->gethostbyname("www.marzot.net");
ok(ref $r eq 'Net::hostent');


$r = $validator->res_query("marzot.net", "IN", "MX");
ok($r);

($pkt, $err) = new Net::DNS::Packet(\$r);
ok(not $err);

# this crashes
$r = $validator->res_query("mail.marzot.net", "IN", "MX");
ok(!$r);
ok($validator->{valStatus} == VAL_NONEXISTENT_TYPE_NOCHAIN);







