#!./perl

BEGIN {
    unless(grep /blib/, @INC) {
        chdir 't' if -d 't';
        @INC = '../lib' if -d '../lib';
    }
}

use Test;

BEGIN { $n = 12; plan tests => $n }

use Net::addrinfo;
use Socket;


my $addrinfo = new Net::addrinfo(flags => AI_CANONNAME, family => AF_INET, 
			     socktype => SOCK_DGRAM, addr => 
			     pack_sockaddr_in(53,inet_aton("www.marzot.net")));
ok(defined($addrinfo));


my (@ainfo_arr) = getaddrinfo("mail.marzot.net");
ok(@ainfo_arr > 1);

foreach my $ainfo (@ainfo_arr) {
    ok(ref $ainfo eq 'Net::addrinfo');
}

my $hint = new Net::addrinfo(flags => AI_CANONNAME, protocol => IPPROTO_IP);

$ainfo = getaddrinfo("mail.marzot.net", undef, $hint);
ok(defined($ainfo) and ref $ainfo eq 'Net::addrinfo');

$hint = new Net::addrinfo(flags => AI_CANONNAME);

$ainfo = getaddrinfo("mail.marzot.net", "mail", $hint);
ok(defined($ainfo) and ref $ainfo eq 'Net::addrinfo');

$hint = new Net::addrinfo(flags => AI_NUMERICHOST);

$ainfo = getaddrinfo("127.0.0.1", undef, $hint);
ok(defined($ainfo) and ref $ainfo eq 'Net::addrinfo');

$hint = new Net::addrinfo(flags => AI_CANONNAME);

$ainfo = getaddrinfo("good-A.test.dnssec-tools.org", "domain", $hint);
ok(defined($ainfo) and ref $ainfo eq 'Net::addrinfo');

$hint = new Net::addrinfo(flags => AI_PASSIVE);

$ainfo = getaddrinfo(undef, "domain", $hint);
ok(defined($ainfo) and ref $ainfo eq 'Net::addrinfo');

$ainfo = getaddrinfo(undef, "domain");
ok(defined($ainfo) and ref $ainfo eq 'Net::addrinfo');

$hint = new Net::addrinfo(flags => AI_CANONNAME);

$ainfo = getaddrinfo(undef, "domain", $hint);
ok(defined($ainfo) and not ref($ainfo) and $ainfo == EAI_BADFLAGS);
