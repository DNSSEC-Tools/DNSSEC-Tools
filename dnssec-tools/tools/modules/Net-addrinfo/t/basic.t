#!./perl

BEGIN {
    unless(grep /blib/, @INC) {
        chdir 't' if -d 't';
        @INC = '../lib' if -d '../lib';
    }
}

use Test;

BEGIN { $n = 9; plan tests => $n }

use Net::addrinfo;
use Socket;


my $addrinfo = new Net::addrinfo(flags => AI_CANONNAME, family => AF_INET, 
			     socktype => SOCK_DGRAM, addr => 
			     pack_sockaddr_in(53,inet_aton("www.marzot.net")));
ok(defined($addrinfo));

print STDERR $addrinfo->stringify();

my $aref = getaddrinfo("mail.marzot.net");
ok(defined($aref) and ref($aref) eq 'ARRAY');

foreach my $ainfo (@$aref) {
    print STDERR $ainfo->stringify();
    print STDERR "-----------------------\n";
}

my $hint = new Net::addrinfo(flags => AI_CANONNAME, protocol => IPPROTO_IP);

$aref = getaddrinfo("mail.marzot.net", undef, $hint);
ok(defined($aref) and ref($aref) eq 'ARRAY');

foreach my $ainfo (@$aref) {
    print STDERR $ainfo->stringify();
    print STDERR "-----------------------\n";
}

$hint = new Net::addrinfo(flags => AI_CANONNAME);

$aref = getaddrinfo("mail.marzot.net", "mail", $hint);
ok(defined($aref) and ref($aref) eq 'ARRAY');

foreach my $ainfo (@$aref) {
    print STDERR $ainfo->stringify();
    print STDERR "-----------------------\n";
}

$hint = new Net::addrinfo(flags => AI_NUMERICHOST);

$aref = getaddrinfo("127.0.0.1", undef, $hint);
ok(defined($aref) and ref($aref) eq 'ARRAY');

foreach my $ainfo (@$aref) {
    print STDERR $ainfo->stringify();
    print STDERR "-----------------------\n";
}

$hint = new Net::addrinfo(flags => AI_CANONNAME);

$aref = getaddrinfo("good-A.test.dnssec-tools.org", "domain", $hint);
ok(defined($aref) and ref($aref) eq 'ARRAY');

foreach my $ainfo (@$aref) {
    print STDERR $ainfo->stringify();
    print STDERR "-----------------------\n";
}

$hint = new Net::addrinfo(flags => AI_PASSIVE);

$aref = getaddrinfo(undef, "domain", $hint);
ok(defined($aref) and ref($aref) eq 'ARRAY');

foreach my $ainfo (@$aref) {
    print STDERR $ainfo->stringify();
    print STDERR "-----------------------\n";
}

$aref = getaddrinfo(undef, "domain");
ok(defined($aref) and ref($aref) eq 'ARRAY');

foreach my $ainfo (@$aref) {
    print STDERR $ainfo->stringify();
    print STDERR "-----------------------\n";
}

$hint = new Net::addrinfo(flags => AI_CANONNAME);

$aref = getaddrinfo(undef, "domain", $hint);
ok(defined($aref) and not ref($aref));


print STDERR "Testing bad flags:$aref:", gai_strerror($aref), ":", IPPROTO_UDP, "\n";
