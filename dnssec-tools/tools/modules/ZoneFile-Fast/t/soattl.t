# This is -*- perl -*-

use IO::File;
use Net::DNS;
use Net::DNS::RR;
use Net::DNS::ZoneFile::Fast;

use Test::More tests => 5;

END {
    unlink "./read.txt";
}

my $zone = q{a.com. 30 IN SOA dns1.a.com. hostmaster.a.com. (1 1 1 1 1)};

ok(defined Net::DNS::ZoneFile::Fast::parse($zone), "parse of the test zone");

my $fh = new IO::File "./read.txt", "w" or die "# Failed to create test file\n";

print $fh $zone;

$fh->close;

$fh = new IO::File "./read.txt" or die "# Failed to open test file\n";

ok(defined Net::DNS::ZoneFile::Fast::parse(fh => $fh), 'readfh');

$fh->close;

ok(defined Net::DNS::ZoneFile::Fast::parse(file => "./read.txt"), 'read');

my $rrset = Net::DNS::ZoneFile::Fast::parse(file => "./read.txt");

ok(defined $rrset, 're-read');

die unless defined $rrset;

my $rr = new Net::DNS::RR $zone;

ok($rr->string eq $rrset->[0]->string, "RR comparison");








