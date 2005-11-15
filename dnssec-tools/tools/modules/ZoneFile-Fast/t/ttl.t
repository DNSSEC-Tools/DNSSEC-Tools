# This is -*- perl -*-

use Net::DNS::ZoneFile::Fast;
use Test::More tests => 24;

ok(defined Net::DNS::ZoneFile::Fast::parse(q{$TTL 30}), 
   'Simple $TTL clause');

ok(defined Net::DNS::ZoneFile::Fast::parse(q{$TTL 30 ; comment}), 
   'Simple $TTL clause with comments');

ok(!defined Net::DNS::ZoneFile::Fast::parse(text => "\$TTL\n30", quiet => 1, soft_errors => 1), 
   '$TTL clause spanning multiple lines');

ok(!defined Net::DNS::ZoneFile::Fast::parse(text => q{$TTL}, quiet => 1, soft_errors => 1),
   '$TTL token alone in the file');

ok(!defined Net::DNS::ZoneFile::Fast::parse(text => q{$TTL 1C3F}, quiet => 1, soft_errors => 1),
   '$TTL expressed in cats per forthnight');

my $p;

ok(defined($p = Net::DNS::ZoneFile::Fast::parse("\$TTL 1800\na.b. A 1.2.3.4")),
   '$TTL as a number');
is($p->[0]->ttl, 1800, "TTL == 1800 seconds");

ok(defined($p = Net::DNS::ZoneFile::Fast::parse("\$TTL 1S\na.b. A 1.2.3.4")),
   '$TTL with seconds');
is($p->[0]->ttl, 1, "TTL == 1 second");

ok(defined($p = Net::DNS::ZoneFile::Fast::parse("\$TTL 1M\na.b. A 1.2.3.4")),
   '$TTL with minutes');
is($p->[0]->ttl, 60, "TTL == 1 minute");

ok(defined($p = Net::DNS::ZoneFile::Fast::parse("\$TTL 1H\na.b. A 1.2.3.4")),
   '$TTL with hours');
is($p->[0]->ttl, 3600, "TTL == 1 hour");

ok(defined($p = Net::DNS::ZoneFile::Fast::parse("\$TTL 2H3h\na.b. A 1.2.3.4")),
   '$TTL with some hours');
is($p->[0]->ttl, 5*3600, "TTL == 5 hours");

ok(defined($p = Net::DNS::ZoneFile::Fast::parse("\$TTL 1D\na.b. A 1.2.3.4")),
   '$TTL with days');
is($p->[0]->ttl, 86400, "TTL == 1 day");

ok(defined($p = Net::DNS::ZoneFile::Fast::parse("\$TTL 1W\na.b. A 1.2.3.4")),
   '$TTL with weeks');
is($p->[0]->ttl, 604800, "TTL == 1 week");

ok(defined($p = Net::DNS::ZoneFile::Fast::parse("\$TTL 2W3D4H30M45S\na.b. A 1.2.3.4")),
   '$TTL with weeks, days, hours, minutes, and seconds [1]');
is($p->[0]->ttl, 1485045, "TTL == something [1]");

ok(!defined($p = Net::DNS::ZoneFile::Fast::parse(text => "\$TTL 2W3D4H30M45\na.b. A 1.2.3.4", quiet => 1, soft_errors => 1)),
   '$TTL with weeks, days, hours, minutes, and seconds [2]');

ok(defined($p = Net::DNS::ZoneFile::Fast::parse("\$TTL 30M45S2W\na.b. A 1.2.3.4")),
   '$TTL with minutes, seconds, and weeks');
is($p->[0]->ttl, 1211445, "TTL == 2w30m45s");
