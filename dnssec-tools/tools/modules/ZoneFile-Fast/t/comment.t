# This is -*- perl -*-

use Net::DNS::ZoneFile::Fast;
use Test::More tests => 6;

ok(defined Net::DNS::ZoneFile::Fast::parse(q{; just a comment}), 
   'Zone with just a bare comment');

ok(defined Net::DNS::ZoneFile::Fast::parse(q{;}), 
   'Zone with just an empty comment');

ok(defined Net::DNS::ZoneFile::Fast::parse(qq{;\n}), 
   'Zone with just an empty comment and a \n');

ok(defined Net::DNS::ZoneFile::Fast::parse(qq{;two\n;things\n}), 
   'Two comments back to back');

ok(defined Net::DNS::ZoneFile::Fast::parse(qq{; just a comment\n. IN A 127.0.0.1}), 
   'A comment and an RR');

ok(defined Net::DNS::ZoneFile::Fast::parse(qq{;two\n;things\n. IN A 127.0.0.1}), 
   'Two comments back to back and an RR');



