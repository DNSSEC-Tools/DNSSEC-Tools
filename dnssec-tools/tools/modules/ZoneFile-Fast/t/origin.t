# This is -*- perl -*-

use Net::DNS::ZoneFile::Fast;
use Test::More tests => 9;

ok(defined Net::DNS::ZoneFile::Fast::parse(q{}), 
   'Empty zone');

ok(defined Net::DNS::ZoneFile::Fast::parse(q{$ORIGIN acme.com.}), 
   'Simple $ORIGIN clause');

ok(defined Net::DNS::ZoneFile::Fast::parse(q{$ORIGIN acme.com. ; comment}), 
   'Simple $ORIGIN clause with comments');

ok(defined Net::DNS::ZoneFile::Fast::parse(q{$ORIGIN acme.com}), 
   'Simple $ORIGIN clause with no trailing dot');

ok(defined Net::DNS::ZoneFile::Fast::parse(q{$ORIGIN acme.com ; comment}), 
   'Simple $ORIGIN clause with comments and no dot');

ok(defined Net::DNS::ZoneFile::Fast::parse(q{$ORIGIN . ; comment}), 
   'Simple $ORIGIN clause with comments and just a dot');

ok(defined Net::DNS::ZoneFile::Fast::parse(q{$ORIGIN .}), 
   'Simple $ORIGIN clause with just a dot');

ok(!defined Net::DNS::ZoneFile::Fast::parse(text => q{$ORIGIN}, quiet => 1, soft_errors => 1),
   '$ORIGIN token alone in the file');

my $rr = Net::DNS::ZoneFile::Fast::parse("\$ORIGIN bork.\n\$ORIGIN moo.bla\nmoof  A 1.2.3.4");
ok(defined($rr) && 1 == @$rr && $rr->[0]->name eq "moof.moo.bla.bork", 'Relative origin');
