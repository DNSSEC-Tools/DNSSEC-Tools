# This is -*- perl -*-

use Net::DNS::ZoneFile::Fast;
use Test::More tests => 4;

my $ln = -1;
my %h = (
	quiet => 1,
	on_error => sub { $ln = $_[0]; },
);

my $z1 = <<EOF;
\$ORIGIN a.com.
\@ A 1.2.3.4   ; line 2
\@ MX 0 mail.a.com.   ; line 3
; line 4
       ; line 5
error at line 6 - syntax error, actually
host A 4.3.2.1   ; line 7
EOF

my $z2 = <<EOF;
\$ORIGIN a.com.
\@ A 1.2.3.4   ; line 2
\@ MX 0 mail.a.com.   ; line 3
\$GENERATE 42-15 \$.1.1.1.in-addr.arpa. IN PTR host-\$.acme.com. ; error at line 4
bla
blu
EOF

ok(!defined Net::DNS::ZoneFile::Fast::parse(text => $z1, %h), 'Bad zone parse.');
ok($ln == 6, 'Error must be at line 6.');
ok(!defined Net::DNS::ZoneFile::Fast::parse(text => $z2, %h), 'Bad zone parse.');
ok($ln == 4, 'Error must be at line 4.');
