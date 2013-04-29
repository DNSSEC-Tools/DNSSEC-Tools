#!/usr/bin/perl

use Test::More qw(no_plan);
use Data::Dumper;
use Net::DNS::SEC::Tools::Donuts::Rule;

######################################################################
BEGIN { use_ok('Net::DNS::SEC::Tools::Donuts'); }
require_ok('Net::DNS::SEC::Tools::Donuts');

my $donuts = new Net::DNS::SEC::Tools::Donuts();

my $result = $donuts->load_zone("t/db.example.com", "example.com");
ok($result == 0, "zone load produced no errors");

my $rrs = $donuts->zone_records();

$donuts->load_rule_files('t/donuts-test-rules.txt');
my @rules = $donuts->rules();
ok($#rules == 1, "rules loaded");

my ($rulecount, $errcount) = $donuts->analyze(9);
ok($rulecount == 2, "2 rules were executed (got: $rulecount)");
ok($errcount == 4, "4 errors were found in the first run (got: $errcount)");

$donuts->parse_config_file('t/donuts-test.conf');

# should be 1 less error this time
($rulecount, $errcount) = $donuts->analyze(9);
ok($rulecount == 2, "2 rules were executed (got: $rulecount)");
ok($errcount == 3, "3 errors were found in the second run (got: $errcount)");

# should be able to set the config rules via an API
$donuts->rule('DONUTS_TEST_RULE_TTL')->config('minttl', 3200);

# we should be back to one more again
($rulecount, $errcount) = $donuts->analyze(9);
ok($errcount == 4, "4 errors were found in the after-config-set run (got: $errcount)");

# running at a lower level should drop us down again
($rulecount, $errcount) = $donuts->analyze(7);
ok($errcount == 3, "3 errors were found in the level 7 run (got: $errcount)");

# the default level (5) should be the same
($rulecount, $errcount) = $donuts->analyze();
ok($errcount == 3, "3 errors were found in the level <default> run (got: $errcount)");
ok($rulecount == 1, "1 rule was run in the level <default> run (got: $rulecount)");

# running at an even lower level should drop all warnings
($rulecount, $errcount) = $donuts->analyze(2);
ok($errcount == 0, "0 errors were found in the level 2 run (got: $errcount)");
ok($rulecount == 0, "0 rules were run in the level 2 run (got: $rulecount)");

# now explicitly remove a rule via the regexp setting
$donuts->set_ignore_list('TEST_DNS_NO_MX');
($rulecount, $errcount) = $donuts->analyze(9);
ok($errcount == 1, "1 errors were found in the ignore run (got: $errcount)");
ok($rulecount == 1, "1 rule was run in the ignore run (got: $rulecount)");
