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
