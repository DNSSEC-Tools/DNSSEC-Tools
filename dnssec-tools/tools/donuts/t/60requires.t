#!/usr/bin/perl

use Test::More qw(no_plan);
use Data::Dumper;
use Net::DNS::SEC::Tools::Donuts::Rule;

######################################################################
BEGIN { use_ok('Net::DNS::SEC::Tools::Donuts'); }
require_ok('Net::DNS::SEC::Tools::Donuts');

use lib "t/lib";

my $donuts = new Net::DNS::SEC::Tools::Donuts();
$donuts->set_output_location("file:/dev/null");

my $resultRef;

my $result = $donuts->load_zone("t/db.example.com", "example.com");
ok($result == 0, "zone load produced no errors");

$donuts->load_rule_files('t/donuts-test-requires.txt');
my @rules = $donuts->rules();

my ($rulecount, $errcount) = $donuts->analyze(9);
ok($rulecount == 2, "2 rules were executed (got: $rulecount)");

# only one of the two loaded rules should fail
ok($errcount == 1, "9 errors were produced (got: $errcount)");



