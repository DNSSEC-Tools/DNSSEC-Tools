#!/usr/bin/perl

use Test::More qw(no_plan);
use Data::Dumper;
use Net::DNS::SEC::Tools::Donuts::Rule;

######################################################################
BEGIN { use_ok('Net::DNS::SEC::Tools::Donuts'); }
require_ok('Net::DNS::SEC::Tools::Donuts');

my $donuts = new Net::DNS::SEC::Tools::Donuts();
$donuts->set_output_location("file:/dev/null");

my $resultRef;

my $result = $donuts->load_zone("t/db.example.com", "example.com");
ok($result == 0, "zone load produced no errors");

$donuts->load_rule_files('t/donuts-test-rules.txt');

my $records = $donuts->find_records_by_name('www.example.com');
ok(defined($records), "something was returned by find_records_by_name");
ok(ref($records) eq 'HASH', "something was a hash");
ok($#{$records->{'MX'}} == 0, "data returned contains 1 MX record");
ok($#{$records->{'A'}} == 0, "data returned contains 1 A record");

my $records = donuts_records_by_name('www.example.com');
ok($#{$records->{'A'}} == 0, "data returned contains 1 A record from global");

