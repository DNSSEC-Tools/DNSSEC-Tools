#!/usr/bin/perl

use Test::More qw(no_plan);
use Data::Dumper;

######################################################################
BEGIN { use_ok('Net::DNS::SEC::Tools::Donuts'); }
require_ok('Net::DNS::SEC::Tools::Donuts');

my $donuts = new Net::DNS::SEC::Tools::Donuts();

my $result = $donuts->load_zone("t/db.example.com", "example.com");
ok($result == 0, "zone load produced no errors");

my $rrs = $donuts->zone_records();
ok($#$rrs > 0, "at least one record was parsed");
ok($rrs->[0]->name eq 'example.com', "the first record does contain a example.com record");
ok($rrs->[0]->type eq 'SOA', "the first record does contain an SOA record");

