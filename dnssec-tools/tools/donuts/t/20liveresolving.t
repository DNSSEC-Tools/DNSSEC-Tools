#!/usr/bin/perl

use Test::More qw(no_plan);
use Data::Dumper;

######################################################################
BEGIN { use_ok('Net::DNS::SEC::Tools::Donuts'); }
require_ok('Net::DNS::SEC::Tools::Donuts');

my $donuts = new Net::DNS::SEC::Tools::Donuts();

# By default we don't do these tests unless we know it's ok
SKIP: {
    skip "set the donuts_live variable to do resolver tests", 5 unless ($ENV{'donuts_live'});

    # run an individual query
    my $rrs = [];
    $rrs = $donuts->query_for_live_records("dnssec-tools.org", "www");
    ok($#$rrs > 0, "quering for DNS records");

    # test the live interface
    my $result = $donuts->load_zone("live:good-a,good-aaaa:aaaa", "test.dnssec-tools.org");
    ok($result == 0, "live zone load produced no errors");

    $rrs = $donuts->zone_records();
    ok($#$rrs > 0, "at least one record was parsed");
    ok($rrs->[0]->name eq 'test.dnssec-tools.org', "the first record does contain a test.example.com record");
    ok($rrs->[0]->type eq 'DNSKEY', "the first record does contain a DNSKEY record");
}
