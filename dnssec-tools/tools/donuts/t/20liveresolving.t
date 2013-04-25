#!/usr/bin/perl

use Test::More qw(no_plan);
use Data::Dumper;

######################################################################
BEGIN { use_ok('Net::DNS::SEC::Tools::Donuts'); }
require_ok('Net::DNS::SEC::Tools::Donuts');

my $donuts = new Net::DNS::SEC::Tools::Donuts();

# By default we don't do these tests unless we know it's ok
SKIP: {
    skip "set the donuts_live variable to do resolver tests", 1 unless ($ENV{'donuts_live'});

    my $rrs = [];
    if ($ENV{'donuts_live'}) {
	$rrs = $donuts->query_for_live_records("dnssec-tools.org", "www,good-a.test");
    }
    ok($#$rrs > 0, "quering for DNS records");
}
