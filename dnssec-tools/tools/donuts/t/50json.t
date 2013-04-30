#!/usr/bin/perl

use Test::More qw(no_plan);
use Data::Dumper;
use Net::DNS::SEC::Tools::Donuts::Rule;

######################################################################
BEGIN { use_ok('Net::DNS::SEC::Tools::Donuts'); }
require_ok('Net::DNS::SEC::Tools::Donuts');

my $have_json = eval 'require Test::JSON;';

SKIP: {
    skip "set the donuts_live variable to do resolver tests", 3 unless ($have_json);

    import Test::JSON;

    my $donuts = new Net::DNS::SEC::Tools::Donuts();

    my $resultRef;
    $donuts->set_output_format('json');
    $donuts->set_output_location('string', \$resultRef);
    $donuts->output()->allow_comments(0);

    my $result = $donuts->load_zone("t/db.example.com", "example.com");
    ok($result == 0, "zone load produced no errors");

    $donuts->load_rule_files('t/donuts-test-rules.txt');
    my @rules = $donuts->rules();

    $donuts->analyze(9);

    ok(length($$resultRef) > 0, "output received");
    is_valid_json($$resultRef, "json is valid");
}


