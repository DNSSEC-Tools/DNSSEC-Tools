#!/usr/bin/perl

use Test::More qw(no_plan);
use Data::Dumper;
use Net::DNS::SEC::Tools::Donuts::Rule;

######################################################################
BEGIN { use_ok('Net::DNS::SEC::Tools::Donuts'); }
require_ok('Net::DNS::SEC::Tools::Donuts');

my $have_json = eval 'require Test::JSON;';
my $have_xml = eval 'require XML::Simple;';

my $donuts = new Net::DNS::SEC::Tools::Donuts();

my $resultRef;

my $result = $donuts->load_zone("t/db.example.com", "example.com");
ok($result == 0, "zone load produced no errors");

$donuts->load_rule_files('t/donuts-test-rules.txt');
my @rules = $donuts->rules();

#
# JSON
#
SKIP: {
    skip "Test::JSON is required for testing json output", 2 unless ($have_xml);

    import Test::JSON;

    $donuts->set_output_format('json');
    $donuts->set_output_location('string', \$resultRef);
    $donuts->output()->allow_comments(0);
    $donuts->analyze(9);

    ok(length($$resultRef) > 0, "output received");

    is_valid_json($$resultRef, "json is valid");
}

#
# XML
#
SKIP: {
    skip "XML::Simple is requried for testing XML output", 3 unless ($have_xml);

    import XML::Simple;

    $donuts->set_output_format('xml');
    $donuts->set_output_location('string', \$resultRef);
    $donuts->output()->allow_comments(0);
    $donuts->analyze(9);

    ok(length($$resultRef) > 0, "output received");

    my $parsed = XMLin($$resultRef);
    ok(ref($parsed) eq 'HASH', "result is a valid hash");
    ok(exists($parsed->{'Donuts-Results'}), "XML results exist");
}

#
# Perl
#
$resultRef = undef;
$donuts->set_output_format('perl');
$donuts->set_output_location('perl', \$resultRef);
ok(defined($resultRef), "perl output defined");
ok(ref($resultRef) eq 'HASH', "perl output defined to a hash");

$donuts->analyze(9);

ok(exists($resultRef->{'Donuts Results'}), "perl results exist");
ok(exists($resultRef->{'Donuts Results'}), "perl results exist");
ok($#{$resultRef->{'Donuts Results'}{'Record Results'}} == 0, "1 record result");
ok($#{$resultRef->{'Donuts Results'}{'Name Results'}} == 2, "3 name results");

