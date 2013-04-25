#!/usr/bin/perl

use Test::More qw(no_plan);

######################################################################
BEGIN { use_ok('Net::DNS::SEC::Tools::Donuts'); }
require_ok('Net::DNS::SEC::Tools::Donuts');

my $donuts = new Net::DNS::SEC::Tools::Donuts();

# test ignore storage
$donuts->set_ignore_list('ignore', 'this');
my @ignores = $donuts->ignore_list();
ok(is_deeply(\@ignores, ['ignore', 'this']), "ignore list container");

# test features
$donuts->set_feature_list('feat1', 'feat2');
my @features = $donuts->feature_list();
ok(is_deeply(\@features, ['feat1', 'feat2']), "ignore list container");

# test config storage
$donuts->set_config('enable-testing', 'true');
ok(is($donuts->config('enable-testing'), 'true'), "config tester: stored");
ok(is($donuts->config('dne-config'), undef), "config tester: dne");
