#!/usr/bin/perl

use Test::More qw(no_plan);
use XML::Simple;

######################################################################
BEGIN { use_ok('Net::DNS::SEC::Tools::TrustAnchor'); }
require_ok('Net::DNS::SEC::Tools::TrustAnchor');

my $tarfile1 = "t/partial1.csv";
my $tarfile2 = "t/partial2.csv";
my $tarfilecomplete = "t/partialcomplete.csv";
my @tarfiles;

# load the first one
my ($mod, $file, $options) = parse_component("csv:$tarfile1");

ok($mod, "parse_component failed of $tarfile1");

my $tar1 = $mod->read();

ok($tar1, "failed to read the tar from $tarfile1");

# load the second one
($mod, $file, $options) = parse_component("csv:$tarfile2");

ok($mod, "parse_component failed of $tarfile2");

my $tar2 = $mod->read();

ok($tar2, "failed to read the tar from $tarfile2");

# merge them together
$tar1->merge($tar2);

# load the complete one to compare against
($mod, $file, $options) = parse_component("csv:$tarfilecomplete");

ok($mod, "parse_component failed of $tarfilecomplete");

my $tarcomplete = $mod->read();

ok($tarcomplete, "failed to read the tar from $tarfilecomplete");

#
# compare them deeply to ensure they're the same
#
is_deeply($tar1, $tarcomplete, "comparison of merged and expected TARs do not match");

ok(1, "didn't get to the end");
