#!/usr/bin/perl

use Test::More qw(no_plan);
use XML::Simple;

######################################################################
BEGIN { use_ok('Net::DNS::SEC::Tools::TrustAnchor'); }
require_ok('Net::DNS::SEC::Tools::TrustAnchor');

my $tarfile = "t/itar.xml";

my ($mod, $file, $options) = parse_component("itar:$tarfile");

ok($mod, "parse_component failed of $tarfile");

my $tar = $mod->read();

ok($mod, "failed to read the tar from $tarfile");

#
# write it back out
#

my $outfile = "t/outtar.csv";
($mod, $file, $options) = parse_component("csv:$outfile");
ok($mod, "parse_component failed of $outfile");
$mod->write($tar, $file);

#
# read it in
#
($mod, $file, $options) = parse_component("csv:$outfile");
ok($mod, "parse_component failed of $outfile");
my $newtar = $mod->read();

#
# compare them deeply to ensure they're the same
#
is_deeply($newtar, $tar, "comparison of input and output data differ");

unlink($outfile);

ok(1, "didn't get to the end");
