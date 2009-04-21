#!/usr/bin/perl

use Test::More qw(no_plan);
use XML::Simple;

######################################################################
BEGIN { use_ok('Net::DNS::SEC::Tools::TrustAnchor'); }
require_ok('Net::DNS::SEC::Tools::TrustAnchor');

# XXX: currently bind doesn't handle DS records as trust anchors
my $tarfile = "t/itar-nods.xml";

my ($mod, $file, $options) = parse_component("itar:$tarfile");

ok($mod, "parse_component failed of $tarfile");

my $tar = $mod->read();

ok($mod, "failed to read the tar from $tarfile");

#
# write it back out
#

my $outfile = "t/tmp.outbind.conf";
($mod, $file, $options) = parse_component("bind:$outfile");
ok($mod, "parse_component failed of $outfile");
$mod->write($tar, $file);

#
# read it in
#
($mod, $file, $options) = parse_component("bind:$outfile");
ok($mod, "parse_component failed of $outfile");
my $newtar = $mod->read();

#
# compare them deeply to ensure they're the same
#
is_deeply($newtar, $tar, "comparison of input and output data differ");

ok(1, "didn't get to the end");
