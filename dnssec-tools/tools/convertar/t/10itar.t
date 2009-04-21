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


my $outfile = "t/tmp.outtar.xml";
($mod, $file, $options) = parse_component("itar:$outfile");
ok($mod, "parse_component failed of $outfile");
$mod->write($tar, $file);

#
# now read them both in and compare them deeply to ensure they're the same
#
my $f1 = XMLin($tarfile);
my $f2 = XMLin($outfile);

is_deeply($f2, $f1, "comparison of input and output XML structures differ");

ok(1, "didn't get to the end");
