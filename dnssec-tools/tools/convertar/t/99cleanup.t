#!/usr/bin/perl

use Test::More qw(no_plan);
use XML::Simple;

if (!$ENV{'DTNOCLEAN'}) {
    unlink(<t/tmp.*>);
}

ok(1);
