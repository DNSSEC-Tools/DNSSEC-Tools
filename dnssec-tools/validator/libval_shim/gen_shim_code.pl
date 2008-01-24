#!/usr/bin/perl

use Getopt::Std;

our $header_tmpl = <<'HTMPL';
#include <stdio.h>

#define __USE_GNU // This is needed for the RTLD_NEXT definition
#include <stdlib.h>
#include <dlfcn.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <netinet/in.h>
#include <resolv.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>

HTMPL

our $func_tmpl = <<'FTMPL';

%ret%
%func%(%args%)
{
  int (*lib_%func%)(%args%);
  char *error;

  lib_%func% = dlsym(RTLD_NEXT, "%func%");

  if ((error = dlerror()) != NULL) {
    fprintf(stderr, "unable to load %func%: %s\n", error);
    exit(1);
  }

  fprintf(stderr, "libval_shim: %func% called: pass-thru\n");

  return (%ret%)lib_%func%(%vals%);
}


FTMPL

our $nfunc_tmpl = <<'NFTMPL';

%ret%
%func%(%args%)
{
  // int (*lib_%func%)(%args%);
  // char *error;

  // lib_%func% = dlsym(RTLD_NEXT, "%func%");
  //
  // if ((error = dlerror()) != NULL) {
  //   fprintf(stderr, "unable to load %func%: %s\n", error);
  //   exit(1);
  // }

  fprintf(stderr, "libval_shim: %func%: called: not-avail\n");

  return (%ret%)NULL;
}

NFTMPL

getopts("Ff:o:");

our $infile = $opt_f || "./libval_shim.funcs";
our $outfile = $opt_o || "./libval_shim.c";
our $force = $opt_F;

open(IN,"<$infile") or die "unable to open \"$infile\" for input\n";
if (-f $outfile and not $force) {
  die "\"$outfile\" exists and would be overwritten. aborting..\n";
}
open(OUT,">$outfile") or die "unable to open \"$outfile\" for output\n";

while (<IN>) {
  next if /^\s*\#/ or /^\s*$/;
  my ($ret, $func, $args, $not_avail) =  /^\s*(.*?)\s*(\w+)\s*\(\s*([^\)]+)\s*\)\s*\;\s*(\%not-avail\%)?\s*$/;
  my $vals = join(', ', map(/^.*?(\w+)$/, split(/\s*,\s*/, $args)));
  undef $vals if $vals =~ /^\s*void\s*$/;
  push(@funcs, [$ret, $func, $args, $vals, $not_avail])
}
close(IN);

print OUT $header_tmpl;
foreach $func (@funcs) {
  $out = ($func->[4] ? $nfunc_tmpl : $func_tmpl);
  $out =~ s/\%ret\%/$func->[0]/g;
  $out =~ s/\%func\%/$func->[1]/g;
  $out =~ s/\%args\%/$func->[2]/g;
  $out =~ s/\%vals\%/$func->[3]/g;
  print OUT $out;
}
close(OUT);
