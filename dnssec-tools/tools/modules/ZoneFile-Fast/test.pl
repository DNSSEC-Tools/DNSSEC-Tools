#!/usr/bin/perl

use Net::DNS::ZoneFile::Fast;

my $rrset = Net::DNS::ZoneFile::Fast::parse(file => ($ARGV[0] || "/home/hardaker/src/dnssec/testzone/example.com.signed.signed"),
					    origin => "example.com",
					    soft_errors => 1,
					    on_error => \&print_parse_error);

print $#$rrset,"\n";

sub print_parse_error { print STDERR "hererr\n"; }
