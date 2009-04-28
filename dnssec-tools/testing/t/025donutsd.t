# This is -*- perl -*-

use strict;
use Test::More tests => 3;
use File::Copy;
use File::Path;

my %lconf  = ();
# $lconf{verbose} = 1;

my $zonesigner  = "$ENV{'BUILDDIR'}/tools/scripts/zonesigner";
my $donutsd     = "$ENV{'BUILDDIR'}/tools/donuts/donutsd";
my $donutsrules = "$ENV{'BUILDDIR'}/tools/donuts/rules/*";

my $testdir    = "$ENV{'BUILDDIR'}/testing/donutsd";
my $logfile    = "$ENV{'BUILDDIR'}/testing/donutsd/test.log";

my $domain     = "example.com";
my $domainfile = $domain;
my $statedir   = "$testdir/tmp";

my %donutsd_response = ( 
    "loops3" =>   q{running donuts on example.com.signed/example.com
  running: donuts -C -r '/home/baerm/snmp/svn-dnssec/trunk/dnssec-tools/tools/donuts/rules/*'   example.com.signed example.com > ./tmp/example.com.new 2>&1
  there was no data from a previous run
  output changed; mailing  about example.com.signed
  Warning: invalid mail address: mail can not be sent
  running: tail -1 ./tmp/example.com.new >> ./tmp/donuts.summary.new
  ./tmp/example.com.new => ./tmp/example.com
  ./tmp/donuts.summary.new => ./tmp/donuts.summary
sleeping for 10
running donuts on example.com.signed/example.com
  running: donuts -C -r '/home/baerm/snmp/svn-dnssec/trunk/dnssec-tools/tools/donuts/rules/*'   example.com.signed example.com > ./tmp/example.com.new 2>&1
  comparing results from last run
  running: tail -1 ./tmp/example.com.new >> ./tmp/donuts.summary.new
  ./tmp/example.com.new => ./tmp/example.com
  ./tmp/donuts.summary.new => ./tmp/donuts.summary
sleeping for 10
},
 );


#    ****    MAIN    ****

# Remove and create directory to work in (via creating the path to
# the state directory)

if ((!rmtree("$testdir",)) && ("No such file or directory" ne "$!")) {
  die "unable to remove \'$testdir\' directory: $!\n";
}
mkpath("$statedir",) or
  die "unable to make \'$statedir\' directory: $!\n";
chdir "$testdir" or die "unable to change to \'$testdir\' directory: $!\n";

$ENV{'DT_STATEDIR'} = "$statedir";

# move test file over
copy ("../saved-example.com","example.com") or
  die "Unable to copy saved-example.com to example.com : $!\n";


# testing

my $command = "perl -I$ENV{'BUILDDIR'}/tools/modules/blib/lib -I$ENV{'BUILDDIR'}/tools/modules/blib/arch $zonesigner -v -genkeys $domain >> /dev/null 2>&1";

is(system("$command"), 0, "Checking donutsd: zonesigner signing '$domainfile' for donutsd");


$command = "perl -I$ENV{'BUILDDIR'}/tools/modules/blib/lib  -I$ENV{'BUILDDIR'}/tools/modules/blib/arch  $donutsd --time-between-checks=10  --temporary-directory=$statedir --verbose  --donuts-arguments=\"-C -r '$donutsrules' \" -s '' -O 1 $domainfile.signed $domainfile ''   >> $logfile 2>&1";

# print STDERR "using command: $commandn";

print "       Checking a running donutsd, should take about 20 seconds\n";
is(system("$command"), 0, "Checking donutsd: running donutsd on zone file '$domainfile'");

my $log = parselog();
is($log, $donutsd_response{loops3}, "Checking donutsd: donutsd output");



#    **** procedures ****

sub parselog {
  #  $lconf{verbose} = 1;
  my $logtext = `cat $logfile`;
  print "before:\n$logtext\n" if (exists $lconf{verbose});

  $logtext =~ s/$testdir/./g;

  print "after:\n$logtext\n" if (exists $lconf{verbose});
  return $logtext;
}
