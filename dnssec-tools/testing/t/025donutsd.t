# This is -*- perl -*-

use strict;
use Test::Builder;

use File::Copy;
use File::Path;

require "$ENV{'BUILDDIR'}/testing/t/dt_testingtools.pl";

# verbosity check
use Getopt::Std;
my %options = ();
getopts("v",\%options);

# TEST object
my $test = Test::Builder->new;
$test->plan( tests => 3);

#verbose setup for test object and dt_testingtools.
if (exists $options{v}) { $test->no_diag(0); dt_testingtools_verbose(1); }
else                    { $test->no_diag(1); dt_testingtools_verbose(0); }


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
  running: donuts -C -r '../../tools/donuts/rules/*'   example.com.signed example.com > ./tmp/example.com.new 2>&1
  there was no data from a previous run
  output changed; mailing  about example.com.signed
  Warning: invalid mail address: mail can not be sent
  running: tail -1 ./tmp/example.com.new >> ./tmp/donuts.summary.new
  ./tmp/example.com.new => ./tmp/example.com
  ./tmp/donuts.summary.new => ./tmp/donuts.summary
sleeping for 10
running donuts on example.com.signed/example.com
  running: donuts -C -r '../../tools/donuts/rules/*'   example.com.signed example.com > ./tmp/example.com.new 2>&1
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

rmtree("$testdir",);
die "unable to remove \'$testdir\' directory: $!\n" if ( -e "$testdir" );

mkpath("$statedir",) or
  die "unable to make \'$statedir\' directory: $!\n";
chdir "$testdir" or die "unable to change to \'$testdir\' directory: $!\n";

$ENV{'DT_STATEDIR'} = "$statedir";

# move test file over
copy ("../saved-example.com","example.com") or
  die "Unable to copy saved-example.com to example.com : $!\n";


# sign the zone file

my $keygen    = `which dnssec-keygen`;
my $zonecheck = `which named-checkzone`;
my $zonesign  = `which dnssec-signzone`;
chomp ($keygen, $zonecheck, $zonesign);

my $command = "perl -I$ENV{'BUILDDIR'}/tools/modules/blib/lib -I$ENV{'BUILDDIR'}/tools/modules/blib/arch $zonesigner -v -keygen $keygen -zonecheck $zonecheck -zonesign $zonesign -archivedir ./keyarchive -genkeys $domain >> /dev/null 2>&1";

$test->is_eq(system("$command"), 0, 
	     "donutsd: signing '$domainfile'");

# test donutsd

$command = "perl -I$ENV{'BUILDDIR'}/tools/modules/blib/lib  -I$ENV{'BUILDDIR'}/tools/modules/blib/arch  $donutsd --time-between-checks=10  --temporary-directory=$statedir --verbose  --donuts-arguments=\"-C -r '$donutsrules' \" -s '' -O 1 $domainfile.signed $domainfile ''   >> $logfile 2>&1";

# print STDERR "using command: $commandn";

print "       Checking a running donutsd, should take about 20 seconds\n";
$test->is_eq(system("$command"), 0, 
	     "donutsd: using zone file '$domainfile.signed'");

my $log = parselog();
do_is($test, $log, $donutsd_response{loops3}, 
      "donutsd: donutsd output");


summary($test, "donutsd");

exit(0);


# end MAIN


#    **** procedures ****


sub parselog {
  my $logtext = `cat $logfile`;
#   print "before:\n$logtext\n"  if (exists $options{v});

  $logtext =~ s/$testdir/./g;
  $logtext =~ s/$ENV{'BUILDDIR'}/..\/../g;

#   print "after:\n$logtext\n"  if (exists $options{v});
  return $logtext;
}
