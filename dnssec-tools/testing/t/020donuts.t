# This is -*- perl -*-

use strict;
use Test::Builder;

use File::Path;
use File::Copy;

require "$ENV{'BUILDDIR'}/testing/t/dt_testingtools.pl";

# verbosity check
use Getopt::Std;
my %options = ();
getopts("v",\%options);

# TEST object
my $test = Test::Builder->new;
$test->diag("Testing Donuts");
$test->plan( tests => 2);

#verbose setup for test object and dt_testingtools.
if (exists $options{v}) { $test->no_diag(0); dt_testingtools_verbose(1); }
else                    { $test->no_diag(1); dt_testingtools_verbose(0); }

my $zonesigner  = "$ENV{'BUILDDIR'}/tools/scripts/zonesigner";
my $donuts      = "$ENV{'BUILDDIR'}/tools/donuts/donuts";
my $donutsrules = "$ENV{'BUILDDIR'}/tools/donuts/rules/*";

my $testdir    = "$ENV{'BUILDDIR'}/testing/donuts/";
my $locallibpath = "$testdir/lib/Net/DNS/SEC/Tools/Donuts";
my $logfile    = "$ENV{'BUILDDIR'}/testing/donuts/test.log";

my $domain     = "example.com";
my $domainfile = $domain;
my $statedir   = "$testdir/tmp";


# Remove and create directory to work in (via creating the path to
# the state directory)

rmtree("$testdir",);
die "unable to remove \'$testdir\' directory: $!\n" if ( -e "$testdir" );

mkpath("$statedir",) or
  die "unable to make \'$statedir\' directory: $!\n";
mkpath("$locallibpath",) or
  die "unable to make \'$locallibpath\' directory: $!\n";
chdir "$testdir" or die "unable to change to \'$testdir\' directory: $!\n";

$ENV{'DT_STATEDIR'} = "$statedir";

# move test file over
copy ("../saved-example.com","example.com") or
  die "Unable to copy saved-example.com to example.com : $!\n";

copy ("$ENV{'BUILDDIR'}/tools/donuts/Rule.pm","$locallibpath/") or
  die "Unable to copy Rule.pm to local lib directory : $!\n";


# sign the zone file

my $keygen    = `which dnssec-keygen`;
my $zonecheck = `which named-checkzone`;
my $zonesign  = `which dnssec-signzone`;
chomp ($keygen, $zonecheck, $zonesign);

my $zonesigner_signzone = "perl -I$ENV{'BUILDDIR'}/tools/modules/blib/lib -I$ENV{'BUILDDIR'}/tools/modules/blib/arch $zonesigner -v -keygen $keygen -zonecheck $zonecheck -zonesign $zonesign -archivedir ./keyarchive -genkeys $domain >> $logfile 2>&1";

my $donuts_command = "perl -I$ENV{'BUILDDIR'}/tools/modules/blib/lib -I$ENV{'BUILDDIR'}/tools/modules/blib/arch -I$testdir/lib $donuts -v -C -r \'$donutsrules\' $domainfile.signed $domain >> $logfile 2>&1";

if (exists $options{v}) {
  print "zonesigner_signzone:\n$zonesigner_signzone\n";
  print "donuts_command:\n$donuts_command\n";
}


# tests

# sign zone

$test->is_eq(system("$zonesigner_signzone"), 0,
	     "donuts: signing \'$domainfile\' for donuts");

# run donuts

$test->is_eq(system("$donuts_command"), 0, "Checking donuts: donuts checking zone file \'$domainfile\'");


summary($test, "donuts");

exit(0);


# end MAIN
