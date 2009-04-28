# This is -*- perl -*-

use strict;
use Test::More tests => 2;
use File::Path;
use File::Copy;

my $zonesigner  = "$ENV{'BUILDDIR'}/tools/scripts/zonesigner";
my $donuts      = "$ENV{'BUILDDIR'}/tools/donuts/donuts";
my $donutsrules = "$ENV{'BUILDDIR'}/tools/donuts/rules/*";

my $testdir    = "$ENV{'BUILDDIR'}/testing/donuts/";
my $logfile    = "$ENV{'BUILDDIR'}/testing/donuts/test.log";

my $domain     = "example.com";
my $domainfile = $domain;
my $statedir   = "$testdir/tmp";


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

my $command = "perl -I$ENV{'BUILDDIR'}/tools/modules/blib/lib -I$ENV{'BUILDDIR'}/tools/modules/blib/arch $zonesigner -v -genkeys $domain >> $logfile 2>&1";

is(system("$command"), 0, "Checking donuts: zonesigner signing \'$domainfile\' for donuts");


$command = "perl -I$ENV{'BUILDDIR'}/tools/modules/blib/lib -I$ENV{'BUILDDIR'}/tools/modules/blib/arch  $donuts -C -r \'$donutsrules\' $domainfile.signed $domain >> $logfile 2>&1";

is(system("$command"), 0, "Checking donuts: donuts checking zone file \'$domainfile\'");
