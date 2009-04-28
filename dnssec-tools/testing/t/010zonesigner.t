# This is -*- perl -*-

use strict;
use Test::More tests => 1;
use File::Copy;
use File::Path;

my $zonesigner  = "$ENV{'BUILDDIR'}/tools/scripts/zonesigner";

my $testdir    = "$ENV{'BUILDDIR'}/testing/zones/";
my $logfile    = "$ENV{'BUILDDIR'}/testing/zones/test.log";

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


my $command = "perl -I$ENV{'BUILDDIR'}/tools/modules/blib/lib -I$ENV{'BUILDDIR'}/tools/modules/blib/arch $zonesigner -v -genkeys $domain >> $logfile 2>&1";
# print "$command\n";
is(system("$command"), 0, "Checking zonesigner: signing \'$domainfile\'");

