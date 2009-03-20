# This is -*- perl -*-

use strict;
use Test::More tests => 2;

my $zonesigner  = "$ENV{'BUILDDIR'}/tools/scripts/zonesigner";
my $donuts      = "$ENV{'BUILDDIR'}/tools/donuts/donuts";
my $donutsrules = "$ENV{'BUILDDIR'}/tools/donuts/rules/*";

my $testdir    = "$ENV{'BUILDDIR'}/testing/donuts/";
my $logfile    = "$ENV{'BUILDDIR'}/testing/donuts/test.log";

my $domain     = "example.com";
my $domainfile = $domain;
my $statedir   = "tmp";

chdir "$testdir" or die "unable to change to \'$testdir\' directory: $!\n";

# State directory needed to run an uninstalled dnssec.
# Remove the local state directory, create a new one, set
# environmental variable.
rmdir "$statedir";
mkdir "$statedir" or die "unable to create \'$statedir\' directory: $!\n";
$ENV{'DT_STATEDIR'} = "$statedir";


# Cleanup any earlier created files
opendir DIRH, "."; my @dirlist = readdir DIRH; closedir DIRH;
@dirlist = grep /((keyset|dsset)-$domainfile\.|($domainfile\.(krf|signed|zs))|(K$domainfile\..*\.(key|private)))$/, @dirlist;
unlink @dirlist;
unlink $logfile;


my $command = "perl -I$ENV{'BUILDDIR'}/tools/modules/blib/lib -I$ENV{'BUILDDIR'}/tools/modules/blib/arch $zonesigner -v -genkeys $domain >> $logfile 2>&1";

is(system("$command"), 0, "Checking donuts: zonesigner signing \'$domainfile\' for donuts");


$command = "perl -I$ENV{'BUILDDIR'}/tools/modules/blib/lib -I$ENV{'BUILDDIR'}/tools/modules/blib/arch  $donuts -C -r \'$donutsrules\' $domainfile.signed $domain >> $logfile 2>&1";

is(system("$command"), 0, "Checking donuts: donuts checking zone file \'$domainfile\'");
