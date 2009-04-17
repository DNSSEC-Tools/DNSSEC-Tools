# This is -*- perl -*-

use strict;
use Test::More tests => 1;

my $zonesigner  = "$ENV{'BUILDDIR'}/tools/scripts/zonesigner";

my $testdir    = "$ENV{'BUILDDIR'}/testing/zones/";
my $logfile    = "$ENV{'BUILDDIR'}/testing/zones/test.log";

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
# print "$command\n";
is(system("$command"), 0, "Checking zonesigner: signing \'$domainfile\'");

