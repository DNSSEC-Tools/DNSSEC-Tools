# This is -*- perl -*-

use strict;
use Test::More tests => 2;
use File::Path;
use File::Copy;

my %lconf  = ();
# $lconf{verbose} = 1;

my $trustman    = "$ENV{'BUILDDIR'}/tools/scripts/trustman";

my $etcfiles    = "$ENV{'BUILDDIR'}/validator/etc";
my $testdir     = "$ENV{'BUILDDIR'}/testing/trustman";
my $locallibpath = "$testdir/lib/Net/DNS/SEC";
my $statedir    = "$testdir/tmp";

my $logfile     = "$testdir/trustman.log";
my $anchor_data = "$testdir/anchor_data";

my $libvalpath  = "$ENV{'BUILDDIR'}/validator/libval/.libs";
my $libsrespath  = "$ENV{'BUILDDIR'}/validator/libsres/.libs";

$ENV{'LD_LIBRARY_PATH'} = "$libvalpath:$libsrespath";


my %trustman_response = (
    "firsttest" =>   q{Reading and parsing trust keys from ./dnsval.conf
 Found a key for dnssec-tools.org
 Found a key for dnsops.gov
 Found a key for dnsops.biz
 Checking zone keys for validity
 Checking the live "dnsops.biz" key
  dnsops.biz ...  refresh_secs=1800, refresh_time=12
 Checking the live "dnsops.gov" key
  dnsops.gov ...  refresh_secs=1800, refresh_time=12
 Checking the live "dnssec-tools.org" key
  dnssec-tools.org ...  refresh_secs=43200, refresh_time=12
  adding holddown for new key in dnssec-tools.org (12 seconds from now)
vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv
A new key has been received for zone dnssec-tools.org.
   It will be added when the add holddown time is reached.
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Writing new keys to
checking new keys for timing
 hold down timer for dnssec-tools.org still in the future (25 seconds)
}
);


# MAIN


# Remove and create directory to work in (via creating the path to
# the state directory)

!rmtree("$testdir",);
die "unable to remove \'$testdir\' directory: $!\n" if ( -e "$testdir" );

mkpath("$statedir",) or
  die "unable to make \'$statedir\' directory: $!\n";
mkpath("$locallibpath",) or
  die "unable to make \'$locallibpath\' directory: $!\n";
chdir "$testdir" or die "unable to change to \'$testdir\' directory: $!\n";

$ENV{'DT_STATEDIR'} = "$statedir";

# setup default files
copy ("$etcfiles/dnsval.conf","dnsval.conf") or
  die "Unable to copy $etcfiles/dnsval.conf to dnsval.conf : $!\n";
copy ("$etcfiles/root.hints","root.hints") or
  die "Unable to copy $etcfiles/root.hints to root.hints : $!\n";
copy ("$etcfiles/resolv.conf","resolv.conf") or
  die "Unable to copy $etcfiles/resolv.conf to resolv.conf : $!\n";
`touch $anchor_data`;
copy ("$ENV{'BUILDDIR'}/tools/modules/Net-DNS-SEC-Validator/Validator.pm","$locallibpath/")
  or die "Unable to copy Validator.pm to local lib directory : $!\n";


# commands

my $trustman_command = "perl -I$ENV{'BUILDDIR'}/tools/modules/blib/lib -I$ENV{'BUILDDIR'}/tools/modules/blib/arch -I$testdir/lib $trustman -k ./dnsval.conf -S -f -v -p --nomail --smtp_server localhost --anchor_data_file $anchor_data --resolv_conf ./resolv.conf -o ./root.hints --tmp_dir $statedir >> $logfile 2>&1 ";

# print "trustmand command :\n$trustman_command\n";

# Tests


is(system("$trustman_command"), 0,
   "Checking trustman: trustman examining \'dnsval.conf\'");

my $log = &parselog;
is($log, $trustman_response{firsttest},
   "Checking trustman: checking the output from examining \'dnsval.conf\'");




#  **** procedures ****

sub parselog {
#  $lconf{verbose} = 1;
  my $logtext = `cat $logfile`;
  print "before:\n$logtext\n" if (exists $lconf{verbose});

  $logtext =~ s/time=12(\d+)/time=12/g;
  $logtext =~ s/(\d\d)\d+ +seconds/\1 seconds/g;
  $logtext =~ s/Writing new keys to.*/Writing new keys to/g;
  print "after:\n$logtext\n" if (exists $lconf{verbose});
  return $logtext;
}

