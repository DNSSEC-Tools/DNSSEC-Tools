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
$test->plan( tests => 2);

#verbose setup for test object and dt_testingtools.
if (exists $options{v}) { $test->no_diag(0); dt_testingtools_verbose(1); }
else                    { $test->no_diag(1); dt_testingtools_verbose(0); }


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
  dnsops.biz ...  refresh_secs=18, refresh_time=12
 Checking the live "dnsops.gov" key
  dnsops.gov ...  refresh_secs=18, refresh_time=12
 Checking the live "dnssec-tools.org" key
  dnssec-tools.org ...  refresh_secs=18, refresh_time=12
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

print "trustmand command :\n$trustman_command\n" if (exists $options{v});


# Tests

$test->is_eq(system("$trustman_command"), 0,
	     "trustman: examining \'dnsval.conf\'");

my $log = &parselog;
if (! do_ok($test, $log, $trustman_response{firsttest},
	    "trustman: output from examining \'dnsval.conf\'") ) {
  print"\tPossible Problems: \n";
  print"\t\tThe DNS used does not support DNSSEC (e.g. ISP, opendns.org).\n";
  print"\t\tThis host has an incorrect date (e.g. 1+ days incorrect).\n";
}


summary($test, "trustman");

exit(0);


# end MAIN


#  **** procedures ****


sub parselog {
  my $logtext = `cat $logfile`;
  #   print "before:\n$logtext\n"  if (exists $options{v});

  $logtext =~ s/secs=\d+,/secs=18,/g;
  $logtext =~ s/time=12(\d+)/time=12/g;
  $logtext =~ s/(\d\d)\d+ +seconds/\1 seconds/g;
  $logtext =~ s/Writing new keys to.*/Writing new keys to/g;

#   print "after:\n$logtext\n"  if (exists $options{v});
  return $logtext;
}

