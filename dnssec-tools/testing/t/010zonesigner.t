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
$test->diag("Testing Zonesigner");
$test->plan( tests => 4);

#verbose setup for test object and dt_testingtools.
if (exists $options{v}) { $test->no_diag(0); dt_testingtools_verbose(1); }
else                    { $test->no_diag(1); dt_testingtools_verbose(0); }


my $zonesigner  = "$ENV{'BUILDDIR'}/tools/scripts/zonesigner";

my $testdir    = "$ENV{'BUILDDIR'}/testing/zones/";
my $logfile    = "$ENV{'BUILDDIR'}/testing/zones/test.log";

my $domain     = "example.com";
my $domainfile = $domain;
my $statedir   = "$testdir/tmp";

my $bindnsec3version = "9.6";

my %zonesigner_response = (
    "gentest" =>   q{    using default keyrec file example.com.krf
    checking options and arguments
    using keyrec file example.com.krf
    check existence of zone file
    initial zone verification

     if zonesigner appears hung, strike keys until the program completes
     (see the "Entropy" section in the man page for details)

    generating key files
    adding key includes to zone file
    signing zone
Verifying the zone using the following algorithms: RSASHA1.
Zone signing complete:
Algorithm: RSASHA1: ZSKs: 2, KSKs: 1 active, 0 revoked, 0 stand-by
    checking zone

zone signed successfully

example.com:
     KSK (cur) 12345  -b 2048  01/01/01     (example.com-signset-00003)
     ZSK (cur) 12345  -b 2048  01/01/01     (example.com-signset-00001)
     ZSK (pub) 12345  -b 2048  01/01/01     (example.com-signset-00002)

zone will expire in 4 weeks, 2 days, 0 seconds
DO NOT delete the keys until this time has passed.
},
    "nsec3test" =>   q{    using default keyrec file nsec3.example.com.krf
    checking options and arguments
    using keyrec file nsec3.example.com.krf
    check existence of zone file
    initial zone verification

     if zonesigner appears hung, strike keys until the program completes
     (see the "Entropy" section in the man page for details)

    generating key files
    adding key includes to zone file
    signing zone
Verifying the zone using the following algorithms: NSEC3RSASHA1.
Zone signing complete:
Algorithm: NSEC3RSASHA1: ZSKs: 2, KSKs: 1 active, 0 revoked, 0 stand-by
    checking zone

zone signed successfully

nsec3.example.com:
     KSK (cur) 12345  -b 2048  01/01/01     (nsec3.example.com-signset-00003)
     ZSK (cur) 12345  -b 2048  01/01/01     (nsec3.example.com-signset-00001)
     ZSK (pub) 12345  -b 2048  01/01/01     (nsec3.example.com-signset-00002)

zone will expire in 4 weeks, 2 days, 0 seconds
DO NOT delete the keys until this time has passed.
}
);



# MAIN


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

copy ("../saved-nsec3.example.com","nsec3.example.com") or
  die "Unable to copy saved-nsec3.example.com to nsec3.example.com : $!\n";

# run zonesigner

my $keyarch   = "$ENV{'BUILDDIR'}/tools/scripts/keyarch";
my $keygen    = `which dnssec-keygen`;
my $zonecheck = `which named-checkzone`;
my $zonesign  = `which dnssec-signzone`;
chomp ($keygen, $zonecheck, $zonesign);

my $gencommand = "perl -I$ENV{'BUILDDIR'}/tools/modules/blib/lib -I$ENV{'BUILDDIR'}/tools/modules/blib/arch $zonesigner -v -keyarch $keyarch -keygen $keygen -zonecheck $zonecheck -zonesign $zonesign -archivedir ./keyarchive -genkeys $domain >> $logfile 2>&1";

# generate new keys in order to support nsec3
my $nsec3command = "perl -I$ENV{'BUILDDIR'}/tools/modules/blib/lib -I$ENV{'BUILDDIR'}/tools/modules/blib/arch $zonesigner -v -keyarch $keyarch -keygen $keygen -zonecheck $zonecheck -zonesign $zonesign -archivedir ./keyarchive -algorithm nsec3rsasha1 -genkeys -usensec3 nsec3.$domain >> $logfile 2>&1";

if (exists $options{v}) {
  print "general command:\n$gencommand\n";
  print "nsec3 command:\n$nsec3command\n";
}

$test->is_eq(system("$gencommand"), 0,
	     "zonesigner: signing \'$domainfile\'");

my $log = &parselog;
do_is($test, $log, $zonesigner_response{gentest},
      "zonesigner: output of signing: \'$domainfile\'");


unlink "$logfile";


my $bindversion = dnssecsignzone_version();
if ($bindversion < $bindnsec3version) {
  print "       NSEC3 requires bind version >= $bindnsec3version (current v$bindversion)\n";
  $test->skip("NSEC3 not supported");
  $test->skip("NSEC3 not supported");
}
else {
  $test->is_eq(system("$nsec3command"), 0,
	       "zonesigner: signing with nsec3 \'nsec3.$domainfile\'");
  $log = &parselog;
  do_is($test, $log, $zonesigner_response{nsec3test},
	"zonesigner: output of nsec3 signing : \'nsec3.$domainfile\'");
}

summary($test, "zonesigner");

exit(0);


# end MAIN


####    **** procedures ****    ####


sub parselog {
  my $logtext = `cat $logfile`;
#   print "before:\n$logtext\n"  if (exists $options{v});

  $logtext =~ s/\d+\/\d+\/\d+/01\/01\/01/g;
  $logtext =~ s/\((cur|pub)\) \d\d\d\d\d  -b \d\d\d\d/(\1) 12345  -b 2048/g;
  $logtext =~ s/\d+ +seconds/0 seconds/g;
  $logtext =~ s/\t/     /g;
  # commands not currently used by zonesigner, but searched for by
  # configuration modules
  $logtext =~ s/^command ".*\/(keyarch|rndc|rollrec-check)" does not exist; please install(.*)\n//g;

#   print "after:\n$logtext\n"  if (exists $options{v});
  return $logtext;
}


sub dnssecsignzone_version {
  my $version = 0;
  my $resp = `dnssec-signzone -h 2>&1`;
  if ($resp =~ /Version: +([0-9.]+)/ ) {
    $version = sprintf("%.1f", $1);
  }
  return $version;
}
