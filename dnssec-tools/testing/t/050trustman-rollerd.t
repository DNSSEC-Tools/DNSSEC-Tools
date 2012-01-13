# This is -*- perl -*-

use strict;
use Test::Builder;

use File::Copy qw( copy );
use File::Path qw( rmtree mkpath);

unshift @INC, "$ENV{'BUILDDIR'}/tools/modules/blib/arch";
unshift @INC, "$ENV{'BUILDDIR'}/tools/modules/blib/lib";
use Net::DNS::SEC::Validator;

require "$ENV{'BUILDDIR'}/testing/t/dt_testingtools.pl";

my $buildloc = dt_strip_dots("$ENV{BUILDDIR}");

#SIGNAL CATCHING
$SIG{INT}  = sub { &local_cleanup(); exit; };
$SIG{TERM} = sub { &local_cleanup(); exit; };

# verbosity check
use Getopt::Std;
my %options = ();
getopts("vV",\%options);

# $options{V} =1;  # extra local verbosity

# TEST object
my $test = Test::Builder->new;
$test->diag("Testing Trustman interacting with Rollerd");
$test->plan( tests => 24);

#verbose setup for test object and dt_testingtools.
if (exists $options{v}) { $test->no_diag(0); dt_testingtools_verbose(1); }
else                    { $test->no_diag(1); dt_testingtools_verbose(0); }
dt_testingtools_bail(1,\&local_cleanup);

# Variables

my $testdir    = "$buildloc/testing/trustman-rollerd";

# Note: $statedir uses a relative path because socket names get
# truncated if the path is too long (rollctl can not communicate to
# rollerd)

my $statedir   = "./tmp";

# rollerd variables

my $zonesigner = "$buildloc/tools/scripts/zonesigner";
my $rollerd    = "$buildloc/tools/scripts/rollerd";
my $rollctl    = "$buildloc/tools/scripts/rollctl";

my $dt_plibs   = "$buildloc/tools/modules/blib/lib";
my $dt_parch   = "$buildloc/tools/modules/blib/arch";

my $rlogfile   = "$testdir/rollerd.log";
my $phaselog   = "$testdir/phase.log";

my $domain     = "example.com";
my $domainfile = $domain;

my $pidfile    = "$testdir/rollmgr.pid";
my $archivedir = "$testdir/keyarchive";

$ENV{'PERL5LIB'} = "$dt_plibs:$dt_parch";

# trustman variables

my $trustman    = "$buildloc/tools/scripts/trustman";
my $etcfiles    = "$buildloc/validator/etc";

my $tlogfile    = "$testdir/trustman.log";
my $anchor_data = "$testdir/anchor_data";

my $libvalpath  = "$buildloc/validator/libval/.libs";
my $libsrespath = "$buildloc/validator/libsres/.libs";

$ENV{'LD_LIBRARY_PATH'} = "$libvalpath:$libsrespath";

# validation/trustman variables

my $resconffile   = "./resolv.conf";
my $dnsvalfile    = "./dnsval.conf";
my $dnsvaloldkey  = "./dnsval.conf.oldkey";
my $roothintsfile = "./root.hints";

use Net::DNS::SEC::Validator;

# check for bind commands
my $keygen    = `which dnssec-keygen`;
my $zonecheck = `which named-checkzone`;
my $zonesign  = `which dnssec-signzone`;
my $named     = `which named`;
my $rndc      = `which rndc`;
chomp ($keygen, $zonecheck, $zonesign, $named, $named, $rndc);

if (!( -x $keygen && -x $zonecheck && -x $zonesign &&
       -x $named && -x $rndc )) {
  die "Unable to execute/find 1+ of: $keygen, $zonecheck, $zonesign, $named, or $rndc\n\n\tA Bind installation is required for this test.\n";
}


my $zsargs = "-v -nodroprevoke -keygen $keygen -zonecheck $zonecheck -zonesign $zonesign -archivedir $archivedir -szopts -P -zskcount 1 -kskcount 1";
my $zsargs_resp   = parsepstring($zsargs);


my %rollerd_response = ( 
    "ksk1" =>   q{ rollerd starting ----------------------------------------
 rollerd parameters:
 rollrec file "../../testing/trustman-rollerd/example.rollrec"
 directory "../../testing/trustman-rollerd"
 config file "./dnssec-tools.conf"
 logfile "../../testing/trustman-rollerd/phase.log"
 loglevel "info"
 logtz ""
 single-run "1"
 zone reload "1"
 event method "Full List"
 
 
 Using the full_list_event_loop() processor!!!
 example.com: adding missing zonename field (example.com) to rollrec
 example.com: creating new ksk_rollsecs record and forcing KSK rollover
 example.com: KSK phase 1
 rollover manager shutting down at end of single-run execution
 rollover manager shutting down...
},

    "ksk23" =>  qq{ rollerd starting ----------------------------------------
 rollerd parameters:
 rollrec file "../../testing/trustman-rollerd/example.rollrec"
 directory "../../testing/trustman-rollerd"
 config file "./dnssec-tools.conf"
 logfile "../../testing/trustman-rollerd/phase.log"
 loglevel "info"
 logtz ""
 single-run "1"
 zone reload "1"
 event method "Full List"
 
 
 Using the full_list_event_loop() processor!!!
 example.com: KSK phase 2
 example.com: executing "../../tools/scripts/zonesigner -dtconfig ./dnssec-tools.conf -newpubksk $zsargs_resp -krf example.com.krf example.com example.com.signed"
 example.com: reloading zone for KSK phase 2
 example.com: KSK phase 2: unable to reload zone, rc - 1
 example.com: KSK phase 3
 example.com: KSK phase 3; cache expires in minutes, seconds
 rollover manager shutting down at end of single-run execution
 rollover manager shutting down...
},
    "ksk46" => qq{ rollerd starting ----------------------------------------
 rollerd parameters:
 rollrec file "../../testing/trustman-rollerd/example.rollrec"
 directory "../../testing/trustman-rollerd"
 config file "./dnssec-tools.conf"
 logfile "../../testing/trustman-rollerd/phase.log"
 loglevel "info"
 logtz ""
 single-run ""
 zone reload "1"
 event method "Full List"
 
 
 Using the full_list_event_loop() processor!!!
 example.com: KSK phase 4
 example.com: executing "../../tools/scripts/zonesigner -dtconfig ./dnssec-tools.conf -rollksk -v -nodroprevoke -keygen /opt/local/sbin/dnssec-keygen -zonecheck /opt/local/sbin/named-checkzone -zonesign /opt/local/sbin/dnssec-signzone -archivedir ../../testing/trustman-rollerd/keyarchive -szopts -P -zskcount 1 -kskcount 1 -krf example.com.krf example.com example.com.signed"
 example.com: KSK phase 5
 example.com: KSK phase 5: admin notified to transfer keyset
 example.com: KSK phase 6
 example.com: KSK phase 6: waiting for parental publication of DS record
},
    "ksk7" => qq{ rollerd starting ----------------------------------------
 rollerd parameters:
 rollrec file "../../testing/trustman-rollerd/example.rollrec"
 directory "../../testing/trustman-rollerd"
 config file "./dnssec-tools.conf"
 logfile "../../testing/trustman-rollerd/phase.log"
 loglevel "info"
 logtz ""
 single-run ""
 zone reload "1"
 event method "Full List"
 
 
 Using the full_list_event_loop() processor!!!
 example.com: KSK phase 4
 example.com: executing "../../tools/scripts/zonesigner -dtconfig ./dnssec-tools.conf -rollksk -v -nodroprevoke -keygen /opt/local/sbin/dnssec-keygen -zonecheck /opt/local/sbin/named-checkzone -zonesign /opt/local/sbin/dnssec-signzone -archivedir ../../testing/trustman-rollerd/keyarchive -szopts -P -zskcount 1 -kskcount 1 -krf example.com.krf example.com example.com.signed"
 example.com: KSK phase 5
 example.com: KSK phase 5: admin notified to transfer keyset
 example.com: KSK phase 6
 example.com: KSK phase 6: waiting for parental publication of DS record
 example.com: KSK phase 7
},
    "kskhalt" => qq{ rollerd starting ----------------------------------------
 rollerd parameters:
 rollrec file "../../testing/trustman-rollerd/example.rollrec"
 directory "../../testing/trustman-rollerd"
 config file "./dnssec-tools.conf"
 logfile "../../testing/trustman-rollerd/phase.log"
 loglevel "info"
 logtz ""
 single-run ""
 zone reload "1"
 event method "Full List"
 
 
 Using the full_list_event_loop() processor!!!
 example.com: KSK phase 4
 example.com: executing "../../tools/scripts/zonesigner -dtconfig ./dnssec-tools.conf -rollksk -v -nodroprevoke -keygen /opt/local/sbin/dnssec-keygen -zonecheck /opt/local/sbin/named-checkzone -zonesign /opt/local/sbin/dnssec-signzone -archivedir ../../testing/trustman-rollerd/keyarchive -szopts -P -zskcount 1 -kskcount 1 -krf example.com.krf example.com example.com.signed"
 example.com: KSK phase 5
 example.com: KSK phase 5: admin notified to transfer keyset
 example.com: KSK phase 6
 example.com: KSK phase 6: waiting for parental publication of DS record
 example.com: KSK phase 7
 rollover manager shutting down...
},
);

my %trustman_response = (
    "talktonamed" => qq{Reading and parsing trust keys from $dnsvalfile
 Found a key for example.com
 Found a key for 
 Checking zone keys for validity
 Checking the live "" key
 adding holddown for new key in (12 seconds from now)
vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv
A new key has been received for zone .
 It will be added when the add holddown time is reached.
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Writing new keys to ../../testing/trustman-rollerd/anchor_data
 Checking the live "example.com" key
checking new keys for timing
 hold down timer for still in the future (12 seconds)
},
    "findnewkey" => qq{Reading and parsing trust keys from $dnsvalfile
 Found a key for example.com
 Found a key for 
 Checking zone keys for validity
 Checking the live "" key
 pending key for 
 Checking the live "example.com" key
 adding holddown for new key in example.com (12 seconds from now)
vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv
A new key has been received for zone example.com.
 It will be added when the add holddown time is reached.
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Writing new keys to ../../testing/trustman-rollerd/anchor_data
checking new keys for timing
 hold down timer for still in the future (12 seconds)
 hold down timer for example.com still in the future (12 seconds)
},
    "newkeytodnsval" => qq{Reading and parsing trust keys from $dnsvalfile
 Found a key for example.com
 Found a key for 
 Checking zone keys for validity
 Checking the live "" key
 pending key for 
 Checking the live "example.com" key
 pending key for example.com
checking new keys for timing
 hold down timer for still in the future (12 seconds)
 hold down timer for example.com reached (now 12 > 11)
Opened ./tmp/tmp/dnsval-tmp.conf to create a replacement for ./dnsval.conf
Adding the following key to ./dnsval.conf:
example.com. "257 3 5 XXX"
vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv
New key added to ./dnsval.conf for zone example.com
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Closed tmp/dnsval-tmp.conf and renamed back to ./dnsval.conf
Writing new keys to ../../testing/trustman-rollerd/anchor_data
},
    "revokeoldkeyindnsval" => qq{Reading and parsing trust keys from $dnsvalfile
 Found a key for example.com
 Found a key for 
 Found a key for example.com
 Checking zone keys for validity
 Checking the live "" key
 pending key for 
 Checking the live "example.com" key
Opened ./tmp/tmp/dnsval-tmp.conf to create a replacement for ./dnsval.conf
vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv
The following key has been revoked from zone example.com:
example.com. "385 3 5 XXX"
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Closed tmp/dnsval-tmp.conf and renamed back to ./dnsval.conf
checking new keys for timing
 hold down timer for still in the future (12 seconds)
},
);


#                    ****   MAIN   ****


# Remove, create, and change to work directory.
# Then create the state directory.
rmtree("$testdir",);
die "Unable to remove \'$testdir\' directory: $!\n" if ( -e "$testdir");
mkpath("$testdir",) or die "Unable to make \'$testdir\' directory: $!\n";
chdir "$testdir" or die "unable to change to \'$testdir\' directory: $!\n";

mkpath("$statedir",) or die "Unable to make \'$statedir\' directory: $!\n";
mkpath("$archivedir",) or die "Unable to make \'$archivedir\' directory: $!\n";

$ENV{'DT_STATEDIR'} = "$statedir";


# setup rollerd default files
copy ("../rollerd-example.com","example.com") or
  die "Unable to copy saved-example.com to example.com: $!\n";
copy ("../saved-example.rollrec","example.rollrec") or
  die "Unable to copy saved-example.rollrec to example.rollrec: $!\n";

# setup trustman default files
# Note: dnsval.conf is parsed later
copy ("$etcfiles/root.hints","root.hints") or
  die "Unable to copy $etcfiles/root.hints to root.hints : $!\n";
copy ("$etcfiles/resolv.conf","resolv.conf") or
  die "Unable to copy $etcfiles/resolv.conf to resolv.conf : $!\n";

`touch $anchor_data`;

open(RESOLV, ">>$resconffile") or
  die "Unable to open $resconffile to add local name server : $!\n";
print RESOLV "nameserver [127.0.0.1]:1153\n";
close(RESOLV);

# setup named default files
copy ("../saved-named.rfc1912.zones","named.rfc1912.zones") or
  die "Unable to copy ../saved-named.rfc1912.zones to named.rfc1912.zones : $!\n";
copy ("../saved-named.ca","named.ca") or
  die "Unable to copy ../saved-named.ca to named.ca : $!\n";
copy ("../saved-rndc.key","rndc.key") or
  die "Unable to copy ../saved-rndc.key to rndc.key : $!\n";
copy ("../saved-named.conf","named.conf") or
  die "Unable to copy ../saved-named.conf to named.conf : $!\n";



# inupt file values for local configuration

open(ROLLREC, ">>./example.rollrec") || 
  die "Unable to open ./example.rollrec to add arguments";
print ROLLREC "\tkeygen\t\"$keygen\"\n";
print ROLLREC "\tzonecheck\t\"$zonecheck\"\n";
print ROLLREC "\tzonesign\t\"$zonesign\"\n";
print ROLLREC "\tarchivedir\t\"$archivedir\"\n";
print ROLLREC "\tzsargs\t\"$zsargs\"\n";
close (ROLLREC);

# Note: rndc includes command line arguments. Correct parsing by
# rollerd requires no quotes around the executable and arguments.
open(DTC, ">./dnssec-tools.conf") || 
  die "Unable to create ./dnssec-tools.conf ";
print DTC "admin-email\n\n";
print DTC "keyarch\t$buildloc/tools/scripts/keyarch\n";
print DTC "zonecheck\t\"$zonecheck\"\n";
print DTC "zonesign\t\"$zonesign\"\n";
print DTC "zonesigner\t\"$zonesign\"\n";
print DTC "archivedir\t\"$archivedir\"\n";
# print DTC "rndc \t$rndc -p 1953 -k ./rndc.key\n";
close (DTC);


# Create Commands

my $named_command = "$named -c ./named.conf";

my $trustman_command = "perl -I$buildloc/tools/modules/blib/lib -I$buildloc/tools/modules/blib/arch $trustman -k $dnsvalfile -S -f -v -p -w 5 --nomail --smtp_server localhost --anchor_data_file $anchor_data --resolv_conf $resconffile -o $roothintsfile --tmp_dir $statedir >> $tlogfile 2>&1 ";

my $zonesigner_signzone = "perl -I$dt_plibs -I$dt_parch $zonesigner $zsargs -genkeys $domain >> $rlogfile 2>&1 ";

my $rollerd_singlerun =   "perl -I$dt_plibs -I$dt_parch  $rollerd -dir . -logfile $phaselog -loglevel info -sleep 15 -rrf example.rollrec -pidfile $pidfile -zonesigner $zonesigner -dtconf ./dnssec-tools.conf -singlerun >> $rlogfile 2>&1 ";

my $rollerd_tillstopped = "perl -I$dt_plibs -I$dt_parch  $rollerd -dir . -logfile $phaselog -loglevel info -sleep 15 -rrf example.rollrec -pidfile $pidfile -zonesigner $zonesigner -dtconf ./dnssec-tools.conf >> $rlogfile 2>&1 ";

my $rollctl_dspub = "perl -I$dt_plibs -I$dt_parch  $rollctl -pidfile $pidfile -dspub $domain >> $rlogfile 2>&1 ";

my $rollctl_halt = "perl -I$dt_plibs -I$dt_parch  $rollctl -pidfile $pidfile -halt >> $rlogfile 2>&1 ";

if (exists $options{v}) {
  print "named command :\n$named_command\n";
  print "trustman command :\n$trustman_command\n";
  print "zonesigner_signzone:\n$zonesigner_signzone\n";
  print "rollerd_singlerun:\n$rollerd_singlerun\n";
  print "rollerd_tillstopped:\n$rollerd_tillstopped\n";
  print "rollctl_dspub:\n$rollctl_dspub\n";
  print "rollctl_halt:\n$rollctl_halt\n";
}



#         ********        RUN TESTS        ********


# prepare by signing zone
do_is($test, system("$zonesigner_signzone"), 0,
      "trust/roll: zonesigner: signing \'$domainfile\'");

&insert_newksk_dnsval;

# start named
do_is($test, system("$named_command"), 0,
      "trust/roll: named: starting named");

my $named_pid = `cat ./named.pid`;  chomp $named_pid;

$test->is_eq(system("$trustman_command"), 0,
         "trust/roll: trustman: connect to named for \'dnsval.conf\'");

my $log = &parsetlog;
if (! do_ok($test, $log, $trustman_response{talktonamed},
        "trust/roll: trustman: check connection to named") ) {
  print"\tPossible Problems: \n";
  print"\t\tThe DNS used does not support DNSSEC (e.g. ISP).\n";
  print"\t\tThis host has an incorrect date (e.g. 1+ days incorrect).\n";
}


# rollerd PHASE 1 KSK,
# Initiate rollerd files
# Phase 1: wait for TTL to ensure current zone values have been
# distributed.

unlink "$phaselog";
$test->is_eq(system("$rollerd_singlerun"), 0,
         "trust/roll: rollerd: rolling \'$domainfile\' KSK phase 1");

$log = &parseplog;
do_is($test, $log, $rollerd_response{ksk1},
      "trust/roll: rollerd: checking KSK phase 1 output");

&waittime(125, 5, "       Waiting on TTL for next key rolling phases");


# rollerd PHASE 2-3 KSK
# Phase 2: create new published ksk
# Phase 3: wait TTL for pub ksk distribution

unlink "$phaselog";
$test->is_eq(system("$rollerd_singlerun"), 0,
         "trust/roll: rollerd: rolling \'$domainfile\' KSK phase 2-3");

$log = &parseplog;
do_is($test, $log, $rollerd_response{ksk23},
      "trust/roll: rollerd: checking KSK phase 2-3 output");

reload_named();

# trustman should find the newly published key

unlink $tlogfile;
$test->is_eq(system("$trustman_command"), 0,
         "trust/roll: trustman: find new key for \'$domain\'");

$log = &parsetlog;
do_ok($test, $log, $trustman_response{findnewkey},
      "trust/roll: trustman: if new key found for \'$domain\'");

&waittime(65, 5, "       Waiting on trustman's new key hold down time");

# trustman should add the new key to dnsval.conf

unlink $tlogfile;
$test->is_eq(system("$trustman_command"), 0,
         "trust/roll: trustman: add the new key to \'dnsval.conf\'");

$log = &parsetlog;
do_ok($test, $log, $trustman_response{newkeytodnsval},
      "trust/roll: trustman: if new key added to \'dnsval.conf\'") ;

# validates with NO new key
$test->is_eq(&validate("www.$domain", $resconffile,
               $dnsvaloldkey, $roothintsfile),
         0, "trust/roll: checking validation with old key in dnsval.conf");

# validates with new key
$test->is_eq(&validate("www.$domain", $resconffile,
               $dnsvalfile, $roothintsfile),
         0, "trust/roll: checking validation with new key in dnsval.conf");

&waittime(60, 5, "       Waiting on TTL for next key rolling phases");

# rollerd PHASE 4-6 KSK
# Note: not stopping rollerd
# Phase 4: roll, curksk -> obsksk, pubksk -> curksk
# Phase 5: notifiy admin of change and DS update
# Phase 6: wait to be notified that parent has published the new DS
#          record.

unlink "$phaselog";
$test->is_eq(system("$rollerd_tillstopped"), 0,
         "trust/roll: rolling \'$domainfile\' KSK phase 4-6");

&waittime(10, 1, "       Waiting for phase 4-6 transition");

$log = &parseplog;
do_is($test, $log, $rollerd_response{ksk46},
      "trust/roll: checking KSK phase 4-6 output");

reload_named();

# rollctl and rollerd PHASE 7 KSK
# Phase 7: Notified of parent DS publication

do_is($test, system("$rollctl_dspub"), 0,
      "trust/roll:rollctl: notifying rollerd of DS publication");

$log = &parseplog;
do_is($test, $log, $rollerd_response{ksk7},
      "trust/roll: checking KSK phase 7 output");

do_is($test, system("$rollctl_halt"), 0,
      "rollerd/rollctl: notifying rollerd to shutdown");

# need to reload named again.
reload_named();

# rollerd shutdown
$log = &parseplog;
do_is($test, $log, $rollerd_response{kskhalt}, 
      "rollerd/rollctl: checking shutdown output");


# revoke old key in dnsval.conf
unlink $tlogfile;
$test->is_eq(system("$trustman_command"), 0,
             "trust/roll: trustman: revoke old key in \'dnsval.conf\'");

$log = &parsetlog;
do_ok($test, $log, $trustman_response{revokeoldkeyindnsval},
      "trust/roll: trustman: if old key revoked in \'dnsval.conf\'") ;

# need to reload named again.
# reload_named();

# should fail to validate with old key only
$test->is_eq(&validate("www.$domain", $resconffile, 
                       $dnsvaloldkey, $roothintsfile),
         1, "trust/roll: checking validation with old key in dnsval.conf");

# should validate with new key
$test->is_eq(&validate("www.$domain", $resconffile,
               $dnsvalfile, $roothintsfile),
         0, "trust/roll: checking validation with new key in dnsval.conf");


&local_cleanup();
exit(0);


# end MAIN


#                   **** PROCEDURES ****

sub reload_named {
  `$rndc -s 127.0.0.1 -p 1953 -k ./rndc.key reload`;
  if ($? != 0) {
    local_cleanup();
    die "Error failed to reload named using rndc\n";
  }
}


sub local_cleanup {
  my $tkill = "";
  $tkill = `kill $named_pid` if (int($named_pid) > 0);

  if ( $tkill ne "") {
    print "Warning: trust/roll: killing named: \'$tkill\'\n"
  }
  elsif ( exists($options{v}) ) { print "trust/roll: killed named\n"; }

  if ( -r "$pidfile" ) {
    my $rollerd_pid = `cat $pidfile`;  chomp $rollerd_pid;
    my $rollkill = `kill $rollerd_pid`;
    print "Warning: had to kill rollerd pid \'$rollerd_pid\': $rollkill\n";
  }

  summary($test, "trustman-rollerd");
}


sub parseplog {
  my $logtext = `cat $phaselog`;
  print "before:\n$logtext\n"  if (exists $options{V});

  $logtext = parsepstring($logtext);

  print "after:\n$logtext\n"  if (exists $options{V});
  return $logtext;
}


sub parsetlog {
  my $logtext = `cat $tlogfile`;
  print "before:\n$logtext\n"  if (exists $options{V});

  $logtext =~ s/$buildloc/..\/../g;
  $logtext =~ s/[ \t]+/ /g;
  $logtext =~ s/secs=(\d|\.)+,/secs=18,/g;
  $logtext =~ s/time=(\d|\.)+/time=12/g;
  $logtext =~ s/\d+ +seconds/12 seconds/g;
  $logtext =~ s/$domain reached \(now = \d+ > \d+\)/$domain reached (now 12 > 11)/g;
  $logtext =~ s/$domain\. "(\d+) 3 5 .*"/$domain. "\1 3 5 XXX"/g;
  $logtext =~ s/(Opened|Closed)(.*)dnsval-......\.conf(.*)/\1\2dnsval-tmp.conf\3/g;

  print "after:\n$logtext\n"  if (exists $options{V});
  return $logtext;
}


sub parsepstring {
  my $pstring = @_[0];

  $pstring =~ s/.*2\d\d\d:(.*)/\1/g;
  $pstring =~ s/(logfile.*"|rollrec file.*").*(testing\/rollerd\/)/\1\2/g;
  $pstring =~ s/[ \t]+/ /g;
  $pstring =~ s/cache expires in (\d+) (minutes*)(, (\d+) seconds)*/cache expires in minutes, seconds/g;
  $pstring =~ s/expires in (\d+) days, (\d+) hours, (\d+) minutes, (\d+) seconds/expires in days, hours, minutes, seconds/g;
  $pstring =~ s/expiration in \d+.*/expiration in weeks, days, hours, seconds/g;
  $pstring =~ s/admin must transfer/admin notified to transfer/g;
  $pstring =~ s/.*invalid admin; unable to notify.*\n//g;
  $pstring =~ s/$buildloc/..\/../g;
  $pstring =~ s/example.com: KSK phase (\d+): unable to reload zone, rc - \d+/example.com: KSK phase \1: unable to reload zone, rc - 1/g;

  return $pstring;
}


# validate uses the dnssec-tools validator perl plugin to validate a
# passed in host name far an "IN", "A" type lookup.
# It returns 0 on success (validated) and 1 on failure (not validate).
# I left in error output for errors that shouldn't occur.
sub validate {
  my($host, $rcfile, $dvfile, $rhfile) = @_;

  my $validator = new Net::DNS::SEC::Validator
    (resolv_conf => "$rcfile",
     dnsval_conf => "$dvfile",
     root_hints  => "$rhfile");

  if (!$validator) {
    print "Error: Failed to create validator object using:\n  resolv_conf: \'$resconffile\', dnsval_conf: \'$dnsvalfile\', root_hints: \'$roothintsfile\'\n";
    return 1;
  }

  my $r = $validator->res_query("$host", "IN", "A");
  if ($r && $validator->isvalidated) {
    my ($pkt, $err) = new Net::DNS::Packet(\$r);
    if (!$err) {
      print "       Validated \'$host\'\n"  if (exists $options{v});
      return 0;
    }
    else {
      print "Error in validating packet: $err\n";
    }
  }
  elsif ($r) {
    #    print "Error: Failed to validate keys for \"$host\"\n";
  } else {
    print "Error: validation resolving failed\n";
  }

  print "       Not Validated \'$host\'\n"  if (exists $options{v});
  return 1;
}


# insert_newksk_dnsval
# Parses zonesigner's output to get the new KSK value.
# Opens up the key file to retrieve the zone and public key value.
# Inserts the KSK values into dnsval.conf
sub insert_newksk_dnsval {
  my $logtext = `cat $rlogfile`;
  my $ksknum = 0;

  if ($logtext =~ /\s+KSK\s+\(cur\)\s+(\d+)\s+-b.*/ )  {
    $ksknum = $1;
  }
  else {
    die "Unable to calculate new KSK number from zonesigner output";
  }

  my $zone;
  my $keyval;
  my $line = `cat Kexample.com.+005+$ksknum.key`;
  chomp $line;

  if ( $line =~ /(\S+) IN DNSKEY (257.*)/ ){
    $zone   = $1;
    $keyval = $2;
    $zone   =~ s/\.$//g;
  }
  else { die "Unable to parse key file to retrieve KSK\n"; }

  open (DNSVALIN, "<$etcfiles/dnsval.conf") or
    die "Unable to open $etcfiles/dnsval.conf for reading: $!";
  open (DNSVALOUT, ">$dnsvalfile") or
    die "Unable to open $dnsvalfile for writing: $!";

  while ( $line = <DNSVALIN> ) {
    print DNSVALOUT "$line";
    if ( $line =~ /^:\s+trust-anchor/ ) {
      print DNSVALOUT "                $zone \"$keyval\"\n";
    }
    elsif ( $line =~ /^:\s+zone-security-expectation/ ) {
      print DNSVALOUT "                $zone validate\n";
    }
  }

  close DNSVALIN;
  close DNSVALOUT;
  copy ("$dnsvalfile","$dnsvaloldkey") or
    die "Unable to copy $dnsvalfile to $dnsvaloldkey: $!\n";

} # insert_newksk_dnsval



