# This is -*- perl -*-

use strict;
use Test::Builder;

use File::Copy;
use File::Path;

require "$ENV{'BUILDDIR'}/testing/t/dt_testingtools.pl";

my $buildloc = dt_strip_dots("$ENV{BUILDDIR}");

#SIGNAL CATCHING
$SIG{INT}  = sub { &local_cleanup(); exit; };
$SIG{TERM} = sub { &local_cleanup(); exit; };

# verbosity check
use Getopt::Std;
my %options = ();
getopts("vV",\%options);

# TEST object
my $test = Test::Builder->new;
$test->diag("Testing Rollerd");
$test->plan( tests => 17);

#verbose setup for test object and dt_testingtools.
if (exists $options{v}) { $test->no_diag(0); dt_testingtools_verbose(1); }
else                    { $test->no_diag(1); dt_testingtools_verbose(0); }
dt_testingtools_bail(1, \&local_cleanup);

# Variables

my $zonesigner = "$buildloc/tools/scripts/zonesigner";
my $rollerd    = "$buildloc/tools/scripts/rollerd";
my $rollctl    = "$buildloc/tools/scripts/rollctl";

my $dt_plibs   = "$buildloc/tools/modules/blib/lib";
my $dt_parch   = "$buildloc/tools/modules/blib/arch";
# my $dt_plibs   = "$buildloc/tools/blib/lib";
# my $dt_parch   = "$buildloc/tools/blib/arch";

my $testdir    = "$buildloc/testing/rollerd";
my $logfile    = "$testdir/rollerd.log";
my $phaselog   = "$testdir/phase.log";

my $domain     = "example.com";
my $domainfile = $domain;

my $statedir   = "./tmp";
my $pidfile    = "$testdir/rollmgr.pid";
my $archivedir = "$testdir/keyarchive";

# find bind commands
my $keygen    = `which dnssec-keygen`;
my $zonecheck = `which named-checkzone`;
my $zonesign  = `which dnssec-signzone`;
my $rndc      = `which rndc`;
chomp ($keygen, $zonecheck, $zonesign, $rndc);

if (!( -x $keygen && -x $zonecheck && -x $zonesign && -x $rndc)) {
  die "Unable to execute/find 1+ of $keygen, $zonecheck, or $zonesign\n\n\tA Bind installation is required for this test.\n";
}

$ENV{'PERL5LIB'} = "$dt_plibs:$dt_parch";

my $zsargs = "-v -keygen $keygen -zonecheck $zonecheck -zonesign $zonesign -archivedir $archivedir -szopts -P";
# my $zsargs = "-v -keygen $keygen -zonecheck $zonecheck -zonesign $zonesign -archivedir $archivedir -szopts -P";
my $zsargs_resp   = parsestring($zsargs);


my %rollerd_response = ( 
    "ksk1" =>   q{ rollerd starting ----------------------------------------
 rollerd parameters:
 rollrec file "testing/rollerd/example.rollrec"
 directory "../../testing/rollerd"
 config file "./dnssec-tools.conf"
 logfile "testing/rollerd/phase.log"
 loglevel "info"
 zone reload "1"
 sleeptime "15"
 
 example.com: adding missing zonename field (example.com) to rollrec
 example.com: creating new ksk_rollsecs record and forcing KSK rollover
 example.com: KSK phase 1 (Waiting for old zone data to expire from caches)
 rollover manager shutting down...
},

    "ksk23" =>  qq{ rollerd starting ----------------------------------------
 rollerd parameters:
 rollrec file "testing/rollerd/example.rollrec"
 directory "../../testing/rollerd"
 config file "./dnssec-tools.conf"
 logfile "testing/rollerd/phase.log"
 loglevel "info"
 zone reload "1"
 sleeptime "15"
 
 example.com: KSK phase 2 (Generating new Published KSK)
 example.com: executing "../../tools/scripts/zonesigner -dtconfig ./dnssec-tools.conf -newpubksk $zsargs_resp -krf example.com.krf example.com example.com.signed"
 example.com: reloading zone for KSK phase 2
 example.com: KSK phase 2: unable to reload zone, rc - 1
 example.com: KSK phase 3 (Waiting for cache or holddown timer expiration)
 example.com: KSK phase 3 (Waiting for cache or holddown timer expiration); cache expires in minutes, seconds
 rollover manager shutting down...
},
    "ksk46" => qq{ rollerd starting ----------------------------------------
 rollerd parameters:
 rollrec file "testing/rollerd/example.rollrec"
 directory "../../testing/rollerd"
 config file "./dnssec-tools.conf"
 logfile "testing/rollerd/phase.log"
 loglevel "info"
 zone reload "1"
 sleeptime "15"
 
 example.com: KSK phase 4 (Rolling the KSK(s))
 example.com: executing "../../tools/scripts/zonesigner -dtconfig ./dnssec-tools.conf -rollksk $zsargs_resp -krf example.com.krf example.com example.com.signed"
 example.com: KSK phase 5 (Transfer New KSK keyset to parent)
 example.com: KSK phase 5: admin notified to transfer keyset
 example.com: KSK phase 6 (Waiting for parent to publish new DS record)
 example.com: KSK phase 6: waiting for parental publication of DS record
},
    "ksk7" => qq{ rollerd starting ----------------------------------------
 rollerd parameters:
 rollrec file "testing/rollerd/example.rollrec"
 directory "../../testing/rollerd"
 config file "./dnssec-tools.conf"
 logfile "testing/rollerd/phase.log"
 loglevel "info"
 zone reload "1"
 sleeptime "15"
 
 example.com: KSK phase 4 (Rolling the KSK(s))
 example.com: executing "../../tools/scripts/zonesigner -dtconfig ./dnssec-tools.conf -rollksk $zsargs_resp -krf example.com.krf example.com example.com.signed"
 example.com: KSK phase 5 (Transfer New KSK keyset to parent)
 example.com: KSK phase 5: admin notified to transfer keyset
 example.com: KSK phase 6 (Waiting for parent to publish new DS record)
 example.com: KSK phase 6: waiting for parental publication of DS record
 example.com: KSK phase 7 (Reloading the zone)
},
    "kskhalt" => qq{ rollerd starting ----------------------------------------
 rollerd parameters:
 rollrec file "testing/rollerd/example.rollrec"
 directory "../../testing/rollerd"
 config file "./dnssec-tools.conf"
 logfile "testing/rollerd/phase.log"
 loglevel "info"
 zone reload "1"
 sleeptime "15"
 
 example.com: KSK phase 4 (Rolling the KSK(s))
 example.com: executing "../../tools/scripts/zonesigner -dtconfig ./dnssec-tools.conf -rollksk $zsargs_resp -krf example.com.krf example.com example.com.signed"
 example.com: KSK phase 5 (Transfer New KSK keyset to parent)
 example.com: KSK phase 5: admin notified to transfer keyset
 example.com: KSK phase 6 (Waiting for parent to publish new DS record)
 example.com: KSK phase 6: waiting for parental publication of DS record
 example.com: KSK phase 7 (Reloading the zone)
 rollover manager shutting down...
},
    "zsk1" => q{ rollerd starting ----------------------------------------
 rollerd parameters:
 rollrec file "testing/rollerd/example.rollrec"
 directory "../../testing/rollerd"
 config file "./dnssec-tools.conf"
 logfile "testing/rollerd/phase.log"
 loglevel "info"
 zone reload "1"
 sleeptime "15"
 
 example.com: reloading zone for KSK phase 7
 example.com: KSK phase 7: unable to reload zone, rc - 1
 example.com: KSK phase 7: zone, key files archived
 example.com: KSK phase 0 (Not Rolling)
 example.com: KSK expiration in weeks, days, hours, seconds
 example.com: creating new zsk_rollsecs record and forcing ZSK rollover
 example.com: current ZSK has expired
 example.com: ZSK phase 1 (Waiting for old zone data to expire from caches)
 rollover manager shutting down...
},
    "zsk23" => qq{ rollerd starting ----------------------------------------
 rollerd parameters:
 rollrec file "testing/rollerd/example.rollrec"
 directory "../../testing/rollerd"
 config file "./dnssec-tools.conf"
 logfile "testing/rollerd/phase.log"
 loglevel "info"
 zone reload "1"
 sleeptime "15"
 
 example.com: ZSK phase 2 (Signing zone with KSK and Published ZSK)
 example.com: executing "../../tools/scripts/zonesigner -dtconfig ./dnssec-tools.conf -usezskpub $zsargs_resp -krf example.com.krf example.com example.com.signed"
 example.com: reloading zone for ZSK phase 2
 example.com: ZSK phase 2: unable to reload zone, rc - 1
 example.com: ZSK phase 3 (Waiting for old zone data to expire from caches)
 example.com: ZSK phase 3 (Waiting for old zone data to expire from caches); cache expires in minutes, seconds
 rollover manager shutting down...
},
    "zsk4" => qq{ rollerd starting ----------------------------------------
 rollerd parameters:
 rollrec file "testing/rollerd/example.rollrec"
 directory "../../testing/rollerd"
 config file "./dnssec-tools.conf"
 logfile "testing/rollerd/phase.log"
 loglevel "info"
 zone reload "1"
 sleeptime "15"
 
 example.com: ZSK phase 4 (Adjusting keys in keyrec and signing zone with New ZSK)
 example.com: executing "../../tools/scripts/zonesigner -dtconfig ./dnssec-tools.conf -rollzsk $zsargs_resp -krf example.com.krf example.com example.com.signed"
 example.com: executing "../../tools/scripts/zonesigner -dtconfig ./dnssec-tools.conf $zsargs_resp -krf example.com.krf example.com example.com.signed"
 example.com: reloading zone for ZSK phase 4
 example.com: ZSK phase 4: unable to reload zone, rc - 1
 example.com: ZSK phase 0 (Not Rolling)
 example.com: ZSK expiration in weeks, days, hours, seconds
 rollover manager shutting down...
},
 );


#                    ****   MAIN   ****


# Remove and create directory to work in (via creating the path to
# the state directory)
rmtree("$testdir",);
die "Unable to remove \'$testdir\' directory: $!\n" if ( -e "$testdir");

mkpath("$testdir",) or die "Unable to make \'$testdir\' directory: $!\n";
chdir "$testdir" or die "unable to change to \'$testdir\' directory: $!\n";
# $statedir is a relative path, must change to $testdir first.
mkpath("$statedir",) or die "Unable to make \'$statedir\' directory: $!\n";
chdir "$testdir" or die "unable to change to \'$testdir\' directory: $!\n";
mkpath("$archivedir",) or die "Unable to make \'$archivedir\' directory: $!\n";

$ENV{'DT_STATEDIR'} = "$statedir";


# setup default files
copy ("../rollerd-example.com","example.com") or
  die "Unable to copy saved-example.com to example.com: $!\n";
copy ("../saved-example.rollrec","example.rollrec") or
  die "Unable to copy saved-example.rollrec to example.rollrec: $!\n";

# rndc setup files
copy ("../saved-rndc.key","rndc.key") or
  die "Unable to copy ../saved-rndc.key to rndc.key : $!\n";

open(ROLLREC, ">>./example.rollrec") || 
  die "Unable to open ./example.rollrec to add arguments";
print ROLLREC "\tkeygen\t\"$keygen\"\n";
print ROLLREC "\tzonecheck\t\"$zonecheck\"\n";
print ROLLREC "\tzonesign\t\"$zonesign\"\n";
print ROLLREC "\tarchivedir\t\"$archivedir\"\n";
print ROLLREC "\tzsargs\t\"$zsargs\"\n";
close (ROLLREC);

open(DTC, ">./dnssec-tools.conf") || 
  die "Unable to create ./dnssec-tools.conf ";
print DTC "admin-email\n\n";
print DTC "keyarch\t$buildloc/tools/scripts/keyarch\n";
print DTC "zonecheck\t\"$zonecheck\"\n";
print DTC "zonesign\t$zonesign\n";
print DTC "zonesigner\t$zonesign\n";
print DTC "archivedir\t\"$archivedir\"\n";
print DTC "rndc \t$rndc\n";
close (DTC);


# Create Commands

my $zonesigner_signzone = "perl -I$dt_plibs -I$dt_parch $zonesigner $zsargs -genkeys $domain >> $logfile 2>&1 ";

my $rollerd_singlerun =   "perl -I$dt_plibs -I$dt_parch  $rollerd -dir . -logfile $phaselog -loglevel info -sleep 15 -rrf example.rollrec -pidfile $pidfile -zonesigner $zonesigner -dtconf ./dnssec-tools.conf -singlerun >> $logfile 2>&1 ";

my $rollerd_tillstopped = "perl -I$dt_plibs -I$dt_parch  $rollerd -dir . -logfile $phaselog -loglevel info -sleep 15 -rrf example.rollrec -pidfile $pidfile -zonesigner $zonesigner -dtconf ./dnssec-tools.conf >> $logfile 2>&1 ";

my $rollctl_dspub = "perl -I$dt_plibs -I$dt_parch  $rollctl -pidfile $pidfile -dspub $domain >> $logfile 2>&1 ";

my $rollctl_halt = "perl -I$dt_plibs -I$dt_parch  $rollctl -pidfile $pidfile -halt >> $logfile 2>&1 ";

if (exists $options{v}) {
  print "builddir \'$buildloc\'\n";
  print "zonesigner_signzone:\n$zonesigner_signzone\n";
  print "rollerd_singlerun:\n$rollerd_singlerun\n";
  print "rollerd_tillstopped:\n$rollerd_tillstopped\n";
  print "rollctl_dspub:\n$rollctl_dspub\n";
  print "rollctl_halt:\n$rollctl_halt\n";
}


# run tests

# prepare by signing zone
do_is($test, system("$zonesigner_signzone"), 0,
	  "rollerd: signing \'$domainfile\'");


# rollerd PHASE 1 KSK,
# Initiate rollerd files
# Phase 1: wait for TTL to ensure current zone values have been
# distributed.

unlink "$phaselog";
$test->is_eq(system("$rollerd_singlerun"), 0, 
	     "rollerd: rolling \'$domainfile\' KSK phase 1");

my $log = &parselog;
do_is($test, $log, $rollerd_response{ksk1}, 
      "rollerd: checking KSK phase 1 output");

&waittime(125, 5, "       Waiting on TTL for next key rolling phase");


# rollerd PHASE 2-3 KSK
# Phase 2: create new published ksk
# Phase 3: wait TTL for pub ksk distribution

unlink "$phaselog";
$test->is_eq(system("$rollerd_singlerun"), 0,
	     "rollerd: rolling \'$domainfile\' KSK phase 2-3");

$log = &parselog;
do_is($test, $log, $rollerd_response{ksk23},
      "rollerd: checking KSK phase 2-3 output");

&waittime(125, 5, "       Waiting on TTL for next key rolling phase");


# rollerd PHASE 4-6 KSK
# Note: not stopping rollerd
# Phase 4: roll, curksk -> obsksk, pubksk -> curksk
# Phase 5: notifiy admin of change and DS update
# Phase 6: wait to be notified that parent has published the new DS
#          record.

unlink "$phaselog";
$test->is_eq(system("$rollerd_tillstopped"), 0, 
	     "rollerd: rolling \'$domainfile\' KSK phase 4-6");

&waittime(10, 1, "       Waiting for phase 4-6 transition");

$log = &parselog;
#$test->is_eq(1, 1, "Skipping: rollerd: checking KSK phase 4-6 output");
do_is($test, $log, $rollerd_response{ksk46},
	  "rollerd: checking KSK phase 4-6 output");

# rollctl and rollerd PHASE 7 KSK
# Phase 7: Notified of parent DS publication

$test->is_eq(system("$rollctl_dspub"), 0, 
	     "rollerd/rollctl: notifying rollerd of DS publication");

$log = &parselog;
do_is($test, $log, $rollerd_response{ksk7}, 
      "rollerd: checking KSK phase 7 output");

$test->is_eq(system("$rollctl_halt"), 0, 
	     "rollerd/rollctl: notifying rollerd to shutdown");

# rollerd shutdown
$log = &parselog;
do_is($test, $log, $rollerd_response{kskhalt}, 
      "rollerd/rollctl: checking shutdown output");


# rollerd PHASE 1 ZSK
# Phase 1: wait for TTL to ensure current zone values have been
# distributed.

unlink "$phaselog";
$test->is_eq(system("$rollerd_singlerun"), 0, 
	     "rollerd: rolling \'$domainfile\' ZSK phase 1");
$log = &parselog;
do_is($test, $log, $rollerd_response{zsk1}, 
      "rollerd: checking ZSK phase 1 output");
&waittime(125, 5, "        Waiting on TTL for next key rolling phase");


# rollerd PHASE 2-3 ZSK
# Phase 2: sign with pubzsk
# Phase 3: wait for TTL to ensure pubzsk RRSIG values distributed

unlink "$phaselog";
$test->is_eq(system("$rollerd_singlerun"), 0, 
	     "rollerd: rolling \'$domainfile\' ZSK phase 2");
$log = &parselog;
do_is($test, $log, $rollerd_response{zsk23}, 
      "rollerd: checking ZSK phase 2-3 output");
&waittime(125, 5, "        Waiting on TTL for next key rolling phase");


# rollerd PHASE 4 ZSK
# Phase 4: roll, curzsk->obszsk, pubzsk->curzsk, create new pubzsk

unlink "$phaselog";
$test->is_eq(system("$rollerd_singlerun"), 0, 
	     "rollerd: rolling \'$domainfile\' ZSK phase 4");
$log = &parselog;
do_is($test, $log, $rollerd_response{zsk4},
      "rollerd: checking ZSK phase 4 output");


&local_cleanup();

exit(0);


# end MAIN


#                   **** PROCEDURES ****



sub local_cleanup {

  if ( -r "$pidfile" ) {
    my $rollerd_pid = `cat $pidfile`;  chomp $rollerd_pid;
    my $rollkill = `kill $rollerd_pid`;
    print "Warning: had to kill rollerd: $rollkill\n";
  }

  summary($test, "rollerd");
}


sub parselog {
  my $logtext = `cat $phaselog`;
  print "before:\n$logtext\n"  if (exists $options{V});

  $logtext = parsestring($logtext);

  print "after:\n$logtext\n"  if (exists $options{V});
  return $logtext;
}


sub parsestring {
  my $pstring = @_[0];

  $pstring =~ s/.*2\d\d\d:(.*)/\1/g;
  $pstring =~ s/(logfile.*"|rollrec file.*").*(testing\/rollerd\/)/\1\2/g;
  $pstring =~ s/[ \t]+/ /g;
  $pstring =~ s/cache expires in (\d+) (minutes*)(, (\d+) seconds)*/cache expires in minutes, seconds/g;
  $pstring =~ s/expiration in \d+.*/expiration in weeks, days, hours, seconds/g;
  $pstring =~ s/admin must transfer/admin notified to transfer/g;
  $pstring =~ s/.*invalid admin; unable to notify.*\n//g;
  $pstring =~ s/$buildloc/..\/../g;
  $pstring =~ s/example.com: KSK phase (\d+): unable to reload zone, rc - \d+/example.com: KSK phase \1: unable to reload zone, rc - 1/g;

  return $pstring;
}

