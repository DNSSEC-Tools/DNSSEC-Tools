# This is -*- perl -*-

use strict;
use Test::More tests => 17;
use File::Path ;
use File::Copy;

# Variables

my %lconf  = ();
# $lconf{verbose} = 1;

my $zonesigner = "$ENV{'BUILDDIR'}/tools/scripts/zonesigner";
my $rollerd    = "$ENV{'BUILDDIR'}/tools/scripts/rollerd";
my $rollctl    = "$ENV{'BUILDDIR'}/tools/scripts/rollctl";

my $dt_plibs   = "$ENV{'BUILDDIR'}/tools/modules/blib/lib";
my $dt_parch   = "$ENV{'BUILDDIR'}/tools/modules/blib/arch";

my $testdir    = "$ENV{'BUILDDIR'}/testing/rollerd";
my $logfile    = "$testdir/rollerd.log";
my $phaselog   = "$testdir/phase.log";

my $domain     = "example.com";
my $domainfile = $domain;

my $statedir   = "$testdir/tmp";
my $pidfile    = "$testdir/rollmgr.pid";
my $archivedir = "$testdir/keyarchive";

# find bind commands
my $keygen    = `which dnssec-keygen`;
my $zonecheck = `which named-checkzone`;
my $zonesign  = `which dnssec-signzone`;
chomp ($keygen, $zonecheck, $zonesign);

if (!( -x $keygen && -x $zonecheck && -x $zonesign )) {
  die "Unable to execute/find 1+ of $keygen, $zonecheck, or $zonesign\n";
}

my $zsargs = "-v -keygen $keygen -zonecheck $zonecheck -zonesign $zonesign -archivedir $archivedir";
my $zsargs_resp   = parsestring($zsargs);
my $dt_plibs_resp = parsestring($dt_plibs);
my $dt_parch_resp = parsestring($dt_parch);

my %rollerd_response = ( 
    "ksk1" =>   q{ rollerd starting ----------------------------------------
 rollerd parameters:
 rollrec file "testing/rollerd/example.rollrec"
 logfile "testing/rollerd/phase.log"
 loglevel "info"
 sleeptime "15"
 
 example.com: creating new ksk_rollsecs record and forcing KSK rollover
 example.com: KSK phase 1
 rollover manager shutting down...
},

    "ksk23" =>  qq{ rollerd starting ----------------------------------------
 rollerd parameters:
 rollrec file "testing/rollerd/example.rollrec"
 logfile "testing/rollerd/phase.log"
 loglevel "info"
 sleeptime "15"
 
 example.com: KSK phase 2
 example.com: executing "perl -I$dt_plibs_resp ../../tools/scripts/zonesigner -newpubksk $zsargs_resp example.com example.com.signed"
 example.com: KSK phase 3
 example.com: KSK phase 3 (Waiting for cache or holddown timer expiration); cache expires in minutes, seconds
 rollover manager shutting down...
},
    "ksk46" => qq{ rollerd starting ----------------------------------------
 rollerd parameters:
 rollrec file "testing/rollerd/example.rollrec"
 logfile "testing/rollerd/phase.log"
 loglevel "info"
 sleeptime "15"
 
 example.com: KSK phase 4
 example.com: executing "perl -I$dt_plibs_resp ../../tools/scripts/zonesigner -rollksk $zsargs_resp example.com example.com.signed"
 example.com: KSK phase 5
 example.com: KSK phase 5: admin notified to transfer keyset
 example.com: KSK phase 6
 example.com: KSK phase 6: waiting for parental publication of DS record
},
    "ksk7" => qq{ rollerd starting ----------------------------------------
 rollerd parameters:
 rollrec file "testing/rollerd/example.rollrec"
 logfile "testing/rollerd/phase.log"
 loglevel "info"
 sleeptime "15"
 
 example.com: KSK phase 4
 example.com: executing "perl -I$dt_plibs_resp ../../tools/scripts/zonesigner -rollksk $zsargs_resp example.com example.com.signed"
 example.com: KSK phase 5
 example.com: KSK phase 5: admin notified to transfer keyset
 example.com: KSK phase 6
 example.com: KSK phase 6: waiting for parental publication of DS record
 example.com: KSK phase 7
},
    "kskhalt" => qq{ rollerd starting ----------------------------------------
 rollerd parameters:
 rollrec file "testing/rollerd/example.rollrec"
 logfile "testing/rollerd/phase.log"
 loglevel "info"
 sleeptime "15"
 
 example.com: KSK phase 4
 example.com: executing "perl -I$dt_plibs_resp ../../tools/scripts/zonesigner -rollksk $zsargs_resp example.com example.com.signed"
 example.com: KSK phase 5
 example.com: KSK phase 5: admin notified to transfer keyset
 example.com: KSK phase 6
 example.com: KSK phase 6: waiting for parental publication of DS record
 example.com: KSK phase 7
 rollover manager shutting down...
},
    "zsk1" => q{ rollerd starting ----------------------------------------
 rollerd parameters:
 rollrec file "testing/rollerd/example.rollrec"
 logfile "testing/rollerd/phase.log"
 loglevel "info"
 sleeptime "15"
 
 example.com: KSK phase 7: zone, key files archived
 example.com: KSK phase 0
 example.com: KSK expiration in weeks, days, hours, seconds
 example.com: creating new zsk_rollsecs record and forcing ZSK rollover
 example.com: current ZSK has expired
 example.com: ZSK phase 1 (Waiting for the old zone data to expire from caches)
 rollover manager shutting down...
},
    "zsk23" => qq{ rollerd starting ----------------------------------------
 rollerd parameters:
 rollrec file "testing/rollerd/example.rollrec"
 logfile "testing/rollerd/phase.log"
 loglevel "info"
 sleeptime "15"
 
 example.com: ZSK phase 2 (Signing the zone with the KSK and published ZSK)
 example.com: executing "perl -I$dt_plibs_resp ../../tools/scripts/zonesigner -usezskpub $zsargs_resp example.com example.com.signed"
 example.com: ZSK phase 3 (Waiting for the old zone data to expire from caches)
 example.com: ZSK phase 3 (Waiting for the old zone data to expire from caches); cache expires in minutes, seconds
 rollover manager shutting down...
},
    "zsk4" => qq{ rollerd starting ----------------------------------------
 rollerd parameters:
 rollrec file "testing/rollerd/example.rollrec"
 logfile "testing/rollerd/phase.log"
 loglevel "info"
 sleeptime "15"
 
 example.com: ZSK phase 4 (Adjusting keys in the keyrec and signing the zone with new ZSK)
 example.com: executing "perl -I$dt_plibs_resp ../../tools/scripts/zonesigner -rollzsk $zsargs_resp example.com example.com.signed"
 example.com: executing "perl -I$dt_plibs_resp ../../tools/scripts/zonesigner $zsargs_resp example.com example.com.signed"
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

mkpath("$statedir",) or
  die "Unable to make \'$statedir\' directory: $!\n";
chdir "$testdir" or die "unable to change to \'$testdir\' directory: $!\n";
mkpath("$archivedir",) or
  die "Unable to make \'$archivedir\' directory: $!\n";


$ENV{'DT_STATEDIR'} = "$statedir";

# setup default files
copy ("../rollerd-example.com","example.com") or
  die "Unable to copy saved-example.com to example.com: $!\n";
copy ("../saved-example.rollrec","example.rollrec") or
  die "Unable to copy saved-example.rollrec to example.rollrec: $!\n";

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
print DTC "keyarch\t$ENV{'BUILDDIR'}/tools/scripts/keyarch\n";
print DTC "zonecheck\t\"$zonecheck\"\n";
print DTC "zonesign\t\"$zonesign\"\n";
print DTC "zonesigner\t\"$zonesign\"\n";
print DTC "archivedir\t\"$archivedir\"\n";
close (DTC);

# Create Commands

my $zonesigner_signzone = "perl -I$dt_plibs -I$dt_parch $zonesigner $zsargs -genkeys $domain >> $logfile 2>&1";

my $rollerd_singlerun =   "perl -I$dt_plibs -I$dt_parch  $rollerd -dtplibs $dt_plibs -dir . -logfile $phaselog -loglevel info -sleep 15 -rrf example.rollrec -pidfile $pidfile -zonesigner $zonesigner -dtconf ./dnssec-tools.conf -singlerun >> $logfile 2>&1 ";

my $rollerd_tillstopped = "perl -I$dt_plibs -I$dt_parch  $rollerd -dtplibs $dt_plibs -dir . -logfile $phaselog -loglevel info -sleep 15 -rrf example.rollrec -pidfile $pidfile -zonesigner $zonesigner -dtconf ./dnssec-tools.conf >> $logfile 2>&1 ";

my $rollctl_dspub = "perl -I$dt_plibs -I$dt_parch  $rollctl -pidfile $pidfile -dspub $domain >> $logfile 2>&1 ";

my $rollctl_halt = "perl -I$dt_plibs -I$dt_parch  $rollctl -pidfile $pidfile -halt >> $logfile 2>&1 ";

#print "zonesigner_signzone:\n$zonesigner_signzone\n";
#print "rollerd_singlerun:\n$rollerd_singlerun\n";
#print "rollerd_tillstopped:\n$rollerd_tillstopped\n";
#print "rollctl_dspub:\n$rollctl_dspub\n";
#print "rollctl_halt:\n$rollctl_halt\xn";


# run tests

# prepare by signing zone
dois(system("$zonesigner_signzone"), 0, "Checking rollerd: zonesigner signing \'$domainfile\'");


# rollerd PHASE 1 KSK

unlink "$phaselog";
dois(system("$rollerd_singlerun"), 0, "Checking rollerd: rollerd rolling \'$domainfile\' KSK phase 1");

my $log = &parselog;
dois($log, $rollerd_response{ksk1}, "Checking rollerd: checking rollerd KSK phase 1 output");

&waittime(125, 5, "Waiting until TTL timeout for next key rolling phase");


# rollerd PHASE 2-3 KSK

unlink "$phaselog";
dois(system("$rollerd_singlerun"), 0, "Checking rollerd: rollerd rolling \'$domainfile\' KSK phase 2-3");

$log = &parselog;
dois($log, $rollerd_response{ksk23}, "Checking rollerd: checking rollerd KSK phase 2-3 output");

&waittime(125, 5, "Waiting until TTL timeout for next key rolling phase");


# rollerd PHASE 4-6 KSK
# Note: not stopping rollerd

unlink "$phaselog";
dois(system("$rollerd_tillstopped"), 0, "Checking rollerd: rollerd rolling \'$domainfile\' KSK phase 4-6");

&waittime(10, 1, "Waiting for phase 4-6 transition");

$log = &parselog;
dois($log, $rollerd_response{ksk46}, "Checking rollerd: checking rollerd KSK phase 4-6 output");


# rollctl and rollerd PHASE 7 KSK

dois(system("$rollctl_dspub"), 0, "Checking rollerd/rollctl: rollctl notifying rollerd of \'$domain\' Delegation Signer publish");

$log = &parselog;
dois($log, $rollerd_response{ksk7}, "Checking rollerd: checking rollerd KSK phase 7 output");

dois(system("$rollctl_halt"), 0, "Checking rollerd/rollctl: rollctl notifying rollerd to shutdown");

$log = &parselog;
dois($log, $rollerd_response{kskhalt}, "Checking rollerd/rollctl: checking rollerd shutdown output");


# rollerd PHASE 1 ZSK

unlink "$phaselog";
dois(system("$rollerd_singlerun"), 0, "Checking rollerd: rollerd rolling \'$domainfile\' ZSK phase 1");
$log = &parselog;
dois($log, $rollerd_response{zsk1}, "Checking rollerd: checking rollerd ZSK phase 1 output");
&waittime(125, 5, "Waiting until TTL timeout for next key rolling phase");


# rollerd PHASE 2-3 ZSK

unlink "$phaselog";
dois(system("$rollerd_singlerun"), 0, "Checking rollerd: rollerd rolling \'$domainfile\' ZSK phase 2");
$log = &parselog;
dois($log, $rollerd_response{zsk23}, "Checking rollerd: checking rollerd ZSK phase 2-3 output");
&waittime(125, 5, "Waiting until TTL timeout for next key rolling phase");


# rollerd PHASE 4 ZSK

unlink "$phaselog";
dois(system("$rollerd_singlerun"), 0, "Checking rollerd: rollerd rolling \'$domainfile\' ZSK phase 4");
$log = &parselog;
dois($log, $rollerd_response{zsk4}, "Checking rollerd: checking rollerd ZSK phase 4 output");


# end MAIN


#                   **** PROCEDURES ****


sub waittime {
  my($wait, $sleeptime, $msg) = @_;
  return if( ($wait <= 0) || ($sleeptime <= 0) );
  $msg = "Waiting" if ( $msg eq "" );

  print "$msg: $wait seconds";
  sleep $sleeptime;
  while ($wait > 0) {
    printf "\r$msg: $wait seconds     ";
    sleep $sleeptime;
    $wait = $wait - $sleeptime;
  }
  printf "\r$msg: 0 seconds      \n";
}


sub dois {
  my ($is1, $is2, $istext) = @_;
  if (! is($is1, $is2, $istext) ) {
    BAIL_OUT("Cannot complete succeeding tests after a fail.");
  }
}


sub parselog {
  my $logtext = `cat $phaselog`;
  print "before:\n$logtext\n" if (exists $lconf{verbose});
  $logtext = parsestring($logtext);
  print "after:\n$logtext\n" if (exists $lconf{verbose});
  return $logtext;
}


sub parsestring {
  my $pstring = @_[0];

  $pstring =~ s/.*2\d\d\d:(.*)/\1/g;
  $pstring =~ s/(logfile.*"|rollrec file.*").*(testing\/rollerd\/)/\1\2/g;
  $pstring =~ s/[ \t]+/ /g;
  $pstring =~ s/cache expires in (\d+) (minutes*), (\d+)/cache expires in minutes,/g;
  $pstring =~ s/expiration in \d+.*/expiration in weeks, days, hours, seconds/g;
  $pstring =~ s/admin must transfer/admin notified to transfer/g;
  $pstring =~ s/.*invalid admin; unable to notify.*\n//g;
  $pstring =~ s/$ENV{'BUILDDIR'}/..\/../g;

  return $pstring;
}

