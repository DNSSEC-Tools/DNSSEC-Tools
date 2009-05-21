# This is -*- perl -*-

use strict;
use Test::More tests => 17;
use File::Path ;
use File::Copy;

# Variables

my %lconf  = ();
# $lconf{verbose} = 1;

my $zonesigner  = "$ENV{'BUILDDIR'}/tools/scripts/zonesigner";
my $rollerd     = "$ENV{'BUILDDIR'}/tools/scripts/rollerd";
my $rollctl     = "$ENV{'BUILDDIR'}/tools/scripts/rollctl";

my $testdir    = "$ENV{'BUILDDIR'}/testing/rollerd/";
my $logfile    = "$ENV{'BUILDDIR'}/testing/rollerd/rollerd.log";
my $phaselog   = "$ENV{'BUILDDIR'}/testing/rollerd/phase.log";

my $domain     = "example.com";
my $domainfile = $domain;
my $statedir   = "$testdir/tmp";
my $pidfile    = "./rollmgr.pid";

my $archivedir = "./keyarchive";

# find bind commands
my $keygen    = `which dnssec-keygen`;
my $zonecheck = `which named-checkzone`;
my $zonesign  = `which dnssec-signzone`;
chomp ($keygen, $zonecheck, $zonesign);

if (!( -x $keygen && -x $zonecheck && -x $zonesign )) {
  die "Unable to execute/find 1+ of $keygen, $zonecheck, or $zonesign\n";
}

my $zsargs = "-v -keygen $keygen -zonecheck $zonecheck -zonesign $zonesign -archivedir $archivedir";


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
 example.com: executing "../../tools/scripts/zonesigner -newpubksk $zsargs example.com example.com.signed"
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
 example.com: executing "../../tools/scripts/zonesigner -rollksk $zsargs example.com example.com.signed"
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
 example.com: executing "../../tools/scripts/zonesigner -rollksk $zsargs example.com example.com.signed"
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
 example.com: executing "../../tools/scripts/zonesigner -rollksk $zsargs example.com example.com.signed"
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
 
 example.com: KSK phase 7: unable to archive KSK keys, rc - 0
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
 example.com: executing "../../tools/scripts/zonesigner -usezskpub $zsargs example.com example.com.signed"
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
 example.com: executing "../../tools/scripts/zonesigner -rollzsk $zsargs example.com example.com.signed"
 example.com: executing "../../tools/scripts/zonesigner $zsargs example.com example.com.signed"
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

# Create Commands

my $zonesigner_signzone = "perl -I$ENV{'BUILDDIR'}/tools/modules/blib/lib -I$ENV{'BUILDDIR'}/tools/modules/blib/arch $zonesigner $zsargs -genkeys $domain >> $logfile 2>&1";

my $rollerd_singlerun =   "perl -I$ENV{'BUILDDIR'}/tools/modules/blib/lib -I$ENV{'BUILDDIR'}/tools/modules/blib/arch  $rollerd -dir . -logfile $phaselog -loglevel info -sleep 15 -rrf example.rollrec -pidfile $pidfile -zonesigner $zonesigner -singlerun >> $logfile 2>&1 ";

my $rollerd_tillstopped = "perl -I$ENV{'BUILDDIR'}/tools/modules/blib/lib -I$ENV{'BUILDDIR'}/tools/modules/blib/arch  $rollerd -dir . -logfile $phaselog -loglevel info -sleep 15 -rrf example.rollrec -pidfile $pidfile -zonesigner $zonesigner >> $logfile 2>&1 ";

my $rollctl_dspub = "perl -I$ENV{'BUILDDIR'}/tools/modules/blib/lib -I$ENV{'BUILDDIR'}/tools/modules/blib/arch  $rollctl -pidfile $pidfile -dspub $domain >> $logfile 2>&1 ";

my $rollctl_halt = "perl -I$ENV{'BUILDDIR'}/tools/modules/blib/lib -I$ENV{'BUILDDIR'}/tools/modules/blib/arch  $rollctl -pidfile $pidfile -halt >> $logfile 2>&1 ";

#print "zonesigner_signzone:\n$zonesigner_signzone\n";
#print "rollerd_singlerun:\n$rollerd_singlerun\n";
#print "rollerd_tillstopped:\n$rollerd_tillstopped\n";
#print "rollctl_dspub:\n$rollctl_dspub\n";
#print "rollctl_halt:\n$rollctl_halt\xn";


# run tests

# prepare by signing zone
is(system("$zonesigner_signzone"), 0, "Checking rollerd: zonesigner signing \'$domainfile\'");


# rollerd PHASE 1 KSK

unlink "$phaselog";
is(system("$rollerd_singlerun"), 0, "Checking rollerd: rollerd rolling \'$domainfile\' KSK phase 1");

my $log = &parselog;
is($log, $rollerd_response{ksk1}, "Checking rollerd: checking rollerd KSK phase 1 output");

&waittime(125, 5, "Waiting until TTL timeout for next key rolling phase");


# rollerd PHASE 2-3 KSK

unlink "$phaselog";
is(system("$rollerd_singlerun"), 0, "Checking rollerd: rollerd rolling \'$domainfile\' KSK phase 2-3");

$log = &parselog;
is($log, $rollerd_response{ksk23}, "Checking rollerd: checking rollerd KSK phase 2-3 output");

&waittime(125, 5, "Waiting until TTL timeout for next key rolling phase");


# rollerd PHASE 4-6 KSK
# Note: not stopping rollerd

unlink "$phaselog";
is(system("$rollerd_tillstopped"), 0, "Checking rollerd: rollerd rolling \'$domainfile\' KSK phase 4-6");

&waittime(10, 1, "Waiting for phase 4-6 transition");

$log = &parselog;
is($log, $rollerd_response{ksk46}, "Checking rollerd: checking rollerd KSK phase 4-6 output");


# rollctl and rollerd PHASE 7 KSK

is(system("$rollctl_dspub"), 0, "Checking rollerd/rollctl: rollctl notifying rollerd of \'$domain\' Delegation Signer publish");

$log = &parselog;
is($log, $rollerd_response{ksk7}, "Checking rollerd: checking rollerd KSK phase 7 output");

is(system("$rollctl_halt"), 0, "Checking rollerd/rollctl: rollctl notifying rollerd to shutdown");

$log = &parselog;
is($log, $rollerd_response{kskhalt}, "Checking rollerd/rollctl: checking rollerd shutdown output");


# rollerd PHASE 1 ZSK

unlink "$phaselog";
is(system("$rollerd_singlerun"), 0, "Checking rollerd: rollerd rolling \'$domainfile\' ZSK phase 1");
$log = &parselog;
is($log, $rollerd_response{zsk1}, "Checking rollerd: checking rollerd ZSK phase 1 output");
&waittime(125, 5, "Waiting until TTL timeout for next key rolling phase");


# rollerd PHASE 2-3 ZSK

unlink "$phaselog";
is(system("$rollerd_singlerun"), 0, "Checking rollerd: rollerd rolling \'$domainfile\' ZSK phase 2");
$log = &parselog;
is($log, $rollerd_response{zsk23}, "Checking rollerd: checking rollerd ZSK phase 2-3 output");
&waittime(125, 5, "Waiting until TTL timeout for next key rolling phase");


# rollerd PHASE 4 ZSK

unlink "$phaselog";
is(system("$rollerd_singlerun"), 0, "Checking rollerd: rollerd rolling \'$domainfile\' ZSK phase 4");
$log = &parselog;
is($log, $rollerd_response{zsk4}, "Checking rollerd: checking rollerd ZSK phase 4 output");


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

sub parselog {
  my $logtext = `cat $phaselog`;
  print "before:\n$logtext\n" if (exists $lconf{verbose});
  $logtext =~ s/.*2\d\d\d:(.*)/\1/g;
  $logtext =~ s/(logfile.*"|rollrec file.*").*(testing\/rollerd\/)/\1\2/g;
  $logtext =~ s/[ \t]+/ /g;
  $logtext =~ s/cache expires in (\d+) (minutes*), (\d+)/cache expires in minutes,/g;
  $logtext =~ s/expiration in \d+.*/expiration in weeks, days, hours, seconds/g;
  $logtext =~ s/admin must transfer/admin notified to transfer/g;
  $logtext =~ s/.*invalid admin; unable to notify.*\n//g;
  $logtext =~ s/$ENV{'BUILDDIR'}/..\/../g;

  print "after:\n$logtext\n" if (exists $lconf{verbose});
  return $logtext;
}

