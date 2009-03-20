# This is -*- perl -*-

use strict;
use Test::More tests => 17;
use File::Path;
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
my $statedir   = "tmp";


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

    "ksk23" =>  q{ rollerd starting ----------------------------------------
 rollerd parameters:
 rollrec file "testing/rollerd/example.rollrec"
 logfile "testing/rollerd/phase.log"
 loglevel "info"
 sleeptime "15"
 
 example.com: KSK phase 2
 example.com: executing "/usr/local/bin/zonesigner -newpubksk example.com example.com.signed"
 example.com: KSK phase 3
 example.com: KSK phase 3 (Waiting for cache or holddown timer expiration); cache expires in minutes, seconds
 rollover manager shutting down...
},
    "ksk46" => q{ rollerd starting ----------------------------------------
 rollerd parameters:
 rollrec file "testing/rollerd/example.rollrec"
 logfile "testing/rollerd/phase.log"
 loglevel "info"
 sleeptime "15"
 
 example.com: KSK phase 4
 example.com: executing "/usr/local/bin/zonesigner -rollksk example.com example.com.signed"
 example.com: KSK phase 5
 example.com: KSK phase 5: admin notified to transfer keyset
 example.com: KSK phase 6
 example.com: KSK phase 6: waiting for parental publication of DS record
},
    "ksk7" => q{ rollerd starting ----------------------------------------
 rollerd parameters:
 rollrec file "testing/rollerd/example.rollrec"
 logfile "testing/rollerd/phase.log"
 loglevel "info"
 sleeptime "15"
 
 example.com: KSK phase 4
 example.com: executing "/usr/local/bin/zonesigner -rollksk example.com example.com.signed"
 example.com: KSK phase 5
 example.com: KSK phase 5: admin notified to transfer keyset
 example.com: KSK phase 6
 example.com: KSK phase 6: waiting for parental publication of DS record
 example.com: KSK phase 7
},
    "kskhalt" => q{ rollerd starting ----------------------------------------
 rollerd parameters:
 rollrec file "testing/rollerd/example.rollrec"
 logfile "testing/rollerd/phase.log"
 loglevel "info"
 sleeptime "15"
 
 example.com: KSK phase 4
 example.com: executing "/usr/local/bin/zonesigner -rollksk example.com example.com.signed"
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
 example.com: KSK expiration in 25 weeks, 5 days, 0 seconds
 example.com: creating new zsk_rollsecs record and forcing ZSK rollover
 example.com: current ZSK has expired
 example.com: ZSK phase 1 (Waiting for the old zone data to expire from caches)
 rollover manager shutting down...
},
    "zsk23" => q{ rollerd starting ----------------------------------------
 rollerd parameters:
 rollrec file "testing/rollerd/example.rollrec"
 logfile "testing/rollerd/phase.log"
 loglevel "info"
 sleeptime "15"
 
 example.com: ZSK phase 2 (Signing the zone with the KSK and published ZSK)
 example.com: executing "/usr/local/bin/zonesigner -usezskpub example.com example.com.signed"
 example.com: ZSK phase 3 (Waiting for the old zone data to expire from caches)
 example.com: ZSK phase 3 (Waiting for the old zone data to expire from caches); cache expires in minutes, seconds
 rollover manager shutting down...
},
    "zsk4" => q{ rollerd starting ----------------------------------------
 rollerd parameters:
 rollrec file "testing/rollerd/example.rollrec"
 logfile "testing/rollerd/phase.log"
 loglevel "info"
 sleeptime "15"
 
 example.com: ZSK phase 4 (Adjusting keys in the keyrec and signing the zone with new ZSK)
 example.com: executing "/usr/local/bin/zonesigner -rollzsk example.com example.com.signed"
 example.com: executing "/usr/local/bin/zonesigner example.com example.com.signed"
 example.com: ZSK phase 0 (Not Rolling)
 example.com: ZSK expiration in 1 week, 0 seconds
 rollover manager shutting down...
},
 );



#                    ****   MAIN   ****


chdir "$testdir" or die "unable to change to \'$testdir\' directory: $!\n";

# State directory needed to run an uninstalled dnssec.
# Remove the local state directory, create a new one, set
# environmental variable.
rmtree( ("./$statedir") ) or  die "Unable to remove ./$statedir";
mkdir "$statedir" or die "unable to create \'$statedir\' directory: $!\n";
$ENV{'DT_STATEDIR'} = "$statedir";

# Cleanup any earlier created files
opendir DIRH, "."; my @dirlist = readdir DIRH; closedir DIRH;
@dirlist = grep /((keyset|dsset)-$domainfile\.|($domainfile\.(krf|signed|zs))|(K$domainfile\..*\.(key|private))|$logfile)$/, @dirlist;
unlink @dirlist;

# setup default files
copy ("save-example.com","example.com") or
  die "Unable to copy save-example.com to example.com: $!\n";
copy ("save-example.rollrec","example.rollrec") or
  die "Unable to copy save-example.rollrec to example.rollrec: $!\n";


# create commands

my $zonesigner_signzone = "perl -I$ENV{'BUILDDIR'}/tools/modules/blib/lib -I$ENV{'BUILDDIR'}/tools/modules/blib/arch  $zonesigner -v -genkeys $domain >> $logfile 2>&1";

my $rollerd_singlerun = "perl -I$ENV{'BUILDDIR'}/tools/modules/blib/lib -I$ENV{'BUILDDIR'}/tools/modules/blib/arch  $rollerd -dir . -logfile $phaselog -loglevel info -sleep 15 -rrf example.rollrec -singlerun ";

my $rollerd_tillstopped = "perl -I$ENV{'BUILDDIR'}/tools/modules/blib/lib -I$ENV{'BUILDDIR'}/tools/modules/blib/arch  $rollerd -dir . -logfile $phaselog -loglevel info -sleep 15 -rrf example.rollrec ";

my $rollerd_dspub = "perl -I$ENV{'BUILDDIR'}/tools/modules/blib/lib -I$ENV{'BUILDDIR'}/tools/modules/blib/arch  $rollctl -dspub $domain";

my $rollerd_halt = "perl -I$ENV{'BUILDDIR'}/tools/modules/blib/lib -I$ENV{'BUILDDIR'}/tools/modules/blib/arch  $rollctl -halt";


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

is(system("$rollerd_dspub"), 0, "Checking rollerd: rollctl notifying rollerd of \'$domain\' Delegation Signer publish");

$log = &parselog;
is($log, $rollerd_response{ksk7}, "Checking rollerd: checking rollerd KSK phase 7 output");

is(system("$rollerd_halt"), 0, "Checking rollerd: rollctl notifying rollerd to shutdown");

$log = &parselog;
is($log, $rollerd_response{kskhalt}, "Checking rollerd: checking rollerd shutdown output");


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
  $logtext =~ s/admin must transfer/admin notified to transfer/g;
  $logtext =~ s/.*invalid admin; unable to notify.*\n//g;
  print "after:\n$logtext\n" if (exists $lconf{verbose});
  return $logtext;
}

