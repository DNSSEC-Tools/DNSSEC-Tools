#!/bin/bash

curdir=`pwd`
echo $curdir
dir=/tmp/rolltest
rmdir=1
rrfile=dns.rollrec
ZONEVERSION=`zonesigner 2>&1 -Version | grep "Tools Version" | sed 's/.*: //'`
if [ $ZONEVERSION = '1.12' -o  $ZONEVERSION = '1.12.1' ] ; then
    SKIPZONESIGNER=1
else
    SKIPZONESIGNER=0
fi

ZONESIGNER="zonesigner -verbose -verbose -verbose"
ROLLERD="rollerd -singlerun -rrfile $rrfile -dtconf dnssec-tools.conf -logfile - -loglevel tmi"

zoneinitfile=$curdir/example.com
dtconfinitfile=$curdir/dnssec-tools.conf

export DT_SYSCONFDIR=.

if [ "$rmdir" = "1" ] ; then
    rm -rf $dir
fi
mkdir -p $dir/dnssec-tools
cd $dir



step=1
yearmon=`date +%Y%m`

log() {
  echo "----------------------------------------------------------------------"
  echo "$step --" "$@"
  echo "----------------------------------------------------------------------"
}

getkeyid() {
  keyid=`grep $yearmon example.com.signed | tail -1 | awk '{print $2}'`
  log checked for keyid and found $keyid
}

checkkeyid() {
  getkeyid
  shouldbe=$1
  shift
  log "looking for keyid=$shouldbe (curkey=$curkeyid, pubkey=$pubkeyid)"
  if [ $keyid != $shouldbe ] ; then 
      error "$@"
  fi
}

checkrollerdphase() {
  expected=$1
  shift
  zskphase=`grep zskphase $rrfile | awk '{print $NF}' | sed 's/"//g;'`
  log "Checking rollerd phase (expecting=$1, got=$zskphase)"
  if [ "$expected" != "$zskphase" ] ; then
    if [ "$1" != "" ] ; then
	log "$@"
    fi
    error Got the wrong zsk phase than expected
  fi
}

error() {
  log "FAILURE (exiting)" "$@"
  exit 1;
}

zonesignertest() {
  # sign the zone
  $ZONESIGNER example.com

  # verify it's using the current key (the last signature will be a
  # NSEC, which is ok.  The only thing we don't want is a DNSKEY)
  getkeyid
  curkeyid=$keyid
  log cur zsk used: $curkeyid

  # now sign with the pub and get its keyid
  $ZONESIGNER -usezskpub example.com
  getkeyid
  pubkeyid=$keyid
  log pub zsk used: $pubkeyid

  # resign normally to fall back to cur
  $ZONESIGNER example.com
  checkkeyid $curkeyid Resigning failed to use the current zsk again
}

rollerdtest() {
  ######################################################################
  # rollerd startup
  #
  rollinit example.com > $rrfile
  log generated initi files for rollerd
  checkrollerdphase 0 should be in phase 0 after rollinit

  # run rollerd the first time
  $ROLLERD "$@"
  checkrollerdphase 0 should still be in phase 0 after first rollerd run
  checkkeyid $curkeyid rollerd changed the zsk immediately...  should have waited 60

  # check that zonesigner does the right thing and uses the current key too
  if [ $SKIPZONESIGNER != 1 ]; then
    $ZONESIGNER example.com
    checkkeyid $curkeyid zonesigner used the wrong key when signing after first rollerd call
  fi

  # run again 60 seconds later
  log "sleeping for 60 to let rollerd go to the next phase -> 1"
  sleep 60
  $ROLLERD "$@"
  checkrollerdphase 1 should now have switched to rollerd phase 1
  checkkeyid $curkeyid rollerd updated the key one phase too quickly "(in phase 1)"

  # check that zonesigner does the right thing and uses the current key too
  if [ $SKIPZONESIGNER != 1 ]; then
    log calling zonesigner after switch to phase 1
    $ZONESIGNER example.com
    checkkeyid $curkeyid zonesigner failed to use the curkey that rollerd used
  fi


  # run again in phase 2 (we hope)
  sleep 60
  log "running rollerd again to jump from 1 to 3"
  $ROLLERD "$@"
  checkrollerdphase 3 should now have switched to rollerd phase 3
  checkkeyid $pubkeyid rollerd should have started using the pub key "(in phase 3)"

  # check that zonesigner does the right thing and uses the current key too
  if [ $SKIPZONESIGNER != 1 ]; then
    log calling zonesigner after switch to phase 3
    $ZONESIGNER example.com
    checkkeyid $pubkeyid zonesigner should be using the pub key now in phase 3
    log checked phase 3 '(right after 2)' for rollerd/zonesigner
  fi


  # run again in phase 3 immediately (we hope)
  log "running rollerd again in phase 3, using the pub key again"
  $ROLLERD "$@"
  checkrollerdphase 3 should still be in phase three as we have not waited long enough.
  checkkeyid $pubkeyid rollerd should have started using the pub key "(in phase 3)"

  # check that zonesigner does the right thing and uses the current key too
  if [ $SKIPZONESIGNER != 1 ]; then
    $ZONESIGNER example.com
    checkkeyid $pubkeyid zonesigner should be using the pub key now
    log checked phase 3 for rollerd/zonesigner
  fi

  # sleep and run again and pub should switch to current and we should
  # get a new pub
  sleep 60
  log "running rollerd again to jump from 3 and resetting to 0"
  $ROLLERD "$@"
  checkrollerdphase 0 after a final roll we should switch back to phase 0
  checkkeyid $pubkeyid rollerd should now be using the old pub key as current "(in phase 0)"

  # check that zonesigner does the right thing and uses the current key too
  if [ $SKIPZONESIGNER != 1 ]; then
    $ZONESIGNER example.com
    checkkeyid $pubkeyid zonesigner should be using the current key which was the pub key
    log checked phase 0 for rollerd/zonesigner
  fi
}

cp $zoneinitfile .
cp $dtconfinitfile dnssec-tools/

######################################################################
# basic signing tests
#

# test zonesigner
step=1
zonesignertest

# test rollerd
step=2
rollerdtest

# test zonesigner again (primarily to pull the new keyids)
step=3
zonesignertest

# test rollerd again
step=4
rollerdtest -alwayssign

