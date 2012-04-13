#!/bin/bash

curdir=`pwd`
echo $curdir
dir=/tmp/rolltest
rmdir=1
rrfile=dns.rollrec
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
  zskphase=`grep zskphase $rrfile | awk '{print $NF}' | sed 's/"//g;'`
  log "Checking rollerd phase (expecting=$1, got=$zskphase)"
  if [ "$expected" != "$zskphase" ] ; then
    error Got the wrong zsk phase than expected
  fi
}

error() {
  log "FAILURE (exiting)" "$@"
  exit 1;
}

cp $zoneinitfile .
cp $dtconfinitfile dnssec-tools/

######################################################################
# basic signing tests
#

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

######################################################################
# rollerd startup
#
step=2
rollinit example.com > $rrfile
log generated initi files for rollerd
checkrollerdphase 0

# run rollerd the first time
$ROLLERD
checkrollerdphase 0
checkkeyid $curkeyid rollerd changed the zsk immediately...  should have waited 60

# check that zonesigner does the right thing and uses the current key too
$ZONESIGNER example.com
checkkeyid $curkeyid zonesigner used the wrong key when signing after first rollerd call


# run again 60 seconds later
log "sleeping for 60 to let rollerd go to the next phase -> 1"
sleep 60
$ROLLERD
checkrollerdphase 1
checkkeyid $curkeyid rollerd updated the key one phase too quickly "(in phase 1)"

# check that zonesigner does the right thing and uses the current key too
$ZONESIGNER example.com
checkkeyid $curkeyid zonesigner failed to use the curkey that rollerd used



# run again in phase 2 (we hope)
sleep 60
log "running rollerd again to jump from 1 to 3"
$ROLLERD
checkrollerdphase 3
checkkeyid $pubkeyid rollerd should have started using the pub key "(in phase 3)"

# check that zonesigner does the right thing and uses the current key too
$ZONESIGNER example.com
checkkeyid $pubkeyid zonesigner should be using the pub key now
log checked phase 3 '(right after 2)' for rollerd/zonesigner



# run again in phase 3 immediately (we hope)
log "running rollerd again in phase 3, using the pub key again"
$ROLLERD
checkrollerdphase 3
checkkeyid $pubkeyid rollerd should have started using the pub key "(in phase 3)"

# check that zonesigner does the right thing and uses the current key too
$ZONESIGNER example.com
checkkeyid $pubkeyid zonesigner should be using the pub key now
log checked phase 3 for rollerd/zonesigner


# sleep and run again and pub should switch to current and we should
# get a new pub
sleep 60
log "running rollerd again to jump from 2 to 3"
$ROLLERD
checkrollerdphase 3
checkkeyid $pubkeyid rollerd should have started using the pub key "(in phase 3)"

# check that zonesigner does the right thing and uses the current key too
$ZONESIGNER example.com
checkkeyid $pubkeyid zonesigner should be using the pub key now
log checked phase 3 '(right after 2)' for rollerd/zonesigner
