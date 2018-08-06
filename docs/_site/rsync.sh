#!/bin/sh

if [ ! -f rsync.sh ] ; then
  echo "This must be run from within the htdocs dir itself"
  exit
fi

pwd=`pwd`
dir=`basename $pwd`
cd ..
rsync --delete-excluded --exclude .svn --exclude 'docs/step-by-step/*.ps' -av $dir hardaker,dnssec-tools@web.sourceforge.net:/home/groups/d/dn/dnssec-tools/
