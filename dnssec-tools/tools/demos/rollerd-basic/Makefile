#
# Copyright 2007-2011 SPARTA, Inc.  All rights reserved.
# See the COPYING file included with the DNSSEC-Tools package for details.
#
# Makefile for building demo data for the basic rollerd demo.
#

all: basic

basic:		short

basic-rollerd:	basic

basic-short:	short

basic-same:	same

basic-long:	long

new-files:
	cp save-demo.rollrec demo.rollrec
	cp save-example.com example.com
	cp save-test.com test.com

	phaser demo.rollrec

zones-short:
	zonesigner -zsklife 30 -genkeys example.com
	zonesigner -zsklife 30 -e now+25 -genkeys test.com

#	zonesigner -zsklife 30 -kskdirectory /tmp/e-ksk -zskdirectory /tmp/e-zsk -genkeys example.com
#	zonesigner -zsklife 30 -e now+25 -kskdirectory /tmp/t-ksk -zskdirectory /tmp/t-zsk -genkeys test.com

zones-same:
	zonesigner -zsklife 30 -genkeys example.com
	zonesigner -zsklife 30 -genkeys test.com

zones-diff:
	zonesigner -zsklife 90 -genkeys example.com
	zonesigner -zsklife 90 -ksklife 90 -genkeys test.com

zones-long:
	zonesigner -zsklife 7200 -genkeys example.com
	zonesigner -zsklife 3600 -e now+25 -genkeys test.com


long:	clean zones-long new-files

short:	clean new-files zones-short

same:	clean zones-same new-files

clean:
	rm -f K* db.* dsset-* keyset-* *.krf *.signed
	rm -f example.com test.com demo.rollrec
	rm -fr SAVE-KEYS*
	@echo NOT deleting log.demo

