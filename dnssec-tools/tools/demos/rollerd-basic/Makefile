#
# Copyright 2006 SPARTA, Inc.  All rights reserved.
# See the COPYING file included with the DNSSEC-Tools package for details.
#
# Makefile for building demo data for the basic rollerd demo.
#

basic-rollerd:	basic

basic:		short

basic-short:	short

basic-same:	same

basic-long:	long

pristine-files:
	cp save-demo.rollrec demo.rollrec
	cp save-db.cache db.cache
	cp save-dummy.com dummy.com
	cp save-example.com example.com
	cp save-test.com test.com
	phaser demo.rollrec

zones-short:
	zonesigner -zsklife 15 -e +25 -genkeys dummy.com
	zonesigner -zsklife 60 -genkeys example.com
	zonesigner -zsklife 30 -genkeys test.com

zones-same:
	zonesigner -zsklife 60 -genkeys dummy.com
	zonesigner -zsklife 60 -genkeys example.com
	zonesigner -zsklife 60 -genkeys test.com

zones-long:
	zonesigner -zsklife 600 -e +25 -genkeys dummy.com
	zonesigner -zsklife 7200 -genkeys example.com
	zonesigner -zsklife 3600 -genkeys test.com


long:	clean zones-long pristine-files

short:	clean pristine-files zones-short

same:	clean zones-same pristine-files

clean:
	rm -f K* db.* dsset-* keyset-* *.krf *.signed
	rm -f dummy.com example.com test.com db.cache demo.rollrec
	@echo NOT deleting log.demo
