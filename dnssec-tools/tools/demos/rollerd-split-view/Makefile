#
# Copyright 2007-2010 SPARTA, Inc.  All rights reserved.
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
	cp save-subdom.example.com subdom.example.com
	cp save-subdom.in.example.com subdom.in.example.com
	cp save-test.com test.com

	phaser demo.rollrec

zones-short:
	zonesigner -krf subdom.example.com.krf -zone subdom.example.com -zsklife 60 -genkeys subdom.example.com
	zonesigner -krf subdom.in.example.com.krf -zone subdom.example.com -zsklife 30 -e +25 -genkeys subdom.in.example.com
	zonesigner -zsklife 30 -genkeys test.com

zones-same:
	zonesigner -zsklife 60 -genkeys subdom.example.com
	zonesigner -zsklife 60 -genkeys subdom.in.example.com
	zonesigner -zsklife 60 -genkeys test.com

zones-long:
	zonesigner -zsklife 7200 -genkeys subdom.example.com
	zonesigner -zsklife 3600 -e +25 -genkeys subdom.in.example.com
	zonesigner -zsklife 7200 -genkeys test.com


long:	clean zones-long new-files

short:	clean new-files zones-short

same:	clean zones-same new-files

clean:
	rm -f K* db.* dsset-* keyset-* *.krf *.signed
	rm -f subdom.example.com subdom.in.example.com test.com demo.rollrec
	rm -fr SAVE-KEYS*
	@echo NOT deleting log.demo

