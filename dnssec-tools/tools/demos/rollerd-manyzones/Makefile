#
# Copyright 2006-2012 SPARTA, Inc.  All rights reserved.
# See the COPYING file included with the DNSSEC-Tools package for details.
#
# Makefile for building demo data for the many-zones rollerd demo.
#

all:	clean pristine-files zones

pristine-files:
	cp save-demo.rollrec demo.rollrec
#	cp save-demo-smallset.rollrec demo-smallset.rollrec
	cp save-dummy.com dummy.com
	cp save-example.com example.com
	cp save-test.com test.com
	cp save-woof.com woof.com
	cp save-xorn.com xorn.com
	cp save-yowzah.com yowzah.com
	cp save-zero.com zero.com
	phaser demo.rollrec
#	phaser demo-smallset.rollrec

zones:
	zonesigner -ksklife 600  -zsklife 120  -genkeys -e +25 dummy.com
	zonesigner -ksklife 125  -zsklife 30   -genkeys example.com
	zonesigner -ksklife 180  -zsklife 60   -genkeys test.com
	zonesigner -ksklife 300  -zsklife 120  -genkeys woof.com
	zonesigner -ksklife 800  -zsklife 300  -genkeys xorn.com
	zonesigner -ksklife 1200 -zsklife 600  -genkeys yowzah.com
	zonesigner -ksklife 7200 -zsklife 3600 -genkeys zero.com

clean:
	rm -f K* db.* dsset-* keyset-* *.krf *.signed
	rm -f dummy.com example.com test.com woof.com xorn.com yowzah.com zero.com
	rm -f demo.rollrec demo-smallset.rollrec
	@echo NOT deleting log.demo
	@echo ' '

