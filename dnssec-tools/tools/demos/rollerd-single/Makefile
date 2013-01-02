#
# Copyright 2012-2013 SPARTA, Inc.  All rights reserved.
# See the COPYING file included with the DNSSEC-Tools package for details.
#
# Makefile for building demo data for the basic rollerd demo.
#

all: clean new-files zones

new-files:
	cp save-demo.rollrec demo.rollrec
	cp save-example.com example.com

	phaser demo.rollrec

zones:
	zonesigner -zsklife 15 -ksklife 60 -e +864000 -genkeys example.com


clean:
	rm -f K* db.* dsset-* keyset-* *.krf *.signed
	rm -f example.com demo.rollrec log.demo
	rm -fr SAVE-KEYS*
#	@echo NOT deleting log.demo

