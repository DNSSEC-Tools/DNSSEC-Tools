#
# Copyright 2008 SPARTA, Inc.  All rights reserved.
# See the COPYING file included with the DNSSEC-Tools package for details.
#
# Makefile for building test data for the basic rollerd/zonesigner test.
#

test:	clean newfiles zones runit

newfiles:
	cp save-test.rollrec test.rollrec
	cp save-db.cache db.cache
	cp save-example.com example.com

zones:
	zonesigner -zsklife 60 -genkeys example.com

runit:
	phaser test.rollrec


clean:
	rm -f K* db.* dsset-* keyset-* *.krf *.signed
	rm -f example.com db.cache test.rollrec
	@echo NOT deleting log.test
