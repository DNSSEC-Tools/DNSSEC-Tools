#
# Copyright 2011-2013 SPARTA, Inc.  All rights reserved.
# See the COPYING file included with the DNSSEC-Tools package for details.
#
# Makefile for building demo data for the basic rollerd demo.
#

all: clean new-files zones

new-files:
	cp save-demo.rollrec demo.rollrec
	cp save-example-000.com example-000.com
	cp save-example-001.com example-001.com
	cp save-example-002.com example-002.com
	cp save-example-003.com example-003.com
	cp save-example-004.com example-004.com
	cp save-example-005.com example-005.com
	cp save-example-006.com example-006.com
	cp save-example-007.com example-007.com
	cp save-example-008.com example-008.com
	cp save-example-009.com example-009.com

	phaser demo.rollrec

zones:
	zonesigner -zsklife 30 -ksklife 30 example-000.com
	zonesigner -zsklife 45 -ksklife 45 example-001.com
	zonesigner -zsklife 60 -ksklife 60 example-002.com
	zonesigner -zsklife 45 -ksklife 45 example-003.com
	zonesigner -zsklife 30 -ksklife 30 example-004.com
	zonesigner -zsklife 45 -ksklife 45 example-005.com
	zonesigner -zsklife 60 -ksklife 60 example-006.com
	zonesigner -zsklife 45 -ksklife 45 example-007.com
	zonesigner -zsklife 30 -ksklife 30 example-008.com
	zonesigner -zsklife 45 -ksklife 45 example-009.com

clean:
	rm -f K* db.* dsset-* keyset-* *.krf *.signed
	rm -f example*.com demo.rollrec
	rm -fr SAVE-KEYS*
	@echo NOT deleting log.demo

