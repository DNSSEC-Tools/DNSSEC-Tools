#
# Copyright 2007-2011 SPARTA, Inc.  All rights reserved.
# See the COPYING file included with the DNSSEC-Tools package for details.
#
# Makefile for building demo data for the basic rollerd demo.
#

DIREXIN=	dir-example-in
DIREXOUT=	dir-example-out

all: basic

basic:		clean new-files zones-short

new-files:
	mkdir ${DIREXIN}
	mkdir ${DIREXOUT}

	cp save-demo.rollrec demo.rollrec
	cp save-example.com ${DIREXOUT}/example.com
	cp save-inside.example.com ${DIREXIN}/inside.example.com
	cp save-test.com test.com

	phaser demo.rollrec

zones-short:
	cd ${DIREXOUT} ; zonesigner -krf example.com.krf -zone example.com -zsklife 90 -genkeys example.com
	cd ${DIREXIN} ; zonesigner -krf inside.example.com.krf -zone example.com -zsklife 60 -e now+25 -genkeys inside.example.com
	zonesigner -zsklife 30 -genkeys test.com

clean:
	rm -f K* db.* dsset-* keyset-* *.krf *.signed
	rm -f test.com demo.rollrec
	rm -fr SAVE-KEYS*
	rm -fr ${DIREXIN} ${DIREXOUT}
	@echo NOT deleting log.demo

