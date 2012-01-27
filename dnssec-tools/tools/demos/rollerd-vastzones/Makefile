#
# Copyright 2011-2012 SPARTA, Inc.  All rights reserved.
# See the COPYING file included with the DNSSEC-Tools package for details.
#
# Makefile for building demo data for the vastzones rollerd demo.
#

all: fifty

ten:	clean
	makezones -count 10 -zs -genkeys

fifty:	clean
	makezones -count 50 -zs -genkeys

two-hundred:	clean
	makezones -count 200 -zs -genkeys


clean:
	rm -f K* db.* dsset-* keyset-* *.krf *.signed
	rm -f example* demo.rollrec
	rm -fr SAVE-KEYS*
	@echo NOT deleting log.demo

