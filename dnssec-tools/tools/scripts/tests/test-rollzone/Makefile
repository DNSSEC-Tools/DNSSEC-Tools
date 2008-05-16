#
# Copyright 2008 SPARTA, Inc.  All rights reserved.
# See the COPYING file included with the DNSSEC-Tools package for details.
#
# Makefile for building test data for the basic rollerd/zonesigner test.
#

default:	newfiles

newfiles:
	@echo ' '
	@echo 'Copying template files'
	@echo ' '
	@cp save-test.rollrec test.rollrec
	@cp save-db.cache db.cache
	@cp save-example.com example.com
	@echo 'You must now execute "runtest"'
	@echo ' '

clean-quiet:
	@rm -f K* db.* dsset-* keyset-* *.krf *.signed
	@rm -f example.com db.cache test.rollrec
	@rm -f log.test

clean:
	@echo ' '
	@echo 'Cleaning old test files'
	@echo ' '
	rm -f K* db.* dsset-* keyset-* *.krf *.signed
	rm -f example.com db.cache test.rollrec
	@echo NOT deleting log.test

targets:
	@echo ' '
	@echo 'available targets:  newfiles, clean, and clean-quiet'
