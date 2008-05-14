#
# Copyright 2008 SPARTA, Inc.  All rights reserved.
# See the COPYING file included with the DNSSEC-Tools package for details.
#
# Makefile for building test data for the basic rollerd/zonesigner test.
#

default:	test-short

test-short:	clean-quiet newfiles zones-short runit message

test-medium:	clean-quiet newfiles zones-medium runit message

test-long:	clean-quiet newfiles zones-long runit message

newfiles:
	@echo 'Copying template files'
	@echo ' '
	@cp save-test.rollrec test.rollrec
	@cp save-db.cache db.cache
	@cp save-example.com example.com

zones-short:
	@echo 'Test has KSK lifespan of 8 minutes and ZSK lifespan of 1 minute'
	@echo ' '
	@perl -pi -e 's/ttl/1m/' example.com
	zonesigner -zsklife 60 -ksklife 480 -genkeys example.com

zones-medium:
	@echo 'Test has KSK lifespan of 10 minutes and ZSK lifespan of 30 seconds'
	@echo ' '
	@perl -pi -e 's/ttl/30s/' example.com
	zonesigner -zsklife 30 -ksklife 600 -genkeys example.com

zones-long:
	@echo 'Test has KSK lifespan of 40 minutes and ZSK lifespan of 5 minutes'
	@echo ' '
	@perl -pi -e 's/ttl/5m/' example.com
	zonesigner -zsklife 300 -ksklife 2400 -genkeys example.com

runit:
	@echo ' '
	@echo 'Adjusting phasestart in rollrec'
	@echo ' '
	@phaser test.rollrec

message:
	@echo ' '
	@echo 'You must now execute "runtest"'
	@echo ' '


clean-quiet:
	@echo ' '
	@echo 'Cleaning old test files'
	@echo ' '
	@rm -f K* db.* dsset-* keyset-* *.krf *.signed
	@rm -f example.com db.cache test.rollrec
	@rm -f log.test

clean:
	rm -f K* db.* dsset-* keyset-* *.krf *.signed
	rm -f example.com db.cache test.rollrec
	@echo NOT deleting log.test

targets:
	@echo ' '
	@echo 'available targets:  test-short (default), test-medium, test-long, clean'
