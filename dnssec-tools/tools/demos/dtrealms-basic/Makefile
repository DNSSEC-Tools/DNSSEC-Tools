#
# Copyright 2012 SPARTA, Inc.  All rights reserved.
# See the COPYING file included with the DNSSEC-Tools package for details.
#
# Makefile for building demo data for the basic dtrealms demo.
#

all: basic

basic:		new-files setup
	@echo ' '
	@echo ' '
	@echo ' ----------------------------------------------------------- '
#	./dtrealms

new-files:	clean example-realm test-realm
	@cp savefiles/demo.realm .

example-realm:
	@echo ' '
	@echo 'building the example realm'
	@echo '	building configuration directories'
	@mkdir -p configs/example/dnssec-tools
	@cp savefiles/example-conf configs/example/dnssec-tools/dnssec-tools.conf
	@echo '	building state directories'
	@mkdir -p states/example
	@echo '	building directory for r-example'
	@mkdir -p r-example/dnssec-tools
	@cp savefiles/example-Makefile r-example/Makefile
	@cp savefiles/example-rollrec r-example/demo-example.rollrec
	@cp savefiles/example-demo.com r-example/demo.com
	@cp savefiles/example-example.com r-example/example.com
	@cp savefiles/example-test.com r-example/test.com
	@cp savefiles/rc.blinkenlights r-example/
	@echo '	building other files'
	@mkconffiles configs/example/dnssec-tools/dnssec-tools.conf r-example

test-realm:
	@echo ' '
	@echo 'building the test realm'
	@echo '	building configuration directories'
	@mkdir -p configs/test/dnssec-tools
	@cp savefiles/test-conf configs/test/dnssec-tools/dnssec-tools.conf
	@echo '	building state directories'
	@mkdir -p states/test
	@echo '	building directory for r-test'
	@mkdir -p r-test/dnssec-tools
	@cp savefiles/test-Makefile r-test/Makefile
	@cp savefiles/test-rollrec r-test/demo-test.rollrec
	@cp savefiles/test-dev.com r-test/dev.com
	@cp savefiles/test-test.com r-test/test.com
	@cp savefiles/rc.blinkenlights r-test/
	@echo '	building other files'
	@mkconffiles configs/test/dnssec-tools/dnssec-tools.conf r-test

setup:	setup-example setup-test

setup-example:
	@echo ' '
	@echo ' ----------------------------------------------------------- '
	@echo 'setting up files for r-example'
	cd r-example ; make

setup-test:
	@echo ' '
	@echo ' ----------------------------------------------------------- '
	@echo 'setting up files for r-test'
	cd r-test ; make

clean:
	@rm -fr configs
	@rm -fr run
	@rm -fr states
	@rm -fr r-example
	@rm -fr r-test
	@rm -f demo.realm

