#!/usr/bin/perl

open(MF,"> Makefile");

print MF <<EOF;
#
# Copyright 2004 Sparta, inc.  All rights reserved.  See the COPYING
# file distributed with this software for details
#
# This is a makefile for the test directory of the dnssec-tools perl modules.
#

TESTFILES=	isles.keyrec	\\
		test.keyrec	\\
		tools.conf

all:
	\@echo nothing to make

install:
	\@echo nothing to install

clean:
	\@rm -f \${TESTFILES}
EOF

exit(0);
