#!/usr/bin/perl
# Copyright 2004 SPARTA, Inc.  All rights reserved.  See the COPYING
# file distributed with this software for details

use ExtUtils::MakeMaker;

%opts = (
	 'NAME' => 'etc',
#	 'depend' => {'pure__install' => 'installrulefiles'},
	);

# this should be a function of PREFIX and be able to be relocated(?)

sub MY::postamble {
    return '

CONFDIR=/usr/local/etc/dnssec
INSTALL=$(PERLRUN) "-MExtUtils::Command" -e cp

install:: installrulefiles

installrulefiles:
	$(MKPATH) $(CONFDIR)
	$(INSTALL) dnssec/dnssec-tools.conf $(CONFDIR)

';
}

WriteMakefile(%opts);

