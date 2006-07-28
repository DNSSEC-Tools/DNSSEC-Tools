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
	if test -f $(CONFDIR)/dnssec-tools.conf ; then \\
		echo "**********************************************************************" ; \\
		echo "*** Not installing over $(CONFDIR)/dnssec-tools.conf" ; \\
		echo "**********************************************************************" ; \\
	else \\
		$(INSTALL) dnssec/dnssec-tools.conf $(CONFDIR) ; \\
	fi

';
}

WriteMakefile(%opts);

