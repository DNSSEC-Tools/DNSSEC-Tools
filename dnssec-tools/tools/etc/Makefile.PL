#!/usr/bin/perl
# Copyright 2004-2011 SPARTA, Inc.  All rights reserved.  See the COPYING
# file distributed with this software for details

use ExtUtils::MakeMaker;
require 5;
use Getopt::Long;
my %cmdopts;
# determine if we are in larger build and prepend libval-config path 
GetOptions(\%cmdopts, 'sysconfdir=s', 'topdir=s');

%opts = (
	 'NAME' => 'etc',
#	 'depend' => {'pure__install' => 'installrulefiles'},
	);

# this should be a function of PREFIX and be able to be relocated(?)

sub MY::postamble {
    return '

SYSCONFDIR=' . "$cmdopts{sysconfdir}" . '
CONFDIR=$(SYSCONFDIR)/dnssec-tools
DESTCONFDIR=$(DESTDIR)$(CONFDIR)
INSTALL=$(PERLRUN) "-MExtUtils::Command" -e cp

install:: installrulefiles

installrulefiles:
	$(MKPATH) $(DESTCONFDIR)
	@if test -f $(DESTCONFDIR)/dnssec-tools.conf ; then \
		echo "**********************************************************************" ; \
		echo "*** Not installing over $(DESTCONFDIR)/dnssec-tools.conf" ; \
		echo "**********************************************************************" ; \
	else \
		$(INSTALL) dnssec-tools/dnssec-tools.conf $(DESTCONFDIR) ; \
		echo "installing dnssec-tools.conf in $(DESTCONFDIR)" ; \
	fi
';
}

WriteMakefile(%opts);

