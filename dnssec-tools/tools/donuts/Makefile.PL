#!/usr/bin/perl
# Copyright 2004-2007 SPARTA, Inc.  All rights reserved.  See the COPYING
# file distributed with this software for details

use ExtUtils::MakeMaker;

%opts = (
	 'NAME'		=> 'Net::DNS::SEC::Tools::Donuts::donuts',
	 'PREREQ_PM'    => { Date::Parse => '2.2',
			   },
	 'EXE_FILES' => [qw(donuts donutsd)],
	 'PM_FILTER' => 'sed -e "s|/usr/local/share|$(PREFIX)/share|"',

#	 'depend' => {'pure__install' => 'installrulefiles'},

	);

WriteMakefile(%opts);

sub MY::postamble {
    return '

RULESDIR=$(DESTDIR)/$(PREFIX)/share/donuts/rules

INSTALL=$(PERL) "-MExtUtils::Command" -e cp

install:: installrulefiles

installrulefiles:
	$(MKPATH) $(RULESDIR)
	$(INSTALL) rules/*.txt $(RULESDIR)
';
}
