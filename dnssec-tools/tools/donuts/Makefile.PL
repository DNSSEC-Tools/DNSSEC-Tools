#!/usr/bin/perl
# Copyright 2004 SPARTA, Inc.  All rights reserved.  See the COPYING
# file distributed with this software for details

use ExtUtils::MakeMaker;

%opts = (
	 'NAME'		=> 'Net::DNS::SEC::Tools::Donuts::donuts',
	 'PREREQ_PM'    => { Date::Parse => '2.2',
			   },
	 'EXE_FILES' => [qw(donuts donutsd)],

#	 'depend' => {'pure__install' => 'installrulefiles'},

	);

WriteMakefile(%opts);

sub MY::postamble {
    return '

RULESDIR=$(SITEPREFIX)/share/donuts/rules
INSTALL=$(PERLRUN) "-MExtUtils::Command" -e cp

install:: installrulefiles

installrulefiles:
	$(MKPATH) $(RULESDIR)
	$(INSTALL) rules/*.txt $(RULESDIR)

';
}
