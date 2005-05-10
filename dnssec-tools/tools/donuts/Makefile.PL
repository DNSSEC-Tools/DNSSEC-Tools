#!/usr/bin/perl
# Copyright 2004 Sparta, inc.  All rights reserved.  See the COPYING
# file distributed with this software for details

use ExtUtils::MakeMaker;

%opts = (
	 'NAME'		=> 'Net::DNS::SEC::Tools::Donuts::donuts',
	 'PREREQ_PM'    => { Text::Wrap => '2001'
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
