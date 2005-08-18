#!/usr/bin/perl
# Copyright 2004 Sparta, inc.  All rights reserved.  See the COPYING
# file distributed with this software for details

use ExtUtils::MakeMaker;

%opts = (
	 'NAME'		=> 'Net::DNS::SEC::Tools::Dnspktflow::dnspktflow',
	 'PREREQ_PM'    => { GraphViz => 0,
			     File::Temp => 0,
			     IO::File => 0
			   },
	 'EXE_FILES' => [qw(dnspktflow)],

#	 'depend' => {'pure__install' => 'installrulefiles'},

	);

WriteMakefile(%opts);
