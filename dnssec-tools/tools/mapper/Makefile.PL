#!/usr/bin/perl
# Copyright 2004 SPARTA, Inc.  All rights reserved.  See the COPYING
# file distributed with this software for details

use ExtUtils::MakeMaker;

%opts = (
	 'NAME'		=> 'Net::DNS::SEC::Tools::Mapper::mapper',
	 'PREREQ_PM'    => { Text::Wrap => '2001'
			   },
	 'EXE_FILES' => [qw(mapper)],

#	 'depend' => {'pure__install' => 'installrulefiles'},

	);

WriteMakefile(%opts);
