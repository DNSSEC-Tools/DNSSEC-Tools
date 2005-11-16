#!/usr/bin/perl
# Copyright 2004 SPARTA, Inc.  All rights reserved.  See the COPYING
# file distributed with this software for details

use ExtUtils::MakeMaker;

%opts = (
	 'NAME'		=> 'Net::DNS::SEC::Tools::drawvalmap',
	 'PREREQ_PM'    => { GraphViz => 0,
                 Getopt::Long => 0,
                 IO::Socket::INET => 0,
			     IO::File => 0
			   },
	);

WriteMakefile(%opts);
