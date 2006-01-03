#!/usr/bin/perl
# Copyright 2005 SPARTA, Inc.  All rights reserved.
# See the COPYING file distributed with this software for details

use ExtUtils::MakeMaker;

%opts = (
	 'NAME'		=> 'dnssec-tools',
	 'PREREQ_PM'    => { Net::DNS::SEC::Tools::conf => '0.01',
			     Net::DNS::SEC::Tools::keyrec => '0.01',
			     Net::DNS::SEC::Tools::tooloptions => '0.01',
			   },
#	 'VERSION_FROM'	=> 'zonesigner', # finds $VERSION
	 'EXE_FILES' => [qw(expchk keyrec-check lskrf getdnskeys
			    genkrf zonesigner)]
	);

WriteMakefile(%opts);
