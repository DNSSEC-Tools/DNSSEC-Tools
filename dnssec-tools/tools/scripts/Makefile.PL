#!/usr/bin/perl
# Copyright 2004 Sparta, Inc.  All rights reserved.  See the COPYING
# file distributed with this software for details

use ExtUtils::MakeMaker;

%opts = (
	 'NAME'		=> 'dnssec-tools',
	 'PREREQ_PM'    => { Net::DNS::Sec::DNSSecTools::conf => '0.01',
			     Net::DNS::Sec::DNSSecTools::keyrec => '0.01',
			     Net::DNS::Sec::DNSSecTools::tooloptions => '0.01',
			   },
#	 'VERSION_FROM'	=> 'zonesigner', # finds $VERSION
	 'EXE_FILES' => [qw(expchk keyrec-check lskrf zonesigner)]
	);

WriteMakefile(%opts);
