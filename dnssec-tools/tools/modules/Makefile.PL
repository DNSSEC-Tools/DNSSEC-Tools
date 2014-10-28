#!/usr/bin/perl
# Copyright 2004-2014 SPARTA, Inc.  All rights reserved.  See the COPYING
# file distributed with this software for details

use ExtUtils::MakeMaker;

%opts = InitMakeParams();

WriteMakefile(%opts);

appendstuff();

sub InitMakeParams {
    $DIRS = ['ZoneFile-Fast'];
    if ($ARGV[0] ne 'NOVALIDATOR') {
	unshift @$DIRS, 'Net-DNS-SEC-Validator', 'Net-addrinfo';
    }

    %opts = (
	     'NAME'		=> 'Net::DNS::SEC::Tools::conf',
	     'VERSION_FROM'	=> 'conf.pm', # finds $VERSION
	     'DIR'          => $DIRS, # avoids the testing dir
	    );
    return %opts;
}

sub appendstuff {
	open(MK,">> Makefile");

	print MK '

%.pm:   %.pm.in
	cd $(CURDIR)/../.. && ./config.status

';

	close(MK);
}
