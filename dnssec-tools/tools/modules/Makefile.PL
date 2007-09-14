#!/usr/bin/perl
# Copyright 2004-2007 SPARTA, Inc.  All rights reserved.  See the COPYING
# file distributed with this software for details

$DIRS = ['ZoneFile-Fast'];
if ($ARGV[0] ne 'NOVALIDATOR') {
    push @$DIRS, 'Net-DNS-SEC-Validator', 'Net-addrinfo';
}

use ExtUtils::MakeMaker;

%opts = (
	 'NAME'		=> 'Net::DNS::SEC::Tools::conf',
	 'VERSION_FROM'	=> 'conf.pm', # finds $VERSION
<<<<<<< .mine
	 'DIR'          => ['ZoneFile-Fast',
#			    'Net-DNS-SEC-Validator',
			    'Net-addrinfo'],   # avoids the testing dir
=======
	 'DIR'          => $DIRS,   # avoids the testing dir
>>>>>>> .r3648
#	 'PM' =>           { conf.pm => '$(INST_LIBDIR)/install_as.pm'}
	);

WriteMakefile(%opts);
