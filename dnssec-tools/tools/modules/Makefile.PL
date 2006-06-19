#!/usr/bin/perl
# Copyright 2004-2006 SPARTA, Inc.  All rights reserved.  See the COPYING
# file distributed with this software for details

use ExtUtils::MakeMaker;

%opts = (
	 'NAME'		=> 'Net::DNS::SEC::Tools::conf',
	 'VERSION_FROM'	=> 'conf.pm', # finds $VERSION
	 'DIR'          => ['ZoneFile-Fast'],   # avoids the testing dir
#	 'PM' =>           { conf.pm => '$(INST_LIBDIR)/install_as.pm'}
	);

WriteMakefile(%opts);
