#!/usr/bin/perl
# Copyright 2004-2013 SPARTA, Inc.  All rights reserved.  See the COPYING
# file distributed with this software for details

use ExtUtils::MakeMaker;

%opts = (
	 'NAME'		=> 'Net::DNS::SEC::Tools::TrustAnchor::Itar',
	 'VERSION_FROM'	=> 'Itar.pm', # finds $VERSION
	);

WriteMakefile(%opts);
