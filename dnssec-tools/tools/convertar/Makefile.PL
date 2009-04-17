#!/usr/bin/perl
# Copyright 2005-2009 SPARTA, Inc.  All rights reserved.
# See the COPYING file distributed with this software for details.

use ExtUtils::MakeMaker;

%opts = (
	 'NAME'		=> 'convertar',
	 'EXE_FILES' => [qw(convertar)]
	);

WriteMakefile(%opts);
