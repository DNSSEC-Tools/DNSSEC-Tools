#!/usr/bin/perl
#
# Copyright 2009-2013 SPARTA, Inc.  All rights reserved.  See the COPYING
# file distributed with this software for details
#


use ExtUtils::MakeMaker;

%opts = (
		'NAME'	=> 'DNSSEC-Tools'
	);

WriteMakefile(%opts);

#------------------------------------------------------------------------

use strict;

#------------------------------------------------------------------------
#
# The packer parts of the makefile are the next large block of text.
#
# The following targets are available for general use:
#
#	packed_dist		Gather the packed commands, building if needed.
#	packed_distclean	Clean the gathered packed commands.
#       packed_commands         Build the packed command files.
#       clean_packed            Clean the packed commands.
#

my $packedmakefilestr = "

##########################################################################
#
# The following Makefile sections are for creating packed commands.
#

RM	= /bin/rm
MKDIR	= /bin/mkdir
CP	= /bin/cp

PACKED_DIRS =	convertar	\\
		donuts		\\
		mapper		\\
		scripts

PACKDIR = packed-tools

packed_dist:	packed_commands
	\$(RM) -fr \$(PACKDIR)
	\$(MKDIR) \$(PACKDIR)
	\$(CP) `find . -name '*.Darwin' -print` \$(PACKDIR)

packed_distclean:
	\$(RM) -fr \$(PACKDIR)

packed_commands:
	\@for d in \$(PACKED_DIRS);				\\
	do							\\
		echo \"building packed commands in \$\$d\";	\\
		cd \$\$d;					\\
		make packed_commands;				\\
		echo \" \";					\\
		cd ..;						\\
	done

clean_packed:
	\@for d in \$(PACKED_DIRS);				\\
	do							\\
		echo \"cleaning packed commands in \$\$d\";	\\
		cd \$\$d;					\\
		make clean_packed;				\\
		echo \" \";					\\
		cd ..;						\\
	done


";

#
# This is the end of the packer text that is added to the makefile.
#
#------------------------------------------------------------------------


#
# Write the makefile lines to the makefile.
#
open(MK,">> Makefile");
print MK $packedmakefilestr;
close(MK);

