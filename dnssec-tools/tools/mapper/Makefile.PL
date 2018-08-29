#!/usr/bin/perl
# Copyright 2004-2013 SPARTA, Inc.  All rights reserved.  See the COPYING
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

#------------------------------------------------------------------------

use strict;

my $packedmakefilestr;			# Makefile lines for packing files.


#------------------------------------------------------------------------
#
# The packer parts of the makefile are the next large block of text.
#
# The following targets are available for general use:
#
#	packed_commands		Build the packed command files.
#	clean_packed		Clean the packed commands.
#

$packedmakefilestr = "

##########################################################################
#
# The following Makefile sections are for creating packed commands.
#

RM	= /bin/rm
PP	= /usr/bin/pp


DTCONFFILE = dnssec-tools.conf.PAR
CONF_DT    = -a \"dnssec-tools.conf.PAR;dnssec-tools.conf\"

#######

MOD_STD = -M Date::Parse -M QWizard -M Data::Dumper -M Getopt::Long

MOD_DNS = -M Net::DNS::SEC::Tools::conf		\\
	  -M Net::DNS::SEC::Tools::QWPrimitives	\\
	  -M Net::DNS::SEC::Tools::BootStrap

MODULES = \$(MOD_DNS) \$(MOD_STD)

#######

PACKEDCMDS = pack_mapper

packer_mapper	  = mapper.\`uname -s\`

packed_commands: newconf \$(PACKEDCMDS) pack_cleaner

#######

newconf:
	dtinitconf -noprompt -overwrite -binddir .	\\
		-outfile \$(DTCONFFILE)

pack_mapper:
	\$(RM) -f \$(packer_mapper)
	\$(PP) -o \$(packer_mapper) \$(MODULES) \$(CONF_DT) mapper
	\@echo ' '


clean_packed:	pack_cleaner
	\$(RM) -f \$(packer_mapper)

pack_cleaner:
	\$(RM) -f dnssec-tools.conf.PAR

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
