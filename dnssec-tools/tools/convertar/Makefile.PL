#!/usr/bin/perl
# Copyright 2005-2011 SPARTA, Inc.  All rights reserved.
# See the COPYING file distributed with this software for details.

use ExtUtils::MakeMaker;

%opts = (
	 'NAME'		=> 'convertar',
	 'EXE_FILES' => [qw(convertar)],
	 'PREREQ_PM'    => { XML::Simple => 0,
			     IO::File => 0 },
	);

WriteMakefile(%opts);


#------------------------------------------------------------------------

use strict;

my $havexmlsax = eval {
	require XML::SAX;
};

my $packedmakefilestr;			# Makefile lines for packing files.
my $xmlsaxmods = "";			# XML::SAX available modules
my $xmlsaxcpcmds = "";			# XML::SAX install commands
my $xmlsaxcleancmds = "";		# XML::SAX clean-up commands
my $xmlsaxppargs = "";			# XML::SAX needed pp arguments

if ($havexmlsax) {
	import XML::SAX;

	my $pddir;				# Parser-details directory.
	my $pdfile = "ParserDetails.ini";	# Actual parser-details file.
	my $parserdetails;			# Parser-details file.

	#
	# Get a path to the XML::SAX ParserDetails file.
	#
	$pddir = "$INC{'XML/SAX.pm'}";
	$pddir =~ s/\.pm$//;
	$parserdetails = "$pddir/$pdfile";

	$xmlsaxmods ="-M XML::LibXML::SAX		\\
	  -M XML::SAX::PurePerl         \\\n";
	$xmlsaxcpcmds = "\$(RM) -fr SAX
	\$(MKDIR) SAX
	\$(CP) $parserdetails SAX/$pdfile\n";

	$xmlsaxcleancmds ="\$(RM) -f \$(packer_convertar) \$(DTCONFFILE) $pdfile
	\$(RM) -fr SAX\n";

	$xmlsaxppargs = "-a SAX/$pdfile"

}

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

CP	= /bin/cp
MKDIR	= /bin/mkdir
RM	= /bin/rm
PP	= /usr/bin/pp


DTCONFFILE = dnssec-tools.conf.PAR
CONF_DT    = -a \"dnssec-tools.conf.PAR;dnssec-tools.conf\"

#######


MODULES = \$(MOD_DNS) \$(MOD_TAR) \$(MOD_STD) \$(CONF_DT)

#######

PACKEDCMDS = pack_convertar

packer_convertar = convertar.\`uname -s\`

packed_commands: newconf \$(PACKEDCMDS) pack_cleaner

#######

newconf:
	dtinitconf -noprompt -overwrite -outfile \$(DTCONFFILE)

pack_convertar: copy_parser
	\$(RM) -f \$(packer_convertar)
	\$(PP) -o \$(packer_convertar) $xmlsaxppargs \$(MODULES) convertar
	\@echo ' '

copy_parser:
	$xmlsaxcpcmds

pack_cleaner:
	\$(RM) -f \$(DTCONFFILE)

clean_packed:
	\$(RM) -f \$(packer_convertar)
	$xmlsaxcleancmds

MOD_TAR =							\\
	-M Net::DNS::SEC::Tools::TrustAnchor			\\
	-M Net::DNS::SEC::Tools::TrustAnchor::Bind		\\
	-M Net::DNS::SEC::Tools::TrustAnchor::Csv		\\
	-M Net::DNS::SEC::Tools::TrustAnchor::Dump		\\
	-M Net::DNS::SEC::Tools::TrustAnchor::Itar		\\
	-M Net::DNS::SEC::Tools::TrustAnchor::Libval		\\
	-M Net::DNS::SEC::Tools::TrustAnchor::Mf

MOD_DNS = -M Net::DNS::SEC::Tools::conf			\\
	  -M Net::DNS::SEC::Tools::QWPrimitives

MOD_STD = $xmlsaxmods	  -M Data::Dumper		\\
	  -M Exporter			\\
	  -M IO::File			\\
	  -M Text::CSV			\\
	  -M Text::CSV_PP		\\
	  -M XML::Simple		

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
