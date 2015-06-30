#!/usr/bin/perl
# Copyright 2004-2013 SPARTA, Inc.  All rights reserved.  See the COPYING
# file distributed with this software for details

use ExtUtils::MakeMaker;

%opts = (
	 'NAME'		=> 'Net::DNS::SEC::Tools::Donuts::donuts',
	 'PREREQ_PM'    => { Date::Parse => '2.2',
			   },
	 'EXE_FILES' => [qw(donuts donutsd)],
	 'PM_FILTER' => 'sed -e "s|/usr/local/share|$(PREFIX)/share|"',

#	 'depend' => {'pure__install' => 'installrulefiles'},

	);

WriteMakefile(%opts);

sub MY::postamble {
    return '

RULESDIR=$(DESTDIR)/$(PREFIX)/share/dnssec-tools/donuts/rules

INSTALL=$(PERL) "-MExtUtils::Command" -e cp

install:: installrulefiles installfixpaths

installrulefiles:
	$(MKPATH) $(RULESDIR)
	$(INSTALL) rules/*.txt $(RULESDIR)

installfixpaths:
	$(PERL) -p -i -e "s|/usr/local/share|$(PREFIX)/share|" $(DISTDIR)/$(INSTALLBIN)/donuts
';
}

#------------------------------------------------------------------------

use strict;

my $tddir;				# tcpdump directory.
my $packedmakefilestr;			# Makefile lines for packing files.

my $tdcmd = "tcpdump";			# tcpdump command to look for.
my @commondirs =			# Directories to search for tcpdump.
(
	"/bin",
	"/sbin",
	"/usr/sbin",
	"/usr/bin",
	"/usr/local/bin",
	"/usr/local/sbin",
	"/opt/local/bin",
	"/opt/local/sbin",
);

#
# Finds the location of tcpdump.
# The location is saved, or NULL if the command wasn't found.
#
foreach my $dir (@commondirs)
{
	my $bpath;				# tcpdump path.

	$bpath = "$dir/$tdcmd";

	if((-e $bpath) && (-f $bpath))
	{
		$tddir = $dir;
		last;
	}
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

TDDIR = $tddir

CP	= cp
RM	= rm
PP	= pp
FIND	= find
GREP	= grep

#######

LOCALRULESDIR	= rules
RULESFILE	= rules.list

DTCONFFILE = dnssec-tools.conf.PAR
CONF_DT    = -a \"dnssec-tools.conf.PAR;dnssec-tools.conf\"

#######

MODULES = \$(MOD_NET) \$(MOD_DNS) \$(MOD_DT) \$(MOD_DNSRR) \$(MOD_STD) \$(PACKLIBS)

MOD_DONUTSD = -M Net::SMTP				\\
	      -M XML::Smart				\\
	      -M Net::DNS::SEC::Tools::conf		\\
	      -M Net::DNS::SEC::Tools::QWPrimitives 

#######

STDLIBS = -l crypto -l pcap

PACKLIBS  = \$(STDLIBS)

#######

PROGS_TD   = -a tcpdump

PROGS_PACK = \$(PROGS_TD)

#######

PACKEDCMDS = pack_donuts pack_donutsd

packer_donuts  = donuts.\`uname -s\`
packer_donutsd = donutsd.\`uname -s\`

packed_commands: newconf \$(PACKEDCMDS) pack_cleaner

#######

newconf:
	dtinitconf -noprompt -overwrite -outfile \$(DTCONFFILE)

pack_donuts:	copy_tcpdump new_rules
	\$(RM) -f \$(packer_donuts)
	\$(PP) -o \$(packer_donuts) \$(MODULES) \$(CONF_DT) 		\\
		  -A \$(RULESFILE) \$(PROGS_PACK) donuts
	\@echo ' '

pack_donutsd:
	\$(RM) -f \$(packer_donutsd)
	\$(PP) -o \$(packer_donutsd) \$(CONF_DT) \$(MOD_DONUTSD)	\\
		  \$(PACKLIBS) -a donuts donutsd
	\@echo ' '

copy_tcpdump:
	\$(RM) -f tcpdump
	\$(CP) \$(TDDIR)/tcpdump tcpdump

new_rules:
	\$(RM) -f \$(RULESFILE)
	\$(FIND) \$(LOCALRULESDIR) | \$(GREP) -v '~' | \$(GREP) -v '.bak' | \$(GREP) -v '.svn' | \$(GREP) \\/ > \$(RULESFILE)


clean_packed:	pack_cleaner
	\$(RM) -f \$(packer_donuts) \$(packer_donutsd)

pack_cleaner:
	\$(RM) -f dnssec-tools.conf.PAR
	\$(RM) -f tcpdump
#	\$(RM) -f \$(RULESFILE)

MOD_STD =						\\
	-M Config      					\\
	-M Data::Dumper      				\\
	-M Date::Format					\\
	-M Date::Parse					\\
	-M Getopt::GUI::Long				\\
	-M Gtk2						\\
	-M QWizard					\\
	-M Text::Wrap

MOD_NET =						\\
	-M Net::DNS					

MOD_DT =						\\
	-M Net::DNS::SEC::Tools::BootStrap		\\
	-M Net::DNS::SEC::Tools::Donuts::Rule		\\
	-M Net::DNS::SEC::Tools::QWPrimitives		\\
	-M Net::DNS::SEC::Tools::conf			\\
	-M Net::DNS::SEC::Tools::defaults		\\
	-M Net::DNS::SEC::Tools::dnssectools

MOD_DNSRR =						\\
	-M Net::DNS::RR					\\
	-M Net::DNS::RR::DNSKEY				\\
	-M Net::DNS::RR::DS				\\
	-M Net::DNS::RR::NSEC				\\
	-M Net::DNS::RR::RRSIG

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
