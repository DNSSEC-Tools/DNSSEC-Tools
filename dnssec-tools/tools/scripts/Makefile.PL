#!/usr/bin/perl
# Copyright 2005-2014 SPARTA, Inc.  All rights reserved.
# See the COPYING file distributed with this software for details.

use ExtUtils::MakeMaker;

%opts = (
	 'NAME'		=> 'dnssec-tools',
	 'PREREQ_PM'    => { 
			    Net::DNS::SEC::Tools::conf => '0.01',
			    Net::DNS::SEC::Tools::keyrec => '0.01',
			    Net::DNS::SEC::Tools::tooloptions => '0.01',
			   },
#	 'VERSION_FROM'	=> 'zonesigner', # finds $VERSION
	 'EXE_FILES' => [qw(
			    blinkenlights
			    bubbles
			    buildrealms
                            check-zone-expiration
			    cleanarch
			    cleankrf
			    dtck
			    dtconf
			    dtconfchk
			    dtdefs
			    dtinitconf
			    dtrealms
			    expchk
			    fixkrf
			    genkrf
			    getdnskeys
			    getds
			    grandvizier
			    keyarch
			    keymod
			    krfcheck
			    lights
			    lsdnssec
			    lskrf
			    lsrealm
			    lsroll
			    realmchk
			    realmctl
			    realminit
			    realmset
			    rollchk
			    rollctl
			    rollerd
			    rollinit
			    rolllog
			    rollrec-editor
			    rollset
			    signset-editor
			    tachk
			    timetrans
			    trustman
			    zonesigner
			   )]
	);

WriteMakefile(%opts);

#------------------------------------------------------------------------

use strict;

my $binddir;				# BIND directory.
my $packedmakefilestr;			# Makefile lines for packing files.

my $bindcmd = "dnssec-keygen";		# BIND command to look for.
my @commondirs =			# Common directories to search for BIND.
(
	"/bin",
	"/sbin",
	"/usr/bin",
	"/usr/sbin",
	"/usr/local/bin",
	"/usr/local/sbin",
	"/opt/local/bin",
	"/opt/local/sbin",
	"/etc/dnssec",
	"/etc",
);

#
# Finds the location of the BIND tools.  (A BIND tool...)
# The location is returned, or NULL if the command wasn't found.
#
foreach my $dir (@commondirs)
{
	my $bpath;				# BIND path.

	$bpath = "$dir/$bindcmd";

	if((-e $bpath) && (-f $bpath))
	{
		$binddir = $dir;
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

BINDDIR = $binddir

CP	= /bin/cp
RM	= /bin/rm
PP	= /usr/local/bin/pp


DTCONFFILE = dnssec-tools.conf.PAR
CONF_DT    = -a \"dnssec-tools.conf.PAR;dnssec-tools.conf\"

ROOTHINTSFILE = root.hints
ROOTHINTS  = -a \$(ROOTHINTSFILE)

RESOLVCONFFILE = resolv.conf
RESOLVCONF = -a \$(RESOLVCONFFILE)

#######

MOD_STD = -M lib -M Text::Wrap -M Date::Parse -M Date::Format -M Mail::Mailer::sendmail

MOD_NET	= -M Net::addrinfo -M Net::hostent -M Carp

MOD_DNS = -M Net::DNS -M Net::DNS::Keyset -M Net::DNS::SEC -M Net::DNS::SEC::Private

MODULES = \$(MOD_NET) \$(MOD_DNS) \$(MOD_DT) \$(MOD_DNSRR) \$(MOD_STD) \$(PACKLIBS)

#######

STDLIBS = -l crypto		\\
	  -l pthread

DTLIBS  = -l sres		\\
	  -l val-threads


PACKLIBS  = \$(STDLIBS) \$(DTLIBS)

#######

PROGS_BIND = -a dnssec-keygen -a dnssec-signzone -a named-checkzone -a rndc
PROGS_DT   = -a keyarch -a rollchk -a zonesigner

PROGS_PACK = \$(PROGS_BIND) \$(PROGS_DT)

#######

PACKEDCMDS = pack_rollctl pack_rollerd pack_zonesigner pack_trustman

packer_rollctl	  = rollctl.\`uname -s\`
packer_rollerd	  = rollerd.\`uname -s\`
packer_trustman	  = trustman.\`uname -s\`
packer_getds	  = getds.\`uname -s\`
packer_zonesigner = zonesigner.\`uname -s\`

packed_commands: newconf \$(PACKEDCMDS) pack_cleaner

#######

newconf:
	\$(RM) -f \$(ROOTHINTSFILE)
	\$(CP) /dev/null \$(RESOLVCONFFILE)
	dtinitconf -noprompt -overwrite -binddir .	\\
		-ksklife 60 -ksklength 2048		\\
		-zsklife 30 -zsklength 2048		\\
		-roll-sleep 60 -roll-loglevel info	\\
		-ta-resolvconf \$(RESOLVCONFFILE)	\\
		-genroothints \$(ROOTHINTSFILE)		\\
		-outfile \$(DTCONFFILE)

pack_rollctl:		copy_bind
	\$(RM) -f \$(packer_rollctl)
	\$(PP) -o \$(packer_rollctl) \$(MODULES) rollctl
	\@echo ' '

pack_rollerd:		copy_bind
	\$(RM) -f \$(packer_rollerd)
	\$(PP) -o \$(packer_rollerd) \$(MODULES) \$(CONF_DT) \$(PROGS_PACK) rollerd
	\@echo ' '

pack_trustman:		copy_bind
	\$(RM) -f \$(packer_trustman)
	\$(PP) -o \$(packer_trustman) \$(MODULES) \$(CONF_DT) \$(RESOLVCONF) \$(ROOTHINTS) trustman
	\@echo ' '

pack_getds:
	\$(RM) -f \$(packer_trustman)
	\$(PP) -o \$(packer_getds) \$(MODULES) \$(CONF_DT) \$(RESOLVCONF) \$(ROOTHINTS) getds
	\@echo ' '

pack_zonesigner:	copy_bind
	\$(RM) -f \$(packer_zonesigner)
	\$(PP) -o \$(packer_zonesigner) \$(MODULES) \$(CONF_DT) \$(PROGS_PACK) zonesigner
	\@echo ' '

copy_bind:
	\@for p in \$(PROGS_BIND);			\\
	 do						\\
		if test \"\$\$p\" != -a ;			\\
		then					\\
			\$(RM) -f \$\$p;			\\
			fp=\"\$(BINDDIR)/\$\$p\";		\\
			\$(CP) \$\$fp \$\$p;			\\
		fi					\\
	 done


clean_packed:	pack_cleaner
	\$(RM) -f \$(packer_rollctl) \$(packer_rollerd)
	\$(RM) -f \$(packer_trustman) \$(packer_zonesigner)

pack_cleaner:
	\@for p in \$(PROGS_BIND);			\\
	 do						\\
		if test \"\$\$p\" != -a ;			\\
		then					\\
			echo \$(RM) -f \$\$p;		\\
			\$(RM) -f \$\$p;			\\
		fi					\\
	 done
	\$(RM) -f dnssec-tools.conf.PAR
	\$(RM) -f root.hints


MOD_DT =						\\
	-M Net::DNS::SEC::Tools::BootStrap		\\
	-M Net::DNS::SEC::Tools::conf			\\
	-M Net::DNS::SEC::Tools::defaults		\\
	-M Net::DNS::SEC::Tools::dnssectools		\\
	-M Net::DNS::SEC::Tools::keyrec			\\
	-M Net::DNS::SEC::Tools::rolllog		\\
	-M Net::DNS::SEC::Tools::rollmgr		\\
	-M Net::DNS::SEC::Tools::rollrec		\\
	-M Net::DNS::SEC::Tools::timetrans		\\
	-M Net::DNS::SEC::Tools::tooloptions		\\
	-M Net::DNS::SEC::Validator \\

MOD_DNSRR =						\\
	-M Net::DNS::RR					\\
	-M Net::DNS::RR::A				\\
	-M Net::DNS::RR::AAAA				\\
	-M Net::DNS::RR::AFSDB				\\
	-M Net::DNS::RR::APL::ApItem			\\
	-M Net::DNS::RR::APL				\\
	-M Net::DNS::RR::CERT				\\
	-M Net::DNS::RR::CNAME				\\
	-M Net::DNS::RR::DLV				\\
	-M Net::DNS::RR::DNAME				\\
	-M Net::DNS::RR::DNSKEY				\\
	-M Net::DNS::RR::DS				\\
	-M Net::DNS::RR::EID				\\
	-M Net::DNS::RR::HINFO				\\
	-M Net::DNS::RR::IPSECKEY			\\
	-M Net::DNS::RR::ISDN				\\
	-M Net::DNS::RR::KEY				\\
	-M Net::DNS::RR::LOC				\\
	-M Net::DNS::RR::MB				\\
	-M Net::DNS::RR::MG				\\
	-M Net::DNS::RR::MINFO				\\
	-M Net::DNS::RR::MR				\\
	-M Net::DNS::RR::MX				\\
	-M Net::DNS::RR::NAPTR				\\
	-M Net::DNS::RR::NIMLOC				\\
	-M Net::DNS::RR::NS				\\
	-M Net::DNS::RR::NSAP				\\
	-M Net::DNS::RR::NSEC				\\
	-M Net::DNS::RR::NSEC3				\\
	-M Net::DNS::RR::NSEC3PARAM			\\
	-M Net::DNS::RR::NULL				\\
	-M Net::DNS::RR::NXT				\\
	-M Net::DNS::RR::OPT				\\
	-M Net::DNS::RR::PTR				\\
	-M Net::DNS::RR::PX				\\
	-M Net::DNS::RR::RP				\\
	-M Net::DNS::RR::RRSIG				\\
	-M Net::DNS::RR::RT				\\
	-M Net::DNS::RR::SIG				\\
	-M Net::DNS::RR::SOA				\\
	-M Net::DNS::RR::SPF				\\
	-M Net::DNS::RR::SRV				\\
	-M Net::DNS::RR::SSHFP				\\
	-M Net::DNS::RR::TKEY				\\
	-M Net::DNS::RR::TSIG				\\
	-M Net::DNS::RR::TXT				\\
	-M Net::DNS::RR::Unknown			\\
	-M Net::DNS::RR::X25

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
