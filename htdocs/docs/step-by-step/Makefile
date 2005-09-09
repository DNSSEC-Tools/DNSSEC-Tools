#
# Copyright 2004-2005 SPARTA, Inc.  All rights reserved.
# See the COPYING file included with the dnssec-tools package for details.
#
#	Makefile for the DNSSEC-Tools Step-by-Step Operator's Guide.
#

SRC=					\
	sbs.tex		\
	check-zonefile-signed.tex	\
	check-zonefile-unsigned.tex	\
	checklists.tex			\
	delete-old-ksk.tex		\
	delete-old-zsk.tex		\
	intro.tex			\
	key-perms.tex			\
	keygen-set.tex			\
	keygen-zsk-keytag.tex		\
	keygen-zsk.tex			\
	keys-separation.tex		\
	keytag-delcurzsk.tex		\
	keytag-expire.tex		\
	keytag-template.tex		\
	signzone-curzsk-msg.tex		\
	signzone-ksk-new.tex		\
	step-delegation-child.tex	\
	step-delegation-parent.tex	\
	step-emergency-curzsk.tex	\
	step-emergency-ksk.tex		\
	step-emergency-parent-ksk.tex	\
	step-emergency-pubzsk.tex	\
	step-emergency-zsks.tex		\
	step-kskgen.tex			\
	step-rollover-ksk.tex		\
	step-rollover-zsk.tex		\
	step-sign-has-deleg.tex		\
	step-sign-no-deleg.tex		\
	step-zone-serving.tex		\
	step-zskgen.tex			\
	update-zonefile-newzsk.tex	\
	update-zonefile.tex		\
	zone-reload.tex

sbs.ps:	sbs.dvi
		dvips -f sbs.dvi > sbs.ps

sbs.dvi:	${SRC}
		latex sbs.tex
		latex sbs.tex
		latex sbs.tex

clean:
		rm -f *.aux *.bz2 *.dvi *.lof *.log sbs.ps *.toc
