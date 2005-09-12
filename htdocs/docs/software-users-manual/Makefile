#
# Copyright 2004-2005 SPARTA, Inc.  All rights reserved.
# See the COPYING file included with the dnssec-tools package for details.
#
#	Makefile for the DNSSEC-Tools Software User's Manual.
#

SRC=	sum.tex							\
	man-libs.tex						\
	man-cmds.tex						\
	man-files.tex						\
	man-modules.tex						\
	manpages/lib::libsres::libsres.tex			\
	manpages/lib::libval::val_getaddrinfo.tex		\
	manpages/lib::libval::val_gethostbyname.tex		\
	manpages/lib::libval::val_query.tex			\
	manpages/tools::dnspktflow::dnspktflow.tex		\
	manpages/tools::donuts::donuts.tex			\
	manpages/tools::donuts::donuts::Rule.tex		\
	manpages/tools::donuts::donutsd.tex			\
	manpages/tools::etc::dnssec::dnssec-tools.conf.tex	\
	manpages/tools::mapper::mapper.tex			\
	manpages/tools::modules::QWPrimitives.pm.tex		\
	manpages/tools::modules::conf.pm.tex			\
	manpages/tools::modules::file-keyrec.tex		\
	manpages/tools::modules::keyrec.pm.tex			\
	manpages/tools::modules::timetrans.pm.tex		\
	manpages/tools::modules::tooloptions.pm.tex		\
	manpages/tools::scripts::clean-keyrec.tex		\
	manpages/tools::scripts::confchk.tex			\
	manpages/tools::scripts::expchk.tex			\
	manpages/tools::scripts::fixkrf.tex			\
	manpages/tools::scripts::keyrec-check.tex		\
	manpages/tools::scripts::lskrf.tex			\
	manpages/tools::scripts::timetrans.tex			\
	manpages/tools::scripts::zonesigner.tex			\

sum:		sum.ps

sum.ps:		sum.dvi
		dvips -f sum.dvi > sum.ps

sum.dvi:	${SRC}
		latex sum.tex
		latex sum.tex
		latex sum.tex

clean:
		rm -f *.aux *.bz2 *.dvi *.log *.ps *.toc
