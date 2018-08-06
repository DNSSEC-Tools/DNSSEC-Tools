#
# Copyright 2004-2005 SPARTA, Inc.  All rights reserved.
# See the COPYING file included with the dnssec-tools package for details.
#
#	Makefile for the DNSSEC-Tools Software User's Manual.
#

SRC=	installguide.tex

installguide:		installguide.ps

installguide.ps:	installguide.dvi
			dvips -f installguide.dvi > installguide.ps

installguide.dvi:	${SRC}
			latex installguide.tex
			latex installguide.tex
			latex installguide.tex

clean:
			rm -f *.aux *.bz2 *.dvi *.log *.ps *.toc
