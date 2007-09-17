#
# Copyright 2004-2006 SPARTA, Inc.  All rights reserved.
# See the COPYING file included with the dnssec-tools package for details.
#
#	Makefile for the DNSSEC-Tools Software User's Manual.
#

sum:		sum.ps

pdf:		sum.dvi
		dvipdf sum.dvi SUM.pdf

sum.ps:		sum.dvi
		dvips -f sum.dvi > SUM.ps

sum.dvi:
		latex sum.tex
		latex sum.tex
		latex sum.tex

clean:
		rm -f *.aux *.bz2 *.dvi *.log *.ps *.toc
