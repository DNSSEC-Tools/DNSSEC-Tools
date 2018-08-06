#
# Copyright 2004-2005 SPARTA, Inc.  All rights reserved.
# See the COPYING file included with the dnssec-tools package for details.
#
#	Makefile for the DNSSEC-Tools Keytag-Table.
#

SRC=	keytag-table.tex

keytag-table.ps:	keytag-table.dvi
			dvips -f keytag-table.dvi > keytag-table.ps

keytag-table.dvi:	${SRC}
			latex ${SRC}
			latex ${SRC}
			latex ${SRC}

clean:
			rm -f *.aux *.bz2 *.dvi *.log *.ps *.toc
