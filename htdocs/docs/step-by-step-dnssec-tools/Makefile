#
# Copyright 2004-2005 SPARTA, Inc.  All rights reserved.
# See the COPYING file included with the dnssec-tools package for details.
#
#	Makefile for the Step-by-Step DNSSEC-Tools Operator Guidance Document.
#

# NOTE: This needs to point to the DocBook XSL Stylesheet directory
DOCBOOK_XSL="/Applications/xxe-std-30/XMLEditor.app/Contents/Resources/addon/config/docbook/xsl"

# NOTE: This may need to be adjusted to point to your libxslt installation
XSLTPROC=/usr/bin/xsltproc

# NOTE: These may need to be adjusted to point to your FOP installation
FOP=/opt/fop/fop.sh
XALAN=/opt/fop/xalan.sh

SRC = \
	sbs-dt.xml \
	intro.xml \
	step-delegation-child.xml \
	step-delegation-parent.xml \
	step-emergency-ksk-parent.xml \
	step-emergency-ksk.xml \
	step-emergency-zsk-current.xml \
	step-emergency-zsk-published.xml \
	step-emergency-zsk.xml \
	step-rollover-ksk.xml \
	step-rollover-zsk.xml \
	step-toolset-configure.xml \
	step-zone-check-signature-expiration.xml \
	step-zone-initial-sign.xml \
	step-zone-resign.xml \
	step-zone-serve.xml \
	resign-zone.xml \
	reload-zone.xml

all: html pdf

html: ${SRC} xsl/html/sbs-dt.xsl
	${XSLTPROC} --xinclude xsl/html/sbs-dt.xsl sbs-dt.xml

pdf: sbs-dt.fo
	${FOP} -fo sbs-dt.fo -pdf sbs-dt.pdf

sbs-dt.fo: ${SRC} xsl/fo/sbs-dt.xsl xsl/fo/titlepage.xsl
	${XSLTPROC} --xinclude --output sbs-dt.fo xsl/fo/sbs-dt.xsl sbs-dt.xml

xsl/fo/titlepage.xsl: xsl/fo/titlepage.spec.xml
	${XSLTPROC} --output xsl/fo/titlepage.xsl ${DOCBOOK_XSL}/template/titlepage.xsl xsl/fo/titlepage.spec.xml

clean:
	rm -f html/* sbs-dt.fo sbs-dt.pdf xsl/fo/titlepage.xsl
