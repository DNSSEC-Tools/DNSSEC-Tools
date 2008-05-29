TOOLSDIR=../dnssec-tools

FIXBOT=perl -p -i fixhtml
all: tools modules 
# stepbystep

# (perl specific for manual extraction)
TOOLS=\
	dnspktflow/dnspktflow \
	donuts/donuts \
	donuts/donutsd \
	drawvalmap/drawvalmap \
	maketestzone/maketestzone \
	mapper/mapper \
	scripts/cleankrf \
	scripts/dtconfchk \
	scripts/dtdefs \
	scripts/dtinitconf \
	scripts/expchk \
	scripts/fixkrf \
	scripts/genkrf \
	scripts/getdnskeys \
	scripts/keyarch \
	scripts/krfcheck \
	scripts/lskrf \
	scripts/lsroll \
	scripts/rollchk \
	scripts/rollctl \
	scripts/rollerd \
	scripts/rollinit \
	scripts/rolllog \
	scripts/rollset \
	scripts/signset-editor \
	scripts/tachk \
	scripts/timetrans \
	scripts/trustman \
	scripts/zonesigner

MODS=\
	donuts/Rule \
	modules/BootStrap \
	modules/Net-DNS-SEC-Validator/Validator \
	modules/Net-addrinfo/addrinfo \
	modules/QWPrimitives \
	modules/ZoneFile-Fast/Fast \
	modules/conf \
	modules/defaults \
	modules/keyrec \
	modules/rollmgr \
	modules/rollrec \
	modules/timetrans \
	modules/tooloptions

tools:
	for i in $(TOOLS) ; do \
		ibase=`basename $$i` ; \
		echo creating docs/tool-description/$$ibase.html ; \
		pod2html $(TOOLSDIR)/tools/$$i > docs/tool-description/$$ibase.html ; \
		$(FIXBOT) docs/$$ibase.html ; \
	done

modules:
	for i in $(MODS) ; do \
		ibase=`basename $$i` ; \
		echo creating docs/tool-description/$$ibase.html ; \
		pod2html $(TOOLSDIR)/tools/$$i.pm > docs/tool-description/$$ibase.html ; \
		$(FIXBOT) docs/$$ibase.html ; \
	done

help-txt:
	for i in $(TOOLS) ; do \
		ibase=`basename $$i` ; \
		echo creating txt/$$ibase-help.txt ; \
		$$ibase -h > txt/$$ibase-help.txt 2>&1 ; \
	done


stepbystep:
	wvHtml --targetdir=docs/step-by-step docs/step-by-step-guide-draft-v0.4.doc step-by-step-guide-draft-v0.4.html
	$(FIXBOT) docs/step-by-step/step-by-step-guide-draft-v0.4.html
