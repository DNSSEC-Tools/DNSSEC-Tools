TOOLSDIR=../dnssec-tools

FIXBOT=perl -p -i fixhtml
all: tools modules 
# stepbystep

TOOLS=donuts/donuts donuts/donutsd mapper/mapper \
	scripts/zonesigner dnspktflow/dnspktflow maketestzone/maketestzone \
	scripts/getdnskeys scripts/TrustMan \
	scripts/lskrf scripts/keyrec-check scripts/genkrf scripts/expchk \
	drawvalmap/drawvalmap 

MODS=modules/conf modules/keyrec modules/tooloptions donuts/Rule \
	modules/QWPrimitives modules/timetrans modules/ZoneFile-Fast/Fast

tools:
	for i in $(TOOLS) ; do \
		ibase=`basename $$i` ; \
		echo creating docs/$$ibase.html ; \
		pod2html $(TOOLSDIR)/tools/$$i > docs/$$ibase.html ; \
		$(FIXBOT) docs/$$ibase.html ; \
	done

modules:
	for i in $(MODS) ; do \
		ibase=`basename $$i` ; \
		echo creating docs/$$ibase.html ; \
		pod2html $(TOOLSDIR)/tools/$$i.pm > docs/$$ibase.html ; \
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
