TOOLSDIR=../dnssec-tools

FIXBOT=perl -p -i fixhtml
all: tools modules libs
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

LIBS=\
	validator/doc/dnsval.conf\
	validator/doc/dt-danechk\
	validator/doc/dt-getaddr\
	validator/doc/dt-gethost\
	validator/doc/dt-getname\
	validator/doc/dt-getquery\
	validator/doc/dt-getrrset\
	validator/doc/dt-libval_check_conf\
	validator/doc/dt-validate\
	validator/doc/libsres\
	validator/doc/libval\
	validator/doc/libval_async\
	validator/doc/libval_shim\
	validator/doc/val_get_rrset\
	validator/doc/val_getaddrinfo\
	validator/doc/val_getdaneinfo\
	validator/doc/val_gethostbyname\
	validator/doc/val_res_query


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

libs:
	for i in $(LIBS) ; do \
		ibase=`basename $$i` ; \
		echo creating docs/tool-description/$$ibase.html ; \
		pod2html $(TOOLSDIR)/$$i.pod > docs/tool-description/$$ibase.html ; \
		$(FIXBOT) docs/tool-description/$$ibase.html ; \
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

owl:
	cp $(TOOLSDIR)/apps/owl-monitor/docs/* ./docs/owl-monitor

