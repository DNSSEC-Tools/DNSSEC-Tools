TOOLSDIR=../dnssec-tools

FIXBOT=perl -p -i fixhtml
all: tools modules stepbystep

tools:
	pod2html $(TOOLSDIR)/tools/donuts/donuts > docs/donuts.html
	$(FIXBOT) docs/donuts.html
	pod2html $(TOOLSDIR)/tools/donuts/donutsd > docs/donutsd.html
	$(FIXBOT) docs/donutsd.html
	pod2html $(TOOLSDIR)/tools/mapper/mapper > docs/mapper.html
	$(FIXBOT) docs/mapper.html
	pod2html $(TOOLSDIR)/tools/scripts/zonesigner > docs/zonesigner.html
	$(FIXBOT) docs/zonesigner.html

modules:
	pod2html $(TOOLSDIR)/tools/modules/conf.pm > docs/conf.html
	$(FIXBOT) docs/conf.html
	pod2html $(TOOLSDIR)/tools/modules/keyrec.pm > docs/keyrec.html
	$(FIXBOT) docs/keyrec.html
	pod2html $(TOOLSDIR)/tools/modules/tooloptions.pm > docs/tooloptions.html
	$(FIXBOT) docs/tooloptions.html

stepbystep:
	wvHtml --targetdir=docs/step-by-step docs/step-by-step-guide-draft-v0.4.doc step-by-step-guide-draft-v0.4.html
	$(FIXBOT) docs/step-by-step/step-by-step-guide-draft-v0.4.html
