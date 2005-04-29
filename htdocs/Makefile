TOOLSDIR=../dnssec-tools

all: tools modules stepbystep

tools:
	pod2html $(TOOLSDIR)/tools/donuts/donuts > docs/donuts.html
	pod2html $(TOOLSDIR)/tools/mapper/mapper > docs/mapper.html
	pod2html $(TOOLSDIR)/tools/scripts/zonesigner > docs/zonesigner.html

modules:
	pod2html $(TOOLSDIR)/tools/modules/conf.pm > docs/conf.html
	pod2html $(TOOLSDIR)/tools/modules/keyrec.pm > docs/keyrec.html
	pod2html $(TOOLSDIR)/tools/modules/tooloptions.pm > docs/tooloptions.html

stepbystep:
	wvHtml --targetdir=docs/step-by-step docs/step-by-step-guide-draft-v0.4.doc step-by-step-guide-draft-v0.4.html
