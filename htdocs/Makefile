TOOLSDIR=../dnssec-tools

all: tools stepbystep

tools:
	pod2html $(TOOLSDIR)/tools/donuts/donuts > docs/donuts.html
	pod2html $(TOOLSDIR)/tools/donuts/mapper > docs/mapper.html

stepbystep:
	wvHtml --targetdir=docs/step-by-step docs/step-by-step-guide-draft-v0.4.doc step-by-step-guide-draft-v0.4.html
