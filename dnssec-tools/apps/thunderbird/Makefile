
CONTENT_FILES= content/spfdnssec/contents.rdf \
	content/spfdnssec/spfDnssecOverlay.js \
	content/spfdnssec/spfDnssecOverlay.xul

LOCALE_FILES= locale/en-US/spfdnssec/contents.rdf \
	locale/en-US/spfdnssec/spfDnssecOverlay.dtd

SKIN_FILES= skin/classic/spfdnssec/contents.rdf \
	skin/classic/spfdnssec/spfdnssec.png

all: spfdnssec.xpi

spfdnssec.xpi: spfdnssec.jar install.rdf
	@rm -f spfdnssec.xpi
	@zip -0 -r spfdnssec.xpi install.rdf chrome
	@rm -rf chrome
	@echo "spfdnssec.xpi created"

spfdnssec.jar: ${CONTENT_FILES} ${LOCALE_FILES} ${SKIN_FILES}
	@rm -rf chrome
	@zip -0 -r spfdnssec.jar content locale skin
	@mkdir chrome
	@cp spfdnssec.jar chrome	
	@rm -f spfdnssec.jar

clean:
	@rm -rf spfdnssec.jar spfdnssec.xpi chrome
