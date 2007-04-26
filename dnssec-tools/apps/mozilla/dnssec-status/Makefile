all: dnssecstatus-0.1.xpi 

dnssecstatus-0.1.xpi: dnssecstatus.jar
	rm -f dnssecstatus-0.1.xpi
	zip -0 -r dnssecstatus-0.1.xpi defaults install.rdf chrome/dnssecstatus.jar
	rm  -f chrome/dnssecstatus.jar

dnssecstatus.jar:
	cd chrome; zip -0 -r dnssecstatus.jar content skin

clean:
	rm -f dnssecstatus-0.1.xpi chrome/dnssecstatus.jar
