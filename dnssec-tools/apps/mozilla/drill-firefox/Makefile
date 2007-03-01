all: drill-0.6.xpi 

drill-0.6.xpi: drill.jar
	\rm -f drill-0.6.xpi
	zip -0 -r drill-0.6.xpi defaults install.rdf chrome/drill.jar
	\rm  -f chrome/drill.jar
	
drill.jar:
	cd chrome;\
	zip -0 -r drill.jar content skin

clean:
	\rm -f drill-0.6.xpi chrome/drill.jar
