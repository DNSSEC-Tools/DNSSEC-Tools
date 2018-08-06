SRC=\
	dg.tex\
	validator.tex

dg.ps: dg.dvi
	dvips -f dg.dvi > dg.ps
                                                                                                                             
dg.dvi: ${SRC}
	latex dg.tex
	latex dg.tex
	latex dg.tex
                                                                                                                             
clean:
		rm -f *.aux *.bz2 *.dvi *.lof *.log dg.ps *.toc
