#!/usr/bin/perl

open(MF,"> Makefile");

print MF <<EOF;

MODULES=	conf.pm		\\
		keyrec.pm	\\
		tooloptions.pm

DESTDIR=	/usr/local/lib/perl5/site_perl/5.8.2/DNSSEC

all:
	\@echo nothing to make

install:	install-dir
	\@echo "installing modules in \${DESTDIR}"
	\@install -m 0444 \${MODULES} \${DESTDIR}

install-dir:
	\@if test ! -d \$(DESTDIR) ; then				\\
		echo "creating DNSSEC module directory";	\\
		mkdir -p \$(DESTDIR);				\\
	fi

clean:
	\@echo nothing to clean
EOF

exit(0);
