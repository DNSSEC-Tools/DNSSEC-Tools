#!/usr/bin/perl

open(MF,"> Makefile");

print MF <<EOF;

all:
	\@echo nothing to make

install:
	\@echo nothing to install

clean:
	\@echo nothing to clean
EOF

exit(0);
