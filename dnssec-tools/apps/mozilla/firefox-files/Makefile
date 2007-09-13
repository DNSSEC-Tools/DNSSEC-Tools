VERSION=1.5.0.10
FULLPATCHFILE=dnssec-both.patch

INCLUDEDEBUGGING=1
PRPATCHFILE=prnetdb-patch
BASEBUILD=/usr/src/redhat/BUILD/firefox-$(VERSION)

NORMALFILES=\
	prnetdb.h		\
	nsHostResolver.cpp	\
	nsHostResolver.h	\
	nsIDNSService.idl	\
	nsIDNSRecord.idl	\
	nsSocketTransport2.cpp	\
	nsSocketTransport2.h	\
	nsDNSService2.cpp	\
	nsProtocolProxyService.cpp	\
	nsHttpChannel.cpp	\
	nsWebShell.cpp		\
	nsPACMan.cpp		\
	netError.xhtml		\
	appstrings.properties	\
	pref-dnssec.dtd		\
	prerr.c			\
	prerr.h			\
	prerr.et		\
	prerr.properties	\
	nsDocShell.cpp		\
	nsNetError.h		\
	netError.dtd

all: help

help:
	echo make patchfile             -- builds just the patch
	echo make INCLUDEDEBUGGING=0    -- builds the patch without DEBUG
	echo make build			-- builds FF from the build tree
	echo make getoriginals		-- copies .orig files from source

patchfile: $(FULLPATCHFILE)

rmpatch:
	rm -f $(PRPATCHFILE)

getoriginals:
	perl getorig $(BASEBUILD) $(NORMALFILES) prnetdb.c

# upgrading to a new set of FF patches:
# 1) make current patch set without path changes
# 2) get new files from new tree  requires NEWVERSION= on command line
# 3) cp to current file and then patch with created patch
upgrade: 
	rm *.patch
	make normalpatches X=no
	make getoriginals VERSION=$(NEWVERSION)
	for i in $(NORMALFILES) ; do \
		cp $$i.orig $$i ; \
		patch -p0 < $$i.patch ; \
	done
	@echo ""
	@echo "make sure to change VERSION= in the Makefile"

.PHONY: $(PRPATCHFILE) prpatchfile
prpatchfile: rmpatch normalpatches $(PRPATCHFILE)
$(PRPATCHFILE): prnetdb-real.c
	if [ ! -d temp ] ; then mkdir temp ; fi
	cp $< temp/prnetdb.c
	cp prnetdb.c.orig temp/
	(cd temp && diff -u prnetdb.c.orig prnetdb.c) | perl addpath $(X) > $@

prnetdb-real.c: prnetdb.c
	if test $(INCLUDEDEBUGGING) = 1 ; then 		\
		cp $< $@ ; 				\
	else 						\
		perl removeinternal < $< > $@ ;		\
	fi

normalpatches:
	for i in $(NORMALFILES) ; do \
		diff -u $$i.orig $$i | perl addpath $(X) > $$i.patch ; \
	done ;

.PHONY: $(FULLPATCHFILE) normalpatches
$(FULLPATCHFILE): prpatchfile normalpatches
	cp patch.base $(FULLPATCHFILE)
	for i in $(NORMALFILES) ; do \
		cat $$i.patch >> $(FULLPATCHFILE) ; \
	done
	cat $(PRPATCHFILE) >> $(FULLPATCHFILE) ; \

clean:
	rm -f $(PRPATCHFILE)
	for i in $(NORMALFILES) ; do \
		rm -f $$i.patch ; \
	done

NOOP=sudo
install: prnetdb-real.c
	$(NOOP) cp -p prnetdb-real.c $(BASEBUILD)/mozilla/nsprpub/pr/src/misc/prnetdb.c
	for i in $(NORMALFILES) ; do \
		$(NOOP) cp -p $$i $(BASEBUILD)/`perl getpath $$i`$$i ; \
	done

# -O2 -fPIC -DLINUX1_2 -Di386 -D_XOPEN_SOURCE -DLINUX2_1  -ansi -Wall -pipe -DLINUX -Dlinux -D_POSIX_SOURCE -D_BSD_SO URCE -DHAVE_STRERROR -DXP_UNIX -DSHLIB_SUFFIX=\"so\" -DSHLIB_PREFIX=\"lib\" -UDE BUG -DNDEBUG -D_REENTRANT -I/opt/vmware/part2/BUILD/firefox-1.5.0.10/mozilla/dis t/include  -I../../../../../dist/public/nss -I../../../../../dist/private/nss -I ../../../../../dist/include -I/opt/vmware/part2/BUILD/firefox-1.5.0.10/mozilla/d ist/include/nspr -I/opt/vmware/part2/BUILD/firefox-1.5.0.10/mozilla/dist/include /dbm  
build: install
	cd $(BASEBUILD)/mozilla/; sudo make -f client.mk build LDFLAGS="-Wl,-rpath,/usr/lib/firefox-1.5.0.10"
	sudo cp $(BASEBUILD)/mozilla/dist/bin/*.so /usr/lib/firefox-$(VERSION)/
	sudo cp $(BASEBUILD)/mozilla/dist/bin/components/*.so /usr/lib/firefox-$(VERSION)/components/

#	cd $(BASEBUILD)/mozilla/; sudo make -f client.mk build LDFLAGS="-Wl,-rpath,/usr/lib/firefox-1.5.0.10" CFLAGS="-g -fPIC -DLINUX1_2 -Di386 -D_XOPEN_SOURCE -DLINUX2_1  -ansi -Wall -pipe -DLINUX -Dlinux -D_POSIX_SOURCE -D_BSD_SOURCE -DHAVE_STRERROR -DXP_UNIX -DSHLIB_SUFFIX=\"so\" -DSHLIB_PREFIX=\"lib\" -UDEBUG -DNDEBUG -D_REENTRANT -I/opt/vmware/part2/BUILD/firefox-1.5.0.10/mozilla/dist/include  -I../../../../../dist/public/nss -I../../../../../dist/private/nss -I../../../../../dist/include -I/opt/vmware/part2/BUILD/firefox-1.5.0.10/mozilla/dist/include/nspr -I/opt/vmware/part2/BUILD/firefox-1.5.0.10/mozilla/dist/include/dbm"

buildnetwork:
	cd $(BASEBUILD)/mozilla/nsprpub/pr/src/; sudo make
	cd $(BASEBUILD)/mozilla/netwerk/dns/src/; sudo make
	sudo cp $(BASEBUILD)/mozilla/dist/bin/*.so /usr/lib/firefox-$(VERSION)/
	sudo cp $(BASEBUILD)/mozilla/dist/bin/components/*.so /usr/lib/firefox-$(VERSION)/components/

launch:
	cd $(BASEBUILD)/mozilla/dist/bin; ./firefox http://badsign-a.test.dnssec-tools.org/bumper.png
