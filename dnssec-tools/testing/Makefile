prefix=/usr/local
exec_prefix=${prefix}
sysconfdir=${prefix}/etc
bindir=${exec_prefix}/bin
sbindir=${exec_prefix}/sbin
libdir=${exec_prefix}/lib
datarootdir=${prefix}/share
datadir=${datarootdir}
includedir=${prefix}/include
mandir=${datarootdir}/man
top_srcdir=..

export BUILDDIR=/home/baerm/snmp/svn-dnssec/trunk/dnssec-tools
PERLDIRS=tools/modules tools/donuts tools/mapper tools/scripts \
         tools/dnspktflow tools/maketestzone tools/etc tools/drawvalmap

QUIET=@
# QUIET=''


TEST_FILES=t/*.t


all :: authtest


authtest : $(TEST_FILES)
	$(QUIET) for i in $(TEST_FILES) ; do \
	  perl $$i ;               \
        done

rollerd : t/040rollerd.t
	perl rollerd.t 

