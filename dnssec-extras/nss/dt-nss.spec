%global nspr_version 4.9.2
%global nss_util_version 3.14
%global nss_softokn_fips_version 3.12.9
%global nss_softokn_version 3.14
%global unsupported_tools_directory %{_libdir}/nss/unsupported-tools

Summary:          Network Security Services
Name:             nss
Version:          3.14
Release:          7%{?dist}
License:          MPLv2.0
URL:              http://www.mozilla.org/projects/security/pki/nss/
Group:            System Environment/Libraries
Requires:         nspr >= %{nspr_version}
Requires:         nss-util >= %{nss_util_version}
# TODO: revert to same version as nss once we are done with the merge
Requires:         nss-softokn%{_isa} >= %{nss_softokn_version}
Requires:         nss-system-init
BuildRoot:        %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildRequires:    nspr-devel >= %{nspr_version}
# TODO: revert to same version as nss once we are done with the merge
# Using '>=' but on RHEL the requires should be '='
BuildRequires:    nss-softokn-devel >= %{nss_softokn_version}
BuildRequires:    nss-util-devel >= %{nss_util_version}
BuildRequires:    sqlite-devel
BuildRequires:    zlib-devel
BuildRequires:    pkgconfig
BuildRequires:    gawk
BuildRequires:    psmisc
BuildRequires:    perl

Source0:          %{name}-%{version}-stripped.tar.bz2
# The stripped tar ball is a subset of the upstream sources with
# patent-encumbered cryptographic algorithms removed.
# Use this script to remove them and create the stripped archive.
# 1. Download the sources nss-{version}.tar.gz found within 
# http://ftp.mozilla.org/pub/mozilla.org/security/nss/releases/
# in a subdirectory named NSS_${major}_${minor}_${maint}_RTM/src
# 2. In the download directory execute
# ./mozilla-crypto-strip.sh ${name}-${version}.tar.gz
# to produce ${name}-${version}-stripped.tar.bz2
# for uploading to the lookaside cache.
Source100:        mozilla-crypto-strip.sh

Source1:          nss.pc.in
Source2:          nss-config.in
Source3:          blank-cert8.db
Source4:          blank-key3.db
Source5:          blank-secmod.db
Source6:          blank-cert9.db
Source7:          blank-key4.db
Source8:          system-pkcs11.txt
Source9:          setup-nsssysinit.sh
Source10:         PayPalEE.cert
Source12:         %{name}-pem-20120811.tar.bz2

Patch2:           add-relro-linker-option.patch
Patch3:           renegotiate-transitional.patch
Patch6:           nss-enable-pem.patch
Patch16:          nss-539183.patch
Patch18:          nss-646045.patch
# must statically link pem against the freebl in the buildroot
# Needed only when freebl on tree has newe APIS
Patch25:          nsspem-use-system-freebl.patch
# This patch is currently meant for stable branches
Patch29:          nss-ssl-cbc-random-iv-off-by-default.patch
# Prevent users from trying to enable ssl pkcs11 bypass
Patch39:          nss-ssl-enforce-no-pkcs11-bypass.path
# TODO: Remove this patch when the ocsp test are fixed
Patch40:          nss-3.14.0.0-disble-ocsp-test.patch

# upstream: https://bugzilla.mozilla.org/show_bug.cgi?id=357025
Patch41:          Bug-872124-fix-pk11wrap-locking.patch
# upstream: https://bugzilla.mozilla.org/show_bug.cgi?id=807890
Patch42:          0001-Add-extended-key-usage-for-MS-Authenticode-Code-Sign.patch

%description
Network Security Services (NSS) is a set of libraries designed to
support cross-platform development of security-enabled client and
server applications. Applications built with NSS can support SSL v2
and v3, TLS, PKCS #5, PKCS #7, PKCS #11, PKCS #12, S/MIME, X.509
v3 certificates, and other security standards.

%package tools
Summary:          Tools for the Network Security Services
Group:            System Environment/Base
Requires:         %{name}%{?_isa} = %{version}-%{release}

%description tools
Network Security Services (NSS) is a set of libraries designed to
support cross-platform development of security-enabled client and
server applications. Applications built with NSS can support SSL v2
and v3, TLS, PKCS #5, PKCS #7, PKCS #11, PKCS #12, S/MIME, X.509
v3 certificates, and other security standards.

Install the nss-tools package if you need command-line tools to
manipulate the NSS certificate and key database.

%package sysinit
Summary:          System NSS Initialization
Group:            System Environment/Base
# providing nss-system-init without version so that it can
# be replaced by a better one, e.g. supplied by the os vendor
Provides:         nss-system-init
Requires:         nss = %{version}-%{release}
Requires(post):   coreutils, sed

%description sysinit
Default Operating System module that manages applications loading
NSS globally on the system. This module loads the system defined
PKCS #11 modules for NSS and chains with other NSS modules to load
any system or user configured modules.

%package devel
Summary:          Development libraries for Network Security Services
Group:            Development/Libraries
Provides:         nss-static = %{version}-%{release}
Requires:         nss = %{version}-%{release}
Requires:         nss-util-devel
Requires:         nss-softokn-devel
Requires:         nspr-devel >= %{nspr_version}
Requires:         pkgconfig

%description devel
Header and Library files for doing development with Network Security Services.


%package pkcs11-devel
Summary:          Development libraries for PKCS #11 (Cryptoki) using NSS
Group:            Development/Libraries
Provides:         nss-pkcs11-devel-static = %{version}-%{release}
Requires:         nss-devel = %{version}-%{release}
# TODO: revert to using nss_softokn_version once we are done with
# the merge into to new rhel git repo
# For RHEL we should have '=' instead of '>='
Requires:         nss-softokn-freebl-devel >= %{nss_softokn_version}

%description pkcs11-devel
Library files for developing PKCS #11 modules using basic NSS 
low level services.


%prep
%setup -q
%{__cp} %{SOURCE10} -f ./mozilla/security/nss/tests/libpkix/certs
%setup -q -T -D -n %{name}-%{version} -a 12

%patch2 -p0 -b .relro
%patch3 -p0 -b .transitional
%patch6 -p0 -b .libpem
%patch16 -p0 -b .539183
%patch18 -p0 -b .646045
# link pem against buildroot's freebl, esential wen mixing and matching
%patch25 -p0 -b .systemfreebl
# activate for stable and beta branches
%patch29 -p0 -b .770682
%patch39 -p1 -b .nobypass
%patch40 -p1 -b .noocsptest
%patch41 -p0 -b .872124
%patch42 -p0 -b .870864

%build

NSS_NO_PKCS11_BYPASS=1
export NSS_NO_PKCS11_BYPASS

FREEBL_NO_DEPEND=1
export FREEBL_NO_DEPEND

# Enable compiler optimizations and disable debugging code
BUILD_OPT=1
export BUILD_OPT

# Uncomment to disable optimizations
#RPM_OPT_FLAGS=`echo $RPM_OPT_FLAGS | sed -e 's/-O2/-O0/g'`
#export RPM_OPT_FLAGS

# Generate symbolic info for debuggers
XCFLAGS=$RPM_OPT_FLAGS
export XCFLAGS

PKG_CONFIG_ALLOW_SYSTEM_LIBS=1
PKG_CONFIG_ALLOW_SYSTEM_CFLAGS=1

export PKG_CONFIG_ALLOW_SYSTEM_LIBS
export PKG_CONFIG_ALLOW_SYSTEM_CFLAGS

NSPR_INCLUDE_DIR=`/usr/bin/pkg-config --cflags-only-I nspr | sed 's/-I//'`
NSPR_LIB_DIR=%{_libdir}

export NSPR_INCLUDE_DIR
export NSPR_LIB_DIR

export FREEBL_INCLUDE_DIR=`/usr/bin/pkg-config --cflags-only-I nss-softokn | sed 's/-I//'`
export FREEBL_LIB_DIR=%{_libdir}
export USE_SYSTEM_FREEBL=1

NSS_USE_SYSTEM_SQLITE=1
export NSS_USE_SYSTEM_SQLITE

%ifarch x86_64 ppc64 ia64 s390x sparc64
USE_64=1
export USE_64
%endif

##### phase 1: build freebl/softokn shared libraries
# there no ecc in freebl
unset NSS_ENABLE_ECC
# Compile softoken plus needed support
%{__make} -C ./mozilla/security/coreconf
%{__make} -C ./mozilla/security/dbm

%{__make} -C ./mozilla/security/nss/lib/util export
%{__make} -C ./mozilla/security/nss/lib/freebl export
%{__make} -C ./mozilla/security/nss/lib/softoken export

%{__make} -C ./mozilla/security/nss/lib/util
%{__make} -C ./mozilla/security/nss/lib/freebl
%{__make} -C ./mozilla/security/nss/lib/softoken

# stash away the bltest and fipstest to build them last
tar cf build_these_later.tar ./mozilla/security/nss/cmd/bltest ./mozilla/security/nss/cmd/fipstest
rm -rf ./mozilla/security/nss/cmd/bltest
rm -rf ./mozilla/security/nss/cmd/fipstest

##### phase 2: build the rest of nss
# nss supports pluggable ecc
NSS_ENABLE_ECC=1
export NSS_ENABLE_ECC
NSS_ECC_MORE_THAN_SUITE_B=1
export NSS_ECC_MORE_THAN_SUITE_B

# We only ship the nss proper libraries, no softoken nor util, yet                                   
# we must compile with the entire source tree because nss needs                               
# private exports from util. The install section will ensure not
# to override nss-util and nss-softoken headers already installed.
#     
%{__make} -C ./mozilla/security/coreconf
%{__make} -C ./mozilla/security/dbm
%{__make} -C ./mozilla/security/nss

##### phase 3: build bltest and fipstest
tar xf build_these_later.tar
unset NSS_ENABLE_ECC; %{__make} -C ./mozilla/security/nss/cmd/bltest
unset NSS_ENABLE_ECC; %{__make} -C ./mozilla/security/nss/cmd/fipstest
%{__rm} -f build_these_later.tar

# Set up our package file
# The nspr_version and nss_{util|softokn}_version globals used
# here match the ones nss has for its Requires. 
# Using the current %%{nss_softokn_version} for fedora again
%{__mkdir_p} ./mozilla/dist/pkgconfig
%{__cat} %{SOURCE1} | sed -e "s,%%libdir%%,%{_libdir},g" \
                          -e "s,%%prefix%%,%{_prefix},g" \
                          -e "s,%%exec_prefix%%,%{_prefix},g" \
                          -e "s,%%includedir%%,%{_includedir}/nss3,g" \
                          -e "s,%%NSS_VERSION%%,%{version},g" \
                          -e "s,%%NSPR_VERSION%%,%{nspr_version},g" \
                          -e "s,%%NSSUTIL_VERSION%%,%{nss_util_version},g" \
                          -e "s,%%SOFTOKEN_VERSION%%,%{nss_softokn_version},g" > \
                          ./mozilla/dist/pkgconfig/nss.pc

NSS_VMAJOR=`cat mozilla/security/nss/lib/nss/nss.h | grep "#define.*NSS_VMAJOR" | awk '{print $3}'`
NSS_VMINOR=`cat mozilla/security/nss/lib/nss/nss.h | grep "#define.*NSS_VMINOR" | awk '{print $3}'`
NSS_VPATCH=`cat mozilla/security/nss/lib/nss/nss.h | grep "#define.*NSS_VPATCH" | awk '{print $3}'`

export NSS_VMAJOR 
export NSS_VMINOR 
export NSS_VPATCH

%{__cat} %{SOURCE2} | sed -e "s,@libdir@,%{_libdir},g" \
                          -e "s,@prefix@,%{_prefix},g" \
                          -e "s,@exec_prefix@,%{_prefix},g" \
                          -e "s,@includedir@,%{_includedir}/nss3,g" \
                          -e "s,@MOD_MAJOR_VERSION@,$NSS_VMAJOR,g" \
                          -e "s,@MOD_MINOR_VERSION@,$NSS_VMINOR,g" \
                          -e "s,@MOD_PATCH_VERSION@,$NSS_VPATCH,g" \
                          > ./mozilla/dist/pkgconfig/nss-config

chmod 755 ./mozilla/dist/pkgconfig/nss-config

%{__cat} %{SOURCE9} > ./mozilla/dist/pkgconfig/setup-nsssysinit.sh
chmod 755 ./mozilla/dist/pkgconfig/setup-nsssysinit.sh

%check

# Begin -- copied from the build section
FREEBL_NO_DEPEND=1
export FREEBL_NO_DEPEND

BUILD_OPT=1
export BUILD_OPT

%ifarch x86_64 ppc64 ia64 s390x sparc64
USE_64=1
export USE_64
%endif
# End -- copied from the build section

# enable the following line to force a test failure
# find ./mozilla -name \*.chk | xargs rm -f

# Run test suite.
# In order to support multiple concurrent executions of the test suite
# (caused by concurrent RPM builds) on a single host,
# we'll use a random port. Also, we want to clean up any stuck
# selfserv processes. If process name "selfserv" is used everywhere,
# we can't simply do a "killall selfserv", because it could disturb
# concurrent builds. Therefore we'll do a search and replace and use
# a different process name.
# Using xargs doesn't mix well with spaces in filenames, in order to
# avoid weird quoting we'll require that no spaces are being used.

SPACEISBAD=`find ./mozilla/security/nss/tests | grep -c ' '` ||:
if [ $SPACEISBAD -ne 0 ]; then
  echo "error: filenames containing space are not supported (xargs)"
  exit 1
fi
MYRAND=`perl -e 'print 9000 + int rand 1000'`; echo $MYRAND ||:
RANDSERV=selfserv_${MYRAND}; echo $RANDSERV ||:
DISTBINDIR=`ls -d ./mozilla/dist/*.OBJ/bin`; echo $DISTBINDIR ||:
pushd `pwd`
cd $DISTBINDIR
ln -s selfserv $RANDSERV
popd
# man perlrun, man perlrequick
# replace word-occurrences of selfserv with selfserv_$MYRAND
find ./mozilla/security/nss/tests -type f |\
  grep -v "\.db$" |grep -v "\.crl$" | grep -v "\.crt$" |\
  grep -vw CVS  |xargs grep -lw selfserv |\
  xargs -l perl -pi -e "s/\bselfserv\b/$RANDSERV/g" ||:

killall $RANDSERV || :

rm -rf ./mozilla/tests_results
cd ./mozilla/security/nss/tests/
# all.sh is the test suite script

#  don't need to run all the tests when testing packaging
#  nss_cycles: standard pkix upgradedb sharedb
nss_tests="cipher libpkix cert dbtests tools fips sdr crmf smime ssl merge pkits chains"
#  nss_ssl_tests: crl bypass_normal normal_bypass normal_fips fips_normal iopr
#  nss_ssl_run: cov auth stress
#
# Uncomment these lines if you need to temporarily
# disable some test suites for faster test builds
# global nss_ssl_tests "normal_fips"
# global nss_ssl_run "cov auth"

HOST=localhost DOMSUF=localdomain PORT=$MYRAND NSS_CYCLES=%{?nss_cycles} NSS_TESTS=%{?nss_tests} NSS_SSL_TESTS=%{?nss_ssl_tests} NSS_SSL_RUN=%{?nss_ssl_run} ./all.sh

cd ../../../../

killall $RANDSERV || :

TEST_FAILURES=`grep -c FAILED ./mozilla/tests_results/security/localhost.1/output.log` || :
# test suite is failing on arm and has for awhile let's run the test suite but make it non fatal on arm
%ifnarch %{arm}
if [ $TEST_FAILURES -ne 0 ]; then
  echo "error: test suite returned failure(s)"
  exit 1
fi
echo "test suite completed"
%endif

%install

%{__rm} -rf $RPM_BUILD_ROOT

# There is no make install target so we'll do it ourselves.

%{__mkdir_p} $RPM_BUILD_ROOT/%{_includedir}/nss3
%{__mkdir_p} $RPM_BUILD_ROOT/%{_bindir}
%{__mkdir_p} $RPM_BUILD_ROOT/%{_libdir}
%{__mkdir_p} $RPM_BUILD_ROOT/%{unsupported_tools_directory}
%{__mkdir_p} $RPM_BUILD_ROOT/%{_libdir}/pkgconfig

# Copy the binary libraries we want
for file in libnss3.so libnssckbi.so libnsspem.so libnsssysinit.so libsmime3.so libssl3.so
do
  %{__install} -p -m 755 mozilla/dist/*.OBJ/lib/$file $RPM_BUILD_ROOT/%{_libdir}
done

# Install the empty NSS db files
# Legacy db
%{__mkdir_p} $RPM_BUILD_ROOT/%{_sysconfdir}/pki/nssdb
%{__install} -p -m 644 %{SOURCE3} $RPM_BUILD_ROOT/%{_sysconfdir}/pki/nssdb/cert8.db
%{__install} -p -m 644 %{SOURCE4} $RPM_BUILD_ROOT/%{_sysconfdir}/pki/nssdb/key3.db
%{__install} -p -m 644 %{SOURCE5} $RPM_BUILD_ROOT/%{_sysconfdir}/pki/nssdb/secmod.db
# Shared db
%{__install} -p -m 644 %{SOURCE6} $RPM_BUILD_ROOT/%{_sysconfdir}/pki/nssdb/cert9.db
%{__install} -p -m 644 %{SOURCE7} $RPM_BUILD_ROOT/%{_sysconfdir}/pki/nssdb/key4.db
%{__install} -p -m 644 %{SOURCE8} $RPM_BUILD_ROOT/%{_sysconfdir}/pki/nssdb/pkcs11.txt
     
# Copy the development libraries we want
for file in libcrmf.a libnssb.a libnssckfw.a
do
  %{__install} -p -m 644 mozilla/dist/*.OBJ/lib/$file $RPM_BUILD_ROOT/%{_libdir}
done

# Copy the binaries we want
for file in certutil cmsutil crlutil modutil pk12util signtool signver ssltap
do
  %{__install} -p -m 755 mozilla/dist/*.OBJ/bin/$file $RPM_BUILD_ROOT/%{_bindir}
done

# Copy the binaries we ship as unsupported
for file in atob btoa derdump ocspclnt pp selfserv strsclnt symkeyutil tstclnt vfyserv vfychain
do
  %{__install} -p -m 755 mozilla/dist/*.OBJ/bin/$file $RPM_BUILD_ROOT/%{unsupported_tools_directory}
done

# Copy the include files we want
for file in mozilla/dist/public/nss/*.h
do
  %{__install} -p -m 644 $file $RPM_BUILD_ROOT/%{_includedir}/nss3
done

# Copy the package configuration files
%{__install} -p -m 644 ./mozilla/dist/pkgconfig/nss.pc $RPM_BUILD_ROOT/%{_libdir}/pkgconfig/nss.pc
%{__install} -p -m 755 ./mozilla/dist/pkgconfig/nss-config $RPM_BUILD_ROOT/%{_bindir}/nss-config
# Copy the pkcs #11 configuration script
%{__install} -p -m 755 ./mozilla/dist/pkgconfig/setup-nsssysinit.sh $RPM_BUILD_ROOT/%{_bindir}/setup-nsssysinit.sh

#remove the nss-util-devel headers
rm -f $RPM_BUILD_ROOT/%{_includedir}/nss3/base64.h
rm -f $RPM_BUILD_ROOT/%{_includedir}/nss3/ciferfam.h
rm -f $RPM_BUILD_ROOT/%{_includedir}/nss3/nssb64.h
rm -f $RPM_BUILD_ROOT/%{_includedir}/nss3/nssb64t.h
rm -f $RPM_BUILD_ROOT/%{_includedir}/nss3/nsslocks.h
rm -f $RPM_BUILD_ROOT/%{_includedir}/nss3/nssilock.h
rm -f $RPM_BUILD_ROOT/%{_includedir}/nss3/nssilckt.h
rm -f $RPM_BUILD_ROOT/%{_includedir}/nss3/nssrwlk.h
rm -f $RPM_BUILD_ROOT/%{_includedir}/nss3/nssrwlkt.h
rm -f $RPM_BUILD_ROOT/%{_includedir}/nss3/nssutil.h
rm -f $RPM_BUILD_ROOT/%{_includedir}/nss3/pkcs11.h
rm -f $RPM_BUILD_ROOT/%{_includedir}/nss3/pkcs11f.h
rm -f $RPM_BUILD_ROOT/%{_includedir}/nss3/pkcs11n.h
rm -f $RPM_BUILD_ROOT/%{_includedir}/nss3/pkcs11p.h
rm -f $RPM_BUILD_ROOT/%{_includedir}/nss3/pkcs11t.h
rm -f $RPM_BUILD_ROOT/%{_includedir}/nss3/pkcs11u.h
rm -f $RPM_BUILD_ROOT/%{_includedir}/nss3/portreg.h
rm -f $RPM_BUILD_ROOT/%{_includedir}/nss3/secasn1.h
rm -f $RPM_BUILD_ROOT/%{_includedir}/nss3/secasn1t.h
rm -f $RPM_BUILD_ROOT/%{_includedir}/nss3/seccomon.h
rm -f $RPM_BUILD_ROOT/%{_includedir}/nss3/secder.h
rm -f $RPM_BUILD_ROOT/%{_includedir}/nss3/secdert.h
rm -f $RPM_BUILD_ROOT/%{_includedir}/nss3/secdig.h
rm -f $RPM_BUILD_ROOT/%{_includedir}/nss3/secdigt.h
rm -f $RPM_BUILD_ROOT/%{_includedir}/nss3/secerr.h
rm -f $RPM_BUILD_ROOT/%{_includedir}/nss3/secitem.h
rm -f $RPM_BUILD_ROOT/%{_includedir}/nss3/secoid.h
rm -f $RPM_BUILD_ROOT/%{_includedir}/nss3/secoidt.h
rm -f $RPM_BUILD_ROOT/%{_includedir}/nss3/secport.h
rm -f $RPM_BUILD_ROOT/%{_includedir}/nss3/utilrename.h
rm -f $RPM_BUILD_ROOT/%{_includedir}/nss3/utilmodt.h
rm -f $RPM_BUILD_ROOT/%{_includedir}/nss3/utilpars.h
rm -f $RPM_BUILD_ROOT/%{_includedir}/nss3/utilparst.h

#remove headers shipped nss-softokn-devel and nss-softokn-freebl-devel
rm -f $RPM_BUILD_ROOT/%{_includedir}/nss3/alghmac.h
rm -f $RPM_BUILD_ROOT/%{_includedir}/nss3/blapit.h
rm -f $RPM_BUILD_ROOT/%{_includedir}/nss3/ecl-exp.h
rm -f $RPM_BUILD_ROOT/%{_includedir}/nss3/hasht.h
rm -f $RPM_BUILD_ROOT/%{_includedir}/nss3/shsign.h
rm -f $RPM_BUILD_ROOT/%{_includedir}/nss3/nsslowhash.h

%clean
%{__rm} -rf $RPM_BUILD_ROOT

%triggerpostun -n nss-sysinit -- nss-sysinit < 3.12.8-3
# Reverse unwanted disabling of sysinit by faulty preun sysinit scriplet
# from previous versions of nss.spec
/usr/bin/setup-nsssysinit.sh on

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig


%files
%defattr(-,root,root)
%{_libdir}/libnss3.so
%{_libdir}/libssl3.so
%{_libdir}/libsmime3.so
%{_libdir}/libnssckbi.so
%{_libdir}/libnsspem.so
%dir %{_sysconfdir}/pki/nssdb
%config(noreplace) %verify(not md5 size mtime) %{_sysconfdir}/pki/nssdb/cert8.db
%config(noreplace) %verify(not md5 size mtime) %{_sysconfdir}/pki/nssdb/key3.db
%config(noreplace) %verify(not md5 size mtime) %{_sysconfdir}/pki/nssdb/secmod.db

%files sysinit
%defattr(-,root,root)
%{_libdir}/libnsssysinit.so
%config(noreplace) %verify(not md5 size mtime) %{_sysconfdir}/pki/nssdb/cert9.db
%config(noreplace) %verify(not md5 size mtime) %{_sysconfdir}/pki/nssdb/key4.db
%config(noreplace) %verify(not md5 size mtime) %{_sysconfdir}/pki/nssdb/pkcs11.txt
%{_bindir}/setup-nsssysinit.sh

%files tools
%defattr(-,root,root)
%{_bindir}/certutil
%{_bindir}/cmsutil
%{_bindir}/crlutil
%{_bindir}/modutil
%{_bindir}/pk12util
%{_bindir}/signtool
%{_bindir}/signver
%{_bindir}/ssltap
%{unsupported_tools_directory}/atob
%{unsupported_tools_directory}/btoa
%{unsupported_tools_directory}/derdump
%{unsupported_tools_directory}/ocspclnt
%{unsupported_tools_directory}/pp
%{unsupported_tools_directory}/selfserv
%{unsupported_tools_directory}/strsclnt
%{unsupported_tools_directory}/symkeyutil
%{unsupported_tools_directory}/tstclnt
%{unsupported_tools_directory}/vfyserv
%{unsupported_tools_directory}/vfychain

%files devel
%defattr(-,root,root)
%{_libdir}/libcrmf.a
%{_libdir}/pkgconfig/nss.pc
%{_bindir}/nss-config

%dir %{_includedir}/nss3
%{_includedir}/nss3/cert.h
%{_includedir}/nss3/certdb.h
%{_includedir}/nss3/certt.h
%{_includedir}/nss3/cmmf.h
%{_includedir}/nss3/cmmft.h
%{_includedir}/nss3/cms.h
%{_includedir}/nss3/cmsreclist.h
%{_includedir}/nss3/cmst.h
%{_includedir}/nss3/crmf.h
%{_includedir}/nss3/crmft.h
%{_includedir}/nss3/cryptohi.h
%{_includedir}/nss3/cryptoht.h
%{_includedir}/nss3/sechash.h
%{_includedir}/nss3/jar-ds.h
%{_includedir}/nss3/jar.h
%{_includedir}/nss3/jarfile.h
%{_includedir}/nss3/key.h
%{_includedir}/nss3/keyhi.h
%{_includedir}/nss3/keyt.h
%{_includedir}/nss3/keythi.h
%{_includedir}/nss3/nss.h
%{_includedir}/nss3/nssckbi.h
%{_includedir}/nss3/nsspem.h
%{_includedir}/nss3/ocsp.h
%{_includedir}/nss3/ocspt.h
%{_includedir}/nss3/p12.h
%{_includedir}/nss3/p12plcy.h
%{_includedir}/nss3/p12t.h
%{_includedir}/nss3/pk11func.h
%{_includedir}/nss3/pk11pqg.h
%{_includedir}/nss3/pk11priv.h
%{_includedir}/nss3/pk11pub.h
%{_includedir}/nss3/pk11sdr.h
%{_includedir}/nss3/pkcs12.h
%{_includedir}/nss3/pkcs12t.h
%{_includedir}/nss3/pkcs7t.h
%{_includedir}/nss3/preenc.h
%{_includedir}/nss3/secmime.h
%{_includedir}/nss3/secmod.h
%{_includedir}/nss3/secmodt.h
%{_includedir}/nss3/secpkcs5.h
%{_includedir}/nss3/secpkcs7.h
%{_includedir}/nss3/smime.h
%{_includedir}/nss3/ssl.h
%{_includedir}/nss3/sslerr.h
%{_includedir}/nss3/sslproto.h
%{_includedir}/nss3/sslt.h


%files pkcs11-devel
%defattr(-, root, root)
%{_includedir}/nss3/nssbase.h
%{_includedir}/nss3/nssbaset.h
%{_includedir}/nss3/nssckepv.h
%{_includedir}/nss3/nssckft.h
%{_includedir}/nss3/nssckfw.h
%{_includedir}/nss3/nssckfwc.h
%{_includedir}/nss3/nssckfwt.h
%{_includedir}/nss3/nssckg.h
%{_includedir}/nss3/nssckmdt.h
%{_includedir}/nss3/nssckt.h
%{_libdir}/libnssb.a
%{_libdir}/libnssckfw.a


%changelog
* Mon Nov 19 2012 Elio Maldonado <emaldona@redhat.com> - 3.14-7
- Bug 870864 - Add support in NSS for Secure Boot

* Fri Nov 09 2012 Elio Maldonado <emaldona@redhat.com> - 3.14-6
- Disable bypass code at build time and return failure on attempts to enable at runtime
- Bug 806588 - Disable SSL PKCS #11 bypass at build time
- Fix changelog release tags to match what was actually built

* Mon Nov 05 2012 Elio Maldonado <emaldona@redhat.com> - 3.14-5
- Fix pk11wrap locking which fixes 'fedpkg new-sources' and 'fedpkg update' hangs
- Bug 872124 - nss-3.14 breaks fedpkg new-sources

* Thu Nov 01 2012 Elio Maldonado <emaldona@redhat.com> - 3.14-4
- Add a dummy source file for testing /preventing fedpkg breakage
- Helps test the fedpkg new-sources and upload commands for breakage by nss updates
- Related to Bug 872124 - nss 3.14 breaks fedpkg new-sources

* Thu Nov 01 2012 Elio Maldonado <emaldona@redhat.com> - 3.14-3
- Reenable patch to set NSS_SSL_CBC_RANDOM_IV to 1 by default
- Update the patch to account for the new sources
- Resolves Bug 872124 - nss 3.14 breaks fedpkg new-sources

* Wed Oct 31 2012 Elio Maldonado <emaldona@redhat.com> - 3.14-2
- Fix the spec file so sechash.h gets installed
- Resolves: rhbz#871882 - missing header: sechash.h in nss 3.14

* Sat Oct 27 2012 Elio Maldonado <emaldona@redhat.com> - 3.14-4
- Update the license to MPLv2.0

* Wed Oct 24 2012 Elio Maldonado <emaldona@redhat.com> - 3.14-3
- Use only -f when removing unwanted headers

* Tue Oct 23 2012 Elio Maldonado <emaldona@redhat.com> - 3.14-2
- Add secmodt.h to the headers installed by nss-devel
- nss-devel must install secmodt.h which moved from softoken to pk11wrap with nss-3.14

* Mon Oct 22 2012 Elio Maldonado <emaldona@redhat.com> - 3.14-1
- Update to NSS_3_14_RTM

* Sun Oct 21 2012 Elio Maldonado <emaldona@redhat.com> - 3.14-0.1.rc.1
- Update to NSS_3_14_RC1
- update nss-589636.patch to apply to httpdserv
- turn off ocsp tests for now
- remove no longer needed patches
- remove headers shipped by nss-util

* Fri Oct 05 2012 Kai Engert <kaie@redhat.com> - 3.13.6-1
- Update to NSS_3_13_6_RTM

* Fri Aug 31 2012 Elio Maldonado <emaldona@redhat.com> - 3.13.5-8
- Rebase pem sources to fedora-hosted upstream to pick up two fixes from rhel-6.3
- Resolves: rhbz#847460 - Fix invalid read and free on invalid cert load
- Resolves: rhbz#847462 - PEM module may attempt to free uninitialized pointer 
- Remove unneeded fix gcc 4.7 c++ issue in secmodt.h that actually undoes the upstream fix
- Selective merge from master

* Mon Aug 13 2012 Elio Maldonado <emaldona@redhat.com> - 3.13.5-7
- Fix pluggable ecc support

* Sun Jul 01 2012 Elio Maldonado <emaldona@redhat.com> - 3.13.5-1
- Update to NSS_3_13_5_RTM
- Resolves: Bug 830410 - Missing Requires %%{?_isa}
- Use Requires: %%{name}%%{?_isa} = %%{version}-%%{release} on tools
- Drop zlib requires which rpmlint reports as error E: explicit-lib-dependency zlib
- Enable sha224 portion of powerup selftest when running test suites
- Require nspr 4.9.1
- Selective merge from master

* Fri Apr 13 2012 Elio Maldonado <emaldona@redhat.com> - 3.13.4-3
- Resolves: Bug 812423 - nss_Init leaks memory, fix from RHEL 6.3

* Sun Apr 08 2012 Elio Maldonado <emaldona@redhat.com> - 3.13.4-2
- Resolves: Bug 805723 - Library needs partial RELRO support added
- Patch coreconf/Linux.mk as done on RHEL 6.2

* Fri Apr 06 2012 Elio Maldonado <emaldona@redhat.com> - 3.13.4-1
- Update to NSS_3_13_4_RTM
- Update the nss-pem source archive to the latest version
- Remove no longer needed patches
- Resolves: Bug 806043 - use pem files interchangeably in a single process
- Resolves: Bug 806051 - PEM various flaws detected by Coverity
- Resolves: Bug 806058 - PEM pem_CreateObject leaks memory given a non-existing file name

* Wed Mar 21 2012 Elio Maldonado <emaldona@redhat.com> - 3.13.3-4
- Resolves: Bug 805723 - Library needs partial RELRO support added

* Fri Mar 09 2012 Elio Maldonado <emaldona@redhat.com> - 3.13.3-3
- Cleanup of the spec file
- Add references to the upstream bugs
- Fix typo in Summary for sysinit

* Thu Mar 08 2012 Elio Maldonado <emaldona@redhat.com> - 3.13.3-2
- Pick up fixes from RHEL
- Resolves: rhbz#800674 - Unable to contact LDAP Server during winsync
- Resolves: rhbz#800682 - Qpid AMQP daemon fails to load after nss update
- Resolves: rhbz#800676 - NSS workaround for freebl bug that causes openswan to drop connections

* Thu Mar 01 2012 Elio Maldonado <emaldona@redhat.com> - 3.13.3-1
- Update to NSS_3_13_3_RTM

* Mon Jan 30 2012 Tom Callaway <spot@fedoraproject.org> - 3.13.1-13
- fix issue with gcc 4.7 in secmodt.h and C++11 user-defined literals

* Thu Jan 26 2012 Elio Maldonado <emaldona@redhat.com> - 3.13.1-12
- Resolves: Bug 784672 - nss should protect against being called before nss_Init

* Fri Jan 13 2012 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 3.13.1-11
- Rebuilt for https://fedoraproject.org/wiki/Fedora_17_Mass_Rebuild

* Fri Jan 06 2012 Elio Maldonado <emaldona@redhat.com> - 3.13.1-11
- Deactivate a patch currently meant for stable branches only

* Fri Jan 06 2012 Elio Maldonado <emaldona@redhat.com> - 3.13.1-10
- Resolves: Bug 770682 - nss update breaks pidgin-sipe connectivity
- NSS_SSL_CBC_RANDOM_IV set to 0 by default and changed to 1 on user request

* Tue Dec 13 2011 elio maldonado <emaldona@redhat.com> - 3.13.1-9
- Revert to using current nss_softokn_version
- Patch to deal with lack of sha224 is no longer needed

* Tue Dec 13 2011 Elio Maldonado <emaldona@redhat.com> - 3.13.1-8
- Resolves: Bug 754771 - [PEM] an unregistered callback causes a SIGSEGV

* Mon Dec 12 2011 Elio Maldonado <emaldona@redhat.com> - 3.13.1-7
- Resolves: Bug 750376 - nss 3.13 breaks sssd TLS
- Fix how pem is built so that nss-3.13.x works with nss-softokn-3.12.y
- Only patch blapitest for the lack of sha224 on system freebl
- Completed the patch to make pem link against system freebl

* Mon Dec 05 2011 Elio Maldonado <emaldona@redhat.com> - 3.13.1-6
- Removed unwanted /usr/include/nss3 in front of the normal cflags include path
- Removed unnecessary patch dealing with CERTDB_TERMINAL_RECORD, it's visible

* Sun Dec 04 2011 Elio Maldonado <emaldona@redhat.com> - 3.13.1-5
- Statically link the pem module against system freebl found in buildroot
- Disabling sha224-related powerup selftest until we update softokn
- Disable sha224 and pss tests which nss-softokn 3.12.x doesn't support

* Fri Dec 02 2011 Elio Maldonado Batiz <emaldona@redhat.com> - 3.13.1-4
- Rebuild with nss-softokn from 3.12 in the buildroot
- Allows the pem module to statically link against 3.12.x freebl
- Required for using nss-3.13.x with nss-softokn-3.12.y for a merge inrto rhel git repo
- Build will be temprarily placed on buildroot override but not pushed in bodhi

* Fri Nov 04 2011 Elio Maldonado <emaldona@redhat.com> - 3.13.1-2
- Fix broken dependencies by updating the nss-util and nss-softokn versions

* Thu Nov 03 2011 Elio Maldonado <emaldona@redhat.com> - 3.13.1-1
- Update to NSS_3_13_1_RTM
- Update builtin certs to those from NSSCKBI_1_88_RTM

* Sat Oct 15 2011 Elio Maldonado <emaldona@redhat.com> - 3.13-1
- Update to NSS_3_13_RTM

* Sat Oct 08 2011 Elio Maldonado <emaldona@redhat.com> - 3.13-0.1.rc0.1
- Update to NSS_3_13_RC0

* Wed Sep 14 2011 Elio Maldonado <emaldona@redhat.com> - 3.12.11-3
- Fix attempt to free initilized pointer (#717338)
- Fix leak on pem_CreateObject when given non-existing file name (#734760)
- Fix pem_Initialize to return CKR_CANT_LOCK on multi-treaded calls (#736410)

* Tue Sep 06 2011 Kai Engert <kaie@redhat.com> - 3.12.11-2
- Update builtins certs to those from NSSCKBI_1_87_RTM

* Tue Aug 09 2011 Elio Maldonado <emaldona@redhat.com> - 3.12.11-1
- Update to NSS_3_12_11_RTM

* Sat Jul 23 2011 Elio Maldonado <emaldona@redhat.com> - 3.12.10-6
- Indicate the provenance of stripped source tarball (#688015)

* Mon Jun 27 2011 Michael Schwendt <mschwendt@fedoraproject.org> - 3.12.10-5
- Provide virtual -static package to meet guidelines (#609612).

* Fri Jun 10 2011 Elio Maldonado <emaldona@redhat.com> - 3.12.10-4
- Enable pluggable ecc support (#712556)
- Disable the nssdb write-access-on-read-only-dir tests when user is root (#646045)

* Fri May 20 2011 Dennis Gilmore <dennis@ausil.us> - 3.12.10-3
- make the testsuite non fatal on arm arches

* Tue May 17 2011 Elio Maldonado <emaldona@redhat.com> - 3.12.10-2
- Fix crmf hard-coded maximum size for wrapped private keys (#703656)

* Fri May 06 2011 Elio Maldonado <emaldona@redhat.com> - 3.12.10-1
- Update to NSS_3_12_10_RTM

* Wed Apr 27 2011 Elio Maldonado <emaldona@redhat.com> - 3.12.10-0.1.beta1
- Update to NSS_3_12_10_BETA1

* Mon Apr 11 2011 Elio Maldonado <emaldona@redhat.com> - 3.12.9-15
- Implement PEM logging using NSPR's own (#695011)

* Wed Mar 23 2011 Elio Maldonado <emaldona@redhat.com> - 3.12.9-14
- Update to NSS_3.12.9_WITH_CKBI_1_82_RTM

* Wed Feb 24 2011 Elio Maldonado <emaldona@redhat.com> - 3.12.9-13
- Short-term fix for ssl test suites hangs on ipv6 type connections (#539183)

* Fri Feb 18 2011 Elio Maldonado <emaldona@redhat.com> - 3.12.9-12
- Add a missing requires for pkcs11-devel (#675196)

* Tue Feb 15 2011 Elio Maldonado <emaldona@redhat.com> - 3.12.9-11
- Run the test suites in the check section (#677809)

* Thu Feb 10 2011 Elio Maldonado <emaldona@redhat.com> - 3.12.9-10
- Fix cms headers to not use c++ reserved words (#676036)
- Reenabling Bug 499444 patches
- Fix to swap internal key slot on fips mode switches

* Tue Feb 08 2011 Elio Maldonado <emaldona@redhat.com> - 3.12.9-9
- Revert patches for 499444 until all c++ reserved words are found and extirpated

* Tue Feb 08 2011 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 3.12.9-8
- Rebuilt for https://fedoraproject.org/wiki/Fedora_15_Mass_Rebuild

* Tue Feb 08 2011 Elio Maldonado <emaldona@redhat.com> - 3.12.9-7
- Fix cms header to not use c++ reserved word (#676036)
- Reenable patches for bug 499444

* Tue Feb 08 2011 Christopher Aillon <caillon@redhat.com> - 3.12.9-6
- Revert patches for 499444 as they use a C++ reserved word and
  cause compilation of Firefox to fail

* Fri Feb 04 2011 Elio Maldonado <emaldona@redhat.com> - 3.12.9-5
- Fix the earlier infinite recursion patch (#499444)
- Remove a header that now nss-softokn-freebl-devel ships

* Tue Feb 01 2011 Elio Maldonado <emaldona@redhat.com> - 3.12.9-4
- Fix infinite recursion when encoding NSS enveloped/digested data (#499444)

* Mon Jan 31 2011 Elio Maldonado <emaldona@redhat.com> - 3.12.9-3
- Update the cacert trust patch per upstream review requests (#633043)

* Wed Jan 19 2011 Elio Maldonado <emaldona@redhat.com> - 3.12.9-2
- Fix to honor the user's cert trust preferences (#633043)
- Remove obsoleted patch

* Wed Jan 12 2011 Elio Maldonado <emaldona@redhat.com> - 3.12.9-1
- Update to 3.12.9

* Mon Dec 27 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.9-0.1.beta2
- Rebuilt according to fedora pre-release package naming guidelines

* Fri Dec 10 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.8.99.2-1
- Update to NSS_3_12_9_BETA2
- Fix libpnsspem crash when cacert dir contains other directories (#642433)

* Wed Dec 08 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.8.99.1-1
- Update to NSS_3_12_9_BETA1

* Thu Nov 25 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.8-9
- Update pem source tar with fixes for 614532 and 596674
- Remove no longer needed patches

* Fri Nov 05 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.8-8
- Update PayPalEE.cert test certificate which had expired

* Sun Oct 31 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.8-7
- Tell rpm not to verify md5, size, and modtime of configurations file

* Wed Oct 18 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.8-6
- Fix certificates trust order (#643134)
- Apply nss-sysinit-userdb-first.patch last

* Wed Oct 06 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.8-5
- Move triggerpostun -n nss-sysinit script ahead of the other ones (#639248)

* Tue Oct 05 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.8-4
- Fix invalid %postun scriptlet (#639248)

* Wed Sep 29 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.8-3
- Replace posttrans sysinit scriptlet with a triggerpostun one (#636787)
- Fix and cleanup the setup-nsssysinit.sh script (#636792, #636801)

* Mon Sep 27 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.8-2
- Add posttrans scriptlet (#636787)

* Thu Sep 23 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.8-1
- Update to 3.12.8
- Prevent disabling of nss-sysinit on package upgrade (#636787)
- Create pkcs11.txt with correct permissions regardless of umask (#636792) 
- Setup-nsssysinit.sh reports whether nss-sysinit is turned on or off (#636801)
- Added provides pkcs11-devel-static to comply with packaging guidelines (#609612)

* Sat Sep 18 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.7.99.4-1
- NSS 3.12.8 RC0

* Sun Sep 05 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.7.99.3-2
- Fix nss-util_version and nss_softokn_version required to be 3.12.7.99.3

* Sat Sep 04 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.7.99.3-1
- NSS 3.12.8 Beta3
- Fix unclosed comment in renegotiate-transitional.patch

* Sat Aug 28 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.7-3
- Change BuildRequries to available version of nss-util-devel

* Sat Aug 28 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.7-2
- Define NSS_USE_SYSTEM_SQLITE and remove unneeded patch
- Add comments regarding an unversioned provides which triggers rpmlint warning
- Build requires nss-softokn-devel >= 3.12.7

* Mon Aug 16 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.7-1
- Update to 3.12.7

* Sat Aug 14 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.6-12
- Apply the patches to fix rhbz#614532

* Mon Aug 09 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.6-11
- Removed pem sourecs as they are in the cache

* Mon Aug 09 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.6-10
- Add support for PKCS#8 encoded PEM RSA private key files (#614532)

* Fri Jul 31 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.6-9
- Fix nsssysinit to return userdb ahead of systemdb (#603313)

* Tue Jun 08 2010 Dennis Gilmore <dennis@ausil.us> - 3.12.6-8
- Require and BuildRequire >= the listed version not =

* Tue Jun 08 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.6-7
- Require nss-softoken 3.12.6

* Sun Jun 06 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.6-6
- Fix SIGSEGV within CreateObject (#596674)

* Sat Apr 12 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.6-5
- Update pem source tar to pick up the following bug fixes:
- PEM - Allow collect objects to search through all objects
- PEM - Make CopyObject return a new shallow copy
- PEM - Fix memory leak in pem_mdCryptoOperationRSAPriv

* Wed Apr 07 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.6-4
- Update the test cert in the setup phase

* Wed Apr 07 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.6-3
- Add sed to sysinit requires as setup-nsssysinit.sh requires it (#576071)
- Update PayPalEE test cert with unexpired one (#580207)

* Thu Mar 18 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.6-2
- Fix ns.spec to not require nss-softokn (#575001)

* Sat Mar 06 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.6-1.2
- rebuilt with all tests enabled

* Sat Mar 06 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.6-1.1
- Using SSL_RENEGOTIATE_TRANSITIONAL as default while on transition period
- Disabling ssl tests suites until bug 539183 is resolved

* Sat Mar 06 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.6-1
- Update to 3.12.6
- Reactivate all tests
- Patch tools to validate command line options arguments

* Mon Jan 25 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.5-8
- Fix curl related regression and general patch code clean up

* Wed Jan 13 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.5-5
-  retagging

* Tue Jan 12 2010 Elio Maldonado <emaldona@redhat.com> - 3.12.5-1.1
- Fix SIGSEGV on call of NSS_Initialize (#553638)

* Wed Jan 06 2010 Elio Maldonado<emaldona@redhat.com> - 3.12.5-1.13.2
- New version of patch to allow root to modify ystem database (#547860)

* Thu Dec 31 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.5-1.13.1
- Temporarily disabling the ssl tests

* Sat Dec 26 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.5-1.13
- Fix nsssysinit to allow root to modify the nss system database (#547860)

* Fri Dec 25 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.5-1.11
- Fix an error introduced when adapting the patch for rhbz #546211

* Sat Dec 19 2009 Elio maldonado<emaldona@redhat.com> - 3.12.5-1.9
- Remove left over trace statements from nsssysinit patching

* Fri Dec 18 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.5-2.7
- Fix a misconstructed patch

* Thu Dec 17 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.5-1.6
- Fix nsssysinit to enable apps to use system cert store, patch contributed by David Woodhouse (#546221)
- Fix spec so sysinit requires coreutils for post install scriplet (#547067)
- Fix segmentation fault when listing keys or certs in the database, patch contributed by Kamil Dudka (#540387)

* Thu Dec 10 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.5-1.5
- Fix nsssysinit to set the default flags on the crypto module (#545779)
- Remove redundant header from the pem module

* Wed Dec 09 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.5-1.1
- Remove unneeded patch

* Thu Dec 03 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.5-1.1
- Retagging to include missing patch

* Thu Dec 03 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.5-1
- Update to 3.12.5
- Patch to allow ssl/tls clients to interoperate with servers that require renogiation

* Fri Nov 20 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.4-14.1
- Retagging

* Tue Oct 20 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.4-13.1
- Require nss-softoken of same architecture as nss (#527867)
- Merge setup-nsssysinit.sh improvements from F-12 (#527051)

* Mon Oct 03 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.4-13
- User no longer prompted for a password when listing keys an empty system db (#527048)
- Fix setup-nsssysinit to handle more general formats (#527051)

* Sun Sep 27 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.4-12
- Fix syntax error in setup-nsssysinit.sh

* Sun Sep 27 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.4-11
- Fix sysinit to be under mozilla/security/nss/lib

* Sat Sep 26 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.4-10
- Add nss-sysinit activation/deactivation script

* Fri Sep 18 2009 Elio Maldonado<emaldona@redhat.com - 3.12.4-9
- Install blank databases and configuration file for system shared database
- nsssysinit queries system for fips mode before relying on environment variable

* Thu Sep 10 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.4-8
- Restoring nssutil and -rpath-link to nss-config for now - 522477

* Tue Sep 08 2009 Elio Maldonado<emaldona@redhat.com - 3.12.4-7
- Add the nss-sysinit subpackage

* Tue Sep 08 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.4-6
- Installing shared libraries to %%{_libdir}

* Mon Sep 07 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.4-5
- Retagging to pick up new sources

* Mon Sep 07 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.4-4
- Update pem enabling source tar with latest fixes (509705, 51209)

* Sun Sep 06 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.4-3
- PEM module implements memory management for internal objects - 509705
- PEM module doesn't crash when processing malformed key files - 512019

* Sat Sep 05 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.4-2
- Remove symbolic links to shared libraries from devel - 521155
- No rpath-link in nss-softokn-config

* Tue Sep 01 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.4-1
- Update to 3.12.4

* Mon Aug 31 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.3.99.3-30
- Fix FORTIFY_SOURCE buffer overflows in test suite on ppc and ppc64 - bug 519766
- Fixed requires and buildrequires as per recommendations in spec file review

* Sun Aug 30 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.3.99.3-29
- Restoring patches 2 and 7 as we still compile all sources
- Applying the nss-nolocalsql.patch solves nss-tools sqlite dependency problems

* Sun Aug 30 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.3.99.3-28
- restore require sqlite

* Sat Aug 29 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.3.99.3-27
- Don't require sqlite for nss

* Sat Aug 29 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.3.99.3-26
- Ensure versions in the requires match those used when creating nss.pc

* Fri Aug 28 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.3.99.3-25
- Remove nss-prelink.conf as signed all shared libraries moved to nss-softokn
- Add a temprary hack to nss.pc.in to unblock builds

* Fri Aug 28 2009 Warren Togami <wtogami@redhat.com> - 3.12.3.99.3-24
- caolan's nss.pc patch

* Thu Aug 27 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.3.99.3-23
- Bump the release number for a chained build of nss-util, nss-softokn and nss

* Thu Aug 27 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.3.99.3-22
- Fix nss-config not to include nssutil
- Add BuildRequires on nss-softokn and nss-util since build also runs the test suite

* Wed Aug 27 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.3.99.3-21
- disabling all tests while we investigate a buffer overflow bug

* Wed Aug 27 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.3.99.3-20
- disabling some tests while we investigate a buffer overflow bug - 519766

* Wed Aug 27 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.3.99.3-19
- remove patches that are now in nss-softokn and
- remove spurious exec-permissions for nss.pc per rpmlint
- single requires line in nss.pc.in

* Wed Aug 26 2009 Elio Maldonado<emaldona@redhat.com> - 3.12.3.99.3-18
- Fix BuildRequires: nss-softokn-devel release number

* Wed Aug 26 2009 Elio Maldonado<emaldona@redhat.com - 3.12.3.99.3-17
- fix nss.pc.in to have one single requires line

* Tue Aug 25 2009 Dennis Gilmore <dennis@ausil.us> - 3.12.3.99.3-16
- cleanups for softokn

* Tue Aug 25 2009 Dennis Gilmore <dennis@ausil.us> - 3.12.3.99.3-15
- remove the softokn subpackages

* Mon Aug 24 2009 Dennis Gilmore <dennis@ausil.us> - 3.12.3.99.3-14
- don install the nss-util pkgconfig bits

* Mon Aug 24 2009 Dennis Gilmore <dennis@ausil.us> - 3.12.3.99.3-13
- remove from -devel the 3 headers that ship in nss-util-devel

* Mon Aug 24 2009 Dennis Gilmore <dennis@ausil.us> - 3.12.3.99.3-12
- kill off the nss-util nss-util-devel subpackages

* Sun Aug 23 2009 Elio Maldonado+emaldona@redhat.com - 3.12.3.99.3-11
- split off nss-softokn and nss-util as subpackages with their own rpms
- first phase of splitting nss-softokn and nss-util as their own packages

* Thu Aug 20 2009 Elio Maldonado <emaldona@redhat.com> - 3.12.3.99.3-10
- must install libnssutil3.since nss-util is untagged at the moment
- preserve time stamps when installing various files

* Thu Aug 20 2009 Dennis Gilmore <dennis@ausil.us> - 3.12.3.99.3-9
- dont install libnssutil3.so since its now in nss-util

* Sat Aug 06 2009 Elio Maldonado <emaldona@redhat.com> - 3.12.3.99.3-7.1
- Fix spec file problems uncovered by Fedora_12_Mass_Rebuild

* Sat Jul 25 2009 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 3.12.3.99.3-7
- Rebuilt for https://fedoraproject.org/wiki/Fedora_12_Mass_Rebuild

* Mon Jun 22 2009 Elio Maldonado <emaldona@redhat.com> - 3.12.3.99.3-6
- removed two patch files which are no longer needed and fixed previous change log number
* Mon Jun 22 2009 Elio Maldonado <emaldona@redhat.com> - 3.12.3.99.3-5
- updated pem module incorporates various patches
- fix off-by-one error when computing size to reduce memory leak. (483855)
- fix data type to work on x86_64 systems. (429175)
- fix various memory leaks and free internal objects on module unload. (501080)
- fix to not clone internal objects in collect_objects().  (501118)
- fix to not bypass initialization if module arguments are omitted. (501058)
- fix numerous gcc warnings. (500815)
- fix to support arbitrarily long password while loading a private key. (500180) 
- fix memory leak in make_key and memory leaks and return values in pem_mdSession_Login (501191)
* Fri Jun 08 2009 Elio Maldonado <emaldona@redhat.com> - 3.12.3.99.3-4
- add patch for bug 502133 upstream bug 496997
* Fri Jun 05 2009 Kai Engert <kaie@redhat.com> - 3.12.3.99.3-3
- rebuild with higher release number for upgrade sanity
* Fri Jun 05 2009 Kai Engert <kaie@redhat.com> - 3.12.3.99.3-2
- updated to NSS_3_12_4_FIPS1_WITH_CKBI_1_75
* Thu May 07 2009 Kai Engert <kaie@redhat.com> - 3.12.3-7
- re-enable test suite
- add patch for upstream bug 488646 and add newer paypal
  certs in order to make the test suite pass
* Wed May 06 2009 Kai Engert <kaie@redhat.com> - 3.12.3-4
- add conflicts info in order to fix bug 499436
* Tue Apr 14 2009 Kai Engert <kaie@redhat.com> - 3.12.3-3
- ship .chk files instead of running shlibsign at install time
- include .chk file in softokn-freebl subpackage
- add patch for upstream nss bug 488350
* Tue Apr 14 2009 Kai Engert <kaie@redhat.com> - 3.12.3-2
- Update to NSS 3.12.3
* Mon Apr 06 2009 Kai Engert <kaie@redhat.com> - 3.12.2.99.3-7
- temporarily disable the test suite because of bug 494266
* Mon Apr 06 2009 Kai Engert <kaie@redhat.com> - 3.12.2.99.3-6
- fix softokn-freebl dependency for multilib (bug 494122)
* Thu Apr 02 2009 Kai Engert <kaie@redhat.com> - 3.12.2.99.3-5
- introduce separate nss-softokn-freebl package
* Thu Apr 02 2009 Kai Engert <kaie@redhat.com> - 3.12.2.99.3-4
- disable execstack when building freebl
* Tue Mar 31 2009 Kai Engert <kaie@redhat.com> - 3.12.2.99.3-3
- add upstream patch to fix bug 483855
* Tue Mar 31 2009 Kai Engert <kaie@redhat.com> - 3.12.2.99.3-2
- build nspr-less freebl library
* Tue Mar 31 2009 Kai Engert <kaie@redhat.com> - 3.12.2.99.3-1
- Update to NSS_3_12_3_BETA4

* Wed Feb 25 2009 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 3.12.2.0-4
- Rebuilt for https://fedoraproject.org/wiki/Fedora_11_Mass_Rebuild

* Wed Oct 22 2008 Kai Engert <kaie@redhat.com> - 3.12.2.0-3
- update to NSS_3_12_2_RC1
- use system zlib
* Tue Sep 30 2008 Dennis Gilmore <dennis@ausil.us> - 3.12.1.1-4
- add sparc64 to the list of 64 bit arches

* Wed Sep 24 2008 Kai Engert <kaie@redhat.com> - 3.12.1.1-3
- bug 456847, move pkgconfig requirement to devel package
* Fri Sep 05 2008 Kai Engert <kengert@redhat.com> - 3.12.1.1-2
- Update to NSS_3_12_1_RC2
* Fri Aug 22 2008 Kai Engert <kaie@redhat.com> - 3.12.1.0-2
- NSS 3.12.1 RC1
* Fri Aug 15 2008 Kai Engert <kaie@redhat.com> - 3.12.0.3-7
- fix bug bug 429175 in libpem module
* Tue Aug 05 2008 Kai Engert <kengert@redhat.com> - 3.12.0.3-6
- bug 456847, add Requires: pkgconfig
* Tue Jun 24 2008 Kai Engert <kengert@redhat.com> - 3.12.0.3-3
- nss package should own /etc/prelink.conf.d folder, rhbz#452062
- use upstream patch to fix test suite abort
* Mon Jun 02 2008 Kai Engert <kengert@redhat.com> - 3.12.0.3-2
- Update to NSS_3_12_RC4
* Mon Apr 14 2008 Kai Engert <kengert@redhat.com> - 3.12.0.1-1
- Update to NSS_3_12_RC2
* Thu Mar 20 2008 Jesse Keating <jkeating@redhat.com> - 3.11.99.5-2
- Zapping old Obsoletes/Provides.  No longer needed, causes multilib headache.
* Mon Mar 17 2008 Kai Engert <kengert@redhat.com> - 3.11.99.5-1
- Update to NSS_3_12_BETA3
* Fri Feb 22 2008 Kai Engert <kengert@redhat.com> - 3.11.99.4-1
- NSS 3.12 Beta 2
- Use /usr/lib{64} as devel libdir, create symbolic links.
* Sat Feb 16 2008 Kai Engert <kengert@redhat.com> - 3.11.99.3-6
- Apply upstream patch for bug 417664, enable test suite on pcc.
* Fri Feb 15 2008 Kai Engert <kengert@redhat.com> - 3.11.99.3-5
- Support concurrent runs of the test suite on a single build host.
* Thu Feb 14 2008 Kai Engert <kengert@redhat.com> - 3.11.99.3-4
- disable test suite on ppc
* Thu Feb 14 2008 Kai Engert <kengert@redhat.com> - 3.11.99.3-3
- disable test suite on ppc64

* Thu Feb 14 2008 Kai Engert <kengert@redhat.com> - 3.11.99.3-2
- Build against gcc 4.3.0, use workaround for bug 432146
- Run the test suite after the build and abort on failures.

* Thu Jan 24 2008 Kai Engert <kengert@redhat.com> - 3.11.99.3-1
* NSS 3.12 Beta 1

* Mon Jan 07 2008 Kai Engert <kengert@redhat.com> - 3.11.99.2b-3
- move .so files to /lib

* Wed Dec 12 2007 Kai Engert <kengert@redhat.com> - 3.11.99.2b-2
- NSS 3.12 alpha 2b

* Mon Dec 03 2007 Kai Engert <kengert@redhat.com> - 3.11.99.2-2
- upstream patches to avoid calling netstat for random data

* Wed Nov 07 2007 Kai Engert <kengert@redhat.com> - 3.11.99.2-1
- NSS 3.12 alpha 2

* Wed Oct 10 2007 Kai Engert <kengert@redhat.com> - 3.11.7-10
- Add /etc/prelink.conf.d/nss-prelink.conf in order to blacklist
  our signed libraries and protect them from modification.

* Thu Sep 06 2007 Rob Crittenden <rcritten@redhat.com> - 3.11.7-9
- Fix off-by-one error in the PEM module

* Thu Sep 06 2007 Kai Engert <kengert@redhat.com> - 3.11.7-8
- fix a C++ mode compilation error

* Wed Sep 05 2007 Bob Relyea <rrelyea@redhat.com> - 3.11.7-7
- Add 3.12 ckfw and libnsspem

* Tue Aug 28 2007 Kai Engert <kengert@redhat.com> - 3.11.7-6
- Updated license tag

* Wed Jul 11 2007 Kai Engert <kengert@redhat.com> - 3.11.7-5
- Ensure the workaround for mozilla bug 51429 really get's built.

* Mon Jun 18 2007 Kai Engert <kengert@redhat.com> - 3.11.7-4
- Better approach to ship freebl/softokn based on 3.11.5
- Remove link time dependency on softokn

* Sun Jun 10 2007 Kai Engert <kengert@redhat.com> - 3.11.7-3
- Fix unowned directories, rhbz#233890

* Fri Jun 01 2007 Kai Engert <kengert@redhat.com> - 3.11.7-2
- Update to 3.11.7, but freebl/softokn remain at 3.11.5.
- Use a workaround to avoid mozilla bug 51429.

* Fri Mar 02 2007 Kai Engert <kengert@redhat.com> - 3.11.5-2
- Fix rhbz#230545, failure to enable FIPS mode
- Fix rhbz#220542, make NSS more tolerant of resets when in the 
  middle of prompting for a user password.

* Sat Feb 24 2007 Kai Engert <kengert@redhat.com> - 3.11.5-1
- Update to 3.11.5
- This update fixes two security vulnerabilities with SSL 2
- Do not use -rpath link option
- Added several unsupported tools to tools package

* Tue Jan  9 2007 Bob Relyea <rrelyea@redhat.com> - 3.11.4-4
- disable ECC, cleanout dead code

* Tue Nov 28 2006 Kai Engert <kengert@redhat.com> - 3.11.4-1
- Update to 3.11.4

* Thu Sep 14 2006 Kai Engert <kengert@redhat.com> - 3.11.3-2
- Revert the attempt to require latest NSPR, as it is not yet available
  in the build infrastructure.

* Thu Sep 14 2006 Kai Engert <kengert@redhat.com> - 3.11.3-1
- Update to 3.11.3

* Thu Aug 03 2006 Kai Engert <kengert@redhat.com> - 3.11.2-2
- Add /etc/pki/nssdb

* Wed Jul 12 2006 Jesse Keating <jkeating@redhat.com> - 3.11.2-1.1
- rebuild

* Fri Jun 30 2006 Kai Engert <kengert@redhat.com> - 3.11.2-1
- Update to 3.11.2
- Enable executable bit on shared libs, also fixes debug info.

* Wed Jun 14 2006 Kai Engert <kengert@redhat.com> - 3.11.1-2
- Enable Elliptic Curve Cryptography (ECC)

* Fri May 26 2006 Kai Engert <kengert@redhat.com> - 3.11.1-1
- Update to 3.11.1
- Include upstream patch to limit curves

* Wed Feb 15 2006 Kai Engert <kengert@redhat.com> - 3.11-4
- add --noexecstack when compiling assembler on x86_64

* Fri Feb 10 2006 Jesse Keating <jkeating@redhat.com> - 3.11-3.2
- bump again for double-long bug on ppc(64)

* Tue Feb 07 2006 Jesse Keating <jkeating@redhat.com> - 3.11-3.1
- rebuilt for new gcc4.1 snapshot and glibc changes

* Thu Jan 19 2006 Ray Strode <rstrode@redhat.com> 3.11-3
- rebuild

* Fri Dec 16 2005 Christopher Aillon <caillon@redhat.com> 3.11-2
- Update file list for the devel packages

* Thu Dec 15 2005 Christopher Aillon <caillon@redhat.com> 3.11-1
- Update to 3.11

* Thu Dec 15 2005 Christopher Aillon <caillon@redhat.com> 3.11-0.cvs.2
- Add patch to allow building on ppc*
- Update the pkgconfig file to Require nspr

* Thu Dec 15 2005 Christopher Aillon <caillon@redhat.com> 3.11-0.cvs
- Initial import into Fedora Core, based on a CVS snapshot of
  the NSS_3_11_RTM tag
- Fix up the pkcs11-devel subpackage to contain the proper headers
- Build with RPM_OPT_FLAGS
- No need to have rpath of /usr/lib in the pc file

* Thu Dec 15 2005 Kai Engert <kengert@redhat.com>
- Adressed review comments by Wan-Teh Chang, Bob Relyea,
  Christopher Aillon.

* Tue Jul  9 2005 Rob Crittenden <rcritten@redhat.com> 3.10-1
- Initial build
