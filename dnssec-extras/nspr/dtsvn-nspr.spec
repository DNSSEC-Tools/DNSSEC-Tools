# DNSSEC-Tools
%define _default_patch_fuzz 2
#
%define _prefix /usr/local/dtsvn
%define __exec_prefix       %{_prefix}
%define _sysconfdir         %{_prefix}/etc
%define _libexecdir         %{_prefix}/libexec
%define _datadir            %{_prefix}/share
%define _localstatedir      %{_prefix}/%{_var}
%define _sharedstatedir     %{_prefix}/%{_var}/lib
%define _libexecdir         %{_prefix}/%{_lib}/security
%define _unitdir            %{_prefix}/%{_lib}/systemd/system
%define _bindir             %{_exec_prefix}/bin
%define _libdir             %{_exec_prefix}/%{_lib}
%define _libexecdir         %{_exec_prefix}/libexec
%define _sbindir            %{_exec_prefix}/sbin
%define _datarootdir        %{_prefix}/share
%define _datadir            %{_datarootdir}
%define _docdir             %{_datadir}/doc
%define _infodir            %{_prefix}/share/info
%define _mandir             %{_prefix}/share/man
%define _initddir           %{_sysconfdir}/rc.d/init.d
%define _usr                %{_prefix}/usr
%define _usrsrc             %{_prefix}/usr/src

Summary:        Netscape Portable Runtime
Name:           dtsvn-nspr
Version:        4.9.2
Release:        1%{?dist}
License:        MPLv2.0
URL:            http://www.mozilla.org/projects/nspr/
Group:          System Environment/Libraries
BuildRoot:      %{_tmppath}/%{name}-%{version}-root
Conflicts:      filesystem < 3
Requires:       dtsvn-dnsval-libs >= 1.14-1.svn7143
BuildRequires:  dtsvn-dnsval-libs-devel openssl-devel autoconf213


# Sources available at ftp://ftp.mozilla.org/pub/mozilla.org/nspr/releases/
# When CVS tag based snapshots are being used, refer to CVS documentation on
# mozilla.org and check out subdirectory mozilla/nsprpub.
Source0:        nspr-%{version}.tar.bz2

Patch1:         nspr-config-pc.patch

# DNSSEC-Tools
Patch1001:     nspr-0001-getaddr-patch-for-mozilla-bug-699055.patch
Patch1002:     nspr-0002-add-NSPR-log-module-for-DNS.patch
Patch1003:     nspr-0003-add-dnssec-options-flags-to-configure-and-makefiles.patch
Patch1004:     nspr-0004-add-DNSSEC-error-codes-and-text.patch
Patch1005:     nspr-0005-factor-out-common-code-from-PR_GetAddrInfoByName.patch
Patch1006:     nspr-0006-header-definitions-for-Extended-DNSSEC-and-asynchron.patch
Patch1007:     nspr-0007-add-dnssec-validation-to-prnetdb.patch
Patch1008:     nspr-0008-update-getai-to-test-async-disable-validation.patch


%description
NSPR provides platform independence for non-GUI operating system 
facilities. These facilities include threads, thread synchronization, 
normal file and network I/O, interval timing and calendar time, basic 
memory management (malloc and free) and shared library linking.

%package devel
Summary:        Development libraries for the Netscape Portable Runtime
Group:          Development/Libraries
Requires:       dtsvn-nspr = %{version}-%{release}
Requires:       pkgconfig
Conflicts:      filesystem < 3

%description devel
Header files for doing development with the Netscape Portable Runtime.

%prep

%setup -q -n nspr-%{version}

# Original nspr-config is not suitable for our distribution,
# because on different platforms it contains different dynamic content.
# Therefore we produce an adjusted copy of nspr-config that will be 
# identical on all platforms.
# However, we need to use original nspr-config to produce some variables
# that go into nspr.pc for pkg-config.

cp ./mozilla/nsprpub/config/nspr-config.in ./mozilla/nsprpub/config/nspr-config-pc.in
%patch1 -p0

###############################
# begin dnssec related patches
%patch1001 -p1 -d mozilla -b .dnssec
%patch1002 -p1 -d mozilla -b .dnssec
%patch1003 -p1 -d mozilla -b .dnssec
%patch1004 -p1 -d mozilla -b .dnssec
%patch1005 -p1 -d mozilla -b .dnssec
%patch1006 -p1 -d mozilla -b .dnssec
%patch1007 -p1 -d mozilla -b .dnssec
%patch1008 -p1 -d mozilla -b .dnssec
# rebuild configure(s) due to dnssec patches
(cd mozilla/nsprpub/; /bin/rm -f ./configure; /usr/bin/autoconf-2.13)
# end dnssec related patches
###############################

%build

# use dtsvn
export PATH=/usr/local/dtsvn/bin:/usr/local/dtsvn/sbin:$PATH
export LDFLAGS="-L%{_libdir} -Wl,-rpath,%{_libdir} "
export CFLAGS="-I%{_prefix}/include "

# partial RELRO support as a security enhancement
LDFLAGS+=-Wl,-z,relro
export LDFLAGS

./mozilla/nsprpub/configure \
                 --prefix=%{_prefix} \
                 --libdir=%{_libdir} \
                 --includedir=%{_includedir}/nspr4 \
%ifarch x86_64 ppc64 ia64 s390x sparc64
                 --enable-64bit \
%endif
%ifarch armv7l armv7hl armv7nhl
                 --enable-thumb2 \
%endif
                 --enable-optimize="$RPM_OPT_FLAGS" \
                 --with-system-val \
                 --disable-debug

make
make -C pr/tests getai

%check

# Run test suite.
perl ./mozilla/nsprpub/pr/tests/runtests.pl 2>&1 | tee output.log

TEST_FAILURES=`grep -c FAILED ./output.log` || :
if [ $TEST_FAILURES -ne 0 ]; then
  echo "error: test suite returned failure(s)"
  exit 1
fi
echo "test suite completed"

%install

%{__rm} -Rf $RPM_BUILD_ROOT

DESTDIR=$RPM_BUILD_ROOT \
  make install

NSPR_LIBS=`./config/nspr-config --libs`
NSPR_CFLAGS=`./config/nspr-config --cflags`
NSPR_VERSION=`./config/nspr-config --version`
%{__mkdir_p} $RPM_BUILD_ROOT/%{_libdir}/pkgconfig

# Get rid of the things we don't want installed (per upstream)
%{__rm} -rf \
   $RPM_BUILD_ROOT/%{_bindir}/compile-et.pl \
   $RPM_BUILD_ROOT/%{_bindir}/prerr.properties \
   $RPM_BUILD_ROOT/%{_libdir}/libnspr4.a \
   $RPM_BUILD_ROOT/%{_libdir}/libplc4.a \
   $RPM_BUILD_ROOT/%{_libdir}/libplds4.a \
   $RPM_BUILD_ROOT/%{_datadir}/aclocal/nspr.m4 \
   $RPM_BUILD_ROOT/%{_includedir}/nspr4/md

%{__cp} -a pr/tests/getai $RPM_BUILD_ROOT/%{_bindir}/

%clean
%{__rm} -Rf $RPM_BUILD_ROOT

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files
%defattr(-,root,root)
%{_bindir}/getai
%{_libdir}/libnspr4.so
%{_libdir}/libplc4.so
%{_libdir}/libplds4.so

%files devel
%defattr(-, root, root)
%{_includedir}/nspr4
%{_libdir}/pkgconfig/nspr.pc
%{_bindir}/nspr-config

%changelog
* Wed Aug 29 2012 Elio Maldonado <emaldona@redhat.com> - 4.9.2-1
- Update to NSPR_4_9_2_RTM

* Wed Jul 11 2012 Elio Maldonado <emaldona@redhat.com> - 4.9.1-2
- Updated License: to MPLv2.0 per upstream

* Fri Jun 22 2012 Elio Maldonado <emaldona@redhat.com> - 4.9.1-1
- Update to NSPR_4_9_1_RTM

* Wed Mar 21 2012 Elio Maldonado <emaldona@redhat.com> - 4.9-2
- Resolves: Bug 805672 - Library needs partial RELRO support added

* Wed Feb 29 2012 Elio Maldonado <emaldona@redhat.com> - 4.9-1
- Update to NSPR_4_9_RTM

* Wed Jan 25 2012 Harald Hoyer <harald@redhat.com> 4.9-0.2.beta3.1
- install everything in /usr
  https://fedoraproject.org/wiki/Features/UsrMove

* Wed Jan 25 2012 Harald Hoyer <harald@redhat.com> 4.9-0.2.beta3.1
- 

* Fri Jan 13 2012 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 4.9-0.2.beta3
- Rebuilt for https://fedoraproject.org/wiki/Fedora_17_Mass_Rebuild

* Thu Oct 06 2011 Elio Maldonado <emaldona@redhat.com> - 4.9-0.1.beta3
- Update to NSPR_4_9_BETA3

* Thu Sep  8 2011 Ville Skyttä <ville.skytta@iki.fi> - 4.8.9-2
- Avoid %%post/un shell invocations and dependencies.

* Tue Aug 09 2011 Elio Maldonado <emaldona@redhat.com> - 4.8.9-1
- Update to NSPR_4_8_9_RTM

* Mon Jul 18 2011 Elio Maldonado <emaldona@redhat.com> - 4.8.8-4
- The tests must pass for the build to succeed

* Mon Jul 18 2011 Elio Maldonado <emaldona@redhat.com> - 4.8.8-3
- Run the nspr test suite in the %%check section

* Wed Jul 06 2011 Elio Maldonado <emaldona@redhat.com> - 4.8.8-2
- Conditionalize Thumb2 build support on right Arm arches

* Fri May 06 2011 Elio Maldonado <emaldona@redhat.com> - 4.8.8-1
- Update to NSPR_4_8_8_RTM

* Mon Apr 25 2011 Elio Maldonado Batiz <emaldona@redhat.com> - 4.8.8-0.1.beta3
- Update to NSPR_4_8_8_BETA3

* Tue Feb 08 2011 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 4.8.7-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_15_Mass_Rebuild

* Wed Jan 12 2011 Elio Maldonado <emaldona@redhat.com> - 4.8.7-1
- Update to 4.8.7

* Mon Dec 27 2010 Elio Maldonado <emaldona@redhat.com> - 4.8.7-0.1beta2
- Rebuilt according to fedora pre-release naming guidelines

* Fri Dec 10 2010 Elio Maldonado <emaldona@redhat.com> - 4.8.6.99.2-1
- Update to NSPR_4_8_7_BETA2

* Tue Dec 07 2010 Elio Maldonado <emaldona@redhat.com> - 4.8.6.99.1-1
- Update to NSPR_4_8_7_BETA1

* Mon Aug 16 2010 Elio Maldonado <emaldona@redhat.com> - 4.8.6-1
- Update to 4.8.6

* Fri Mar 12 2010 Till Maas <opensource@till.name> - 4.8.4-2
- Fix release value

* Tue Feb 23 2010 Elio Maldonado <emaldona@redhat.com> - 4.8.4-1
- Update to 4.8.4

* Sat Nov 14 2009 Elio Maldonado<emaldona@redhat.com> - 4.8.2-3
- update to 4.8.2

* Sat Jul 25 2009 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 4.8-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_12_Mass_Rebuild

* Tue Jun 30 2009 Christopher Aillon <caillon@redhat.com> 4.8-1
- update to 4.8

* Fri Jun 05 2009 Kai Engert <kaie@redhat.com> - 4.7.4-2
- update to 4.7.4

* Wed Mar 04 2009 Kai Engert <kaie@redhat.com> - 4.7.3-5
- add a workaround for bug 487844

* Wed Feb 25 2009 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 4.7.3-4
- Rebuilt for https://fedoraproject.org/wiki/Fedora_11_Mass_Rebuild

* Wed Dec  3 2008 Ignacio Vazquez-Abrams <ivazqueznet+rpm@gmail.com> - 4.7.3-3
- Rebuild for pkgconfig

* Wed Nov 19 2008 Kai Engert <kaie@redhat.com> - 4.7.3-2
- update to 4.7.3
* Thu Oct 23 2008 Kai Engert <kaie@redhat.com> - 4.7.2-2
- update to 4.7.2

* Thu Oct  9 2008 Tom "spot" Callaway <tcallawa@redhat.com> - 4.7.1-5
- forgot to cvs add patch... whoops. :/

* Thu Oct  9 2008 Tom "spot" Callaway <tcallawa@redhat.com> - 4.7.1-4
- properly handle sparc64 in nspr code

* Tue Sep 30 2008 Dennis Gilmore <dennis@ausil.us> - 4.7.1-3
- add sparc64 to the list of 64 bit arches

* Mon Jun 02 2008 Kai Engert <kengert@redhat.com> - 4.7.1-2
- Update to 4.7.1

* Thu Mar 20 2008 Jesse Keating <jkeating@redhat.com> - 4.7.0.99.2-2
- Drop the old obsoletes/provides that aren't needed anymore.

* Mon Mar 17 2008 Kai Engert <kengert@redhat.com> - 4.7.0.99.2-1
- Update to NSPR_4_7_1_BETA2
* Tue Feb 26 2008 Kai Engert <kengert@redhat.com> - 4.7.0.99.1-2
- Addressed cosmetic review comments from bug 226202
* Fri Feb 22 2008 Kai Engert <kengert@redhat.com> - 4.7.0.99.1-1
- Update to NSPR 4.7.1 Beta 1
- Use /usr/lib{64} as devel libdir, create symbolic links.
* Sat Feb 09 2008 Kai Engert <kengert@redhat.com> - 4.7-1
- Update to NSPR 4.7

* Thu Jan 24 2008 Kai Engert <kengert@redhat.com> - 4.6.99.3-1
* NSPR 4.7 beta snapshot 20080120

* Mon Jan 07 2008 Kai Engert <kengert@redhat.com> - 4.6.99-2
- move .so files to /lib

* Wed Nov 07 2007 Kai Engert <kengert@redhat.com> - 4.6.99-1
- NSPR 4.7 alpha

* Tue Aug 28 2007 Kai Engert <kengert@redhat.com> - 4.6.7-3
- Updated license tag

* Fri Jul 06 2007 Kai Engert <kengert@redhat.com> - 4.6.7-2
- Update to 4.6.7

* Fri Jul 06 2007 Kai Engert <kengert@redhat.com> - 4.6.6-2
- Update thread-cleanup patch to latest upstream version
- Add upstream patch to support PR_STATIC_ASSERT

* Wed Mar 07 2007 Kai Engert <kengert@redhat.com> - 4.6.6-1
- Update to 4.6.6
- Adjust IPv6 patch to latest upstream version

* Sat Feb 24 2007 Kai Engert <kengert@redhat.com> - 4.6.5-2
- Update to latest ipv6 upstream patch
- Add upstream patch to fix a thread cleanup issue
- Now requires pkgconfig

* Mon Jan 22 2007 Wan-Teh Chang <wtchang@redhat.com> - 4.6.5-1
- Update to 4.6.5

* Tue Jan 16 2007 Kai Engert <kengert@redhat.com> - 4.6.4-2
- Include upstream patch to fix ipv6 support (rhbz 222554)

* Tue Nov 21 2006 Kai Engert <kengert@redhat.com> - 4.6.4-1
- Update to 4.6.4

* Thu Sep 14 2006 Kai Engert <kengert@redhat.com> - 4.6.3-1
- Update to 4.6.3

* Wed Jul 12 2006 Jesse Keating <jkeating@redhat.com> - 4.6.2-1.1
- rebuild

* Fri May 26 2006 Kai Engert <kengert@redhat.com> - 4.6.2-1
- Update to 4.6.2
- Tweak nspr-config to be identical on all platforms.

* Fri Feb 10 2006 Jesse Keating <jkeating@redhat.com> - 4.6.1-2.2
- bump again for double-long bug on ppc(64)

* Tue Feb 07 2006 Jesse Keating <jkeating@redhat.com> - 4.6.1-2.1
- rebuilt for new gcc4.1 snapshot and glibc changes

* Thu Jan  5 2006 Kai Engert <kengert@redhat.com> 4.6.1-2
- Do not use -ansi when compiling, because of a compilation
  problem with latest glibc and anonymous unions.
  See also bugzilla.mozilla.org # 322427.

* Wed Jan  4 2006 Kai Engert <kengert@redhat.com>
- Add an upstream patch to fix gcc visibility issues.

* Tue Jan  3 2006 Christopher Aillon <caillon@redhat.com>
- Stop shipping static libraries; NSS and dependencies no longer
  require static libraries to build.

* Thu Dec 15 2005 Christopher Aillon <caillon@redhat.com> 4.6.1-1
- Update to 4.6.1

* Fri Dec 09 2005 Jesse Keating <jkeating@redhat.com>
- rebuilt

* Fri Jul 15 2005 Christopher Aillon <caillon@redhat.com> 4.6-4
- Use the NSPR version numbering scheme reported by NSPR,
  which unfortunately is not exactly the same as the real
  version (4.6 != 4.6.0 according to RPM and pkgconfig).

* Fri Jul 15 2005 Christopher Aillon <caillon@redhat.com> 4.6-3
- Correct the CFLAGS reported by pkgconfig

* Tue Jul 12 2005 Christopher Aillon <caillon@redhat.com> 4.6-2
- Temporarily include the static libraries allowing nss and 
  its dependencies to build. 

* Tue Jul 12 2005 Christopher Aillon <caillon@redhat.com> 4.6-1
- Update to NSPR 4.6

* Wed Apr 20 2005 Christopher Aillon <caillon@redhat.com> 4.4.1-2
- NSPR doesn't have make install, but it has make real_install.  Use it.

* Thu Apr 14 2005 Christopher Aillon <caillon@redhat.com> 4.4.1-1
- Let's make an RPM.
