#
%define _prefix /usr/local/opt
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

# Use system nspr/nss?
%define system_nss        1

# Use system sqlite?
%if 0%{?fedora} <= 17
%define system_sqlite     0
%else
%define system_sqlite     1
%endif

# Use system cairo?
%define system_cairo      0

# Build as a debug package?
%define debug_build       1

# Minimal required versions
%global cairo_version 1.10.2
%global freetype_version 2.1.9
%global libnotify_version 0.7.0
%global libvpx_version 1.0.0

%if %{?system_nss}
%global nspr_version 4.9
%global nss_version 3.13.3
%endif

%if %{?system_sqlite}
%global sqlite_version 3.7.7.1
# The actual sqlite version (see #480989):
%global sqlite_build_version %(pkg-config --silence-errors --modversion sqlite3 2>/dev/null || echo 65536)
%endif

# gecko_dir_ver should be set to the version in our directory names
# alpha_version should be set to the alpha number if using an alpha, 0 otherwise
# beta_version  should be set to the beta number if using a beta, 0 otherwise
# rc_version    should be set to the RC number if using an RC, 0 otherwise
%global gecko_dir_ver 2
%global alpha_version 0
%global beta_version  0
%global rc_version    0

%define base_name     xulrunner
%global mozappdir     %{_libdir}/%{base_name}-%{gecko_dir_ver}
%global tarballdir    mozilla-release

# crash reporter work only on x86/x86_64
%ifarch %{ix86} x86_64
%global enable_mozilla_crashreporter 0
%else
%global enable_mozilla_crashreporter 0
%endif

%if %{alpha_version} > 0
%global pre_version a%{alpha_version}
%global tarballdir  mozilla-beta
%endif
%if %{beta_version} > 0
%global pre_version b%{beta_version}
%global tarballdir  mozilla-beta
%endif
%if %{rc_version} > 0
%global pre_version rc%{rc_version}
%global tarballdir  mozilla-release
%endif

%if %{defined pre_version}
%global gecko_verrel %{expand:%%{version}}-%{pre_version}
%global pre_tag .%{pre_version}
%else
%global gecko_verrel %{expand:%%{version}}
%endif

Summary:        XUL Runtime for Gecko Applications
Name:           dt-xulrunner
Version:        15.0
Release:        2%{?pre_tag}%{?dist}
URL:            http://developer.mozilla.org/En/XULRunner
License:        MPLv1.1 or GPLv2+ or LGPLv2+
Group:          Applications/Internet
Source0:        ftp://ftp.mozilla.org/pub/%{base_name}/releases/%{version}%{?pre_version}/source/%{base_name}-%{version}%{?pre_version}.source.tar.bz2
Source10:       %{base_name}-mozconfig
Source11:       %{base_name}-mozconfig-debuginfo
Source12:       %{base_name}-redhat-default-prefs.js
Source21:       %{base_name}.sh.in

# build patches
Patch0:         xulrunner-version.patch
Patch1:         mozilla-build.patch
Patch14:        xulrunner-2.0-chromium-types.patch
%if 0%{?fedora} <= 15
Patch16:        add-gtkmozembed-11.0.patch
%endif
Patch17:        xulrunner-15.0-gcc47.patch
# https://bugzilla.redhat.com/show_bug.cgi?id=814879#c3
Patch18:        xulrunner-12.0-jemalloc-ppc.patch

# Fedora specific patches
Patch20:        mozilla-193-pkgconfig.patch

# Upstream patches
Patch49:        mozilla-746112.patch
Patch51:        mozilla-709732-gfx-icc-profile-fix.patch

# ---------------------------------------------------

%if %{?system_nss}
BuildRequires:  dt-nspr-devel >= %{nspr_version}
BuildRequires:  nss-devel >= %{nss_version}
BuildRequires:  nss-static >= %{nss_version}
%endif
%if %{?system_cairo}
BuildRequires:  cairo-devel >= %{cairo_version}
%endif
BuildRequires:  libpng-devel
BuildRequires:  libjpeg-devel
BuildRequires:  zip
BuildRequires:  bzip2-devel
BuildRequires:  zlib-devel
BuildRequires:  libIDL-devel
BuildRequires:  gtk2-devel
BuildRequires:  krb5-devel
BuildRequires:  pango-devel
BuildRequires:  freetype-devel >= %{freetype_version}
BuildRequires:  libXt-devel
BuildRequires:  libXrender-devel
BuildRequires:  hunspell-devel
BuildRequires:  startup-notification-devel
BuildRequires:  alsa-lib-devel
BuildRequires:  libnotify-devel >= %{libnotify_version}
BuildRequires:  mesa-libGL-devel
BuildRequires:  libcurl-devel
BuildRequires:  libvpx-devel >= %{libvpx_version}

Requires:       mozilla-filesystem
%if %{?system_nss}
Requires:       dt-nspr >= %{nspr_version}
Requires:       nss >= %{nss_version}
%endif
Provides:       gecko-libs = %{gecko_verrel}
Provides:       gecko-libs%{?_isa} = %{gecko_verrel}
Conflicts:      firefox < 3.6

%if %{?system_sqlite}
BuildRequires:  sqlite-devel >= %{sqlite_version}
Requires:       sqlite >= %{sqlite_build_version}
%endif

%description
XULRunner is a Mozilla runtime package that can be used to bootstrap XUL+XPCOM
applications that are as rich as Firefox and Thunderbird. It provides mechanisms
for installing, upgrading, and uninstalling these applications. XULRunner also
provides libxul, a solution which allows the embedding of Mozilla technologies
in other projects and products.

%package devel
Summary: Development files for Gecko
Group: Development/Libraries
Obsoletes: mozilla-devel < 1.9
Obsoletes: firefox-devel < 2.1
Obsoletes: dt-xulrunner-devel-unstable
Provides: gecko-devel = %{gecko_verrel}
Provides: gecko-devel%{?_isa} = %{gecko_verrel}
Provides: gecko-devel-unstable = %{gecko_verrel}
Provides: gecko-devel-unstable%{?_isa} = %{gecko_verrel}

Requires: dt-xulrunner = %{version}-%{release}
%if %{?system_nss}
Requires: dt-nspr-devel >= %{nspr_version}
Requires: nss-devel >= %{nss_version}
%endif
%if %{?system_cairo}
Requires: cairo-devel >= %{cairo_version}
%endif
Requires: libjpeg-devel
Requires: zip
Requires: bzip2-devel
Requires: zlib-devel
Requires: libIDL-devel
Requires: gtk2-devel
Requires: krb5-devel
Requires: pango-devel
Requires: freetype-devel >= %{freetype_version}
Requires: libXt-devel
Requires: libXrender-devel
Requires: hunspell-devel
%if %{?system_sqlite}
Requires: sqlite-devel
%endif
Requires: startup-notification-devel
Requires: alsa-lib-devel
Requires: libnotify-devel
Requires: mesa-libGL-devel
Requires: libvpx-devel >= %{libvpx_version}

%description devel
This package contains the libraries amd header files that are needed
for writing XUL+XPCOM applications with Mozilla XULRunner and Gecko.

%if %{enable_mozilla_crashreporter}
%global moz_debug_prefix %{_prefix}/lib/debug
%global moz_debug_dir %{moz_debug_prefix}%{mozappdir}
%global uname_m %(uname -m)
%global symbols_file_name %{base_name}-%{version}.en-US.%{_os}-%{uname_m}.crashreporter-symbols.zip
%global symbols_file_path %{moz_debug_dir}/%{symbols_file_name}
%global _find_debuginfo_opts -p %{symbols_file_path} -o debugcrashreporter.list
%global crashreporter_pkg_name mozilla-crashreporter-%{base_name}-debuginfo
%package -n %{crashreporter_pkg_name}
Summary: Debugging symbols used by Mozilla's crash reporter servers
Group: Development/Debug
%description -n %{crashreporter_pkg_name}
This package provides debug information for XULRunner, for use by
Mozilla's crash reporter servers.  If you are trying to locally
debug %{base_name}, you want to install %{base_name}-debuginfo instead.
%files -n %{crashreporter_pkg_name} -f debugcrashreporter.list
%defattr(-,root,root)
%endif

#---------------------------------------------------------------------

%prep
%setup -q -c
cd %{tarballdir}

sed -e 's/__RPM_VERSION_INTERNAL__/%{gecko_dir_ver}/' %{P:%%PATCH0} \
    > version.patch
%{__patch} -p1 -b --suffix .version --fuzz=0 < version.patch

%patch1  -p1 -b .build
%patch14 -p1 -b .chromium-types
%if 0%{?fedora} <= 15
%patch16 -p2 -b .gtkmozembed
%endif
%patch17 -p2 -b .gcc47
%patch18 -p2 -b .jemalloc-ppc

%patch20 -p2 -b .pk

%ifarch ppc ppc64
%patch49 -p2 -b .746112
%endif
%patch51 -p1 -b .709732

%{__rm} -f .mozconfig
%{__cp} %{SOURCE10} .mozconfig
%if %{enable_mozilla_crashreporter}
%{__cat} %{SOURCE11} >> .mozconfig
%endif

%if %{?system_nss}
echo "ac_add_options --with-system-nspr" >> .mozconfig
echo "ac_add_options --with-system-nss" >> .mozconfig
%else
echo "ac_add_options --without-system-nspr" >> .mozconfig
echo "ac_add_options --without-system-nss" >> .mozconfig
%endif

%if %{?system_sqlite}
echo "ac_add_options --enable-system-sqlite" >> .mozconfig
%else
echo "ac_add_options --disable-system-sqlite" >> .mozconfig
%endif

%if %{?system_cairo}
echo "ac_add_options --enable-system-cairo" >> .mozconfig
%else
echo "ac_add_options --disable-system-cairo" >> .mozconfig
%endif

%if %{?debug_build}
echo "ac_add_options --enable-debug" >> .mozconfig
echo "ac_add_options --disable-optimize" >> .mozconfig
%else
echo "ac_add_options --disable-debug" >> .mozconfig
echo "ac_add_options --enable-optimize" >> .mozconfig
%endif

# s390(x) fails to start with jemalloc enabled
%ifarch s390 s390x
echo "ac_add_options --disable-jemalloc" >> .mozconfig
%endif

%ifarch armv7hl
echo "ac_add_options --with-arch=armv7-a" >> .mozconfig
echo "ac_add_options --with-float-abi=hard" >> .mozconfig
echo "ac_add_options --with-fpu=vfpv3-d16" >> .mozconfig
echo "ac_add_options --disable-elf-hack" >> .mozconfig
%endif
%ifarch armv7hnl
echo "ac_add_options --with-arch=armv7-a" >> .mozconfig
echo "ac_add_options --with-float-abi=hard" >> .mozconfig
echo "ac_add_options --with-fpu=neon" >> .mozconfig
echo "ac_add_options --disable-elf-hack" >> .mozconfig
%endif
%ifarch armv5tel
echo "ac_add_options --with-arch=armv5te" >> .mozconfig
echo "ac_add_options --with-float-abi=soft" >> .mozconfig
echo "ac_add_options --disable-elf-hack" >> .mozconfig
%endif

%ifnarch %{ix86} x86_64
echo "ac_add_options --disable-methodjit" >> .mozconfig
echo "ac_add_options --disable-monoic" >> .mozconfig
echo "ac_add_options --disable-polyic" >> .mozconfig
echo "ac_add_options --disable-tracejit" >> .mozconfig
%endif

#---------------------------------------------------------------------

%build
%if %{?system_sqlite}
# Do not proceed with build if the sqlite require would be broken:
# make sure the minimum requirement is non-empty, ...
sqlite_version=$(expr "%{sqlite_version}" : '\([0-9]*\.\)[0-9]*\.') || exit 1
# ... and that major number of the computed build-time version matches:
case "%{sqlite_build_version}" in
  "$sqlite_version"*) ;;
  *) exit 1 ;;
esac
%endif

cd %{tarballdir}

# use dt-nspr
export PATH=/usr/local/opt/bin:/usr/local/opt/sbin:$PATH
export LDFLAGS="-Wl,-rpath,%{mozappdir} -Wl,-rpath,%{_libdir}"


# -fpermissive is needed to build with gcc 4.6+ which has become stricter
# 
# Mozilla builds with -Wall with exception of a few warnings which show up
# everywhere in the code; so, don't override that.
#
# Disable C++ exceptions since Mozilla code is not exception-safe
#
MOZ_OPT_FLAGS=$(echo "$RPM_OPT_FLAGS -fpermissive" | \
                      %{__sed} -e 's/-Wall//' -e 's/-fexceptions/-fno-exceptions/g')
%if %{?debug_build}
MOZ_OPT_FLAGS=$(echo "$MOZ_OPT_FLAGS" | %{__sed} -e 's/-O2//')
%endif
export CFLAGS=$MOZ_OPT_FLAGS
export CXXFLAGS=$MOZ_OPT_FLAGS

export PREFIX='%{_prefix}'
export LIBDIR='%{_libdir}'

MOZ_SMP_FLAGS=-j1
# On x86 architectures, Mozilla can build up to 4 jobs at once in parallel,
# however builds tend to fail on other arches when building in parallel.
%ifarch %{ix86} x86_64 ppc ppc64
[ -z "$RPM_BUILD_NCPUS" ] && \
     RPM_BUILD_NCPUS="`/usr/bin/getconf _NPROCESSORS_ONLN`"
[ "$RPM_BUILD_NCPUS" -ge 2 ] && MOZ_SMP_FLAGS=-j2
[ "$RPM_BUILD_NCPUS" -ge 4 ] && MOZ_SMP_FLAGS=-j4
[ "$RPM_BUILD_NCPUS" -ge 8 ] && MOZ_SMP_FLAGS=-j8
%endif

make -f client.mk build STRIP="/bin/true" MOZ_MAKE_FLAGS="$MOZ_SMP_FLAGS" MOZ_SERVICES_SYNC="1"

# create debuginfo for crash-stats.mozilla.com
%if %{enable_mozilla_crashreporter}
#cd %{moz_objdir}
make -C objdir buildsymbols
%endif

#---------------------------------------------------------------------

%install
cd %{tarballdir}

# set up our prefs before install, so it gets pulled in to omni.jar
%{__cp} -p %{SOURCE12} objdir/dist/bin/defaults/pref/all-redhat.js

DESTDIR=$RPM_BUILD_ROOT make -C objdir install

# Start script install
%{__rm} -rf $RPM_BUILD_ROOT%{_bindir}/%{base_name}
%{__cat} %{SOURCE21} | %{__sed} -e 's,XULRUNNER_VERSION,%{gecko_dir_ver},g' > \
  $RPM_BUILD_ROOT%{_bindir}/%{base_name}
%{__chmod} 755 $RPM_BUILD_ROOT%{_bindir}/%{base_name}

%{__rm} -f $RPM_BUILD_ROOT%{mozappdir}/%{base_name}-config

# Copy pc files (for compatibility with 1.9.1)
%{__cp} $RPM_BUILD_ROOT/%{_libdir}/pkgconfig/libxul.pc \
        $RPM_BUILD_ROOT/%{_libdir}/pkgconfig/libxul-unstable.pc
%{__cp} $RPM_BUILD_ROOT/%{_libdir}/pkgconfig/libxul-embedding.pc \
        $RPM_BUILD_ROOT/%{_libdir}/pkgconfig/libxul-embedding-unstable.pc

# Fix multilib devel conflicts...
function install_file() {
genheader=$*
mv ${genheader}.h ${genheader}%{__isa_bits}.h
cat > ${genheader}.h << EOF
/* This file exists to fix multilib conflicts */
#if defined(__x86_64__) || defined(__ia64__) || defined(__s390x__) || defined(__powerpc64__) || (defined(__sparc__) && defined(__arch64__))
#include "${genheader}64.h"
#else
#include "${genheader}32.h"
#endif
EOF
}

INTERNAL_APP_NAME=%{base_name}-%{gecko_dir_ver}

pushd $RPM_BUILD_ROOT/%{_includedir}/${INTERNAL_APP_NAME}
install_file "mozilla-config"
install_file "js-config"
popd

# Link libraries in sdk directory instead of copying them:
pushd $RPM_BUILD_ROOT%{_libdir}/%{base_name}-devel-%{gecko_dir_ver}/sdk/lib
for i in *.so; do
     rm $i
     ln -s %{mozappdir}/$i $i
done
popd

# Library path
LD_SO_CONF_D=%{_sysconfdir}/ld.so.conf.d
LD_CONF_FILE=xulrunner-%{__isa_bits}.conf

%{__mkdir_p} ${RPM_BUILD_ROOT}${LD_SO_CONF_D}
%{__cat} > ${RPM_BUILD_ROOT}${LD_SO_CONF_D}/${LD_CONF_FILE} << EOF
%{mozappdir}
EOF

# Copy over the LICENSE
%{__install} -p -c -m 644 LICENSE $RPM_BUILD_ROOT%{mozappdir}

# Install xpcshell
%{__cp} objdir/dist/bin/xpcshell $RPM_BUILD_ROOT/%{mozappdir}

# Install run-mozilla.sh
%{__cp} objdir/dist/bin/run-mozilla.sh $RPM_BUILD_ROOT/%{mozappdir}

# Use the system hunspell dictionaries
%{__rm} -rf ${RPM_BUILD_ROOT}%{mozappdir}/dictionaries
ln -s %{_datadir}/myspell ${RPM_BUILD_ROOT}%{mozappdir}/dictionaries

# ghost files
%{__mkdir_p} $RPM_BUILD_ROOT%{mozappdir}/components
touch $RPM_BUILD_ROOT%{mozappdir}/components/compreg.dat
touch $RPM_BUILD_ROOT%{mozappdir}/components/xpti.dat

# Add debuginfo for crash-stats.mozilla.com 
%if %{enable_mozilla_crashreporter}
%{__mkdir_p} $RPM_BUILD_ROOT/%{moz_debug_dir}
%{__cp} objdir/dist/%{symbols_file_name} $RPM_BUILD_ROOT/%{moz_debug_dir}
%endif

#---------------------------------------------------------------------

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%preun
# is it a final removal?
if [ $1 -eq 0 ]; then
  %{__rm} -rf %{mozappdir}/components
fi

%files
%defattr(-,root,root,-)
%{_bindir}/xulrunner
%dir %{mozappdir}
%doc %attr(644, root, root) %{mozappdir}/LICENSE
%doc %attr(644, root, root) %{mozappdir}/README.xulrunner
%{mozappdir}/chrome
%{mozappdir}/chrome.manifest
%{mozappdir}/dictionaries
%dir %{mozappdir}/components
%ghost %{mozappdir}/components/compreg.dat
%ghost %{mozappdir}/components/xpti.dat
%{mozappdir}/components/*.so
%{mozappdir}/components/*.manifest
%{mozappdir}/omni.ja
%{mozappdir}/plugins
%{mozappdir}/*.so
%{mozappdir}/mozilla-xremote-client
%{mozappdir}/run-mozilla.sh
%{mozappdir}/xulrunner
%{mozappdir}/xulrunner-stub
%{mozappdir}/platform.ini
%{mozappdir}/dependentlibs.list
%{_sysconfdir}/ld.so.conf.d/xulrunner*.conf
%{mozappdir}/plugin-container
%if !%{?system_nss}
%{mozappdir}/*.chk
%endif
%if %{enable_mozilla_crashreporter}
%{mozappdir}/crashreporter
%{mozappdir}/crashreporter.ini
%{mozappdir}/Throbber-small.gif
%endif

%files devel
%defattr(-,root,root,-)
%dir %{_libdir}/%{base_name}-devel-*
%{_datadir}/idl/%{base_name}*%{gecko_dir_ver}
%{_includedir}/%{base_name}*%{gecko_dir_ver}
%{_libdir}/%{base_name}-devel-*/*
%{_libdir}/pkgconfig/*.pc
%{mozappdir}/xpcshell

#---------------------------------------------------------------------

%changelog
* Wed Aug 22 2012 Martin Stransky <stransky@redhat.com> - 15.0-2
- Update to 15.0

* Thu Aug  9 2012 Jan Horak <jhorak@redhat.com> - 14.0.1-6
- Added fix for mozbz#709732

* Wed Jul 25 2012 Dan Horák <dan[at]danny.cz> - 14.0.1-5
- Added fix for secondary arches - mozbz#750620

* Sun Jul 22 2012 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 14.0.1-4
- Rebuilt for https://fedoraproject.org/wiki/Fedora_18_Mass_Rebuild

* Mon Jul 16 2012 Martin Stransky <stransky@redhat.com> - 14.0.1-3
- Update to 14.0.1

* Sat Jun 16 2012 Jan Horak <jhorak@redhat.com> - 13.0.1-1
- Update to 13.0.1

* Wed Jun 5 2012 Martin Stransky <stransky@redhat.com> - 13.0-2
- src.rpm should include all patches

* Mon Jun 4 2012 Martin Stransky <stransky@redhat.com> - 13.0-1
- Update to 13.0

* Mon May 28 2012 Martin Stransky <stransky@redhat.com> - 12.0-7
- More ppc(64) fixes - mozbz#746112

* Mon May 28 2012 Martin Stransky <stransky@redhat.com> - 12.0-6
- Added workaround for ppc(64) - mozbz#746112

* Mon May 7 2012 Dan Horák <dan[at]danny.cz> - 12.0-5
- Used backported upstream patch from mozb#734335 for fixing the sps profiler build
- Fixed build of jemalloc on ppc (patch by Gustavo Luiz Duarte/IBM)

* Fri May 4 2012 Dan Horák <dan[at]danny.cz> - 12.0-4
- Added new patch for 691898 - backport from trunk
- Added build fix for secondary arches

* Fri May 4 2012 Martin Stransky <stransky@redhat.com> - 12.0-3
- Added requires for nss-static (rhbz#717247)

* Mon Apr 30 2012 Martin Stransky <stransky@redhat.com> - 12.0-2
- Enable ppc(64) paralell builds (rhbz#816612)

* Tue Apr 24 2012 Martin Stransky <stransky@redhat.com> - 12.0-1
- Update to 12.0

* Tue Mar 13 2012 Martin Stransky <stransky@redhat.com> - 11.0-3
- Update to 11.0
- Fixed libvpx-devel dependency

* Fri Mar 9 2012 Martin Stransky <stransky@redhat.com> - 11.0-1
- Update to 11.0 Beta 7

* Fri Mar 09 2012 Dan Horák <dan[at]danny.cz> - 10.0.1-5
- Add fix for secondary arches from mozb#691898

* Mon Feb 27 2012 Martin Stransky <stransky@redhat.com> - 10.0.1-4
- Added fix from rhbz#796929 - xulrunner doesn't compile on ARM

* Tue Feb 16 2012 Martin Stransky <stransky@redhat.com> - 10.0.1-3
- Added fix for mozbz#727401

* Tue Feb 14 2012 Martin Stransky <stransky@redhat.com> - 10.0.1-2
- Allow network manager to handle the offline status

* Thu Feb  9 2012 Jan Horak <jhorak@redhat.com> - 10.0.1-1
- Update to 10.0.1

* Tue Jan 31 2012 Jan Horak <jhorak@redhat.com> - 10.0-1
- Update to 10.0

* Mon Jan 30 2012 Tom Callaway <spot@fedoraproject.org> 10.0-3
- fix issues causing ftbfs in rawhide

* Mon Jan 30 2012 Tom Callaway <spot@fedoraproject.org> 10.0-2
- rebuild against libvpx 1.0.0 (and BR 1.0.0 or greater)

* Mon Jan 23 2012 Martin Stransky <stransky@redhat.com> 10.0-1
- Update to 10.0 Beta 6

* Thu Jan 19 2012 Dennis Gilmore <dennis@ausil.us> - 9.0.1-4
- add missing v from armv7hl and armv7hnl config options

* Wed Jan 04 2012 Dan Horák <dan[at]danny.cz> - 9.0.1-3
- fix build on secondary arches (cherry-picked from 13afcd4c097c)

* Fri Dec 23 2011 Peter Robinson <pbrobinson@fedoraproject.org> - 9.0.1-2
- Add compile options for ARM hfp/sfp - RHBZ #738509

* Fri Dec 23 2011 Jan Horak <jhorak@redhat.com> - 9.0.1-1
- Update to 9.0.1

* Tue Dec 20 2011 Jan Horak <jhorak@redhat.com> - 9.0-2
- Update to 9.0

* Fri Dec 9 2011 Martin Stransky <stransky@redhat.com> 9.0-1.beta5
- Updated to 9.0 Beta 5

* Wed Dec  7 2011 Jan Horak <jhorak@redhat.com> - 8.0-5
- Gnome 3 proxy settings are now honoured (mozbz#682832)

* Tue Dec  6 2011 Tom Callaway <spot@fedoraproject.org> 8.0-4
- fix bug in npapi.h causing compile failures

* Fri Nov 25 2011 Martin Stransky <stransky@redhat.com> 8.0-3
- s390 build fixes

* Mon Nov 7 2011 Martin Stransky <stransky@redhat.com> 8.0-1
- Updated to 8.0

* Tue Oct 18 2011 Ville Skyttä <ville.skytta@iki.fi> - 7.0.1-5
- Avoid %%post/un shell invocations 
  and dependencies (rhbz#736830).

* Tue Oct 18 2011 Martin Stransky <stransky@redhat.com> 7.0.1-4
- Updated cairo dependency (rhbz#742853)

* Tue Oct 11 2011 Dan Horák <dan[at]danny.cz> 7.0.1-3
- fix build on secondary arches

* Mon Oct 10 2011 Martin Stransky <stransky@redhat.com> 7.0.1-2
- Removed GRE stuff
- Removed xulrunner rpath (mozbz#686434)

* Fri Sep 30 2011 Jan Horak <jhorak@redhat.com> - 7.0.1-1
- Update to 7.0.1

* Tue Sep 27 2011 Jan Horak <jhorak@redhat.com> - 7.0-1
- Update to 7.0

* Tue Sep  6 2011 Jan Horak <jhorak@redhat.com> - 6.0.2-1
- Update to 6.0.2

* Wed Aug 31 2011 Jan Horak <jhorak@redhat.com> - 6.0-3
- Distrust a specific Certificate Authority

* Tue Aug 16 2011 Martin Stransky <stransky@redhat.com> 6.0-2
- Updated gtkmozembed patch

* Tue Aug 16 2011 Martin Stransky <stransky@redhat.com> 6.0-1
- 6.0

* Thu Jun 30 2011 Martin Stransky <stransky@redhat.com> 5.0-5
- Fixed build on powerpc(64)

* Tue Jun 28 2011 Dan Horák <dan[at]danny.cz> - 5.0-4
- fix build on secondary arches with IPC enabled

* Tue Jun 24 2011 Martin Stransky <stransky@redhat.com> 5.0-3
- libCurl build fix

* Wed Jun 22 2011 Martin Stransky <stransky@redhat.com> 5.0-2
- Reverted mozbz#648156 - Remove gtkmozembed

* Tue Jun 21 2011 Martin Stransky <stransky@redhat.com> 5.0-1
- 5.0

* Thu May 26 2011 Martin Stransky <stransky@redhat.com> 2.0.1-2
- Rebuild for new hunspell (rhbz#707760)

* Thu Apr 28 2011 Christopher Aillon <caillon@redhat.com> - 2.0.1-1
- 2.0.1

* Thu Apr 21 2011 Christopher Aillon <caillon@redhat.com> - 2.0-4
- Split out mozilla crashreporter symbols to its own debuginfo package

* Sun Apr 10 2011 Christopher Aillon <caillon@redhat.com> - 2.0-3
- Fix offline status issue on version upgrades
- Fix a hang with 20+ extensions

* Mon Apr  4 2011 Christopher Aillon <caillon@redhat.com> - 2.0-2
- Fix SIGABRT in X_CloseDevice: XI_BadDevice
- Updates for NetworkManager 0.9
- Updates for GNOME 3

* Tue Mar 22 2011 Christopher Aillon <caillon@redhat.com> - 2.0-1
- 2.0

* Fri Mar 18 2011 Christopher Aillon <caillon@redhat.com> - 2.0-0.28
- Update to 2.0 RC2

* Thu Mar 17 2011 Jan Horak <jhorak@redhat.com> - 2.0-0.27
- Disabled gnomevfs
- Enabled gio
- Build with system libvpx

* Wed Mar  9 2011 Christopher Aillon <caillon@redhat.com> - 2.0-0.26
- Update to 2.0 RC 1

* Sun Feb 27 2011 Christopher Aillon <caillon@redhat.com> - 2.0-0.25
- Make Firefox's User-Agent string match upstream's

* Sat Feb 26 2011 Christopher Aillon <caillon@redhat.com> - 2.0-0.24
- Switch to using the omni chrome file format

* Fri Feb 25 2011 Christopher Aillon <caillon@redhat.com> - 2.0-0.23
- Update to 2.0 Beta 12

* Sun Feb 13 2011 Dennis Gilmore <dennis@ausil.us> 2.0-0.22
- disable nanojit on sparc64 its not supported and doesnt get automatically switched off

* Thu Feb 10 2011 Christopher Aillon <caillon@redhat.com> - 2.0-0.21
- Also provide arch-agnostic versions of gecko virtual provides

* Thu Feb 10 2011 Christopher Aillon <caillon@redhat.com> - 2.0-0.20
- Introduce better versioning for our gecko virtual provides
- Now, the gecko-libs and gecko-devel virtual provides will be pinned
  to an individual Gecko release, so packages can do things like
    Requires: gecko-libs = 2.0-beta11
    BuildRequires: gecko-libs = 2.0-beta11
- Final releases will be pinned to e.g. 2.0-1 regardless of %%{release}
- Also, make sure those virtual provides are arch-specific

* Tue Feb  8 2011 Christopher Aillon <caillon@redhat.com> - 2.0-0.19
- Update to 2.0 Beta 11

* Wed Jan 26 2011 Christopher Aillon <caillon@redhat.com> - 2.0-0.18
- Fix issue with popup windows showing in the wrong place

* Tue Jan 25 2011 Christopher Aillon <caillon@redhat.com> - 2.0-0.17
- Update to 2.0 Beta 10

* Fri Jan 21 2011 Dan Horák <dan[at]danny.cz> - 2.0-0.16.b9
- updated the 64bit-big-endian patch (bmo#627664)
- added fix for build with --disable-methodjit (bmo#623277)

* Fri Jan 14 2011 Christopher Aillon <caillon@redhat.com> 2.0-0.15.b9
- Update to 2.0 Beta 9

* Thu Jan 11 2011 Tom Callaway <spot@fedoraproject.org> 2.0-0.14.b8
- enable system sqlite (see https://fedorahosted.org/fpc/ticket/34)

* Thu Dec 23 2010 Martin Stransky <stransky@redhat.com> 2.0-0.13.b8
- reverted fix for rhbz#658471

* Wed Dec 22 2010 Dan Horák <dan[at]danny.cz> - 2.0-0.11.b8
- updated the 64bit-big-endian patch

* Tue Dec 21 2010 Martin Stransky <stransky@redhat.com> 2.0-0.11.b8
- enable url-classifier and jar format for chrome files

* Tue Dec 21 2010 Martin Stransky <stransky@redhat.com> 2.0-0.10.b8
- Update to 2.0b8

* Mon Dec 20 2010 Martin Stransky <stransky@redhat.com> 2.0-0.9.b8
- removed unused library path (rhbz#658471)

* Fri Dec 17 2010 Dan Horák <dan[at]danny.cz> - 2.0-0.8.b7
- disable the crash reporter on non-x86 arches
- add sparc64 as 64-bit arch

* Tue Dec 14 2010 Jan Horak <jhorak@redhat.com> - 2.0-0.7.b7
- Enable mozilla crash reporter

* Thu Nov 11 2010 Dan Horák <dan[at]danny.cz> - 2.0-0.6.b7
- The s390 patch is not needed anymore

* Thu Nov 11 2010 Jan Horak <jhorak@redhat.com> - 2.0-0.5.b7
- Update to 2.0b7

* Thu Nov 4 2010 Christopher Aillon <caillon@redhat.com> 2.0-0.4.b6
- Ensure that WM_CLASS matches the desktop file

* Wed Nov 3 2010 Martin Stransky <stransky@redhat.com> 2.0-0.3.b6
- Libnotify rebuild (rhbz#649071)

* Wed Sep 29 2010 jkeating - 2.0-0.2b6
- Rebuilt for gcc bug 634757

* Tue Sep 21 2010 Martin Stransky <stransky@redhat.com> 2.0-0.1.b6
- Update to 2.0b6

* Tue Sep  7 2010 Tom "spot" Callaway <tcallawa@redhat.com> 1.9.3.0-0.2.b4
- spec file cleanup

* Fri Aug 27 2010 Martin Stransky <stransky@redhat.com> 1.9.3.0-0.1.b4
- Update to 1.9.3.1 beta 4

* Mon Aug 16 2010 Martin Stransky <stransky@redhat.com> 1.9.3.0-0.b3
- Update to 1.9.3.1 beta 3

* Tue Jul 20 2010 Jan Horak <jhorak@redhat.com> - 1.9.2.7-1
- Update to 1.9.2.7

* Wed Jul 1 2010 Martin Stransky <stransky@redhat.com> 1.9.2.6-2
- Disabled oopp on unsupported arches (rhbz#614363)

* Wed Jun 30 2010 Jan Horak <jhorak@redhat.com> - 1.9.2.6-1
- Update to 1.9.2.6

* Tue Jun 22 2010 Jan Horak <jhorak@redhat.com> - 1.9.2.4-1
- Update to 1.9.2.4

* Tue Jun 15 2010 Dan Horák <dan@danny.cz> 1.9.2.3-2
- Fixed build on s390

* Fri Apr 2 2010 Martin Stransky <stransky@redhat.com> 1.9.2.3-1
- Update to 1.9.2.3

* Tue Mar 23 2010 Jan Horak <jhorak@redhat.com> - 1.9.2.2-1
- Update to 1.9.2.2

* Mon Mar 15 2010 Colin Walters <walters@verbum.org> - 1.9.2.1-4
- Enable startup notification, closes #445543

* Thu Feb 18 2010 Jan Horak <jhorak@redhat.com> - 1.9.2.1-3
- Added fix for mozbz#462919 - Override NSS database path 
  for xulrunner application
       
* Wed Feb 17 2010 Martin Stransky <stransky@redhat.com> 1.9.2.1-2
- Added fix for #564184 - xulrunner-devel multilib conflict

* Fri Jan 22 2010 Martin Stransky <stransky@redhat.com> 1.9.2.1-1
- Update to 1.9.2.1

* Wed Jan 18 2010 Martin Stransky <stransky@redhat.com> 1.9.2.1-0.10.rc1
- Update to 1.9.2.1 RC2

* Wed Jan 13 2010 Martin Stransky <stransky@redhat.com> 1.9.2.1-0.9.rc1
- Update to 1.9.2.1 RC1

* Mon Dec 21 2009 Martin Stransky <stransky@redhat.com> 1.9.2.1-0.8.b5
- Update to 1.9.2.1 Beta 5

* Thu Dec 17 2009 Martin Stransky <stransky@redhat.com> 1.9.2.1-0.7.b4
- Added fix for mozbz#543585 - jemalloc alignment assertion 
  and abort on Linux

* Thu Dec 3 2009 Martin Stransky <stransky@redhat.com> 1.9.2.1-0.6.b4
- Added fix for #543585 - mozilla-plugin.pc contains incorrect CFLAGS

* Fri Nov 27 2009 Martin Stransky <stransky@redhat.com> 1.9.2.1-0.5.b4
- Update to 1.9.2.1 Beta 4

* Mon Nov 23 2009 Martin Stransky <stransky@redhat.com> 1.9.2.1-0.4.b3
- added -unstable.pc files for compatibility with 1.9.1

* Fri Nov 20 2009 Martin Stransky <stransky@redhat.com> 1.9.2.1-0.3.b3
- Necko wifi monitor disabled
- fixed a dependency (#539261)
- added source URL (#521704)

* Wed Nov 18 2009 Martin Stransky <stransky@redhat.com> 1.9.2.1-0.2.b3
- Rebase to 1.9.2.1 Beta 3

* Fri Nov 13 2009 Martin Stransky <stransky@redhat.com> 1.9.2.1-0.1.beta2
- Rebase to 1.9.2.1 Beta 2
- fix the sqlite runtime requires again (#480989), add a check 
  that the sqlite requires is sane (by Stepan Kasal)

* Thu Nov  5 2009 Jan Horak <jhorak@redhat.com> - 1.9.1.5-1
- Update to 1.9.1.5

* Mon Oct 26 2009 Jan Horak <jhorak@redhat.com> - 1.9.1.4-1
- Update to 1.9.1.4

* Mon Sep  7 2009 Jan Horak <jhorak@redhat.com> - 1.9.1.3-1
- Update to 1.9.1.3

* Fri Aug 21 2009 Jan Horak <jhorak@redhat.com> - 1.9.1.2-4
- Added libnotify support

* Wed Aug 12 2009 Martin Stransky <stransky@redhat.com> 1.9.1.2-3
- Added fix from #516118 - Headers not C89

* Mon Aug 6 2009 Martin Stransky <stransky@redhat.com> 1.9.1.2-2
- Rebuilt

* Mon Aug 3 2009 Martin Stransky <stransky@redhat.com> 1.9.1.2-1
- Update to 1.9.1.2

* Mon Jul 27 2009 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 1.9.1.1-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_12_Mass_Rebuild

* Fri Jul 17 2009 Christopher Aillon <caillon@redhat.com> - 1.9.1.1-1
- Update to 1.9.1.1

* Mon Jul 13 2009 Jan Horak <jhorak@redhat.com> - 1.9.1-3
- Fixed wrong version of Firefox when loading 'about:' as location
- Added patch to compile against latest GTK

* Tue Jun 30 2009 Yanko Kaneti <yaneti@declera.com> - 1.9.1-2
- Build using system hunspell

* Tue Jun 30 2009 Christopher Aillon <caillon@redhat.com> 1.9.1-1
- Update to 1.9.1 final release

* Wed Jun 24 2009 Martin Stransky <stransky@redhat.com> 1.9.1-0.23
- Rebuilt because of gcc update (#506952)

* Thu Jun 18 2009 Martin Stransky <stransky@redhat.com> 1.9.1-0.22
- Backed out last change, it does not work inside mock (koji)

* Tue Jun 16 2009 Stepan Kasal <skasal@redhat.com> 1.9.1-0.21
- require sqlite of version >= what was used at buildtime (#480989)
- in devel subpackage, drop version from sqlite-devel require; that's
  handled indirectly through the versioned require in main package

* Mon Apr 27 2009 Christopher Aillon <caillon@redhat.com> 1.9.1-0.20
- 1.9.1 beta 4

* Fri Mar 27 2009 Christopher Aillon <caillon@redhat.com> 1.9.1-0.11
- Add patches for MFSA-2009-12, MFSA-2009-13

* Fri Mar 13 2009 Christopher Aillon <caillon@redhat.com> 1.9.1-0.10
- 1.9.1 beta 3

* Fri Feb 27 2009 Martin Stransky <stransky@redhat.com> 1.9.1-0.9
- Build fix for pango 1.23
- Misc. build fixes

* Thu Feb 26 2009 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 1.9.1-0.8.beta2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_11_Mass_Rebuild

* Wed Jan 28 2009 Christopher Aillon <caillon@redhat.com> 1.9.1-0.7
- Re-enable NM by default

* Wed Jan  7 2009 Martin Stransky <stransky@redhat.com> 1.9.1-0.6
- Copied mozilla-config.h to stable include dir (#478445)

* Mon Dec 22 2008 Christopher Aillon <caillon@redhat.com> 1.9.1-0.5
- Typo fix

* Sat Dec 20 2008 Christopher Aillon <caillon@redhat.com> 1.9.1-0.4
- 1.9.1 beta 2

* Tue Dec  9 2008 Christopher Aillon <caillon@redhat.com> 1.9.1-0.3
- Mark this as a pre-release

* Tue Dec  9 2008 Christopher Aillon <caillon@redhat.com> 1.9.1-0.2
- Add needed -devel requires to the -devel package

* Thu Dec  4 2008 Christopher Aillon <caillon@redhat.com> 1.9.1-0.1
- 1.9.1 beta 1

* Wed Nov 12 2008 Christopher Aillon <caillon@redhat.com> 1.9.0.4-1
- Update to 1.9.0.4

* Mon Oct 27 2008 Christopher Aillon <caillon@redhat.com> 1.9.0.2-5
- Password manager fixes from upstream

* Tue Oct  7 2008 Marco Pesenti Gritti <mpg@redhat.com> 1.9.0.2-4
- Add missing dependency on python-devel

* Sun Oct  5 2008 Christopher Aillon <caillon@redhat.com> 1.9.0.2-3
- Enable PyXPCOM

* Thu Sep 25 2008 Martin Stransky <stransky@redhat.com> 1.9.0.2-2 
- Build with system cairo (#463341)

* Tue Sep 23 2008 Christopher Aillon <caillon@redhat.com> 1.9.0.2-1
- Update to 1.9.0.2

* Wed Jul 23 2008 Christopher Aillon <caillon@redhat.com> 1.9.0.1-2
- Disable system hunspell for now as it's causing some crashes (447444)

* Wed Jul 16 2008 Christopher Aillon <caillon@redhat.com> 1.9.0.1-1
- Update to 1.9.0.1

* Tue Jun 17 2008 Christopher Aillon <caillon@redhat.com> 1.9-1
- Update to 1.9 final

* Thu May 29 2008 Christopher Aillon <caillon@redhat.com> 1.9-0.63
- Simplify PS/PDF operators

* Thu May 22 2008 Christopher Aillon <caillon@redhat.com> 1.9-0.62
- Upstream patch to fsync() less

* Thu May 08 2008 Colin Walters <walters@redhat.com> 1.9-0.61
- Ensure we enable startup notification; add BR and modify config
  (bug #445543)

* Wed Apr 30 2008 Christopher Aillon <caillon@redhat.com> 1.9-0.60
- Some files moved to mozilla-filesystem; kill them and add the Req

* Mon Apr 28 2008 Christopher Aillon <caillon@redhat.com> 1.9-0.59
- Clean up the %%files list and get rid of the executable bit on some files

* Sat Apr 26 2008 Christopher Aillon <caillon@redhat.com> 1.9-0.58
- Fix font scaling

* Fri Apr 25 2008 Martin Stransky <stransky@redhat.com> 1.9-0.57
- Enabled phishing protection (#443403)

* Wed Apr 23 2008 Martin Stransky <stransky@redhat.com> 1.9-0.56
- Changed "__ppc64__" to "__powerpc64__", 
  "__ppc64__" doesn't work anymore
- Added fix for #443725 - Critical hanging bug with fix 
  available upstream (mozbz#429903)

* Fri Apr 18 2008 Martin Stransky <stransky@redhat.com> 1.9-0.55
- Fixed multilib issues, added starting script instead of a symlink
  to binary (#436393)

* Sat Apr 12 2008 Christopher Aillon <caillon@redhat.com> 1.9-0.54
- Add upstream patches for dpi, toolbar buttons, and invalid keys
- Re-enable system cairo

* Mon Apr  7 2008 Christopher Aillon <caillon@redhat.com> 1.9-0.53
- Spec cleanups

* Wed Apr  2 2008 Christopher Aillon <caillon@redhat.com> 1.9-0.52
- Beta 5

* Mon Mar 31 2008 Christopher Aillon <caillon@redhat.com> 1.9-0.51
- Beta 5 RC2

* Thu Mar 27 2008 Christopher Aillon <caillon@redhat.com> 1.9-0.50
- Update to latest trunk (2008-03-27)

* Wed Mar 26 2008 Christopher Aillon <caillon@redhat.com> 1.9-0.49
- Update to latest trunk (2008-03-26)

* Tue Mar 25 2008 Christopher Aillon <caillon@redhat.com> 1.9-0.48
- Update to latest trunk (2008-03-25)

* Mon Mar 24 2008 Christopher Aillon <caillon@redhat.com> 1.9-0.47
- Update to latest trunk (2008-03-24)

* Thu Mar 20 2008 Christopher Aillon <caillon@redhat.com> 1.9-0.46
- Update to latest trunk (2008-03-20)

* Mon Mar 17 2008 Christopher Aillon <caillon@redhat.com> 1.9-0.45
- Update to latest trunk (2008-03-17)

* Mon Mar 17 2008 Christopher Aillon <caillon@redhat.com> 1.9-0.44
- Revert to trunk from the 15th to fix crashes on HTTPS sites

* Sun Mar 16 2008 Christopher Aillon <caillon@redhat.com> 1.9-0.43
- Update to latest trunk (2008-03-16)
- Add patch to negate a11y slowdown on some pages (#431162)

* Sat Mar 15 2008 Christopher Aillon <caillon@redhat.com> 1.9-0.42
- Update to latest trunk (2008-03-15)

* Sat Mar 15 2008 Christopher Aillon <caillon@redhat.com> 1.9-0.41
- Avoid conflicts between gecko debuginfo packages

* Wed Mar 12 2008 Christopher Aillon <caillon@redhat.com> 1.9-0.40
- Update to latest trunk (2008-03-12)

* Tue Mar 11 2008 Christopher Aillon <caillon@redhat.com> 1.9-0.39
- Update to latest trunk (2008-03-11)

* Mon Mar 10 2008 Christopher Aillon <caillon@redhat.com> 1.9-0.38
- Update to latest trunk (2008-03-10)

* Sun Mar  9 2008 Christopher Aillon <caillon@redhat.com> 1.9-0.37
- Update to latest trunk (2008-03-09)

* Fri Mar  7 2008 Christopher Aillon <caillon@redhat.com> 1.9-0.beta4.36
- Update to latest trunk (2008-03-07)

* Thu Mar  6 2008 Christopher Aillon <caillon@redhat.com> 1.9-0.beta4.35
- Update to latest trunk (2008-03-06)

* Tue Mar  4 2008 Christopher Aillon <caillon@redhat.com> 1.9-0.beta4.34
- Update to latest trunk (2008-03-04)

* Sun Mar  2 2008 Christopher Aillon <caillon@redhat.com> 1.9-0.beta3.33
- Update to latest trunk (2008-03-02)

* Sat Mar  1 2008 Christopher Aillon <caillon@redhat.com> 1.9-0.beta3.32
- Update to latest trunk (2008-03-01)

* Fri Feb 29 2008 Christopher Aillon <caillon@redhat.com> 1.9-0.beta3.31
- Update to latest trunk (2008-02-29)

* Thu Feb 28 2008 Christopher Aillon <caillon@redhat.com> 1.9-0.beta3.30
- Update to latest trunk (2008-02-28)

* Wed Feb 27 2008 Christopher Aillon <caillon@redhat.com> 1.9-0.beta3.29
- Update to latest trunk (2008-02-27)

* Tue Feb 26 2008 Christopher Aillon <caillon@redhat.com> 1.9-0.beta3.28
- Update to latest trunk (2008-02-26)

* Sat Feb 23 2008 Christopher Aillon <caillon@redhat.com> 1.9-0.beta3.27
- Update to latest trunk (2008-02-23)

* Fri Feb 22 2008 Christopher Aillon <caillon@redhat.com> 1.9-0.beta3.26
- Update to latest trunk (2008-02-22)

* Thu Feb 21 2008 Christopher Aillon <caillon@redhat.com> 1.9-0.beta3.25
- Update to latest trunk (2008-02-21)

* Wed Feb 20 2008 Christopher Aillon <caillon@redhat.com> 1.9-0.beta3.24
- Update to latest trunk (2008-02-20)

* Sun Feb 17 2008 Christopher Aillon <caillon@redhat.com> 1.9-0.beta3.23
- Update to latest trunk (2008-02-17)

* Fri Feb 15 2008 Christopher Aillon <caillon@redhat.com> 1.9-0.beta3.22
- Update to latest trunk (2008-02-15)

* Thu Feb 14 2008 Christopher Aillon <caillon@redhat.com> 1.9-0.beta3.21
- Update to latest trunk (2008-02-14)
- Use system hunspell

* Mon Feb 11 2008 Christopher Aillon <caillon@redhat.com> 1.9-0.beta2.19
- Update to latest trunk (2008-02-11)

* Mon Feb 11 2008 Adam Jackson <ajax@redhat.com> 1.9-0.beta2.19
- STRIP="/bin/true" on the %%make line so xulrunner-debuginfo contains,
  you know, debuginfo.

* Sun Feb 10 2008 Christopher Aillon <caillon@redhat.com> 1.9-0.beta2.18
- Update to latest trunk (2008-02-10)

* Sat Feb  9 2008 Christopher Aillon <caillon@redhat.com> 1.9-0.beta2.17
- Update to latest trunk (2008-02-09)

* Wed Feb  6 2008 Christopher Aillon <caillon@redhat.com> 1.9-0.beta2.16
- Update to latest trunk (2008-02-06)

* Tue Jan 29 2008 Christopher Aillon <caillon@redhat.com> 1.9-0.beta2.15
- Update to latest trunk (2008-01-30)

* Wed Jan 25 2008 Martin Stransky <stransky@redhat.com> 1.9-0.beta2.14
- rebuild agains new nss
- enabled gnome vfs

* Wed Jan 23 2008 Martin Stransky <stransky@redhat.com> 1.9-0.beta2.13
- fixed stable pkg-config files (#429654)
- removed sqlite patch

* Mon Jan 21 2008 Christopher Aillon <caillon@redhat.com> 1.9-0.beta2.12
- Update to latest trunk (2008-01-21)

* Tue Jan 15 2008 Christopher Aillon <caillon@redhat.com> 1.9-0.beta2.11
- Update to latest trunk (2008-01-15)
- Now with system extensions directory support

* Sat Jan 13 2008 Christopher Aillon <caillon@redhat.com> 1.9-0.beta2.10
- Update to latest trunk (2008-01-13)
- Use CFLAGS instead of configure arguments
- Random cleanups: BuildRequires, scriptlets, prefs, etc.

* Sat Jan 12 2008 Christopher Aillon <caillon@redhat.com> 1.9-0.beta2.9
- Provide gecko-devel-unstable as well

* Wed Jan 9 2008 Martin Stransky <stransky@redhat.com> 1.9-0.beta2.8
- divided devel package to devel and devel-unstable

* Mon Jan 7 2008 Martin Stransky <stransky@redhat.com> 1.9-0.beta2.7
- removed fedora specific pkg-config files
- updated to the latest trunk (2008-01-07)
- removed unnecessary patches
- fixed idl dir (#427965)

* Thu Jan 3 2008 Christopher Aillon <caillon@redhat.com> 1.9-0.beta2.6
- Re-enable camellia256 support now that NSS supports it

* Thu Jan 3 2008 Martin Stransky <stransky@redhat.com> 1.9-0.beta2.5
- updated to the latest trunk (2008-01-03)

* Mon Dec 24 2007 Christopher Aillon <caillon@redhat.com> 1.9-0.beta2.4
- Don't Provide webclient (xulrunner is not itself a webclient)
- Don't Obsolete old firefox, only firefox-devel
- Kill legacy obsoletes (phoenix, etc) that were never in rawhide

* Thu Dec 21 2007 Martin Stransky <stransky@redhat.com> 1.9-0.beta2.3
- added java and plugin subdirs to plugin includes

* Thu Dec 20 2007 Martin Stransky <stransky@redhat.com> 1.9-0.beta2.2
- dependency fixes, obsoletes firefox < 3 and firefox-devel now

* Wed Dec 12 2007 Martin Stransky <stransky@redhat.com> 1.9-0.beta2.1
- updated to Beta 2.
- moved SDK to xulrunner-sdk

* Thu Dec 06 2007 Martin Stransky <stransky@redhat.com> 1.9-0.beta1.4
- fixed mozilla-plugin.pc (#412971)

* Tue Nov 27 2007 Martin Stransky <stransky@redhat.com> 1.9-0.beta1.3
- export /etc/gre.d/gre.conf (it's used by python gecko applications)

* Mon Nov 26 2007 Martin Stransky <stransky@redhat.com> 1.9-0.beta1.2
- added xulrunner/js include dir to xulrunner-js

* Tue Nov 20 2007 Martin Stransky <stransky@redhat.com> 1.9-0.beta1.1
- update to beta 1

* Mon Nov 19 2007 Martin Stransky <stransky@redhat.com> 1.9-0.alpha9.6
- packed all gecko libraries (#389391)

* Thu Nov 15 2007 Martin Stransky <stransky@redhat.com> 1.9-0.alpha9.5
- registered xulrunner libs system-wide
- added xulrunner-gtkmozembed.pc

* Wed Nov 14 2007 Martin Stransky <stransky@redhat.com> 1.9-0.alpha9.4
- added proper nss/nspr dependencies

* Wed Nov 14 2007 Martin Stransky <stransky@redhat.com> 1.9-0.alpha9.3
- more build fixes, use system nss libraries

* Tue Nov 6 2007 Martin Stransky <stransky@redhat.com> 1.9-0.alpha9.2
- build fixes

* Tue Oct 30 2007 Martin Stransky <stransky@redhat.com> 1.9-0.alpha9.1
- updated to the latest trunk

* Thu Sep 20 2007 David Woodhouse <dwmw2@infradead.org> 1.9-0.alpha7.4
- build fixes for ppc/ppc64

* Tue Sep 20 2007 Martin Stransky <stransky@redhat.com> 1.9-0.alpha7.3
- removed conflicts with the current gecko-based apps
- added updated ppc64 patch

* Tue Sep 18 2007 Martin Stransky <stransky@redhat.com> 1.9-0.alpha7.2
- build fixes

* Wed Sep  5 2007 Christopher Aillon <caillon@redhat.com> 1.9-0.alpha7.1
- Initial cut at XULRunner 1.9 Alpha 7
- Temporarily revert camellia 256 support since our nss doesn't support it yet
