Summary: A suite of tools for managing dnssec aware DNS usage
Name: dnssec-tools
Version: 1.1
Release: 2%{?dist}
License: BSD
Group: System Environment/Base
URL: http://www.dnssec-tools.org/
Source0: %{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
Requires: perl-Net-DNS, dnssec-tools-perlmods, bind
Requires:  perl(:MODULE_COMPAT_%(eval "`%{__perl} -V:version`"; echo $version))
BuildRequires: openssl-devel
Patch4: dnssec-tools-linux-conf-paths-1.1.patch
Patch5: dnssec-tools-conf-file-location.patch
Patch6: dnssec-tools-donuts-rules-paths.patch
# remove after 1.1:
Patch8: dnssec-tools-1.1-header-perms.patch
Patch9: dnssec-tools-pass-destdir.patch

%description

The goal of the DNSSEC-Tools project is to create a set of tools,
patches, applications, wrappers, extensions, and plugins that will
help ease the deployment of DNSSEC-related technologies.

%package perlmods
Group: System Environment/Libraries
Summary: Perl modules supporting DNSSEC (needed by the dnssec-tools)

%description perlmods

The dnssec-tools project comes with a number of perl modules that are
required by the DNSSEC tools themselves as well as modules that are
useful for other developers.

%package libs
Group: System Environment/Libraries
Summary: C-based libraries for dnssec aware tools
Requires: openssl

%description libs
C-based libraries useful for developing dnssec aware tools.

%package libs-devel
Group: Development/Libraries
Summary: C-based development libraries for dnssec aware tools
Requires: dnssec-tools-libs = %{version}-%{release}

%description libs-devel
C-based libraries useful for developing dnssec aware tools.

%package libs-debuginfo
Group: Development/Libraries
Summary: Debug information for package dnssec-tools

%description libs-debuginfo
This package provides debug information for package dnssec-tools.
Debug information is useful when developing applications that use this
package or when debugging this package.

%prep
%setup -q

%patch4 -p0
%patch5 -p0
%patch6 -p0
%patch8 -p0
%patch9 -p0

%build
%configure --with-perl-build-args="INSTALLDIRS=vendor"
sed -i 's|^hardcode_libdir_flag_spec=.*|hardcode_libdir_flag_spec=""|g' libtool
sed -i 's|^runpath_var=LD_RUN_PATH|runpath_var=DIE_RPATH_DIE|g' libtool
sed -i 's|^hardcode_libdir_flag_spec=.*|hardcode_libdir_flag_spec=""|g' validator/libtool
sed -i 's|^runpath_var=LD_RUN_PATH|runpath_var=DIE_RPATH_DIE|g' validator/libtool
make %{?_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT
make install DESTCONFDIR=$RPM_BUILD_ROOT/etc/dnssec/ DESTDIR=$RPM_BUILD_ROOT QUIET=

# remove unneeded perl install files
find $RPM_BUILD_ROOT -type f -name .packlist -exec rm -f {} ';'
find $RPM_BUILD_ROOT -type f -name perllocal.pod -exec rm -f {} ';'
# remove empty directories
find $RPM_BUILD_ROOT -type d -depth -exec rmdir {} 2>/dev/null ';'
chmod -R u+w $RPM_BUILD_ROOT/*
rm -f $RPM_BUILD_ROOT%{_libdir}/*.la

%post libs -p /sbin/ldconfig

%postun libs -p /sbin/ldconfig

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%doc README INSTALL COPYING

%config(noreplace) /etc/dnssec/dnssec-tools.conf

%{_bindir}/dnspktflow
%{_bindir}/donuts
%{_bindir}/donutsd
%{_bindir}/drawvalmap
%{_bindir}/expchk
%{_bindir}/genkrf
%{_bindir}/getdnskeys
%{_bindir}/lskrf
%{_bindir}/maketestzone
%{_bindir}/mapper
%{_bindir}/zonesigner
# this doesn't use %{_datadir} because patch6 above uses this exact path
/usr/share/dnssec-tools/donuts/rules/*

%{_bindir}/dtconfchk
%{_bindir}/dtdefs
%{_bindir}/dtinitconf
%{_bindir}/fixkrf
%{_bindir}/tachk
%{_bindir}/timetrans

%{_bindir}/lsroll
%{_bindir}/rollchk
%{_bindir}/rollctl
%{_bindir}/rollerd
%{_bindir}/rollinit
%{_bindir}/rollset

%{_bindir}/validate

%{_bindir}/TrustMan.pl
%{_bindir}/trustman
%{_bindir}/blinkenlights
%{_bindir}/cleankrf
%{_bindir}/krfcheck
%{_bindir}/rolllog
%{_bindir}/signset-editor


%{_mandir}/man1/dnspktflow.1.gz
%{_mandir}/man1/donuts.1.gz
%{_mandir}/man1/donutsd.1.gz
%{_mandir}/man1/drawvalmap.1.gz
%{_mandir}/man1/expchk.1.gz
%{_mandir}/man1/genkrf.1.gz
%{_mandir}/man1/getdnskeys.1.gz
%{_mandir}/man1/lskrf.1.gz
%{_mandir}/man1/maketestzone.1.gz
%{_mandir}/man1/mapper.1.gz
%{_mandir}/man1/validate.1.gz
%{_mandir}/man1/zonesigner.1.gz

%{_mandir}/man1/dtconfchk.1.gz
%{_mandir}/man1/dtdefs.1.gz
%{_mandir}/man1/dtinitconf.1.gz
%{_mandir}/man1/fixkrf.1.gz
%{_mandir}/man1/tachk.1.gz
%{_mandir}/man1/timetrans.1.gz

%{_mandir}/man1/lsroll.1.gz
%{_mandir}/man1/rollchk.1.gz
%{_mandir}/man1/rollctl.1.gz
%{_mandir}/man1/rollerd.1.gz
%{_mandir}/man1/rollinit.1.gz
%{_mandir}/man1/rollset.1.gz
%{_mandir}/man1/TrustMan.pl.1.gz
%{_mandir}/man1/blinkenlights.1.gz
%{_mandir}/man1/cleankrf.1.gz
%{_mandir}/man1/krfcheck.1.gz
%{_mandir}/man1/rolllog.1.gz
%{_mandir}/man1/signset-editor.1.gz
%{_mandir}/man1/trustman.1.gz

%{_mandir}/man3/TrustMan.3pm.gz
%{_mandir}/man3/p_ac_status.3.gz
%{_mandir}/man3/p_val_status.3.gz

%files perlmods
%defattr(-,root,root)

%{perl_vendorlib}/Net/DNS/SEC/Tools/Donuts/Rule.pm
%{perl_vendorlib}/Net/DNS/SEC/Tools/QWPrimitives.pm
%{perl_vendorlib}/Net/DNS/SEC/Tools/BootStrap.pm
%{perl_vendorlib}/Net/DNS/SEC/Tools/conf.pm
%{perl_vendorlib}/Net/DNS/SEC/Tools/keyrec.pm
%{perl_vendorlib}/Net/DNS/SEC/Tools/keyrec.pod
%{perl_vendorlib}/Net/DNS/SEC/Tools/rollmgr.pm
%{perl_vendorlib}/Net/DNS/SEC/Tools/rollrec.pm
%{perl_vendorlib}/Net/DNS/SEC/Tools/rollrec.pod
%{perl_vendorlib}/Net/DNS/SEC/Tools/defaults.pm
%{perl_vendorlib}/Net/DNS/SEC/Tools/timetrans.pm
%{perl_vendorlib}/Net/DNS/SEC/Tools/tooloptions.pm
%{perl_vendorlib}/Net/DNS/SEC/Tools/dnssectools.pm
%{perl_vendorlib}/Net/DNS/ZoneFile/Fast.pm
%{perl_vendorlib}/TrustMan.pl

%{_mandir}/man3/Net::DNS::SEC::Tools::Donuts::Rule.3pm.gz
%{_mandir}/man3/Net::DNS::SEC::Tools::QWPrimitives.3pm.gz
%{_mandir}/man3/Net::DNS::SEC::Tools::BootStrap.3pm.gz
%{_mandir}/man3/Net::DNS::SEC::Tools::conf.3pm.gz
%{_mandir}/man3/Net::DNS::SEC::Tools::keyrec.3pm.gz
%{_mandir}/man3/Net::DNS::SEC::Tools::rollmgr.3pm.gz
%{_mandir}/man3/Net::DNS::SEC::Tools::rollrec.3pm.gz
%{_mandir}/man3/Net::DNS::SEC::Tools::defaults.3pm.gz
%{_mandir}/man3/Net::DNS::SEC::Tools::timetrans.3pm.gz
%{_mandir}/man3/Net::DNS::SEC::Tools::tooloptions.3pm.gz
%{_mandir}/man3/Net::DNS::SEC::Tools::dnssectools.3pm.gz
%{_mandir}/man3/Net::DNS::ZoneFile::Fast.3pm.gz

%files libs
%defattr(-,root,root)
%{_libdir}/*.so.*

%files libs-devel
%defattr(-,root,root)
%{_includedir}/validator/*.h
%{_libdir}/*.a
%{_libdir}/*.so

%{_mandir}/man3/libval.3.gz
%{_mandir}/man3/val_getaddrinfo.3.gz
%{_mandir}/man3/val_gethostbyname.3.gz
%{_mandir}/man3/val_query.3.gz
%{_mandir}/man3/dnsval.conf.3.gz
%{_mandir}/man3/dnsval_conf_get.3.gz
%{_mandir}/man3/dnsval_conf_set.3.gz
%{_mandir}/man3/libsres.3.gz
%{_mandir}/man3/resolver_config_get.3.gz
%{_mandir}/man3/resolver_config_set.3.gz
%{_mandir}/man3/root_hints_get.3.gz
%{_mandir}/man3/root_hints_set.3.gz
%{_mandir}/man3/val_create_context.3.gz
%{_mandir}/man3/val_free_context.3.gz
%{_mandir}/man3/val_free_result_chain.3.gz
%{_mandir}/man3/val_istrusted.3.gz
%{_mandir}/man3/val_resolve_and_check.3.gz

%files libs-debuginfo
%{_libdir}/debug/%{_bindir}/validate.debug
%{_libdir}/debug/%{_libdir}/libsres.so.3.0.0.debug
%{_libdir}/debug/%{_libdir}/libval-threads.so.3.0.0.debug
%{_prefix}/src/debug/%{name}-%{version}/validator/*/*.c
%attr(644,root,root) %{_prefix}/src/debug/%{name}-%{version}/validator/*/*.h

%changelog
* Tue Mar 20 2007  <Wes Hardaker <hardaker@users.sourceforge.net>> - 1.1-2
- cleaned up spec file further for future submission to Fedora Extras
- made -libs-devel depend on exact version of -libs
- remove installed .la files
- added patch to use proper DESTDIR passing in the top Makefile

* Mon Mar 19 2007  <Wes Hardaker <hardaker@users.sourceforge.net>> - 1.1-1
- Updated to 1.1 and fixed rpmlint issues

* Mon Dec 04 2006   <Wes Hardaker <hardaker@users.sourceforge.net>> - 1.0
- updated to 1.0

* Mon Jun 19 2006   <Wes Hardaker <hardaker@users.sourceforge.net>> - 0.9.2-4
- updated to 0.9.2
- modified installation paths as appropriate to 

* Mon Jun 19 2006   <Wes Hardaker <hardaker@users.sourceforge.net>> - 0.9.1-1
- updated to 0.9.1

* Thu Feb  9 2006  <Wes Hardaker <hardaker@users.sourceforge.net> - 0.9.0
- initial rpm
