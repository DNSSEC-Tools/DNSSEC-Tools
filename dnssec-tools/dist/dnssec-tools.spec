Summary: A suite of tools for managing dnssec aware DNS usage
Name: dnssec-tools
Version: 0.9.2
Release: 4%{?dist}
License: BSD
Group: System Environment
URL: http://www.dnssec-tools.org/
Source0: %{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
# we auto-load at runtime (with errors and help text) a bunch of stuff
# so we try to not force require some perl modules that the rpm build
# system would otherwise find.  Hence the no auto requirement derivation.
#AutoReqProv: no
Requires: perl-Net-DNS, dnssec-tools-perlmods, bind
Requires:  perl(:MODULE_COMPAT_%(eval "`%{__perl} -V:version`"; echo $version))
BuildRequires: openssl-devel
Patch1: dnssec-tools-runtime-perlloading.patch
Patch2: dnssec-tools-zonefilefast.ssh.patch
Patch3: dnssec-tools-conf-install-dir.patch
Patch4: dnssec-tools-linux-conf-paths.patch
Patch5: dnssec-tools-conf-file-location.patch
Patch6: dnssec-tools-donuts-rules-destdir.patch

%description

The goal of the DNSSEC-Tools project is to create a set of tools,
patches, applications, wrappers, extensions, and plugins that will
help ease the deployment of DNSSEC-related technologies.

%package perlmods
Group: System Environment/Libraries
Summary: Perl modules supporting DNSSEC (needed by the dnssec-tools)
#Provides: perl(Net::DNS::SEC::Tools::timetrans), perl(Net::DNS::SEC::Tools::QWPrimitives), perl(Net::DNS::SEC::Tools::conf), perl(Net::DNS::SEC::Tools::keyrec), perl(Net::DNS::SEC::Tools::timetrans), perl(Net::DNS::SEC::Tools::tooloptions), perl(Net::DNS::ZoneFile::Fast)

%description perlmods

The dnssec-tools project comes with a number of perl modules that are
required by the DNSSEC tools themselves as well as modules that are
useful for other developers.

%package libs
Group: System Environment/Libraries
Summary: C-based libraries for dnssec aware tools.
Requires: openssl

%description libs
C-based libraries useful for developing dnssec aware tools.

%package libs-devel
Group: Development/Libraries
Summary: development libraries for dnssec aware tools.

%description libs-devel
C-based libraries useful for developing dnssec aware tools.

%package libs-debug
Group: Development/Libraries
Summary: debugging symbols for dnssec-tools libraries.

%description libs-debug
debugging symbols for dnssec-tools libraries.

%prep
%setup -q

%patch1 -p0
%patch2 -p0
%patch3 -p0
%patch4 -p0
%patch5 -p0
%patch6 -p0

%build
%configure --with-perl-build-args="INSTALLDIRS=vendor"
make %{?_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT
%makeinstall DESTCONFDIR=$RPM_BUILD_ROOT/etc/dnssec/ DESTDIR=$RPM_BUILD_ROOT

# remove unneeded perl install files
find $RPM_BUILD_ROOT -type f -name .packlist -exec rm -f {} ';'
find $RPM_BUILD_ROOT -type f -name perllocal.pod -exec rm -f {} ';'
# remove empty directories
find $RPM_BUILD_ROOT -type d -depth -exec rmdir {} 2>/dev/null ';'
chmod -R u+w $RPM_BUILD_ROOT/*

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
%{_bindir}/keyrec-check
%{_bindir}/lskrf
%{_bindir}/maketestzone
%{_bindir}/mapper
%{_bindir}/zonesigner
%{_datadir}/donuts/rules/*

# newer
%{_bindir}/clean-keyrec
%{_bindir}/dtconfchk
%{_bindir}/dtdefs
%{_bindir}/dtinitconf
%{_bindir}/fixkrf
%{_bindir}/tachk
%{_bindir}/timetrans

# 0.9.1
%{_bindir}/TrustMan
%{_bindir}/lsroll
%{_bindir}/rollchk
%{_bindir}/rollctl
%{_bindir}/rollerd
%{_bindir}/rollinit

%{_bindir}/validate

%{_mandir}/man1/dnspktflow.1.gz
%{_mandir}/man1/donuts.1.gz
%{_mandir}/man1/donutsd.1.gz
%{_mandir}/man1/drawvalmap.1.gz
%{_mandir}/man1/expchk.1.gz
%{_mandir}/man1/genkrf.1.gz
%{_mandir}/man1/getdnskeys.1.gz
%{_mandir}/man1/keyrec-check.1.gz
%{_mandir}/man1/lskrf.1.gz
%{_mandir}/man1/maketestzone.1.gz
%{_mandir}/man1/mapper.1.gz
%{_mandir}/man1/validate.1.gz
%{_mandir}/man1/zonesigner.1.gz

# newer
%{_mandir}/man1/clean-keyrec.1.gz
%{_mandir}/man1/dtconfchk.1.gz
%{_mandir}/man1/dtdefs.1.gz
%{_mandir}/man1/dtinitconf.1.gz
%{_mandir}/man1/fixkrf.1.gz
%{_mandir}/man1/tachk.1.gz
%{_mandir}/man1/timetrans.1.gz

# 0.9.1
%{_mandir}/man1/TrustMan.1.gz
%{_mandir}/man1/lsroll.1.gz
%{_mandir}/man1/rollchk.1.gz
%{_mandir}/man1/rollctl.1.gz
%{_mandir}/man1/rollerd.1.gz
%{_mandir}/man1/rollinit.1.gz

##%{_mandir}/man*/*

%files perlmods
%defattr(-,root,root)

%{perl_vendorlib}/Net/DNS/SEC/Tools/Donuts/Rule.pm
%{perl_vendorlib}/Net/DNS/SEC/Tools/QWPrimitives.pm
%{perl_vendorlib}/Net/DNS/SEC/Tools/BootStrap.pm
%{perl_vendorlib}/Net/DNS/SEC/Tools/conf.pm
%{perl_vendorlib}/Net/DNS/SEC/Tools/keyrec.pm
%{perl_vendorlib}/Net/DNS/SEC/Tools/rollmgr.pm
%{perl_vendorlib}/Net/DNS/SEC/Tools/rollrec.pm
%{perl_vendorlib}/Net/DNS/SEC/Tools/defaults.pm
%{perl_vendorlib}/Net/DNS/SEC/Tools/timetrans.pm
%{perl_vendorlib}/Net/DNS/SEC/Tools/tooloptions.pm
%{perl_vendorlib}/Net/DNS/ZoneFile/Fast.pm

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
%{_mandir}/man3/Net::DNS::ZoneFile::Fast.3pm.gz

%files libs
%defattr(-,root,root)
%{_libdir}/*.so*

%files libs-devel
%defattr(-,root,root)
%{_includedir}
%{_libdir}/*.a
%{_libdir}/*.la

%{_mandir}/man3/libval.3.gz
%{_mandir}/man3/val_getaddrinfo.3.gz
%{_mandir}/man3/val_gethostbyname.3.gz
%{_mandir}/man3/val_query.3.gz
%{_mandir}/man3/dnsval.conf.3.gz
%{_mandir}/man3/dnsval_conf_get.3.gz
%{_mandir}/man3/dnsval_conf_set.3.gz
%{_mandir}/man3/libsres.3.gz
%{_mandir}/man3/p_as_error.3.gz
%{_mandir}/man3/p_val_error.3.gz
%{_mandir}/man3/resolver_config_get.3.gz
%{_mandir}/man3/resolver_config_set.3.gz
%{_mandir}/man3/root_hints_get.3.gz
%{_mandir}/man3/root_hints_set.3.gz
%{_mandir}/man3/val_create_context.3.gz
%{_mandir}/man3/val_free_context.3.gz
%{_mandir}/man3/val_free_result_chain.3.gz
%{_mandir}/man3/val_istrusted.3.gz
%{_mandir}/man3/val_resolve_and_check.3.gz
%{_mandir}/man3/val_switch_policy_scope.3.gz

%files libs-debug
%{_libdir}/debug/%{_bindir}/validate.debug
%{_libdir}/debug/%{_libdir}/libsres.so.1.0.0.debug
%{_libdir}/debug/%{_libdir}/libval.so.1.0.0.debug
%{_prefix}/src/debug/%{name}-%{version}/validator/*/*.c
%{_prefix}/src/debug/%{name}-%{version}/validator/*/*.h
%{_prefix}/src/debug/%{name}-%{version}/validator/libval/crypto/*.c
%changelog

* Mon Jun 19 2006   <Wes Hardaker <hardaker@users.sourceforge.net>> - 0.9.2-4
- updated to 0.9.2
- modified installation paths as appropriate to 

* Mon Jun 19 2006   <Wes Hardaker <hardaker@users.sourceforge.net>> - 0.9.1-1
- updated to 0.9.1

* Thu Feb  9 2006  <Wes Hardaker <hardaker@users.sourceforge.net> - 0.9.0
- initial rpm
