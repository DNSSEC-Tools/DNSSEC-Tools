Summary: A suite of tools for managing dnssec aware DNS usage
Name: dnssec-tools
Version: 1.3dev
Release: 1%{?dist}
License: BSD-like
Group: System Environment/Base
URL: http://www.dnssec-tools.org/
Source0: http://downloads.sourceforge.net/sourceforge/%{name}/%{name}-%{version}.tar.gz
Source1: dnssec-tools-dnsval.conf
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
# Require note: the auto-detection for perl-Net-DNS-SEC will not work since
# the tools do run time tests for their existence.  But most of the tools
# are much more useful with the modules in place, so we hand require them.
Requires: perl(Net::DNS), perl(Net::DNS::SEC), dnssec-tools-perlmods, bind
Requires:  perl(:MODULE_COMPAT_%(eval "`%{__perl} -V:version`"; echo $version))
BuildRequires: openssl-devel
BuildRequires: perl(Test) perl(ExtUtils::MakeMaker)

Patch4: dnssec-tools-linux-conf-paths-1.2.patch
Patch6: dnssec-tools-donuts-rules-paths.patch

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

%prep
%setup -q

%patch4 -p0
%patch6 -p0

%build
%configure --with-validator-testcases-file=%{_datadir}/dnssec-tools/validator-testcases --with-perl-build-args="INSTALLDIRS=vendor OPTIMIZE='$RPM_OPT_FLAGS'" --sysconfdir=/etc --with-root-hints=/etc/named.root.hints --with-resolv-conf=/etc/resolv.conf
sed -i 's|^hardcode_libdir_flag_spec=.*|hardcode_libdir_flag_spec=""|g' libtool
sed -i 's|^runpath_var=LD_RUN_PATH|runpath_var=DIE_RPATH_DIE|g' libtool
sed -i 's|^hardcode_libdir_flag_spec=.*|hardcode_libdir_flag_spec=""|g' validator/libtool
sed -i 's|^runpath_var=LD_RUN_PATH|runpath_var=DIE_RPATH_DIE|g' validator/libtool
make %{?_smp_mflags}

%install
rm -rf %{buildroot}
make install DESTCONFDIR=%{buildroot}/etc/dnssec-tools/ DESTDIR=%{buildroot} QUIET=

%{__install} -m 644 %{SOURCE1} %{buildroot}/etc/dnssec-tools/dnsval.conf

# remove unneeded perl install files
find %{buildroot} -type f -name .packlist -exec rm -f {} ';'
find %{buildroot} -type f -name perllocal.pod -exec rm -f {} ';'
find %{buildroot} -type f -name '*.bs' -size 0 -exec rm -f {} \;
# remove empty directories
find %{buildroot} -depth -type d -exec rmdir {} 2>/dev/null ';'
chmod -R u+w %{buildroot}/*
rm -f %{buildroot}%{_libdir}/*.la

%post libs -p /sbin/ldconfig

%postun libs -p /sbin/ldconfig

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
%doc README INSTALL COPYING

%config(noreplace) /etc/dnssec-tools/dnssec-tools.conf
%config(noreplace) /etc/dnssec-tools/dnsval.conf

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
%{_bindir}/keyarch
%{_bindir}/cleanarch

%{_bindir}/validate
# configure above 
%{_datadir}/dnssec-tools/validator-testcases
%{_bindir}/getaddr
%{_bindir}/gethost

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
%{_mandir}/man1/keyarch.1.gz
%{_mandir}/man1/maketestzone.1.gz
%{_mandir}/man1/mapper.1.gz
%{_mandir}/man1/validate.1.gz
%{_mandir}/man1/getaddr.1.gz
%{_mandir}/man1/gethost.1.gz
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
%{_mandir}/man1/cleanarch.1.gz
%{_mandir}/man1/blinkenlights.1.gz
%{_mandir}/man1/cleankrf.1.gz
%{_mandir}/man1/krfcheck.1.gz
%{_mandir}/man1/rolllog.1.gz
%{_mandir}/man1/signset-editor.1.gz
%{_mandir}/man1/trustman.1.gz

%{_mandir}/man3/p_ac_status.3.gz
%{_mandir}/man3/p_val_status.3.gz

%files perlmods
%defattr(-,root,root)

%{perl_vendorarch}/Net/addrinfo*
%{perl_vendorarch}/Net/DNS/SEC/*
%{perl_vendorarch}/auto/Net/DNS/SEC/Validator
%{perl_vendorarch}/auto/Net/addrinfo/
%{perl_vendorarch}/Net/DNS/ZoneFile/
%{perl_vendorlib}/Net/DNS/SEC/Tools/Donuts/

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
%{_mandir}/man3/Net::DNS::SEC::Validator.3pm.gz
%{_mandir}/man3/Net::addrinfo.3pm.gz
%{_mandir}/man3/Net::DNS::SEC::Tools::Donuts::Rule.3pm.gz
%{_mandir}/man3/Net::DNS::ZoneFile::Fast.3pm.gz

%files libs
%defattr(-,root,root)
%{_libdir}/*.so.*

%files libs-devel
%defattr(-,root,root)
%{_includedir}/validator
%{_libdir}/*.a
%{_libdir}/*.so

%{_bindir}/libval-config

%{_mandir}/man3/libval.3.gz
%{_mandir}/man3/val_getaddrinfo.3.gz
%{_mandir}/man3/val_gethostbyname.3.gz
%{_mandir}/man3/val_query.3.gz
%{_mandir}/man3/dnsval.conf.3.gz
%{_mandir}/man3/dnsval_conf_get.3.gz
%{_mandir}/man3/dnsval_conf_set.3.gz
%{_mandir}/man3/libsres.3.gz
%{_mandir}/man3/root_hints_get.3.gz
%{_mandir}/man3/root_hints_set.3.gz
%{_mandir}/man3/resolv_conf_get.3.gz
%{_mandir}/man3/resolv_conf_set.3.gz
%{_mandir}/man3/val_create_context.3.gz
%{_mandir}/man3/val_free_context.3.gz
%{_mandir}/man3/val_free_result_chain.3.gz
%{_mandir}/man3/val_istrusted.3.gz
%{_mandir}/man3/val_resolve_and_check.3.gz
%{_mandir}/man3/val_gethostbyaddr.3.gz
%{_mandir}/man3/val_gethostbyaddr_r.3.gz
%{_mandir}/man3/val_gethostbyname2.3.gz
%{_mandir}/man3/val_gethostbyname2_r.3.gz
%{_mandir}/man3/val_gethostbyname_r.3.gz
%{_mandir}/man3/val_getnameinfo.3.gz
%{_mandir}/man3/val_isvalidated.3.gz
%{_mandir}/man3/val_res_query.3.gz
%{_mandir}/man3/val_res_search.3.gz
#%{_mandir}/man3/val_addrinfo.3.gz
%{_mandir}/man3/val_add_valpolicy.3.gz
%{_mandir}/man3/val_create_context_with_conf.3.gz
%{_mandir}/man3/val_does_not_exist.3.gz
%{_mandir}/man3/val_free_response.3.gz
%{_mandir}/man3/val_freeaddrinfo.3.gz

%changelog
* Thu Jul 12 2007 Wes Hardaker <wjhns174@hardakers.net> - 1.2-4
- patch to fix a donuts rule for newer perl-Net::DNS update
- patch for maketestzone to work around a bug in Net::DNS::RR::DS

* Wed Jul 11 2007 Wes Hardaker <wjhns174@hardakers.net> - 1.2-3
- Added more Requires and better BuildRequires

* Thu May 31 2007 Wes Hardaker <wjhns174@hardakers.net> - 1.2-2
- fixed missing destdir in validator/Makefile.in
- add optimize flags to perl build
- syntatic ordering cleanup of the find argument

* Tue May 22 2007 Wes Hardaker <wjhns174@hardakers.net> - 1.2-1
- Update to 1.2 release

* Wed Apr 18 2007  Wes Hardaker <wjhns174@hardakers.net> - 1.1.1-4
- Fix changelog so it doesn't have a macro in the documentation
- Added a dnsval.conf starting file.
- Remove include subdir wildcard expansion since the entire directory
  is owned.

* Wed Apr 18 2007  Wes Hardaker <wjhns174@hardakers.net> - 1.1.1-3
- Add patch to make Net::DNS::SEC optional
- Fix date in previous log

* Wed Apr 18 2007  Wes Hardaker <wjhns174@hardakers.net> - 1.1.1-2
- Pointed Source0 at the sourceforge server instead of a local file
- Set License to BSD-like
- Took ownership of includedir/validator

* Tue Apr 10 2007  Wes Hardaker <wjhns174@hardakers.net> - 1.1.1-1
- Updated to upstream version 1.1.1

* Tue Mar 20 2007  Wes Hardaker <wjhns174@hardakers.net> - 1.1-2
- cleaned up spec file further for future submission to Fedora Extras
- made -libs-devel depend on exact version of -libs
- remove installed .la files
- added patch to use proper DESTDIR passing in the top Makefile

* Mon Mar 19 2007  Wes Hardaker <wjhns174@hardakers.net> - 1.1-1
- Updated to 1.1 and fixed rpmlint issues

* Mon Dec 04 2006   Wes Hardaker <wjhns174@hardakers.net> - 1.0
- updated to 1.0

* Mon Jun 19 2006   Wes Hardaker <wjhns174@hardakers.net> - 0.9.2-4
- updated to 0.9.2
- modified installation paths as appropriate to 

* Mon Jun 19 2006   Wes Hardaker <wjhns174@hardakers.net> - 0.9.1-1
- updated to 0.9.1

* Thu Feb  9 2006  Wes Hardaker <wjhns174@hardakers.net> - 0.9.0
- initial rpm
