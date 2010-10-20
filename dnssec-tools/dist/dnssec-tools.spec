Summary: A suite of tools for managing dnssec aware DNS usage
Name: dnssec-tools
Version: 1.8
Release: 3%{?dist}
License: BSD
Group: System Environment/Base
URL: http://www.dnssec-tools.org/
Source0: https://www.dnssec-tools.org/downloads/%{name}-%{version}.tar.gz
Source1: dnssec-tools-dnsval.conf
Source2: libval-config
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
# Require note: the auto-detection for perl-Net-DNS-SEC will not work since
# the tools do run time tests for their existence.  But most of the tools
# are much more useful with the modules in place, so we hand require them.
Requires: perl(Net::DNS), perl(Net::DNS::SEC), dnssec-tools-perlmods, bind
Requires:  perl(:MODULE_COMPAT_%(eval "`%{__perl} -V:version`"; echo $version))
BuildRequires: openssl-devel
BuildRequires: perl(Test) perl(ExtUtils::MakeMaker)

Patch4: dnssec-tools-linux-conf-paths-1.7.patch

%description

The goal of the DNSSEC-Tools project is to create a set of tools,
patches, applications, wrappers, extensions, and plugins that will
help ease the deployment of DNSSEC-related technologies.

%package perlmods
Group: System Environment/Libraries
Summary: Perl modules supporting DNSSEC (needed by the dnssec-tools)
Requires: perl(Net::DNS), perl(Net::DNS::SEC)

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

%build
%configure --with-validator-testcases-file=%{_datadir}/dnssec-tools/validator-testcases --with-perl-build-args="INSTALLDIRS=vendor OPTIMIZE='$RPM_OPT_FLAGS'" --sysconfdir=/etc --with-root-hints=/etc/named.root.hints --with-resolv-conf=/etc/resolv.conf --disable-static --with-nsec3 --with-ipv6 --with-dlv
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

# Move the architecture dependent config file to its own place
# (this allows multiple architecture rpms to be installed at the same time)
mv ${RPM_BUILD_ROOT}/%{_bindir}/libval-config ${RPM_BUILD_ROOT}/%{_bindir}/libval-config-${basearch}
# Add a new wrapper script that calls the right file at run time
install -m 755 %SOURCE2 ${RPM_BUILD_ROOT}/%{_bindir}/libval-config


%post libs -p /sbin/ldconfig

%postun libs -p /sbin/ldconfig

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
%doc README INSTALL COPYING

%dir %{_sysconfdir}/dnssec-tools/
%config(noreplace) %{_sysconfdir}/dnssec-tools/dnssec-tools.conf
%config(noreplace) %{_sysconfdir}/dnssec-tools/dnsval.conf

%{_bindir}/dnspktflow
%{_bindir}/donuts
%{_bindir}/donutsd
%{_bindir}/drawvalmap
%{_bindir}/expchk
%{_bindir}/genkrf
%{_bindir}/getdnskeys
%{_bindir}/getds
%{_bindir}/lskrf
%{_bindir}/maketestzone
%{_bindir}/mapper
%{_bindir}/zonesigner
# this doesn't use %{_datadir} because patch6 above uses this exact path
/usr/share/dnssec-tools
#/usr/share/dnssec-tools/donuts
#/usr/share/dnssec-tools/donuts/rules
#/usr/share/dnssec-tools/donuts/rules/*

%{_bindir}/dtck
%{_bindir}/dtconfchk
%{_bindir}/dtconf
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

%{_bindir}/libval_check_conf
%{_bindir}/validate
# configure above 
#%{_datadir}/dnssec-tools/validator-testcases
%{_bindir}/getaddr
%{_bindir}/gethost
%{_bindir}/getname
%{_bindir}/getquery
%{_bindir}/getrrset

%{_bindir}/trustman
%{_bindir}/blinkenlights
%{_bindir}/cleankrf
%{_bindir}/krfcheck
%{_bindir}/rolllog
%{_bindir}/signset-editor
%{_bindir}/rollrec-editor

%{_bindir}/lsdnssec

%{_bindir}/bubbles
%{_bindir}/convertar

%{_mandir}/man1/dnssec-tools.1.gz
%{_mandir}/man1/dnspktflow.1.gz
%{_mandir}/man1/donuts.1.gz
%{_mandir}/man1/donutsd.1.gz
%{_mandir}/man1/drawvalmap.1.gz
%{_mandir}/man1/expchk.1.gz
%{_mandir}/man1/genkrf.1.gz
%{_mandir}/man1/getdnskeys.1.gz
%{_mandir}/man1/getds.1.gz
%{_mandir}/man1/lskrf.1.gz
%{_mandir}/man1/keyarch.1.gz
%{_mandir}/man1/maketestzone.1.gz
%{_mandir}/man1/mapper.1.gz
%{_mandir}/man1/validate.1.gz
%{_mandir}/man1/getaddr.1.gz
%{_mandir}/man1/gethost.1.gz
%{_mandir}/man1/getname.1.gz
%{_mandir}/man1/getquery.1.gz
%{_mandir}/man1/getrrset.1.gz
%{_mandir}/man1/zonesigner.1.gz

%{_mandir}/man1/dtconfchk.1.gz
%{_mandir}/man1/dtdefs.1.gz
%{_mandir}/man1/dtinitconf.1.gz
%{_mandir}/man1/fixkrf.1.gz
%{_mandir}/man1/tachk.1.gz
%{_mandir}/man1/timetrans.1.gz

%{_mandir}/man1/bubbles.1.gz
%{_mandir}/man1/convertar.1.gz

%{_mandir}/man1/lsroll.1.gz
%{_mandir}/man1/rollchk.1.gz
%{_mandir}/man1/rollctl.1.gz
%{_mandir}/man1/rollerd.1.gz
%{_mandir}/man1/rollinit.1.gz
%{_mandir}/man1/rollset.1.gz
%{_mandir}/man1/lsdnssec.1.gz
%{_mandir}/man1/cleanarch.1.gz
%{_mandir}/man1/blinkenlights.1.gz
%{_mandir}/man1/cleankrf.1.gz
%{_mandir}/man1/krfcheck.1.gz
%{_mandir}/man1/rolllog.1.gz
%{_mandir}/man1/signset-editor.1.gz
%{_mandir}/man1/trustman.1.gz
%{_mandir}/man1/dtck.1.gz
%{_mandir}/man1/dtconf.1.gz
%{_mandir}/man1/libval_check_conf.1.gz
%{_mandir}/man1/rollrec-editor.1.gz
%{_mandir}/man3/p_ac_status.3.gz
%{_mandir}/man3/p_val_status.3.gz

%files perlmods
%defattr(-,root,root)

# perl-Net-DNS-SEC is noarch and cannot own this directory:
%dir %{perl_vendorarch}/Net/DNS/SEC

%{perl_vendorarch}/Net/DNS/SEC/Tools
%{perl_vendorarch}/Net/addrinfo*
%{perl_vendorarch}/Net/DNS/SEC/*.pm
%{perl_vendorarch}/Net/DNS/SEC/*.pl
%{perl_vendorarch}/auto/Net/DNS/SEC/Validator
%{perl_vendorarch}/auto/Net/addrinfo/
%{perl_vendorarch}/Net/DNS/ZoneFile/
%{perl_vendorlib}/Net/DNS/SEC/Tools/

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
%{_mandir}/man3/Net::DNS::SEC::Tools::rolllog.3pm.gz

%{_mandir}/man3/Net::DNS::SEC::Tools::TrustAnchor.3pm.gz
%{_mandir}/man3/Net::DNS::SEC::Tools::TrustAnchor::Bind.3pm.gz
%{_mandir}/man3/Net::DNS::SEC::Tools::TrustAnchor::Csv.3pm.gz
%{_mandir}/man3/Net::DNS::SEC::Tools::TrustAnchor::Dns.3pm.gz
%{_mandir}/man3/Net::DNS::SEC::Tools::TrustAnchor::Dump.3pm.gz
%{_mandir}/man3/Net::DNS::SEC::Tools::TrustAnchor::Itar.3pm.gz
%{_mandir}/man3/Net::DNS::SEC::Tools::TrustAnchor::Libval.3pm.gz
%{_mandir}/man3/Net::DNS::SEC::Tools::TrustAnchor::Mf.3pm.gz
%{_mandir}/man3/Net::DNS::SEC::Tools::TrustAnchor::Secspider.3pm.gz

%files libs
%defattr(-,root,root)
%{_libdir}/*.so.*

%files libs-devel
%defattr(-,root,root)
%{_includedir}/validator
%{_libdir}/*.so

%{_bindir}/libval-config*

%{_mandir}/man3/libval.3.gz
%{_mandir}/man3/libval_shim.3.gz
%{_mandir}/man3/val_free_answer_chain.3.gz
%{_mandir}/man3/val_get_rrset.3.gz
%{_mandir}/man3/val_getaddrinfo.3.gz
%{_mandir}/man3/val_gethostbyname.3.gz
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
* Tue Oct  5 2010 Wes Hardaker <wjhns174@hardakers.net> - 1.8-3
- Added the . trust anchor and set default policy

* Tue Oct  5 2010 Wes Hardaker <wjhns174@hardakers.net> - 1.8-2
- Added nsec3 option

* Fri Sep 24 2010 Wes Hardaker <wjhns174@hardakers.net> - 1.8-1
- Update to the upstream 1.8 release

* Thu Jul  1 2010 Wes Hardaker <wjhns174@hardakers.net> - 1.7-1
- Update to upstream version 1.7

* Tue Jun 01 2010 Marcela Maslanova <mmaslano@redhat.com> - 1.6-4
- Mass rebuild with perl-5.12.0

* Fri May 21 2010 Tom "spot" Callaway <tcallawa@redhat.com> - 1.6-3
- disable static libs
- cleanup filelist to avoid duplication

* Mon Apr  5 2010 Wes Hardaker <wjhns174@hardakers.net> - 1.6-2
- version bump

* Mon Apr  5 2010 Wes Hardaker <wjhns174@hardakers.net> - 1.6-1
- Updated to 1.6

* Fri Aug 21 2009 Tomas Mraz <tmraz@redhat.com> - 1.5-4
- rebuilt with new openssl

* Fri Jul 24 2009 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 1.5-3
- Rebuilt for https://fedoraproject.org/wiki/Fedora_12_Mass_Rebuild

* Wed Apr  1 2009 Michael Schwendt <mschwendt@fedoraproject.org> - 1.5-2
- Fix unowned directories (#483339).

* Fri Mar  6 2009 Wes Hardaker <wjhns174@hardakers.net> - 1.5-1
- Update to 1.5

* Tue Feb 24 2009 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 1.4.1-7
- Rebuilt for https://fedoraproject.org/wiki/Fedora_11_Mass_Rebuild

* Wed Feb  4 2009 Wes Hardaker <wjhns174@hardakers.net> - 1.4.1-6
- make the perlmods module directly require the needed perl mods
  mainly for directory ownership.

* Mon Jan 26 2009 Wes Hardaker <wjhns174@hardakers.net> - 1.4.1-5
- Fixed arpa header compile conflict

* Thu Jan 15 2009 Tomas Mraz <tmraz@redhat.com> - 1.4.1-4
- rebuild with new openssl

* Mon Dec  1 2008 Wes Hardaker <wjhns174@hardakers.net> - 1.4.1-3
- Added package directories we own, left out ones we don't.

* Tue Jul 22 2008 Wes Hardaker <wjhns174@hardakers.net> - 1.4.1-2
- Added missing log message for security release

* Tue Jul 22 2008 Wes Hardaker <wjhns174@hardakers.net> - 1.4.1-1
- Update to upstream 1.4.1 which fixes the random port issue being
  broadcast about every resolver known to man including this one; note
  that DNSSEC itself will actually protect against the attack but
  libval is vulnerable to non-DNSSEC-protected zones without this fix.

* Tue May 27 2008 Wes Hardaker <wjhns174@hardakers.net> - 1.4.rc1-1
- Update to upstream 1.4

* Thu Mar 06 2008 Tom "spot" Callaway <tcallawa@redhat.com> - 1.3.2-2
Rebuild for new perl

* Fri Feb 15 2008 Wes Hardaker <wjhns174@hardakers.net> - 1.3.2-1
- Jump to upstream to grab latest identical fixes

* Fri Feb 15 2008 Wes Hardaker <wjhns174@hardakers.net> - 1.3.1-2
- Fix top level makefile for bulid dirs

* Fri Feb 15 2008 Wes Hardaker <wjhns174@hardakers.net> - 1.3.1-1
- Update to 1.3.1 to fix:
- A security bug in parent surrounding trust anchor checking in the
  libval library.
- Small fixes with donuts
- Small fixes with the ZoneFile::Fast parser

* Mon Jan  7 2008 Wes Hardaker <wjhns174@hardakers.net> - 1.3-7
- Fix donuts hard-coded rules path

* Fri Dec 07 2007 Release Engineering <rel-eng at fedoraproject dot org> - 1.3-6
- Rebuild for deps

* Tue Nov 27 2007 Wes Hardaker <wjhns174@hardakers.net> - 1.3-5
- Added a libval-config wrapper to get around a multi-arch issue

* Mon Nov 19 2007 Wes Hardaker <wjhns174@hardakers.net> - 1.3-4
- Bogus release bump to fix fedora tag issue

* Mon Nov 19 2007 Wes Hardaker <wjhns174@hardakers.net> - 1.3-3
- dnsval.conf syntax fix

* Mon Nov 19 2007 Wes Hardaker <wjhns174@hardakers.net> - 1.3-2
- New dnssec-tools.org dnskey

* Wed Oct 31 2007 Wes Hardaker <wjhns174@hardakers.net> - 1.3-1
- Update to 1.3

* Wed Aug  8 2007 Wes Hardaker <wjhns174@hardakers.net> - 1.2-6
- Actually apply the patch (sigh).

* Wed Aug  8 2007 Wes Hardaker <wjhns174@hardakers.net> - 1.2-5
- Fix make -jN support for the top level makefile

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
