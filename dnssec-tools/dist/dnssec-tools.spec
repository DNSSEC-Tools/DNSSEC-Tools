Summary: A suite of tools for managing dnssec aware DNS usage
Name: dnssec-tools
Version: 0.9.2
Release: 3
License: BSD
Group: System Environment
URL: http://www.dnssec-tools.org/
Source0: %{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root
BuildRequires: autoconf213
# we auto-load at runtime (with errors and help text) a bunch of stuff
# so we try to not force require some perl modules that the rpm build
# system would otherwise find.  Hence the no auto requirement derivation.
#AutoReqProv: no
Requires: perl, perl-Net-DNS, dnssec-tools-perlmods, bind
Patch1: dnssec-tools-runtime-perlloading.patch
Patch2: zonefilefast.ssh.patch
Patch3: dnssec-tools-conf-install-dir.patch
Patch4: dnssec-tools-linux-conf-paths.patch
Patch4: dnssec-tools-conf-file-location.patch

%description

The goal of the DNSSEC-Tools project is to create a set of tools,
patches, applications, wrappers, extensions, and plugins that will
help ease the deployment of DNSSEC-related technologies.

%package perlmods
Group: System Environment/Libraries
Summary: Perl modules supporting DNSSEC (needed by the dnssec-tools)
Provides: perl(Net::DNS::SEC::Tools::timetrans), perl(Net::DNS::SEC::Tools::QWPrimitives), perl(Net::DNS::SEC::Tools::conf), perl(Net::DNS::SEC::Tools::keyrec), perl(Net::DNS::SEC::Tools::timetrans), perl(Net::DNS::SEC::Tools::tooloptions), perl(Net::DNS::ZoneFile::Fast)

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

%prep
%setup -q

%patch1 -p0
%patch2 -p0
%patch3 -p0
%patch4 -p0

%configure --with-perl-build-args="PREFIX=$RPM_BUILD_ROOT%{_prefix} INSTALLDIRS=vendor"
make

%install
rm -rf $RPM_BUILD_ROOT
%makeinstall DESTCONFDIR=$RPM_BUILD_ROOT/etc/dnssec

find $RPM_BUILD_ROOT/usr/lib/perl5/ -name .packlist | xargs rm -rf
find $RPM_BUILD_ROOT/usr/lib/perl5/ -name perllocal.pod | xargs rm -f

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%doc README INSTALL COPYING

%config(noreplace) /etc/dnssec/dnssec-tools.conf

   /usr/bin/dnspktflow
   /usr/bin/donuts
   /usr/bin/donutsd
   /usr/bin/drawvalmap
   /usr/bin/expchk
   /usr/bin/genkrf
   /usr/bin/getdnskeys
   /usr/bin/keyrec-check
   /usr/bin/lskrf
   /usr/bin/maketestzone
   /usr/bin/mapper
   /usr/bin/zonesigner
   /usr/share/donuts/rules/*

# newer
   /usr/bin/clean-keyrec
   /usr/bin/dtconfchk
   /usr/bin/dtdefs
   /usr/bin/dtinitconf
   /usr/bin/fixkrf
   /usr/bin/tachk
   /usr/bin/timetrans

# 0.9.1
   /usr/bin/TrustMan
   /usr/bin/lsroll
   /usr/bin/rollchk
   /usr/bin/rollctl
   /usr/bin/rollerd
   /usr/bin/rollinit




   /usr/share/man/man1/dnspktflow.1.gz
   /usr/share/man/man1/donuts.1.gz
   /usr/share/man/man1/donutsd.1.gz
   /usr/share/man/man1/drawvalmap.1.gz
   /usr/share/man/man1/expchk.1.gz
   /usr/share/man/man1/genkrf.1.gz
   /usr/share/man/man1/getdnskeys.1.gz
   /usr/share/man/man1/keyrec-check.1.gz
   /usr/share/man/man1/lskrf.1.gz
   /usr/share/man/man1/maketestzone.1.gz
   /usr/share/man/man1/mapper.1.gz
   /usr/share/man/man1/validate.1.gz
   /usr/share/man/man1/zonesigner.1.gz

# newer
   /usr/share/man/man1/clean-keyrec.1.gz
   /usr/share/man/man1/dtconfchk.1.gz
   /usr/share/man/man1/dtdefs.1.gz
   /usr/share/man/man1/dtinitconf.1.gz
   /usr/share/man/man1/fixkrf.1.gz
   /usr/share/man/man1/tachk.1.gz
   /usr/share/man/man1/timetrans.1.gz

# 0.9.1
   /usr/share/man/man1/TrustMan.1.gz
   /usr/share/man/man1/lsroll.1.gz
   /usr/share/man/man1/rollchk.1.gz
   /usr/share/man/man1/rollctl.1.gz
   /usr/share/man/man1/rollerd.1.gz
   /usr/share/man/man1/rollinit.1.gz

##%{_mandir}/man*/*

%files perlmods
%defattr(-,root,root)

   /usr/lib/perl5/vendor_perl/*/Net/DNS/SEC/Tools/Donuts/Rule.pm
   /usr/lib/perl5/vendor_perl/*/Net/DNS/SEC/Tools/QWPrimitives.pm
   /usr/lib/perl5/vendor_perl/*/Net/DNS/SEC/Tools/BootStrap.pm
   /usr/lib/perl5/vendor_perl/*/Net/DNS/SEC/Tools/conf.pm
   /usr/lib/perl5/vendor_perl/*/Net/DNS/SEC/Tools/keyrec.pm
   /usr/lib/perl5/vendor_perl/*/Net/DNS/SEC/Tools/rollmgr.pm
   /usr/lib/perl5/vendor_perl/*/Net/DNS/SEC/Tools/rollrec.pm
   /usr/lib/perl5/vendor_perl/*/Net/DNS/SEC/Tools/defaults.pm
   /usr/lib/perl5/vendor_perl/*/Net/DNS/SEC/Tools/timetrans.pm
   /usr/lib/perl5/vendor_perl/*/Net/DNS/SEC/Tools/tooloptions.pm
   /usr/lib/perl5/vendor_perl/*/Net/DNS/ZoneFile/Fast.pm

   /usr/share/man/man3/Net::DNS::SEC::Tools::Donuts::Rule.3pm.gz
   /usr/share/man/man3/Net::DNS::SEC::Tools::QWPrimitives.3pm.gz
   /usr/share/man/man3/Net::DNS::SEC::Tools::BootStrap.3pm.gz
   /usr/share/man/man3/Net::DNS::SEC::Tools::conf.3pm.gz
   /usr/share/man/man3/Net::DNS::SEC::Tools::keyrec.3pm.gz
   /usr/share/man/man3/Net::DNS::SEC::Tools::rollmgr.3pm.gz
   /usr/share/man/man3/Net::DNS::SEC::Tools::rollrec.3pm.gz
   /usr/share/man/man3/Net::DNS::SEC::Tools::defaults.3pm.gz
   /usr/share/man/man3/Net::DNS::SEC::Tools::timetrans.3pm.gz
   /usr/share/man/man3/Net::DNS::SEC::Tools::tooloptions.3pm.gz
   /usr/share/man/man3/Net::DNS::ZoneFile::Fast.3pm.gz

%files libs
%defattr(-,root,root)
%{_bindir}/validate
%{_libdir}/*.so*

%files libs-devel
%defattr(-,root,root)
%{_includedir}
%{_libdir}/*.a
%{_libdir}/*.la

   /usr/share/man/man3/libval.3.gz
   /usr/share/man/man3/val_getaddrinfo.3.gz
   /usr/share/man/man3/val_gethostbyname.3.gz
   /usr/share/man/man3/val_query.3.gz
   /usr/share/man/man3/dnsval.conf.3.gz
   /usr/share/man/man3/dnsval_conf_get.3.gz
   /usr/share/man/man3/dnsval_conf_set.3.gz
   /usr/share/man/man3/libsres.3.gz
   /usr/share/man/man3/p_as_error.3.gz
   /usr/share/man/man3/p_val_error.3.gz
   /usr/share/man/man3/resolver_config_get.3.gz
   /usr/share/man/man3/resolver_config_set.3.gz
   /usr/share/man/man3/root_hints_get.3.gz
   /usr/share/man/man3/root_hints_set.3.gz
   /usr/share/man/man3/val_create_context.3.gz
   /usr/share/man/man3/val_free_context.3.gz
   /usr/share/man/man3/val_free_result_chain.3.gz
   /usr/share/man/man3/val_istrusted.3.gz
   /usr/share/man/man3/val_resolve_and_check.3.gz
   /usr/share/man/man3/val_switch_policy_scope.3.gz

%changelog

* Mon Jun 19 2006   <Wes Hardaker <hardaker@users.sourceforge.net>> - 0.9.2-4
- updated to 0.9.2
- modified installation paths as appropriate to 

* Mon Jun 19 2006   <Wes Hardaker <hardaker@users.sourceforge.net>> - 0.9.1-1
- updated to 0.9.1

* Thu Feb  9 2006  <Wes Hardaker <hardaker@users.sourceforge.net> - 0.9.0
- initial rpm
