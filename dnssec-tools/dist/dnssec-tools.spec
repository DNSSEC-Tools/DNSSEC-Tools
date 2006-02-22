Summary: A suite of tools for managing dnssec aware DNS usage
Name: dnssec-tools
Version: 0.9
Release: 1
License: BSD
Group: System Environment
URL: http://www.dnssec-tools.org/
Source0: %{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root
Requires: perl
BuildRequires: autoconf213

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

%build
%configure --with-perl-build-args="PREFIX=$RPM_BUILD_ROOT%{_prefix} INSTALLDIRS=vendor"
make

%install
rm -rf $RPM_BUILD_ROOT
%makeinstall

find $RPM_BUILD_ROOT/usr/lib/perl5/ -name .packlist | xargs rm -rf
find $RPM_BUILD_ROOT/usr/lib/perl5/ -name perllocal.pod | xargs rm -f

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%doc README INSTALL COPYING

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

##%{_mandir}/man*/*

%files perlmods
%defattr(-,root,root)

   /usr/lib/perl5/vendor_perl/*/Net/DNS/SEC/Tools/Donuts/Rule.pm
   /usr/lib/perl5/vendor_perl/*/Net/DNS/SEC/Tools/QWPrimitives.pm
   /usr/lib/perl5/vendor_perl/*/Net/DNS/SEC/Tools/conf.pm
   /usr/lib/perl5/vendor_perl/*/Net/DNS/SEC/Tools/keyrec.pm
#   /usr/lib/perl5/vendor_perl/*/Net/DNS/SEC/Tools/rollmgr.pm
#   /usr/lib/perl5/vendor_perl/*/Net/DNS/SEC/Tools/rollrec.pm
   /usr/lib/perl5/vendor_perl/*/Net/DNS/SEC/Tools/timetrans.pm
   /usr/lib/perl5/vendor_perl/*/Net/DNS/SEC/Tools/tooloptions.pm
   /usr/lib/perl5/vendor_perl/*/Net/DNS/ZoneFile/Fast.pm

   /usr/share/man/man3/Net::DNS::SEC::Tools::Donuts::Rule.3pm.gz
   /usr/share/man/man3/Net::DNS::SEC::Tools::QWPrimitives.3pm.gz
   /usr/share/man/man3/Net::DNS::SEC::Tools::conf.3pm.gz
   /usr/share/man/man3/Net::DNS::SEC::Tools::keyrec.3pm.gz
#   /usr/share/man/man3/Net::DNS::SEC::Tools::rollmgr.3pm.gz
#   /usr/share/man/man3/Net::DNS::SEC::Tools::rollrec.3pm.gz
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

%changelog
* Thu Feb  9 2006  <Wes Hardaker <hardaker@users.sourceforge.net>> - tools-1
- Initial build.

