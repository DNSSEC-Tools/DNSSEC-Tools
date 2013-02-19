%define _prefix /opt/dt-dnsval
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

%define orig_name           dnssec-tools

Summary: C-based libraries for dnssec aware tools
Name: dt-dnsval-libs
Version: 1.13
Release: 1%{?dist}
License: BSD
Group: System Environment/Libraries
URL: http://www.dnssec-tools.org/
Source0: https://www.dnssec-tools.org/downloads/%{orig_name}-%{version}.tar.gz
Source1: dnssec-tools-dnsval.conf
Source2: libval-config
Requires: openssl
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildRequires: openssl-devel gzip

%description
C-based libraries useful for developing dnssec aware tools.

%package devel
Group: Development/Libraries
Summary: C-based development libraries for dnssec aware tools
Requires: dt-dnsval-libs = %{version}-%{release}

%description devel
C-based libraries useful for developing dnssec aware tools.

%prep
%setup -q -n %{orig_name}-%{version}

%build
cd validator
%configure --with-validator-testcases-file=%{_datadir}/dnssec-tools/validator-testcases --with-root-hints=%{_sysconfdir}/dnssec-tools/root.hints --with-resolv-conf=%{_sysconfdir}/dnssec-tools/resolv.conf --disable-static --with-nsec3 --with-ipv6 --with-dlv
sed -i 's|^hardcode_libdir_flag_spec=.*|hardcode_libdir_flag_spec=""|g' libtool
sed -i 's|^runpath_var=LD_RUN_PATH|runpath_var=DIE_RPATH_DIE|g' libtool
make %{?_smp_mflags}

%install
cd validator
rm -rf %{buildroot}
make install DESTCONFDIR=%{buildroot}%{_sysconfdir}/dnssec-tools/ DESTDIR=%{buildroot} QUIET=

%{__install} -m 644 %{SOURCE1} %{buildroot}%{_sysconfdir}/dnssec-tools/dnsval.conf
%{__install} -m 644 etc/root.hints %{buildroot}%{_sysconfdir}/dnssec-tools/root.hints

# remove empty directories
find %{buildroot} -depth -type d -exec rmdir {} 2>/dev/null ';'
chmod -R u+w %{buildroot}/*
rm -f %{buildroot}%{_libdir}/*.la

# Move the architecture dependent config file to its own place
# (this allows multiple architecture rpms to be installed at the same time)
mv %{buildroot}/%{_bindir}/libval-config %{buildroot}/%{_bindir}/libval-config-%{__isa_name}_%{__isa_bits}
# Add a new wrapper script that calls the right file at run time
install -m 755 %SOURCE2 %{buildroot}/%{_bindir}/libval-config

# rpm normally compresses man pages for you, but only if you use
# standard locations..
for f in %{buildroot}%{_mandir}/man?/*.?; do
   gzip -9 -n $f
done

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
%doc README INSTALL COPYING

%{_bindir}/libval_check_conf
%{_bindir}/dt-validate
%{_datadir}/dnssec-tools/validator-testcases
%{_bindir}/dt-getaddr
%{_bindir}/dt-gethost
%{_bindir}/dt-getname
%{_bindir}/dt-getquery
%{_bindir}/dt-getrrset

%{_libdir}/*.so.*
%config(noreplace) %{_sysconfdir}/dnssec-tools/dnsval.conf
%config(noreplace) %{_sysconfdir}/dnssec-tools/root.hints

%{_mandir}/man1/dt-validate.1.gz
%{_mandir}/man1/dt-getaddr.1.gz
%{_mandir}/man1/dt-gethost.1.gz
%{_mandir}/man1/dt-getname.1.gz
%{_mandir}/man1/dt-getquery.1.gz
%{_mandir}/man1/dt-getrrset.1.gz
%{_mandir}/man1/dt-libval_check_conf.1.gz
%{_mandir}/man3/p_ac_status.3.gz
%{_mandir}/man3/p_val_status.3.gz

%files devel
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
%{_mandir}/man3/val_context_setqflags.3.gz
%{_mandir}/man3/val_does_not_exist.3.gz
%{_mandir}/man3/val_free_response.3.gz
%{_mandir}/man3/val_freeaddrinfo.3.gz

%changelog
* Thu Jun 21 2012 Wes Hardaker <wjhns174@hardakers.net> - 1.13-1
- New 1.13 upstream release
