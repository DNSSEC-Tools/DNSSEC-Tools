%bcond_without mysql
%bcond_with pgsql
%bcond_without ldap
%bcond_without pcre
%bcond_without sasl
%bcond_without tls
%bcond_without ipv6
%bcond_without pflogsumm

%global sysv2systemdnvr 2.8.12-2

# hardened build if not overrided
%{!?_hardened_build:%global _hardened_build 1}

# Postfix requires one exlusive uid/gid and a 2nd exclusive gid for its own
# use.  Let me know if the second gid collides with another package.
# Be careful: Redhat's 'mail' user & group isn't unique!
%define postfix_uid	89
%define postfix_user	postfix
%define postfix_gid	89
%define postfix_group	postfix
%define maildrop_group	postdrop
%define maildrop_gid	90

%define postfix_config_dir	%{_sysconfdir}/postfix
%define postfix_daemon_dir	%{_libexecdir}/postfix
%define postfix_command_dir	%{_sbindir}
%define postfix_queue_dir	%{_var}/spool/postfix
%define postfix_data_dir	%{_var}/lib/postfix
%define postfix_doc_dir		%{_docdir}/%{name}-%{version}
%define postfix_sample_dir	%{postfix_doc_dir}/samples
%define postfix_readme_dir	%{postfix_doc_dir}/README_FILES

%if %{?_hardened_build:%{_hardened_build}}%{!?_hardened_build:0}
%global harden -pie -Wl,-z,relro,-z,now
%endif

Name: postfix
Summary: Postfix Mail Transport Agent
Version: 2.9.4
Release: 2%{?dist}
Epoch: 2
Group: System Environment/Daemons
URL: http://www.postfix.org
License: IBM
Requires(post): systemd-units systemd-sysv 
Requires(post): %{_sbindir}/alternatives
Requires(pre): %{_sbindir}/groupadd
Requires(pre): %{_sbindir}/useradd
Requires(preun): %{_sbindir}/alternatives
Requires(preun): systemd-units
Requires(postun): systemd-units
Provides: MTA smtpd smtpdaemon server(smtp)

Source0: ftp://ftp.porcupine.org/mirrors/postfix-release/official/%{name}-%{version}.tar.gz
Source1: postfix-etc-init.d-postfix
Source2: postfix.service
Source3: README-Postfix-SASL-RedHat.txt
Source4: postfix.aliasesdb

# Sources 50-99 are upstream [patch] contributions

%define pflogsumm_ver 1.1.3

%if %{with pflogsumm}
# Postfix Log Entry Summarizer: http://jimsun.linxnet.com/postfix_contrib.html
Source53: http://jimsun.linxnet.com/downloads/pflogsumm-%{pflogsumm_ver}.tar.gz
%endif

# Sources >= 100 are config files

Source100: postfix-sasl.conf
Source101: postfix-pam.conf

# Patches

Patch1: postfix-2.7.0-config.patch
Patch2: postfix-2.6.1-files.patch
Patch3: postfix-alternatives.patch
Patch8: postfix-large-fs.patch
Patch9: pflogsumm-1.1.3-datecalc.patch

# Optional patches - set the appropriate environment variables to include
#		     them when building the package/spec file

BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

# Determine the different packages required for building postfix
BuildRequires: libdb-devel, pkgconfig, zlib-devel
BuildRequires: systemd-units

%{?with_ldap:BuildRequires: openldap-devel}
%{?with_sasl:BuildRequires: cyrus-sasl-devel}
%{?with_pcre:BuildRequires: pcre-devel}
%{?with_mysql:BuildRequires: mysql-devel}
%{?with_pgsql:BuildRequires: postgresql-devel}
%{?with_tls:BuildRequires: openssl-devel}

%description
Postfix is a Mail Transport Agent (MTA), supporting LDAP, SMTP AUTH (SASL),
TLS

%package sysvinit
Summary: SysV initscript for postfix
Group: System Environment/Daemons
BuildArch: noarch
Requires: %{name} = %{epoch}:%{version}-%{release}
Requires(preun): chkconfig
Requires(post): chkconfig

%description sysvinit
This package contains the SysV initscript.

%package perl-scripts
Summary: Postfix utilities written in perl
Group: Applications/System
Requires: %{name} = %{epoch}:%{version}-%{release}
# perl-scripts introduced in 2:2.5.5-2
Obsoletes: postfix < 2:2.5.5-2
%if %{with pflogsumm}
Provides: postfix-pflogsumm = %{epoch}:%{version}-%{release}
Obsoletes: postfix-pflogsumm < 2:2.5.5-2
%endif
%description perl-scripts
This package contains perl scripts pflogsumm and qshape.

Pflogsumm is a log analyzer/summarizer for the Postfix MTA. It is
designed to provide an over-view of Postfix activity. Pflogsumm
generates summaries and, in some cases, detailed reports of mail
server traffic volumes, rejected and bounced email, and server
warnings, errors and panics.

qshape prints Postfix queue domain and age distribution.

%prep
%setup -q
# Apply obligatory patches
%patch1 -p1 -b .config
%patch2 -p1 -b .files
%patch3 -p1 -b .alternatives
%patch8 -p1 -b .large-fs

%if %{with pflogsumm}
gzip -dc %{SOURCE53} | tar xf -
pushd pflogsumm-%{pflogsumm_ver}
%patch9 -p1 -b .datecalc
popd
%endif

for f in README_FILES/TLS_{LEGACY_,}README TLS_ACKNOWLEDGEMENTS; do
	iconv -f iso8859-1 -t utf8 -o ${f}{_,} &&
		touch -r ${f}{,_} && mv -f ${f}{_,}
done

%build
CCARGS=-fPIC
AUXLIBS=

%ifarch s390 s390x ppc
CCARGS="${CCARGS} -fsigned-char"
%endif

%if %{with ldap}
  CCARGS="${CCARGS} -DHAS_LDAP -DLDAP_DEPRECATED=1"
  AUXLIBS="${AUXLIBS} -lldap -llber"
%endif
%if %{with pcre}
  # -I option required for pcre 3.4 (and later?)
  CCARGS="${CCARGS} -DHAS_PCRE -I%{_includedir}/pcre"
  AUXLIBS="${AUXLIBS} -lpcre"
%endif
%if %{with mysql}
  CCARGS="${CCARGS} -DHAS_MYSQL -I%{_includedir}/mysql"
  AUXLIBS="${AUXLIBS} -L%{_libdir}/mysql -lmysqlclient -lm"
%endif
%if %{with pgsql}
  CCARGS="${CCARGS} -DHAS_PGSQL -I%{_includedir}/pgsql"
  AUXLIBS="${AUXLIBS} -lpq"
%endif
%if %{with sasl}
  CCARGS="${CCARGS} -DUSE_SASL_AUTH -DUSE_CYRUS_SASL -I%{_includedir}/sasl"
  AUXLIBS="${AUXLIBS} -L%{_libdir}/sasl2 -lsasl2"
  %global sasl_config_dir %{_sysconfdir}/sasl2
%endif
%if %{with tls}
  if pkg-config openssl ; then
    CCARGS="${CCARGS} -DUSE_TLS `pkg-config --cflags openssl`"
    AUXLIBS="${AUXLIBS} `pkg-config --libs openssl`"
  else
    CCARGS="${CCARGS} -DUSE_TLS -I/usr/include/openssl"
    AUXLIBS="${AUXLIBS} -lssl -lcrypto"
  fi
%endif
%if ! %{with ipv6}
  CCARGS="${CCARGS} -DNO_IPV6"
%endif

CCARGS="${CCARGS} -DDEF_CONFIG_DIR=\\\"%{postfix_config_dir}\\\""
CCARGS="${CCARGS} $(getconf LFS_CFLAGS)"

AUXLIBS="${AUXLIBS} %{?harden:%{harden}}"

make -f Makefile.init makefiles CCARGS="${CCARGS}" AUXLIBS="${AUXLIBS}" \
  DEBUG="" OPT="$RPM_OPT_FLAGS -Wno-comment"

make %{?_smp_mflags} 

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT

# install postfix into $RPM_BUILD_ROOT

# Move stuff around so we don't conflict with sendmail
for i in man1/mailq.1 man1/newaliases.1 man1/sendmail.1 man5/aliases.5; do
  dest=$(echo $i | sed 's|\.[1-9]$|.postfix\0|')
  mv man/$i man/$dest
  sed -i "s|^\.so $i|\.so $dest|" man/man?/*.[1-9]
done

sh postfix-install -non-interactive \
       install_root=$RPM_BUILD_ROOT \
       config_directory=%{postfix_config_dir} \
       daemon_directory=%{postfix_daemon_dir} \
       command_directory=%{postfix_command_dir} \
       queue_directory=%{postfix_queue_dir} \
       data_directory=%{postfix_data_dir} \
       sendmail_path=%{postfix_command_dir}/sendmail.postfix \
       newaliases_path=%{_bindir}/newaliases.postfix \
       mailq_path=%{_bindir}/mailq.postfix \
       mail_owner=%{postfix_user} \
       setgid_group=%{maildrop_group} \
       manpage_directory=%{_mandir} \
       sample_directory=%{postfix_sample_dir} \
       readme_directory=%{postfix_readme_dir} || exit 1

# This installs into the /etc/rc.d/init.d directory
mkdir -p $RPM_BUILD_ROOT%{_initrddir}
install -c %{SOURCE1} $RPM_BUILD_ROOT%{_initrddir}/postfix

# Systemd
mkdir -p %{buildroot}%{_unitdir}
install -m 644 %{SOURCE2} %{buildroot}%{_unitdir}
install -m 755 %{SOURCE4} %{buildroot}%{postfix_daemon_dir}/aliasesdb

install -c auxiliary/rmail/rmail $RPM_BUILD_ROOT%{_bindir}/rmail.postfix

for i in active bounce corrupt defer deferred flush incoming private saved maildrop public pid saved trace; do
    mkdir -p $RPM_BUILD_ROOT%{postfix_queue_dir}/$i
done

# install performance benchmark tools by hand
for i in smtp-sink smtp-source ; do
  install -c -m 755 bin/$i $RPM_BUILD_ROOT%{postfix_command_dir}/
  install -c -m 755 man/man1/$i.1 $RPM_BUILD_ROOT%{_mandir}/man1/
done

## RPM compresses man pages automatically.
## - Edit postfix-files to reflect this, so post-install won't get confused
##   when called during package installation.
sed -i -r "s#(/man[158]/.*.[158]):f#\1.gz:f#" $RPM_BUILD_ROOT%{postfix_daemon_dir}/postfix-files

cat $RPM_BUILD_ROOT%{postfix_daemon_dir}/postfix-files
%if %{with sasl}
# Install the smtpd.conf file for SASL support.
mkdir -p $RPM_BUILD_ROOT%{sasl_config_dir}
install -m 644 %{SOURCE100} $RPM_BUILD_ROOT%{sasl_config_dir}/smtpd.conf
%endif

mkdir -p $RPM_BUILD_ROOT%{_sysconfdir}/pam.d
install -m 644 %{SOURCE101} $RPM_BUILD_ROOT%{_sysconfdir}/pam.d/smtp.postfix

# prepare documentation
mkdir -p $RPM_BUILD_ROOT%{postfix_doc_dir}
cp -p %{SOURCE3} COMPATIBILITY LICENSE TLS_ACKNOWLEDGEMENTS TLS_LICENSE $RPM_BUILD_ROOT%{postfix_doc_dir}

mkdir -p $RPM_BUILD_ROOT%{postfix_doc_dir}/examples{,/chroot-setup}
cp -pr examples/{qmail-local,smtpd-policy} $RPM_BUILD_ROOT%{postfix_doc_dir}/examples
cp -p examples/chroot-setup/LINUX2 $RPM_BUILD_ROOT%{postfix_doc_dir}/examples/chroot-setup

cp conf/{main,bounce}.cf.default $RPM_BUILD_ROOT%{postfix_doc_dir}
sed -i 's#%{postfix_config_dir}\(/bounce\.cf\.default\)#%{postfix_doc_dir}\1#' $RPM_BUILD_ROOT%{_mandir}/man5/bounce.5
rm -f $RPM_BUILD_ROOT%{postfix_config_dir}/{TLS_,}LICENSE

find $RPM_BUILD_ROOT%{postfix_doc_dir} -type f | xargs chmod 644
find $RPM_BUILD_ROOT%{postfix_doc_dir} -type d | xargs chmod 755

%if %{with pflogsumm}
install -c -m 644 pflogsumm-%{pflogsumm_ver}/pflogsumm-faq.txt $RPM_BUILD_ROOT%{postfix_doc_dir}/pflogsumm-faq.txt
install -c -m 644 pflogsumm-%{pflogsumm_ver}/pflogsumm.1 $RPM_BUILD_ROOT%{_mandir}/man1/pflogsumm.1
install -c pflogsumm-%{pflogsumm_ver}/pflogsumm.pl $RPM_BUILD_ROOT%{postfix_command_dir}/pflogsumm
%endif

# install qshape
mantools/srctoman - auxiliary/qshape/qshape.pl > qshape.1
install -c qshape.1 $RPM_BUILD_ROOT%{_mandir}/man1/qshape.1
install -c auxiliary/qshape/qshape.pl $RPM_BUILD_ROOT%{postfix_command_dir}/qshape

# remove alias file
rm -f $RPM_BUILD_ROOT%{postfix_config_dir}/aliases

# create /usr/lib/sendmail
mkdir -p $RPM_BUILD_ROOT/usr/lib
pushd $RPM_BUILD_ROOT/usr/lib
ln -sf ../sbin/sendmail.postfix .
popd

mkdir -p $RPM_BUILD_ROOT%{_var}/lib/misc
touch $RPM_BUILD_ROOT%{_var}/lib/misc/postfix.aliasesdb-stamp

# prepare alternatives ghosts 
for i in %{postfix_command_dir}/sendmail %{_bindir}/{mailq,newaliases,rmail} \
	%{_sysconfdir}/pam.d/smtp /usr/lib/sendmail \
	%{_mandir}/{man1/{mailq.1,newaliases.1},man5/aliases.5,man8/sendmail.8}
do
	touch $RPM_BUILD_ROOT$i
done

%post
[ $1 -eq 1 ] && bin/systemctl daemon-reload >/dev/null 2>&1 || :

# upgrade configuration files if necessary
%{_sbindir}/postfix set-permissions upgrade-configuration \
	daemon_directory=%{postfix_daemon_dir} \
	command_directory=%{postfix_command_dir} \
	mail_owner=%{postfix_user} \
	setgid_group=%{maildrop_group} \
	manpage_directory=%{_mandir} \
	sample_directory=%{postfix_sample_dir} \
	readme_directory=%{postfix_readme_dir} &> /dev/null

%{_sbindir}/alternatives --install %{postfix_command_dir}/sendmail mta %{postfix_command_dir}/sendmail.postfix 30 \
	--slave %{_bindir}/mailq mta-mailq %{_bindir}/mailq.postfix \
	--slave %{_bindir}/newaliases mta-newaliases %{_bindir}/newaliases.postfix \
	--slave %{_sysconfdir}/pam.d/smtp mta-pam %{_sysconfdir}/pam.d/smtp.postfix \
	--slave %{_bindir}/rmail mta-rmail %{_bindir}/rmail.postfix \
	--slave /usr/lib/sendmail mta-sendmail /usr/lib/sendmail.postfix \
	--slave %{_mandir}/man1/mailq.1.gz mta-mailqman %{_mandir}/man1/mailq.postfix.1.gz \
	--slave %{_mandir}/man1/newaliases.1.gz mta-newaliasesman %{_mandir}/man1/newaliases.postfix.1.gz \
	--slave %{_mandir}/man8/sendmail.8.gz mta-sendmailman %{_mandir}/man1/sendmail.postfix.1.gz \
	--slave %{_mandir}/man5/aliases.5.gz mta-aliasesman %{_mandir}/man5/aliases.postfix.5.gz \
	--initscript postfix

%if %{with sasl}
# Move sasl config to new location
if [ -f %{_libdir}/sasl2/smtpd.conf ]; then
	mv -f %{_libdir}/sasl2/smtpd.conf %{sasl_config_dir}/smtpd.conf
	/sbin/restorecon %{sasl_config_dir}/smtpd.conf 2> /dev/null
fi
%endif

exit 0

%pre
# Add user and groups if necessary
%{_sbindir}/groupadd -g %{maildrop_gid} -r %{maildrop_group} 2>/dev/null
%{_sbindir}/groupadd -g %{postfix_gid} -r %{postfix_group} 2>/dev/null
%{_sbindir}/groupadd -g 12 -r mail 2>/dev/null
%{_sbindir}/useradd -d %{postfix_queue_dir} -s /sbin/nologin -g %{postfix_group} -G mail -M -r -u %{postfix_uid} %{postfix_user} 2>/dev/null
exit 0

%preun
if [ "$1" = 0 ]; then
    /bin/systemctl --no-reload disable postfix.service > /dev/null 2>&1 || :
    /bin/systemctl stop postfix.service > /dev/null 2>&1 || :
    %{_sbindir}/alternatives --remove mta %{postfix_command_dir}/sendmail.postfix
fi
exit 0

%postun
/bin/systemctl daemon-reload >/dev/null 2>&1 || :
if [ "$1" -ge 1 ]; then
    /bin/systemctl try-restart postfix.service >/dev/null 2>&1 || :
fi

%post sysvinit
/sbin/chkconfig --add postfix >/dev/null 2>&1 ||:

%preun sysvinit
if [ "$1" = 0 ]; then
    %{_initrddir}/postfix stop >/dev/null 2>&1 ||:
    /sbin/chkconfig --del postfix >/dev/null 2>&1 ||:
fi

%postun sysvinit
[ "$1" -ge 1 ] && %{_initrddir}/postfix condrestart >/dev/null 2>&1 ||:

%triggerun -- postfix < %{sysv2systemdnvr}
%{_bindir}/systemd-sysv-convert --save postfix >/dev/null 2>&1 ||:
%{_bindir}/systemd-sysv-convert --apply postfix >/dev/null 2>&1 ||:
/sbin/chkconfig --del postfix >/dev/null 2>&1 || :
/bin/systemctl try-restart postfix.service >/dev/null 2>&1 || :

%triggerpostun -n postfix-sysvinit -- postfix < %{sysv2systemdnvr}
/sbin/chkconfig --add postfix >/dev/null 2>&1 || :


%clean
rm -rf $RPM_BUILD_ROOT


%files

# For correct directory permissions check postfix-install script.
# It reads the file postfix-files which defines the ownership
# and permissions for all files postfix installs.

%defattr(-, root, root, -)

# Config files not part of upstream

%if %{with sasl}
%config(noreplace) %{sasl_config_dir}/smtpd.conf
%endif
%config(noreplace) %{_sysconfdir}/pam.d/smtp.postfix
%{_unitdir}/postfix.service

# Documentation

%{postfix_doc_dir}
%if %{with pflogsumm}
%exclude %{postfix_doc_dir}/pflogsumm-faq.txt
%endif

# Misc files

%dir %attr(0755, root, root) %{postfix_config_dir}
%dir %attr(0755, root, root) %{postfix_daemon_dir}
%dir %attr(0755, root, root) %{postfix_queue_dir}
%dir %attr(0700, %{postfix_user}, root) %{postfix_queue_dir}/active
%dir %attr(0700, %{postfix_user}, root) %{postfix_queue_dir}/bounce
%dir %attr(0700, %{postfix_user}, root) %{postfix_queue_dir}/corrupt
%dir %attr(0700, %{postfix_user}, root) %{postfix_queue_dir}/defer
%dir %attr(0700, %{postfix_user}, root) %{postfix_queue_dir}/deferred
%dir %attr(0700, %{postfix_user}, root) %{postfix_queue_dir}/flush
%dir %attr(0700, %{postfix_user}, root) %{postfix_queue_dir}/hold
%dir %attr(0700, %{postfix_user}, root) %{postfix_queue_dir}/incoming
%dir %attr(0700, %{postfix_user}, root) %{postfix_queue_dir}/saved
%dir %attr(0700, %{postfix_user}, root) %{postfix_queue_dir}/trace
%dir %attr(0730, %{postfix_user}, %{maildrop_group}) %{postfix_queue_dir}/maildrop
%dir %attr(0755, root, root) %{postfix_queue_dir}/pid
%dir %attr(0700, %{postfix_user}, root) %{postfix_queue_dir}/private
%dir %attr(0710, %{postfix_user}, %{maildrop_group}) %{postfix_queue_dir}/public
%dir %attr(0700, %{postfix_user}, root) %{postfix_data_dir}

%attr(0644, root, root) %{_mandir}/man1/post*.1*
%attr(0644, root, root) %{_mandir}/man1/smtp*.1*
%attr(0644, root, root) %{_mandir}/man1/*.postfix.1*
%attr(0644, root, root) %{_mandir}/man5/access.5*
%attr(0644, root, root) %{_mandir}/man5/[b-v]*.5*
%attr(0644, root, root) %{_mandir}/man5/*.postfix.5*
%attr(0644, root, root) %{_mandir}/man8/[a-qt-v]*.8*
%attr(0644, root, root) %{_mandir}/man8/s[ch-p]*.8*

%attr(0755, root, root) %{postfix_command_dir}/smtp-sink
%attr(0755, root, root) %{postfix_command_dir}/smtp-source

%attr(0755, root, root) %{postfix_command_dir}/postalias
%attr(0755, root, root) %{postfix_command_dir}/postcat
%attr(0755, root, root) %{postfix_command_dir}/postconf
%attr(2755, root, %{maildrop_group}) %{postfix_command_dir}/postdrop
%attr(0755, root, root) %{postfix_command_dir}/postfix
%attr(0755, root, root) %{postfix_command_dir}/postkick
%attr(0755, root, root) %{postfix_command_dir}/postlock
%attr(0755, root, root) %{postfix_command_dir}/postlog
%attr(0755, root, root) %{postfix_command_dir}/postmap
%attr(0755, root, root) %{postfix_command_dir}/postmulti
%attr(2755, root, %{maildrop_group}) %{postfix_command_dir}/postqueue
%attr(0755, root, root) %{postfix_command_dir}/postsuper
%attr(0644, root, root) %config(noreplace) %{postfix_config_dir}/access
%attr(0644, root, root) %config(noreplace) %{postfix_config_dir}/canonical
%attr(0644, root, root) %config(noreplace) %{postfix_config_dir}/generic
%attr(0644, root, root) %config(noreplace) %{postfix_config_dir}/header_checks
%attr(0644, root, root) %config(noreplace) %{postfix_config_dir}/main.cf
%attr(0644, root, root) %config(noreplace) %{postfix_config_dir}/master.cf
%attr(0644, root, root) %config(noreplace) %{postfix_config_dir}/relocated
%attr(0644, root, root) %config(noreplace) %{postfix_config_dir}/transport
%attr(0644, root, root) %config(noreplace) %{postfix_config_dir}/virtual
%attr(0755, root, root) %{postfix_daemon_dir}/[^mp]*
%attr(0644, root, root) %{postfix_daemon_dir}/main.cf
%attr(0644, root, root) %{postfix_daemon_dir}/master.cf
%attr(0755, root, root) %{postfix_daemon_dir}/master
%attr(0755, root, root) %{postfix_daemon_dir}/pickup
%attr(0755, root, root) %{postfix_daemon_dir}/pipe
%attr(0755, root, root) %{postfix_daemon_dir}/post-install
%attr(0644, root, root) %{postfix_daemon_dir}/postfix-files
%attr(0755, root, root) %{postfix_daemon_dir}/postfix-script
%attr(0755, root, root) %{postfix_daemon_dir}/postfix-wrapper
%attr(0755, root, root) %{postfix_daemon_dir}/postmulti-script
%attr(0755, root, root) %{postfix_daemon_dir}/postscreen
%attr(0755, root, root) %{postfix_daemon_dir}/proxymap
%attr(0755, root, root) %{_bindir}/mailq.postfix
%attr(0755, root, root) %{_bindir}/newaliases.postfix
%attr(0755, root, root) %{_bindir}/rmail.postfix
%attr(0755, root, root) %{_sbindir}/sendmail.postfix
%attr(0755, root, root) /usr/lib/sendmail.postfix

%ghost %{_sysconfdir}/pam.d/smtp

%ghost %{_mandir}/man1/mailq.1.gz
%ghost %{_mandir}/man1/newaliases.1.gz
%ghost %{_mandir}/man5/aliases.5.gz
%ghost %{_mandir}/man8/sendmail.8.gz

%ghost %attr(0755, root, root) %{_bindir}/mailq
%ghost %attr(0755, root, root) %{_bindir}/newaliases
%ghost %attr(0755, root, root) %{_bindir}/rmail
%ghost %attr(0755, root, root) %{_sbindir}/sendmail
%ghost %attr(0755, root, root) /usr/lib/sendmail

%ghost %attr(0644, root, root) %{_var}/lib/misc/postfix.aliasesdb-stamp

%files sysvinit
%defattr(-, root, root, -)
%{_initrddir}/postfix

%files perl-scripts
%defattr(-, root, root, -)
%attr(0755, root, root) %{postfix_command_dir}/qshape
%attr(0644, root, root) %{_mandir}/man1/qshape*
%if %{with pflogsumm}
%doc %{postfix_doc_dir}/pflogsumm-faq.txt
%attr(0644, root, root) %{_mandir}/man1/pflogsumm.1.gz
%attr(0755, root, root) %{postfix_command_dir}/pflogsumm
%endif

%changelog
* Fri Aug  3 2012 Jaroslav Škarvada <jskarvad@redhat.com> - 2:2.9.4-2
- Fixed sysv2systemd upgrade from f16

* Thu Aug  2 2012 Jaroslav Škarvada <jskarvad@redhat.com> - 2:2.9.4-1
- New version
  Resolves: rhbz#845298
- Dropped biff-cloexec patch (upstreamed)

* Sat Jul 21 2012 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 2:2.9.3-3
- Rebuilt for https://fedoraproject.org/wiki/Fedora_18_Mass_Rebuild

* Tue Jul 03 2012 Jaroslav Škarvada <jskarvad@redhat.com> - 2:2.9.3-2
- Fixed FD leak in biff

* Tue Jun  5 2012 Jaroslav Škarvada <jskarvad@redhat.com> - 2:2.9.3-1
- New version
  Resolves: rhbz#828242
  Fixed sysv2systemd upgrade from f16

* Wed Apr 25 2012 Jaroslav Škarvada <jskarvad@redhat.com> - 2:2.9.2-2
- Fixed sysv2systemd upgrade from f15 / f16

* Wed Apr 25 2012 Jaroslav Škarvada <jskarvad@redhat.com> - 2:2.9.2-1
- New version
  Resolves: rhbz#816139

* Fri Apr  6 2012 Jaroslav Škarvada <jskarvad@redhat.com> - 2:2.9.1-2
- Rebuilt with libdb-5.2

* Mon Feb 20 2012 Jaroslav Škarvada <jskarvad@redhat.com> - 2:2.9.1-1
- New version
  Resolves: rhbz#794976

* Fri Feb 10 2012 Petr Pisar <ppisar@redhat.com> - 2:2.9.0-2
- Rebuild against PCRE 8.30

* Fri Feb  3 2012 Jaroslav Škarvada <jskarvad@redhat.com> - 2:2.9.0-1
- New version
  Resolves: rhbz#786792

* Sat Jan 14 2012 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 2:2.8.7-5
- Rebuilt for https://fedoraproject.org/wiki/Fedora_17_Mass_Rebuild

* Thu Nov 10 2011 Jaroslav Škarvada <jskarvad@redhat.com> - 2:2.8.7-4
- Added epoch to sysvinit subpackage requires

* Tue Nov  8 2011 Jaroslav Škarvada <jskarvad@redhat.com> - 2:2.8.7-3
- Fixed sysvinit preun scriptlet

* Tue Nov  8 2011 Jaroslav Škarvada <jskarvad@redhat.com> - 2:2.8.7-2
- Introduce systemd unit file, thanks to Jóhann B. Guðmundsson <johannbg@hi.is>
  Resolves: rhbz#718793

* Mon Nov  7 2011 Jaroslav Škarvada <jskarvad@redhat.com> - 2:2.8.7-1
- Update to 2.8.7
  Resolves: rhbz#751622

* Mon Oct 24 2011 Jaroslav Škarvada <jskarvad@redhat.com> - 2:2.8.6-1
- Update to 2.8.6
  Resolves: rhbz#748389

* Mon Sep 12 2011 Jaroslav Škarvada <jskarvad@redhat.com> - 2:2.8.5-1
- Update to 2.8.5
  Resolves: rhbz#735543

* Tue Aug 30 2011 Jaroslav Škarvada <jskarvad@redhat.com> - 2:2.8.4-4
- Enable override of hardened build settings

* Tue Aug 30 2011 Jaroslav Škarvada <jskarvad@redhat.com> - 2:2.8.4-3
- Hardened build, rebuilt with full relro

* Tue Aug 30 2011 Jaroslav Škarvada <jskarvad@redhat.com> - 2:2.8.4-2
- Rebuilt with libdb-5.1
  Resolves: rhbz#734084

* Thu Jul 07 2011 Jaroslav Škarvada <jskarvad@redhat.com> - 2:2.8.4-1
- update to 2.8.4

* Mon May 09 2011 Jaroslav Škarvada <jskarvad@redhat.com> - 2:2.8.3-1
- update to 2.8.3
- fix CVE-2011-1720

* Wed Mar 23 2011 Dan Horák <dan@danny.cz> - 2:2.8.2-2
- rebuilt for mysql 5.5.10 (soname bump in libmysqlclient)

* Tue Mar 22 2011 Jaroslav Škarvada <jskarvad@redhat.com> - 2:2.8.2-1
- update to 2.8.2

* Wed Feb 23 2011 Miroslav Lichvar <mlichvar@redhat.com> 2:2.8.1-1
- update to 2.8.1

* Wed Feb 09 2011 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 2:2.8.0-3
- Rebuilt for https://fedoraproject.org/wiki/Fedora_15_Mass_Rebuild

* Mon Feb 07 2011 Miroslav Lichvar <mlichvar@redhat.com> 2:2.8.0-2
- don't set config_directory when upgrading configuration (#675654)

* Wed Jan 26 2011 Miroslav Lichvar <mlichvar@redhat.com> 2:2.8.0-1
- update to 2.8.0

* Fri Nov 26 2010 Miroslav Lichvar <mlichvar@redhat.com> 2:2.7.2-1
- update to 2.7.2
- change LSB init header to provide $mail-transport-agent (#627411)

* Thu Jun 10 2010 Miroslav Lichvar <mlichvar@redhat.com> 2:2.7.1-1
- update to 2.7.1
- update pflogsumm to 1.1.3

* Wed Mar 17 2010 Miroslav Lichvar <mlichvar@redhat.com> 2:2.7.0-2
- follow guidelines for alternatives (#570801)
- move sasl config to /etc/sasl2 (#574434)
- drop sasl v1 support
- remove unnecessary requirements
- use bcond macros

* Fri Feb 26 2010 Miroslav Lichvar <mlichvar@redhat.com> 2:2.7.0-1
- update to 2.7.0

* Fri Jan 29 2010 Miroslav Lichvar <mlichvar@redhat.com> 2:2.6.5-3
- fix init script LSB compliance (#528151)
- update pflogsumm to 1.1.2
- require Date::Calc for pflogsumm (#536678)
- fix some rpmlint warnings

* Wed Sep 16 2009 Tomas Mraz <tmraz@redhat.com> - 2:2.6.5-2
- use password-auth common PAM configuration instead of system-auth

* Tue Sep 01 2009 Miroslav Lichvar <mlichvar@redhat.com> 2:2.6.5-1
- update to 2.6.5

* Fri Aug 21 2009 Tomas Mraz <tmraz@redhat.com> - 2:2.6.2-3
- rebuilt with new openssl

* Sun Jul 26 2009 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 2:2.6.2-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_12_Mass_Rebuild

* Thu Jun 18 2009 Miroslav Lichvar <mlichvar@redhat.com> 2:2.6.2-1
- update to 2.6.2

* Tue May 26 2009 Miroslav Lichvar <mlichvar@redhat.com> 2:2.6.1-1
- update to 2.6.1
- move non-config files out of /etc/postfix (#490983)
- fix multilib conflict in postfix-files (#502211)
- run chroot-update script in init script (#483186)
- package examples (#251677)
- provide all alternatives files
- suppress postfix output in post script

* Thu Feb 26 2009 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 2:2.5.6-3
- Rebuilt for https://fedoraproject.org/wiki/Fedora_11_Mass_Rebuild

* Fri Jan 23 2009 Miroslav Lichvar <mlichvar@redhat.com> 2:2.5.6-2
- rebuild for new mysql

* Thu Jan 22 2009 Miroslav Lichvar <mlichvar@redhat.com> 2:2.5.6-1
- update to 2.5.6 (#479108)
- rebuild /etc/aliases.db only when necessary (#327651)
- convert doc files to UTF-8

* Thu Nov 20 2008 Miroslav Lichvar <mlichvar@redhat.com> 2:2.5.5-2
- enable Large file support on 32-bit archs (#428996)
- fix mailq(1) and newaliases(1) man pages (#429501)
- move pflogsumm and qshape to -perl-scripts subpackage (#467529)
- update pflogsumm to 1.1.1
- fix large-fs patch
- drop open_define patch
- add -Wno-comment to CFLAGS

* Wed Sep 17 2008 Thomas Woerner <twoerner@redhat.com> 2:2.5.5-1
- new version 2.5.5
  fixes CVE-2008-2936, CVE-2008-2937 and CVE-2008-3889 (rhbz#459101)

* Thu Aug 28 2008 Tom "spot" Callaway <tcallawa@redhat.com> 2:2.5.1-4
- fix license tag

* Thu Aug 14 2008 Thomas Woerner <twoerner@redhat.com> 2:2.5.1-3
- fixed postfix privilege problem with symlinks in the mail spool directory
  (CVE-2008-2936) (rhbz#459101)

* Wed Mar 12 2008 Thomas Woerner <twoerner@redhat.com> 2:2.5.1-2
- fixed fix for enabling IPv6 support (rhbz#437024)
- added new postfix data directory (rhbz#437042)

* Thu Feb 21 2008 Thomas Woerner <twoerner@redhat.com> 2:2.5.1-1
- new verison 2.5.1

* Wed Feb 20 2008 Fedora Release Engineering <rel-eng@fedoraproject.org> - 2:2.4.6-3
- Autorebuild for GCC 4.3

* Thu Dec 06 2007 Release Engineering <rel-eng at fedoraproject dot org> - 2.4.6-2
- Rebuild for deps

* Wed Nov 28 2007 Thomas Woerner <twoerner@redhat.com> 2:2.4.6-1
- new verison 2.4.6
- added virtual server(smtp) provide (rhbz#380631)
- enabling IPv6 support (rhbz#197105)
- made the MYSQL and PGSQL defines overloadable as build argument

* Wed Nov  7 2007 Thomas Woerner <twoerner@redhat.com> 2:2.4.5-3
- fixed multilib conflict for makedefs.out: rename to makedefs.out-%%{_arch}
  (rhbz#342941)
- enabled mysql support

* Thu Oct  4 2007 Thomas Woerner <twoerner@redhat.com> 2:2.4.5-2
- made init script lsb conform (#243286, rhbz#247025)
- added link to postfix sasl readme into Postfix-SASL-RedHat readme

* Mon Aug 13 2007 Thomas Woerner <twoerner@redhat.com> 2:2.4.5-1
- new version 2.4.5
- fixed compile proplem with glibc-2.6.90+

* Fri Jun 15 2007 Thomas Woerner <twoerner@redhat.com> 2:2.4.3-3
- added missing epoch in requirement of pflogsumm sub package

* Thu Jun 14 2007 Thomas Woerner <twoerner@redhat.com> 2:2.4.3-2
- diabled mysql support again (rhbz#185515)
- added support flag for PostgreSQL build (rhbz#180579)
  Ben: Thanks for the patch
- Fixed remaining rewiew problems (rhbz#226307)

* Tue Jun  5 2007 Thomas Woerner <twoerner@redhat.com> 2:2.4.3-1
- allow to build without LDAP but SASL2 support (rhbz#216792)

* Tue Jun  5 2007 Thomas Woerner <twoerner@redhat.com> 2:2.4.3-1
- new stable version 2.4.3
- enabled mysql support (rhbz#185515)
- dropped build requirements for gawk, ed and sed

* Tue Jan 23 2007 Thomas Woerner <twoerner@redhat.com> 2:2.3.6-1
- new version 2.3.6
- limiting SASL mechanisms to plain login for sasl with saslauthd (#175259)
- dropped usage of ed in the install stage

* Tue Nov  7 2006 Thomas Woerner <twoerner@redhat.com> 2:2.3.4-1
- new version 2.3.4

* Fri Sep  1 2006 Thomas Woerner <twoerner@redhat.com> 2:2.3.3-2
- fixed upgrade procedure (#202357)

* Fri Sep  1 2006 Thomas Woerner <twoerner@redhat.com> 2:2.3.3-1
- new version 2.3.3
- fixed permissions of TLS_LICENSE file

* Fri Aug 18 2006 Jesse Keating <jkeating@redhat.com> - 2:2.3.2-2
- rebuilt with latest binutils to pick up 64K -z commonpagesize on ppc*
  (#203001)

* Mon Jul 31 2006 Thomas Woerner <twoerner@redhat.com> 2:2.3.2-1
- new version 2.3.2 with major upstream fixes:
  - corrupted queue file after a request to modify a short message header
  - panic after spurious Milter request when a client was rejected
  - maked the Milter more tolerant for redundant "data cleanup" requests
- applying pflogsumm-conn-delays-dsn-patch from postfix tree to pflogsumm

* Fri Jul 28 2006 Thomas Woerner <twoerner@redhat.com> 2:2.3.1-1
- new version 2.3.1
- fixes problems with TLS and Milter support

* Tue Jul 25 2006 Thomas Woerner <twoerner@redhat.com> 2:2.3.0-2
- fixed SASL build (#200079)
  thanks to Kaj J. Niemi for the patch

* Mon Jul 24 2006 Thomas Woerner <twoerner@redhat.com> 2:2.3.0-1
- new version 2.3.0
- dropped hostname-fqdn patch

* Wed Jul 12 2006 Jesse Keating <jkeating@redhat.com> - 2:2.2.10-2.1
- rebuild

* Wed May 10 2006 Thomas Woerner <twoerner@redhat.com> 2:2.2.10-2
- added RELRO security protection

* Tue Apr 11 2006 Thomas Woerner <twoerner@redhat.com> 2:2.2.10-1
- new version 2.2.10
- added option LDAP_DEPRECATED to support deprecated ldap functions for now
- fixed build without pflogsumm support (#188470)

* Fri Feb 10 2006 Jesse Keating <jkeating@redhat.com> - 2:2.2.8-1.2
- bump again for double-long bug on ppc(64)

* Tue Feb 07 2006 Jesse Keating <jkeating@redhat.com> - 2:2.2.8-1.1
- rebuilt for new gcc4.1 snapshot and glibc changes

* Tue Jan 24 2006 Florian Festi <ffesti@redhat.com> 2:2.2.8-1
- new version 2.2.8

* Tue Dec 13 2005 Thomas Woerner <twoerner@redhat.com> 2:2.2.7-1
- new version 2.2.7

* Fri Dec 09 2005 Jesse Keating <jkeating@redhat.com>
- rebuilt

* Fri Nov 11 2005 Thomas Woerner <twoerner@redhat.com> 2:2.2.5-2.1
- replaced postconf and postalias call in initscript with newaliases (#156358)
- fixed initscripts messages (#155774)
- fixed build problems when sasl is disabled (#164773)
- fixed pre-definition of mailbox_transport lmtp socket path (#122910)

* Thu Nov 10 2005 Tomas Mraz <tmraz@redhat.com> 2:2.2.5-2
- rebuilt against new openssl

* Fri Oct  7 2005 Tomas Mraz <tmraz@redhat.com>
- use include instead of pam_stack in pam config

* Thu Sep  8 2005 Thomas Woerner <twoerner@redhat.com> 2:2.2.5-1
- new version 2.2.5

* Thu May 12 2005 Thomas Woerner <twoerner@redhat.com> 2:2.2.3-1
- new version 2.2.3
- compiling all binaries PIE, dropped old pie patch

* Wed Apr 20 2005 Tomas Mraz <tmraz@redhat.com> 2:2.2.2-2
- fix fsspace on large filesystems (>2G blocks)

* Tue Apr 12 2005 Thomas Woerner <twoerner@redhat.com> 2:2.2.2-1
- new version 2.2.2

* Fri Mar 18 2005 Thomas Woerner <twoerner@redhat.com> 2:2.2.1-1
- new version 2.2.1
- allow to start postfix without alias_database (#149657)

* Fri Mar 11 2005 Thomas Woerner <twoerner@redhat.com> 2:2.2.0-1
- new version 2.2.0
- cleanup of spec file: removed external TLS and IPV6 patches, removed 
  smtp_sasl_proto patch
- dropped samples directory till there are good examples again (was TLS and
  IPV6)
- v2.2.0 fixes code problems: #132798 and #137858

* Fri Feb 11 2005 Thomas Woerner <twoerner@redhat.com> 2:2.1.5-5.1
- fixed open relay bug in postfix ipv6 patch: new version 1.26 (#146731)
- fixed permissions on doc directory (#147280)
- integrated fixed fqdn patch from Joseph Dunn (#139983)

* Tue Nov 23 2004 Thomas Woerner <twoerner@redhat.com> 2:2.1.5-4.1
- removed double quotes from postalias call, second fix for #138354

* Thu Nov 11 2004 Jeff Johnson <jbj@jbj.org> 2:2.1.5-4
- rebuild against db-4.3.21.
- remove Requires: db4, the soname linkage dependency is sufficient.

* Thu Nov 11 2004 Thomas Woerner <twoerner@redhat.com> 2:2.1.5-3.1
- fixed problem with multiple alias maps (#138354)

* Tue Oct 26 2004 Thomas Woerner <twoerner@redhat.com> 2:2.1.5-3
- fixed wrong path for cyrus-imapd (#137074)

* Mon Oct 18 2004 Thomas Woerner <twoerner@redhat.com> 2:2.1.5-2.2
- automated postalias call in init script
- removed postconf call from spec file: moved changes into patch

* Fri Oct 15 2004 Thomas Woerner <twoerner@redhat.com> 2:2.1.5-2.1
- removed aliases from postfix-files (#135840)
- fixed postalias call in init script

* Thu Oct 14 2004 Thomas Woerner <twoerner@redhat.com> 2:2.1.5-2
- switched over to system aliases file and database in /etc/ (#117661)
- new reuires and buildrequires for setup >= 2.5.36-1

* Mon Oct  4 2004 Thomas Woerner <twoerner@redhat.com> 2:2.1.5-1
- new version 2.1.5
- new ipv6 and tls+ipv6 patches: 1.25-pf-2.1.5

* Thu Aug  5 2004 Thomas Woerner <twoerner@redhat.com> 2:2.1.4-1
- new version 2.1.4
- new ipv6 and tls+ipv6 patches: 1.25-pf-2.1.4
- new pfixtls-0.8.18-2.1.3-0.9.7d patch

* Mon Jun 21 2004 Thomas Woerner <twoerner@redhat.com> 2:2.1.1-3.1
- fixed directory permissions in %%doc (#125406)
- fixed missing spool dirs (#125460)
- fixed verify problem for aliases.db (#125461)
- fixed bogus upgrade warning (#125628)
- more spec file cleanup

* Tue Jun 15 2004 Elliot Lee <sopwith@redhat.com>
- rebuilt

* Sun Jun 06 2004 Florian La Roche <Florian.LaRoche@redhat.de>
- make sure pflog files have same permissions even if in multiple
  sub-rpms

* Fri Jun  4 2004 Thomas Woerner <twoerner@redhat.com> 2:2.1.1-1
- new version 2.1.1
- compiling postfix PIE
- new alternatives slave for /usr/lib/sendmail

* Wed Mar 31 2004 John Dennis <jdennis@redhat.com> 2:2.0.18-4
- remove version from pflogsumm subpackage, it was resetting the
  version used in the doc directory, fixes bug 119213

* Tue Mar 30 2004 Bill Nottingham <notting@redhat.com> 2:2.0.18-3
- add %%defattr for pflogsumm package

* Tue Mar 16 2004 John Dennis <jdennis@finch.boston.redhat.com> 2:2.0.18-2
- fix sendmail man page (again), make pflogsumm a subpackage

* Mon Mar 15 2004 John Dennis <jdennis@finch.boston.redhat.com> 2:2.0.18-1
- bring source up to upstream release 2.0.18
- include pflogsumm, fixes bug #68799
- include smtp-sink, smtp-source man pages, fixes bug #118163

* Tue Mar 02 2004 Elliot Lee <sopwith@redhat.com>
- rebuilt

* Tue Feb 24 2004 John Dennis <jdennis@finch.boston.redhat.com> 2:2.0.16-14
- fix bug 74553, make alternatives track sendmail man page

* Tue Feb 24 2004 John Dennis <jdennis@finch.boston.redhat.com> 2:2.0.16-13
- remove /etc/sysconfig/saslauthd from rpm, fixes bug 113975

* Wed Feb 18 2004 John Dennis <jdennis@porkchop.devel.redhat.com>
- set sasl back to v2 for mainline, this is good for fedora and beyond,
  for RHEL3, we'll branch and set set sasl to v1 and turn off ipv6

* Tue Feb 17 2004 John Dennis <jdennis@porkchop.devel.redhat.com>
- revert back to v1 of sasl because LDAP still links against v1 and we can't 
- bump revision for build
  have two different versions of the sasl library loaded in one load image at
  the same time. How is that possible? Because the sasl libraries have different 
  names (libsasl.so & libsasl2.so) but export the same symbols :-(
  Fixes bugs 115249 and 111767

* Fri Feb 13 2004 Elliot Lee <sopwith@redhat.com>
- rebuilt

* Wed Jan 21 2004 John Dennis <jdennis@finch.boston.redhat.com> 2:2.0.16-7
- fix bug 77216, support snapshot builds

* Tue Jan 20 2004 John Dennis <jdennis@finch.boston.redhat.com> 2:2.0.16-6
- add support for IPv6 via Dean Strik's patches, fixes bug 112491

* Tue Jan 13 2004 John Dennis <jdennis@finch.boston.redhat.com> 2:2.0.16-4
- remove mysqlclient prereq, fixes bug 101779
- remove md5 verification override, this fixes bug 113370. Write parse-postfix-files
  script to generate explicit list of all upstream files with ownership, modes, etc.
  carefully add back in all other not upstream files, files list is hopefully
  rock solid now.

* Mon Jan 12 2004 John Dennis <jdennis@finch.boston.redhat.com> 2:2.0.16-3
- add zlib-devel build prereq, fixes bug 112822
- remove copy of resolve.conf into chroot jail, fixes bug 111923

* Tue Dec 16 2003 John Dennis <jdennis@porkchop.devel.redhat.com>
- bump release to build 3.0E errata update

* Sat Dec 13 2003 Jeff Johnson <jbj@jbj.org> 2:2.0.16-2
- rebuild against db-4.2.52.
 
* Mon Nov 17 2003 John Dennis <jdennis@finch.boston.redhat.com> 2:2.0.16-1
- sync up with current upstream release, 2.0.16, fixes bug #108960

* Thu Sep 25 2003 Jeff Johnson <jbj@jbj.org> 2.0.11-6
- rebuild against db-4.2.42.

* Tue Jul 22 2003 Nalin Dahyabhai <nalin@redhat.com> 2.0.11-5
- rebuild

* Thu Jun 26 2003 John Dennis <jdennis@finch.boston.redhat.com>
- bug 98095, change rmail.postfix to rmail for uucp invocation in master.cf

* Wed Jun 25 2003 John Dennis <jdennis@finch.boston.redhat.com>
- add missing dependency for db3/db4

* Thu Jun 19 2003 John Dennis <jdennis@finch.boston.redhat.com>
- upgrade to new 2.0.11 upstream release
- fix authentication problems
- rewrite SASL documentation
- upgrade to use SASL version 2
- Fix bugs 75439, 81913 90412, 91225, 78020, 90891, 88131

* Wed Jun 04 2003 Elliot Lee <sopwith@redhat.com>
- rebuilt

* Fri Mar  7 2003 John Dennis <jdennis@finch.boston.redhat.com>
- upgrade to release 2.0.6
- remove chroot as this is now the preferred installation according to Wietse Venema, the postfix author

* Mon Feb 24 2003 Elliot Lee <sopwith@redhat.com>
- rebuilt

* Tue Feb 18 2003 Bill Nottingham <notting@redhat.com> 2:1.1.11-10
- don't copy winbind/wins nss modules, fixes #84553

* Sat Feb 01 2003 Florian La Roche <Florian.LaRoche@redhat.de>
- sanitize rpm scripts a bit

* Wed Jan 22 2003 Tim Powers <timp@redhat.com>
- rebuilt

* Sat Jan 11 2003 Karsten Hopp <karsten@redhat.de> 2:1.1.11-8
- rebuild to fix krb5.h issue

* Tue Jan  7 2003 Nalin Dahyabhai <nalin@redhat.com> 2:1.1.11-7
- rebuild

* Fri Jan  3 2003 Nalin Dahyabhai <nalin@redhat.com>
- if pkgconfig knows about openssl, use its cflags and linker flags

* Thu Dec 12 2002 Tim Powers <timp@redhat.com> 2:1.1.11-6
- lib64'ize
- build on all arches

* Wed Jul 24 2002 Karsten Hopp <karsten@redhat.de>
- make aliases.db config(noreplace) (#69612)

* Tue Jul 23 2002 Karsten Hopp <karsten@redhat.de>
- postfix has its own filelist, remove LICENSE entry from it (#69069)

* Tue Jul 16 2002 Karsten Hopp <karsten@redhat.de>
- fix shell in /etc/passwd (#68373)
- fix documentation in /etc/postfix (#65858)
- Provides: /usr/bin/newaliases (#66746)
- fix autorequires by changing /usr/local/bin/perl to /usr/bin/perl in a
  script in %%doc (#68852), although I don't think this is necessary anymore

* Mon Jul 15 2002 Phil Knirsch <pknirsch@redhat.com>
- Fixed missing smtpd.conf file for SASL support and included SASL Postfix
  Red Hat HOWTO (#62505).
- Included SASL2 support patch (#68800).

* Mon Jun 24 2002 Karsten Hopp <karsten@redhat.de>
- 1.1.11, TLS 0.8.11a
- fix #66219 and #66233 (perl required for %%post)

* Fri Jun 21 2002 Tim Powers <timp@redhat.com>
- automated rebuild

* Sun May 26 2002 Tim Powers <timp@redhat.com>
- automated rebuild

* Thu May 23 2002 Bernhard Rosenkraenzer <bero@redhat.com> 1.1.10-1
- 1.1.10, TLS 0.8.10
- Build with db4
- Enable SASL

* Mon Apr 15 2002 Bernhard Rosenkraenzer <bero@redhat.com> 1.1.7-2
- Fix bugs #62358 and #62783
- Make sure libdb-3.3.so is in the chroot jail (#62906)

* Mon Apr  8 2002 Bernhard Rosenkraenzer <bero@redhat.com> 1.1.7-1
- 1.1.7, fixes 2 critical bugs
- Make sure there's a resolv.conf in the chroot jail

* Wed Mar 27 2002 Bernhard Rosenkraenzer <bero@redhat.com> 1.1.5-3
- Add Provides: lines for alternatives stuff (#60879)

* Tue Mar 26 2002 Nalin Dahyabhai <nalin@redhat.com> 1.1.5-2
- rebuild

* Tue Mar 26 2002 Bernhard Rosenkraenzer <bero@redhat.com> 1.1.5-1
- 1.1.5 (bugfix release)
- Rebuild with current db

* Thu Mar 14 2002 Bill Nottingham <notting@redhat.com> 1.1.4-3
- remove db trigger, it's both dangerous and pointless
- clean up other triggers a little

* Wed Mar 13 2002 Bernhard Rosenkraenzer <bero@redhat.com> 1.1.4-2
- Some trigger tweaks to make absolutely sure /etc/services is in the
  chroot jail

* Mon Mar 11 2002 Bernhard Rosenkraenzer <bero@redhat.com> 1.1.4-1
- 1.1.4
- TLS 0.8.4
- Move postalias run from %%post to init script to work around
  anaconda being broken.

* Fri Mar  8 2002 Bill Nottingham <notting@redhat.com> 1.1.3-5
- use alternatives --initscript support

* Thu Feb 28 2002 Bill Nottingham <notting@redhat.com> 1.1.3-4
- run alternatives --remove in %%preun
- add various prereqs

* Thu Feb 28 2002 Nalin Dahyabhai <nalin@redhat.com> 1.1.3-3
- adjust the default postfix-files config file to match the alternatives setup
  by altering the arguments passed to post-install in the %%install phase
  (otherwise, it might point to sendmail's binaries, breaking it rather rudely)
- adjust the post-install script so that it silently uses paths which have been
  modified for use with alternatives, for upgrade cases where the postfix-files
  configuration file isn't overwritten
- don't forcefully strip files -- that's a build root policy
- remove hard requirement on openldap, library dependencies take care of it
- redirect %%postun to /dev/null
- don't remove the postfix user and group when the package is removed

* Wed Feb 20 2002 Bernhard Rosenkraenzer <bero@redhat.com> 1.1.3-2
- listen on 127.0.0.1 only by default (#60071)
- Put config samples in %%{_docdir}/%%{name}-%%{version} rather than
  /etc/postfix (#60072)
- Some spec file cleanups

* Tue Feb 19 2002 Bernhard Rosenkraenzer <bero@redhat.com> 1.1.3-1
- 1.1.3, TLS 0.8.3
- Fix updating
- Don't run the statistics cron job
- remove requirement on perl Date::Calc

* Thu Jan 31 2002 Bernhard Rosenkraenzer <bero@redhat.com> 1.1.2-3
- Fix up alternatives stuff

* Wed Jan 30 2002 Bernhard Rosenkraenzer <bero@redhat.com> 1.1.2-2
- Use alternatives

* Sun Jan 27 2002 Bernhard Rosenkraenzer <bero@redhat.com> 1.1.2-1
- Initial Red Hat Linux packaging, based on spec file from
  Simon J Mudd <sjmudd@pobox.com>
- Changes from that:
  - Set up chroot environment in triggers to make sure we catch glibc errata
  - Remove some hacks to support building on all sorts of distributions at
    the cost of specfile readability
  - Remove postdrop group on deletion

