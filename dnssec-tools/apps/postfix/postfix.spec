%define LDAP 2
%define MYSQL 0
%define PCRE 1
%define SASL 2
%define TLS 1
%define IPV6 1
%define POSTDROP_GID 90
%define PFLOGSUMM 1

# On Redhat 8.0.1 and earlier, LDAP is compiled with SASL V1 and won't work
# if postfix is compiled with SASL V2. So we drop to SASL V1 if LDAP is
# requested but use the preferred SASL V2 if LDAP is not requested.
# Sometime soon LDAP will build agains SASL V2 and this won't be needed.

%if %{LDAP} <= 1 && %{SASL} >= 2
%undefine SASL
%define SASL 1
%endif

%if %{PFLOGSUMM}
%define pflogsumm_ver 1.1.0
%endif

# Postfix requires one exlusive uid/gid and a 2nd exclusive gid for its own
# use.  Let me know if the second gid collides with another package.
# Be careful: Redhat's 'mail' user & group isn't unique!
%define postfix_uid    89
%define postfix_user   postfix
%define postfix_gid    89
%define postfix_group  postfix
%define postdrop_group postdrop
%define maildrop_group %{postdrop_group}
%define maildrop_gid   %{POSTDROP_GID}

%define postfix_config_dir  %{_sysconfdir}/postfix
%define postfix_daemon_dir  %{_libexecdir}/postfix
%define postfix_command_dir %{_sbindir}
%define postfix_queue_dir   %{_var}/spool/postfix
%define postfix_doc_dir     %{_docdir}/%{name}-%{version}
%define postfix_sample_dir  %{postfix_doc_dir}/samples
%define postfix_readme_dir  %{postfix_doc_dir}/README_FILES

Name: postfix
Summary: Postfix Mail Transport Agent
Version: 2.3.3
Release: 2.dnssec.1
Epoch: 2
Group: System Environment/Daemons
URL: http://www.postfix.org
License: IBM Public License
PreReq: /sbin/chkconfig, /sbin/service, sh-utils
PreReq: fileutils, textutils,
PreReq: /usr/sbin/alternatives

PreReq: %{_sbindir}/groupadd, %{_sbindir}/useradd

Provides: MTA smtpd smtpdaemon /usr/bin/newaliases

Source0: ftp://ftp.porcupine.org/mirrors/postfix-release/official/%{name}-%{version}.tar.gz
Source1: postfix-etc-init.d-postfix
Source3: README-Postfix-SASL-RedHat.txt

# Sources 50-99 are upstream [patch] contributions

%if %{PFLOGSUMM}
# Postfix Log Entry Summarizer: http://jimsun.linxnet.com/postfix_contrib.html
Source53: http://jimsun.linxnet.com/downloads/pflogsumm-%{pflogsumm_ver}.tar.gz
%endif

# Sources >= 100 are config files

Source100: postfix-sasl.conf
Source101: postfix-pam.conf

# Patches

Patch1: postfix-2.1.1-config.patch
Patch3: postfix-alternatives.patch
Patch6: postfix-2.1.1-obsolete.patch
Patch7: postfix-2.1.5-aliases.patch
Patch8: postfix-large-fs.patch
Patch9: postfix-2.2.5-cyrus.patch

# dnssec patch
patch10: postfix-2.3.3_dnssec.patch

# Optional patches - set the appropriate environment variables to include
#                    them when building the package/spec file

BuildRoot: %{_tmppath}/%{name}-buildroot

# Determine the different packages required for building postfix
BuildRequires: gawk, perl, sed, ed, db4-devel, pkgconfig, zlib-devel

Requires: setup >= 2.5.36-1
BuildRequires: setup >= 2.5.36-1

%if %{LDAP}
BuildRequires: openldap >= 2.0.27, openldap-devel >= 2.0.27
Requires: openldap >= 2.0.27
%endif

%if %{SASL}
BuildRequires: cyrus-sasl >= 2.1.10, cyrus-sasl-devel >= 2.1.10
Requires: cyrus-sasl  >= 2.1.10
%endif

%if %{PCRE}
Requires: pcre
BuildRequires: pcre, pcre-devel
%endif

%if %{MYSQL}
Requires: mysql
BuildRequires: mysql, mysql-devel
%endif

%if %{TLS}
Requires: openssl
BuildRequires: openssl-devel >= 0.9.6
%endif

#dnssec requires
Requires:	dnssec-tools-libs >= 1.1.1
Requires:	dnssec-tools-libs-devel >= 1.1.1

Provides: /usr/sbin/sendmail /usr/bin/mailq /usr/bin/rmail

%description
Postfix is a Mail Transport Agent (MTA), supporting LDAP, SMTP AUTH (SASL),
TLS

%prep
umask 022

%setup -q
# Apply obligatory patches
%patch1 -p1 -b .config
%patch3 -p1 -b .alternatives
%patch6 -p1 -b .obsolete
%patch7 -p1 -b .aliases
%patch8 -p1 -b .large-fs
%patch9 -p1 -b .cyrus

# dnssec patch
%patch10 -p1 -b .dnssec

%if %{PFLOGSUMM}
gzip -dc %{SOURCE53} | tar xf -
pushd pflogsumm-%{pflogsumm_ver}
patch -p0 < ../pflogsumm-conn-delays-dsn-patch
popd
%endif

# pflogsumm subpackage
%if %{PFLOGSUMM}
%package pflogsumm
Group: System Environment/Daemons
Summary: A Log Summarizer/Analyzer for the Postfix MTA
Requires: perl-Date-Calc
%description pflogsumm
Pflogsumm is a log analyzer/summarizer for the Postfix MTA.  It is
designed to provide an over-view of Postfix activity. Pflogsumm
generates summaries and, in some cases, detailed reports of mail
server traffic volumes, rejected and bounced email, and server
warnings, errors and panics.

%endif

%build
umask 022

CCARGS=-fPIC
AUXLIBS=

%ifarch s390 s390x ppc
CCARGS="${CCARGS} -fsigned-char"
%endif

%if %{LDAP}
  CCARGS="${CCARGS} -DHAS_LDAP -DLDAP_DEPRECATED=1"
  AUXLIBS="${AUXLIBS} -L%{_libdir} -lldap -llber"
%endif
%if %{PCRE}
  # -I option required for pcre 3.4 (and later?)
  CCARGS="${CCARGS} -DHAS_PCRE -I/usr/include/pcre"
  AUXLIBS="${AUXLIBS} -lpcre"
%endif
%if %{MYSQL}
  CCARGS="${CCARGS} -DHAS_MYSQL -I/usr/include/mysql"
  AUXLIBS="${AUXLIBS} -L%{_libdir}/mysql -lmysqlclient -lm"
%endif
%if %{SASL}
  %define sasl_v1_lib_dir %{_libdir}/sasl
  %define sasl_v2_lib_dir %{_libdir}/sasl2
  CCARGS="${CCARGS} -DUSE_SASL_AUTH -DUSE_CYRUS_SASL"
  %if %{SASL} <= 1
    %define sasl_lib_dir %{sasl_v1_lib_dir}
    AUXLIBS="${AUXLIBS} -L%{sasl_lib_dir} -lsasl"
  %else
    %define sasl_lib_dir %{sasl_v2_lib_dir}
    CCARGS="${CCARGS} -I/usr/include/sasl"
    AUXLIBS="${AUXLIBS} -L%{sasl_lib_dir} -lsasl2"
  %endif
%endif
%if %{TLS}
  if pkg-config openssl ; then
    CCARGS="${CCARGS} -DUSE_TLS `pkg-config --cflags openssl`"
    AUXLIBS="${AUXLIBS} `pkg-config --libs openssl`"
  else
    CCARGS="${CCARGS} -DUSE_TLS -I/usr/include/openssl"
    AUXLIBS="${AUXLIBS} -lssl -lcrypto"
  fi
%endif
%if %{IPV6} != 1
  CCARGS="${CCARGS} -DNO_IPV6"
%endif

AUXLIBS="${AUXLIBS} -pie -Wl,-z,relro"

export CCARGS AUXLIBS
make -f Makefile.init makefiles

unset CCARGS AUXLIBS
make DEBUG="" OPT="$RPM_OPT_FLAGS"

%install
umask 022
/bin/rm -rf   $RPM_BUILD_ROOT
/bin/mkdir -p $RPM_BUILD_ROOT

# install postfix into $RPM_BUILD_ROOT

# Move stuff around so we don't conflict with sendmail
mv man/man1/mailq.1      man/man1/mailq.postfix.1
mv man/man1/newaliases.1 man/man1/newaliases.postfix.1
mv man/man1/sendmail.1   man/man1/sendmail.postfix.1
mv man/man5/aliases.5    man/man5/aliases.postfix.5

sh postfix-install -non-interactive \
       install_root=$RPM_BUILD_ROOT \
       config_directory=%{postfix_config_dir} \
       daemon_directory=%{postfix_daemon_dir} \
       command_directory=%{postfix_command_dir} \
       queue_directory=%{postfix_queue_dir} \
       sendmail_path=%{postfix_command_dir}/sendmail.postfix \
       newaliases_path=%{_bindir}/newaliases.postfix \
       mailq_path=%{_bindir}/mailq.postfix \
       mail_owner=%{postfix_user} \
       setgid_group=%{maildrop_group} \
       manpage_directory=%{_mandir} \
       sample_directory=%{postfix_sample_dir} \
       readme_directory=%{postfix_readme_dir} || exit 1

# This installs into the /etc/rc.d/init.d directory
/bin/mkdir -p $RPM_BUILD_ROOT/etc/rc.d/init.d
install -c %{_sourcedir}/postfix-etc-init.d-postfix \
                  $RPM_BUILD_ROOT/etc/rc.d/init.d/postfix

install -c auxiliary/rmail/rmail $RPM_BUILD_ROOT%{_bindir}/rmail.postfix

for i in active bounce corrupt defer deferred flush incoming private saved maildrop public pid saved trace; do
    mkdir -p $RPM_BUILD_ROOT%{postfix_queue_dir}/$i
done

# install performance benchmark tools by hand
for i in smtp-sink smtp-source ; do
  install -c -m 755 bin/$i $RPM_BUILD_ROOT%{postfix_command_dir}/
  install -c -m 755 man/man1/$i.1 $RPM_BUILD_ROOT%{_mandir}/man1/
done

# RPM compresses man pages automatically.
# - Edit postfix-files to reflect this, so post-install won't get confused
#   when called during package installation.
ed $RPM_BUILD_ROOT%{postfix_config_dir}/postfix-files <<EOF || exit 1
,s/\(\/man[158]\/.*\.[158]\):/\1.gz:/
,s/\$config_directory\/aliases:f/\#/
w
q
EOF

perl -i -pe 's:/cyrus/bin/deliver:/usr/lib/cyrus-imapd/deliver:' $RPM_BUILD_ROOT%{postfix_config_dir}/master.cf

cat $RPM_BUILD_ROOT%{postfix_config_dir}/postfix-files
%if %{SASL}
# Install the smtpd.conf file for SASL support.
# See README-Postfix-SASL-RedHat.txt for why we need to set saslauthd_version
# in the v1 version of smtpd.conf
mkdir -p $RPM_BUILD_ROOT%{sasl_v1_lib_dir}
install -m 644 %{SOURCE100} $RPM_BUILD_ROOT%{sasl_v1_lib_dir}/smtpd.conf
echo "saslauthd_version: 2" >> $RPM_BUILD_ROOT%{sasl_v1_lib_dir}/smtpd.conf

mkdir -p $RPM_BUILD_ROOT%{sasl_v2_lib_dir}
install -m 644 %{SOURCE100} $RPM_BUILD_ROOT%{sasl_v2_lib_dir}/smtpd.conf
%endif

mkdir -p $RPM_BUILD_ROOT%{_sysconfdir}/pam.d
install -m 644 %{SOURCE101} $RPM_BUILD_ROOT%{_sysconfdir}/pam.d/smtp.postfix

# Install Postfix Red Hat HOWTO.
mkdir -p $RPM_BUILD_ROOT%{postfix_doc_dir}
install -c %{SOURCE3} $RPM_BUILD_ROOT%{postfix_doc_dir}

%if %{PFLOGSUMM}
install -c -m 644 pflogsumm-%{pflogsumm_ver}/pflogsumm-faq.txt $RPM_BUILD_ROOT%{postfix_doc_dir}/pflogsumm-faq.txt
install -c -m 644 pflogsumm-%{pflogsumm_ver}/pflogsumm.1 $RPM_BUILD_ROOT%{_mandir}/man1/pflogsumm.1
install -c pflogsumm-%{pflogsumm_ver}/pflogsumm.pl $RPM_BUILD_ROOT%{postfix_command_dir}/pflogsumm
%endif

# install qshape
mantools/srctoman - auxiliary/qshape/qshape.pl > qshape.1
install -c qshape.1 $RPM_BUILD_ROOT%{_mandir}/man1/qshape.1
install -c auxiliary/qshape/qshape.pl $RPM_BUILD_ROOT%{postfix_command_dir}/qshape

rm -f $RPM_BUILD_ROOT/etc/postfix/aliases

mkdir -p $RPM_BUILD_ROOT/usr/lib
pushd $RPM_BUILD_ROOT/usr/lib
ln -sf ../sbin/sendmail.postfix .
popd

%post
umask 022

/sbin/chkconfig --add postfix

# upgrade configuration files if necessary
%{_sbindir}/postfix set-permissions upgrade-configuration \
	config_directory=%{postfix_config_dir} \
	daemon_directory=%{postfix_daemon_dir} \
	command_directory=%{postfix_command_dir} \
	mail_owner=%{postfix_user} \
	setgid_group=%{maildrop_group} \
	manpage_directory=%{_mandir} \
	sample_directory=%{postfix_sample_dir} \
	readme_directory=%{postfix_readme_dir}

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

%pre
# Add user and groups if necessary
%{_sbindir}/groupadd -g %{maildrop_gid} -r %{maildrop_group} 2>/dev/null
%{_sbindir}/groupadd -g %{postfix_gid} -r %{postfix_group} 2>/dev/null
%{_sbindir}/groupadd -g 12 -r mail 2>/dev/null
%{_sbindir}/useradd -d %{postfix_queue_dir} -s /sbin/nologin -g %{postfix_group} -G mail -M -r -u %{postfix_uid} %{postfix_user} 2>/dev/null
exit 0

%preun
umask 022

if [ "$1" = 0 ]; then
    # stop postfix silently, but only if it's running
    /sbin/service postfix stop &>/dev/null
    /sbin/chkconfig --del postfix
    /usr/sbin/alternatives --remove mta %{postfix_command_dir}/sendmail.postfix
fi

exit 0

%postun
if [ "$1" != 0 ]; then
	/sbin/service postfix condrestart 2>&1 > /dev/null
fi
exit 0

%clean
/bin/rm -rf $RPM_BUILD_ROOT


%files

# For correct directory permissions check postfix-install script.
# It reads the file postfix-files which defines the ownership
# and permissions for all files postfix installs, we avoid explicitly
# setting anything in the %files sections that is handled by
# the upstream install script so we don't have an issue with keeping
# the spec file and upstream in sync.

%defattr(-, root, root)

# Config files not part of upstream

%if %{SASL}
%config(noreplace) %{sasl_v1_lib_dir}/smtpd.conf
%config(noreplace) %{sasl_v2_lib_dir}/smtpd.conf
%endif
%config(noreplace) %{_sysconfdir}/pam.d/smtp.postfix
%attr(0755, root, root) %config /etc/rc.d/init.d/postfix

# Misc files

%attr(0755, root, root) %{_bindir}/rmail.postfix

%attr(0755, root, root) %{postfix_command_dir}/smtp-sink
%attr(0755, root, root) %{postfix_command_dir}/smtp-source
%attr(0755, root, root) %{postfix_command_dir}/qshape
%attr(0755, root, root) /usr/lib/sendmail.postfix

%dir %attr(0755, root, root) %{postfix_doc_dir}
%doc %attr(0644, root, root) %{postfix_doc_dir}/README-*
%dir %attr(0755, root, root) %{postfix_readme_dir}
%doc %attr(0644, root, root) %{postfix_readme_dir}/*
#%dir %attr(0755, root, root) %{postfix_sample_dir}
#%doc %attr(0644, root, root) %{postfix_sample_dir}/*

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

%attr(0644, root, root) %{_mandir}/man1/[a-n]*
%attr(0644, root, root) %{_mandir}/man1/post*
%attr(0644, root, root) %{_mandir}/man1/[q-z]*
%attr(0644, root, root) %{_mandir}/man5/*
%attr(0644, root, root) %{_mandir}/man8/*

%attr(0755, root, root) %{postfix_command_dir}/postalias
%attr(0755, root, root) %{postfix_command_dir}/postcat
%attr(0755, root, root) %{postfix_command_dir}/postconf
%attr(2755, root, %{maildrop_group}) %{postfix_command_dir}/postdrop
%attr(0755, root, root) %{postfix_command_dir}/postfix
%attr(0755, root, root) %{postfix_command_dir}/postkick
%attr(0755, root, root) %{postfix_command_dir}/postlock
%attr(0755, root, root) %{postfix_command_dir}/postlog
%attr(0755, root, root) %{postfix_command_dir}/postmap
%attr(2755, root, %{maildrop_group}) %{postfix_command_dir}/postqueue
%attr(0755, root, root) %{postfix_command_dir}/postsuper
%attr(0644, root, root) %{postfix_config_dir}/LICENSE
%attr(0644, root, root) %config(noreplace) %{postfix_config_dir}/access
%attr(0644, root, root) %config(noreplace) %{postfix_config_dir}/bounce.cf.default
%attr(0644, root, root) %config(noreplace) %{postfix_config_dir}/canonical
%attr(0644, root, root) %config(noreplace) %{postfix_config_dir}/generic
%attr(0644, root, root) %config(noreplace) %{postfix_config_dir}/header_checks
%attr(0644, root, root) %config(noreplace) %{postfix_config_dir}/main.cf
%attr(0644, root, root) %{postfix_config_dir}/main.cf.default
%attr(0644, root, root) %config(noreplace) %{postfix_config_dir}/makedefs.out
%attr(0644, root, root) %config(noreplace) %{postfix_config_dir}/master.cf
%attr(0755, root, root) %{postfix_config_dir}/post-install
%attr(0644, root, root) %{postfix_config_dir}/postfix-files
%attr(0755, root, root) %{postfix_config_dir}/postfix-script
%attr(0644, root, root) %config(noreplace) %{postfix_config_dir}/relocated
%attr(0644, root, root) %{postfix_config_dir}/TLS_LICENSE
%attr(0644, root, root) %config(noreplace) %{postfix_config_dir}/transport
%attr(0644, root, root) %config(noreplace) %{postfix_config_dir}/virtual
%attr(0755, root, root) %{postfix_daemon_dir}/*
%attr(0755, root, root) %{_bindir}/mailq.postfix
%attr(0755, root, root) %{_bindir}/newaliases.postfix
%attr(0755, root, root) %{_sbindir}/sendmail.postfix

%if %{PFLOGSUMM}
%files pflogsumm
%defattr(-, root, root)
    %doc  %{postfix_doc_dir}/pflogsumm-faq.txt
    %{_mandir}/man1/pflogsumm.1.gz
    %attr(0755, root , root) %{postfix_command_dir}/pflogsumm
%endif


%changelog
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
- Put config samples in %{_docdir}/%{name}-%{version} rather than
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

