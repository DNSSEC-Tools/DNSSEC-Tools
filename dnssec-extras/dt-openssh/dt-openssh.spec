# Do we want SELinux & Audit
%if 0%{?!noselinux:1}
%define WITH_SELINUX 1
%else
%define WITH_SELINUX 0
%endif

# OpenSSH privilege separation requires a user & group ID
%define sshd_uid    74
%define sshd_gid    74

# Do we want to disable building of gnome-askpass? (1=yes 0=no)
%define no_gnome_askpass 0

# Do we want to link against a static libcrypto? (1=yes 0=no)
%define static_libcrypto 0

# Do we want smartcard support (1=yes 0=no)
#Smartcard support is broken from 5.4p1
%define scard 0

# Use GTK2 instead of GNOME in gnome-ssh-askpass
%define gtk2 1

# Build position-independent executables (requires toolchain support)?
%define pie 1

# Do we want kerberos5 support (1=yes 0=no)
%define kerberos5 1

# Do we want libedit support
%define libedit 1

# Do we want LDAP support
%define ldap 1

# Do we want NSS tokens support
# NSS support is broken from 5.4p1
%define nss 0

# Whether or not /sbin/nologin exists.
%define nologin 1

# Whether to build pam_ssh_agent_auth
%if 0%{?!nopam:1}
%define pam_ssh_agent 1
%else
%define pam_ssh_agent 0
%endif

# Reserve options to override askpass settings with:
# rpm -ba|--rebuild --define 'skip_xxx 1'
%{?skip_gnome_askpass:%global no_gnome_askpass 1}

# Add option to build without GTK2 for older platforms with only GTK+.
# Red Hat Linux <= 7.2 and Red Hat Advanced Server 2.1 are examples.
# rpm -ba|--rebuild --define 'no_gtk2 1'
%{?no_gtk2:%global gtk2 0}

# Options for static OpenSSL link:
# rpm -ba|--rebuild --define "static_openssl 1"
%{?static_openssl:%global static_libcrypto 1}

# Options for Smartcard support: (needs libsectok and openssl-engine)
# rpm -ba|--rebuild --define "smartcard 1"
%{?smartcard:%global scard 1}

# Is this a build for the rescue CD (without PAM, with MD5)? (1=yes 0=no)
%define rescue 0
%{?build_rescue:%global rescue 1}
%{?build_rescue:%global rescue_rel rescue}

# Turn off some stuff for resuce builds
%if %{rescue}
%define kerberos5 0
%define libedit 0
%define pam_ssh_agent 0
%endif

# Do not forget to bump pam_ssh_agent_auth release if you rewind the main package release to 1
%define openssh_ver 5.8p2
%define openssh_rel 25
%define pam_ssh_agent_ver 0.9.2
%define pam_ssh_agent_rel 31

Summary: An open source implementation of SSH protocol versions 1 and 2
Name: openssh
Version: %{openssh_ver}
Release: %{openssh_rel}%{?dist}%{?rescue_rel}
URL: http://www.openssh.com/portable.html
#URL1: http://pamsshagentauth.sourceforge.net
#Source0: ftp://ftp.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-%{version}.tar.gz
#Source1: ftp://ftp.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-%{version}.tar.gz.asc
# This package differs from the upstream OpenSSH tarball in that
# the ACSS cipher is removed by running openssh-nukeacss.sh in
# the unpacked source directory.
Source0: openssh-%{version}-noacss.tar.bz2
Source1: openssh-nukeacss.sh
Source2: sshd.pam
Source3: sshd.init
Source4: http://prdownloads.sourceforge.net/pamsshagentauth/pam_ssh_agent_auth/pam_ssh_agent_auth-%{pam_ssh_agent_ver}.tar.bz2
Source5: pam_ssh_agent-rmheaders
Source6: ssh-keycat.pam
Source7: sshd.sysconfig
Source8: sshd-keygen.service
Source9: sshd@.service
Source10: sshd.socket
Source11: sshd.service
Source13: sshd-keygen

Patch99: openssh-5.8p1-wIm.patch
#https://bugzilla.mindrot.org/show_bug.cgi?id=1635 (WONTFIX)
Patch0: openssh-5.6p1-redhat.patch
#https://bugzilla.mindrot.org/show_bug.cgi?id=1872
Patch100: openssh-5.8p1-fingerprint.patch
#https://bugzilla.mindrot.org/show_bug.cgi?id=1879
Patch200: openssh-5.8p1-exit.patch
#https://bugzilla.mindrot.org/show_bug.cgi?id=1894
#https://bugzilla.redhat.com/show_bug.cgi?id=735889
Patch300: openssh-5.8p1-getaddrinfo.patch
#https://bugzilla.mindrot.org/show_bug.cgi?id=1402
Patch8: openssh-5.8p1-audit0.patch
Patch1: openssh-5.8p1-audit1.patch
Patch2: openssh-5.8p1-audit2.patch
Patch3: openssh-5.8p1-audit3.patch
Patch4: openssh-5.8p1-audit4.patch
Patch5: openssh-5.8p1-audit5.patch
#https://bugzilla.mindrot.org/show_bug.cgi?id=1889
Patch6: openssh-5.8p1-packet.patch
#https://bugzilla.mindrot.org/show_bug.cgi?id=1890 (WONTFIX) need integration to prng helper
Patch7: openssh-5.8p1-entropy.patch
#https://bugzilla.mindrot.org/show_bug.cgi?id=1640 (WONTFIX)
Patch9: openssh-5.8p1-vendor.patch
# --- pam_ssh-agent ---
Patch10: pam_ssh_agent_auth-0.9-build.patch
Patch11: pam_ssh_agent_auth-0.9.2-seteuid.patch
#https://bugzilla.mindrot.org/show_bug.cgi?id=1663
Patch20: openssh-5.8p1-authorized-keys-command.patch
#?-- unwanted child :(
Patch21: openssh-5.8p1-ldap.patch
# #-mail-conf
# Patch22: openssh-5.8p1-selinux.patch
#https://bugzilla.mindrot.org/show_bug.cgi?id=1641 (WONTFIX)
Patch23: openssh-5.8p1-selinux-role.patch
#?
Patch24: openssh-5.8p1-mls.patch
# #https://bugzilla.mindrot.org/show_bug.cgi?id=1614
# Patch25: openssh-5.6p1-selabel.patch
#https://bugzilla.redhat.com/show_bug.cgi?id=782078
Patch26: openssh-5.8p2-sftp-chroot.patch
#https://bugzilla.mindrot.org/show_bug.cgi?id=1668
Patch30: openssh-5.6p1-keygen.patch
#https://bugzilla.mindrot.org/show_bug.cgi?id=1644
Patch31: openssh-5.2p1-allow-ip-opts.patch
#https://bugzilla.mindrot.org/show_bug.cgi?id=1701
Patch32: openssh-5.8p1-randclean.patch
# #https://bugzilla.mindrot.org/show_bug.cgi?id=1636
# Patch33: openssh-5.1p1-log-in-chroot.patch
#http://cvsweb.netbsd.org/cgi-bin/cvsweb.cgi/src/crypto/dist/ssh/Attic/sftp-glob.c.diff?r1=1.13&r2=1.13.12.1&f=h
Patch35: openssh-5.8p1-glob.patch
#https://bugzilla.mindrot.org/show_bug.cgi?id=1891
Patch36: openssh-5.8p1-pwchange.patch
#https://bugzilla.mindrot.org/show_bug.cgi?id=1893
Patch37: openssh-5.8p1-keyperm.patch
#?
Patch50: openssh-5.8p1-fips.patch
#https://bugzilla.mindrot.org/show_bug.cgi?id=1789
Patch51: openssh-5.5p1-x11.patch
#?
Patch52: openssh-5.6p1-exit-deadlock.patch
#?
Patch53: openssh-5.1p1-askpass-progress.patch
#?
Patch54: openssh-4.3p2-askpass-grab-info.patch
#?
Patch56: openssh-5.2p1-edns.patch
#?
Patch57: openssh-5.1p1-scp-manpage.patch
#?
Patch58: openssh-5.8p1-keycat.patch
#http://www.sxw.org.uk/computing/patches/openssh.html
Patch60: openssh-5.8p1-gsskex.patch
#?
Patch61: openssh-5.8p1-gssapi-canohost.patch
#?
Patch62: openssh-5.8p1-localdomain.patch
#http://www.mail-archive.com/kerberos@mit.edu/msg17591.html
Patch63: openssh-5.8p2-force_krb.patch
#https://bugzilla.mindrot.org/show_bug.cgi?id=1780
Patch64: openssh-5.8p2-kuserok.patch
#https://bugzilla.mindrot.org/show_bug.cgi?id=1329 (WONTFIX)
Patch65: openssh-5.8p2-remove-stale-control-socket.patch
#?
Patch66: openssh-5.8p2-ipv6man.patch
#https://bugzilla.mindrot.org/show_bug.cgi?id=1919
Patch67: openssh-5.8p2-unconfined.patch
#?
Patch69: openssh-5.8p2-askpass-ld.patch
#https://bugzilla.redhat.com/show_bug.cgi?id=739989
Patch70: openssh-5.8p2-copy-id-restorecon.patch
# warn users for unsupported UsePAM=no
Patch71: openssh-5.8p2-log-usepam-no.patch
#---
#https://bugzilla.mindrot.org/show_bug.cgi?id=1604
# sctp
#https://bugzilla.mindrot.org/show_bug.cgi?id=1873 => https://bugzilla.redhat.com/show_bug.cgi?id=668993

License: BSD
Group: Applications/Internet
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
%if %{nologin}
Requires: /sbin/nologin
%endif

Requires: initscripts >= 5.20

%if ! %{no_gnome_askpass}
%if %{gtk2}
BuildRequires: gtk2-devel
BuildRequires: libX11-devel
%else
BuildRequires: gnome-libs-devel
%endif
%endif

%if %{scard}
BuildRequires: sharutils
%endif
%if %{ldap}
BuildRequires: openldap-devel
%endif
BuildRequires: autoconf, automake, perl, zlib-devel
BuildRequires: audit-libs-devel >= 2.0.5
BuildRequires: util-linux, groff
BuildRequires: pam-devel
BuildRequires: tcp_wrappers-devel
BuildRequires: fipscheck-devel >= 1.3.0
BuildRequires: openssl-devel >= 0.9.8j

%if %{kerberos5}
BuildRequires: krb5-devel
%endif

%if %{libedit}
BuildRequires: libedit-devel ncurses-devel
%endif

%if %{nss}
BuildRequires: nss-devel
%endif

%if %{WITH_SELINUX}
Requires: libselinux >= 1.27.7
BuildRequires: libselinux-devel >= 1.27.7
Requires: audit-libs >= 1.0.8
BuildRequires: audit-libs >= 1.0.8
%endif

BuildRequires: xauth

%package clients
Summary: An open source SSH client applications
Group: Applications/Internet
Requires: openssh = %{version}-%{release}
Requires: fipscheck-lib%{_isa} >= 1.3.0

%package server
Summary: An open source SSH server daemon
Group: System Environment/Daemons
Requires: openssh = %{version}-%{release}
Requires(pre): /usr/sbin/useradd
Requires: pam >= 1.0.1-3
Requires: fipscheck-lib%{_isa} >= 1.3.0
Requires(post): systemd-units
Requires(preun): systemd-units
Requires(postun): systemd-units
# This is actually needed for the %triggerun script but Requires(triggerun)
# is not valid.  We can use %post because this particular %triggerun script
# should fire just after this package is installed.
Requires(post): systemd-sysv

# Not yet ready
# %package server-ondemand
# Summary: Systemd unit file to run an ondemand OpenSSH server
# Group: System Environment/Daemons
# Requires: %{name}-server%{?_isa} = %{version}-%{release}

%package server-sysvinit
Summary: The SysV initscript to manage the OpenSSH server.
Group: System Environment/Daemons
Requires: %{name}-server%{?_isa} = %{version}-%{release}

%if %{ldap}
%package ldap
Summary: A LDAP support for open source SSH server daemon
Requires: openssh = %{version}-%{release}
Group: System Environment/Daemons
%endif

%package keycat
Summary: A mls keycat backend for openssh
Requires: openssh = %{version}-%{release}
Group: System Environment/Daemons

%package askpass
Summary: A passphrase dialog for OpenSSH and X
Group: Applications/Internet
Requires: openssh = %{version}-%{release}
Obsoletes: openssh-askpass-gnome
Provides: openssh-askpass-gnome

%package -n pam_ssh_agent_auth
Summary: PAM module for authentication with ssh-agent
Group: System Environment/Base
Version: %{pam_ssh_agent_ver}
Release: %{pam_ssh_agent_rel}.%{openssh_rel}%{?dist}%{?rescue_rel}
License: BSD

%description
SSH (Secure SHell) is a program for logging into and executing
commands on a remote machine. SSH is intended to replace rlogin and
rsh, and to provide secure encrypted communications between two
untrusted hosts over an insecure network. X11 connections and
arbitrary TCP/IP ports can also be forwarded over the secure channel.

OpenSSH is OpenBSD's version of the last free version of SSH, bringing
it up to date in terms of security and features.

This package includes the core files necessary for both the OpenSSH
client and server. To make this package useful, you should also
install openssh-clients, openssh-server, or both.

%description clients
OpenSSH is a free version of SSH (Secure SHell), a program for logging
into and executing commands on a remote machine. This package includes
the clients necessary to make encrypted connections to SSH servers.

%description server
OpenSSH is a free version of SSH (Secure SHell), a program for logging
into and executing commands on a remote machine. This package contains
the secure shell daemon (sshd). The sshd daemon allows SSH clients to
securely connect to your SSH server.

# %description server-ondemand
# OpenSSH is a free version of SSH (Secure SHell), a program for logging
# into and executing commands on a remote machine. This package contains
# the systemd unit files to run an ondemand (socket activated) SSH server.

%description server-sysvinit
OpenSSH is a free version of SSH (Secure SHell), a program for logging
into and executing commands on a remote machine. This package contains
the SysV init script to manage the OpenSSH server when running a legacy
SysV-compatible init system.

It is not required when the init system used is systemd.

%if %{ldap}
%description ldap
OpenSSH LDAP backend is a way how to distribute the authorized tokens
among the servers in the network.
%endif

%description keycat
OpenSSH mls keycat is backend for using the authorized keys in the
openssh in the mls mode.

%description askpass
OpenSSH is a free version of SSH (Secure SHell), a program for logging
into and executing commands on a remote machine. This package contains
an X11 passphrase dialog for OpenSSH.

%description -n pam_ssh_agent_auth
This package contains a PAM module which can be used to authenticate
users using ssh keys stored in a ssh-agent. Through the use of the
forwarding of ssh-agent connection it also allows to authenticate with
remote ssh-agent instance.

The module is most useful for su and sudo service stacks.

%prep
%setup -q -a 4
#Do not enable by default
###%patch99 -p1 -b .wIm

%patch0 -p1 -b .redhat
%patch100 -p1 -b .fingerprint
%patch200 -p1 -b .exit
%patch300 -p1 -b .getaddrinfo
%patch8 -p1 -b .audit0
%patch1 -p1 -b .audit1
%patch2 -p1 -b .audit2
%patch3 -p1 -b .audit3
%patch4 -p1 -b .audit4
%patch5 -p1 -b .audit5
%patch6 -p1 -b .packet
%patch7 -p1 -b .entropy
%patch9 -p1 -b .vendor
%if %{pam_ssh_agent}
pushd pam_ssh_agent_auth-%{pam_ssh_agent_ver}
%patch10 -p1 -b .psaa-build
%patch11 -p1 -b .psaa-seteuid
# Remove duplicate headers
rm -f $(cat %{SOURCE5})
popd
%endif
%patch20 -p1 -b .akc
%if %{ldap}
%patch21 -p1 -b .ldap
%endif
%if %{WITH_SELINUX}
#SELinux
# %patch22 -p1 -b .selinux
%patch23 -p1 -b .role
%patch24 -p1 -b .mls
%patch26 -p1 -b .sftp-chroot
%endif
%patch30 -p1 -b .keygen
%patch31 -p1 -b .ip-opts
%patch32 -p1 -b .randclean
%patch35 -p1 -b .glob
%patch36 -p1 -b .pwchange
%patch37 -p1 -b .keyperm

%patch50 -p1 -b .fips
%patch51 -p1 -b .x11
%patch52 -p1 -b .exit-deadlock
%patch53 -p1 -b .progress
%patch54 -p1 -b .grab-info
%patch56 -p1 -b .edns
%patch57 -p1 -b .manpage
%patch58 -p1 -b .keycat
%patch60 -p1 -b .gsskex
%patch61 -p1 -b .canohost
%patch62 -p1 -b .localdomain
%patch63 -p1 -b .force_krb
%patch64 -p1 -b .kuserok
%patch65 -p1 -b .remove_stale
%patch66 -p1 -b .ipv6man
%patch67 -p1 -b .unconfined
%patch69 -p1 -b .askpass-ld
%patch70 -p1 -b .restorecon
%patch71 -p1 -b .log-usepam-no

autoreconf
pushd pam_ssh_agent_auth-%{pam_ssh_agent_ver}
autoreconf
popd

%build
CFLAGS="$RPM_OPT_FLAGS"; export CFLAGS
%if %{rescue}
CFLAGS="$CFLAGS -Os"
%endif
%if %{pie}
%ifarch s390 s390x sparc sparcv9 sparc64
CFLAGS="$CFLAGS -fPIC"
%else
CFLAGS="$CFLAGS -fpic"
%endif
SAVE_LDFLAGS="$LDFLAGS"
LDFLAGS="$LDFLAGS -pie -z relro -z now"

export CFLAGS
export LDFLAGS

%endif
%if %{kerberos5}
if test -r /etc/profile.d/krb5-devel.sh ; then
        source /etc/profile.d/krb5-devel.sh
fi
krb5_prefix=`krb5-config --prefix`
if test "$krb5_prefix" != "%{_prefix}" ; then
	CPPFLAGS="$CPPFLAGS -I${krb5_prefix}/include -I${krb5_prefix}/include/gssapi"; export CPPFLAGS
	CFLAGS="$CFLAGS -I${krb5_prefix}/include -I${krb5_prefix}/include/gssapi"
	LDFLAGS="$LDFLAGS -L${krb5_prefix}/%{_lib}"; export LDFLAGS
else
	krb5_prefix=
	CPPFLAGS="-I%{_includedir}/gssapi"; export CPPFLAGS
	CFLAGS="$CFLAGS -I%{_includedir}/gssapi"
fi
%endif

%configure \
	--sysconfdir=%{_sysconfdir}/ssh \
	--libexecdir=%{_libexecdir}/openssh \
	--datadir=%{_datadir}/openssh \
	--with-tcp-wrappers \
	--with-default-path=/usr/local/bin:/bin:/usr/bin \
	--with-superuser-path=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin \
	--with-privsep-path=%{_var}/empty/sshd \
	--enable-vendor-patchlevel="FC-%{version}-%{release}" \
	--disable-strip \
	--without-zlib-version-check \
	--with-ssl-engine \
	--with-authorized-keys-command \
%if %{nss}
	--with-nss \
%endif
%if %{scard}
	--with-smartcard \
%endif
%if %{ldap}
	--with-ldap \
%endif
%if %{rescue}
	--without-pam \
%else
	--with-pam \
%endif
%if %{WITH_SELINUX}
	--with-selinux --with-audit=linux \
%endif
%if %{kerberos5}
	--with-kerberos5${krb5_prefix:+=${krb5_prefix}} \
%else
	--without-kerberos5 \
%endif
%if %{libedit}
	--with-libedit
%else
	--without-libedit
%endif

%if %{static_libcrypto}
perl -pi -e "s|-lcrypto|%{_libdir}/libcrypto.a|g" Makefile
%endif

make

# Define a variable to toggle gnome1/gtk2 building.  This is necessary
# because RPM doesn't handle nested %if statements.
%if %{gtk2}
	gtk2=yes
%else
	gtk2=no
%endif

%if ! %{no_gnome_askpass}
pushd contrib
if [ $gtk2 = yes ] ; then
	make gnome-ssh-askpass2
	mv gnome-ssh-askpass2 gnome-ssh-askpass
else
	make gnome-ssh-askpass1
	mv gnome-ssh-askpass1 gnome-ssh-askpass
fi
popd
%endif

%if %{pam_ssh_agent}
pushd pam_ssh_agent_auth-%{pam_ssh_agent_ver}
LDFLAGS="$SAVE_LDFLAGS"
%configure --with-selinux --libexecdir=/%{_lib}/security --with-mantype=man
make
popd
%endif

# Add generation of HMAC checksums of the final stripped binaries
%define __spec_install_post \
    %{?__debug_package:%{__debug_install_post}} \
    %{__arch_install_post} \
    %{__os_install_post} \
    fipshmac -d $RPM_BUILD_ROOT%{_libdir}/fipscheck $RPM_BUILD_ROOT%{_bindir}/ssh $RPM_BUILD_ROOT%{_sbindir}/sshd \
%{nil}

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p -m755 $RPM_BUILD_ROOT%{_sysconfdir}/ssh
mkdir -p -m755 $RPM_BUILD_ROOT%{_libexecdir}/openssh
mkdir -p -m755 $RPM_BUILD_ROOT%{_var}/empty/sshd
make install DESTDIR=$RPM_BUILD_ROOT
rm -f $RPM_BUILD_ROOT%{_sysconfdir}/ssh/ldap.conf

install -d $RPM_BUILD_ROOT/etc/pam.d/
install -d $RPM_BUILD_ROOT/etc/sysconfig/
install -d $RPM_BUILD_ROOT/etc/rc.d/init.d
install -d $RPM_BUILD_ROOT%{_libexecdir}/openssh
install -d $RPM_BUILD_ROOT%{_libdir}/fipscheck
install -m644 %{SOURCE2} $RPM_BUILD_ROOT/etc/pam.d/sshd
install -m644 %{SOURCE6} $RPM_BUILD_ROOT/etc/pam.d/ssh-keycat
install -m755 %{SOURCE3} $RPM_BUILD_ROOT/etc/rc.d/init.d/sshd
install -m644 %{SOURCE7} $RPM_BUILD_ROOT/etc/sysconfig/sshd
install -m755 %{SOURCE13} $RPM_BUILD_ROOT/%{_sbindir}/sshd-keygen
install -d -m755 $RPM_BUILD_ROOT/%{_unitdir}
install -m644 %{SOURCE8} $RPM_BUILD_ROOT/%{_unitdir}/sshd-keygen.service
# install -m644 %{SOURCE9} $RPM_BUILD_ROOT/%{_unitdir}/sshd@.service
# install -m644 %{SOURCE10} $RPM_BUILD_ROOT/%{_unitdir}/sshd.socket
install -m644 %{SOURCE11} $RPM_BUILD_ROOT/%{_unitdir}/sshd.service
install -m755 contrib/ssh-copy-id $RPM_BUILD_ROOT%{_bindir}/
install contrib/ssh-copy-id.1 $RPM_BUILD_ROOT%{_mandir}/man1/

%if ! %{no_gnome_askpass}
install contrib/gnome-ssh-askpass $RPM_BUILD_ROOT%{_libexecdir}/openssh/gnome-ssh-askpass
%endif

%if ! %{scard}
	rm -f $RPM_BUILD_ROOT%{_datadir}/openssh/Ssh.bin
%endif

%if ! %{no_gnome_askpass}
ln -s gnome-ssh-askpass $RPM_BUILD_ROOT%{_libexecdir}/openssh/ssh-askpass
install -m 755 -d $RPM_BUILD_ROOT%{_sysconfdir}/profile.d/
install -m 755 contrib/redhat/gnome-ssh-askpass.csh $RPM_BUILD_ROOT%{_sysconfdir}/profile.d/
install -m 755 contrib/redhat/gnome-ssh-askpass.sh $RPM_BUILD_ROOT%{_sysconfdir}/profile.d/
%endif

%if %{no_gnome_askpass}
rm -f $RPM_BUILD_ROOT/etc/profile.d/gnome-ssh-askpass.*
%endif

perl -pi -e "s|$RPM_BUILD_ROOT||g" $RPM_BUILD_ROOT%{_mandir}/man*/*

rm -f README.nss.nss-keys
%if ! %{nss}
rm -f README.nss
%endif

%if %{pam_ssh_agent}
pushd pam_ssh_agent_auth-%{pam_ssh_agent_ver}
make install DESTDIR=$RPM_BUILD_ROOT
popd
%endif
%clean
rm -rf $RPM_BUILD_ROOT

%pre
getent group ssh_keys >/dev/null || groupadd -r ssh_keys || :

%pre server
getent group sshd >/dev/null || groupadd -g %{sshd_uid} -r sshd || :
%if %{nologin}
getent passwd sshd >/dev/null || \
  useradd -c "Privilege-separated SSH" -u %{sshd_uid} -g sshd  -s /sbin/nologin \
  -s /sbin/nologin -r -d /var/empty/sshd sshd 2> /dev/null || :
%else
getent passwd sshd >/dev/null || \
  useradd -c "Privilege-separated SSH" -u %{sshd_uid} -g sshd  -s /sbin/nologin \
  -s /dev/null -r -d /var/empty/sshd sshd 2> /dev/null || :
%endif

%post server
if [ $1 -eq 1 ] ; then
    /bin/systemctl enable sshd.service >/dev/null 2>&1 || :
    /bin/systemctl enable sshd-keygen.service >/dev/null 2>&1 || :
fi

%postun server
/bin/systemctl daemon-reload >/dev/null 2>&1 || :
if [ $1 -ge 1 ] ; then
    # Package upgrade, not uninstall
    /bin/systemctl try-restart sshd.service >/dev/null 2>&1 || :
    /bin/systemctl try-restart sshd-keygen.service >/dev/null 2>&1 || :
fi

%preun server
if [ $1 -eq 0 ] ; then
    # Package removal, not upgrade
    /bin/systemctl --no-reload disable sshd.service > /dev/null 2>&1 || :
    /bin/systemctl --no-reload disable sshd-keygen.service > /dev/null 2>&1 || :
    /bin/systemctl stop sshd.service > /dev/null 2>&1 || :
    /bin/systemctl stop sshd-keygen.service > /dev/null 2>&1 || :
fi

%triggerun -n openssh-server -- openssh-server < 5.8p2-12
/usr/bin/systemd-sysv-convert --save sshd >/dev/null 2>&1 || :
/bin/systemctl enable sshd.service >/dev/null 2>&1
/bin/systemctl enable sshd-keygen.service >/dev/null 2>&1
/sbin/chkconfig --del sshd >/dev/null 2>&1 || :
/bin/systemctl try-restart sshd.service >/dev/null 2>&1 || :
# This one was never a service, so we don't simply restart it
/bin/systemctl is-active -q sshd.service && /bin/systemctl start sshd-keygen.service >/dev/null 2>&1 || :

%triggerpostun -n openssh-server-sysvinit -- openssh-server < 5.8p2-12
/sbin/chkconfig --add sshd >/dev/null 2>&1 || :

%files
%defattr(-,root,root)
%doc CREDITS ChangeLog INSTALL LICENCE OVERVIEW PROTOCOL* README README.platform README.privsep README.tun README.dns TODO WARNING*
%attr(0755,root,root) %dir %{_sysconfdir}/ssh
%attr(0600,root,root) %config(noreplace) %{_sysconfdir}/ssh/moduli
%if ! %{rescue}
%attr(0755,root,root) %{_bindir}/ssh-keygen
%attr(0644,root,root) %{_mandir}/man1/ssh-keygen.1*
%attr(0755,root,root) %dir %{_libexecdir}/openssh
%attr(2111,root,ssh_keys) %{_libexecdir}/openssh/ssh-keysign
%attr(0644,root,root) %{_mandir}/man8/ssh-keysign.8*
%endif
%if %{scard}
%attr(0755,root,root) %dir %{_datadir}/openssh
%attr(0644,root,root) %{_datadir}/openssh/Ssh.bin
%endif

%files clients
%defattr(-,root,root)
%attr(0755,root,root) %{_bindir}/ssh
%attr(0644,root,root) %{_libdir}/fipscheck/ssh.hmac
%attr(0644,root,root) %{_mandir}/man1/ssh.1*
%attr(0755,root,root) %{_bindir}/scp
%attr(0644,root,root) %{_mandir}/man1/scp.1*
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/ssh/ssh_config
%attr(0755,root,root) %{_bindir}/slogin
%attr(0644,root,root) %{_mandir}/man1/slogin.1*
%attr(0644,root,root) %{_mandir}/man5/ssh_config.5*
%if ! %{rescue}
%attr(2111,root,nobody) %{_bindir}/ssh-agent
%attr(0755,root,root) %{_bindir}/ssh-add
%attr(0755,root,root) %{_bindir}/ssh-keyscan
%attr(0755,root,root) %{_bindir}/sftp
%attr(0755,root,root) %{_bindir}/ssh-copy-id
%attr(0755,root,root) %{_libexecdir}/openssh/ssh-pkcs11-helper
%attr(0644,root,root) %{_mandir}/man1/ssh-agent.1*
%attr(0644,root,root) %{_mandir}/man1/ssh-add.1*
%attr(0644,root,root) %{_mandir}/man1/ssh-keyscan.1*
%attr(0644,root,root) %{_mandir}/man1/sftp.1*
%attr(0644,root,root) %{_mandir}/man1/ssh-copy-id.1*
%attr(0644,root,root) %{_mandir}/man8/ssh-pkcs11-helper.8*
%endif

%if ! %{rescue}
%files server
%defattr(-,root,root)
%dir %attr(0711,root,root) %{_var}/empty/sshd
%attr(0755,root,root) %{_sbindir}/sshd
%attr(0755,root,root) %{_sbindir}/sshd-keygen
%attr(0644,root,root) %{_libdir}/fipscheck/sshd.hmac
%attr(0755,root,root) %{_libexecdir}/openssh/sftp-server
%attr(0644,root,root) %{_mandir}/man5/sshd_config.5*
%attr(0644,root,root) %{_mandir}/man5/moduli.5*
%attr(0644,root,root) %{_mandir}/man8/sshd.8*
%attr(0644,root,root) %{_mandir}/man8/sftp-server.8*
%attr(0600,root,root) %config(noreplace) %{_sysconfdir}/ssh/sshd_config
%attr(0644,root,root) %config(noreplace) /etc/pam.d/sshd
%attr(0640,root,root) %config(noreplace) /etc/sysconfig/sshd
%attr(0644,root,root) %{_unitdir}/sshd-keygen.service
%attr(0644,root,root) %{_unitdir}/sshd.service

# %files server-ondemand
# %defattr(-,root,root)
# %attr(0644,root,root) %{_unitdir}/sshd@.service
# %attr(0644,root,root) %{_unitdir}/sshd.socket

%files server-sysvinit
%defattr(-,root,root)
%attr(0755,root,root) /etc/rc.d/init.d/sshd
%endif

%if %{ldap}
%files ldap
%defattr(-,root,root)
%doc HOWTO.ldap-keys openssh-lpk-openldap.schema openssh-lpk-sun.schema ldap.conf
%attr(0755,root,root) %{_libexecdir}/openssh/ssh-ldap-helper
%attr(0755,root,root) %{_libexecdir}/openssh/ssh-ldap-wrapper
%attr(0644,root,root) %{_mandir}/man8/ssh-ldap-helper.8*
%attr(0644,root,root) %{_mandir}/man5/ssh-ldap.conf.5*
%endif

%files keycat
%defattr(-,root,root)
%doc HOWTO.ssh-keycat
%attr(0755,root,root) %{_libexecdir}/openssh/ssh-keycat
%attr(0644,root,root) %config(noreplace) /etc/pam.d/ssh-keycat

%if ! %{no_gnome_askpass}
%files askpass
%defattr(-,root,root)
%attr(0644,root,root) %{_sysconfdir}/profile.d/gnome-ssh-askpass.*
%attr(0755,root,root) %{_libexecdir}/openssh/gnome-ssh-askpass
%attr(0755,root,root) %{_libexecdir}/openssh/ssh-askpass
%endif

%if %{pam_ssh_agent}
%files -n pam_ssh_agent_auth
%defattr(-,root,root)
%doc pam_ssh_agent_auth-%{pam_ssh_agent_ver}/OPENSSH_LICENSE
%attr(0755,root,root) /%{_lib}/security/pam_ssh_agent_auth.so
%attr(0644,root,root) %{_mandir}/man8/pam_ssh_agent_auth.8*
%endif

%changelog
* Wed Feb 22 2012 Petr Lautrbach <plautrba@redhat.com> 5.8p2-25 + 0.9.2-31
- Look for x11 forward sockets with AI_ADDRCONFIG flag getaddrinfo (#735889)

* Tue Jan 31 2012 Petr Lautrbach <plautrba@redhat.com> 5.8p2-24 + 0.9.2-31
- backport sftp+chroot+SELinux changes from Rawhide (#782078)

* Tue Dec 06 2011 Petr Lautrbach <plautrba@redhat.com> 5.8p2-23 + 0.9.2-31
- warn about unsupported option UsePAM=no (#757545)

* Wed Nov 23 2011 Petr Lautrbach <plautrba@redhat.com> 5.8p2-22 + 0.9.2-31
- add the restorecon call to ssh-copy-id - it might be needed on older
  distribution (#739989)
- update openssh source file (#755531)

* Fri Nov 18 2011 Tomas Mraz <tmraz@redhat.com> - 5.8p2-21 + 0.9.2-31
- still support /etc/sysconfig/sshd loading in sshd service (#754732)
- fix incorrect key permissions generated by sshd-keygen script (#754779)

* Tue Aug  9 2011 Jan F. Chadima <jchadima@redhat.com> - 5.8p2-20 + 0.9.2-31
- save ssh-askpass's debuginfo

* Mon Aug  8 2011 Jan F. Chadima <jchadima@redhat.com> - 5.8p2-19 + 0.9.2-31
- compile ssh-askpass with corect CFLAGS

* Mon Aug  8 2011 Jan F. Chadima <jchadima@redhat.com> - 5.8p2-17 + 0.9.2-31
- repair broken man pages

* Mon Jul 25 2011 Jan F. Chadima <jchadima@redhat.com> - 5.8p2-16 + 0.9.2-31
- rebuild due to broken rpmbiild

* Thu Jul 21 2011 Jan F. Chadima <jchadima@redhat.com> - 5.8p2-15 + 0.9.2-31
- Do not change context when run under unconfined_t

* Thu Jul 14 2011 Jan F. Chadima <jchadima@redhat.com> - 5.8p2-14 + 0.9.2-31
- Add postlogin to pam. (#718807)

* Tue Jun 28 2011 Jan F. Chadima <jchadima@redhat.com> - 5.8p2-12 + 0.9.2-31
- Systemd compatibility according to Mathieu Bridon <bochecha@fedoraproject.org>
- Split out the host keygen into their own command, to ease future migration
  to systemd. Compatitbility with the init script was kept.
- Migrate the package to full native systemd unit files, according to the Fedora
  packaging guidelines.
- Prepate the unit files for running an ondemand server. (do not add it actually)

* Tue Jun 21 2011 Jan F. Chadima <jchadima@redhat.com> - 5.8p2-10 + 0.9.2-31
- Mention IPv6 usage in man pages

* Mon Jun 20 2011 Jan F. Chadima <jchadima@redhat.com> - 5.8p2-9 + 0.9.2-31
- Improve init script

* Thu Jun 16 2011 Jan F. Chadima <jchadima@redhat.com> - 5.8p2-7 + 0.9.2-31
- Add possibility to compile openssh without downstream patches

* Thu Jun  9 2011 Jan F. Chadima <jchadima@redhat.com> - 5.8p2-6 + 0.9.2-31
- remove stale control sockets (#706396)

* Tue May 31 2011 Jan F. Chadima <jchadima@redhat.com> - 5.8p2-5 + 0.9.2-31
- improove entropy manuals

* Fri May 27 2011 Jan F. Chadima <jchadima@redhat.com> - 5.8p2-4 + 0.9.2-31
- improove entropy handling
- concat ldap patches

* Tue May 24 2011 Jan F. Chadima <jchadima@redhat.com> - 5.8p2-3 + 0.9.2-31
- improove ldap manuals

* Mon May 23 2011 Jan F. Chadima <jchadima@redhat.com> - 5.8p2-2 + 0.9.2-31
- add gssapi forced command

* Tue May  3 2011 Jan F. Chadima <jchadima@redhat.com> - 5.8p2-1 + 0.9.2-31
- update the openssh version

* Thu Apr 28 2011 Jan F. Chadima <jchadima@redhat.com> - 5.8p1-34 + 0.9.2-30
- temporarily disabling systemd units

* Wed Apr 27 2011 Jan F. Chadima <jchadima@redhat.com> - 5.8p1-33 + 0.9.2-30
- add flags AI_V4MAPPED and AI_ADDRCONFIG to getaddrinfo

* Tue Apr 26 2011 Jan F. Chadima <jchadima@redhat.com> - 5.8p1-32 + 0.9.2-30
- update scriptlets

* Fri Apr 22 2011 Jan F. Chadima <jchadima@redhat.com> - 5.8p1-30 + 0.9.2-30
- add systemd units

* Fri Apr 22 2011 Jan F. Chadima <jchadima@redhat.com> - 5.8p1-28 + 0.9.2-30
- improving sshd -> passwd transation
- add template for .local domain to sshd_config

* Thu Apr 21 2011 Jan F. Chadima <jchadima@redhat.com> - 5.8p1-27 + 0.9.2-30
- the private keys may be 640 root:ssh_keys ssh_keysign is sgid

* Wed Apr 20 2011 Jan F. Chadima <jchadima@redhat.com> - 5.8p1-26 + 0.9.2-30
- improving sshd -> passwd transation

* Tue Apr  5 2011 Jan F. Chadima <jchadima@redhat.com> - 5.8p1-25 + 0.9.2-30
- the intermediate context is set to sshd_sftpd_t
- do not crash in packet.c if no connection

* Thu Mar 31 2011 Jan F. Chadima <jchadima@redhat.com> - 5.8p1-24 + 0.9.2-30
- resolve warnings in port_linux.c

* Tue Mar 29 2011 Jan F. Chadima <jchadima@redhat.com> - 5.8p1-23 + 0.9.2-30
- add /etc/sysconfig/sshd

* Mon Mar 28 2011 Jan F. Chadima <jchadima@redhat.com> - 5.8p1-22 + 0.9.2-30
- improve reseeding and seed source (documentation)

* Tue Mar 22 2011 Jan F. Chadima <jchadima@redhat.com> - 5.8p1-20 + 0.9.2-30
- use /dev/random or /dev/urandom for seeding prng
- improve periodical reseeding of random generator

* Thu Mar 17 2011 Jan F. Chadima <jchadima@redhat.com> - 5.8p1-18 + 0.9.2-30
- add periodical reseeding of random generator 
- change selinux contex for internal sftp in do_usercontext
- exit(0) after sigterm

* Thu Mar 10 2011 Jan F. Chadima <jchadima@redhat.com> - 5.8p1-17 + 0.9.2-30
- improove ssh-ldap (documentation)

* Tue Mar  8 2011 Jan F. Chadima <jchadima@redhat.com> - 5.8p1-16 + 0.9.2-30
- improve session keys audit

* Mon Mar  7 2011 Jan F. Chadima <jchadima@redhat.com> - 5.8p1-15 + 0.9.2-30
- CVE-2010-4755

* Fri Mar  4 2011 Jan F. Chadima <jchadima@redhat.com> - 5.8p1-14 + 0.9.2-30
- improove ssh-keycat (documentation)

* Thu Mar  3 2011 Jan F. Chadima <jchadima@redhat.com> - 5.8p1-13 + 0.9.2-30
- improve audit of logins and auths

* Tue Mar  1 2011 Jan F. Chadima <jchadima@redhat.com> - 5.8p1-12 + 0.9.2-30
- improove ssk-keycat

* Mon Feb 28 2011 Jan F. Chadima <jchadima@redhat.com> - 5.8p1-11 + 0.9.2-30
- add ssk-keycat

* Fri Feb 25 2011 Jan F. Chadima <jchadima@redhat.com> - 5.8p1-10 + 0.9.2-30
- reenable auth-keys ldap backend

* Fri Feb 25 2011 Jan F. Chadima <jchadima@redhat.com> - 5.8p1-9 + 0.9.2-30
- another audit improovements

* Thu Feb 24 2011 Jan F. Chadima <jchadima@redhat.com> - 5.8p1-8 + 0.9.2-30
- another audit improovements
- switchable fingerprint mode

* Thu Feb 17 2011 Jan F. Chadima <jchadima@redhat.com> - 5.8p1-4 + 0.9.2-30
- improve audit of server key management

* Wed Feb 16 2011 Jan F. Chadima <jchadima@redhat.com> - 5.8p1-3 + 0.9.2-30
- improve audit of logins and auths

* Mon Feb 14 2011 Jan F. Chadima <jchadima@redhat.com> - 5.8p1-1 + 0.9.2-30
- bump openssh version to 5.8p1

* Tue Feb 08 2011 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 5.6p1-30.1
- Rebuilt for https://fedoraproject.org/wiki/Fedora_15_Mass_Rebuild

* Mon Feb  7 2011 Jan F. Chadima <jchadima@redhat.com> - 5.6p1-30 + 0.9.2-29
- clean the data structures in the non privileged process
- clean the data structures when roaming

* Tue Feb  2 2011 Jan F. Chadima <jchadima@redhat.com> - 5.6p1-28 + 0.9.2-29
- clean the data structures in the privileged process

* Tue Jan 25 2011 Jan F. Chadima <jchadima@redhat.com> - 5.6p1-25 + 0.9.2-29
- clean the data structures before exit net process

* Mon Jan 17 2011 Jan F. Chadima <jchadima@redhat.com> - 5.6p1-24 + 0.9.2-29
- make audit compatible with the fips mode

* Fri Jan 14 2011 Jan F. Chadima <jchadima@redhat.com> - 5.6p1-23 + 0.9.2-29
- add audit of destruction the server keys

* Wed Jan 12 2011 Jan F. Chadima <jchadima@redhat.com> - 5.6p1-22 + 0.9.2-29
- add audit of destruction the session keys

* Fri Dec 10 2010 Jan F. Chadima <jchadima@redhat.com> - 5.6p1-21 + 0.9.2-29
- reenable run sshd as non root user
- renable rekeying

* Wed Nov 24 2010 Jan F. Chadima <jchadima@redhat.com> - 5.6p1-20 + 0.9.2-29
- reapair clientloop crash (#627332)
- properly restore euid in case connect to the ssh-agent socket fails

* Mon Nov 22 2010 Jan F. Chadima <jchadima@redhat.com> - 5.6p1-19 + 0.9.2-28
- striped read permissions from suid and sgid binaries

* Mon Nov 15 2010 Jan F. Chadima <jchadima@redhat.com> - 5.6p1-18 + 0.9.2-27
- used upstream version of the biguid patch

* Mon Nov 15 2010 Jan F. Chadima <jchadima@redhat.com> - 5.6p1-17 + 0.9.2-27
- improoved kuserok patch

* Fri Nov  5 2010 Jan F. Chadima <jchadima@redhat.com> - 5.6p1-16 + 0.9.2-27
- add auditing the host based key ussage
- repait X11 abstract layer socket (#648896)

* Wed Nov  3 2010 Jan F. Chadima <jchadima@redhat.com> - 5.6p1-15 + 0.9.2-27
- add auditing the kex result

* Fri Nov  2 2010 Jan F. Chadima <jchadima@redhat.com> - 5.6p1-14 + 0.9.2-27
- add auditing the key ussage

* Fri Oct 20 2010 Jan F. Chadima <jchadima@redhat.com> - 5.6p1-12 + 0.9.2-27
- update gsskex patch (#645389)

* Wed Oct 20 2010 Jan F. Chadima <jchadima@redhat.com> - 5.6p1-11 + 0.9.2-27
- rebase linux audit according to upstream

* Fri Oct  1 2010 Jan F. Chadima <jchadima@redhat.com> - 5.6p1-10 + 0.9.2-27
- add missing headers to linux audit

* Wed Sep 29 2010 Jan F. Chadima <jchadima@redhat.com> - 5.6p1-9 + 0.9.2-27
- audit module now uses openssh audit framevork

* Wed Sep 15 2010 Jan F. Chadima <jchadima@redhat.com> - 5.6p1-8 + 0.9.2-27
- Add the GSSAPI kuserok switch to the kuserok patch

* Wed Sep 15 2010 Jan F. Chadima <jchadima@redhat.com> - 5.6p1-7 + 0.9.2-27
- Repaired the kuserok patch

* Mon Sep 13 2010 Jan F. Chadima <jchadima@redhat.com> - 5.6p1-6 + 0.9.2-27
- Repaired the problem with puting entries with very big uid into lastlog

* Mon Sep 13 2010 Jan F. Chadima <jchadima@redhat.com> - 5.6p1-5 + 0.9.2-27
- Merging selabel patch with the upstream version. (#632914)

* Mon Sep 13 2010 Jan F. Chadima <jchadima@redhat.com> - 5.6p1-4 + 0.9.2-27
- Tweaking selabel patch to work properly without selinux rules loaded. (#632914)

* Wed Sep  8 2010 Tomas Mraz <tmraz@redhat.com> - 5.6p1-3 + 0.9.2-27
- Make fipscheck hmacs compliant with FHS - requires new fipscheck

* Fri Sep  3 2010 Jan F. Chadima <jchadima@redhat.com> - 5.6p1-2 + 0.9.2-27
- Added -z relro -z now to LDFLAGS

* Fri Sep  3 2010 Jan F. Chadima <jchadima@redhat.com> - 5.6p1-1 + 0.9.2-27
- Rebased to openssh5.6p1

* Wed Jul  7 2010 Jan F. Chadima <jchadima@redhat.com> - 5.5p1-18 + 0.9.2-26
- merged with newer bugzilla's version of authorized keys command patch

* Wed Jun 30 2010 Jan F. Chadima <jchadima@redhat.com> - 5.5p1-17 + 0.9.2-26
- improved the x11 patch according to upstream (#598671)

* Thu Jun 25 2010 Jan F. Chadima <jchadima@redhat.com> - 5.5p1-16 + 0.9.2-26
- improved the x11 patch (#598671)

* Thu Jun 24 2010 Jan F. Chadima <jchadima@redhat.com> - 5.5p1-15 + 0.9.2-26
- changed _PATH_UNIX_X to unexistent file name (#598671)

* Wed Jun 23 2010 Jan F. Chadima <jchadima@redhat.com> - 5.5p1-14 + 0.9.2-26
- sftp works in deviceless chroot again (broken from 5.5p1-3)

* Tue Jun  8 2010 Jan F. Chadima <jchadima@redhat.com> - 5.5p1-13 + 0.9.2-26
- add option to switch out krb5_kuserok

* Fri May 21 2010 Jan F. Chadima <jchadima@redhat.com> - 5.5p1-12 + 0.9.2-26
- synchronize uid and gid for the user sshd

* Thu May 20 2010 Jan F. Chadima <jchadima@redhat.com> - 5.5p1-11 + 0.9.2-26
- Typo in ssh-ldap.conf(5) and ssh-ladap-helper(8)

* Fri May 14 2010 Jan F. Chadima <jchadima@redhat.com> - 5.5p1-10 + 0.9.2-26
- Repair the reference in man ssh-ldap-helper(8)
- Repair the PubkeyAgent section in sshd_config(5)
- Provide example ldap.conf

* Thu May 13 2010 Jan F. Chadima <jchadima@redhat.com> - 5.5p1-9 + 0.9.2-26
- Make the Ldap configuration widely compatible
- create the aditional docs for LDAP support.

* Thu May  6 2010 Jan F. Chadima <jchadima@redhat.com> - 5.5p1-8 + 0.9.2-26
- Make LDAP config elements TLS_CACERT and TLS_REQCERT compatiple with pam_ldap (#589360)

* Thu May  6 2010 Jan F. Chadima <jchadima@redhat.com> - 5.5p1-7 + 0.9.2-26
- Make LDAP config element tls_checkpeer compatiple with nss_ldap (#589360)

* Tue May  4 2010 Jan F. Chadima <jchadima@redhat.com> - 5.5p1-6 + 0.9.2-26
- Comment spec.file
- Sync patches from upstream

* Mon May  3 2010 Jan F. Chadima <jchadima@redhat.com> - 5.5p1-5 + 0.9.2-26
- Create separate ldap package
- Tweak the ldap patch
- Rename stderr patch properly

* Wed Apr 29 2010 Jan F. Chadima <jchadima@redhat.com> - 5.5p1-4 + 0.9.2-26
- Added LDAP support

* Mon Apr 26 2010 Jan F. Chadima <jchadima@redhat.com> - 5.5p1-3 + 0.9.2-26
- Ignore .bashrc output to stderr in the subsystems

* Tue Apr 20 2010 Jan F. Chadima <jchadima@redhat.com> - 5.5p1-2 + 0.9.2-26
- Drop dependency on man

* Fri Apr 16 2010 Jan F. Chadima <jchadima@redhat.com> - 5.5p1-1 + 0.9.2-26
- Update to 5.5p1

* Fri Mar 12 2010 Jan F. Chadima <jchadima@redhat.com> - 5.4p1-3 + 0.9.2-25
- repair configure script of pam_ssh_agent
- repair error mesage in ssh-keygen

* Fri Mar 12 2010 Jan F. Chadima <jchadima@redhat.com> - 5.4p1-2
- source krb5-devel profile script only if exists

* Tue Mar  9 2010 Jan F. Chadima <jchadima@redhat.com> - 5.4p1-1
- Update to 5.4p1
- discontinued support for nss-keys
- discontinued support for scard

* Wed Mar  3 2010 Jan F. Chadima <jchadima@redhat.com> - 5.4p1-0.snap20100302.1
- Prepare update to 5.4p1

* Mon Feb 15 2010 Jan F. Chadima <jchadima@redhat.com> - 5.3p1-22
- ImplicitDSOLinking (#564824)

* Fri Jan 29 2010 Jan F. Chadima <jchadima@redhat.com> - 5.3p1-21
- Allow to use hardware crypto if awailable (#559555)

* Mon Jan 25 2010 Jan F. Chadima <jchadima@redhat.com> - 5.3p1-20
- optimized FD_CLOEXEC on accept socket (#541809)

* Mon Jan 25 2010 Tomas Mraz <tmraz@redhat.com> - 5.3p1-19
- updated pam_ssh_agent_auth to new version from upstream (just
  a licence change)

* Thu Jan 21 2010 Jan F. Chadima <jchadima@redhat.com> - 5.3p1-18
- optimized RAND_cleanup patch (#557166)

* Wed Jan 20 2010 Jan F. Chadima <jchadima@redhat.com> - 5.3p1-17
- add RAND_cleanup at the exit of each program using RAND (#557166)

* Tue Jan 19 2010 Jan F. Chadima <jchadima@redhat.com> - 5.3p1-16
- set FD_CLOEXEC on accepted socket (#541809)

* Fri Jan  8 2010 Jan F. Chadima <jchadima@redhat.com> - 5.3p1-15
- replaced define by global in macros

* Tue Jan  5 2010 Jan F. Chadima <jchadima@redhat.com> - 5.3p1-14
- Update the pka patch

* Mon Dec 21 2009 Jan F. Chadima <jchadima@redhat.com> - 5.3p1-13
- Update the audit patch

* Fri Dec  4 2009 Jan F. Chadima <jchadima@redhat.com> - 5.3p1-12
- Add possibility to autocreate only RSA key into initscript (#533339)

* Fri Nov 27 2009 Jan F. Chadima <jchadima@redhat.com> - 5.3p1-11
- Prepare NSS key patch for future SEC_ERROR_LOCKED_PASSWORD (#537411)

* Tue Nov 24 2009 Jan F. Chadima <jchadima@redhat.com> - 5.3p1-10
- Update NSS key patch (#537411, #356451)

* Fri Nov 20 2009 Jan F. Chadima <jchadima@redhat.com> - 5.3p1-9
- Add gssapi key exchange patch (#455351)

* Fri Nov 20 2009 Jan F. Chadima <jchadima@redhat.com> - 5.3p1-8
- Add public key agent patch (#455350)

* Mon Nov  2 2009 Jan F. Chadima <jchadima@redhat.com> - 5.3p1-7
- Repair canohost patch to allow gssapi to work when host is acessed via pipe proxy (#531849)

* Thu Oct 29 2009 Jan F. Chadima <jchadima@redhat.com> - 5.3p1-6
- Modify the init script to prevent it to hang during generating the keys (#515145)

* Tue Oct 27 2009 Jan F. Chadima <jchadima@redhat.com> - 5.3p1-5
- Add README.nss

* Mon Oct 19 2009 Tomas Mraz <tmraz@redhat.com> - 5.3p1-4
- Add pam_ssh_agent_auth module to a subpackage.

* Fri Oct 16 2009 Jan F. Chadima <jchadima@redhat.com> - 5.3p1-3
- Reenable audit.

* Fri Oct  2 2009 Jan F. Chadima <jchadima@redhat.com> - 5.3p1-2
- Upgrade to new wersion 5.3p1

* Tue Sep 29 2009 Jan F. Chadima <jchadima@redhat.com> - 5.2p1-29
- Resolve locking in ssh-add (#491312)

* Thu Sep 24 2009 Jan F. Chadima <jchadima@redhat.com> - 5.2p1-28
- Repair initscript to be acord to guidelines (#521860)
- Add bugzilla# to application of edns and xmodifiers patch

* Wed Sep 16 2009 Jan F. Chadima <jchadima@redhat.com> - 5.2p1-26
- Changed pam stack to password-auth

* Fri Sep 11 2009 Jan F. Chadima <jchadima@redhat.com> - 5.2p1-25
- Dropped homechroot patch

* Mon Sep  7 2009 Jan F. Chadima <jchadima@redhat.com> - 5.2p1-24
- Add check for nosuid, nodev in homechroot

* Tue Sep  1 2009 Jan F. Chadima <jchadima@redhat.com> - 5.2p1-23
- add correct patch for ip-opts

* Tue Sep  1 2009 Jan F. Chadima <jchadima@redhat.com> - 5.2p1-22
- replace ip-opts patch by an upstream candidate version

* Mon Aug 31 2009 Jan F. Chadima <jchadima@redhat.com> - 5.2p1-21
- rearange selinux patch to be acceptable for upstream
- replace seftp patch by an upstream version

* Fri Aug 28 2009 Jan F. Chadima <jchadima@redhat.com> - 5.2p1-20
- merged xmodifiers to redhat patch
- merged gssapi-role to selinux patch
- merged cve-2007_3102 to audit patch
- sesftp patch only with WITH_SELINUX flag
- rearange sesftp patch according to upstream request

* Wed Aug 26 2009 Jan F. Chadima <jchadima@redhat.com> - 5.2p1-19
- minor change in sesftp patch

* Fri Aug 21 2009 Tomas Mraz <tmraz@redhat.com> - 5.2p1-18
- rebuilt with new openssl

* Thu Jul 30 2009 Jan F. Chadima <jchadima@redhat.com> - 5.2p1-17
- Added dnssec support. (#205842)

* Sat Jul 25 2009 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 5.2p1-16
- Rebuilt for https://fedoraproject.org/wiki/Fedora_12_Mass_Rebuild

* Fri Jul 24 2009 Jan F. Chadima <jchadima@redhat.com> - 5.2p1-15
- only INTERNAL_SFTP can be home-chrooted
- save _u and _r parts of context changing to sftpd_t

* Fri Jul 17 2009 Jan F. Chadima <jchadima@redhat.com> - 5.2p1-14
- changed internal-sftp context to sftpd_t

* Fri Jul  3 2009 Jan F. Chadima <jchadima@redhat.com> - 5.2p1-13
- changed home length path patch to upstream version

* Tue Jun 30 2009 Jan F. Chadima <jchadima@redhat.com> - 5.2p1-12
- create '~/.ssh/known_hosts' within proper context

* Mon Jun 29 2009 Jan F. Chadima <jchadima@redhat.com> - 5.2p1-11
- length of home path in ssh now limited by PATH_MAX
- correct timezone with daylight processing

* Sat Jun 27 2009 Jan F. Chadima <jchadima@redhat.com> - 5.2p1-10
- final version chroot %%h (sftp only)

* Tue Jun 23 2009 Jan F. Chadima <jchadima@redhat.com> - 5.2p1-9
- repair broken ls in chroot %%h

* Fri Jun 12 2009 Jan F. Chadima <jchadima@redhat.com> - 5.2p1-8
- add XMODIFIERS to exported environment (#495690)

* Fri May 15 2009 Tomas Mraz <tmraz@redhat.com> - 5.2p1-6
- allow only protocol 2 in the FIPS mode

* Thu Apr 30 2009 Tomas Mraz <tmraz@redhat.com> - 5.2p1-5
- do integrity verification only on binaries which are part
  of the OpenSSH FIPS modules

* Mon Apr 20 2009 Tomas Mraz <tmraz@redhat.com> - 5.2p1-4
- log if FIPS mode is initialized
- make aes-ctr cipher modes work in the FIPS mode

* Fri Apr  3 2009 Jan F. Chadima <jchadima@redhat.com> - 5.2p1-3
- fix logging after chroot
- enable non root users to use chroot %%h in internal-sftp

* Fri Mar 13 2009 Tomas Mraz <tmraz@redhat.com> - 5.2p1-2
- add AES-CTR ciphers to the FIPS mode proposal

* Mon Mar  9 2009 Jan F. Chadima <jchadima@redhat.com> - 5.2p1-1
- upgrade to new upstream release

* Thu Feb 26 2009 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 5.1p1-8
- Rebuilt for https://fedoraproject.org/wiki/Fedora_11_Mass_Rebuild

* Thu Feb 12 2009 Tomas Mraz <tmraz@redhat.com> - 5.1p1-7
- drop obsolete triggers
- add testing FIPS mode support
- LSBize the initscript (#247014)

* Fri Jan 30 2009 Tomas Mraz <tmraz@redhat.com> - 5.1p1-6
- enable use of ssl engines (#481100)

* Thu Jan 15 2009 Tomas Mraz <tmraz@redhat.com> - 5.1p1-5
- remove obsolete --with-rsh (#478298)
- add pam_sepermit to allow blocking confined users in permissive mode
  (#471746)
- move system-auth after pam_selinux in the session stack

* Thu Dec 11 2008 Tomas Mraz <tmraz@redhat.com> - 5.1p1-4
- set FD_CLOEXEC on channel sockets (#475866)
- adjust summary
- adjust nss-keys patch so it is applicable without selinux patches (#470859)

* Fri Oct 17 2008 Tomas Mraz <tmraz@redhat.com> - 5.1p1-3
- fix compatibility with some servers (#466818)

* Thu Jul 31 2008 Tomas Mraz <tmraz@redhat.com> - 5.1p1-2
- fixed zero length banner problem (#457326)

* Wed Jul 23 2008 Tomas Mraz <tmraz@redhat.com> - 5.1p1-1
- upgrade to new upstream release
- fixed a problem with public key authentication and explicitely
  specified SELinux role

* Wed May 21 2008 Tomas Mraz <tmraz@redhat.com> - 5.0p1-3
- pass the connection socket to ssh-keysign (#447680)

* Mon May 19 2008 Tomas Mraz <tmraz@redhat.com> - 5.0p1-2
- add LANGUAGE to accepted/sent environment variables (#443231)
- use pam_selinux to obtain the user context instead of doing it itself
- unbreak server keep alive settings (patch from upstream)
- small addition to scp manpage

* Mon Apr  7 2008 Tomas Mraz <tmraz@redhat.com> - 5.0p1-1
- upgrade to new upstream (#441066)
- prevent initscript from killing itself on halt with upstart (#438449)
- initscript status should show that the daemon is running
  only when the main daemon is still alive (#430882)

* Thu Mar  6 2008 Tomas Mraz <tmraz@redhat.com> - 4.7p1-10
- fix race on control master and cleanup stale control socket (#436311)
  patches by David Woodhouse

* Fri Feb 29 2008 Tomas Mraz <tmraz@redhat.com> - 4.7p1-9
- set FD_CLOEXEC on client socket
- apply real fix for window size problem (#286181) from upstream
- apply fix for the spurious failed bind from upstream
- apply open handle leak in sftp fix from upstream

* Tue Feb 12 2008 Dennis Gilmore <dennis@ausil.us> - 4.7p1-8
- we build for sparcv9 now  and it needs -fPIE

* Thu Jan  3 2008 Tomas Mraz <tmraz@redhat.com> - 4.7p1-7
- fix gssapi auth with explicit selinux role requested (#427303) - patch
  by Nalin Dahyabhai

* Tue Dec  4 2007 Tomas Mraz <tmraz@redhat.com> - 4.7p1-6
- explicitly source krb5-devel profile script

* Tue Dec 04 2007 Release Engineering <rel-eng at fedoraproject dot org> - 4.7p1-5
- Rebuild for openssl bump

* Tue Nov 20 2007 Tomas Mraz <tmraz@redhat.com> - 4.7p1-4
- do not copy /etc/localtime into the chroot as it is not
  necessary anymore (#193184)
- call setkeycreatecon when selinux context is established
- test for NULL privk when freeing key (#391871) - patch by
  Pierre Ossman

* Mon Sep 17 2007 Tomas Mraz <tmraz@redhat.com> - 4.7p1-2
- revert default window size adjustments (#286181)

* Thu Sep  6 2007 Tomas Mraz <tmraz@redhat.com> - 4.7p1-1
- upgrade to latest upstream
- use libedit in sftp (#203009)
- fixed audit log injection problem (CVE-2007-3102)

* Thu Aug  9 2007 Tomas Mraz <tmraz@redhat.com> - 4.5p1-8
- fix sftp client problems on write error (#247802)
- allow disabling autocreation of server keys (#235466)

* Wed Jun 20 2007 Tomas Mraz <tmraz@redhat.com> - 4.5p1-7
- experimental NSS keys support
- correctly setup context when empty level requested (#234951)

* Tue Mar 20 2007 Tomas Mraz <tmraz@redhat.com> - 4.5p1-6
- mls level check must be done with default role same as requested

* Mon Mar 19 2007 Tomas Mraz <tmraz@redhat.com> - 4.5p1-5
- make profile.d/gnome-ssh-askpass.* regular files (#226218)

* Thu Feb 27 2007 Tomas Mraz <tmraz@redhat.com> - 4.5p1-4
- reject connection if requested mls range is not obtained (#229278)

* Wed Feb 22 2007 Tomas Mraz <tmraz@redhat.com> - 4.5p1-3
- improve Buildroot
- remove duplicate /etc/ssh from files

* Tue Jan 16 2007 Tomas Mraz <tmraz@redhat.com> - 4.5p1-2
- support mls on labeled networks (#220487)
- support mls level selection on unlabeled networks
- allow / in usernames in scp (only beginning /, ./, and ../ is special) 

* Thu Dec 21 2006 Tomas Mraz <tmraz@redhat.com> - 4.5p1-1
- update to 4.5p1 (#212606)

* Thu Nov 30 2006 Tomas Mraz <tmraz@redhat.com> - 4.3p2-14
- fix gssapi with DNS loadbalanced clusters (#216857)

* Tue Nov 28 2006 Tomas Mraz <tmraz@redhat.com> - 4.3p2-13
- improved pam_session patch so it doesn't regress, the patch is necessary
  for the pam_session_close to be called correctly as uid 0

* Fri Nov 10 2006 Tomas Mraz <tmraz@redhat.com> - 4.3p2-12
- CVE-2006-5794 - properly detect failed key verify in monitor (#214641)

* Thu Nov  2 2006 Tomas Mraz <tmraz@redhat.com> - 4.3p2-11
- merge sshd initscript patches
- kill all ssh sessions when stop is called in halt or reboot runlevel
- remove -TERM option from killproc so we don't race on sshd restart

* Mon Oct  2 2006 Tomas Mraz <tmraz@redhat.com> - 4.3p2-10
- improve gssapi-no-spnego patch (#208102)
- CVE-2006-4924 - prevent DoS on deattack detector (#207957)
- CVE-2006-5051 - don't call cleanups from signal handler (#208459)

* Wed Aug 23 2006 Tomas Mraz <tmraz@redhat.com> - 4.3p2-9
- don't report duplicate syslog messages, use correct local time (#189158)
- don't allow spnego as gssapi mechanism (from upstream)
- fixed memleaks found by Coverity (from upstream)
- allow ip options except source routing (#202856) (patch by HP)

* Tue Aug  8 2006 Tomas Mraz <tmraz@redhat.com> - 4.3p2-8
- drop the pam-session patch from the previous build (#201341)
- don't set IPV6_V6ONLY sock opt when listening on wildcard addr (#201594)

* Thu Jul 20 2006 Tomas Mraz <tmraz@redhat.com> - 4.3p2-7
- dropped old ssh obsoletes
- call the pam_session_open/close from the monitor when privsep is
  enabled so it is always called as root (patch by Darren Tucker)

* Mon Jul 17 2006 Tomas Mraz <tmraz@redhat.com> - 4.3p2-6
- improve selinux patch (by Jan Kiszka)
- upstream patch for buffer append space error (#191940)
- fixed typo in configure.ac (#198986)
- added pam_keyinit to pam configuration (#198628)
- improved error message when askpass dialog cannot grab
  keyboard input (#198332)
- buildrequires xauth instead of xorg-x11-xauth
- fixed a few rpmlint warnings

* Wed Jul 12 2006 Jesse Keating <jkeating@redhat.com> - 4.3p2-5.1
- rebuild

* Fri Apr 14 2006 Tomas Mraz <tmraz@redhat.com> - 4.3p2-5
- don't request pseudoterminal allocation if stdin is not tty (#188983)

* Thu Mar  2 2006 Tomas Mraz <tmraz@redhat.com> - 4.3p2-4
- allow access if audit is not compiled in kernel (#183243)

* Fri Feb 24 2006 Tomas Mraz <tmraz@redhat.com> - 4.3p2-3
- enable the subprocess in chroot to send messages to system log
- sshd should prevent login if audit call fails

* Tue Feb 21 2006 Tomas Mraz <tmraz@redhat.com> - 4.3p2-2
- print error from scp if not remote (patch by Bjorn Augustsson #178923)

* Mon Feb 13 2006 Tomas Mraz <tmraz@redhat.com> - 4.3p2-1
- new version

* Fri Feb 10 2006 Jesse Keating <jkeating@redhat.com> - 4.3p1-2.1
- bump again for double-long bug on ppc(64)

* Mon Feb  6 2006 Tomas Mraz <tmraz@redhat.com> - 4.3p1-2
- fixed another place where syslog was called in signal handler
- pass locale environment variables to server, accept them there (#179851)

* Wed Feb  1 2006 Tomas Mraz <tmraz@redhat.com> - 4.3p1-1
- new version, dropped obsolete patches

* Tue Dec 20 2005 Tomas Mraz <tmraz@redhat.com> - 4.2p1-10
- hopefully make the askpass dialog less confusing (#174765)

* Fri Dec 09 2005 Jesse Keating <jkeating@redhat.com>
- rebuilt

* Tue Nov 22 2005 Tomas Mraz <tmraz@redhat.com> - 4.2p1-9
- drop x11-ssh-askpass from the package
- drop old build_6x ifs from spec file
- improve gnome-ssh-askpass so it doesn't reveal number of passphrase 
  characters to person looking at the display
- less hackish fix for the __USE_GNU problem

* Fri Nov 18 2005 Nalin Dahyabhai <nalin@redhat.com> - 4.2p1-8
- work around missing gccmakedep by wrapping makedepend in a local script
- remove now-obsolete build dependency on "xauth"

* Thu Nov 17 2005 Warren Togami <wtogami@redhat.com> - 4.2p1-7
- xorg-x11-devel -> libXt-devel
- rebuild for new xauth location so X forwarding works
- buildreq audit-libs-devel
- buildreq automake for aclocal
- buildreq imake for xmkmf
-  -D_GNU_SOURCE in flags in order to get it to build
   Ugly hack to workaround openssh defining __USE_GNU which is
   not allowed and causes problems according to Ulrich Drepper
   fix this the correct way after FC5test1

* Wed Nov  9 2005 Jeremy Katz <katzj@redhat.com> - 4.2p1-6
- rebuild against new openssl

* Fri Oct 28 2005 Tomas Mraz <tmraz@redhat.com> 4.2p1-5
- put back the possibility to skip SELinux patch
- add patch for user login auditing by Steve Grubb

* Tue Oct 18 2005 Dan Walsh <dwalsh@redhat.com> 4.2p1-4
- Change selinux patch to use get_default_context_with_rolelevel in libselinux.

* Thu Oct 13 2005 Tomas Mraz <tmraz@redhat.com> 4.2p1-3
- Update selinux patch to use getseuserbyname

* Fri Oct  7 2005 Tomas Mraz <tmraz@redhat.com> 4.2p1-2
- use include instead of pam_stack in pam config
- use fork+exec instead of system in scp - CVE-2006-0225 (#168167)
- upstream patch for displaying authentication errors

* Tue Sep 06 2005 Tomas Mraz <tmraz@redhat.com> 4.2p1-1
- upgrade to a new upstream version

* Tue Aug 16 2005 Tomas Mraz <tmraz@redhat.com> 4.1p1-5
- use x11-ssh-askpass if openssh-askpass-gnome is not installed (#165207)
- install ssh-copy-id from contrib (#88707)

* Wed Jul 27 2005 Tomas Mraz <tmraz@redhat.com> 4.1p1-4
- don't deadlock on exit with multiple X forwarded channels (#152432)
- don't use X11 port which can't be bound on all IP families (#163732)

* Wed Jun 29 2005 Tomas Mraz <tmraz@redhat.com> 4.1p1-3
- fix small regression caused by the nologin patch (#161956)
- fix race in getpeername error checking (mindrot #1054)

* Thu Jun  9 2005 Tomas Mraz <tmraz@redhat.com> 4.1p1-2
- use only pam_nologin for nologin testing

* Mon Jun  6 2005 Tomas Mraz <tmraz@redhat.com> 4.1p1-1
- upgrade to a new upstream version
- call pam_loginuid as a pam session module

* Mon May 16 2005 Tomas Mraz <tmraz@redhat.com> 4.0p1-3
- link libselinux only to sshd (#157678)

* Mon Apr  4 2005 Tomas Mraz <tmraz@redhat.com> 4.0p1-2
- fixed Local/RemoteForward in ssh_config.5 manpage
- fix fatal when Local/RemoteForward is used and scp run (#153258)
- don't leak user validity when using krb5 authentication

* Thu Mar 24 2005 Tomas Mraz <tmraz@redhat.com> 4.0p1-1
- upgrade to 4.0p1
- remove obsolete groups patch

* Wed Mar 16 2005 Elliot Lee <sopwith@redhat.com>
- rebuilt

* Mon Feb 28 2005 Nalin Dahyabhai <nalin@redhat.com> 3.9p1-12
- rebuild so that configure can detect that krb5_init_ets is gone now

* Mon Feb 21 2005 Tomas Mraz <tmraz@redhat.com> 3.9p1-11
- don't call syslog in signal handler
- allow password authentication when copying from remote
  to remote machine (#103364)

* Wed Feb  9 2005 Tomas Mraz <tmraz@redhat.com>
- add spaces to messages in initscript (#138508)

* Tue Feb  8 2005 Tomas Mraz <tmraz@redhat.com> 3.9p1-10
- enable trusted forwarding by default if X11 forwarding is 
  required by user (#137685 and duplicates)
- disable protocol 1 support by default in sshd server config (#88329)
- keep the gnome-askpass dialog above others (#69131)

* Fri Feb  4 2005 Tomas Mraz <tmraz@redhat.com>
- change permissions on pam.d/sshd to 0644 (#64697)
- patch initscript so it doesn't kill opened sessions if
  the sshd daemon isn't running anymore (#67624)

* Mon Jan  3 2005 Bill Nottingham <notting@redhat.com> 3.9p1-9
- don't use initlog

* Mon Nov 29 2004 Thomas Woerner <twoerner@redhat.com> 3.9p1-8.1
- fixed PIE build for all architectures

* Mon Oct  4 2004 Nalin Dahyabhai <nalin@redhat.com> 3.9p1-8
- add a --enable-vendor-patchlevel option which allows a ShowPatchLevel option
  to enable display of a vendor patch level during version exchange (#120285)
- configure with --disable-strip to build useful debuginfo subpackages

* Mon Sep 20 2004 Bill Nottingham <notting@redhat.com> 3.9p1-7
- when using gtk2 for askpass, don't buildprereq gnome-libs-devel

* Tue Sep 14 2004 Nalin Dahyabhai <nalin@redhat.com> 3.9p1-6
- build

* Mon Sep 13 2004 Nalin Dahyabhai <nalin@redhat.com>
- disable ACSS support

* Thu Sep 2 2004 Daniel Walsh <dwalsh@redhat.com> 3.9p1-5
- Change selinux patch to use get_default_context_with_role in libselinux.

* Thu Sep 2 2004 Daniel Walsh <dwalsh@redhat.com> 3.9p1-4
- Fix patch
	* Bad debug statement.
	* Handle root/sysadm_r:kerberos

* Thu Sep 2 2004 Daniel Walsh <dwalsh@redhat.com> 3.9p1-3
- Modify Colin Walter's patch to allow specifying rule during connection

* Tue Aug 31 2004 Daniel Walsh <dwalsh@redhat.com> 3.9p1-2
- Fix TTY handling for SELinux

* Tue Aug 24 2004 Daniel Walsh <dwalsh@redhat.com> 3.9p1-1
- Update to upstream

* Sun Aug 1 2004 Alan Cox <alan@redhat.com> 3.8.1p1-5
- Apply buildreq fixup patch (#125296)

* Tue Jun 15 2004 Daniel Walsh <dwalsh@redhat.com> 3.8.1p1-4
- Clean up patch for upstream submission.

* Tue Jun 15 2004 Elliot Lee <sopwith@redhat.com>
- rebuilt

* Wed Jun 9 2004 Daniel Walsh <dwalsh@redhat.com> 3.8.1p1-2
- Remove use of pam_selinux and patch selinux in directly.  

* Mon Jun  7 2004 Nalin Dahyabhai <nalin@redhat.com> 3.8.1p1-1
- request gssapi-with-mic by default but not delegation (flag day for anyone
  who used previous gssapi patches)
- no longer request x11 forwarding by default

* Thu Jun 3 2004 Daniel Walsh <dwalsh@redhat.com> 3.6.1p2-36
- Change pam file to use open and close with pam_selinux

* Tue Jun  1 2004 Nalin Dahyabhai <nalin@redhat.com> 3.8.1p1-0
- update to 3.8.1p1
- add workaround from CVS to reintroduce passwordauth using pam

* Tue Jun 1 2004 Daniel Walsh <dwalsh@redhat.com> 3.6.1p2-35
- Remove CLOSEXEC on STDERR

* Tue Mar 16 2004 Daniel Walsh <dwalsh@redhat.com> 3.6.1p2-34

* Wed Mar 03 2004 Phil Knirsch <pknirsch@redhat.com> 3.6.1p2-33.30.1
- Built RHLE3 U2 update package.

* Wed Mar 3 2004 Daniel Walsh <dwalsh@redhat.com> 3.6.1p2-33
- Close file descriptors on exec 

* Mon Mar  1 2004 Thomas Woerner <twoerner@redhat.com> 3.6.1p2-32
- fixed pie build

* Thu Feb 26 2004 Daniel Walsh <dwalsh@redhat.com> 3.6.1p2-31
- Add restorecon to startup scripts

* Thu Feb 26 2004 Daniel Walsh <dwalsh@redhat.com> 3.6.1p2-30
- Add multiple qualified to openssh

* Mon Feb 23 2004 Daniel Walsh <dwalsh@redhat.com> 3.6.1p2-29
- Eliminate selinux code and use pam_selinux

* Fri Feb 13 2004 Elliot Lee <sopwith@redhat.com>
- rebuilt

* Mon Jan 26 2004 Daniel Walsh <dwalsh@redhat.com> 3.6.1p2-27
- turn off pie on ppc

* Mon Jan 26 2004 Daniel Walsh <dwalsh@redhat.com> 3.6.1p2-26
- fix is_selinux_enabled

* Wed Jan 14 2004 Daniel Walsh <dwalsh@redhat.com> 3.6.1p2-25
- Rebuild to grab shared libselinux

* Wed Dec 3 2003 Daniel Walsh <dwalsh@redhat.com> 3.6.1p2-24
- turn on selinux

* Tue Nov 18 2003 Nalin Dahyabhai <nalin@redhat.com>
- un#ifdef out code for reporting password expiration in non-privsep
  mode (#83585)

* Mon Nov 10 2003 Nalin Dahyabhai <nalin@redhat.com>
- add machinery to build with/without -fpie/-pie, default to doing so

* Thu Nov 06 2003 David Woodhouse <dwmw2@redhat.com> 3.6.1p2-23
- Don't whinge about getsockopt failing (#109161)

* Fri Oct 24 2003 Nalin Dahyabhai <nalin@redhat.com>
- add missing buildprereq on zlib-devel (#104558)

* Mon Oct 13 2003 Daniel Walsh <dwalsh@redhat.com> 3.6.1p2-22
- turn selinux off

* Mon Oct 13 2003 Daniel Walsh <dwalsh@redhat.com> 3.6.1p2-21.sel
- turn selinux on

* Fri Sep 19 2003 Daniel Walsh <dwalsh@redhat.com> 3.6.1p2-21
- turn selinux off

* Fri Sep 19 2003 Daniel Walsh <dwalsh@redhat.com> 3.6.1p2-20.sel
- turn selinux on

* Fri Sep 19 2003 Nalin Dahyabhai <nalin@redhat.com>
- additional fix for apparently-never-happens double-free in buffer_free()
- extend fix for #103998 to cover SSH1

* Wed Sep 17 2003 Nalin Dahyabhai <nalin@redhat.com> 3.6.1p2-19
- rebuild

* Wed Sep 17 2003 Nalin Dahyabhai <nalin@redhat.com> 3.6.1p2-18
- additional buffer manipulation cleanups from Solar Designer

* Wed Sep 17 2003 Daniel Walsh <dwalsh@redhat.com> 3.6.1p2-17
- turn selinux off

* Wed Sep 17 2003 Daniel Walsh <dwalsh@redhat.com> 3.6.1p2-16.sel
- turn selinux on

* Tue Sep 16 2003 Bill Nottingham <notting@redhat.com> 3.6.1p2-15
- rebuild

* Tue Sep 16 2003 Bill Nottingham <notting@redhat.com> 3.6.1p2-14
- additional buffer manipulation fixes (CAN-2003-0695)

* Tue Sep 16 2003 Daniel Walsh <dwalsh@redhat.com> 3.6.1p2-13.sel
- turn selinux on

* Tue Sep 16 2003 Nalin Dahyabhai <nalin@redhat.com> 3.6.1p2-12
- rebuild

* Tue Sep 16 2003 Nalin Dahyabhai <nalin@redhat.com> 3.6.1p2-11
- apply patch to store the correct buffer size in allocated buffers
  (CAN-2003-0693)
- skip the initial PAM authentication attempt with an empty password if
  empty passwords are not permitted in our configuration (#103998)

* Fri Sep 5 2003 Daniel Walsh <dwalsh@redhat.com> 3.6.1p2-10
- turn selinux off

* Fri Sep 5 2003 Daniel Walsh <dwalsh@redhat.com> 3.6.1p2-9.sel
- turn selinux on

* Tue Aug 26 2003 Daniel Walsh <dwalsh@redhat.com> 3.6.1p2-8
- Add BuildPreReq gtk2-devel if gtk2

* Tue Aug 12 2003 Nalin Dahyabhai <nalin@redhat.com> 3.6.1p2-7
- rebuild

* Tue Aug 12 2003 Nalin Dahyabhai <nalin@redhat.com> 3.6.1p2-6
- modify patch which clears the supplemental group list at startup to only
  complain if setgroups() fails if sshd has euid == 0
- handle krb5 installed in %%{_prefix} or elsewhere by using krb5-config

* Tue Jul 28 2003 Daniel Walsh <dwalsh@redhat.com> 3.6.1p2-5
- Add SELinux patch

* Tue Jul 22 2003 Nalin Dahyabhai <nalin@redhat.com> 3.6.1p2-4
- rebuild

* Wed Jun 16 2003 Nalin Dahyabhai <nalin@redhat.com> 3.6.1p2-3
- rebuild

* Wed Jun 16 2003 Nalin Dahyabhai <nalin@redhat.com> 3.6.1p2-2
- rebuild

* Thu Jun  5 2003 Nalin Dahyabhai <nalin@redhat.com> 3.6.1p2-1
- update to 3.6.1p2

* Wed Jun 04 2003 Elliot Lee <sopwith@redhat.com>
6 rebuilt

* Mon Mar 24 2003 Florian La Roche <Florian.LaRoche@redhat.de>
- add patch for getsockopt() call to work on bigendian 64bit archs

* Fri Feb 14 2003 Nalin Dahyabhai <nalin@redhat.com> 3.5p1-6
- move scp to the -clients subpackage, because it directly depends on ssh
  which is also in -clients (#84329)

* Mon Feb 10 2003 Nalin Dahyabhai <nalin@redhat.com> 3.5p1-5
- rebuild

* Wed Jan 22 2003 Tim Powers <timp@redhat.com>
- rebuilt

* Tue Jan  7 2003 Nalin Dahyabhai <nalin@redhat.com> 3.5p1-3
- rebuild

* Tue Nov 12 2002 Nalin Dahyabhai <nalin@redhat.com> 3.5p1-2
- patch PAM configuration to use relative path names for the modules, allowing
  us to not worry about which arch the modules are built for on multilib systems

* Tue Oct 15 2002 Nalin Dahyabhai <nalin@redhat.com> 3.5p1-1
- update to 3.5p1, merging in filelist/perm changes from the upstream spec

* Fri Oct  4 2002 Nalin Dahyabhai <nalin@redhat.com> 3.4p1-3
- merge

* Thu Sep 12 2002  Than Ngo <than@redhat.com> 3.4p1-2.1
- fix to build on multilib systems

* Thu Aug 29 2002 Curtis Zinzilieta <curtisz@redhat.com> 3.4p1-2gss
- added gssapi patches and uncommented patch here

* Wed Aug 14 2002 Nalin Dahyabhai <nalin@redhat.com> 3.4p1-2
- pull patch from CVS to fix too-early free in ssh-keysign (#70009)

* Thu Jun 27 2002 Nalin Dahyabhai <nalin@redhat.com> 3.4p1-1
- 3.4p1
- drop anon mmap patch

* Tue Jun 25 2002 Nalin Dahyabhai <nalin@redhat.com> 3.3p1-2
- rework the close-on-exit docs
- include configuration file man pages
- make use of nologin as the privsep shell optional

* Mon Jun 24 2002 Nalin Dahyabhai <nalin@redhat.com> 3.3p1-1
- update to 3.3p1
- merge in spec file changes from upstream (remove setuid from ssh, ssh-keysign)
- disable gtk2 askpass
- require pam-devel by filename rather than by package for erratum
- include patch from Solar Designer to work around anonymous mmap failures

* Fri Jun 21 2002 Tim Powers <timp@redhat.com>
- automated rebuild

* Fri Jun  7 2002 Nalin Dahyabhai <nalin@redhat.com> 3.2.3p1-3
- don't require autoconf any more

* Fri May 31 2002 Nalin Dahyabhai <nalin@redhat.com> 3.2.3p1-2
- build gnome-ssh-askpass with gtk2

* Tue May 28 2002 Nalin Dahyabhai <nalin@redhat.com> 3.2.3p1-1
- update to 3.2.3p1
- merge in spec file changes from upstream

* Fri May 17 2002 Nalin Dahyabhai <nalin@redhat.com> 3.2.2p1-1
- update to 3.2.2p1

* Fri May 17 2002 Nalin Dahyabhai <nalin@redhat.com> 3.1p1-4
- drop buildreq on db1-devel
- require pam-devel by package name
- require autoconf instead of autoconf253 again

* Tue Apr  2 2002 Nalin Dahyabhai <nalin@redhat.com> 3.1p1-3
- pull patch from CVS to avoid printing error messages when some of the
  default keys aren't available when running ssh-add
- refresh to current revisions of Simon's patches
 
* Thu Mar 21 2002 Nalin Dahyabhai <nalin@redhat.com> 3.1p1-2gss
- reintroduce Simon's gssapi patches
- add buildprereq for autoconf253, which is needed to regenerate configure
  after applying the gssapi patches
- refresh to the latest version of Markus's patch to build properly with
  older versions of OpenSSL

* Thu Mar  7 2002 Nalin Dahyabhai <nalin@redhat.com> 3.1p1-2
- bump and grind (through the build system)

* Thu Mar  7 2002 Nalin Dahyabhai <nalin@redhat.com> 3.1p1-1
- require sharutils for building (mindrot #137)
- require db1-devel only when building for 6.x (#55105), which probably won't
  work anyway (3.1 requires OpenSSL 0.9.6 to build), but what the heck
- require pam-devel by file (not by package name) again
- add Markus's patch to compile with OpenSSL 0.9.5a (from
  http://bugzilla.mindrot.org/show_bug.cgi?id=141) and apply it if we're
  building for 6.x

* Thu Mar  7 2002 Nalin Dahyabhai <nalin@redhat.com> 3.1p1-0
- update to 3.1p1

* Tue Mar  5 2002 Nalin Dahyabhai <nalin@redhat.com> SNAP-20020305
- update to SNAP-20020305
- drop debug patch, fixed upstream

* Wed Feb 20 2002 Nalin Dahyabhai <nalin@redhat.com> SNAP-20020220
- update to SNAP-20020220 for testing purposes (you've been warned, if there's
  anything to be warned about, gss patches won't apply, I don't mind)

* Wed Feb 13 2002 Nalin Dahyabhai <nalin@redhat.com> 3.0.2p1-3
- add patches from Simon Wilkinson and Nicolas Williams for GSSAPI key
  exchange, authentication, and named key support

* Wed Jan 23 2002 Nalin Dahyabhai <nalin@redhat.com> 3.0.2p1-2
- remove dependency on db1-devel, which has just been swallowed up whole
  by gnome-libs-devel

* Sun Dec 29 2001 Nalin Dahyabhai <nalin@redhat.com>
- adjust build dependencies so that build6x actually works right (fix
  from Hugo van der Kooij)

* Tue Dec  4 2001 Nalin Dahyabhai <nalin@redhat.com> 3.0.2p1-1
- update to 3.0.2p1

* Fri Nov 16 2001 Nalin Dahyabhai <nalin@redhat.com> 3.0.1p1-1
- update to 3.0.1p1

* Tue Nov 13 2001 Nalin Dahyabhai <nalin@redhat.com>
- update to current CVS (not for use in distribution)

* Thu Nov  8 2001 Nalin Dahyabhai <nalin@redhat.com> 3.0p1-1
- merge some of Damien Miller <djm@mindrot.org> changes from the upstream
  3.0p1 spec file and init script

* Wed Nov  7 2001 Nalin Dahyabhai <nalin@redhat.com>
- update to 3.0p1
- update to x11-ssh-askpass 1.2.4.1
- change build dependency on a file from pam-devel to the pam-devel package
- replace primes with moduli

* Thu Sep 27 2001 Nalin Dahyabhai <nalin@redhat.com> 2.9p2-9
- incorporate fix from Markus Friedl's advisory for IP-based authorization bugs

* Thu Sep 13 2001 Bernhard Rosenkraenzer <bero@redhat.com> 2.9p2-8
- Merge changes to rescue build from current sysadmin survival cd

* Thu Sep  6 2001 Nalin Dahyabhai <nalin@redhat.com> 2.9p2-7
- fix scp's server's reporting of file sizes, and build with the proper
  preprocessor define to get large-file capable open(), stat(), etc.
  (sftp has been doing this correctly all along) (#51827)
- configure without --with-ipv4-default on RHL 7.x and newer (#45987,#52247)
- pull cvs patch to fix support for /etc/nologin for non-PAM logins (#47298)
- mark profile.d scriptlets as config files (#42337)
- refer to Jason Stone's mail for zsh workaround for exit-hanging quasi-bug
- change a couple of log() statements to debug() statements (#50751)
- pull cvs patch to add -t flag to sshd (#28611)
- clear fd_sets correctly (one bit per FD, not one byte per FD) (#43221)

* Mon Aug 20 2001 Nalin Dahyabhai <nalin@redhat.com> 2.9p2-6
- add db1-devel as a BuildPrerequisite (noted by Hans Ecke)

* Thu Aug 16 2001 Nalin Dahyabhai <nalin@redhat.com>
- pull cvs patch to fix remote port forwarding with protocol 2

* Thu Aug  9 2001 Nalin Dahyabhai <nalin@redhat.com>
- pull cvs patch to add session initialization to no-pty sessions
- pull cvs patch to not cut off challengeresponse auth needlessly
- refuse to do X11 forwarding if xauth isn't there, handy if you enable
  it by default on a system that doesn't have X installed (#49263)

* Wed Aug  8 2001 Nalin Dahyabhai <nalin@redhat.com>
- don't apply patches to code we don't intend to build (spotted by Matt Galgoci)

* Mon Aug  6 2001 Nalin Dahyabhai <nalin@redhat.com>
- pass OPTIONS correctly to initlog (#50151)

* Wed Jul 25 2001 Nalin Dahyabhai <nalin@redhat.com>
- switch to x11-ssh-askpass 1.2.2

* Wed Jul 11 2001 Nalin Dahyabhai <nalin@redhat.com>
- rebuild in new environment

* Mon Jun 25 2001 Nalin Dahyabhai <nalin@redhat.com>
- disable the gssapi patch

* Mon Jun 18 2001 Nalin Dahyabhai <nalin@redhat.com>
- update to 2.9p2
- refresh to a new version of the gssapi patch

* Thu Jun  7 2001 Nalin Dahyabhai <nalin@redhat.com>
- change Copyright: BSD to License: BSD
- add Markus Friedl's unverified patch for the cookie file deletion problem
  so that we can verify it
- drop patch to check if xauth is present (was folded into cookie patch)
- don't apply gssapi patches for the errata candidate
- clear supplemental groups list at startup

* Fri May 25 2001 Nalin Dahyabhai <nalin@redhat.com>
- fix an error parsing the new default sshd_config
- add a fix from Markus Friedl (via openssh-unix-dev) for ssh-keygen not
  dealing with comments right

* Thu May 24 2001 Nalin Dahyabhai <nalin@redhat.com>
- add in Simon Wilkinson's GSSAPI patch to give it some testing in-house,
  to be removed before the next beta cycle because it's a big departure
  from the upstream version

* Thu May  3 2001 Nalin Dahyabhai <nalin@redhat.com>
- finish marking strings in the init script for translation
- modify init script to source /etc/sysconfig/sshd and pass $OPTIONS to sshd
  at startup (change merged from openssh.com init script, originally by
  Pekka Savola)
- refuse to do X11 forwarding if xauth isn't there, handy if you enable
  it by default on a system that doesn't have X installed

* Wed May  2 2001 Nalin Dahyabhai <nalin@redhat.com>
- update to 2.9
- drop various patches that came from or went upstream or to or from CVS

* Wed Apr 18 2001 Nalin Dahyabhai <nalin@redhat.com>
- only require initscripts 5.00 on 6.2 (reported by Peter Bieringer)

* Sun Apr  8 2001 Preston Brown <pbrown@redhat.com>
- remove explicit openssl requirement, fixes builddistro issue
- make initscript stop() function wait until sshd really dead to avoid 
  races in condrestart

* Mon Apr  2 2001 Nalin Dahyabhai <nalin@redhat.com>
- mention that challengereponse supports PAM, so disabling password doesn't
  limit users to pubkey and rsa auth (#34378)
- bypass the daemon() function in the init script and call initlog directly,
  because daemon() won't start a daemon it detects is already running (like
  open connections)
- require the version of openssl we had when we were built

* Fri Mar 23 2001 Nalin Dahyabhai <nalin@redhat.com>
- make do_pam_setcred() smart enough to know when to establish creds and
  when to reinitialize them
- add in a couple of other fixes from Damien for inclusion in the errata

* Thu Mar 22 2001 Nalin Dahyabhai <nalin@redhat.com>
- update to 2.5.2p2
- call setcred() again after initgroups, because the "creds" could actually
  be group memberships

* Tue Mar 20 2001 Nalin Dahyabhai <nalin@redhat.com>
- update to 2.5.2p1 (includes endianness fixes in the rijndael implementation)
- don't enable challenge-response by default until we find a way to not
  have too many userauth requests (we may make up to six pubkey and up to
  three password attempts as it is)
- remove build dependency on rsh to match openssh.com's packages more closely

* Sat Mar  3 2001 Nalin Dahyabhai <nalin@redhat.com>
- remove dependency on openssl -- would need to be too precise

* Fri Mar  2 2001 Nalin Dahyabhai <nalin@redhat.com>
- rebuild in new environment

* Mon Feb 26 2001 Nalin Dahyabhai <nalin@redhat.com>
- Revert the patch to move pam_open_session.
- Init script and spec file changes from Pekka Savola. (#28750)
- Patch sftp to recognize '-o protocol' arguments. (#29540)

* Thu Feb 22 2001 Nalin Dahyabhai <nalin@redhat.com>
- Chuck the closing patch.
- Add a trigger to add host keys for protocol 2 to the config file, now that
  configuration file syntax requires us to specify it with HostKey if we
  specify any other HostKey values, which we do.

* Tue Feb 20 2001 Nalin Dahyabhai <nalin@redhat.com>
- Redo patch to move pam_open_session after the server setuid()s to the user.
- Rework the nopam patch to use be picked up by autoconf.

* Mon Feb 19 2001 Nalin Dahyabhai <nalin@redhat.com>
- Update for 2.5.1p1.
- Add init script mods from Pekka Savola.
- Tweak the init script to match the CVS contrib script more closely.
- Redo patch to ssh-add to try to adding both identity and id_dsa to also try
  adding id_rsa.

* Fri Feb 16 2001 Nalin Dahyabhai <nalin@redhat.com>
- Update for 2.5.0p1.
- Use $RPM_OPT_FLAGS instead of -O when building gnome-ssh-askpass
- Resync with parts of Damien Miller's openssh.spec from CVS, including
  update of x11 askpass to 1.2.0.
- Only require openssl (don't prereq) because we generate keys in the init
  script now.

* Tue Feb 13 2001 Nalin Dahyabhai <nalin@redhat.com>
- Don't open a PAM session until we've forked and become the user (#25690).
- Apply Andrew Bartlett's patch for letting pam_authenticate() know which
  host the user is attempting a login from.
- Resync with parts of Damien Miller's openssh.spec from CVS.
- Don't expose KbdInt responses in debug messages (from CVS).
- Detect and handle errors in rsa_{public,private}_decrypt (from CVS).

* Wed Feb  7 2001 Trond Eivind Glomsrxd <teg@redhat.com>
- i18n-tweak to initscript.

* Tue Jan 23 2001 Nalin Dahyabhai <nalin@redhat.com>
- More gettextizing.
- Close all files after going into daemon mode (needs more testing).
- Extract patch from CVS to handle auth banners (in the client).
- Extract patch from CVS to handle compat weirdness.

* Fri Jan 19 2001 Nalin Dahyabhai <nalin@redhat.com>
- Finish with the gettextizing.

* Thu Jan 18 2001 Nalin Dahyabhai <nalin@redhat.com>
- Fix a bug in auth2-pam.c (#23877)
- Gettextize the init script.

* Wed Dec 20 2000 Nalin Dahyabhai <nalin@redhat.com>
- Incorporate a switch for using PAM configs for 6.x, just in case.

* Tue Dec  5 2000 Nalin Dahyabhai <nalin@redhat.com>
- Incorporate Bero's changes for a build specifically for rescue CDs.

* Wed Nov 29 2000 Nalin Dahyabhai <nalin@redhat.com>
- Don't treat pam_setcred() failure as fatal unless pam_authenticate() has
  succeeded, to allow public-key authentication after a failure with "none"
  authentication.  (#21268)

* Tue Nov 28 2000 Nalin Dahyabhai <nalin@redhat.com>
- Update to x11-askpass 1.1.1. (#21301)
- Don't second-guess fixpaths, which causes paths to get fixed twice. (#21290)

* Mon Nov 27 2000 Nalin Dahyabhai <nalin@redhat.com>
- Merge multiple PAM text messages into subsequent prompts when possible when
  doing keyboard-interactive authentication.

* Sun Nov 26 2000 Nalin Dahyabhai <nalin@redhat.com>
- Disable the built-in MD5 password support.  We're using PAM.
- Take a crack at doing keyboard-interactive authentication with PAM, and
  enable use of it in the default client configuration so that the client
  will try it when the server disallows password authentication.
- Build with debugging flags.  Build root policies strip all binaries anyway.

* Tue Nov 21 2000 Nalin Dahyabhai <nalin@redhat.com>
- Use DESTDIR instead of %%makeinstall.
- Remove /usr/X11R6/bin from the path-fixing patch.

* Mon Nov 20 2000 Nalin Dahyabhai <nalin@redhat.com>
- Add the primes file from the latest snapshot to the main package (#20884).
- Add the dev package to the prereq list (#19984).
- Remove the default path and mimic login's behavior in the server itself.

* Fri Nov 17 2000 Nalin Dahyabhai <nalin@redhat.com>
- Resync with conditional options in Damien Miller's .spec file for an errata.
- Change libexecdir from %%{_libexecdir}/ssh to %%{_libexecdir}/openssh.

* Tue Nov  7 2000 Nalin Dahyabhai <nalin@redhat.com>
- Update to OpenSSH 2.3.0p1.
- Update to x11-askpass 1.1.0.
- Enable keyboard-interactive authentication.

* Mon Oct 30 2000 Nalin Dahyabhai <nalin@redhat.com>
- Update to ssh-askpass-x11 1.0.3.
- Change authentication related messages to be private (#19966).

* Tue Oct 10 2000 Nalin Dahyabhai <nalin@redhat.com>
- Patch ssh-keygen to be able to list signatures for DSA public key files
  it generates.

* Thu Oct  5 2000 Nalin Dahyabhai <nalin@redhat.com>
- Add BuildPreReq on /usr/include/security/pam_appl.h to be sure we always
  build PAM authentication in.
- Try setting SSH_ASKPASS if gnome-ssh-askpass is installed.
- Clean out no-longer-used patches.
- Patch ssh-add to try to add both identity and id_dsa, and to error only
  when neither exists.

* Mon Oct  2 2000 Nalin Dahyabhai <nalin@redhat.com>
- Update x11-askpass to 1.0.2. (#17835)
- Add BuildPreReqs for /bin/login and /usr/bin/rsh so that configure will
  always find them in the right place. (#17909)
- Set the default path to be the same as the one supplied by /bin/login, but
  add /usr/X11R6/bin. (#17909)
- Try to handle obsoletion of ssh-server more cleanly.  Package names
  are different, but init script name isn't. (#17865)

* Wed Sep  6 2000 Nalin Dahyabhai <nalin@redhat.com>
- Update to 2.2.0p1. (#17835)
- Tweak the init script to allow proper restarting. (#18023)

* Wed Aug 23 2000 Nalin Dahyabhai <nalin@redhat.com>
- Update to 20000823 snapshot.
- Change subpackage requirements from %%{version} to %%{version}-%%{release}
- Back out the pipe patch.

* Mon Jul 17 2000 Nalin Dahyabhai <nalin@redhat.com>
- Update to 2.1.1p4, which includes fixes for config file parsing problems.
- Move the init script back.
- Add Damien's quick fix for wackiness.

* Wed Jul 12 2000 Nalin Dahyabhai <nalin@redhat.com>
- Update to 2.1.1p3, which includes fixes for X11 forwarding and strtok().

* Thu Jul  6 2000 Nalin Dahyabhai <nalin@redhat.com>
- Move condrestart to server postun.
- Move key generation to init script.
- Actually use the right patch for moving the key generation to the init script.
- Clean up the init script a bit.

* Wed Jul  5 2000 Nalin Dahyabhai <nalin@redhat.com>
- Fix X11 forwarding, from mail post by Chan Shih-Ping Richard.

* Sun Jul  2 2000 Nalin Dahyabhai <nalin@redhat.com>
- Update to 2.1.1p2.
- Use of strtok() considered harmful.

* Sat Jul  1 2000 Nalin Dahyabhai <nalin@redhat.com>
- Get the build root out of the man pages.

* Thu Jun 29 2000 Nalin Dahyabhai <nalin@redhat.com>
- Add and use condrestart support in the init script.
- Add newer initscripts as a prereq.

* Tue Jun 27 2000 Nalin Dahyabhai <nalin@redhat.com>
- Build in new environment (release 2)
- Move -clients subpackage to Applications/Internet group

* Fri Jun  9 2000 Nalin Dahyabhai <nalin@redhat.com>
- Update to 2.2.1p1

* Sat Jun  3 2000 Nalin Dahyabhai <nalin@redhat.com>
- Patch to build with neither RSA nor RSAref.
- Miscellaneous FHS-compliance tweaks.
- Fix for possibly-compressed man pages.

* Wed Mar 15 2000 Damien Miller <djm@ibs.com.au>
- Updated for new location
- Updated for new gnome-ssh-askpass build

* Sun Dec 26 1999 Damien Miller <djm@mindrot.org>
- Added Jim Knoble's <jmknoble@pobox.com> askpass

* Mon Nov 15 1999 Damien Miller <djm@mindrot.org>
- Split subpackages further based on patch from jim knoble <jmknoble@pobox.com>

* Sat Nov 13 1999 Damien Miller <djm@mindrot.org>
- Added 'Obsoletes' directives

* Tue Nov 09 1999 Damien Miller <djm@ibs.com.au>
- Use make install
- Subpackages

* Mon Nov 08 1999 Damien Miller <djm@ibs.com.au>
- Added links for slogin
- Fixed perms on manpages

* Sat Oct 30 1999 Damien Miller <djm@ibs.com.au>
- Renamed init script

* Fri Oct 29 1999 Damien Miller <djm@ibs.com.au>
- Back to old binary names

* Thu Oct 28 1999 Damien Miller <djm@ibs.com.au>
- Use autoconf
- New binary names

* Wed Oct 27 1999 Damien Miller <djm@ibs.com.au>
- Initial RPMification, based on Jan "Yenya" Kasprzak's <kas@fi.muni.cz> spec.
