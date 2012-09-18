#
%define _prefix /usr/local/opt
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
%define _includedir         %{_prefix}/include
%define _infodir            %{_prefix}/share/info
%define _mandir             %{_prefix}/share/man
%define _initddir           %{_sysconfdir}/rc.d/init.d
%define _tmppath            %{_var}/tmp
%define _usr                %{_prefix}/usr
%define _usrsrc             %{_prefix}/usr/src

#%define BuildRoot /tmp/%{name}-%{version}
%define __spec_install_post %{nil}

Summary: A web-based administration interface for Unix systems.
Name: dt-webmin
Version: 1.590
Release: 1%{?dist}
Provides: %{name}-%{version}
PreReq: /bin/sh /usr/bin/perl /bin/rm
Requires: /bin/sh /usr/bin/perl /bin/rm
AutoReq: 0
License: Freeware
Group: System/Tools
Source: http://www.webmin.com/download/webmin-%{version}.tar.gz
Vendor: Jamie Cameron
BuildRoot: /tmp/%{name}-%{version}
BuildArchitectures: noarch

Patch99: webmin-dnssec.patch

%description
A web-based administration interface for Unix systems. Using Webmin you can
configure DNS, Samba, NFS, local/remote filesystems and more using your
web browser.

After installation, enter the URL http://localhost:10000/ into your
browser and login as root with your root password.

%prep
%setup -q -n webmin-%{version}

patch99 -p1 -b .dnssec

%build
(find . -name '*.cgi' ; find . -name '*.pl') | perl perlpath.pl /usr/bin/perl -
rm -f mount/freebsd-mounts*
rm -f mount/openbsd-mounts*
rm -f mount/macos-mounts*
rm -f webmin-gentoo-init
rm -rf format bsdexports hpuxexports sgiexports zones rbac
rm -rf acl/Authen-SolarisRBAC-0.1*
chmod -R og-w .

%install
mkdir -p %{buildroot}%{_prefix}/usr/libexec/webmin
mkdir -p %{buildroot}%{_prefix}/etc/sysconfig/daemons
mkdir -p %{buildroot}%{_prefix}/etc/rc.d/{rc0.d,rc1.d,rc2.d,rc3.d,rc5.d,rc6.d}
mkdir -p %{buildroot}%{_prefix}/etc/init.d
mkdir -p %{buildroot}%{_prefix}/etc/pam.d
cp -rp * %{buildroot}%{_prefix}/usr/libexec/webmin
cp webmin-daemon %{buildroot}%{_prefix}/etc/sysconfig/daemons/webmin
cp webmin-init %{buildroot}%{_prefix}/etc/init.d/webmin
cp webmin-pam %{buildroot}%{_prefix}/etc/pam.d/webmin
ln -s /etc/init.d/webmin %{buildroot}%{_prefix}/etc/rc.d/rc2.d/S99webmin
ln -s /etc/init.d/webmin %{buildroot}%{_prefix}/etc/rc.d/rc3.d/S99webmin
ln -s /etc/init.d/webmin %{buildroot}%{_prefix}/etc/rc.d/rc5.d/S99webmin
ln -s /etc/init.d/webmin %{buildroot}%{_prefix}/etc/rc.d/rc0.d/K10webmin
ln -s /etc/init.d/webmin %{buildroot}%{_prefix}/etc/rc.d/rc1.d/K10webmin
ln -s /etc/init.d/webmin %{buildroot}%{_prefix}/etc/rc.d/rc6.d/K10webmin
echo rpm >%{buildroot}%{_prefix}/usr/libexec/webmin/install-type

%clean
#%{rmDESTDIR}
[ "%{buildroot}" != "/" ] && rm -rf %{buildroot}

%files
%defattr(-,root,root)
%{_prefix}/usr/libexec/webmin
%config %{_prefix}/etc/sysconfig/daemons/webmin
%{_prefix}/etc/init.d/webmin
%{_prefix}/etc/rc.d/rc2.d/S99webmin
%{_prefix}/etc/rc.d/rc3.d/S99webmin
%{_prefix}/etc/rc.d/rc5.d/S99webmin
%{_prefix}/etc/rc.d/rc0.d/K10webmin
%{_prefix}/etc/rc.d/rc1.d/K10webmin
%{_prefix}/etc/rc.d/rc6.d/K10webmin
%config %{_prefix}/etc/pam.d/webmin

%pre
perl <<EOD;
# maketemp.pl
# Create the /tmp/.webmin directory if needed

\$tmp_dir = \$ENV{'tempdir'} || "/tmp/.webmin";

while(\$tries++ < 10) {
	local @st = lstat(\$tmp_dir);
	exit(0) if (\$st[4] == \$< && (-d _) && (\$st[2] & 0777) == 0755);
	if (@st) {
		unlink(\$tmp_dir) || rmdir(\$tmp_dir) ||
			system("/bin/rm -rf ".quotemeta(\$tmp_dir));
		}
	mkdir(\$tmp_dir, 0755) || next;
	chown(\$<, \$(, \$tmp_dir);
	chmod(0755, \$tmp_dir);
	}
exit(1);

EOD
if [ "$?" != "0" ]; then
	echo "Failed to create or check temp files directory /tmp/.webmin"
	exit 1
fi
if [ "$tempdir" = "" ]; then
	tempdir=/tmp/.webmin
fi
perl >/$$.check <<EOD;
if (-r "/etc/.issue") {
	\$etc_issue = \`cat /etc/.issue\`;
	}
elsif (-r "/etc/issue") {
	\$etc_issue = \`cat /etc/issue\`;
	}
\$uname = \`uname -a\`;
if (\`cat /etc/pardus-release 2>/dev/null\` =~ /Pardus\\s+1.0\\s+/i) {
	print "oscheck='Pardus Linux'\\n";
	}
elsif (\`cat /etc/pardus-release 2>/dev/null\` =~ /Pardus\\s+2007\\s+/i) {
	print "oscheck='Pardus Linux'\\n";
	}
elsif (\`cat /etc/pardus-release 2>/dev/null\` =~ /Pardus\\s+2007.1\\s+/i) {
	print "oscheck='Pardus Linux'\\n";
	}
elsif (\`cat /etc/pardus-release 2>/dev/null\` =~ /Pardus\\s+2007.2\\s+/i) {
	print "oscheck='Pardus Linux'\\n";
	}
elsif (\`cat /etc/pardus-release 2>/dev/null\` =~ /Pardus\\s+2007.3\\s+/i) {
	print "oscheck='Pardus Linux'\\n";
	}
elsif (\`cat /etc/pardus-release 2>/dev/null\` =~ /Pardus\\s+2008\\s+/i) {
	print "oscheck='Pardus Linux'\\n";
	}
elsif (\`cat /etc/pardus-release 2>/dev/null\` =~ /Pardus\\s+2008.1\\s+/i) {
	print "oscheck='Pardus Linux'\\n";
	}
elsif (\`cat /etc/pardus-release 2>/dev/null\` =~ /Pardus\\s+2008.2\\s+/i) {
	print "oscheck='Pardus Linux'\\n";
	}
elsif (\`cat /etc/pardus-release 2>/dev/null\` =~ /Pardus\\s+2009\\s+/i) {
	print "oscheck='Pardus Linux'\\n";
	}
elsif (\`cat /etc/pardus-release 2>/dev/null\` =~ /Pardus\\s+2009.1\\s+/i) {
	print "oscheck='Pardus Linux'\\n";
	}
elsif (\`cat /etc/pardus-release 2>/dev/null\` =~ /Pardus\\s+2009.2\\s+/i) {
	print "oscheck='Pardus Linux'\\n";
	}
elsif (\`cat /etc/pardus-release 2>/dev/null\` =~ /Pardus\\s+2011\\s+/i) {
	print "oscheck='Pardus Linux'\\n";
	}
elsif (\`cat /etc/pardus-release 2>/dev/null\` =~ /Pardus\\s+2011\\s+/i) {
	print "oscheck='Pardus Linux'\\n";
	}
elsif (\`cat /etc/pardus-release 2>/dev/null\` =~ /Pardus\\s+2011\\s+/i) {
	print "oscheck='Pardus Linux'\\n";
	}
elsif (\$uname =~ /SunOS.*\\s5\\.5\\.1\\s/i) {
	print "oscheck='Sun Solaris'\\n";
	}
elsif (\$uname =~ /SunOS.*\\s5\\.6\\s/i) {
	print "oscheck='Sun Solaris'\\n";
	}
elsif (\$uname =~ /SunOS.*\\s5\\.(\\S+)\\s/i) {
	print "oscheck='Sun Solaris'\\n";
	}
elsif (\$etc_issue =~ /Lycoris Desktop/i) {
	print "oscheck='Lycoris Desktop/LX'\\n";
	}
elsif (\$etc_issue =~ /OpenLinux.*eServer.*\\n.*\\s2\\.3\\s/i) {
	print "oscheck='Caldera OpenLinux eServer'\\n";
	}
elsif (\$etc_issue =~ /OpenLinux.*\\n.*\\s2\\.3\\s/i) {
	print "oscheck='Caldera OpenLinux'\\n";
	}
elsif (\$etc_issue =~ /OpenLinux.*\\n.*\\s2\\.4\\s/i) {
	print "oscheck='Caldera OpenLinux'\\n";
	}
elsif (\$etc_issue =~ /OpenLinux.*\\n.*\\s2\\.5\\s/i || \$etc_issue =~ /Caldera.*2000/i) {
	print "oscheck='Caldera OpenLinux'\\n";
	}
elsif (\$etc_issue =~ /OpenLinux.*3\\.1/i) {
	print "oscheck='Caldera OpenLinux'\\n";
	}
elsif (\$etc_issue =~ /OpenLinux.*3\\.2/i) {
	print "oscheck='Caldera OpenLinux'\\n";
	}
elsif (\`cat /etc/asianux-release 2>/dev/null\` =~ /Asianux\\s+Server\\s+(\\d+)/i) {
	print "oscheck='Asianux Server'\\n";
	}
elsif (\`cat /etc/asianux-release 2>/dev/null\` =~ /Asianux\\s+release\\s+(\\d+\\.\\d+)/i) {
	print "oscheck='Asianux'\\n";
	}
elsif (\`cat /etc/whitebox-release 2>/dev/null\` =~ /White\\s+Box\\s+Enterprise\\s+Linux\\s+release\\s+(\\S+)/i) {
	print "oscheck='Whitebox Linux'\\n";
	}
elsif (\`cat /etc/redhat-release 2>/dev/null\` =~ /Tao\\s+Linux\\s+release\\s+(\\S+)/i) {
	print "oscheck='Tao Linux'\\n";
	}
elsif (\`cat /etc/centos-release /etc/redhat-release 2>/dev/null\` =~ /CentOS\\s+release\\s+(\\S+)/i && \$1 < 4) {
	print "oscheck='CentOS Linux'\\n";
	}
elsif (\`cat /etc/centos-release /etc/redhat-release 2>/dev/null\` =~ /CentOS\\s+(Linux\\s+)?release\\s+(\\S+)/i && \$2 >= 4) {
	print "oscheck='CentOS Linux'\\n";
	}
elsif (\`cat /etc/redhat-release 2>/dev/null\` =~ /Scientific\\s+Linux.*\\s+release\\s+(\\S+)/i && \$1 < 4) {
	print "oscheck='Scientific Linux'\\n";
	}
elsif (\`cat /etc/redhat-release 2>/dev/null\` =~ /Scientific\\s+Linux.*\\s+release\\s+([0-9\\.]+)/i && \$1 >= 4) {
	print "oscheck='Scientific Linux'\\n";
	}
elsif (\`cat /etc/redhtat-release 2>/dev/null\` =~ /Gralinux\\s+(ES|AS|WS)\\s+release\\s+(\\d+)/i) {
	print "oscheck='Gralinux'\\n";
	}
elsif (\`cat /etc/neoshine-release 2>/dev/null\` =~ /NeoShine\\s+Linux.*release\\s+(\\d+)/i) {
	print "oscheck='NeoShine Linux'\\n";
	}
elsif (\`cat /etc/endian-release 2>/dev/null\` =~ /release\\s+(\\S+)/) {
	print "oscheck='Endian Firewall Linux'\\n";
	}
elsif (\`cat /etc/enterprise-release 2>/dev/null\` =~ /Enterprise.*Linux\\s+Enterprise\\s+Linux\\s+Server\\s+release\\s+(\\d+)/i) {
	print "oscheck='Oracle Enterprise Linux'\\n";
	}
elsif (\`cat /etc/ovs-release 2>/dev/null\` =~ /Oracle.*VM\\s+server\\s+release\\s+(\\d+)/i) {
	print "oscheck='Oracle VM'\\n";
	}
elsif (\`cat /etc/redhat-release 2>/dev/null\` =~ /XenServer\\s+release\\s+5\\./) {
	print "oscheck='XenServer Linux'\\n";
	}
elsif (\`cat /etc/redhat-release 2>/dev/null\` =~ /(Advanced\\s+Server.*2\\.1)|(AS.*2\\.1)/i) {
	print "oscheck='Redhat Enterprise Linux'\\n";
	}
elsif (\`cat /etc/redhat-release 2>/dev/null\` =~ /ES.*2\\.1/) {
	print "oscheck='Redhat Enterprise Linux'\\n";
	}
elsif (\`cat /etc/redhat-release 2>/dev/null\` =~ /WS.*2\\.1/) {
	print "oscheck='Redhat Enterprise Linux'\\n";
	}
elsif (\`cat /etc/redhat-release 2>/dev/null\` =~ /(3\\.0AS)|(2\\.9\\.5AS)|(AS\\s+release\\s+3)/i) {
	print "oscheck='Redhat Enterprise Linux'\\n";
	}
elsif (\`cat /etc/redhat-release 2>/dev/null\` =~ /(ES|AS|WS)\\s+release\\s+(\\S+)/) {
	print "oscheck='Redhat Enterprise Linux'\\n";
	}
elsif (\`cat /etc/redhat-release 2>/dev/null\` =~ /Red.*Hat\\s+Enterprise\\s+Linux\\s+(Server|Client|Workstation)\\s+release\\s+(\\d+)/i) {
	print "oscheck='Redhat Enterprise Linux'\\n";
	}
elsif (\`cat /etc/redhat-release 2>/dev/null\` =~ /Desktop\\s+release\\s+(\\S+)/i || \`cat /etc/redhat-release 2>/dev/null\` =~ /ES\\s+release\\s+(\\S+)/i) {
	print "oscheck='Redhat Linux Desktop'\\n";
	}
elsif (\`cat /etc/alphacore-release 2>/dev/null\` =~ /Alpha\\s*Core\\s+release\\s+(\\S+)\\s/i) {
	print "oscheck='AlphaCore Linux'\\n";
	}
elsif (\`cat /etc/redhat-release /etc/fedora-release 2>/dev/null\` =~ /X\\/OS.*release\\s(\\S+)\\s/i) {
	print "oscheck='X/OS Linux'\\n";
	}
elsif (\`cat /etc/Haansoft-release 2>/dev/null\` =~ /Haansoft\\s+Linux\\s+OS\\s+release\\s+(\\S+)/i) {
	print "oscheck='Haansoft Linux'\\n";
	}
elsif (\`cat /etc/caos-release 2>/dev/null\` =~ /release\\s+(\\S+)/i) {
	print "oscheck='cAos Linux'\\n";
	}
elsif (\`cat /etc/wrs-release 2>/dev/null\` =~ /Wind\\s+River\\s+Linux\\s+3\\.0/) {
	print "oscheck='Wind River Linux'\\n";
	}
elsif (\`cat /etc/wrs-release 2>/dev/null\` =~ /Wind\\s+River\\s+Linux\\s+2\\.0/) {
	print "oscheck='Wind River Linux'\\n";
	}
elsif (\`cat /etc/system-release 2>/dev/null\` =~ /Amazon\\s+Linux.*\\s(201[1-9])/) {
	print "oscheck='Amazon Linux'\\n";
	}
elsif (\`cat /etc/redhat-release 2>/dev/null\` =~ /red.*hat.*release\\s+(\\S+)/i && \`cat /etc/redhat-release 2>/dev/null\` !~ /[eE]nterprise|AS|ES|WS|[aA]dvanced/) {
	print "oscheck='Redhat Linux'\\n";
	}
elsif (\`cat /etc/redhat-release /etc/fedora-release 2>/dev/null\` =~ /Fedora.*\\s([0-9\\.]+)\\s/i || \`cat /etc/redhat-release /etc/fedora-release 2>/dev/null\` =~ /Fedora.*\\sFC(\\S+)\\s/i) {
	print "oscheck='Fedora Linux'\\n";
	}
elsif (\`cat /tmp/wd/version 2>/dev/null\` =~ /2\\.1\\.0/) {
	print "oscheck='White Dwarf Linux'\\n";
	}
elsif (\`cat /etc/slamd64-version 2>/dev/null\` =~ /\\s([0-9\\.]+)/) {
	print "oscheck='Slamd64 Linux'\\n";
	}
elsif (\`cat /etc/slackware-version 2>/dev/null\` =~ /Slackware ([0-9\\.]+)/i) {
	print "oscheck='Slackware Linux'\\n";
	}
elsif (\$etc_issue =~ /Xandros.*\\s2\\.0/i) {
	print "oscheck='Xandros Linux'\\n";
	}
elsif (\$etc_issue =~ /Xandros.*\\s3\\.0/i) {
	print "oscheck='Xandros Linux'\\n";
	}
elsif (\$etc_issue =~ /Xandros.*\\s(4\\.\\d+)/i) {
	print "oscheck='Xandros Linux'\\n";
	}
elsif (\$etc_issue =~ /APLINUX.*1\\.3/i) {
	print "oscheck='APLINUX'\\n";
	}
elsif (\`cat /etc/bigblock-revision 2>/dev/null\` =~ /Version:\\s(1[0-9\\.-]+)\\s/i) {
	print "oscheck='BigBlock'\\n";
	}
elsif (\`cat /etc/bigblock-revision 2>/dev/null\` =~ /Version:\\s(2[0-9\\.-]+)\\s/i) {
	print "oscheck='BigBlock'\\n";
	}
elsif (\$etc_issue =~ /Ubuntu.*\\sgutsy/i) {
	print "oscheck='Ubuntu Linux'\\n";
	}
elsif (\$etc_issue =~ /Ubuntu.*\\s(7\\.[0-9\\.]+)\\s/i) {
	print "oscheck='Ubuntu Linux'\\n";
	}
elsif (\$etc_issue =~ /Ubuntu.*\\s(8\\.[0-9\\.]+)\\s/i) {
	print "oscheck='Ubuntu Linux'\\n";
	}
elsif (\$etc_issue =~ /Ubuntu.*\\s(9\\.[0-9\\.]+)\\s/i) {
	print "oscheck='Ubuntu Linux'\\n";
	}
elsif (\$etc_issue =~ /Ubuntu.*\\s(10\\.[0-9\\.]+)\\s/i) {
	print "oscheck='Ubuntu Linux'\\n";
	}
elsif (\$etc_issue =~ /Ubuntu.*\\s(11\\.[0-9\\.]+)\\s/i || \$etc_issue =~ /Ubuntu\\s+natty/i) {
	print "oscheck='Ubuntu Linux'\\n";
	}
elsif (\$etc_issue =~ /Ubuntu.*\\s(12\\.[0-9\\.]+)\\s/i || \$etc_issue =~ /Ubuntu\\s+precise/i) {
	print "oscheck='Ubuntu Linux'\\n";
	}
elsif (\$etc_issue =~ /Ubuntu.*\\s([0-9\\.]+)\\s/i) {
	print "oscheck='Ubuntu Linux'\\n";
	}
elsif (\$etc_issue =~ /MEPIS/ && \`cat /etc/debian_version 2>/dev/null\` =~ /([0-9\\.]+)/) {
	print "oscheck='Mepis Linux'\\n";
	}
elsif (\$etc_issue =~ /MEPIS/ && \`cat /etc/debian_version 2>/dev/null\` =~ /(stable)/) {
	print "oscheck='Mepis Linux'\\n";
	}
elsif (\`cat /etc/lsb-release | grep DISTRIB_DESCRIPTION\` =~ /^DISTRIB_DESCRIPTION="Linux Mint 6 Felicia"/) {
	print "oscheck='Linux Mint  '\\n";
	}
elsif (\`cat /etc/lsb-release | grep DISTRIB_DESCRIPTION\` =~ /^DISTRIB_DESCRIPTION="Linux Mint 7 Gloria"/) {
	print "oscheck='Linux Mint'\\n";
	}
elsif (\`cat /etc/lsb-release | grep DISTRIB_DESCRIPTION\` =~ /^DISTRIB_DESCRIPTION="Linux Mint 8 Helena"/) {
	print "oscheck='Linux Mint'\\n";
	}
elsif (\`cat /etc/lsb-release | grep DISTRIB_DESCRIPTION\` =~ /^DISTRIB_DESCRIPTION="Linux Mint 9 Isadora"/) {
	print "oscheck='Linux Mint'\\n";
	}
elsif (\`cat /etc/lsb-release | grep DISTRIB_DESCRIPTION\` =~ /^DISTRIB_DESCRIPTION="Linux Mint 10 Julia"/) {
	print "oscheck='Linux Mint'\\n";
	}
elsif (\`cat /etc/lsb-release | grep DISTRIB_DESCRIPTION\` =~ /^DISTRIB_DESCRIPTION="Linux Mint 11 Katya"/) {
	print "oscheck='Linux Mint'\\n";
	}
elsif (\`cat /etc/lsb-release | grep DISTRIB_DESCRIPTION\` =~ /^DISTRIB_DESCRIPTION="Linux Mint 12 Lisa"/) {
	print "oscheck='Linux Mint'\\n";
	}
elsif (\$etc_issue =~ /Debian.*\\s([0-9\\.]+)\\s/i || \`cat /etc/debian_version 2>/dev/null\` =~ /([0-9\\.]+)/) {
	print "oscheck='Debian Linux'\\n";
	}
elsif (\`cat /etc/debian_version 2>/dev/null\` =~ /^(hamm)/i) {
	print "oscheck='Debian Linux'\\n";
	}
elsif (\`cat /etc/debian_version 2>/dev/null\` =~ /^(slink)/i) {
	print "oscheck='Debian Linux'\\n";
	}
elsif (\`cat /etc/debian_version 2>/dev/null\` =~ /^(potato)/i) {
	print "oscheck='Debian Linux'\\n";
	}
elsif (\`cat /etc/debian_version 2>/dev/null\` =~ /^(woody)/i) {
	print "oscheck='Debian Linux'\\n";
	}
elsif (\`cat /etc/debian_version 2>/dev/null\` =~ /^(sarge)/i) {
	print "oscheck='Debian Linux'\\n";
	}
elsif (\`cat /etc/debian_version 2>/dev/null\` =~ /^(etch)/i) {
	print "oscheck='Debian Linux'\\n";
	}
elsif (\`cat /etc/debian_version 2>/dev/null\` =~ /^(lenny)/i) {
	print "oscheck='Debian Linux'\\n";
	}
elsif (\`cat /etc/debian_version 2>/dev/null\` =~ /^(squeeze)/i) {
	print "oscheck='Debian Linux'\\n";
	}
elsif (\`cat /etc/debian_version 2>/dev/null\` =~ /^(wheezy)/i) {
	print "oscheck='Debian Linux'\\n";
	}
elsif (\`cat /etc/debian_version 2>/dev/null\` =~ /^(stable)/i) {
	print "oscheck='Debian Linux'\\n";
	}
elsif (\`cat /etc/debian_version 2>/dev/null\` =~ /^(testing)/i) {
	print "oscheck='Debian Linux'\\n";
	}
elsif (\`cat /etc/debian_version 2>/dev/null\` =~ /^(unstable)/i) {
	print "oscheck='Debian Linux'\\n";
	}
elsif (\`cat /etc/debian_version 2>/dev/null\` =~ /^(sid)/i) {
	print "oscheck='Debian Linux'\\n";
	}
elsif (\`cat /etc/SLOX-release 2>/dev/null\` =~ /VERSION\\s+=\\s+(\\S+)/i) {
	print "oscheck='SuSE OpenExchange Linux'\\n";
	}
elsif (\$etc_issue =~ /SuSE\\s+SLES-(\\S+)/i) {
	print "oscheck='SuSE SLES Linux'\\n";
	}
elsif (\`cat /etc/SuSE-release 2>/dev/null\` =~ /([0-9\\.]+)/ || \$etc_issue =~ /SuSE\\s+Linux\\s+(\\S+)\\s/i) {
	print "oscheck='SuSE Linux'\\n";
	}
elsif (\`cat /etc/UnitedLinux-release 2>/dev/null\` =~ /([0-9\\.]+)/) {
	print "oscheck='United Linux'\\n";
	}
elsif (\$etc_issue =~ /Corel\\s+LINUX\\s+(\\S+)/i) {
	print "oscheck='Corel Linux'\\n";
	}
elsif (\`cat /etc/turbolinux-release 2>/dev/null\` =~ /([0-9\\.]+)/i) {
	print "oscheck='TurboLinux'\\n";
	}
elsif (\$etc_issue =~ /Cobalt\\s+Linux\\s+release\\s+(\\S+)/i || \`cat /etc/cobalt-release 2>/dev/null\` =~ /([0-9\\.]+)/) {
	print "oscheck='Cobalt Linux'\\n";
	}
elsif (\`uname -r\` =~ /2.2.16/ && -r "/etc/cobalt-release") {
	print "oscheck='Cobalt Linux'\\n";
	}
elsif (\$etc_issue =~ /Mandrake\\s+Corporate\\s+Server\\s+release\\s+1\\.0/i) {
	print "oscheck='Mandrake Linux Corporate Server'\\n";
	}
elsif (\`cat /etc/mandrake-release 2>/dev/null\` =~ /pclinuxos\\s+Linux\\s+release\\s+2005/i) {
	print "oscheck='pclinuxos Linux'\\n";
	}
elsif (\`cat /etc/mandrake-release 2>/dev/null\` =~ /pclinuxos\\s+Linux\\s+release\\s+2006/i) {
	print "oscheck='pclinuxos Linux'\\n";
	}
elsif (\`cat /etc/mandrake-release 2>/dev/null\` =~ /PCLinuxOS\\s+release\\s+2007/i) {
	print "oscheck='pclinuxos Linux'\\n";
	}
elsif (\`cat /etc/mandrake-release 2>/dev/null\` =~ /PCLinuxOS\\s+release\\s+2008/i) {
	print "oscheck='pclinuxos Linux'\\n";
	}
elsif (\`cat /etc/mandrake-release 2>/dev/null\` =~ /PCLinuxOS\\s+release\\s+2009/i) {
	print "oscheck='pclinuxos Linux'\\n";
	}
elsif (\$etc_issue =~ /Mandrake\\s+release\\s+5\\.3/i) {
	print "oscheck='Mandrake Linux'\\n";
	}
elsif (\$etc_issue =~ /Mandrake\\s+release\\s+6\\.0/i) {
	print "oscheck='Mandrake Linux'\\n";
	}
elsif (\$etc_issue =~ /Mandrake\\s+release\\s+6\\.1/i) {
	print "oscheck='Mandrake Linux'\\n";
	}
elsif (\$etc_issue =~ /Mandrake\\s+release\\s+7\\.0/i) {
	print "oscheck='Mandrake Linux'\\n";
	}
elsif (\$etc_issue =~ /Mandrake\\s+release\\s+7\\.1/i) {
	print "oscheck='Mandrake Linux'\\n";
	}
elsif (\`cat /etc/mandrake-release 2>/dev/null\` =~ /Mandrake.*?([0-9\\.]+)/i || \$etc_issue =~ /Mandrake\\s+release\\s+([0-9\\.]+)/i || \$etc_issue =~ /Mandrakelinux\\s+release\\s+([0-9\\.]+)/i) {
	print "oscheck='Mandrake Linux'\\n";
	}
elsif (\$etc_issue =~ /(Mandrakelinux|Mandriva).*(2006\\.\\d+)/i || \`cat /etc/mandrake-release 2>/dev/null\` =~ /(Mandrakelinux|Mandriva).*(2007\\.\\d+)/i) {
	print "oscheck='Mandriva Linux'\\n";
	}
elsif (\$etc_issue =~ /(Mandrakelinux|Mandriva).*(2007\\.\\d+)/i || \`cat /etc/mandrake-release 2>/dev/null\` =~ /(Mandrakelinux|Mandriva).*(2007\\.\\d+)/i) {
	print "oscheck='Mandriva Linux'\\n";
	}
elsif (\$etc_issue =~ /(Mandrakelinux|Mandriva).*(2008\\.\\d+)/i || \`cat /etc/mandrake-release 2>/dev/null\` =~ /(Mandrakelinux|Mandriva).*(2008\\.\\d+)/i) {
	print "oscheck='Mandriva Linux'\\n";
	}
elsif (\$etc_issue =~ /(Mandrakelinux|Mandriva).*(2009\\.\\d+)/i || \`cat /etc/mandrake-release 2>/dev/null\` =~ /(Mandrakelinux|Mandriva).*(2009\\.\\d+)/i) {
	print "oscheck='Mandriva Linux'\\n";
	}
elsif (\$etc_issue =~ /(Mandriva).*(20\\d\\d\\.\\d+)/i || \`cat /etc/mandriva-release 2>/dev/null\` =~ /(Mandriva).*(20\\d\\d\\.\\d+)/i) {
	print "oscheck='Mandriva Linux'\\n";
	}
elsif (\$etc_issue =~ /Mandrake\\s+Linux\\s+Corporate\\s+Server\\s+release\\s+([0-9\\.]+)/i) {
	print "oscheck='Mandrake Linux Corporate Server'\\n";
	}
elsif (\$etc_issue =~ /Mandriva\\s+Linux\\s+Enterprise\\s+Server\\s+release\\s+5\\.0\\s+\\(Official\\)\\s+for\\s+(i586|x86_64)/i) {
	print "oscheck='Mandriva Linux Enterprise Server'\\n";
	}
elsif (\$etc_issue =~ /Conectiva.*Linux.*3\\.0/i) {
	print "oscheck='Conectiva Linux'\\n";
	}
elsif (\$etc_issue =~ /Conectiva.*Linux.*4\\.0/i) {
	print "oscheck='Conectiva Linux'\\n";
	}
elsif (\$etc_issue =~ /Conectiva.*Linux.*4\\.1/i) {
	print "oscheck='Conectiva Linux'\\n";
	}
elsif (\$etc_issue =~ /Conectiva.*Linux.*4\\.2/i) {
	print "oscheck='Conectiva Linux'\\n";
	}
elsif (\$etc_issue =~ /Conectiva.*Linux.*5\\.0/i) {
	print "oscheck='Conectiva Linux'\\n";
	}
elsif (\$etc_issue =~ /Conectiva.*Linux.*5\\.1/i) {
	print "oscheck='Conectiva Linux'\\n";
	}
elsif (\$etc_issue =~ /Conectiva.*Linux.*6\\.0/i) {
	print "oscheck='Conectiva Linux'\\n";
	}
elsif (\$etc_issue =~ /Conectiva.*Linux.*7\\.0/i) {
	print "oscheck='Conectiva Linux'\\n";
	}
elsif (\$etc_issue =~ /Conectiva.*Linux.*\\s8/i) {
	print "oscheck='Conectiva Linux'\\n";
	}
elsif (\$etc_issue =~ /Conectiva.*Linux.*\\s9/i) {
	print "oscheck='Conectiva Linux'\\n";
	}
elsif (\$etc_issue =~ /Conectiva.*Linux.*\\s10\\s/i) {
	print "oscheck='Conectiva Linux'\\n";
	}
elsif (\$etc_issue =~ /Thiz.*Linux.*\\s5\\.0/i) {
	print "oscheck='ThizLinux Desktop'\\n";
	}
elsif (\$etc_issue =~ /Thiz.*Linux.*\\s6\\.0/i) {
	print "oscheck='ThizLinux Desktop'\\n";
	}
elsif (\$etc_issue =~ /Thiz.*Linux.*\\s6\\.2/i) {
	print "oscheck='ThizLinux Desktop'\\n";
	}
elsif (\$etc_issue =~ /Thiz.*Linux.*\\s7\\.0/i) {
	print "oscheck='ThizLinux Desktop'\\n";
	}
elsif (\$etc_issue =~ /Thiz.*\\s?Server.*\\s4\\.3/i) {
	print "oscheck='ThizServer'\\n";
	}
elsif (\$etc_issue =~ /Thiz.*\\s?Server.*\\s6\\.0/i) {
	print "oscheck='ThizServer'\\n";
	}
elsif (\$etc_issue =~ /Thiz.*\\s?Server.*\\s7\\.0/i) {
	print "oscheck='ThizServer'\\n";
	}
elsif (\`cat /etc/msclinux-release 2>/dev/null\` =~ /2001.*January/i || \$etc_issue =~ /2001.*January/i) {
	print "oscheck='MSC Linux'\\n";
	}
elsif (\`cat /etc/msclinux-release 2>/dev/null\` =~ /2001.*February/i || \$etc_issue =~ /2001.*February/i) {
	print "oscheck='MSC Linux'\\n";
	}
elsif (\`cat /etc/msclinux-release 2>/dev/null\` =~ /2001.*May/i || \$etc_issue =~ /2001.*May/i) {
	print "oscheck='MSC Linux'\\n";
	}
elsif (\`cat /etc/msclinux-release 2>/dev/null\` =~ /2001.*June/i || \$etc_issue =~ /2001.*June/i) {
	print "oscheck='MSC Linux'\\n";
	}
elsif (\`cat /etc/msclinux-release 2>/dev/null\` =~ /2001.*August/i || \$etc_issue =~ /2001.*August/i) {
	print "oscheck='MSC Linux'\\n";
	}
elsif (\`cat /etc/msclinux-release 2>/dev/null\` =~ /2002.*February/i || \$etc_issue =~ /2002.*February/i) {
	print "oscheck='MSC Linux'\\n";
	}
elsif (\`cat /etc/msclinux-release 2>/dev/null\` =~ /2002.*March/i || \$etc_issue =~ /2002.*March/i) {
	print "oscheck='MSC Linux'\\n";
	}
elsif (\`cat /etc/msclinux-release 2>/dev/null\` =~ /2002.*May/i || \$etc_issue =~ /2002.*May/i) {
	print "oscheck='MSC Linux'\\n";
	}
elsif (\`cat /etc/msclinux-release 2>/dev/null\` =~ /2002.*July/i || \$etc_issue =~ /2002.*July/i) {
	print "oscheck='MSC Linux'\\n";
	}
elsif (\`cat /etc/msclinux-release 2>/dev/null\` =~ /2002.*Nov/i || \$etc_issue =~ /2002.*Nov/i) {
	print "oscheck='MSC Linux'\\n";
	}
elsif (\`cat /etc/scilinux-relase 2>/dev/null\` =~ /2003.*Summer/i) {
	print "oscheck='SCI Linux'\\n";
	}
elsif (\`cat /etc/scilinux-relase 2>/dev/null\` =~ /2004.*Summer/i) {
	print "oscheck='SCI Linux'\\n";
	}
elsif (\`cat /etc/scilinux-relase 2>/dev/null\` =~ /2005.*Summer/i) {
	print "oscheck='SCI Linux'\\n";
	}
elsif (\$etc_issue =~ /LinuxPPC\\s+2000/i) {
	print "oscheck='LinuxPPC'\\n";
	}
elsif (\$etc_issue =~ /Trustix.*Enterprise.*([0-9\\.]+)/i) {
	print "oscheck='Trustix SE'\\n";
	}
elsif (\$etc_issue =~ /Trustix.*1\\.1/i) {
	print "oscheck='Trustix'\\n";
	}
elsif (\$etc_issue =~ /Trustix.*1\\.2/i) {
	print "oscheck='Trustix'\\n";
	}
elsif (\$etc_issue =~ /Trustix.*1\\.5/i) {
	print "oscheck='Trustix'\\n";
	}
elsif (\$etc_issue =~ /Trustix.*\\s([0-9\\.]+)/i) {
	print "oscheck='Trustix'\\n";
	}
elsif (\$etc_issue =~ /Tawie\\s+Server\\s+Linux.*([0-9\\.]+)/i) {
	print "oscheck='Tawie Server Linux'\\n";
	}
elsif (\$etc_issue =~ /tinysofa.*release\\s+1\\.0/i) {
	print "oscheck='TinySofa Linux'\\n";
	}
elsif (\`cat /etc/tinysofa-release 2>/dev/null\` =~ /classic.*release\\s+2\\.0/i) {
	print "oscheck='TinySofa Linux'\\n";
	}
elsif (\`cat /etc/tinysofa-release 2>/dev/null\` =~ /enterprise.*release\\s+2\\.0/i) {
	print "oscheck='TinySofa Linux'\\n";
	}
elsif (\$etc_issue =~ /Cendio\\s*LBS.*\\s3\\.1/i || \`cat /etc/lbs-release 2>/dev/null\` =~ /3\\.1/) {
	print "oscheck='Cendio LBS Linux'\\n";
	}
elsif (\$etc_issue =~ /Cendio\\s*LBS.*\\s3\\.2/i || \`cat /etc/lbs-release 2>/dev/null\` =~ /3\\.2/) {
	print "oscheck='Cendio LBS Linux'\\n";
	}
elsif (\$etc_issue =~ /Cendio\\s*LBS.*\\s3\\.3/i || \`cat /etc/lbs-release 2>/dev/null\` =~ /3\\.3/) {
	print "oscheck='Cendio LBS Linux'\\n";
	}
elsif (\$etc_issue =~ /Cendio\\s*LBS.*\\s4\\.0/i || \`cat /etc/lbs-release 2>/dev/null\` =~ /4\\.0/) {
	print "oscheck='Cendio LBS Linux'\\n";
	}
elsif (\$etc_issue =~ /Cendio\\s*LBS.*\\s4\\.1/i || \`cat /etc/lbs-release 2>/dev/null\` =~ /4\\.1/) {
	print "oscheck='Cendio LBS Linux'\\n";
	}
elsif (\`cat /etc/ute-release 2>/dev/null\` =~ /Ute\\s+Linux\\s+release\\s+1\\.0/i) {
	print "oscheck='Ute Linux'\\n";
	}
elsif (\$etc_issue =~ /Lanthan\\s+Linux\\s+release\\s+1\\.0/i || \`cat /etc/lanthan-release 2>/dev/null\` =~ /1\\.0/) {
	print "oscheck='Lanthan Linux'\\n";
	}
elsif (\$etc_issue =~ /Lanthan\\s+Linux\\s+release\\s+2\\.0/i || \`cat /etc/lanthan-release 2>/dev/null\` =~ /2\\.0/) {
	print "oscheck='Lanthan Linux'\\n";
	}
elsif (\$etc_issue =~ /Lanthan\\s+Linux\\s+release\\s+3\\.0/i || \`cat /etc/lanthan-release 2>/dev/null\` =~ /3\\.0/) {
	print "oscheck='Lanthan Linux'\\n";
	}
elsif (\$etc_issue =~ /Yellow\\s+Dog\\s+Linux\\s+release\\s+2\\.0\\s+/i || \`cat /etc/yellowdog-release 2>/dev/null\` =~ /Yellow\\s+Dog\\s+Linux\\s+release\\s+2\\.0\\s+/i) {
	print "oscheck='Yellow Dog Linux'\\n";
	}
elsif (\$etc_issue =~ /Yellow\\s+Dog\\s+Linux\\s+release\\s+2\\.1\\s+/i || \`cat /etc/yellowdog-release 2>/dev/null\` =~ /Yellow\\s+Dog\\s+Linux\\s+release\\s+2\\.1\\s+/i) {
	print "oscheck='Yellow Dog Linux'\\n";
	}
elsif (\$etc_issue =~ /Yellow\\s+Dog\\s+Linux\\s+release\\s+2\\.2\\s+/i || \`cat /etc/yellowdog-release 2>/dev/null\` =~ /Yellow\\s+Dog\\s+Linux\\s+release\\s+2\\.2\\s+/i) {
	print "oscheck='Yellow Dog Linux'\\n";
	}
elsif (\$etc_issue =~ /Yellow\\s+Dog\\s+Linux\\s+release\\s+2\\.3\\s+/i || \`cat /etc/yellowdog-release 2>/dev/null\` =~ /Yellow\\s+Dog\\s+Linux\\s+release\\s+2\\.3\\s+/i) {
	print "oscheck='Yellow Dog Linux'\\n";
	}
elsif (\$etc_issue =~ /Yellow\\s+Dog\\s+Linux\\s+release\\s+3\\.0\\s+/i || \`cat /etc/yellowdog-release 2>/dev/null\` =~ /Yellow\\s+Dog\\s+Linux\\s+release\\s+3\\.0\\s+/i) {
	print "oscheck='Yellow Dog Linux'\\n";
	}
elsif (\$etc_issue =~ /Yellow\\s+Dog\\s+Linux\\s+release\\s+4\\.0\\s+/i || \`cat /etc/yellowdog-release 2>/dev/null\` =~ /\\s4\\.0\\s/i) {
	print "oscheck='Yellow Dog Linux'\\n";
	}
elsif (\`cat /etc/latinux-release 2>/dev/null\` =~ /Latinux\\s+8\\s/i) {
	print "oscheck='Corvus Latinux'\\n";
	}
elsif (\$etc_issue =~ /Immunix.*\\s([0-9\\.]+)/i || \`cat /etc/immunix-release 2>/dev/null\` =~ /([0-9\\.]+)/) {
	print "oscheck='Immunix Linux'\\n";
	}
elsif (-d "/usr/portage") {
	print "oscheck='Gentoo Linux'\\n";
	}
elsif (\`cat /etc/securelinux-release 2>/dev/null\` =~ /SecureLinux.*1\\.0/i) {
	print "oscheck='Secure Linux'\\n";
	}
elsif (\`cat /etc/openna-release 2>/dev/null\` =~ /release\\s+1\\.0\\s/i) {
	print "oscheck='OpenNA Linux'\\n";
	}
elsif (\`cat /etc/openna-release 2>/dev/null\` =~ /release\\s+2\\.0\\s/i) {
	print "oscheck='OpenNA Linux'\\n";
	}
elsif (-r "/etc/antitachyon-distribution" && \`uname -r\` =~ /2\\.4\\./) {
	print "oscheck='SoL Linux'\\n";
	}
elsif (-r "/etc/antitachyon-distribution" && \`uname -r\` =~ /2\\.6\\./) {
	print "oscheck='SoL Linux'\\n";
	}
elsif (\$etc_issue =~ /coherent\\s*technology.*\\s([0-9\\.]+)/i || \`cat /etc/coherent-release 2>/dev/null\` =~ /([0-9\\.]+)/ ) {
	print "oscheck='Coherent Technology Linux'\\n";
	}
elsif (\$etc_issue =~ /PS2\\s+Linux\\s+release\\s+1.0/i) {
	print "oscheck='Playstation Linux'\\n";
	}
elsif (\`cat /etc/startcom-release 2>/dev/null\` =~ /([0-9\\.]+)/) {
	print "oscheck='StartCom Linux'\\n";
	}
elsif (\`cat /etc/yoper-release 2>/dev/null\` =~ /Yoper\\s+Linux\\s+2.0/i) {
	print "oscheck='Yoper Linux'\\n";
	}
elsif (\`cat /etc/yoper-release 2>/dev/null\` =~ /Yoper\\s+Linux\\s+2.1/i) {
	print "oscheck='Yoper Linux'\\n";
	}
elsif (\`cat /etc/yoper-release 2>/dev/null\` =~ /Yoper\\s+Linux\\s+2.2/i) {
	print "oscheck='Yoper Linux'\\n";
	}
elsif (\`cat /etc/CxM-release 2>/dev/null\` =~ /8\\.1/ || \$etc_issue =~ /Caixa\\s+8\\.1\\s/i) {
	print "oscheck='Caixa Magica'\\n";
	}
elsif (\`cat /etc/CxM-release 2>/dev/null\` =~ /10\\.0/ || \$etc_issue =~ /Caixa\\s+10\\.0\\s/i) {
	print "oscheck='Caixa Magica'\\n";
	}
elsif (\`cat /etc/openmamba-release 2>/dev/null\` =~ /openmamba\\s+release\\s+(\\S+)/i) {
	print "oscheck='openmamba Linux'\\n";
	}
elsif (\$uname =~ /FreeBSD.*?\\s([0-9]+\\.[0-9\\.]+)/i) {
	print "oscheck='FreeBSD'\\n";
	}
elsif (\$uname =~ /DragonFly.*?\\s1\\.0A/i) {
	print "oscheck='DragonFly BSD'\\n";
	}
elsif (\$uname =~ /DragonFly.*?\\s1\\.2A/i) {
	print "oscheck='DragonFly BSD'\\n";
	}
elsif (\$uname =~ /OpenBSD.*?\\s([0-9\\.]+)/i) {
	print "oscheck='OpenBSD'\\n";
	}
elsif (\$uname =~ /NetBSD.*1\\.5/i) {
	print "oscheck='NetBSD'\\n";
	}
elsif (\$uname =~ /NetBSD.*1\\.6/i) {
	print "oscheck='NetBSD'\\n";
	}
elsif (\$uname =~ /NetBSD.*2\\.0/i) {
	print "oscheck='NetBSD'\\n";
	}
elsif (\$uname =~ /NetBSD.*3\\.0/i) {
	print "oscheck='NetBSD'\\n";
	}
elsif (\$uname =~ /NetBSD.*4\\.0/i) {
	print "oscheck='NetBSD'\\n";
	}
elsif (\`uname\` =~ /NetBSD/ && \`uname -r\` =~ /([\\d.]+)/) {
	print "oscheck='NetBSD'\\n";
	}
elsif (\$uname =~ /BSDI.*\\s([0-9\\.]+)/i) {
	print "oscheck='BSDI'\\n";
	}
elsif (\$uname =~ /HP-UX.*(1[01]\\.[0-9\\.]+)/) {
	print "oscheck='HP/UX'\\n";
	}
elsif (\$uname =~ /IRIX.*([0-9]+\\.[0-9]+)/i) {
	print "oscheck='SGI Irix'\\n";
	}
elsif (\$uname =~ /OSF1.*4\\.0/) {
	print "oscheck='DEC/Compaq OSF/1'\\n";
	}
elsif (\$uname =~ /OSF1.*V5.1/) {
	print "oscheck='DEC/Compaq OSF/1'\\n";
	}
elsif (\$uname =~ /AIX\\s+\\S+\\s+(\\d+)\\s+(\\d+)\\s+/i) {
	print "oscheck='IBM AIX'\\n";
	}
elsif (\$uname =~ /SCO_SV.*\\s5\\./i) {
	print "oscheck='SCO OpenServer'\\n";
	}
elsif (\$uname =~ /SCO_SV.*\\s6\\./i) {
	print "oscheck='SCO OpenServer'\\n";
	}
elsif (\`sw_vers 2>/dev/null\` =~ /ProductVersion:\\s+10\\.0/i) {
	print "oscheck='Mac OS X'\\n";
	}
elsif (\`sw_vers 2>/dev/null\` =~ /ProductVersion:\\s+10\\.1/i) {
	print "oscheck='Mac OS X'\\n";
	}
elsif (\`sw_vers 2>/dev/null\` =~ /ProductVersion:\\s+10\\.2/i) {
	print "oscheck='Mac OS X'\\n";
	}
elsif (\`sw_vers 2>/dev/null\` =~ /ProductVersion:\\s+10\\.3/i) {
	print "oscheck='Mac OS X'\\n";
	}
elsif (\`sw_vers 2>/dev/null\` =~ /ProductVersion:\\s+10\\.4/i) {
	print "oscheck='Mac OS X'\\n";
	}
elsif (\`sw_vers 2>/dev/null\` =~ /ProductVersion:\\s+10\\.5/i) {
	print "oscheck='Mac OS X'\\n";
	}
elsif (\`sw_vers 2>/dev/null\` =~ /ProductVersion:\\s+10\\.6/i) {
	print "oscheck='Mac OS X'\\n";
	}
elsif (\`sw_vers 2>/dev/null\` =~ /ProductVersion:\\s+10\\.7/i) {
	print "oscheck='Mac OS X'\\n";
	}
elsif (\`sw_vers 2>/dev/null\` =~ /ProductVersion:\\s+10\\.8/i) {
	print "oscheck='Mac OS X'\\n";
	}
elsif (\$uname =~ /Darwin.*\\s([0-9\\.]+)/) {
	print "oscheck='Darwin'\\n";
	}
elsif (\`cat /etc/SuSE-release 2>/dev/null\` =~ /Java Desktop System.*\\nVERSION = 1\\.0/i) {
	print "oscheck='Sun Java Desktop System'\\n";
	}
elsif (\`cat /etc/SuSE-release 2>/dev/null\` =~ /Java Desktop System.*\\nVERSION = 2\\.0/i) {
	print "oscheck='Sun Java Desktop System'\\n";
	}
elsif (\`cat /etc/SuSE-release 2>/dev/null\` =~ /Java Desktop System.*\\nVERSION = 3\\.0/i) {
	print "oscheck='Sun Java Desktop System'\\n";
	}
elsif (\$uname =~ /SunOS.*\\s5\\.9\\s/i && \`cat /etc/sun-release 2>/dev/null\` =~ /Sun\\s+Java\\s+Desktop/) {
	print "oscheck='Sun Java Desktop System'\\n";
	}
elsif (\`uname -r\` =~ /2\\.0\\./) {
	print "oscheck='Generic Linux'\\n";
	}
elsif (\`uname -r\` =~ /2\\.2\\./) {
	print "oscheck='Generic Linux'\\n";
	}
elsif (\`uname -r\` =~ /2\\.4\\./) {
	print "oscheck='Generic Linux'\\n";
	}
elsif (\`uname -r\` =~ /2\\.4\\./) {
	print "oscheck='Generic Linux'\\n";
	}
elsif (\`uname -r\` =~ /2\\.6\\./) {
	print "oscheck='Generic Linux'\\n";
	}
elsif (\`uname -r\` =~ /2\\.7\\./) {
	print "oscheck='Generic Linux'\\n";
	}
elsif (\`uname -r\` =~ /3\\.0\\./) {
	print "oscheck='Generic Linux'\\n";
	}
elsif (\`uname -r\` =~ /3\\.1\\./) {
	print "oscheck='Generic Linux'\\n";
	}
elsif (\`uname -r\` =~ /3\\.2\\./) {
	print "oscheck='Generic Linux'\\n";
	}
elsif (\`uname -r\` =~ /3\\.3\\./) {
	print "oscheck='Generic Linux'\\n";
	}
elsif (\`uname -r\` =~ /3\\.4\\./) {
	print "oscheck='Generic Linux'\\n";
	}
elsif (\`uname -r\` =~ /3\\.5\\./) {
	print "oscheck='Generic Linux'\\n";
	}
elsif ((-d "c:/windows" || -d "c:/winnt") && \`ver\` =~ /XP/) {
	print "oscheck='Windows'\\n";
	}
elsif ((-d "c:/windows" || -d "c:/winnt") && \`ver\` =~ /2000/) {
	print "oscheck='Windows'\\n";
	}
elsif ((-d "c:/windows" || -d "c:/winnt") && \`ver\` =~ /2003|\\s5\\.2/) {
	print "oscheck='Windows'\\n";
	}
elsif ((-d "c:/windows" || -d "c:/winnt") && \`ver\` =~ /\\s6\\.0\\.6001/) {
	print "oscheck='Windows'\\n";
	}
elsif ((-d "c:/windows" || -d "c:/winnt") && \`ver\` =~ /\\s6\\.0\\.6002/) {
	print "oscheck='Windows'\\n";
	}
elsif ((-d "c:/windows" || -d "c:/winnt") && \`ver\` =~ /\\s6\\.0\\.76[0-9][0-9]/) {
	print "oscheck='Windows'\\n";
	}

EOD
. /$$.check
rm -f /$$.check
if [ ! -r %{_prefix}/etc/webmin/config ]; then
	if [ "$oscheck" = "" ]; then
		echo Unable to identify operating system
		exit 2
	fi
	echo Operating system is $oscheck
	if [ "$WEBMIN_PORT" != "" ]; then
		port=$WEBMIN_PORT
	else
		port=10000
	fi
	perl -e 'use Socket; socket(FOO, PF_INET, SOCK_STREAM, getprotobyname("tcp")); setsockopt(FOO, SOL_SOCKET, SO_REUSEADDR, pack("l", 1)); bind(FOO, pack_sockaddr_in($ARGV[0], INADDR_ANY)) || exit(1); exit(0);' $port
	if [ "$?" != "0" ]; then
		echo Port $port is already in use
		exit 2
	fi
fi
# Save /etc/webmin in case the upgrade trashes it
if [ "$1" != 1 ]; then
	rm -rf %{_prefix}/etc/.webmin-backup
	cp -r %{_prefix}/etc/webmin %{_prefix}/etc/.webmin-backup
fi
# Put back old /etc/webmin saved when an RPM was removed
if [ "$1" = 1 -a ! -d %{_prefix}/etc/webmin -a -d %{_prefix}/etc/webmin.rpmsave ]; then
	mv %{_prefix}/etc/webmin.rpmsave %{_prefix}/etc/webmin
fi
/bin/true

%post
inetd=`grep "^inetd=" %{_prefix}/etc/webmin/miniserv.conf 2>/dev/null | sed -e 's/inetd=//g'`
startafter=0
if [ "$1" != 1 ]; then
	# Upgrading the RPM, so stop the old webmin properly
	if [ "$inetd" != "1" ]; then
		kill -0 `cat %{_prefix}/var/webmin/miniserv.pid 2>/dev/null` 2>/dev/null
		if [ "$?" = 0 ]; then
		  startafter=1
		fi
		%{_prefix}/etc/init.d/webmin stop >/dev/null 2>&1 </dev/null
	fi
else
  startafter=1
fi
cd %{_prefix}/usr/libexec/webmin
config_dir=%{_prefix}/etc/webmin
var_dir=%{_prefix}/var/webmin
perl=/usr/bin/perl
autoos=3
if [ "$WEBMIN_PORT" != "" ]; then
	port=$WEBMIN_PORT
else
	port=10000
fi
login=root
if [ -r /etc/shadow ]; then
	#crypt=`grep "^root:" /etc/shadow | cut -f 2 -d :`
	crypt=x
else
	crypt=`grep "^root:" /etc/passwd | cut -f 2 -d :`
fi
host=`hostname`
ssl=1
atboot=1
nochown=1
autothird=1
noperlpath=1
nouninstall=1
nostart=1
if [ "$tempdir" = "" ]; then
	tempdir=/tmp/.webmin
fi
export config_dir var_dir perl autoos port login crypt host ssl nochown autothird noperlpath nouninstall nostart allow atboot
./setup.sh >$tempdir/webmin-setup.out 2>&1
chmod 600 $tempdir/webmin-setup.out
rm -f %{_prefix}/var/lock/subsys/webmin
if [ "$inetd" != "1" -a "$startafter" = "1" ]; then
	%{_prefix}/etc/init.d/webmin start >/dev/null 2>&1 </dev/null
fi
cat >%{_prefix}/etc/webmin/uninstall.sh <<EOFF
#!/bin/sh
printf "Are you sure you want to uninstall Webmin? (y/n) : "
read answer
printf "\n"
if [ "\$answer" = "y" ]; then
	echo "Removing webmin RPM .."
	rpm -e --nodeps webmin
	echo "Done!"
fi
EOFF
chmod +x %{_prefix}/etc/webmin/uninstall.sh
port=`grep "^port=" %{_prefix}/etc/webmin/miniserv.conf | sed -e 's/port=//g'`
perl -e 'use Net::SSLeay' >/dev/null 2>/dev/null
sslmode=0
if [ "$?" = "0" ]; then
	grep ssl=1 %{_prefix}/etc/webmin/miniserv.conf >/dev/null 2>/dev/null
	if [ "$?" = "0" ]; then
		sslmode=1
	fi
fi
musthost=`grep musthost= %{_prefix}/etc/webmin/miniserv.conf | sed -e 's/musthost=//'`
if [ "" != "" ]; then
	host=
fi
if [ "$sslmode" = "1" ]; then
	echo "Webmin install complete. You can now login to https://$host:$port/"
else
	echo "Webmin install complete. You can now login to http://$host:$port/"
fi
echo "as root with your root password."
/bin/true

%preun
if [ "$1" = 0 ]; then
	grep root=%{_prefix}/usr/libexec/webmin %{_prefix}/etc/webmin/miniserv.conf >/dev/null 2>&1
	if [ "$?" = 0 ]; then
		# RPM is being removed, and no new version of webmin
		# has taken it's place. Run uninstalls and stop the server
		echo "Running uninstall scripts .."
		(cd %{_prefix}/usr/libexec/webmin ; WEBMIN_CONFIG=%{_prefix}/etc/webmin WEBMIN_VAR=%{_prefix}/var/webmin LANG= %{_prefix}/usr/libexec/webmin/run-uninstalls.pl)
		%{_prefix}/etc/init.d/webmin stop >/dev/null 2>&1 </dev/null
		%{_prefix}/etc/webmin/stop >/dev/null 2>&1 </dev/null
	fi
fi
/bin/true

%postun
if [ "$1" = 0 ]; then
	grep root=%{_prefix}/usr/libexec/webmin %{_prefix}/etc/webmin/miniserv.conf >/dev/null 2>&1
	if [ "$?" = 0 ]; then
		# RPM is being removed, and no new version of webmin
		# has taken it's place. Rename away the /etc/webmin directory
		rm -rf %{_prefix}/etc/webmin.rpmsave
		mv %{_prefix}/etc/webmin %{_prefix}/etc/webmin.rpmsave
		rm -rf %{_prefix}/var/webmin
	fi
fi
/bin/true

%triggerpostun -- webmin
if [ ! -d %{_prefix}/var/webmin -a "$1" = 2 ]; then
	echo Re-creating %{_prefix}/var/webmin directory
	mkdir %{_prefix}/var/webmin
fi
if [ ! -r %{_prefix}/etc/webmin/miniserv.conf -a -d %{_prefix}/etc/.webmin-backup -a "$1" = 2 ]; then
	echo Recovering %{_prefix}/etc/webmin directory
	rm -rf %{_prefix}/etc/.webmin-broken
	mv %{_prefix}/etc/webmin %{_prefix}/etc/.webmin-broken
	mv %{_prefix}/etc/.webmin-backup %{_prefix}/etc/webmin
	%{_prefix}/etc/init.d/webmin stop >/dev/null 2>&1 </dev/null
	%{_prefix}/etc/init.d/webmin start >/dev/null 2>&1 </dev/null
else
	rm -rf %{_prefix}/etc/.webmin-backup
fi
/bin/true

