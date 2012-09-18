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
%define _infodir            %{_prefix}/share/info
%define _mandir             %{_prefix}/share/man
%define _initddir           %{_sysconfdir}/rc.d/init.d
%define _tmppath            %{_var}/tmp
%define _usr                %{_prefix}/usr
%define _usrsrc             %{_prefix}/usr/src

Summary: Improved console FTP client
Name: dt-ncftp
Version: 3.2.5
Release: 3%{?dist}
Epoch: 2
License: Artistic clarified
Group: Applications/Internet
URL: http://www.ncftp.com/ncftp/
Source: ftp://ftp.ncftp.com/ncftp/ncftp-%{version}-src.tar.bz2
#Patch0: ftp://ftp.kame.net/pub/kame/misc/ncftp-320-v6-20061109b.diff.gz
Patch1: ncftp-3.0.3-resume.patch
Patch2: ncftp-3.1.5-pmeter.patch
Patch3: ncftp-3.2.3-ncursesw.patch
Patch99: ncftp-ssl-search.patch
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root
BuildRequires: ncurses-devel net-tools dnssec-tools-libs-devel openssl-devel autoconf213 automake

%description
Ncftp is an improved FTP client. Ncftp's improvements include support
for command line editing, command histories, recursive gets, automatic
anonymous logins, and more.


%prep
%setup -q -n ncftp-%{version}
#patch0 -p1 -b .ipv6
%patch1 -p1 -b .res
%patch2 -p1 -b .pmeter
%patch3 -p1 -b .ncursesw
%patch99 -p1 -b .ssl-search

autoreconf-2.13 -l autoconf_local

%build
%configure --enable-signals --with-dnssec-local-validation
%{__make} STRIPFLAG=""


%install
%{__rm} -rf %{buildroot}
%{__mkdir_p} %{buildroot}{%{_bindir},%{_mandir}/man1}
%{__make} install DESTDIR=%{buildroot}


%clean
%{__rm} -rf %{buildroot}


%files
%defattr(-,root,root,-)
%doc README* doc/html/
%doc doc/CHANGELOG.txt doc/FIREWALLS_AND_PROXIES.txt doc/LICENSE.txt
%doc doc/READLINE.txt doc/what_changed_between_v2_v3.txt
%{_bindir}/ncftp
%{_bindir}/ncftpget
%{_bindir}/ncftpput
%{_bindir}/ncftpbatch
%{_bindir}/ncftpls
%{_bindir}/ncftpbookmarks
%{_bindir}/ncftpspooler
%{_mandir}/man1/ncftp.1*
%{_mandir}/man1/ncftpget.1*
%{_mandir}/man1/ncftpput.1*
%{_mandir}/man1/ncftpbatch.1*
%{_mandir}/man1/ncftpls.1*
%{_mandir}/man1/ncftpspooler.1*


%changelog
* Fri Jan 13 2012 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 2:3.2.5-3
- Rebuilt for https://fedoraproject.org/wiki/Fedora_17_Mass_Rebuild

* Tue Feb 08 2011 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 2:3.2.5-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_15_Mass_Rebuild

* Sat Feb  5 2011 Matthias Saou <http://freshrpms.net/> 2:3.2.5-1
- Update to 3.2.5, live from FOSDEM.
- Remove upstreamed pref patch.

* Mon Apr 26 2010 Matthias Saou <http://freshrpms.net/> 2:3.2.4-1
- Update to 3.2.4.

* Tue Dec  8 2009 Matthias Saou <http://freshrpms.net/> 2:3.2.3-1
- Update to 3.2.3.
- Rebase the ncursesw patch.
- Remove no longer required no_lfs64_source patch.

* Sat Jul 25 2009 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 2:3.2.2-3
- Rebuilt for https://fedoraproject.org/wiki/Fedora_12_Mass_Rebuild

* Wed Feb 25 2009 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 2:3.2.2-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_11_Mass_Rebuild

* Fri Aug 29 2008 Matthias Saou <http://freshrpms.net/> 2:3.2.2-1
- Update to 3.2.2.
- Include no_lfs64_source from Gentoo to fix the build.

* Tue Feb 19 2008 Fedora Release Engineering <rel-eng@fedoraproject.org>
- Autorebuild for GCC 4.3

* Fri Aug 17 2007 Matthias Saou <http://freshrpms.net/> 2:3.2.1-1
- Update to 3.2.1.
- Drop Kame IPv6 patch, should fix #153019. Upstream doesn't seem to want to
  support IPv6 just yet, so for people requiring IPv6, switching to lftp or
  some other alternative is probably best.
- Drop epsv patch, since it applied on top of the IPv6 patch.
- Clean up included docs (don't include Windows specific ones).

* Sun Aug  5 2007 Matthias Saou <http://freshrpms.net/> 2:3.2.0-4
- Update License field.
- Use DESTDIR install method.
- Version 3.2.1 is out, but the KAME IPv6 patch hasn't been updated yet.

* Mon Feb  5 2007 Matthias Saou <http://freshrpms.net/> 2:3.2.0-3
- Update IPv6 patch from 20060806 to 20061109b (getnameinfo vs. getaddrinfo).

* Mon Aug 28 2006 Matthias Saou <http://freshrpms.net/> 2:3.2.0-2
- FC6 rebuild.

* Tue Aug 22 2006 Matthias Saou <http://freshrpms.net/> 2:3.2.0-1
- Update to 3.2.0.
- Update IPv6 patch to 320-v6-20060806.
- Remove dirlist patch (merged upstream).
- Remove rh1 (ask_save) patch, not applied for a while.
- Remove shell patch (xclam args removed).

* Fri May 12 2006 Matthias Saou <http://freshrpms.net/> 2:3.1.9-4
- Include dirlist patch from Mike Gleason to fix bug #187605 reported by
  Lauri Nurmi when using fi_FI.UTF-8 locale.

* Mon Mar  6 2006 Matthias Saou <http://freshrpms.net/> 2:3.1.9-3
- FC5 rebuild.

* Thu Feb  9 2006 Matthias Saou <http://freshrpms.net/> 2:3.1.9-2
- Rebuild for new gcc/glibc.

* Thu Apr 21 2005 Matthias Saou <http://freshrpms.net/> 2:3.1.9-1
- Update to 3.1.9.
- Update IPv6 KAME patch to ncftp-319-v6-20050419.diff.
- Add EPSV/LPSV IPv6 patch (#149494).

* Sat Mar  5 2005 Matthias Saou <http://freshrpms.net/> 2:3.1.8-5
- Spec file cleanup.
- Remove man pages from docs.
- Update summary.

* Wed Mar 02 2005 Karsten Hopp <karsten@redhat.de> 2:3.1.8-4
- build with gcc-4

* Wed Feb 09 2005 Karsten Hopp <karsten@redhat.de> 2:3.1.8-3
- rebuilt

* Thu Aug 26 2004 Karsten Hopp <karsten@redhat.de> 3.1.8-2
- new upstream ipv6 patch, enable ipv6 again

* Mon Aug 09 2004 Karsten Hopp <karsten@redhat.de> 3.1.8-1
- update to version 3.1.8
- new ipv6 patch, but currently disabled due to problems with active-ftp
  (#127553)

* Wed Jul 07 2004 Karsten Hopp <karsten@redhat.de> 2:3.1.7-5
- rebuild with new gcc

* Mon Jul 05 2004 Karsten Hopp <karsten@redhat.de> 3.1.7-4
- add new ipv6 patch (#124232)

* Tue Jun 15 2004 Elliot Lee <sopwith@redhat.com>
- rebuilt

* Fri Feb 13 2004 Elliot Lee <sopwith@redhat.com>
- rebuilt

* Wed Jan 14 2004 Karsten Hopp <karsten@redhat.de> 3.1.7-1
- update to 3.1.7

* Mon Oct 27 2003 Karsten Hopp <karsten@redhat.de> 2:3.1.6-2
- don't ask again if the password should be saved when it already is in the
  bookmarks file (#62177)

* Fri Oct 03 2003 Florian La Roche <Florian.LaRoche@redhat.de>
- 3.1.6
- disabled patch6, seems not necessary

* Tue Aug 12 2003 Karsten Hopp <karsten@redhat.de> 2:3.1.5-7
- don't terminate when 8bit characters are entered (#83107)
- link ncursesw if available

* Wed Jun 04 2003 Elliot Lee <sopwith@redhat.com>
- rebuilt

* Sun Feb 23 2003 Tim Powers <timp@redhat.com>
- rebuild to try and fix a missing dep on libresolv.so.2

* Tue Feb 04 2003 Karsten Hopp <karsten@redhat.de> 3.1.5-4
- updated ipv6 patch (#83186)

* Wed Jan 22 2003 Tim Powers <timp@redhat.com>
- rebuilt

* Wed Dec 04 2002 Karsten Hopp <karsten@redhat.de> 3.1.5-2
- don't enable progressbar when called from a script (#78905)

* Mon Nov 18 2002 Karsten Hopp <karsten@redhat.de> 3.1.5-1
- update to 3.1.5
- fix #75253
- disable patch3
- fix filelist

* Mon Jul  1 2002 Bernhard Rosenkraenzer <bero@redhat.com> 3.1.3-6
- Bring back IPv6 support (#67322)

* Fri Jun 21 2002 Tim Powers <timp@redhat.com>
- automated rebuild

* Thu May 23 2002 Tim Powers <timp@redhat.com>
- automated rebuild

* Wed Apr 10 2002 Florian La Roche <Florian.LaRoche@redhat.de>
- add new patch from Jakub as given in #61961
  select his second patch, that seems a very clean solution

* Wed Mar 27 2002 Bernhard Rosenkraenzer <bero@redhat.com> 3.1.3-2
- Add workaround for glibc bug #61961 (should-fix)

* Sat Feb  9 2002 Bernhard Rosenkraenzer <bero@redhat.com> 3.1.3-1
- 3.1.3

* Mon Jan 21 2002 Bernhard Rosenkraenzer <bero@redhat.com> 3.1.1-1
- Update to 3.1.1
- Temporarily disable the IPv6 patch as it breaks IPv4 connecting
  to machines with both an IPv6 and an IPv4 address

* Tue Nov 20 2001 Bernhard Rosenkraenzer <bero@redhat.com> 3.0.4-2
- Update IPv6 patch

* Wed Oct 31 2001 Bernhard Rosenkraenzer <bero@redhat.com> 3.0.4-1
- 3.0.4
- Add URL tag to spec file (RFE #54622)
- Update and port IPv6 patches
- Fix build with gcc 3.1

* Sat Aug  4 2001 Bernhard Rosenkraenzer <bero@redhat.com> 3.0.3-6
- Fix suspend (#44101, #50846)

* Sun Jul 22 2001 Bernhard Rosenkraenzer <bero@redhat.com> 3.0.3-5
- Add build requirements (#49541)

* Sat Jul 21 2001 Tim Powers <timp@redhat.com>
- no ncftp applnk entry, it's cluttering the menus

* Wed Jul 18 2001 Bernhard Rosenkraenzer <bero@redhat.com> 3.0.3-3
- Fix ipv6 crash (Patch from Pekka Savola, #47763)

* Tue May 22 2001 Bernhard Rosenkraenzer <bero@redhat.com> 3.0.3-2
- Default to auto-resume=yes (REF #28705)

* Tue Apr 24 2001 Bernhard Rosenkraenzer <bero@redhat.com> 3.0.3-1
- Update to 3.0.3

* Sun Apr 15 2001 Bernhard Rosenkraenzer <bero@redhat.com>
- Add PLD's IPv6 patches (#35645)

* Fri Oct 20 2000 Bernhard Rosenkraenzer <bero@redhat.com>
- 3.0.2

* Thu Aug 24 2000 Philipp Knirsch <pknirsch@redhat.com>
- Fixed bug in ncftp/cmds.c in LocalListCmd where the use of the popen/pclose
  was simply wrong and ocasionally resulted in a SIGSEGV (#16315)

* Fri Aug  4 2000 Bernhard Rosenkraenzer <bero@redhat.com>
- Add Swedish and German translations to .desktop file, Bug #15325

* Sun Jul 30 2000 Florian La Roche <Florian.LaRoche@redhat.de>
- small changes to spec file and redo prev patch

* Sun Jul 30 2000 Florian La Roche <Florian.LaRoche@redhat.de>
- set "confirm-close no" per default

* Wed Jul 12 2000 Prospector <bugzilla@redhat.com>
- automatic rebuild

* Mon Jun 19 2000 Bernhard Rosenkraenzer <bero@redhat.com>
- FHSify

* Sun Apr 02 2000 Bernhard Rosenkraenzer <bero@redhat.com>
- 3.0.1

* Fri Mar 24 2000 Bernhard Rosenkraenzer <bero@redhat.com>
- 3.0.0 final

* Mon Mar  6 2000 Jeff Johnson <jbj@redhat.com>
- permit 8-bit input chars to be returned without exiting (#9981),

* Sat Feb  5 2000 Bernhard Rosenkraenzer <bero@redhat.com>
- Deal with rpm compressing man pages
- remove wmconfig stuff

* Thu Jan  6 2000 Jeff Johnson <jbj@redhat.com>
- add missing docs.
- y2k wartlet (#8225)

* Tue Nov  9 1999 Bernhard Rosenkraenzer <bero@redhat.com>
- 3.0b21
- enable signal usage

* Sat Jun 12 1999 Jeff Johnson <jbj@redhat.com>
- 3.0b19

* Sun Mar 21 1999 Cristian Gafton <gafton@redhat.com>
- auto rebuild in the new build environment (release 3)

* Wed Feb 24 1999 Bill Nottingham <notting@redhat.com>
- return of wmconfig

* Tue Feb 23 1999 Bill Nottingham <notting@redhat.com>
- 3.0b18

* Fri Feb 12 1999 Bill Nottingham <notting@redhat.com>
- 3.0b17

* Wed Dec  2 1998 Bill Nottingham <notting@redhat.com>
- 3.0b16

* Wed Nov 18 1998 Bill Nottingham <notting@redhat.com>
- add docs

* Thu Nov  5 1998 Bill Nottingham <notting@redhat.com>
- update to 3.0beta15

* Thu Aug 13 1998 Jeff Johnson <jbj@redhat.com>
- build root

* Fri Apr 24 1998 Prospector System <bugs@redhat.com>
- translations modified for de, fr, tr

* Wed Apr 08 1998 Cristian Gafton <gafton@redhat.com>
- compiled for Manhattan

* Fri Mar 20 1998 Cristian Gafton <gafton@redhat.com>
- updated to 2.4.3 for security reasons

* Wed Nov 05 1997 Donnie Barnes <djb@redhat.com>
- added wmconfig entry

* Wed Oct 21 1997 Cristian Gafton <gafton@redhat.com>
- fixed the spec file

* Fri Oct 10 1997 Erik Troan <ewt@redhat.com>
- updated to ncftp 2.4.2

* Thu Jul 10 1997 Erik Troan <ewt@redhat.com>
- built against glibc

* Tue Mar 25 1997 Donnie Barnes <djb@redhat.com>
- Rebuild as Sun version didn't work.

