%define indexhtml file:///usr/share/doc/HTML/index.html
%define desktop_file_utils_version 0.9
%define nspr_version 4.6
%define nss_version 3.10
%define cairo_version 0.5

%define official_branding 1

Summary:        Mozilla Firefox Web browser.
Name:           firefox
Version:        1.5
Release:        dnssec.1
URL:            http://www.mozilla.org/projects/firefox/
License:        MPL/LGPL
Group:          Applications/Internet
%if %{official_branding}
%define tarball firefox-%{version}-source.tar.bz2
%else
%define tarball firefox-1.5rc3-source.tar.bz2
%endif
Source0:        %{tarball}
Source1:        firefox-gnomestripe-0.1.tar.gz
Source2:        firefox-1.0-locales.tar.bz2

Source10:       firefox-mozconfig
Source11:       firefox-mozconfig-branded
Source12:       firefox-redhat-default-bookmarks.html
Source13:       firefox-redhat-default-prefs.js
Source20:       firefox.desktop
Source21:       firefox.sh.in
Source22:       firefox.png
Source23:       firefox.xpm
Source24:       firefox.1
Source50:       firefox-xremote-client.sh.in
Source100:      find-external-requires

# build patches
Patch1:         firefox-1.0-prdtoa.patch
Patch3:         firefox-1.1-nss-system-nspr.patch
Patch4:         firefox-1.5-with-system-nss.patch
Patch5:         firefox-1.1-visibility.patch

# customization patches
Patch20:        firefox-redhat-homepage.patch
Patch21:        firefox-0.7.3-default-plugin-less-annoying.patch
Patch22:        firefox-0.7.3-psfonts.patch
Patch24:        firefox-1.1-default-applications.patch
Patch25:        firefox-1.1-software-update.patch
Patch26:        firefox-RC1-stock-icons-be.patch
Patch27:        firefox-RC1-stock-icons-fe.patch
Patch28:        firefox-RC1-stock-icons-gnomestripe.patch
Patch29:        firefox-gnomestripe-0.1-livemarks.patch

# local bugfixes
Patch42:        firefox-1.1-uriloader.patch

# font system fixes
Patch81:        firefox-nopangoxft.patch

# patches from upstream (Patch100+)
Patch100:       firefox-bug305970.patch

# DNSSEC patch
Patch200:	firefox-dnssec-rpm.patch


# ---------------------------------------------------

BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
#BuildRequires:  nspr-devel >= %{nspr_version}
#BuildRequires:  nss-devel >= %{nss_version}
#BuildRequires:  cairo-devel >= %{cairo_version}
BuildRequires:  libpng-devel, libjpeg-devel
BuildRequires:  zlib-devel, zip
BuildRequires:  libIDL-devel
BuildRequires:  desktop-file-utils
BuildRequires:  gtk2-devel
BuildRequires:  gnome-vfs2-devel
BuildRequires:  libgnome-devel
BuildRequires:  libgnomeui-devel
BuildRequires:  krb5-devel
BuildRequires:  pango-devel
BuildRequires:  freetype-devel >= 2.1.9

#Requires:       nspr >= %{nspr_version}
#Requires:       nss >= %{nss_version}
Requires:       desktop-file-utils >= %{desktop_file_utils_version}
Obsoletes:      phoenix, mozilla-firebird, MozillaFirebird
Provides:       mozilla-firebird = %{epoch}:%{version}, MozillaFirebird = %{epoch}:%{version}
Provides:       webclient
%define ffdir %{_libdir}/firefox-%{version}

AutoProv: 0
%define _use_internal_dependency_generator 0
%define __find_requires %{SOURCE100}

%description
Mozilla Firefox is an open-source web browser, designed for standards
compliance, performance and portability.

#---------------------------------------------------------------------

%prep
%setup -q -n mozilla
#%{__tar} -xzf %{SOURCE1}
%patch3  -p1
%patch4  -p1

# Pragma visibility is broken on most platforms for some reason.
# It works on i386 so leave it alone there.  Disable elsewhere.
# See http://gcc.gnu.org/bugzilla/show_bug.cgi?id=20297
%ifnarch i386
%patch5  -p0
%endif

%patch20 -p0
%patch21 -p1
%patch22 -p1
%patch24 -p0
#%patch25 -p0
#%patch26 -p0
#%patch27 -p0
#%patch28 -p0
#%patch29 -p1
%patch42 -p0
%patch81 -p1

%patch100 -p1

%patch200 -p1

%{__rm} -f .mozconfig
%{__cp} %{SOURCE10} .mozconfig
%if %{official_branding}
%{__cat} %{SOURCE11} >> .mozconfig
%endif

# set up our default bookmarks
%{__cp} %{SOURCE12} $RPM_BUILD_DIR/mozilla/profile/defaults/bookmarks.html

# rebuild configure(s)
/bin/rm -f ./configure
/usr/bin/autoconf-2.13
/bin/rm -f ./nsprpub/configure
(cd nsprpub && /usr/bin/autoconf-2.13)

#---------------------------------------------------------------------

%build

# rerun config.status since one of the dnssec patches apparently
# doesn't get it to regneerate.

export RPM_OPT_FLAGS=`echo $RPM_OPT_FLAGS | %{__sed} s/-O2/-Os/`
MAKE="gmake %{?_smp_mflags}" make -f client.mk build

for locale in `cat browser/locales/all-locales`
do
  if [ -d browser/locales/$locale ] ; then
    %{__perl} -pi -e "s|browser.startup.homepage.*$|browser.startup.homepage=%{indexhtml}|g;" \
       browser/locales/$locale/chrome/browser-region/region.properties
    %{__make} -C browser/locales AB_CD=$locale
  fi
  if [ -d toolkit/locales/$locale ] ; then
    %{__make} -C toolkit/locales AB_CD=$locale
  fi
done

#---------------------------------------------------------------------

%install
%{__rm} -rf $RPM_BUILD_ROOT

cd browser/installer
%{__make} STRIP=/bin/true
cd -

%{__mkdir_p} $RPM_BUILD_ROOT{%{_libdir},%{_bindir},%{_datadir}/applications}

%{__tar} -C $RPM_BUILD_ROOT%{_libdir}/ -xzf dist/%{name}-*linux*.tar.gz
%{__mv} $RPM_BUILD_ROOT%{_libdir}/%{name} $RPM_BUILD_ROOT%{ffdir}

%{__rm} -f $RPM_BUILD_ROOT%{_libdir}/%{name}-*linux*.tar

%{__install} -p -D %{SOURCE22} $RPM_BUILD_ROOT%{_datadir}/pixmaps/%{name}.png

desktop-file-install --vendor mozilla \
  --dir $RPM_BUILD_ROOT%{_datadir}/applications \
  --add-category X-Fedora \
  --add-category Application \
  --add-category Network \
  %{SOURCE20} 

# set up the firefox start script
%{__cat} %{SOURCE21} | %{__sed} -e 's,FIREFOX_VERSION,%{version},g' > \
  $RPM_BUILD_ROOT%{_bindir}/firefox
%{__chmod} 755 $RPM_BUILD_ROOT%{_bindir}/firefox

# set up our default preferences
%{__cat} %{SOURCE13} | %{__sed} -e 's,FIREFOX_RPM_VR,%{version}-%{release},g' > rh-default-prefs
%{__cp} rh-default-prefs $RPM_BUILD_ROOT/%{ffdir}/greprefs/all-redhat.js
%{__cp} rh-default-prefs $RPM_BUILD_ROOT/%{ffdir}/defaults/pref/all-redhat.js
%{__rm} rh-default-prefs

# set up our default bookmarks
%{__install} -p -D %{SOURCE12} $RPM_BUILD_ROOT%{ffdir}/defaults/profile/bookmarks.html

%{__cat} %{SOURCE50} | %{__sed} -e 's,FFDIR,%{ffdir},g' -e 's,LIBDIR,%{_libdir},g' > \
  $RPM_BUILD_ROOT%{ffdir}/firefox-xremote-client

%{__chmod} 755 $RPM_BUILD_ROOT%{ffdir}/firefox-xremote-client
%{__install} -p -D %{SOURCE24} $RPM_BUILD_ROOT%{_mandir}/man1/firefox.1

%{__rm} -f $RPM_BUILD_ROOT%{ffdir}/firefox-config

cd $RPM_BUILD_ROOT%{ffdir}/chrome
find . -name "*" -type d -maxdepth 1 -exec %{__rm} -rf {} \;
cd -

%{__cat} > $RPM_BUILD_ROOT%{ffdir}/defaults/pref/firefox-l10n.js << EOF
pref("general.useragent.locale", "chrome://global/locale/intl.properties");
EOF
%{__chmod} 644 $RPM_BUILD_ROOT%{ffdir}/defaults/pref/firefox-l10n.js

%{__mkdir_p} $RPM_BUILD_ROOT%{ffdir}/chrome/icons/default/
%{__cp} %{SOURCE23} $RPM_BUILD_ROOT%{ffdir}/chrome/icons/default/default.xpm
%{__cp} %{SOURCE23} $RPM_BUILD_ROOT%{ffdir}/icons/default.xpm

# own mozilla plugin dir (#135050)
%{__mkdir_p} $RPM_BUILD_ROOT%{_libdir}/mozilla/plugins

# ghost files
touch $RPM_BUILD_ROOT%{ffdir}/components/compreg.dat
touch $RPM_BUILD_ROOT%{ffdir}/components/xpti.dat

#---------------------------------------------------------------------

%clean
%{__rm} -rf $RPM_BUILD_ROOT

#---------------------------------------------------------------------

%post
update-desktop-database %{_datadir}/applications

%postun
update-desktop-database %{_datadir}/applications

%preun
# is it a final removal?
if [ $1 -eq 0 ]; then
  %{__rm} -rf %{ffdir}/components
  %{__rm} -rf %{ffdir}/extensions
fi

%files
%defattr(-,root,root,-)
%{_bindir}/firefox
%{_mandir}/man1/*
%{_datadir}/applications/mozilla-%{name}.desktop
%{_datadir}/pixmaps/firefox.png
%{ffdir}
%{_libdir}/mozilla

%ghost %{ffdir}/components/compreg.dat
%ghost %{ffdir}/components/xpti.dat


#---------------------------------------------------------------------

%changelog
* Tue Jan  3 2006 Christopher Aillon <caillon@redhat.com> - 1.5-4
- Looks like we can build ppc64 again.  Happy New Year!

* Fri Dec 16 2005 Christopher Aillon <caillon@redhat.com> - 1.5-3
- Once again, disable ppc64 because of a new issue.
  See https://bugzilla.redhat.com/bugzilla/show_bug.cgi?id=175944

* Thu Dec 15 2005 Christopher Aillon <caillon@redhat.com> - 1.5-2
- Use the system NSS libraries
- Build on ppc64

* Fri Dec 09 2005 Jesse Keating <jkeating@redhat.com>
- rebuilt

* Tue Nov 29 2005 Christopher Aillon <caillon@redhat.com> - 1.5-1
- Update to Firefox 1.5

* Mon Nov 28 2005 Christopher Aillon <caillon@redhat.com> - 1.5-0.5.1.rc3
- Fix issue with popup dialogs and other actions causing lockups

* Fri Nov 18 2005 Christopher Aillon <caillon@redhat.com> - 1.5-0.5.0.rc3
- Update to 1.5 rc3

* Thu Nov  3 2005 Christopher Aillon <caillon@redhat.com> - 1.5-0.5.0.rc1
- Update to 1.5 rc1
- Clean up the default bookmarks

* Sat Oct  8 2005 Christopher Aillon <caillon@redhat.com> - 1.5-0.5.0.beta2
- Update to 1.5 beta 2

* Wed Sep 14 2005 Christopher Aillon <caillon@redhat.com> - 1.5-0.5.0.beta1
- Update to 1.5 beta 1.
- Add patch to svg rendering to adjust for cairo behavior.
- Happy birthday, dad!

* Sat Aug 27 2005 Christopher Aillon <caillon@redhat.com> - 1.1-0.2.8.deerpark.alpha2
- Re-enable SVG, canvas, and system cairo.
- Fix issue with typing in proxy preference panel

* Thu Aug 18 2005 Jeremy Katz <katzj@redhat.com> - 1.1-0.2.7.deerpark.alpha2.1
- another fix to not use pango_xft

* Mon Aug 15 2005 Christopher Aillon <caillon@redhat.com> 1.1-0.2.6.deerpark.alpha2
- Rebuild

* Fri Jul 29 2005 Christopher Aillon <caillon@redhat.com> 1.1-0.2.5.deerpark.alpha2
- Re-enable ppc now that its binutils are fixed.
- Disable SVG and canvas again.  The in-tree copy does not build against new pango.
- When clicking a link and going back via history, don't keep the link focused.

* Fri Jul 22 2005 Christopher Aillon <caillon@redhat.com> 1.1-0.2.4.deerpark.alpha2
- Add patch from Christian Persch to make the file chooser modal
- Change default behavior of opening links from external apps to: New Tab
- New build options:
  --enable-svg
  --enable-canvas

* Wed Jul 20 2005 Christopher Aillon <caillon@redhat.com> 1.1-0.2.3.deerpark.alpha2
- Update firefox-1.1-uriloader.patch to fix crashes when calling into gnome-vfs2

* Tue Jul 19 2005 Christopher Aillon <caillon@redhat.com> 1.1-0.2.2.deerpark.alpha2
- Do away with firefox-rebuild-databases.pl

* Mon Jul 18 2005 Christopher Aillon <caillon@redhat.com> 1.1-0.2.1.deerpark.alpha2
- Rebuild

* Mon Jul 18 2005 Christopher Aillon <caillon@redhat.com> 1.1-0.0.1.deerpark.alpha2
- Update to Deer Park Alpha 2
  - STILL TODO:
    - This build is not localized yet.
    - Theme issues not yet resolved.
    - Building on ppc platforms is busted, disable them for now.
    - Forward port all remaining patches.

* Sun Jul 17 2005 Christopher Aillon <caillon@redhat.com> 0:1.0.4-6
- Avoid a crash on 64bit platforms
- Use system NSPR

* Thu Jun 23 2005 Kristian Høgsberg <krh@redhat.com>  0:1.0.4-5
- Add firefox-1.0-pango-cairo.patch to get rid of the last few Xft
  references, fixing the "no fonts" problem.
- Copy over changes from FC4 branch.

* Tue May 24 2005 Christopher Aillon <caillon@redhat.com> 0:1.0.4-4
- Only install searchplugins for en-US, since there isn't any way
  to dynamically select searchplugins per locale yet.

* Mon May 23 2005 Christopher Aillon <caillon@redhat.com> 0:1.0.4-3
- Add support for locales:
    af-ZA, ast-ES, ca-AD, cs-CZ, cy-GB, da-DK, de-DE, el-GR,
    en-GB  es-AR, es-ES, eu-ES, fi-FI, fr-FR, ga-IE, he-IL,
    hu-HU, it-IT, ko-KR, ja-JP, ja-JPM, mk-MK, nb-NO, nl-NL,
    pa-IN, pl-PL, pt-BR, pt-PT, ro-RO, ru-RU, sk-SK, sl-SI,
    sq-AL, sv-SE, tr-TR, zh-CN, zh-TW

* Wed May 11 2005 Christopher Aillon <caillon@redhat.com> 0:1.0.4-2
- Update to 1.0.4

* Mon May  9 2005 Christopher Aillon <caillon@redhat.com> 0:1.0.3-5
- Correctly position the IM candidate window for most locales
  Note: it is still incorrectly positioned for zh_TW after this fix
- Add temporary workaround to not create files in the user's $HOME (#149664)

* Tue May  3 2005 Christopher Aillon <caillon@redhat.com> 0:1.0.3-4
- Rebuild

* Tue May  3 2005 Christopher Aillon <caillon@redhat.com>
- Patch from Marcel Mol supporting launching with filenames
  containing whitespace.

* Tue May  3 2005 Christopher Aillon <caillon@redhat.com> 0:1.0.3-3
- Firefox script fixes to support multilib installs.
- Add upstream patch to fix bidi justification of pango
- Add patch to fix launching of helper applications

* Wed Apr 27 2005 Warren Togami <wtogami@redhat.com>
- remove JVM version probing (#116445)
- correct confusing PANGO vars in startup script

* Fri Apr 15 2005 Christopher Aillon <caillon@redhat.com> 0:1.0.3-2
- Add patch to properly link against libgfxshared_s.a

* Fri Apr 15 2005 Christopher Aillon <caillon@redhat.com> 0:1.0.3-1
- Update to security release 1.0.3

* Tue Apr 12 2005 Christopher Aillon <caillon@redhat.com> 0:1.0.2-4
- Update useragent patch to match upstream.
- Add nspr-config 64 bit patch from rstrode@redhat.com

* Mon Mar 28 2005 Christopher Aillon <caillon@redhat.com> 0:1.0.2-3
- Updated firefox icon (https://bugzilla.mozilla.org/show_bug.cgi?id=261679)
- Fix for some more cursor issues in textareas (149991, 150002, 152089)

* Fri Mar 25 2005 Christopher Aillon <caillon@redhat.com> 0:1.0.2-2
- Make the "browser.link.open_external" pref work (David Fraser)

* Wed Mar 23 2005 Christopher Aillon <caillon@redhat.com> 0:1.0.2-1
- Firefox 1.0.2

* Tue Mar 22 2005 Christopher Aillon <caillon@redhat.com> 0:1.0.1-6
- Add patch to fix italic rendering errors with certain fonts (e.g. Tahoma)
- Re-enable jsd since there is now a venkman version that works with Firefox.

* Tue Mar  8 2005 Christopher Aillon <caillon@redhat.com> 0:1.0.1-5
- Add patch to compile against new fortified glibc macros

* Fri Mar  4 2005 Christopher Aillon <caillon@redhat.com> 0:1.0.1-4
- Build against gcc4, add build patches to do so.

* Thu Mar  3 2005 Christopher Aillon <caillon@redhat.com> 0:1.0.1-3
- Remerge firefox-1.0-pango-selection.patch
- Add execshield patches for ia64 and ppc
- BuildRequires libgnome-devel, libgnomeui-devel

* Sun Feb 27 2005 Christopher Aillon <caillon@redhat.com> 0:1.0.1-2
- Add upstream fix to reduce round trips to xserver during remote control
- Add upstream fix to call g_set_application_name

* Thu Feb 24 2005 Christopher Aillon <caillon@redhat.com> 0:1.0.1-1
- Update to 1.0.1 fixing several security flaws.
- Temporarily disable langpacks to workaround startup issues (#145806)
- Request the correct system colors from gtk (#143423)

* Tue Dec 28 2004 Christopher Aillon <caillon@redhat.com> 0:1.0-8
- Add upstream langpacks

* Sat Dec 25 2004 Christopher Aillon <caillon@redhat.com> 0:1.0-7
- Make sure we get a URL passed in to firefox (#138861)
- Mark some generated files as ghost (#136015)

* Wed Dec 15 2004 Christopher Aillon <caillon@redhat.com> 0:1.0-6
- Don't have downloads "disappear" when downloading to desktop (#139015)
- Add RPM version to the useragent
- BuildRequires pango-devel

* Sat Dec 11 2004 Christopher Aillon <caillon@redhat.com> 0:1.0-5
- Fix spacing in textareas when using pango for rendering
- Enable pango rendering by default.
- Enable smooth scrolling by default

* Fri Dec  3 2004 Christopher Aillon <caillon@redhat.com> 0:1.0-4
- Add StartupWMClass patch from Damian Christey (#135830)
- Use system colors by default (#137810)
- Re-add s390(x)

* Sat Nov 20 2004 Christopher Blizzard <blizzard@redhat.com> 0:1.0-3
- Add patch that uses pango for selection.

* Fri Nov 12 2004 Christopher Aillon <caillon@redhat.com> 0:1.0-2
- Fix livemarks icon issue. (#138989)

* Tue Nov  8 2004 Christopher Aillon <caillon@redhat.com> 0:1.0-1
- Firefox 1.0

* Thu Nov  4 2004 Christopher Aillon <caillon@redhat.com> 0:0.99-1.0RC1.3
- Add support for GNOME stock icons. (bmo #233461)

* Sat Oct 30 2004 Warren Togami <wtogami@redhat.com> 0:0.99-1.0RC1.2
- #136330 BR freetype-devel with conditions
- #135050 firefox should own mozilla plugin dir

* Sat Oct 30 2004 Christopher Aillon <caillon@redhat.com> 0:0.99-1.0RC1.1
- Update to firefox-rc1
- Add patch for s390(x)

* Tue Oct 26 2004 Christopher Aillon <caillon@redhat.com>
- Fix LD_LIBRARY_PATH at startup (Steve Knodle)

* Fri Oct 22 2004 Christopher Aillon <caillon@redhat.com> 0:0.10.1-1.0PR1.21
- Prevent inlining of stack direction detection (#135255)

* Tue Oct 19 2004 Christopher Aillon <caillon@redhat.com> 0:0.10.1-1.0PR1.20
- More file chooser fixes:
    Pop up a confirmation dialog before overwriting files (#134648)
    Allow saving as complete once again
- Fix for upstream 263263.

* Tue Oct 19 2004 Christopher Aillon <caillon@redhat.com> 0:0.10.1-1.0PR1.18
- Fix for upstream 262689.

* Mon Oct 18 2004 Christopher Blizzard <blizzard@redhat.com 0:0.10.1-1.0PR1.16
- Update pango patch to one that defaults to off

* Mon Oct 18 2004 Christopher Blizzard <blizzard@redhat.com> 0:0.10.1-1.0PR1.15
- Fix problem where default apps aren't showing up in the download
  dialog (#136261)
- Fix default height being larger than the available area, cherry picked
  from upstream

* Mon Oct 18 2004 Christopher Blizzard <blizzard@redhat.com> 0:0.10.1-1.0PR1.13
- Actually turn on pango in the mozconfig

* Sat Oct 16 2004 Christopher Aillon <caillon@redhat.com> 0:0.10.1-1.0PR1.12
- Disable the default application checks. (#133713)
- Disable the software update feature. (#136017)

* Wed Oct 13 2004 Christopher Blizzard <blizzard@redhat.com>
- Use pango for rendering

* Tue Oct 12 2004 Christopher Aillon <caillon@redhat.com> 0:0.10.1-1.0PR1.10
- Fix for 64 bit crash at startup (b.m.o #256603)

* Fri Oct  8 2004 Christopher Aillon <caillon@redhat.com> 0:0.10.1-1.0PR1.9
- Fix compile issues (#134914)
- Add patch to fix button focus issues (#133507)
- Add patches to fix tab focus stealing issue (b.m.o #124750)

* Fri Oct  1 2004 Christopher Aillon <caillon@redhat.com> 0:0.10.1-1.0PR1.8
- Update to 0.10.1
- Fix tab switching keybindings (#133504)

* Fri Oct  1 2004 Bill Nottingham <notting@redhat.com> 0:0.10.0-1.0PR1.7
- filter out library Provides: and internal Requires:

* Thu Sep 30 2004 Christopher Aillon <caillon@redhat.com> 0:0.10.0-1.0PR1.6
- Prereq desktop-file-utils >= 0.9

* Thu Sep 30 2004 Christopher Aillon <caillon@redhat.com> 0:0.10.0-1.0PR1.5
- Add clipboard access prevention patch.

* Wed Sep 29 2004 Christopher Aillon <caillon@redhat.com> 0:0.10.0-1.0PR1.4
- Add the xul mime type to the .desktop file

* Tue Sep 28 2004 Christopher Aillon <caillon@redhat.com> 0:0.10.0-1.0PR1.3
- Backport the GTK+ file chooser.
- Update desktop database after uninstall.

* Mon Sep 27 2004 Christopher Aillon <caillon@redhat.com> 0:0.10.0-1.0PR1.2
- Change the vendor to mozilla not fedora
- Build with --disable-strip so debuginfo packages work (#133738)
- Add pkgconfig patch (bmo #261090)

* Fri Sep 24 2004 Christopher Aillon <caillon@redhat.com> 0:0.10.0-1.0PR1.1
- Add a BR for desktop-file-utils
- Update default configuration options to use the firefox mozconfig (#132916)
- Use Red Hat bookmarks (#133262)
- Update default homepage (#132721)
- Fix JS math on AMD64 (#133226)
- Build with MOZILLA_OFICIAL (#132917)

* Tue Sep 14 2004 Christopher Aillon <caillon@redhat.com> 0:0.10.0-1.0PR1.0
- Update to 1.0PR1
- Update man page references to say Firefox instead of Firebird
- Remove gcc34 and extensions patch; they are now upstream
- Update desktop database
- Minor tweaks to the .desktop file

* Fri Sep 03 2004 Christopher Aillon <caillon@redhat.com> 0:0.9.3-8
- Fixup .desktop entry Name, GenericName, and Comment (#131602)
- Add MimeType desktop entry (patch from jrb@redhat.com)
- Build with --disable-xprint

* Tue Aug 31 2004 Warren Togami <wtogami@redhat.com> 0:0.9.3-7
- rawhide import
- fedora.us #1765 NetBSD's freetype 2.1.8 compat patch

* Sun Aug 29 2004 Adrian Reber <adrian@lisas.de> 0:0.9.3-0.fdr.6
- and mng support is disabled again as it seams that there is
  no real mng support in the code

* Sat Aug 28 2004 Adrian Reber <adrian@lisas.de> 0:0.9.3-0.fdr.5
- remove ldconfig from scriptlets (bug #1846 comment #40)
- reenabled mng support (bug #1971)
- removed --enable-strip to let rpm to the stripping (bug #1971)
- honor system settings in firefox.sh (bug #1971)
- setting umask 022 in scriptlets (bug #1962)

* Sat Aug 07 2004 Adrian Reber <adrian@lisas.de> 0:0.9.3-0.fdr.4
- copy the icon to the right place(TM)

* Fri Aug 06 2004 Adrian Reber <adrian@lisas.de> 0:0.9.3-0.fdr.3
- readded the xpm removed in 0:0.9.2-0.fdr.5

* Thu Aug 05 2004 Adrian Reber <adrian@lisas.de> 0:0.9.3-0.fdr.2
- added mozilla-1.7-psfonts.patch from rawhide mozilla

* Thu Aug 05 2004 Adrian Reber <adrian@lisas.de> 0:0.9.3-0.fdr.1
- updated to 0.9.3
- removed following from .mozconfig:
    ac_add_options --with-system-mng
    ac_add_options --enable-xprint
    ac_add_options --disable-dtd-debug
    ac_add_options --disable-freetype2
    ac_add_options --enable-strip-libs
    ac_add_options --enable-reorder
    ac_add_options --enable-mathml
    ac_add_options --without-system-nspr

* Tue Aug 03 2004 Adrian Reber <adrian@lisas.de> 0:0.9.2-0.fdr.5
- applied parts of the patch from Matthias Saou (bug #1846)
- delete empty directories in %%{ffdir}/chrome
- more cosmetic changes to the spec file

* Wed Jul 14 2004 Adrian Reber <adrian@lisas.de> 0:0.9.2-0.fdr.4
- mozilla-default-plugin-less-annoying.patch readded

* Tue Jul 13 2004 Adrian Reber <adrian@lisas.de> 0:0.9.2-0.fdr.3
- added krb5-devel as build requirement

* Tue Jul 13 2004 Adrian Reber <adrian@lisas.de> 0:0.9.2-0.fdr.2
- added patch from bugzilla.mozilla.org (bug #247846)
- removed Xvfb hack

* Fri Jul 09 2004 Adrian Reber <adrian@lisas.de> 0:0.9.2-0.fdr.1
- updated to 0.9.2

* Mon Jul 05 2004 Warren Togami <wtogami@redhat.com> 0:0.9.1-0.fdr.3
- mharris suggestion for backwards compatibilty with Xvfb hack

* Tue Jun 29 2004 Adrian Reber <adrian@lisas.de> 0:0.9.1-0.fdr.2
- added massive hack from the debian package to create the
  extension directory

* Tue Jun 29 2004 Adrian Reber <adrian@lisas.de> 0:0.9.1-0.fdr.1
- updated to 0.9.1

* Wed Jun 17 2004 Adrian Reber <adrian@lisas.de> 0:0.9-0.fdr.4
- remove extensions patch
- add post hack to create extensions
- enable negotiateauth extension
- copy icon to browser/app/default.xpm
- --enable-official-branding

* Wed Jun 17 2004 Adrian Reber <adrian@lisas.de> 0:0.9-0.fdr.3
- extensions patch

* Wed Jun 16 2004 Adrian Reber <adrian@lisas.de> 0:0.9-0.fdr.2
- added gnome-vfs2-devel as BuildRequires
- added gcc-3.4 patch 

* Wed Jun 16 2004 Adrian Reber <adrian@lisas.de> 0:0.9-0.fdr.1
- updated to 0.9
- dropped x86_64 patches
- dropped xremote patches

* Wed May 26 2004 Adrian Reber <adrian@lisas.de> 0:0.8-0.fdr.13
- remove unused files: mozilla-config

* Sun May 23 2004 David Hill <djh[at]ii.net> 0:0.8-0.fdr.12
- update mozconfig (fixes bug #1443)
- installation directory includes version number

* Mon May 10 2004 Justin M. Forbes <64bit_fedora@comcast.net> 0:0.8-0.fdr.11
- merge x86_64 release 10 with fedora.us release 10 bump release to 11

* Mon Apr 19 2004 Justin M. Forbes <64bit_fedora@comcast.net> 0:0.8-0.fdr.10
- rebuild for FC2
- change Source71 to properly replace Source7 for maintainability

* Sun Apr 18 2004 Warren Togami <wtogami@redhat.com> 0:0.8-0.fdr.10
- 3rd xremote patch
- test -Os rather than -O2

* Sun Apr 18 2004 Gene Czarcinski <gene@czarc.net>
- more x86_64 fixes
- fix firefix-xremote-client for x86_64 (similar to what is done for
  firefox.sh.in)

* Sat Apr 03 2004 Warren Togami <wtogami@redhat.com> 0:0.8-0.fdr.9
- xremote patch for thunderbird integration #1113
- back out ugly hack from /usr/bin/firefox
- correct default bookmarks

* Wed Feb 25 2004 Adrian Reber <adrian@lisas.de> - 0:0.8-0.fdr.7
- readded the new firefox icons

* Sat Feb 21 2004 Adrian Reber <adrian@lisas.de> - 0:0.8-0.fdr.6
- removed new firefox icons

* Wed Feb 18 2004 Adrian Reber <adrian@lisas.de> - 0:0.8-0.fdr.5
- nothing

* Thu Feb 12 2004 Gene Czarcinski <czar@acm.org>
- update for x86_64 ... usr mozilla-1.6 patches
- change "firefox-i*" to "firefox-*" in above stuff

* Tue Feb 10 2004 Adrian Reber <adrian@lisas.de> - 0:0.8-0.fdr.4
- another icon changed

* Tue Feb 10 2004 Adrian Reber <adrian@lisas.de> - 0:0.8-0.fdr.3
- startup script modified

* Mon Feb 09 2004 Adrian Reber <adrian@lisas.de> - 0:0.8-0.fdr.2
- new firefox icon
- more s/firebird/firefox/

* Mon Feb 09 2004 Adrian Reber <adrian@lisas.de> - 0:0.8-0.fdr.1
- new version: 0.8
- new name: firefox

* Sun Oct 19 2003 Adrian Reber <adrian@lisas.de> - 0:0.7-0.fdr.2
- s/0.6.1/0.7/
- changed user-app-dir back to .phoenix as .mozilla-firebird
  is not working as expected
- manpage now also available as MozillaFirebird.1

* Thu Oct 16 2003 Adrian Reber <adrian@lisas.de> - 0:0.7-0.fdr.1
- updated to 0.7
- provides webclient
- run regxpcom and regchrome after installation and removal
- added a man page from the debian package
- changed user-app-dir from .phoenix to .mozilla-firebird

* Tue Jul 29 2003 Adrian Reber <adrian@lisas.de> - 0:0.6.1-0.fdr.2
- now with mozilla-default-plugin-less-annoying.patch; see bug #586

* Tue Jul 29 2003 Adrian Reber <adrian@lisas.de> - 0:0.6.1-0.fdr.1
- updated to 0.6.1
- changed buildrequires for XFree86-devel from 0:4.3.0 to 0:4.2.1 
  it should now also build on RH80

* Sun Jul 13 2003 Adrian Reber <adrian@lisas.de> - 0:0.6-0.fdr.5.rh90
- enabled the type ahead extension: bug #484

* Sun Jul 13 2003 Adrian Reber <adrian@lisas.de> - 0:0.6-0.fdr.4.rh90
- renamed it again back to MozillaFirbird
- added libmng-devel to BuildRequires
- startup homepage is now www.fedora.us
- improved the startup script to use the unix remote protocol 
  to open a new window

* Thu May 19 2003 Adrian Reber <adrian@lisas.de> - 0:0.6-0.fdr.3.rh90
- new icon from http://iconpacks.mozdev.org/phoenix/iconshots/flame48true.png
- now using gtk2 as toolkit
- renamed again back to mozilla-firebird (I like it better)
- Provides: MozillaFirebird for compatibility with previous releases
- changed default bookmarks.html to contain links to www.fedora.us

* Thu May 19 2003 Adrian Reber <adrian@lisas.de> - 0:0.6-0.fdr.2.rh90
- renamed package to MozillaFirebird and all files with the old name
- enabled mng, mathml, xinerama support
- now honouring RPM_OPT_FLAGS

* Thu May 19 2003 Adrian Reber <adrian@lisas.de> - 0:0.6-0.fdr.1.rh90
- updated to 0.6

* Thu May 01 2003 Phillip Compton <pcompton[AT]proteinmedia.com> - 0:0.6-0.fdr.0.1.cvs20030501.rh90
- Updated to CVS.
- Renamed to mozilla-firebird.

* Sat Apr 05 2003 Phillip Compton <pcompton[AT]proteinmedia.com> - 0:0.6-0.fdr.0.3.cvs20030409.rh90
- Updated to CVS.
- Removed hard-coded library path.

* Sat Apr 05 2003 Phillip Compton <pcompton[AT]proteinmedia.com> - 0:0.6-0.fdr.0.3.cvs20030402.rh90
- Changed Prereq to Requires.
- Changed BuildRequires to gtk+-devel (instead of file).
- Recompressed source with bzip2.
- Removed post.

* Tue Apr 02 2003 Phillip Compton <pcompton[AT]proteinmedia.com> - 0:0.6-0.fdr.0.2.cvs20030402.rh90
- Added desktop-file-utils to BuildRequires.
- Changed category to X-Fedora-Extra.
- Updated to CVS.

* Sun Mar 30 2003 Phillip Compton <pcompton[AT]proteinmedia.com> - 0:0.6-0.fdr.0.2.cvs20030328.rh90
- Added Epoch:0.
- Added libgtk-1.2.so.0 to the BuildRequires

* Fri Mar 28 2003 Phillip Compton <pcompton[AT]proteinmedia.com> - 0.6-0.fdr.0.1.cvs20030328.rh90
- Updated to latest CVS.
- Moved phoenix startup script into its own file

* Wed Mar 26 2003 Phillip Compton <pcompton[AT]proteinmedia.com> - 0.6-0.fdr.0.1.cvs20030326.rh90
- Updated to latest CVS.
- Changed release to 9 vs 8.1.
- Added cvs script.
- added encoding to desktop file.

* Sun Mar 23 2003 Phillip Compton <pcompton[AT]proteinmedia.com> - 0.6-0.fdr.0.1.cvs20030323.rh81
- Updated to latest CVS.
- added release specification XFree86-devel Build Requirement.
- changed chmod to %attr

* Fri Mar 21 2003 Phillip Compton <pcompton[AT]proteinmedia.com> - 0.6-0.fdr.0.1.cvs20030317.rh81
- Fixed naming scheme.
- Fixed .desktop file.

* Mon Mar 17 2003 Phillip Compton <pcompton[AT]proteinmedia.com> - 0.6-cvs20030317.1
- Updated to CVS.

* Fri Mar 14 2003 Phillip Compton <pcompton[AT]proteinmedia.com> - 0.6-cvs20030313.2
- General Tweaking.

* Thu Mar 13 2003 Phillip Compton <pcompton[AT]proteinmedia.com> - 0.6-cvs20030313.1
- Updated CVS.
- Modified mozconfig.

* Sun Mar 09 2003 Phillip Compton <pcompton[AT]proteinmedia.com> - 0.6-cvs20030309.1
- Initial RPM release.
