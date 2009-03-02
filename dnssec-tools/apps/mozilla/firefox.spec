%define homepage http://start.fedoraproject.org/
%define default_bookmarks_file %{_datadir}/bookmarks/default-bookmarks.html
%define desktop_file_utils_version 0.9
%define firefox_app_id \{ec8030f7-c20a-464f-9b0e-13a3a9e97384\}

%define mozappdir            %{_libdir}/%{name}-%{version}

%define gecko_version 1.9.0.6

%define official_branding    1
%define build_langpacks      1

%if ! %{official_branding}
%define cvsdate 20080327
%define nightly .cvs%{cvsdate}
%endif

Summary:        Mozilla Firefox Web browser
Name:           firefox
Version:        3.0.6
Release:        1%{?dist}
URL:            http://www.mozilla.org/projects/firefox/
License:        MPLv1.1 or GPLv2+ or LGPLv2+
Group:          Applications/Internet
%if %{official_branding}
%define tarball firefox-%{version}-source.tar.bz2
%else
%define tarball mozilla-%{cvsdate}.tar.bz2
%endif
Source0:        %{tarball}
%if %{build_langpacks}
Source2:        firefox-langpacks-%{version}-20090204.tar.bz2
%endif
Source10:       firefox-mozconfig
Source11:       firefox-mozconfig-branded
Source12:       firefox-redhat-default-prefs.js
Source20:       firefox.desktop
Source21:       firefox.sh.in
Source22:       firefox.png
Source23:       firefox.1
Source100:      find-external-requires


# Upstream patches

# DNSSEC Patches
Patch201:       dnssec-firefox.patch
Patch203:       dnssec-both.patch
Patch205:       dnssec-mozconfig.patch

%if %{official_branding}
# Required by Mozilla Corporation


%else
# Not yet approved by Mozillla Corporation


%endif

# ---------------------------------------------------

BuildRoot:      %(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)
BuildRequires:  zip
BuildRequires:  libIDL-devel
BuildRequires:  desktop-file-utils
BuildRequires:  gtk2-devel
BuildRequires:  gnome-vfs2-devel
BuildRequires:  libgnomeui-devel
BuildRequires:  krb5-devel
BuildRequires:  pango-devel
BuildRequires:  freetype-devel >= 2.1.9
BuildRequires:  libXt-devel
BuildRequires:  libXrender-devel
BuildRequires:  system-bookmarks
BuildRequires:  startup-notification-devel
BuildRequires:  gecko-devel-unstable = %{gecko_version}
BuildRequires:  autoconf213

Requires:       desktop-file-utils >= %{desktop_file_utils_version}
Requires:       gecko-libs = %{gecko_version}
Requires:       system-bookmarks
Obsoletes:      mozilla <= 37:1.7.13
Provides:       webclient


%define _use_internal_dependency_generator 0
%define __find_requires %{SOURCE100}

%description
Mozilla Firefox is an open-source web browser, designed for standards
compliance, performance and portability.

#---------------------------------------------------------------------

%prep
%setup -q -c
cd mozilla

# For branding specific patches.

%if %{official_branding}
# Required by Mozilla Corporation

%else
# Not yet approved by Mozilla Corporation


%endif


%{__rm} -f .mozconfig
%{__cp} %{SOURCE10} .mozconfig
%if %{official_branding}
%{__cat} %{SOURCE11} >> .mozconfig
%endif

# Manually generate configure since we patched the base
autoconf-2.13


# Set up SDK path
echo "ac_add_options --with-libxul-sdk=\
`pkg-config --variable=sdkdir libxul`" >> .mozconfig

###############################
# begin dnssec related patches
%patch201 -b.dnssec -p1
%patch203 -b.dnssec -p1
# remove the system-nspr and system-nss from the normal fedora mozconfig
%patch205 -b.dnssec -p0

#%patch202 -p0
#%patch204 -p0

# rebuild configure(s) due to dnssec patches
/bin/rm -f ./configure
/usr/bin/autoconf-2.13
/bin/rm -f ./nsprpub/configure
(cd nsprpub && /usr/bin/autoconf-2.13)
# end dnssec related patches
###############################


#---------------------------------------------------------------------

%build
cd mozilla

# Mozilla builds with -Wall with exception of a few warnings which show up
# everywhere in the code; so, don't override that.
MOZ_OPT_FLAGS=$(echo $RPM_OPT_FLAGS | %{__sed} -e 's/-Wall//')
export CFLAGS=$MOZ_OPT_FLAGS
export CXXFLAGS=$MOZ_OPT_FLAGS

export PREFIX='%{_prefix}'
export LIBDIR='%{_libdir}'

MOZ_SMP_FLAGS=-j1
%ifnarch ppc ppc64 s390 s390x
[ -z "$RPM_BUILD_NCPUS" ] && \
     RPM_BUILD_NCPUS="`/usr/bin/getconf _NPROCESSORS_ONLN`"
[ "$RPM_BUILD_NCPUS" -gt 1 ] && MOZ_SMP_FLAGS=-j2
%endif

INTERNAL_GECKO=%{version}
MOZ_APP_DIR=%{_libdir}/%{name}-${INTERNAL_GECKO}

export LDFLAGS="-Wl,-rpath,${MOZ_APP_DIR}"
make -f client.mk build STRIP="/bin/true" MOZ_MAKE_FLAGS="$MOZ_SMP_FLAGS"

#---------------------------------------------------------------------

%install
%{__rm} -rf $RPM_BUILD_ROOT
cd mozilla

DESTDIR=$RPM_BUILD_ROOT make install

%{__mkdir_p} $RPM_BUILD_ROOT{%{_libdir},%{_bindir},%{_datadir}/applications,%{_datadir}/pixmaps},

%{__install} -p -D -m 644 %{SOURCE22} $RPM_BUILD_ROOT%{_datadir}/pixmaps/%{name}.png

desktop-file-install --vendor mozilla \
  --dir $RPM_BUILD_ROOT%{_datadir}/applications \
  --add-category WebBrowser \
  --add-category Network \
  %{SOURCE20} 

# set up the firefox start script
%{__rm} -rf $RPM_BUILD_ROOT%{_bindir}/firefox
%{__cat} %{SOURCE21} | %{__sed} -e 's,FIREFOX_VERSION,%{version},g' > \
  $RPM_BUILD_ROOT%{_bindir}/firefox
%{__chmod} 755 $RPM_BUILD_ROOT%{_bindir}/firefox

# set up our default preferences
%{__cat} %{SOURCE12} | %{__sed} -e 's,FIREFOX_RPM_VR,%{version}-%{release},g' > rh-default-prefs

# set up our default homepage
%{__cat} > $RPM_BUILD_ROOT/%{mozappdir}/browserconfig.properties << EOF
browser.startup.homepage=%{homepage}
EOF

# Export correct locale
%{__cat} > $RPM_BUILD_ROOT/%{mozappdir}/defaults/preferences/firefox-l10n.js << EOF
pref("general.useragent.locale", "chrome://global/locale/intl.properties");
EOF
%{__chmod} 644 $RPM_BUILD_ROOT/%{mozappdir}/defaults/preferences/firefox-l10n.js

# place the preferences
%{__cp} rh-default-prefs $RPM_BUILD_ROOT/%{mozappdir}/defaults/preferences/all-redhat.js
%{__rm} rh-default-prefs

# set up our default bookmarks
%{__rm} -f $RPM_BUILD_ROOT/%{mozappdir}/defaults/profile/bookmarks.html
ln -s %{default_bookmarks_file} $RPM_BUILD_ROOT/%{mozappdir}/defaults/profile/bookmarks.html

%{__install} -p -D -m 644 %{SOURCE23} $RPM_BUILD_ROOT%{_mandir}/man1/firefox.1

%{__rm} -f $RPM_BUILD_ROOT/%{mozappdir}/firefox-config

#cd $RPM_BUILD_ROOT/%{mozappdir}/chrome
#find . -name "*" -type d -maxdepth 1 -exec %{__rm} -rf {} \;
#cd -

#%{__cat} > $RPM_BUILD_ROOT/%{mozappdir}/defaults/pref/firefox-l10n.js << EOF
#pref("general.useragent.locale", "chrome://global/locale/intl.properties");
#EOF
#%{__chmod} 644 $RPM_BUILD_ROOT/%{mozappdir}/defaults/pref/firefox-l10n.js

%{__mkdir_p} $RPM_BUILD_ROOT/%{mozappdir}/chrome/icons/default/
%{__cp} other-licenses/branding/%{name}/default16.png \
        $RPM_BUILD_ROOT/%{mozappdir}/chrome/icons/default/ 
%{__cp} other-licenses/branding/%{name}/default16.png \
        $RPM_BUILD_ROOT/%{mozappdir}/icons/

echo > ../%{name}.lang
%if %{build_langpacks}
# Install langpacks
%{__mkdir_p} $RPM_BUILD_ROOT/%{mozappdir}/extensions
%{__tar} xjf %{SOURCE2}
for langpack in `ls firefox-langpacks/*.xpi`; do
  language=`basename $langpack .xpi`
  extensiondir=$RPM_BUILD_ROOT/%{mozappdir}/extensions/langpack-$language@firefox.mozilla.org
  %{__mkdir_p} $extensiondir
  unzip $langpack -d $extensiondir
  find $extensiondir -type f | xargs chmod 644

  tmpdir=`mktemp -d %{name}.XXXXXXXX`
  langtmp=$tmpdir/%{name}/langpack-$language
  %{__mkdir_p} $langtmp
  jarfile=$extensiondir/chrome/$language.jar
  unzip $jarfile -d $langtmp

  sed -i -e "s|browser.startup.homepage.*$|browser.startup.homepage=%{homepage}|g;" \
         $langtmp/locale/browser-region/region.properties

  find $langtmp -type f | xargs chmod 644
  %{__rm} -rf $jarfile
  cd $langtmp
  zip -r -D $jarfile locale
  cd -
  %{__rm} -rf $tmpdir

  language=`echo $language | sed -e 's/-/_/g'`
  extensiondir=`echo $extensiondir | sed -e "s,^$RPM_BUILD_ROOT,,"`
  echo "%%lang($language) $extensiondir" >> ../%{name}.lang
done
%{__rm} -rf firefox-langpacks
%endif # build_langpacks

# System extensions
%{__mkdir_p} $RPM_BUILD_ROOT%{_datadir}/mozilla/extensions/%{firefox_app_id}
%{__mkdir_p} $RPM_BUILD_ROOT%{_libdir}/mozilla/extensions/%{firefox_app_id}

# Copy over the LICENSE
%{__install} -p -c -m 644 LICENSE $RPM_BUILD_ROOT/%{mozappdir}

# ghost files
touch $RPM_BUILD_ROOT/%{mozappdir}/components/compreg.dat
touch $RPM_BUILD_ROOT/%{mozappdir}/components/xpti.dat

# jemalloc shows up sometimes, but it's not needed here, it's in XR
%{__rm} -f $RPM_BUILD_ROOT/%{mozappdir}/libjemalloc.so

#---------------------------------------------------------------------

%clean
%{__rm} -rf $RPM_BUILD_ROOT

#---------------------------------------------------------------------

%post
update-desktop-database &> /dev/null || :
touch --no-create %{_datadir}/icons/hicolor
if [ -x %{_bindir}/gtk-update-icon-cache ]; then
  %{_bindir}/gtk-update-icon-cache --quiet %{_datadir}/icons/hicolor || :
fi

%postun
update-desktop-database &> /dev/null || :
touch --no-create %{_datadir}/icons/hicolor
if [ -x %{_bindir}/gtk-update-icon-cache ]; then
  %{_bindir}/gtk-update-icon-cache --quiet %{_datadir}/icons/hicolor || :
fi

%preun
# is it a final removal?
if [ $1 -eq 0 ]; then
  %{__rm} -rf %{mozappdir}/components
  %{__rm} -rf %{mozappdir}/extensions
  %{__rm} -rf %{mozappdir}/plugins
fi


%files -f %{name}.lang
%defattr(-,root,root,-)
%{_bindir}/firefox
%doc %{_mandir}/man1/*
%dir %{_datadir}/mozilla/extensions/%{firefox_app_id}
%dir %{_libdir}/mozilla/extensions/%{firefox_app_id}
%{_datadir}/applications/mozilla-%{name}.desktop
%{_datadir}/pixmaps/firefox.png
%dir %{mozappdir}
%doc %{mozappdir}/LICENSE
%doc %{mozappdir}/README.txt
%{mozappdir}/*.properties
%{mozappdir}/chrome
%dir %{mozappdir}/components
%ghost %{mozappdir}/components/compreg.dat
%ghost %{mozappdir}/components/xpti.dat
%{mozappdir}/components/*.so
%{mozappdir}/components/*.xpt
%attr(644, root, root) %{mozappdir}/blocklist.xml
%attr(644, root, root) %{mozappdir}/components/*.js
%{mozappdir}/defaults
%dir %{mozappdir}/extensions
%{mozappdir}/extensions/{972ce4c6-7e08-4474-a285-3208198ce6fd}
%{mozappdir}/icons
%{mozappdir}/searchplugins
%{mozappdir}/firefox
%{mozappdir}/run-mozilla.sh
%{mozappdir}/application.ini
%dir %{mozappdir}/modules
%{mozappdir}/modules/distribution.js
%{mozappdir}/.autoreg
# XXX See if these are needed still
%{mozappdir}/updater*
%exclude %{mozappdir}/removed-files

#---------------------------------------------------------------------

%changelog
* Wed Feb  4 2009 Christopher Aillon <caillon@redhat.com> - 3.0.6-1
- Update to 3.0.6

* Wed Jan  7 2009 Jan Horak <jhorak@redhat.com> - 3.0.5-2
- Fixed wrong LANG and LC_MESSAGES variables interpretation (#441973) 
  in startup script.

* Tue Dec 16 2008 Christopher Aillon <caillon@redhat.com> 3.0.5-1
- Update to 3.0.5

* Tue Nov 13 2008 Jan Horak <jhorak@redhat.com> 3.0.4-2
- Removed firefox-2.0-getstartpage.patch patch 
- Start page is set by different way

* Wed Nov 12 2008 Christopher Aillon <caillon@redhat.com> 3.0.4-1
- Update to 3.0.4

* Tue Sep 23 2008 Christopher Aillon <caillon@redhat.com> 3.0.2-1
- Update to 3.0.2

* Wed Jul 16 2008 Christopher Aillon <caillon@redhat.com> 3.0.1-1
- Update to 3.0.1

* Tue Jun 17 2008 Christopher Aillon <caillon@redhat.com> 3.0-1
- Firefox 3 Final

* Thu May 08 2008 Colin Walters <walters@redhat.com> 3.0-0.61
- Rebuild to pick up new xulrunner (bug #445543)

* Wed Apr 30 2008 Christopher Aillon <caillon@redhat.com> 3.0-0.60
- Rebuild

* Mon Apr 28 2008 Christopher Aillon <caillon@redhat.com> 3.0-0.59
- Zero out the lang file we generate during builds

* Mon Apr 28 2008 Christopher Aillon <caillon@redhat.com> 3.0-0.58
- Bounce a few unneeded items from the spec and clean up some tabs

* Fri Apr 25 2008 Martin Stransky <stransky@redhat.com> 3.0-0.57
- Enable anti-pishing protection (#443403)

* Fri Apr 18 2008 Martin Stransky <stransky@redhat.com> 3.0-0.55
- Don't show an welcome page during first browser start (#437065)

* Sat Apr 12 2008 Christopher Aillon <caillon@redhat.com> 3.0-0.54
- Remove the broken Macedonian (mk) langpack
- Download to Download/

* Mon Apr  7 2008 Christopher Aillon <caillon@redhat.com> 3.0-0.53
- Add langpacks, marked with %%lang
- Translate the .desktop file

* Wed Apr  2 2008 Christopher Aillon <caillon@redhat.com> 3.0-0.52
- Beta 5

* Mon Mar 31 2008 Christopher Aillon <caillon@redhat.com> 3.0-0.51
- Beta 5 RC2

* Thu Mar 27 2008 Christopher Aillon <caillon@redhat.com> 3.0-0.50
- Update to latest trunk (2008-03-27)

* Wed Mar 26 2008 Christopher Aillon <caillon@redhat.com> 3.0-0.49
- Update to latest trunk (2008-03-26)

* Tue Mar 25 2008 Christopher Aillon <caillon@redhat.com> 3.0-0.48
- Update to latest trunk (2008-03-25)

* Mon Mar 24 2008 Christopher Aillon <caillon@redhat.com> 3.0-0.47
- Update to latest trunk (2008-03-24)

* Thu Mar 20 2008 Christopher Aillon <caillon@redhat.com> 3.0-0.46
- Update to latest trunk (2008-03-20)

* Mon Mar 17 2008 Christopher Aillon <caillon@redhat.com> 3.0-0.45
- Update to latest trunk (2008-03-17)

* Mon Mar 17 2008 Christopher Aillon <caillon@redhat.com> 3.0-0.44
- Revert to trunk from the 15th to fix crashes on HTTPS sites

* Sun Mar 16 2008 Christopher Aillon <caillon@redhat.com> 3.0-0.43
- Update to latest trunk (2008-03-16)

* Sat Mar 15 2008 Christopher Aillon <caillon@redhat.com> 3.0-0.42
- Update to latest trunk (2008-03-15)

* Sat Mar 15 2008 Christopher Aillon <caillon@redhat.com> 3.0-0.41
- Avoid conflicts between gecko debuginfo packages

* Wed Mar 12 2008 Christopher Aillon <caillon@redhat.com> 3.0-0.40
- Update to latest trunk (2008-03-12)

* Tue Mar 11 2008 Christopher Aillon <caillon@redhat.com> 3.0-0.39
- Update to latest trunk (2008-03-11)

* Mon Mar 10 2008 Christopher Aillon <caillon@redhat.com> 3.0-0.38
- Update to latest trunk (2008-03-10)

* Sun Mar  9 2008 Christopher Aillon <caillon@redhat.com> 3.0-0.37
- Update to latest trunk (2008-03-09)

* Fri Mar  7 2008 Christopher Aillon <caillon@redhat.com> 3.0-0.beta4.36
- Update to latest trunk (2008-03-07)

* Thu Mar  6 2008 Christopher Aillon <caillon@redhat.com> 3.0-0.beta4.35
- Update to latest trunk (2008-03-06)

* Tue Mar  4 2008 Christopher Aillon <caillon@redhat.com> 3.0-0.beta3.34
- Update to latest trunk (2008-03-04)

* Sun Mar  2 2008 Christopher Aillon <caillon@redhat.com> 3.0-0.beta3.33
- Update to latest trunk (2008-03-02)

* Sat Mar  1 2008 Christopher Aillon <caillon@redhat.com> 3.0-0.beta3.32
- Update to latest trunk (2008-03-01)

* Fri Feb 29 2008 Christopher Aillon <caillon@redhat.com> 3.0-0.beta3.31
- Update to latest trunk (2008-02-29)

* Thu Feb 28 2008 Christopher Aillon <caillon@redhat.com> 3.0-0.beta3.30
- Update to latest trunk (2008-02-28)

* Wed Feb 27 2008 Christopher Aillon <caillon@redhat.com> 3.0-0.beta3.29
- Update to latest trunk (2008-02-27)

* Tue Feb 26 2008 Christopher Aillon <caillon@redhat.com> 3.0-0.beta3.28
- Update to latest trunk (2008-02-26)

* Sat Feb 23 2008 Christopher Aillon <caillon@redhat.com> 3.0-0.beta3.27
- Update to latest trunk (2008-02-23)

* Fri Feb 22 2008 Christopher Aillon <caillon@redhat.com> 3.0-0.beta3.26
- Update to latest trunk (2008-02-22)

* Thu Feb 21 2008 Christopher Aillon <caillon@redhat.com> 3.0-0.beta3.25
- Update to latest trunk (2008-02-21)

* Sun Feb 17 2008 Christopher Aillon <caillon@redhat.com> 3.0-0.beta3.23
- Update to latest trunk (2008-02-17)

* Fri Feb 15 2008 Christopher Aillon <caillon@redhat.com> 3.0-0.beta3.22
- Update to latest trunk (2008-02-15)

* Thu Feb 14 2008 Christopher Aillon <caillon@redhat.com> 3.0-0.beta3.21
- Update to latest trunk (2008-02-14)

* Wed Feb 13 2008 Christopher Aillon <caillon@redhat.com> 3.0-0.beta3.20
- Update to latest trunk (2008-02-13)

* Mon Feb 11 2008 Christopher Aillon <caillon@redhat.com> 3.0-0.beta2.19
- Update to latest trunk (2008-02-11)

* Sun Feb 10 2008 Christopher Aillon <caillon@redhat.com> 3.0-0.beta2.18
- Update to latest trunk (2008-02-10)

* Sat Feb  9 2008 Christopher Aillon <caillon@redhat.com> 3.0-0.beta2.17
- Update to latest trunk (2008-02-09)

* Wed Feb  6 2008 Christopher Aillon <caillon@redhat.com> 3.0-0.beta2.16
- Update to latest trunk (2008-02-06)

* Wed Jan 30 2008 Martin Stransky <stransky@redhat.com> 3.0-0.beta2.15
- Update to latest trunk (2008-01-30)
- Backported an old laucher

* Mon Jan 28 2008 Martin Stransky <stransky@redhat.com> 3.0-0.beta2.13
- cleared starting scripts, removed useless parts

* Mon Jan 21 2008 Christopher Aillon <caillon@redhat.com> 3.0-0.beta2.12
- Update to latest trunk (2008-01-21)

* Tue Jan 15 2008 Christopher Aillon <caillon@redhat.com> 3.0-0.beta2.11
- Update to latest trunk (2008-01-15)
- Now with system extensions directory support
- Temporarily disable langpacks while we're on the bleeding edge
- Remove skeleton files; they are in xulrunner now

* Sun Jan 13 2008 Christopher Aillon <caillon@redhat.com> 3.0-0.beta2.10
- Update to latest trunk (20080113)
- Fix the default prefs, homepage, and useragent string

* Thu Jan 10 2008 Martin Stransky <stransky@redhat.com> 3.0-0.beta2.9
- rebuilt agains xulrunner-devel-unstable

* Mon Jan 7 2008 Martin Stransky <stransky@redhat.com> 3.0-0.beta2.8
- added ssl exception patch (mozbz #411037)

* Fri Jan 4 2008 Martin Stransky <stransky@redhat.com> 3.0-0.beta2.7
- removed broken langpack
- built against libxul

* Thu Jan 3 2008 Martin Stransky <stransky@redhat.com> 3.0-0.beta2.6
- updated to the latest trunk (20080103)

* Wed Jan 2 2008 Martin Stransky <stransky@redhat.com> 3.0-0.beta2.5
- added default fedora homepage
- updated a language pack (#427182)

* Mon Dec 31 2007 Christopher Aillon <caillon@redhat.com> 3.0-0.beta2.4
- Create and own /etc/skel/.mozilla
- No longer need add-gecko-provides

* Sat Dec 22 2007 Christopher Aillon <caillon@redhat.com> 3.0-0.beta2.3
- When there are both 32- and 64-bit versions of XPCOM installed on disk
  make sure to load the correct one.

* Tue Dec 20 2007 Martin Stransky <stransky@redhat.com> 3.0-0.beta2.2
- fixed xulrunner dependency

* Tue Dec 18 2007 Martin Stransky <stransky@redhat.com> 3.0-0.beta2.1
- moved to XUL Runner and updated to 3.0b3pre
- removed firefox-devel package, gecko-libs is provided 
  by xulrunner-devel now.

* Thu Dec 13 2007 Christopher Aillon <caillon@redhat.com> 2.0.0.10-5
- Fix the getStartPage method to not return blank.
  Patch by pspencer@fields.utoronto.ca

* Sun Dec  9 2007 Christopher Aillon <caillon@redhat.com> 2.0.0.10-4
- Fix up some rpmlint warnings
- Use only one pref for the homepage for now
- Drop some old patches and some obsolote Obsoletes

* Tue Dec 4 2007 Martin Stransky <stransky@redhat.com> 2.0.0.10-3
- fixed an icon location

* Mon Dec 3 2007 Martin Stransky <stransky@redhat.com> 2.0.0.10-2
- removed gre.conf file (most of the gtkmozembed applications
  run with xulrunner now)

* Mon Nov 26 2007 Christopher Aillon <caillon@redhat.com> 2.0.0.10-1
- Update to 2.0.0.10

* Tue Nov 5 2007 Martin Stransky <stransky@redhat.com> 2.0.0.9-1
- updated to the latest upstream

* Wed Oct 31 2007 Martin Stransky <stransky@redhat.com> 2.0.0.8-3
- added mozilla-plugin-config to startup script

* Tue Oct 30 2007 Christopher Aillon <caillon@redhat.com> 2.0.0.8-2
- Tweak the default backspace behavior to be more in line with
  GNOME convention, Mozilla upstream, and other distros

* Tue Oct 23 2007 Martin Stransky <stransky@redhat.com> 2.0.0.8-1
- updated to the latest upstream
- moved preference updates to build section

* Thu Oct 18 2007 Jesse Keating <jkeating@redhat.com> - 2.0.0.6-12
- Disable the Firefox startup notification support for now.

* Mon Sep 26 2007 Martin Stransky <stransky@redhat.com> 2.0.0.6-11
- Fixed #242657 - firefox -g doesn't work

* Mon Sep 25 2007 Martin Stransky <stransky@redhat.com> 2.0.0.6-10
- Removed hardcoded MAX_PATH, PATH_MAX and MAXPATHLEN macros

* Mon Sep 24 2007 Christopher Aillon <caillon@redhat.com> 2.0.0.6-9
- Startup notification support

* Tue Sep 11 2007 Christopher Aillon <caillon@redhat.com> 2.0.0.6-8
- Fix crashes when using GTK+ themes containing a gtkrc which specify 
  GtkOptionMenu::indicator_size and GtkOptionMenu::indicator_spacing

* Mon Sep 10 2007 Martin Stransky <stransky@redhat.com> 2.0.0.6-7
- added fix for #246248 - firefox crashes when searching for word "do"

* Thu Sep  6 2007 Christopher Aillon <caillon@redhat.com> - 2.0.0.6-6
- Fix default page for all locales

* Wed Aug 29 2007 Christopher Aillon <caillon@redhat.com> - 2.0.0.6-5
- Tweak the default home page

* Fri Aug 24 2007 Adam Jackson <ajax@redhat.com> - 2.0.0.6-4
- Rebuild for build ID

* Mon Aug 13 2007 Christopher Aillon <caillon@redhat.com> 2.0.0.6-3
- Update the license tag

* Mon Aug  6 2007 Martin Stransky <stransky@redhat.com> 2.0.0.6-2
- unwrapped plugins moved to the old location
- removed plugin configuration utility

* Sat Aug  4 2007 Christopher Aillon <caillon@redhat.com> 2.0.0.6-1
- Update to 2.0.0.6
- Fix dnd support to/from gtk2 apps
- Fix installed permissions of *.png

* Mon Jul 23 2007 Martin Stransky <stransky@redhat.com> 2.0.0.5-3
- added nspluginwrapper support

* Wed Jul 18 2007 Kai Engert <kengert@redhat.com> - 2.0.0.5-2
- Update to 2.0.0.5

* Fri Jun 29 2007 Martin Stransky <stransky@redhat.com> 2.0.0.4-3
- backported pango patches from FC6 (1.5.0.12)

* Sun Jun  3 2007 Christopher Aillon <caillon@redhat.com> 2.0.0.4-2
- Properly clean up threads with newer NSPR

* Wed May 30 2007 Christopher Aillon <caillon@redhat.com> 2.0.0.4-1
- Final version

* Wed May 23 2007 Christopher Aillon <caillon@redhat.com> 2.0.0.4-0.rc3
- Update to 2.0.0.4 RC3

* Tue Apr 17 2007 Christopher Aillon <caillon@redhat.com> 2.0.0.3-4
- Fix permissions of the man page

* Tue Apr 10 2007 Christopher Aillon <caillon@redhat.com> 2.0.0.3-3
- Ensure initial homepage on all locales is our proper default

* Sun Mar 25 2007 Christopher Aillon <caillon@redhat.com> 2.0.0.3-2
- Fix the symlink to default bookmarks
- Use mktemp for temp dirs

* Tue Mar 20 2007 Christopher Aillon <caillon@redhat.com> 2.0.0.3-1
- Update to 2.0.0.3

* Tue Mar 20 2007 Christopher Aillon <caillon@redhat.com> 2.0.0.2-3
- Default bookmarks no longer live here; use system-bookmarks

* Mon Mar 12 2007 Christopher Aillon <caillon@redhat.com> 2.0.0.2-2
- Oops, define the variables I expect to use.

* Fri Feb 23 2007 Martin Stransky <stransky@redhat.com> 2.0.0.2-1
- Update to 2002

* Wed Feb 21 2007 David Woodhouse <dwmw2@redhat.com> 2.0.0.1-6
- Fix PPC64 runtime
- Fix firefox script to use 32-bit browser by default on PPC64 hardware

* Fri Feb  9 2007 Christopher Aillon <caillon@redhat.com> 2.0.0.1-5
- Start using the specified locale

* Tue Jan 30 2007 Christopher Aillon <caillon@redhat.com> 2.0.0.1-4
- Fix the DND implementation to not grab, so it works with new GTK+.

* Thu Jan 18 2007 Christopher Aillon <caillon@redhat.com> 2.0.0.1-3
- Remove the XLIB_SKIP_ARGB_VISUALS=1 workaround; the plugin got fixed.

* Fri Dec 22 2006 Christopher Aillon <caillon@redhat.com> 2.0.0.1-2
- Strip out some frequent warnings; they muddy up the build output

* Thu Dec 21 2006 Christopher Aillon <caillon@redhat.com> 2.0.0.1-1
- Update to 2001

* Fri Oct 27 2006 Christopher Aillon <caillon@redhat.com> 2.0-2
- Tweak the .desktop file

* Tue Oct 24 2006 Christopher Aillon <caillon@redhat.com> 2.0-1
- Update to 2.0
- Add patch from Behdad to fix pango printing.

* Wed Oct 11 2006 Christopher Aillon <caillon@redhat.com> 1.5.0.7-7
- Add virtual provides for gecko applications.

* Wed Oct  4 2006 Christopher Aillon <caillon@redhat.com> 1.5.0.7-6
- Bring the invisible character to parity with GTK+

* Tue Sep 26 2006 Christopher Aillon <caillon@redhat.com> 1.5.0.7-5
- Fix crash when changing gtk key theme
- Fix gtkmozembed window visibility
- Prevent UI freezes while changing GNOME theme
- Remove verbiage about pango; no longer required by upstream.

* Tue Sep 19 2006 Christopher Aillon <caillon@redhat/com> 1.5.0.7-4
- Arrrr! Add Obsoletes: mozilla to avoid GRE conflicts, me hearties!

* Mon Sep 18 2006 Christopher Aillon <caillon@redhat.com> 1.5.0.7-3
- Bring back the GRE files for embeddors

* Thu Sep 14 2006 Christopher Aillon <caillon@redhat.com> 1.5.0.7-2
- Update default bookmarks for FC6

* Wed Sep 13 2006 Christopher Aillon <caillon@redhat.com> 1.5.0.7-1
- Update to 1.5.0.7

* Thu Sep  7 2006 Christopher Aillon <caillon@redhat.com> 1.5.0.6-12
- Icon tweaks and minor spec-file variable cleanup: s/ffdir/mozappdir/g

* Wed Sep  6 2006 Christopher Aillon <caillon@redhat.com> 1.5.0.6-11
- Fix for cursor position in editor widgets by tagoh and behdad (#198759)

* Sun Sep  3 2006 Christopher Aillon <caillon@redhat.com> 1.5.0.6-10
- Enable GCC visibility
- export XLIB_SKIP_ARGB_VISUALS=1 as a temporary workaround to prevent
  a broken Adobe/Macromedia Flash Player plugin taking the X server.

* Tue Aug 29 2006 Christopher Aillon <caillon@redhat.com> 1.5.0.6-9
- Build with -rpath (#161958)

* Mon Aug 28 2006 Behdad Esfahbod <besfahbo@redhat.com> 
- Remove "Pango breaks MathML" from firefox.sh.in

* Mon Aug 28 2006 Christopher Aillon <caillon@redhat.com> 1.5.0.6-8
- Turn visibility back off again for now, as it still breaks the build.

* Sat Aug 26 2006 Behdad Esfahbod <besfahbo@redhat.com> 1.5.0.6-7
- Remove "Pango breaks MathML" from firefox-1.5-pango-about.patch

* Thu Aug 24 2006 Behdad Esfahbod <besfahbo@redhat.com> 1.5.0.6-6
- Remove debugging statement from firefox-1.5-pango-mathml.patch

* Wed Aug 23 2006 Christopher Aillon <caillon@redhat.com> 1.5.0.6-5
- Attempt to turn visibility back on since the GCC issues should have
  been fixed.

* Tue Aug 22 2006 Christopher Aillon <caillon@redhat.com> 1.5.0.6-4
- Update NSS requires to workaround a bug introduced by NSS changes.
  https://bugzilla.mozilla.org/show_bug.cgi?id=294542
  https://bugzilla.redhat.com/bugzilla/show_bug.cgi?id=201922

* Tue Aug 22 2006 Behdad Esfahbod <besfahbo@redhat.com>
- Add a better nopangoxft patch that doesn't depend on pangocairo
- Add firefox-1.5-pango-mathml.patch (bug 150393)

* Tue Aug 08 2006 Kai Engert <kengert@redhat.com> - 1.5.0.6-3
- Rebuild

* Thu Aug 03 2006 Kai Engert <kengert@redhat.com> - 1.5.0.6-2
- Update to 1.5.0.6

* Sun Jul 30 2006 Matthias Clasen <mclasen@redhat.com> - 1.5.0.5-8
- Pass --libdir to configure

* Fri Jul 28 2006 Christopher Aillon <caillon@redhat.com> - 1.5.0.5-7
- Dereference links in %%install so the files get put in the
  right place.

* Fri Jul 28 2006 Christopher Aillon <caillon@redhat.com> - 1.5.0.5-6
- Actually, those pkgconfig files really shouldn't be here as we use
  system nss and nspr.

* Fri Jul 28 2006 Matthias Clasen <mclasen@redhat.com> - 1.5.0.5-5
- Add more pkgconfig files

* Thu Jul 27 2006 Christopher Aillon <caillon@redhat.com> - 1.5.0.5-4
- Add pkgconfig files

* Thu Jul 27 2006 Christopher Aillon <caillon@redhat.com> - 1.5.0.5-3
- Don't strip provides when building the devel package

* Wed Jul 26 2006 Christopher Aillon <caillon@redhat.com> - 1.5.0.5-2
- Update to 1.5.0.5

* Mon Jul 24 2006 Christopher Aillon <caillon@redhat.com> - 1.5.0.4-4
- Ugh:
  - Mozilla the platform is deprecated
  - XULrunner has been promised for a while but is still not 1.0
  - Ship a firefox-devel for now as we need a devel platform.
  - The plan is to kill firefox-devel when xulrunner 1.0 ships. 
- Clean up the files list a little bit.

* Thu Jun 15 2006 Kai Engert <kengert@redhat.com> - 1.5.0.4-3
- Force "gmake -j1" on ppc ppc64 s390 s390x

* Mon Jun 12 2006 Kai Engert <kengert@redhat.com> - 1.5.0.4-2
- Firefox 1.5.0.4

* Thu May  4 2006 Christopher Aillon <caillon@redhat.com> - 1.5.0.3-2
- Firefox 1.5.0.3

* Wed Apr 19 2006 Christopher Aillon <caillon@redhat.com> - 1.5.0.2-4
- Really drop the broken langpacks this time.

* Tue Apr 18 2006 Christopher Aillon <caillon@redhat.com> - 1.5.0.2-3
- Drop some broken langpacks

* Thu Apr 13 2006 Christopher Aillon <caillon@redhat.com> - 1.5.0.2-2
- Firefox 1.5.0.2

* Sat Mar 11 2006 Christopher Aillon <caillon@redhat.com> - 1.5.0.1-9
- Add a notice to the about dialog denoting this is a pango enabled build.
- Tweak the user agent denoting this is a pango enabled build.

* Mon Mar  6 2006 Warren Togami <wtogami@redhat.com> - 1.5.0.1-7
- make links point to the correct release

* Mon Mar  6 2006 Ray Strode <rstrode@redhat.com> - 1.5.0.1-6
- Add new bookmarks file from Warren (bug 182386)

* Tue Feb 28 2006 Karsten Hopp <karsten@redhat.de>
- add buildrequires libXt-devel for X11/Intrinsic.h, X11/Shell.h

* Mon Feb 20 2006 Christopher Aillon <caillon@redhat.com> - 1.5.0.1-5
- Rebuild

* Mon Feb 20 2006 Christopher Aillon <caillon@redhat.com> - 1.5.0.1-4
- Ensure our wrapper handles URLs with commas/spaces (Ilya Konstantinov)
- Fix a pango typo

* Fri Feb 10 2006 Christopher Aillon <caillon@redhat.com> - 1.5.0.1-3
- Improve the langpack install stuff
- Fix up dumpstack.patch to match the finalized change

* Tue Feb  7 2006 Jesse Keating <jkeating@redhat.com> - 1.5.0.1-2.1
- rebuilt for new gcc4.1 snapshot and glibc changes

* Wed Feb  1 2006 Christopher Aillon <caillon@redhat.com> - 1.5.0.1-2
- Update language packs to 1.5.0.1
- Add dumpstack.patch

* Wed Feb  1 2006 Christopher Aillon <caillon@redhat.com> - 1.5.0.1-1
- Update to 1.5.0.1

* Thu Jan 26 2006 Christopher Aillon <caillon@redhat.com> - 1.5-5
- Ship langpacks again from upstream
- Stop providing MozillaFirebird and mozilla-firebird

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
