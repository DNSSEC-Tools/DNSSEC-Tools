# Separated plugins are supported on x86(64) only
%ifarch %{ix86} x86_64
%define separated_plugins 1
%else
%define separated_plugins 0
%endif

# Build as a debug package?
%define debug_build       0

%if 0%{?fedora}
%define homepage http://start.fedoraproject.org/
%else
%define homepage file:///usr/share/doc/HTML/index.html
%endif
%define default_bookmarks_file %{_datadir}/bookmarks/default-bookmarks.html
%define firefox_app_id \{ec8030f7-c20a-464f-9b0e-13a3a9e97384\}

%global xulrunner_version      15.0
%global xulrunner_release      1
%global alpha_version          0
%global beta_version           0
%global rc_version             0

%global mozappdir     %{_libdir}/%{name}
%global langpackdir   %{mozappdir}/langpacks
%global tarballdir    mozilla-release

%define official_branding       1
%define build_langpacks         1
%define include_debuginfo       0

%if %{alpha_version} > 0
%global pre_version a%{alpha_version}
%global pre_name    alpha%{alpha_version}
%global tarballdir  mozilla-alpha
%endif
%if %{beta_version} > 0
%global pre_version b%{beta_version}
%global pre_name    beta%{beta_version}
%global tarballdir  mozilla-beta
%endif
%if %{rc_version} > 0
%global pre_version rc%{rc_version}
%global pre_name    rc%{rc_version}
%global tarballdir  mozilla-release
%endif
%if %{defined pre_version}
%global xulrunner_verrel %{xulrunner_version}-%{xulrunner_release}%{pre_name}
%global pre_tag .%{pre_version}
%else
%global xulrunner_verrel %{xulrunner_version}-%{xulrunner_release}
%endif

Summary:        Mozilla Firefox Web browser
Name:           firefox
Version:        15.0
Release:        1%{?pre_tag}%{?dist}
URL:            http://www.mozilla.org/projects/firefox/
License:        MPLv1.1 or GPLv2+ or LGPLv2+
Group:          Applications/Internet
Source0:        ftp://ftp.mozilla.org/pub/firefox/releases/%{version}%{?pre_version}/source/firefox-%{version}%{?pre_version}.source.tar.bz2
%if %{build_langpacks}
Source1:        firefox-langpacks-%{version}%{?pre_version}-20120827.tar.xz
%endif
Source10:       firefox-mozconfig
Source11:       firefox-mozconfig-branded
Source12:       firefox-redhat-default-prefs.js
Source13:       firefox-mozconfig-debuginfo
Source20:       firefox.desktop
Source21:       firefox.sh.in
Source23:       firefox.1

#Build patches
Patch0:         firefox-install-dir.patch

# Fedora patches
Patch14:        firefox-5.0-asciidel.patch
Patch15:        firefox-15.0-enable-addons.patch

# Upstream patches

%if %{official_branding}
# Required by Mozilla Corporation


%else
# Not yet approved by Mozillla Corporation


%endif

# ---------------------------------------------------

BuildRequires:  desktop-file-utils
BuildRequires:  system-bookmarks
BuildRequires:  xulrunner-devel%{?_isa} >= %{xulrunner_verrel}

Requires:       xulrunner%{?_isa} >= %{xulrunner_verrel}
Requires:       system-bookmarks
Obsoletes:      mozilla <= 37:1.7.13
Provides:       webclient

%description
Mozilla Firefox is an open-source web browser, designed for standards
compliance, performance and portability.

#---------------------------------------------------------------------

%prep
%setup -q -c
cd %{tarballdir}

# Build patches, can't change backup suffix from default because during build
# there is a compare of config and js/config directories and .orig suffix is 
# ignored during this compare.
%patch0 -p2 -b .orig

# For branding specific patches.

# Fedora patches
%patch14 -p1 -b .asciidel
%patch15 -p2 -b .addons

# Upstream patches

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
%if %{include_debuginfo}
%{__cat} %{SOURCE13} >> .mozconfig
%endif

# Set up SDK path
echo "ac_add_options --with-libxul-sdk=\
`pkg-config --variable=sdkdir libxul`" >> .mozconfig

%if !%{?separated_plugins}
echo "ac_add_options --disable-ipc" >> .mozconfig
%endif

%ifarch %{arm}
echo "ac_add_options --disable-elf-hack" >> .mozconfig
%endif

%if %{?debug_build}
echo "ac_add_options --enable-debug" >> .mozconfig
echo "ac_add_options --disable-optimize" >> .mozconfig
%else
echo "ac_add_options --disable-debug" >> .mozconfig
echo "ac_add_options --enable-optimize" >> .mozconfig
%endif

#---------------------------------------------------------------------

%build
cd %{tarballdir}

# Mozilla builds with -Wall with exception of a few warnings which show up
# everywhere in the code; so, don't override that.
#
# Disable C++ exceptions since Mozilla code is not exception-safe
#
MOZ_OPT_FLAGS=$(echo $RPM_OPT_FLAGS | \
                     %{__sed} -e 's/-Wall//' -e 's/-fexceptions/-fno-exceptions/g')
%if %{?debug_build}
MOZ_OPT_FLAGS=$(echo "$MOZ_OPT_FLAGS" | %{__sed} -e 's/-O2//')
%endif
export CFLAGS=$MOZ_OPT_FLAGS
export CXXFLAGS=$MOZ_OPT_FLAGS

export PREFIX='%{_prefix}'
export LIBDIR='%{_libdir}'

MOZ_SMP_FLAGS=-j1
# On x86 architectures, Mozilla can build up to 4 jobs at once in parallel,
# however builds tend to fail on other arches when building in parallel.
%ifarch %{ix86} x86_64
[ -z "$RPM_BUILD_NCPUS" ] && \
     RPM_BUILD_NCPUS="`/usr/bin/getconf _NPROCESSORS_ONLN`"
[ "$RPM_BUILD_NCPUS" -ge 2 ] && MOZ_SMP_FLAGS=-j2
[ "$RPM_BUILD_NCPUS" -ge 4 ] && MOZ_SMP_FLAGS=-j4
%endif

export LDFLAGS="-Wl,-rpath,%{mozappdir}"
make -f client.mk build STRIP="/bin/true" MOZ_MAKE_FLAGS="$MOZ_SMP_FLAGS"

# create debuginfo for crash-stats.mozilla.com
%if %{include_debuginfo}
#cd %{moz_objdir}
make buildsymbols
%endif

#---------------------------------------------------------------------

%install
cd %{tarballdir}

# set up our prefs and add it to the package manifest file, so it gets pulled in
# to omni.jar which gets created during make install
%{__cp} %{SOURCE12} dist/bin/defaults/preferences/all-redhat.js
# This sed call "replaces" firefox.js with all-redhat.js, newline, and itself (&)
# having the net effect of prepending all-redhat.js above firefox.js
%{__sed} -i -e\
    's|@BINPATH@/@PREF_DIR@/firefox.js|@BINPATH@/@PREF_DIR@/all-redhat.js\n&|' \
    browser/installer/package-manifest.in

# set up our default bookmarks
%{__cp} -p %{default_bookmarks_file} dist/bin/defaults/profile/bookmarks.html

# Make sure locale works for langpacks
%{__cat} > dist/bin/defaults/preferences/firefox-l10n.js << EOF
pref("general.useragent.locale", "chrome://global/locale/intl.properties");
EOF

# resolves bug #461880
%{__cat} > dist/bin/chrome/en-US/locale/branding/browserconfig.properties << EOF
browser.startup.homepage=%{homepage}
EOF

DESTDIR=$RPM_BUILD_ROOT make install

%{__mkdir_p} $RPM_BUILD_ROOT{%{_libdir},%{_bindir},%{_datadir}/applications}

%if 0%{?fedora} <= 16
desktop-file-install --vendor mozilla --dir $RPM_BUILD_ROOT%{_datadir}/applications %{SOURCE20}
%else
desktop-file-install --dir $RPM_BUILD_ROOT%{_datadir}/applications %{SOURCE20}
%endif

# set up the firefox start script
%{__rm} -rf $RPM_BUILD_ROOT%{_bindir}/firefox
XULRUNNER_DIR=`pkg-config --variable=libdir libxul | %{__sed} -e "s,%{_libdir},,g"`
%{__cat} %{SOURCE21} | %{__sed} -e "s,XULRUNNER_DIRECTORY,$XULRUNNER_DIR,g" > \
  $RPM_BUILD_ROOT%{_bindir}/firefox
%{__chmod} 755 $RPM_BUILD_ROOT%{_bindir}/firefox

# Link with xulrunner 
ln -s `pkg-config --variable=libdir libxul` $RPM_BUILD_ROOT/%{mozappdir}/xulrunner

%{__install} -p -D -m 644 %{SOURCE23} $RPM_BUILD_ROOT%{_mandir}/man1/firefox.1

%{__rm} -f $RPM_BUILD_ROOT/%{mozappdir}/firefox-config
%{__rm} -f $RPM_BUILD_ROOT/%{mozappdir}/update-settings.ini

for s in 16 22 24 32 48 256; do
    %{__mkdir_p} $RPM_BUILD_ROOT%{_datadir}/icons/hicolor/${s}x${s}/apps
    %{__cp} -p browser/branding/official/default${s}.png \
               $RPM_BUILD_ROOT%{_datadir}/icons/hicolor/${s}x${s}/apps/firefox.png
done

echo > ../%{name}.lang
%if %{build_langpacks}
# Extract langpacks, make any mods needed, repack the langpack, and install it.
%{__mkdir_p} $RPM_BUILD_ROOT%{langpackdir}
%{__tar} xf %{SOURCE1}
for langpack in `ls firefox-langpacks/*.xpi`; do
  language=`basename $langpack .xpi`
  extensionID=langpack-$language@firefox.mozilla.org
  %{__mkdir_p} $extensionID
  unzip $langpack -d $extensionID
  find $extensionID -type f | xargs chmod 644

  sed -i -e "s|browser.startup.homepage.*$|browser.startup.homepage=%{homepage}|g;" \
     $extensionID/chrome/$language/locale/branding/browserconfig.properties

  cd $extensionID
  zip -r9mX ../${extensionID}.xpi *
  cd -

  %{__install} -m 644 ${extensionID}.xpi $RPM_BUILD_ROOT%{langpackdir}
  language=`echo $language | sed -e 's/-/_/g'`
  echo "%%lang($language) %{langpackdir}/${extensionID}.xpi" >> ../%{name}.lang
done
%{__rm} -rf firefox-langpacks
%endif # build_langpacks

# Install langpack workaround (see #707100, #821169)
function create_default_langpack() {
language_long=$1
language_short=$2
cd $RPM_BUILD_ROOT%{langpackdir}
ln -s langpack-$language_long@firefox.mozilla.org.xpi langpack-$language_short@firefox.mozilla.org.xpi
cd -
echo "%%lang($language_short) %{langpackdir}/langpack-$language_short@firefox.mozilla.org.xpi" >> ../%{name}.lang
}

# Table of fallbacks for each language
# please file a bug at bugzilla.redhat.com if the assignment is incorrect
create_default_langpack "bn-IN" "bn"
create_default_langpack "es-AR" "es"
create_default_langpack "fy-NL" "fy"
create_default_langpack "ga-IE" "ga"
create_default_langpack "gu-IN" "gu"
create_default_langpack "hi-IN" "hi"
create_default_langpack "hy-AM" "hy"
create_default_langpack "nb-NO" "nb"
create_default_langpack "nn-NO" "nn"
create_default_langpack "pa-IN" "pa"
create_default_langpack "pt-PT" "pt"
create_default_langpack "sv-SE" "sv"
create_default_langpack "zh-TW" "zh"

# System extensions
%{__mkdir_p} $RPM_BUILD_ROOT%{_datadir}/mozilla/extensions/%{firefox_app_id}
%{__mkdir_p} $RPM_BUILD_ROOT%{_libdir}/mozilla/extensions/%{firefox_app_id}

# Copy over the LICENSE
%{__install} -p -c -m 644 LICENSE $RPM_BUILD_ROOT/%{mozappdir}

# Enable crash reporter for Firefox application
%if %{include_debuginfo}
sed -i -e "s/\[Crash Reporter\]/[Crash Reporter]\nEnabled=1/" $RPM_BUILD_ROOT/%{mozappdir}/application.ini
%endif

#---------------------------------------------------------------------

%preun
# is it a final removal?
if [ $1 -eq 0 ]; then
  %{__rm} -rf %{mozappdir}/components
  %{__rm} -rf %{mozappdir}/extensions
  %{__rm} -rf %{mozappdir}/plugins
  %{__rm} -rf %{langpackdir}
fi

%post
update-desktop-database &> /dev/null || :
touch --no-create %{_datadir}/icons/hicolor &>/dev/null || :

%postun
update-desktop-database &> /dev/null || :
if [ $1 -eq 0 ] ; then
    touch --no-create %{_datadir}/icons/hicolor &>/dev/null
    gtk-update-icon-cache %{_datadir}/icons/hicolor &>/dev/null || :
fi

%posttrans
gtk-update-icon-cache %{_datadir}/icons/hicolor &>/dev/null || :

%files -f %{name}.lang
%defattr(-,root,root,-)
%{_bindir}/firefox
%{mozappdir}/firefox
%doc %{_mandir}/man1/*
%dir %{_datadir}/mozilla/extensions/%{firefox_app_id}
%dir %{_libdir}/mozilla/extensions/%{firefox_app_id}
%{_datadir}/applications/*.desktop
%dir %{mozappdir}
%doc %{mozappdir}/LICENSE
%{mozappdir}/chrome
%{mozappdir}/chrome.manifest
%dir %{mozappdir}/components
%{mozappdir}/components/*.so
%{mozappdir}/components/binary.manifest
%{mozappdir}/defaults/preferences/channel-prefs.js
%attr(644, root, root) %{mozappdir}/blocklist.xml
%dir %{mozappdir}/extensions
%{mozappdir}/extensions/{972ce4c6-7e08-4474-a285-3208198ce6fd}
%if %{build_langpacks}
%dir %{langpackdir}
%endif
%{mozappdir}/omni.ja
%{mozappdir}/icons
%{mozappdir}/searchplugins
%{mozappdir}/run-mozilla.sh
%{mozappdir}/application.ini
%exclude %{mozappdir}/removed-files
%{_datadir}/icons/hicolor/16x16/apps/firefox.png
%{_datadir}/icons/hicolor/22x22/apps/firefox.png
%{_datadir}/icons/hicolor/24x24/apps/firefox.png
%{_datadir}/icons/hicolor/256x256/apps/firefox.png
%{_datadir}/icons/hicolor/32x32/apps/firefox.png
%{_datadir}/icons/hicolor/48x48/apps/firefox.png
%{mozappdir}/xulrunner

%if %{include_debuginfo}
#%{mozappdir}/crashreporter
%{mozappdir}/crashreporter-override.ini
#%{mozappdir}/Throbber-small.gif
#%{mozappdir}/plugin-container
%endif

#---------------------------------------------------------------------

%changelog
* Mon Aug 27 2012 Martin Stransky <stransky@redhat.com> - 15.0-1
- Update to 15.0

* Wed Aug 22 2012 Dan Horák <dan[at]danny.cz> - 14.0.1-3
- add fix for secondary arches from xulrunner

* Wed Aug 1 2012 Martin Stransky <stransky@redhat.com> - 14.0.1-2
- removed StartupWMClass (rhbz#844860)

* Mon Jul 16 2012 Martin Stransky <stransky@redhat.com> - 14.0.1-1
- Update to 14.0.1

* Tue Jul 10 2012 Martin Stransky <stransky@redhat.com> - 13.0.1-2
- Fixed rhbz#707100, rhbz#821169

* Sat Jun 16 2012 Jan Horak <jhorak@redhat.com> - 13.0.1-1
- Update to 13.0.1

* Tue Jun 5 2012 Martin Stransky <stransky@redhat.com> - 13.0-1
- Update to 13.0

* Tue Apr 24 2012 Martin Stransky <stransky@redhat.com> - 12.0-1
- Update to 12.0

* Thu Mar 15 2012 Martin Stransky <stransky@redhat.com> - 11.0-2
- Switched dependency to xulrunner (rhbz#803471)

* Tue Mar 13 2012 Martin Stransky <stransky@redhat.com> - 11.0-1
- Update to 11.0
- Fixed rhbz#800622 - make default home page of fedoraproject.org conditional
- Fixed rhbz#801796 - enable debug build by some simple way

* Mon Feb 27 2012 Peter Robinson <pbrobinson@fedoraproject.org> - 10.0.1-2
- Add ARM config options to fix compile

* Thu Feb  9 2012 Jan Horak <jhorak@redhat.com> - 10.0.1-1
- Update to 10.0.1

* Fri Feb  3 2012 Jan Horak <jhorak@redhat.com> - 10.0-2
- Fixed rhbz#786983

* Tue Jan 31 2012 Jan Horak <jhorak@redhat.com> - 10.0-1
- Update to 10.0

* Fri Jan 13 2012 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 9.0.1-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_17_Mass_Rebuild

* Fri Dec 23 2011 Jan Horak <jhorak@redhat.com> - 9.0.1-1
- Update to 9.0.1

* Wed Dec 21 2011 Jan Horak <jhorak@redhat.com> - 9.0-3
- Update to 9.0

* Thu Dec 15 2011 Jan Horak <jhorak@redhat.com> - 9.0-1.beta5
- Update to 9.0 Beta 5

* Tue Nov 15 2011 Martin Stransky <stransky@redhat.com> - 8.0-3
- Disabled addon check UI (#753551)

* Tue Nov 15 2011 Martin Stransky <stransky@redhat.com> - 8.0-2
- Temporary workaround for langpacks (#753551)

* Tue Nov  8 2011 Jan Horak <jhorak@redhat.com> - 8.0-1
- Update to 8.0

* Mon Oct 24 2011 Martin Stransky <stransky@redhat.com> - 7.0.1-3
- reverted the desktop file name for Fedora15 & 16

* Mon Oct 24 2011 Martin Stransky <stransky@redhat.com> - 7.0.1-2
- renamed mozilla-firefox.desktop to firefox.desktop (#736558)
- nspluginwrapper is not run in plugin-container (#747981)

* Fri Sep 30 2011 Jan Horak <jhorak@redhat.com> - 7.0.1-1
- Update to 7.0.1

* Tue Sep 27 2011 Jan Horak <jhorak@redhat.com> - 7.0
- Update to 7.0

* Tue Sep  6 2011 Jan Horak <jhorak@redhat.com> - 6.0.2-1
- Update to 6.0.2

* Tue Aug 16 2011 Martin Stransky <stransky@redhat.com> - 6.0-1
- Update to 6.0

* Fri Jun 24 2011 Bill Nottingham <notting@redhat.com> - 5.0-2
- Fix an issue with a stray glyph in the window title

* Tue Jun 21 2011 Martin Stransky <stransky@redhat.com> - 5.0-1
- Update to 5.0

* Tue May 10 2011 Martin Stransky <stransky@redhat.com> - 4.0.1-2
- Fixed rhbz#676183 - "firefox -g" is broken

* Thu Apr 28 2011 Christopher Aillon <caillon@redhat.com> - 4.0.1-1
- Update to 4.0.1

* Thu Apr 21 2011 Christopher Aillon <caillon@redhat.com> - 4.0-4
- Spec file cleanups

* Mon Apr  4 2011 Christopher Aillon <caillon@redhat.com> - 4.0-3
- Updates for NetworkManager 0.9
- Updates for GNOME 3

* Tue Mar 22 2011 Christopher Aillon <caillon@redhat.com> - 4.0-2
- Rebuild

* Tue Mar 22 2011 Christopher Aillon <caillon@redhat.com> - 4.0-1
- Firefox 4

* Fri Mar 18 2011 Christopher Aillon <caillon@redhat.com> - 4.0-0.21
- Firefox 4.0 RC 2

* Thu Mar 17 2011 Jan Horak <jhorak@redhat.com> - 4.0-0.20
- Rebuild against xulrunner with disabled gnomevfs and enabled gio

* Wed Mar  9 2011 Christopher Aillon <caillon@redhat.com> - 4.0-0.19
- Firefox 4.0 RC 1

* Sat Feb 26 2011 Christopher Aillon <caillon@redhat.com> - 4.0-0.18b12
- Switch to using the omni chrome file format

* Fri Feb 25 2011 Christopher Aillon <caillon@redhat.com> - 4.0-0.17b12
- Firefox 4.0 Beta 12

* Thu Feb 10 2011 Christopher Aillon <caillon@redhat.com> - 4.0-0.16b11
- Update gecko-{libs,devel} requires

* Tue Feb 08 2011 Christopher Aillon <caillon@redhat.com> - 4.0-0.15b11
- Firefox 4.0 Beta 11

* Mon Feb 07 2011 Christopher Aillon <caillon@redhat.com> - 4.0-0.14b10
- Bring back the default browser check

* Tue Jan 25 2011 Christopher Aillon <caillon@redhat.com> - 4.0-0.13b10
- Firefox 4.0 Beta 10

* Fri Jan 14 2011 Christopher Aillon <caillon@redhat.com> - 4.0-0.12b9
- Firefox 4.0 Beta 9

* Thu Jan 6 2011 Dan Horák <dan[at]danny.cz> - 4.0-0.11b8
- disable ipc on non-x86 arches to match xulrunner

* Thu Jan 6 2011 Martin Stransky <stransky@redhat.com> - 4.0-0.10b8
- application.ini permission check fix

* Thu Jan 6 2011 Martin Stransky <stransky@redhat.com> - 4.0-0.9b8
- Fixed rhbz#667477 - broken launch script

* Tue Jan 4 2011 Martin Stransky <stransky@redhat.com> - 4.0-0.8b8
- Fixed rhbz#664877 - Cannot read application.ini

* Tue Dec 21 2010 Martin Stransky <stransky@redhat.com> - 4.0-0.7b8
- Update to Beta 8
- Fixed rhbz#437608 - When prelink is installed, 
  rpm builds are garbage

* Wed Dec  8 2010 Christopher Aillon <caillon@redhat.com> - 4.0-0.6b7
- Use official branding since this is an official beta
- Fix Tab Candy/Panorama (#658573)

* Thu Nov 11 2010 Jan Horak <jhorak@redhat.com> - 4.0b7-1
- Update to 4.0b7
- Added x-scheme-handler to firefox.desktop

* Wed Sep 29 2010 jkeating - 4.0-0.4b6
- Rebuilt for gcc bug 634757

* Tue Sep 21 2010 Martin Stransky <stransky@redhat.com> - 4.0-0.3.b6
- Update to 4.0 Beta 6

* Tue Sep  7 2010 Tom "spot" Callaway <tcallawa@redhat.com> - 4.0-0.2.b4
- get package building and mostly functional

* Mon Aug 30 2010 Martin Stransky <stransky@redhat.com> - 4.0-0.1.b4
- Update to 4.0 Beta 4

* Tue Jun 24 2010 Martin Stransky <stransky@redhat.com> - 3.6.4-2
- Fixed rhbz#531159 - disable firefox default browser check
- Disabled automatic updates

* Wed Jun 23 2010 Jan Horak <jhorak@redhat.com> -3.6.4-1
- Update to 3.6.4

* Tue Apr 13 2010 Martin Stransky <stransky@redhat.com> - 3.6.3-4
- Fixed language packs (#559960)

* Mon Apr 12 2010 Martin Stransky <stransky@redhat.com> - 3.6.3-3
- Fixed multilib conflict

* Tue Apr 6 2010 Martin Stransky <stransky@redhat.com> - 3.6.3-2
- Fixed install dir

* Sat Apr 3 2010 Martin Stransky <stransky@redhat.com> - 3.6.3-1
- Update to 3.6.3

* Tue Mar 23 2010 Jan Horak <jhorak@redhat.com> - 3.6.2-1
- Update to 3.6.2

* Wed Feb 24 2010 Martin Stransky <stransky@redhat.com> - 3.6.1-2
- Added fix for #559960 - [all Lang]Translation is not 
  available with 3.6 release

* Wed Jan 18 2010 Martin Stransky <stransky@redhat.com> - 3.6.1-1
- Update to 3.6

* Wed Jan 18 2010 Martin Stransky <stransky@redhat.com> - 3.6.1-0.11.rc2
- Update to 3.6.1 RC2
- Fix for #556428 - Restricted maximal xulrunner version

* Wed Jan 13 2010 Martin Stransky <stransky@redhat.com> - 3.6.1-0.10.rc1
- Update to 3.6.1 RC1

* Thu Jan 7 2010 Martin Stransky <stransky@redhat.com> - 3.6.1-0.9.b4
- firefox.sh fixes (error messages, #553184)

* Tue Jan 5 2010 Martin Stransky <stransky@redhat.com> - 3.6.1-0.8.b4
- Removed MOZ_LOCAL_LANGPACKS from browser launcher script (#284011)

* Mon Dec 21 2009 Martin Stransky <stransky@redhat.com> - 3.6.1-0.7.b4
- Update to 3.6.1 Beta 5

* Wed Nov 27 2009 Martin Stransky <stransky@redhat.com> - 3.6.1-0.6.b4
- Added fix for mozbz#526152 - jemalloc fix

* Wed Nov 27 2009 Martin Stransky <stransky@redhat.com> - 3.6.1-0.5.b4
- Update to 3.6.1 Beta 4

* Wed Nov 25 2009 Martin Stransky <stransky@redhat.com> - 3.6.1-0.4.b3
- Language pack updated (#284011)

* Fri Nov 20 2009 Martin Stransky <stransky@redhat.com> - 3.6.1-0.3.b3
- Necko wifi monitor disabled
- Added source URL (#521704)

* Wed Nov 18 2009 Martin Stransky <stransky@redhat.com> - 3.6.1-0.2.b3
- Rebase to 3.6.1 Beta 3

* Fri Nov 13 2009 Martin Stransky <stransky@redhat.com> - 3.6.1-0.1.b2
- Rebase to 3.6.1 Beta 2

* Thu Nov  5 2009 Jan Horak <jhorak@redhat.com> - 3.5.5-1
- Update to 3.5.5

* Mon Oct 26 2009 Jan Horak <jhorak@redhat.com> - 3.5.4-1
- Update to 3.5.4

* Mon Sep  7 2009 Jan Horak <jhorak@redhat.com> - 3.5.3-1
- Update to 3.5.3

* Thu Aug 6 2009 Martin Stransky <stransky@redhat.com> - 3.5.2-3
- Rebuilt

* Thu Aug 6 2009 Martin Stransky <stransky@redhat.com> - 3.5.2-2
- Fix for #437596 - Firefox needs to register proper name
  for session restore.

* Mon Aug  3 2009 Christopher Aillon <caillon@redhat.com> - 3.5.2-1
- Update to 3.5.2

* Fri Jul 24 2009 Jan Horak <jhorak@redhat.com> - 3.5.1-3
- Adjust icons cache update according to template

* Wed Jul 22 2009 Jan Horak <jhorak@redhat.com> - 3.5.1-2
- New icons fixed

* Fri Jul 17 2009 Christopher Aillon <caillon@redhat.com> - 3.5.1-1
- Update to 3.5.1

* Mon Jul 13 2009 Jan Horak <jhorak@redhat.com> - 3.5-2
- Updated icon

* Tue Jun 30 2009 Christopher Aillon <caillon@redhat.com> - 3.5-1
- Firefox 3.5 final release

* Tue May 26 2009 Martin Stransky <stransky@redhat.com> - 3.5-0.21
- fix for #502541 - Firefox version should depend 
  on Xulrunner but does not

* Mon Apr 27 2009 Christopher Aillon <caillon@redhat.com> - 3.5-0.20
- 3.5 beta 4

* Fri Mar 27 2009 Christopher Aillon <caillon@redhat.com> - 3.1-0.11
- Rebuild against newer gecko

* Fri Mar 13 2009 Christopher Aillon <caillon@redhat.com> - 3.1-0.10
- 3.1 beta 3

* Tue Feb 24 2009 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 3.1-0.7.beta2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_11_Mass_Rebuild

* Wed Feb 11 2009 Christopher Aillon <caillon@redhat.com> - 3.1-0.6
- Drop explicit requirement on desktop-file-utils

* Wed Jan  7 2009 Jan Horak <jhorak@redhat.com> - 3.1-0.5
- Fixed wrong LANG and LC_MESSAGES variables interpretation (#441973) 
  in startup script.

* Sat Dec 20 2008 Christopher Aillon <caillon@redhat.com> 3.1-0.4
- 3.1 beta 2

* Tue Dec  9 2008 Christopher Aillon <caillon@redhat.com> 3.1-0.3
- Rebuild

* Thu Dec  4 2008 Christopher Aillon <caillon@redhat.com> 3.1-0.1
- Update to 3.1 beta 1

* Tue Nov 11 2008 Jan Horak <jhorak@redhat.com> 3.0.2-2
- Removed firefox-2.0-getstartpage.patch patch 
- Start page is set by different way

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
