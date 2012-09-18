
Name:           dnssec-extras-release
Version:        1
Release:        0.3
Summary:        DNSSEC Extras Repository Configuration

Group:          System Environment/Base
License:        BSD
URL:            http://dnssec-tools.org/dnssec-extras
Source1:        dnssec-extras.repo
#Source2:        dnssec-extras-updates.repo
#Source3:        dnssec-extras-updates-testing.repo
#Source4:        dnssec-extras-rawhide.repo
Source16:       RPM-GPG-KEY-dnssec-extras-fedora-16
Source17:       RPM-GPG-KEY-dnssec-extras-fedora-17
Source18:       RPM-GPG-KEY-dnssec-extras-fedora-18
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildArch:      noarch

Requires:       system-release >= %{version}

# If apt is around, it needs to be a version with repomd support
Conflicts:      apt < 0.5.15lorg3

%description
The DNSSEC Extras repository contains open source software that has in
some way relates to DNSSEC. Several pagckages are patched versions of
packages with DNSSEC support added. In order to not conflict with
the base distributions packages, all packages use the alternative
prefix /usr/local/opt and a prefixed with "dt-".

This package contains the DNSSEC Extras GPG key as well as Yum package manager
configuration files for the DNSSEC Extras repository.

#%prep
#echo "Nothing to prep"

#%build
#echo "Nothing to build"

%install
rm -rf $RPM_BUILD_ROOT

# Create dirs
install -d -m755 \
  $RPM_BUILD_ROOT%{_sysconfdir}/pki/rpm-gpg  \
  $RPM_BUILD_ROOT%{_sysconfdir}/yum.repos.d

# GPG Key
%{__install} -Dp -m644 \
    %{SOURCE17} \
    %{SOURCE18} \
    $RPM_BUILD_ROOT%{_sysconfdir}/pki/rpm-gpg

# compatibility symlink for easy transition to F11
ln -s $(basename %{SOURCE17}) $RPM_BUILD_ROOT%{_sysconfdir}/pki/rpm-gpg/RPM-GPG-KEY-dnssec-extras-fedora

# Links for the keys
for i in i386 x86_64; do
  ln -s $(basename %{SOURCE16}) $RPM_BUILD_ROOT%{_sysconfdir}/pki/rpm-gpg/RPM-GPG-KEY-dnssec-extras-fedora-16-${i}
  ln -s $(basename %{SOURCE17}) $RPM_BUILD_ROOT%{_sysconfdir}/pki/rpm-gpg/RPM-GPG-KEY-dnssec-extras-fedora-17-${i}
  ln -s $(basename %{SOURCE17}) $RPM_BUILD_ROOT%{_sysconfdir}/pki/rpm-gpg/RPM-GPG-KEY-dnssec-extras-fedora-latest-${i}
  ln -s $(basename %{SOURCE18}) $RPM_BUILD_ROOT%{_sysconfdir}/pki/rpm-gpg/RPM-GPG-KEY-dnssec-extras-fedora-rawhide-${i}
done


# Yum .repo files
#%{__install} -p -m644 %{SOURCE1} %{SOURCE2} %{SOURCE3} %{SOURCE4} \
%{__install} -p -m644 %{SOURCE1} \
    $RPM_BUILD_ROOT%{_sysconfdir}/yum.repos.d


%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%{_sysconfdir}/pki/rpm-gpg/*
%config(noreplace) %{_sysconfdir}/yum.repos.d/*

%changelog
* Fri Jun 29 2012 Robert Story <rstory@tislabs.com> - 1-0.3
- Initial RPM release (based on rpmfusion's spec file)

