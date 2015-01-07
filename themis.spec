%define name themis
%define version 0.1
%define unmangled_version 0.1
%define unmangled_version 0.1
%define release 1

Summary: Postfix milter behavior rate limiter
Name: %{name}
Version: %{version}
Release: %{release}
Source0: %{name}-%{unmangled_version}.tar.gz
License: Apache2.0
Group: Development/Libraries
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-buildroot
Prefix: %{_prefix}
BuildArch: x86_64
Vendor: Sandro Mello <sandromll@gmail.com>
Url: https://github.com/sandromello/themis-py

BuildRequires: systemd, systemd-units
Requires: python2.7, systemd, themis-core, python-pyspf, python-pymilter >= 0.9 

%description
Themis is a policy daemon to predict and control the rate of sending mails in Postfix. Is designed for large scale mail hosting environments, build on top of the python-milter API. The features was built not only for rate limiting but also to provide useful information about your mail environment.

%prep
%setup -n %{name}-%{unmangled_version} -n %{name}-%{unmangled_version}
#%setup -q

%build
pushd src
popd

%install
%{__mkdir} -p %{buildroot}/%{_localstatedir}/log/themis
%{__mkdir} -p %{buildroot}/%{_sysconfdir}/themis
%{__mkdir} -p %{buildroot}/%{_bindir}
%{__mkdir} -p %{buildroot}/%{_unitdir}
%{__mkdir} -p %{buildroot}/%{_localstatedir}/log/themis

%{__install} -m 0600 src/config/config.yaml %{buildroot}/%{_sysconfdir}/themis/config.yaml
%{__install} -m 0644 src/systemd/themisd.service %{buildroot}/%{_unitdir}/themisd.service
%{__install} -m 755 src/themismilter.py %{buildroot}/%{_bindir}/themismilter.py
%{__cp} -f src/config/config.yaml %{buildroot}/%{_sysconfdir}/themis/config.yaml

%post
%systemd_post themisd.service

if ! getent passwd themisd > /dev/null; then
  adduser --user-group --system --no-create-home --shell /usr/sbin/nologin themisd
  usermod -g themisd themisd
fi
if ! getent group themisd > /dev/null; then
  groupadd --system themisd
  usermod -g themisd themisd
fi

if [ $1 -eq 1 ] ; then 
  # Initial installation
  /bin/systemctl enable themisd.service >/dev/null 2>&1 || :
fi

%preun
%systemd_preun themisd.service

%postun
%systemd_postun_with_restart themisd.service

%clean
rm -rf %{buildroot}

%files 
%defattr(0755,themisd,themisd,-)
%{_bindir}/themismilter.py*
%dir %{_localstatedir}/log/themis
%defattr(0600,themisd,themisd,-)
%{_sysconfdir}/themis/config.yaml
%defattr(0644,root,root,-)
%{_unitdir}/themisd.service
%doc CHANGELOG.md LICENSE
