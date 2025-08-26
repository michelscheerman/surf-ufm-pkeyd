Name:           surf-ufm-pkeyd
Version:        1.0.0
Release:        1%{?dist}
Summary:        SURF UFM PKey Daemon for InfiniBand partition management

License:        GPL-3.0-or-later
URL:            https://github.com/michelscheerman/claude-code
Source0:        %{name}-%{version}.tar.gz

BuildArch:      noarch
BuildRequires:  python3-devel
BuildRequires:  systemd-rpm-macros

Requires:       python3
Requires:       python3-requests
Requires:       python3-pyyaml
Requires:       python3-urllib3
Requires:       systemd

%{?systemd_requires}

%description
SURF UFM PKey Daemon is a unified daemon that combines etcd monitoring, 
UFM PKey management, and direct etcd operations. Designed for SURF's 
SNELLIUS HPC cluster to manage InfiniBand partition keys automatically.

Features:
- Monitor etcd for PKey configuration changes and sync to NVIDIA UFM Enterprise  
- Direct UFM PKey management operations (list, create, delete, manage GUIDs)
- Direct etcd key-value operations (list, get, put, delete)
- PCOCC integration with automatic configuration loading
- Comprehensive logging and error handling
- SSL support with configurable verification

%prep
%autosetup

%build
# No build required for Python script

%install
# Create directories
install -d %{buildroot}%{_bindir}
install -d %{buildroot}%{_unitdir}
install -d %{buildroot}%{_sysconfdir}/pcocc
install -d %{buildroot}%{_docdir}/%{name}

# Install main script
install -m 755 surf_ufm_pkeyd.py %{buildroot}%{_bindir}/surf_ufm_pkeyd.py

# Install systemd service file
install -m 644 surf-ufm-pkeyd.service %{buildroot}%{_unitdir}/surf-ufm-pkeyd.service

# Install documentation
install -m 644 README.md %{buildroot}%{_docdir}/%{name}/README.md
install -m 644 requirements.txt %{buildroot}%{_docdir}/%{name}/requirements.txt

# Create configuration directory
install -d %{buildroot}%{_sysconfdir}/pcocc

%pre
# Create pcocc user and group
getent group pcocc >/dev/null || groupadd -r pcocc
getent passwd pcocc >/dev/null || \
    useradd -r -g pcocc -d /var/lib/pcocc -s /sbin/nologin \
    -c "PCOCC service account" pcocc
exit 0

%post
%systemd_post surf-ufm-pkeyd.service

# Set permissions on configuration directory
chown root:pcocc %{_sysconfdir}/pcocc
chmod 750 %{_sysconfdir}/pcocc

%preun
%systemd_preun surf-ufm-pkeyd.service

%postun
%systemd_postun_with_restart surf-ufm-pkeyd.service

%files
%doc %{_docdir}/%{name}/README.md
%doc %{_docdir}/%{name}/requirements.txt
%{_bindir}/surf_ufm_pkeyd.py
%{_unitdir}/surf-ufm-pkeyd.service
%dir %attr(750,root,pcocc) %{_sysconfdir}/pcocc

%changelog
* Mon Aug 26 2024 SURF SNELLIUS Team <support@surf.nl> - 1.0.0-1
- Initial RPM package
- Unified daemon with etcd monitoring and UFM PKey management
- PCOCC integration for automatic configuration
- Systemd service with proper logging to journalctl
- Security hardening with dedicated user account
- SSL support and comprehensive error handling