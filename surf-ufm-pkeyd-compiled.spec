Name:           surf-ufm-pkeyd
Version:        1.0.0
Release:        1%{?dist}
Summary:        SURF UFM PKey Daemon for InfiniBand partition management (compiled)

License:        GPL-3.0-or-later
URL:            
Source0:        %{name}-%{version}.tar.gz

BuildArch:      x86_64
BuildRequires:  systemd-rpm-macros

# Disable debug package for compiled binary
%global debug_package %{nil}

# No Python runtime dependencies needed for compiled version
Requires:       systemd

%{?systemd_requires}

%description
SURF UFM PKey Daemon is a unified daemon that combines etcd monitoring, 
UFM PKey management, and direct etcd operations. Designed for SURF's 
SNELLIUS HPC cluster to manage InfiniBand partition keys automatically.

This is the compiled standalone executable version that doesn't require
Python runtime dependencies.

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
# No build required for pre-compiled executable

%install
# Create directories
install -d %{buildroot}%{_bindir}
install -d %{buildroot}%{_unitdir}
install -d %{buildroot}%{_sysconfdir}/pcocc
install -d %{buildroot}%{_docdir}/%{name}

# Install compiled executable
install -m 755 surf_ufm_pkeyd %{buildroot}%{_bindir}/surf_ufm_pkeyd

# Install systemd service file
install -m 644 surf-ufm-pkeyd.service %{buildroot}%{_unitdir}/surf-ufm-pkeyd.service

# Install documentation
install -m 644 README.md %{buildroot}%{_docdir}/%{name}/README.md
install -m 644 requirements.txt %{buildroot}%{_docdir}/%{name}/requirements.txt

# Create configuration directory
install -d %{buildroot}%{_sysconfdir}/pcocc

%pre
# No user creation needed - service runs as root

%post
%systemd_post surf-ufm-pkeyd.service

# Set permissions on configuration directory
chmod 755 %{_sysconfdir}/pcocc

%preun
%systemd_preun surf-ufm-pkeyd.service

%postun
%systemd_postun_with_restart surf-ufm-pkeyd.service

%files
%doc %{_docdir}/%{name}/README.md
%doc %{_docdir}/%{name}/requirements.txt
%{_bindir}/surf_ufm_pkeyd
%{_unitdir}/surf-ufm-pkeyd.service
%dir %attr(755,root,root) %{_sysconfdir}/pcocc

%changelog
* Mon Aug 26 2024 SURF SNELLIUS Team <support@surf.nl> - 1.0.0-1
- Initial RPM package for compiled version
- Standalone executable without Python runtime dependencies
- Unified daemon with etcd monitoring and UFM PKey management
- PCOCC integration for automatic configuration
- Systemd service with proper logging to journalctl
- Security hardening and comprehensive error handling
