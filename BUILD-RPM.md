# Building RPM Package for SURF UFM PKey Daemon

## Prerequisites

Install required packages:

```bash
sudo dnf install -y rpm-build rpmdevtools
```

## Setup RPM Build Environment

```bash
rpmdev-setuptree
```

This creates the RPM build directory structure in `~/rpmbuild/`.

## Build Process

1. **Create source tarball:**
   ```bash
   # Create directory for source files
   mkdir surf-ufm-pkeyd-1.0.0
   
   # Copy source files
   cp surf_ufm_pkeyd.py surf-ufm-pkeyd-1.0.0/
   cp surf-ufm-pkeyd.service surf-ufm-pkeyd-1.0.0/
   cp README.md surf-ufm-pkeyd-1.0.0/
   cp requirements.txt surf-ufm-pkeyd-1.0.0/
   
   # Create tarball
   tar czf surf-ufm-pkeyd-1.0.0.tar.gz surf-ufm-pkeyd-1.0.0/
   
   # Move to SOURCES directory
   mv surf-ufm-pkeyd-1.0.0.tar.gz ~/rpmbuild/SOURCES/
   
   # Clean up
   rm -rf surf-ufm-pkeyd-1.0.0/
   ```

2. **Copy spec file:**
   ```bash
   cp surf-ufm-pkeyd.spec ~/rpmbuild/SPECS/
   ```

3. **Build RPM:**
   ```bash
   rpmbuild -bb ~/rpmbuild/SPECS/surf-ufm-pkeyd.spec
   ```

## Installation

After building, install the RPM:

```bash
sudo dnf install ~/rpmbuild/RPMS/noarch/surf-ufm-pkeyd-1.0.0-1*.noarch.rpm
```

## Configuration

Before starting the service, create configuration files:

1. **UFM Configuration** (`/etc/pcocc/ufm.yaml`):
   ```yaml
   settings:
     ufm-auth-type: password
     ufm-servers:
     - ufm1.local.snellius.surf.nl
   ```

2. **UFM Password** (`/etc/pcocc/ufm-password`):
   ```bash
   echo "your_ufm_password" | sudo tee /etc/pcocc/ufm-password
   sudo chmod 600 /etc/pcocc/ufm-password
   sudo chown root:root /etc/pcocc/ufm-password
   ```

3. **etcd Configuration** (`/etc/pcocc/batch.yaml`):
   ```yaml
   settings:
     etcd-servers: ["etcd1.local", "etcd2.local"]
     etcd-client-port: 2379
     etcd-protocol: "https"
     etcd-ca-cert: "/etc/pcocc/ca.crt"
   ```

4. **etcd Password** (`/etc/pcocc/etcd-password`):
   ```bash
   echo "your_etcd_password" | sudo tee /etc/pcocc/etcd-password
   sudo chmod 600 /etc/pcocc/etcd-password
   sudo chown root:root /etc/pcocc/etcd-password
   ```

## Service Management

```bash
# Enable service
sudo systemctl enable surf-ufm-pkeyd

# Start service
sudo systemctl start surf-ufm-pkeyd

# Check status
sudo systemctl status surf-ufm-pkeyd

# View logs
sudo journalctl -u surf-ufm-pkeyd -f

# Stop service
sudo systemctl stop surf-ufm-pkeyd

# Restart service
sudo systemctl restart surf-ufm-pkeyd
```

## Package Contents

The RPM installs:

- `/usr/bin/surf_ufm_pkeyd.py` - Main daemon script
- `/etc/systemd/system/surf-ufm-pkeyd.service` - Systemd service unit
- `/etc/pcocc/` - Configuration directory (owned by root:root, 755 permissions)
- `/usr/share/doc/surf-ufm-pkeyd/` - Documentation files

## Security Features

- Runs as root for full system access when needed
- Configuration files secured with 600 permissions (root-only access)
- Systemd security hardening enabled
- No network privileges beyond what's needed
- Resource limits enforced