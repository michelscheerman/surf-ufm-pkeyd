# SURF UFM PKey Daemon

A unified daemon that combines etcd monitoring, UFM PKey management, and direct etcd operations. Designed for SURF's SNELLIUS HPC cluster to manage InfiniBand partition keys automatically.

## Features

- **Monitor Mode**: Automatically monitor etcd for PKey configuration changes and sync to NVIDIA UFM Enterprise
- **UFM Mode**: Direct UFM PKey management operations (list, create, delete, manage GUIDs)
- **ETCD Mode**: Direct etcd key-value operations (list, get, put, delete)
- **PCOCC Integration**: Automatic configuration loading from `/etc/pcocc/batch.yaml`
- **Password File Support**: Automatic password loading from `/etc/pcocc/etcd-password`
- **Comprehensive Logging**: Debug logging and error handling
- **SSL Support**: Configurable SSL verification and certificate handling
- **Protocol Flexibility**: Support for both HTTP and HTTPS for etcd and UFM

## Installation

```bash
# Install required Python packages
pip install -r requirements.txt

# Make the script executable
chmod +x surf_ufm_pkeyd.py
```

## Configuration

The daemon automatically loads configuration from PCOCC files when available:

- **etcd Configuration**: `/etc/pcocc/batch.yaml` 
- **etcd Password**: `/etc/pcocc/etcd-password`

### PCOCC batch.yaml Format
```yaml
cluster:
  etcd:
    servers: ["etcd1.local", "etcd2.local", "etcd3.local"]
    port: 2379
    protocol: "https"  # or "http"
    ca_cert: "/etc/pcocc/ca.crt"
```

## Usage

### Monitor Mode (Default)

Continuously monitor etcd for PKey changes and automatically configure them in UFM.

```bash
# Basic monitoring with automatic PCOCC configuration
./surf_ufm_pkeyd.py monitor --ufm-host ufm1.local --ufm-user admin --ufm-password secret

# Monitoring with custom etcd configuration
./surf_ufm_pkeyd.py monitor \
  --ufm-host ufm1.local.snellius.surf.nl \
  --ufm-user admin \
  --ufm-password 123456 \
  --no-ssl-verify \
  --etcd-user root \
  --etcd-host etcd.local \
  --poll-interval 60 \
  --debug

# Monitoring with certificate authentication
./surf_ufm_pkeyd.py monitor \
  --ufm-host ufm1.local \
  --ufm-user admin \
  --ufm-password secret \
  --etcd-ca-cert /path/to/ca.crt \
  --etcd-cert-file /path/to/client.crt \
  --etcd-key-file /path/to/client.key \
  --etcd-user root

# Monitoring with multiple etcd endpoints
./surf_ufm_pkeyd.py monitor \
  --ufm-host ufm1.local \
  --ufm-user admin \
  --ufm-password secret \
  --etcd-endpoints "etcd1.local:2379,etcd2.local:2379,etcd3.local:2379" \
  --etcd-user root
```

### UFM Mode

Direct UFM PKey management operations.

```bash
# List all PKeys
./surf_ufm_pkeyd.py ufm --host ufm1.local --username admin --password secret --list

# Get specific PKey information
./surf_ufm_pkeyd.py ufm --host ufm1.local --username admin --password secret --get-pkey 0x5000

# Create a new PKey
./surf_ufm_pkeyd.py ufm --host ufm1.local --username admin --password secret --create-pkey 0x6000

# Delete a PKey
./surf_ufm_pkeyd.py ufm --host ufm1.local --username admin --password secret --delete-pkey 0x6000

# Add GUIDs to a PKey
./surf_ufm_pkeyd.py ufm \
  --host ufm1.local --username admin --password secret \
  --pkey 0x5000 \
  --guids 0002c903000e0b72,0002c903000e0b73 \
  --membership full

# Remove GUIDs from a PKey
./surf_ufm_pkeyd.py ufm \
  --host ufm1.local --username admin --password secret \
  --pkey 0x5000 \
  --guids 0002c903000e0b72 \
  --remove-guids

# UFM operations with SSL disabled
./surf_ufm_pkeyd.py ufm \
  --host ufm1.local.snellius.surf.nl \
  --username admin \
  --password 123456 \
  --no-ssl-verify \
  --list

# UFM operations over HTTP
./surf_ufm_pkeyd.py ufm \
  --host ufm1.local \
  --username admin \
  --password secret \
  --http \
  --list
```

### ETCD Mode

Direct etcd key-value operations.

```bash
# List all keys
./surf_ufm_pkeyd.py etcd --etcd-user root --list

# List keys with prefix filter
./surf_ufm_pkeyd.py etcd --etcd-user root --list --prefix /pcocc/global/opensm/pkeys/

# Get a specific key
./surf_ufm_pkeyd.py etcd --etcd-user root --get /pcocc/global/opensm/pkeys/0x2000

# Set a key-value pair
./surf_ufm_pkeyd.py etcd \
  --etcd-user root \
  --put /pcocc/global/opensm/pkeys/0x3000 \
  --value '{"host_guids": ["0x043f720300f55176"], "vf_guids": ["0xc0cc300000000000"]}'

# Set a key with TTL (time-to-live)
./surf_ufm_pkeyd.py etcd \
  --etcd-user root \
  --put /temp/test-key \
  --value "temporary value" \
  --ttl 3600

# Delete a key
./surf_ufm_pkeyd.py etcd --etcd-user root --delete /pcocc/global/opensm/pkeys/0x3000

# ETCD operations with certificate authentication
./surf_ufm_pkeyd.py etcd \
  --etcd-ca-cert /path/to/ca.crt \
  --etcd-cert-file /path/to/client.crt \
  --etcd-key-file /path/to/client.key \
  --etcd-user root \
  --list --prefix /pcocc/

# ETCD operations with debug output
./surf_ufm_pkeyd.py etcd --etcd-user root --get /pcocc/global/opensm/pkeys/0x2000 --debug
```

## Command-Line Options

### Global Options

- `--help, -h`: Show help message and exit

### Monitor Mode Options

#### ETCD Configuration
- `--etcd-host`: ETCD host (overrides batch.yaml)
- `--etcd-port`: ETCD port (overrides batch.yaml)
- `--etcd-endpoints`: Comma-separated ETCD endpoints (overrides batch.yaml)
- `--etcd-ca-cert`: Path to ETCD CA certificate (overrides batch.yaml)
- `--etcd-cert-file`: Path to ETCD client certificate
- `--etcd-key-file`: Path to ETCD client key
- `--etcd-user`: ETCD username
- `--etcd-password`: ETCD password
- `--etcd-prompt-password`: Let etcdctl prompt for password interactively
- `--etcd-timeout`: ETCD timeout in seconds (default: 30)

#### UFM Configuration
- `--ufm-host`: UFM host address (required)
- `--ufm-user`: UFM username (required)
- `--ufm-password`: UFM password (required)
- `--no-ssl-verify`: Disable SSL verification for UFM
- `--http`: Use HTTP instead of HTTPS for UFM

#### Monitor Configuration
- `--poll-interval`: Poll interval in seconds (default: 30)
- `--debug`: Enable debug logging

### UFM Mode Options

#### UFM Connection
- `--host`: UFM host address (required)
- `--username`: UFM username (required)
- `--password`: UFM password (required)
- `--no-ssl-verify`: Disable SSL verification
- `--http`: Use HTTP instead of HTTPS

#### UFM Operations (mutually exclusive)
- `--list`: List all PKeys
- `--get-pkey PKEY`: Get specific PKey information (e.g., 0x5000)
- `--create-pkey PKEY`: Create new PKey (e.g., 0x6000)
- `--delete-pkey PKEY`: Delete PKey (e.g., 0x6000)
- `--pkey PKEY`: PKey for GUID operations (e.g., 0x5000)

#### GUID Management
- `--guids`: Comma-separated list of GUIDs (e.g., guid1,guid2,guid3)
- `--membership`: GUID membership type - `full` or `limited` (default: full)
- `--index0`: Enable index0 (default: true)
- `--ip-over-ib`: Enable IP over InfiniBand
- `--remove-guids`: Remove GUIDs instead of adding them

### ETCD Mode Options

#### ETCD Connection
- `--etcd-host`: ETCD host (overrides batch.yaml)
- `--etcd-port`: ETCD port (overrides batch.yaml)
- `--etcd-endpoints`: Comma-separated ETCD endpoints (overrides batch.yaml)
- `--etcd-ca-cert`: Path to ETCD CA certificate
- `--etcd-cert-file`: Path to ETCD client certificate
- `--etcd-key-file`: Path to ETCD client key
- `--etcd-user`: ETCD username
- `--etcd-password`: ETCD password
- `--etcd-prompt-password`: Let etcdctl prompt for password interactively
- `--etcd-timeout`: ETCD timeout in seconds (default: 30)

#### ETCD Operations (mutually exclusive)
- `--list`: List all keys
- `--get KEY`: Get value for specific key
- `--put KEY`: Set/update key-value pair (requires --value)
- `--delete KEY`: Delete specific key

#### ETCD Options
- `--prefix`: Prefix filter for list operation
- `--value`: Value to set (required with --put)
- `--ttl`: TTL in seconds for put operation
- `--debug`: Enable debug output

## PKey Data Format

The daemon expects PKey data in etcd to follow this JSON format:

```json
{
  "host_guids": ["0x043f720300f55176", "0x043f720300f55177"],
  "vf_guids": ["0xc0cc200e00000000", "0xc0cc200e00000001"]
}
```

### ETCD Key Structure
```
/pcocc/global/opensm/pkeys/0x200e -> {"host_guids": [...], "vf_guids": [...]}
/pcocc/global/opensm/pkeys/0x5000 -> {"host_guids": [...], "vf_guids": [...]}
```

## Monitoring Workflow

When running in monitor mode, the daemon:

1. **Initialization**:
   - Loads configuration from `/etc/pcocc/batch.yaml`
   - Authenticates with both etcd and UFM
   - Performs initial scan of existing PKeys

2. **Monitoring Loop** (every poll interval):
   - Scans etcd for keys under `/pcocc/global/opensm/pkeys/`
   - Identifies new, modified, or deleted PKeys
   - Synchronizes changes with UFM:
     - Creates missing PKeys in UFM
     - Adds/removes GUIDs as needed
     - Removes PKeys that no longer exist in etcd
   - Reports unmanaged PKeys (PKeys in UFM not managed through etcd)

3. **GUID Synchronization**:
   - Supports both `host_guids` and `vf_guids` from etcd
   - Strips `0x` prefixes before sending to UFM API
   - Uses full membership for all GUIDs
   - Handles mixed add/remove operations efficiently

## Validation

The daemon performs comprehensive validation:

- **PKey Format**: Must be in format 0x0000-0x7fff
- **GUID Format**: Must be 16 hexadecimal characters (with or without 0x prefix)
- **JSON Format**: etcd values must be valid JSON with expected structure
- **UFM Connectivity**: Verifies UFM authentication before starting monitoring

## Security Considerations

- **Credentials**: UFM and etcd credentials are passed via command line or configuration files
- **SSL Verification**: Can be disabled for self-signed certificates using `--no-ssl-verify`
- **Certificate Authentication**: Supports client certificate authentication for etcd
- **Password Files**: Supports secure password storage in `/etc/pcocc/etcd-password`
- **Interactive Passwords**: Supports interactive password prompting with `--etcd-prompt-password`

## Logging

The daemon provides structured logging:

- **INFO**: Normal operation messages, successful operations
- **WARNING**: Non-fatal issues like invalid GUIDs or missing keys
- **ERROR**: Failures that prevent processing specific operations
- **DEBUG**: Detailed operation information (enabled with --debug)

## Error Handling

Robust error handling includes:

- **Authentication Failures**: Exits gracefully if UFM or etcd authentication fails
- **Connection Issues**: Logs errors and continues monitoring (for transient issues)
- **Invalid Data**: Skips malformed PKey data with warning logs
- **API Errors**: Logs failures but continues processing other operations
- **Signal Handling**: Graceful shutdown on SIGINT/SIGTERM

## Service Deployment

For production deployment:

1. **System Service**: Run as systemd service or similar
2. **Configuration Management**: Use `/etc/pcocc/batch.yaml` for etcd configuration
3. **Credential Security**: Store passwords in `/etc/pcocc/etcd-password` file
4. **Logging**: Configure appropriate log rotation
5. **Monitoring**: Monitor daemon health and log output
6. **Network Access**: Ensure connectivity to both etcd and UFM servers

## Troubleshooting

### Common Issues

1. **Authentication Failures**:
   ```bash
   # Verify UFM credentials and connectivity
   ./surf_ufm_pkeyd.py ufm --host ufm1.local --username admin --password secret --list
   
   # Test etcd connectivity  
   ./surf_ufm_pkeyd.py etcd --etcd-user root --list
   ```

2. **SSL Certificate Issues**:
   ```bash
   # Disable SSL verification for testing
   ./surf_ufm_pkeyd.py ufm --host ufm1.local --username admin --password secret --no-ssl-verify --list
   
   # Use HTTP instead of HTTPS
   ./surf_ufm_pkeyd.py ufm --host ufm1.local --username admin --password secret --http --list
   ```

3. **ETCD Connection Problems**:
   ```bash
   # Test with debug output
   ./surf_ufm_pkeyd.py etcd --etcd-user root --list --debug
   
   # Test specific endpoints
   ./surf_ufm_pkeyd.py etcd --etcd-endpoints "etcd1.local:2379" --etcd-user root --list
   ```

4. **No PKeys Found**:
   ```bash
   # Check etcd key structure
   ./surf_ufm_pkeyd.py etcd --etcd-user root --list --prefix /pcocc/global/opensm/pkeys/
   
   # Enable debug logging for monitoring
   ./surf_ufm_pkeyd.py monitor --ufm-host ufm1.local --ufm-user admin --ufm-password secret --debug
   ```

## Authors

SURF SNELLIUS Team with Claude Code assistance

## License

This software is developed for SURF's SNELLIUS HPC cluster infrastructure.