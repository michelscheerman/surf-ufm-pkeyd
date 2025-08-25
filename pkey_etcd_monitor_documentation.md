# PKey ETCD Monitor Documentation

## Overview

The PKey ETCD Monitor (`pkey_etcd_monitor.py`) is an automated service that monitors an etcd database for new InfiniBand partition key (PKey) configurations and automatically provisions them in NVIDIA UFM Enterprise through the REST API.

## Purpose

This service bridges the gap between infrastructure-as-code PKey definitions stored in etcd and their actual configuration in UFM, enabling automated InfiniBand network partition management without manual intervention.

## Architecture

The monitor consists of three main components:

1. **ETCD Integration** - Uses `ETCDManager` to connect and query etcd
2. **UFM Integration** - Uses `UFMAPIClient` to configure PKeys in UFM
3. **Monitoring Loop** - Continuously polls etcd for changes and processes new PKeys

## Key Features

- **Automatic Discovery**: Monitors `/pcocc/global/opensm/pkeys/` directory in etcd
- **UFM Integration**: Creates and configures PKeys with GUIDs in UFM Enterprise  
- **Validation**: Validates PKey formats (0x0000-0x7fff) and GUID formats
- **Error Handling**: Robust error handling with logging and retry logic
- **Signal Handling**: Graceful shutdown on SIGINT/SIGTERM
- **Deduplication**: Tracks processed keys to avoid duplicate operations

## Configuration

### ETCD Configuration
- **Host/Port**: etcd server connection details
- **Authentication**: Username/password or certificate-based auth
- **TLS**: Support for CA certificates and client certificates
- **Endpoints**: Support for multiple etcd endpoints

### UFM Configuration  
- **Host**: UFM server hostname/IP
- **Authentication**: HTTP Basic Authentication with username/password
- **SSL**: Configurable SSL verification (supports self-signed certificates)
- **Protocol**: HTTP or HTTPS support

### Monitor Configuration
- **Poll Interval**: Configurable polling frequency (default: 30 seconds)
- **Debug Logging**: Optional verbose logging for troubleshooting

## Data Format

### ETCD Key Structure
```
Key: /pcocc/global/opensm/pkeys/0x200e
Value: {
  "host_guids": ["0x043f720300f55176"],
  "vf_guids": ["0xc0cc200e00000000"]
}
```

### Supported GUID Types
- **host_guids**: Physical host adapter GUIDs
- **vf_guids**: Virtual function GUIDs

## Workflow

1. **Initialization**:
   - Connect to etcd using provided configuration
   - Authenticate with UFM API using HTTP Basic Auth
   - Perform initial scan of existing PKeys

2. **Monitoring Loop**:
   - Poll etcd for keys in `/pcocc/global/opensm/pkeys/`
   - Identify new keys not previously processed
   - Retrieve and parse PKey data from etcd

3. **PKey Processing**:
   - Validate PKey format and GUID formats
   - Check if PKey exists in UFM (create if needed)
   - Add all GUIDs to PKey with full membership
   - Mark key as processed to prevent reprocessing

## Usage Examples

### Basic Usage
```bash
./pkey_etcd_monitor.py \
  --etcd-host etcd.local \
  --etcd-user admin \
  --etcd-password secret \
  --ufm-host ufm1.local.snellius.surf.nl \
  --ufm-user admin \
  --ufm-password 123456 \
  --no-ssl-verify
```

### With Certificate Authentication
```bash
./pkey_etcd_monitor.py \
  --etcd-host etcd.local \
  --etcd-ca-cert /path/to/ca.crt \
  --etcd-cert-file /path/to/client.crt \
  --etcd-key-file /path/to/client.key \
  --ufm-host ufm1.local \
  --ufm-user admin \
  --ufm-password 123456
```

### Multiple ETCD Endpoints
```bash
./pkey_etcd_monitor.py \
  --etcd-endpoints "etcd1.local:2379,etcd2.local:2379,etcd3.local:2379" \
  --ufm-host ufm1.local \
  --ufm-user admin \
  --ufm-password 123456
```

## Command Line Options

### ETCD Configuration
- `--etcd-host`: ETCD host (default: localhost)
- `--etcd-port`: ETCD port (default: 2379)  
- `--etcd-endpoints`: Comma-separated ETCD endpoints
- `--etcd-ca-cert`: Path to ETCD CA certificate
- `--etcd-cert-file`: Path to ETCD client certificate
- `--etcd-key-file`: Path to ETCD client key
- `--etcd-user`: ETCD username
- `--etcd-password`: ETCD password
- `--etcd-timeout`: ETCD timeout in seconds (default: 30)

### UFM Configuration
- `--ufm-host`: UFM host address (required)
- `--ufm-user`: UFM username (required)
- `--ufm-password`: UFM password (required)
- `--no-ssl-verify`: Disable SSL verification for UFM
- `--http`: Use HTTP instead of HTTPS for UFM

### Monitor Configuration
- `--poll-interval`: Poll interval in seconds (default: 30)
- `--debug`: Enable debug logging

## Error Handling

The monitor includes comprehensive error handling:

- **Authentication Failures**: Exits if UFM authentication fails
- **ETCD Connection Issues**: Logs errors and continues monitoring
- **Invalid Data**: Skips malformed PKey data with warning logs
- **UFM API Errors**: Logs failures but continues processing other keys
- **JSON Parse Errors**: Handles malformed etcd values gracefully

## Logging

The service provides structured logging with timestamps:

- **INFO**: Normal operation messages, successful operations
- **WARNING**: Non-fatal issues like invalid GUIDs
- **ERROR**: Failures that prevent processing specific keys
- **DEBUG**: Detailed operation information (with --debug flag)

## Dependencies

- `etcd_manager.py`: ETCD client wrapper
- `ufm_pkey_manager.py`: UFM API client and validation functions
- Python standard library modules: `argparse`, `json`, `logging`, `signal`, `sys`, `threading`, `time`, `subprocess`, `os`

## Security Considerations

- **Credentials**: UFM credentials are passed via command line (consider environment variables)
- **SSL Verification**: Can be disabled for self-signed certificates
- **Authentication**: Uses HTTP Basic Auth for UFM (credentials in memory)
- **ETCD Security**: Supports certificate-based authentication

## Service Deployment

For production deployment:
1. Run as a system service (systemd, etc.)
2. Configure appropriate logging rotation
3. Monitor process health
4. Use configuration files instead of command-line arguments for credentials
5. Implement proper credential management (secrets management system)

## Troubleshooting

### Common Issues

1. **Authentication Failures**:
   - Verify UFM credentials
   - Check UFM server accessibility
   - Ensure SSL settings match UFM configuration

2. **ETCD Connection Issues**:
   - Verify etcd server is running and accessible
   - Check authentication credentials
   - Validate certificate paths if using TLS

3. **No PKeys Found**:
   - Verify etcd key path `/pcocc/global/opensm/pkeys/`
   - Check etcd permissions for the monitoring user
   - Enable debug logging to see detailed scan results

4. **UFM Configuration Failures**:
   - Check UFM server logs for API errors
   - Verify PKey doesn't already exist with conflicting configuration
   - Ensure UFM user has sufficient privileges for PKey management