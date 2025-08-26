# NVIDIA UFM Enterprise PKey GUID Manager

This Python program uses the NVIDIA UFM Enterprise API to manage InfiniBand GUIDs in partition keys.

## Features

- Add InfiniBand GUIDs to partition keys
- Remove GUIDs from partition keys
- Create and delete partition keys
- List all partition keys with GUID information
- Full error handling and validation
- Support for both HTTP and HTTPS connections

## Installation

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Make the script executable:
```bash
chmod +x ufm_pkey_manager.py
```

## Usage

### Basic Usage - Add GUIDs to PKey

```bash
python ufm_pkey_manager.py \
  --host 192.168.1.100 \
  --username admin \
  --password your_password \
  --pkey 0x0a12 \
  --guids 0002c903000e0b72 0002c903000e0b73
```

### Advanced Options

```bash
python ufm_pkey_manager.py \
  --host ufm.example.com \
  --username admin \
  --password your_password \
  --pkey 0x1234 \
  --guids 0002c903000e0b72 0002c903000e0b73 0002c903000e0b74 \
  --membership limited \
  --ip-over-ib \
  --no-ssl-verify
```

### Command Line Options

- `--host`: UFM host address (required)
- `--username`: UFM username (required)
- `--password`: UFM password (required)
- `--pkey`: Partition Key in hex format 0x0000-0x7fff (required)
- `--guids`: List of 16-character hex GUIDs (required)
- `--membership`: Membership type - "full" or "limited" (default: full)
- `--no-index0`: Do not store PKey at index 0
- `--ip-over-ib`: Enable IP over InfiniBand
- `--no-ssl-verify`: Disable SSL certificate verification
- `--http`: Use HTTP instead of HTTPS

## API Reference

The `UFMAPIClient` class provides these methods:

### Authentication
- `authenticate()`: Authenticate with UFM and get access token

### PKey Management
- `get_pkey(pkey, include_guids=True)`: Get PKey information
- `list_pkeys(include_guids=True, include_qos=False)`: List all PKeys
- `create_pkey(pkey, index0=True, ip_over_ib=False)`: Create empty PKey
- `delete_pkey(pkey)`: Delete PKey and all GUIDs

### GUID Management
- `add_guids_to_pkey(pkey, guids, membership="full", index0=True, ip_over_ib=False)`: Add GUIDs to PKey
- `remove_guids_from_pkey(pkey, guids)`: Remove GUIDs from PKey

## Examples

### Python Script Usage

```python
from ufm_pkey_manager import UFMAPIClient

# Create client
client = UFMAPIClient(
    host="192.168.1.100",
    username="admin", 
    password="password",
    verify_ssl=False
)

# Authenticate
if client.authenticate():
    # Add GUIDs to PKey
    success = client.add_guids_to_pkey(
        pkey="0x0a12",
        guids=["0002c903000e0b72", "0002c903000e0b73"],
        membership="full"
    )
    
    if success:
        # Get updated PKey info
        pkey_info = client.get_pkey("0x0a12")
        print("PKey info:", pkey_info)
```

### Batch GUID Addition

```bash
# Add multiple GUIDs from different hosts
python ufm_pkey_manager.py \
  --host ufm.cluster.local \
  --username operator \
  --password secret123 \
  --pkey 0x2001 \
  --guids \
    0002c903000e0b72 \
    0002c903000e0b73 \
    0002c903000e0b74 \
    0002c903000e0b75 \
  --membership full \
  --ip-over-ib
```

## Error Handling

The program includes comprehensive error handling:

- Validates PKey format (0x0000-0x7fff)
- Validates GUID format (16 hex characters)
- Handles authentication failures
- Provides detailed error messages for API failures
- Supports SSL verification bypass for development

## Security Notes

- Use `--no-ssl-verify` only in development environments
- Store credentials securely, consider environment variables
- Use HTTPS in production environments
- Implement proper access controls on UFM

## UFM API Endpoints Used

- `POST /ufmRest/app/tokens` - Authentication
- `GET /ufmRest/resources/pkeys/<pkey>` - Get PKey info
- `GET /ufmRest/resources/pkeys` - List all PKeys
- `POST /ufmRest/resources/pkeys/` - Add GUIDs to PKey
- `DELETE /ufmRest/resources/pkeys/<pkey>/guids/<guids>` - Remove GUIDs
- `POST /ufmRest/resources/pkeys/add` - Create PKey
- `DELETE /ufmRest/resources/pkeys/<pkey>` - Delete PKey