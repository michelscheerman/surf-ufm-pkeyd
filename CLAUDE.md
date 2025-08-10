# Claude Memory - UFM PKey Manager Project

## Project Overview
This is a Python script for managing NVIDIA UFM Enterprise PKey (Partition Key) GUID assignments through the REST API.

## Key Files
- `ufm_pkey_manager.py` - Main script for UFM PKey management

## UFM API Details Discovered
- **Authentication**: Uses HTTP Basic Authentication (not token-based)
- **Base URL**: `https://{host}/ufmRest/`
- **SSL**: Server uses self-signed certificates, requires `--no-ssl-verify` flag
- **PKeys endpoint**: `/ufmRest/resources/pkeys`

## Authentication Evolution
1. Initially tried token-based auth at `/ufmRest/app/tokens` - failed (returned HTML login page)
2. Tried multiple token endpoints - all returned HTML
3. Successfully implemented HTTP Basic Authentication using `requests.auth.HTTPBasicAuth`

## Script Capabilities
- **List PKeys**: `--list` to show all defined partition keys with GUID information
- **Add GUIDs**: `--pkey 0x5000 --guids <guid>` to add GUIDs to a partition key
- **Authentication**: Supports both HTTP and HTTPS with SSL verification options
- **Validation**: Validates PKey format (0x0000-0x7fff) and GUID format (16 hex chars)

## Usage Examples
```bash
# List all PKeys
./ufm_pkey_manager.py --host ufm1.local.snellius.surf.nl --username admin --password 123456 --list --no-ssl-verify

# Add GUID to PKey
./ufm_pkey_manager.py --host ufm1.local.snellius.surf.nl --username admin --password 123456 --pkey 0x5000 --guids 0002c903000e0b72 --membership full --no-ssl-verify
```

## Git Repository
- Remote: github.com:michelscheerman/claude-code.git
- Main branch: main
- Recent commits focused on authentication fixes and adding list functionality

## Testing Results
- Successfully authenticated with UFM server using Basic Auth
- Successfully added GUID to PKey 0x5000 with full membership
- PKey information retrieval working correctly
- JSON response parsing working for PKey data

## Code Quality
- Uses proper error handling for HTTP requests and JSON parsing
- Validates input formats before making API calls  
- Supports multiple authentication methods as fallbacks
- Uses argparse for clean command-line interface