#!/usr/bin/env python3

import requests
import json
import sys
import argparse
from typing import List, Dict, Optional
from urllib.parse import urljoin
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class UFMAPIClient:
    def __init__(self, host: str, username: str, password: str, use_https: bool = True, verify_ssl: bool = False):
        self.host = host
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.protocol = "https" if use_https else "http"
        self.base_url = f"{self.protocol}://{self.host}"
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.token = None
        
    def authenticate(self) -> bool:
        """Authenticate with UFM API and get access token"""
        auth_url = urljoin(self.base_url, "/ufmRest/app/tokens")
        
        auth_data = {
            "username": self.username,
            "password": self.password
        }
        
        try:
            response = self.session.post(auth_url, json=auth_data)
            print(f"Response status: {response.status_code}")
            print(f"Response content: {response.text}")
            response.raise_for_status()
            
            if not response.text.strip():
                print("Authentication failed: Empty response from server")
                return False
            
            try:
                token_data = response.json()
            except json.JSONDecodeError as e:
                print(f"Authentication failed: Invalid JSON response - {e}")
                print(f"Raw response: {response.text}")
                return False
                
            self.token = token_data.get("access_token")
            
            if self.token:
                self.session.headers.update({"Authorization": f"Bearer {self.token}"})
                return True
            else:
                print("Failed to get authentication token")
                return False
                
        except requests.exceptions.RequestException as e:
            print(f"Authentication failed: {e}")
            return False
    
    def get_pkey(self, pkey: str, include_guids: bool = True) -> Optional[Dict]:
        """Get information about a specific PKey"""
        url = urljoin(self.base_url, f"/ufmRest/resources/pkeys/{pkey}")
        params = {"guids_data": str(include_guids).lower()}
        
        try:
            response = self.session.get(url, params=params)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Failed to get PKey {pkey}: {e}")
            return None
    
    def list_pkeys(self, include_guids: bool = True, include_qos: bool = False) -> Optional[List[Dict]]:
        """List all PKeys"""
        url = urljoin(self.base_url, "/ufmRest/resources/pkeys")
        params = {
            "guids_data": str(include_guids).lower(),
            "qos_conf": str(include_qos).lower()
        }
        
        try:
            response = self.session.get(url, params=params)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Failed to list PKeys: {e}")
            return None
    
    def add_guids_to_pkey(self, pkey: str, guids: List[str], membership: str = "full", 
                         index0: bool = True, ip_over_ib: bool = False) -> bool:
        """Add GUIDs to a partition key"""
        url = urljoin(self.base_url, "/ufmRest/resources/pkeys/")
        
        data = {
            "pkey": pkey,
            "guids": guids,
            "membership": membership,
            "index0": index0,
            "ip_over_ib": ip_over_ib
        }
        
        try:
            response = self.session.post(url, json=data)
            response.raise_for_status()
            print(f"Successfully added {len(guids)} GUIDs to PKey {pkey}")
            return True
        except requests.exceptions.RequestException as e:
            print(f"Failed to add GUIDs to PKey {pkey}: {e}")
            if hasattr(e.response, 'text'):
                print(f"Response: {e.response.text}")
            return False
    
    def remove_guids_from_pkey(self, pkey: str, guids: List[str]) -> bool:
        """Remove GUIDs from a partition key"""
        guids_str = ",".join(guids)
        url = urljoin(self.base_url, f"/ufmRest/resources/pkeys/{pkey}/guids/{guids_str}")
        
        try:
            response = self.session.delete(url)
            response.raise_for_status()
            print(f"Successfully removed {len(guids)} GUIDs from PKey {pkey}")
            return True
        except requests.exceptions.RequestException as e:
            print(f"Failed to remove GUIDs from PKey {pkey}: {e}")
            if hasattr(e.response, 'text'):
                print(f"Response: {e.response.text}")
            return False
    
    def create_pkey(self, pkey: str, index0: bool = True, ip_over_ib: bool = False) -> bool:
        """Create an empty PKey"""
        url = urljoin(self.base_url, "/ufmRest/resources/pkeys/add")
        
        data = {
            "pkey": pkey,
            "index0": index0,
            "ip_over_ib": ip_over_ib
        }
        
        try:
            response = self.session.post(url, json=data)
            response.raise_for_status()
            print(f"Successfully created PKey {pkey}")
            return True
        except requests.exceptions.RequestException as e:
            print(f"Failed to create PKey {pkey}: {e}")
            if hasattr(e.response, 'text'):
                print(f"Response: {e.response.text}")
            return False
    
    def delete_pkey(self, pkey: str) -> bool:
        """Delete a PKey and all its configured GUIDs"""
        url = urljoin(self.base_url, f"/ufmRest/resources/pkeys/{pkey}")
        
        try:
            response = self.session.delete(url)
            response.raise_for_status()
            print(f"Successfully deleted PKey {pkey}")
            return True
        except requests.exceptions.RequestException as e:
            print(f"Failed to delete PKey {pkey}: {e}")
            if hasattr(e.response, 'text'):
                print(f"Response: {e.response.text}")
            return False


def validate_pkey(pkey: str) -> bool:
    """Validate PKey format (0x0000 to 0x7fff)"""
    try:
        if not pkey.startswith('0x'):
            return False
        pkey_int = int(pkey, 16)
        return 0x0000 <= pkey_int <= 0x7fff
    except ValueError:
        return False


def validate_guid(guid: str) -> bool:
    """Validate GUID format (16 hex characters)"""
    try:
        if len(guid) != 16:
            return False
        int(guid, 16)
        return True
    except ValueError:
        return False


def main():
    parser = argparse.ArgumentParser(description="NVIDIA UFM Enterprise PKey GUID Manager")
    parser.add_argument("--host", required=True, help="UFM host address")
    parser.add_argument("--username", required=True, help="UFM username")
    parser.add_argument("--password", required=True, help="UFM password")
    parser.add_argument("--pkey", required=True, help="Partition Key (e.g., 0x0a12)")
    parser.add_argument("--guids", required=True, nargs="+", 
                       help="List of InfiniBand GUIDs to add (e.g., 0002c903000e0b72)")
    parser.add_argument("--membership", choices=["full", "limited"], default="full",
                       help="Membership type (default: full)")
    parser.add_argument("--no-index0", action="store_true", 
                       help="Do not store PKey at index 0")
    parser.add_argument("--ip-over-ib", action="store_true",
                       help="Enable IP over InfiniBand")
    parser.add_argument("--no-ssl-verify", action="store_true",
                       help="Disable SSL certificate verification")
    parser.add_argument("--http", action="store_true",
                       help="Use HTTP instead of HTTPS")
    
    args = parser.parse_args()
    
    # Validate PKey
    if not validate_pkey(args.pkey):
        print(f"Error: Invalid PKey format '{args.pkey}'. Must be in format 0x0000-0x7fff")
        sys.exit(1)
    
    # Validate GUIDs
    invalid_guids = [guid for guid in args.guids if not validate_guid(guid)]
    if invalid_guids:
        print(f"Error: Invalid GUID format(s): {', '.join(invalid_guids)}")
        print("GUIDs must be 16 hexadecimal characters")
        sys.exit(1)
    
    # Create UFM client
    client = UFMAPIClient(
        host=args.host,
        username=args.username,
        password=args.password,
        use_https=not args.http,
        verify_ssl=not args.no_ssl_verify
    )
    
    # Authenticate
    if not client.authenticate():
        print("Failed to authenticate with UFM")
        sys.exit(1)
    
    print(f"Successfully authenticated with UFM at {client.base_url}")
    
    # Add GUIDs to PKey
    success = client.add_guids_to_pkey(
        pkey=args.pkey,
        guids=args.guids,
        membership=args.membership,
        index0=not args.no_index0,
        ip_over_ib=args.ip_over_ib
    )
    
    if success:
        print(f"Operation completed successfully!")
        
        # Show updated PKey info
        pkey_info = client.get_pkey(args.pkey)
        if pkey_info:
            print(f"\nUpdated PKey {args.pkey} information:")
            print(json.dumps(pkey_info, indent=2))
    else:
        print("Operation failed!")
        sys.exit(1)


if __name__ == "__main__":
    main()