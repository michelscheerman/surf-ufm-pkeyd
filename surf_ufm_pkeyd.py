#!/usr/bin/env python3
"""
SURF UFM PKey Daemon

A unified daemon that combines etcd monitoring, UFM PKey management, and direct etcd operations.
Designed for SURF's SNELLIUS HPC cluster to manage InfiniBand partition keys automatically.

Features:
- Monitor etcd for PKey configuration changes
- Automatically configure PKeys in NVIDIA UFM Enterprise
- Direct UFM PKey management operations
- Direct etcd key-value operations
- PCOCC batch.yaml integration for configuration
- Comprehensive logging and error handling
- Support for both HTTP and HTTPS etcd
- Password file integration for production deployment

Authors: SURF SNELLIUS Team with Claude Code assistance
"""

import argparse
import getpass
import json
import logging
import os
import signal
import subprocess
import sys
import threading
import time
import yaml
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ============================================================================
# CONFIGURATION AND UTILITIES
# ============================================================================

def load_pcocc_config(config_path: str = "/etc/pcocc/batch.yaml") -> Dict:
    """Load PCOCC batch configuration from YAML file"""
    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        
        settings = config.get('settings', {})
        etcd_config = {
            'servers': settings.get('etcd-servers', []),
            'port': settings.get('etcd-client-port', 2379),
            'protocol': settings.get('etcd-protocol', 'http'),
            'auth_type': settings.get('etcd-auth-type', 'password'),
            'ca_cert': settings.get('etcd-ca-cert'),
        }
        
        return etcd_config
    except (FileNotFoundError, yaml.YAMLError, KeyError) as e:
        print(f"Warning: Could not load PCOCC config from {config_path}: {e}")
        return {}


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
    """Validate GUID format (16 hex characters, with or without 0x prefix)"""
    try:
        # Remove 0x prefix if present
        if guid.startswith('0x') or guid.startswith('0X'):
            guid = guid[2:]
        
        if len(guid) != 16:
            return False
        int(guid, 16)
        return True
    except ValueError:
        return False


# ============================================================================
# ETCD MANAGER CLASS
# ============================================================================

class ETCDManager:
    """Enhanced ETCD client using etcdctl with API version selection"""
    
    def __init__(self, endpoints: Optional[List[str]] = None, host: str = "localhost", 
                 port: int = 2379, ca_cert: Optional[str] = None, 
                 cert_file: Optional[str] = None, key_file: Optional[str] = None,
                 user: Optional[str] = None, password: Optional[str] = None,
                 timeout: int = 30, debug: bool = False, protocol: str = "http"):
        self.timeout = timeout
        self.debug = debug
        self._cached_password = None
        self.protocol = protocol
        
        if endpoints:
            self.endpoints = endpoints
        else:
            self.endpoints = [f"{host}:{port}"]
        
        self.ca_cert = ca_cert
        self.cert_file = cert_file
        self.key_file = key_file
        self.user = user
        self.password = password
    
    def _run_etcdctl(self, args: list, input_data: Optional[str] = None) -> Tuple[bool, str, str]:
        """Run etcdctl command and return success status, stdout, stderr"""
        cmd = ["/opt/etcd/current/etcdctl", "--endpoints", ",".join(self.endpoints)]
        
        # Add authentication
        if self.user:
            password_to_use = self._cached_password or self.password
            if password_to_use:
                cmd.extend(["--username", f"{self.user}:{password_to_use}"])
            else:
                cmd.extend(["--username", self.user])
        
        # Add TLS options - different flags for different API versions
        api_version = "3" if self.protocol == "https" and (self.ca_cert or self.cert_file) else "2"
        
        if self.ca_cert:
            if api_version == "3":
                cmd.extend(["--cacert", self.ca_cert])
            else:
                cmd.extend(["--ca-file", self.ca_cert])
        if self.cert_file:
            if api_version == "3":
                cmd.extend(["--cert", self.cert_file])
            else:
                cmd.extend(["--cert-file", self.cert_file])
        if self.key_file:
            if api_version == "3":
                cmd.extend(["--key", self.key_file])
            else:
                cmd.extend(["--key-file", self.key_file])
        
        cmd.extend(args)
        
        # Set up environment
        env = os.environ.copy()
        
        # Choose API version based on protocol and certificate usage
        if self.protocol == "https" and (self.ca_cert or self.cert_file):
            env["ETCDCTL_API"] = "3"
            if self.debug:
                print(f"DEBUG: Using etcd API v3 for HTTPS protocol", file=sys.stderr)
        else:
            env["ETCDCTL_API"] = "2"
            if self.debug:
                print(f"DEBUG: Using etcd API v2 for HTTP protocol", file=sys.stderr)
        
        if self.debug:
            debug_cmd = cmd.copy()
            for i, arg in enumerate(debug_cmd):
                if arg == "--username" and i + 1 < len(debug_cmd) and ":" in debug_cmd[i + 1]:
                    user_part = debug_cmd[i + 1].split(':')[0]
                    debug_cmd[i + 1] = f"{user_part}:***"
            print(f"DEBUG: Running command: {' '.join(debug_cmd)}", file=sys.stderr)
        
        try:
            # Handle interactive password
            if self.user and not (self._cached_password or self.password):
                import getpass
                if not self._cached_password:
                    self._cached_password = getpass.getpass(f"ETCD password for user '{self.user}': ")
                # Rebuild command with cached password
                cmd = ["/opt/etcd/current/etcdctl", "--endpoints", ",".join(self.endpoints)]
                if self.user:
                    cmd.extend(["--username", f"{self.user}:{self._cached_password}"])
                if self.ca_cert:
                    if api_version == "3":
                        cmd.extend(["--cacert", self.ca_cert])
                    else:
                        cmd.extend(["--ca-file", self.ca_cert])
                if self.cert_file:
                    if api_version == "3":
                        cmd.extend(["--cert", self.cert_file])
                    else:
                        cmd.extend(["--cert-file", self.cert_file])
                if self.key_file:
                    if api_version == "3":
                        cmd.extend(["--key", self.key_file])
                    else:
                        cmd.extend(["--key-file", self.key_file])
                cmd.extend(args)
                
                result = subprocess.run(cmd, capture_output=True, text=True, 
                                      timeout=self.timeout, input=input_data, env=env)
                stdout = result.stdout
                stderr = result.stderr
            else:
                result = subprocess.run(cmd, capture_output=True, text=True, 
                                      timeout=self.timeout, input=input_data, env=env)
                stdout = result.stdout
                stderr = result.stderr
            
            stdout = stdout or ''
            stderr = stderr or ''
            
            if self.debug:
                print(f"DEBUG: Return code: {result.returncode}", file=sys.stderr)
                print(f"DEBUG: Stdout: '{stdout}'", file=sys.stderr)
                print(f"DEBUG: Stderr: '{stderr}'", file=sys.stderr)
            return result.returncode == 0, stdout, stderr
        except subprocess.TimeoutExpired:
            return False, "", "Command timed out"
        except FileNotFoundError:
            return False, "", "etcdctl command not found at /opt/etcd/current/etcdctl. Please install etcd client."
    
    def list_all_keys(self, prefix: str = "") -> bool:
        """List all keys in the etcd cluster"""
        cmd_args = ["ls", prefix] if prefix else ["ls", "/"]
        success, stdout, stderr = self._run_etcdctl(cmd_args)
        
        if success:
            if stdout.strip():
                print(f"Keys in etcd cluster{' (prefix: ' + prefix + ')' if prefix else ''}:")
                for key in stdout.strip().split('\n'):
                    if key.strip():
                        print(f"  {key}")
            else:
                print(f"No keys found{' with prefix: ' + prefix if prefix else ''}")
            return True
        else:
            if "key not found" in stderr.lower():
                print(f"No keys found{' with prefix: ' + prefix if prefix else ''}")
                return True
            print(f"Error listing keys: {stderr}", file=sys.stderr)
            return False
    
    def get_key(self, key: str) -> bool:
        """Get value for a specific key"""
        success, stdout, stderr = self._run_etcdctl(["get", key])
        if success:
            if stdout.strip():
                print(f"Key: {key}")
                print(f"Value: {stdout.strip()}")
            else:
                print(f"Key '{key}' not found")
            return True
        else:
            print(f"Error getting key '{key}': {stderr}", file=sys.stderr)
            return False
    
    def put_key(self, key: str, value: str, ttl: Optional[int] = None) -> bool:
        """Set/update a key-value pair"""
        cmd_args = ["set", key, value]
        if ttl:
            cmd_args.extend(["--ttl", str(ttl)])
        
        success, stdout, stderr = self._run_etcdctl(cmd_args)
        if success:
            print(f"Successfully set key '{key}' to '{value}'" + (f" with TTL {ttl}s" if ttl else ""))
            return True
        else:
            print(f"Error setting key '{key}': {stderr}", file=sys.stderr)
            return False
    
    def delete_key(self, key: str) -> bool:
        """Delete a key"""
        success, stdout, stderr = self._run_etcdctl(["rm", key])
        if success:
            print(f"Successfully deleted key '{key}'")
            return True
        else:
            if "key not found" in stderr.lower():
                print(f"Key '{key}' not found")
                return True
            print(f"Error deleting key '{key}': {stderr}", file=sys.stderr)
            return False


# ============================================================================
# UFM API CLIENT CLASS
# ============================================================================

class UFMAPIClient:
    """NVIDIA UFM Enterprise REST API client"""
    
    def __init__(self, host: str, username: str, password: str, 
                 use_https: bool = True, verify_ssl: bool = True):
        self.host = host
        self.username = username
        self.password = password
        self.use_https = use_https
        self.verify_ssl = verify_ssl
        
        protocol = "https" if use_https else "http"
        self.base_url = f"{protocol}://{host}"
        
        self.session = requests.Session()
        self.session.verify = verify_ssl
        
        # Configure retries
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
    
    def authenticate(self) -> bool:
        """Authenticate with UFM using HTTP Basic Authentication"""
        print("Trying HTTP Basic Authentication...")
        
        # Test basic auth with a simple API call
        self.session.auth = requests.auth.HTTPBasicAuth(self.username, self.password)
        
        try:
            test_url = urljoin(self.base_url, "/ufmRest/resources/pkeys")
            response = self.session.get(test_url, params={"guids_data": "false"}, timeout=10)
            print(f"Testing URL: {test_url}")
            print(f"Basic auth test - Status: {response.status_code}")
            
            if response.status_code == 200:
                print("Basic authentication successful!")
                return True
            else:
                print(f"Basic authentication failed with status: {response.status_code}")
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
    
    def list_pkeys(self, include_guids: bool = True) -> Optional[Dict]:
        """List all PKeys"""
        url = urljoin(self.base_url, "/ufmRest/resources/pkeys")
        params = {"guids_data": str(include_guids).lower()}
        
        try:
            response = self.session.get(url, params=params)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Failed to list PKeys: {e}")
            return None
    
    def create_pkey(self, pkey: str, index0: bool = True, ip_over_ib: bool = False) -> bool:
        """Create a new partition key"""
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
            return False
    
    def delete_pkey(self, pkey: str) -> bool:
        """Delete a partition key"""
        url = urljoin(self.base_url, f"/ufmRest/resources/pkeys/{pkey}")
        
        try:
            response = self.session.delete(url)
            response.raise_for_status()
            print(f"Successfully deleted PKey {pkey}")
            return True
        except requests.exceptions.RequestException as e:
            print(f"Failed to delete PKey {pkey}: {e}")
            return False
    
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
            return False


# ============================================================================
# PKEY MONITOR CLASS
# ============================================================================

class PKeyMonitor:
    """Monitor etcd for PKey changes and synchronize with UFM"""
    
    def __init__(self, etcd_config: Dict, ufm_config: Dict, poll_interval: int = 30):
        self.etcd_config = etcd_config
        self.ufm_config = ufm_config
        self.poll_interval = poll_interval
        self.running = False
        self.processed_keys: Set[str] = set()
        self.last_known_etcd_keys: Optional[Set[str]] = None
        self.debug = etcd_config.get('debug', False)
        
        # Initialize ETCD manager
        self.etcd = ETCDManager(
            endpoints=etcd_config.get('endpoints'),
            host=etcd_config.get('host', 'localhost'),
            port=etcd_config.get('port', 2379),
            ca_cert=etcd_config.get('ca_cert'),
            cert_file=etcd_config.get('cert_file'),
            key_file=etcd_config.get('key_file'),
            user=etcd_config.get('user'),
            password=etcd_config.get('password'),
            timeout=etcd_config.get('timeout', 30),
            debug=etcd_config.get('debug', False),
            protocol=etcd_config.get('protocol', 'http')
        )
        
        # Initialize UFM client
        self.ufm = UFMAPIClient(
            host=ufm_config['host'],
            username=ufm_config['username'],
            password=ufm_config['password'],
            use_https=ufm_config.get('use_https', True),
            verify_ssl=ufm_config.get('verify_ssl', False)
        )
        
        # Set up logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
    
    def authenticate_ufm(self) -> bool:
        """Authenticate with UFM API"""
        self.logger.info("Authenticating with UFM...")
        if self.ufm.authenticate():
            self.logger.info(f"Successfully authenticated with UFM at {self.ufm.base_url}")
            return True
        else:
            self.logger.error("Failed to authenticate with UFM")
            return False
    
    def parse_pkey_data(self, key: str, value: str) -> Optional[Dict]:
        """Parse PKey data from etcd value"""
        try:
            pkey = key.split('/')[-1]
            if not validate_pkey(pkey):
                self.logger.error(f"Invalid PKey format in key: {pkey}")
                return None
            
            # Parse JSON value - handle both JSON and Python dict format
            try:
                data = json.loads(value)
            except json.JSONDecodeError:
                import ast
                try:
                    data = ast.literal_eval(value)
                except (ValueError, SyntaxError) as e:
                    self.logger.error(f"Failed to parse value as JSON or Python literal: {e}")
                    return None
            
            if not isinstance(data, dict):
                self.logger.error(f"Expected dict in PKey data, got {type(data)}")
                return None
            
            # Extract and validate GUIDs
            all_guids = []
            
            # Process host_guids
            host_guids = data.get('host_guids', [])
            if isinstance(host_guids, list):
                for guid in host_guids:
                    if validate_guid(guid):
                        # Strip 0x prefix for UFM API
                        clean_guid = guid[2:] if guid.startswith('0x') else guid
                        all_guids.append(clean_guid)
                    else:
                        self.logger.warning(f"Invalid host GUID format: {guid}")
            
            # Process vf_guids
            vf_guids = data.get('vf_guids', [])
            if isinstance(vf_guids, list):
                for guid in vf_guids:
                    if validate_guid(guid):
                        # Strip 0x prefix for UFM API
                        clean_guid = guid[2:] if guid.startswith('0x') else guid
                        all_guids.append(clean_guid)
                    else:
                        self.logger.warning(f"Invalid VF GUID format: {guid}")
            
            if not all_guids:
                self.logger.warning(f"No valid GUIDs found in PKey {pkey}")
                return None
            
            return {
                'pkey': pkey,
                'guids': all_guids,
                'host_guids': host_guids,
                'vf_guids': vf_guids
            }
        
        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse JSON for key {key}: {e}")
            return None
        except Exception as e:
            self.logger.error(f"Error parsing PKey data for {key}: {e}")
            return None
    
    def configure_pkey_in_ufm(self, pkey_data: Dict) -> bool:
        """Configure PKey in UFM with the provided GUIDs"""
        pkey = pkey_data['pkey']
        guids = pkey_data['guids']
        
        self.logger.info(f"Configuring PKey {pkey} with {len(guids)} GUIDs in UFM")
        
        try:
            # Check if PKey already exists
            existing_pkey = self.ufm.get_pkey(pkey, include_guids=True)
            
            if existing_pkey is None:
                # PKey doesn't exist, create it first
                self.logger.info(f"PKey {pkey} doesn't exist, creating it...")
                if not self.ufm.create_pkey(pkey, index0=True, ip_over_ib=False):
                    self.logger.error(f"Failed to create PKey {pkey}")
                    return False
                new_guids = guids
            else:
                # PKey exists, check which GUIDs are already present
                existing_guids = existing_pkey.get('guids', [])
                existing_guid_strings = []
                
                # Handle different formats that UFM might return
                if self.debug:
                    if len(existing_guids) > 0:
                        self.logger.debug(f"PKey {pkey} existing_guids format: {type(existing_guids)}, length: {len(existing_guids)}, sample: {existing_guids[:2] if len(existing_guids) >= 2 else existing_guids}")
                    else:
                        self.logger.debug(f"PKey {pkey} existing_guids is empty: {existing_guids}")
                
                if isinstance(existing_guids, list):
                    # List of strings or dicts
                    for guid_item in existing_guids:
                        if isinstance(guid_item, str):
                            existing_guid_strings.append(guid_item.lower())
                        elif isinstance(guid_item, dict):
                            # Extract GUID from dict (common UFM format)
                            guid_value = (guid_item.get('guid') or 
                                        guid_item.get('GUID') or 
                                        guid_item.get('value') or
                                        guid_item.get('port_guid') or
                                        guid_item.get('node_guid'))
                            if guid_value and isinstance(guid_value, str):
                                existing_guid_strings.append(guid_value.lower())
                            elif self.debug:
                                self.logger.debug(f"Could not extract GUID from dict: {guid_item}")
                        else:
                            if self.debug:
                                self.logger.debug(f"Unknown list item type: {type(guid_item)}, value: {guid_item}")
                elif isinstance(existing_guids, dict):
                    # Handle case where guids is a dict itself  
                    for key, value in existing_guids.items():
                        if isinstance(value, str) and len(value) >= 16:
                            existing_guid_strings.append(value.lower())
                        elif isinstance(key, str) and len(key) >= 16 and key.lower() not in ['count', 'total', 'size']:
                            existing_guid_strings.append(key.lower())
                
                if existing_guid_strings:
                    # Convert to set for comparison (normalize case)
                    existing_guids_set = set(existing_guid_strings)
                    new_guids_set = {guid.lower() for guid in guids}
                    
                    # Find GUIDs that need to be added
                    missing_guids = new_guids_set - existing_guids_set
                    new_guids = [guid for guid in guids if guid.lower() in missing_guids]
                    
                    # Find GUIDs that need to be removed (exist in UFM but not in etcd)
                    obsolete_guids = existing_guids_set - new_guids_set
                    remove_guids = [guid for guid in existing_guid_strings if guid in obsolete_guids]
                    
                    # Handle GUID removals first
                    if remove_guids:
                        self.logger.info(f"PKey {pkey} removing {len(remove_guids)} obsolete GUIDs: {remove_guids}")
                        removal_success = self.ufm.remove_guids_from_pkey(pkey, remove_guids)
                        if not removal_success:
                            self.logger.error(f"Failed to remove obsolete GUIDs from PKey {pkey}")
                    
                    if not new_guids and not remove_guids:
                        self.logger.info(f"PKey {pkey} is already synchronized (no changes needed)")
                        return True
                    elif new_guids:
                        self.logger.info(f"PKey {pkey} exists, adding {len(new_guids)} new GUIDs: {new_guids}")
                else:
                    # Couldn't parse existing GUIDs, add all
                    new_guids = guids
                    self.logger.warning(f"Could not parse existing GUIDs for PKey {pkey} (found {len(existing_guid_strings)} valid GUIDs from {type(existing_guids)}), adding all")
            
            # Add only the new GUIDs to PKey
            if new_guids:
                success = self.ufm.add_guids_to_pkey(
                    pkey=pkey,
                    guids=new_guids,
                    membership="full",
                    index0=True,
                    ip_over_ib=False
                )
                
                if success:
                    self.logger.info(f"Successfully added {len(new_guids)} new GUIDs to PKey {pkey}: {new_guids}")
                    return True
                else:
                    self.logger.error(f"Failed to add GUIDs to PKey {pkey}")
                    return False
            else:
                # Only removals were performed, or no changes needed
                return True
                
        except Exception as e:
            self.logger.error(f"Error configuring PKey {pkey} in UFM: {e}")
            return False
    
    def remove_pkey_from_ufm(self, pkey: str) -> bool:
        """Remove PKey from UFM"""
        self.logger.info(f"Removing PKey {pkey} from UFM (no longer exists in etcd)")
        
        try:
            existing_pkey = self.ufm.get_pkey(pkey, include_guids=False)
            
            if existing_pkey is None:
                self.logger.info(f"PKey {pkey} doesn't exist in UFM, nothing to remove")
                return True
            
            success = self.ufm.delete_pkey(pkey)
            
            if success:
                self.logger.info(f"Successfully removed PKey {pkey} from UFM")
                return True
            else:
                self.logger.error(f"Failed to remove PKey {pkey} from UFM")
                return False
                
        except Exception as e:
            self.logger.error(f"Error removing PKey {pkey} from UFM: {e}")
            return False
    
    def report_unmanaged_pkeys(self, current_etcd_keys: Set[str]) -> None:
        """Report PKeys that exist in UFM but are not managed through etcd"""
        try:
            self.logger.debug("Querying UFM for all PKeys...")
            # Get all PKeys from UFM - try with guids=True first (like manual command)
            ufm_pkeys = self.ufm.list_pkeys(include_guids=True)
            
            self.logger.debug(f"UFM list_pkeys returned: {type(ufm_pkeys)}, value: {ufm_pkeys}")
            
            # If that failed, try without GUIDs
            if not ufm_pkeys:
                self.logger.debug("Retrying UFM list_pkeys without GUIDs...")
                ufm_pkeys = self.ufm.list_pkeys(include_guids=False)
                self.logger.debug(f"UFM list_pkeys (no guids) returned: {type(ufm_pkeys)}, value: {ufm_pkeys}")
            
            if not ufm_pkeys:
                self.logger.warning("Could not retrieve PKey list from UFM (empty or None response)")
                return
            
            if self.debug:
                if isinstance(ufm_pkeys, dict):
                    sample_keys = list(ufm_pkeys.keys())[:3] if len(ufm_pkeys) >= 3 else list(ufm_pkeys.keys())
                    self.logger.debug(f"UFM returned {len(ufm_pkeys)} PKeys (dict format): {sample_keys}...")
                else:
                    self.logger.debug(f"UFM returned {len(ufm_pkeys)} PKeys: {ufm_pkeys[:3] if len(ufm_pkeys) >= 3 else ufm_pkeys}...")
            
            # Extract PKey values from UFM response
            ufm_pkey_values = set()
            if isinstance(ufm_pkeys, dict):
                # UFM returns dict format: {"0x4000": {...}, "0x5000": {...}}
                ufm_pkey_values = set(ufm_pkeys.keys())
            elif isinstance(ufm_pkeys, list):
                # Handle list format if UFM ever changes: [{"pkey": "0x4000"}, ...]
                for pkey_info in ufm_pkeys:
                    if isinstance(pkey_info, dict):
                        pkey_value = pkey_info.get('pkey') or pkey_info.get('partition_key')
                        if pkey_value:
                            ufm_pkey_values.add(pkey_value)
            
            # Extract PKey values from etcd keys (remove path prefix)
            etcd_pkey_values = set()
            for etcd_key in current_etcd_keys:
                pkey = etcd_key.split('/')[-1]
                if validate_pkey(pkey):
                    etcd_pkey_values.add(pkey)
            
            # Find PKeys in UFM that are not managed by etcd
            unmanaged_pkeys = ufm_pkey_values - etcd_pkey_values
            
            if self.debug:
                self.logger.debug(f"UFM PKeys: {sorted(ufm_pkey_values)}")
                self.logger.debug(f"etcd PKeys: {sorted(etcd_pkey_values)}")
                self.logger.debug(f"Unmanaged PKeys: {sorted(unmanaged_pkeys)}")
            
            # Always show UFM perspective summary
            self.logger.info(f"UFM Status: {len(ufm_pkey_values)} total PKeys, {len(etcd_pkey_values)} managed via etcd, {len(unmanaged_pkeys)} unmanaged")
            
            if unmanaged_pkeys:
                self.logger.info(f"UFM PKeys NOT managed through etcd: {sorted(unmanaged_pkeys)}")
            
            if etcd_pkey_values:
                self.logger.info(f"UFM PKeys managed through etcd: {sorted(etcd_pkey_values)}")
                
        except Exception as e:
            self.logger.error(f"Error reporting unmanaged PKeys: {e}")
    
    def scan_pkeys(self) -> None:
        """Scan for PKeys in etcd and process new ones"""
        self.logger.debug("Scanning for PKeys in etcd...")
        
        # Get all keys with the PKey prefix
        prefix = "/pcocc/global/opensm/pkeys/"
        success, stdout, stderr = self.etcd._run_etcdctl(["ls", prefix])
        
        if not success:
            if "key not found" in stderr.lower():
                self.logger.debug("No PKeys found in etcd")
                current_etcd_keys = set()
            else:
                self.logger.error(f"Failed to list PKeys from etcd: {stderr}")
                return
        else:
            if not stdout.strip():
                self.logger.debug("No PKeys found in etcd")
                current_etcd_keys = set()
            else:
                # Process each key - filter out password prompts and invalid keys
                keys = [key.strip() for key in stdout.strip().split('\n') 
                        if key.strip() and not key.strip().endswith(':') and key.strip().startswith('/')]
                current_etcd_keys = set(keys)
        
        # Handle PKey deletions (only if we got a valid response from etcd)
        if self.last_known_etcd_keys is not None:
            deleted_keys = self.last_known_etcd_keys - current_etcd_keys
            
            if deleted_keys:
                self.logger.info(f"Found {len(deleted_keys)} deleted PKey(s): {list(deleted_keys)}")
                
                for deleted_key in deleted_keys:
                    try:
                        # Extract PKey from the key path
                        pkey = deleted_key.split('/')[-1]
                        if validate_pkey(pkey):
                            self.remove_pkey_from_ufm(pkey)
                            # Remove from processed_keys so it can be re-added if it comes back
                            self.processed_keys.discard(deleted_key)
                        else:
                            self.logger.warning(f"Invalid PKey format in deleted key: {pkey}")
                    except Exception as e:
                        self.logger.error(f"Error processing deleted key {deleted_key}: {e}")
        
        # Update the last known etcd state
        self.last_known_etcd_keys = current_etcd_keys
        
        # Report unmanaged PKeys (only on successful etcd response)
        self.report_unmanaged_pkeys(current_etcd_keys)
        
        # Process new keys
        new_keys = [key for key in current_etcd_keys if key not in self.processed_keys]
        
        if new_keys:
            self.logger.info(f"Found {len(new_keys)} new PKey(s): {new_keys}")
        
        for key in new_keys:
            try:
                # Get the value for this key
                get_success, get_stdout, get_stderr = self.etcd._run_etcdctl(["get", key])
                
                if not get_success:
                    self.logger.error(f"Failed to get value for key {key}: {get_stderr}")
                    continue
                
                if not get_stdout.strip():
                    self.logger.warning(f"Empty value for key {key}")
                    continue
                
                # Parse and process the PKey data
                pkey_data = self.parse_pkey_data(key, get_stdout.strip())
                
                if pkey_data:
                    if self.configure_pkey_in_ufm(pkey_data):
                        self.processed_keys.add(key)
                        self.logger.info(f"Successfully synchronized PKey {pkey_data['pkey']}")
                    else:
                        self.logger.error(f"Failed to configure PKey {pkey_data['pkey']} in UFM")
                else:
                    self.logger.error(f"Failed to parse PKey data for key {key}")
                    
            except Exception as e:
                self.logger.error(f"Error processing key {key}: {e}")
    
    def run(self) -> None:
        """Main monitoring loop"""
        self.logger.info("Starting PKey monitor...")
        
        # Authenticate with UFM first
        if not self.authenticate_ufm():
            self.logger.error("Cannot proceed without UFM authentication")
            return
        
        # Initial scan to catch up with existing keys
        self.logger.info("Performing initial PKey scan...")
        self.scan_pkeys()
        
        # Main monitoring loop
        self.running = True
        self.logger.info(f"Starting monitoring loop (poll interval: {self.poll_interval}s)")
        
        while self.running:
            try:
                time.sleep(self.poll_interval)
                if self.running:
                    self.scan_pkeys()
            except KeyboardInterrupt:
                self.logger.info("Received interrupt signal")
                break
            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {e}")
                time.sleep(10)
        
        self.logger.info("PKey monitor stopped")
    
    def stop(self) -> None:
        """Stop the monitoring loop"""
        self.logger.info("Stopping PKey monitor...")
        self.running = False


# ============================================================================
# SIGNAL HANDLING
# ============================================================================

def signal_handler(signum, frame, monitor):
    """Handle shutdown signals"""
    print(f"\nReceived signal {signum}, shutting down...")
    monitor.stop()
    sys.exit(0)


# ============================================================================
# MAIN FUNCTION AND CLI
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="SURF UFM PKey Daemon - Unified etcd monitoring and UFM PKey management",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Monitor mode (default) - automatically sync etcd PKeys to UFM
  %(prog)s monitor --ufm-host ufm1.local --ufm-user admin --ufm-password pass --etcd-user root

  # UFM PKey management
  %(prog)s ufm --host ufm1.local --username admin --password pass --list
  %(prog)s ufm --host ufm1.local --username admin --password pass --pkey 0x5000 --guids guid1,guid2

  # ETCD operations
  %(prog)s etcd --etcd-user root --list --prefix /pcocc/global/opensm/pkeys/
  %(prog)s etcd --etcd-user root --get /pcocc/global/opensm/pkeys/0x2000

Configuration is automatically loaded from /etc/pcocc/batch.yaml when available.
        """
    )
    
    # Add subcommands
    subparsers = parser.add_subparsers(dest='mode', help='Operation modes')
    
    # ========================================================================
    # MONITOR MODE (default)
    # ========================================================================
    monitor_parser = subparsers.add_parser('monitor', help='Monitor etcd and sync PKeys to UFM')
    
    # ETCD Configuration (will use /etc/pcocc/batch.yaml by default)
    etcd_group = monitor_parser.add_argument_group("ETCD Configuration")
    etcd_group.add_argument("--etcd-host", help="ETCD host (overrides batch.yaml)")
    etcd_group.add_argument("--etcd-port", type=int, help="ETCD port (overrides batch.yaml)")
    etcd_group.add_argument("--etcd-endpoints", help="Comma-separated ETCD endpoints (overrides batch.yaml)")
    etcd_group.add_argument("--etcd-ca-cert", help="Path to ETCD CA certificate (overrides batch.yaml)")
    etcd_group.add_argument("--etcd-cert-file", help="Path to ETCD client certificate")
    etcd_group.add_argument("--etcd-key-file", help="Path to ETCD client key")
    etcd_group.add_argument("--etcd-user", help="ETCD username")
    etcd_group.add_argument("--etcd-password", help="ETCD password")
    etcd_group.add_argument("--etcd-prompt-password", action="store_true", help="Let etcdctl prompt for password")
    etcd_group.add_argument("--etcd-timeout", type=int, default=30, help="ETCD timeout (default: 30)")
    
    # UFM Configuration
    ufm_group = monitor_parser.add_argument_group("UFM Configuration")
    ufm_group.add_argument("--ufm-host", required=True, help="UFM host address")
    ufm_group.add_argument("--ufm-user", required=True, help="UFM username")
    ufm_group.add_argument("--ufm-password", required=True, help="UFM password")
    ufm_group.add_argument("--no-ssl-verify", action="store_true", help="Disable SSL verification for UFM")
    ufm_group.add_argument("--http", action="store_true", help="Use HTTP instead of HTTPS for UFM")
    
    # Monitor Configuration
    monitor_config_group = monitor_parser.add_argument_group("Monitor Configuration")
    monitor_config_group.add_argument("--poll-interval", type=int, default=30, help="Poll interval in seconds (default: 30)")
    monitor_config_group.add_argument("--debug", action="store_true", help="Enable debug logging")
    
    # ========================================================================
    # UFM MODE
    # ========================================================================
    ufm_parser = subparsers.add_parser('ufm', help='Direct UFM PKey management operations')
    
    ufm_parser.add_argument("--host", required=True, help="UFM host address")
    ufm_parser.add_argument("--username", required=True, help="UFM username")
    ufm_parser.add_argument("--password", required=True, help="UFM password")
    ufm_parser.add_argument("--no-ssl-verify", action="store_true", help="Disable SSL verification")
    ufm_parser.add_argument("--http", action="store_true", help="Use HTTP instead of HTTPS")
    
    # UFM Operations (mutually exclusive)
    ufm_ops = ufm_parser.add_mutually_exclusive_group(required=True)
    ufm_ops.add_argument("--list", action="store_true", help="List all PKeys")
    ufm_ops.add_argument("--get-pkey", metavar="PKEY", help="Get specific PKey information")
    ufm_ops.add_argument("--create-pkey", metavar="PKEY", help="Create new PKey")
    ufm_ops.add_argument("--delete-pkey", metavar="PKEY", help="Delete PKey")
    ufm_ops.add_argument("--pkey", help="PKey for GUID operations")
    
    # Additional options for UFM operations
    ufm_parser.add_argument("--guids", help="Comma-separated list of GUIDs")
    ufm_parser.add_argument("--membership", choices=["full", "limited"], default="full", help="GUID membership type")
    ufm_parser.add_argument("--index0", action="store_true", default=True, help="Enable index0")
    ufm_parser.add_argument("--ip-over-ib", action="store_true", help="Enable IP over InfiniBand")
    ufm_parser.add_argument("--remove-guids", action="store_true", help="Remove GUIDs instead of adding")
    
    # ========================================================================
    # ETCD MODE  
    # ========================================================================
    etcd_parser = subparsers.add_parser('etcd', help='Direct etcd key-value operations')
    
    # ETCD connection options
    etcd_parser.add_argument("--etcd-host", help="ETCD host (overrides batch.yaml)")
    etcd_parser.add_argument("--etcd-port", type=int, help="ETCD port (overrides batch.yaml)")
    etcd_parser.add_argument("--etcd-endpoints", help="Comma-separated ETCD endpoints (overrides batch.yaml)")
    etcd_parser.add_argument("--etcd-ca-cert", help="Path to ETCD CA certificate")
    etcd_parser.add_argument("--etcd-cert-file", help="Path to ETCD client certificate")
    etcd_parser.add_argument("--etcd-key-file", help="Path to ETCD client key")
    etcd_parser.add_argument("--etcd-user", help="ETCD username")
    etcd_parser.add_argument("--etcd-password", help="ETCD password")
    etcd_parser.add_argument("--etcd-prompt-password", action="store_true", help="Let etcdctl prompt for password")
    etcd_parser.add_argument("--etcd-timeout", type=int, default=30, help="ETCD timeout (default: 30)")
    
    # ETCD Operations (mutually exclusive)
    etcd_ops = etcd_parser.add_mutually_exclusive_group(required=True)
    etcd_ops.add_argument("--list", action="store_true", help="List all keys")
    etcd_ops.add_argument("--get", metavar="KEY", help="Get value for specific key")
    etcd_ops.add_argument("--put", metavar="KEY", help="Set/update key-value pair")
    etcd_ops.add_argument("--delete", metavar="KEY", help="Delete specific key")
    
    # Additional options for ETCD operations
    etcd_parser.add_argument("--prefix", help="Prefix filter for list operation")
    etcd_parser.add_argument("--value", help="Value to set (required with --put)")
    etcd_parser.add_argument("--ttl", type=int, help="TTL in seconds for put operation")
    etcd_parser.add_argument("--debug", action="store_true", help="Enable debug output")
    
    # Parse arguments
    args = parser.parse_args()
    
    # Default to monitor mode if no mode specified
    if not args.mode:
        args.mode = 'monitor'
        # Set required UFM args as optional for backward compatibility
        if not hasattr(args, 'ufm_host') or not args.ufm_host:
            print("Error: UFM host is required for monitor mode")
            return 1
    
    # ========================================================================
    # HANDLE DIFFERENT MODES
    # ========================================================================
    
    if args.mode == 'monitor':
        return run_monitor_mode(args)
    elif args.mode == 'ufm':
        return run_ufm_mode(args)
    elif args.mode == 'etcd':
        return run_etcd_mode(args)
    else:
        print(f"Unknown mode: {args.mode}")
        return 1


def run_monitor_mode(args):
    """Run the PKey monitoring daemon"""
    # Set up logging level
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Load PCOCC configuration
    pcocc_config = load_pcocc_config()
    if pcocc_config:
        print(f"Loaded etcd configuration from /etc/pcocc/batch.yaml")
        print(f"  Servers: {pcocc_config.get('servers', [])}")
        print(f"  Port: {pcocc_config.get('port', 2379)}")
        print(f"  Protocol: {pcocc_config.get('protocol', 'http')}")
    
    # Build ETCD endpoints from PCOCC config or command line
    etcd_endpoints = None
    if args.etcd_endpoints:
        etcd_endpoints = [e.strip() for e in args.etcd_endpoints.split(',')]
    elif pcocc_config.get('servers'):
        protocol = pcocc_config.get('protocol', 'http')
        port = pcocc_config.get('port', 2379)
        etcd_endpoints = [f"{protocol}://{server}:{port}" for server in pcocc_config['servers']]
    
    # Determine etcd host and port (for backwards compatibility)
    etcd_host = args.etcd_host
    etcd_port = args.etcd_port
    if not etcd_host and pcocc_config.get('servers'):
        etcd_host = pcocc_config['servers'][0]
    if not etcd_port and pcocc_config.get('port'):
        etcd_port = pcocc_config['port']
    
    # Use defaults if nothing specified
    if not etcd_host:
        etcd_host = "localhost"
    if not etcd_port:
        etcd_port = 2379
    
    # Handle ETCD password from multiple sources
    etcd_password = args.etcd_password
    
    # Try to read password from file if user provided but no password given
    if args.etcd_user and not etcd_password and not args.etcd_prompt_password:
        password_file = "/etc/pcocc/etcd-password"
        try:
            if os.path.exists(password_file):
                with open(password_file, 'r') as f:
                    etcd_password = f.read().strip()
                    if etcd_password:
                        print(f"Using etcd password from {password_file}")
                    else:
                        print(f"Warning: {password_file} is empty")
                        etcd_password = None
            else:
                print(f"Password file {password_file} not found, prompting for password")
        except (IOError, OSError) as e:
            print(f"Could not read password file {password_file}: {e}")
        
        # If still no password, prompt for it
        if not etcd_password:
            etcd_password = getpass.getpass(f"ETCD password for user '{args.etcd_user}': ")
    elif args.etcd_prompt_password:
        # Let etcdctl prompt for password - don't provide it via command line
        etcd_password = None
    
    # Determine if we need CA cert based on protocol
    ca_cert_path = args.etcd_ca_cert
    if not ca_cert_path and pcocc_config.get('protocol') == 'https':
        ca_cert_path = pcocc_config.get('ca_cert')
    
    # Build configuration dictionaries  
    etcd_config = {
        'endpoints': etcd_endpoints,
        'host': etcd_host,
        'port': etcd_port,
        'ca_cert': ca_cert_path,
        'cert_file': args.etcd_cert_file,
        'key_file': args.etcd_key_file,
        'user': args.etcd_user,
        'password': etcd_password,
        'timeout': args.etcd_timeout,
        'debug': args.debug,
        'protocol': pcocc_config.get('protocol', 'http')
    }
    
    ufm_config = {
        'host': args.ufm_host,
        'username': args.ufm_user,
        'password': args.ufm_password,
        'use_https': not args.http,
        'verify_ssl': not args.no_ssl_verify
    }
    
    # Create and start monitor
    monitor = PKeyMonitor(etcd_config, ufm_config, args.poll_interval)
    
    # Set up signal handlers
    signal.signal(signal.SIGINT, lambda s, f: signal_handler(s, f, monitor))
    signal.signal(signal.SIGTERM, lambda s, f: signal_handler(s, f, monitor))
    
    try:
        monitor.run()
        return 0
    except Exception as e:
        logging.error(f"Fatal error: {e}")
        return 1


def run_ufm_mode(args):
    """Run UFM management operations"""
    # Create UFM client
    ufm = UFMAPIClient(
        host=args.host,
        username=args.username,
        password=args.password,
        use_https=not args.http,
        verify_ssl=not args.no_ssl_verify
    )
    
    # Authenticate
    if not ufm.authenticate():
        print("Failed to authenticate with UFM")
        return 1
    
    # Execute operations
    try:
        if args.list:
            pkeys = ufm.list_pkeys()
            if pkeys:
                print(json.dumps(pkeys, indent=2))
            return 0
        
        elif args.get_pkey:
            if not validate_pkey(args.get_pkey):
                print(f"Invalid PKey format: {args.get_pkey}")
                return 1
            pkey_info = ufm.get_pkey(args.get_pkey)
            if pkey_info:
                print(json.dumps(pkey_info, indent=2))
            return 0
        
        elif args.create_pkey:
            if not validate_pkey(args.create_pkey):
                print(f"Invalid PKey format: {args.create_pkey}")
                return 1
            success = ufm.create_pkey(args.create_pkey, args.index0, args.ip_over_ib)
            return 0 if success else 1
        
        elif args.delete_pkey:
            if not validate_pkey(args.delete_pkey):
                print(f"Invalid PKey format: {args.delete_pkey}")
                return 1
            success = ufm.delete_pkey(args.delete_pkey)
            return 0 if success else 1
        
        elif args.pkey:
            if not validate_pkey(args.pkey):
                print(f"Invalid PKey format: {args.pkey}")
                return 1
            
            if not args.guids:
                print("GUIDs are required for PKey GUID operations")
                return 1
            
            guids = [g.strip() for g in args.guids.split(',')]
            for guid in guids:
                if not validate_guid(guid):
                    print(f"Invalid GUID format: {guid}")
                    return 1
            
            # Strip 0x prefix for UFM API
            clean_guids = [guid[2:] if guid.startswith('0x') else guid for guid in guids]
            
            if args.remove_guids:
                success = ufm.remove_guids_from_pkey(args.pkey, clean_guids)
            else:
                success = ufm.add_guids_to_pkey(args.pkey, clean_guids, args.membership, args.index0, args.ip_over_ib)
            
            return 0 if success else 1
            
    except Exception as e:
        print(f"Error: {e}")
        return 1
    
    return 0


def run_etcd_mode(args):
    """Run etcd operations"""
    # Load PCOCC configuration for etcd settings
    pcocc_config = load_pcocc_config()
    
    # Build ETCD endpoints
    etcd_endpoints = None
    if args.etcd_endpoints:
        etcd_endpoints = [e.strip() for e in args.etcd_endpoints.split(',')]
    elif pcocc_config.get('servers'):
        protocol = pcocc_config.get('protocol', 'http')
        port = pcocc_config.get('port', 2379)
        etcd_endpoints = [f"{protocol}://{server}:{port}" for server in pcocc_config['servers']]
    
    # Determine etcd host and port
    etcd_host = args.etcd_host or (pcocc_config.get('servers', ['localhost'])[0])
    etcd_port = args.etcd_port or pcocc_config.get('port', 2379)
    
    # Handle password
    etcd_password = args.etcd_password
    if args.etcd_user and not etcd_password and not args.etcd_prompt_password:
        password_file = "/etc/pcocc/etcd-password"
        try:
            if os.path.exists(password_file):
                with open(password_file, 'r') as f:
                    etcd_password = f.read().strip()
        except (IOError, OSError):
            pass
        
        if not etcd_password:
            etcd_password = getpass.getpass(f"ETCD password for user '{args.etcd_user}': ")
    elif args.etcd_prompt_password:
        etcd_password = None
    
    # Create ETCD manager
    etcd = ETCDManager(
        endpoints=etcd_endpoints,
        host=etcd_host,
        port=etcd_port,
        ca_cert=args.etcd_ca_cert or (pcocc_config.get('ca_cert') if pcocc_config.get('protocol') == 'https' else None),
        cert_file=args.etcd_cert_file,
        key_file=args.etcd_key_file,
        user=args.etcd_user,
        password=etcd_password,
        timeout=args.etcd_timeout,
        debug=args.debug,
        protocol=pcocc_config.get('protocol', 'http')
    )
    
    # Execute operations
    try:
        if args.list:
            success = etcd.list_all_keys(prefix=args.prefix or "")
            return 0 if success else 1
        
        elif args.get:
            success = etcd.get_key(args.get)
            return 0 if success else 1
        
        elif args.put:
            if not args.value:
                print("Value is required for put operation")
                return 1
            success = etcd.put_key(args.put, args.value, args.ttl)
            return 0 if success else 1
        
        elif args.delete:
            success = etcd.delete_key(args.delete)
            return 0 if success else 1
            
    except Exception as e:
        print(f"Error: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())