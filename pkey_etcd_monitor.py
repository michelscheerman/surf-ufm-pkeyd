#!/usr/bin/env python3
"""
PKey ETCD Monitor

Monitors /pcocc/global/opensm/pkeys/ directory in etcd for new partition keys
and automatically configures them in NVIDIA UFM Enterprise using the UFM API.

Example etcd key data format:
Key: /pcocc/global/opensm/pkeys/0x200e 
Value: {'host_guids': ['0x043f720300f55176'], 'vf_guids': ['0xc0cc200e00000000']}
"""

import argparse
import getpass
import json
import logging
import signal
import sys
import threading
import time
from typing import Dict, List, Optional, Set
import subprocess
import os

# Import our existing modules
from etcd_manager import ETCDManager
from ufm_pkey_manager import UFMAPIClient, validate_pkey, validate_guid


class PKeyMonitor:
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
            debug=etcd_config.get('debug', False)
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
            # Extract PKey from the key path
            pkey = key.split('/')[-1]
            if not validate_pkey(pkey):
                self.logger.error(f"Invalid PKey format in key: {pkey}")
                return None
            
            # Parse JSON value - handle both JSON and Python dict format
            try:
                data = json.loads(value)
            except json.JSONDecodeError:
                # Try parsing as Python literal (handles single quotes)
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
                # After creating, we need to add all GUIDs
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
                            # Continue with additions even if removal failed
                    
                    if not new_guids and not remove_guids:
                        self.logger.info(f"PKey {pkey} is already synchronized (no changes needed)")
                        return True
                    elif new_guids:
                        self.logger.info(f"PKey {pkey} exists, adding {len(new_guids)} new GUIDs: {new_guids}")
                else:
                    # Couldn't parse existing GUIDs, add all
                    new_guids = guids
                    remove_guids = []
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
            # Check if PKey exists in UFM first
            existing_pkey = self.ufm.get_pkey(pkey, include_guids=False)
            
            if existing_pkey is None:
                self.logger.info(f"PKey {pkey} doesn't exist in UFM, nothing to remove")
                return True
            
            # Remove the PKey from UFM
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
                current_etcd_keys = set()  # Empty set for no keys found
            else:
                self.logger.error(f"Failed to list PKeys from etcd: {stderr}")
                return  # Don't update last_known_etcd_keys if etcd failed
        else:
            if not stdout.strip():
                self.logger.debug("No PKeys found in etcd")
                current_etcd_keys = set()  # Empty set for no keys found
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
                if self.running:  # Check again after sleep
                    self.scan_pkeys()
            except KeyboardInterrupt:
                self.logger.info("Received interrupt signal")
                break
            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {e}")
                time.sleep(10)  # Wait before retrying
        
        self.logger.info("PKey monitor stopped")
    
    def stop(self) -> None:
        """Stop the monitoring loop"""
        self.logger.info("Stopping PKey monitor...")
        self.running = False


def signal_handler(signum, frame, monitor):
    """Handle shutdown signals"""
    print(f"\nReceived signal {signum}, shutting down...")
    monitor.stop()
    sys.exit(0)


def main():
    parser = argparse.ArgumentParser(
        description="Monitor etcd for new PKeys and configure them in NVIDIA UFM Enterprise",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --etcd-host etcd.local --etcd-user admin --etcd-password secret \\
           --ufm-host ufm1.local.snellius.surf.nl --ufm-user admin --ufm-password 123456 \\
           --no-ssl-verify
        """
    )
    
    # ETCD Configuration
    etcd_group = parser.add_argument_group("ETCD Configuration")
    etcd_group.add_argument("--etcd-host", default="localhost", help="ETCD host (default: localhost)")
    etcd_group.add_argument("--etcd-port", type=int, default=2379, help="ETCD port (default: 2379)")
    etcd_group.add_argument("--etcd-endpoints", help="Comma-separated ETCD endpoints")
    etcd_group.add_argument("--etcd-ca-cert", help="Path to ETCD CA certificate")
    etcd_group.add_argument("--etcd-cert-file", help="Path to ETCD client certificate")
    etcd_group.add_argument("--etcd-key-file", help="Path to ETCD client key")
    etcd_group.add_argument("--etcd-user", help="ETCD username")
    etcd_group.add_argument("--etcd-password", help="ETCD password")
    etcd_group.add_argument("--etcd-prompt-password", action="store_true", help="Let etcdctl prompt for password (more secure)")
    etcd_group.add_argument("--etcd-timeout", type=int, default=30, help="ETCD timeout (default: 30)")
    
    # UFM Configuration
    ufm_group = parser.add_argument_group("UFM Configuration")
    ufm_group.add_argument("--ufm-host", required=True, help="UFM host address")
    ufm_group.add_argument("--ufm-user", required=True, help="UFM username")
    ufm_group.add_argument("--ufm-password", required=True, help="UFM password")
    ufm_group.add_argument("--no-ssl-verify", action="store_true", help="Disable SSL verification for UFM")
    ufm_group.add_argument("--http", action="store_true", help="Use HTTP instead of HTTPS for UFM")
    
    # Monitor Configuration
    monitor_group = parser.add_argument_group("Monitor Configuration")
    monitor_group.add_argument("--poll-interval", type=int, default=30, 
                              help="Poll interval in seconds (default: 30)")
    monitor_group.add_argument("--debug", action="store_true", help="Enable debug logging")
    
    args = parser.parse_args()
    
    # Set up logging level
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Parse ETCD endpoints
    etcd_endpoints = None
    if args.etcd_endpoints:
        etcd_endpoints = [e.strip() for e in args.etcd_endpoints.split(',')]
    
    # Handle ETCD password prompting
    etcd_password = args.etcd_password
    if args.etcd_user and not etcd_password and not args.etcd_prompt_password:
        etcd_password = getpass.getpass(f"ETCD password for user '{args.etcd_user}': ")
    elif args.etcd_prompt_password:
        # Let etcdctl prompt for password - don't provide it via command line
        etcd_password = None
    
    # Build configuration dictionaries
    etcd_config = {
        'endpoints': etcd_endpoints,
        'host': args.etcd_host,
        'port': args.etcd_port,
        'ca_cert': args.etcd_ca_cert,
        'cert_file': args.etcd_cert_file,
        'key_file': args.etcd_key_file,
        'user': args.etcd_user,
        'password': etcd_password,
        'timeout': args.etcd_timeout,
        'debug': args.debug
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
    except Exception as e:
        logging.error(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()