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
            
            # Parse JSON value
            data = json.loads(value)
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
                        all_guids.append(guid)
                    else:
                        self.logger.warning(f"Invalid host GUID format: {guid}")
            
            # Process vf_guids
            vf_guids = data.get('vf_guids', [])
            if isinstance(vf_guids, list):
                for guid in vf_guids:
                    if validate_guid(guid):
                        all_guids.append(guid)
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
            
            # Add GUIDs to PKey
            success = self.ufm.add_guids_to_pkey(
                pkey=pkey,
                guids=guids,
                membership="full",
                index0=True,
                ip_over_ib=False
            )
            
            if success:
                self.logger.info(f"Successfully configured PKey {pkey} with GUIDs: {guids}")
                return True
            else:
                self.logger.error(f"Failed to add GUIDs to PKey {pkey}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error configuring PKey {pkey} in UFM: {e}")
            return False
    
    def scan_pkeys(self) -> None:
        """Scan for PKeys in etcd and process new ones"""
        self.logger.debug("Scanning for PKeys in etcd...")
        
        # Get all keys with the PKey prefix
        prefix = "/pcocc/global/opensm/pkeys/"
        success, stdout, stderr = self.etcd._run_etcdctl(["ls", prefix])
        
        if not success:
            if "key not found" in stderr.lower():
                self.logger.debug("No PKeys found in etcd")
            else:
                self.logger.error(f"Failed to list PKeys from etcd: {stderr}")
            return
        
        if not stdout.strip():
            self.logger.debug("No PKeys found in etcd")
            return
        
        # Process each key - filter out password prompts and invalid keys
        keys = [key.strip() for key in stdout.strip().split('\n') 
                if key.strip() and not key.strip().endswith(':') and key.strip().startswith('/')]
        new_keys = [key for key in keys if key not in self.processed_keys]
        
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
                        self.logger.info(f"Successfully processed PKey {pkey_data['pkey']}")
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