#!/usr/bin/env python3
"""
ETCD Key-Value Manager (Enhanced with etcdctl)

A comprehensive script for managing key-value pairs in an etcd cluster using etcdctl.
Supports operations: list, get, get-prefix, put, delete, delete-prefix, watch, 
lease management, cluster status, and more.
"""

import argparse
import getpass
import json
import os
import signal
import sys
import subprocess
import threading
import time
from typing import Optional, Dict, Any, List


class ETCDManager:
    def __init__(self, endpoints: Optional[List[str]] = None, host: str = "localhost", 
                 port: int = 2379, ca_cert: Optional[str] = None, 
                 cert_file: Optional[str] = None, key_file: Optional[str] = None,
                 user: Optional[str] = None, password: Optional[str] = None,
                 timeout: int = 30, debug: bool = False):
        self.timeout = timeout
        self.debug = debug
        
        if endpoints:
            self.endpoints = endpoints
        else:
            self.endpoints = [f"{host}:{port}"]
        
        self.ca_cert = ca_cert
        self.cert_file = cert_file
        self.key_file = key_file
        self.user = user
        self.password = password
    
    def _run_etcdctl(self, args: list, input_data: Optional[str] = None) -> tuple[bool, str, str]:
        """Run etcdctl command and return success status, stdout, stderr"""
        # Build command in the order: etcdctl --endpoints <endpoint> [auth flags] [tls flags] <command> <args>
        # This matches the working example format
        cmd = ["/opt/etcd/current/etcdctl", "--endpoints", ",".join(self.endpoints)]
        
        # Add authentication before the command (matching working example)  
        if self.user:
            cmd.extend(["--username", self.user])
            # Only add --password if password is provided, otherwise etcdctl will prompt
            if self.password:
                cmd.extend(["--password", self.password])
        
        # Add TLS options if provided - use command line flags only to avoid conflicts
        if self.ca_cert:
            cmd.extend(["--cacert", self.ca_cert])
        if self.cert_file:
            cmd.extend(["--cert", self.cert_file])
        if self.key_file:
            cmd.extend(["--key", self.key_file])
            
        # Add the actual command and its arguments
        cmd.extend(args)
        
        # Set up environment for etcdctl
        env = os.environ.copy()
        
        # Force API version 2 (based on working example)
        env["ETCDCTL_API"] = "2"
            
        if self.debug:
            # Print command for debugging (hide password)
            debug_cmd = cmd.copy()
            for i, arg in enumerate(debug_cmd):
                if arg == "--password" and i + 1 < len(debug_cmd):
                    debug_cmd[i + 1] = "***"
            print(f"DEBUG: Running command: {' '.join(debug_cmd)}", file=sys.stderr)
            
        try:
            # If no password provided, allow interactive password prompt
            if self.user and not self.password:
                result = subprocess.run(cmd, text=True, timeout=self.timeout, 
                                      input=input_data, env=env)
                stdout = getattr(result, 'stdout', '')
                stderr = getattr(result, 'stderr', '')
            else:
                result = subprocess.run(cmd, capture_output=True, text=True, 
                                      timeout=self.timeout, input=input_data, env=env)
                stdout = result.stdout
                stderr = result.stderr
                
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
        """List all keys in the etcd cluster, optionally with a prefix"""
        if prefix:
            cmd_args = ["ls", prefix]
        else:
            cmd_args = ["ls", "/"]
            
        success, stdout, stderr = self._run_etcdctl(cmd_args)
        if success:
            if stdout.strip():
                print(f"Keys in etcd cluster{' (prefix: ' + prefix + ')' if prefix else ''}:")
                for key in stdout.strip().split('\n'):
                    if key.strip():  # Skip empty lines
                        print(f"  {key}")
            else:
                print(f"No keys found{' with prefix: ' + prefix if prefix else ''}")
            return True
        else:
            # Check for specific authentication errors
            if "authentication is not enabled" in stderr.lower():
                print(f"Error: Authentication is not enabled on the etcd server. Try running without --user flag.", file=sys.stderr)
            elif "authentication" in stderr.lower() or "permission" in stderr.lower() or "unauthorized" in stderr.lower():
                print(f"Authentication failed: {stderr}", file=sys.stderr)
            else:
                print(f"Error listing keys: {stderr}", file=sys.stderr)
            return False
    
    def get_key(self, key: str, show_metadata: bool = False) -> bool:
        """Get value for a specific key"""
        cmd_args = ["get", key]
        # Note: API v2 doesn't support --write-out=json metadata format
            
        success, stdout, stderr = self._run_etcdctl(cmd_args)
        if success:
            if stdout.strip():
                print(f"Key: {key}")
                print(f"Value: {stdout.strip()}")
                if show_metadata:
                    print("Note: Detailed metadata not available in API v2")
            else:
                print(f"Key '{key}' not found")
            return True
        else:
            print(f"Error getting key '{key}': {stderr}", file=sys.stderr)
            return False
    
    def get_keys_with_prefix(self, prefix: str, show_metadata: bool = False) -> bool:
        """Get all keys and values with a specific prefix"""
        # API v2 uses ls to list keys, then individual get commands for values
        cmd_args = ["ls", prefix]
            
        success, stdout, stderr = self._run_etcdctl(cmd_args)
        if success:
            if stdout.strip():
                keys = [key.strip() for key in stdout.strip().split('\n') if key.strip()]
                if keys:
                    print(f"Keys with prefix '{prefix}':")
                    for key in keys:
                        # Get value for each key
                        get_success, get_stdout, get_stderr = self._run_etcdctl(["get", key])
                        if get_success:
                            print(f"  {key}: {get_stdout.strip()}")
                        else:
                            print(f"  {key}: <error getting value>")
                    if show_metadata:
                        print("Note: Detailed metadata not available in API v2")
                else:
                    print(f"No keys found with prefix '{prefix}'")
            else:
                print(f"No keys found with prefix '{prefix}'")
            return True
        else:
            print(f"Error getting keys with prefix '{prefix}': {stderr}", file=sys.stderr)
            return False
    
    def put_key(self, key: str, value: str, ttl: Optional[int] = None) -> bool:
        """Set/update a key-value pair, optionally with TTL"""
        cmd_args = ["set", key, value]  # API v2 uses 'set' instead of 'put'
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
        success, stdout, stderr = self._run_etcdctl(["rm", key])  # API v2 uses 'rm' instead of 'del'
        if success:
            print(f"Successfully deleted key '{key}'")
            return True
        else:
            if "key not found" in stderr.lower():
                print(f"Key '{key}' not found")
            else:
                print(f"Error deleting key '{key}': {stderr}", file=sys.stderr)
            return False
    
    def delete_prefix(self, prefix: str) -> bool:
        """Delete all keys with a specific prefix"""
        success, stdout, stderr = self._run_etcdctl(["rm", "--recursive", prefix])  # API v2 uses '--recursive'
        if success:
            print(f"Successfully deleted keys with prefix '{prefix}'")
            return True
        else:
            if "key not found" in stderr.lower():
                print(f"No keys found with prefix '{prefix}' to delete")
            else:
                print(f"Error deleting keys with prefix '{prefix}': {stderr}", file=sys.stderr)
            return False
    
    def create_lease(self, ttl: int) -> Optional[str]:
        """Create a lease with specified TTL in seconds"""
        print("Error: Lease functionality is not available in etcd API v2", file=sys.stderr)
        return None
    
    def revoke_lease(self, lease_id: str) -> bool:
        """Revoke a lease"""
        print("Error: Lease functionality is not available in etcd API v2", file=sys.stderr)
        return False
    
    def lease_timetolive(self, lease_id: str, show_keys: bool = False) -> bool:
        """Get lease time-to-live information"""
        print("Error: Lease functionality is not available in etcd API v2", file=sys.stderr)
        return False
    
    def watch_key(self, key: str, prefix: bool = False, timeout_seconds: Optional[int] = None) -> bool:
        """Watch for changes on a key or prefix"""
        cmd_args = ["watch"]
        if prefix:
            cmd_args.extend(["--recursive", key])  # API v2 uses --recursive instead of --prefix
        else:
            cmd_args.append(key)
            
        print(f"Watching {'prefix' if prefix else 'key'} '{key}' for changes... (Press Ctrl+C to stop)")
        
        try:
            cmd = ["/opt/etcd/current/etcdctl", "--endpoints", ",".join(self.endpoints)] + cmd_args
            
            # Add authentication if provided
            if self.user and self.password:
                cmd.extend(["--user", f"{self.user}:{self.password}"])
            
            # Add TLS options if provided
            if self.ca_cert:
                cmd.extend(["--cacert", self.ca_cert])
            if self.cert_file:
                cmd.extend(["--cert", self.cert_file])
            if self.key_file:
                cmd.extend(["--key", self.key_file])
            
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
                                     text=True, bufsize=1, universal_newlines=True)
            
            def timeout_handler():
                if timeout_seconds:
                    time.sleep(timeout_seconds)
                    process.terminate()
            
            timeout_thread = None
            if timeout_seconds:
                timeout_thread = threading.Thread(target=timeout_handler)
                timeout_thread.daemon = True
                timeout_thread.start()
            
            try:
                while True:
                    output = process.stdout.readline()
                    if output == '' and process.poll() is not None:
                        break
                    if output:
                        print(f"Change detected: {output.strip()}")
            except KeyboardInterrupt:
                print("\nWatch stopped by user")
                process.terminate()
            
            process.wait()
            return True
            
        except Exception as e:
            print(f"Error watching {'prefix' if prefix else 'key'} '{key}': {e}", file=sys.stderr)
            return False
    
    def get_cluster_status(self) -> bool:
        """Get etcd cluster status information"""
        success, stdout, stderr = self._run_etcdctl(["cluster-health"])  # API v2 uses cluster-health
        if success:
            print("Cluster Status:")
            print(stdout)
            return True
        else:
            print(f"Error getting cluster status: {stderr}", file=sys.stderr)
            return False


def main():
    parser = argparse.ArgumentParser(
        description="Manage key-value pairs in an etcd cluster using etcdctl (enhanced version)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --list                                                    # List all keys
  %(prog)s --list --prefix /config                                   # List keys with prefix
  %(prog)s --get /config/app                                         # Get specific key
  %(prog)s --get /config/app --metadata                              # Get key with metadata
  %(prog)s --get-prefix /config --metadata                           # Get all keys with prefix and metadata
  %(prog)s --put /config/app --value "production"                    # Set key-value pair
  %(prog)s --put /config/temp --value "test" --ttl 60                 # Set key with 60s TTL
  %(prog)s --delete /config/app                                      # Delete specific key
  %(prog)s --delete-prefix /config                                   # Delete all keys with prefix
  %(prog)s --watch /config/app                                       # Watch key for changes
  %(prog)s --watch /config --prefix                                  # Watch prefix for changes
  %(prog)s --lease-grant 300                                         # Create lease with 300s TTL
  %(prog)s --lease-revoke 694d71c6b17a4ca3                           # Revoke specific lease
  %(prog)s --status                                                  # Show cluster status
  %(prog)s --endpoints "host1:2379,host2:2379,host3:2379" --ca-cert ca.pem --list  # Multi-server with CA cert
        """
    )
    
    # Connection options
    parser.add_argument("--host", default="localhost", help="ETCD host (default: localhost)")
    parser.add_argument("--port", type=int, default=2379, help="ETCD port (default: 2379)")
    parser.add_argument("--endpoints", help="Comma-separated list of ETCD endpoints (e.g., host1:2379,host2:2379,host3:2379)")
    parser.add_argument("--ca-cert", help="Path to CA certificate file")
    parser.add_argument("--cert-file", help="Path to client certificate file")
    parser.add_argument("--key-file", help="Path to client private key file")
    parser.add_argument("--user", help="Username for authentication")
    parser.add_argument("--password", help="Password for authentication (will prompt if user provided but password not)")
    parser.add_argument("--prompt-password", action="store_true", help="Let etcdctl prompt for password (more secure, matches working example)")
    parser.add_argument("--timeout", type=int, default=30, help="Connection timeout in seconds (default: 30)")
    
    # Operations (mutually exclusive)
    operations = parser.add_mutually_exclusive_group(required=True)
    operations.add_argument("--list", action="store_true", help="List all keys")
    operations.add_argument("--get", metavar="KEY", help="Get value for specific key")
    operations.add_argument("--get-prefix", metavar="PREFIX", help="Get all keys with prefix")
    operations.add_argument("--put", metavar="KEY", help="Set/update key-value pair")
    operations.add_argument("--delete", metavar="KEY", help="Delete specific key")
    operations.add_argument("--delete-prefix", metavar="PREFIX", help="Delete all keys with prefix")
    operations.add_argument("--watch", metavar="KEY", help="Watch key or prefix for changes")
    operations.add_argument("--lease-grant", metavar="TTL", type=int, help="Create lease with TTL in seconds")
    operations.add_argument("--lease-revoke", metavar="LEASE_ID", help="Revoke specific lease")
    operations.add_argument("--lease-timetolive", metavar="LEASE_ID", help="Get lease time-to-live information")
    operations.add_argument("--status", action="store_true", help="Show cluster status")
    
    # Additional options
    parser.add_argument("--prefix", help="Prefix filter for --list operation or use with --watch")
    parser.add_argument("--value", help="Value to set (required with --put)")
    parser.add_argument("--metadata", action="store_true", help="Show metadata with get operations")
    parser.add_argument("--ttl", type=int, help="TTL in seconds for put operation (creates lease)")
    parser.add_argument("--watch-timeout", type=int, help="Timeout for watch operation in seconds")
    parser.add_argument("--lease-keys", action="store_true", help="Show keys attached to lease (use with --lease-timetolive)")
    parser.add_argument("--debug", action="store_true", help="Enable debug output to see etcdctl commands and responses")
    
    args = parser.parse_args()
    
    # Validate arguments
    if args.put and not args.value:
        parser.error("--value is required when using --put")
    
    if args.prefix and not (args.list or args.watch):
        parser.error("--prefix can only be used with --list or --watch")
    
    # Parse endpoints if provided
    endpoints_list = None
    if args.endpoints:
        endpoints_list = [e.strip() for e in args.endpoints.split(',')]
    
    # Handle password prompting
    password = args.password
    if args.user and not password and not args.prompt_password:
        password = getpass.getpass(f"Password for user '{args.user}': ")
    elif args.prompt_password:
        # Let etcdctl prompt for password - don't provide it via command line
        password = None
    
    # Create ETCD manager
    etcd = ETCDManager(
        endpoints=endpoints_list,
        host=args.host,
        port=args.port,
        ca_cert=args.ca_cert,
        cert_file=args.cert_file,
        key_file=args.key_file,
        user=args.user,
        password=password,
        timeout=args.timeout,
        debug=args.debug
    )
    
    # Execute operation
    success = False
    if args.list:
        success = etcd.list_all_keys(prefix=args.prefix or "")
    elif args.get:
        success = etcd.get_key(args.get, show_metadata=args.metadata)
    elif args.get_prefix:
        success = etcd.get_keys_with_prefix(args.get_prefix, show_metadata=args.metadata)
    elif args.put:
        success = etcd.put_key(args.put, args.value, ttl=args.ttl)
    elif args.delete:
        success = etcd.delete_key(args.delete)
    elif args.delete_prefix:
        success = etcd.delete_prefix(args.delete_prefix)
    elif args.watch:
        success = etcd.watch_key(args.watch, prefix=bool(args.prefix), timeout_seconds=args.watch_timeout)
    elif args.lease_grant:
        lease_id = etcd.create_lease(args.lease_grant)
        success = lease_id is not None
    elif args.lease_revoke:
        success = etcd.revoke_lease(args.lease_revoke)
    elif args.lease_timetolive:
        success = etcd.lease_timetolive(args.lease_timetolive, show_keys=args.lease_keys)
    elif args.status:
        success = etcd.get_cluster_status()
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()