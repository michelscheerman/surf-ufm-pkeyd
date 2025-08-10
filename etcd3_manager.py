#!/usr/bin/env python3
"""
ETCD3 Key-Value Manager (using python-etcd3)

A script for managing key-value pairs in an etcd cluster using the python-etcd3 library.
Supports operations: list all keys, get specific key, edit, and delete.
"""

import argparse
import json
import sys
from typing import Optional, List, Tuple, Any

try:
    import etcd3
except ImportError:
    print("Error: python-etcd3 library not found. Install with: pip install etcd3", file=sys.stderr)
    sys.exit(1)


class ETCD3Manager:
    def __init__(self, host: str = "localhost", port: int = 2379, ca_cert: Optional[str] = None, 
                 cert_cert: Optional[str] = None, cert_key: Optional[str] = None,
                 timeout: Optional[int] = None, user: Optional[str] = None, 
                 password: Optional[str] = None):
        """Initialize ETCD3 client with connection parameters"""
        try:
            self.client = etcd3.client(
                host=host,
                port=port,
                ca_cert=ca_cert,
                cert_cert=cert_cert,
                cert_key=cert_key,
                timeout=timeout,
                user=user,
                password=password
            )
            # Test connection
            self.client.status()
        except Exception as e:
            print(f"Error connecting to etcd: {e}", file=sys.stderr)
            sys.exit(1)
    
    def list_all_keys(self, prefix: str = "") -> bool:
        """List all keys in the etcd cluster, optionally with a prefix"""
        try:
            if prefix:
                results = self.client.get_prefix(prefix)
            else:
                results = self.client.get_prefix("")
            
            keys = []
            for value, metadata in results:
                key = metadata.key.decode('utf-8')
                keys.append(key)
            
            if keys:
                print(f"Keys in etcd cluster{' (prefix: ' + prefix + ')' if prefix else ''}:")
                for key in sorted(keys):
                    print(f"  {key}")
            else:
                print(f"No keys found{' with prefix: ' + prefix if prefix else ''}")
            return True
        except Exception as e:
            print(f"Error listing keys: {e}", file=sys.stderr)
            return False
    
    def get_key(self, key: str, show_metadata: bool = False) -> bool:
        """Get value for a specific key"""
        try:
            value, metadata = self.client.get(key)
            
            if value is None:
                print(f"Key '{key}' not found")
                return True
            
            print(f"Key: {key}")
            print(f"Value: {value.decode('utf-8')}")
            
            if show_metadata and metadata:
                print(f"Create Revision: {metadata.create_revision}")
                print(f"Mod Revision: {metadata.mod_revision}")
                print(f"Version: {metadata.version}")
                if metadata.lease_id:
                    print(f"Lease ID: {metadata.lease_id}")
            
            return True
        except Exception as e:
            print(f"Error getting key '{key}': {e}", file=sys.stderr)
            return False
    
    def get_keys_with_prefix(self, prefix: str, show_metadata: bool = False) -> bool:
        """Get all keys and values with a specific prefix"""
        try:
            results = self.client.get_prefix(prefix)
            
            found_keys = []
            for value, metadata in results:
                key = metadata.key.decode('utf-8')
                val = value.decode('utf-8') if value else ""
                found_keys.append((key, val, metadata))
            
            if not found_keys:
                print(f"No keys found with prefix '{prefix}'")
                return True
            
            print(f"Keys with prefix '{prefix}':")
            for key, value, metadata in sorted(found_keys, key=lambda x: x[0]):
                print(f"  {key}: {value}")
                if show_metadata:
                    print(f"    Create Rev: {metadata.create_revision}, Mod Rev: {metadata.mod_revision}, Version: {metadata.version}")
            
            return True
        except Exception as e:
            print(f"Error getting keys with prefix '{prefix}': {e}", file=sys.stderr)
            return False
    
    def put_key(self, key: str, value: str, lease_id: Optional[int] = None) -> bool:
        """Set/update a key-value pair"""
        try:
            self.client.put(key, value, lease=lease_id)
            print(f"Successfully set key '{key}' to '{value}'")
            if lease_id:
                print(f"  with lease ID: {lease_id}")
            return True
        except Exception as e:
            print(f"Error setting key '{key}': {e}", file=sys.stderr)
            return False
    
    def delete_key(self, key: str) -> bool:
        """Delete a specific key"""
        try:
            deleted = self.client.delete(key)
            if deleted:
                print(f"Successfully deleted key '{key}'")
            else:
                print(f"Key '{key}' not found or already deleted")
            return True
        except Exception as e:
            print(f"Error deleting key '{key}': {e}", file=sys.stderr)
            return False
    
    def delete_prefix(self, prefix: str) -> bool:
        """Delete all keys with a specific prefix"""
        try:
            deleted_count = self.client.delete_prefix(prefix)
            if deleted_count > 0:
                print(f"Successfully deleted {deleted_count} keys with prefix '{prefix}'")
            else:
                print(f"No keys found with prefix '{prefix}' to delete")
            return True
        except Exception as e:
            print(f"Error deleting keys with prefix '{prefix}': {e}", file=sys.stderr)
            return False
    
    def create_lease(self, ttl: int) -> Optional[int]:
        """Create a lease with specified TTL in seconds"""
        try:
            lease = self.client.lease(ttl)
            print(f"Created lease with ID: {lease.id} (TTL: {ttl}s)")
            return lease.id
        except Exception as e:
            print(f"Error creating lease: {e}", file=sys.stderr)
            return None
    
    def get_cluster_status(self) -> bool:
        """Get etcd cluster status information"""
        try:
            status = self.client.status()
            print("Cluster Status:")
            print(f"  Version: {status.version}")
            print(f"  DB Size: {status.db_size} bytes")
            print(f"  Leader ID: {status.leader}")
            print(f"  Raft Index: {status.raft_index}")
            print(f"  Raft Term: {status.raft_term}")
            return True
        except Exception as e:
            print(f"Error getting cluster status: {e}", file=sys.stderr)
            return False


def main():
    parser = argparse.ArgumentParser(
        description="Manage key-value pairs in an etcd cluster using python-etcd3",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --list                                    # List all keys
  %(prog)s --list --prefix /config                   # List keys with prefix
  %(prog)s --get /config/app                         # Get specific key
  %(prog)s --get-prefix /config --metadata           # Get all keys with prefix and metadata
  %(prog)s --put /config/app --value "production"    # Set key-value pair
  %(prog)s --put /config/temp --value "test" --ttl 60 # Set key with 60s TTL
  %(prog)s --delete /config/app                      # Delete specific key
  %(prog)s --delete-prefix /config                   # Delete all keys with prefix
  %(prog)s --status                                  # Show cluster status
        """
    )
    
    # Connection options
    parser.add_argument("--host", default="localhost", help="ETCD host (default: localhost)")
    parser.add_argument("--port", type=int, default=2379, help="ETCD port (default: 2379)")
    parser.add_argument("--ca-cert", help="Path to CA certificate file")
    parser.add_argument("--cert", help="Path to client certificate file")
    parser.add_argument("--key", help="Path to client private key file")
    parser.add_argument("--user", help="Username for authentication")
    parser.add_argument("--password", help="Password for authentication")
    parser.add_argument("--timeout", type=int, help="Connection timeout in seconds")
    
    # Operations (mutually exclusive)
    operations = parser.add_mutually_exclusive_group(required=True)
    operations.add_argument("--list", action="store_true", help="List all keys")
    operations.add_argument("--get", metavar="KEY", help="Get value for specific key")
    operations.add_argument("--get-prefix", metavar="PREFIX", help="Get all keys with prefix")
    operations.add_argument("--put", metavar="KEY", help="Set/update key-value pair")
    operations.add_argument("--delete", metavar="KEY", help="Delete specific key")
    operations.add_argument("--delete-prefix", metavar="PREFIX", help="Delete all keys with prefix")
    operations.add_argument("--status", action="store_true", help="Show cluster status")
    
    # Additional options
    parser.add_argument("--prefix", help="Prefix filter for --list operation")
    parser.add_argument("--value", help="Value to set (required with --put)")
    parser.add_argument("--metadata", action="store_true", help="Show metadata with get operations")
    parser.add_argument("--ttl", type=int, help="TTL in seconds for put operation (creates lease)")
    
    args = parser.parse_args()
    
    # Validate arguments
    if args.put and not args.value:
        parser.error("--value is required when using --put")
    
    if args.prefix and not args.list:
        parser.error("--prefix can only be used with --list")
    
    # Create ETCD3 manager
    etcd = ETCD3Manager(
        host=args.host,
        port=args.port,
        ca_cert=args.ca_cert,
        cert_cert=args.cert,
        cert_key=args.key,
        timeout=args.timeout,
        user=args.user,
        password=args.password
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
        lease_id = None
        if args.ttl:
            lease_id = etcd.create_lease(args.ttl)
            if lease_id is None:
                sys.exit(1)
        success = etcd.put_key(args.put, args.value, lease_id=lease_id)
    elif args.delete:
        success = etcd.delete_key(args.delete)
    elif args.delete_prefix:
        success = etcd.delete_prefix(args.delete_prefix)
    elif args.status:
        success = etcd.get_cluster_status()
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()