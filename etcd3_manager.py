#!/usr/bin/env python3
"""
ETCD Key-Value Manager (using python-etcd)

A script for managing key-value pairs in an etcd cluster using the python-etcd library.
Supports operations: list all keys, get specific key, edit, and delete.
"""

import argparse
import json
import sys
from typing import Optional, List, Tuple, Any

try:
    import etcd
except ImportError:
    print("Error: python-etcd library not found. Install with: pip install python-etcd", file=sys.stderr)
    sys.exit(1)


class ETCDManager:
    def __init__(self, host: str = "localhost", port: int = 4001, ca_cert: Optional[str] = None, 
                 cert_cert: Optional[str] = None, cert_key: Optional[str] = None,
                 timeout: Optional[int] = None, user: Optional[str] = None, 
                 password: Optional[str] = None, protocol: str = "http"):
        """Initialize ETCD client with connection parameters"""
        try:
            # python-etcd uses different parameter names and defaults
            kwargs = {
                'host': host,
                'port': port,
                'protocol': protocol,
                'allow_reconnect': True,
                'allow_redirect': False
            }
            
            if ca_cert:
                kwargs['ca_cert'] = ca_cert
            if cert_cert and cert_key:
                kwargs['cert'] = (cert_cert, cert_key)
            if user and password:
                kwargs['username'] = user
                kwargs['password'] = password
            if timeout:
                kwargs['read_timeout'] = timeout
                
            self.client = etcd.Client(**kwargs)
            # Test connection by trying to read root
            self.client.read('/', timeout=5)
        except etcd.EtcdKeyNotFound:
            # This is expected for root path, connection is working
            pass
        except Exception as e:
            print(f"Error connecting to etcd: {e}", file=sys.stderr)
            sys.exit(1)
    
    def list_all_keys(self, prefix: str = "/") -> bool:
        """List all keys in the etcd cluster, optionally with a prefix"""
        try:
            # For python-etcd, we need to do a recursive read
            result = self.client.read(prefix, recursive=True)
            
            keys = []
            if result._children:
                for child in result._children:
                    if not child.dir:  # Only include actual keys, not directories
                        keys.append(child.key)
                    else:
                        # If it's a directory, recursively collect keys
                        try:
                            dir_result = self.client.read(child.key, recursive=True)
                            if dir_result._children:
                                for subchild in dir_result._children:
                                    if not subchild.dir:
                                        keys.append(subchild.key)
                        except:
                            pass
            elif not result.dir:
                keys.append(result.key)
                
            if keys:
                print(f"Keys in etcd cluster{' (prefix: ' + prefix + ')' if prefix != '/' else ''}:")
                for key in sorted(keys):
                    print(f"  {key}")
            else:
                print(f"No keys found{' with prefix: ' + prefix if prefix != '/' else ''}")
            return True
        except etcd.EtcdKeyNotFound:
            print(f"No keys found{' with prefix: ' + prefix if prefix != '/' else ''}")
            return True
        except Exception as e:
            print(f"Error listing keys: {e}", file=sys.stderr)
            return False
    
    def get_key(self, key: str, show_metadata: bool = False) -> bool:
        """Get value for a specific key"""
        try:
            result = self.client.read(key)
            
            print(f"Key: {key}")
            print(f"Value: {result.value}")
            
            if show_metadata:
                print(f"Modified Index: {result.modifiedIndex}")
                print(f"Created Index: {result.createdIndex}")
                if result.ttl:
                    print(f"TTL: {result.ttl}")
                print(f"Directory: {result.dir}")
            
            return True
        except etcd.EtcdKeyNotFound:
            print(f"Key '{key}' not found")
            return True
        except Exception as e:
            print(f"Error getting key '{key}': {e}", file=sys.stderr)
            return False
    
    def get_keys_with_prefix(self, prefix: str, show_metadata: bool = False) -> bool:
        """Get all keys and values with a specific prefix"""
        try:
            result = self.client.read(prefix, recursive=True)
            
            found_keys = []
            if result._children:
                for child in result._children:
                    if not child.dir:  # Only include actual keys, not directories
                        found_keys.append((child.key, child.value, child))
            elif not result.dir:
                found_keys.append((result.key, result.value, result))
            
            if not found_keys:
                print(f"No keys found with prefix '{prefix}'")
                return True
            
            print(f"Keys with prefix '{prefix}':")
            for key, value, metadata in sorted(found_keys, key=lambda x: x[0]):
                print(f"  {key}: {value}")
                if show_metadata:
                    print(f"    Created Index: {metadata.createdIndex}, Modified Index: {metadata.modifiedIndex}")
                    if metadata.ttl:
                        print(f"    TTL: {metadata.ttl}")
            
            return True
        except etcd.EtcdKeyNotFound:
            print(f"No keys found with prefix '{prefix}'")
            return True
        except Exception as e:
            print(f"Error getting keys with prefix '{prefix}': {e}", file=sys.stderr)
            return False
    
    def put_key(self, key: str, value: str, ttl: Optional[int] = None) -> bool:
        """Set/update a key-value pair"""
        try:
            if ttl:
                self.client.write(key, value, ttl=ttl)
                print(f"Successfully set key '{key}' to '{value}' with TTL {ttl}s")
            else:
                self.client.write(key, value)
                print(f"Successfully set key '{key}' to '{value}'")
            return True
        except Exception as e:
            print(f"Error setting key '{key}': {e}", file=sys.stderr)
            return False
    
    def delete_key(self, key: str) -> bool:
        """Delete a specific key"""
        try:
            self.client.delete(key)
            print(f"Successfully deleted key '{key}'")
            return True
        except etcd.EtcdKeyNotFound:
            print(f"Key '{key}' not found")
            return True
        except Exception as e:
            print(f"Error deleting key '{key}': {e}", file=sys.stderr)
            return False
    
    def delete_prefix(self, prefix: str) -> bool:
        """Delete all keys with a specific prefix"""
        try:
            # python-etcd doesn't have delete_prefix, so we need to list keys first
            result = self.client.read(prefix, recursive=True)
            deleted_count = 0
            
            keys_to_delete = []
            if result._children:
                for child in result._children:
                    if not child.dir:
                        keys_to_delete.append(child.key)
            elif not result.dir:
                keys_to_delete.append(result.key)
                
            for key in keys_to_delete:
                try:
                    self.client.delete(key)
                    deleted_count += 1
                except etcd.EtcdKeyNotFound:
                    pass
                    
            if deleted_count > 0:
                print(f"Successfully deleted {deleted_count} keys with prefix '{prefix}'")
            else:
                print(f"No keys found with prefix '{prefix}' to delete")
            return True
        except etcd.EtcdKeyNotFound:
            print(f"No keys found with prefix '{prefix}' to delete")
            return True
        except Exception as e:
            print(f"Error deleting keys with prefix '{prefix}': {e}", file=sys.stderr)
            return False
    
    def create_lease(self, ttl: int) -> Optional[int]:
        """Create a lease with specified TTL in seconds (not supported in python-etcd)"""
        print(f"Note: python-etcd does not support separate lease creation. TTL is set per key.")
        return ttl
    
    def get_cluster_status(self) -> bool:
        """Get etcd cluster status information"""
        try:
            # python-etcd v2 API has limited cluster status info
            stats = self.client.stats
            print("Cluster Status:")
            print(f"  Leader: {stats.leader}")
            print(f"  Machine: {self.client.host}:{self.client.port}")
            print(f"  Protocol: {self.client.protocol}")
            return True
        except Exception as e:
            print(f"Error getting cluster status: {e}", file=sys.stderr)
            return False


def main():
    parser = argparse.ArgumentParser(
        description="Manage key-value pairs in an etcd cluster using python-etcd",
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
    parser.add_argument("--port", type=int, default=4001, help="ETCD port (default: 4001)")
    parser.add_argument("--ca-cert", help="Path to CA certificate file")
    parser.add_argument("--cert", help="Path to client certificate file")
    parser.add_argument("--key", help="Path to client private key file")
    parser.add_argument("--user", help="Username for authentication")
    parser.add_argument("--password", help="Password for authentication")
    parser.add_argument("--timeout", type=int, help="Connection timeout in seconds")
    parser.add_argument("--protocol", default="http", help="Protocol to use (http or https, default: http)")
    
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
    
    # Create ETCD manager
    etcd = ETCDManager(
        host=args.host,
        port=args.port,
        ca_cert=args.ca_cert,
        cert_cert=args.cert,
        cert_key=args.key,
        timeout=args.timeout,
        user=args.user,
        password=args.password,
        protocol=args.protocol
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
    elif args.status:
        success = etcd.get_cluster_status()
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()