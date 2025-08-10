#!/usr/bin/env python3
"""
ETCD Key-Value Manager

A script for managing key-value pairs in an etcd cluster.
Supports operations: list all keys, get specific key, edit, and delete.
"""

import argparse
import json
import sys
import subprocess
from typing import Optional, Dict, Any


class ETCDManager:
    def __init__(self, host: str = "localhost", port: int = 2379, ssl: bool = False):
        self.host = host
        self.port = port
        self.ssl = ssl
        self.endpoint = f"{'https' if ssl else 'http'}://{host}:{port}"
    
    def _run_etcdctl(self, args: list) -> tuple[bool, str, str]:
        """Run etcdctl command and return success status, stdout, stderr"""
        cmd = ["etcdctl", "--endpoints", self.endpoint] + args
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            return result.returncode == 0, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return False, "", "Command timed out"
        except FileNotFoundError:
            return False, "", "etcdctl command not found. Please install etcd client."
    
    def list_all_keys(self) -> bool:
        """List all keys in the etcd cluster"""
        success, stdout, stderr = self._run_etcdctl(["get", "", "--prefix", "--keys-only"])
        if success:
            if stdout.strip():
                print("Keys in etcd cluster:")
                for key in stdout.strip().split('\n'):
                    print(f"  {key}")
            else:
                print("No keys found in etcd cluster")
            return True
        else:
            print(f"Error listing keys: {stderr}", file=sys.stderr)
            return False
    
    def get_key(self, key: str) -> bool:
        """Get value for a specific key"""
        success, stdout, stderr = self._run_etcdctl(["get", key])
        if success:
            lines = stdout.strip().split('\n')
            if len(lines) >= 2:
                print(f"Key: {lines[0]}")
                print(f"Value: {lines[1]}")
            elif len(lines) == 1 and lines[0]:
                print(f"Key: {key}")
                print(f"Value: {lines[0]}")
            else:
                print(f"Key '{key}' not found")
            return True
        else:
            print(f"Error getting key '{key}': {stderr}", file=sys.stderr)
            return False
    
    def put_key(self, key: str, value: str) -> bool:
        """Set/update a key-value pair"""
        success, stdout, stderr = self._run_etcdctl(["put", key, value])
        if success:
            print(f"Successfully set key '{key}' to '{value}'")
            return True
        else:
            print(f"Error setting key '{key}': {stderr}", file=sys.stderr)
            return False
    
    def delete_key(self, key: str) -> bool:
        """Delete a key"""
        success, stdout, stderr = self._run_etcdctl(["del", key])
        if success:
            deleted_count = stdout.strip()
            if deleted_count == "1":
                print(f"Successfully deleted key '{key}'")
            else:
                print(f"Key '{key}' not found")
            return True
        else:
            print(f"Error deleting key '{key}': {stderr}", file=sys.stderr)
            return False


def main():
    parser = argparse.ArgumentParser(
        description="Manage key-value pairs in an etcd cluster",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --list                           # List all keys
  %(prog)s --get /config/app                # Get specific key
  %(prog)s --put /config/app --value "test" # Set key-value pair
  %(prog)s --delete /config/app             # Delete key
        """
    )
    
    # Connection options
    parser.add_argument("--host", default="localhost", help="ETCD host (default: localhost)")
    parser.add_argument("--port", type=int, default=2379, help="ETCD port (default: 2379)")
    parser.add_argument("--ssl", action="store_true", help="Use HTTPS instead of HTTP")
    
    # Operations (mutually exclusive)
    operations = parser.add_mutually_exclusive_group(required=True)
    operations.add_argument("--list", action="store_true", help="List all keys")
    operations.add_argument("--get", metavar="KEY", help="Get value for specific key")
    operations.add_argument("--put", metavar="KEY", help="Set/update key-value pair")
    operations.add_argument("--delete", metavar="KEY", help="Delete key")
    
    # Value for put operation
    parser.add_argument("--value", help="Value to set (required with --put)")
    
    args = parser.parse_args()
    
    # Validate arguments
    if args.put and not args.value:
        parser.error("--value is required when using --put")
    
    # Create ETCD manager
    etcd = ETCDManager(host=args.host, port=args.port, ssl=args.ssl)
    
    # Execute operation
    success = False
    if args.list:
        success = etcd.list_all_keys()
    elif args.get:
        success = etcd.get_key(args.get)
    elif args.put:
        success = etcd.put_key(args.put, args.value)
    elif args.delete:
        success = etcd.delete_key(args.delete)
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()