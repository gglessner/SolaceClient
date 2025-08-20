#!/usr/bin/env python3
"""
SolaceVPNscan.py - Solace VPN Enumeration Tool

A tool for enumerating valid VPN names on Solace PubSub+ brokers by analyzing
authentication error responses. This tool determines VPN existence based on
error message analysis without requiring valid credentials.

Author: Garland Glessner <gglessner@gmail.com>
License: GNU General Public License v3.0

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

import argparse
import sys
import time
import csv
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any

try:
    from solace.messaging.messaging_service import MessagingService
    from solace.messaging.config.authentication_strategy import BasicUserNamePassword
    from solace.messaging.config.transport_security_strategy import TLS
except ImportError as e:
    print("Error: solace-pubsubplus library not found or import failed.")
    print(f"Import error: {e}")
    print("Install with: pip install solace-pubsubplus")
    sys.exit(1)


class SolaceVPNScanner:
    """Main class for VPN enumeration operations."""
    
    def __init__(self, host: str, port: int, use_tls: bool = True):
        self.host = host
        self.port = port
        self.use_tls = use_tls
        self.results = []
    
    def test_vpn(self, vpn_name: str) -> Dict[str, Any]:
        """Test a single VPN name to determine if it exists."""
        print(f"Testing VPN: {vpn_name}")
        
        result = {
            "vpn_name": vpn_name,
            "status": "UNKNOWN",
            "error_details": "",
            "timestamp": datetime.now().isoformat()
        }
        
        try:
            # Build service properties
            protocol = "tcps" if self.use_tls else "tcp"
            service_props = {
                "solace.messaging.transport.host": f"{protocol}://{self.host}:{self.port}",
                "solace.messaging.service.vpn-name": vpn_name,
                "solace.messaging.service.receiver.direct.subscription-reapply": True
            }
            
            # Create messaging service with empty credentials
            builder = MessagingService.builder().from_properties(service_props)
            
            # Use empty credentials for anonymous/guest authentication attempt
            auth_strategy = BasicUserNamePassword.of("", "")
            builder = builder.with_authentication_strategy(auth_strategy)
            
            # Add TLS if enabled
            if self.use_tls:
                tls_strategy = TLS.create().without_certificate_validation()
                builder = builder.with_transport_security_strategy(tls_strategy)
            
            # Build and attempt connection
            messaging_service = builder.build()
            messaging_service.connect()
            
            # If we get here, connection succeeded (unexpected)
            result["status"] = "EXISTS"
            result["error_details"] = "Connection succeeded with empty credentials"
            print(f"  Status: EXISTS (connection succeeded)")
            
            try:
                messaging_service.disconnect()
            except:
                pass
                
        except Exception as e:
            error_message = str(e)
            result["error_details"] = error_message
            
            # Analyze error message to determine VPN existence
            if "Message VPN Not Allowed" in error_message or "VPN Not Allowed" in error_message:
                result["status"] = "NOT_EXISTS"
                print(f"  Status: NOT_EXISTS (VPN not found)")
            elif "Unauthorized" in error_message or "Authentication" in error_message:
                result["status"] = "EXISTS"
                print(f"  Status: EXISTS (unauthorized access)")
            elif "Connection" in error_message or "timeout" in error_message.lower():
                result["status"] = "CONNECTION_ERROR"
                print(f"  Status: CONNECTION_ERROR")
            else:
                result["status"] = "UNKNOWN"
                print(f"  Status: UNKNOWN (unexpected error)")
            
            print(f"  Error: {error_message}")
        
        return result
    
    def scan_vpns_from_file(self, vpn_file: str, case_variations: bool = False) -> List[Dict[str, Any]]:
        """Scan VPNs from a text file containing VPN names."""
        try:
            with open(vpn_file, 'r') as f:
                base_vpn_names = [line.strip() for line in f.readlines() if line.strip()]
        except FileNotFoundError:
            print(f"Error: VPN file not found: {vpn_file}")
            return []
        except Exception as e:
            print(f"Error reading VPN file: {e}")
            return []
        
        if not base_vpn_names:
            print("Error: No VPN names found in file")
            return []
        
        # Generate case variations if requested
        vpn_names = []
        for base_name in base_vpn_names:
            vpn_names.append(base_name)  # Original name
            
            if case_variations:
                # Add case variations (avoid duplicates)
                variations = [
                    base_name.lower(),
                    base_name.upper(), 
                    base_name.title()
                ]
                for variation in variations:
                    if variation not in vpn_names:
                        vpn_names.append(variation)
        
        if case_variations:
            print(f"Generated {len(vpn_names)} total VPN names (including case variations) from {len(base_vpn_names)} base names")
        
        print(f"Found {len(vpn_names)} VPN names to test")
        print(f"Target: {self.host}:{self.port}")
        print(f"TLS: {'Enabled' if self.use_tls else 'Disabled'}")
        print("-" * 50)
        
        results = []
        for i, vpn_name in enumerate(vpn_names, 1):
            print(f"[{i}/{len(vpn_names)}] ", end="")
            result = self.test_vpn(vpn_name)
            results.append(result)
            self.results.append(result)
            
            # Small delay to avoid overwhelming the broker
            time.sleep(0.5)
        
        return results
    
    def save_csv(self, output_file: str):
        """Save results to CSV file."""
        try:
            with open(output_file, 'w', newline='') as csvfile:
                fieldnames = ['VPN_Name', 'Status', 'Error_Details', 'Timestamp']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                
                writer.writeheader()
                for result in self.results:
                    writer.writerow({
                        'VPN_Name': result['vpn_name'],
                        'Status': result['status'],
                        'Error_Details': result['error_details'],
                        'Timestamp': result['timestamp']
                    })
            
            print(f"\nResults saved to: {output_file}")
        except Exception as e:
            print(f"Error saving CSV file: {e}")
    
    def print_summary(self):
        """Print summary of scan results."""
        if not self.results:
            return
        
        exists_count = sum(1 for r in self.results if r['status'] == 'EXISTS')
        not_exists_count = sum(1 for r in self.results if r['status'] == 'NOT_EXISTS')
        unknown_count = sum(1 for r in self.results if r['status'] in ['UNKNOWN', 'CONNECTION_ERROR'])
        
        print("\n" + "=" * 50)
        print("SCAN SUMMARY")
        print("=" * 50)
        print(f"Total VPNs tested: {len(self.results)}")
        print(f"VPNs that exist: {exists_count}")
        print(f"VPNs that don't exist: {not_exists_count}")
        print(f"Unknown/Error: {unknown_count}")
        
        if exists_count > 0:
            print(f"\nVPNs that exist:")
            for result in self.results:
                if result['status'] == 'EXISTS':
                    print(f"  - {result['vpn_name']}")


def main():
    """Main entry point for the VPN scanning tool."""
    parser = argparse.ArgumentParser(
        description="Solace VPN Enumeration Tool",
        epilog="Author: Garland Glessner <gglessner@gmail.com> | License: GNU GPL v3.0"
    )
    
    # Connection arguments
    parser.add_argument("--server", required=True, help="Solace server in host:port format")
    parser.add_argument("--no-tls", action="store_true", help="Disable TLS (use unencrypted connection)")
    
    # VPN list argument
    parser.add_argument("--vpn-list", required=True, help="Text file containing VPN names (one per line)")
    
    # Case variation option
    parser.add_argument("--case-variations", action="store_true", 
                        help="Generate lowercase, uppercase, and title case variations of each VPN name")
    
    # Output arguments
    parser.add_argument("--csv", help="Save results to CSV file")
    
    args = parser.parse_args()
    
    # Parse server
    try:
        host, port = args.server.split(":")
        port = int(port)
    except ValueError:
        print("Error: --server must be in host:port format")
        sys.exit(1)
    
    # Check if VPN list file exists
    if not Path(args.vpn_list).exists():
        print(f"Error: VPN list file not found: {args.vpn_list}")
        sys.exit(1)
    
    # Create VPN scanner instance
    scanner = SolaceVPNScanner(
        host=host,
        port=port,
        use_tls=not args.no_tls
    )
    
    try:
        # Perform VPN scanning
        results = scanner.scan_vpns_from_file(args.vpn_list, args.case_variations)
        
        if results:
            # Print summary
            scanner.print_summary()
            
            # Save to CSV if requested
            if args.csv:
                scanner.save_csv(args.csv)
        
    except KeyboardInterrupt:
        print("\nVPN scanning interrupted by user")
        if scanner.results and args.csv:
            print("Saving partial results...")
            scanner.save_csv(args.csv)
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
