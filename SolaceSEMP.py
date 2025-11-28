#!/usr/bin/env python3
"""
SolaceSEMP.py - Solace SEMP API Penetration Testing Tool

A specialized tool for testing Solace Event Broker management plane security
through the SEMP (Solace Element Management Protocol) v2 REST API.
This tool focuses on configuration enumeration, administrative access testing,
and management plane security assessment.

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
import getpass
import sys
import json
import time
import requests
import urllib3
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, List, Any, Tuple
import base64

# Disable SSL warnings for testing purposes
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class SolaceSEMPTester:
    """Main class for SEMP API penetration testing operations."""
    
    def __init__(self, host: str, port: int, username: str, password: str, use_tls: bool = True,
                 oauth_token: Optional[str] = None, cert_file: Optional[str] = None,
                 cert_password: Optional[str] = None, key_file: Optional[str] = None):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.use_tls = use_tls
        self.oauth_token = oauth_token
        self.cert_file = cert_file
        self.cert_password = cert_password
        self.key_file = key_file
        
        # Build base URL
        protocol = "https" if use_tls else "http"
        self.base_url = f"{protocol}://{host}:{port}/SEMP/v2"
        
        # Setup session
        self.session = requests.Session()
        self.session.verify = False  # Disable SSL verification for testing
        
        # Setup authentication
        self._setup_authentication()
    
    def _pem_contains_private_key(self, pem_file: str) -> bool:
        """Check if a PEM file contains a private key."""
        try:
            with open(pem_file, 'r') as f:
                content = f.read()
                # Look for private key markers
                return ('-----BEGIN PRIVATE KEY-----' in content or 
                        '-----BEGIN RSA PRIVATE KEY-----' in content or
                        '-----BEGIN EC PRIVATE KEY-----' in content or
                        '-----BEGIN DSA PRIVATE KEY-----' in content)
        except Exception:
            return False
    
    def _setup_authentication(self):
        """Setup authentication for SEMP API requests."""
        if self.oauth_token:
            self.session.headers.update({
                'Authorization': f'Bearer {self.oauth_token}'
            })
            print("Using OAuth token authentication for SEMP API")
        elif self.cert_file:
            # Handle different certificate file types for SEMP API
            if self.cert_file.lower().endswith('.jks'):
                print("ERROR: JKS files are not supported by Solace Python API.")
                print("Please convert your JKS file to PEM format:")
                print("1. Convert JKS to PKCS12: keytool -importkeystore -srckeystore file.jks -destkeystore file.p12 -srcstoretype jks -deststoretype pkcs12")
                print("2. Extract certificate: openssl pkcs12 -in file.p12 -clcerts -nokeys -out cert.pem")
                print("3. Extract private key: openssl pkcs12 -in file.p12 -nocerts -out key.pem")
                print("4. Use: --cert-file cert.pem --key-file key.pem")
                raise ValueError("JKS files not supported - convert to PEM format first")
            
            elif self.cert_file.lower().endswith(('.p12', '.pfx')):
                # PKCS12 files contain both cert and key
                if self.cert_password:
                    self.session.cert = (self.cert_file, self.cert_password)
                else:
                    self.session.cert = self.cert_file
                print("Using PKCS12 client certificate authentication for SEMP API")
            else:
                # PEM files - check if they contain private key or need separate key file
                if self._pem_contains_private_key(self.cert_file):
                    # PEM file contains both cert and private key
                    self.session.cert = self.cert_file
                    print("Using PEM client certificate authentication for SEMP API (single file)")
                else:
                    # PEM file only contains certificate, need separate key file
                    if not self.key_file:
                        print("ERROR: PEM certificate file does not contain a private key.")
                        print("Use --key-file to specify the private key file.")
                        raise ValueError("PEM certificate requires --key-file parameter")
                    
                    # For PEM files, we need to combine cert and key files
                    # The requests library expects a tuple of (cert_file, key_file) for PEM files
                    self.session.cert = (self.cert_file, self.key_file)
                    print("Using PEM client certificate authentication for SEMP API (separate files)")
        else:
            # Basic authentication
            auth_string = base64.b64encode(f"{self.username}:{self.password}".encode()).decode()
            self.session.headers.update({
                'Authorization': f'Basic {auth_string}'
            })
            print("Using basic authentication for SEMP API")
        
        # Set common headers
        self.session.headers.update({
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        })
    
    def test_connection(self) -> bool:
        """Test SEMP API connectivity and authentication."""
        try:
            print(f"Testing SEMP API connection to {self.host}:{self.port}...")
            
            # Try to access the about endpoint
            response = self.session.get(f"{self.base_url}/about/api", timeout=10)
            
            if response.status_code == 200:
                api_info = response.json()
                print("OK: SEMP API connection successful")
                print(f"  API Version: {api_info.get('data', {}).get('sempVersion', 'Unknown')}")
                print(f"  Platform: {api_info.get('data', {}).get('platform', 'Unknown')}")
                return True
            elif response.status_code == 401:
                print("ERROR: Authentication failed - Invalid credentials")
                return False
            elif response.status_code == 403:
                print("ERROR: Access forbidden - Insufficient permissions")
                return False
            else:
                print(f"ERROR: Connection failed - HTTP {response.status_code}: {response.text}")
                return False
                
        except requests.exceptions.Timeout:
            print("ERROR: Connection timeout - SEMP API may not be available")
            return False
        except requests.exceptions.ConnectionError:
            print("ERROR: Connection error - Cannot reach SEMP API endpoint")
            return False
        except Exception as e:
            print(f"ERROR: Unexpected error: {e}")
            return False
    
    def enumerate_brokers(self) -> Dict[str, Any]:
        """Enumerate available brokers and their basic information."""
        print("\n=== Broker Enumeration ===")
        results = {
            "timestamp": datetime.now().isoformat(),
            "brokers": [],
            "errors": []
        }
        
        try:
            response = self.session.get(f"{self.base_url}/config/brokers", timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                brokers = data.get('data', [])
                
                for broker in brokers:
                    broker_name = broker.get('brokerName', 'Unknown')
                    print(f"Found broker: {broker_name}")
                    
                    broker_info = {
                        "name": broker_name,
                        "serviceRedundancyState": broker.get('serviceRedundancyState'),
                        "serviceRestartState": broker.get('serviceRestartState'),
                        "tlsServerCertEnforceTrustedCommonNameEnabled": broker.get('tlsServerCertEnforceTrustedCommonNameEnabled'),
                        "authClientCertRevocationCheckMode": broker.get('authClientCertRevocationCheckMode'),
                        "guaranteedMsgingEnabled": broker.get('guaranteedMsgingEnabled')
                    }
                    results["brokers"].append(broker_info)
                
                print(f"Found {len(brokers)} broker(s)")
            else:
                error_msg = f"Failed to enumerate brokers: HTTP {response.status_code}"
                results["errors"].append(error_msg)
                print(f"ERROR: {error_msg}")
                
        except Exception as e:
            error_msg = f"Error enumerating brokers: {e}"
            results["errors"].append(error_msg)
            print(f"ERROR: {error_msg}")
        
        return results
    
    def enumerate_vpns(self) -> Dict[str, Any]:
        """Enumerate Message VPNs and their configurations."""
        print("\n=== Message VPN Enumeration ===")
        results = {
            "timestamp": datetime.now().isoformat(),
            "vpns": [],
            "errors": []
        }
        
        try:
            response = self.session.get(f"{self.base_url}/config/msgVpns", timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                vpns = data.get('data', [])
                
                for vpn in vpns:
                    vpn_name = vpn.get('msgVpnName', 'Unknown')
                    print(f"Found VPN: {vpn_name}")
                    
                    vpn_info = {
                        "name": vpn_name,
                        "enabled": vpn.get('enabled'),
                        "authenticationBasicEnabled": vpn.get('authenticationBasicEnabled'),
                        "authenticationClientCertEnabled": vpn.get('authenticationClientCertEnabled'),
                        "authenticationOauthEnabled": vpn.get('authenticationOauthEnabled'),
                        "bridgingTlsServerCertEnforceTrustedCommonNameEnabled": vpn.get('bridgingTlsServerCertEnforceTrustedCommonNameEnabled'),
                        "restTlsServerCertEnforceTrustedCommonNameEnabled": vpn.get('restTlsServerCertEnforceTrustedCommonNameEnabled'),
                        "serviceSmfMaxConnectionCountPerClientUsername": vpn.get('serviceSmfMaxConnectionCountPerClientUsername'),
                        "serviceWebMaxConnectionCountPerClientUsername": vpn.get('serviceWebMaxConnectionCountPerClientUsername')
                    }
                    results["vpns"].append(vpn_info)
                
                print(f"Found {len(vpns)} VPN(s)")
            else:
                error_msg = f"Failed to enumerate VPNs: HTTP {response.status_code}"
                results["errors"].append(error_msg)
                print(f"ERROR: {error_msg}")
                
        except Exception as e:
            error_msg = f"Error enumerating VPNs: {e}"
            results["errors"].append(error_msg)
            print(f"ERROR: {error_msg}")
        
        return results
    
    def enumerate_users(self, vpn_name: str = None) -> Dict[str, Any]:
        """Enumerate client users for specified VPN or all VPNs."""
        print(f"\n=== User Enumeration {f'(VPN: {vpn_name})' if vpn_name else '(All VPNs)'} ===")
        results = {
            "timestamp": datetime.now().isoformat(),
            "users": [],
            "errors": []
        }
        
        try:
            if vpn_name:
                url = f"{self.base_url}/config/msgVpns/{vpn_name}/clientUsernames"
            else:
                # First get all VPNs, then enumerate users for each
                vpn_response = self.session.get(f"{self.base_url}/config/msgVpns", timeout=10)
                if vpn_response.status_code != 200:
                    results["errors"].append("Failed to get VPN list")
                    return results
                
                vpns = vpn_response.json().get('data', [])
                
                for vpn in vpns:
                    vpn_name = vpn.get('msgVpnName')
                    url = f"{self.base_url}/config/msgVpns/{vpn_name}/clientUsernames"
                    
                    response = self.session.get(url, timeout=10)
                    if response.status_code == 200:
                        users = response.json().get('data', [])
                        for user in users:
                            username = user.get('clientUsername', 'Unknown')
                            print(f"Found user: {username} (VPN: {vpn_name})")
                            
                            user_info = {
                                "username": username,
                                "vpn": vpn_name,
                                "enabled": user.get('enabled'),
                                "aclProfileName": user.get('aclProfileName'),
                                "clientProfileName": user.get('clientProfileName'),
                                "guaranteedEndpointPermissionOverrideEnabled": user.get('guaranteedEndpointPermissionOverrideEnabled'),
                                "subscriptionManagerEnabled": user.get('subscriptionManagerEnabled')
                            }
                            results["users"].append(user_info)
                    else:
                        error_msg = f"Failed to enumerate users for VPN {vpn_name}: HTTP {response.status_code}"
                        results["errors"].append(error_msg)
                
                return results
            
            # Single VPN enumeration
            response = self.session.get(url, timeout=10)
            if response.status_code == 200:
                users = response.json().get('data', [])
                for user in users:
                    username = user.get('clientUsername', 'Unknown')
                    print(f"Found user: {username}")
                    
                    user_info = {
                        "username": username,
                        "vpn": vpn_name,
                        "enabled": user.get('enabled'),
                        "aclProfileName": user.get('aclProfileName'),
                        "clientProfileName": user.get('clientProfileName'),
                        "guaranteedEndpointPermissionOverrideEnabled": user.get('guaranteedEndpointPermissionOverrideEnabled'),
                        "subscriptionManagerEnabled": user.get('subscriptionManagerEnabled')
                    }
                    results["users"].append(user_info)
                
                print(f"Found {len(users)} user(s)")
            else:
                error_msg = f"Failed to enumerate users: HTTP {response.status_code}"
                results["errors"].append(error_msg)
                print(f"ERROR: {error_msg}")
                
        except Exception as e:
            error_msg = f"Error enumerating users: {e}"
            results["errors"].append(error_msg)
            print(f"ERROR: {error_msg}")
        
        return results
    
    def enumerate_acl_profiles(self, vpn_name: str) -> Dict[str, Any]:
        """Enumerate ACL profiles for a specific VPN."""
        print(f"\n=== ACL Profile Enumeration (VPN: {vpn_name}) ===")
        results = {
            "timestamp": datetime.now().isoformat(),
            "acl_profiles": [],
            "errors": []
        }
        
        try:
            url = f"{self.base_url}/config/msgVpns/{vpn_name}/aclProfiles"
            response = self.session.get(url, timeout=10)
            
            if response.status_code == 200:
                profiles = response.json().get('data', [])
                for profile in profiles:
                    profile_name = profile.get('aclProfileName', 'Unknown')
                    print(f"Found ACL profile: {profile_name}")
                    
                    profile_info = {
                        "name": profile_name,
                        "vpn": vpn_name,
                        "clientConnectDefaultAction": profile.get('clientConnectDefaultAction'),
                        "publishTopicDefaultAction": profile.get('publishTopicDefaultAction'),
                        "subscribeTopicDefaultAction": profile.get('subscribeTopicDefaultAction'),
                        "subscribeShareNameDefaultAction": profile.get('subscribeShareNameDefaultAction')
                    }
                    results["acl_profiles"].append(profile_info)
                
                print(f"Found {len(profiles)} ACL profile(s)")
            else:
                error_msg = f"Failed to enumerate ACL profiles: HTTP {response.status_code}"
                results["errors"].append(error_msg)
                print(f"ERROR: {error_msg}")
                
        except Exception as e:
            error_msg = f"Error enumerating ACL profiles: {e}"
            results["errors"].append(error_msg)
            print(f"ERROR: {error_msg}")
        
        return results
    
    def test_administrative_access(self) -> Dict[str, Any]:
        """Test access to administrative functions and sensitive endpoints."""
        print("\n=== Administrative Access Testing ===")
        results = {
            "timestamp": datetime.now().isoformat(),
            "admin_access_tests": [],
            "sensitive_endpoints": [],
            "errors": []
        }
        
        # List of administrative endpoints to test
        admin_endpoints = [
            ("/config/brokers", "Broker configuration"),
            ("/config/systemInformation", "System information"),
            ("/config/virtualHostnames", "Virtual hostnames"),
            ("/config/certAuthorities", "Certificate authorities"),
            ("/config/clientCertAuthorities", "Client certificate authorities"),
            ("/config/domainCertAuthorities", "Domain certificate authorities"),
            ("/action/brokers", "Broker actions"),
            ("/monitor/brokers", "Broker monitoring"),
            ("/config/msgVpns/default/bridges", "Bridge configuration"),
            ("/config/msgVpns/default/restDeliveryPoints", "REST delivery points")
        ]
        
        for endpoint, description in admin_endpoints:
            try:
                url = f"{self.base_url}{endpoint}"
                response = self.session.get(url, timeout=5)
                
                test_result = {
                    "endpoint": endpoint,
                    "description": description,
                    "status_code": response.status_code,
                    "accessible": response.status_code == 200,
                    "response_size": len(response.content)
                }
                
                if response.status_code == 200:
                    print(f"WARNING: ADMIN ACCESS: {description} - {endpoint}")
                    test_result["security_risk"] = "HIGH"
                elif response.status_code == 401:
                    print(f"OK: Properly protected: {description}")
                    test_result["security_risk"] = "NONE"
                elif response.status_code == 403:
                    print(f"OK: Access forbidden: {description}")
                    test_result["security_risk"] = "LOW"
                else:
                    print(f"? Unexpected response for {description}: HTTP {response.status_code}")
                    test_result["security_risk"] = "UNKNOWN"
                
                results["admin_access_tests"].append(test_result)
                
            except Exception as e:
                error_msg = f"Error testing {endpoint}: {e}"
                results["errors"].append(error_msg)
                print(f"ERROR: {error_msg}")
        
        return results
    
    def generate_report(self, output_file: str, *result_sets):
        """Generate a comprehensive security assessment report."""
        print(f"\n=== Generating Security Report ===")
        
        report = {
            "scan_info": {
                "timestamp": datetime.now().isoformat(),
                "target": f"{self.host}:{self.port}",
                "semp_base_url": self.base_url,
                "authentication_method": "OAuth" if self.oauth_token else "Certificate" if self.cert_file else "Basic"
            },
            "results": {}
        }
        
        # Combine all result sets
        for result_set in result_sets:
            if isinstance(result_set, dict):
                report["results"].update(result_set)
        
        # Security summary
        security_issues = []
        admin_tests = report["results"].get("admin_access_tests", [])
        for test in admin_tests:
            if test.get("security_risk") == "HIGH":
                security_issues.append(f"Administrative access to: {test['description']}")
        
        report["security_summary"] = {
            "total_issues": len(security_issues),
            "critical_issues": security_issues,
            "vpn_count": len(report["results"].get("vpns", [])),
            "user_count": len(report["results"].get("users", [])),
            "broker_count": len(report["results"].get("brokers", []))
        }
        
        # Write report
        try:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"Security report saved to: {output_file}")
            
            # Print summary
            print(f"\n=== Security Assessment Summary ===")
            print(f"Target: {self.host}:{self.port}")
            print(f"Critical Issues: {len(security_issues)}")
            print(f"VPNs Found: {report['security_summary']['vpn_count']}")
            print(f"Users Found: {report['security_summary']['user_count']}")
            print(f"Brokers Found: {report['security_summary']['broker_count']}")
            
            if security_issues:
                print(f"\nCRITICAL SECURITY ISSUES:")
                for issue in security_issues:
                    print(f"  - {issue}")
            else:
                print(f"\nNo critical security issues detected")
                
        except Exception as e:
            print(f"ERROR: Error saving report: {e}")


def main():
    """Main entry point for the SEMP penetration testing tool."""
    parser = argparse.ArgumentParser(
        description="Solace SEMP API Penetration Testing Tool",
        epilog="Author: Garland Glessner <gglessner@gmail.com> | License: GNU GPL v3.0"
    )
    
    # Connection arguments
    parser.add_argument("--server", required=True, help="Solace SEMP server in host:port format")
    parser.add_argument("--username", help="Username for basic authentication")
    parser.add_argument("--password", help="Password for basic authentication (if not provided, will prompt)")
    parser.add_argument("--no-tls", action="store_true", help="Disable TLS (use HTTP instead of HTTPS)")
    
    # Authentication arguments
    parser.add_argument("--oauth-token", help="OAuth token for authentication")
    parser.add_argument("--cert-file", help="Client certificate file path (PEM/PKCS12 format)")
    parser.add_argument("--key-file", help="Private key file path (required for PEM certificates)")
    
    # Operation arguments
    parser.add_argument("--test-connection", action="store_true", help="Test SEMP API connection and exit")
    parser.add_argument("--enumerate-all", action="store_true", help="Perform comprehensive enumeration")
    parser.add_argument("--enumerate-brokers", action="store_true", help="Enumerate broker information")
    parser.add_argument("--enumerate-vpns", action="store_true", help="Enumerate Message VPNs")
    parser.add_argument("--enumerate-users", help="Enumerate users (specify VPN name or 'all')")
    parser.add_argument("--enumerate-acls", help="Enumerate ACL profiles for specified VPN")
    parser.add_argument("--test-admin-access", action="store_true", help="Test administrative access")
    
    # Output arguments
    parser.add_argument("--output", "-o", help="Output file for security report (JSON format)")
    
    args = parser.parse_args()
    
    # Parse server
    try:
        host, port = args.server.split(":")
        port = int(port)
    except ValueError:
        print("Error: --server must be in host:port format")
        sys.exit(1)
    
    # Handle authentication method selection and secure prompting
    password = None
    cert_password = None
    
    # Validate authentication arguments
    auth_methods = sum([bool(args.username), bool(args.oauth_token), bool(args.cert_file)])
    if auth_methods == 0:
        print("Error: Must specify one authentication method (--username, --oauth-token, or --cert-file)")
        sys.exit(1)
    elif auth_methods > 1:
        print("Error: Cannot specify multiple authentication methods")
        sys.exit(1)
    
    # Prompt for passwords based on authentication method
    try:
        if args.username:
            if args.password:
                password = args.password
            else:
                password = getpass.getpass(f"Password for user '{args.username}': ")
            if not password:
                print("Error: Password cannot be empty")
                sys.exit(1)
        elif args.cert_file:
            import os
            if not os.path.exists(args.cert_file):
                print(f"Error: Certificate file not found: {args.cert_file}")
                sys.exit(1)
            # Only prompt for password if it's a PKCS12 file
            if args.cert_file.lower().endswith(('.p12', '.pfx')):
                cert_password = getpass.getpass("Certificate password (press Enter if none): ")
            else:
                # PEM files typically don't have passwords
                cert_password = ""
        elif args.oauth_token:
            # OAuth token provided directly, no additional prompting needed
            pass
    except KeyboardInterrupt:
        print("\nOperation cancelled")
        sys.exit(1)
    
    # Create SEMP tester instance
    semp_tester = SolaceSEMPTester(
        host=host,
        port=port,
        username=args.username or "",
        password=password or "",
        use_tls=not args.no_tls,
        oauth_token=args.oauth_token,
        cert_file=args.cert_file,
        cert_password=cert_password,
        key_file=args.key_file
    )
    
    try:
        results = []
        
        # Handle operations
        if args.test_connection:
            success = semp_tester.test_connection()
            sys.exit(0 if success else 1)
        
        if args.enumerate_all:
            print("Performing comprehensive SEMP enumeration...")
            results.append(semp_tester.enumerate_brokers())
            results.append(semp_tester.enumerate_vpns())
            results.append(semp_tester.enumerate_users())
            results.append(semp_tester.test_administrative_access())
        
        if args.enumerate_brokers:
            results.append(semp_tester.enumerate_brokers())
        
        if args.enumerate_vpns:
            results.append(semp_tester.enumerate_vpns())
        
        if args.enumerate_users:
            vpn_name = None if args.enumerate_users.lower() == 'all' else args.enumerate_users
            results.append(semp_tester.enumerate_users(vpn_name))
        
        if args.enumerate_acls:
            results.append(semp_tester.enumerate_acl_profiles(args.enumerate_acls))
        
        if args.test_admin_access:
            results.append(semp_tester.test_administrative_access())
        
        # Generate report if requested
        if args.output and results:
            semp_tester.generate_report(args.output, *results)
        elif results:
            # Print results to stdout
            for result in results:
                print(json.dumps(result, indent=2))
        
        # If no specific operation was requested, show help
        if not any([args.test_connection, args.enumerate_all, args.enumerate_brokers, 
                   args.enumerate_vpns, args.enumerate_users, args.enumerate_acls, 
                   args.test_admin_access]):
            parser.print_help()
    
    except KeyboardInterrupt:
        print("\nOperation interrupted by user")
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
