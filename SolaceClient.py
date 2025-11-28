#!/usr/bin/env python3
"""
Solace PubSub+ Penetration Testing Tool

A comprehensive penetration testing tool for Solace PubSub+ brokers that provides
capabilities for connection validation, information gathering, message monitoring,
and message replay for security testing purposes.

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
import time
import os
import json
import signal
import threading
import base64
import ssl
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, List, Any

try:
    from solace.messaging.messaging_service import MessagingService
    from solace.messaging.config.authentication_strategy import BasicUserNamePassword, OAuth2, ClientCertificateAuthentication
    from solace.messaging.config.transport_security_strategy import TLS
    from solace.messaging.resources.queue import Queue
    from solace.messaging.resources.topic_subscription import TopicSubscription
    from solace.messaging.receiver.persistent_message_receiver import PersistentMessageReceiver
    from solace.messaging.receiver.direct_message_receiver import DirectMessageReceiver
    from solace.messaging.publisher.persistent_message_publisher import PersistentMessagePublisher
    from solace.messaging.publisher.direct_message_publisher import DirectMessagePublisher
except ImportError as e:
    print("Error: solace-pubsubplus library not found or import failed.")
    print(f"Import error: {e}")
    print("Install with: pip install solace-pubsubplus")
    sys.exit(1)


class SolacePenTest:
    """Main class for Solace penetration testing operations."""
    
    def __init__(self, host: str, port: int, username: str, password: str, vpn: str, use_tls: bool = True, 
                 oauth_token: Optional[str] = None, cert_file: Optional[str] = None, 
                 cert_password: Optional[str] = None, key_file: Optional[str] = None, check_auth: bool = False):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.vpn = vpn
        self.use_tls = use_tls
        self.oauth_token = oauth_token
        self.cert_file = cert_file
        self.cert_password = cert_password
        self.key_file = key_file
        self.check_auth = check_auth
        self.messaging_service = None
        self.is_connected = False
        self.stop_event = threading.Event()
        
        # Set up signal handler for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
    
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
    
    
    def _signal_handler(self, signum, frame):
        """Handle Ctrl+C gracefully."""
        print("\nReceived interrupt signal. Shutting down gracefully...")
        self.stop_event.set()
        if self.is_connected and self.messaging_service:
            self.messaging_service.disconnect()
        sys.exit(0)
    
    def connect(self) -> bool:
        """Establish connection to Solace broker."""
        try:
            # Build service properties dictionary with correct protocol
            protocol = "tcps" if self.use_tls else "tcp"
            service_props = {
                "solace.messaging.transport.host": f"{protocol}://{self.host}:{self.port}",
                "solace.messaging.service.vpn-name": self.vpn,
                "solace.messaging.service.receiver.direct.subscription-reapply": True
            }
            
            # Create messaging service builder
            builder = MessagingService.builder().from_properties(service_props)
            
            # Choose authentication strategy
            if self.oauth_token:
                # OAuth token authentication
                print("Using OAuth token authentication")
                auth_strategy = OAuth2.of(self.oauth_token)
            elif self.cert_file:
                # Client certificate authentication
                print("Using client certificate authentication")
                
                # Handle different certificate file types
                if self.cert_file.lower().endswith('.jks'):
                    print("ERROR: JKS files are not supported by Solace Python API.")
                    print("Please convert your JKS file to PEM format:")
                    print("1. Convert JKS to PKCS12: keytool -importkeystore -srckeystore file.jks -destkeystore file.p12 -srcstoretype jks -deststoretype pkcs12")
                    print("2. Extract certificate: openssl pkcs12 -in file.p12 -clcerts -nokeys -out cert.pem")
                    print("3. Extract private key: openssl pkcs12 -in file.p12 -nocerts -out key.pem")
                    print("4. Use: --cert-file cert.pem --key-file key.pem")
                    raise ValueError("JKS files not supported - convert to PEM format first")
                
                elif self.cert_file.lower().endswith(('.p12', '.pfx')):
                    # PKCS12 files are not supported by ClientCertificateAuthentication.of()
                    # User needs to convert to PEM format first
                    print("ERROR: PKCS12 files (.p12, .pfx) require conversion to PEM format.")
                    print("Convert your PKCS12 file to PEM format:")
                    print("1. Extract certificate: openssl pkcs12 -in file.p12 -clcerts -nokeys -out cert.pem")
                    print("2. Extract private key: openssl pkcs12 -in file.p12 -nocerts -out key.pem")
                    print("3. Use: --cert-file cert.pem --key-file key.pem")
                    raise ValueError("PKCS12 files not supported - convert to PEM format first")
                else:
                    # PEM files - require separate certificate and key files
                    if self._pem_contains_private_key(self.cert_file):
                        print("ERROR: PEM files containing both certificate and private key are not supported.")
                        print("Please split your PEM file into separate certificate and key files:")
                        print("1. Extract certificate: openssl x509 -in combined.pem -out cert.pem")
                        print("2. Extract private key: openssl pkey -in combined.pem -out key.pem")
                        print("3. Use: --cert-file cert.pem --key-file key.pem")
                        raise ValueError("Combined PEM files not supported - split into separate files")
                    else:
                        # PEM file only contains certificate, need separate key file
                        if not hasattr(self, 'key_file') or not self.key_file:
                            print("ERROR: PEM certificate file does not contain a private key.")
                            print("Use --key-file to specify the private key file.")
                            raise ValueError("PEM certificate requires --key-file parameter")
                        
                        auth_strategy = ClientCertificateAuthentication.of(
                            self.cert_file, self.key_file, self.cert_password or None
                        )
            else:
                # Basic username/password authentication
                print("Using basic username/password authentication")
                auth_strategy = BasicUserNamePassword.of(
                    self.username, self.password
                )
            
            builder = builder.with_authentication_strategy(auth_strategy)
            
            # Add TLS if enabled
            if self.use_tls:
                tls_strategy = TLS.create().without_certificate_validation()
                builder = builder.with_transport_security_strategy(tls_strategy)
            
            # Build and connect
            self.messaging_service = builder.build()
            self.messaging_service.connect()
            self.is_connected = True
            
            auth_method = "OAuth" if self.oauth_token else "Certificate" if self.cert_file else "Basic"
            print(f"Successfully connected to Solace broker at {self.host}:{self.port} using {auth_method} authentication")
            return True
            
        except Exception as e:
            print(f"Failed to connect to Solace broker: {e}")
            return False
    
    def disconnect(self):
        """Disconnect from Solace broker."""
        if self.is_connected and self.messaging_service:
            try:
                self.messaging_service.disconnect()
                self.is_connected = False
                print("Disconnected from Solace broker")
            except Exception as e:
                print(f"Error during disconnect: {e}")
    
    def validate_connection(self) -> bool:
        """Validate that the account can login to the broker."""
        print(f"Validating connection to {self.host}:{self.port} with user '{self.username}' on VPN '{self.vpn}'...")
        
        if self.connect():
            print("Connection validation successful")
            self.disconnect()
            return True
        else:
            print("Connection validation failed")
            return False
    
    def get_broker_info(self) -> Dict[str, Any]:
        """Gather information about the Solace broker."""
        if not self.is_connected:
            if not self.connect():
                return {}
        
        info = {
            "connection": {
                "host": self.host,
                "port": self.port,
                "username": self.username,
                "vpn": self.vpn,
                "tls_enabled": self.use_tls,
                "connected_at": datetime.now().isoformat()
            }
        }
        
        try:
            # Get service info (this is limited with the client library)
            # Most detailed broker info requires admin access via SEMP
            print("Broker connection information gathered:")
            for key, value in info["connection"].items():
                print(f"  {key}: {value}")
                
        except Exception as e:
            print(f"Error gathering broker info: {e}")
        
        return info
    
    def check_authorization(self) -> Dict[str, Any]:
        """Check authorization by testing access to common default administrative topics and queues."""
        if not self.is_connected:
            if not self.connect():
                return {}
        
        print("Testing authorization against common administrative resources...")
        
        auth_results = {
            "tested_at": datetime.now().isoformat(),
            "admin_topics": {},
            "admin_queues": {},
            "system_topics": {},
            "unauthorized_access": []
        }
        
        # Common administrative topics that should be restricted
        admin_topics = [
            "#LOG/*",
            "#SYSTEM/*", 
            "#CONFIG-SYNC/*",
            "#P2P/QUE/*",
            "$SYS/*",
            "#CLIENT/*",
            "#STATS/*"
        ]
        
        # Common administrative queues
        admin_queues = [
            "#SYSTEM_ADMIN_QUEUE",
            "#CONFIG_SYNC_QUEUE",
            "#LOG_QUEUE",
            "ADMIN_CONFIG_QUEUE"
        ]
        
        # Test topic subscriptions
        for topic in admin_topics:
            try:
                receiver = self.messaging_service.create_direct_message_receiver_builder() \
                    .with_subscriptions([TopicSubscription.of(topic)]) \
                    .build()
                receiver.start()
                auth_results["admin_topics"][topic] = "ACCESS_GRANTED"
                auth_results["unauthorized_access"].append(f"Unauthorized access to admin topic: {topic}")
                receiver.terminate()
                print(f"WARNING: Gained access to admin topic: {topic}")
            except Exception as e:
                auth_results["admin_topics"][topic] = f"ACCESS_DENIED: {str(e)}"
                print(f"OK: Properly denied access to admin topic: {topic}")
        
        # Test queue access
        for queue_name in admin_queues:
            try:
                queue = Queue.durable_exclusive_queue(queue_name)
                receiver = self.messaging_service.create_persistent_message_receiver_builder() \
                    .build(queue)
                receiver.start()
                auth_results["admin_queues"][queue_name] = "ACCESS_GRANTED"
                auth_results["unauthorized_access"].append(f"Unauthorized access to admin queue: {queue_name}")
                receiver.terminate()
                print(f"WARNING: Gained access to admin queue: {queue_name}")
            except Exception as e:
                auth_results["admin_queues"][queue_name] = f"ACCESS_DENIED: {str(e)}"
                print(f"OK: Properly denied access to admin queue: {queue_name}")
        
        # Test cross-VPN access (if applicable)
        test_vpns = ["default", "mgmt", "admin", "system"]
        for test_vpn in test_vpns:
            if test_vpn != self.vpn:
                try:
                    # Create a new service for cross-VPN testing
                    protocol = "tcps" if self.use_tls else "tcp"
                    test_service_props = {
                        "solace.messaging.transport.host": f"{protocol}://{self.host}:{self.port}",
                        "solace.messaging.service.vpn-name": test_vpn,
                        "solace.messaging.service.receiver.direct.subscription-reapply": True
                    }
                    
                    test_builder = MessagingService.builder().from_properties(test_service_props)
                    
                    if self.oauth_token:
                        auth_strategy = OAuth2.of(self.oauth_token)
                    elif self.cert_file:
                        # Handle different certificate file types for cross-VPN testing
                        if self.cert_file.lower().endswith(('.p12', '.pfx')):
                            # PKCS12 files not supported
                            continue  # Skip this VPN test
                        else:
                            # PEM files - check if they contain private key or need separate key file
                            if self._pem_contains_private_key(self.cert_file):
                                # Combined PEM files not supported
                                continue  # Skip this VPN test
                            else:
                                # PEM file only contains certificate, need separate key file
                                if not hasattr(self, 'key_file') or not self.key_file:
                                    continue  # Skip this VPN test if key file not available
                                
                                auth_strategy = ClientCertificateAuthentication.of(
                                    self.cert_file, self.key_file, self.cert_password or None
                                )
                    else:
                        auth_strategy = BasicUserNamePassword.of(
                            self.username, self.password
                        )
                    
                    test_builder = test_builder.with_authentication_strategy(auth_strategy)
                    
                    if self.use_tls:
                        tls_strategy = TLS.create().without_certificate_validation()
                        test_builder = test_builder.with_transport_security_strategy(tls_strategy)
                    
                    test_service = test_builder.build()
                    test_service.connect()
                    
                    auth_results["unauthorized_access"].append(f"Cross-VPN access gained to VPN: {test_vpn}")
                    print(f"WARNING: Cross-VPN access to {test_vpn} from {self.vpn}")
                    test_service.disconnect()
                    
                except Exception as e:
                    print(f"OK: Properly denied cross-VPN access to: {test_vpn}")
        
        if auth_results["unauthorized_access"]:
            print(f"\nSECURITY ISSUES FOUND: {len(auth_results['unauthorized_access'])} unauthorized access attempts succeeded")
        else:
            print("\nAuthorization checks passed - no unauthorized access detected")
        
        return auth_results
    
    def monitor_queues(self, queue_names: List[str], output_dir: Optional[str] = None):
        """Monitor messages from specified queues (WARNING: DESTRUCTIVE - messages will be consumed/removed)."""
        if not self.is_connected:
            if not self.connect():
                return
        
        print(f"WARNING: Starting DESTRUCTIVE monitoring of queues (messages will be consumed): {queue_names}")
        print("NOTE: Solace Python API does not support non-destructive queue browsing")
        
        # Safety confirmation for production environments
        try:
            confirmation = input("Continue with DESTRUCTIVE queue monitoring? (yes/no): ").lower().strip()
            if confirmation not in ['yes', 'y']:
                print("Queue monitoring cancelled by user")
                return
        except KeyboardInterrupt:
            print("\nQueue monitoring cancelled by user")
            return
        
        if output_dir:
            Path(output_dir).mkdir(parents=True, exist_ok=True)
            print(f"Messages will be logged to: {output_dir}")
        
        receivers = []
        
        try:
            for queue_name in queue_names:
                queue = Queue.durable_exclusive_queue(queue_name)
                
                # Create persistent message receiver
                receiver = self.messaging_service.create_persistent_message_receiver_builder() \
                    .with_message_selector("") \
                    .build(queue)
                
                receiver.start()
                receivers.append((receiver, queue_name))
                print(f"Started monitoring queue: {queue_name}")
            
            # Monitor messages
            while not self.stop_event.is_set():
                for receiver, queue_name in receivers:
                    try:
                        message = receiver.receive_message(timeout_ms=1000)
                        if message:
                            timestamp = int(time.time() * 1000)  # Epoch milliseconds
                            print(f"[{datetime.now()}] Queue '{queue_name}': {message.get_payload_as_string()}")
                            
                            if output_dir:
                                filename = f"queue_{queue_name}_{timestamp}.json"
                                filepath = Path(output_dir) / filename
                                
                                message_data = {
                                    "source_type": "queue",
                                    "source_name": queue_name,
                                    "timestamp": timestamp,
                                    "datetime": datetime.now().isoformat(),
                                    "payload": message.get_payload_as_string(),
                                    "properties": {}
                                }
                                
                                # Add message properties if available
                                try:
                                    if hasattr(message, 'get_properties'):
                                        message_data["properties"] = message.get_properties()
                                except:
                                    pass
                                
                                with open(filepath, 'w') as f:
                                    json.dump(message_data, f, indent=2)
                    
                    except Exception as e:
                        if "timeout" not in str(e).lower():
                            print(f"Error receiving from queue {queue_name}: {e}")
                
                time.sleep(0.1)  # Small delay to prevent busy waiting
                
        except Exception as e:
            print(f"Error in queue monitoring: {e}")
        finally:
            # Clean up receivers
            for receiver, _ in receivers:
                try:
                    receiver.terminate()
                except:
                    pass
    
    def monitor_topics(self, topic_patterns: List[str], output_dir: Optional[str] = None, wildcard: Optional[str] = None):
        """Monitor messages from specified topics."""
        if not self.is_connected:
            if not self.connect():
                return
        
        # Add wildcard subscription if specified
        if wildcard:
            topic_patterns.append(f"{wildcard}*")
        
        print(f"Starting monitoring of topics: {topic_patterns}")
        if output_dir:
            Path(output_dir).mkdir(parents=True, exist_ok=True)
            print(f"Messages will be logged to: {output_dir}")
        
        try:
            # Create direct message receiver
            receiver = self.messaging_service.create_direct_message_receiver_builder() \
                .with_subscriptions([TopicSubscription.of(pattern) for pattern in topic_patterns]) \
                .build()
            
            receiver.start()
            
            while not self.stop_event.is_set():
                try:
                    message = receiver.receive_message(timeout_ms=1000)
                    if message:
                        topic_name = message.get_destination_name() if hasattr(message, 'get_destination_name') else "unknown"
                        timestamp = int(time.time() * 1000)  # Epoch milliseconds
                        print(f"[{datetime.now()}] Topic '{topic_name}': {message.get_payload_as_string()}")
                        
                        if output_dir:
                            # Clean topic name for filename
                            clean_topic = topic_name.replace('/', '_').replace('*', 'wildcard')
                            filename = f"topic_{clean_topic}_{timestamp}.json"
                            filepath = Path(output_dir) / filename
                            
                            message_data = {
                                "source_type": "topic",
                                "source_name": topic_name,
                                "timestamp": timestamp,
                                "datetime": datetime.now().isoformat(),
                                "payload": message.get_payload_as_string(),
                                "properties": {}
                            }
                            
                            # Add message properties if available
                            try:
                                if hasattr(message, 'get_properties'):
                                    message_data["properties"] = message.get_properties()
                            except:
                                pass
                            
                            with open(filepath, 'w') as f:
                                json.dump(message_data, f, indent=2)
                
                except Exception as e:
                    if "timeout" not in str(e).lower():
                        print(f"Error receiving from topics: {e}")
                
                time.sleep(0.1)  # Small delay to prevent busy waiting
            
        except Exception as e:
            print(f"Error in topic monitoring: {e}")
        finally:
            try:
                receiver.terminate()
            except:
                pass
    
    def send_from_files(self, file_dir: str):
        """Send messages from logged files back to their original destinations."""
        if not self.is_connected:
            if not self.connect():
                return
        
        files_dir = Path(file_dir)
        if not files_dir.exists():
            print(f"Directory {file_dir} does not exist")
            return
        
        message_files = list(files_dir.glob("*.json"))
        if not message_files:
            print(f"No JSON message files found in {file_dir}")
            return
        
        print(f"Found {len(message_files)} message files to replay")
        
        # Create publishers
        direct_publisher = self.messaging_service.create_direct_message_publisher_builder().build()
        persistent_publisher = self.messaging_service.create_persistent_message_publisher_builder().build()
        
        direct_publisher.start()
        persistent_publisher.start()
        
        try:
            for file_path in message_files:
                try:
                    with open(file_path, 'r') as f:
                        message_data = json.load(f)
                    
                    source_type = message_data.get("source_type")
                    source_name = message_data.get("source_name")
                    payload = message_data.get("payload", "")
                    
                    if source_type == "topic":
                        # Send to topic using direct publisher
                        topic = TopicSubscription.of(source_name)
                        message = self.messaging_service.message_builder().with_payload(payload).build()
                        direct_publisher.publish(message, topic)
                        print(f"Sent message to topic: {source_name}")
                        
                    elif source_type == "queue":
                        # Send to queue using persistent publisher
                        queue = Queue.durable_exclusive_queue(source_name)
                        message = self.messaging_service.message_builder().with_payload(payload).build()
                        persistent_publisher.publish(message, queue)
                        print(f"Sent message to queue: {source_name}")
                    
                    time.sleep(0.1)  # Small delay between messages
                    
                except Exception as e:
                    print(f"Error processing file {file_path}: {e}")
        
        except Exception as e:
            print(f"Error in message replay: {e}")
        finally:
            try:
                direct_publisher.terminate()
                persistent_publisher.terminate()
            except:
                pass


def main():
    """Main entry point for the Solace penetration testing tool."""
    parser = argparse.ArgumentParser(
        description="Solace PubSub+ Penetration Testing Tool",
        epilog="Author: Garland Glessner <gglessner@gmail.com> | License: GNU GPL v3.0"
    )
    
    # Connection arguments
    parser.add_argument("--server", required=True, help="Solace server in host:port format")
    parser.add_argument("--username", help="Username for basic authentication")
    parser.add_argument("--password", help="Password for basic authentication (if not provided, will prompt)")
    parser.add_argument("--vpn", required=True, help="VPN name on the Solace broker")
    parser.add_argument("--no-tls", action="store_true", help="Disable TLS (use unencrypted connection)")
    
    # Authentication arguments
    parser.add_argument("--oauth-token", help="OAuth token for authentication")
    parser.add_argument("--cert-file", help="Client certificate file path (PEM/PKCS12 format)")
    parser.add_argument("--key-file", help="Private key file path (required for PEM certificates)")
    
    # Operation arguments
    parser.add_argument("--validate", action="store_true", help="Validate broker connection and exit")
    parser.add_argument("--info", action="store_true", help="Gather broker information")
    parser.add_argument("--check-auth", action="store_true", help="Test authorization against administrative resources")
    parser.add_argument("--monitor-queues", nargs="+", help="Monitor specified queues (WARNING: DESTRUCTIVE - consumes messages)")
    parser.add_argument("--monitor-topics", nargs="+", help="Monitor specified topics")
    parser.add_argument("--subscribe-wildcard", help="Subscribe to topics starting with specified string")
    parser.add_argument("--send-from-files", help="Send messages from logged files in specified directory")
    
    # Output arguments
    parser.add_argument("-dir", "--output-dir", help="Directory to save message logs")
    
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
    
    # Create penetration testing instance
    pentest = SolacePenTest(
        host=host,
        port=port,
        username=args.username or "",
        password=password or "",
        vpn=args.vpn,
        use_tls=not args.no_tls,
        oauth_token=args.oauth_token,
        cert_file=args.cert_file,
        cert_password=cert_password,
        key_file=args.key_file,
        check_auth=args.check_auth
    )
    
    try:
        # Handle operations
        if args.validate:
            success = pentest.validate_connection()
            sys.exit(0 if success else 1)
        
        if args.info:
            info = pentest.get_broker_info()
            print(json.dumps(info, indent=2))
        
        if args.check_auth:
            auth_results = pentest.check_authorization()
            print(json.dumps(auth_results, indent=2))
        
        if args.send_from_files:
            pentest.send_from_files(args.send_from_files)
        
        if args.monitor_queues:
            pentest.monitor_queues(args.monitor_queues, args.output_dir)
        
        if args.monitor_topics or args.subscribe_wildcard:
            topics = args.monitor_topics or []
            pentest.monitor_topics(topics, args.output_dir, args.subscribe_wildcard)
        
        # If no specific operation was requested, show help
        if not any([args.validate, args.info, args.check_auth, args.monitor_queues, args.monitor_topics, 
                   args.subscribe_wildcard, args.send_from_files]):
            parser.print_help()
    
    except KeyboardInterrupt:
        print("\nOperation interrupted by user")
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)
    finally:
        pentest.disconnect()


if __name__ == "__main__":
    main()
