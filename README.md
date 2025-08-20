# SolaceClient.py

A comprehensive penetration testing tool for Solace PubSub+ brokers that provides capabilities for connection validation, information gathering, message monitoring, and message replay for security testing purposes.

## Author

**Garland Glessner** <gglessner@gmail.com>

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

## Features

### SolaceClient.py - Data Plane Testing
- **Multiple Authentication Methods**: Basic auth, OAuth tokens, and client certificates
- **Connection Validation**: Test broker connectivity with specified credentials
- **TLS Support**: Secure connections with optional certificate validation bypass
- **Authorization Testing**: Test access to administrative topics and queues
- **Cross-VPN Testing**: Validate VPN isolation and access controls
- **Information Gathering**: Collect broker connection details
- **Queue Monitoring**: Monitor queue messages (WARNING: Destructive - consumes messages)
- **Topic Subscription**: Subscribe to specific topics or wildcard patterns
- **Message Logging**: Save intercepted messages to timestamped files
- **Message Replay**: Send captured messages back to their original destinations
- **Graceful Shutdown**: Handle Ctrl+C interrupts cleanly

### SolaceSEMP.py - Management Plane Testing
- **SEMP API Testing**: Comprehensive SEMP v2 REST API security assessment
- **Configuration Enumeration**: Discover brokers, VPNs, users, and ACL profiles
- **Administrative Access Testing**: Test access to management functions
- **Authentication Support**: Basic auth, OAuth, and client certificate authentication
- **Security Reporting**: Generate detailed JSON security assessment reports
- **Production Safe**: Non-destructive testing suitable for production environments

### SolaceVPNscan.py - VPN Enumeration
- **VPN Discovery**: Enumerate valid VPN names on Solace brokers
- **Error Analysis**: Determines VPN existence based on authentication error responses
- **Batch Processing**: Test multiple VPNs from a text file
- **CSV Reporting**: Export results to CSV format for analysis
- **Production Safe**: Uses anonymous authentication attempts, no valid credentials required

## Installation

### Prerequisites

- Python 3.7 or higher
- pip package manager
- Access to a Solace PubSub+ broker for testing

### Installation Steps

#### 1. Clone or Download the Tool

```bash
# If using git
git clone <repository-url>
cd SolaceClient

# Or download and extract the files to a directory
```

#### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

#### 3. Verify Installation

Test the tool by viewing the help:

```bash
python SolaceClient.py --help
```

#### 4. Test Connection (Optional)

If you have access to a Solace broker, test the connection:

```bash
python SolaceClient.py --server your-broker:55443 --username your-user --vpn your-vpn --validate
```

### Platform-Specific Notes

#### Windows
- Use PowerShell or Command Prompt
- Python should be available as `python` or `python3`
- Ensure Python is in your PATH

#### Linux/macOS
- You may need to use `python3` instead of `python`
- Consider using a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
# or
venv\Scripts\activate     # Windows
pip install -r requirements.txt
```

### Troubleshooting

#### Import Errors
If you get import errors for the solace module:
```bash
pip install --upgrade solace-pubsubplus
```

#### Connection Issues
- Verify the broker address and port
- Check if TLS is required (default) or use `--no-tls` for unencrypted connections
- Confirm your username and VPN name are correct
- Ensure your account has the necessary permissions

#### Permission Errors
- Make sure you have permission to access the specified queues and topics
- Some operations may require administrative privileges on the broker

## Usage

### Basic Connection Validation

```bash
# Basic authentication
python SolaceClient.py --server hostname:55443 --username testuser --vpn default --validate

# OAuth authentication
python SolaceClient.py --server hostname:55443 --oauth-token "your-oauth-token" --vpn default --validate

# Client certificate authentication
python SolaceClient.py --server hostname:55443 --cert-file /path/to/client.pem --vpn default --validate
```

### Monitor Topics with Message Logging

```bash
python SolaceClient.py --server hostname:55443 --username testuser --vpn default \
    --monitor-topics topic1 topic2 -dir ./captured_messages
```

### Subscribe to Wildcard Topics

```bash
python SolaceClient.py --server hostname:55443 --username testuser --vpn default \
    --subscribe-wildcard "telemetry/" -dir ./telemetry_logs
```

### Monitor Queues (Destructive - Consumes Messages)

**⚠️ WARNING: This operation consumes/removes messages from queues!**

```bash
python SolaceClient.py --server hostname:55443 --username testuser --vpn default \
    --monitor-queues queue1 queue2 -dir ./queue_messages
```

**Note**: The Solace Python API does not support non-destructive queue browsing. Messages will be permanently removed from the queue.

### Replay Captured Messages

```bash
python SolaceClient.py --server hostname:55443 --username testuser --vpn default \
    --send-from-files ./captured_messages
```

### Disable TLS for Testing

```bash
python SolaceClient.py --server hostname:55555 --username testuser --vpn default \
    --no-tls --validate
```

### Authorization Testing

```bash
# Test access to administrative resources
python SolaceClient.py --server hostname:55443 --username testuser --vpn default --check-auth
```

### SEMP API Testing

```bash
# Test SEMP API connection
python SolaceSEMP.py --server hostname:8080 --username admin --test-connection

# Comprehensive enumeration
python SolaceSEMP.py --server hostname:8080 --username admin --enumerate-all --output security_report.json

# Test administrative access
python SolaceSEMP.py --server hostname:8080 --username admin --test-admin-access
```

### VPN Enumeration

```bash
# Basic VPN enumeration
python SolaceVPNscan.py --server hostname:55443 --vpn-list vpn_names.txt

# VPN enumeration with CSV output
python SolaceVPNscan.py --server hostname:55443 --vpn-list vpn_names.txt --csv vpn_results.csv

# VPN enumeration without TLS
python SolaceVPNscan.py --server hostname:55555 --no-tls --vpn-list vpn_names.txt --csv results.csv
```

## Command Line Options

### SolaceClient.py - Data Plane Testing

#### Connection Parameters
- `--server HOST:PORT` - Solace broker address (required)
- `--username USERNAME` - Username for basic authentication
- `--vpn VPN_NAME` - VPN name on the broker (required)
- `--no-tls` - Disable TLS encryption (optional)

#### Authentication Options
- `--oauth-token TOKEN` - OAuth token for authentication
- `--cert-file PATH` - Client certificate file (PEM/PKCS12 format)

#### Operations
- `--validate` - Test connection and exit
- `--info` - Gather and display broker information
- `--check-auth` - Test authorization against administrative resources
- `--monitor-queues QUEUE [QUEUE ...]` - Monitor specified queues (WARNING: Destructive - consumes messages)
- `--monitor-topics TOPIC [TOPIC ...]` - Monitor specified topics
- `--subscribe-wildcard PREFIX` - Subscribe to topics starting with prefix
- `--send-from-files DIRECTORY` - Replay messages from logged files

#### Output Options
- `-dir, --output-dir DIRECTORY` - Save captured messages to directory

### SolaceSEMP.py - Management Plane Testing

#### Connection Parameters
- `--server HOST:PORT` - SEMP API server address (required)
- `--username USERNAME` - Username for basic authentication
- `--no-tls` - Use HTTP instead of HTTPS

#### Authentication Options
- `--oauth-token TOKEN` - OAuth token for authentication
- `--cert-file PATH` - Client certificate file (PEM/PKCS12 format)

#### Operations
- `--test-connection` - Test SEMP API connection and exit
- `--enumerate-all` - Perform comprehensive enumeration
- `--enumerate-brokers` - Enumerate broker information
- `--enumerate-vpns` - Enumerate Message VPNs
- `--enumerate-users VPN|all` - Enumerate users for VPN or all VPNs
- `--enumerate-acls VPN` - Enumerate ACL profiles for specified VPN
- `--test-admin-access` - Test administrative access

#### Output Options
- `--output, -o FILE` - Output file for security report (JSON format)

### SolaceVPNscan.py - VPN Enumeration

#### Connection Parameters
- `--server HOST:PORT` - Solace server address (required)
- `--no-tls` - Use unencrypted connection

#### Input/Output Options
- `--vpn-list FILE` - Text file containing VPN names, one per line (required)
- `--case-variations` - Generate lowercase, uppercase, and title case variations of each VPN name
- `--csv FILE` - Save results to CSV file

#### Important Notes
- **VPN names are case-sensitive** in Solace (e.g., "default" ≠ "Default" ≠ "DEFAULT")
- Use `--case-variations` to automatically test common case variations
- Consider testing both common naming patterns and case variations for thorough enumeration

## Security Considerations

This tool is designed for authorized penetration testing and security assessments. Users must:

- Have explicit permission to test the target Solace broker
- Comply with all applicable laws and regulations
- Use responsibly in production environments
- Understand that message monitoring may capture sensitive data

## Message File Format

Captured messages are saved as JSON files with the following structure:

```json
{
  "source_type": "topic|queue",
  "source_name": "topic_or_queue_name",
  "timestamp": 1634567890123,
  "datetime": "2021-10-18T10:31:30.123456",
  "payload": "message content",
  "properties": {}
}
```

## Limitations

- **Queue monitoring is DESTRUCTIVE** - messages are consumed/removed from queues (Solace Python API limitation)
- Queue monitoring requires appropriate permissions on the target broker
- Some broker information gathering features require administrative access
- Wildcard subscriptions follow Solace topic syntax rules
- Message replay preserves original content but may not preserve all message properties
- For non-destructive queue browsing, use alternative tools like Solace's PrettyDump or Java-based solutions

## Getting Help

- Review examples.sh for common scenarios and command examples
- Ensure you have proper authorization before testing any broker
- Check the troubleshooting section above for common issues

## Contributing

This project is open source under the GNU GPL v3.0 license. Contributions are welcome via pull requests.

## Disclaimer

This tool is provided for educational and authorized testing purposes only. The authors are not responsible for any misuse or damage caused by this software. Always ensure you have proper authorization before testing any systems.
