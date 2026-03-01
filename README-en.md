# GYscan - Comprehensive Penetration Testing Tool in Go

## Project Overview

GYscan is a comprehensive penetration testing tool developed in Go, focusing on asset detection, vulnerability scanning, and security validation. Developed by BiliBili blogger "弈秋啊" (Yi Qiu), this tool provides rich security testing capabilities suitable for authorized security assessments and penetration testing scenarios.

## Key Features

### Core Functional Modules

1. **Network Scanning**
   - Port scanning and service identification
   - Subdomain enumeration
   - FTP service scanning and brute-force
   - SSH service scanning and brute-force

2. **Web Security**
   - Directory scanning
   - XSS vulnerability detection
   - CSRF vulnerability detection
   - Web fingerprint identification
   - WAF detection

3. **Database Security**
   - Database weak password brute-force
   - Supports mainstream databases like MySQL, PostgreSQL, MongoDB, etc.

4. **System Security**
   - Configuration auditing
   - Weak password detection
   - Risk assessment

5. **Other Tools**
   - Encryption and decryption tools
   - Password dictionary generation
   - Network packet analysis

## Installation and Usage

### Environment Requirements

- Go 1.24+ development environment
- Supports Windows/Linux/macOS operating systems

### Installation Steps

```bash
# Clone the project
git clone <repository-url>

# Enter project directory
cd GYscan/Client

# Build the project
go build -o GYscan.exe
```

### Quick Start

```bash
# View help information
./GYscan help

# Perform port scanning
./GYscan nmap -t target.com

# Perform directory scanning
./GYscan dirscan -u http://target.com
```

## Command List

| Command | Description |
|---------|-------------|
| `about` | Show tool information |
| `ca` | Certificate-related operations |
| `crunch` | Generate password dictionaries |
| `cupp` | Generate personalized passwords |
| `database` | Database security testing |
| `dirscan` | Directory scanning |
| `ftp` | FTP service testing |
| `fu` | Fuzz testing |
| `linenum` | System information collection |
| `linux-kernel` | Linux kernel vulnerability detection |
| `mg` | Mail service testing |
| `pc` | Port scanning |
| `process` | Process information collection |
| `registry` | Windows registry operations |
| `route` | Route information collection |
| `ssh` | SSH service testing |
| `userinfo` | User information collection |
| `waf` | WAF detection |
| `webshell` | WebShell detection |
| `whois` | Whois query |
| `ws` | WebSocket testing |
| `wwifi` | WiFi security testing |

## Important Notes

1. **Legal Use**: This tool is only for authorized security testing. Unauthorized use is strictly prohibited.
2. **License Key**: The tool uses a one-machine-one-key system. A valid license key is required for usage.
3. **Version Updates**: License keys are version-specific. Please use the corresponding key for your tool version.

## License Key Acquisition

1. Join QQ channel: pd50818078
2. Pass the channel owner's (author's) review to obtain the license key
3. License keys use the strongest encryption algorithm of 2026, making cracking extremely difficult

## Author Information

- Author: BiliBili-弈秋啊 (Yi Qiu)
- Version: v2.9.0
- Warning: Only for authorized testing. Unauthorized use is strictly prohibited!

## Disclaimer

This tool is only for legal security testing and educational purposes. Users must comply with local laws and regulations and must not use it for illegal activities. The author is not responsible for any losses caused by the use of this tool.