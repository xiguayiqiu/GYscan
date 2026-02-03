[中文文档](README.md)

# GYscan - Internal Network Lateral Boundary Security Testing Tool

**For this project, when sharing, whether it's an article, tool introduction, or video introduction, please make sure to keep the original author's repository name! Thank you for your cooperation!**

**To those who replace or alter the original author's work, you might receive a legal summons one day~~**

## Project Overview

GYscan is a professional tool focused on internal network lateral movement and boundary security testing, developed using Go language. This tool integrates rich internal network penetration testing capabilities, including port scanning, service identification, vulnerability detection, remote command execution, and weak password brute-forcing, providing security researchers and penetration testers with efficient and reliable internal network security assessment solutions.

## GYscan Official Website 
Please make sure to visit the official website of this project. This software has only this one website; all the others are fake! Please pay attention!

[GYscan - 内网安全测试工具](https://www.gyscan.dpdns.org/)（https://www.gyscan.dpdns.org/）

## Core Advantages

- **Focused on Internal Network Security**: Specifically optimized for internal network lateral movement and boundary security testing scenarios
- **Feature-Rich**: Integrates port scanning, service identification, remote command execution, weak password brute-forcing, configuration auditing, and more
- **Cross-Platform Support**: Supports Windows, Linux, and macOS three major operating systems
- **Modular Design**: Plugin-based architecture, supporting functional extensions and custom module development
- **Configuration Auditing**: Based on CIS Benchmark security baseline, supporting 58 checks across five major categories
- **Evidence Tracking**: Audit checks display specific configuration files, configuration items, current values, and remediation suggestions
- **High Performance**: Developed with Go language, featuring excellent concurrent processing capabilities

### Basic Information

| Item | Information |
|------|-------------|
| **Project Name** | GYscan |
| **Development Language** | Go 1.24+ |
| **Supported Platforms** | Windows 7+/Linux/macOS |
| **License** | Apache 2.0 |
| **Latest Version** | v2.7.2 |

### Legal Disclaimer

**Important Notice**: This tool is intended for authorized security testing purposes only. Any unauthorized use is illegal, and users bear corresponding legal responsibilities.

## Quick Start

### Environment Setup

1. **Install Go Environment** (Version 1.18+)
   ```bash
   # Download and install Go
   https://golang.org/dl/
   
   # Verify installation
   go version
   ```

2. **Obtain Project Code**
   ```bash
   # Github
   git clone https://github.com/xiguayiqiu/GYscan.git
   # Gitee
   git clone https://gitee.com/bzhanyiqiua/GYscan.git
   cd GYscan
   ```

### Build and Install

```bash
# Build client
cd Client
go build -o GYscan.exe
```

### One-Click Build Script

```bash
# Windows platform
.\build.ps1

# Linux platform
chmod +x build_linux.sh
./build_linux.sh
```

### Linux Platform Dependency Installation

GYscan requires system dependency packages for Linux platform builds. Installation commands for different distributions are as follows:

#### Debian/Ubuntu/Kali Linux/Parrot Security
```bash
# Update package manager
sudo apt update

# Install dependency packages
sudo apt install -y \
    libx11-dev \
    libxcursor-dev \
    libxrandr-dev \
    libxinerama-dev \
    libxi-dev \
    libxxf86vm-dev \
    libgl1-mesa-dev \
    libglu1-mesa-dev \
    mesa-common-dev \
    build-essential \
    pkg-config \
    dbus-x11 \
    libdbus-1-dev \
    libpcap-dev \
    man-db
```

#### RedHat/CentOS/Fedora/Rocky Linux
```bash
# Install dependency packages
sudo yum install -y \
    libX11-devel \
    libXcursor-devel \
    libXrandr-devel \
    libXinerama-devel \
    libXi-devel \
    libXxf86vm-devel \
    mesa-libGL-devel \
    mesa-libGLU-devel \
    mesa-libGLw-devel \
    gcc-c++ \
    pkgconfig \
    dbus-x11 \
    dbus-devel \
    libpcap-devel \
    man-db
```

#### Arch Linux/Manjaro
```bash
# Install dependency packages
sudo pacman -S --noconfirm \
    libx11 \
    libxcursor \
    libxrandr \
    libxinerama \
    libxi \
    libxxf86vm \
    mesa \
    glu \
    base-devel \
    pkg-config \
    dbus \
    dbus-glib \
    libpcap \
    man-db
```

#### OpenSUSE
```bash
# Install dependency packages
sudo zypper install -y \
    libX11-devel \
    libXcursor-devel \
    libXrandr-devel \
    libXinerama-devel \
    libXi-devel \
    libXxf86vm-devel \
    Mesa-libGL-devel \
    Mesa-libGLU-devel \
    Mesa-dri-devel \
    gcc-c++ \
    pkgconfig \
    dbus-1-x11 \
    dbus-1-devel \
    libpcap-devel \
    man-db
```

> **Note**: The build script `build_linux.sh` automatically detects the system distribution and prompts for missing dependencies.

## Feature List

### Stable Commands

| Command | Description | Status |
|---------|-------------|--------|
| about | View tool information | ✅ Stable |
| ca | Configuration audit tool, system configuration security check based on CIS baseline | ✅ Stable |
| crunch | Password dictionary generation tool | ✅ Stable |
| database | Database password brute-forcing tool | ✅ Stable |
| dirscan | Website directory scanning tool | ✅ Stable |
| ftp | FTP password brute-forcing | ✅ Stable |
| passhash | Credential pass-the-hash attack module | ✅ Stable |
| powershell | PowerShell remote execution tool [WinRM service exploitation] | ✅ Stable |
| process | Process and service information collection tool | ✅ Stable |
| rdp | RDP remote desktop tool | ✅ Stable |
| route | Route hop detection | ✅ Stable |
| scan | Network scanning tool, supporting host discovery, port scanning, service identification, IPv6 scanning | ✅ Stable |
| scapy | Advanced network packet manipulation tool, supporting raw packet construction, interface detection and demonstrations | ✅ Stable |
| ssh | SSH password brute-forcing tool (Hydra-style) | ✅ Stable |
| userinfo | Local user and group analysis | ✅ Stable |
| webshell | WebShell generation tool | ✅ Stable |
| wmi | WMI remote management tool | ✅ Stable |
| waf | WAF detection tool, supporting mainstream WAF identification and detection | ✅ Stable |
| xss | XSS vulnerability detection tool, supporting reflected, stored, DOM XSS detection | ✅ Stable |
| winlog | Windows log viewing tool, supporting local and remote log queries | ✅ Stable |
| clean | Advanced hacker trace detection and cleanup tool | ✅ Stable |
| fu | File upload vulnerability check tool | ✅ Stable |
| wwifi | Windows system WiFi cracking functionality | ✅ Stable |
| ws | WebSocket testing tool, supporting connection testing, message sending, response assertions, auto-reconnect, and heartbeat detection | ✅ Stable |

### Beta Commands

| Command | Description | Status |
|---------|-------------|--------|
| adcs | AD CS vulnerability detection tool, detects ESC1-ESC8 vulnerabilities [Beta] | ⚠️ Beta |
| csrf | CSRF vulnerability detection [Beta] | ⚠️ Beta |
| dcom | DCOM remote execution module [Beta] | ⚠️ Beta |
| ldap | LDAP enumeration module [Beta] | ⚠️ Beta |
| mg | Honeypot identification tool - detects if target is a honeypot system [Beta] | ⚠️ Beta |

## Configuration Audit Feature

GYscan v2.7 introduces the Configuration Audit module, performing configuration compliance checks on target systems based on CIS Benchmark security baseline.

### Audit Categories

GYscan configuration auditing supports five categories with 58 checks:

| Category | Check Count | Main Content |
|----------|-------------|--------------|
| Windows Configuration Audit | 10 checks | Account policy, service configuration, registry security, audit policy, LSA security, UAC configuration, firewall rules, SMB security |
| Linux Configuration Audit | 10 checks | Account management, password policy, service management, kernel parameters, file permissions, SSH configuration, audit configuration, firewall |
| Web Configuration Audit | 13 checks | HTTP security headers, CORS configuration, SSL/TLS configuration, session security, XSS protection, CSRF protection, information leakage protection |
| SSH Configuration Audit | 15 checks | SSH protocol version, authentication method, root login permission, encryption algorithms, MAC algorithms, key exchange algorithms, login banner |
| Middleware Configuration Audit | 10 checks | Database account permissions, network access control, encryption configuration, audit logs, password policies, application server management interface |

### Configuration Evidence Feature

GYscan configuration auditing provides detailed configuration evidence tracking. When configuration problems are detected, the report clearly shows:

- **Configuration File Path**: Points to the specific configuration file with issues
- **Configuration Item Name**: Indicates the specific security setting item
- **Current Value**: Displays the current insecure configuration value
- **Expected Value**: Explains the compliant value that should be set
- **Risk Description**: Explains the security impact of the configuration issue
- **Remediation Suggestions**: Provides specific remediation steps

### Usage Examples

```bash
# Execute all categories of local configuration audit
./GYscan.exe ca run --target localhost

# Audit local Linux system configuration
./GYscan.exe ca run --target localhost --os-type linux

# Audit local Windows system configuration
./GYscan.exe ca run --target localhost --os-type windows

# Specify audit category for local audit
./GYscan.exe ca run --category linux

# Audit local Web service configuration
./GYscan.exe ca run --category web

# Audit local SSH configuration
./GYscan.exe ca run --category ssh

# Audit local middleware configuration
./GYscan.exe ca run --category middleware

# Generate JSON format local audit report
./GYscan.exe ca run --target localhost -o audit.json --format json

# Generate HTML format local audit report
./GYscan.exe ca run --target localhost -o audit.html --format html

# List all available check items
./GYscan.exe ca list

# List check items under specified category
./GYscan.exe ca list --category linux

# Generate security baseline report for target system
./GYscan.exe ca baseline --target localhost -o baseline.json

# Generate configuration remediation suggestion plan
./GYscan.exe ca remediate --target localhost
```

#### Local Audit Description

GYscan configuration audit module focuses on local system configuration audit, directly reading target system configuration files and parameters for detection:

- **No Remote Connection Required**: Does not rely on SSH, WMI, or other remote protocols, directly analyzes local file system
- **Secure and Reliable**: Avoids authentication and permission issues from remote connections
- **Comprehensive Coverage**: Supports five major categories: Windows, Linux, Web, SSH, Middleware

### Output Formats

GYscan configuration auditing supports three output formats:

| Format | Description | Use Case |
|--------|-------------|----------|
| text | Text format, default output | Terminal direct viewing |
| json | JSON format, suitable for program processing | Automation integration, data analysis |
| html | HTML format, interactive report | Detailed audit reports, demonstrations |

## Common Usage Examples

### Network Scanning

```bash
# Scan single IP address
./GYscan.exe scan --target 192.168.1.100

# Scan IP range
./GYscan.exe scan --target 192.168.1.0/24

# Scan specified port range
./GYscan.exe scan --target 192.168.1.100 --ports 80,443,22,21
```

### PowerShell Remote Execution

```bash
# Execute remote PowerShell command
./GYscan.exe powershell exec --target 192.168.1.100 --user Administrator --password "Password123" --command "whoami"

# Test WinRM port
./GYscan.exe powershell test --target 192.168.1.100 --port 5985
```

### WMI Remote Management

```bash
# Get operating system information
./GYscan.exe wmi osinfo --target 192.168.1.100 --user Administrator --password "Password123"

# Execute remote command
./GYscan.exe wmi exec --target 192.168.1.100 --user Administrator --password "Password123" --command "whoami"
```

### DCOM Remote Execution

GYscan's DCOM remote execution module executes remote commands on target Windows hosts through the DCOM protocol, supporting multiple execution methods.

#### Command Description

| Subcommand | Description |
|------------|-------------|
| execute | Execute remote commands via DCOM |
| connect | Test DCOM connection reachability |
| list | Enumerate DCOM objects on remote host |

#### Common Parameters

| Parameter | Short | Description |
|-----------|-------|-------------|
| --target | -t | Target host IP address or hostname (required) |
| --username | -u | Username (required) |
| --password | -p | Password (required) |
| --domain | -d | Domain (optional) |
| --command | -c | Command to execute (required) |
| --method | -m | DCOM execution method: mmc20, shellwindows, wmiexecute (default: mmc20) |
| --timeout | -o | Connection timeout in seconds (default: 30) |
| --verbose | -v | Show verbose output |
| --ssl | -S | Use SSL encrypted connection |

#### Usage Examples

```bash
# Test DCOM connection reachability
./GYscan.exe dcom connect --target 192.168.1.100 --username Administrator --password "Password123"

# Execute remote command using MMC20.Application method (default)
./GYscan.exe dcom execute --target 192.168.1.100 --username Administrator --password "Password123" --command "whoami"

# Execute remote command using ShellWindows method
./GYscan.exe dcom execute --target 192.168.1.100 --username Administrator --password "Password123" --command "ipconfig" --method shellwindows

# Execute remote command using WMI Execute method
./GYscan.exe dcom execute --target 192.168.1.100 --username Administrator --password "Password123" --command "hostname" --method wmiexecute

# Execute multiple commands
./GYscan.exe dcom execute --target 192.168.1.100 --username Administrator --password "Password123" --command "whoami & hostname"

# DCOM execution in domain environment
./GYscan.exe dcom execute --target 192.168.1.100 --username admin --password "Password123" --domain CORP --command "whoami"

# DCOM execution with verbose output
./GYscan.exe dcom execute --target 192.168.1.100 --username Administrator --password "Password123" --command "systeminfo" --verbose

# Enumerate DCOM objects on remote host
./GYscan.exe dcom list --target 192.168.1.100 --username Administrator --password "Password123"
```

#### DCOM Execution Method Description

| Method | Description | Use Case |
|--------|-------------|----------|
| mmc20 | Execute command using MMC20.Application COM object | General use, default method |
| shellwindows | Execute command using ShellWindows COM object | Alternative when MMC20 is disabled |
| wmiexecute | Execute command using WMI CIM object | When WMI access is required |

#### Port Requirements

DCOM remote execution requires target host to have port 135 open (RPC endpoint mapper):

```bash
# Verify target port 135 is open
telnet 192.168.1.100 135
```

If port 135 is not available, a connection error will be returned. Please check:
- Whether Windows Firewall allows port 135 inbound
- Whether RPC service (rpcss) is running
- Whether network firewall allows port 135 communication

### RDP Remote Desktop

```bash
# Check RDP service availability
./GYscan.exe rdp check --target 192.168.1.100

# Connect to RDP service
./GYscan.exe rdp connect --target 192.168.1.100 --user Administrator --password "Password123"
```

### SMB Protocol Operations

```bash
# Detect SMB version
./GYscan.exe smb version --target 192.168.1.100

# List SMB shares
./GYscan.exe smb shares --target 192.168.1.100 --user Administrator --password "Password123"
```

### Vulnerability Detection

```bash
# XSS vulnerability detection
./GYscan.exe xss --target http://example.com --payload "<script>alert('xss')</script>"

# CSRF vulnerability detection
./GYscan.exe csrf --target http://example.com/vul/csrf.php -X POST -d "action=delete&id=1"
```

### Weak Password Brute-Forcing

```bash
# SSH weak password detection
./GYscan.exe ssh --target 192.168.1.100 --user admin --wordlist passwords.txt

# FTP weak password detection
./GYscan.exe ftp --target 192.168.1.100 --user anonymous --wordlist passwords.txt

# WAF detection
./GYscan.exe waf -u "https://www.example.com/"
```

### AD CS Vulnerability Detection

GYscan's AD CS vulnerability detection module can detect various security vulnerabilities in Active Directory Certificate Services, including ESC1-ESC8 and other common configuration issues.

#### Supported Vulnerabilities

| Vulnerability | Description | Severity |
|---------------|-------------|----------|
| ESC1 | Certificate template allows enrollee to supply SAN + client authentication | 🔴 High |
| ESC2 | Any Purpose EKU or undefined EKU | 🔴 High |
| ESC3-1 | Certificate Request Agent + no signature | 🔴 High |
| ESC3-2 | Certificate Request Agent + 1 signature | 🟠 Medium |
| ESC4 | Template ACL too permissive | 🔴 High |
| ESC6 | EDITF_ATTRIBUTESUBJECTALTNAME2 flag | 🔴 High |
| ESC7 | CA permission configuration issues | 🟠 Medium |
| ESC8 | NTLM relay risk | 🟠 Medium |

#### Usage Examples

```bash
# Basic scan
./GYscan.exe adcs --target dc.domain.local --user domain\\admin --password Pass123

# Specify domain and output file
./GYscan.exe adcs --target dc.domain.local --user admin --password Pass123 -d domain.local -o results.json

# Detect specific vulnerabilities only
./GYscan.exe adcs --target dc.domain.local --user admin --password Pass123 --filters esc1,esc2

# JSON format output
./GYscan.exe adcs --target dc.domain.local --user admin --password Pass123 -f json

# Verbose output mode
./GYscan.exe adcs --target dc.domain.local --user admin --password Pass123 -v
```

#### Parameter Description

| Parameter | Short | Description |
|-----------|-------|-------------|
| --target | -t | Target domain controller address (required) |
| --port | -p | LDAP port (default: 389, LDAPS: 636) |
| --user | -u | Username (required, format: DOMAIN\\user or user@domain.com) |
| --password | -w | Password (required) |
| --domain | -d | Domain name (optional) |
| --output | -o | Output file path (optional) |
| --format | -f | Output format: text/json (default: text) |
| --filters | -x | Vulnerability filter, comma-separated (e.g., esc1,esc2,esc6) |
| --verbose | -v | Verbose output mode |

#### Authentication Format

Supports two authentication formats:
- `DOMAIN\\username` (Windows style)
- `username@domain.com` (UPN style)

## Technical Architecture

### Project Structure

```
GYscan/
├── Client/                # Client main program (penetration testing tool)
│   ├── internal/          # Internal function modules
│   │   ├── adcs/          # AD CS vulnerability detection module (v2.7 new)
│   │   ├── cli/           # Command-line interface and command registration
│   │   ├── config/        # Configuration management module
│   │   ├── configaudit/   # Configuration audit module (v2.7 new)
│   │   ├── csrf/          # CSRF vulnerability detection module
│   │   ├── database/      # Database password brute-forcing tool
│   │   ├── dirscan/       # Website directory scanning module
│   │   ├── ftp/           # FTP password brute-forcing module
│   │   ├── powershell/    # PowerShell remote execution module
│   │   ├── process/       # Process and service information collection
│   │   ├── rdp/           # RDP remote desktop module
│   │   ├── smb/           # SMB protocol operation module
│   │   ├── ssh/           # SSH password brute-forcing module
│   │   ├── userinfo/      # Local user and group analysis tool
│   │   ├── waf/           # WAF detection tool
│   │   ├── weakpass/      # Weak password detection framework
│   │   ├── webshell/      # WebShell generation tool
│   │   ├── wmi/           # WMI remote management module
│   │   └── xss/           # XSS vulnerability detection module
│   ├── main.go            # Program main entry file
│   └── go.mod             # Go module dependency configuration
├── doc/                   # Documentation directory
│   └── man/               # Man manual pages
└── README-en.md           # English project documentation
```

### Technology Stack

GYscan is built using a modern technology stack to ensure high performance, scalability, and usability:

| Category | Technology/Library | Purpose |
|----------|-------------------|---------|
| **Core Language** | Go 1.24+ | Primary development language |
| **CLI Framework** | cobra | Command-line interface and command registration system |
| **HTTP Client** | resty/v2 | API requests and network communication |
| **HTML Parsing** | goquery | Web content parsing and processing |
| **Color Output** | color | Command-line color output |
| **Database Driver** | go-sql-driver/mysql | MySQL database support |
| **Database Driver** | go-mssqldb | SQL Server database support |
| **Database Driver** | lib/pq | PostgreSQL database support |
| **Database Driver** | go-ora | Oracle database support |
| **SMB Protocol** | go-smb2 | SMB protocol support |
| **LDAP Client** | go-ldap/ldap | LDAP protocol support |
| **YAML Parsing** | yaml.v3 | YAML configuration file parsing |

### Recent modifications:

### v2.7.2

**IPv6 Support Enhancement**

#### New Features

- **IPv6 Scanning Support**
  - Added `-6, --ipv6` flag to enable IPv6 scanning mode
  - Supports standard IPv6 addresses: `2001:db8::1`, `::1`, `fe80::1`
  - Supports IPv6 address resolution and DNS queries (AAAA records)
  - Supports IPv6 host discovery (ICMPv6 Echo requests)
  - Supports IPv6 port scanning and service identification
  - Supports IPv6 link-local addresses (with zone ID)
  - Automatically detects IPv4/IPv6 addresses and selects appropriate network connection method

#### Technical Improvements

- Added `isIPv6()` function for IPv6 address detection
- Added `isPrivateIPv6()` function for IPv6 private address ranges (RFC 4193 ULA, RFC 3879 link-local)
- Added `formatIPForConnection()` function to handle IPv6 address formatting (bracket wrapping)
- Updated `RemoveProtocolPrefix()` to properly handle IPv6 addresses
- Added `icmpv6Ping()` and `systemPing6()` functions for ICMPv6 detection
- Added `isLinux()` and `isMacOS()` helper functions
- Updated `hostDiscovery()` to skip ARP detection for IPv6 targets

- **WebSocket Testing Tool (ws command)**
  - Supports WebSocket connection testing (ws:// and wss://)
  - Supports text and binary message sending (with base64/hex encoding)
  - Supports custom HTTP headers and Origin request header
  - Supports WSS TLS certificate verification skip
  - Supports WebSocket subprotocols
  - Supports auto-reconnect mechanism (exponential backoff + jitter)
  - Supports response assertion validation (contains/regex/json/length_greater)
  - Supports heartbeat detection (Ping/Pong)
  - Supports message count and interval control
  - Supports verbose output and performance monitoring

## Changelog

### v2.7.1

**SSH Module Enhancement and Bug Fixes**

#### Feature Improvements

- **SSH Batch Target Brute Force Optimization**
  - Supports loading target IPs from file via `--file` parameter
  - Optimized multi-target concurrent brute force logic
  - Added real-time progress display, similar to Hydra-style output

#### Bug Fixes

- Fixed SSH target file parsing issue, supports loading multiple targets from text file
- Fixed incorrect result statistics in multi-target mode
- Fixed real-time progress not displaying during batch brute force
- Optimized SSH connection algorithm configuration for better compatibility

#### SSH Module Enhancements

- Added `--file` parameter support: load target IPs from text file in batch
- Added `--verbose` mode: display each authentication attempt in real-time
- Optimized error handling and logging for better debugging
- Supports multi-target concurrent brute force, significantly improving batch testing efficiency

### v2.7-beta

**Version Update and Command Adjustments**

- **Version Upgrade**: GYscan upgraded from v2.6.3 to v2.7-beta
- **Command Adjustment**: Moved mg (honeypot identification tool) from stable to beta commands
- **Command Adjustment**: Moved tui (start TUI mode) from stable to beta commands, planned for removal in subsequent versions
- **Honeypot Identification Optimization**: Honeypot identification tool added HFish honeypot support
- **Code Structure Optimization**: Adjusted command classification to make stable commands more stable and reliable

### v2.6.3

**Feature Optimization and Enhancement**

- **File Upload Vulnerability Check Mechanism Optimization**
  - Frontend validation bypass detection
  - Filename bypass detection enhanced
  - MIME type bypass detection new
  - Race condition detection new

- **Website Directory Scanning Feature Optimization**
  - File extension scanning support
  - Ctrl+C interrupt handling optimization
  - Cross-platform clear screen function
  - Scan results organized display

### v2.6.2

- **New pc command** - Remote patch detection tool, remotely query target system middleware component versions and patch status without login
  - Based on WhatWeb fingerprint recognition technology, supports 1999+ web fingerprints
  - Supports Web servers: Nginx, Apache, Tomcat, IIS
  - Supports databases: MySQL, SQL Server, Oracle, PostgreSQL
  - Supports cache/messaging: Redis, Memcached, RabbitMQ
  - Supports middleware: WebLogic, JBoss, GlassFish
  - Supports CMS systems: WordPress, Drupal, Joomla
  - Component version correlation analysis with official vulnerability database
  - Supports multiple output formats and filtering options

- **New fu command** - File upload vulnerability check feature, supports multiple bypass techniques
- **New wwifi command** - Windows system WiFi cracking functionality

### v2.6.0

- **New scapy module** - Integrated advanced network packet manipulation tool
  - Raw network packet construction and sending functionality
  - Network interface detection and status analysis
  - Feature demonstration and example code

### v2.5.4

- **New linenum feature** - Linux local information enumeration and privilege escalation tool
- **New linux-kernel feature** - Linux kernel vulnerability detection tool

### v2.5.2

- **New winlog command** - Windows log viewing tool
- Optimized log entry display format

### v2.5.1

- **New waf command** - WAF detection tool
- Optimized WAF detection module code

### v2.5.0

- Unified command registration mechanism
- Implemented command grouping display
- Completed PowerShell module, added HTTPS support
- Enhanced WMI module functionality

### v2.0.0

- **New csrf command** - CSRF vulnerability detection module
- Improved XSS detection functionality

### v1.0.0

- **Initial Release**: Basic port scanning functionality
- Service identification and fingerprinting
- Weak password brute-forcing framework
- Basic vulnerability detection functionality

## Contributing Guide

Welcome to submit Issues and Pull Requests to improve the project. Please ensure:
1. Code complies with Go language specifications
2. Add appropriate test cases
3. Update relevant documentation
4. Follow secure development specifications

## License

This project uses MIT license. See LICENSE file for details.

## Disclaimer

**Important Notice**: This tool is for security research and authorized testing only. Any unauthorized use is illegal, and users bear corresponding legal responsibilities. The author does not assume any direct or indirect liability arising from the use of this tool.

---

**GYscan - Focused on Internal Network Security, Guarding Network Boundaries** 🛡️
