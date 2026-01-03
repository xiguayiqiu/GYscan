[中文文档](README.md)

# GYscan - Internal Network Lateral Boundary Security Testing Tool

## Project Overview

GYscan is a professional tool focused on internal network lateral movement and boundary security testing, developed using Go language. This tool integrates rich internal network penetration testing capabilities, including port scanning, service identification, vulnerability detection, remote command execution, and weak password brute-forcing, providing security researchers and penetration testers with efficient and reliable internal network security assessment solutions.

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
| **Latest Version** | v2.7 |

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
| scan | Network scanning tool, supporting host discovery, port scanning, service identification | ✅ Stable |
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

### Beta Commands

| Command | Description | Status |
|---------|-------------|--------|
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

# Use SSH to connect to remote Linux system for audit (password authentication)
./GYscan.exe ca 192.168.1.100 --os-type linux --ssh-user root --ssh-password yourpassword

# Use SSH to connect to remote Linux system for audit (private key authentication)
./GYscan.exe ca 192.168.1.100 --os-type linux --connection-mode ssh --ssh-user root --ssh-key ~/.ssh/id_rsa

# Specify SSH port for audit
./GYscan.exe ca 192.168.1.100 --os-type linux --ssh-user admin --ssh-password pass --ssh-port 2222

# Use WMI to connect to remote Windows system for audit
./GYscan.exe ca 192.168.1.50 --os-type windows --wmi-user administrator --wmi-password yourpassword

# Use domain account to connect to Windows system for audit
./GYscan.exe ca 192.168.1.50 --connection-mode wmi --wmi-user domain\\admin --wmi-password pass --wmi-domain CORP

# Auto-detect target system type and select connection method
./GYscan.exe ca 192.168.1.100 --detect-os --connection-mode auto --ssh-user root --ssh-password pass

# Audit remote Linux system and generate HTML report
./GYscan.exe ca 192.168.1.100 --os-type linux --ssh-user root --ssh-key ~/.ssh/id_rsa -o audit.html --format html

# Audit remote Windows system configuration
./GYscan.exe ca 192.168.1.50 --os-type windows --wmi-user admin --wmi-password pass --category os

# List all check items under Linux category
./GYscan.exe ca list --category linux

# Generate security baseline report for target system
./GYscan.exe ca baseline --target localhost -o baseline.json

# Generate configuration remediation suggestion plan
./GYscan.exe ca remediate --target localhost
```

#### Windows System Port 135 Issue Handling

When the target Windows system has port 135 closed, detailed guidance will be displayed:

```bash
# Attempt to audit Windows system
./GYscan.exe ca 192.168.1.50 --os-type windows --wmi-user admin --wmi-password pass
```

The output will include:
- **Steps to enable port 135 via GUI** - Windows Firewall configuration wizard
- **Command line method to enable port 135** - netsh advfirewall firewall commands
- **Firewall configuration instructions** - Inbound rule settings, port exceptions
- **RPC service startup and verification methods** - sc start rpcss, sc query rpcss
- **Verification steps after completion** - telnet test, port scan verification

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

## Technical Architecture

### Project Structure

```
GYscan/
├── Client/                # Client main program (penetration testing tool)
│   ├── internal/          # Internal function modules
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
| **YAML Parsing** | yaml.v3 | YAML configuration file parsing |

## Changelog

### v2.7

**Version Update and Configuration Audit Feature Release**

#### New Features

- **pc command** - Remote patch detection tool, remotely query target system middleware component versions and patch status without login
  - Based on WhatWeb fingerprint recognition technology, supports 1999+ web fingerprints
  - Supports Web servers: Nginx, Apache, Tomcat, IIS
  - Supports databases: MySQL, SQL Server, Oracle, PostgreSQL
  - Supports cache/messaging: Redis, Memcached, RabbitMQ
  - Supports middleware: WebLogic, JBoss, GlassFish
  - Supports CMS systems: WordPress, Drupal, Joomla
  - Component version correlation analysis with official vulnerability database
  - Supports multiple output formats and filtering options

- **Configuration Audit (CA) Module** - Newly Released
  - Configuration compliance checks based on CIS Benchmark security baseline
  - Supports five audit categories: Windows, Linux, Web, SSH, Middleware
  - Total of 58 configuration check items
  - Supports JSON, HTML, Text three output formats

- **Configuration Evidence Feature**
  - Displays specific configuration file paths
  - Displays configuration item names and current values
  - Provides expected values and remediation suggestions
  - Detailed risk descriptions and remediation steps

#### Command Adjustments

- Added `ca` command - Configuration audit tool
- Added `pc` command - Remote patch detection tool
- Moved mg (honeypot identification tool) from stable to beta commands
- Removed tui (start TUI mode), TUI development no longer considered

#### Technical Optimizations

- Enhanced CheckResult structure, supports configuration evidence fields
- Optimized report generator, supports multiple output formats
- Improved HTML report styles and interactivity

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
