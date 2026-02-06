[**中文文档**](README.md)

# GYscan - Comprehensive Penetration Testing Tool

[![Version](https://img.shields.io/badge/Version-v2.8.1-blue)](https://gyscan.space)
[![Go](https://img.shields.io/badge/Go-1.24+-00ADD8?style=flat&logo=go)](https://golang.org/)
[![License](https://img.shields.io/badge/License-Apache%202.0-yellowgreen)](https://www.apache.org/licenses/LICENSE-2.0)

---

## ⚠️ Copyright Notice & Anti-Piracy Warning

**【IMPORTANT】When sharing this project, whether in articles, tool introductions, or video content, you MUST preserve the original author's repository name and credit! Unauthorized reproduction, modification, or redistribution constitutes copyright infringement!**

### Legal Consequences of Infringement

Unauthorized use of this tool for unauthorized testing, modifying source code, or repackaging may result in:
- **Civil Liability**: Copyright infringement, requiring compensation and corrective actions
- **Administrative Liability**: Violation of cybersecurity laws and regulations
- **Criminal Liability**: Severe cases may constitute illegal computer system intrusion

**We have implemented technical traceability for all modified versions - plagiarizers will be prosecuted!**

---

## 🔒 Anti-Piracy Statement

This project is ONLY released through the following official channels. All other sources are pirated:

| Channel | Address |
|---------|---------|
| **GitHub Main Repository** | https://github.com/gyscan/GYscan |
| **Gitee Main Repository** | https://gitee.com/bzhanyiqiua/GYscan |
| **Official Website** | https://gyscan.space |

### How to Identify Pirated Copies

1. **Non-Official Domains**: All domains other than gyscan.space are pirated
2. **Modified Author Info**: Removal or modification of original project credits
3. **Redistribution**: Unauthorized reproduction and republication
4. **Paid Sales**: This project is completely FREE - any paid offering is a scam

> **If you discover pirated copies, please report via the website contact. We will pursue legal action!**

---

## 📢 Website Migration Notice

GYscan official website has migrated to the new domain **gyscan.space**. The old domain is no longer active.

---

## 🏢 Official Website

**Please use the only official website! This software has ONLY ONE official website - all others are impersonations!**

> **⚠️ Beware of Fake Websites**
> We will NEVER ask for your account credentials, passwords, or payments through unofficial channels
> If you encounter a fake website, stop immediately and report it via the official website

**[GYscan Official Website](https://gyscan.space/)**

---

## 📋 Table of Contents

- [Project Overview](#project-overview)
- [Core Features](#core-features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Command List](#command-list)
- [Changelog](#changelog)
- [Contributing](#contributing)
- [License](#license)
- [Disclaimer](#disclaimer)

---

## Project Overview

GYscan is a professional comprehensive penetration testing tool developed using Go language. Based on Go's high-performance characteristics, GYscan offers excellent concurrent processing capabilities and cross-platform compatibility, efficiently assisting security researchers and penetration testers in completing security assessments.

The tool integrates rich penetration testing function modules, covering port scanning, service identification, vulnerability detection, remote command execution, weak password brute-forcing, configuration auditing, and other core capabilities, providing users with a one-stop security assessment solution.

### Basic Information

| Attribute | Value |
|-----------|-------|
| **Project Name** | GYscan |
| **Development Language** | Go 1.24+ |
| **Supported Platforms** | Windows 7+/Linux/macOS |
| **License** | Apache 2.0 |
| **Latest Version** | v2.8.1 |
| **Author** | BiliBili-弈秋啊 |

---

## Core Features

### 🔍 Network Discovery & Scanning

| Feature | Description |
|---------|-------------|
| **Port Scanning** | Multiple scanning techniques: TCP SYN/Connect/ACK/FIN/XMAS/NULL |
| **Service Identification** | Fingerprint-based service version detection, 1999+ web fingerprints |
| **Host Discovery** | ICMP/ARP/TCP/UDP multi-protocol discovery, IPv4/IPv6 support |
| **OS Detection** | Remote operating system fingerprinting |

### 🔐 Password Attacks & Credential Harvesting

| Feature | Description |
|---------|-------------|
| **SSH Brute-Force** | Hydra-style multi-threaded SSH password cracking |
| **SMB Attacks** | SMB connection testing, share enumeration, remote command execution |
| **FTP Brute-Force** | FTP server password cracking |
| **Database Brute-Force** | MySQL, PostgreSQL, Oracle, MSSQL weak password detection |

### 🌐 Web Application Security

| Feature | Description |
|---------|-------------|
| **Web Fingerprinting** | Website technology stack detection with 105+ fingerprints |
| **XSS Detection** | Reflected, Stored, DOM XSS vulnerability detection |
| **CSRF Detection** | Cross-Site Request Forgery vulnerability detection |
| **WAF Identification** | Detect if target is behind WAF and identify WAF type |
| **Directory Scanning** | Web path enumeration with custom dictionaries and extensions |
| **File Upload Testing** | File upload vulnerability detection with bypass techniques |
| **WebSocket Testing** | WebSocket connection testing and protocol analysis |

### 🏢 Active Directory Security

| Feature | Description |
|---------|-------------|
| **AD CS Vulnerability** | ESC1-ESC8 certificate template vulnerability detection |
| **LDAP Enumeration** | Domain users, groups, computers, organizational units enumeration |
| **Kerberoasting** | SPN account discovery for ticket attacks |
| **AS-REP Roasting** | Pre-authentication bypass account detection |

### 📡 Remote Management

| Feature | Description |
|---------|-------------|
| **PowerShell** | PowerShell remote command execution |
| **WMI** | WMI remote management tool |
| **RDP** | RDP remote desktop related functions |
| **DCOM** | DCOM remote execution |

### 🔎 Security Assessment

| Feature | Description |
|---------|-------------|
| **Configuration Auditing** | CIS Benchmark-based 58 configuration checks |
| **Honeypot Detection** | Identify if target is a honeypot system |
| **Patch Detection** | Remote system patch status detection |
| **Exploit-DB** | Integrated 46,928 exploit entries |

### 💻 System Information Gathering

| Feature | Description |
|---------|-------------|
| **Subdomain Discovery** | DNS-based subdomain enumeration with dictionary brute-force |
| **Process Info** | Remote system process and service enumeration |
| **User Enumeration** | Local user and group information gathering |
| **Windows Logs** | Windows event log viewing |
| **Linux Enumeration** | Linux local information and privilege escalation detection |
| **WiFi Password** | Windows system WiFi password retrieval |

---

## Installation

### Requirements

- **Operating System**: Windows 10+/Linux/macOS
- **Go Version**: Go 1.24 or higher
- **Dependencies**: Nmap (required for some features)

### Linux Installation

```bash
# Clone the project
git clone https://github.com/gyscan/GYscan.git
cd GYscan/Client

# Install dependencies
go mod download

# Build the project
go build -o GYscan .

# Copy to system path (optional)
sudo cp GYscan /usr/local/bin/
```

### Windows Installation

```powershell
# Build using PowerShell
cd GYscan
.\build.ps1
```

### Dependency Installation (Linux)

```bash
# Debian/Ubuntu/Kali
sudo apt install -y libx11-dev libxcursor-dev libxrandr-dev libxinerama-dev \
    libxi-dev libxxf86vm-dev libgl1-mesa-dev libglu1-mesa-dev mesa-common-dev \
    build-essential pkg-config dbus-x11 libdbus-1-dev libpcap-dev

# RedHat/CentOS/Fedora
sudo yum install -y libX11-devel libXcursor-devel libXrandr-devel libXinerama-devel \
    libXi-devel libXxf86vm-devel mesa-libGL-devel mesa-libGLU-devel \
    gcc-c++ pkgconfig dbus-x11 dbus-devel libpcap-devel
```

---

## Quick Start

### Basic Usage

```bash
# Display help information
./GYscan help

# Display version information
./GYscan --version

# Disable color output
./GYscan --no-color

# Use proxy
./GYscan --proxy socks5://127.0.0.1:1080
```

### Common Command Examples

```bash
# Port scanning
./GYscan scan -t 192.168.1.1 -p 1-1000

# SSH password brute-forcing
./GYscan ssh -t 192.168.1.1 -u root -P /path/to/passwords.txt

# Web directory scanning
./GYscan dirscan -u http://example.com -w dirmap/dicc.txt

# XSS vulnerability detection
./GYscan xss -u "http://example.com/?id=1"

# WAF identification
./GYscan waf -u http://example.com

# Honeypot detection
./GYscan mg -t 192.168.1.1

# AD CS vulnerability detection
./GYscan adcs -t dc.example.com

# Configuration auditing
./GYscan ca -t 192.168.1.1
```

---

## Command List

### Stable Commands

| Command | Group | Description |
|---------|-------|-------------|
| `scan` | Network | Comprehensive port scanner |
| `nmap` | Network | Nmap scan result parsing |
| `dirscan` | Network | Web directory enumeration |
| `route` | Network | Route hop detection |
| `whois` | Network | Whois domain query |
| `scapy` | Network | Advanced packet manipulation |
| `ssh` | Password | SSH password brute-forcing |
| `ftp` | Password | FTP password cracking |
| `database` | Password | Database password cracking |
| `crunch` | Password | Password dictionary generation |
| `smb` | Remote | SMB protocol operations |
| `rdp` | Remote | RDP remote desktop |
| `powershell` | Remote | PowerShell execution |
| `wmi` | Remote | WMI remote management |
| `webshell` | Web | WebShell generation |
| `waf` | Web | WAF detection |
| `xss` | Web | XSS vulnerability detection |
| `fu` | Web | File upload testing |
| `ws` | Web | WebSocket testing |
| `exp` | Web | Exploit-DB search |
| `process` | Info | Process enumeration |
| `userinfo` | Info | User information gathering |
| `winlog` | Info | Windows log viewing |
| `pc` | Info | Patch detection |
| `linenum` | General | Linux information enumeration |
| `linux-kernel` | General | Linux kernel vulnerabilities |
| `wwifi` | General | WiFi password retrieval |
| `about` | General | Tool information |

### Beta Commands

| Command | Description |
|---------|-------------|
| `csrf` | CSRF vulnerability detection |
| `dcom` | DCOM remote execution |
| `ldap` | LDAP enumeration |
| `mg` | Honeypot identification |
| `adcs` | AD CS vulnerability detection |

---

## Changelog

### v2.8.1

**Subdomain Discovery and Web Fingerprinting**

#### New Features

- **sub command - Subdomain Discovery Tool**
  - DNS-based subdomain enumeration
  - Custom dictionary brute-force (500+ built-in subdomain entries)
  - DNS record query (A/CNAME/MX/TXT/NS)
  - High-concurrency scanning (default 50 threads)
  - Automatic wildcard detection and filtering
  - HTTP verification to confirm subdomain availability
  - Real-time progress display and colored output
  - Support saving results to files

- **webfp command - Web Technology Fingerprinting**
  - Fingerprint detection based on HTTP headers, HTML content, and resource paths
  - Supports 105+ technology fingerprints across 20+ categories
  - Frontend frameworks: React, Vue.js, Angular, Svelte, Next.js, Nuxt.js
  - Backend frameworks: Express, NestJS, Django, Flask, Laravel
  - CMS systems: WordPress, Drupal, Joomla, Shopify
  - UI frameworks: Bootstrap, Tailwind CSS, Ant Design
  - JavaScript libraries: jQuery, Lodash, Axios
  - CDN/Hosting: Cloudflare, Vercel, Netlify
  - Analytics: Google Analytics, Hotjar
  - Confidence scoring mechanism
  - JSON format output support

#### Technical Improvements

- HTTP client optimization with timeout and redirect control
- Enhanced HTML parsing for scripts, CSS, and meta tags
- Multi-dimensional fingerprint matching algorithm
- Thread-safe scanning engine
- Graceful shutdown support (Ctrl+C interrupt handling)

#### Command Examples

```bash
# Subdomain discovery
./GYscan sub example.com
./GYscan sub example.com -w subdomains.txt
./GYscan sub example.com -t 100
./GYscan sub example.com -T CNAME
./GYscan sub example.com -f results.txt
./GYscan sub example.com --no-http

# Web fingerprinting
./GYscan webfp https://example.com
./GYscan webfp https://example.com -v
./GYscan webfp https://example.com -o result.json
./GYscan webfp https://example.com -c "Frontend Frameworks"
./GYscan webfp https://example.com -t 30s
```

### v2.8.0

**Exploit-DB Integration and Exploit Management**

#### New Features

- **exp command - Exploit-DB Vulnerability Management Module**
  - Integrated Exploit-DB database with 46,928 exploits and 1,065 shellcodes
  - Supports multiple search methods: keywords, CVE numbers, platforms, vulnerability types
  - Supports exact match and case-sensitive search
  - Supports JSON and text format output
  - Supports saving search results to files

- **Exploit Details Viewing**
  - Query vulnerability details by EDB-ID
  - Displays vulnerability description, platform, type, author, publication date, CVE, etc.
  - Supports verbose mode to show tags and aliases

- **PoC Code Management**
  - `show` subcommand: View exploit code content
  - `copy` subcommand: Copy exploit code to specified directory
  - `generate` subcommand: Generate PoC code with GYscan header
  - Supports custom target parameters (-t target, -p port, --ssl)

- **PoC Template Generation**
  - `simple` subcommand: Generate simple Python PoC templates
  - Supports rapid testing and custom development
  - Supports parameterized target address and port

- **Nmap NSE Script Generation**
  - `nmap` subcommand: Generate Nmap vulnerability detection scripts
  - Can be directly used with Nmap scans
  - Supports output to Nmap scripts directory

- **Database Management**
  - `stats` subcommand: Display database statistics
  - `list` subcommand: List available platforms and vulnerability types
  - `reload` subcommand: Reload database
  - Supports lazy loading for faster startup

#### Technical Improvements

- Database CSV parsing optimization
- Multi-path lookup support (supports various installation paths)
- Thread-safe database loading
- Smart file path matching
- Colored terminal output support

#### Command Examples

```bash
# Search for exploits
./GYscan exp search "apache struts"
./GYscan exp search --cve CVE-2021-44228
./GYscan exp search --platform windows --type local

# View exploit details
./GYscan exp info 40564
./GYscan exp info 40564 -v

# View and copy PoC code
./GYscan exp show 40564 > poc.py
./GYscan exp copy 40564 /tmp/exploits/

# Generate PoC
./GYscan exp generate 40564 -t 192.168.1.100 -p 8080 -o /tmp/pocs/
./GYscan exp simple 40564 -t 192.168.1.100 -o poc.py

# Generate Nmap scripts
./GYscan exp nmap 40564 -o /usr/share/nmap/scripts/

# Database management
./GYscan exp stats
./GYscan exp list platforms
./GYscan exp list types
```

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
- Added `isPrivateIPv6()` function for IPv6 private address ranges
- Added `formatIPForConnection()` function for IPv6 address formatting
- Added `icmpv6Ping()` and `systemPing6()` functions for ICMPv6 detection
- Updated `hostDiscovery()` to skip ARP detection for IPv6 targets

- **WebSocket Testing Tool (ws command)**
  - Supports WebSocket connection testing (ws:// and wss://)
  - Supports text and binary message sending (with base64/hex encoding)
  - Supports custom HTTP headers and Origin request header
  - Supports WSS TLS certificate verification skip
  - Supports WebSocket subprotocols
  - Supports auto-reconnect mechanism (exponential backoff + jitter)
  - Supports response assertion validation
  - Supports heartbeat detection (Ping/Pong)

- **Scan Module Port Scanning Optimization**
  - Supports six complete port state detection
  - Added covert scanning types: TCP FIN/XMAS/NULL/ACK/Window/Maimon scan
  - Fixed UDP scanning accuracy bug
  - Optimized host discovery strategy

### v2.7.1

**SSH Module Enhancement and Bug Fixes**

- **SSH Batch Target Brute Force Optimization**
  - Supports loading target IPs from file via `--file` parameter
  - Optimized multi-target concurrent brute force logic
  - Added real-time progress display, similar to Hydra-style output format

- **Bug Fixes**
  - Fixed SSH target file parsing issue
  - Fixed incorrect result statistics in multi-target mode
  - Fixed real-time progress not displaying during batch brute force
  - Optimized SSH connection algorithm configuration for better compatibility

### v2.7

**Version Update and Configuration Auditing**

#### New Features

- **pc command - Remote Patch Detection Tool**
  - Based on WhatWeb fingerprint recognition technology, supports 1999+ web fingerprints
  - Supports Web servers, databases, messaging, middleware, CMS system identification
  - Component version correlation with official vulnerability database

- **Configuration Auditing (CA) Module**
  - CIS Benchmark-based configuration compliance checking
  - Supports five audit categories: Windows, Linux, Web, SSH, Middleware
  - 58 configuration check items
  - Supports JSON, HTML, Text output formats

- **Configuration Evidence Feature**
  - Displays specific configuration file paths
  - Displays configuration item names and current values
  - Provides expected values and remediation suggestions

#### Command Adjustments

- Added `ca` command - Configuration auditing tool
- Added `pc` command - Remote patch detection tool
- Moved `mg` (honeypot identification) from stable to beta commands
- Removed `tui` (start TUI mode)

### v2.6.3

**Feature Optimization and Enhancement**

- **File Upload Vulnerability Check Optimization**
  - Frontend validation bypass detection
  - Filename bypass detection enhanced
  - MIME type bypass detection new
  - Race condition detection new

- **Website Directory Scanning Optimization**
  - File extension scanning support
  - Ctrl+C interrupt handling optimization
  - Cross-platform clear screen function
  - Scan results organized display

### v2.6.2

- **New pc command** - Remote patch detection tool
- **New fu command** - File upload vulnerability check feature
- **New wwifi command** - Windows system WiFi cracking functionality

### v2.6.0

- **New scapy module** - Integrated advanced network packet manipulation tool
  - Raw network packet construction and sending functionality
  - Network interface detection and status analysis

### v2.5.4

- **New linenum feature** - Linux local information enumeration and privilege escalation tool
- **New linux-kernel feature** - Linux kernel vulnerability detection tool

### v2.5.2

- **New winlog command** - Windows log viewing tool

### v2.5.1

- **New waf command** - WAF detection tool

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

---

## Contributing

Welcome to submit Issues and Pull Requests to improve the project. Please ensure:

1. Code complies with Go language specifications
2. Add appropriate test cases
3. Update relevant documentation
4. Follow secure development specifications

---

## License

This project is licensed under the **Apache License 2.0**.

**You are free to**: freely use, modify, and distribute this project's code, subject to:
- Preserving the original copyright notice
- Adding notices to modified files
- Derivative works must use the same license

**See**: [LICENSE](LICENSE) file for details

---

## ⚖️ Disclaimer

**【Please Read Before Use】**

1. **Usage Restrictions**: This tool is strictly limited to:Authorised security testing
   - Security testing projects with explicit authorization
   - Network security research and educational purposes
   - Internal enterprise security assessments (requires written authorization)

2. **Prohibited Activities**:
   - ❌ Unauthorized penetration of any systems
   - ❌ Illegal access or damage to others' computer systems
   - ❌ Use for any illegal activities
   - ❌ Using this tool on targets without authorization

3. **Liability Statement**:
   - Users must ensure they have obtained all necessary authorizations
   - Authors and contributors accept no legal responsibility for misuse
   - This tool provides NO warranty of any kind

4. **Compliance Requirements**: Before using this tool, ensure compliance with:
   - Local laws and regulations
   - Written authorization from target system owners
   - Use only within authorized scope

---

**GYscan - Focused on Penetration Testing, Safeguarding Cybersecurity** 🛡️
