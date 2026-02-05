[中文文档](README.md)

# GYscan - Internal Network Lateral Boundary Security Testing Tool

## ⚠️ Copyright Notice & Anti-Piracy Warning

**【IMPORTANT】When sharing this project, whether in articles, tool introductions, or video content, you MUST preserve the original author's repository name and credit! Unauthorized reproduction, modification, or redistribution constitutes copyright infringement!**

### Legal Consequences of Infringement

Unauthorized use of this tool for unauthorized testing, modifying source code, or repackaging may result in:
- **Civil Liability**: Copyright infringement, requiring compensation and corrective actions
- **Administrative Liability**: Violation of cybersecurity laws and regulations
- **Criminal Liability**: Severe cases may constitute illegal computer system intrusion

**We have implemented technical traceability for all modified versions - plagiarizers will be prosecuted!**

## 🔒 Anti-Piracy Statement

This project is ONLY released through the following official channels. All other sources are pirated:

### Official Distribution Channels
- **GitHub Main Repository**: https://github.com/gyscan/GYscan
- **Gitee Main Repository**：https://gitee.com/bzhanyiqiua/GYscan
- **Official Website**: https://gyscan.space
- **Official Communication Group**: See website for details

### How to Identify Pirated Copies
1. **Non-Official Domains**: All domains other than gyscan.space are pirated
2. **Modified Author Info**: Removal or modification of original project credits
3. **Redistribution**: Unauthorized reproduction and republication
4. **Paid Sales**: This project is completely FREE - any paid offering is a scam

**If you discover pirated copies, please report via the website contact. We will pursue legal action!**

## 📢 Website Migration Notice

GYscan official website has migrated to the new domain **gyscan.space**. The old domain is no longer active.

## 🏢 Official Website

**Please use the only official website! This software has ONLY ONE official website - all others are impersonations!**

> **⚠️ Beware of Fake Websites**  
> We will NEVER ask for your account credentials, passwords, or payments through unofficial channels  
> If you encounter a fake website, stop immediately and report it via the official website

**GYscan Official Website**: [https://gyscan.space](https://gyscan.space/)

## Project Overview

GYscan is a professional tool focused on internal network lateral movement and boundary security testing, developed using Go language. This tool integrates rich internal network penetration testing capabilities, including:

- **Port Scanning**: Fast and accurate network port discovery
- **Service Identification**: Detailed service and version fingerprinting
- **Vulnerability Detection**: Integration with CVE databases and exploit frameworks
- **Remote Command Execution**: Secure command execution capabilities
- **Weak Password Brute-Forcing**: Multi-protocol credential testing
- **Configuration Auditing**: CIS Benchmark-based security checks

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
| **Latest Version** | v2.8.0 |

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

- **Scan Module Port Scanning Optimization and Enhancement**
  - **Port State Detection Enhancement**
    - Supports six complete port states: open, closed, filtered, unfiltered, open|filtered, closed|filtered
    - Added constants: `PortStateOpen`, `PortStateClosed`, `PortStateFiltered`, `PortStateUnfiltered`, `PortStateOpenFiltered`, `PortStateClosedFiltered`
    - Updated `PortInfo` struct to support complete port state fields

  - **New Covert Scanning Types**
    - `--sF` TCP FIN scan: Sends FIN packets, determines port state per RFC 793
    - `--sX` TCP XMAS scan: Sends FIN/URG/PSH flag packets
    - `--sN` TCP NULL scan: Sends packets with no flags set
    - `--sA` TCP ACK scan: Determines if port is filtered
    - `--sW` TCP window scan: Determines state via TCP window size
    - `--sM` TCP Maimon scan: Sends FIN/ACK flag packets

  - **Scanning Function Enhancements**
    - Added `finScan()` function for TCP FIN scanning
    - Added `xmasScan()` function for TCP XMAS scanning
    - Added `nullScan()` function for TCP NULL scanning
    - Added `ackScan()` function for TCP ACK scanning
    - Added `windowScan()` function for TCP window scanning
    - Added `maimonScan()` function for TCP Maimon scanning
    - Added `connCloseWithoutError()` safe connection close helper function
    - Updated `detectUDPPortState()` to support open|filtered state

  - **UDP Scanning Accuracy Fix**
    - Fixed `udpConnect()` function bug: previously returned true regardless of response
    - Now correctly distinguishes open (response received), filtered (timeout, no response), closed (connection failed)
    - Significantly improves UDP port scanning accuracy

  - **Host Discovery Optimization**
    - Optimized timeout allocation strategy: public hosts use 2/3 timeout per probe method (was 1/3)
    - Simplified public host probing methods: only 3 efficient methods (tcpPing, icmpPing, tcpSynPing)
    - Lowered public host confirmation threshold: only 1 method needed to confirm alive (was 2)
    - Reduced TCP ping port count: from 16 to 5 common ports (80, 443, 8080, 22, 53)
    - Optimized retry wait time: from 100ms to 50ms
    - Improves public target host discovery success rate and speed

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

## ⚖️ Disclaimer

**【Please Read Before Use】**

1. **Usage Restrictions**: This tool is strictly limited to:
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

## 📄 License

This project is licensed under the **Apache License 2.0**.

**You are free to**: freely use, modify, and distribute this project's code, subject to:
- Preserving the original copyright notice
- Adding notices to modified files
- Derivative works must use the same license

**See**: [LICENSE](LICENSE) file for details.

---

**GYscan - Focused on Internal Network Security, Guarding Network Boundaries** 🛡️
