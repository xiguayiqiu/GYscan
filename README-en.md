# GYscan - Internal Network Lateral Boundary Security Testing Tool

## Project Introduction

GYscan is a professional tool focused on internal network lateral movement and boundary security testing, developed based on the Go language. This tool integrates rich internal network penetration testing functions, including port scanning, service identification, vulnerability detection, remote command execution, weak password brute force cracking and other core functions, providing efficient and reliable internal network security assessment solutions for security researchers and penetration testers.

## Core Advantages

- **Focus on Internal Network Security**: Specially optimized for internal network lateral movement and boundary security testing scenarios
- **Rich Functions**: Integrates multiple functions such as port scanning, service identification, remote command execution, weak password brute force cracking, etc.
- **Cross-Platform Support**: Supports Windows, Linux, macOS three mainstream operating systems
- **Modular Design**: Adopts plug-in architecture, supports function expansion and custom module development
- **Strong Usability**: Provides a concise command-line interface and detailed help documentation
- **Excellent Performance**: Developed based on Go language, with excellent concurrent processing capabilities

### 📋 Basic Information

| Project | Information |
|---------|-------------|
| **Project Name** | GYscan |
| **Development Language** | Go 1.24+ |
| **Supported Platforms** | Windows 7+/Linux/macOS |
| **License** | Apache2.0 |
| **Latest Version** | v2.6.0 |

### ⚠️ Legal Statement

**Important Note**: This tool is only for authorized testing purposes. Any unauthorized use is illegal, and users shall bear corresponding legal responsibilities.

## 🚀 Quick Start

### Environment Preparation

1. **Install Go Environment** (version 1.18+)
   ```bash
   # Download and install Go
   https://golang.org/dl/
   
   # Verify installation
   go version
   ```

2. **Get Project Code**
   ```bash
   # Github
   git clone https://github.com/xiguayiqiu/GYscan.git
   # Gitee
   git clone https://gitee.com/bzhanyiqiua/GYscan.git
   cd GYscan
   ```

### Compilation and Installation

#### Windows Platform Compilation
```bash
# Compile client
cd Client
go build -o GYscan.exe
```

#### Linux Platform Compilation
```bash
# Compile client
cd Client
go build -o GYscan-linux-amd64
```

#### Cross Compilation
```bash
# Compile Windows version (on Linux)
cd Client
GOOS=windows GOARCH=amd64 go build -o GYscan.exe

# Compile Linux version (on Windows)
cd Client
GOOS=linux GOARCH=amd64 go build -o GYscan-linux-amd64
```

### One-Click Build Script
```bash
# Windows platform
.build.ps1

# Linux platform
chmod +x build_linux.sh
./build_linux.sh
```

### Linux Platform Dependency Installation

### Linux/Unix Platform Adaptation

GYscan v2.6.0 adds comprehensive support for Linux/Unix systems, including Linux, macOS, FreeBSD and other mainstream Unix systems.

#### Cross-Platform Features

- **Automatic Platform Detection**: Automatically identifies the current operating system and optimizes configuration parameters
- **Smart Interface Selection**: Selects default network interfaces based on different systems (Linux: eth0, Windows: WLAN, macOS: en0)
- **Performance Optimization**: Adjusts buffer size and snapshot length according to platform characteristics
- **Permission Management**: Automatically handles permission requirements for different systems
- **Error Handling**: Provides detailed platform-specific error information

#### Supported Platforms

| Platform | Status | Default Interface | Notes |
|----------|--------|-------------------|-------|
| Windows | ✅ Full Support | WLAN | Supports raw sockets and compatibility mode |
| Linux | ✅ Full Support | eth0 | Requires root privileges for raw packet operations |
| macOS | ✅ Full Support | en0 | Requires Xcode command line tools installation |
| FreeBSD | ✅ Full Support | em0 | Requires root privileges |
| Other Unix | 🔄 Basic Support | eth0 | Uses compatibility mode |

#### Linux Platform Dependency Installation

GYscan requires system dependency packages to be installed on Linux platforms. The installation commands for different distributions are as follows:

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
    libpcap-dev
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
    libpcap-devel
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
    libpcap
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
    pkg-config \
    dbus-1-x11 \
    dbus-1-devel \
    libpcap-devel
```

> **Note**: The build script `build_linux.sh` will automatically detect the system distribution and prompt to install missing dependency packages.

## 📋 Function List

### Official Commands

| Command | Function Description | Status |
|---------|---------------------|--------|
| about | View tool information | ✅ Stable |
| clean | Advanced hacker attack trace detection and cleanup tool | ✅ Stable |
| crunch | Password dictionary generation tool | ✅ Stable |
| database | Database password cracking tool | ✅ Stable |
| dirscan | Website directory scanning tool | ✅ Stable |
| ftp | FTP password cracking | ✅ Stable |
| passhash | Credential passing attack module | ✅ Stable |
| powershell | PowerShell remote execution tool [WinRM service utilization] | ✅ Stable |
| process | Process and service information collection tool | ✅ Stable |
| rdp | RDP remote desktop tool | ✅ Stable |
| route | Route hop detection | ✅ Stable |
| scan | Network scanning tool, supporting host discovery, port scanning, service identification, etc. | ✅ Stable |
| scapy | Advanced network packet manipulation tool, supporting raw packet construction, interface detection and function demonstration | ✅ Stable |
| ssh | SSH password brute force tool (Hydra style) | ✅ Stable |
| userinfo | Local user and group analysis | ✅ Stable |
| webshell | WebShell generation tool | ✅ Stable |
| wmi | WMI remote management tool | ✅ Stable |
| waf | WAF detection tool, supporting mainstream WAF identification and detection | ✅ Stable |
| xss | XSS vulnerability detection tool, supporting reflected, stored, DOM-based XSS detection | ✅ Stable |
| winlog | Windows log viewing tool, supporting local and remote log query | ✅ Stable |
| clean | Advanced hacker attack trace detection and cleanup tool | ✅ Stable |

### Testing Phase Commands

| Command | Function Description | Status |
|---------|---------------------|--------|
| csrf | CSRF vulnerability detection [Testing phase] | ⚠️ Testing phase |
| dcom | DCOM remote execution module [Testing phase] | ⚠️ Testing phase |
| ldap | LDAP enumeration module [Testing phase] | ⚠️ Testing phase |



## 💡 Common Function Usage Examples

### 1. Network Scanning

> [!NOTE]
>
>
> If the scan parameter is a public domain name or public IP, the `-T` parameter cannot be speed level 5, otherwise it will link timeout and show the host as down state, because the connection rate is too fast to connect normally. The recommended connection speed for public networks is level 3-4, and try to keep the connection rate between 500ms and 1s!



```bash
# Scan a single IP address
./GYscan.exe scan --target 192.168.1.100

# Scan IP range
./GYscan.exe scan --target 192.168.1.0/24

# Scan specified port range
./GYscan.exe scan --target 192.168.1.100 --ports 80,443,22,21

### 2. PowerShell Remote Execution

```bash
# Execute remote PowerShell command
./GYscan.exe powershell exec --target 192.168.1.100 --user Administrator --password "Password123" --command "whoami"

# Test WinRM port
./GYscan.exe powershell test --target 192.168.1.100 --port 5985

# Use HTTPS connection
./GYscan.exe powershell exec --target 192.168.1.100 --user Administrator --password "Password123" --command "whoami" --https
```

### 3. WMI Remote Management

```bash
# Get operating system information
./GYscan.exe wmi osinfo --target 192.168.1.100 --user Administrator --password "Password123"

# Execute remote command
./GYscan.exe wmi exec --target 192.168.1.100 --user Administrator --password "Password123" --command "whoami"

# List remote processes
./GYscan.exe wmi processes --target 192.168.1.100 --user Administrator --password "Password123"

# Query WMI data
./GYscan.exe wmi query --target 192.168.1.100 --user Administrator --password "Password123" --query "SELECT * FROM Win32_OperatingSystem"
```

### 4. RDP Remote Desktop

```bash
# Check RDP service availability
./GYscan.exe rdp check --target 192.168.1.100

# Connect to RDP service
./GYscan.exe rdp connect --target 192.168.1.100 --user Administrator --password "Password123"

# List RDP sessions
./GYscan.exe rdp sessions --target 192.168.1.100 --user Administrator --password "Password123"

# List remote processes
./GYscan.exe rdp processes --target 192.168.1.100 --user Administrator --password "Password123"
```

### 5. SMB Protocol Operations

```bash
# Detect SMB version
./GYscan.exe smb version --target 192.168.1.100

# List SMB shares
./GYscan.exe smb shares --target 192.168.1.100 --user Administrator --password "Password123"

# Execute remote command
./GYscan.exe smb exec --target 192.168.1.100 --user Administrator --password "Password123" --command "whoami"
```

### 6. Vulnerability Detection

```bash
# XSS vulnerability detection
./GYscan.exe xss --target http://example.com --payload "<script>alert('xss')</script>"

# CSRF vulnerability detection
./GYscan.exe csrf --target http://example.com/vul/csrf.php -X POST -d "action=delete&id=1"
```

### 7. Weak Password Brute Force

```bash
# SSH weak password detection
./GYscan.exe ssh --target 192.168.1.100 --user admin --wordlist passwords.txt

# FTP weak password detection
./GYscan.exe ftp --target 192.168.1.100 --user anonymous --wordlist passwords.txt

# WAF detection
# Detect single URL
./GYscan.exe waf -u "https://www.example.com/"

# Detect multiple URLs
./GYscan.exe waf -u "https://www.example.com/" -u "https://test.com/"
```

### 8. Windows Log Viewing

```bash
# View local system logs
./GYscan.exe winlog system

# View remote system logs
./GYscan.exe winlog system --target 192.168.1.100 --user admin --password password

# View security logs (login events)
./GYscan.exe winlog security --target 192.168.1.100 --user admin --password password --event-id 4624

# View application logs
./GYscan.exe winlog application --target 192.168.1.100 --user admin --password password --hours 24

# View setup logs
./GYscan.exe winlog setup --target 192.168.1.100 --user admin --password password --event-id 2001

# View forwarded events logs
./GYscan.exe winlog forwardedevents --target 192.168.1.100 --user admin --password password --limit 50

# Use domain account authentication
./GYscan.exe winlog system --target 192.168.1.100 --domain example.com --user admin --password password

# Enable verbose output and color display
./GYscan.exe winlog security --target 192.168.1.100 --user admin --password password --verbose --color
```

### 9. Scapy Network Packet Operations

```bash
# View scapy module help
./GYscan.exe scapy --help

# Network packet construction and sending
./GYscan.exe scapy packet --target 192.168.1.100 --dport 80 --syn
./GYscan.exe scapy packet --target 192.168.1.100 --dport 443 --ack --ttl 128
./GYscan.exe scapy packet --target 192.168.1.100 --dport 53 --udp --payload "test payload"

# Network interface detection
./GYscan.exe scapy interface
./GYscan.exe scapy interface --verbose

# Function demonstration and examples
./GYscan.exe scapy example
```

## ⚙️ Advanced Configuration

### Performance Tuning

```
# Set concurrent threads

./GYscan.exe scan --target 192.168.1.0/24 --threads 50

# Set timeout

./GYscan.exe scan --target 192.168.1.100 --timeout 3
```



### Output Control

```bash
# Silent mode (only output key results)
./GYscan.exe scan --target 192.168.1.100 --silent

# Verbose output mode
./GYscan.exe scan --target 192.168.1.100 --verbose

# More verbose output mode
./GYscan.exe scan --target 192.168.1.100 --very-verbose
```

## 🏗️ Technical Architecture

### Project Structure

```
GYscan/
├── C2/                    # C2 server side (Command and Control)
│   ├── Linux/             # Linux version C2 server
│   │   ├── cmd/           # Command line entry program
│   │   ├── go.mod         # Go module dependency configuration
│   │   ├── go.sum         # Go module verification file
│   │   ├── internal/      # Internal implementation modules
│   │   ├── pkg/           # Public packages (scanners, tools, etc.)
│   │   └── tools/         # Integrated tools (Lynis, Trivy, etc.)
│   └── Windows/           # Windows version C2 server
│       ├── cmd/           # Command line entry program
│       ├── go.mod         # Go module dependency configuration
│       ├── go.sum         # Go module verification file
│       ├── internal/      # Internal implementation modules
│       ├── pkg/           # Public packages (auditors, scanners, etc.)
│       └── tools/         # Integrated tools (Goss, etc.)
├── Client/                # Penetration testing client
│   ├── GYscan.exe         # Compiled Windows executable file
│   ├── app.ico            # Application icon
│   ├── app.manifest       # Application manifest file
│   ├── app.png            # Application image
│   ├── config/            # Configuration file directory
│   │   └── logging.json   # Log configuration file
│   ├── dirmap/            # Directory scanning dictionary files
│   │   ├── dicc.txt       # Directory scanning dictionary
│   │   └── medium.txt     # Medium-scale dictionary
│   ├── go.mod             # Go module dependency configuration
│   ├── go.sum             # Go module verification file
│   ├── internal/          # Internal function modules
│   │   ├── cli/           # Command line interface and command registration
│   │   ├── config/        # Configuration management module
│   │   ├── csrf/          # CSRF vulnerability detection module
│   │   ├── database/      # Database password cracking tool
│   │   ├── dcom/          # DCOM remote execution module
│   │   ├── dirscan/       # Website directory scanning module
│   │   ├── ftp/           # FTP password cracking module
│   │   ├── ldap/          # LDAP enumeration module (testing phase)
│   │   ├── logging/       # Logging system module
│   │   ├── network/       # Network scanning and host discovery
│   │   ├── nmap/          # Nmap integration functions
│   │   ├── plugin/        # Plugin system framework
│   │   ├── powershell/    # PowerShell remote execution module
│   │   ├── process/       # Process and service information collection
│   │   ├── rdp/           # RDP remote desktop module
│   │   ├── reports/       # Report generation module
│   │   ├── security/      # Security related functions
│   │   ├── smb/           # SMB protocol operation module
│   │   ├── ssh/           # SSH password brute force module
│   │   ├── system/        # System operation module
│   │   ├── userinfo/      # Local user and group analysis
│   │   ├── utils/         # Utility functions and helper methods
│   │   ├── waf/           # WAF detection tool
│   │   ├── weakpass/      # Weak password detection framework
│   │   ├── webshell/      # WebShell generation tool
│   │   ├── whois/         # WHOIS information query module
│   │   ├── wmi/           # WMI remote management module
│   │   └── xss/           # XSS vulnerability detection module
│   ├── main.go            # Main program entry file
│   ├── reports/           # Report output directory
│   └── rsrc.syso          # Windows system resource file
├── PSTools/               # Microsoft PSTools suite (Windows system testing tools)
│   ├── PsExec.exe         # Remote command execution tool
│   ├── PsExec64.exe       # 64-bit remote command execution tool
│   ├── PsGetsid.exe       # SID query tool
│   ├── PsGetsid64.exe     # 64-bit SID query tool
│   ├── PsInfo.exe         # System information collection tool
│   ├── PsInfo64.exe       # 64-bit system information collection tool
│   ├── PsService.exe      # Service management tool
│   ├── PsService64.exe    # 64-bit service management tool
│   ├── PsLoggedon.exe     # Logged-on user viewing tool
│   ├── PsLoggedon64.exe   # 64-bit logged-on user viewing tool
│   ├── Pstools.chm        # Help documentation
│   ├── accesschk.exe      # Access permission checking tool
│   ├── psfile.exe         # File share viewing tool
│   ├── psfile64.exe       # 64-bit file share viewing tool
│   ├── pskill.exe         # Process termination tool
│   ├── pskill64.exe       # 64-bit process termination tool
│   ├── pslist.exe         # Process list viewing tool
│   ├── pslist64.exe       # 64-bit process list viewing tool
│   ├── psloglist.exe      # Event log viewing tool
│   ├── psloglist64.exe    # 64-bit event log viewing tool
│   ├── pspasswd.exe       # Password modification tool
│   ├── pspasswd64.exe     # 64-bit password modification tool
│   ├── psping.exe         # Network connectivity testing tool
│   ├── psping64.exe       # 64-bit network connectivity testing tool
│   ├── psshutdown.exe     # Remote shutdown tool
│   ├── psshutdown64.exe   # 64-bit remote shutdown tool
│   ├── pssuspend.exe      # Process suspension tool
│   ├── pssuspend64.exe    # 64-bit process suspension tool
│   ├── Eula.txt           # End User License Agreement
│   └── psversion.txt      # Version information file
├── app.ico                # Application icon file
├── go.mod                 # Go module dependency configuration
├── LICENSE                # Project license file
├── README-en.md           # English project description documentation
├── README.md              # Chinese project description documentation
├── build.ps1              # Windows platform build script
└── build_linux.sh         # Linux platform build script
```

### Detailed Directory Description

#### C2/ - Command and Control Server Side
- **Linux/** - Linux version C2 server
  - **cmd/** - Command line entry program, containing main program logic
  - **internal/** - Internal implementation modules, including system information collection, vulnerability detection and other core functions
  - **pkg/** - Public packages, containing reusable components such as scanners and tools
  - **tools/** - Integrated third-party tools, such as Lynis (system security audit), Trivy (container security scanning)
- **Windows/** - Windows version C2 server
  - **cmd/** - Command line entry program, supporting multiple scan types
  - **internal/** - Internal implementation modules, including Windows system audit, vulnerability detection
  - **pkg/** - Public packages, containing audit managers, scanners, etc.
  - **tools/** - Integrated third-party tools, such as Goss (infrastructure testing)

#### Client/ - Penetration Testing Client
- **internal/** - Core function modules
  - **cli/** - Command line interface and command registration system, supporting command group display, including winlog and other command implementations
  - **csrf/** - CSRF vulnerability detection module, supporting POST request detection
  - **database/** - Database password cracking tool, supporting multiple database types
  - **dcom/** - DCOM remote execution module (testing phase)
  - **dirscan/** - Website directory scanning module, supporting custom dictionaries
  - **ftp/** - FTP password cracking module, supporting anonymous login detection
  - **kerberos/** - Kerberos protocol related function module
  - **ldap/** - LDAP enumeration module (testing phase)
  - **network/** - Network scanning and host discovery, supporting TCP/UDP scanning
  - **nmap/** - Nmap integration functions, supporting full port scanning and service identification
  - **plugin/** - Plugin system framework, supporting function expansion
  - **powershell/** - PowerShell remote execution module, supporting WinRM service utilization
  - **process/** - Process and service information collection tool
  - **rdp/** - RDP remote desktop module, supporting session management and process viewing
  - **security/** - Security related function module
  - **smb/** - SMB protocol operation module, supporting version detection and share enumeration
  - **ssh/** - SSH password brute force module, Hydra style implementation
  - **userinfo/** - Local user and group analysis tool
  - **utils/** - Utility functions and helper methods
  - **waf/** - WAF detection tool, supporting mainstream WAF identification
  - **weakpass/** - Weak password detection framework
  - **webshell/** - WebShell generation tool
  - **wmi/** - WMI remote management module, supporting remote command execution
  - **xss/** - XSS vulnerability detection module, supporting multiple XSS type detection
  - **winlog function** - Windows log viewing tool, supporting local and remote log query, including:
    - System log viewing (System)
    - Security log viewing (Security)
    - Application log viewing (Application)
    - Setup log viewing (Setup)
    - Forwarded events log viewing (ForwardedEvents)
    - Filter by event ID
    - Filter by time range
    - Filter by quantity limit
    - Support for domain account authentication
    - Automatic error recovery and alternative query
- **dirmap/** - Directory scanning dictionary files
  - **dicc.txt** - Common directory scanning dictionary
  - **medium.txt** - Medium-scale directory dictionary

#### PSTools/ - Microsoft PSTools Suite
- Contains a complete set of Windows system testing tools for system management, process control, service management, etc.
- Supports 32-bit and 64-bit systems, providing rich system management functions

### Technology Stack

GYscan is built with modern technology stack to ensure high performance, scalability, and usability:

| Category | Technology/Library | Version | Purpose |
|----------|--------------------|---------|---------|
| **Core Language** | Go | 1.24+ | Main development language |
| **AI Integration** | go-openai | v1.24.0 | OpenAI API client, supporting AI features |
| **CLI Framework** | cobra | v1.9.1 | Command-line interface and command registration system |
| **HTTP Client** | resty/v2 | v2.16.5 | API requests and network communication |
| **HTML Parsing** | goquery | v1.11.0 | Web content parsing and processing |
| **Color Output** | color | v1.18.0 | Command-line colorized output |
| **LDAP Client** | ldap/v3 | v3.4.12 | LDAP protocol support |
| **Database Driver** | go-sql-driver/mysql | v1.9.3 | MySQL database support |
| **Database Driver** | go-mssqldb | v0.12.3 | SQL Server database support |
| **Database Driver** | lib/pq | v1.10.9 | PostgreSQL database support |
| **Database Driver** | go-ora | v1.3.2 | Oracle database support |
| **SMB Protocol** | go-smb2 | v1.1.0 | SMB protocol support |
| **Network Library** | x/net | v0.47.0 | Network programming support |
| **Crypto Library** | x/crypto | v0.44.0 | Cryptographic algorithms support |
| **System Library** | x/sys | v0.38.0 | System calls and OS interaction |
| **YAML Parsing** | yaml.v3 | v3.0.1 | YAML configuration file parsing |
| **Logging Library** | logrus | v1.9.3 | Structured logging |
| **UUID Generation** | google/uuid | v1.6.0 | UUID generation |
| **WHOIS Query** | likexian/whois | v1.15.6 | WHOIS information query |
| **State Machine** | looplab/fsm | v1.0.3 | Finite state machine implementation |
| **WinRM Client** | masterzen/winrm | v0.0.0-20250927112105-5f8e6c707321 | Windows remote management |

### Technical Features

#### High-Performance Concurrency
- **Go Native Concurrency** - Lightweight concurrency model based on goroutines
- **Intelligent Thread Management** - Configurable concurrent thread count
- **Timeout Control** - Configurable timeout mechanism to avoid infinite waiting

#### Security Mechanisms
- **Error Isolation** - Modular error handling to avoid single point of failure
- **Resource Management** - Intelligent resource release to prevent memory leaks
- **Input Validation** - Strict parameter validation to ensure operation security

#### User Experience
- **Real-Time Progress** - Detailed scan progress and statistics
- **Multiple Outputs** - Support for console and file output formats
- **Intelligent Tips** - Friendly error prompts and usage suggestions

#### Extensibility Design
- **Modular Architecture** - Clear module separation, easy for function expansion
- **Configuration Driven** - Flexible configuration system, supporting multiple scenarios
- **Standard Interface** - Unified interface specifications, convenient for secondary development

### Recent Optimizations
- **Important Change**: AI command has been moved from official commands to testing phase commands, status updated to "⚠️ Testing phase"
- **Function Optimization**: scan perfectly supports short domain names, full domain names, IP addresses, and IP network segments
- **UI Optimization**: Change the app mascot and the app icon to the official app icon

### Planned Features
- ⏳ Advanced vulnerability detection plugins
- ⏳ Distributed scanning architecture

## 📝 Changelog

### v2.6.0
Feature Updates:
- **Added scapy module** - Integrated advanced network packet manipulation tool, providing Python Scapy-like low-level network packet operation capabilities
  - **packet subcommand** - Raw network packet construction and sending functionality
    - Support for TCP SYN/ACK/FIN packet construction
    - Support for UDP packet construction and sending
    - Support for custom payload, TTL, window size and other parameters
    - Support for multi-protocol packet construction (Ethernet/IP/TCP/UDP)
  - **interface subcommand** - Network interface detection and status analysis
    - Detect all available network interfaces
    - Display interface detailed information (MAC address, IP address, MTU, etc.)
    - Support interface status classification (enabled/disabled, wired/wireless)
    - Support verbose output mode
  - **example subcommand** - Function demonstration and example code
    - Provide network packet construction examples
    - Showcase interface detection functionality
    - Include practical code examples and best practices
- **Removed scan functionality** - Deleted network scanning functionality in scapy module, focusing on packet construction and interface detection
- **Optimized code structure** - Cleaned up scan-related code and parameters, improving module stability
- **Maintained core functionality** - Preserved packet construction/sending, interface detection, and example demonstration core functions

### v2.5.4
New features:
- **linenum Function ** - Added linenum function, supporting local scanning of targets [including but not limited to]
- Local file system scan
- Local directory traversal
- Local file content reading
- Local system information acquisition
- **linux-kernel Functionality ** - Added linux-kernel functionality, supporting local scanning of targets [including but not limited to]
- Local kernel version acquisition
- Local vulnerability detection
Currently, only the Debain system is supported

### v2.5.3.1
-**Optimization Function**:  Optimize the issue where cracking a single target in the database module and ftp module does not immediately end when a single target is successfully cracked, and add 'ctrl+C' to organize the context and display the successfully cracked target after multiple targets are successfully cracked

### v2.5.2.1

- **Function Fix**: Fixed dirscan module embedded dictionary loading issue, please create a dirmap folder in the software directory, place dicc.txt and mediume.txt, otherwise use the `-w` parameter to specify the file
- **Function Optimization**: Improved dirscan CLI interface, optimized dictionary selection logic and error handling
- **Function Verification**: Verified large dictionary (9756 entries) and medium dictionary (2762 entries) loading functions

### v2.5.2

- **New Function**: Local remote Windows log tool
- **Version Update**: Project version iterated to v2.5.2
- **Function Optimization**: Fixed winlog command help manual parameter display issue, added detailed parameter description and usage examples
- **Function Optimization**: Improved log entry display format, increased message display length limit from 50 characters to 100 characters
- **Bug Fix**: Fixed log query default pagination issue, confirmed program defaults to no pagination display
- **Code Quality**: Improved code stability and readability

### v2.5.1
- **New Function**: Added WAF detection module, supporting detection of multiple WAF types
- **Version Update**: Project version iterated to v2.5.1
- **Function Optimization**: Optimized WAF detection module code, improved string comparison efficiency, used strings.EqualFold instead of strings.ToLower for case-insensitive comparison
- **Bug Fix**: Fixed code yellow warnings related to WAF detection
- **Code Quality**: Improved code stability and readability

### v2.5.0
- **Function Optimization**: Unified command registration mechanism, resolved command duplicate registration issue
- **Function Optimization**: Implemented command group display, divided into official commands and testing phase commands
- **Function Fix**: Fixed format string error in WebShell generator
- **Function Optimization**: Optimized tool help information display, improved user experience
- **New Function**: Improved PowerShell module, added HTTPS support
- **New Function**: Enhanced WMI module functions, supporting more remote management operations
- **New Function**: Improved RDP module, supporting session management and process viewing
- **New Function**: Optimized SMB module, supporting version detection and share enumeration
- **Code Optimization**: Optimized code structure and performance of each module

### v2.0.1
- **Function Optimization**: Removed Payload generation function, focused on security testing
- **Code Optimization**: Optimized code structure and performance
- **Documentation Improvement**: Updated help documentation and examples

### v2.0.0
- **New Function**: Added CSRF vulnerability detection module
- **Function Enhancement**: Improved XSS detection function
- **Module Optimization**: Improved performance and stability of each function module

### v1.0.0
- **Initial Release**: Basic port scanning function
- **Function Implementation**: Service identification and fingerprint collection
- **Framework Construction**: Weak password brute force framework
- **Basic Detection**: Basic vulnerability detection function

## 🤝 Contribution Guide

Welcome to submit Issues and Pull Requests to improve the project. Please ensure:
1. Code conforms to Go language specifications
2. Add appropriate test cases
3. Update relevant documentation
4. Follow secure development specifications

## 📄 License

This project adopts the MIT License. For details, please check the LICENSE file.

## ⚠️ Disclaimer

**Important Note**: This tool is only for security research and authorized testing purposes. Any unauthorized use is illegal, and users shall bear corresponding legal responsibilities. The author does not assume any direct or indirect responsibility arising from the use of this tool.

---

**GYscan - Focus on Internal Network Security, Guard Network Boundaries** 🛡️