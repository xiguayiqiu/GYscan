# AGENTS.md - Development Guidelines for GYscan

This document provides guidelines for agentic coding agents working on the GYscan codebase.

## Project Overview

GYscan is an internal network lateral movement and boundary security testing tool written in Go. The project consists of:
- **Client**: Main penetration testing application (Go 1.24+, located in `/home/yiqiu/GYscan/Client`)
- **C2**: C2 server implementation (located in `/home/yiqiu/GYscan/C2`)

## Build Commands

### Client (Main Application)

```bash
cd /home/yiqiu/GYscan/Client

# Download dependencies
go mod download

# Build for current platform
go build -o GYscan .

# Build with optimization flags
go build -ldflags "-s -w" -o GYscan .

# Clean build cache
go clean -cache

# Set Go proxy for faster downloads (China mirror)
go env -w GOPROXY=https://goproxy.cn,direct
```

### Linux Build Script

```bash
cd /home/yiqiu/GYscan
chmod +x build-linux.sh
./build-linux.sh
```

The script automatically detects the Linux distribution and installs required system dependencies.

### Windows Build

```powershell
cd /home/yiqiu/GYscan
.\build.ps1
```

### Dependencies Required for Linux Build

**Debian/Ubuntu/Kali:**
```bash
sudo apt install -y libx11-dev libxcursor-dev libxrandr-dev libxinerama-dev \
    libxi-dev libxxf86vm-dev libgl1-mesa-dev libglu1-mesa-dev mesa-common-dev \
    build-essential pkg-config dbus-x11 libdbus-1-dev libpcap-dev man-db
```

**RedHat/CentOS/Fedora:**
```bash
sudo yum install -y libX11-devel libXcursor-devel libXrandr-devel libXinerama-devel \
    libXi-devel libXxf86vm-devel mesa-libGL-devel mesa-libGLU-devel mesa-libGLw-devel \
    gcc-c++ pkgconfig dbus-x11 dbus-devel libpcap-devel man-db
```

## Linting and Code Quality

### Go Formatting

```bash
# Format code
gofmt -w /path/to/file.go

# Check formatting (without modifying)
gofmt -d /path/to/file.go
```

### Go Vet

```bash
go vet ./...
```

Note: `golangci-lint` is not currently installed but recommended for future use.

## Testing

### Running Tests

```bash
# Run all tests in Client
cd /home/yiqiu/GYscan/Client
go test ./...

# Run tests for specific package
go test ./internal/utils/...

# Run tests with verbose output
go test -v ./internal/utils/...

# Run a single test function
go test -v -run TestFunctionName ./internal/utils/...

# Run tests with coverage
go test -coverprofile=coverage.out ./...
go tool cover -func=coverage.out
```

### Test File Convention

Test files should follow Go conventions:
- Named `*_test.go`
- Test functions start with `Test` prefix
- Use the `testing` package

## Code Style Guidelines

### Import Organization

Imports should be organized in groups with blank lines between groups:

1. Standard library imports
2. Third-party imports
3. Internal/module imports (prefixed with `GYscan/`)

```go
import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"GYscan/internal/cli"
	"GYscan/internal/config"
	"GYscan/internal/utils"
)
```

### Naming Conventions

**Packages:**
- Use lowercase, single-word names
- Be descriptive: `utils`, `config`, `nmap`, `database`

**Constants:**
- Use CamelCase for exported constants
- Use ALL_CAPS for grouped related constants
- Group constants with a clear prefix when they belong to a feature

```go
// Exported constant
const Version = "v2.7"

// Grouped constants with prefix
const (
	// Port constants
	MinPort = 1
	MaxPort = 65535
	DefaultScanPortRange = "1-1000"

	// Timeout constants
	DefaultTimeout   = 30 * time.Second
	LongTimeout      = 60 * time.Second
	FastTimeout      = 5 * time.Second

	// Thread constants
	ParanoidThreads = 5
	DefaultThreads  = 50
	InsaneThreads   = 500
)
```

**Variables:**
- Use CamelCase
- Prefer short, descriptive names
- Use `err` for error variables

**Types:**
- Use CamelCase for type names
- Use descriptive names that indicate purpose
- Avoid generic names like `Config1`, `Data2`

```go
type DatabaseType string
type DatabaseConfig struct {
	Type     DatabaseType
	Host     string
	Port     int
	Username string
	Password string
	Database string
	SSL      bool
	Timeout  int
	Threads  int
}
```

**Functions:**
- Use CamelCase
- Be descriptive: `ValidateConnection`, `ParsePorts`, `BuildRegistry`
- Getter/setter methods: `GetConfig()`, `SetTimeout()`

**Files:**
- Use lowercase with underscores for multi-word names: `root.go`, `logging.go`, `config_audit.go`

### Error Handling

**Principles:**
1. Return errors to callers instead of logging them immediately (let caller decide)
2. Use `fmt.Errorf` with context for error messages
3. Handle errors explicitly with `if err != nil`

```go
// Good: Return error with context
func (c *DatabaseConfig) Validate() error {
	if c.Host == "" {
		return fmt.Errorf("host cannot be empty")
	}
	if c.Port < 1 || c.Port > 65535 {
		return fmt.Errorf("invalid port number: %d", c.Port)
	}
	return nil
}

// Good: Handle errors explicitly
func TestConnection(ctx context.Context, config *DatabaseConfig) error {
	ctx, cancel := context.WithTimeout(ctx, time.Duration(config.Timeout)*time.Second)
	defer cancel()

	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return fmt.Errorf("failed to open database connection: %v", err)
	}
	defer db.Close()

	err = db.PingContext(ctx)
	if err != nil {
		return fmt.Errorf("connection test failed: %v", err)
	}
	return nil
}
```

**Logging Errors:**

Use the utils package for user-facing logs:

```go
// For configuration errors - warn but continue with defaults
if err := config.InitConfig(); err != nil {
	utils.LogWarning("配置加载失败，使用默认配置: %v", err)
}

// For fatal errors - log and exit
if err := rootCmd.Execute(); err != nil {
	utils.LogError("命令执行失败: %v", err)
	os.Exit(1)
}
```

### Logging Functions (utils package)

Available logging functions in `GYscan/internal/utils`:

```go
// Output functions (print immediately)
utils.SuccessPrint(format string, a ...interface{})
utils.ErrorPrint(format string, a ...interface{})
utils.WarningPrint(format string, a ...interface{})
utils.InfoPrint(format string, a ...interface{})
utils.ProgressPrint(format string, a ...interface{})
utils.ResultPrint(format string, a ...interface{})

// Logging functions (with level semantics)
utils.LogSuccess(format string, a ...interface{})
utils.LogError(format string, a ...interface{})
utils.LogWarning(format string, a ...interface{})
utils.LogInfo(format string, a ...interface{})
utils.LogDebug(format string, a ...interface{})

// Color functions (return colored strings)
utils.Success(format string, a ...interface{}) string
utils.Error(format string, a ...interface{}) string
utils.Warning(format string, a ...interface{}) string
utils.Info(format string, a ...interface{}) string
utils.BoldInfo(format string, a ...interface{}) string
```

### Global Flags and Configuration

The application supports these global flags:

```bash
--no-banner      # Disable startup banner
--no-color       # Disable colored output
-q, --silent     # Silent mode (only critical results)
-v, --verbose    # Detailed output
-V, --version    # Show version
--proxy string   # Proxy server (HTTP/SOCKS5)
--key string     # Traffic encryption key (AES-256)
```

### Context Usage

Use context for cancellation and timeouts:

```go
ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()

// Pass ctx to functions that may take time
result, err := DoLongOperation(ctx, params)
```

### Cobra Command Structure

Commands should follow this pattern:

```go
var (
	target    string
	timeout   int
	verbose   bool
)

var Cmd = &cobra.Command{
	Use:   "commandname [flags]",
	Short: "Brief description of the command",
	Long: `Longer description with examples
	Can span multiple lines`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runCommand()
	},
}

func init() {
	Cmd.Flags().StringVarP(&target, "target", "t", "", "Target to scan")
	Cmd.Flags().IntVarP(&timeout, "timeout", "o", 30, "Timeout in seconds")
	Cmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
}
```

### File Structure (internal packages)

Each feature module in `/home/yiqiu/GYscan/Client/internal/` should follow:

```
internal/
├── modulename/
│   ├── modulename.go      # Main command definition
│   ├── flags.go           # Flag definitions
│   ├── core.go            # Core implementation
│   ├── helper.go          # Helper functions
│   └── ...
```

### Go Module

The project uses Go modules:

- Module name: `GYscan`
- Go version: 1.24.2+
- Dependencies managed via `go.mod` and `go.sum`

### Code Comments

- Use Chinese comments for user-facing documentation (following project convention)
- Use English for code logic explanations
- Comment exported functions and types
- Keep comments concise but descriptive

```go
// Validate 验证配置参数
func (c *DatabaseConfig) Validate() error {
	// 检查主机地址是否为空
	if c.Host == "" {
		return fmt.Errorf("host cannot be empty")
	}
	return nil
}
```

### Performance Considerations

- Pre-compile regex patterns at package level
- Use constants instead of magic numbers
- Use connection pooling and connection limits
- Implement proper timeouts for network operations
- Use goroutines for concurrent operations with proper synchronization

```go
// Pre-compile regex at package level
var mysqlVersionRegex = regexp.MustCompile(`(\d+)\.(\d+)\.(\d+)`)

// Use constants for configuration values
const (
	MaxConnections    = 10
	ConnectionTimeout = 30 * time.Second
	QueryTimeout      = 60 * time.Second
)
```

### Security Considerations

- Never log passwords or sensitive data
- Validate all user inputs
- Use parameterized queries for database operations
- Implement proper error handling without information disclosure
- Follow secure coding practices for penetration testing tools

## Project Structure

```
GYscan/
├── Client/                    # Main application
│   ├── main.go               # Entry point
│   ├── go.mod                # Go module config
│   └── internal/
│       ├── cli/              # Command-line interface
│       ├── config/           # Configuration management
│       ├── utils/            # Utility functions
│       ├── nmap/             # Network scanning
│       ├── database/         # Database modules
│       ├── smb/              # SMB protocol
│       ├── ssh/              # SSH modules
│       ├── ldap/             # LDAP modules
│       └── ...               # Other modules
├── C2/                        # C2 server
│   ├── Linux/
│   ├── Windows/
│   └── ...
├── build-linux.sh            # Linux build script
├── build.ps1                 # Windows build script
└── README.md                 # Documentation
```

## Common Tasks

### Adding a New Command

1. Create new directory in `/home/yiqiu/GYscan/Client/internal/`
2. Create command file with Cobra structure
3. Register command in `/home/yiqiu/GYscan/Client/internal/cli/registry.go`
4. Add to appropriate command group (Stable or Testing)

### Adding a New Module

1. Create new subdirectory in `/home/yiqiu/GYscan/Client/internal/`
2. Create implementation files
3. Export main functionality
4. Import and use in command files

### Modifying Configuration

Configuration files are stored in `~/.GYscan/` with permissions 0600.
