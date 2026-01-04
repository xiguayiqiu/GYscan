package configaudit

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
)

type OSType string

const (
	OSWindows OSType = "windows"
	OSLinux   OSType = "linux"
	OSMacOS   OSType = "macos"
	OSUnknown OSType = "unknown"
	OSAuto    OSType = "auto"
)

type SystemInfo struct {
	OSType      OSType
	OSVersion   string
	OSName      string
	Kernel      string
	Arch        string
	Hostname    string
	CPUCores    int
	MemoryTotal uint64
	IsContainer bool
	IsVM        bool
}

type RemoteTargetInfo struct {
	Target      string
	OSType      OSType
	PortOpen    map[int]bool
	Services    []string
	NetworkInfo map[string]string
}

func DetectLocalSystem() *SystemInfo {
	info := &SystemInfo{
		OSType:   OSUnknown,
		Arch:     runtime.GOARCH,
		CPUCores: runtime.NumCPU(),
	}

	switch runtime.GOOS {
	case "windows":
		info.OSType = OSWindows
		info.OSName = "Windows"
		if info.Kernel = getWindowsVersion(); info.Kernel != "" {
			info.OSVersion = info.Kernel
		}
	case "linux":
		info.OSType = OSLinux
		if info.OSName = getLinuxDistribution(); info.OSName != "" {
		}
		if info.Kernel = getLinuxKernel(); info.Kernel != "" {
		}
		if info.IsContainer = detectContainer(); info.IsContainer {
			info.OSName += " (Container)"
		}
		if info.IsVM = detectVM(); info.IsVM {
			info.OSName += " (VM)"
		}
	case "darwin":
		info.OSType = OSMacOS
		info.OSName = "macOS"
		if info.Kernel = getMacOSVersion(); info.Kernel != "" {
			info.OSVersion = info.Kernel
		}
	}

	info.Hostname, _ = os.Hostname()

	return info
}

func getWindowsVersion() string {
	methods := []struct {
		name string
		fn   func() string
	}{
		{"wmic", getWindowsVersionWMIC},
		{"powershell", getWindowsVersionPowerShell},
		{"registry", getWindowsVersionRegistry},
	}

	for _, method := range methods {
		if version := method.fn(); version != "" {
			return version
		}
	}

	return ""
}

func getWindowsVersionWMIC() string {
	cmd := exec.Command("wmic", "os", "get", "Version,CSDVersion,ReleaseId", "/value")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return ""
	}

	outputStr := string(output)
	versionMatch := regexp.MustCompile(`Version=(\d+\.\d+\.\d+)`)
	if match := versionMatch.FindStringSubmatch(outputStr); len(match) > 1 {
		return match[1]
	}

	return ""
}

func getWindowsVersionPowerShell() string {
	cmd := exec.Command("powershell", "-Command",
		"Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object -ExpandProperty Version")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}

	version := strings.TrimSpace(string(output))
	if matched, _ := regexp.MatchString(`^\d+\.\d+\.\d+`, version); matched {
		return version
	}

	return ""
}

func getWindowsVersionRegistry() string {
	cmd := exec.Command("reg", "query", `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`, "/v", "CurrentVersion")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}

	outputStr := string(output)
	versionMatch := regexp.MustCompile(`CurrentVersion\s+REG_SZ\s+(\d+\.\d+)`)
	if match := versionMatch.FindStringSubmatch(outputStr); len(match) > 1 {
		return match[1] + ".0"
	}

	return ""
}

func getLinuxDistribution() string {
	distFiles := []string{
		"/etc/os-release",
		"/etc/redhat-release",
		"/etc/centos-release",
		"/etc/debian_version",
		"/etc/SuSe-release",
		"/etc/alpine-release",
		"/etc/arch-release",
	}

	for _, file := range distFiles {
		if fileContent, err := readFileSimple(file); err == nil {
			contentStr := strings.TrimSpace(string(fileContent))
			if contentStr != "" {
				if strings.Contains(file, "os-release") {
					nameMatch := regexp.MustCompile(`PRETTY_NAME="([^"]+)"`)
					if match := nameMatch.FindStringSubmatch(contentStr); len(match) > 1 {
						return match[1]
					}
				}
				lines := strings.Split(contentStr, "\n")
				if len(lines) > 0 {
					return strings.TrimSpace(lines[0])
				}
			}
		}
	}

	return "Linux"
}

func getLinuxKernel() string {
	cmd := exec.Command("uname", "-r")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(output))
}

func getMacOSVersion() string {
	cmd := exec.Command("sw_vers", "-productVersion")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(output))
}

func detectContainer() bool {
	containerIndicators := []string{
		"/.dockerenv",
		"/run/.containerenv",
		"/proc/1/cgroup",
	}

	cgroupPath := "/proc/1/cgroup"
	if cgroup, err := readFileSimple(cgroupPath); err == nil {
		cgroupStr := string(cgroup)
		if strings.Contains(cgroupStr, "docker") ||
			strings.Contains(cgroupStr, "containerd") ||
			strings.Contains(cgroupStr, "kubepods") {
			return true
		}
	}

	for _, indicator := range containerIndicators {
		if _, err := os.Stat(indicator); err == nil {
			return true
		}
	}

	return false
}

func detectVM() bool {
	vendorPath := "/sys/class/dmi/id/sys_vendor"
	if vendor, err := readFileSimple(vendorPath); err == nil {
		vendorStr := string(vendor)
		vmVendors := []string{"VMware", "VirtualBox", "QEMU", "KVM", "Hyper-V", "Bochs", "Parallels"}
		for _, vm := range vmVendors {
			if strings.Contains(strings.ToLower(vendorStr), strings.ToLower(vm)) {
				return true
			}
		}
	}

	return false
}

func DetectRemoteSystem(target string, timeout time.Duration) (*RemoteTargetInfo, error) {
	info := &RemoteTargetInfo{
		Target:      target,
		PortOpen:    make(map[int]bool),
		Services:    []string{},
		NetworkInfo: make(map[string]string),
	}

	commonPorts := []int{22, 135, 139, 445, 3389, 5985, 8080}

	var wg sync.WaitGroup
	var mu sync.Mutex
	wg.Add(len(commonPorts))

	for _, port := range commonPorts {
		go func(p int) {
			defer wg.Done()
			open := checkPort(target, p, timeout)
			mu.Lock()
			info.PortOpen[p] = open
			mu.Unlock()

			if open {
				service := identifyService(p, target, timeout)
				if service != "" {
					mu.Lock()
					info.Services = append(info.Services, fmt.Sprintf("%d:%s", p, service))
					mu.Unlock()
				}
			}
		}(port)
	}

	wg.Wait()

	info.OSType = identifyOSType(info.PortOpen, info.Services)

	return info, nil
}

func checkPort(host string, port int, timeout time.Duration) bool {
	host, portStr, err := net.SplitHostPort(host)
	if err != nil {
		host = net.JoinHostPort(host, fmt.Sprintf("%d", port))
	} else {
		host = net.JoinHostPort(host, portStr)
	}
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	return true
}

func identifyService(port int, host string, timeout time.Duration) string {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(timeout))
	buffer := make([]byte, 1024)
	n, _ := conn.Read(buffer)
	if n > 0 {
		data := string(buffer[:n])

		serviceSignatures := map[string]string{
			"SSH":   "SSH",
			"RDP":   "\x03\x00",
			"SMB":   "\xffSMB",
			"HTTP":  "HTTP/",
			"HTTPS": "HTTP/",
			"WinRM": "HTTP/",
			"SMTP":  "220",
			"POP3":  "+OK",
			"IMAP":  "* OK",
			"DNS":   "",
			"Ldap":  "ldap",
		}

		for service, sig := range serviceSignatures {
			if sig == "" && port == 53 {
				return "DNS"
			}
			if sig != "" && strings.Contains(data, sig) {
				return service
			}
		}

		portServices := map[int]string{
			22:   "SSH",
			23:   "Telnet",
			25:   "SMTP",
			53:   "DNS",
			80:   "HTTP",
			110:  "POP3",
			135:  "MSRPC",
			139:  "NetBIOS",
			143:  "IMAP",
			443:  "HTTPS",
			445:  "SMB",
			3389: "RDP",
			5985: "WinRM",
			5986: "WinRM HTTPS",
			8080: "HTTP Proxy",
			8443: "HTTPS Alt",
		}

		if service, ok := portServices[port]; ok {
			return service
		}
	}

	return ""
}

func identifyOSType(portOpen map[int]bool, services []string) OSType {
	windowsIndicators := 0
	linuxIndicators := 0

	windowsPorts := []int{135, 139, 445, 3389, 5985}
	for _, port := range windowsPorts {
		if portOpen[port] {
			windowsIndicators++
		}
	}

	linuxPorts := []int{22}
	for _, port := range linuxPorts {
		if portOpen[port] {
			linuxIndicators++
		}
	}

	for _, service := range services {
		if strings.Contains(service, "MSRPC") ||
			strings.Contains(service, "SMB") ||
			strings.Contains(service, "RDP") ||
			strings.Contains(service, "WinRM") {
			windowsIndicators++
		}
		if strings.Contains(service, "SSH") {
			linuxIndicators++
		}
	}

	if windowsIndicators > linuxIndicators {
		return OSWindows
	}
	if linuxIndicators > windowsIndicators {
		return OSLinux
	}

	if portOpen[22] && !portOpen[135] {
		return OSLinux
	}

	return OSUnknown
}

func IsWindowsSystem(osType OSType) bool {
	return osType == OSWindows
}

func IsLinuxSystem(osType OSType) bool {
	return osType == OSLinux
}

func GetConnectionModeForOS(osType OSType) ConnectionMode {
	switch osType {
	case OSWindows:
		return ConnectionModeWMI
	case OSLinux:
		return ConnectionModeSSH
	default:
		return ConnectionModeAuto
	}
}

func readFileSimple(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	content, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, err
	}

	return content, nil
}

type ConnectionMode string

const (
	ConnectionModeAuto ConnectionMode = "auto"
	ConnectionModeSSH  ConnectionMode = "ssh"
	ConnectionModeWMI  ConnectionMode = "wmi"
	ConnectionModeNone ConnectionMode = "none"
)

func (m ConnectionMode) String() string {
	return string(m)
}

func ParseConnectionMode(mode string) ConnectionMode {
	switch strings.ToLower(mode) {
	case "ssh":
		return ConnectionModeSSH
	case "wmi":
		return ConnectionModeWMI
	case "auto":
		return ConnectionModeAuto
	default:
		return ConnectionModeAuto
	}
}
