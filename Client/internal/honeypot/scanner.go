package honeypot

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"GYscan/internal/utils"
)

type ServiceScanner struct {
	Timeout time.Duration
	Verbose bool
}

func NewServiceScanner(timeout time.Duration, verbose bool) *ServiceScanner {
	return &ServiceScanner{
		Timeout: timeout,
		Verbose: verbose,
	}
}

func (s *ServiceScanner) ScanPort(target string, port int, protocol string) (*ServiceInfo, error) {
	addr := fmt.Sprintf("%s:%d", target, port)
	
	var conn net.Conn
	var err error
	
	isHTTPS := port == 443 || port == 8443 || port == 4433 || port == 4434 || port == 4435
	
	if isHTTPS {
		conn, err = net.DialTimeout("tcp", addr, s.Timeout)
	} else {
		conn, err = net.DialTimeout(protocol, addr, s.Timeout)
	}
	
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(s.Timeout))

	probe := GetProtocolProbe(port)
	if probe != "" {
		conn.Write([]byte(probe))
		time.Sleep(100 * time.Millisecond)
	}

	if isHTTPS {
		tlsConn := tls.Client(conn, &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         target,
		})
		err = tlsConn.Handshake()
		if err != nil {
			return nil, err
		}
		
		paths := []string{
			"/", "/web/", "/web/scanners", "/web/login", "/web/dashboard", "/web/attack",
			"/login", "/admin", "/dashboard", "/index", "/home",
			"/api/", "/api/v1/", "/api/attack", "/api/node", "/api/login",
			"/static/", "/assets/", "/favicon.ico", "/logo", "/css/", "/js/",
			"/login.html", "/dashboard.html", "/index.html", "/main.html",
			"/hf/", "/hfish/", "/honeypot/", "/manage/", "/console/",
			"/index.php", "/admin.php", "/login.php", "/dashboard.php",
		}
		var fullBanner string
		
		for _, path := range paths {
			httpReq := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nAccept: */*\r\nUser-Agent: GYscan-Honeypot-Detector/1.0\r\nConnection: close\r\n\r\n", path, target)
			tlsConn.Write([]byte(httpReq))
			time.Sleep(100 * time.Millisecond)
			
			bannerReader := bufio.NewReader(tlsConn)
			banner, _ := bannerReader.ReadString('\n')
			banner = strings.TrimSpace(banner)
			
			if banner == "" {
				data, _ := bannerReader.ReadBytes(0)
				if len(data) > 0 {
					banner = strings.TrimSpace(string(data))
				}
			}
			
			remaining, _ := bannerReader.ReadBytes(0)
			if len(remaining) > 0 {
				banner = banner + "\r\n" + strings.TrimSpace(string(remaining))
			}
			
			if len(banner) > len(fullBanner) {
				fullBanner = banner
			}
			
			honeypotIndicators := []string{"HFish", "hfish", "honeypot", "蜜罐", "安全感知", "威胁感知", "dashboard", "login", "Go-http-client", "attack", "scanners", "态势感知", "威胁情报", "攻击地图", "数据大屏", "node", "session"}
			for _, indicator := range honeypotIndicators {
				if strings.Contains(banner, indicator) {
					return &ServiceInfo{
						Port:     port,
						Protocol: "https",
						Banner:   banner,
						Version:  ExtractVersion(banner),
					}, nil
				}
			}
			
			time.Sleep(20 * time.Millisecond)
		}
		
		postPaths := []string{"/api/login", "/login", "/web/login", "/api/v1/login", "/admin/login"}
		for _, path := range postPaths {
			postReq := fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\nAccept: */*\r\nContent-Type: application/json\r\nContent-Length: 0\r\nUser-Agent: GYscan-Honeypot-Detector/1.0\r\nConnection: close\r\n\r\n", path, target)
			tlsConn.Write([]byte(postReq))
			time.Sleep(150 * time.Millisecond)
			
			bannerReader := bufio.NewReader(tlsConn)
			banner, _ := bannerReader.ReadString('\n')
			banner = strings.TrimSpace(banner)
			
			if banner == "" {
				data, _ := bannerReader.ReadBytes(0)
				if len(data) > 0 {
					banner = strings.TrimSpace(string(data))
				}
			}
			
			remaining, _ := bannerReader.ReadBytes(0)
			if len(remaining) > 0 {
				banner = banner + "\r\n" + strings.TrimSpace(string(remaining))
			}
			
			if len(banner) > len(fullBanner) {
				fullBanner = banner
			}
			
			honeypotIndicators := []string{"HFish", "hfish", "honeypot", "蜜罐", "安全感知", "威胁感知", "dashboard", "login", "Go-http-client", "attack", "scanners", "态势感知", "威胁情报", "攻击地图", "数据大屏", "node", "session", "token", "jwt"}
			for _, indicator := range honeypotIndicators {
				if strings.Contains(banner, indicator) {
					return &ServiceInfo{
						Port:     port,
						Protocol: "https",
						Banner:   banner,
						Version:  ExtractVersion(banner),
					}, nil
				}
			}
			
			time.Sleep(20 * time.Millisecond)
		}
		
		banner := fullBanner
		if banner == "" {
			banner = fmt.Sprintf("%s service on port %d", strings.ToUpper(protocol), port)
		}

		return &ServiceInfo{
			Port:     port,
			Protocol: "https",
			Banner:   banner,
			Version:  ExtractVersion(banner),
		}, nil
	}

	bannerReader := bufio.NewReader(conn)
	banner, _ := bannerReader.ReadString('\n')
	banner = strings.TrimSpace(banner)

	if banner == "" {
		data, _ := bannerReader.ReadBytes(0)
		if len(data) > 0 {
			banner = strings.TrimSpace(string(data))
		}
	}

	isHTTP := port == 80 || port == 443 || port == 8080 || port == 8443
	if isHTTP && banner != "" {
		remaining, _ := bannerReader.ReadBytes(0)
		if len(remaining) > 0 {
			banner = banner + "\r\n" + strings.TrimSpace(string(remaining))
		}
	}

	if banner == "" {
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		data, _ := bannerReader.ReadBytes(0)
		if len(data) > 0 {
			banner = strings.TrimSpace(string(data))
		}
	}

	if banner == "" {
		conn.SetReadDeadline(time.Now().Add(s.Timeout))
		buf := make([]byte, 4096)
		n, _ := conn.Read(buf)
		if n > 0 {
			banner = strings.TrimSpace(string(buf[:n]))
		}
	}

	if banner == "" {
		banner = fmt.Sprintf("%s service on port %d", strings.ToUpper(protocol), port)
	}

	return &ServiceInfo{
		Port:     port,
		Protocol: protocol,
		Banner:   banner,
		Version:  ExtractVersion(banner),
	}, nil
}

func GetProtocolProbe(port int) string {
	probes := map[int]string{
		21:  "NOOP\r\n",
		22:  "",
		23:  "",
		25:  "NOOP\r\n",
		80:  "GET / HTTP/1.1\r\nHost: localhost\r\nAccept: */*\r\nConnection: close\r\n\r\n",
		110: "NOOP\r\n",
		143: "NOOP\r\n",
		443: "GET / HTTP/1.1\r\nHost: localhost\r\nAccept: */*\r\nConnection: close\r\n\r\n",
		445: "",
		993: "NOOP\r\n",
		995: "NOOP\r\n",
		1433: "",
		1434: "",
		1521: "",
		3306: "",
		3389: "",
		5432: "",
		5900: "",
		6379: "PING\r\n",
		8080: "GET / HTTP/1.1\r\nHost: localhost\r\nAccept: */*\r\nConnection: close\r\n\r\n",
		8443: "GET / HTTP/1.1\r\nHost: localhost\r\nAccept: */*\r\nConnection: close\r\n\r\n",
	}
	if probe, ok := probes[port]; ok {
		return probe
	}
	return ""
}

func (s *ServiceScanner) DetectService(target string, port int) (*ServiceInfo, error) {
	protocols := []string{"tcp", "tcp"}

	for _, proto := range protocols {
		info, err := s.ScanPort(target, port, proto)
		if err == nil {
			return info, nil
		}
	}

	return nil, fmt.Errorf("no service detected on port %d", port)
}

func (s *ServiceScanner) ScanPorts(target string, ports []int, protocols map[int]string) []*ServiceInfo {
	var results []*ServiceInfo
	for _, port := range ports {
		protocol := protocols[port]
		if protocol == "" {
			protocol = "tcp"
		}

		info, err := s.DetectService(target, port)
		if err != nil {
			if s.Verbose {
				utils.DebugPrint("[*] Port %d: %v", port, err)
			}
			continue
		}

		if s.Verbose {
			utils.InfoPrint("[+] Port %d: %s", port, info.Banner)
		}
		results = append(results, info)
	}
	return results
}

func (s *ServiceScanner) ScanAndIdentify(target string, ports []int) []*ServiceInfo {
	protocols := map[int]string{
		21:  "tcp",
		22:  "tcp",
		23:  "tcp",
		25:  "tcp",
		53:  "udp",
		80:  "tcp",
		110: "tcp",
		143: "tcp",
		443: "tcp",
		445:  "tcp",
		993:  "tcp",
		995:  "tcp",
		1433: "tcp",
		1434: "tcp",
		1521: "tcp",
		3306: "tcp",
		3389: "tcp",
		5432: "tcp",
		5900: "tcp",
		6379: "tcp",
		8080: "tcp",
		8443: "tcp",
	}

	return s.ScanPorts(target, ports, protocols)
}

func ExtractVersion(banner string) string {
	parts := strings.Fields(banner)
	if len(parts) >= 2 {
		if strings.Contains(parts[0], "/") || strings.Contains(parts[0], "-") {
			return parts[0]
		}
		for i, part := range parts {
			if strings.Contains(part, "/") {
				return part
			}
			if i > 0 && (strings.HasPrefix(part, "v") || strings.HasPrefix(part, "V")) {
				return strings.Join(parts[i-1:i+1], " ")
			}
		}
	}

	patterns := []string{
		`([A-Za-z]+[-]?[A-Za-z]*/[0-9]+\.[0-9]+)`,
		`(Version\s*[0-9]+\.[0-9]+)`,
		`([0-9]+\.[0-9]+\.[0-9]+)`,
	}

	for _, pattern := range patterns {
		for _, match := range ExtractByRegex(banner, pattern) {
			if len(match) >= 2 {
				return match[1]
			}
		}
	}

	return ""
}

func ExtractByRegex(s string, pattern string) [][]string {
	re := regexp.MustCompile(pattern)
	return re.FindAllStringSubmatch(s, -1)
}

func IdentifyService(banner string) string {
	bannerLower := strings.ToLower(banner)

	serviceIndicators := map[string][]string{
		"ssh":    {"ssh", "openssh", "dropbear", "tinyssh"},
		"http":   {"http", "nginx", "apache", "iis", "lighttpd", "caddy", "tomcat"},
		"https":  {"https", "nginx", "apache", "iis"},
		"ftp":    {"ftp", "vsftpd", "proftpd", "filezilla", "wu-ftpd"},
		"telnet": {"telnet", "busybox"},
		"mysql":  {"mysql", "mariadb", "percona"},
		"postgres": {"postgresql", "postgres"},
		"rdp":    {"rdp", "terminal", "mstsc"},
		"smb":    {"smb", "samba", "microsoft-ds"},
		"dns":    {"dns", "bind"},
		"ldap":   {"ldap", "openldap"},
		"smtp":   {"smtp", "sendmail", "postfix", "exim", "mail"},
		"pop3":   {"pop3", "dovecot", "courier"},
		"imap":   {"imap", "dovecot", "courier"},
		"vnc":    {"vnc", "x11"},
		"redis":  {"redis"},
		"mongodb": {"mongodb"},
	}

	for service, indicators := range serviceIndicators {
		for _, indicator := range indicators {
			if strings.Contains(bannerLower, indicator) {
				return service
			}
		}
	}

	return "unknown"
}

func (s *ServiceScanner) MeasureResponseTime(target string, port int, protocol string, samples int) ([]time.Duration, error) {
	var times []time.Duration

	for i := 0; i < samples; i++ {
		start := time.Now()
		conn, err := net.DialTimeout(protocol, fmt.Sprintf("%s:%d", target, port), s.Timeout)
		if err != nil {
			break
		}
		conn.Close()
		elapsed := time.Since(start)
		times = append(times, elapsed)
	}

	return times, nil
}

func (s *ServiceScanner) CheckProtocolConsistency(target string, port int, protocol string) (*BehaviorAnalysis, error) {
	analysis := &BehaviorAnalysis{}

	times, err := s.MeasureResponseTime(target, port, protocol, 5)
	if err != nil || len(times) < 2 {
		analysis.Details = "无法进行响应时间测试"
		return analysis, nil
	}

	avgTime := times[len(times)/2]
	_ = avgTime
	variance := CalculateVariance(times)

	if variance < 50*time.Millisecond {
		analysis.ResponseTimeFixed = true
	}

	conn, err := net.DialTimeout(protocol, fmt.Sprintf("%s:%d", target, port), s.Timeout)
	if err != nil {
		analysis.Details = "无法建立连接"
		return analysis, nil
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(s.Timeout))

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err == nil && n > 0 {
		initialBanner := strings.TrimSpace(string(buf[:n]))
		if initialBanner == "" {
			analysis.ProtocolInconsistent = true
			analysis.Details = "协议响应为空"
		}
	}

	if analysis.ResponseTimeFixed && analysis.ProtocolInconsistent {
		analysis.Details = "检测到异常行为：响应时间过于规律，可能为蜜罐"
	} else if analysis.ResponseTimeFixed {
		analysis.Details = "响应时间过于规律，建议进一步检测"
	} else if analysis.ProtocolInconsistent {
		analysis.Details = "协议响应异常，建议进一步检测"
	} else {
		analysis.Details = "未检测到明显异常"
	}

	return analysis, nil
}

func CalculateVariance(times []time.Duration) time.Duration {
	if len(times) == 0 {
		return 0
	}

	var sum time.Duration
	for _, t := range times {
		sum += t
	}
	mean := sum / time.Duration(len(times))

	var varianceSum float64
	for _, t := range times {
		diff := float64(t - mean)
		varianceSum += diff * diff
	}

	return time.Duration(varianceSum / float64(len(times)))
}
