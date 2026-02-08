package nmap

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
)

type TracerouteConfig struct {
	MaxHops    int
	Timeout    time.Duration
	Retries    int
	Port       int
	Protocol   string
	PacketSize int
	FirstTTL   int
}

type TracerouteResult struct {
	Target    string
	Hops      []Hop
	Complete  bool
	StartTime time.Time
	EndTime   time.Time
}

type Hop struct {
	TTL       int
	IP        string
	Hostname  string
	RTT       time.Duration
	ReplyIP   string
	ProbePort int
	Status    string
}

const (
	TraceDefaultMaxHops = 30
	TraceDefaultTimeout = 3 * time.Second
	TraceDefaultRetries = 3
	TraceDefaultPort    = 33434
)

func NewTracerouteConfig() *TracerouteConfig {
	return &TracerouteConfig{
		MaxHops:    TraceDefaultMaxHops,
		Timeout:    TraceDefaultTimeout,
		Retries:    TraceDefaultRetries,
		Port:       TraceDefaultPort,
		Protocol:   "icmp",
		PacketSize: 44,
		FirstTTL:   1,
	}
}

func (c *TracerouteConfig) Validate() {
	if c.MaxHops <= 0 {
		c.MaxHops = TraceDefaultMaxHops
	}
	if c.Timeout <= 0 {
		c.Timeout = TraceDefaultTimeout
	}
	if c.Retries <= 0 {
		c.Retries = TraceDefaultRetries
	}
	if c.Port <= 0 {
		c.Port = TraceDefaultPort
	}
	if c.FirstTTL <= 0 {
		c.FirstTTL = 1
	}
	if c.PacketSize < 44 {
		c.PacketSize = 44
	}
	if c.PacketSize > 1500 {
		c.PacketSize = 1500
	}
}

var (
	traceIPRegex   = regexp.MustCompile(`(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`)
	traceTimeRegex = regexp.MustCompile(`time[=<]?\s*([\d.]+)\s*ms`)
	traceHostRegex = regexp.MustCompile(`from\s+([a-zA-Z0-9.-]+)`)
	traceHopsRegex = regexp.MustCompile(`ttl=(\d+)`)
)

func NewTracerouteResult(target string) *TracerouteResult {
	return &TracerouteResult{
		Target:    target,
		Hops:      make([]Hop, 0),
		Complete:  false,
		StartTime: time.Now(),
	}
}

func Traceroute(ctx context.Context, target string, config *TracerouteConfig) *TracerouteResult {
	result := NewTracerouteResult(target)
	if config == nil {
		config = NewTracerouteConfig()
	}
	config.Validate()

	if runtime.GOOS == "windows" {
		result.Hops = windowsTraceroute(ctx, target, config)
	} else if runtime.GOOS == "linux" {
		result.Hops = linuxTraceroute(ctx, target, config)
	} else if runtime.GOOS == "darwin" {
		result.Hops = macOSTraceroute(ctx, target, config)
	} else {
		result.Hops = fallbackTraceroute(ctx, target, config)
	}

	result.Complete = len(result.Hops) > 0 && result.Hops[len(result.Hops)-1].IP == target
	result.EndTime = time.Now()
	return result
}

func windowsTraceroute(ctx context.Context, target string, config *TracerouteConfig) []Hop {
	var hops []Hop

	for ttl := config.FirstTTL; ttl <= config.MaxHops; ttl++ {
		select {
		case <-ctx.Done():
			return hops
		default:
		}

		hop := Hop{TTL: ttl}

		for retry := 0; retry < config.Retries; retry++ {
			cmd := exec.CommandContext(ctx, "tracert",
				"-h", fmt.Sprintf("%d", ttl),
				"-w", fmt.Sprintf("%d", int(config.Timeout.Milliseconds())),
				"-d",
				target)

			output, err := cmd.CombinedOutput()
			outputStr := string(output)

			if err == nil {
				if ip := traceIPRegex.FindString(outputStr); ip != "" {
					hop.IP = ip
					hop.Status = "success"
					break
				}
			}

			if strings.Contains(outputStr, "Request timed out") {
				hop.Status = "timeout"
				hop.IP = "*"
				break
			}

			if strings.Contains(outputStr, "Destination host unreachable") {
				hop.Status = "unreachable"
				hop.IP = "*"
				break
			}
		}

		hops = append(hops, hop)

		if hop.IP == target {
			break
		}
	}

	return hops
}

func linuxTraceroute(ctx context.Context, target string, config *TracerouteConfig) []Hop {
	var hops []Hop

	for ttl := config.FirstTTL; ttl <= config.MaxHops; ttl++ {
		select {
		case <-ctx.Done():
			return hops
		default:
		}

		hop := Hop{TTL: ttl}

		cmd := exec.CommandContext(ctx, "tracepath",
			"-m", fmt.Sprintf("%d", config.MaxHops),
			"-n",
			"-p", fmt.Sprintf("%d", config.Port),
			target)

		output, err := cmd.CombinedOutput()
		outputStr := string(output)

		if err == nil {
			lines := strings.Split(outputStr, "\n")
			for _, line := range lines {
				if strings.Contains(line, fmt.Sprintf("%d:", ttl)) || strings.Contains(line, target) {
					if ip := traceIPRegex.FindString(line); ip != "" {
						hop.IP = ip
						hop.Status = "success"
						break
					}
				}
			}
		}

		if hop.IP == "" {
			hop.Status = "timeout"
			hop.IP = "*"
		}

		hops = append(hops, hop)

		if hop.IP == target {
			break
		}
	}

	return hops
}

func macOSTraceroute(ctx context.Context, target string, config *TracerouteConfig) []Hop {
	var hops []Hop

	for ttl := config.FirstTTL; ttl <= config.MaxHops; ttl++ {
		select {
		case <-ctx.Done():
			return hops
		default:
		}

		hop := Hop{TTL: ttl}

		cmd := exec.CommandContext(ctx, "traceroute",
			"-n",
			"-m", fmt.Sprintf("%d", config.MaxHops),
			"-w", fmt.Sprintf("%.1f", config.Timeout.Seconds()),
			"-q", fmt.Sprintf("%d", config.Retries),
			target)

		output, err := cmd.CombinedOutput()
		outputStr := string(output)

		if err == nil {
			lines := strings.Split(outputStr, "\n")
			for _, line := range lines {
				if strings.HasPrefix(line, fmt.Sprintf("%d  ", ttl)) || strings.HasPrefix(line, fmt.Sprintf("%d ", ttl)) {
					if ip := traceIPRegex.FindString(line); ip != "" {
						hop.IP = ip
						hop.Status = "success"
						break
					}
				}
			}
		}

		if hop.IP == "" {
			hop.Status = "timeout"
			hop.IP = "*"
		}

		hops = append(hops, hop)

		if hop.IP == target {
			break
		}
	}

	return hops
}

func fallbackTraceroute(ctx context.Context, target string, config *TracerouteConfig) []Hop {
	var hops []Hop
	var mu sync.Mutex
	var wg sync.WaitGroup

	for ttl := config.FirstTTL; ttl <= config.MaxHops; ttl++ {
		select {
		case <-ctx.Done():
			return hops
		default:
		}

		wg.Add(1)
		go func(t int) {
			defer wg.Done()

			hop := Hop{TTL: t}

			switch runtime.GOOS {
			case "windows":
				output, _ := exec.CommandContext(ctx, "tracert",
					"-h", fmt.Sprintf("%d", t),
					"-w", fmt.Sprintf("%d", int(config.Timeout.Milliseconds())),
					"-d",
					target).CombinedOutput()

				if ip := traceIPRegex.FindString(string(output)); ip != "" {
					hop.IP = ip
					hop.Status = "success"
				}
			default:
				output, _ := exec.CommandContext(ctx, "tracepath",
					"-m", fmt.Sprintf("%d", config.MaxHops),
					"-n",
					target).CombinedOutput()

				if ip := traceIPRegex.FindString(string(output)); ip != "" {
					hop.IP = ip
					hop.Status = "success"
				}
			}

			if hop.IP == "" {
				hop.Status = "timeout"
				hop.IP = "*"
			}

			mu.Lock()
			hops = append(hops, hop)
			mu.Unlock()
		}(ttl)
	}

	wg.Wait()
	return hops
}

func (r *TracerouteResult) String() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Traceroute to %s\n", r.Target))
	sb.WriteString(fmt.Sprintf("Maximum hops: %d, Duration: %v\n\n", len(r.Hops), r.EndTime.Sub(r.StartTime)))

	for _, hop := range r.Hops {
		if hop.Hostname != "" {
			sb.WriteString(fmt.Sprintf("%3d  %s (%s)  %v\n", hop.TTL, hop.Hostname, hop.IP, hop.RTT))
		} else {
			sb.WriteString(fmt.Sprintf("%3d  %s  %v\n", hop.TTL, hop.IP, hop.RTT))
		}
	}

	return sb.String()
}

func PerformEnhancedTraceroute(ip string, maxHops int, timeout time.Duration) []Hop {
	config := NewTracerouteConfig()
	config.MaxHops = maxHops
	config.Timeout = timeout

	ctx, cancel := context.WithTimeout(context.Background(), timeout*time.Duration(maxHops))
	defer cancel()

	result := Traceroute(ctx, ip, config)
	return result.Hops
}

func ParseTracerouteOutput(output string) []Hop {
	var hops []Hop

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.Contains(line, "traceroute") || strings.Contains(line, "tracepath") {
			continue
		}

		if ip := traceIPRegex.FindString(line); ip != "" {
			hop := Hop{
				IP:     ip,
				Status: "success",
			}

			if ttl := traceHopsRegex.FindStringSubmatch(line); len(ttl) > 1 {
				fmt.Sscanf(ttl[1], "%d", &hop.TTL)
			}

			if rtt := traceTimeRegex.FindStringSubmatch(line); len(rtt) > 1 {
				if rttVal, err := fmt.Scanf("%f", rtt[1]); err == nil && rttVal > 0 {
					hop.RTT = time.Duration(rttVal) * time.Millisecond
				}
			}

			if host := traceHostRegex.FindStringSubmatch(line); len(host) > 1 {
				hop.Hostname = host[1]
			}

			hops = append(hops, hop)
		}
	}

	return hops
}

func GetNetworkDistance(target string, timeout time.Duration) int {
	config := NewTracerouteConfig()
	config.Timeout = timeout
	config.MaxHops = 15

	ctx, cancel := context.WithTimeout(context.Background(), timeout*15)
	defer cancel()

	result := Traceroute(ctx, target, config)

	for _, hop := range result.Hops {
		if hop.IP == target {
			return hop.TTL
		}
	}

	return -1
}

func DetectNetworkPath(target string) (*TracerouteResult, error) {
	config := NewTracerouteConfig()
	config.MaxHops = 20
	config.Timeout = 2 * time.Second

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	result := Traceroute(ctx, target, config)

	if len(result.Hops) == 0 {
		return nil, fmt.Errorf("无法到达目标主机")
	}

	return result, nil
}

func TraceWithUDP(target string, maxHops int, timeout time.Duration) []Hop {
	var hops []Hop

	conn, err := net.DialTimeout("udp", fmt.Sprintf("%s:%d", target, 33434), timeout)
	if err != nil {
		return hops
	}
	defer conn.Close()

	for ttl := 1; ttl <= maxHops; ttl++ {
		hop := Hop{
			TTL:    ttl,
			IP:     "*",
			Status: "timeout",
		}

		hops = append(hops, hop)

		replyIP := conn.RemoteAddr().(*net.UDPAddr).IP.String()
		if replyIP == target {
			hop.IP = target
			hop.Status = "success"
			break
		}
	}

	return hops
}
