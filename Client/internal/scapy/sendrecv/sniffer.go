package sendrecv

import (
	"fmt"
	"net"
	"time"

	"GYscan/internal/scapy/core"

	"github.com/google/gopacket"
	gplayers "github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// Sniffer 包捕获器
type Sniffer struct {
	iface      *net.Interface // 网络接口
	handle     *pcap.Handle   // pcap句柄
	filter     string         // BPF过滤器
	bufferSize int            // 缓冲区大小
	timeout    time.Duration  // 超时时间
	promisc    bool           // 混杂模式
}

// SnifferConfig 捕获器配置
type SnifferConfig struct {
	Filter     string        // BPF过滤器
	BufferSize int           // 缓冲区大小
	Timeout    time.Duration // 超时时间
	Promisc    bool          // 混杂模式
	Snaplen    int           // 快照长度
}

// DefaultSnifferConfig 默认捕获器配置
var DefaultSnifferConfig = SnifferConfig{
	Filter:     "",
	BufferSize: 65536,
	Timeout:    30 * time.Second,
	Promisc:    false,
	Snaplen:    65536,
}

// NewSniffer 创建新的包捕获器
func NewSniffer(ifaceName string, config SnifferConfig) (*Sniffer, error) {
	// 获取网络接口
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("failed to get interface %s: %v", ifaceName, err)
	}

	// 打开pcap句柄
	handle, err := pcap.OpenLive(ifaceName, int32(config.Snaplen), config.Promisc, config.Timeout)
	if err != nil {
		return nil, fmt.Errorf("failed to open pcap handle: %v", err)
	}

	// 设置BPF过滤器
	if config.Filter != "" {
		err = handle.SetBPFFilter(config.Filter)
		if err != nil {
			handle.Close()
			return nil, fmt.Errorf("failed to set BPF filter: %v", err)
		}
	}

	return &Sniffer{
		iface:      iface,
		handle:     handle,
		filter:     config.Filter,
		bufferSize: config.BufferSize,
		timeout:    config.Timeout,
		promisc:    config.Promisc,
	}, nil
}

// Close 关闭捕获器
func (s *Sniffer) Close() error {
	if s.handle != nil {
		s.handle.Close()
	}
	return nil
}

// StartCapture 开始捕获数据包
func (s *Sniffer) StartCapture() (<-chan *core.PacketInfo, <-chan error) {
	packetChan := make(chan *core.PacketInfo, s.bufferSize)
	errChan := make(chan error, 1)

	go func() {
		defer close(packetChan)
		defer close(errChan)

		// 创建包源
		packetSource := gopacket.NewPacketSource(s.handle, s.handle.LinkType())
		packetSource.DecodeOptions.Lazy = true
		packetSource.DecodeOptions.NoCopy = true

		for packet := range packetSource.Packets() {
			packetInfo := s.parsePacket(packet)
			packetChan <- packetInfo
		}
	}()

	return packetChan, errChan
}

// CapturePackets 捕获指定数量的数据包
func (s *Sniffer) CapturePackets(count int) ([]*core.PacketInfo, error) {
	var packets []*core.PacketInfo

	packetChan, errChan := s.StartCapture()

	for i := 0; i < count; i++ {
		select {
		case packet, ok := <-packetChan:
			if !ok {
				return packets, nil
			}
			packets = append(packets, packet)

		case err := <-errChan:
			return packets, err

		case <-time.After(s.timeout):
			return packets, fmt.Errorf("capture timeout after %v", s.timeout)
		}
	}

	s.Close()
	return packets, nil
}

// CaptureWithTimeout 在指定时间内捕获数据包
func (s *Sniffer) CaptureWithTimeout(timeout time.Duration) ([]*core.PacketInfo, error) {
	var packets []*core.PacketInfo

	packetChan, errChan := s.StartCapture()
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	for {
		select {
		case packet, ok := <-packetChan:
			if !ok {
				return packets, nil
			}
			packets = append(packets, packet)

		case err := <-errChan:
			return packets, err

		case <-timer.C:
			s.Close()
			return packets, nil
		}
	}
}

// parsePacket 解析gopacket包到PacketInfo
func (s *Sniffer) parsePacket(packet gopacket.Packet) *core.PacketInfo {
	packetInfo := &core.PacketInfo{
		Timestamp: packet.Metadata().Timestamp,
		Length:    len(packet.Data()),
		RawData:   packet.Data(),
		Layers:    make([]core.LayerInfo, 0),
	}

	// 解析各层协议
	for _, layer := range packet.Layers() {
		switch layer.LayerType() {
		case gplayers.LayerTypeEthernet:
			ethLayer := packet.Layer(gplayers.LayerTypeEthernet)
			if eth, ok := ethLayer.(*gplayers.Ethernet); ok {
				layerInfo := s.parseEthernetLayer(eth)
				packetInfo.Layers = append(packetInfo.Layers, *layerInfo)
			}

		case gplayers.LayerTypeIPv4:
			ipLayer := packet.Layer(gplayers.LayerTypeIPv4)
			if ip, ok := ipLayer.(*gplayers.IPv4); ok {
				layerInfo := s.parseIPLayer(ip)
				packetInfo.Layers = append(packetInfo.Layers, *layerInfo)
			}

		case gplayers.LayerTypeTCP:
			tcpLayer := packet.Layer(gplayers.LayerTypeTCP)
			if tcp, ok := tcpLayer.(*gplayers.TCP); ok {
				layerInfo := s.parseTCPLayer(tcp)
				packetInfo.Layers = append(packetInfo.Layers, *layerInfo)
			}

		case gplayers.LayerTypeUDP:
			udpLayer := packet.Layer(gplayers.LayerTypeUDP)
			if udp, ok := udpLayer.(*gplayers.UDP); ok {
				layerInfo := s.parseUDPLayer(udp)
				packetInfo.Layers = append(packetInfo.Layers, *layerInfo)
			}

		default:
			// 其他协议层
			layerInfo := core.LayerInfo{
				Type: layer.LayerType().String(),
				Data: layer.LayerContents(),
			}
			packetInfo.Layers = append(packetInfo.Layers, layerInfo)
		}
	}

	return packetInfo
}

// parseEthernetLayer 解析以太网层
func (s *Sniffer) parseEthernetLayer(eth *gplayers.Ethernet) *core.LayerInfo {
	return &core.LayerInfo{
		Type: "ethernet",
		Fields: map[string]interface{}{
			"src_mac":   eth.SrcMAC.String(),
			"dst_mac":   eth.DstMAC.String(),
			"ethertype": eth.EthernetType,
		},
		Data: eth.LayerContents(),
	}
}

// parseIPLayer 解析IP层
func (s *Sniffer) parseIPLayer(ip *gplayers.IPv4) *core.LayerInfo {
	return &core.LayerInfo{
		Type: "ip",
		Fields: map[string]interface{}{
			"src_ip":      ip.SrcIP.String(),
			"dst_ip":      ip.DstIP.String(),
			"protocol":    ip.Protocol,
			"ttl":         ip.TTL,
			"length":      ip.Length,
			"id":          ip.Id,
			"frag_offset": ip.FragOffset,
		},
		Data: ip.LayerContents(),
	}
}

// parseTCPLayer 解析TCP层
func (s *Sniffer) parseTCPLayer(tcp *gplayers.TCP) *core.LayerInfo {
	flags := ""
	if tcp.FIN {
		flags += "F"
	}
	if tcp.SYN {
		flags += "S"
	}
	if tcp.RST {
		flags += "R"
	}
	if tcp.PSH {
		flags += "P"
	}
	if tcp.ACK {
		flags += "A"
	}
	if tcp.URG {
		flags += "U"
	}
	if tcp.ECE {
		flags += "E"
	}
	if tcp.CWR {
		flags += "C"
	}

	return &core.LayerInfo{
		Type: "tcp",
		Fields: map[string]interface{}{
			"src_port": tcp.SrcPort,
			"dst_port": tcp.DstPort,
			"seq":      tcp.Seq,
			"ack":      tcp.Ack,
			"flags":    flags,
			"window":   tcp.Window,
			"urgent":   tcp.Urgent,
		},
		Data: tcp.LayerContents(),
	}
}

// parseUDPLayer 解析UDP层
func (s *Sniffer) parseUDPLayer(udp *gplayers.UDP) *core.LayerInfo {
	return &core.LayerInfo{
		Type: "udp",
		Fields: map[string]interface{}{
			"src_port": udp.SrcPort,
			"dst_port": udp.DstPort,
			"length":   udp.Length,
		},
		Data: udp.LayerContents(),
	}
}

// SetFilter 设置BPF过滤器
func (s *Sniffer) SetFilter(filter string) error {
	err := s.handle.SetBPFFilter(filter)
	if err != nil {
		return err
	}
	s.filter = filter
	return nil
}

// GetInterface 获取网络接口
func (s *Sniffer) GetInterface() *net.Interface {
	return s.iface
}

// GetFilter 获取当前过滤器
func (s *Sniffer) GetFilter() string {
	return s.filter
}

// GetStats 获取捕获统计信息
func (s *Sniffer) GetStats() (*pcap.Stats, error) {
	return s.handle.Stats()
}

// ListInterfaces 列出所有可用网络接口
func ListInterfaces() ([]net.Interface, error) {
	return net.Interfaces()
}

// FindInterfaceByName 按名称查找网络接口
func FindInterfaceByName(name string) (*net.Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range ifaces {
		if iface.Name == name {
			return &iface, nil
		}
	}

	return nil, fmt.Errorf("interface %s not found", name)
}

// FindInterfaceByIP 按IP地址查找网络接口
func FindInterfaceByIP(ip string) (*net.Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	targetIP := net.ParseIP(ip)
	if targetIP == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ip)
	}

	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				if ipnet.IP.Equal(targetIP) {
					return &iface, nil
				}
			}
		}
	}

	return nil, fmt.Errorf("interface with IP %s not found", ip)
}

// CommonFilters 常用BPF过滤器
const (
	FilterTCP   = "tcp"
	FilterUDP   = "udp"
	FilterICMP  = "icmp"
	FilterHTTP  = "tcp port 80"
	FilterHTTPS = "tcp port 443"
	FilterDNS   = "udp port 53"
	FilterDHCP  = "udp port 67 or udp port 68"
	FilterSSH   = "tcp port 22"
	FilterSMTP  = "tcp port 25"
	FilterFTP   = "tcp port 21"
)

// PacketHandler 包处理函数类型
type PacketHandler func(packet *core.PacketInfo) error

// AsyncSniffer 异步捕获器
type AsyncSniffer struct {
	*Sniffer
	handler  PacketHandler
	stopChan chan struct{}
}

// NewAsyncSniffer 创建异步捕获器
func NewAsyncSniffer(ifaceName string, config SnifferConfig, handler PacketHandler) (*AsyncSniffer, error) {
	sniffer, err := NewSniffer(ifaceName, config)
	if err != nil {
		return nil, err
	}

	return &AsyncSniffer{
		Sniffer:  sniffer,
		handler:  handler,
		stopChan: make(chan struct{}),
	}, nil
}

// Start 开始异步捕获
func (as *AsyncSniffer) Start() error {
	packetChan, errChan := as.StartCapture()

	go func() {
		for {
			select {
			case packet, ok := <-packetChan:
				if !ok {
					return
				}

				if err := as.handler(packet); err != nil {
					// 处理错误，但不停止捕获
					fmt.Printf("Packet handler error: %v\n", err)
				}

			case err := <-errChan:
				fmt.Printf("Capture error: %v\n", err)
				return

			case <-as.stopChan:
				return
			}
		}
	}()

	return nil
}

// Stop 停止异步捕获
func (as *AsyncSniffer) Stop() {
	close(as.stopChan)
	as.Close()
}
