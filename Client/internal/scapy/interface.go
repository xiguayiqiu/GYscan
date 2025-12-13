package scapy

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"GYscan/internal/utils"
)

// InterfaceInfo 网络接口信息
type InterfaceInfo struct {
	Name        string   // 接口名称
	Description string   // 接口描述
	MACAddress  string   // MAC地址
	IPAddresses []string // IP地址列表
	MTU         int      // MTU值
	Flags       string   // 接口标志
	IsUp        bool     // 是否启用
	IsLoopback  bool     // 是否回环接口
	IsWireless  bool     // 是否无线接口
	IsEthernet  bool     // 是否以太网接口
}

// InterfaceDetector 网卡检测器
type InterfaceDetector struct {
	interfaces []InterfaceInfo
}

// NewInterfaceDetector 创建新的网卡检测器
func NewInterfaceDetector() *InterfaceDetector {
	return &InterfaceDetector{}
}

// DetectInterfaces 检测所有网络接口
func (d *InterfaceDetector) DetectInterfaces() ([]InterfaceInfo, error) {
	// 获取所有网络接口
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("获取网络接口失败: %v", err)
	}

	var interfaceList []InterfaceInfo

	for _, iface := range ifaces {
		info := d.analyzeInterface(iface)
		interfaceList = append(interfaceList, info)
	}

	// 按接口名称排序
	sort.Slice(interfaceList, func(i, j int) bool {
		return interfaceList[i].Name < interfaceList[j].Name
	})

	d.interfaces = interfaceList
	return interfaceList, nil
}

// analyzeInterface 分析单个网络接口
func (d *InterfaceDetector) analyzeInterface(iface net.Interface) InterfaceInfo {
	info := InterfaceInfo{
		Name:        iface.Name,
		Description: iface.Name,
		MACAddress:  iface.HardwareAddr.String(),
		MTU:         iface.MTU,
		Flags:       iface.Flags.String(),
		IsUp:        iface.Flags&net.FlagUp != 0,
		IsLoopback:  iface.Flags&net.FlagLoopback != 0,
		IsWireless:  d.isWirelessInterface(iface.Name),
		IsEthernet:  d.isEthernetInterface(iface.Name),
	}

	// 获取接口的IP地址
	addrs, err := iface.Addrs()
	if err == nil {
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				if ipnet.IP.To4() != nil {
					info.IPAddresses = append(info.IPAddresses, ipnet.IP.String())
				}
			}
		}
	}

	// 设置接口描述
	info.Description = d.getInterfaceDescription(iface.Name)

	return info
}

// isWirelessInterface 判断是否为无线接口
func (d *InterfaceDetector) isWirelessInterface(name string) bool {
	wirelessKeywords := []string{"wlan", "wireless", "wi-fi", "wifi", "ath", "wlp"}
	nameLower := strings.ToLower(name)

	for _, keyword := range wirelessKeywords {
		if strings.Contains(nameLower, keyword) {
			return true
		}
	}

	return false
}

// isEthernetInterface 判断是否为以太网接口
func (d *InterfaceDetector) isEthernetInterface(name string) bool {
	ethernetKeywords := []string{"eth", "ethernet", "en", "lan", "local area"}
	nameLower := strings.ToLower(name)

	for _, keyword := range ethernetKeywords {
		if strings.Contains(nameLower, keyword) {
			return true
		}
	}

	// 排除无线和回环接口
	if d.isWirelessInterface(name) || strings.Contains(nameLower, "lo") {
		return false
	}

	// 默认认为是以太网接口
	return true
}

// getInterfaceDescription 获取接口描述
func (d *InterfaceDetector) getInterfaceDescription(name string) string {
	descriptions := map[string]string{
		"lo":                    "Loopback Interface",
		"eth0":                  "Primary Ethernet Interface",
		"eth1":                  "Secondary Ethernet Interface",
		"wlan0":                 "Primary Wireless Interface",
		"wlan1":                 "Secondary Wireless Interface",
		"en0":                   "Primary Network Interface",
		"en1":                   "Secondary Network Interface",
		"WLAN":                  "Wireless LAN Adapter",
		"Ethernet":              "Ethernet Adapter",
		"Local Area Connection": "Local Area Network",
	}

	// 精确匹配
	if desc, exists := descriptions[name]; exists {
		return desc
	}

	// 模糊匹配
	nameLower := strings.ToLower(name)
	for key, desc := range descriptions {
		if strings.Contains(nameLower, strings.ToLower(key)) {
			return desc
		}
	}

	// 根据接口类型生成描述
	if d.isWirelessInterface(name) {
		return "Wireless Network Interface"
	} else if d.isEthernetInterface(name) {
		return "Ethernet Network Interface"
	} else if strings.Contains(nameLower, "lo") {
		return "Loopback Interface"
	}

	return "Network Interface"
}

// GetInterfaceByName 按名称获取接口信息
func (d *InterfaceDetector) GetInterfaceByName(name string) (*InterfaceInfo, error) {
	if d.interfaces == nil {
		_, err := d.DetectInterfaces()
		if err != nil {
			return nil, err
		}
	}

	for _, iface := range d.interfaces {
		if iface.Name == name {
			return &iface, nil
		}
	}

	return nil, fmt.Errorf("接口 %s 未找到", name)
}

// GetInterfaceByIP 按IP地址获取接口信息
func (d *InterfaceDetector) GetInterfaceByIP(ip string) (*InterfaceInfo, error) {
	if d.interfaces == nil {
		_, err := d.DetectInterfaces()
		if err != nil {
			return nil, err
		}
	}

	targetIP := net.ParseIP(ip)
	if targetIP == nil {
		return nil, fmt.Errorf("无效的IP地址: %s", ip)
	}

	for _, iface := range d.interfaces {
		for _, addr := range iface.IPAddresses {
			ifaceIP := net.ParseIP(addr)
			if ifaceIP != nil && ifaceIP.Equal(targetIP) {
				return &iface, nil
			}
		}
	}

	return nil, fmt.Errorf("未找到拥有IP地址 %s 的接口", ip)
}

// GetActiveInterfaces 获取活动的网络接口
func (d *InterfaceDetector) GetActiveInterfaces() []InterfaceInfo {
	if d.interfaces == nil {
		_, err := d.DetectInterfaces()
		if err != nil {
			return nil
		}
	}

	var activeInterfaces []InterfaceInfo
	for _, iface := range d.interfaces {
		if iface.IsUp && !iface.IsLoopback && len(iface.IPAddresses) > 0 {
			activeInterfaces = append(activeInterfaces, iface)
		}
	}

	return activeInterfaces
}

// GetWirelessInterfaces 获取无线网络接口
func (d *InterfaceDetector) GetWirelessInterfaces() []InterfaceInfo {
	if d.interfaces == nil {
		_, err := d.DetectInterfaces()
		if err != nil {
			return nil
		}
	}

	var wirelessInterfaces []InterfaceInfo
	for _, iface := range d.interfaces {
		if iface.IsWireless && iface.IsUp {
			wirelessInterfaces = append(wirelessInterfaces, iface)
		}
	}

	return wirelessInterfaces
}

// GetEthernetInterfaces 获取以太网接口
func (d *InterfaceDetector) GetEthernetInterfaces() []InterfaceInfo {
	if d.interfaces == nil {
		_, err := d.DetectInterfaces()
		if err != nil {
			return nil
		}
	}

	var ethernetInterfaces []InterfaceInfo
	for _, iface := range d.interfaces {
		if iface.IsEthernet && iface.IsUp {
			ethernetInterfaces = append(ethernetInterfaces, iface)
		}
	}

	return ethernetInterfaces
}

// PrintInterfaceList 打印接口列表
func (d *InterfaceDetector) PrintInterfaceList() {
	if d.interfaces == nil {
		_, err := d.DetectInterfaces()
		if err != nil {
			utils.ErrorPrint("检测网络接口失败: %v", err)
			return
		}
	}

	utils.InfoPrint("检测到 %d 个网络接口:", len(d.interfaces))
	fmt.Println("========================================")

	for i, iface := range d.interfaces {
		status := "禁用"
		if iface.IsUp {
			status = "启用"
		}

		typeDesc := "有线"
		if iface.IsWireless {
			typeDesc = "无线"
		} else if iface.IsLoopback {
			typeDesc = "回环"
		}

		utils.InfoPrint("%d. %s (%s) - %s", i+1, iface.Name, iface.Description, status)
		utils.InfoPrint("   MAC地址: %s", iface.MACAddress)
		utils.InfoPrint("   IP地址: %s", strings.Join(iface.IPAddresses, ", "))
		utils.InfoPrint("   MTU: %d, 类型: %s", iface.MTU, typeDesc)
		utils.InfoPrint("")
	}

	// 显示统计信息
	active := d.GetActiveInterfaces()
	wireless := d.GetWirelessInterfaces()
	ethernet := d.GetEthernetInterfaces()

	utils.SuccessPrint("统计信息:")
	fmt.Println("----------------------------------------")
	utils.InfoPrint("  活动接口: %d", len(active))
	utils.InfoPrint("  无线接口: %d", len(wireless))
	utils.InfoPrint("  有线接口: %d", len(ethernet))
	utils.InfoPrint("  回环接口: %d", 1) // 通常只有一个lo接口
}

// PrintInterfaceDetails 打印指定接口的详细信息
func (d *InterfaceDetector) PrintInterfaceDetails(name string) {
	iface, err := d.GetInterfaceByName(name)
	if err != nil {
		utils.ErrorPrint("获取接口信息失败: %v", err)
		return
	}

	utils.InfoPrint("接口详细信息 - %s", name)
	fmt.Println("========================================")

	utils.InfoPrint("名称: %s", iface.Name)
	utils.InfoPrint("描述: %s", iface.Description)
	utils.InfoPrint("MAC地址: %s", iface.MACAddress)
	utils.InfoPrint("MTU: %d", iface.MTU)
	utils.InfoPrint("状态: %s", d.getStatusText(iface.IsUp))
	utils.InfoPrint("类型: %s", d.getTypeText(iface))
	utils.InfoPrint("标志: %s", iface.Flags)

	utils.InfoPrint("IP地址:")
	if len(iface.IPAddresses) > 0 {
		for _, ip := range iface.IPAddresses {
			utils.InfoPrint("  • %s", ip)
		}
	} else {
		utils.InfoPrint("  无IP地址")
	}

	// 显示接口能力
	utils.InfoPrint("接口能力:")
	if iface.IsWireless {
		utils.InfoPrint("  • 支持无线网络")
	}
	if iface.IsEthernet {
		utils.InfoPrint("  • 支持有线网络")
	}
	if iface.IsLoopback {
		utils.InfoPrint("  • 回环接口")
	}
}

// getStatusText 获取状态文本
func (d *InterfaceDetector) getStatusText(isUp bool) string {
	if isUp {
		return "启用"
	}
	return "禁用"
}

// getTypeText 获取类型文本
func (d *InterfaceDetector) getTypeText(iface *InterfaceInfo) string {
	if iface.IsWireless {
		return "无线网络接口"
	} else if iface.IsEthernet {
		return "有线网络接口"
	} else if iface.IsLoopback {
		return "回环接口"
	}
	return "未知类型"
}
