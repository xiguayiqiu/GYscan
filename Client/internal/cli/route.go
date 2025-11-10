package cli

import (
	"fmt"
	"net"
	"os"
	"time"

	"GYscan/internal/utils"
	"github.com/spf13/cobra"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// 全局变量
var (
	routeMaxHops int
	routeTimeout int
	routeCount   int
)

// routeCmd 路由检测命令
var routeCmd = &cobra.Command{
	Use:   "route [目标IP或域名]",
	Short: "路由跳数检测",
	Long: `路由跳数检测工具，用于追踪网络数据包从源到目标的路径。

示例:
  GYscan route 8.8.8.8                    # 检测到Google DNS的路由
  GYscan route google.com --max-hops 10   # 检测到Google的路由，最大10跳
  GYscan route 192.168.1.1 --count 5      # 每个跳数探测5次
  GYscan route example.com --timeout 5    # 设置5秒超时
`,
	Args: func(cmd *cobra.Command, args []string) error {
		// 检查是否请求帮助
		if len(args) > 0 && args[0] == "help" {
			return nil
		}
		
		if len(args) < 1 {
			return fmt.Errorf("需要指定目标IP或域名")
		}
		// 验证目标地址（支持IP和域名）
		if _, err := net.ResolveIPAddr("ip", args[0]); err != nil {
			// 如果是域名，尝试解析
			if _, err := net.LookupHost(args[0]); err != nil {
				return fmt.Errorf("无效的目标地址或域名: %v", err)
			}
		}
		return nil
	},
	RunE: runRouteDetection,
}

func init() {
	// 添加route命令的参数
	routeCmd.Flags().IntVarP(&routeMaxHops, "max-hops", "m", 30, "最大跳数")
	routeCmd.Flags().IntVarP(&routeTimeout, "timeout", "t", 3, "超时时间（秒）")
	routeCmd.Flags().IntVarP(&routeCount, "count", "c", 3, "每个跳数的探测次数")
}

// 路由检测结果结构
type RouteHop struct {
	Hop      string  `json:"hop"`
	IP       net.IP  `json:"ip"`
	Hostname string  `json:"hostname"`
	AvgDelay float64 `json:"avg_delay"`
	LossRate float64 `json:"loss_rate"`
}

// 运行路由检测
func runRouteDetection(cmd *cobra.Command, args []string) error {
	// 检查是否请求帮助
	if len(args) > 0 && args[0] == "help" {
		return cmd.Help()
	}
	
	target := args[0]
	
	utils.InfoPrint("[+] 开始路由检测到目标: %s", target)
	fmt.Printf("    - 最大跳数: %d\n", routeMaxHops)
	fmt.Printf("    - 超时时间: %d秒\n", routeTimeout)
	fmt.Printf("    - 探测次数: %d\n", routeCount)

	// 解析目标IP
	targetIP, err := net.ResolveIPAddr("ip", target)
	if err != nil {
		return fmt.Errorf("解析目标地址失败: %v", err)
	}

	utils.InfoPrint("[+] 目标IP: %s\n", targetIP.String())

	// 执行路由检测
	hops, err := traceRoute(targetIP.IP, routeMaxHops, routeTimeout, routeCount)
	if err != nil {
		return fmt.Errorf("路由检测失败: %v", err)
	}

	// 显示结果
	utils.InfoPrint("[+] 路由检测结果:")
	fmt.Println("跳数\tIP地址\t\t主机名\t\t延时(ms)\t丢包率")
	fmt.Println("----\t-------\t\t------\t\t--------\t------")

	for _, hop := range hops {
		hostname := hop.Hostname
		if hostname == "" {
			hostname = "未知"
		}
		
		ipStr := "*"
		if hop.IP != nil {
			ipStr = hop.IP.String()
		}
		
		packetLoss := fmt.Sprintf("%.1f%%", hop.LossRate)
		
		fmt.Printf("%s\t%s\t%s\t%.2f\t%s\n", 
			hop.Hop, 
			ipStr, 
			hostname, 
			hop.AvgDelay,
			packetLoss)
	}

	utils.SuccessPrint("\n[+] 路由检测完成！共检测到 %d 跳", len(hops))
	
	return nil
}

// ICMP消息类型常量
const (
	ProtocolICMP = 1
	EchoRequest  = 8
	EchoReply    = 0
	TimeExceeded = 11
)

// 路由检测核心函数 - 使用Go原生ICMP实现
func traceRoute(target net.IP, maxHops, timeoutSec, count int) ([]RouteHop, error) {
	var hops []RouteHop
	
	// 创建ICMP连接
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return nil, fmt.Errorf("创建ICMP连接失败: %v", err)
	}
	defer conn.Close()
	
	// 设置IP层选项以控制TTL - 使用conn.IPv4PacketConn()
	pconn := conn.IPv4PacketConn()
	if pconn == nil {
		return nil, fmt.Errorf("无法获取IPv4 PacketConn")
	}
	
	// 对每个跳数进行探测
	for ttl := 1; ttl <= maxHops; ttl++ {
		// 设置TTL
		if err := pconn.SetTTL(ttl); err != nil {
			return nil, fmt.Errorf("设置TTL失败: %v", err)
		}
		
		var hop RouteHop
		var delays []time.Duration
		var successCount int
		
		// 对每个跳数进行多次探测
		for probe := 0; probe < count; probe++ {
			// 创建ICMP Echo请求消息
			msg := icmp.Message{
				Type: ipv4.ICMPTypeEcho,
				Code: 0,
				Body: &icmp.Echo{
					ID:   os.Getpid() & 0xffff,
					Seq:  ttl*count + probe,
					Data: []byte("GYscan Route Detection"),
				},
			}
			
			// 序列化消息
			msgBytes, err := msg.Marshal(nil)
			if err != nil {
				return nil, fmt.Errorf("序列化ICMP消息失败: %v", err)
			}
			
			// 发送ICMP Echo请求
			startTime := time.Now()
			_, err = conn.WriteTo(msgBytes, &net.IPAddr{IP: target})
			if err != nil {
				continue // 发送失败，继续下一次探测
			}
			
			// 设置读取超时
			conn.SetReadDeadline(time.Now().Add(time.Duration(timeoutSec) * time.Second))
			
			// 读取回复
			reply := make([]byte, 1500)
			n, peer, err := conn.ReadFrom(reply)
			if err != nil {
				// 超时或读取错误，记录为丢包
				continue
			}
			
			// 解析回复消息
			replyMsg, err := icmp.ParseMessage(ProtocolICMP, reply[:n])
			if err != nil {
				continue
			}
			
			// 计算延迟
			latency := time.Since(startTime)
			
			switch replyMsg.Type {
			case ipv4.ICMPTypeEchoReply:
				// 到达目标
				echo, ok := replyMsg.Body.(*icmp.Echo)
				if ok && echo.ID == msg.Body.(*icmp.Echo).ID && echo.Seq == msg.Body.(*icmp.Echo).Seq {
					delays = append(delays, latency)
					successCount++
					
					// 如果是第一次成功探测，记录跳数信息
					if hop.IP == nil {
						hop.Hop = fmt.Sprintf("%d", ttl)
						hop.IP = peer.(*net.IPAddr).IP
						
						// 尝试解析主机名
						if names, err := net.LookupAddr(hop.IP.String()); err == nil && len(names) > 0 {
							hop.Hostname = names[0]
						}
					}
				}
				
				// 到达目标，结束路由检测
				if len(delays) > 0 {
					var totalLatency time.Duration
					for _, d := range delays {
						totalLatency += d
					}
					hop.AvgDelay = float64(totalLatency.Microseconds()) / float64(len(delays)) / 1000.0
					hop.LossRate = float64(count-successCount) / float64(count) * 100.0
					hops = append(hops, hop)
				}
				return hops, nil
				
			case ipv4.ICMPTypeTimeExceeded:
				// 中间路由器返回超时
				delays = append(delays, latency)
				successCount++
				
				// 如果是第一次成功探测，记录跳数信息
				if hop.IP == nil {
					hop.Hop = fmt.Sprintf("%d", ttl)
					hop.IP = peer.(*net.IPAddr).IP
					
					// 尝试解析主机名
					if names, err := net.LookupAddr(hop.IP.String()); err == nil && len(names) > 0 {
						hop.Hostname = names[0]
					}
				}
			}
		}
		
		// 记录当前跳数的结果
		if hop.IP != nil {
			if len(delays) > 0 {
				var totalLatency time.Duration
				for _, d := range delays {
					totalLatency += d
				}
				hop.AvgDelay = float64(totalLatency.Microseconds()) / float64(len(delays)) / 1000.0
			}
			hop.LossRate = float64(count-successCount) / float64(count) * 100.0
			hops = append(hops, hop)
		} else {
			// 当前跳数无响应
			hops = append(hops, RouteHop{
				Hop:      fmt.Sprintf("%d", ttl),
				AvgDelay: 0,
				LossRate: 100.0,
			})
		}
	}
	
	return hops, nil
}