package cli

import (
	"fmt"
	"strings"
	"GYscan/internal/tunnel"

	"github.com/spf13/cobra"
)

var (
	tunnelConfig = &tunnel.TunnelConfig{}
	tunnelClient *tunnel.TunnelClient

	// tunnelCmd 网络隧道主命令
	tunnelCmd = &cobra.Command{
		Use:   "tunnel",
		Short: "网络隧道功能 [测试阶段]",
		Long:  `提供多种网络隧道技术，包括HTTP、HTTPS、SOCKS、TCP、ICMP和DNS隧道等。[测试阶段]`,
	}

	// startTunnelCmd 启动隧道命令
	startTunnelCmd = &cobra.Command{
		Use:   "start",
		Short: "启动隧道",
		Long:  `启动指定类型的网络隧道。`,
		Run:   executeStartTunnel,
	}

	// stopTunnelCmd 停止隧道命令
	stopTunnelCmd = &cobra.Command{
		Use:   "stop",
		Short: "停止隧道",
		Long:  `停止当前运行的隧道。`,
		Run:   executeStopTunnel,
	}

	// statusTunnelCmd 查看隧道状态命令
	statusTunnelCmd = &cobra.Command{
		Use:   "status",
		Short: "查看隧道状态",
		Long:  `显示当前隧道的运行状态。`,
		Run:   executeTunnelStatus,
	}

	// listTunnelCmd 列出支持的隧道类型命令
	listTunnelCmd = &cobra.Command{
		Use:   "list",
		Short: "列出支持的隧道类型",
		Long:  `显示所有支持的隧道类型。`,
		Run:   executeListTunnelTypes,
	}
)

func init() {
	// 将隧道命令添加到根命令
	// rootCmd.AddCommand(tunnelCmd) // 命令注册已移至root.go的RegisterCommands函数中统一管理

	// 添加子命令
	tunnelCmd.AddCommand(startTunnelCmd)
	tunnelCmd.AddCommand(stopTunnelCmd)
	tunnelCmd.AddCommand(statusTunnelCmd)
	tunnelCmd.AddCommand(listTunnelCmd)

	// 通用参数
	tunnelCmd.PersistentFlags().StringVarP(&tunnelConfig.Type, "type", "t", "", "隧道类型")

	// 启动隧道特定参数
	startTunnelCmd.Flags().StringVarP(&tunnelConfig.ListenAddr, "listen", "l", "", "本地监听地址（格式: 127.0.0.1:8080）")
	startTunnelCmd.Flags().StringVarP(&tunnelConfig.RemoteAddr, "remote", "r", "", "远程目标地址（格式: example.com:80）")
	startTunnelCmd.Flags().StringVarP(&tunnelConfig.ServerAddr, "server", "s", "", "隧道服务器地址")
	startTunnelCmd.Flags().StringVarP(&tunnelConfig.LocalAddr, "local", "L", "", "本地地址（适用于ICMP隧道）")
	startTunnelCmd.Flags().StringVarP(&tunnelConfig.Certificate, "cert", "c", "", "HTTPS证书路径")
	startTunnelCmd.Flags().StringVarP(&tunnelConfig.PrivateKey, "key", "k", "", "HTTPS私钥路径")
	startTunnelCmd.Flags().StringVarP(&tunnelConfig.Password, "password", "p", "", "隧道密码")
	startTunnelCmd.Flags().StringVarP(&tunnelConfig.Domain, "domain", "d", "", "DNS隧道域名")
	startTunnelCmd.Flags().IntVarP(&tunnelConfig.Interval, "interval", "i", 1000, "ICMP/DNS隧道的时间间隔（毫秒）")
	startTunnelCmd.Flags().IntVarP(&tunnelConfig.MaxPacketSize, "packet-size", "m", 1500, "最大数据包大小")

	// 必需参数验证已移至validateTunnelParams函数中，以确保帮助功能正常工作
}

// executeStartTunnel 执行启动隧道操作
func executeStartTunnel(cmd *cobra.Command, args []string) {
	// 验证隧道类型
	supportedTypes := tunnel.ListTunnelTypes()
	supported := false
	for _, t := range supportedTypes {
		if tunnelConfig.Type == t {
			supported = true
			break
		}
	}

	if !supported {
		fmt.Printf("不支持的隧道类型: %s\n", tunnelConfig.Type)
		fmt.Println("支持的类型: http, https, socks, tcp, icmp, dns")
		return
	}

	// 根据隧道类型验证必需参数
	errors := validateTunnelParams(tunnelConfig)
	if len(errors) > 0 {
		fmt.Println("参数验证失败:")
		for _, err := range errors {
			fmt.Printf("  - %s\n", err)
		}
		return
	}

	// 创建客户端并启动隧道
	tunnelClient = tunnel.NewTunnelClient(tunnelConfig)
	result, err := tunnelClient.StartTunnel()
	if err != nil {
		fmt.Printf("启动隧道失败: %v\n", err)
		return
	}

	// 输出结果
	if result.Success {
		fmt.Printf("隧道启动成功!\n类型: %s\n详情: %s\n\n", result.TunnelType, result.Message)
		fmt.Println("按Ctrl+C停止隧道...")
		// 保持命令运行
		select {}
	} else {
		fmt.Printf("隧道启动失败!\n类型: %s\n错误信息: %s\n", result.TunnelType, result.Message)
	}
}

// executeStopTunnel 执行停止隧道操作
func executeStopTunnel(cmd *cobra.Command, args []string) {
	if tunnelClient == nil || !tunnelClient.IsRunning() {
		fmt.Println("没有运行中的隧道")
		return
	}

	result, err := tunnelClient.StopTunnel()
	if err != nil {
		fmt.Printf("停止隧道失败: %v\n", err)
		return
	}

	// 输出结果
	if result.Success {
		fmt.Printf("隧道停止成功!\n类型: %s\n详情: %s\n", result.TunnelType, result.Message)
	} else {
		fmt.Printf("隧道停止失败!\n类型: %s\n错误信息: %s\n", result.TunnelType, result.Message)
	}
}

// executeTunnelStatus 执行查看隧道状态操作
func executeTunnelStatus(cmd *cobra.Command, args []string) {
	if tunnelClient == nil {
		fmt.Println("隧道状态: 未初始化")
		return
	}

	status := tunnelClient.GetStatus()
	fmt.Printf("隧道状态: %s\n", status)

	if tunnelClient.IsRunning() {
		fmt.Printf("隧道类型: %s\n", tunnelClient.Config.Type)
		switch tunnelClient.Config.Type {
		case "tcp":
			fmt.Printf("监听地址: %s\n", tunnelClient.Config.ListenAddr)
			fmt.Printf("远程地址: %s\n", tunnelClient.Config.RemoteAddr)
		case "http", "https":
			fmt.Printf("监听地址: %s\n", tunnelClient.Config.ListenAddr)
			fmt.Printf("服务器地址: %s\n", tunnelClient.Config.ServerAddr)
		case "socks":
			fmt.Printf("监听地址: %s\n", tunnelClient.Config.ListenAddr)
		case "icmp":
			fmt.Printf("本地地址: %s\n", tunnelClient.Config.LocalAddr)
			fmt.Printf("远程地址: %s\n", tunnelClient.Config.RemoteAddr)
			fmt.Printf("时间间隔: %dms\n", tunnelClient.Config.Interval)
		case "dns":
			fmt.Printf("域名: %s\n", tunnelClient.Config.Domain)
			fmt.Printf("时间间隔: %dms\n", tunnelClient.Config.Interval)
		}
	}
}

// executeListTunnelTypes 执行列出支持的隧道类型操作
func executeListTunnelTypes(cmd *cobra.Command, args []string) {
	fmt.Println("支持的隧道类型:")
	fmt.Println()

	// 隧道类型和描述
	tunnels := map[string]string{
		"http":  "HTTP隧道 - 通过HTTP协议封装流量",
		"https": "HTTPS隧道 - 通过加密的HTTPS协议封装流量",
		"socks": "SOCKS代理 - SOCKS5代理服务器",
		"tcp":   "TCP端口转发 - 简单的TCP端口转发",
		"icmp":  "ICMP隧道 - 通过ICMP协议封装数据",
		"dns":   "DNS隧道 - 通过DNS查询封装数据",
	}

	// 遍历并显示每个隧道类型
	for t, desc := range tunnels {
		fmt.Printf("  %-8s %s\n", t, desc)
	}

	fmt.Println()
	fmt.Println("使用示例:")
	fmt.Println("  gyscan tunnel start --type tcp --listen 127.0.0.1:8080 --remote example.com:80")
	fmt.Println("  gyscan tunnel start --type https --listen 127.0.0.1:8443 --server example.com:443 --cert cert.pem --key key.pem")
	fmt.Println("  gyscan tunnel start --type dns --domain tunnel.example.com --interval 2000")
	fmt.Println("  gyscan tunnel stop")
}

// validateTunnelParams 验证隧道参数
func validateTunnelParams(config *tunnel.TunnelConfig) []string {
	var errors []string

	// 验证隧道类型
	if config.Type == "" {
		errors = append(errors, "必须指定隧道类型 (--type)")
		return errors
	}

	switch config.Type {
	case "tcp":
		if config.ListenAddr == "" {
			errors = append(errors, "TCP隧道需要指定监听地址 (--listen)")
		}
		if config.RemoteAddr == "" {
			errors = append(errors, "TCP隧道需要指定远程地址 (--remote)")
		}
	case "http", "https":
		if config.ListenAddr == "" {
			errors = append(errors, fmt.Sprintf("%s隧道需要指定监听地址 (--listen)", strings.ToUpper(config.Type)))
		}
		if config.ServerAddr == "" {
			errors = append(errors, fmt.Sprintf("%s隧道需要指定服务器地址 (--server)", strings.ToUpper(config.Type)))
		}
		if config.Type == "https" {
			if config.Certificate == "" {
				errors = append(errors, "HTTPS隧道需要指定证书路径 (--cert)")
			}
			if config.PrivateKey == "" {
				errors = append(errors, "HTTPS隧道需要指定私钥路径 (--key)")
			}
		}
	case "socks":
		if config.ListenAddr == "" {
			errors = append(errors, "SOCKS隧道需要指定监听地址 (--listen)")
		}
	case "icmp":
		if config.LocalAddr == "" {
			errors = append(errors, "ICMP隧道需要指定本地地址 (--local)")
		}
		if config.RemoteAddr == "" {
			errors = append(errors, "ICMP隧道需要指定远程地址 (--remote)")
		}
	case "dns":
		if config.Domain == "" {
			errors = append(errors, "DNS隧道需要指定域名 (--domain)")
		}
	}

	return errors
}