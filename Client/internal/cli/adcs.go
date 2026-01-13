package cli

import (
	"fmt"
	"strings"

	"GYscan/internal/adcs"
	"GYscan/internal/utils"

	"github.com/spf13/cobra"
)

var (
	target       string
	port         int
	username     string
	password     string
	domain       string
	output       string
	outputFormat string
	filters      string
	verbose      bool
	timeout      int
)

var adcsCmd = &cobra.Command{
	Use:   "adcs",
	Short: "AD CS 漏洞检测工具 [测试阶段]",
	Long: `AD CS 漏洞检测工具 - Active Directory Certificate Services 安全评估

支持检测以下漏洞类型:
  ESC1: 错误配置的证书模板 (SubjectAltName 欺骗) - 高危
  ESC2: Any Purpose EKU 证书模板 - 高危
  ESC3: 注册代理模板错误配置 - 高危/中危
  ESC4: 证书模板访问控制漏洞 - 高危
  ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 标志 - 高危
  ESC7: CA 权限配置问题 - 中危
  ESC8: NTLM 中继到 HTTP 端点 - 中危

使用示例:
  # 基本扫描
  ./GYscan adcs --target dc.domain.local --user domain\\admin --password Pass123

  # 指定域和输出文件
  ./GYscan adcs --target dc.domain.local --user admin --password Pass123 -d domain.local -o results.json

  # 仅检测特定漏洞
  ./GYscan adcs --target dc.domain.local -u admin -w Pass123 --filters esc1,esc2

  # JSON 格式输出
  ./GYscan adcs --target dc.domain.local -u admin -w Pass123 -f json

  # 详细输出模式
  ./GYscan adcs --target dc.domain.local -u admin -w Pass123 -v

认证格式:
  DOMAIN\\username  (Windows 风格)
  username@domain.com (UPN 风格)

注意事项:
  - 此工具仅用于授权的安全测试
  - 需要具有域用户权限的账号
  - 默认 LDAP 端口为 389，如需 LDAPS 使用 636`,
	DisableFlagsInUseLine: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := validateFlags(); err != nil {
			utils.ErrorPrint("参数验证失败: %v", err)
			cmd.Help()
			return err
		}

		filterList := parseFilters(filters)

		if len(filterList) > 0 {
			validFilters := []string{"ESC1", "ESC2", "ESC3", "ESC4", "ESC6", "ESC7", "ESC8"}
			for _, f := range filterList {
				isValid := false
				for _, vf := range validFilters {
					if strings.EqualFold(strings.TrimSpace(f), vf) {
						isValid = true
						break
					}
				}
				if !isValid {
					utils.WarningPrint("[!] 无效的漏洞过滤器: %s", f)
				}
			}
		}

		config := adcs.Config{
			Target:       target,
			Port:         port,
			Username:     username,
			Password:     password,
			Domain:       domain,
			OutputFile:   output,
			OutputFormat: outputFormat,
			Verbose:      verbose,
			JSONIndent:   2,
			Filters:      filterList,
		}

		utils.SuccessPrint("[+] AD CS 漏洞检测工具启动")
		utils.InfoPrint("[*] 目标服务器: %s:%d", target, port)

		if domain != "" {
			utils.InfoPrint("[*] 域: %s", domain)
		}

		if len(filterList) > 0 {
			utils.InfoPrint("[*] 检测过滤器: %v", filterList)
		}

		if verbose {
			utils.InfoPrint("[*] 用户名: %s", username)
		}

		scanner := adcs.NewScanner(config)

		result, err := scanner.Scan()
		if err != nil {
			utils.ErrorPrint("扫描失败: %v", err)
			utils.InfoPrint("[*] 失败可能原因:")
			utils.InfoPrint("    - 无法连接到目标服务器")
			utils.InfoPrint("    - 用户名或密码错误")
			utils.InfoPrint("    - 用户权限不足")
			utils.InfoPrint("    - 目标未安装 AD CS 角色")
			return err
		}

		switch outputFormat {
		case "json":
			if err := scanner.ExportJSON(result); err != nil {
				utils.ErrorPrint("导出失败: %v", err)
				return err
			}
		default:
			scanner.PrintResult(result)
		}

		fmt.Println()
		utils.InfoPrint("[*] 扫描完成")

		return nil
	},
}

func validateFlags() error {
	if target == "" {
		return fmt.Errorf("必须指定目标服务器 (--target 或 -t)")
	}

	if username == "" {
		return fmt.Errorf("必须指定用户名 (--user 或 -u)")
	}

	if password == "" {
		return fmt.Errorf("必须指定密码 (--password 或 -w)")
	}

	if port <= 0 || port > 65535 {
		return fmt.Errorf("无效的端口号: %d", port)
	}

	validFormats := []string{"text", "json"}
	isValidFormat := false
	for _, vf := range validFormats {
		if outputFormat == vf {
			isValidFormat = true
			break
		}
	}
	if !isValidFormat {
		return fmt.Errorf("无效的输出格式: %s (支持: text, json)", outputFormat)
	}

	return nil
}

func parseFilters(filtersStr string) []string {
	if strings.TrimSpace(filtersStr) == "" {
		return []string{}
	}

	filters := []string{}
	parts := strings.Split(filtersStr, ",")

	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			filters = append(filters, trimmed)
		}
	}

	return filters
}

func init() {
	adcsCmd.Flags().SortFlags = false

	adcsCmd.Flags().StringVarP(&target, "target", "t", "", "目标域控制器地址 (必填)")
	adcsCmd.Flags().IntVarP(&port, "port", "p", 389, "LDAP 端口 (默认: 389, LDAPS: 636)")
	adcsCmd.Flags().StringVarP(&username, "user", "u", "", "用户名 (必填，格式: DOMAIN\\user 或 user@domain.com)")
	adcsCmd.Flags().StringVarP(&password, "password", "w", "", "密码 (必填)")
	adcsCmd.Flags().StringVarP(&domain, "domain", "d", "", "域名称 (可选，自动从用户名提取)")
	adcsCmd.Flags().StringVarP(&output, "output", "o", "", "输出文件路径 (可选)")
	adcsCmd.Flags().StringVarP(&outputFormat, "format", "f", "text", "输出格式: text/json")
	adcsCmd.Flags().StringVarP(&filters, "filters", "x", "", "漏洞过滤器，用逗号分隔 (如: esc1,esc2,esc6)")
	adcsCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "详细输出模式")
	adcsCmd.Flags().IntVarP(&timeout, "timeout", "T", 30, "连接超时时间 (秒)")

	adcsCmd.Flags().MarkHidden("timeout")
}
