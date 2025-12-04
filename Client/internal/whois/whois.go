package whois

import (
	"fmt"
	"github.com/likexian/whois"
	parser "github.com/likexian/whois-parser"
	"strings"
	"time"
)

// WhoisResult 表示Whois查询结果
type WhoisResult struct {
	Query     string
	Raw       string
	Parsed    parser.WhoisInfo
	Error     error
	StartTime time.Time
	EndTime   time.Time
}

// Whois 查询域名或IP地址的Whois信息
func Whois(query string) (WhoisResult, error) {
	result := WhoisResult{
		Query:     query,
		StartTime: time.Now(),
	}

	// 执行Whois查询
	raw, err := whois.Whois(query)
	result.EndTime = time.Now()
	if err != nil {
		result.Error = err
		return result, err
	}
	result.Raw = raw

	// 解析Whois响应
	parsed, err := parser.Parse(raw)
	if err != nil {
		result.Error = err
		return result, err
	}
	result.Parsed = parsed

	return result, nil
}

// FormatResult 格式化Whois查询结果
func FormatResult(result WhoisResult) string {
	var output strings.Builder

	output.WriteString("=== Whois查询结果 ===\n")
	output.WriteString(fmt.Sprintf("查询目标: %s\n", result.Query))
	output.WriteString(fmt.Sprintf("耗时: %v\n\n", result.EndTime.Sub(result.StartTime)))

	if result.Error != nil {
		output.WriteString(fmt.Sprintf("错误: %v\n", result.Error))
		if result.Raw != "" {
			output.WriteString(fmt.Sprintf("原始响应:\n%s\n", result.Raw))
		}
		return output.String()
	}

	// 域名信息
	if result.Parsed.Domain != nil {
		output.WriteString("域名信息:\n")
		if result.Parsed.Domain.Name != "" {
			output.WriteString(fmt.Sprintf("  域名: %s\n", result.Parsed.Domain.Name))
		}
		if result.Parsed.Domain.ID != "" {
			output.WriteString(fmt.Sprintf("  域名ID: %s\n", result.Parsed.Domain.ID))
		}
		if len(result.Parsed.Domain.Status) > 0 {
			output.WriteString(fmt.Sprintf("  状态: %s\n", strings.Join(result.Parsed.Domain.Status, ", ")))
		}
		if result.Parsed.Domain.CreatedDate != "" {
			output.WriteString(fmt.Sprintf("  创建时间: %s\n", result.Parsed.Domain.CreatedDate))
		}
		if result.Parsed.Domain.UpdatedDate != "" {
			output.WriteString(fmt.Sprintf("  更新时间: %s\n", result.Parsed.Domain.UpdatedDate))
		}
		if result.Parsed.Domain.ExpirationDate != "" {
			output.WriteString(fmt.Sprintf("  过期时间: %s\n", result.Parsed.Domain.ExpirationDate))
		}
		if len(result.Parsed.Domain.NameServers) > 0 {
			output.WriteString(fmt.Sprintf("  名称服务器: %s\n", strings.Join(result.Parsed.Domain.NameServers, ", ")))
		}
		output.WriteString("\n")
	}

	// 注册商信息
	if result.Parsed.Registrar != nil {
		output.WriteString("注册商信息:\n")
		if result.Parsed.Registrar.Name != "" {
			output.WriteString(fmt.Sprintf("  注册商: %s\n", result.Parsed.Registrar.Name))
		}
		output.WriteString("\n")
	}

	// 注册人信息
	if result.Parsed.Registrant != nil {
		output.WriteString("注册人信息:\n")
		if result.Parsed.Registrant.Name != "" {
			output.WriteString(fmt.Sprintf("  名称: %s\n", result.Parsed.Registrant.Name))
		}
		if result.Parsed.Registrant.Email != "" {
			output.WriteString(fmt.Sprintf("  邮箱: %s\n", result.Parsed.Registrant.Email))
		}
		if result.Parsed.Registrant.Organization != "" {
			output.WriteString(fmt.Sprintf("  组织: %s\n", result.Parsed.Registrant.Organization))
		}
		output.WriteString("\n")
	}

	// 原始响应（如果需要）
	if result.Raw != "" {
		output.WriteString(fmt.Sprintf("原始响应:\n%s\n", result.Raw))
	}

	return output.String()
}

// BatchWhois 批量查询Whois信息
func BatchWhois(queries []string) []WhoisResult {
	results := make([]WhoisResult, len(queries))

	for i, query := range queries {
		result, _ := Whois(query)
		results[i] = result
	}

	return results
}