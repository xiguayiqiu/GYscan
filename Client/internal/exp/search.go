package exp

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"GYscan/internal/utils"

	"github.com/fatih/color"
)

func SearchExploits(options SearchOptions) (*SearchResult, error) {
	if err := LoadDatabase(); err != nil {
		return nil, fmt.Errorf("加载数据库失败: %v", err)
	}

	exploits := GetExploits()
	shellcodes := GetShellcodes()

	var matchingExploits []Exploit
	var matchingShellcodes []Shellcode

	for _, exploit := range exploits {
		if exploit.MatchesSearch(options) {
			matchingExploits = append(matchingExploits, exploit)
		}
	}

	for _, shellcode := range shellcodes {
		if shellcode.MatchesSearch(options) {
			matchingShellcodes = append(matchingShellcodes, shellcode)
		}
	}

	sort.Slice(matchingExploits, func(i, j int) bool {
		return matchingExploits[i].ID > matchingExploits[j].ID
	})

	sort.Slice(matchingShellcodes, func(i, j int) bool {
		return matchingShellcodes[i].ID > matchingShellcodes[j].ID
	})

	if options.OutputPath != "" {
		if err := saveResults(matchingExploits, matchingShellcodes, options.OutputPath, options.Format); err != nil {
			utils.LogWarning("保存结果失败: %v", err)
		}
	}

	return &SearchResult{
		TotalFound: len(matchingExploits) + len(matchingShellcodes),
		Exploits:   matchingExploits,
		Shellcodes: matchingShellcodes,
	}, nil
}

func SearchByCVE(cveID string) (*SearchResult, error) {
	options := SearchOptions{
		CVE:    cveID,
		Format: "text",
	}
	return SearchExploits(options)
}

func SearchByPlatform(platform string) (*SearchResult, error) {
	options := SearchOptions{
		Platform: platform,
		Format:   "text",
	}
	return SearchExploits(options)
}

func SearchByKeyword(keyword string) (*SearchResult, error) {
	options := SearchOptions{
		Query:  keyword,
		Format: "text",
	}
	return SearchExploits(options)
}

func PrintResults(result *SearchResult, verbose bool) {
	utils.LogSuccess("找到 %d 条匹配结果", result.TotalFound)
	fmt.Println()

	if len(result.Exploits) > 0 {
		printExploits(result.Exploits, verbose)
	}

	if len(result.Shellcodes) > 0 {
		printShellcodes(result.Shellcodes, verbose)
	}
}

func printExploits(exploits []Exploit, verbose bool) {
	cyan := color.New(color.FgCyan)
	yellow := color.New(color.FgYellow)
	green := color.New(color.FgGreen)
	white := color.New(color.FgWhite)

	utils.LogInfo("漏洞利用 (%d 条)", len(exploits))
	fmt.Println(strings.Repeat("-", 80))

	if len(exploits) > 50 && !verbose {
		utils.LogWarning("显示前50条结果 (共 %d 条)", len(exploits))
		exploits = exploits[:50]
	}

	for _, exploit := range exploits {
		cyan.Printf("[%06d] ", exploit.ID)
		white.Println(truncateString(exploit.Description, 60))

		if verbose {
			yellow.Printf("    平台: %s | 类型: %s | 作者: %s\n", exploit.Platform, exploit.Type, exploit.Author)
			yellow.Printf("    文件: %s\n", exploit.File)

			if exploit.Codes != "" {
				cves := extractCVEs(exploit.Codes)
				for _, cve := range cves {
					green.Printf("    CVE: %s\n", cve)
				}
			}

			if exploit.Verified {
				green.Printf("    [已验证]\n")
			}

			fmt.Println()
		}
	}
}

func printShellcodes(shellcodes []Shellcode, verbose bool) {
	cyan := color.New(color.FgCyan)
	magenta := color.New(color.FgMagenta)
	white := color.New(color.FgWhite)

	utils.LogInfo("Shellcode (%d 条)", len(shellcodes))
	fmt.Println(strings.Repeat("-", 80))

	if len(shellcodes) > 50 && !verbose {
		utils.LogWarning("显示前50条结果 (共 %d 条)", len(shellcodes))
		shellcodes = shellcodes[:50]
	}

	for _, shellcode := range shellcodes {
		cyan.Printf("[%06d] ", shellcode.ID)
		white.Println(truncateString(shellcode.Description, 60))

		if verbose {
			magenta.Printf("    平台: %s | 大小: %s 字节 | 作者: %s\n",
				shellcode.Platform, shellcode.Size, shellcode.Author)

			if shellcode.Verified {
				utils.SuccessPrint("    [已验证]")
			}

			fmt.Println()
		}
	}
}

func saveResults(exploits []Exploit, shellcodes []Shellcode, outputPath string, format string) error {
	var data struct {
		Exploits   []Exploit   `json:"exploits"`
		Shellcodes []Shellcode `json:"shellcodes"`
		TotalFound int         `json:"total_found"`
	}

	data.Exploits = exploits
	data.Shellcodes = shellcodes
	data.TotalFound = len(exploits) + len(shellcodes)

	if format == "json" {
		jsonData, err := json.MarshalIndent(data, "", "  ")
		if err != nil {
			return err
		}
		return os.WriteFile(outputPath, jsonData, 0644)
	}

	var result strings.Builder
	result.WriteString(fmt.Sprintf("搜索结果\n"))
	result.WriteString(fmt.Sprintf("总计找到: %d 条记录\n\n", data.TotalFound))

	if len(exploits) > 0 {
		result.WriteString(fmt.Sprintf("漏洞利用 (%d 条)\n", len(exploits)))
		result.WriteString(strings.Repeat("=", 80) + "\n")
		for _, e := range exploits {
			result.WriteString(fmt.Sprintf("[%06d] %s\n", e.ID, e.Description))
			result.WriteString(fmt.Sprintf("    平台: %s | 类型: %s | 文件: %s\n", e.Platform, e.Type, e.File))
			if e.Codes != "" {
				result.WriteString(fmt.Sprintf("    CVE: %s\n", e.Codes))
			}
			result.WriteString("\n")
		}
	}

	if len(shellcodes) > 0 {
		result.WriteString(fmt.Sprintf("\nShellcode (%d 条)\n", len(shellcodes)))
		result.WriteString(strings.Repeat("=", 80) + "\n")
		for _, s := range shellcodes {
			result.WriteString(fmt.Sprintf("[%06d] %s\n", s.ID, s.Description))
			result.WriteString(fmt.Sprintf("    平台: %s | 大小: %s 字节\n", s.Platform, s.Size))
			result.WriteString("\n")
		}
	}

	return os.WriteFile(outputPath, []byte(result.String()), 0644)
}

func truncateString(s string, maxLength int) string {
	if len(s) <= maxLength {
		return s
	}
	return s[:maxLength-3] + "..."
}

func extractCVEs(codes string) []string {
	var cves []string
	parts := strings.Split(codes, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToUpper(part), "CVE-") {
			cves = append(cves, part)
		}
	}
	return cves
}

func GetExploitDetails(id int) (*Exploit, error) {
	if err := LoadDatabase(); err != nil {
		return nil, fmt.Errorf("加载数据库失败: %v", err)
	}

	exploit := GetExploitByID(id)
	if exploit == nil {
		return nil, fmt.Errorf("未找到ID为 %d 的漏洞利用", id)
	}

	return exploit, nil
}

func GetShellcodeDetails(id int) (*Shellcode, error) {
	if err := LoadDatabase(); err != nil {
		return nil, fmt.Errorf("加载数据库失败: %v", err)
	}

	shellcode := GetShellcodeByID(id)
	if shellcode == nil {
		return nil, fmt.Errorf("未找到ID为 %d 的shellcode", id)
	}

	return shellcode, nil
}

func ListPlatforms() []string {
	if err := LoadDatabase(); err != nil {
		return nil
	}

	exploits := GetExploits()
	platformSet := make(map[string]bool)

	for _, exploit := range exploits {
		if exploit.Platform != "" {
			platforms := strings.Split(exploit.Platform, "/")
			for _, p := range platforms {
				platformSet[strings.TrimSpace(p)] = true
			}
		}
	}

	platforms := make([]string, 0, len(platformSet))
	for p := range platformSet {
		platforms = append(platforms, p)
	}

	sort.Strings(platforms)
	return platforms
}

func ListExploitTypes() []string {
	if err := LoadDatabase(); err != nil {
		return nil
	}

	exploits := GetExploits()
	typeSet := make(map[string]bool)

	for _, exploit := range exploits {
		if exploit.Type != "" {
			typeSet[exploit.Type] = true
		}
	}

	types := make([]string, 0, len(typeSet))
	for t := range typeSet {
		types = append(types, t)
	}

	sort.Strings(types)
	return types
}
