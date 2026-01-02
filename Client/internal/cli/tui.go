package cli

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"GYscan/internal/utils"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"
)

var tuiCmd = &cobra.Command{
	Use:   "tui",
	Short: "启动 TUI 模式 [测试阶段]",
	Long:  `启动 GYscan 的交互式 TUI 模式，提供可视化操作界面 [测试阶段]`,
	Run: func(cmd *cobra.Command, args []string) {
		p := tea.NewProgram(initialModel(), tea.WithAltScreen())
		if err := p.Start(); err != nil {
			utils.LogError("TUI 模式启动失败: %v", err)
			utils.ErrorPrint("TUI 模式启动失败: %v", err)
			os.Exit(1)
		}
	},
}

var (
	primaryColor   = lipgloss.Color("#6C5CE7")
	secondaryColor = lipgloss.Color("#00B894")
	focusedColor   = lipgloss.Color("#FD79A8")
	borderColor    = lipgloss.Color("#636E72")
	textColor      = lipgloss.Color("#DFE6E9")
	dimTextColor   = lipgloss.Color("#B2BEC3")
	commandParams  map[string][]paramDefinition

	dimTextStyle       = lipgloss.NewStyle().Foreground(dimTextColor)
	secondaryStyle     = lipgloss.NewStyle().Foreground(secondaryColor)
	focusedTextStyle   = lipgloss.NewStyle().Foreground(focusedColor)
	normalTextStyle    = lipgloss.NewStyle().Foreground(textColor)
	resultFocusedStyle = lipgloss.NewStyle().
				Border(lipgloss.NormalBorder()).
				BorderForeground(lipgloss.Color("#00FF00")).
				Padding(0).
				Foreground(textColor)

	menuPanelStyle = lipgloss.NewStyle().
			Border(lipgloss.NormalBorder()).
			BorderForeground(primaryColor).
			Padding(0, 1).
			Foreground(textColor)

	paramPanelStyle = lipgloss.NewStyle().
			Border(lipgloss.NormalBorder()).
			BorderForeground(secondaryColor).
			Padding(1, 1).
			Foreground(textColor)

	resultPanelStyle = lipgloss.NewStyle().
				Border(lipgloss.NormalBorder()).
				BorderForeground(focusedColor).
				Padding(0).
				Foreground(textColor)

	activeTabStyle = lipgloss.NewStyle().
			Foreground(primaryColor).
			Bold(true).
			Padding(0, 1)

	inactiveTabStyle = lipgloss.NewStyle().
				Foreground(dimTextColor).
				Padding(0, 1)

	focusedInputStyle = lipgloss.NewStyle().
				Foreground(focusedColor).
				Bold(true)

	blurredInputStyle = lipgloss.NewStyle().
				Foreground(textColor)

	dividerStyle = lipgloss.NewStyle().
			Foreground(borderColor)

	statusStyle = lipgloss.NewStyle().
			Foreground(dimTextColor).
			Padding(0, 0)

	listDelegateStyle = list.NewDefaultDelegate()
)

func init() {
	listDelegateStyle.Styles.SelectedTitle = lipgloss.NewStyle().Foreground(secondaryColor).Bold(true)
	listDelegateStyle.Styles.SelectedDesc = lipgloss.NewStyle().Foreground(secondaryColor)
	listDelegateStyle.Styles.NormalTitle = lipgloss.NewStyle().Foreground(textColor)
	listDelegateStyle.Styles.NormalDesc = lipgloss.NewStyle().Foreground(dimTextColor)
}

type CommandItem struct {
	Name           string
	DescriptionStr string
	Group          string
}

func (i CommandItem) Title() string       { return i.Name }
func (i CommandItem) Description() string { return i.DescriptionStr }
func (i CommandItem) FilterValue() string { return i.Name }

type paramDefinition struct {
	Name        string
	ShortName   string
	Description string
	Required    bool
	Default     string
	Type        string
	Positional  bool
}

type model struct {
	width              int
	height             int
	showWelcome        bool
	activeTab          int
	tabs               []string
	commandLists       map[string]list.Model
	activeCommandList  string
	commandParams      map[string][]paramDefinition
	inputs             map[string][]textinput.Model
	activeInput        int
	inputFocus         bool
	results            map[string]string
	resultLogs         map[string][]string
	resultContent      string
	resultPlainContent string
	currentCommand     string
	lastResultContent  string
	running            bool
	runningStatus      string
	quitting           bool
	viewport           viewport.Model
	parameterMode      bool
	focusArea          string
}

var tabToCommandList = map[string]string{
	"Tools":  "综合工具",
	"Crack":  "密码学工具",
	"Scan":   "网络扫描工具",
	"Remote": "远程管理工具",
	"Info":   "信息收集工具",
	"Web":    "Web安全工具",
	"Test":   "测试阶段命令",
}

type commandGroup struct {
	Name     string
	Commands []list.Item
}

func initialModel() model {
	commandGroups := map[string]commandGroup{
		"综合工具": {
			Name: "综合工具",
			Commands: []list.Item{
				CommandItem{Name: "about", DescriptionStr: "综合测试工具"},
				CommandItem{Name: "linenum", DescriptionStr: "Linux本地信息枚举"},
				CommandItem{Name: "linux-kernel", DescriptionStr: "Linux内核漏洞检测"},
			},
		},
		"密码学工具": {
			Name: "密码学工具",
			Commands: []list.Item{
				CommandItem{Name: "crunch", DescriptionStr: "密码字典生成"},
				CommandItem{Name: "database", DescriptionStr: "数据库密码破解"},
				CommandItem{Name: "ftp", DescriptionStr: "FTP密码破解"},
				CommandItem{Name: "ssh", DescriptionStr: "SSH密码爆破"},
			},
		},
		"网络扫描工具": {
			Name: "网络扫描工具",
			Commands: []list.Item{
				CommandItem{Name: "scan", DescriptionStr: "网络扫描"},
				CommandItem{Name: "dirscan", DescriptionStr: "目录扫描"},
				CommandItem{Name: "route", DescriptionStr: "路由跳数检测"},
				CommandItem{Name: "whois", DescriptionStr: "Whois查询"},
			},
		},
		"远程管理工具": {
			Name: "远程管理工具",
			Commands: []list.Item{
				CommandItem{Name: "rdp", DescriptionStr: "RDP远程桌面"},
				CommandItem{Name: "smb", DescriptionStr: "SMB协议操作"},
				CommandItem{Name: "powershell", DescriptionStr: "PowerShell远程执行"},
				CommandItem{Name: "wmi", DescriptionStr: "WMI远程管理"},
				CommandItem{Name: "winlog", DescriptionStr: "Windows日志查看"},
			},
		},
		"信息收集工具": {
			Name: "信息收集工具",
			Commands: []list.Item{
				CommandItem{Name: "userinfo", DescriptionStr: "用户和组分析"},
				CommandItem{Name: "process", DescriptionStr: "进程与服务信息"},
			},
		},
		"Web安全工具": {
			Name: "Web安全工具",
			Commands: []list.Item{
				CommandItem{Name: "webshell", DescriptionStr: "WebShell生成"},
				CommandItem{Name: "fu", DescriptionStr: "文件上传漏洞"},
				CommandItem{Name: "waf", DescriptionStr: "WAF识别"},
				CommandItem{Name: "wwifi", DescriptionStr: "WiFi密码破解"},
			},
		},
		"测试阶段命令": {
			Name: "测试阶段命令",
			Commands: []list.Item{
				CommandItem{Name: "csrf", DescriptionStr: "CSRF漏洞检测"},
				CommandItem{Name: "ldap", DescriptionStr: "LDAP枚举"},
				CommandItem{Name: "dcom", DescriptionStr: "DCOM远程执行"},
			},
		},
	}

	commandLists := make(map[string]list.Model)
	for groupName, group := range commandGroups {
		l := list.New(group.Commands, listDelegateStyle, 0, 0)
		l.Title = groupName
		l.SetShowHelp(false)
		l.SetShowStatusBar(false)
		l.SetFilteringEnabled(true)
		commandLists[groupName] = l
	}

	commandParams = map[string][]paramDefinition{
		"about": {},
		"linenum": {
			{Name: "keyword", ShortName: "k", Description: "搜索关键词", Required: false, Default: "", Type: "string"},
			{Name: "export", ShortName: "e", Description: "导出位置", Required: false, Default: "", Type: "string"},
			{Name: "report", ShortName: "r", Description: "报告名称", Required: false, Default: "", Type: "string"},
			{Name: "thorough", ShortName: "t", Description: "详细测试模式", Required: false, Default: "false", Type: "bool"},
			{Name: "sudo-password", ShortName: "s", Description: "sudo密码检查", Required: false, Default: "false", Type: "bool"},
		},
		"linux-kernel": {
			{Name: "kernel", ShortName: "k", Description: "指定内核版本", Required: false, Default: "", Type: "string"},
			{Name: "uname", ShortName: "u", Description: "uname字符串", Required: false, Default: "", Type: "string"},
			{Name: "pkglist-file", ShortName: "p", Description: "包列表文件", Required: false, Default: "", Type: "string"},
			{Name: "full", ShortName: "f", Description: "显示完整信息", Required: false, Default: "false", Type: "bool"},
			{Name: "short", ShortName: "g", Description: "简化信息模式", Required: false, Default: "false", Type: "bool"},
			{Name: "checksec", ShortName: "c", Description: "系统安全检查", Required: false, Default: "false", Type: "bool"},
		},
		"crunch": {
			{Name: "min", ShortName: "m", Description: "最小长度", Required: true, Default: "4", Type: "int", Positional: true},
			{Name: "max", ShortName: "M", Description: "最大长度", Required: true, Default: "6", Type: "int", Positional: true},
			{Name: "charset", ShortName: "c", Description: "字符集", Required: true, Default: "", Type: "string", Positional: true},
			{Name: "output", ShortName: "o", Description: "输出文件路径", Required: true, Default: "", Type: "string"},
			{Name: "threads", ShortName: "t", Description: "线程数", Required: false, Default: "4", Type: "int"},
		},
		"database": {
			{Name: "type", ShortName: "t", Description: "数据库类型", Required: true, Default: "", Type: "select"},
			{Name: "host", ShortName: "H", Description: "目标主机", Required: true, Default: "", Type: "string"},
			{Name: "port", ShortName: "P", Description: "端口", Required: false, Default: "3306", Type: "int"},
			{Name: "user", ShortName: "U", Description: "用户名", Required: true, Default: "root", Type: "string"},
			{Name: "wordlist", ShortName: "w", Description: "密码字典", Required: true, Default: "", Type: "string"},
		},
		"ftp": {
			{Name: "host", ShortName: "H", Description: "目标主机", Required: true, Default: "", Type: "string"},
			{Name: "port", ShortName: "P", Description: "端口", Required: false, Default: "21", Type: "int"},
			{Name: "user", ShortName: "U", Description: "用户名", Required: false, Default: "anonymous", Type: "string"},
			{Name: "password", ShortName: "p", Description: "密码", Required: false, Default: "anonymous@", Type: "string"},
			{Name: "wordlist", ShortName: "w", Description: "密码字典", Required: false, Default: "", Type: "string"},
		},
		"ssh": {
			{Name: "target", ShortName: "t", Description: "目标IP", Required: false, Default: "", Type: "string"},
			{Name: "file", ShortName: "f", Description: "目标列表文件", Required: false, Default: "", Type: "string"},
			{Name: "port", ShortName: "P", Description: "端口", Required: false, Default: "22", Type: "int"},
			{Name: "user", ShortName: "U", Description: "用户名", Required: false, Default: "", Type: "string"},
			{Name: "users", ShortName: "u", Description: "用户名列表文件", Required: false, Default: "", Type: "string"},
			{Name: "passwords", ShortName: "w", Description: "密码字典文件", Required: true, Default: "", Type: "string"},
			{Name: "threads", ShortName: "T", Description: "线程数", Required: false, Default: "1", Type: "int"},
			{Name: "timeout", ShortName: "t", Description: "超时(秒)", Required: false, Default: "15", Type: "int"},
			{Name: "delay", ShortName: "d", Description: "尝试间隔(ms)", Required: false, Default: "2000", Type: "int"},
			{Name: "output", ShortName: "o", Description: "输出文件", Required: false, Default: "", Type: "string"},
		},
		"scan": {
			{Name: "target", ShortName: "t", Description: "目标IP/网段", Required: true, Default: "", Type: "string"},
			{Name: "ports", ShortName: "p", Description: "端口范围", Required: false, Default: "1-1000", Type: "string"},
			{Name: "timeout", ShortName: "T", Description: "超时(ms)", Required: false, Default: "1000", Type: "int"},
			{Name: "threads", ShortName: "c", Description: "线程数", Required: false, Default: "50", Type: "int"},
			{Name: "output", ShortName: "o", Description: "输出文件", Required: false, Default: "", Type: "string"},
		},
		"dirscan": {
			{Name: "url", ShortName: "u", Description: "目标URL", Required: true, Default: "", Type: "string"},
			{Name: "wordlist", ShortName: "w", Description: "字典文件路径", Required: true, Default: "", Type: "string"},
			{Name: "threads", ShortName: "t", Description: "并发线程数", Required: false, Default: "20", Type: "int"},
			{Name: "timeout", ShortName: "T", Description: "请求超时(秒)", Required: false, Default: "10", Type: "int"},
			{Name: "extensions", ShortName: "e", Description: "扩展名扫描", Required: false, Default: "", Type: "string"},
			{Name: "user-agent", ShortName: "a", Description: "自定义User-Agent", Required: false, Default: "", Type: "string"},
			{Name: "proxy", ShortName: "x", Description: "代理服务器", Required: false, Default: "", Type: "string"},
			{Name: "output", ShortName: "o", Description: "结果输出文件", Required: false, Default: "", Type: "string"},
		},
		"route": {
			{Name: "target", ShortName: "t", Description: "目标IP", Required: true, Default: "", Type: "string"},
			{Name: "max-hops", ShortName: "m", Description: "最大跳数", Required: false, Default: "30", Type: "int"},
		},
		"whois": {
			{Name: "domain", ShortName: "d", Description: "查询域名", Required: true, Default: "", Type: "string", Positional: true},
			{Name: "server", ShortName: "s", Description: "Whois服务器", Required: false, Default: "", Type: "string"},
		},
		"rdp": {
			{Name: "target", ShortName: "t", Description: "目标IP", Required: true, Default: "", Type: "string"},
			{Name: "port", ShortName: "P", Description: "端口", Required: false, Default: "3389", Type: "int"},
			{Name: "user", ShortName: "U", Description: "用户名", Required: false, Default: "", Type: "string"},
			{Name: "password", ShortName: "p", Description: "密码", Required: false, Default: "", Type: "string"},
			{Name: "domain", ShortName: "d", Description: "域名", Required: false, Default: "", Type: "string"},
			{Name: "timeout", ShortName: "T", Description: "超时(秒)", Required: false, Default: "10", Type: "int"},
		},
		"smb": {
			{Name: "target", ShortName: "t", Description: "目标IP", Required: true, Default: "", Type: "string"},
			{Name: "port", ShortName: "P", Description: "端口", Required: false, Default: "445", Type: "int"},
			{Name: "user", ShortName: "U", Description: "用户名", Required: false, Default: "", Type: "string"},
			{Name: "password", ShortName: "p", Description: "密码", Required: false, Default: "", Type: "string"},
			{Name: "domain", ShortName: "d", Description: "域名", Required: false, Default: "", Type: "string"},
			{Name: "command", ShortName: "c", Description: "执行命令", Required: false, Default: "", Type: "string"},
			{Name: "path", ShortName: "P", Description: "共享路径", Required: false, Default: "", Type: "string"},
			{Name: "timeout", ShortName: "T", Description: "超时(秒)", Required: false, Default: "10", Type: "int"},
		},
		"powershell": {
			{Name: "target", ShortName: "t", Description: "目标IP", Required: true, Default: "", Type: "string"},
			{Name: "port", ShortName: "P", Description: "端口", Required: false, Default: "5985", Type: "int"},
			{Name: "user", ShortName: "U", Description: "用户名", Required: true, Default: "", Type: "string"},
			{Name: "password", ShortName: "p", Description: "密码", Required: true, Default: "", Type: "string"},
			{Name: "command", ShortName: "c", Description: "执行的命令", Required: true, Default: "whoami", Type: "string"},
		},
		"wmi": {
			{Name: "target", ShortName: "t", Description: "目标IP", Required: true, Default: "", Type: "string"},
			{Name: "port", ShortName: "P", Description: "端口", Required: false, Default: "135", Type: "int"},
			{Name: "user", ShortName: "U", Description: "用户名", Required: true, Default: "", Type: "string"},
			{Name: "password", ShortName: "p", Description: "密码", Required: true, Default: "", Type: "string"},
			{Name: "domain", ShortName: "d", Description: "域名", Required: false, Default: "", Type: "string"},
			{Name: "command", ShortName: "c", Description: "执行的命令", Required: false, Default: "whoami", Type: "string"},
		},
		"winlog": {
			{Name: "target", ShortName: "t", Description: "目标IP", Required: true, Default: "", Type: "string"},
			{Name: "port", ShortName: "P", Description: "端口", Required: false, Default: "135", Type: "int"},
			{Name: "user", ShortName: "U", Description: "用户名", Required: true, Default: "", Type: "string"},
			{Name: "password", ShortName: "p", Description: "密码", Required: true, Default: "", Type: "string"},
			{Name: "domain", ShortName: "d", Description: "域名", Required: false, Default: "", Type: "string"},
			{Name: "log", ShortName: "l", Description: "日志类型", Required: false, Default: "System", Type: "string"},
		},
		"userinfo": {
			{Name: "users-only", ShortName: "u", Description: "仅显示用户", Required: false, Default: "false", Type: "bool"},
			{Name: "groups-only", ShortName: "g", Description: "仅显示组", Required: false, Default: "false", Type: "bool"},
			{Name: "detailed", ShortName: "d", Description: "显示详细信息", Required: false, Default: "false", Type: "bool"},
		},
		"process": {
			{Name: "high", ShortName: "H", Description: "仅高权限进程", Required: false, Default: "false", Type: "bool"},
			{Name: "process", ShortName: "p", Description: "仅显示进程", Required: false, Default: "false", Type: "bool"},
			{Name: "service", ShortName: "S", Description: "仅显示服务", Required: false, Default: "false", Type: "bool"},
			{Name: "output", ShortName: "o", Description: "输出格式", Required: false, Default: "text", Type: "select"},
		},
		"webshell": {
			{Name: "type", ShortName: "t", Description: "WebShell类型", Required: true, Default: "", Type: "select"},
			{Name: "password", ShortName: "p", Description: "连接密码", Required: true, Default: "", Type: "string"},
			{Name: "host", ShortName: "H", Description: "目标地址", Required: true, Default: "", Type: "string"},
			{Name: "port", ShortName: "P", Description: "端口", Required: false, Default: "80", Type: "int"},
			{Name: "path", ShortName: "f", Description: "WebShell路径", Required: true, Default: "", Type: "string"},
		},
		"fu": {
			{Name: "url", ShortName: "u", Description: "目标URL", Required: true, Default: "", Type: "string"},
			{Name: "method", ShortName: "m", Description: "请求方法", Required: false, Default: "POST", Type: "select"},
			{Name: "file", ShortName: "f", Description: "上传文件路径", Required: false, Default: "", Type: "string"},
			{Name: "shell", ShortName: "s", Description: "Shell类型", Required: false, Default: "php", Type: "select"},
		},
		"waf": {
			{Name: "url", ShortName: "u", Description: "目标URL", Required: false, Default: "", Type: "string"},
			{Name: "file", ShortName: "f", Description: "目标列表文件", Required: false, Default: "", Type: "string"},
			{Name: "concurrency", ShortName: "c", Description: "并发数量", Required: false, Default: "20", Type: "int"},
			{Name: "rules", ShortName: "r", Description: "WAF规则文件", Required: false, Default: "", Type: "string"},
			{Name: "output", ShortName: "o", Description: "输出文件", Required: false, Default: "", Type: "string"},
			{Name: "format", ShortName: "F", Description: "输出格式", Required: false, Default: "txt", Type: "select"},
		},
		"wwifi": {
			{Name: "profile", ShortName: "p", Description: "WiFi配置文件", Required: false, Default: "", Type: "string"},
			{Name: "wordlist", ShortName: "w", Description: "密码字典", Required: false, Default: "", Type: "string"},
			{Name: "ssid", ShortName: "s", Description: "WiFi名称", Required: false, Default: "", Type: "string"},
		},
		"csrf": {
			{Name: "url", ShortName: "u", Description: "目标URL", Required: true, Default: "", Type: "string"},
			{Name: "method", ShortName: "m", Description: "请求方法", Required: false, Default: "POST", Type: "select"},
			{Name: "params", ShortName: "p", Description: "测试参数", Required: false, Default: "", Type: "string"},
			{Name: "payload", ShortName: "P", Description: "CSRF载荷", Required: false, Default: "", Type: "string"},
		},
		"ldap": {
			{Name: "server", ShortName: "s", Description: "LDAP服务器", Required: false, Default: "", Type: "string"},
			{Name: "port", ShortName: "P", Description: "端口", Required: false, Default: "389", Type: "int"},
			{Name: "domain", ShortName: "d", Description: "域名", Required: false, Default: "", Type: "string"},
			{Name: "username", ShortName: "u", Description: "用户名", Required: false, Default: "", Type: "string"},
			{Name: "password", ShortName: "w", Description: "密码", Required: false, Default: "", Type: "string"},
			{Name: "base", ShortName: "b", Description: "基础DN", Required: false, Default: "", Type: "string"},
			{Name: "protocol", ShortName: "P", Description: "协议类型", Required: false, Default: "ldap", Type: "select"},
			{Name: "timeout", ShortName: "t", Description: "超时时间", Required: false, Default: "30", Type: "int"},
			{Name: "filter", ShortName: "f", Description: "LDAP过滤器", Required: false, Default: "", Type: "string"},
		},
		"dcom": {
			{Name: "target", ShortName: "t", Description: "目标IP", Required: true, Default: "", Type: "string"},
			{Name: "port", ShortName: "P", Description: "端口", Required: false, Default: "135", Type: "int"},
			{Name: "user", ShortName: "U", Description: "用户名", Required: true, Default: "", Type: "string"},
			{Name: "password", ShortName: "p", Description: "密码", Required: true, Default: "", Type: "string"},
			{Name: "domain", ShortName: "d", Description: "域名", Required: false, Default: "", Type: "string"},
			{Name: "command", ShortName: "c", Description: "执行的命令", Required: false, Default: "calc.exe", Type: "string"},
		},
	}

	return model{
		width:              0,
		height:             0,
		showWelcome:        true,
		activeTab:          0,
		tabs:               []string{"Tools", "Crack", "Scan", "Remote", "Info", "Web", "Test"},
		commandLists:       commandLists,
		commandParams:      commandParams,
		activeCommandList:  "综合工具",
		inputs:             make(map[string][]textinput.Model),
		activeInput:        0,
		inputFocus:         false,
		results:            make(map[string]string),
		resultLogs:         make(map[string][]string),
		resultContent:      "",
		resultPlainContent: "",
		currentCommand:     "",
		lastResultContent:  "",
		running:            false,
		runningStatus:      "",
		quitting:           false,
		viewport:           viewport.New(0, 0),
		parameterMode:      false,
		focusArea:          "menu",
	}
}

type resultUpdateMsg struct {
	command string
	result  string
	log     string
}

func (m model) Init() tea.Cmd {
	return nil
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		paramWidth := 35
		resultWidth := msg.Width - 18 - paramWidth - 6
		if resultWidth < 40 {
			resultWidth = 40
		}
		m.viewport.Width = resultWidth - 4
		m.viewport.Height = msg.Height - 7
		return m, nil

	case tea.KeyMsg:
		key := msg.String()

		if key == "ctrl+c" {
			m.quitting = true
			return m, tea.Quit
		}

		if m.showWelcome {
			if key == "enter" {
				m.showWelcome = false
			}
			return m, nil
		}

		selectedItem := m.commandLists[m.activeCommandList].SelectedItem()
		var commandName string
		if selectedItem != nil {
			commandName = selectedItem.(CommandItem).Name
		}

		if m.focusArea == "result" {
			if key == "esc" || key == "left" {
				m.focusArea = "menu"
				return m, nil
			}
			if key == "pgup" {
				m.viewport.LineUp(10)
				return m, nil
			}
			if key == "pgdown" {
				m.viewport.LineDown(10)
				return m, nil
			}
			if key == "home" {
				m.viewport.GotoTop()
				return m, nil
			}
			if key == "end" {
				m.viewport.GotoBottom()
				return m, nil
			}
			if key == "up" {
				m.viewport.LineUp(1)
				return m, nil
			}
			if key == "down" {
				m.viewport.LineDown(1)
				return m, nil
			}
			var cmd tea.Cmd
			m.viewport, cmd = m.viewport.Update(msg)
			if cmd != nil {
				cmds = append(cmds, cmd)
			}
			return m, tea.Batch(cmds...)
		}

		if m.focusArea == "menu" {
			if key == "ctrl+right" || key == "ctrl+l" {
				m.focusArea = "result"
				if commandName != "" && m.resultContent == "" {
					m.updateResultContent(commandName)
				}
				if m.resultContent != "" {
					m.viewport.SetContent(m.resultContent)
				}
				return m, nil
			}
		}

		if m.focusArea == "param" {
			if key == "esc" || key == "left" {
				m.focusArea = "menu"
				m.parameterMode = false
				m.inputFocus = false
				if commandName != "" {
					inputs := m.inputs[commandName]
					if len(inputs) > 0 && m.activeInput < len(inputs) {
						inputs[m.activeInput].Blur()
						m.inputs[commandName] = inputs
					}
				}
				m.activeInput = 0
				return m, nil
			}
			if key == "ctrl+right" || key == "ctrl+l" {
				m.focusArea = "result"
				if commandName != "" && m.resultContent == "" {
					m.updateResultContent(commandName)
				}
				if m.resultContent != "" {
					m.viewport.SetContent(m.resultContent)
				}
				return m, nil
			}
		}

		if m.parameterMode && commandName != "" && m.focusArea == "param" {
			inputs, hasInputs := m.inputs[commandName]
			if hasInputs && len(inputs) > 0 && m.activeInput < len(inputs) {
				currentInput := inputs[m.activeInput]

				if key == "down" || key == "tab" {
					currentInput.Blur()
					inputs[m.activeInput] = currentInput
					m.activeInput++
					if m.activeInput >= len(inputs) {
						m.activeInput = 0
					}
					inputs[m.activeInput].Focus()
					m.inputs[commandName] = inputs
					return m, nil
				}

				if key == "shift+tab" {
					currentInput.Blur()
					inputs[m.activeInput] = currentInput
					m.activeInput--
					if m.activeInput < 0 {
						m.activeInput = len(inputs) - 1
					}
					inputs[m.activeInput].Focus()
					m.inputs[commandName] = inputs
					return m, nil
				}

				newInput, inputCmd := currentInput.Update(msg)
				inputs[m.activeInput] = newInput
				m.inputs[commandName] = inputs
				if inputCmd != nil {
					cmds = append(cmds, inputCmd)
				}
			}

			if key == "enter" {
				paramValues := make(map[string]string)
				params := m.commandParams[commandName]
				allValid := true
				for i, param := range params {
					if i < len(inputs) {
						value := inputs[i].Value()
						paramValues[param.Name] = value
						if param.Required && value == "" {
							m.resultLogs[commandName] = append(m.resultLogs[commandName], fmt.Sprintf("错误: 参数 %s 是必填项", param.Name))
							allValid = false
						}
						if param.Type == "int" && value != "" {
							if _, err := strconv.Atoi(value); err != nil {
								m.resultLogs[commandName] = append(m.resultLogs[commandName], fmt.Sprintf("错误: 参数 %s 必须是数字", param.Name))
								allValid = false
							}
						}
					}
				}
				if allValid {
					m.running = true
					m.runningStatus = "正在执行命令..."
					m.resultContent = secondaryStyle.Render("⏳ "+m.runningStatus) + "\n\n"
					m.viewport.SetContent(m.resultContent)
					cmds = append(cmds, executeCommand(commandName, paramValues))
				}
				return m, tea.Batch(cmds...)
			}

			return m, tea.Batch(cmds...)
		}

		if !m.parameterMode && m.focusArea == "menu" {
			if key == "enter" && commandName != "" {
				params := m.commandParams[commandName]
				m.currentCommand = commandName
				m.parameterMode = true
				m.focusArea = "param"
				m.activeInput = 0

				if len(params) > 0 {
					m.inputFocus = true
					oldInputs, inputsExist := m.inputs[commandName]
					if !inputsExist {
						oldInputs = make([]textinput.Model, len(params))
						for i, param := range params {
							oldInputs[i] = textinput.New()
							oldInputs[i].Placeholder = param.Default
							oldInputs[i].SetValue(param.Default)
							oldInputs[i].Prompt = param.Name + ": "
							oldInputs[i].Width = 25
						}
						m.inputs[commandName] = oldInputs
					}
					for i := range oldInputs {
						oldInputs[i].Blur()
					}
					if len(oldInputs) > 0 {
						oldInputs[0].Focus()
						m.inputs[commandName] = oldInputs
					}
				} else {
					m.running = true
					m.runningStatus = "正在执行命令..."
					m.resultContent = secondaryStyle.Render("⏳ "+m.runningStatus) + "\n\n"
					m.viewport.SetContent(m.resultContent)
					cmds = append(cmds, executeCommand(commandName, make(map[string]string)))
				}
				return m, tea.Batch(cmds...)
			}
		}

		if key == "left" {
			if m.activeTab > 0 {
				m.activeTab--
				tabName := m.tabs[m.activeTab]
				if commandListName, ok := tabToCommandList[tabName]; ok {
					m.activeCommandList = commandListName
				}
				m.parameterMode = false
				m.inputFocus = false
				m.focusArea = "menu"
			}
			return m, nil
		}

		if key == "right" {
			if m.activeTab < len(m.tabs)-1 {
				m.activeTab++
				tabName := m.tabs[m.activeTab]
				if commandListName, ok := tabToCommandList[tabName]; ok {
					m.activeCommandList = commandListName
				}
				m.parameterMode = false
				m.inputFocus = false
				m.focusArea = "menu"
			}
			return m, nil
		}

		if key == "pgup" && m.focusArea == "menu" {
			m.viewport.LineUp(10)
			return m, nil
		}

		if key == "pgdown" && m.focusArea == "menu" {
			m.viewport.LineDown(10)
			return m, nil
		}

		if key == "home" && m.focusArea == "menu" {
			m.viewport.GotoTop()
			return m, nil
		}

		if key == "end" && m.focusArea == "menu" {
			m.viewport.GotoBottom()
			return m, nil
		}

		oldSelectedItem := selectedItem
		l := m.commandLists[m.activeCommandList]
		newList, cmd := l.Update(msg)
		m.commandLists[m.activeCommandList] = newList
		cmds = append(cmds, cmd)

		var newSelectedItem list.Item
		newSelectedItem = m.commandLists[m.activeCommandList].SelectedItem()
		if newSelectedItem != nil && (oldSelectedItem == nil || newSelectedItem.(CommandItem).Name != oldSelectedItem.(CommandItem).Name) {
			newCommandName := newSelectedItem.(CommandItem).Name
			m.currentCommand = newCommandName
			m.updateResultContent(newCommandName)
		}

		return m, tea.Batch(cmds...)

	case resultUpdateMsg:
		m.results[msg.command] = msg.result
		m.running = false
		m.runningStatus = ""
		if msg.log != "" {
			if m.resultLogs[msg.command] == nil {
				m.resultLogs[msg.command] = []string{}
			}
			m.resultLogs[msg.command] = append(m.resultLogs[msg.command], msg.log)
		}
		if m.currentCommand == msg.command {
			m.resultPlainContent = msg.result
			m.resultContent = msg.result
		} else {
			m.updateResultContent(msg.command)
		}
		m.lastResultContent = m.resultPlainContent
		m.viewport.SetContent(m.resultContent)
		m.parameterMode = false
		m.focusArea = "menu"
		m.inputFocus = false
		return m, nil

	default:
		return m, nil
	}
}

func (m model) View() string {
	if m.quitting {
		return "正在退出..."
	}

	if m.showWelcome {
		return m.welcomeView()
	}

	return m.mainView()
}

func (m model) welcomeView() string {
	boxStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(primaryColor).
		Padding(2, 4).
		Foreground(textColor).
		Align(lipgloss.Center)

	art := `    ____  __   __                               
   / ___| / /  ___    ___    __ _   _ __  
  | |  _   V /  / __|  / __|  / _` + "`" + ` | | '_ \ 
  | |_| |   | |   \__ \ | (__  | (_| | | | | | 
   \____|   |_|   |___/  \___|  \__,_| |_| |_|`

	content := art + "\n\n"
	content += "GYscan v2.6.3\n"
	content += dimTextStyle.Render("Network Security Testing Tool") + "\n\n"
	content += "[Enter] Menu    [Ctrl+C] Quit"

	return lipgloss.JoinVertical(lipgloss.Center, boxStyle.Render(content))
}

const (
	minWidth  = 80
	minHeight = 15
)

func (m model) mainView() string {
	if m.width == 0 || m.height == 0 {
		return "正在初始化..."
	}

	if m.width < minWidth || m.height < minHeight {
		return m.renderSizeWarning()
	}

	panelHeight := m.height - 3
	menuWidth := 17
	paramWidth := 34
	borderSpace := 2
	resultWidth := m.width - menuWidth - paramWidth - borderSpace*2

	if resultWidth < 40 {
		resultWidth = 40
	}

	menuPanel := m.renderMenuPanel(menuWidth, panelHeight)
	paramPanel := m.renderParamPanel(paramWidth, panelHeight)
	resultPanel := m.renderResultPanel(resultWidth, panelHeight)

	return lipgloss.JoinVertical(
		lipgloss.Left,
		m.renderCompactTabs(),
		lipgloss.JoinHorizontal(
			lipgloss.Top,
			menuPanel,
			"",
			paramPanel,
			"",
			resultPanel,
		),
	)
}

func (m model) renderMenuPanel(width, height int) string {
	l := m.commandLists[m.activeCommandList]
	listHeight := height - 4
	if listHeight < 5 {
		listHeight = 5
	}
	l.SetWidth(width - 2)
	l.SetHeight(listHeight)

	listView := l.View()

	title := lipgloss.NewStyle().Foreground(primaryColor).Bold(true).Render("Menu")
	if m.focusArea == "menu" {
		title = lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF00")).Bold(true).Render("Menu ◄")
	}
	divider := dividerStyle.Render("─")

	panelStyle := menuPanelStyle
	if m.focusArea == "menu" {
		panelStyle = menuPanelStyle.BorderForeground(lipgloss.Color("#00FF00"))
	}

	return panelStyle.
		Width(width).
		Height(height).
		Padding(0, 1).
		Render(title + "\n" + divider + "\n" + listView)
}

func (m model) renderParamPanel(width, height int) string {
	selectedItem := m.commandLists[m.activeCommandList].SelectedItem()
	var commandName string
	if selectedItem != nil {
		commandName = selectedItem.(CommandItem).Name
	}

	var content strings.Builder

	title := lipgloss.NewStyle().Foreground(secondaryColor).Bold(true).Render("Settings")
	if m.focusArea == "param" {
		title = lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF00")).Bold(true).Render("Settings ◄")
	}
	divider := dividerStyle.Render("─")
	content.WriteString(title + "\n" + divider + "\n")

	if commandName != "" {
		desc := lipgloss.NewStyle().Foreground(dimTextColor).Italic(true).Render("命令: " + commandName)
		content.WriteString(desc)
		content.WriteString("\n\n")
	}

	params, exists := m.commandParams[commandName]
	if !exists || len(params) == 0 {
		content.WriteString(dimTextStyle.Render("无需参数"))
		content.WriteString("\n")
		content.WriteString("\n")
		if m.running {
			content.WriteString(secondaryStyle.Render("⏳ 执行中..."))
		} else {
			content.WriteString(secondaryStyle.Render("[Enter] 执行命令"))
		}
		content.WriteString("\n")
	} else {
		for i, param := range params {
			mark := ""
			if param.Required {
				mark = focusedTextStyle.Render("*")
			}

			typeHint := ""
			switch param.Type {
			case "int":
				typeHint = dimTextStyle.Render(" (数字)")
			case "string":
				typeHint = dimTextStyle.Render(" (文本)")
			}

			label := lipgloss.NewStyle().Foreground(textColor).Render(param.Description) + mark + typeHint
			value := ""

			if len(m.inputs) > 0 && len(m.inputs[commandName]) > i {
				inputModel := m.inputs[commandName][i]
				if i == m.activeInput && m.inputFocus {
					value = focusedInputStyle.Render(inputModel.View())
				} else {
					value = blurredInputStyle.Render(inputModel.View())
				}
			} else {
				value = dimTextStyle.Render(param.Default)
			}

			content.WriteString(label + "\n")
			content.WriteString("  " + value + "\n")
		}

		content.WriteString("\n")
		hint := lipgloss.NewStyle().Foreground(dimTextColor).Render("提示: * 为必填项")
		content.WriteString(hint)
		content.WriteString("\n\n")

		if commandName == "crunch" {
			example := lipgloss.NewStyle().
				Foreground(lipgloss.Color("#74B9FF")).
				Bold(true).
				Render("示例: crunch 6 8 abcdef -o pass.txt")
			content.WriteString("格式: min max charset -o output\n")
			content.WriteString(example)
			content.WriteString("\n\n")
		}

		if m.running {
			content.WriteString(secondaryStyle.Render("⏳ 执行中..."))
		} else {
			content.WriteString(secondaryStyle.Render("[Enter] 执行"))
			content.WriteString("   ")
			content.WriteString(focusedTextStyle.Render("[Esc] 返回"))
		}
		content.WriteString("\n")
	}

	panelStyle := paramPanelStyle
	if m.focusArea == "param" {
		panelStyle = paramPanelStyle.BorderForeground(lipgloss.Color("#00FF00"))
	}

	return panelStyle.
		Width(width).
		Height(height).
		Render(content.String())
}

func (m model) updateResultContent(commandName string) {
	var plainContent strings.Builder
	var styledContent strings.Builder

	logs := m.resultLogs[commandName]
	if len(logs) > 0 {
		for _, log := range logs {
			plainContent.WriteString(log)
			plainContent.WriteString("\n")

			if strings.Contains(log, "错误") || strings.Contains(log, "Error") || strings.Contains(log, "失败") {
				styledContent.WriteString(focusedTextStyle.Render(log))
			} else if strings.Contains(log, "[+]") || strings.Contains(log, "[*]") {
				styledContent.WriteString(secondaryStyle.Render(log))
			} else {
				styledContent.WriteString(normalTextStyle.Render(log))
			}
			styledContent.WriteString("\n")
		}
	}

	result := m.results[commandName]
	if result != "" {
		if len(logs) > 0 {
			plainContent.WriteString("─")
			plainContent.WriteString("\n")
			styledContent.WriteString(dividerStyle.Render("─"))
			styledContent.WriteString("\n")
		}

		resultLines := strings.Split(result, "\n")
		for _, line := range resultLines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			plainContent.WriteString(line)
			plainContent.WriteString("\n")

			if strings.Contains(line, "错误") || strings.Contains(line, "Error") || strings.Contains(line, "失败") || strings.Contains(line, "✗") {
				styledContent.WriteString(focusedTextStyle.Render(line))
			} else if strings.Contains(line, "✓") || strings.Contains(line, "[+]") || strings.Contains(line, "[*]") || strings.Contains(line, "【") {
				styledContent.WriteString(secondaryStyle.Render(line))
			} else {
				styledContent.WriteString(normalTextStyle.Render(line))
			}
			styledContent.WriteString("\n")
		}
	}

	if len(logs) == 0 && result == "" {
		plainContent.WriteString("等待执行...")
		plainContent.WriteString("\n")
		styledContent.WriteString(dimTextStyle.Render("等待执行..."))
		styledContent.WriteString("\n")
	}

	m.resultPlainContent = plainContent.String()
	m.resultContent = styledContent.String()
}

func (m model) renderResultPanel(width, height int) string {
	selectedItem := m.commandLists[m.activeCommandList].SelectedItem()
	var commandName string
	if selectedItem != nil {
		commandName = selectedItem.(CommandItem).Name
	}

	viewportHeight := height - 4
	if viewportHeight < 5 {
		viewportHeight = 5
	}

	m.viewport.Width = width - 4
	m.viewport.Height = viewportHeight

	if commandName != "" && commandName != m.currentCommand {
		m.currentCommand = commandName
		m.updateResultContent(commandName)
	}

	if m.resultPlainContent == "" {
		m.resultPlainContent = "等待执行..."
		m.resultContent = dimTextStyle.Render("等待执行...")
	}

	if m.running && m.resultPlainContent == "等待执行..." {
		m.resultPlainContent = "⏳ " + m.runningStatus
		m.resultContent = secondaryStyle.Render("⏳ " + m.runningStatus)
	}

	if m.resultPlainContent != m.lastResultContent {
		m.lastResultContent = m.resultPlainContent
		m.viewport.SetContent(m.resultContent)
	}

	title := lipgloss.NewStyle().Foreground(focusedColor).Bold(true).Render("Output")
	divider := dividerStyle.Render("─")

	panelStyle := resultPanelStyle
	if m.focusArea == "result" {
		panelStyle = resultFocusedStyle
		title = lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF00")).Bold(true).Render("Output ◄")
	}

	panelContent := title + "\n" + divider + "\n" + m.viewport.View()

	return panelStyle.
		Height(height).
		Render(panelContent)
}

func (m model) renderSizeWarning() string {
	warningStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#FF0000")).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#FF0000")).
		Padding(2, 4).
		Align(lipgloss.Center).
		Width(minWidth - 10).
		Height(minHeight - 10)

	warning := fmt.Sprintf(`
终端尺寸不足！

当前尺寸: %dx%d
所需尺寸: %dx%d

请调整终端窗口大小后重试。

按 Ctrl+C 退出`, m.width, m.height, minWidth, minHeight)

	return lipgloss.Place(
		m.width,
		m.height,
		lipgloss.Center,
		lipgloss.Center,
		warningStyle.Render(warning),
	)
}

func (m model) renderCompactTabs() string {
	var tabs []string
	tabNames := []string{"Tools", "Crack", "Scan", "Remote", "Info", "Web", "Test"}

	for i, tab := range tabNames {
		if i == m.activeTab {
			tabs = append(tabs, activeTabStyle.Render("["+tab+"]"))
		} else {
			tabs = append(tabs, inactiveTabStyle.Render(tab))
		}
	}

	return lipgloss.JoinHorizontal(lipgloss.Left, tabs...)
}

func executeCommand(commandName string, paramValues map[string]string) tea.Cmd {
	return func() tea.Msg {
		args := []string{commandName}
		flags := []string{}
		positional := []string{}

		for name, value := range paramValues {
			if value != "" {
				isPositional := false
				if params, ok := commandParams[commandName]; ok {
					for _, param := range params {
						if param.Name == name && param.Positional {
							isPositional = true
							break
						}
					}
				}
				if isPositional {
					positional = append(positional, value)
				} else {
					flags = append(flags, fmt.Sprintf("--%s=%s", name, value))
				}
			}
		}

		args = append(args, positional...)
		args = append(args, flags...)

		cmdStr := commandName
		for _, p := range positional {
			cmdStr += fmt.Sprintf(" %s", p)
		}
		for _, f := range flags {
			cmdStr += fmt.Sprintf(" %s", f)
		}

		startTime := time.Now()

		oldStdout := os.Stdout
		oldStderr := os.Stderr

		stdoutReader, stdoutWriter, _ := os.Pipe()
		stderrReader, stderrWriter, _ := os.Pipe()

		os.Stdout = stdoutWriter
		os.Stderr = stderrWriter

		var stdoutBuf, stderrBuf strings.Builder

		go func() {
			io.Copy(&stdoutBuf, stdoutReader)
		}()

		go func() {
			io.Copy(&stderrBuf, stderrReader)
		}()

		cmd := rootCmd
		cmd.SetArgs(args)
		err := cmd.Execute()

		stdoutWriter.Close()
		stderrWriter.Close()

		os.Stdout = oldStdout
		os.Stderr = oldStderr

		execTime := time.Since(startTime)

		result := fmt.Sprintf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
		result += fmt.Sprintf("命令: %s\n", commandName)
		result += fmt.Sprintf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")
		result += fmt.Sprintf("执行命令: %s\n\n", cmdStr)
		result += "【参数值】\n"
		for name, value := range paramValues {
			result += fmt.Sprintf("  • %s: %s\n", name, value)
		}
		result += "\n【执行结果】\n"

		stdout := stdoutBuf.String()
		if stdout != "" {
			result += stdout + "\n"
		}

		stderr := stderrBuf.String()
		if stderr != "" {
			result += "【错误输出】\n" + stderr + "\n"
		}

		if err != nil {
			result += fmt.Sprintf("✗ 执行失败: %v\n", err)
			result += fmt.Sprintf("返回码: 1\n")
		} else {
			result += "✓ 执行成功！\n"
			result += fmt.Sprintf("返回码: 0\n")
		}

		result += fmt.Sprintf("\n【执行信息】\n")
		result += fmt.Sprintf("  • 耗时: %v\n", execTime)
		result += fmt.Sprintf("  • 时间: %s\n", time.Now().Format("2006-01-02 15:04:05"))

		logOutput := fmt.Sprintf("[+] 开始执行: %s", commandName)
		if stdout != "" {
			lines := strings.Split(stdout, "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line != "" && (strings.HasPrefix(line, "[+]") || strings.HasPrefix(line, "[*]") || strings.HasPrefix(line, "[-]")) {
					logOutput += "\n" + line
				}
			}
		}

		return resultUpdateMsg{
			command: commandName,
			result:  result,
			log:     logOutput,
		}
	}
}
