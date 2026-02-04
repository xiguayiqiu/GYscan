package cli

import (
	"GYscan/internal/csrf"
	"GYscan/internal/exp"
	"GYscan/internal/nmap"
	"GYscan/internal/scapy"
	"GYscan/internal/xss"

	"github.com/spf13/cobra"
)

type CommandGroup string

const (
	GroupGeneral  CommandGroup = "综合工具"
	GroupPassword CommandGroup = "密码学工具"
	GroupNetwork  CommandGroup = "网络扫描工具"
	GroupRemote   CommandGroup = "远程管理工具"
	GroupInfo     CommandGroup = "信息收集工具"
	GroupWeb      CommandGroup = "Web安全工具"
	GroupTesting  CommandGroup = "测试阶段命令"
)

type CommandRegistry struct {
	commands map[string]*cobra.Command
	groups   map[CommandGroup][]*cobra.Command
}

func NewRegistry() *CommandRegistry {
	return &CommandRegistry{
		commands: make(map[string]*cobra.Command),
		groups:   make(map[CommandGroup][]*cobra.Command),
	}
}

func (r *CommandRegistry) Register(cmd *cobra.Command, group CommandGroup) {
	r.commands[cmd.Name()] = cmd
	r.groups[group] = append(r.groups[group], cmd)
}

func (r *CommandRegistry) GetCommand(name string) *cobra.Command {
	return r.commands[name]
}

func (r *CommandRegistry) GetGroup(group CommandGroup) []*cobra.Command {
	return r.groups[group]
}

func (r *CommandRegistry) GetAllCommands() []*cobra.Command {
	var cmds []*cobra.Command
	for _, cmd := range r.commands {
		cmds = append(cmds, cmd)
	}
	return cmds
}

func (r *CommandRegistry) GetGroupsInOrder() []CommandGroup {
	return []CommandGroup{
		GroupGeneral,
		GroupPassword,
		GroupNetwork,
		GroupRemote,
		GroupInfo,
		GroupWeb,
		GroupTesting,
	}
}

func BuildRegistry() *CommandRegistry {
	r := NewRegistry()

	r.Register(aboutCmd, GroupGeneral)
	r.Register(crunchCmd, GroupPassword)
	r.Register(databaseCmd, GroupPassword)
	r.Register(ftpCmd, GroupPassword)
	r.Register(sshCmd, GroupPassword)

	r.Register(nmap.ScanCmd, GroupNetwork)
	r.Register(dirscanCmd, GroupNetwork)
	r.Register(routeCmd, GroupNetwork)
	r.Register(whoisCmd, GroupNetwork)
	r.Register(scapy.ScapyCmd, GroupNetwork)

	r.Register(powershellCmd, GroupRemote)
	r.Register(rdpCmd, GroupRemote)
	r.Register(smbCmd, GroupRemote)
	r.Register(wmiCmd, GroupRemote)

	r.Register(processCmd, GroupInfo)
	r.Register(userinfoCmd, GroupInfo)
	r.Register(winlogCmd, GroupInfo)
	r.Register(pcCmd, GroupInfo)

	r.Register(webshellCmd, GroupWeb)
	r.Register(wafCmd, GroupWeb)
	r.Register(xss.XssCmd, GroupWeb)
	r.Register(fuCmd, GroupWeb)
	r.Register(wsCmd, GroupWeb)

	r.Register(linenumCmd, GroupGeneral)
	r.Register(linuxKernelCmd, GroupGeneral)
	r.Register(wwifiCmd, GroupGeneral)

	r.Register(csrf.Cmd, GroupTesting)
	r.Register(dcomCmd, GroupTesting)
	r.Register(ldapCmd, GroupTesting)
	r.Register(mgCmd, GroupTesting)
	r.Register(adcsCmd, GroupTesting)
	r.Register(exp.ExpCmd, GroupWeb)

	return r
}

func RegisterAllCommands(cmd *cobra.Command) {
	r := BuildRegistry()
	for _, c := range r.GetAllCommands() {
		cmd.AddCommand(c)
	}
}
