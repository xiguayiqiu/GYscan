package cli

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"
)

type FlagParser struct {
	cmd     *cobra.Command
	verbose bool
}

func NewFlagParser(cmd *cobra.Command) *FlagParser {
	return &FlagParser{cmd: cmd}
}

func (p *FlagParser) GetString(name string) string {
	val, err := p.cmd.Flags().GetString(name)
	if err != nil {
		return ""
	}
	return val
}

func (p *FlagParser) GetInt(name string) int {
	val, err := p.cmd.Flags().GetInt(name)
	if err != nil {
		return 0
	}
	return val
}

func (p *FlagParser) GetBool(name string) bool {
	val, err := p.cmd.Flags().GetBool(name)
	if err != nil {
		return false
	}
	return val
}

func (p *FlagParser) GetStringSlice(name string) []string {
	val, err := p.cmd.Flags().GetStringSlice(name)
	if err != nil {
		return []string{}
	}
	return val
}

func (p *FlagParser) GetIntSlice(name string) []int {
	val, err := p.cmd.Flags().GetIntSlice(name)
	if err != nil {
		return []int{}
	}
	return val
}

func (p *FlagParser) Required(names ...string) error {
	var missing []string
	for _, name := range names {
		if p.GetString(name) == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("required flags not set: %v", missing)
	}
	return nil
}

func (p *FlagParser) AtLeastOne(names ...string) error {
	for _, name := range names {
		if p.GetString(name) != "" {
			return nil
		}
	}
	return errors.New("at least one of these flags must be set: " + fmt.Sprint(names))
}

func (p *FlagParser) MutuallyExclusive(names ...string) error {
	setCount := 0
	for _, name := range names {
		if p.GetString(name) != "" {
			setCount++
		}
	}
	if setCount > 1 {
		return errors.New("these flags are mutually exclusive: " + fmt.Sprint(names))
	}
	return nil
}

func (p *FlagParser) SetVerbose(v bool) {
	p.verbose = v
}

func (p *FlagParser) IsVerbose() bool {
	return p.verbose
}

type SSHFlags struct {
	target    string
	targets   string
	port      int
	user      string
	users     string
	passwords string
	threads   int
	timeout   int
	delay     int
	output    string
	verbose   bool
}

func ParseSSHFlags(cmd *cobra.Command) *SSHFlags {
	f := NewFlagParser(cmd)
	return &SSHFlags{
		target:    f.GetString("target"),
		targets:   f.GetString("file"),
		port:      f.GetInt("port"),
		user:      f.GetString("user"),
		users:     f.GetString("users"),
		passwords: f.GetString("passwords"),
		threads:   f.GetInt("threads"),
		timeout:   f.GetInt("timeout"),
		delay:     f.GetInt("delay"),
		output:    f.GetString("output"),
		verbose:   f.GetBool("verbose"),
	}
}

func (f *SSHFlags) Validate() error {
	p := &FlagParser{}
	if err := p.Required("passwords"); err != nil {
		return err
	}
	if err := p.AtLeastOne("target", "targets"); err != nil {
		return err
	}
	if err := p.AtLeastOne("user", "users"); err != nil {
		return err
	}
	return nil
}

type ScanFlags struct {
	target  string
	ports   string
	timeout int
	threads int
	output  string
	verbose bool
}

func ParseScanFlags(cmd *cobra.Command) *ScanFlags {
	f := NewFlagParser(cmd)
	return &ScanFlags{
		target:  f.GetString("target"),
		ports:   f.GetString("ports"),
		timeout: f.GetInt("timeout"),
		threads: f.GetInt("threads"),
		output:  f.GetString("output"),
		verbose: f.GetBool("verbose"),
	}
}

type BruteForceFlags struct {
	target    string
	user      string
	users     string
	passwords string
	port      int
	threads   int
	timeout   int
	output    string
	verbose   bool
}

func ParseBruteForceFlags(cmd *cobra.Command) *BruteForceFlags {
	f := NewFlagParser(cmd)
	return &BruteForceFlags{
		target:    f.GetString("target"),
		user:      f.GetString("user"),
		users:     f.GetString("users"),
		passwords: f.GetString("passwords"),
		port:      f.GetInt("port"),
		threads:   f.GetInt("threads"),
		timeout:   f.GetInt("timeout"),
		output:    f.GetString("output"),
		verbose:   f.GetBool("verbose"),
	}
}
