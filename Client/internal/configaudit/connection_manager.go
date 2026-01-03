package configaudit

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

type ConnectionManager struct {
	mu            sync.RWMutex
	sshClient     *SSHClient
	wmiClient     *WMIClient
	winRMClient   *WindowsRMClient
	currentMode   ConnectionMode
	targetOS      OSType
	target        string
	config        *ConnectionConfig
}

type ConnectionConfig struct {
	Target          string
	OSType          OSType
	SSHConfig       *SSHConfig
	WMIConfig       *WMIConfig
	WinRMConfig     *WindowsRMConfig
	PreferredMode   ConnectionMode
	Timeout         time.Duration
	AutoDetect      bool
	ForceMode       bool
}

type ConnectionState int

const (
	StateDisconnected ConnectionState = iota
	StateConnecting
	StateConnected
	StateFailed
)

type ConnectionStatus struct {
	State       ConnectionState
	Mode        ConnectionMode
	OSType      OSType
	Error       error
	Message     string
	ConnectedAt time.Time
}

func NewConnectionManager(config *ConnectionConfig) *ConnectionManager {
	return &ConnectionManager{
		config: config,
	}
}

func (m *ConnectionManager) Connect() (*ConnectionStatus, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	status := &ConnectionStatus{
		State: StateConnecting,
	}

	if m.config.AutoDetect {
		targetInfo, err := DetectRemoteSystem(m.config.Target, m.config.Timeout)
		if err != nil {
			status.State = StateFailed
			status.Error = err
			status.Message = fmt.Sprintf("系统检测失败: %v", err)
			return status, err
		}

		m.targetOS = targetInfo.OSType
		status.OSType = targetInfo.OSType
	}

	if m.config.OSType != OSUnknown && m.config.OSType != "" {
		m.targetOS = m.config.OSType
	}

	if m.targetOS == OSUnknown && m.config.PreferredMode == ConnectionModeAuto {
		m.targetOS = OSWindows
	}

	var err error
	var mode ConnectionMode

	if m.config.ForceMode {
		mode = m.config.PreferredMode
	} else {
		mode = m.determineBestMode()
	}

	m.currentMode = mode
	status.Mode = mode

	switch m.targetOS {
	case OSWindows:
		err = m.connectWindows(mode)
	case OSLinux:
		err = m.connectLinux(mode)
	default:
		err = m.connectLinux(mode)
	}

	if err != nil {
		status.State = StateFailed
		status.Error = err
		status.Message = fmt.Sprintf("连接失败 (%s模式): %v", mode, err)
		return status, err
	}

	status.State = StateConnected
	status.Message = fmt.Sprintf("成功建立%s连接", mode)
	status.ConnectedAt = time.Now()

	return status, nil
}

func (m *ConnectionManager) determineBestMode() ConnectionMode {
	if m.config.ForceMode {
		return m.config.PreferredMode
	}

	if m.config.PreferredMode != ConnectionModeAuto {
		return m.config.PreferredMode
	}

	switch m.targetOS {
	case OSWindows:
		if m.config.WMIConfig != nil {
			return ConnectionModeWMI
		}
		return ConnectionModeAuto

	case OSLinux:
		if m.config.SSHConfig != nil {
			return ConnectionModeSSH
		}
		return ConnectionModeAuto
	default:
		return ConnectionModeAuto
	}
}

func (m *ConnectionManager) connectWindows(mode ConnectionMode) error {
	switch mode {
	case ConnectionModeWMI:
		if m.config.WMIConfig == nil {
			return fmt.Errorf("Windows连接需要WMI配置")
		}
		m.wmiClient = NewWMIClient(m.config.WMIConfig)
		return m.wmiClient.Connect()
	case ConnectionModeAuto:
		m.wmiClient = NewWMIClient(m.config.WMIConfig)
		err := m.wmiClient.Connect()
		if err == nil {
			m.currentMode = ConnectionModeWMI
			return nil
		}
		return fmt.Errorf("无法建立任何Windows连接: %v", err)
	default:
		return fmt.Errorf("Windows系统不支持 %s 连接模式，请使用WMI模式", mode)
	}
}

func (m *ConnectionManager) connectLinux(mode ConnectionMode) error {
	switch mode {
	case ConnectionModeSSH:
		if m.config.SSHConfig == nil {
			return fmt.Errorf("Linux连接需要SSH配置")
		}
		m.sshClient = NewSSHClient(m.config.SSHConfig)
		return m.sshClient.Connect()
	case ConnectionModeAuto:
		m.sshClient = NewSSHClient(m.config.SSHConfig)
		err := m.sshClient.Connect()
		if err == nil {
			m.currentMode = ConnectionModeSSH
			return nil
		}
		return fmt.Errorf("无法建立任何Linux连接: %v", err)
	default:
		return fmt.Errorf("Linux系统不支持 %s 连接模式，请使用SSH模式", mode)
	}
}

func (m *ConnectionManager) Disconnect() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.sshClient != nil {
		m.sshClient.Close()
		m.sshClient = nil
	}

	if m.wmiClient != nil {
		m.wmiClient.Close()
		m.wmiClient = nil
	}

	m.currentMode = ConnectionModeNone
}

func (m *ConnectionManager) GetStatus() *ConnectionStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return &ConnectionStatus{
		State:       StateConnected,
		Mode:        m.currentMode,
		OSType:      m.targetOS,
		ConnectedAt: time.Now(),
	}
}

func (m *ConnectionManager) GetSSHClient() *SSHClient {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.sshClient
}

func (m *ConnectionManager) GetWMIClient() *WMIClient {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.wmiClient
}

func (m *ConnectionManager) GetCurrentMode() ConnectionMode {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.currentMode
}

func (m *ConnectionManager) GetTargetOSType() OSType {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.targetOS
}

func (m *ConnectionManager) CollectConfig() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var collector ConfigCollector

	switch m.targetOS {
	case OSWindows:
		collector = NewWMIRemoteConfigCollector(m.wmiClient)
	case OSLinux:
		collector = NewSSHRemoteConfigCollector(m.sshClient)
	default:
		if m.sshClient != nil {
			collector = NewSSHRemoteConfigCollector(m.sshClient)
		} else if m.wmiClient != nil {
			collector = NewWMIRemoteConfigCollector(m.wmiClient)
		} else {
			return make(map[string]interface{})
		}
	}

	return collector.CollectAllConfig()
}

type ConfigCollector interface {
	CollectAllConfig() map[string]interface{}
}

type WMIRemoteConfigCollector struct {
	client *WMIClient
}

func NewWMIRemoteConfigCollector(client *WMIClient) *WMIRemoteConfigCollector {
	return &WMIRemoteConfigCollector{
		client: client,
	}
}

func (c *WMIRemoteConfigCollector) CollectAllConfig() map[string]interface{} {
	if c.client == nil {
		return make(map[string]interface{})
	}
	return c.client.CollectAllConfig()
}

type ConnectionModeValidator struct {
	rules map[OSType][]ConnectionMode
}

func NewConnectionModeValidator() *ConnectionModeValidator {
	v := &ConnectionModeValidator{
		rules: make(map[OSType][]ConnectionMode),
	}

	v.rules[OSWindows] = []ConnectionMode{
		ConnectionModeWMI,
		ConnectionModeAuto,
	}

	v.rules[OSLinux] = []ConnectionMode{
		ConnectionModeSSH,
		ConnectionModeAuto,
	}

	v.rules[OSMacOS] = []ConnectionMode{
		ConnectionModeSSH,
		ConnectionModeAuto,
	}

	v.rules[OSUnknown] = []ConnectionMode{
		ConnectionModeAuto,
		ConnectionModeSSH,
		ConnectionModeWMI,
	}

	return v
}

func (v *ConnectionModeValidator) IsValidMode(osType OSType, mode ConnectionMode) bool {
	if mode == ConnectionModeAuto {
		return true
	}

	allowedModes, exists := v.rules[osType]
	if !exists {
		return false
	}

	for _, allowed := range allowedModes {
		if allowed == mode {
			return true
		}
	}

	return false
}

func (v *ConnectionModeValidator) GetAllowedModes(osType OSType) []ConnectionMode {
	if modes, exists := v.rules[osType]; exists {
		return modes
	}
	return []ConnectionMode{ConnectionModeAuto}
}

func (v *ConnectionModeValidator) GetDefaultMode(osType OSType) ConnectionMode {
	switch osType {
	case OSWindows:
		return ConnectionModeWMI
	case OSLinux, OSMacOS:
		return ConnectionModeSSH
	default:
		return ConnectionModeAuto
	}
}

func (v *ConnectionModeValidator) ValidateConnection(osType OSType, mode ConnectionMode) *ValidationResult {
	result := &ValidationResult{
		Valid:    true,
		OSType:   osType,
		Mode:     mode,
		Messages: []string{},
	}

	if mode == ConnectionModeAuto {
		result.Messages = append(result.Messages, fmt.Sprintf("自动选择适用于%s的连接模式", osType))
		return result
	}

	if !v.IsValidMode(osType, mode) {
		result.Valid = false
		defaultMode := v.GetDefaultMode(osType)
		result.Messages = append(result.Messages,
			fmt.Sprintf("错误: %s 模式不适用于 %s 系统", mode, osType),
			fmt.Sprintf("建议使用: %s 模式", defaultMode),
		)
		return result
	}

	result.Messages = append(result.Messages, fmt.Sprintf("%s 模式适用于 %s 系统 ✓", mode, osType))

	return result
}

type ValidationResult struct {
	Valid    bool
	OSType   OSType
	Mode     ConnectionMode
	Messages []string
	Suggestion string
}

func (r *ValidationResult) String() string {
	var sb strings.Builder

	if r.Valid {
		sb.WriteString("✓ 连接模式验证通过\n")
	} else {
		sb.WriteString("✗ 连接模式验证失败\n")
	}

	for _, msg := range r.Messages {
		sb.WriteString("  - ")
		sb.WriteString(msg)
		sb.WriteString("\n")
	}

	if r.Suggestion != "" {
		sb.WriteString("建议: ")
		sb.WriteString(r.Suggestion)
	}

	return sb.String()
}

func AutoDetectAndConnect(target string, sshConfig *SSHConfig, wmiConfig *WMIConfig, timeout time.Duration) (*ConnectionManager, *ConnectionStatus, error) {
	config := &ConnectionConfig{
		Target:        target,
		SSHConfig:     sshConfig,
		WMIConfig:     wmiConfig,
		PreferredMode: ConnectionModeAuto,
		Timeout:       timeout,
		AutoDetect:    true,
	}

	manager := NewConnectionManager(config)
	status, err := manager.Connect()

	return manager, status, err
}

func ForceConnect(target string, osType OSType, mode ConnectionMode, sshConfig *SSHConfig, wmiConfig *WMIConfig, timeout time.Duration) (*ConnectionManager, *ConnectionStatus, error) {
	config := &ConnectionConfig{
		Target:        target,
		OSType:        osType,
		SSHConfig:     sshConfig,
		WMIConfig:     wmiConfig,
		PreferredMode: mode,
		Timeout:       timeout,
		AutoDetect:    false,
		ForceMode:     true,
	}

	manager := NewConnectionManager(config)
	status, err := manager.Connect()

	return manager, status, err
}
