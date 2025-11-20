package cli

import (
	"flag"
	"fmt"
	"strconv"
	"time"

	"GYscan/internal/ldap"
	"GYscan/internal/utils"

	"github.com/spf13/cobra"
)

var (
	// ldap命令的全局参数
	ldapServer     string
	ldapPort       int
	ldapDomain     string
	ldapUsername   string
	ldapPassword   string
	ldapBaseDN     string
	ldapProtocol   string
	ldapTimeout    time.Duration
	ldapVerbose    bool
	ldapOutputFile string
	ldapFilter     string
	ldapAttributes []string
)

// ldap命令 - LDAP枚举模块
var ldapCmd = &cobra.Command{
	Use:   "ldap",
	Short: "LDAP枚举模块 [测试阶段]",
	Long:  `用于枚举域环境中的用户、组、计算机、策略等信息。[测试阶段]`,
}

// ldap users子命令 - 枚举用户
var ldapUsersCmd = &cobra.Command{
	Use:   "users",
	Short: "枚举域用户",
	Long:  `枚举活动目录中的用户账户信息。`,
	Run:   executeLDAPUsers,
}

// ldap groups子命令 - 枚举组
var ldapGroupsCmd = &cobra.Command{
	Use:   "groups",
	Short: "枚举域组",
	Long:  `枚举活动目录中的组信息。`,
	Run:   executeLDAPGroups,
}

// ldap computers子命令 - 枚举计算机
var ldapComputersCmd = &cobra.Command{
	Use:   "computers",
	Short: "枚举域计算机",
	Long:  `枚举活动目录中的计算机账户信息。`,
	Run:   executeLDAPComputers,
}

// ldap ous子命令 - 枚举组织单位
var ldapOUsCmd = &cobra.Command{
	Use:   "ous",
	Short: "枚举组织单位",
	Long:  `枚举活动目录中的组织单位(OU)信息。`,
	Run:   executeLDAPOUs,
}

// ldap policy子命令 - 枚举域策略
var ldapPolicyCmd = &cobra.Command{
	Use:   "policy",
	Short: "枚举域策略",
	Long:  `枚举域密码策略和账户策略信息。`,
	Run:   executeLDAPPolicy,
}

// ldap trusts子命令 - 枚举信任关系
var ldapTrustsCmd = &cobra.Command{
	Use:   "trusts",
	Short: "枚举域信任关系",
	Long:  `枚举域间的信任关系。`,
	Run:   executeLDAPTrusts,
}

// ldap spns子命令 - 查找SPN
var ldapSPNsCmd = &cobra.Command{
	Use:   "spns",
	Short: "查找配置了SPN的账户",
	Long:  `查找配置了服务主体名称(SPN)的账户，可用于Kerberoasting攻击。`,
	Run:   executeLDAPSPNs,
}

// ldap asrep子命令 - 查找可AS-REP Roasting的账户
var ldapASREPCmd = &cobra.Command{
	Use:   "asrep",
	Short: "查找无需预认证的账户",
	Long:  `查找配置为无需Kerberos预认证的账户，可用于AS-REP Roasting攻击。`,
	Run:   executeLDAPASREP,
}

// ldap search子命令 - 自定义搜索
var ldapSearchCmd = &cobra.Command{
	Use:   "search",
	Short: "执行自定义LDAP搜索",
	Long:  `使用自定义过滤器和属性执行LDAP搜索。`,
	Run:   executeLDAPSearch,
}

// ldap connect子命令 - 测试连接
var ldapConnectCmd = &cobra.Command{
	Use:   "connect",
	Short: "测试LDAP连接",
	Long:  `测试与LDAP服务器的连接。`,
	Run:   testLDAPConnection,
}

func init() {
	// 将ldap命令添加到root命令
	// rootCmd.AddCommand(ldapCmd) // 命令注册已移至root.go的RegisterCommands函数中统一管理
	
	// 添加子命令
	ldapCmd.AddCommand(
		ldapUsersCmd,
		ldapGroupsCmd,
		ldapComputersCmd,
		ldapOUsCmd,
		ldapPolicyCmd,
		ldapTrustsCmd,
		ldapSPNsCmd,
		ldapASREPCmd,
		ldapSearchCmd,
		ldapConnectCmd,
	)
	
	// 设置全局参数
	setupLDAPGlobalFlags()
	
	// 设置各子命令特定参数
	setupLDAPSearchFlags(ldapSearchCmd)
}

// 设置全局参数
func setupLDAPGlobalFlags() {
	ldapCmd.PersistentFlags().StringVarP(&ldapServer, "server", "s", "", "LDAP服务器IP地址或主机名")
	ldapCmd.PersistentFlags().IntVarP(&ldapPort, "port", "p", 389, "LDAP服务器端口")
	ldapCmd.PersistentFlags().StringVarP(&ldapDomain, "domain", "d", "", "域名")
	ldapCmd.PersistentFlags().StringVarP(&ldapUsername, "username", "u", "", "用户名")
	ldapCmd.PersistentFlags().StringVarP(&ldapPassword, "password", "w", "", "密码")
	ldapCmd.PersistentFlags().StringVar(&ldapBaseDN, "base", "", "基础DN")
	ldapCmd.PersistentFlags().StringVar(&ldapProtocol, "protocol", "ldap", "协议(ldap, ldaps)")
	ldapCmd.PersistentFlags().DurationVar(&ldapTimeout, "timeout", 30*time.Second, "连接超时时间")
	ldapCmd.PersistentFlags().BoolVarP(&ldapVerbose, "verbose", "v", false, "启用详细输出")
	ldapCmd.PersistentFlags().StringVarP(&ldapOutputFile, "output", "o", "", "输出文件路径")
	
	// 设置默认端口
	ldapCmd.PersistentFlags().Lookup("port").NoOptDefVal = "389"
}

// 设置搜索子命令参数
func setupLDAPSearchFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&ldapFilter, "filter", "", "LDAP过滤器")
	cmd.Flags().StringSliceVarP(&ldapAttributes, "attributes", "a", []string{}, "要查询的属性列表")
	
	// 移除自动参数验证，改用手动验证
}

// 创建LDAP客户端并建立连接
func createLDAPClientAndConnect() (*ldap.LDAPClient, error) {
	// 如果未指定服务器但指定了域名，尝试使用域控
	if ldapServer == "" && ldapDomain != "" {
		ldapServer = "dc." + ldapDomain
		if ldapVerbose {
			utils.WarningPrint(fmt.Sprintf("自动使用域控制器: %s", ldapServer))
		}
	}
	
	// 如果协议是ldaps且端口未指定，使用636
	if ldapProtocol == "ldaps" && ldapPort == 389 {
		ldapPort = 636
	}
	
	// 构建配置
	config := &ldap.LDAPConfig{
		Server:     ldapServer,
		Port:       ldapPort,
		Domain:     ldapDomain,
		Username:   ldapUsername,
		Password:   ldapPassword,
		BaseDN:     ldapBaseDN,
		Protocol:   ldapProtocol,
		Timeout:    ldapTimeout,
		Verbose:    ldapVerbose,
		OutputFile: ldapOutputFile,
	}
	
	// 创建客户端
	client := ldap.NewLDAPClient(config)
	
	// 建立连接
	err := client.Connect()
	if err != nil {
		return nil, err
	}
	
	// 绑定
	err = client.Bind()
	if err != nil {
		client.Close()
		return nil, err
	}
	
	return client, nil
}

// 枚举用户
func executeLDAPUsers(cmd *cobra.Command, args []string) {
	client, err := createLDAPClientAndConnect()
	if err != nil {
		utils.ErrorPrint(fmt.Sprintf("LDAP连接失败: %v", err))
		return
	}
	defer client.Close()
	
	utils.SuccessPrint("开始枚举域用户")
	result := client.EnumUsers(ldapFilter)
	
	printLDAPResult(result, client)
}

// 枚举组
func executeLDAPGroups(cmd *cobra.Command, args []string) {
	client, err := createLDAPClientAndConnect()
	if err != nil {
		utils.ErrorPrint(fmt.Sprintf("LDAP连接失败: %v", err))
		return
	}
	defer client.Close()
	
	utils.SuccessPrint("开始枚举域组")
	result := client.EnumGroups(ldapFilter)
	
	printLDAPResult(result, client)
}

// 枚举计算机
func executeLDAPComputers(cmd *cobra.Command, args []string) {
	client, err := createLDAPClientAndConnect()
	if err != nil {
		utils.ErrorPrint(fmt.Sprintf("LDAP连接失败: %v", err))
		return
	}
	defer client.Close()
	
	utils.SuccessPrint("开始枚举域计算机")
	result := client.EnumComputers(ldapFilter)
	
	printLDAPResult(result, client)
}

// 枚举组织单位
func executeLDAPOUs(cmd *cobra.Command, args []string) {
	client, err := createLDAPClientAndConnect()
	if err != nil {
		utils.ErrorPrint(fmt.Sprintf("LDAP连接失败: %v", err))
		return
	}
	defer client.Close()
	
	utils.SuccessPrint("开始枚举组织单位")
	result := client.EnumOUs(ldapFilter)
	
	printLDAPResult(result, client)
}

// 枚举域策略
func executeLDAPPolicy(cmd *cobra.Command, args []string) {
	client, err := createLDAPClientAndConnect()
	if err != nil {
		utils.ErrorPrint(fmt.Sprintf("LDAP连接失败: %v", err))
		return
	}
	defer client.Close()
	
	utils.SuccessPrint("开始枚举域策略")
	result := client.EnumDomainPolicy()
	
	printLDAPResult(result, client)
}

// 枚举信任关系
func executeLDAPTrusts(cmd *cobra.Command, args []string) {
	client, err := createLDAPClientAndConnect()
	if err != nil {
		utils.ErrorPrint(fmt.Sprintf("LDAP连接失败: %v", err))
		return
	}
	defer client.Close()
	
	utils.SuccessPrint("开始枚举域信任关系")
	result := client.EnumTrusts()
	
	printLDAPResult(result, client)
}

// 查找SPN
func executeLDAPSPNs(cmd *cobra.Command, args []string) {
	client, err := createLDAPClientAndConnect()
	if err != nil {
		utils.ErrorPrint(fmt.Sprintf("LDAP连接失败: %v", err))
		return
	}
	defer client.Close()
	
	utils.SuccessPrint("开始查找配置了SPN的账户")
	result := client.FindSPNs()
	
	printLDAPResult(result, client)
}

// 查找可AS-REP Roasting的账户
func executeLDAPASREP(cmd *cobra.Command, args []string) {
	client, err := createLDAPClientAndConnect()
	if err != nil {
		utils.ErrorPrint(fmt.Sprintf("LDAP连接失败: %v", err))
		return
	}
	defer client.Close()
	
	utils.SuccessPrint("开始查找无需预认证的账户")
	result := client.FindASREPPrincipal()
	
	printLDAPResult(result, client)
}

// 执行自定义搜索
func executeLDAPSearch(cmd *cobra.Command, args []string) {
	// 参数验证
	if ldapFilter == "" {
		utils.ErrorPrint("[错误] 必须指定LDAP过滤器 (--filter)")
		return
	}

	client, err := createLDAPClientAndConnect()
	if err != nil {
		utils.ErrorPrint(fmt.Sprintf("LDAP连接失败: %v", err))
		return
	}
	defer client.Close()
	
	utils.SuccessPrint("执行自定义LDAP搜索")
	result := client.Search(ldapFilter, ldapAttributes)
	
	printLDAPResult(result, client)
}

// 测试LDAP连接
func testLDAPConnection(cmd *cobra.Command, args []string) {
	// 如果未指定服务器但指定了域名，尝试使用域控
	if ldapServer == "" && ldapDomain != "" {
		ldapServer = "dc." + ldapDomain
	}
	
	// 如果协议是ldaps且端口未指定，使用636
	if ldapProtocol == "ldaps" && ldapPort == 389 {
		ldapPort = 636
	}
	
	utils.SuccessPrint(fmt.Sprintf("测试LDAP连接: %s://%s:%d", ldapProtocol, ldapServer, ldapPort))
	
	// 构建配置
	config := &ldap.LDAPConfig{
		Server:   ldapServer,
		Port:     ldapPort,
		Domain:   ldapDomain,
		Username: ldapUsername,
		Password: ldapPassword,
		BaseDN:   ldapBaseDN,
		Protocol: ldapProtocol,
		Timeout:  ldapTimeout,
		Verbose:  ldapVerbose,
	}
	
	// 创建客户端
	client := ldap.NewLDAPClient(config)
	defer client.Close()
	
	// 建立连接
	err := client.Connect()
	if err != nil {
		utils.ErrorPrint(fmt.Sprintf("连接失败: %v", err))
		return
	}
	utils.SuccessPrint("连接成功")
	
	// 如果提供了凭证，进行绑定测试
	if ldapUsername != "" {
		err = client.Bind()
		if err != nil {
			utils.ErrorPrint(fmt.Sprintf("绑定失败: %v", err))
			return
		}
		utils.SuccessPrint("绑定成功")
	}
	
	utils.SuccessPrint("LDAP连接测试通过")
}

// 打印LDAP结果
func printLDAPResult(result *ldap.LDAPResult, client *ldap.LDAPClient) {
	if result.Success {
		utils.SuccessPrint(fmt.Sprintf("LDAP查询成功，找到 %d 个条目", result.Count))
		fmt.Println(client.FormatResult(result))
	} else {
		utils.ErrorPrint(fmt.Sprintf("LDAP查询失败: %v", result.Error))
	}
}

// 为flag包提供自定义类型，用于解析字符串切片
func init() {
	// 注册命令行参数解析函数
	flag.CommandLine.VisitAll(func(f *flag.Flag) {
		if f.Name == "attributes" {
			f.Value = &stringSliceValue{values: []string{}}
		}
	})
}

// stringSliceValue 用于解析字符串切片

type stringSliceValue struct {
	values []string
}

func (s *stringSliceValue) String() string {
	return fmt.Sprintf("%v", s.values)
}

func (s *stringSliceValue) Set(val string) error {
	s.values = append(s.values, val)
	return nil
}

func (s *stringSliceValue) Get() interface{} {
	return s.values
}

// 辅助函数：将字符串转换为整数
func parseInt(s string, defaultValue int) int {
	if s == "" {
		return defaultValue
	}
	val, err := strconv.Atoi(s)
	if err != nil {
		return defaultValue
	}
	return val
}