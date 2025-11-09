package userinfo

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
	"io"
	"GYscan/internal/utils"
)

// UserInfo 用户信息结构体
type UserInfo struct {
	Username    string
	UID         string
	GID         string
	FullName    string
	HomeDir     string
	Shell       string
	Groups      []string
}

// GroupInfo 组信息结构体
type GroupInfo struct {
	GroupName string
	GID       string
	Members   []string
}

// AnalyzeLocalUsers 分析本地用户信息
func AnalyzeLocalUsers() ([]UserInfo, error) {
	switch runtime.GOOS {
	case "windows":
		return analyzeWindowsUsers()
	case "linux", "darwin":
		return analyzeUnixUsers()
	default:
		return nil, fmt.Errorf("不支持的操作系统: %s", runtime.GOOS)
	}
}

// AnalyzeLocalGroups 分析本地组信息
func AnalyzeLocalGroups() ([]GroupInfo, error) {
	switch runtime.GOOS {
	case "windows":
		return analyzeWindowsGroups()
	case "linux", "darwin":
		return analyzeUnixGroups()
	default:
		return nil, fmt.Errorf("不支持的操作系统: %s", runtime.GOOS)
	}
}

// analyzeWindowsUsers 分析Windows系统用户
func analyzeWindowsUsers() ([]UserInfo, error) {
	var users []UserInfo
	
	// 使用net user命令（带编码转换）
	output, err := executeWindowsCommand("net", "user")
	if err != nil {
		return nil, fmt.Errorf("执行net user命令失败: %v", err)
	}
	
	lines := strings.Split(output, "\n")
	inUserList := false
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		
		if strings.Contains(line, "--------") {
			inUserList = !inUserList
			continue
		}
		
		if inUserList && line != "" {
			// 解析用户名
			fields := strings.Fields(line)
			if len(fields) > 0 {
				username := fields[0]
				
				// 获取用户详细信息
				userDetail, err := getWindowsUserDetail(username)
				if err == nil {
					users = append(users, userDetail)
				}
			}
		}
	}
	
	return users, nil
}

// getWindowsUserDetail 获取Windows用户详细信息
func getWindowsUserDetail(username string) (UserInfo, error) {
	user := UserInfo{
		Username: username,
		Groups:   []string{},
	}
	
	// 获取用户详细信息（带编码转换）
	output, err := executeWindowsCommand("net", "user", username)
	if err != nil {
		return user, err
	}
	
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		
		if strings.HasPrefix(line, "全名") || strings.HasPrefix(line, "Full Name") {
			parts := strings.SplitN(line, " ", 3)
			if len(parts) >= 3 {
				user.FullName = strings.TrimSpace(parts[2])
			}
		}
		
		if strings.HasPrefix(line, "本地组成员") || strings.HasPrefix(line, "Local Group Memberships") {
			parts := strings.SplitN(line, "*", 2)
			if len(parts) >= 2 {
				groups := strings.Split(parts[1], " ")
				for _, group := range groups {
					group = strings.TrimSpace(group)
					if group != "" && group != "*" {
						user.Groups = append(user.Groups, group)
					}
				}
			}
		}
	}
	
	return user, nil
}

// analyzeWindowsGroups 分析Windows系统组
func analyzeWindowsGroups() ([]GroupInfo, error) {
	var groups []GroupInfo
	
	// 使用net localgroup命令（带编码转换）
	output, err := executeWindowsCommand("net", "localgroup")
	if err != nil {
		return nil, fmt.Errorf("执行net localgroup命令失败: %v", err)
	}
	
	lines := strings.Split(output, "\n")
	inGroupList := false
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		
		// 检查是否进入组列表区域
		if strings.Contains(line, "--------") {
			inGroupList = !inGroupList
			continue
		}
		
		// 检查是否在组列表区域
		if inGroupList && line != "" {
			// 跳过命令成功完成的提示行
			if strings.Contains(line, "命令成功完成") || strings.Contains(line, "The command completed successfully") {
				continue
			}
			
			// 解析组名（去掉星号）
			if strings.HasPrefix(line, "*") {
				groupname := strings.TrimPrefix(line, "*")
				groupname = strings.TrimSpace(groupname)
				
				// 获取组详细信息
				groupDetail, err := getWindowsGroupDetail(groupname)
				if err == nil {
					groups = append(groups, groupDetail)
				}
			}
		}
	}
	
	return groups, nil
}

// getWindowsGroupDetail 获取Windows组详细信息
func getWindowsGroupDetail(groupname string) (GroupInfo, error) {
	group := GroupInfo{
		GroupName: groupname,
		Members:   []string{},
	}
	
	// 获取组成员信息（带编码转换）
	output, err := executeWindowsCommand("net", "localgroup", groupname)
	if err != nil {
		return group, err
	}
	
	lines := strings.Split(output, "\n")
	inMemberList := false
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		
		if strings.Contains(line, "--------") {
			inMemberList = !inMemberList
			continue
		}
		
		if inMemberList && line != "" {
			// 跳过命令成功完成的提示行
			if strings.Contains(line, "命令成功完成") || strings.Contains(line, "The command completed successfully") {
				continue
			}
			
			// 解析成员
			fields := strings.Fields(line)
			if len(fields) > 0 {
				member := fields[0]
				// 过滤掉空成员和星号
				if member != "" && member != "*" {
					group.Members = append(group.Members, member)
				}
			}
		}
	}
	
	return group, nil
}

// analyzeUnixUsers 分析Unix系统用户
func analyzeUnixUsers() ([]UserInfo, error) {
	var users []UserInfo
	
	// 读取/etc/passwd文件
	file, err := os.Open("/etc/passwd")
	if err != nil {
		return nil, fmt.Errorf("无法打开/etc/passwd文件: %v", err)
	}
	defer file.Close()
	
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		
		fields := strings.Split(line, ":")
		if len(fields) >= 7 {
			user := UserInfo{
				Username: fields[0],
				UID:      fields[2],
				GID:      fields[3],
				FullName: fields[4],
				HomeDir:  fields[5],
				Shell:    fields[6],
				Groups:   []string{},
			}
			
			// 获取用户所属组
			groups, err := getUserGroups(user.Username)
			if err == nil {
				user.Groups = groups
			}
			
			users = append(users, user)
		}
	}
	
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("读取/etc/passwd文件失败: %v", err)
	}
	
	return users, nil
}

// analyzeUnixGroups 分析Unix系统组
func analyzeUnixGroups() ([]GroupInfo, error) {
	var groups []GroupInfo
	
	// 读取/etc/group文件
	file, err := os.Open("/etc/group")
	if err != nil {
		return nil, fmt.Errorf("无法打开/etc/group文件: %v", err)
	}
	defer file.Close()
	
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		
		fields := strings.Split(line, ":")
		if len(fields) >= 4 {
			group := GroupInfo{
				GroupName: fields[0],
				GID:       fields[2],
				Members:   []string{},
			}
			
			// 解析组成员
			if fields[3] != "" {
				members := strings.Split(fields[3], ",")
				for _, member := range members {
					if member != "" {
						group.Members = append(group.Members, member)
					}
				}
			}
			
			groups = append(groups, group)
		}
	}
	
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("读取/etc/group文件失败: %v", err)
	}
	
	return groups, nil
}

// convertGBKToUTF8 将GBK编码转换为UTF-8编码
func convertGBKToUTF8(gbkBytes []byte) (string, error) {
	decoder := simplifiedchinese.GBK.NewDecoder()
	reader := transform.NewReader(strings.NewReader(string(gbkBytes)), decoder)
	utf8Bytes, err := io.ReadAll(reader)
	if err != nil {
		return "", err
	}
	return string(utf8Bytes), nil
}

// executeWindowsCommand 执行Windows命令并处理编码转换
func executeWindowsCommand(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	
	// 尝试将GBK编码转换为UTF-8
	utf8Output, err := convertGBKToUTF8(output)
	if err != nil {
		// 如果转换失败，返回原始输出
		return string(output), nil
	}
	
	return utf8Output, nil
}

// getUserGroups 获取用户所属的所有组
func getUserGroups(username string) ([]string, error) {
	var groups []string
	
	// 使用groups命令
	cmd := exec.Command("groups", username)
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	
	line := strings.TrimSpace(string(output))
	if strings.Contains(line, ":") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) >= 2 {
			groupList := strings.Fields(parts[1])
			groups = append(groups, groupList...)
		}
	} else {
		groupList := strings.Fields(line)
		groups = append(groups, groupList...)
	}
	
	return groups, nil
}

// FormatUserInfo 格式化用户信息输出
func FormatUserInfo(users []UserInfo) string {
	var result strings.Builder
	
	result.WriteString(utils.Banner("=== 本地用户信息 ===") + "\n")
	result.WriteString(utils.Info(fmt.Sprintf("系统类型: %s", runtime.GOOS)) + "\n")
	result.WriteString(utils.Success(fmt.Sprintf("用户总数: %d", len(users))) + "\n\n")
	
	for i, user := range users {
		result.WriteString(utils.Highlight(fmt.Sprintf("用户 %d:", i+1)) + "\n")
		result.WriteString(utils.BoldInfo("  用户名: ") + utils.BoldInfo("%s", user.Username) + "\n")
		if user.UID != "" {
			result.WriteString(utils.BoldInfo("  UID: ") + utils.Info(user.UID) + "\n")
		}
		if user.GID != "" {
			result.WriteString(utils.BoldInfo("  GID: ") + utils.Info(user.GID) + "\n")
		}
		if user.FullName != "" {
			result.WriteString(utils.BoldInfo("  全名: ") + utils.Info(user.FullName) + "\n")
		}
		if user.HomeDir != "" {
			result.WriteString(utils.BoldInfo("  主目录: ") + utils.Info(user.HomeDir) + "\n")
		}
		if user.Shell != "" {
			result.WriteString(utils.BoldInfo("  Shell: ") + utils.Info(user.Shell) + "\n")
		}
		if len(user.Groups) > 0 {
			result.WriteString(utils.BoldInfo("  所属组: ") + utils.Success(strings.Join(user.Groups, ", ")) + "\n")
		}
		result.WriteString("\n")
	}
	
	return result.String()
}

// FormatGroupInfo 格式化组信息输出
func FormatGroupInfo(groups []GroupInfo) string {
	var result strings.Builder
	
	result.WriteString(utils.Banner("=== 本地组信息 ===") + "\n")
	result.WriteString(utils.Info(fmt.Sprintf("系统类型: %s", runtime.GOOS)) + "\n")


	result.WriteString(utils.Success(fmt.Sprintf("组总数: %d", len(groups))) + "\n\n")
	
	for i, group := range groups {
		result.WriteString(utils.Highlight(fmt.Sprintf("组 %d:", i+1)) + "\n")
		result.WriteString(utils.BoldInfo("  组名: %s", group.GroupName) + "\n")
		if group.GID != "" {
			result.WriteString(utils.BoldInfo("  GID: ") + utils.Info(group.GID) + "\n")
		}
		if len(group.Members) > 0 {
			result.WriteString(utils.BoldInfo("  成员: ") + utils.Success(strings.Join(group.Members, ", ")) + "\n")
		} else {
			result.WriteString(utils.BoldInfo("  成员: ") + utils.Warning("无") + "\n")
		}
		result.WriteString("\n")
	}
	
	return result.String()
}