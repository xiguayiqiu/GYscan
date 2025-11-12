package userinfo

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/text/encoding/simplifiedchinese"
	"GYscan-linux-C2/pkg/utils"
)

// UserInfo 用户信息结构体
type UserInfo struct {
	Name     string
	FullName string
	Comment  string
	SID      string
}

// GroupInfo 组信息结构体
type GroupInfo struct {
	Name        string
	Description string
	Members     []string
}

// AnalyzeLocalUsers 分析本地用户信息
func AnalyzeLocalUsers() ([]UserInfo, error) {
	if runtime.GOOS == "windows" {
		return analyzeWindowsUsers()
	}
	return analyzeLinuxUsers()
}

// AnalyzeLocalGroups 分析本地组信息
func AnalyzeLocalGroups() ([]GroupInfo, error) {
	if runtime.GOOS == "windows" {
		return analyzeWindowsGroups()
	}
	return analyzeLinuxGroups()
}

// analyzeWindowsUsers Windows下分析用户信息
func analyzeWindowsUsers() ([]UserInfo, error) {
	var users []UserInfo

	cmd := exec.Command("net", "user")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("执行net user命令失败: %v", err)
	}

	// 转换编码
	decoder := simplifiedchinese.GB18030.NewDecoder()
	decodedOutput, err := decoder.Bytes(output)
	if err != nil {
		return nil, fmt.Errorf("解码输出失败: %v", err)
	}

	lines := strings.Split(string(decodedOutput), "\n")
	inUserList := false

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "--------") {
			inUserList = !inUserList
			continue
		}

		if inUserList && line != "" {
			userNames := strings.Fields(line)
			for _, userName := range userNames {
				if userName != "命令成功完成。" {
					userDetail, err := getWindowsUserDetail(userName)
					if err != nil {
						logrus.Warnf("获取用户%s详细信息失败: %v", userName, err)
						continue
					}
					users = append(users, userDetail)
				}
			}
		}
	}

	return users, nil
}

// getWindowsUserDetail 获取Windows用户详细信息
func getWindowsUserDetail(userName string) (UserInfo, error) {
	var user UserInfo
	user.Name = userName

	// 获取用户详细信息
	cmd := exec.Command("net", "user", userName)
	output, err := cmd.Output()
	if err != nil {
		return user, fmt.Errorf("执行net user %s命令失败: %v", userName, err)
	}

	decoder := simplifiedchinese.GB18030.NewDecoder()
	decodedOutput, err := decoder.Bytes(output)
	if err != nil {
		return user, fmt.Errorf("解码输出失败: %v", err)
	}

	lines := strings.Split(string(decodedOutput), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "全名") {
			user.FullName = strings.TrimSpace(strings.TrimPrefix(line, "全名"))
		} else if strings.HasPrefix(line, "注释") {
			user.Comment = strings.TrimSpace(strings.TrimPrefix(line, "注释"))
		}
	}

	// 获取SID
	sidCmd := exec.Command("wmic", "useraccount", "where", fmt.Sprintf("name='%s'", userName), "get", "sid")
	sidOutput, err := sidCmd.Output()
	if err == nil {
		sidLines := strings.Split(string(sidOutput), "\n")
		for _, line := range sidLines {
			line = strings.TrimSpace(line)
			if line != "" && line != "SID" && !strings.Contains(line, "wmic:") {
				user.SID = line
				break
			}
		}
	}

	return user, nil
}

// analyzeWindowsGroups Windows下分析组信息
func analyzeWindowsGroups() ([]GroupInfo, error) {
	var groups []GroupInfo

	cmd := exec.Command("net", "localgroup")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("执行net localgroup命令失败: %v", err)
	}

	decoder := simplifiedchinese.GB18030.NewDecoder()
	decodedOutput, err := decoder.Bytes(output)
	if err != nil {
		return nil, fmt.Errorf("解码输出失败: %v", err)
	}

	lines := strings.Split(string(decodedOutput), "\n")
	inGroupList := false

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "--------") {
			inGroupList = !inGroupList
			continue
		}

		if inGroupList && line != "" {
			groupNames := strings.Fields(line)
			for _, groupName := range groupNames {
				if groupName != "命令成功完成。" {
					groupDetail, err := getWindowsGroupDetail(groupName)
					if err != nil {
						logrus.Warnf("获取组%s详细信息失败: %v", groupName, err)
						continue
					}
					groups = append(groups, groupDetail)
				}
			}
		}
	}

	return groups, nil
}

// getWindowsGroupDetail 获取Windows组详细信息
func getWindowsGroupDetail(groupName string) (GroupInfo, error) {
	var group GroupInfo
	group.Name = groupName

	cmd := exec.Command("net", "localgroup", groupName)
	output, err := cmd.Output()
	if err != nil {
		return group, fmt.Errorf("执行net localgroup %s命令失败: %v", groupName, err)
	}

	decoder := simplifiedchinese.GB18030.NewDecoder()
	decodedOutput, err := decoder.Bytes(output)
	if err != nil {
		return group, fmt.Errorf("解码输出失败: %v", err)
	}

	lines := strings.Split(string(decodedOutput), "\n")
	inMemberList := false

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "注释") {
			group.Description = strings.TrimSpace(strings.TrimPrefix(line, "注释"))
		} else if strings.Contains(line, "--------") {
			inMemberList = !inMemberList
			continue
		}

		if inMemberList && line != "" {
			if !strings.Contains(line, "命令成功完成") && !strings.Contains(line, "成员") {
				group.Members = append(group.Members, strings.TrimSpace(line))
			}
		}
	}

	return group, nil
}

// analyzeLinuxUsers Linux下分析用户信息
func analyzeLinuxUsers() ([]UserInfo, error) {
	var users []UserInfo

	file, err := os.Open("/etc/passwd")
	if err != nil {
		return nil, fmt.Errorf("打开/etc/passwd文件失败: %v", err)
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
			uid, err := strconv.Atoi(fields[2])
			if err != nil || uid < 1000 {
				continue // 跳过系统用户
			}

			user := UserInfo{
				Name:     fields[0],
				FullName: fields[4],
				Comment:  fields[5],
			}
			users = append(users, user)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("读取/etc/passwd文件失败: %v", err)
	}

	return users, nil
}

// analyzeLinuxGroups Linux下分析组信息
func analyzeLinuxGroups() ([]GroupInfo, error) {
	var groups []GroupInfo

	file, err := os.Open("/etc/group")
	if err != nil {
		return nil, fmt.Errorf("打开/etc/group文件失败: %v", err)
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
			gid, err := strconv.Atoi(fields[2])
			if err != nil || gid < 1000 {
				continue // 跳过系统组
			}

			var members []string
			if fields[3] != "" {
				members = strings.Split(fields[3], ",")
			}

			group := GroupInfo{
				Name:        fields[0],
				Description: fields[3],
				Members:     members,
			}
			groups = append(groups, group)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("读取/etc/group文件失败: %v", err)
	}

	return groups, nil
}

// FormatUserInfo 格式化用户信息输出
func FormatUserInfo(users []UserInfo) string {
	var result strings.Builder
	
	color := utils.NewColor()
	
	result.WriteString(color.Title("=== 本地用户信息分析报告 ===\n"))
	result.WriteString(fmt.Sprintf("分析时间: %s\n", time.Now().Format("2006-01-02 15:04:05")))
	result.WriteString(fmt.Sprintf("发现用户数量: %d\n\n", len(users)))
	
	for i, user := range users {
		result.WriteString(color.Success(fmt.Sprintf("用户 %d:\n", i+1)))
		result.WriteString(fmt.Sprintf("  用户名: %s\n", user.Name))
		if user.FullName != "" {
			result.WriteString(fmt.Sprintf("  全名: %s\n", user.FullName))
		}
		if user.Comment != "" {
			result.WriteString(fmt.Sprintf("  注释: %s\n", user.Comment))
		}
		if user.SID != "" {
			result.WriteString(fmt.Sprintf("  SID: %s\n", user.SID))
		}
		result.WriteString("\n")
	}
	
	return result.String()
}

// FormatGroupInfo 格式化组信息输出
func FormatGroupInfo(groups []GroupInfo) string {
	var result strings.Builder
	
	color := utils.NewColor()
	
	result.WriteString(color.Title("=== 本地组信息分析报告 ===\n"))
	result.WriteString(fmt.Sprintf("分析时间: %s\n", time.Now().Format("2006-01-02 15:04:05")))
	result.WriteString(fmt.Sprintf("发现组数量: %d\n\n", len(groups)))
	
	for i, group := range groups {
		result.WriteString(color.Success(fmt.Sprintf("组 %d:\n", i+1)))
		result.WriteString(fmt.Sprintf("  组名: %s\n", group.Name))
		if group.Description != "" {
			result.WriteString(fmt.Sprintf("  描述: %s\n", group.Description))
		}
		if len(group.Members) > 0 {
			result.WriteString(fmt.Sprintf("  成员: %s\n", strings.Join(group.Members, ", ")))
		}
		result.WriteString("\n")
	}
	
	return result.String()
}