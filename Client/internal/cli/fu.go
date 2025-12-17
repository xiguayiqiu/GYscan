package cli

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"mime/multipart"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"GYscan/internal/utils"

	"github.com/fatih/color"
	"github.com/go-resty/resty/v2"
	"github.com/spf13/cobra"
)

// FileUploadResult 表示文件上传漏洞检查结果
type FileUploadResult struct {
	Vulnerable   bool   `json:"vulnerable"`
	TestType     string `json:"test_type"`
	Technique    string `json:"technique"`
	FileName     string `json:"file_name"`
	StatusCode   int    `json:"status_code"`
	ResponseSize int    `json:"response_size"`
	Message      string `json:"message"`
	Url          string `json:"url"`
}

// UploadFormInfo 存储上传表单信息
type UploadFormInfo struct {
	Action           string            // 表单提交地址
	Method           string            // 请求方法
	FileField        string            // 文件字段名
	AdditionalFields map[string]string // 其他表单字段
	Enctype          string            // 表单编码类型
}

// FileUploadScanner 表示文件上传漏洞扫描器
type FileUploadScanner struct {
	client     *resty.Client
	target     string
	scanType   string
	payload    string
	thread     int
	timeout    int
	verbose    bool
	results    []FileUploadResult
	outputFile string
	mutex      sync.Mutex
	formInfo   *UploadFormInfo // 解析到的上传表单信息
}

// fuCmd 表示文件上传漏洞检查命令
var fuCmd = &cobra.Command{
	Use:   "fu [target] [flags]",
	Short: "文件上传漏洞检查工具",
	Long: `文件上传漏洞检查工具 - 用于检测Web应用中的文件上传漏洞
支持多种绕过技术，包括文件类型检测绕过、文件名绕过、路径绕过等
警告：仅用于授权测试，严禁未授权使用！`,
	Args: cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		target := args[0]
		utils.LogInfo("开始执行文件上传漏洞检查，目标: %s", target)

		// 解析命令行参数
		scanType, _ := cmd.Flags().GetString("type")
		payload, _ := cmd.Flags().GetString("payload")
		thread, _ := cmd.Flags().GetInt("thread")
		timeout, _ := cmd.Flags().GetInt("timeout")
		verbose, _ := cmd.Flags().GetBool("verbose")
		outputFile, _ := cmd.Flags().GetString("output")

		// 执行文件上传漏洞检查
		runFileUploadScan(target, scanType, payload, thread, timeout, verbose, outputFile)

		utils.LogInfo("文件上传漏洞检查完成，目标: %s", target)
	},
}

// runFileUploadScan 执行文件上传漏洞检查
func runFileUploadScan(target, scanType, payload string, thread, timeout int, verbose bool, outputFile string) {
	// 验证目标URL
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		utils.ErrorPrint("目标URL格式错误，必须以http://或https://开头")
		return
	}

	// 初始化扫描器
	scanner := &FileUploadScanner{
		target:   target,
		scanType: scanType,
		payload:  payload,
		thread:   thread,
		timeout:  timeout,
		verbose:  verbose,
		results:  []FileUploadResult{},
	}

	// 设置输出文件
	scanner.outputFile = outputFile

	// 配置HTTP客户端
	scanner.client = resty.New().
		SetTimeout(time.Duration(timeout)*time.Second).
		SetRetryCount(3).
		SetRetryWaitTime(1*time.Second).
		SetRetryMaxWaitTime(3*time.Second).
		SetHeader("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")

	utils.BoldInfo("==============================================")
	utils.BoldInfo("文件上传漏洞检查工具")
	utils.BoldInfo("目标URL: %s", target)
	utils.BoldInfo("扫描类型: %s", scanType)
	if payload != "" {
		utils.BoldInfo("自定义Payload: %s", payload)
	}
	utils.BoldInfo("线程数: %d", thread)
	utils.BoldInfo("超时时间: %d秒", timeout)
	utils.BoldInfo("==============================================")

	fmt.Println()
	utils.InfoPrint("正在初始化文件上传漏洞检查...")
	utils.InfoPrint("配置HTTP客户端...")
	utils.InfoPrint("加载multipart/form-data处理库...")
	utils.InfoPrint("初始化绕过技术库...")

	fmt.Println()
	utils.InfoPrint("开始检测目标网站的文件上传功能...")

	// 1. 获取目标页面，解析上传表单信息
	utils.InfoPrint("正在获取目标页面，解析上传表单信息...")
	resp, err := scanner.client.R().Get(target)
	if err != nil {
		utils.ErrorPrint("获取目标页面失败: %v", err)
		utils.InfoPrint("将使用默认表单配置进行扫描...")
	} else {
		// 解析表单信息
		scanner.formInfo = scanner.parseUploadForm(resp)

		// 打印解析到的表单信息
		utils.SuccessPrint("成功解析上传表单信息:")
		utils.InfoPrint("  表单提交地址: %s", scanner.formInfo.Action)
		utils.InfoPrint("  请求方法: %s", scanner.formInfo.Method)
		utils.InfoPrint("  文件字段名: %s", scanner.formInfo.FileField)
		utils.InfoPrint("  编码类型: %s", scanner.formInfo.Enctype)
		if len(scanner.formInfo.AdditionalFields) > 0 {
			utils.InfoPrint("  其他字段数: %d", len(scanner.formInfo.AdditionalFields))
		}
	}

	fmt.Println()

	// 2. 执行不同类型的扫描
	switch scanType {
	case "all":
		scanner.testFileTypeBypass()
		scanner.testFileNameBypass()
		scanner.testPathTraversal()
		scanner.testContentBypass()
		scanner.testDoubleExtension()
		scanner.testNullByteInjection()
		scanner.testCaseMismatch()
		scanner.testVariantExtensions()
	case "bypass":
		scanner.testFileTypeBypass()
		scanner.testFileNameBypass()
		scanner.testDoubleExtension()
		scanner.testNullByteInjection()
		scanner.testCaseMismatch()
		scanner.testVariantExtensions()
	case "direct":
		scanner.testDirectUpload()
		scanner.testPathTraversal()
		scanner.testContentBypass()
	}

	fmt.Println()
	utils.SuccessPrint("文件上传漏洞检查完成！")
	utils.SuccessPrint("检测结果将保存到指定文件中")

	// 生成测试报告
	scanner.generateTestReport()
}

// newScanner 创建并初始化新的文件上传扫描器
func newScanner(target, scanType, payload string, thread, timeout int, verbose bool) *FileUploadScanner {
	return &FileUploadScanner{
		target:   target,
		scanType: scanType,
		payload:  payload,
		thread:   thread,
		timeout:  timeout,
		verbose:  verbose,
		results:  []FileUploadResult{},
		client: resty.New().
			SetTimeout(time.Duration(timeout)*time.Second).
			SetRetryCount(3).
			SetRetryWaitTime(1*time.Second).
			SetRetryMaxWaitTime(3*time.Second).
			SetHeader("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"),
	}
}

// generateTestReport 生成测试报告
func (s *FileUploadScanner) generateTestReport() {
	// 统计结果
	vulnerableCount := 0
	for _, result := range s.results {
		if result.Vulnerable {
			vulnerableCount++
		}
	}

	// 生成报告内容
	var report strings.Builder
	report.WriteString("文件上传漏洞检查报告\n")
	report.WriteString("==============================================\n")
	report.WriteString(fmt.Sprintf("目标URL: %s\n", s.target))
	report.WriteString(fmt.Sprintf("扫描时间: %s\n", utils.GetCurrentTime()))
	report.WriteString(fmt.Sprintf("扫描类型: %s\n", s.scanType))
	report.WriteString(fmt.Sprintf("线程数: %d\n", s.thread))
	report.WriteString(fmt.Sprintf("超时时间: %d秒\n", s.timeout))
	report.WriteString(fmt.Sprintf("测试总数: %d\n", len(s.results)))
	report.WriteString(fmt.Sprintf("存在风险: %d\n", vulnerableCount))
	report.WriteString("\n检测结果:\n")

	// 写入详细结果
	for i, result := range s.results {
		status := "安全"
		if result.Vulnerable {
			status = "存在风险"
		}
		report.WriteString(fmt.Sprintf("%d. %s (%s): %s\n", i+1, result.TestType, result.Technique, status))
		report.WriteString(fmt.Sprintf("   文件名: %s\n", result.FileName))
		report.WriteString(fmt.Sprintf("   状态码: %d\n", result.StatusCode))
		report.WriteString(fmt.Sprintf("   响应大小: %d bytes\n", result.ResponseSize))
		report.WriteString(fmt.Sprintf("   消息: %s\n\n", result.Message))
	}

	// 写入修复建议
	// report.WriteString("建议修复:\n")
	// report.WriteString("1. 加强文件类型检测，使用文件头+后缀双重验证\n")
	// report.WriteString("2. 统一文件名格式，移除特殊字符\n")
	// report.WriteString("3. 限制上传文件大小\n")
	// report.WriteString("4. 配置正确的文件上传目录权限\n")
	// report.WriteString("5. 实现上传文件的访问控制\n")
	// report.WriteString("6. 对上传文件进行重命名，避免路径预测\n")
	// report.WriteString("7. 禁止上传可执行文件到web目录\n")
	// report.WriteString("8. 实现上传文件的白名单机制\n")
	report.WriteString("==============================================")

	// 输出到终端
	fmt.Println()
	fmt.Println(report.String())

	// 保存报告到文件
	outputPath := "fu_result.txt"
	if s.outputFile != "" {
		outputPath = s.outputFile
	}

	if err := os.WriteFile(outputPath, []byte(report.String()), 0644); err != nil {
		utils.ErrorPrint("保存报告失败: %v", err)
		return
	}

	color.Green("\n报告已保存到 %s", outputPath)
}

// addResult 添加测试结果
func (s *FileUploadScanner) addResult(result FileUploadResult) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.results = append(s.results, result)
}

// createMultipartForm 创建multipart/form-data表单
func (s *FileUploadScanner) createMultipartForm(fileName, contentType string, fileContent []byte) (*bytes.Buffer, string, error) {
	var b bytes.Buffer
	w := multipart.NewWriter(&b)

	// 使用解析到的文件字段名，默认为"file"
	fileField := "file"
	if s.formInfo != nil && s.formInfo.FileField != "" {
		fileField = s.formInfo.FileField
	}

	// 创建文件字段
	partHeader := make(map[string][]string)
	partHeader["Content-Type"] = []string{contentType}
	fw, err := w.CreateFormFile(fileField, fileName)
	if err != nil {
		return nil, "", err
	}

	// 写入文件内容
	_, err = fw.Write(fileContent)
	if err != nil {
		return nil, "", err
	}

	// 添加其他表单字段
	if s.formInfo != nil {
		for fieldName, fieldValue := range s.formInfo.AdditionalFields {
			if fieldName != fileField { // 跳过文件字段
				err = w.WriteField(fieldName, fieldValue)
				if err != nil {
					return nil, "", err
				}
			}
		}
	}

	// 关闭multipart writer
	err = w.Close()
	if err != nil {
		return nil, "", err
	}

	return &b, w.FormDataContentType(), nil
}

// sendFileUploadRequest 发送文件上传请求
func (s *FileUploadScanner) sendFileUploadRequest(fileName, contentType string, fileContent []byte) (*resty.Response, error) {
	form, contentType, err := s.createMultipartForm(fileName, contentType, fileContent)
	if err != nil {
		return nil, err
	}

	// 确定请求URL和方法
	requestURL := s.target
	requestMethod := "POST"

	if s.formInfo != nil {
		if s.formInfo.Action != "" {
			requestURL = s.formInfo.Action
		}
		if s.formInfo.Method != "" {
			requestMethod = s.formInfo.Method
		}
	}

	// 发送请求
	var resp *resty.Response

	req := s.client.R().
		SetHeader("Content-Type", contentType).
		SetBody(form.Bytes())

	if strings.ToUpper(requestMethod) == "GET" {
		resp, err = req.Get(requestURL)
	} else {
		resp, err = req.Post(requestURL)
	}

	return resp, err
}

// parseUploadForm 从HTML响应中解析上传表单信息
func (s *FileUploadScanner) parseUploadForm(resp *resty.Response) *UploadFormInfo {
	// 初始化表单信息
	formInfo := &UploadFormInfo{
		Action:           s.target, // 默认使用当前URL
		Method:           "POST",   // 默认使用POST方法
		FileField:        "file",   // 默认文件字段名为file
		AdditionalFields: make(map[string]string),
		Enctype:          "multipart/form-data", // 默认编码类型
	}

	// 确保响应体有效
	if resp.Body() == nil || len(resp.Body()) == 0 {
		return formInfo
	}

	responseBody := string(resp.Body())
	lowerBody := strings.ToLower(responseBody)

	// 1. 简化表单action解析
	formStart := strings.Index(lowerBody, "<form")
	if formStart != -1 {
		// 查找form标签的结束位置
		formEnd := strings.Index(lowerBody[formStart:], ">")
		if formEnd != -1 {
			formTag := responseBody[formStart : formStart+formEnd+1]
			lowerFormTag := strings.ToLower(formTag)

			// 解析action
			actionStart := strings.Index(lowerFormTag, "action=")
			if actionStart != -1 {
				actionStart += 7
				if actionStart < len(lowerFormTag) {
					quote := formTag[actionStart]
					actionEnd := strings.Index(formTag[actionStart+1:], string(quote))
					if actionEnd != -1 {
						action := formTag[actionStart+1 : actionStart+1+actionEnd]
						// 处理相对路径
						if !strings.HasPrefix(action, "http://") && !strings.HasPrefix(action, "https://") {
							baseURL, err := url.Parse(s.target)
							if err == nil {
								parsedAction, err := url.Parse(action)
								if err == nil {
									formInfo.Action = baseURL.ResolveReference(parsedAction).String()
								}
							}
						} else {
							formInfo.Action = action
						}
					}
				}
			}

			// 解析method
			methodStart := strings.Index(lowerFormTag, "method=")
			if methodStart != -1 {
				methodStart += 7
				if methodStart < len(lowerFormTag) {
					quote := formTag[methodStart]
					methodEnd := strings.Index(formTag[methodStart+1:], string(quote))
					if methodEnd != -1 {
						method := strings.ToUpper(formTag[methodStart+1 : methodStart+1+methodEnd])
						if method == "GET" || method == "POST" {
							formInfo.Method = method
						}
					}
				}
			}
		}
	}

	// 2. 简化file input字段解析
	fileTypePos := strings.Index(lowerBody, "type=\"file\"")
	if fileTypePos == -1 {
		fileTypePos = strings.Index(lowerBody, "type='file'")
	}

	if fileTypePos != -1 {
		// 查找最近的<input标签
		inputStart := strings.LastIndex(lowerBody[:fileTypePos], "<input")
		if inputStart != -1 {
			// 查找标签结束位置
			inputEnd := strings.Index(lowerBody[inputStart:], ">")
			if inputEnd != -1 {
				inputTag := responseBody[inputStart : inputStart+inputEnd+1]
				lowerInputTag := strings.ToLower(inputTag)

				// 查找name属性
				nameStart := strings.Index(lowerInputTag, "name=")
				if nameStart != -1 {
					nameStart += 5
					if nameStart < len(inputTag) {
						quote := inputTag[nameStart]
						nameEnd := strings.Index(inputTag[nameStart+1:], string(quote))
						if nameEnd != -1 {
							formInfo.FileField = inputTag[nameStart+1 : nameStart+1+nameEnd]
						}
					}
				}
			}
		}
	}

	return formInfo
}

// verifyFileUpload 验证文件是否真的上传成功
func (s *FileUploadScanner) verifyFileUpload(fileName string, resp *resty.Response) bool {
	// 1. 首先检查状态码
	if resp.StatusCode() != 200 && resp.StatusCode() != 201 {
		return false
	}

	// 2. 检查响应大小，过小的响应可能不是真正的文件上传成功
	responseBody := string(resp.Body())
	if len(responseBody) < 100 {
		return false
	}

	lowerBody := strings.ToLower(responseBody)

	// 3. 检查响应是否为典型的文件上传成功页面
	// 排除常见的错误页面和默认页面
	if s.isErrorPage(responseBody, lowerBody) {
		return false
	}

	// 4. 严格检查HTML元素中的成功提示
	if s.isUploadSuccessByHTML(responseBody, lowerBody) {
		return true
	}

	// 5. 严格检查JavaScript中的成功提示
	if s.isUploadSuccessByJS(responseBody, lowerBody, fileName) {
		return true
	}

	// 6. 尝试直接访问上传的文件，这是最可靠的验证方式
	if s.isFileAccessible(fileName, "") {
		return true
	}

	// 7. 严格检查响应内容中的成功关键词
	if s.isUploadSuccessByKeywords(lowerBody) {
		return true
	}

	// 8. 检查是否返回了明确的文件保存路径
	if s.hasExplicitFilePath(lowerBody) {
		return true
	}

	// 9. 检查响应中是否包含我们上传的文件内容特征
	if s.hasFileContentFeature(responseBody, lowerBody) {
		return true
	}

	return false
}

// isErrorPage 检查是否为错误页面或默认页面
func (s *FileUploadScanner) isErrorPage(responseBody, lowerBody string) bool {
	// 常见的错误页面关键词
	errorPatterns := []string{
		"404", "not found", "未找到",
		"error", "错误", "failed", "失败",
		"forbidden", "禁止访问", "403",
		"method not allowed", "不允许的方法", "405",
		"internal server error", "服务器内部错误", "500",
		"bad request", "无效请求", "400",
		"example.com", "示例网站",
		"welcome", "欢迎", "index.html",
		"home page", "首页",
	}

	for _, pattern := range errorPatterns {
		if strings.Contains(lowerBody, pattern) {
			return true
		}
	}

	// 检查是否为默认的index页面
	if strings.Contains(lowerBody, "<title>") && strings.Contains(lowerBody, "example") {
		return true
	}

	return false
}

// hasExplicitFilePath 检查是否返回了明确的文件保存路径
func (s *FileUploadScanner) hasExplicitFilePath(lowerBody string) bool {
	// 查找明确的文件路径模式
	filePathPatterns := []string{
		"file saved to", "文件保存到",
		"uploaded to", "上传到",
		"file path", "文件路径",
		"save path", "保存路径",
		"location:", "位置:",
		"url:", "地址:",
		"upload/", "uploads/",
		"files/", "images/",
		".php", ".jsp", ".asp", ".aspx",
	}

	for _, pattern := range filePathPatterns {
		if strings.Contains(lowerBody, pattern) {
			// 确保这些关键词出现在合适的上下文中
			return true
		}
	}

	return false
}

// hasFileContentFeature 检查响应中是否包含我们上传的文件内容特征
func (s *FileUploadScanner) hasFileContentFeature(responseBody, lowerBody string) bool {
	// 检查我们上传的文件内容特征
	featurePatterns := []string{
		"gif89a", "<?php",
		"base64", "<!--",
	}

	for _, pattern := range featurePatterns {
		if strings.Contains(lowerBody, pattern) {
			return true
		}
	}

	return false
}

// isUploadSuccessByHTML 通过HTML元素判断上传是否成功
func (s *FileUploadScanner) isUploadSuccessByHTML(responseBody, lowerBody string) bool {
	// 1. 查找明确的上传成功文本提示，需要更精确的匹配
	explicitSuccessPatterns := []string{
		"上传成功",
		"文件上传成功",
		"save success",
		"upload success",
		"file uploaded successfully",
	}

	for _, pattern := range explicitSuccessPatterns {
		if strings.Contains(lowerBody, pattern) {
			return true
		}
	}

	// 2. 查找包含成功提示的HTML元素，需要更严格的匹配
	elementSuccessPatterns := []string{
		"<div.*?success",
		"<span.*?success",
		"<p.*?success",
		"<div.*?上传成功",
		"<span.*?上传成功",
		"<p.*?上传成功",
	}

	for _, pattern := range elementSuccessPatterns {
		if strings.Contains(lowerBody, pattern) {
			return true
		}
	}

	// 3. 查找明确的文件路径或链接，需要更严格的验证
	if strings.Contains(lowerBody, "href=") || strings.Contains(lowerBody, "src=") {
		// 查找可能的文件路径，需要包含明确的上传目录
		uploadDirs := []string{"/upload/", "/uploads/", "/files/", "/images/"}
		fileExts := []string{".php", ".jsp", ".asp", ".aspx"}

		for _, dir := range uploadDirs {
			for _, ext := range fileExts {
				if strings.Contains(lowerBody, dir) && strings.Contains(lowerBody, ext) {
					return true
				}
			}
		}
	}

	return false
}

// isUploadSuccessByJS 通过JavaScript判断上传是否成功
func (s *FileUploadScanner) isUploadSuccessByJS(responseBody, lowerBody, fileName string) bool {
	// 1. 查找JavaScript中的明确成功提示
	jsSuccessPatterns := []string{
		"alert.*?success",
		"alert.*?上传成功",
		"console.log.*?success",
		"console.log.*?上传成功",
		"success.*=.*true",
		"success.*=.*1",
		"upload.*success",
		"file.*path.*=",
		"file.*url.*=",
		"uploaded.*file",
	}

	for _, pattern := range jsSuccessPatterns {
		if strings.Contains(lowerBody, pattern) {
			return true
		}
	}

	// 2. 查找JavaScript中的明确文件路径
	// 需要同时包含上传目录和文件扩展名
	uploadDirs := []string{"/upload/", "/uploads/", "/files/", "/images/"}
	fileExts := []string{".php", ".jsp", ".asp", ".aspx"}

	for _, dir := range uploadDirs {
		for _, ext := range fileExts {
			if strings.Contains(lowerBody, dir) && strings.Contains(lowerBody, ext) {
				return true
			}
		}
	}

	// 3. 查找文件名在JS中的明确出现，需要与成功状态相关
	cleanFileName := filepath.Base(fileName)
	lowerFileName := strings.ToLower(cleanFileName)
	if strings.Contains(lowerBody, lowerFileName) {
		// 确保文件名出现在与上传相关的上下文中
		if strings.Contains(lowerBody, "upload") || strings.Contains(lowerBody, "success") || strings.Contains(lowerBody, "file") {
			return true
		}
	}

	return false
}

// isFileAccessible 检查文件是否可以直接访问
func (s *FileUploadScanner) isFileAccessible(fileName, baseURL string) bool {
	if baseURL == "" {
		baseURL = s.target
		if strings.HasSuffix(baseURL, "/") {
			baseURL = baseURL[:len(baseURL)-1]
		}
	}

	// 移除路径部分，只保留域名和端口
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return false
	}

	// 提取文件名（移除可能的路径前缀）
	cleanFileName := filepath.Base(fileName)

	// 构建多种可能的文件访问URL
	possibleURLs := []string{
		fmt.Sprintf("%s/%s", parsedURL.String(), cleanFileName),
		fmt.Sprintf("%s/upload/%s", parsedURL.String(), cleanFileName),
		fmt.Sprintf("%s/uploads/%s", parsedURL.String(), cleanFileName),
		fmt.Sprintf("%s/files/%s", parsedURL.String(), cleanFileName),
		fmt.Sprintf("%s/images/%s", parsedURL.String(), cleanFileName),
		fmt.Sprintf("%s/uploads/2025/%s", parsedURL.String(), cleanFileName),   // 按年份组织
		fmt.Sprintf("%s/uploads/202512/%s", parsedURL.String(), cleanFileName), // 按月组织
	}

	// 尝试访问这些URL，检查文件是否存在
	for _, testURL := range possibleURLs {
		verifyResp, err := s.client.R().Get(testURL)
		if err == nil && verifyResp.StatusCode() == 200 {
			verifyBody := verifyResp.Body()
			verifyBodyStr := string(verifyBody)

			// 检查响应内容是否包含我们上传的文件特征
			// 对于PHP文件，检查是否包含<?php标签
			// 对于GIF文件，检查是否包含GIF89a文件头
			if strings.Contains(verifyBodyStr, "<?php") || strings.Contains(verifyBodyStr, "GIF89a") {
				// 检查响应大小，排除空文件或错误页面
				if len(verifyBody) > 10 {
					return true
				}
			}

			// 检查响应是否包含我们上传的文件名
			if strings.Contains(verifyBodyStr, cleanFileName) {
				return true
			}
		}
	}

	return false
}

// isUploadSuccessByKeywords 通过关键词判断上传是否成功
func (s *FileUploadScanner) isUploadSuccessByKeywords(lowerBody string) bool {
	// 1. 明确的成功关键词，需要更精确的匹配
	explicitSuccessKeywords := []string{
		"上传成功",
		"文件上传成功",
		"文件已上传",
		"文件保存成功",
		"save success",
		"upload success",
		"file uploaded successfully",
		"file saved",
		"upload complete",
	}

	for _, keyword := range explicitSuccessKeywords {
		if strings.Contains(lowerBody, keyword) {
			return true
		}
	}

	// 2. 明确的文件路径关键词，需要上下文关联
	filePathContexts := []string{
		"file path",
		"file url",
		"save path",
		"upload path",
		"文件路径",
		"保存路径",
		"上传路径",
	}

	for _, context := range filePathContexts {
		if strings.Contains(lowerBody, context) {
			return true
		}
	}

	return false
}

// testFileTypeBypass 测试文件类型绕过
func (s *FileUploadScanner) testFileTypeBypass() {
	utils.InfoPrint("正在测试文件类型绕过...")

	// 测试用例：GIF89a文件头+PHP代码
	phpContent := []byte("GIF89a<?php phpinfo(); ?>")
	fileNames := []string{
		"test.gif.php",
		"test.php.gif",
		"test.jpg.php",
		"test.php.jpg",
	}

	for _, fileName := range fileNames {
		resp, err := s.sendFileUploadRequest(fileName, "image/gif", phpContent)
		if err != nil {
			utils.ErrorPrint("发送请求失败: %v", err)
			continue
		}

		result := FileUploadResult{
			TestType:     "文件类型检测",
			Technique:    "GIF文件头绕过",
			FileName:     fileName,
			StatusCode:   resp.StatusCode(),
			ResponseSize: len(resp.Body()),
			Url:          s.target,
		}

		// 验证文件是否真的上传成功
		if s.verifyFileUpload(fileName, resp) {
			result.Vulnerable = true
			result.Message = "文件上传成功，存在文件类型绕过漏洞"
			utils.SuccessPrint("发现漏洞: %s", result.Message)
		} else {
			result.Vulnerable = false
			result.Message = "文件上传失败，文件类型检测有效"
		}

		s.addResult(result)
	}
}

// testFileNameBypass 测试文件名绕过
func (s *FileUploadScanner) testFileNameBypass() {
	utils.InfoPrint("正在测试文件名绕过...")

	// 测试各种文件名绕过技术
	bypassTechniques := []struct {
		name     string
		fileName string
	}{{
		name:     "空格绕过",
		fileName: "test.php ",
	}, {
		name:     "点号绕过",
		fileName: "test.php.",
	}, {
		name:     "双写绕过",
		fileName: "test.pphphp",
	}, {
		name:     "大小写混合",
		fileName: "test.Php",
	}}

	phpContent := []byte("<?php phpinfo(); ?>")

	for _, tech := range bypassTechniques {
		resp, err := s.sendFileUploadRequest(tech.fileName, "application/octet-stream", phpContent)
		if err != nil {
			utils.ErrorPrint("发送请求失败: %v", err)
			continue
		}

		result := FileUploadResult{
			TestType:     "文件名验证",
			Technique:    tech.name,
			FileName:     tech.fileName,
			StatusCode:   resp.StatusCode(),
			ResponseSize: len(resp.Body()),
			Url:          s.target,
		}

		// 验证文件是否真的上传成功
		if s.verifyFileUpload(tech.fileName, resp) {
			result.Vulnerable = true
			result.Message = "文件上传成功，存在文件名绕过漏洞"
			utils.SuccessPrint("发现漏洞: %s", result.Message)
		} else {
			result.Vulnerable = false
			result.Message = "文件上传失败，文件名验证有效"
		}

		s.addResult(result)
	}
}

// testPathTraversal 测试路径穿越
func (s *FileUploadScanner) testPathTraversal() {
	utils.InfoPrint("正在测试路径穿越...")

	// 测试路径穿越Payload
	pathPayloads := []string{
		"../../../../var/www/html/test.php",
		"../../../test.php",
		"../test.php",
		"../../../../test.php", // Windows风格（使用正斜杠兼容）
	}

	phpContent := []byte("<?php phpinfo(); ?>")

	for _, payload := range pathPayloads {
		resp, err := s.sendFileUploadRequest(payload, "application/octet-stream", phpContent)
		if err != nil {
			utils.ErrorPrint("发送请求失败: %v", err)
			continue
		}

		result := FileUploadResult{
			TestType:     "路径处理",
			Technique:    "路径穿越",
			FileName:     payload,
			StatusCode:   resp.StatusCode(),
			ResponseSize: len(resp.Body()),
			Url:          s.target,
		}

		// 验证文件是否真的上传成功
		if s.verifyFileUpload(payload, resp) {
			result.Vulnerable = true
			result.Message = "文件上传成功，存在路径穿越漏洞"
			utils.SuccessPrint("发现漏洞: %s", result.Message)
		} else {
			result.Vulnerable = false
			result.Message = "文件上传失败，路径处理有效"
		}

		s.addResult(result)
	}
}

// testContentBypass 测试内容校验绕过
func (s *FileUploadScanner) testContentBypass() {
	utils.InfoPrint("正在测试内容校验绕过...")

	// 测试Base64编码绕过
	encodedPhp := base64.StdEncoding.EncodeToString([]byte("<?php phpinfo(); ?>"))
	encodedContent := []byte(fmt.Sprintf("<!-- %s -->", encodedPhp))

	resp, err := s.sendFileUploadRequest("test.txt", "text/plain", encodedContent)
	if err != nil {
		utils.ErrorPrint("发送请求失败: %v", err)
		return
	}

	result := FileUploadResult{
		TestType:     "内容校验",
		Technique:    "Base64编码绕过",
		FileName:     "test.txt",
		StatusCode:   resp.StatusCode(),
		ResponseSize: len(resp.Body()),
		Url:          s.target,
	}

	// 验证文件是否真的上传成功
	if s.verifyFileUpload("test.txt", resp) {
		result.Vulnerable = true
		result.Message = "文件上传成功，存在内容校验绕过漏洞"
		utils.SuccessPrint("发现漏洞: %s", result.Message)
	} else {
		result.Vulnerable = false
		result.Message = "文件上传失败，内容校验有效"
	}

	s.addResult(result)
}

// testDoubleExtension 测试双后缀绕过
func (s *FileUploadScanner) testDoubleExtension() {
	utils.InfoPrint("正在测试双后缀绕过...")

	doubleExtensions := []string{
		"test.php.txt",
		"test.txt.php",
		"test.php.jpg",
		"test.jpg.php",
	}

	phpContent := []byte("<?php phpinfo(); ?>")

	for _, ext := range doubleExtensions {
		resp, err := s.sendFileUploadRequest(ext, "image/jpeg", phpContent)
		if err != nil {
			utils.ErrorPrint("发送请求失败: %v", err)
			continue
		}

		result := FileUploadResult{
			TestType:     "文件名验证",
			Technique:    "双后缀绕过",
			FileName:     ext,
			StatusCode:   resp.StatusCode(),
			ResponseSize: len(resp.Body()),
			Url:          s.target,
		}

		// 验证文件是否真的上传成功
		if s.verifyFileUpload(ext, resp) {
			result.Vulnerable = true
			result.Message = "文件上传成功，存在双后缀绕过漏洞"
			utils.SuccessPrint("发现漏洞: %s", result.Message)
		} else {
			result.Vulnerable = false
			result.Message = "文件上传失败，双后缀验证有效"
		}

		s.addResult(result)
	}
}

// testNullByteInjection 测试空字节注入
func (s *FileUploadScanner) testNullByteInjection() {
	utils.InfoPrint("正在测试空字节注入...")

	// URL编码的空字节
	nullByteFileName := "test.php%00.jpg"
	phpContent := []byte("<?php phpinfo(); ?>")

	resp, err := s.sendFileUploadRequest(nullByteFileName, "image/jpeg", phpContent)
	if err != nil {
		utils.ErrorPrint("发送请求失败: %v", err)
		return
	}

	result := FileUploadResult{
		TestType:     "文件名验证",
		Technique:    "空字节注入",
		FileName:     nullByteFileName,
		StatusCode:   resp.StatusCode(),
		ResponseSize: len(resp.Body()),
		Url:          s.target,
	}

	// 验证文件是否真的上传成功
	if s.verifyFileUpload(nullByteFileName, resp) {
		result.Vulnerable = true
		result.Message = "文件上传成功，存在空字节注入漏洞"
		utils.SuccessPrint("发现漏洞: %s", result.Message)
	} else {
		result.Vulnerable = false
		result.Message = "文件上传失败，空字节注入防护有效"
	}

	s.addResult(result)
}

// testCaseMismatch 测试大小写不匹配
func (s *FileUploadScanner) testCaseMismatch() {
	utils.InfoPrint("正在测试大小写不匹配...")

	caseVariants := []string{
		"test.PHP",
		"test.PhP",
		"TEST.php",
		"Test.Php",
	}

	phpContent := []byte("<?php phpinfo(); ?>")

	for _, variant := range caseVariants {
		resp, err := s.sendFileUploadRequest(variant, "application/octet-stream", phpContent)
		if err != nil {
			utils.ErrorPrint("发送请求失败: %v", err)
			continue
		}

		result := FileUploadResult{
			TestType:     "文件名验证",
			Technique:    "大小写不匹配",
			FileName:     variant,
			StatusCode:   resp.StatusCode(),
			ResponseSize: len(resp.Body()),
			Url:          s.target,
		}

		// 验证文件是否真的上传成功
		if s.verifyFileUpload(variant, resp) {
			result.Vulnerable = true
			result.Message = "文件上传成功，存在大小写绕过漏洞"
			utils.SuccessPrint("发现漏洞: %s", result.Message)
		} else {
			result.Vulnerable = false
			result.Message = "文件上传失败，大小写验证有效"
		}

		s.addResult(result)
	}
}

// testVariantExtensions 测试变体后缀
func (s *FileUploadScanner) testVariantExtensions() {
	utils.InfoPrint("正在测试变体后缀...")

	variantExts := []string{
		"test.php5",
		"test.phtml",
		"test.php3",
		"test.php4",
		"test.phps",
	}

	phpContent := []byte("<?php phpinfo(); ?>")

	for _, ext := range variantExts {
		resp, err := s.sendFileUploadRequest(ext, "application/octet-stream", phpContent)
		if err != nil {
			utils.ErrorPrint("发送请求失败: %v", err)
			continue
		}

		result := FileUploadResult{
			TestType:     "文件名验证",
			Technique:    "变体后缀",
			FileName:     ext,
			StatusCode:   resp.StatusCode(),
			ResponseSize: len(resp.Body()),
			Url:          s.target,
		}

		// 验证文件是否真的上传成功
		if s.verifyFileUpload(ext, resp) {
			result.Vulnerable = true
			result.Message = "文件上传成功，存在变体后缀绕过漏洞"
			utils.SuccessPrint("发现漏洞: %s", result.Message)
		} else {
			result.Vulnerable = false
			result.Message = "文件上传失败，变体后缀验证有效"
		}

		s.addResult(result)
	}
}

// testDirectUpload 测试直接上传
func (s *FileUploadScanner) testDirectUpload() {
	utils.InfoPrint("正在测试直接上传...")

	// 直接上传PHP文件
	phpContent := []byte("<?php phpinfo(); ?>")
	resp, err := s.sendFileUploadRequest("test.php", "application/octet-stream", phpContent)
	if err != nil {
		utils.ErrorPrint("发送请求失败: %v", err)
		return
	}

	result := FileUploadResult{
		TestType:     "直接上传",
		Technique:    "无绕过",
		FileName:     "test.php",
		StatusCode:   resp.StatusCode(),
		ResponseSize: len(resp.Body()),
		Url:          s.target,
	}

	// 验证文件是否真的上传成功
	if s.verifyFileUpload("test.php", resp) {
		result.Vulnerable = true
		result.Message = "PHP文件直接上传成功，存在严重文件上传漏洞"
		utils.SuccessPrint("发现严重漏洞: %s", result.Message)
	} else {
		result.Vulnerable = false
		result.Message = "PHP文件直接上传失败，上传验证有效"
	}

	s.addResult(result)
}

func init() {
	// 添加命令参数
	fuCmd.Flags().StringP("type", "t", "all", "扫描类型: all, bypass, direct")
	fuCmd.Flags().StringP("payload", "p", "", "自定义Payload文件路径")
	fuCmd.Flags().IntP("thread", "n", 10, "扫描线程数")
	fuCmd.Flags().IntP("timeout", "T", 30, "请求超时时间(秒)")
	fuCmd.Flags().BoolP("verbose", "v", false, "详细模式")
	fuCmd.Flags().StringP("output", "o", "", "输出文件路径")
}
