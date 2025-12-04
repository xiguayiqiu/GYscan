package types

import (
	"time"
)

// Task 任务定义
type Task struct {
	ID          string    `json:"id"`           // 任务唯一标识符
	Target      string    `json:"target"`       // 目标主机/IP/域名
	Type        string    `json:"type"`         // 任务类型：exp, scan, recon
	Status      string    `json:"status"`       // 任务状态：pending, running, completed, failed
	AIProvider  string    `json:"ai_provider"`  // AI提供商：openai, ollama, deepseek
	CreatedAt   time.Time `json:"created_at"`   // 创建时间
	UpdatedAt   time.Time `json:"updated_at"`   // 更新时间
	StartTime   time.Time `json:"start_time"`   // 开始时间
	EndTime     time.Time `json:"end_time"`     // 结束时间
	Duration    string    `json:"duration"`     // 持续时间
	Results     string    `json:"results"`      // 任务结果摘要
	Error       string    `json:"error"`        // 错误信息
	CurrentStep string    `json:"current_step"` // 当前执行步骤
	Steps       []Step    `json:"steps"`        // 任务步骤
}

// Step 任务步骤
type Step struct {
	ID          string    `json:"id"`           // 步骤ID
	Name        string    `json:"name"`         // 步骤名称：recon, scan, exploit, lateral_movement
	Status      string    `json:"status"`       // 步骤状态：pending, running, completed, failed
	StartTime   time.Time `json:"start_time"`   // 开始时间
	EndTime     time.Time `json:"end_time"`     // 结束时间
	Duration    string    `json:"duration"`     // 持续时间
	Results     string    `json:"results"`      // 步骤结果
	Error       string    `json:"error"`        // 错误信息
	ToolResults []string  `json:"tool_results"` // 工具执行结果ID列表
}

// Credential 凭证定义
type Credential struct {
	ID        string    `json:"id"`         // 凭证ID
	Target    string    `json:"target"`     // 目标主机/IP/域名
	Type      string    `json:"type"`       // 凭证类型：password, ssh_key, token, api_key
	Username  string    `json:"username"`   // 用户名
	Password  string    `json:"password"`   // 密码（加密存储）
	KeyPath   string    `json:"key_path"`   // SSH密钥路径
	Token     string    `json:"token"`      // 令牌
	APIKey    string    `json:"api_key"`    // API密钥
	Port      int       `json:"port"`       // 端口
	Service   string    `json:"service"`    // 服务类型：ssh, rdp, smb, mysql, postgres
	CreatedAt time.Time `json:"created_at"` // 创建时间
	UpdatedAt time.Time `json:"updated_at"` // 更新时间
	Tags      []string  `json:"tags"`       // 标签
}

// ToolResult 工具执行结果
type ToolResult struct {
	ID         string    `json:"id"`          // 结果ID
	TaskID     string    `json:"task_id"`     // 关联任务ID
	StepID     string    `json:"step_id"`     // 关联步骤ID
	ToolName   string    `json:"tool_name"`   // 工具名称：nmap, sqlmap, nuclei, httpx
	Command    string    `json:"command"`     // 执行命令
	ExitCode   int       `json:"exit_code"`   // 退出码
	Stdout     string    `json:"stdout"`      // 标准输出
	Stderr     string    `json:"stderr"`      // 标准错误
	StartTime  time.Time `json:"start_time"`  // 开始时间
	EndTime    time.Time `json:"end_time"`    // 结束时间
	Duration   string    `json:"duration"`    // 持续时间
	ParsedData string    `json:"parsed_data"` // 解析后的数据（JSON格式）
	Status     string    `json:"status"`      // 状态：success, failure
	Severity   string    `json:"severity"`    // 严重程度：critical, high, medium, low, info
}

// Vulnerability 漏洞定义
type Vulnerability struct {
	ID          string    `json:"id"`          // 漏洞ID
	TaskID      string    `json:"task_id"`     // 关联任务ID
	Name        string    `json:"name"`        // 漏洞名称
	Description string    `json:"description"` // 漏洞描述
	Severity    string    `json:"severity"`    // 严重程度：critical, high, medium, low, info
	CVSS        float64   `json:"cvss"`        // CVSS评分
	CVE         string    `json:"cve"`         // CVE编号
	Reference   []string  `json:"reference"`   // 参考链接
	Location    string    `json:"location"`    // 漏洞位置
	ToolName    string    `json:"tool_name"`   // 发现工具
	Confidence  float64   `json:"confidence"`  // 置信度
	CreatedAt   time.Time `json:"created_at"`  // 发现时间
}

// ExploitResult 漏洞利用结果
type ExploitResult struct {
	ID              string    `json:"id"`               // 结果ID
	TaskID          string    `json:"task_id"`          // 关联任务ID
	VulnerabilityID string    `json:"vulnerability_id"` // 关联漏洞ID
	ExploitName     string    `json:"exploit_name"`     // 利用名称
	Status          string    `json:"status"`           // 状态：success, failure
	Output          string    `json:"output"`           // 利用输出
	Payload         string    `json:"payload"`          // 使用的payload
	StartTime       time.Time `json:"start_time"`       // 开始时间
	EndTime         time.Time `json:"end_time"`         // 结束时间
	Duration        string    `json:"duration"`         // 持续时间
}

// AIAnalysis AI分析结果
type AIAnalysis struct {
	ID        string    `json:"id"`         // 分析ID
	TaskID    string    `json:"task_id"`    // 关联任务ID
	Type      string    `json:"type"`       // 分析类型：scan_results, exploit_plan, vulnerability_assessment
	Content   string    `json:"content"`    // 分析内容
	CreatedAt time.Time `json:"created_at"` // 分析时间
	Provider  string    `json:"provider"`   // AI提供商
}

// Finding 发现结果定义
type Finding struct {
	ID             string    `json:"id"`             // 发现ID
	TaskID         string    `json:"task_id"`        // 关联任务ID
	Type           string    `json:"type"`           // 发现类型：vulnerability, configuration, information
	Severity       string    `json:"severity"`       // 严重程度：critical, high, medium, low, info
	Title          string    `json:"title"`          // 标题
	Description    string    `json:"description"`    // 描述
	Location       string    `json:"location"`       // 位置
	Evidence       string    `json:"evidence"`       // 证据
	Recommendation string    `json:"recommendation"` // 建议修复措施
	Impact         string    `json:"impact"`         // 影响分析
	Confidence     float64   `json:"confidence"`     // 置信度
	CreatedAt      time.Time `json:"created_at"`     // 发现时间
	References     []string  `json:"references"`     // 参考链接
}

// WorkflowPhase 工作流阶段枚举定义（结构体定义已移至workflow.go文件）

// WorkflowTask 工作流任务定义
type WorkflowTask struct {
	ID         string            `json:"id"`         // 任务ID
	PhaseID    string            `json:"phase_id"`   // 关联阶段ID
	Name       string            `json:"name"`       // 任务名称
	ToolName   string            `json:"tool_name"`  // 使用工具
	Command    string            `json:"command"`    // 执行命令
	Parameters map[string]string `json:"parameters"` // 任务参数
	Status     string            `json:"status"`     // 任务状态：pending, running, completed, failed
	StartTime  time.Time         `json:"start_time"` // 开始时间
	EndTime    time.Time         `json:"end_time"`   // 结束时间
	Duration   string            `json:"duration"`   // 持续时间
	Output     string            `json:"output"`     // 任务输出
	Error      string            `json:"error"`      // 错误信息
	Priority   int               `json:"priority"`   // 任务优先级
}

// RiskAssessment 风险评估结果
type RiskAssessment struct {
	ID               string    `json:"id"`                // 评估ID
	TaskID           string    `json:"task_id"`           // 关联任务ID
	OverallRisk      string    `json:"overall_risk"`      // 总体风险级别：critical, high, medium, low
	RiskScore        float64   `json:"risk_score"`        // 风险评分（0-10）
	CriticalFindings int       `json:"critical_findings"` // 严重发现数量
	HighFindings     int       `json:"high_findings"`     // 高危发现数量
	MediumFindings   int       `json:"medium_findings"`   // 中危发现数量
	LowFindings      int       `json:"low_findings"`      // 低危发现数量
	Recommendations  []string  `json:"recommendations"`   // 风险缓解建议
	CreatedAt        time.Time `json:"created_at"`        // 评估时间
}

// TargetType 目标类型枚举
type TargetType string

const (
	TargetTypeWebApp  TargetType = "web_application"
	TargetTypeAPI     TargetType = "api"
	TargetTypeNetwork TargetType = "network"
	TargetTypeMobile  TargetType = "mobile"
	TargetTypeIoT     TargetType = "iot"
	TargetTypeCloud   TargetType = "cloud"
)

// RiskLevel 风险级别枚举
type RiskLevel string

const (
	RiskLevelLow    RiskLevel = "low"
	RiskLevelMedium RiskLevel = "medium"
	RiskLevelHigh   RiskLevel = "high"
)

// TargetProfile 目标配置文件
type TargetProfile struct {
	ID           string     `json:"id"`           // 配置ID
	Target       string     `json:"target"`       // 目标地址
	Type         TargetType `json:"type"`         // 目标类型
	RiskLevel    RiskLevel  `json:"risk_level"`   // 风险级别
	Description  string     `json:"description"`  // 目标描述
	Technologies []string   `json:"technologies"` // 使用的技术栈
	OpenPorts    []int      `json:"open_ports"`   // 开放端口
	Services     []string   `json:"services"`     // 运行的服务
	CreatedAt    time.Time  `json:"created_at"`   // 创建时间
	UpdatedAt    time.Time  `json:"updated_at"`   // 更新时间
}

// TrendAnalysis 趋势分析结果
type TrendAnalysis struct {
	ID               string    `json:"id"`                // 分析ID
	Type             string    `json:"type"`              // 分析类型：performance, security, quality
	Period           string    `json:"period"`            // 分析周期：daily, weekly, monthly
	StartDate        time.Time `json:"start_date"`        // 开始日期
	EndDate          time.Time `json:"end_date"`          // 结束日期
	TotalTasks       int       `json:"total_tasks"`       // 总任务数
	SuccessRate      float64   `json:"success_rate"`      // 成功率
	AvgDuration      float64   `json:"avg_duration"`      // 平均耗时
	CriticalFindings int       `json:"critical_findings"` // 严重发现数
	HighFindings     int       `json:"high_findings"`     // 高危发现数
	Trend            string    `json:"trend"`             // 趋势：improving, stable, declining
	Insights         []string  `json:"insights"`          // 分析洞察
	Recommendations  []string  `json:"recommendations"`   // 改进建议
	CreatedAt        time.Time `json:"created_at"`        // 创建时间
}

// ReportData 报告数据
type ReportData struct {
	ID              string            `json:"id"`              // 报告ID
	TaskID          string            `json:"task_id"`         // 关联任务ID
	Title           string            `json:"title"`           // 报告标题
	Summary         string            `json:"summary"`         // 报告摘要
	Findings        []Finding         `json:"findings"`        // 发现结果
	RiskAssessment  RiskAssessment    `json:"risk_assessment"` // 风险评估
	Recommendations []string          `json:"recommendations"` // 建议措施
	CreatedAt       time.Time         `json:"created_at"`      // 创建时间
	Metadata        map[string]string `json:"metadata"`        // 元数据
}

// WorkflowPhase 工作流阶段枚举
type WorkflowPhase string

const (
	PhaseTargetAnalysis    WorkflowPhase = "target_analysis"    // 目标分析
	PhaseReconnaissance    WorkflowPhase = "reconnaissance"     // 信息收集
	PhaseVulnerabilityScan WorkflowPhase = "vulnerability_scan" // 漏洞扫描
	PhaseExploitation      WorkflowPhase = "exploitation"       // 漏洞利用
	PhasePostExploitation  WorkflowPhase = "post_exploitation"  // 后渗透
	PhaseReporting         WorkflowPhase = "reporting"          // 报告生成
)

// TestPhase 测试阶段枚举
type TestPhase string

const (
	TestPhaseReconnaissance    TestPhase = "reconnaissance"     // 信息收集
	TestPhaseVulnerabilityScan TestPhase = "vulnerability_scan" // 漏洞扫描
	TestPhaseExploitation      TestPhase = "exploitation"       // 漏洞利用
	TestPhasePostExploitation  TestPhase = "post_exploitation"  // 后渗透
	TestPhaseReporting         TestPhase = "reporting"          // 报告生成
)

// PhaseStatus 阶段状态枚举
type PhaseStatus string

const (
	StatusPending    PhaseStatus = "pending"     // 待执行
	StatusInProgress PhaseStatus = "in_progress" // 执行中
	StatusCompleted  PhaseStatus = "completed"   // 已完成
	StatusFailed     PhaseStatus = "failed"      // 失败
	StatusSkipped    PhaseStatus = "skipped"     // 跳过
)
