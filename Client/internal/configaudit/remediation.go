package configaudit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type RemediationStatus string

const (
	StatusOpen         RemediationStatus = "open"
	StatusInProgress   RemediationStatus = "in_progress"
	StatusPendingReview RemediationStatus = "pending_review"
	StatusCompleted    RemediationStatus = "completed"
	StatusAcceptedRisk RemediationStatus = "accepted_risk"
	StatusFalsePositive RemediationStatus = "false_positive"
)

type RemediationTicket struct {
	ID            string             `json:"id"`
	CheckID       string             `json:"check_id"`
	Finding       string             `json:"finding"`
	Severity      Severity           `json:"severity"`
	Status        RemediationStatus  `json:"status"`
	Priority      int                `json:"priority"`
	Assignee      string             `json:"assignee"`
	CreatedAt     time.Time          `json:"created_at"`
	UpdatedAt     time.Time          `json:"updated_at"`
	DueDate       time.Time          `json:"due_date"`
	CompletedAt   *time.Time         `json:"completed_at,omitempty"`
	Notes         []RemediationNote  `json:"notes"`
	Evidence      []string           `json:"evidence"`
	Remediation   Remediation        `json:"remediation"`
}

type RemediationNote struct {
	Content   string    `json:"content"`
	Author    string    `json:"author"`
	Timestamp time.Time `json:"timestamp"`
}

type RemediationTracker struct {
	tickets    map[string]*RemediationTicket
	baseDir    string
}

func NewRemediationTracker(baseDir string) *RemediationTracker {
	if baseDir == "" {
		baseDir = "./remediation_tracking"
	}

	tracker := &RemediationTracker{
		tickets: make(map[string]*RemediationTicket),
		baseDir: baseDir,
	}

	os.MkdirAll(baseDir, 0755)
	tracker.loadTickets()

	return tracker
}

func (rt *RemediationTracker) loadTickets() {
	entries, err := os.ReadDir(rt.baseDir)
	if err != nil {
		return
	}

	for _, entry := range entries {
		if entry.IsDir() {
			ticketFile := filepath.Join(rt.baseDir, entry.Name(), "ticket.json")
			data, err := os.ReadFile(ticketFile)
			if err != nil {
				continue
			}

			var ticket RemediationTicket
			if err := json.Unmarshal(data, &ticket); err != nil {
				continue
			}

			rt.tickets[ticket.ID] = &ticket
		}
	}
}

func (rt *RemediationTracker) CreateTicket(report *AuditReport) []*RemediationTicket {
	var tickets []*RemediationTicket

	for _, result := range report.FailedChecks {
		ticket := rt.createTicketFromResult(result, report.Target)
		rt.tickets[ticket.ID] = ticket
		tickets = append(tickets, ticket)

		rt.saveTicket(ticket)
	}

	return tickets
}

func (rt *RemediationTracker) createTicketFromResult(result *CheckResult, target string) *RemediationTicket {
	ticket := &RemediationTicket{
		ID:        fmt.Sprintf("TKT-%s-%d", time.Now().Format("20060102"), len(rt.tickets)+1),
		CheckID:   result.CheckID,
		Finding:   result.Details,
		Severity:  Severity(result.RiskLevel),
		Status:    StatusOpen,
		Priority:  rt.calculatePriority(result),
		Assignee:  "",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		DueDate:   time.Now().AddDate(0, 0, rt.calculateDueDate(result)),
		Notes:     []RemediationNote{},
		Evidence:  []string{},
	}

	if result.Evidence != "" {
		ticket.Evidence = append(ticket.Evidence, result.Evidence)
	}

	return ticket
}

func (rt *RemediationTracker) calculatePriority(result *CheckResult) int {
	switch result.RiskLevel {
	case RiskLevelCritical:
		return 1
	case RiskLevelHigh:
		return 2
	case RiskLevelMedium:
		return 3
	case RiskLevelLow:
		return 4
	default:
		return 5
	}
}

func (rt *RemediationTracker) calculateDueDate(result *CheckResult) int {
	switch result.RiskLevel {
	case RiskLevelCritical:
		return 3
	case RiskLevelHigh:
		return 7
	case RiskLevelMedium:
		return 14
	case RiskLevelLow:
		return 30
	default:
		return 30
	}
}

func (rt *RemediationTracker) saveTicket(ticket *RemediationTicket) {
	ticketDir := filepath.Join(rt.baseDir, ticket.ID)
	os.MkdirAll(ticketDir, 0755)

	ticketFile := filepath.Join(ticketDir, "ticket.json")
	data, _ := json.MarshalIndent(ticket, "", "  ")
	os.WriteFile(ticketFile, data, 0644)
}

func (rt *RemediationTracker) GetTicket(id string) (*RemediationTicket, error) {
	ticket, exists := rt.tickets[id]
	if !exists {
		return nil, fmt.Errorf("未找到工单: %s", id)
	}
	return ticket, nil
}

func (rt *RemediationTracker) UpdateTicketStatus(id string, status RemediationStatus) error {
	ticket, err := rt.GetTicket(id)
	if err != nil {
		return err
	}

	ticket.Status = status
	ticket.UpdatedAt = time.Now()

	if status == StatusCompleted {
		now := time.Now()
		ticket.CompletedAt = &now
	}

	rt.saveTicket(ticket)
	return nil
}

func (rt *RemediationTracker) AddNote(ticketID string, content string, author string) error {
	ticket, err := rt.GetTicket(ticketID)
	if err != nil {
		return err
	}

	note := RemediationNote{
		Content:   content,
		Author:    author,
		Timestamp: time.Now(),
	}

	ticket.Notes = append(ticket.Notes, note)
	ticket.UpdatedAt = time.Now()

	rt.saveTicket(ticket)
	return nil
}

func (rt *RemediationTracker) AssignTicket(ticketID string, assignee string) error {
	ticket, err := rt.GetTicket(ticketID)
	if err != nil {
		return err
	}

	ticket.Assignee = assignee
	ticket.UpdatedAt = time.Now()

	rt.saveTicket(ticket)
	return nil
}

func (rt *RemediationTracker) GetOpenTickets() []*RemediationTicket {
	var openTickets []*RemediationTicket

	for _, ticket := range rt.tickets {
		if ticket.Status == StatusOpen || ticket.Status == StatusInProgress {
			openTickets = append(openTickets, ticket)
		}
	}

	return openTickets
}

func (rt *RemediationTracker) GetOverdueTickets() []*RemediationTicket {
	var overdueTickets []*RemediationTicket
	now := time.Now()

	for _, ticket := range rt.tickets {
		if ticket.Status != StatusCompleted &&
		   ticket.Status != StatusAcceptedRisk &&
		   ticket.Status != StatusFalsePositive &&
		   ticket.DueDate.Before(now) {
			overdueTickets = append(overdueTickets, ticket)
		}
	}

	return overdueTickets
}

func (rt *RemediationTracker) GetTicketsByStatus(status RemediationStatus) []*RemediationTicket {
	var tickets []*RemediationTicket

	for _, ticket := range rt.tickets {
		if ticket.Status == status {
			tickets = append(tickets, ticket)
		}
	}

	return tickets
}

func (rt *RemediationTracker) GenerateSummary() *TrackerSummary {
	summary := &TrackerSummary{
		TotalTickets:  len(rt.tickets),
		ByStatus:     make(map[string]int),
		BySeverity:   make(map[string]int),
	}

	now := time.Now()

	for _, ticket := range rt.tickets {
		summary.ByStatus[string(ticket.Status)]++
		summary.BySeverity[string(ticket.Severity)]++

		if ticket.Status != StatusCompleted &&
		   ticket.Status != StatusAcceptedRisk &&
		   ticket.Status != StatusFalsePositive &&
		   ticket.DueDate.Before(now) {
			summary.OverdueTickets++
		}
	}

	summary.OpenTickets = summary.ByStatus[string(StatusOpen)] + summary.ByStatus[string(StatusInProgress)]
	summary.CompletedTickets = summary.ByStatus[string(StatusCompleted)]

	return summary
}

type TrackerSummary struct {
	TotalTickets     int                   `json:"total_tickets"`
	OpenTickets      int                   `json:"open_tickets"`
	CompletedTickets int                   `json:"completed_tickets"`
	OverdueTickets   int                   `json:"overdue_tickets"`
	ByStatus         map[string]int        `json:"by_status"`
	BySeverity       map[string]int        `json:"by_severity"`
}

func (rt *RemediationTracker) ExportReport(format string) ([]byte, error) {
	summary := rt.GenerateSummary()

	tickets := make([]*RemediationTicket, 0, len(rt.tickets))
	for _, ticket := range rt.tickets {
		tickets = append(tickets, ticket)
	}

	exportData := map[string]interface{}{
		"generated_at": time.Now().Format("2006-01-02 15:04:05"),
		"summary":      summary,
		"tickets":      tickets,
	}

	switch format {
	case "json":
		return json.MarshalIndent(exportData, "", "  ")
	case "csv":
		return rt.generateCSVReport(tickets), nil
	default:
		return rt.generateTextReport(exportData)
	}
}

func (rt *RemediationTracker) generateCSVReport(tickets []*RemediationTicket) []byte {
	csv := "ID,检查ID,发现,严重程度,状态,优先级,负责人,创建时间,截止日期,完成时间\n"

	for _, ticket := range tickets {
		csv += fmt.Sprintf("%s,%s,%s,%s,%s,%d,%s,%s,%s,",
			ticket.ID,
			ticket.CheckID,
			escapeCSV(ticket.Finding),
			ticket.Severity,
			ticket.Status,
			ticket.Priority,
			escapeCSV(ticket.Assignee),
			ticket.CreatedAt.Format("2006-01-02"),
			ticket.DueDate.Format("2006-01-02"),
		)

		if ticket.CompletedAt != nil {
			csv += ticket.CompletedAt.Format("2006-01-02") + "\n"
		} else {
			csv += "\n"
		}
	}

	return []byte(csv)
}

func escapeCSV(s string) string {
	s = fmt.Sprintf("%q", s)
	s = s[1 : len(s)-1]
	return s
}

func (rt *RemediationTracker) generateTextReport(data map[string]interface{}) ([]byte, error) {
	summary := data["summary"].(*TrackerSummary)

	text := "整改跟踪报告\n"
	text += fmt.Sprintf("生成时间: %s\n\n", time.Now().Format("2006-01-02 15:04:05"))

	text += fmt.Sprintf("总计工单: %d\n", summary.TotalTickets)
	text += fmt.Sprintf("开放工单: %d\n", summary.OpenTickets)
	text += fmt.Sprintf("已完成: %d\n", summary.CompletedTickets)
	text += fmt.Sprintf("已逾期: %d\n\n", summary.OverdueTickets)

	text += "按状态统计:\n"
	for status, count := range summary.ByStatus {
		text += fmt.Sprintf("  %s: %d\n", status, count)
	}

	text += "\n按严重程度统计:\n"
	for severity, count := range summary.BySeverity {
		text += fmt.Sprintf("  %s: %d\n", severity, count)
	}

	return []byte(text), nil
}
