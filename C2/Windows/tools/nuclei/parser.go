package nuclei

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Parser handles the parsing of Nuclei template files
type Parser struct {
	verbose bool
}

// NewParser creates a new template parser
func NewParser(verbose bool) *Parser {
	return &Parser{
		verbose: verbose,
	}
}

// ParseTemplate parses a single template file
func (p *Parser) ParseTemplate(filePath string) (*Template, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read template file %s: %v", filePath, err)
	}

	var template Template
	if err := yaml.Unmarshal(data, &template); err != nil {
		return nil, fmt.Errorf("failed to parse template YAML %s: %v", filePath, err)
	}

	// Validate required fields
	if template.ID == "" {
		return nil, fmt.Errorf("template missing required field 'id' in %s", filePath)
	}

	if template.Info.Name == "" {
		return nil, fmt.Errorf("template missing required field 'info.name' in %s", filePath)
	}

	if template.Info.Severity == "" {
		template.Info.Severity = "info" // Default severity
	}

	if p.verbose {
		fmt.Printf("Parsed template: %s (%s)\n", template.Info.Name, template.ID)
	}

	return &template, nil
}

// ParseTemplatesFromDirectory parses all templates in a directory
func (p *Parser) ParseTemplatesFromDirectory(dirPath string) ([]*Template, error) {
	var templates []*Template

	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		// Only parse YAML files
		if strings.ToLower(filepath.Ext(path)) != ".yaml" && strings.ToLower(filepath.Ext(path)) != ".yml" {
			return nil
		}

		template, err := p.ParseTemplate(path)
		if err != nil {
			if p.verbose {
				fmt.Printf("Warning: Failed to parse template %s: %v\n", path, err)
			}
			return nil // Continue with other files
		}

		templates = append(templates, template)
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to walk directory %s: %v", dirPath, err)
	}

	if p.verbose {
		fmt.Printf("Parsed %d templates from directory: %s\n", len(templates), dirPath)
	}

	return templates, nil
}

// ParseTemplateFromReader parses a template from an io.Reader
func (p *Parser) ParseTemplateFromReader(reader io.Reader) (*Template, error) {
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read template data: %v", err)
	}

	var template Template
	if err := yaml.Unmarshal(data, &template); err != nil {
		return nil, fmt.Errorf("failed to parse template YAML: %v", err)
	}

	// Validate required fields
	if template.ID == "" {
		return nil, fmt.Errorf("template missing required field 'id'")
	}

	if template.Info.Name == "" {
		return nil, fmt.Errorf("template missing required field 'info.name'")
	}

	if template.Info.Severity == "" {
		template.Info.Severity = "info" // Default severity
	}

	if p.verbose {
		fmt.Printf("Parsed template: %s (%s)\n", template.Info.Name, template.ID)
	}

	return &template, nil
}

// ValidateTemplate validates a template structure
func (p *Parser) ValidateTemplate(template *Template) error {
	if template.ID == "" {
		return fmt.Errorf("template missing required field 'id'")
	}

	if template.Info.Name == "" {
		return fmt.Errorf("template missing required field 'info.name'")
	}

	// Validate severity
	validSeverities := map[string]bool{
		"info":     true,
		"low":      true,
		"medium":   true,
		"high":     true,
		"critical": true,
	}

	if !validSeverities[strings.ToLower(template.Info.Severity)] {
		return fmt.Errorf("invalid severity '%s', must be one of: info, low, medium, high, critical", template.Info.Severity)
	}

	// Validate that template has at least one request type
	if len(template.HTTP) == 0 && len(template.DNS) == 0 && len(template.Network) == 0 {
		return fmt.Errorf("template must have at least one request type (http, dns, or network)")
	}

	// Validate HTTP requests
	for i, httpReq := range template.HTTP {
		if len(httpReq.Raw) == 0 && len(httpReq.Path) == 0 {
			return fmt.Errorf("HTTP request %d must have either 'raw' or 'path' field", i)
		}
	}

	// Validate DNS requests
	for i, dnsReq := range template.DNS {
		if dnsReq.Name == "" {
			return fmt.Errorf("DNS request %d must have 'name' field", i)
		}
	}

	// Validate Network requests
	for i, netReq := range template.Network {
		if len(netReq.Host) == 0 {
			return fmt.Errorf("Network request %d must have 'host' field", i)
		}
	}

	return nil
}

// TemplateToYAML converts a template back to YAML format
func (p *Parser) TemplateToYAML(template *Template) ([]byte, error) {
	data, err := yaml.Marshal(template)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal template to YAML: %v", err)
	}
	return data, nil
}

// SaveTemplate saves a template to a file
func (p *Parser) SaveTemplate(template *Template, filePath string) error {
	data, err := p.TemplateToYAML(template)
	if err != nil {
		return err
	}

	// Create directory if it doesn't exist
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %v", dir, err)
	}

	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write template to file %s: %v", filePath, err)
	}

	if p.verbose {
		fmt.Printf("Saved template to: %s\n", filePath)
	}

	return nil
}

// FilterTemplates filters templates based on various criteria
func (p *Parser) FilterTemplates(templates []*Template, filters TemplateFilters) []*Template {
	var filtered []*Template

	for _, template := range templates {
		if p.matchesFilters(template, filters) {
			filtered = append(filtered, template)
		}
	}

	return filtered
}

// TemplateFilters defines filtering criteria for templates
type TemplateFilters struct {
	Severities []string
	Tags       []string
	Authors    []string
	IDs        []string
}

// matchesFilters checks if a template matches the given filters
func (p *Parser) matchesFilters(template *Template, filters TemplateFilters) bool {
	// Filter by severity
	if len(filters.Severities) > 0 {
		matched := false
		for _, severity := range filters.Severities {
			if strings.EqualFold(template.Info.Severity, severity) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Filter by tags
	if len(filters.Tags) > 0 {
		matched := false
		for _, filterTag := range filters.Tags {
			for _, templateTag := range template.Info.Tags {
				if strings.EqualFold(templateTag, filterTag) {
					matched = true
					break
				}
			}
			if matched {
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Filter by authors
	if len(filters.Authors) > 0 {
		matched := false
		for _, author := range filters.Authors {
			if strings.Contains(strings.ToLower(template.Info.Author), strings.ToLower(author)) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Filter by IDs
	if len(filters.IDs) > 0 {
		matched := false
		for _, id := range filters.IDs {
			if template.ID == id {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	return true
}

// GetTemplateStats returns statistics about a collection of templates
func (p *Parser) GetTemplateStats(templates []*Template) TemplateStats {
	stats := TemplateStats{
		Total:        len(templates),
		BySeverity:  make(map[string]int),
		ByProtocol:  make(map[string]int),
		UniqueTags:  make(map[string]bool),
		UniqueAuthors: make(map[string]bool),
	}

	for _, template := range templates {
		// Count by severity
		stats.BySeverity[template.Info.Severity]++

		// Count by protocol
		if len(template.HTTP) > 0 {
			stats.ByProtocol["http"]++
		}
		if len(template.DNS) > 0 {
			stats.ByProtocol["dns"]++
		}
		if len(template.Network) > 0 {
			stats.ByProtocol["network"]++
		}

		// Collect unique tags
		for _, tag := range template.Info.Tags {
			stats.UniqueTags[tag] = true
		}

		// Collect unique authors
		if template.Info.Author != "" {
			stats.UniqueAuthors[template.Info.Author] = true
		}
	}

	return stats
}

// TemplateStats contains statistics about templates
type TemplateStats struct {
	Total         int
	BySeverity    map[string]int
	ByProtocol    map[string]int
	UniqueTags    map[string]bool
	UniqueAuthors map[string]bool
}