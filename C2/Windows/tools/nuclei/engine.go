package nuclei

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"

	"gopkg.in/yaml.v3"
)

// Template represents a Nuclei template structure
type Template struct {
	ID         string                 `yaml:"id"`
	Info       TemplateInfo           `yaml:"info"`
	HTTP       []HTTPRequest          `yaml:"http,omitempty"`
	Network    []NetworkRequest       `yaml:"network,omitempty"`
	DNS        []DNSRequest           `yaml:"dns,omitempty"`
	Matchers   []Matcher              `yaml:"matchers,omitempty"`
	Extractors []Extractor            `yaml:"extractors,omitempty"`
	Variables  map[string]interface{} `yaml:"variables,omitempty"`
}

// TemplateInfo contains metadata about the template
type TemplateInfo struct {
	Name           string         `yaml:"name"`
	Author         string         `yaml:"author"`
	Severity       string         `yaml:"severity"`
	Description    string         `yaml:"description"`
	Reference      []string       `yaml:"reference,omitempty"`
	Tags           []string       `yaml:"tags,omitempty"`
	Classification Classification `yaml:"classification,omitempty"`
}

// Classification contains vulnerability classification data
type Classification struct {
	CVEID       []string `yaml:"cve-id,omitempty"`
	CWEID       []string `yaml:"cwe-id,omitempty"`
	CVSSMetrics string   `yaml:"cvss-metrics,omitempty"`
	CVSSScore   float64  `yaml:"cvss-score,omitempty"`
}

// HTTPRequest represents an HTTP request in a template
type HTTPRequest struct {
	Raw               []string          `yaml:"raw,omitempty"`
	Method            string            `yaml:"method,omitempty"`
	Path              []string          `yaml:"path,omitempty"`
	Headers           map[string]string `yaml:"headers,omitempty"`
	Body              string            `yaml:"body,omitempty"`
	Matchers          []Matcher         `yaml:"matchers,omitempty"`
	MatchersCondition string            `yaml:"matchers-condition,omitempty"`
}

// NetworkRequest represents a network request in a template
type NetworkRequest struct {
	Host     []string  `yaml:"host,omitempty"`
	Port     string    `yaml:"port,omitempty"`
	Input    string    `yaml:"input,omitempty"`
	ReadSize int       `yaml:"read-size,omitempty"`
	Matchers []Matcher `yaml:"matchers,omitempty"`
}

// DNSRequest represents a DNS request in a template
type DNSRequest struct {
	Name      string    `yaml:"name,omitempty"`
	Type      string    `yaml:"type,omitempty"`
	Class     string    `yaml:"class,omitempty"`
	Recursion bool      `yaml:"recursion,omitempty"`
	Retries   int       `yaml:"retries,omitempty"`
	Matchers  []Matcher `yaml:"matchers,omitempty"`
}

// Matcher defines conditions for matching responses
type Matcher struct {
	Type      string   `yaml:"type"`
	Condition string   `yaml:"condition,omitempty"`
	Words     []string `yaml:"words,omitempty"`
	Regex     []string `yaml:"regex,omitempty"`
	Part      string   `yaml:"part,omitempty"`
}

// Extractor defines data extraction rules
type Extractor struct {
	Type  string            `yaml:"type"`
	Part  string            `yaml:"part,omitempty"`
	Regex []string          `yaml:"regex,omitempty"`
	KVal  map[string]string `yaml:"kval,omitempty"`
}

// Engine represents the Nuclei scanning engine
type Engine struct {
	templates []*Template
	verbose   bool
	mu        sync.RWMutex
}

// NewEngine creates a new Nuclei engine instance
func NewEngine(verbose bool) *Engine {
	return &Engine{
		templates: make([]*Template, 0),
		verbose:   verbose,
		mu:        sync.RWMutex{},
	}
}

// LoadTemplates loads Nuclei templates from a directory
func (e *Engine) LoadTemplates(templateDir string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.verbose {
		log.Printf("Loading templates from directory: %s", templateDir)
	}

	err := filepath.Walk(templateDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() || filepath.Ext(path) != ".yaml" {
			return nil
		}

		template, err := e.loadTemplate(path)
		if err != nil {
			if e.verbose {
				log.Printf("Failed to load template %s: %v", path, err)
			}
			return nil // Continue with other templates
		}

		e.templates = append(e.templates, template)
		if e.verbose {
			log.Printf("Loaded template: %s (%s)", template.Info.Name, template.ID)
		}

		return nil
	})

	if err != nil {
		return fmt.Errorf("failed to walk template directory: %v", err)
	}

	if e.verbose {
		log.Printf("Loaded %d templates", len(e.templates))
	}

	return nil
}

// loadTemplate loads a single template from a YAML file
func (e *Engine) loadTemplate(filePath string) (*Template, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read template file: %v", err)
	}

	var template Template
	if err := yaml.Unmarshal(data, &template); err != nil {
		return nil, fmt.Errorf("failed to parse template YAML: %v", err)
	}

	return &template, nil
}

// GetTemplates returns all loaded templates
func (e *Engine) GetTemplates() []*Template {
	e.mu.RLock()
	defer e.mu.RUnlock()

	templates := make([]*Template, len(e.templates))
	copy(templates, e.templates)
	return templates
}

// GetTemplateByID returns a template by its ID
func (e *Engine) GetTemplateByID(id string) *Template {
	e.mu.RLock()
	defer e.mu.RUnlock()

	for _, template := range e.templates {
		if template.ID == id {
			return template
		}
	}
	return nil
}

// GetTemplatesBySeverity returns templates filtered by severity
func (e *Engine) GetTemplatesBySeverity(severity string) []*Template {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var result []*Template
	for _, template := range e.templates {
		if template.Info.Severity == severity {
			result = append(result, template)
		}
	}
	return result
}

// GetTemplatesByTag returns templates filtered by tag
func (e *Engine) GetTemplatesByTag(tag string) []*Template {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var result []*Template
	for _, template := range e.templates {
		for _, t := range template.Info.Tags {
			if t == tag {
				result = append(result, template)
				break
			}
		}
	}
	return result
}

// TemplateCount returns the number of loaded templates
func (e *Engine) TemplateCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.templates)
}
