package exp

import (
	"encoding/csv"
	"os"
	"strings"
)

type Exploit struct {
	ID             int
	File           string
	Description    string
	DatePublished  string
	Author         string
	Type           string
	Platform       string
	Port           string
	DateAdded      string
	DateUpdated    string
	Verified       bool
	Codes          string
	Tags           string
	Aliases        string
	ScreenshotURL  string
	ApplicationURL string
	SourceURL      string
}

type Shellcode struct {
	ID             int
	File           string
	Description    string
	DatePublished  string
	Author         string
	Type           string
	Platform       string
	Size           string
	DateAdded      string
	DateUpdated    string
	Verified       bool
	Codes          string
	Tags           string
	Aliases        string
	ScreenshotURL  string
	ApplicationURL string
	SourceURL      string
}

type SearchOptions struct {
	Query         string
	CVE           string
	Platform      string
	Type          string
	ExactMatch    bool
	CaseSensitive bool
	OutputPath    string
	Format        string
}

type SearchResult struct {
	TotalFound int
	Exploits   []Exploit
	Shellcodes []Shellcode
}

func ParseExploit(record []string) Exploit {
	return Exploit{
		ID:             parseInt(record[0]),
		File:           record[1],
		Description:    record[2],
		DatePublished:  record[3],
		Author:         record[4],
		Type:           record[5],
		Platform:       record[6],
		Port:           record[7],
		DateAdded:      record[8],
		DateUpdated:    record[9],
		Verified:       record[10] == "1",
		Codes:          record[11],
		Tags:           record[12],
		Aliases:        record[13],
		ScreenshotURL:  record[14],
		ApplicationURL: record[15],
		SourceURL:      record[16],
	}
}

func ParseShellcode(record []string) Shellcode {
	return Shellcode{
		ID:             parseInt(record[0]),
		File:           record[1],
		Description:    record[2],
		DatePublished:  record[3],
		Author:         record[4],
		Type:           record[5],
		Platform:       record[6],
		Size:           record[7],
		DateAdded:      record[8],
		DateUpdated:    record[9],
		Verified:       record[10] == "1",
		Codes:          record[11],
		Tags:           record[12],
		Aliases:        record[13],
		ScreenshotURL:  record[14],
		ApplicationURL: record[15],
		SourceURL:      record[16],
	}
}

func parseInt(s string) int {
	var result int
	for _, c := range s {
		if c >= '0' && c <= '9' {
			result = result*10 + int(c-'0')
		}
	}
	return result
}

func LoadExploitsCSV(filePath string) ([]Exploit, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	reader := csv.NewReader(file)
	reader.FieldsPerRecord = -1

	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}

	var exploits []Exploit
	for i, record := range records {
		if i == 0 {
			continue
		}
		if len(record) >= 17 {
			exploits = append(exploits, ParseExploit(record))
		}
	}

	return exploits, nil
}

func LoadShellcodesCSV(filePath string) ([]Shellcode, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	reader := csv.NewReader(file)
	reader.FieldsPerRecord = -1

	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}

	var shellcodes []Shellcode
	for i, record := range records {
		if i == 0 {
			continue
		}
		if len(record) >= 17 {
			shellcodes = append(shellcodes, ParseShellcode(record))
		}
	}

	return shellcodes, nil
}

func (e *Exploit) MatchesSearch(options SearchOptions) bool {
	if options.CVE != "" {
		if !strings.Contains(strings.ToLower(e.Codes), strings.ToLower(options.CVE)) {
			return false
		}
	}

	if options.Platform != "" {
		if !strings.Contains(strings.ToLower(e.Platform), strings.ToLower(options.Platform)) {
			return false
		}
	}

	if options.Type != "" {
		if !strings.Contains(strings.ToLower(e.Type), strings.ToLower(options.Type)) {
			return false
		}
	}

	if options.Query != "" {
		searchText := e.Description + " " + e.File + " " + e.Platform + " " + e.Tags
		if options.CaseSensitive {
			if !strings.Contains(searchText, options.Query) {
				return false
			}
		} else {
			if !strings.Contains(strings.ToLower(searchText), strings.ToLower(options.Query)) {
				return false
			}
		}
	}

	return true
}

func (s *Shellcode) MatchesSearch(options SearchOptions) bool {
	if options.Platform != "" {
		if !strings.Contains(strings.ToLower(s.Platform), strings.ToLower(options.Platform)) {
			return false
		}
	}

	if options.Query != "" {
		searchText := s.Description + " " + s.File + " " + s.Platform
		if options.CaseSensitive {
			if !strings.Contains(searchText, options.Query) {
				return false
			}
		} else {
			if !strings.Contains(strings.ToLower(searchText), strings.ToLower(options.Query)) {
				return false
			}
		}
	}

	return true
}
