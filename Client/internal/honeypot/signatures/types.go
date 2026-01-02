package signatures

import (
	"time"
)

type Signature struct {
	Name        string    `json:"name"`
	Category    string    `json:"category"`
	Service     string    `json:"service"`
	Patterns    []Pattern `json:"patterns"`
	Weight      int       `json:"weight"`
	Description string    `json:"description"`
}

type Pattern struct {
	Type      string `json:"type"`
	Pattern   string `json:"pattern"`
	Field     string `json:"field"`
	Condition string `json:"condition"`
}

type SignatureSet struct {
	Name        string      `json:"name"`
	Version     string      `json:"version"`
	Signatures  []Signature `json:"signatures"`
	UpdatedTime time.Time   `json:"updated_time"`
}
