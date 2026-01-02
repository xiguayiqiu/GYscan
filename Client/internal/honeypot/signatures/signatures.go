package signatures

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
)

type SignatureManager struct {
	Signatures map[string][]Signature
	CustomDB   string
}

func NewSignatureManager() *SignatureManager {
	return &SignatureManager{
		Signatures: make(map[string][]Signature),
	}
}

func (sm *SignatureManager) LoadBuiltInSignatures() {
	sm.Signatures["ssh"] = GetSSHSignatures()
	sm.Signatures["http"] = GetHTTPSignatures()
	sm.Signatures["https"] = GetHTTPSignatures()
	sm.Signatures["ftp"] = GetFTPSignatures()
	sm.Signatures["mysql"] = GetMySQLSignatures()
	sm.Signatures["redis"] = GetRedisSignatures()
	sm.Signatures["mongodb"] = GetMongoDBSignatures()
	sm.Signatures["postgres"] = GetPostgreSQLSignatures()
	sm.Signatures["postgresql"] = GetPostgreSQLSignatures()
	sm.Signatures["rdp"] = GetRDPSignatures()
	sm.Signatures["smb"] = GetSMBSignatures()
	sm.Signatures["telnet"] = GetTelnetSignatures()
	sm.Signatures["dns"] = GetDNSSignatures()
	sm.Signatures["smtp"] = GetSMTPSignatures()
	sm.Signatures["sip"] = GetSIPSignatures()
	sm.Signatures["ldap"] = GetLDAPSignatures()
	sm.Signatures["vnc"] = GetVNCSignatures()
	sm.Signatures["snmp"] = GetSNMPSignatures()
	sm.Signatures["elasticsearch"] = GetElasticsearchSignatures()
	sm.Signatures["rabbitmq"] = GetRabbitMQSignatures()
	sm.Signatures["generic"] = GetGenericSignatures()
}

func (sm *SignatureManager) LoadCustomSignatures(path string) error {
	if path == "" {
		return nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	var sigSet SignatureSet
	if err := json.Unmarshal(data, &sigSet); err != nil {
		return err
	}

	for _, sig := range sigSet.Signatures {
		sm.Signatures[sig.Service] = append(sm.Signatures[sig.Service], sig)
	}

	sm.CustomDB = path
	return nil
}

func (sm *SignatureManager) GetSignatures(service string) []Signature {
	return sm.Signatures[service]
}

func (sm *SignatureManager) GetAllSignatures() []Signature {
	var all []Signature
	for _, sigs := range sm.Signatures {
		all = append(all, sigs...)
	}
	return all
}

func MatchPattern(text string, pattern Pattern) bool {
	var targetStr string

	switch pattern.Field {
	case "banner":
		targetStr = text
	case "version":
		idx := strings.Index(text, " ")
		if idx > 0 {
			targetStr = text[:idx]
		} else {
			targetStr = text
		}
	default:
		targetStr = text
	}

	switch pattern.Type {
	case "regex":
		if pattern.Condition == "not" {
			ok, _ := regexp.MatchString(pattern.Pattern, targetStr)
			return !ok
		}
		matched, _ := regexp.MatchString(pattern.Pattern, targetStr)
		return matched
	case "contains":
		if pattern.Condition == "not" {
			return !strings.Contains(targetStr, pattern.Pattern)
		}
		return strings.Contains(targetStr, pattern.Pattern)
	case "exact":
		if pattern.Condition == "not" {
			return targetStr != pattern.Pattern
		}
		return targetStr == pattern.Pattern
	case "prefix":
		if pattern.Condition == "not" {
			return !strings.HasPrefix(targetStr, pattern.Pattern)
		}
		return strings.HasPrefix(targetStr, pattern.Pattern)
	case "suffix":
		if pattern.Condition == "not" {
			return !strings.HasSuffix(targetStr, pattern.Pattern)
		}
		return strings.HasSuffix(targetStr, pattern.Pattern)
	}

	return false
}

type MatchedFeature struct {
	Name        string `json:"name"`
	Weight      int    `json:"weight"`
	Description string `json:"description"`
	Category    string `json:"category"`
}

type ServiceInfo struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Banner   string `json:"banner"`
	Version  string `json:"version"`
}

func (sm *SignatureManager) Match(serviceInfo *ServiceInfo) []MatchedFeature {
	var matched []MatchedFeature

	serviceSignatures := sm.GetSignatures(serviceInfo.Protocol)
	banner := serviceInfo.Banner

	for _, sig := range serviceSignatures {
		for _, pattern := range sig.Patterns {
			if MatchPattern(banner, pattern) {
				matched = append(matched, MatchedFeature{
					Name:        sig.Name,
					Weight:      sig.Weight,
					Description: sig.Description,
					Category:    sig.Category,
				})
			}
		}
	}

	genericSignatures := sm.GetSignatures("generic")
	for _, sig := range genericSignatures {
		for _, pattern := range sig.Patterns {
			if MatchPattern(banner, pattern) {
				matched = append(matched, MatchedFeature{
					Name:        sig.Name,
					Weight:      sig.Weight,
					Description: sig.Description,
					Category:    sig.Category,
				})
			}
		}
	}

	dedupFeatures := sm.deduplicateFeatures(matched)
	return dedupFeatures
}

func (sm *SignatureManager) deduplicateFeatures(features []MatchedFeature) []MatchedFeature {
	seen := make(map[string]bool)
	var result []MatchedFeature

	for _, f := range features {
		key := f.Name
		if !seen[key] {
			seen[key] = true
			result = append(result, f)
		}
	}

	return result
}
