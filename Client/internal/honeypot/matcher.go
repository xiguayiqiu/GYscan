package honeypot

import (
	"sort"
)

type ConfidenceCalculator struct {
	Weights map[string]int
}

func NewConfidenceCalculator() *ConfidenceCalculator {
	return &ConfidenceCalculator{
		Weights: map[string]int{
			"honeypot":       60,
			"version":        20,
			"virtualization": 15,
			"container":      15,
			"behavior":       35,
			"crypto":         20,
			"key_exchange":   25,
			"auth":           40,
			"banner":         15,
			"content":        50,
			"test":           25,
			"generic":        10,
			"fingerprint":    45,
			"management":     40,
			"logging":        35,
			"monitoring":     30,
			"toolchain":      35,
		},
	}
}

func (cc *ConfidenceCalculator) Calculate(features []MatchedFeature) int {
	totalWeight := 0

	for _, feature := range features {
		weight := feature.Weight

		if categoryWeight, ok := cc.Weights[feature.Category]; ok {
			weight = max(weight, categoryWeight)
		}

		switch feature.Category {
		case "honeypot":
			weight = max(weight, 60)
		case "content":
			weight = max(weight, 50)
		case "auth":
			weight = max(weight, 40)
		case "fingerprint":
			weight = max(weight, 45)
		case "behavior":
			weight = max(weight, 35)
		case "management":
			weight = max(weight, 40)
		}

		totalWeight += weight
	}

	confidence := min(totalWeight, 100)
	if len(features) >= 3 {
		confidence = min(confidence+10, 100)
	} else if len(features) >= 2 {
		confidence = min(confidence+5, 100)
	}

	return confidence
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

type Matcher struct {
	Calc *ConfidenceCalculator
}

func NewMatcher() *Matcher {
	return &Matcher{
		Calc: NewConfidenceCalculator(),
	}
}

func (m *Matcher) CalculateConfidence(features []MatchedFeature) int {
	return m.Calc.Calculate(features)
}

func (m *Matcher) GetHoneypotType(features []MatchedFeature) string {
	honeypotScores := map[string]int{
		"Kippo SSH蜜罐":      0,
		"Cowrie蜜罐":         0,
		"Dionaea蜜罐":        0,
		"ConPot工业协议蜜罐":  0,
		"rdpy RDP蜜罐":       0,
		"Generic蜜罐":        0,
	}

	for _, feature := range features {
		switch {
		case containsString(feature.Name, "Kippo") || containsString(feature.Description, "Kippo"):
			honeypotScores["Kippo SSH蜜罐"] += feature.Weight
		case containsString(feature.Name, "Cowrie") || containsString(feature.Description, "Cowrie"):
			honeypotScores["Cowrie蜜罐"] += feature.Weight
		case containsString(feature.Name, "Dionaea") || containsString(feature.Description, "Dionaea"):
			honeypotScores["Dionaea蜜罐"] += feature.Weight
		case containsString(feature.Name, "ConPot") || containsString(feature.Description, "ConPot") || containsString(feature.Name, "ICS") || containsString(feature.Name, "SCADA"):
			honeypotScores["ConPot工业协议蜜罐"] += feature.Weight
		case containsString(feature.Name, "rdpy") || containsString(feature.Description, "rdpy"):
			honeypotScores["rdpy RDP蜜罐"] += feature.Weight
		case feature.Category == "honeypot" || feature.Category == "test":
			honeypotScores["Generic蜜罐"] += feature.Weight
		}
	}

	var maxScore int
	var maxType string
	for honeypotType, score := range honeypotScores {
		if score > maxScore {
			maxScore = score
			maxType = honeypotType
		}
	}

	if maxScore >= 30 {
		return maxType
	}

	return "未识别到明确蜜罐类型"
}

func containsString(s string, substr string) bool {
	if len(s) < len(substr) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func (m *Matcher) GetSuggestions(features []MatchedFeature, confidence int) string {
	if len(features) == 0 {
		return "未检测到蜜罐特征，目标可能是正常系统"
	}

	if confidence >= 80 {
		return "此目标极可能是蜜罐系统，建议谨慎操作，避免暴露敏感信息"
	} else if confidence >= 60 {
		return "此目标可能是蜜罐系统，建议进行深度检测验证"
	} else if confidence >= 40 {
		return "检测到少量蜜罐特征，建议关注目标行为模式"
	} else {
		return "未检测到明显蜜罐特征，目标可能是正常系统"
	}
}

func (m *Matcher) SortFeaturesByWeight(features []MatchedFeature) []MatchedFeature {
	sort.Slice(features, func(i, j int) bool {
		return features[i].Weight > features[j].Weight
	})
	return features
}
