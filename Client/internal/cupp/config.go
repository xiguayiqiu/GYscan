package cupp

import (
	"os"
	"path/filepath"
	"strings"
)

type CUPPConfig struct {
	Years     []string
	Chars     []string
	NumFrom   int
	NumTo     int
	WCFrom    int
	WCTo      int
	Threshold int
	AlectoURL string
	DictURL   string
	LeetMap   map[string]string
}

type Profile struct {
	Name      string
	Surname   string
	Nick      string
	Birthdate string
	Wife      string
	Wifen     string
	Wifeb     string
	Kid       string
	Kidn      string
	Kidb      string
	Pet       string
	Company   string
	Words     []string
	Spechars1 string
	Randnum   string
	Leetmode  string
	Spechars  []string
}

var CONFIG CUPPConfig

func InitConfig() error {
	configPath := filepath.Join(GetCurrentPath(), "cupp.cfg")
	return readConfig(configPath)
}

func GetCurrentPath() string {
	if ex, err := os.Executable(); err == nil {
		return filepath.Dir(ex)
	}
	if wd, err := os.Getwd(); err == nil {
		return wd
	}
	return "."
}

func readConfig(filename string) error {
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		SetDefaultConfig()
		return nil
	}

	file, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	content := string(file)
	lines := strings.Split(content, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if len(line) == 0 || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasPrefix(line, "[") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch key {
		case "years":
			CONFIG.Years = strings.Split(value, ",")
		case "chars":
			CONFIG.Chars = parseChars(value)
		case "from":
			CONFIG.NumFrom = parseInt(value)
		case "to":
			CONFIG.NumTo = parseInt(value)
		case "wcfrom":
			CONFIG.WCFrom = parseInt(value)
		case "wcto":
			CONFIG.WCTo = parseInt(value)
		case "threshold":
			CONFIG.Threshold = parseInt(value)
		case "alectourl":
			CONFIG.AlectoURL = value
		case "dicturl":
			CONFIG.DictURL = value
		}
	}

	initLeetMap()
	return nil
}

func SetDefaultConfig() {
	CONFIG.Years = []string{"1990", "1991", "1992", "1993", "1994", "1995", "1996", "1997", "1998", "1999",
		"2000", "2001", "2002", "2003", "2004", "2005", "2006", "2007", "2008", "2009", "2010",
		"2011", "2012", "2013", "2014", "2015", "2016", "2017", "2018", "2019", "2020"}
	CONFIG.Chars = []string{"!", "@", "#", "$", "%", "&", "*"}
	CONFIG.NumFrom = 0
	CONFIG.NumTo = 100
	CONFIG.WCFrom = 5
	CONFIG.WCTo = 12
	CONFIG.Threshold = 200
	CONFIG.AlectoURL = "https://github.com/yangbh/Hammer/raw/b0446396e8d67a7d4e53d6666026e078262e5bab/lib/cupp/alectodb.csv.gz"
	CONFIG.DictURL = "http://ftp.funet.fi/pub/unix/security/passwd/crack/dictionaries/"
	initLeetMap()
}

func initLeetMap() {
	CONFIG.LeetMap = map[string]string{
		"a": "4",
		"i": "1",
		"e": "3",
		"t": "7",
		"o": "0",
		"s": "5",
		"g": "9",
		"z": "2",
	}
}

func parseChars(s string) []string {
	s = strings.ReplaceAll(s, " ", "")
	result := []string{}
	for _, c := range s {
		if c == ',' {
			continue
		}
		result = append(result, string(c))
	}
	return result
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
