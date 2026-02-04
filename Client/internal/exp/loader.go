package exp

import (
	"os"
	"strings"
	"sync"

	"GYscan/internal/utils"
)

var (
	exploits   []Exploit
	shellcodes []Shellcode
	loaded     bool
	loadMutex  sync.Mutex
)

const (
	ExploitDBPath     = "exploitdb/files_exploits.csv"
	ShellcodeDBPath   = "exploitdb/files_shellcodes.csv"
	ExploitRootPath   = "exploitdb/exploits/"
	ShellcodeRootPath = "exploitdb/shellcodes/"
)

func LoadDatabase() error {
	loadMutex.Lock()
	defer loadMutex.Unlock()

	if loaded {
		return nil
	}

	utils.LogInfo("正在加载漏洞利用数据库...")

	exploitsPath, err := findFilePath(ExploitDBPath)
	if err != nil {
		utils.LogWarning("无法找到漏洞利用数据库文件: %v", err)
	} else {
		exploits, err = LoadExploitsCSV(exploitsPath)
		if err != nil {
			utils.LogWarning("加载漏洞利用数据库失败: %v", err)
		} else {
			utils.LogSuccess("成功加载 %d 条漏洞利用记录", len(exploits))
		}
	}

	shellcodesPath, err := findFilePath(ShellcodeDBPath)
	if err != nil {
		utils.LogWarning("无法找到shellcode数据库文件: %v", err)
	} else {
		shellcodes, err = LoadShellcodesCSV(shellcodesPath)
		if err != nil {
			utils.LogWarning("加载shellcode数据库失败: %v", err)
		} else {
			utils.LogSuccess("成功加载 %d 条shellcode记录", len(shellcodes))
		}
	}

	loaded = true
	return nil
}

func ReloadDatabase() error {
	loadMutex.Lock()
	defer loadMutex.Unlock()

	loaded = false
	exploits = nil
	shellcodes = nil

	return LoadDatabase()
}

func GetExploits() []Exploit {
	loadMutex.Lock()
	defer loadMutex.Unlock()

	if !loaded {
		LoadDatabase()
	}

	return exploits
}

func GetShellcodes() []Shellcode {
	loadMutex.Lock()
	defer loadMutex.Unlock()

	if !loaded {
		LoadDatabase()
	}

	return shellcodes
}

func GetExploitByID(id int) *Exploit {
	for i := range exploits {
		if exploits[i].ID == id {
			return &exploits[i]
		}
	}
	return nil
}

func GetShellcodeByID(id int) *Shellcode {
	for i := range shellcodes {
		if shellcodes[i].ID == id {
			return &shellcodes[i]
		}
	}
	return nil
}

func findFilePath(filename string) (string, error) {
	searchPaths := []string{
		filename,
		"../" + filename,
		"../../" + filename,
		"./" + filename,
		"Client/" + filename,
		"Client/exploitdb/" + filename,
	}

	for _, path := range searchPaths {
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}

	homePath := os.Getenv("HOME")
	if homePath != "" {
		fullPath := homePath + "/GYscan/" + filename
		if _, err := os.Stat(fullPath); err == nil {
			return fullPath, nil
		}
	}

	wd, _ := os.Getwd()
	possiblePaths := []string{
		wd + "/" + filename,
		wd + "/Client/" + filename,
		wd + "/exploitdb/" + filename,
	}

	for _, path := range possiblePaths {
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}

	return "", os.ErrNotExist
}

func GetExploitFilePath(exploit Exploit) (string, error) {
	basePath := findExploitRootPath()
	if basePath == "" {
		return "", os.ErrNotExist
	}

	filePath := exploit.File
	if strings.HasPrefix(filePath, "exploits/") {
		filePath = strings.TrimPrefix(filePath, "exploits/")
	}

	return basePath + filePath, nil
}

func GetShellcodeFilePath(shellcode Shellcode) (string, error) {
	basePath := findShellcodeRootPath()
	if basePath == "" {
		return "", os.ErrNotExist
	}
	return basePath + shellcode.File, nil
}

func findExploitRootPath() string {
	searchPaths := []string{
		ExploitRootPath,
		"../" + ExploitRootPath,
		"../../" + ExploitRootPath,
		"Client/" + ExploitRootPath,
		"Client/exploitdb/exploits/",
	}

	for _, path := range searchPaths {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	wd, _ := os.Getwd()
	for _, suffix := range []string{"", "/Client", "/exploitdb"} {
		path := wd + suffix + "/exploits/"
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	return ""
}

func findShellcodeRootPath() string {
	searchPaths := []string{
		ShellcodeRootPath,
		"../" + ShellcodeRootPath,
		"../../" + ShellcodeRootPath,
		"Client/" + ShellcodeRootPath,
		"Client/exploitdb/shellcodes/",
	}

	for _, path := range searchPaths {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	wd, _ := os.Getwd()
	for _, suffix := range []string{"", "/Client", "/exploitdb"} {
		path := wd + suffix + "/shellcodes/"
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	return ""
}

func IsLoaded() bool {
	loadMutex.Lock()
	defer loadMutex.Unlock()
	return loaded
}

func GetDatabaseStats() (exploitCount, shellcodeCount int) {
	loadMutex.Lock()
	defer loadMutex.Unlock()
	return len(exploits), len(shellcodes)
}
