package main

import (
	"GYscan/internal/cli"
	"GYscan/internal/config"
	"GYscan/internal/utils"
	"os"
	"runtime"
)

func main() {
	setupEncoding()
	setupRuntime()

	if err := config.InitConfig(); err != nil {
		utils.LogWarning("配置加载失败，使用默认配置: %v", err)
	}

	cli.Execute()
}

func setupEncoding() {
	if runtime.GOOS == "windows" {
		os.Setenv("PYTHONIOENCODING", "utf-8")
	}
}

func setupRuntime() {
	runtime.GOMAXPROCS(runtime.NumCPU())
}
