Write-Host "=================================================="
Write-Host "           GYscan Windows构建脚本           "
Write-Host "                版本 1.0                        "
Write-Host "=================================================="
Write-Host ""

# 检测系统环境
Write-Host "[信息] 检测系统环境..."
$OS = "Windows"
$Distro = "windows"
Write-Host "[???] ?????: $OS ($Distro)"
Write-Host ""

# 检查Go环境
Write-Host "[信息] 检查Go环境..."
$goCommand = Get-Command "go" -ErrorAction SilentlyContinue
if (-not $goCommand) {
    Write-Host "[错误] Go未安装，请安装Go 1.21.0或更高版本"
    exit 1
}

$goVersionOutput = go version
$goVersion = ($goVersionOutput -split ' ')[2].Substring(2)
Write-Host "[信息] 当前Go版本: $goVersion"

# 检查Go版本是否符合要求
$requiredVersion = "1.21.0"
$versionParts = $goVersion -split '\.'
$reqVersionParts = $requiredVersion -split '\.'

$isVersionOk = $false

if ([int]$versionParts[0] -gt [int]$reqVersionParts[0]) {
    $isVersionOk = $true
} elseif ([int]$versionParts[0] -eq [int]$reqVersionParts[0]) {
    if ([int]$versionParts[1] -gt [int]$reqVersionParts[1]) {
        $isVersionOk = $true
    } elseif ([int]$versionParts[1] -eq [int]$reqVersionParts[1]) {
        if ([int]$versionParts[2] -ge [int]$reqVersionParts[2]) {
            $isVersionOk = $true
        }
    }
}

if (-not $isVersionOk) {
    Write-Host "[错误] Go版本过低，需要 $requiredVersion 或更高版本"
    exit 1
}

Write-Host "[信息] Go版本符合要求 ($goVersion >= $requiredVersion)"
Write-Host ""

# 设置Go代理
Write-Host "[信息] 设置Go代理..."
go env -w GOPROXY=https://goproxy.cn,direct
go env -w GOSUMDB=sum.golang.google.cn
$proxyValue = go env GOPROXY
Write-Host "[信息] Go代理已设置为: $proxyValue"
Write-Host ""

# 清理构建缓存
Write-Host "[信息] 清理构建缓存..."
go clean -cache

# 下载依赖
Write-Host "[信息] 下载依赖..."
go mod download

# 编译项目
Write-Host "[信息] 编译项目..."

# 显示构建目标选项
Write-Host "构建目标选项:"
Write-Host "1) Client (构建客户端程序)"
Write-Host "2) C2 (构建服务器端程序)"
Write-Host ""

# 显示平台选项
Write-Host "平台选项:"
Write-Host "  windows - Windows平台（默认）"
Write-Host "  linux   - Linux平台"
Write-Host "  darwin  - macOS平台"
Write-Host ""

do {
    $choice = Read-Host "请选择构建目标 (1/2)"
    switch ($choice) {
        "1" { 
            $buildTarget = "Client"
            break
        }
        "2" { 
            $buildTarget = "C2"
            break
        }
        default {
            Write-Host "[错误] 无效的选择，请重新输入"
        }
    }
} while ($choice -notin @("1", "2"))

Write-Host "[信息] 选择的构建目标: $buildTarget"
Write-Host ""

# ??????
if ($buildTarget -eq "Client") {
    Write-Host "请选择Client目标平台:"
Write-Host "1) Linux"
Write-Host "2) Windows"
Write-Host ""

do {
    $choice = Read-Host "请选择目标平台 (1/2)"
    switch ($choice) {
        "1" { 
            $buildPlatform = "linux"
            $buildArch = "amd64"
            $outputName = "GYscan-linux-amd64"
            break
        }
        "2" { 
            $buildPlatform = "windows"
            $buildArch = "amd64"
            $outputName = "GYscan-Windows.exe"
            break
        }
        default {
            Write-Host "无效的选择，请输入 1 或 2"
        }
    }
} while ($choice -notin @("1", "2"))
} else {
    Write-Host "请选择C2目标平台:"
Write-Host "1) Linux"
Write-Host "2) Windows"
Write-Host ""

do {
    $choice = Read-Host "请选择目标平台 (1/2)"
    switch ($choice) {
        "1" { 
            $buildPlatform = "linux"
            $buildArch = "amd64"
            $outputName = "GYscan_C2_Linux"
            $c2Dir = "C2\Linux"
            break
        }
        "2" { 
            $buildPlatform = "windows"
            $buildArch = "amd64"
            $outputName = "GYscan_C2_Windows.exe"
            $c2Dir = "C2\Windows"
            break
        }
        default {
            Write-Host "无效的选择，请输入 1 或 2"
        }
    }
} while ($choice -notin @("1", "2"))
}

Write-Host "[信息] 目标平台: $buildPlatform/$buildArch"
Write-Host "[信息] 输出文件: $outputName"
Write-Host ""

# 显示构建配置
Write-Host "构建配置:"
Write-Host "目标: $buildTarget"
Write-Host "平台: $buildPlatform/$buildArch"
Write-Host "输出: $outputName"
Write-Host ""

$confirm = Read-Host "确认开始构建? (y/N)"
if ($confirm -notmatch "^[Yy]$") {
    Write-Host "[信息] 用户取消构建"
    exit 0
}

Write-Host ""
Write-Host "[信息] 开始构建项目..."

# 保存当前位置
$originalLocation = Get-Location

try {
    if ($buildTarget -eq "Client") {
        Set-Location "Client"
        Write-Host "[信息] 切换到Client目录..."
        
        $env:GOOS = $buildPlatform
        $env:GOARCH = $buildArch
        
        # ?????????????????????
        go build -tags nowasm -ldflags="-s -w" -o "..\$outputName"
    } else {
        Set-Location $c2Dir
        Write-Host "[信息] 切换到C2目录..."
        
        $env:GOOS = $buildPlatform
        $env:GOARCH = $buildArch
        
        go build -tags nowasm -ldflags="-s -w" -o "..\..\$outputName" ./cmd
    }
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[成功] 构建完成!"
        Write-Host "[信息] 输出路径: $(Get-Location)\$outputName"
        
        # 检查文件大小
        if (Test-Path $outputName) {
            Write-Host ""
            Write-Host "文件信息:"
            Get-ChildItem $outputName | Format-Table Name, Length, LastWriteTime -AutoSize
        }
    } else {
        Write-Host "[错误] 构建失败!"
        exit 1
    }
} finally {
    Set-Location $originalLocation
}

Write-Host ""
Write-Host "[成功] 构建完成!"