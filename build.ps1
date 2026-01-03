Write-Host "=================================================="
Write-Host "           GYscan Windows�����ű�           "
Write-Host "                �汾 1.0                        "
Write-Host "=================================================="
Write-Host ""

# ���ϵͳ����?
Write-Host "[��Ϣ] ���ϵͳ����?..."
$OS = "Windows"
$Distro = "windows"
Write-Host "[???] ?????: $OS ($Distro)"
Write-Host ""

# ���Go����
Write-Host "[��Ϣ] ���Go����..."
$goCommand = Get-Command "go" -ErrorAction SilentlyContinue
if (-not $goCommand) {
    Write-Host "[����] Goδ��װ���밲װGo 1.21.0����߰�?"
    exit 1
}

$goVersionOutput = go version
$goVersion = ($goVersionOutput -split ' ')[2].Substring(2)
Write-Host "[��Ϣ] ��ǰGo�汾: $goVersion"

# ���Go�汾�Ƿ����Ҫ��?
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
    Write-Host "[����] Go�汾���ͣ���Ҫ $requiredVersion ����߰�?"
    exit 1
}

Write-Host "[��Ϣ] Go�汾����Ҫ�� ($goVersion >= $requiredVersion)"
Write-Host ""

# ����Go����
Write-Host "[��Ϣ] ����Go����..."
go env -w GOPROXY=https://goproxy.cn,direct
go env -w GOSUMDB=sum.golang.google.cn
$proxyValue = go env GOPROXY
Write-Host "[��Ϣ] Go����������Ϊ: $proxyValue"
Write-Host ""

# ������������
Write-Host "[��Ϣ] ������������..."
go clean -cache

# ��������
Write-Host "[��Ϣ] ��������..."
go mod download

# ������Ŀ
Write-Host "[��Ϣ] ������Ŀ..."

# ��ʾ����Ŀ��ѡ��
Write-Host "����Ŀ��ѡ��:"
Write-Host "1) Client (�����ͻ��˳���)"
Write-Host "2) C2 (�����������˳���)"
Write-Host ""

# ��ʾƽ̨ѡ��
Write-Host "ƽ̨ѡ��:"
Write-Host "  windows - Windowsƽ̨��Ĭ�ϣ�"
Write-Host "  linux   - Linuxƽ̨"
Write-Host "  darwin  - macOSƽ̨"
Write-Host ""

do {
    $choice = Read-Host "��ѡ�񹹽�Ŀ�� (1/2)"
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
            Write-Host "[����] ��Ч��ѡ������������"
        }
    }
} while ($choice -notin @("1", "2"))

Write-Host "[��Ϣ] ѡ��Ĺ���Ŀ��?: $buildTarget"
Write-Host ""

# ??????
if ($buildTarget -eq "Client") {
    Write-Host "��ѡ��ClientĿ��ƽ̨:"
Write-Host "1) Linux"
Write-Host "2) Windows"
Write-Host ""

do {
    $choice = Read-Host "��ѡ��Ŀ��ƽ̨ (1/2)"
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
            Write-Host "��Ч��ѡ�������� 1 �� 2"
        }
    }
} while ($choice -notin @("1", "2"))
} else {
    Write-Host "��ѡ��C2Ŀ��ƽ̨:"
Write-Host "1) Linux"
Write-Host "2) Windows"
Write-Host ""

do {
    $choice = Read-Host "��ѡ��Ŀ��ƽ̨ (1/2)"
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
            Write-Host "��Ч��ѡ�������� 1 �� 2"
        }
    }
} while ($choice -notin @("1", "2"))
}

Write-Host "[��Ϣ] Ŀ��ƽ̨: $buildPlatform/$buildArch"
Write-Host "[��Ϣ] ����ļ�?: $outputName"
Write-Host ""

# ��ʾ��������
Write-Host "��������:"
Write-Host "Ŀ��: $buildTarget"
Write-Host "ƽ̨: $buildPlatform/$buildArch"
Write-Host "���?: $outputName"
Write-Host ""

$confirm = Read-Host "ȷ�Ͽ�ʼ����? (y/N)"
if ($confirm -notmatch "^[Yy]$") {
    Write-Host "[��Ϣ] �û�ȡ������"
    exit 0
}

Write-Host ""
Write-Host "[��Ϣ] ��ʼ������Ŀ..."

# ���浱ǰλ��
$originalLocation = Get-Location

try {
    if ($buildTarget -eq "Client") {
        Set-Location "Client"
        Write-Host "[��Ϣ] �л���ClientĿ¼..."
        
        $env:GOOS = $buildPlatform
        $env:GOARCH = $buildArch
        
        # ?????????????????????
        go build -tags nowasm -ldflags="-s -w" -o "..\$outputName"
    } else {
        Set-Location $c2Dir
        Write-Host "[��Ϣ] �л���C2Ŀ¼..."
        
        $env:GOOS = $buildPlatform
        $env:GOARCH = $buildArch
        
        go build -tags nowasm -ldflags="-s -w" -o "..\..\$outputName" ./cmd
    }
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[�ɹ�] �������?!"
        Write-Host "[��Ϣ] ���·��?: $(Get-Location)\$outputName"
        
        # ����ļ����?
        if (Test-Path $outputName) {
            Write-Host ""
            Write-Host "�ļ���Ϣ:"
            Get-ChildItem $outputName | Format-Table Name, Length, LastWriteTime -AutoSize
        }
    } else {
        Write-Host "[����] ����ʧ��!"
        exit 1
    }
} finally {
    Set-Location $originalLocation
}

Write-Host ""
Write-Host "[�ɹ�] �������?!"