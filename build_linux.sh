#!/bin/bash

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                    GYscan 一键构建脚本                       ║"
echo "║                Automated Build Script v1.0                   ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# 检测系统平台和发行版
echo "[INFO] 检测系统平台和发行版..."

# 检测操作系统
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="Linux"
    # 检测发行版
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        DISTRO=$ID
    elif [[ -f /etc/redhat-release ]]; then
        DISTRO="rhel"
    elif [[ -f /etc/debian_version ]]; then
        DISTRO="debian"
    else
        DISTRO="unknown"
    fi
else
    echo "[ERROR] 不支持的操作系统: $OSTYPE"
    exit 1
fi

echo "[SUCCESS] 检测到系统: $OS ($DISTRO)"

# 检查系统支持
case $DISTRO in
    "ubuntu"|"debian"|"centos"|"rhel"|"fedora"|"alpine")
        echo "[SUCCESS] 系统支持: $DISTRO"
        ;;
    *)
        echo "[WARNING] 未知发行版: $DISTRO，可能无法自动安装Go"
        ;;
esac
echo ""

# 检查Go环境
echo "[INFO] 检查Go环境..."

if command -v go &> /dev/null; then
    GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
    echo "[INFO] 检测到Go版本: $GO_VERSION"
    
    # 检查Go版本是否满足要求
    REQUIRED_VERSION="1.21.0"
    
    # 版本比较函数
    version_compare() {
        if [[ $1 == $2 ]]; then
            return 0
        fi
        local IFS=.
        local i ver1=($1) ver2=($2)
        for ((i=0; i<${#ver1[@]}; i++)); do
            if [[ -z ${ver2[i]} ]]; then
                return 1
            fi
            if ((10#${ver1[i]} > 10#${ver2[i]})); then
                return 1
            fi
            if ((10#${ver1[i]} < 10#${ver2[i]})); then
                return 2
            fi
        done
        return 0
    }
    
    version_compare $GO_VERSION $REQUIRED_VERSION
    COMPARE_RESULT=$?
    
    if [[ $COMPARE_RESULT -eq 2 ]]; then
        echo "[ERROR] Go版本过低，需要 $REQUIRED_VERSION 或更高版本"
        echo "[INFO] 开始自动安装Go 1.24.5..."
        REQUIRED_VERSION="1.24.5"
        
        # 自动安装Go
        install_go() {
            case $DISTRO in
                "ubuntu"|"debian")
                    echo "[INFO] 检测到Debian/Ubuntu系统，使用apt安装..."
                    sudo apt update
                    sudo apt install -y wget tar gzip
                    
                    # 下载Go
                    GO_TAR="go${REQUIRED_VERSION}.linux-amd64.tar.gz"
                    wget "https://golang.org/dl/${GO_TAR}"
                    
                    # 解压安装
                    sudo tar -C /usr/local -xzf "${GO_TAR}"
                    
                    # 设置环境变量
                    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
                    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.profile
                    source ~/.bashrc
                    source ~/.profile
                    
                    # 清理
                    rm "${GO_TAR}"
                    ;;
                "centos"|"rhel"|"fedora")
                    echo "[INFO] 检测到RHEL/CentOS/Fedora系统，使用yum/dnf安装..."
                    if command -v dnf &> /dev/null; then
                        sudo dnf install -y wget tar gzip
                    else
                        sudo yum install -y wget tar gzip
                    fi
                    
                    # 下载Go
                    GO_TAR="go${REQUIRED_VERSION}.linux-amd64.tar.gz"
                    wget "https://golang.org/dl/${GO_TAR}"
                    
                    # 解压安装
                    sudo tar -C /usr/local -xzf "${GO_TAR}"
                    
                    # 设置环境变量
                    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
                    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bash_profile
                    source ~/.bashrc
                    source ~/.bash_profile
                    
                    # 清理
                    rm "${GO_TAR}"
                    ;;
                "alpine")
                    echo "[INFO] 检测到Alpine Linux系统，使用apk安装..."
                    sudo apk add --no-cache wget tar gzip
                    
                    # 下载Go
                    GO_TAR="go${REQUIRED_VERSION}.linux-amd64.tar.gz"
                    wget "https://golang.org/dl/${GO_TAR}"
                    
                    # 解压安装
                    sudo tar -C /usr/local -xzf "${GO_TAR}"
                    
                    # 设置环境变量
                    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.profile
                    source ~/.profile
                    
                    # 清理
                    rm "${GO_TAR}"
                    ;;
                *)
                    echo "[ERROR] 不支持自动安装Go的发行版: $DISTRO"
                    echo "[INFO] 请手动安装Go $REQUIRED_VERSION 或更高版本"
                    exit 1
                    ;;
            esac
        }
        
        install_go
        
        # 验证安装
        if command -v go &> /dev/null; then
            NEW_GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
            echo "[SUCCESS] Go安装成功! 当前版本: $NEW_GO_VERSION"
        else
            echo "[ERROR] Go安装失败，请手动安装"
            exit 1
        fi
    else
        echo "[SUCCESS] Go版本满足要求 ($GO_VERSION >= $REQUIRED_VERSION)"
    fi
else
    echo "[ERROR] Go未安装"
    echo "[INFO] 开始自动安装Go 1.24.5..."
    
    # 自动安装Go（安装最新稳定版本1.24.5）
    REQUIRED_VERSION="1.24.5"
    install_go
    
    # 验证安装
    if command -v go &> /dev/null; then
        NEW_GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
        echo "[SUCCESS] Go安装成功! 当前版本: $NEW_GO_VERSION"
    else
        echo "[ERROR] Go安装失败，请手动安装"
        exit 1
    fi
fi

echo ""

# 配置Go代理
echo "[INFO] 配置Go代理..."
go env -w GOPROXY=https://goproxy.cn,direct
go env -w GOSUMDB=sum.golang.google.cn
PROXY_VALUE=$(go env GOPROXY)
echo "[SUCCESS] Go代理已配置: $PROXY_VALUE"
echo ""

# 用户选择构建目标
echo "选择构建目标:"
echo "1) Client (客户端程序)"
echo "2) C2 (控制服务器)"
echo ""

while true; do
    read -p "请输入选择 (1/2): " CHOICE
    case $CHOICE in
        1)
            BUILD_TARGET="Client"
            break
            ;;
        2)
            BUILD_TARGET="C2"
            break
            ;;
        *)
            echo "无效选择，请输入 1 或 2"
            ;;
    esac
done

echo "[SUCCESS] 已选择构建目标: $BUILD_TARGET"
echo ""

# 选择构建平台
echo "选择构建平台:"
echo "1) Linux"
echo "2) Windows"
echo ""

while true; do
    read -p "请输入选择 (1/2): " CHOICE
    case $CHOICE in
        1)
            BUILD_PLATFORM="linux"
            BUILD_ARCH="amd64"
            if [[ $BUILD_TARGET == "Client" ]]; then
                OUTPUT_NAME="GYscan-linux-amd64"
            else
                OUTPUT_NAME="GYscan_C2_Linux"
                C2_DIR="C2/Linux"
            fi
            break
            ;;
        2)
            BUILD_PLATFORM="windows"
            BUILD_ARCH="amd64"
            if [[ $BUILD_TARGET == "Client" ]]; then
                OUTPUT_NAME="GYscan-Windows.exe"
            else
                OUTPUT_NAME="GYscan_C2_Windows.exe"
                C2_DIR="C2/Windows"
            fi
            break
            ;;
        *)
            echo "无效选择，请输入 1 或 2"
            ;;
    esac
done

echo "[SUCCESS] 已选择构建平台: $BUILD_PLATFORM/$BUILD_ARCH"
echo "[SUCCESS] 输出文件名: $OUTPUT_NAME"
echo ""

# 确认构建
echo "构建配置:"
echo "目标: $BUILD_TARGET"
echo "平台: $BUILD_PLATFORM/$BUILD_ARCH"
echo "输出: $OUTPUT_NAME"
echo ""

read -p "确认开始构建? (y/N): " CONFIRM
if [[ ! $CONFIRM =~ ^[Yy]$ ]]; then
    echo "[INFO] 用户取消构建"
    exit 0
fi

echo ""
echo "[INFO] 开始构建过程..."

# 执行构建
ORIGINAL_LOCATION=$(pwd)

if [[ $BUILD_TARGET == "Client" ]]; then
    cd "Client"
    echo "[INFO] 正在构建Client程序..."
    
    export GOOS=$BUILD_PLATFORM
    export GOARCH=$BUILD_ARCH
    
    go build -ldflags="-s -w" -o "../$OUTPUT_NAME"
else
    cd "$C2_DIR"
    echo "[INFO] 正在构建C2程序..."
    
    export GOOS=$BUILD_PLATFORM
    export GOARCH=$BUILD_ARCH
    
    go build -ldflags="-s -w" -o "../../$OUTPUT_NAME" ./cmd
fi

if [[ $? -eq 0 ]]; then
    echo "[SUCCESS] 构建成功!"
    echo "[SUCCESS] 输出文件: $(pwd)/$OUTPUT_NAME"
    
    # 显示文件信息
    if [[ -f $OUTPUT_NAME ]]; then
        echo ""
        echo "文件信息:"
        ls -la "$OUTPUT_NAME"
    fi
else
    echo "[ERROR] 构建失败!"
    exit 1
fi

cd "$ORIGINAL_LOCATION"

echo ""
echo "[SUCCESS] 构建完成!"