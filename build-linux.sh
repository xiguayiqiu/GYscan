#!/bin/bash

# GYscan Linux构建脚本 - 支持多发行版
echo "=================================================="
echo "           GYscan Linux构建脚本"
echo "          支持Debian/RedHat/Arch/OpenSUSE"
echo "                版本 2.0"
echo "=================================================="
echo ""

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 日志函数
log_info() {
    echo -e "${BLUE}[信息]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[警告]${NC} $1"
}

log_error() {
    echo -e "${RED}[错误]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[成功]${NC} $1"
}

# 检测系统环境
log_info "检测系统环境..."
OS="Linux"

if [ -f /etc/os-release ]; then
    . /etc/os-release
    DISTRO=$ID
    DISTRO_NAME=$NAME
    DISTRO_VERSION=$VERSION_ID
else
    DISTRO="unknown"
    DISTRO_NAME="Unknown Linux"
    DISTRO_VERSION="unknown"
fi

log_info "操作系统: $OS"
log_info "发行版: $DISTRO_NAME ($DISTRO $DISTRO_VERSION)"
echo ""

# 检查Go环境
log_info "检查Go环境..."
if ! command -v go &> /dev/null; then
    log_error "Go未安装，请安装Go 1.21.0或更高版本"
    exit 1
fi

GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
log_info "当前Go版本: $GO_VERSION"

# 检查Go版本
REQUIRED_VERSION="1.21.0"
if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$GO_VERSION" | sort -V | head -n1)" = "$REQUIRED_VERSION" ]; then
    log_success "Go版本符合要求 ($GO_VERSION >= $REQUIRED_VERSION)"
else
    log_error "Go版本过低，需要 $REQUIRED_VERSION 或更高版本"
    exit 1
fi

# 检查GCC环境
log_info "检查GCC环境..."
if ! command -v gcc &> /dev/null; then
    log_warn "GCC未安装，GUI功能将无法编译"
else
    GCC_VERSION=$(gcc --version | head -n1)
    log_info "GCC版本: $GCC_VERSION"
fi

# 定义不同发行版的依赖包
DEBIAN_PACKAGES=(
    "libx11-dev"        # X11开发库
    "libxcursor-dev"    # X光标支持
    "libxrandr-dev"     # X随机数扩展
    "libxinerama-dev"   # X多显示器支持
    "libxi-dev"         # X输入扩展
    "libxxf86vm-dev"    # XFree86视频模式扩展（解决libXxf86vm错误）
    "libgl1-mesa-dev"   # OpenGL Mesa库
    "libglu1-mesa-dev"  # GLU工具库
    "mesa-common-dev"   # Mesa通用开发文件
    "build-essential"   # 构建基础工具
    "pkg-config"        # 包配置工具
    "dbus-x11"          # D-Bus工具（解决dbus-launch错误）
    "libdbus-1-dev"     # D-Bus开发库
    "libpcap-dev"       # libpcap开发库（网络包捕获）
)

REDHAT_PACKAGES=(
    "libX11-devel"
    "libXcursor-devel"
    "libXrandr-devel"
    "libXinerama-devel"
    "libXi-devel"
    "libXxf86vm-devel"  # 解决libXxf86vm错误
    "mesa-libGL-devel"
    "mesa-libGLU-devel"
    "mesa-libGLw-devel"
    "gcc-c++"
    "pkgconfig"
    "dbus-x11"          # D-Bus工具（解决dbus-launch错误）
    "dbus-devel"        # D-Bus开发库
    "libpcap-devel"     # libpcap开发库（网络包捕获）
)

ARCH_PACKAGES=(
    "libx11"
    "libxcursor"
    "libxrandr"
    "libxinerama"
    "libxi"
    "libxxf86vm"        # 解决libXxf86vm错误
    "mesa"
    "glu"
    "base-devel"
    "pkg-config"
    "dbus"               # D-Bus工具（解决dbus-launch错误）
    "dbus-glib"          # D-Bus GLib绑定
    "libpcap"            # libpcap开发库（网络包捕获）
)

OPENSUSE_PACKAGES=(
    "libX11-devel"
    "libXcursor-devel"
    "libXrandr-devel"
    "libXinerama-devel"
    "libXi-devel"
    "libXxf86vm-devel"
    "Mesa-libGL-devel"
    "Mesa-libGLU-devel"
    "Mesa-dri-devel"
    "gcc-c++"
    "pkg-config"
    "dbus-1-x11"        
    "dbus-1-devel"        
    "libpcap-devel"     
)

# 检查依赖包函数
check_dependencies() {
    log_info "检查系统依赖包..."
    
    case $DISTRO in
        "ubuntu"|"debian"|"parrot")
            for pkg in "${DEBIAN_PACKAGES[@]}"; do
                if ! dpkg -l | grep -q "^ii.*$pkg"; then
                    log_warn "缺少包: $pkg"
                    # 对于Parrot Security，检查是否有替代包
                    if [ "$DISTRO" = "parrot" ]; then
                        case "$pkg" in
                            "libxxf86vm-dev")
                                log_info "检查替代包: libxxf86vm1"
                                if dpkg -l | grep -q "^ii.*libxxf86vm1"; then
                                    log_success "找到替代包 libxxf86vm1"
                                    continue
                                fi
                                ;;
                            "libdrm-dev")
                                log_info "检查libdrm相关替代包"
                                if dpkg -l | grep -q "^ii.*libdrm2" && \
                                   dpkg -l | grep -q "^ii.*libdrm-intel1" && \
                                   dpkg -l | grep -q "^ii.*libdrm-radeon1" && \
                                   dpkg -l | grep -q "^ii.*libdrm-nouveau2" && \
                                   dpkg -l | grep -q "^ii.*libdrm-amdgpu1"; then
                                    log_success "找到libdrm替代包组"
                                    continue
                                fi
                                ;;
                            "dbus-x11")
                                log_info "检查D-Bus相关包"
                                if dpkg -l | grep -q "^ii.*dbus" && \
                                   dpkg -l | grep -q "^ii.*dbus-user-session"; then
                                    log_success "找到D-Bus替代包组"
                                    continue
                                fi
                                ;;
                        esac
                    fi
                    return 1
                fi
            done
            ;;
        "centos"|"rhel"|"fedora")
            for pkg in "${REDHAT_PACKAGES[@]}"; do
                if ! rpm -q "$pkg" &> /dev/null; then
                    log_warn "缺少包: $pkg"
                    return 1
                fi
            done
            ;;
        "arch"|"manjaro")
            for pkg in "${ARCH_PACKAGES[@]}"; do
                if ! pacman -Q "$pkg" &> /dev/null; then
                    log_warn "缺少包: $pkg"
                    return 1
                fi
            done
            ;;
        "opensuse"|"suse")
            for pkg in "${OPENSUSE_PACKAGES[@]}"; do
                if ! rpm -q "$pkg" &> /dev/null; then
                    log_warn "缺少包: $pkg"
                    return 1
                fi
            done
            ;;
        *)
            log_warn "未知发行版，无法自动检查依赖"
            return 1
            ;;
    esac
    
    return 0
}

# 安装依赖包函数
install_dependencies() {
    log_info "安装缺失的依赖包..."
    
    case $DISTRO in
        "ubuntu"|"debian"|"parrot")
            sudo apt update
            # 对于Parrot Security，使用高级安装策略
            if [ "$DISTRO" = "parrot" ]; then
                log_info "检测到Parrot Security系统，使用高级安装策略"
                
                # 创建临时包列表，排除有冲突的包
                TEMP_PACKAGES=()
                for pkg in "${DEBIAN_PACKAGES[@]}"; do
                    # 跳过已知有冲突的包
                    if [[ "$pkg" == "libdrm-dev" ]]; then
                        log_warn "跳过已知冲突包: $pkg"
                        continue
                    fi
                    # 对于mesa-common-dev，检查是否已经有更新的版本
                    if [[ "$pkg" == "mesa-common-dev" ]]; then
                        log_info "检查mesa-common-dev是否已安装或可跳过"
                        if dpkg -l | grep -q "^ii.*mesa-common-dev"; then
                            log_success "mesa-common-dev已安装，跳过"
                            continue
                        fi
                    fi
                    TEMP_PACKAGES+=("$pkg")
                done
                
                # 先尝试安装无冲突的包
                log_info "安装无冲突的依赖包..."
                if sudo apt install -y "${TEMP_PACKAGES[@]}"; then
                    log_success "无冲突包安装成功"
                else
                    log_warn "部分包安装失败，尝试逐个安装"
                    for pkg in "${TEMP_PACKAGES[@]}"; do
                        log_info "尝试安装包: $pkg"
                        if sudo apt install -y "$pkg"; then
                            log_success "包 $pkg 安装成功"
                        else
                            log_warn "包 $pkg 安装失败，跳过"
                        fi
                    done
                fi
                
                # 尝试安装libdrm-dev的替代方案
                log_info "尝试安装libdrm相关替代包..."
                sudo apt install -y libdrm2 libdrm-intel1 libdrm-radeon1 libdrm-nouveau2 libdrm-amdgpu1 || log_warn "libdrm替代包安装失败"
                
            else
                sudo apt install -y "${DEBIAN_PACKAGES[@]}"
            fi
            ;;
        "centos"|"rhel")
            sudo yum install -y "${REDHAT_PACKAGES[@]}"
            ;;
        "fedora")
            sudo dnf install -y "${REDHAT_PACKAGES[@]}"
            ;;
        "arch"|"manjaro")
            sudo pacman -Sy --noconfirm "${ARCH_PACKAGES[@]}"
            ;;
        "opensuse"|"suse")
            sudo zypper refresh
            sudo zypper install -y "${OPENSUSE_PACKAGES[@]}"
            ;;
        *)
            log_error "不支持自动安装依赖的发行版"
            echo ""
            echo "请手动安装以下依赖包:"
            echo "- libX11 development files"
            echo "- libXcursor development files"
            echo "- libXrandr development files"
            echo "- libXinerama development files"
            echo "- libXi development files"
            echo "- libXxf86vm development files"
            echo "- Mesa OpenGL development files"
            echo "- GCC compiler"
            echo "- pkg-config tool"
            return 1
            ;;
    esac
    
    if [ $? -eq 0 ]; then
        log_success "依赖包安装完成"
        return 0
    else
        log_error "依赖包安装失败"
        return 1
    fi
}

# 检查并安装依赖
if ! check_dependencies; then
    echo ""
    log_warn "检测到缺少必要的依赖包"
    echo ""
    
    read -p "是否自动安装缺失的依赖包? (y/N): " -n 1 -r
    echo ""
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        if ! install_dependencies; then
            log_error "依赖安装失败，构建无法继续"
            exit 1
        fi
    else
        log_warn "用户选择不安装依赖，GUI功能可能无法编译"
        echo ""
        echo "如需手动安装，请参考以下命令:"
        case $DISTRO in
            "ubuntu"|"debian"|"parrot")
                echo "sudo apt install ${DEBIAN_PACKAGES[*]}"
                ;;
            "centos"|"rhel")
                echo "sudo yum install ${REDHAT_PACKAGES[*]}"
                ;;
            "fedora")
                echo "sudo dnf install ${REDHAT_PACKAGES[*]}"
                ;;
            "arch"|"manjaro")
                echo "sudo pacman -S ${ARCH_PACKAGES[*]}"
                ;;
            "opensuse"|"suse")
                echo "sudo zypper install ${OPENSUSE_PACKAGES[*]}"
                ;;
        esac
        echo ""
    fi
else
    log_success "所有依赖包已安装"
fi

# 进入Client目录并构建
echo ""
log_info "开始构建项目..."
cd Client

# 清理之前的构建
log_info "清理构建缓存..."
go clean -cache

# 设置七牛云代理加速Go依赖下载
log_info "设置七牛云代理加速Go依赖下载..."
go env -w GOPROXY=https://goproxy.cn,direct
# go env -w GOSUMDB=sum.golang.google.cn

# 下载依赖
log_info "下载Go依赖..."
go mod download

# 设置构建参数
BUILD_FLAGS="-ldflags"
LD_FLAGS="-s -w"
OUTPUT_NAME="GYscan-linux"

# 检测架构
ARCH=$(uname -m)
case $ARCH in
    "x86_64")
        OUTPUT_NAME="${OUTPUT_NAME}-amd64"
        ;;
    "aarch64")
        OUTPUT_NAME="${OUTPUT_NAME}-arm64"
        ;;
    "armv7l")
        OUTPUT_NAME="${OUTPUT_NAME}-armv7"
        ;;
    *)
        OUTPUT_NAME="${OUTPUT_NAME}-$ARCH"
        ;;
esac

# 构建项目
log_info "编译项目 (架构: $ARCH)..."
if go build $BUILD_FLAGS "$LD_FLAGS" -o "../$OUTPUT_NAME" .; then
    echo ""
    log_success "构建完成!"
    log_info "可执行文件: ../$OUTPUT_NAME"
    
    # 显示文件信息
    if [ -f "../$OUTPUT_NAME" ]; then
        echo ""
        echo "文件信息:"
        ls -lh "../$OUTPUT_NAME" | awk '{print "大小: " $5 ", 权限: " $1 ", 修改时间: " $6 " " $7 " " $8}'
    fi
else
    echo ""
    log_error "构建失败"
    
    # 提供调试信息
    echo ""
    log_info "调试信息:"
    echo "- Go版本: $(go version)"
    echo "- GCC版本: $(gcc --version | head -n1)"
    echo "- 系统架构: $ARCH"
    echo "- 发行版: $DISTRO $DISTRO_VERSION"
    
    exit 1
fi

# 返回原始目录
cd ..

echo ""
echo "=================================================="
echo "                构建完成"
echo "=================================================="
