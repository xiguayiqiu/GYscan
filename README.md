# GYscan · 综合渗透测试工具集

<div align="center">
  <img src="app.png" alt="GYscan" width="160" />
</div>

<p align="center"><strong>面向红蓝对抗 / 授权渗透 / 安全研究的 Go 原生一体化平台</strong></p>

<p align="center">
  <img src="https://img.shields.io/badge/version-v3.3-blue.svg?style=flat-square" alt="Version">
  <img src="https://img.shields.io/badge/Go-1.25%2B-00ADD8?style=flat-square&logo=go&logoColor=white" alt="Go">
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey?style=flat-square" alt="Platforms">
  <img src="https://img.shields.io/badge/license-Apache%202.0-blue.svg?style=flat-square" alt="License">
  <img src="https://img.shields.io/badge/CVE%20Library-30%2B-red.svg?style=flat-square" alt="CVE">
  <img src="https://img.shields.io/badge/modules-30%2B%20subcommands-brightgreen.svg?style=flat-square" alt="Modules">
  <img src="https://img.shields.io/badge/maintained-yes-success.svg?style=flat-square" alt="Maintained">
</p>

<p align="center">
  <a href="README_EN.md">English</a> ·
  <a href="README.md">简体中文</a> ·
  <a href="https://github.com/xiguayiqiu/GYscan/wiki">文档 Wiki</a> ·
  <a href="#-更新日志">更新日志</a> ·
  <a href="#-faq">FAQ</a>
</p>

---

> ⚠️ **法律声明**
> GYscan 是**攻击性安全工具**，内置漏洞利用、密码爆破、远程命令执行等高危功能，**仅允许在已获书面授权的目标上使用**。任何未授权测试产生的一切后果由使用者自行承担。

---

## ✨ GYscan 是什么？

GYscan 是一套面向授权渗透测试场景的 **Go 原生一体化安全平台**，将信息收集、资产探测、漏洞检测、密码爆破、Web 安全、远程执行、C2 主机巡检、Web 管理后台等多种能力整合到同一工具集中。

🚀 **开源承诺**：我们致力于打造一个完全开源的安全研究平台。目前部分核心功能正在持续打磨和优化中，完整源码将在适当时机全部开放。在此期间，我会持续更新预编译版本，并开放已成熟的模块，欢迎社区监督和参与！
>现在不公开源码的原因是：存在恶意攻击使用者，为了保护用户的安全和隐私，我们先不公开完整源码。等我确认平台的稳定性和安全性后，我会公开发布完整源码。

| 维度      | 能力                                              |
| ------- | ----------------------------------------------- |
| **场景**  | 渗透测试 · 红蓝对抗 · 安全运维 · 应急响应 · CTF                 |
| **部署**  | 跨平台 CLI + 系统托盘 + Vue 3 Web GUI + C2 Agent       |
| **覆盖**  | 30+ 子命令、30+ CVE 漏洞库、1999+ Web 指纹、Exploit-DB 离线库 |

---

## 🚀 核心特性

### 🧠 POC 检测 + 攻击验证一体化（v3.3 全新升级）

- **统一攻击入口**：`poc --exp <分类> [CVE] [目标]`，本地/远程一条命令搞定
- **三阶段工作流**：检测 → 攻击验证 → 审计日志
- **三大攻击模式**：`detection`（安全）/ `verify`（非破坏性验证）/ `exploit`（完整攻击链）
- **30+ 内置 CVE**：覆盖 Linux 内核、NGINX、Fortinet、Inspektor Gadget 等
- **安全约束**：默认 SafeMode、强制超时、远程探测单请求上限、完整审计日志
- **基础设施**：Netlink 套接字、命名空间隔离、堆喷、攻击载荷/结果构建器

### 🔍 信息收集

- 端口扫描 / 服务指纹 / 操作系统识别（封装 Nmap）
- 子域名枚举、Whois、DNS 解析与监听、CDN 识别
- Web 指纹（1999+）、WAF 识别、SSL/TLS 检测
- 目录扫描、社工字典生成（CUPP）

### 💥 漏洞利用

- 离线 Exploit-DB 检索（search / info / show）
- 远程补丁探测（PC：WhatWeb 引擎）
- Web 漏洞：XSS / CSRF / XXE
- 协议漏洞：SSH / FTP / 数据库爆破
- DoS 测试

### 🛡️ 主机巡检（C2 模块）

- **Linux**：trivy 容器扫描、lynis 系统审计、SSH 弱口令、userinfo、内核提权检测
- **Windows**：nuclei 模板扫描、goss 基线检查、SQL 注入/提权 Recon、注册表/事件日志/账号审计

### 🌐 Web 管理后台

- Vue 3 + Vite 构建
- 通过 `go:embed` 嵌入到二进制，单文件部署
- Dashboard · 任务管理 · AI Chat · 系统配置

### 🤖 AI Chat（实验性）

- 内置 AI Provider 抽象层，支持多家 LLM
- Web 端 AI 对话与配置管理

### 🛠️ 工程化能力

- 跨平台编译（Linux / Windows / macOS）
- 系统托盘集成（systray）
- 进程守护 / 后台服务
- 多协议 IPC（WebSocket、HTTP API）
- 一键 `update` 在线升级

---

## 📦 快速开始

### 下载预编译版本

前往 [Releases](https://github.com/xiguayiqiu/GYscan/releases) 下载对应平台的二进制：

| 平台              | 文件                         | 大小     |
| --------------- | -------------------------- | ------ |
| Linux x86_64    | `GYscan-linux-amd64`       | ~30 MB |
| Linux ARM64     | `GYscan-linux-arm64`       | ~30 MB |
| Windows x64     | `GYscan-windows-amd64.exe` | ~32 MB |
| Windows ARM64   | `GYscan-windows-arm64.exe` | ~30 MB |

```bash
# 1. 下载并赋权
chmod +x GYscan-linux-amd64
sudo mv GYscan-linux-amd64 /usr/local/bin/gyscan

# 2. 验证安装
gyscan --version

# 3. 查看帮助
gyscan --help

# 4. 体验 POC 攻击验证（v3.3 重磅）
gyscan poc -l                          # 列出所有 PoC
gyscan poc -l linux-kernel             # 列出 Linux 内核 PoC
gyscan poc -l CVE-2026-31431           # 查看某个 CVE 详情
gyscan poc --cve CVE-2026-31431 -v     # 检测单个漏洞
gyscan poc --exp linux-kernel          # 攻击验证整分类
```

### 在线更新

```bash
sudo gyscan update      # 自动检查并升级到最新版本
```

---

## 📚 功能模块

### 主程序（30+ 子命令）

| 模块类别 | 子命令 |
|---|---|
| **POC / 漏洞** | `poc` · `exp` · `pc` · `kernel_vulns` · `linux-kernel` |
| **信息收集** | `scan` · `sub` · `dns` · `whois` · `cdn` · `waf` · `ssl` |
| **Web 安全** | `web` · `fu` · `dirscan` · `xss` · `csrf` · `xxe` · `webshell` |
| **密码 / 凭据** | `ssh` · `ftp` · `database` · `crunch` · `cupp` · `crack` |
| **主机信息** | `userinfo` · `process` · `registry` · `route` · `linenum` |
| **配置审计** | `configaudit` |
| **横向 / DoS** | `dcom` · `dos` |
| **通信** | `ws` · `agent` · `server` · `daemon` |
| **系统** | `update` · `chat` · `wwifi` · `about` |

### C2 模块

- **Linux C2**：`userinfo` / `trivy` / `ssh` / `lynis` / `getroot` / `show`
- **Windows C2**：`trivy` / `nuclei` / `goss` + `vulnscan` + `audit`

### WebGUI

Vue 3 + Vite 构建，嵌入到主程序二进制：

```bash
cd WebGUI
npm install
npm run dev        # http://localhost:5173
npm run build      # 产物自动嵌入到 Client/internal/web/static/
```

---

## 🎯 v3.3 重点：POC 攻击检测框架

v3.3 引入了**「检测 + 攻击验证」一体化框架**，从「只做指纹探测」进化为「检测 → 攻击验证 → 审计日志」三阶段工作流。

### 统一攻击入口

```bash
# 1) 本地攻击验证整个 linux-kernel 分类
gyscan poc --exp linux-kernel

# 2) 仅攻击验证某一个 CVE
gyscan poc --exp linux-kernel CVE-2023-32233

# 3) 远程攻击验证 nginx 漏洞
gyscan poc --exp nginx CVE-2026-27944 192.168.1.10:9000
gyscan poc --exp nginx CVE-2026-42945 target.com

# 4) 配合审计日志
gyscan poc --exp linux-kernel --attack-log ./audit.log -v
```

### 内置 CVE 库（v3.3）

#### 🐧 Linux 内核（25 个 CVE）

- **Netfilter**：CVE-2023-32233、CVE-2026-23111、CVE-2026-23231
- **调度器**：CVE-2026-22976（QFQ NULL Deref）
- **SMB/CIFS**：CVE-2026-23220、CVE-2026-23228、CVE-2026-23230、CVE-2026-46243
- **文件系统**：CVE-2026-23238、CVE-2026-31431（Copy Fail，本地提权）
- **安全模块**：CVE-2026-23268、CVE-2026-23269、CVE-2026-46333
- **网络子系统**：CVE-2025-21756（VSock UAF）、CVE-2026-43284、CVE-2026-43494、CVE-2026-46300（**Fragnesia**）
- **设备驱动**：CVE-2026-23026 ~ CVE-2026-23037（6 个）
- **加密/其他**：CVE-2026-23222、CVE-2026-23236

#### 🌐 Nginx 远程漏洞（3 个）

- CVE-2026-27944（nginx-ui Backup API 泄露）
- CVE-2026-33032（nginx-ui MCP 未授权）
- CVE-2026-42945（**NGINX Rewrite 堆缓冲区溢出，CVSS 9.8**）

#### 🔧 通用漏洞（2 个）

- CVE-2024-23113（Fortinet Format String，CVSS 9.8）
- CVE-2026-31890（Inspektor Gadget Ring Buffer DoS）

### 安全约束

- ✅ **SafeMode 默认开启**：所有攻击默认为非破坏性
- ✅ **超时保护**：所有操作受 `--attack-timeout` 约束
- ✅ **审计日志**：通过 `--attack-log` 输出完整操作流水
- ✅ **远程探测硬性约束**：每个目标仅 1 次请求，3 次重定向上限
- ✅ **敏感操作显式开启**：`exploit` 模式需明确指定

> ⚠️ 完整 CVE 列表与检测原理属于内部实现细节，请通过 `./gyscan poc -l` 在本地查看。

---

## 🏗️ 架构总览

```
┌─────────────────────────────────────────────────────────────┐
│                         GYscan Platform                     │
├─────────────────────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐    │
│  │  CLI 客户端   │  │   Web GUI    │  │   C2 Agent       │    │
│  │  (Cobra)     │  │  (Vue 3)     │  │  Linux / Windows │    │
│  └──────┬───────┘  └──────┬───────┘  └────────┬─────────┘    │
│         │                 │                   │              │
│  ┌──────┴─────────────────┴───────────────────┴──────────┐   │
│  │              核心能力引擎 (Core Engine)                 │   │
│  │  · POC 检测 / 攻击验证框架     · 信息收集引擎          │   │
│  │  · 漏洞利用框架 (Exploit-DB)   · 主机巡检引擎         │   │
│  │  · 攻击基础设施 (Netlink/NS)   · 协议处理引擎         │   │
│  └──────┬────────────────────────────────────────────────┘   │
│         │                                                     │
│  ┌──────┴───────┐  ┌──────────────┐  ┌──────────────────┐    │
│  │ 离线漏洞库     │  │  指纹库       │  │  字典库           │    │
│  │ Exploit-DB   │  │ WhatWeb 1999+│  │ CUPP / Crunch    │    │
│  └──────────────┘  └──────────────┘  └──────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

---

## ❓ FAQ

<details>
<summary><b>Q: GYscan 的开源许可证是什么？</b></summary>

GYscan 采用 **Apache License 2.0** 开源协议：
- ✅ 我们承诺将项目完全开源，目前正在分阶段开放代码
- ✅ WebGUI 前端、Exploit-DB 索引等模块已完全开放
- ✅ 核心检测引擎等模块正在持续打磨优化中，将在成熟后全面开放
- ✅ 允许商业和非商业用途的自由使用、修改和分发

在此期间，欢迎使用我们提供的预编译版本，并通过 Issues 和 Discussions 参与社区讨论，共同见证项目的成长！

（注：完整源码开放时间将另行公告，敬请期待 🌟）
</details>

<details>
<summary><b>Q: 编译时为什么找不到某些包？</b></summary>

Client 子模块的部分包通过 `replace` 指令指向私有 module。如需完整构建，请前往 [Releases](https://github.com/xiguayiqiu/GYscan/releases) 下载预编译版本。
</details>

<details>
<summary><b>Q: v3.3 攻击模式安全吗？会不会破坏目标？</b></summary>

默认 `detection` 模式**完全安全**，仅做条件检测不执行攻击。`verify` 模式为非破坏性验证。`exploit` 模式才会执行完整攻击链，且需显式指定 `--attack-mode exploit`。
</details>

<details>
<summary><b>Q: 如何贡献 CVE PoC？</b></summary>

1. Fork 本仓库
2. 在 `Client/internal/poc/<分类>/` 下添加新的 `cve_xxx_xxxxx.go`
3. 实现 `Detector` 接口（建议同时实现 `AttackDetector`）
4. 提交 PR 并附 PoC 验证截图
</details>

<details>
<summary><b>Q: 是否支持自定义 POC？</b></summary>

支持。GYscan 使用插件化 Registry 模式，只需实现 `Detector` 接口并在 `init()` 中注册即可被自动加载。
</details>

---

## 🤝 贡献指南

我们欢迎并重视社区贡献！虽然部分核心代码正在完善中，但你可以通过以下方式参与：

| 接受 | 说明 |
| --- | --- |
| 🐛 Bug 报告 | 通过 [Issues](https://github.com/xiguayiqiu/GYscan/issues) 提交 |
| 📖 文档改进 | 修正错别字、补充示例、翻译 |
| 🎨 WebGUI 优化 | Vue 3 前端改进 |
| 💡 功能建议 | 通过 Discussions 发起 |
| 🔌 周边工具 | `GYscan-tools/` 下的工具脚本 |

| 暂不接受 | 原因 |
| --- | --- |
| 核心引擎 PR | 正在内部重构优化，完成后开放 |
| 新增攻击 PoC | 由官方安全团队审核后纳入 |

### 行为准则

- ✅ 仅在授权目标上测试
- ✅ 尊重隐私与数据安全
- ✅ 提交 Issue 时附详细复现步骤
- ❌ 禁止讨论绕过 WAF / 杀软的方法
- ❌ 禁止分享未脱敏的漏洞利用代码

💪 **参与开源建设**：我们的目标是打造一个高质量的开源安全工具。如果你对项目有任何想法或建议，欢迎通过 Discussions 与我们交流，共同推动 GYscan 成为更好的开源项目！

---

## 🌟 Star History

<div align="center">

[![Star History Chart](https://api.star-history.com/svg?repos=xiguayiqiu/GYscan&type=Date)](https://star-history.com/#xiguayiqiu/GYscan&Date)

</div>

---

## 📞 联系方式

| 渠道 | 链接 |
|---|---|
| B 站 | [弈秋啊](https://space.bilibili.com/) |
| 腾讯频道 | 弈秋忘忧白帽：`yiqiuasec0` |
| GitHub | [xiguayiqiu/GYscan](https://github.com/xiguayiqiu/GYscan) |
| Gitee | [bzhanyiqiua/GYscan](https://gitee.com/bzhanyiqiua/GYscan) |
| 文档 Wiki | https://github.com/xiguayiqiu/GYscan/wiki |

---

## 📄 许可与版权

© 2024-2026 BiliBili-弈秋啊 · All Rights Reserved

本项目采用 [Apache License 2.0](LICENSE) 许可协议。

**使用许可**：
- ✅ 允许下载、学习、修改、用于合法授权测试
- ✅ 可用于商业或非商业用途
- ⚠️ 必须保留版权声明和许可证文本

**免责声明**：
本项目作者不对任何因未授权使用造成的法律责任负责。

> ⚠️ **重要提醒**：GYscan 是攻击性安全工具，仅允许在已获书面授权的目标上使用。任何未授权测试产生的一切后果由使用者自行承担。

---

<div align="center">

**如果 GYscan 对你有帮助，欢迎 ⭐ Star 支持！**

Made with ❤️ by [BiliBili-弈秋啊](https://space.bilibili.com/)

</div>
