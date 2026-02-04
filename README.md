[**English**-README](README-en.md)

# GYscan - 内网横向边界安全测试工具

**本项目请大家在分享时，不管是文章、工具介绍、视频介绍都要保留本作者的仓库名字！谢谢大家配合！**

**偷梁换柱改原作者的伙伴说不定哪天你就要收到法律传票了哟~~**

## GYscan官方网站

请认准本项目的官方网站，本软件只有这么一个网站其他的全是假的！请大家注意！

[GYscan - 内网安全测试工具](https://www.gyscan.dpdns.org/)（https://www.gyscan.dpdns.org/）

## 项目简介

GYscan是一款专注于内网横向移动和边界安全测试的专业工具，基于Go语言开发。该工具集成了丰富的内网渗透测试功能，包括端口扫描、服务识别、漏洞检测、远程命令执行、弱口令爆破等核心功能，为安全研究人员和渗透测试人员提供高效、可靠的内网安全评估解决方案。

## 核心优势

- **专注内网安全**：专门针对内网横向移动和边界安全测试场景优化
- **功能丰富**：集成了端口扫描、服务识别、远程命令执行、弱口令爆破、配置审计等多种功能
- **跨平台支持**：支持Windows、Linux、macOS三大主流操作系统
- **模块化设计**：采用插件化架构，支持功能扩展和自定义模块开发
- **配置审计**：基于CIS Benchmark安全基线，支持五大类58项配置检查
- **证据追踪**：审计检查显示具体配置文件、配置项、当前值和修复建议
- **性能优异**：基于Go语言开发，具备出色的并发处理能力

### 基本信息

| 项目 | 信息 |
|------|------|
| **项目名称** | GYscan |
| **开发语言** | Go 1.24+ |
| **支持平台** | Windows 7+/Linux/macOS |
| **许可证** | Apache 2.0 |
| **最新版本** | v2.8.0 |

### v2.8.0

**Exploit-DB 集成与漏洞利用管理**

#### 新增功能

- **exp命令 - Exploit-DB漏洞利用管理模块**
  - 集成Exploit-DB数据库，包含46,928条漏洞利用和1,065条shellcode
  - 支持多种搜索方式：关键词、CVE编号、平台、漏洞类型
  - 支持精确匹配和大小写敏感搜索
  - 支持JSON和文本格式输出
  - 支持将搜索结果保存到文件

- **漏洞利用详情查看**
  - 支持通过EDB-ID查询漏洞详细信息
  - 显示漏洞描述、平台、类型、作者、发布日期、CVE等
  - 支持详细模式显示标签和别名信息

- **PoC代码管理**
  - `show`子命令：查看漏洞利用代码内容
  - `copy`子命令：复制漏洞利用代码到指定目录
  - `generate`子命令：生成带GYscan头部的PoC代码
  - 支持自定义目标参数（-t目标地址、-p端口、--ssl）

- **PoC模板生成**
  - `simple`子命令：生成简单的Python PoC模板
  - 支持快速测试和定制开发
  - 支持参数化目标地址和端口

- **Nmap NSE脚本生成**
  - `nmap`子命令：生成Nmap漏洞检测脚本
  - 可直接用于Nmap扫描
  - 支持输出到Nmap脚本目录

- **数据库管理**
  - `stats`子命令：显示数据库统计信息
  - `list`子命令：列出可用平台和漏洞类型
  - `reload`子命令：重新加载数据库
  - 支持懒加载，优化启动速度

#### 技术改进

- 数据库CSV解析优化
- 多路径查找支持（支持多种安装路径）
- 并发安全的数据库加载
- 智能文件路径匹配
- 彩色终端输出支持

#### 命令示例

```bash
# 搜索漏洞利用
./GYscan exp search "apache struts"
./GYscan exp search --cve CVE-2021-44228
./GYscan exp search --platform windows --type local

# 查看漏洞详情
./GYscan exp info 40564
./GYscan exp info 40564 -v

# 查看和复制PoC代码
./GYscan exp show 40564 > poc.py
./GYscan exp copy 40564 /tmp/exploits/

# 生成PoC
./GYscan exp generate 40564 -t 192.168.1.100 -p 8080 -o /tmp/pocs/
./GYscan exp simple 40564 -t 192.168.1.100 -o poc.py

# 生成Nmap脚本
./GYscan exp nmap 40564 -o /usr/share/nmap/scripts/

# 数据库管理
./GYscan exp stats
./GYscan exp list platforms
./GYscan exp list types
```

### v2.7.2

**IPv6支持增强**

#### 新增功能

- **IPv6扫描支持**
  - 新增 `-6, --ipv6` 标志启用IPv6扫描模式
  - 支持标准IPv6地址：`2001:db8::1`、`::1`、`fe80::1`
  - 支持IPv6地址解析和DNS查询（AAAA记录）
  - 支持IPv6主机发现（ICMPv6 Echo请求）
  - 支持IPv6端口扫描和服务识别
  - 支持IPv6链路本地地址（带zone ID）
  - 自动识别IPv4/IPv6地址并选择合适的网络连接方式

#### 技术改进

- 新增 `isIPv6()` 函数用于IPv6地址检测
- 新增 `isPrivateIPv6()` 函数支持IPv6私有地址范围（RFC 4193 ULA、RFC 3879链路本地）
- 新增 `formatIPForConnection()` 函数处理IPv6地址格式化（方括号包裹）
- 更新 `RemoveProtocolPrefix()` 正确处理IPv6地址
- 新增 `icmpv6Ping()` 和 `systemPing6()` 函数支持ICMPv6探测
- 新增 `isLinux()` 和 `isMacOS()` 辅助函数
- 更新 `hostDiscovery()` 为IPv6目标跳过ARP探测

- **WebSocket测试工具（ws命令）**
  - 支持WebSocket连接测试（ws://和wss://）
  - 支持文本和二进制消息发送（支持base64/hex编码）
  - 支持自定义HTTP头和Origin请求头
  - 支持WSS TLS证书验证跳过
  - 支持WebSocket子协议
  - 支持自动重连机制（指数退避+随机抖动）
  - 支持响应断言验证（contains/regex/json/length_greater）
  - 支持启用心跳检测（Ping/Pong）
  - 支持消息发送次数和间隔控制
  - 支持详细输出和性能监控

- **Scan模块端口扫描优化与增强**
  - **端口状态检测增强**
    - 支持完整六种端口状态：open、closed、filtered、unfiltered、open|filtered、closed|filtered
    - 新增 `PortStateOpen`、`PortStateClosed`、`PortStateFiltered`、`PortStateUnfiltered`、`PortStateOpenFiltered`、`PortStateClosedFiltered` 常量
    - 更新 `PortInfo` 结构体支持完整的端口状态字段

  - **新增隐蔽扫描类型**
    - `--sF` TCP FIN扫描：发送FIN数据包，根据RFC 793判断端口状态
    - `--sX` TCP XMAS扫描：发送FIN/URG/PSH标志位数据包
    - `--sN` TCP NULL扫描：发送不含标志位的数据包
    - `--sA` TCP ACK扫描：判断端口是否被过滤
    - `--sW` TCP窗口扫描：通过TCP窗口大小判断状态
    - `--sM` TCP Maimon扫描：发送FIN/ACK标志位数据包

  - **扫描函数增强**
    - 新增 `finScan()` 函数实现TCP FIN扫描
    - 新增 `xmasScan()` 函数实现TCP XMAS扫描
    - 新增 `nullScan()` 函数实现TCP NULL扫描
    - 新增 `ackScan()` 函数实现TCP ACK扫描
    - 新增 `windowScan()` 函数实现TCP窗口扫描
    - 新增 `maimonScan()` 函数实现TCP Maimon扫描
    - 新增 `connCloseWithoutError()` 安全连接关闭辅助函数
    - 更新 `detectUDPPortState()` 支持open|filtered状态

  - **UDP扫描准确性修复**
    - 修复 `udpConnect()` 函数bug：之前无论是否有响应都返回true
    - 修复后正确区分open（收到响应）、filtered（超时无响应）、closed（连接失败）三种状态
    - 显著提升UDP端口扫描的准确性

  - **主机发现优化**
    - 优化超时分配策略：公网主机每个探测方法使用2/3超时时间（原为1/3）
    - 简化公网探测方法：仅使用3种高效方法（tcpPing、icmpPing、tcpSynPing）
    - 降低公网确认阈值：只需1种方法确认存活（原需2种）
    - 减少TCP ping端口数量：从16个减少到5个常用端口（80, 443, 8080, 22, 53）
    - 优化重试等待时间：从100ms减少到50ms
    - 提升公网目标的主机发现成功率和速度

### v2.7.1

本次更新由 [zzqsmile] 提出，十分感谢
**SSH模块功能增强与问题修复**

#### 功能改进

- **SSH批量目标爆破优化**
  - 支持通过 `--file` 参数从文件批量读取目标IP地址
  - 优化多目标并发爆破逻辑，支持多线程同时处理多个目标
  - 新增实时进度显示，类似Hydra风格的输出格式

#### 问题修复

- 修复SSH目标文件解析问题，支持从文本文件加载多个目标
- 修复多目标模式下结果统计不正确的问题
- 修复批量爆破时实时进度不显示的问题
- 优化SSH连接算法配置，提升与不同SSH服务器的兼容性

#### SSH模块增强

- 添加 `--file` 参数支持：可以从文本文件批量加载目标IP
- 新增 `--verbose` 详细输出模式，实时显示每个尝试的认证过程
- 优化错误处理和日志输出，提升调试便利性
- 支持多目标并发爆破，大幅提升批量测试效率

### v2.7

**版本更新与配置审计功能发布**

#### 新增功能

- **pc命令** - 远程补丁探测工具，无需登录即可远程查询目标系统的中间层组件版本与补丁状态
  - 基于 WhatWeb 指纹识别技术，支持 1999+ 个 Web 指纹识别
  - 支持Web服务器: Nginx, Apache, Tomcat, IIS
  - 支持数据库: MySQL, SQL Server, Oracle, PostgreSQL
  - 支持缓存/消息: Redis, Memcached, RabbitMQ
  - 支持中间件: WebLogic, JBoss, GlassFish
  - 支持CMS系统: WordPress, Drupal, Joomla
  - 组件版本与官方漏洞库关联分析
  - 支持多种输出格式和过滤选项

- **配置审计（CA）模块** - 全新发布
  - 基于CIS Benchmark安全基线的配置合规性检查
  - 支持五大审计类别：Windows、Linux、Web、SSH、中间件
  - 共58项配置检查项
  - 支持JSON、HTML、Text三种输出格式

- **配置证据功能**
  - 显示具体配置文件路径
  - 显示配置项名称和当前值
  - 提供期望值和修复建议
  - 详细的风险说明和整改步骤

#### 命令调整

- 新增 `ca` 命令 - 配置审计工具
- 新增 `pc` 命令 - 远程补丁探测工具
- 将 mg（蜜罐识别工具）从正式命令移至测试阶段命令
- 移除 tui（启动 TUI 模式），不再考虑TUI的开发

#### 技术优化

- 增强 CheckResult 结构，支持配置证据字段
- 优化报告生成器，支持多种输出格式
- 完善 HTML 报告的样式和交互性

### v2.7-beta

**版本更新与命令调整**

- **版本升级**：GYscan从 v2.6.3 升级至 v2.7-beta
- **命令调整**：将 mg（蜜罐识别工具）从正式命令移至测试阶段命令
- **命令调整**：将 tui（启动 TUI 模式）从正式命令移至测试阶段命令，计划在后续版本中移除
- **蜜罐识别优化**：蜜罐识别工具新增 HFish 蜜罐支持
- **代码结构优化**：调整命令分类，使正式命令更加稳定可靠

### v2.6.3

**功能优化与增强**

- **文件上传漏洞检查机制优化**
  - 前端校验绕过检测
  - 后缀名绕过检测增强版
  - MIME类型绕过检测新增
  - 条件竞争检测新增

- **网站目录扫描功能优化**
  - 文件扩展名扫描支持
  - Ctrl+C中断处理优化
  - 跨平台清屏功能
  - 扫描结果整理显示

### v2.6.2

- **新增pc命令** - 远程补丁探测工具，无需登录即可远程查询目标系统的中间层组件版本与补丁状态
  - 基于 WhatWeb 指纹识别技术，支持 1999+ 个 Web 指纹识别
  - 支持Web服务器: Nginx, Apache, Tomcat, IIS
  - 支持数据库: MySQL, SQL Server, Oracle, PostgreSQL
  - 支持缓存/消息: Redis, Memcached, RabbitMQ
  - 支持中间件: WebLogic, JBoss, GlassFish
  - 支持CMS系统: WordPress, Drupal, Joomla
  - 组件版本与官方漏洞库关联分析
  - 支持多种输出格式和过滤选项

- **新增fu命令** - 文件上传漏洞检查功能，支持多种绕过技术
- **新增wwifi命令** - Windows系统WiFi破解功能

### v2.6.0

- **新增scapy模块** - 集成高级网络包操作工具
  - 原始网络包构造和发送功能
  - 网络接口检测和状态分析
  - 功能演示和示例代码

### v2.5.4

- **新增linenum功能** - Linux本地信息枚举和权限提升工具
- **新增linux-kernel功能** - Linux内核漏洞检测工具

### v2.5.2

- **新增winlog命令** - Windows日志查看工具
- 优化日志条目显示格式

### v2.5.1

- **新增waf命令** - WAF检测工具
- 优化WAF检测模块代码

### v2.5.0

- 统一命令注册机制
- 实现命令分组显示
- 完善PowerShell模块，添加HTTPS支持
- 增强WMI模块功能

### v2.0.0

- **新增csrf命令** - CSRF漏洞检测模块
- 完善XSS检测功能

### v1.0.0

- **初始发布**：基础端口扫描功能
- 服务识别和指纹采集
- 弱口令爆破框架
- 基础漏洞检测功能

## 贡献指南

欢迎提交Issue和Pull Request来改进项目。请确保：
1. 代码符合Go语言规范
2. 添加适当的测试用例
3. 更新相关文档
4. 遵循安全开发规范

## 许可证

本项目采用MIT许可证。详情请查看LICENSE文件。

## 免责声明

**重要提示**: 本工具仅供安全研究和授权测试使用。任何未授权的使用行为均属违法，使用者需承担相应的法律责任。作者不承担任何因使用本工具而产生的直接或间接责任。

---

**GYscan - 专注内网安全，守护网络边界** 🛡️
