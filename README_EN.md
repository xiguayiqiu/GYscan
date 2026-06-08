# GYscan · Integrated Penetration Testing Toolkit

<div align="center">
  <img src="app.png" alt="GYscan" width="160" />
</div>

<p align="center"><strong>Go-native integrated platform for red/blue team operations / authorized penetration testing / security research</strong></p>

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
  <a href="./README_EN.md">English</a> ·
  <a href="./README.md">简体中文</a> ·
  <a href="https://github.com/xiguayiqiu/GYscan/wiki">Documentation Wiki</a> ·
  <a href="#-changelog">Changelog</a> ·
  <a href="#-faq">FAQ</a>
</p>

---

> ⚠️ **Legal Notice**
> GYscan is an **offensive security tool** with built-in high-risk features such as vulnerability exploitation, password cracking, and remote command execution. **Only use on targets with written authorization**. All consequences of unauthorized testing are solely the responsibility of the user.

---

## ✨ What is GYscan?

GYscan is a **Go-native integrated security platform** designed for authorized penetration testing scenarios. It integrates information gathering, asset discovery, vulnerability detection, password cracking, web security, remote execution, C2 host inspection, and web management dashboard into a single toolkit.

| Category | Capabilities |
| -------- | ------------ |
| **Scenarios** | Penetration Testing · Red/Blue Team Ops · Security Ops · Incident Response · CTF |
| **Deployment** | Cross-platform CLI + System Tray + Vue 3 Web GUI + C2 Agent |
| **Coverage** | 30+ subcommands, 30+ CVE library, 1999+ web fingerprints, offline Exploit-DB |

---

## 🚀 Key Features

### 🧠 Integrated POC Detection & Exploit Verification (v3.3 New)

- **Unified Attack Entry**: `poc --exp <category> [CVE] [target]`, local/remote in one command
- **Three-Stage Workflow**: Detection → Exploit Verification → Audit Log
- **Three Attack Modes**: `detection` (safe) / `verify` (non-destructive) / `exploit` (full attack chain)
- **30+ Built-in CVEs**: Covers Linux kernel, NGINX, Fortinet, Inspektor Gadget, and more
- **Safety Constraints**: SafeMode by default, mandatory timeouts, single-request limit for remote probing, complete audit logging
- **Infrastructure**: Netlink sockets, namespace isolation, heap spray, payload/result builders

### 🔍 Information Gathering

- Port scanning / service fingerprinting / OS identification (wrapped Nmap)
- Subdomain enumeration, Whois, DNS resolution & monitoring, CDN detection
- Web fingerprints (1999+), WAF detection, SSL/TLS inspection
- Directory scanning, social engineering dictionary generation (CUPP)

### 💥 Vulnerability Exploitation

- Offline Exploit-DB search (search / info / show)
- Remote patch detection (PC: WhatWeb engine)
- Web vulnerabilities: XSS / CSRF / XXE
- Protocol vulnerabilities: SSH / FTP / database brute force
- DoS testing

### 🛡️ Host Inspection (C2 Module)

- **Linux**: trivy container scan, lynis system audit, SSH weak passwords, userinfo, kernel privilege escalation detection
- **Windows**: nuclei template scan, goss baseline check, SQL injection/privesc Recon, registry/event log/account audit

### 🌐 Web Management Dashboard

- Vue 3 + Vite built
- Embedded via `go:embed`, single-file deployment
- Dashboard · Task Management · AI Chat · System Config

### 🤖 AI Chat (Experimental)

- Built-in AI Provider abstraction layer, supports multiple LLMs
- Web-based AI chat and configuration management

### 🛠️ Engineering Capabilities

- Cross-platform compilation (Linux / Windows / macOS)
- System tray integration (systray)
- Process daemon / background service
- Multi-protocol IPC (WebSocket, HTTP API)
- One-click `update` online upgrade

---

## 📦 Quick Start

### Download Prebuilt Binaries

Go to [Releases](https://github.com/xiguayiqiu/GYscan/releases) to download the binary for your platform:

| Platform          | File                       | Size    |
| ----------------- | -------------------------- | ------- |
| Linux x86_64      | `GYscan-linux-amd64`       | ~30 MB  |
| Linux ARM64       | `GYscan-linux-arm64`       | ~30 MB  |
| Windows x64       | `GYscan-windows-amd64.exe` | ~32 MB  |
| Windows ARM64     | `GYscan-windows-arm64.exe` | ~30 MB  |

```bash
# 1. Download and set permissions
chmod +x GYscan-linux-amd64
sudo mv GYscan-linux-amd64 /usr/local/bin/gyscan

# 2. Verify installation
gyscan --version

# 3. View help
gyscan --help

# 4. Try POC exploit verification (v3.3 highlight)
gyscan poc -l                          # List all PoCs
gyscan poc -l linux-kernel             # List Linux kernel PoCs
gyscan poc -l CVE-2026-31431           # View specific CVE details
gyscan poc --cve CVE-2026-31431 -v     # Detect single vulnerability
gyscan poc --exp linux-kernel          # Exploit verify entire category
```

### Online Update

```bash
sudo gyscan update      # Automatically check and upgrade to latest version
```

---

## 📚 Feature Modules

### Main Program (30+ Subcommands)

| Module Category | Subcommands |
| --------------- | ----------- |
| **POC / Vulnerability** | `poc` · `exp` · `pc` · `kernel_vulns` · `linux-kernel` |
| **Information Gathering** | `scan` · `sub` · `dns` · `whois` · `cdn` · `waf` · `ssl` |
| **Web Security** | `web` · `fu` · `dirscan` · `xss` · `csrf` · `xxe` · `webshell` |
| **Password / Credentials** | `ssh` · `ftp` · `database` · `crunch` · `cupp` · `crack` |
| **Host Information** | `userinfo` · `process` · `registry` · `route` · `linenum` |
| **Config Audit** | `configaudit` |
| **Lateral / DoS** | `dcom` · `dos` |
| **Communication** | `ws` · `agent` · `server` · `daemon` |
| **System** | `update` · `chat` · `wwifi` · `about` |

### C2 Module

- **Linux C2**: `userinfo` / `trivy` / `ssh` / `lynis` / `getroot` / `show`
- **Windows C2**: `trivy` / `nuclei` / `goss` + `vulnscan` + `audit`

### WebGUI

Built with Vue 3 + Vite, embedded in the main binary:

```bash
cd WebGUI
npm install
npm run dev        # http://localhost:5173
npm run build      # Output auto-embedded to Client/internal/web/static/
```

---

## 🎯 v3.3 Highlight: POC Attack Detection Framework

v3.3 introduces an **integrated "detection + exploit verification" framework**, evolving from "fingerprint only" to a three-stage workflow of "detection → exploit verification → audit log".

### Unified Attack Entry

```bash
# 1) Local exploit verify entire linux-kernel category
gyscan poc --exp linux-kernel

# 2) Exploit verify single CVE only
gyscan poc --exp linux-kernel CVE-2023-32233

# 3) Remote exploit verify nginx vulnerability
gyscan poc --exp nginx CVE-2026-27944 192.168.1.10:9000
gyscan poc --exp nginx CVE-2026-42945 target.com

# 4) With audit logging
gyscan poc --exp linux-kernel --attack-log ./audit.log -v
```

### Built-in CVE Library (v3.3)

#### 🐧 Linux Kernel (25 CVEs)

- **Netfilter**: CVE-2023-32233, CVE-2026-23111, CVE-2026-23231
- **Scheduler**: CVE-2026-22976 (QFQ NULL Deref)
- **SMB/CIFS**: CVE-2026-23220, CVE-2026-23228, CVE-2026-23230, CVE-2026-46243
- **Filesystem**: CVE-2026-23238, CVE-2026-31431 (Copy Fail, local privilege escalation)
- **Security Modules**: CVE-2026-23268, CVE-2026-23269, CVE-2026-46333
- **Network Subsystem**: CVE-2025-21756 (VSock UAF), CVE-2026-43284, CVE-2026-43494, CVE-2026-46300 (**Fragnesia**)
- **Device Drivers**: CVE-2026-23026 ~ CVE-2026-23037 (6 CVEs)
- **Crypto/Other**: CVE-2026-23222, CVE-2026-23236

#### 🌐 Nginx Remote Vulnerabilities (3 CVEs)

- CVE-2026-27944 (nginx-ui Backup API leak)
- CVE-2026-33032 (nginx-ui MCP unauthorized)
- CVE-2026-42945 (**NGINX Rewrite heap buffer overflow, CVSS 9.8**)

#### 🔧 General Vulnerabilities (2 CVEs)

- CVE-2024-23113 (Fortinet Format String, CVSS 9.8)
- CVE-2026-31890 (Inspektor Gadget Ring Buffer DoS)

### Safety Constraints

- ✅ **SafeMode Default**: All attacks non-destructive by default
- ✅ **Timeout Protection**: All operations constrained by `--attack-timeout`
- ✅ **Audit Log**: Full operation stream via `--attack-log`
- ✅ **Remote Probe Hard Limit**: 1 request per target, max 3 redirects
- ✅ **Sensitive Operations Explicit**: `exploit` mode requires explicit flag

> ⚠️ Full CVE list and detection logic are internal implementation details. View locally with `./gyscan poc -l`.

---

## 🏗️ Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                         GYscan Platform                     │
├─────────────────────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐    │
│  │  CLI Client   │  │   Web GUI    │  │   C2 Agent       │    │
│  │  (Cobra)     │  │  (Vue 3)     │  │  Linux / Windows │    │
│  └──────┬───────┘  └──────┬───────┘  └────────┬─────────┘    │
│         │                 │                   │              │
│  ┌──────┴─────────────────┴───────────────────┴──────────┐   │
│  │              Core Capability Engine                    │   │
│  │  · POC Detection / Exploit Framework  · Info Gathering Engine │   │
│  │  · Exploit Framework (Exploit-DB)      · Host Inspection Engine │   │
│  │  · Attack Infrastructure (Netlink/NS)   · Protocol Handling Engine │   │
│  └──────┬────────────────────────────────────────────────┘   │
│         │                                                     │
│  ┌──────┴───────┐  ┌──────────────┐  ┌──────────────────┐    │
│  │  Offline Exploit DB │  │  Fingerprint DB │  │  Dictionary DB  │    │
│  │  Exploit-DB     │  │  WhatWeb 1999+│  │  CUPP / Crunch    │    │
│  └──────────────┘  └──────────────┘  └──────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

---

## ❓ FAQ

<details>
<summary><b>Q: What is GYscan's open source license?</b></summary>

GYscan uses the **Apache License 2.0**:
- ✅ Core code fully open source under Apache 2.0
- ✅ Free use, modification, and distribution for commercial and non-commercial purposes
- ✅ WebGUI frontend, Exploit-DB index, all fully open source

Users can freely view, modify, and redistribute all components, just keep copyright notice and license text.
</details>

<details>
<summary><b>Q: Why can't I find certain packages when compiling?</b></summary>

Some packages in the Client submodule point to private modules via `replace` directives. For full build, go to [Releases](https://github.com/xiguayiqiu/GYscan/releases) to download prebuilt binaries.
</details>

<details>
<summary><b>Q: Is v3.3 attack mode safe? Will it damage targets?</b></summary>

Default `detection` mode is **completely safe**, only condition checks, no execution. `verify` mode is non-destructive verification. `exploit` mode only runs full attack chain with explicit `--attack-mode exploit` flag.
</details>

<details>
<summary><b>Q: How to contribute CVE PoCs?</b></summary>

1. Fork this repo
2. Add new `cve_xxx_xxxxx.go` under `Client/internal/poc/<category>/`
3. Implement `Detector` interface (recommend also implementing `AttackDetector`)
4. Submit PR with PoC verification screenshots
</details>

<details>
<summary><b>Q: Are custom POCs supported?</b></summary>

Yes. GYscan uses a plugin-based Registry pattern. Just implement the `Detector` interface and register in `init()` to be auto-loaded.
</details>

---

## 🤝 Contributing

We welcome community contributions, but for **security and quality**, only accept the following:

| Accepted | Description |
| -------- | ----------- |
| 🐛 Bug Reports | Submit via [Issues](https://github.com/xiguayiqiu/GYscan/issues) |
| 📖 Documentation | Fix typos, add examples, translations |
| 🎨 WebGUI Improvements | Vue 3 frontend improvements |
| 💡 Feature Ideas | Start via Discussions |
| 🔌 Tools | Tool scripts under `GYscan-tools/` |

| Not Accepted | Reason |
| ------------ | ------ |
| Core Engine PRs | Binary releases |
| New Attack PoCs | Reviewed and integrated by official security team |

### Code of Conduct

- ✅ Only test on authorized targets
- ✅ Respect privacy and data security
- ✅ Include detailed reproduction steps with Issues
- ❌ No discussion of WAF/AV bypass methods
- ❌ No sharing unredacted exploit code

---

## 🌟 Star History

<div align="center">

[![Star History Chart](https://api.star-history.com/svg?repos=xiguayiqiu/GYscan&type=Date)](https://star-history.com/#xiguayiqiu/GYscan&Date)

</div>

---

## 📞 Contact

| Channel | Link |
| ------- | ---- |
| Bilibili | [弈秋啊](https://space.bilibili.com/) |
| Tencent Channel | 弈秋忘忧白帽: `yiqiuasec0` |
| GitHub | [xiguayiqiu/GYscan](https://github.com/xiguayiqiu/GYscan) |
| Gitee | [bzhanyiqiua/GYscan](https://gitee.com/bzhanyiqiua/GYscan) |
| Documentation Wiki | https://github.com/xiguayiqiu/GYscan/wiki |

---

## 📄 License & Copyright

© 2024-2026 BiliBili-弈秋啊 · All Rights Reserved

This project is licensed under the [Apache License 2.0](LICENSE).

**License Terms**:
- ✅ Free to download, study, modify, use for legal authorized testing
- ✅ Commercial and non-commercial use allowed
- ⚠️ Must retain copyright notice and license text

**Disclaimer**:
The project author is not liable for any legal responsibility resulting from unauthorized use.

> ⚠️ **Important Notice**: GYscan is an offensive security tool, only use on targets with written authorization. All consequences of unauthorized testing are solely the responsibility of the user.

---

<div align="center">

**If GYscan helped you, please ⭐ Star to support!**

Made with ❤️ by [BiliBili-弈秋啊](https://space.bilibili.com/)

</div>