# 🛡️ FiveM Backdoor Detector & Cleaner

A **security-focused static analysis tool** for FiveM server owners to **detect, audit, and safely neutralize backdoors** hidden inside FiveM resources.

Built to identify **cipher, obfuscated, reinjecting, and remote-execution backdoors** commonly found in leaked or untrusted FiveM scripts.

---

## 🚨 Why this tool exists

Many FiveM resources (especially closed-source or leaked ones) secretly contain:
- Remote code execution loaders
- Hex / Base64 cipher backdoors
- Self-reinjecting malware
- Discord / Telegram data exfiltration
- ACE privilege escalation
- Obfuscated payloads that reappear after restart

This tool helps you **detect and prove compromise before deploying scripts to your server**.

---

## ✨ Features

### 🔍 Detection Capabilities
- Remote code execution (`load`, `loadstring`, `assert(load())`)
- `PerformHttpRequest` + dynamic execution
- HEX-encoded payloads (`\x50\x65\x72...`)
- Base64-encoded cipher payloads
- Self-reinjecting logic (`SaveResourceFile`, `io.open`, `os.execute`)
- Discord / Telegram webhook exfiltration
- ACE / principal privilege escalation
- Resource name locks
- Identifier harvesting
- High-entropy obfuscated code
- Known malware hash detection
- Lua AST (syntax tree) inspection

---

### 🧠 Safe & Smart Design
- 🟢 **SAFE MODE** – scan only, no file changes
- 🔴 **ACTIVE MODE** – neutralizes **CRITICAL** backdoors only
- 🧯 Protects framework callbacks (ox_lib, qb-core, NUI, statebags)
- 📊 Priority-based results (CRITICAL / HIGH / MEDIUM / LOW)
- 🎨 Clean, color-coded HTML audit report
- 📦 Automatic `.bak` backups when modifying files

---

## 📁 Project Structure

```text
Backdoor-Detector/
├── fivem_backdoor_scanner_ultra.py
├── scan_safe.bat
├── scan_active.bat
├── fivem_scan/          # Scripts to scan
│   ├── resource1
│   ├── resource2
│   └── ...
└── audit_report.html    # Generated after scan
