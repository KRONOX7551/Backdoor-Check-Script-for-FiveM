# 🛡️ FiveM Backdoor Detector & Cleaner

> **Repository description (short):**  
> Static security scanner for FiveM scripts. Detects cipher, obfuscated, reinjecting, and remote-execution backdoors using pattern analysis, entropy checks, AST inspection, and priority-based reporting with safe cleanup options.

---

## 🚨 Why this tool exists

Many FiveM resources (especially leaked, paid, or closed-source scripts) secretly contain:
- Remote code execution backdoors
- Hex / Base64 cipher loaders
- Self-reinjecting malware
- Discord / Telegram data exfiltration
- ACE privilege escalation
- Obfuscated payloads that reappear after restart

This tool allows you to **audit scripts locally before deployment** and **prove compromise safely** without running the scripts.

---

## ✨ Features

### 🔍 Detection Capabilities
- Remote code execution (`load`, `loadstring`, `assert(load())`)
- `PerformHttpRequest` + dynamic execution
- HEX-encoded payloads (`\x50\x65\x72...`)
- Base64-encoded cipher payloads
- Self-reinjecting logic (`SaveResourceFile`, `LoadResourceFile`, `io.open`, `os.execute`)
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
- 🔴 **ACTIVE MODE** – neutralizes **CRITICAL backdoors only**
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

##🧰 Requirements

Python 3.9+
Windows / Linux / macOS
FiveM scripts (.lua, .cfg)
Python Dependencies
--pip install luaparser requests

##Installation
Clone or download this repository
Install Python and dependencies
Edit the scan path inside fivem_backdoor_scanner_ultra.py:
SCAN_PATH = r"C:\path\to\your\fivem_scan"
Copy FiveM scripts you want to scan into that folder

##▶️ Usage
🟢 SAFE MODE (Recommended)
Scans scripts without modifying anything
scan_safe.bat
or manually:
--python fivem_backdoor_scanner_ultra.py --safe
✔ No file changes
✔ Generates audit_report.html

##🔴 ACTIVE MODE (Advanced)
Neutralizes CRITICAL backdoor lines only
scan_active.bat
⚠️ Creates .bak backups
⚠️ Never run directly on a live server
⚠️ Always review SAFE MODE results first

##📊 Audit Report
The generated HTML report includes:
Priority-sorted results
Color-coded severity
File path & line number
Code snippet preview
Priority Levels
Priority	Meaning
🔴 CRITICAL	Almost certainly malicious – remove resource
🟠 HIGH	Very suspicious – manual review required
🟡 MEDIUM	Possibly obfuscated – context needed
🔵 LOW	Informational / common framework usage
🧹 Cleaning Rules (IMPORTANT)

⚠️ If a resource contains encrypted loaders or self-reinjection logic — DELETE IT.

This tool is designed to prove compromise, not magically clean malware.
Never trust scripts that:
Execute remote code dynamically
Write or rewrite Lua files
Contain encrypted payload loaders

##🛑 Limitations
❌ Cannot decrypt encrypted scripts
❌ Does not execute code
❌ Cannot guarantee 100% detection
❌ Does not replace manual review

##🧠 Recommended Workflow
Scan scripts locally (SAFE MODE)
Review audit_report.html
Remove malicious resources entirely
Optionally run ACTIVE MODE
Move clean scripts to your server
Restart server

##👤 Author
KRONOX
Security-focused FiveM server owner

##⚖️ Disclaimer

This tool performs static analysis only.
Use at your own risk.
Always keep backups and manually verify results.
