import os, re, sys, math, hashlib, shutil
from collections import Counter
from datetime import datetime

# ================= USER CONFIG ================= #

SCAN_PATH = r"C:\Users\KRONOX\Downloads\Backdoor Detector\fivem_scan"

# ============================================== #

try:
    from luaparser import ast
except ImportError:
    ast = None

SAFE_MODE = "--safe" in sys.argv
ENTROPY_THRESHOLD = 4.5
REPORT_FILE = "audit_report.html"
BACKUP_SUFFIX = ".bak"

# ================= SAFETY ================= #

SAFE_CALLBACK_KEYWORDS = [
    "RegisterNetEvent",
    "AddEventHandler",
    "RegisterNUICallback",
    "AddStateBagChangeHandler",
    "lib.callback",
    "lib.onCache",
    "exports(",
    "CreateThread",
    "Citizen.CreateThread",
]

# ================= PRIORITY ================= #

PRIORITY_MAP = {
    "Known Malware Hash": "CRITICAL",
    "Remote Code Execution": "CRITICAL",
    "AST Dynamic Execution": "CRITICAL",
    "ACE Privilege Injection": "CRITICAL",
    "Hex-Encoded Payload": "CRITICAL",
    "Self-Reinjecting Backdoor": "CRITICAL",

    "Webhook / Exfiltration": "HIGH",
    "Dynamic Code Execution": "HIGH",
    "Base64 Encoded Payload": "HIGH",

    "High Entropy / Obfuscation": "MEDIUM",
    "Resource Name Lock": "MEDIUM",

    "Identifier Harvesting": "LOW",
}

PRIORITY_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3
}

# ================= MALWARE DATA ================= #

KNOWN_MALWARE_HASHES = {
    "d4735e3a265e16eee03f59718b9b5d03a3f9a47c5d5f7c7d06a2b6a94b7c9d33": "Known HTTP loader backdoor",
}

KNOWN_SNIPPETS = [
    "load(PerformHttpRequest",
    "assert(load(",
    "Citizen.SetTimeout(600000",
    "ExecuteCommand('add_ace'",
]

# ================= REGEX ================= #

HEX_PATTERN = re.compile(r"(\\x[0-9a-fA-F]{2}){6,}")
BASE64_PATTERN = re.compile(r"^[A-Za-z0-9+/]{30,}={0,2}$")

PATTERNS = {
    "Remote Code Execution": [
        r"PerformHttpRequest\s*\(.*load",
        r"PerformHttpRequest\s*\(.*assert",
    ],
    "Dynamic Code Execution": [
        r"\bload\s*\(",
        r"\bloadstring\s*\(",
        r"assert\s*\(\s*load",
    ],
    "ACE Privilege Injection": [
        r"add_ace",
        r"add_principal",
        r"remove_ace",
        r"remove_principal",
    ],
    "Server CFG Manipulation": [
        r"server\.cfg",
        r"ExecuteCommand\s*\(",
    ],
    "Webhook / Exfiltration": [
        r"https://discord(app)?\.com/api/webhooks",
        r"https://api\.telegram\.org",
        r"pastebin\.com",
        r"hastebin",
    ],
    "Identifier Harvesting": [
        r"GetPlayerIdentifiers",
        r"GetPlayerEndpoint",
        r"GetConvar",
    ],
    "Resource Name Lock": [
        r"GetCurrentResourceName\s*\(",
    ],
    "Self-Reinjecting Backdoor": [
        r"SaveResourceFile\s*\(",
        r"LoadResourceFile\s*\(",
        r"io\.open\s*\(",
        r"os\.execute\s*\(",
    ],
}

# ================= UTILS ================= #

def entropy(s):
    if not s:
        return 0
    c = Counter(s)
    l = len(s)
    return -sum((v/l) * math.log2(v/l) for v in c.values())

def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        h.update(f.read())
    return h.hexdigest()

def make_finding(path, line, category, detail, code):
    return {
        "file": path,
        "line": line,
        "category": category,
        "priority": PRIORITY_MAP.get(category, "LOW"),
        "detail": detail,
        "code": code
    }

# ================= SCANNERS ================= #

def scan_lua_ast(path, findings):
    if not ast:
        return
    try:
        tree = ast.parse(open(path, "r", errors="ignore").read())
        for node in ast.walk(tree):
            if hasattr(node, "func") and hasattr(node.func, "id"):
                if node.func.id in ("load", "loadstring"):
                    findings.append(
                        make_finding(path, getattr(node, "lineno", 0),
                                     "AST Dynamic Execution",
                                     "Dynamic execution via AST",
                                     node.func.id)
                    )
    except Exception:
        pass

def scan_file(path):
    findings = []
    lines = open(path, "r", errors="ignore").readlines()

    file_hash = sha256(path)
    if file_hash in KNOWN_MALWARE_HASHES:
        findings.append(
            make_finding(path, 0, "Known Malware Hash",
                         KNOWN_MALWARE_HASHES[file_hash],
                         "FILE HASH MATCH")
        )

    for i, line in enumerate(lines, 1):
        s = line.strip()

        for category, patterns in PATTERNS.items():
            for p in patterns:
                if re.search(p, s):
                    findings.append(
                        make_finding(path, i, category, "Pattern match", s[:150])
                    )

        if any(sn in s for sn in KNOWN_SNIPPETS):
            findings.append(
                make_finding(path, i, "Known Malware Snippet", "Snippet match", s[:150])
            )

        if HEX_PATTERN.search(s):
            findings.append(
                make_finding(path, i, "Hex-Encoded Payload", "Hex encoded payload", s[:150])
            )

        cleaned = s.replace('"', '').replace("'", "")
        if BASE64_PATTERN.match(cleaned):
            findings.append(
                make_finding(path, i, "Base64 Encoded Payload", "Possible encoded payload", s[:150])
            )

        if (
            len(s) > 40
            and entropy(s) > ENTROPY_THRESHOLD
            and "RegisterNUICallback" not in s
        ):
            findings.append(
                make_finding(path, i, "High Entropy / Obfuscation",
                             f"Entropy={entropy(s):.2f}", s[:150])
            )

    scan_lua_ast(path, findings)
    return findings

# ================= NEUTRALIZER ================= #

def neutralize(path, findings):
    if SAFE_MODE:
        return

    backup = path + BACKUP_SUFFIX
    if not os.path.exists(backup):
        shutil.copy2(path, backup)

    lines = open(path, "r", errors="ignore").readlines()

    for f in findings:
        if f["priority"] != "CRITICAL":
            continue
        if f["line"] <= 0:
            continue

        idx = f["line"] - 1
        line = lines[idx]

        if any(k in line for k in SAFE_CALLBACK_KEYWORDS):
            continue

        if not line.lstrip().startswith("--"):
            lines[idx] = "-- [NEUTRALIZED] " + line

    open(path, "w").writelines(lines)

# ================= REPORT ================= #

def report(findings):
    findings.sort(key=lambda x: PRIORITY_ORDER.get(x["priority"], 3))

    rows = ""
    colors = {
        "CRITICAL": "#ff4d4d",
        "HIGH": "#ff9f43",
        "MEDIUM": "#feca57",
        "LOW": "#54a0ff",
    }

    for f in findings:
        rows += f"""
        <tr style="border-left:6px solid {colors[f['priority']]}">
            <td>{f['priority']}</td>
            <td>{f['category']}</td>
            <td>{f['file']}</td>
            <td>{f['line']}</td>
            <td><code>{f['code']}</code></td>
        </tr>
        """

    html = f"""
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>FiveM Backdoor Audit</title>
<style>
body {{ background:#0f172a;color:#e5e7eb;font-family:Segoe UI;padding:20px }}
table {{ width:100%;border-collapse:collapse }}
th,td {{ padding:8px;border-bottom:1px solid #1e293b }}
th {{ background:#020617 }}
code {{ color:#22c55e }}
</style>
</head>
<body>
<h1>FiveM Security Audit Report</h1>
<p>Generated: {datetime.now()}</p>
<p>Mode: {"SAFE" if SAFE_MODE else "ACTIVE"}</p>
<table>
<tr><th>Priority</th><th>Category</th><th>File</th><th>Line</th><th>Code</th></tr>
{rows}
</table>
</body>
</html>
"""
    open(REPORT_FILE, "w", encoding="utf-8").write(html)

# ================= MAIN ================= #

def main():
    if not os.path.exists(SCAN_PATH):
        print(f"❌ Scan path does not exist: {SCAN_PATH}")
        return

    print(f"🔍 Scanning: {SCAN_PATH}")
    findings = []

    for r, _, files in os.walk(SCAN_PATH):
        for f in files:
            if f.endswith(".lua") or f.endswith(".cfg"):
                path = os.path.join(r, f)
                res = scan_file(path)
                if res:
                    findings.extend(res)
                    neutralize(path, res)

    report(findings)
    print(f"📊 Findings: {len(findings)}")
    print(f"📄 Report: {REPORT_FILE}")

if __name__ == "__main__":
    main()
