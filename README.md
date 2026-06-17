<div align="center">

```
╔═══════════════════════════════════════════════════════════════╗
║  ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗   ║
║  ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║   ║
║  ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║   ║
║  ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║   ║
║  ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗║
║  ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝║
║              S H I E L D  —  Threat Detection CLI               ║
╚═══════════════════════════════════════════════════════════════╝
```

# 🛡️ Sentinel Shield

**An advanced, multi-layered malware & ransomware scanner for the command line.**

Built for sysadmins, incident responders, and security-minded developers who want a fast, scriptable, **offline-friendly** scanner they can read, audit, and extend.

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-brightgreen.svg)](https://www.python.org/)
[![Platform: Linux | macOS | Windows](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-lightgrey)](#-installation)
[![Status: Active](https://img.shields.io/badge/status-active-success.svg)](#)

[Features](#-features) · [Installation](#-installation) · [Usage](#-usage) · [Detection Methodology](#-detection-methodology) · [Architecture](#-architecture) · [Contributing](#-contributing) · [License](#-license)


</div>

---

## Features

- **Multi-layered detection** — 6 independent stages: hash matching, static signatures, entropy analysis, PE deep inspection, regex pattern matching, and a correlation engine that suppresses false positives.
- **Ransomware-focused** — recognizes 100+ ransomware-family extensions (LockBit, Hive, BlackCat, Ryuk, Conti, REvil, WannaCry, Petya, Dharma, …) and ransomware-specific crypto-API usage patterns.
- **Zero network dependency** — runs fully offline. No phone-home, no cloud calls. Use it on air-gapped systems without modification.
- **Parallel scanning** — configurable thread pool (`--workers`), chunked streaming reads, and an upper bound on file count/bytes so `sentinel scan /` can't take down a host.
- **PE deep analysis** — Windows `EXE`/`DLL` inspection without executing the file: import table lookups, TLS-callback detection, suspicious entry-point section checks.
- **Anti-false-positive design** — single-occurrence unigrams stay `LOW`; promotion to `MEDIUM`/`HIGH` requires either multiple category hits or a single hit in a high-impact category (RANSOMWARE, DESTRUCTIVE, INJECTION).
- **Beautiful TUI** — Rich-powered tables, progress bars, risk badges, and a final verdict panel. Exports structured JSON for SIEM ingestion.
- **Pluggable threat feed** — drop in a JSON file of `sha256 → label` and Sentinel Shield merges it into the built-in DB at startup.
- **Safe by default** — symlink cycles are detected and pruned; FIFO/devices/sockets are skipped; broken paths warn instead of crash.

---

## Installation

### From source (recommended for auditability)

```bash
git clone https://github.com/your-username/sentinel-shield.git
cd sentinel-shield
pip install -r requirements.txt
chmod +x malware_scaner.py
ln -s "$(pwd)/malware_scaner.py" /usr/local/bin/sentinel   # optional
```

### Requirements

- **Python 3.8+**
- `rich >= 13.0` (TUI)
- `pefile >= 2023.0.0` (Windows PE deep analysis — optional, scanner warns if missing)

A `requirements.txt` is provided:

```text
rich>=13.0
pefile>=2023.0.0
```

### Verify

```bash
sentinel --help
```

If you see the banner and command list, you're good to go.

---

## Usage

### Scan a directory

```bash
sentinel scan ./suspicious_folder
```

### Recursive scan with JSON report

```bash
sentinel scan /var/www --recursive -o report.json
```

### Verbose single-file inspection

```bash
sentinel info ./downloads/file.exe
```

### Hash lookup only

```bash
sentinel hash 44d88612fea8a8f36de82e1278abb02f  # EICAR test
```

### Common flags

| Flag | Description | Default |
|---|---|---|
| `-r, --recursive` | Recurse into subdirectories | `on` |
| `--no-recursive` | Disable recursion | — |
| `-v, --verbose` | Show detail for every file (including clean) | `off` |
| `-a, --all` | Show every file in summary | `off` |
| `--no-pe` | Skip PE deep analysis (no `pefile` needed) | PE on |
| `-o, --output FILE` | Save JSON report | none |
| `--max-size MB` | Skip files larger than N MB | `50` |
| `--max-total-files N` | Hard cap on file count per scan | `200000` |
| `--max-total-bytes BYTES` | Hard cap on total bytes queued | `5 GB` |
| `--follow-symlinks` | Follow symlinks (off by default — cycles possible) | `off` |
| `--workers N` | Thread-pool size | `4` |

### Sample output

```
  ╔════════════════════════════════════════════════════════════╗
  ║  ● CRITICAL   locky_dropper.bin                           ║
  ╠════════════════════════════════════════════════════════════╣
    Path:     /tmp/locky_dropper.bin
    Type:     Windows Executable (PE/EXE/DLL)
    Size:     128.0 KB
    SHA256:   ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e…
    Entropy:  ████████████████████░░░░ 7.94
  ┌─────────────────┬──────────────────┬──────────────────────┐
  │ Severity        │ Category         │ Description          │
  ├─────────────────┼──────────────────┼──────────────────────┤
  │ ● CRITICAL      │ 💀 RANSOMWARE    │ Known ransomware ext │
  │ ▲ HIGH          │ 💉 INJECTION     │ WriteProcessMemory   │
  └─────────────────┴──────────────────┴──────────────────────┘
```

---

## Detection Methodology

Sentinel Shield runs every file through **six independent detection stages**, then a **correlation engine** decides the final severity. Each stage is intentionally cheap and stateless so it can run against millions of files.

### Stage 1 — Identity Layer (Hash Matching)

- Compute **SHA-256** (primary) and **MD5** (legacy) via streaming 64KB reads.
- Compare against a built-in DB of known-bad hashes (initialized with the EICAR test signature).
- Optional JSON threat feed via `SENTINEL_THREAT_FEED=/path/to/feed.json` — entries are validated (lowercase hex, length 64) and merged at startup. Malformed entries are skipped with a warning rather than crashing the scanner.
- **Any hit → `KNOWN_MALWARE / CRITICAL`.** This is the strongest signal; nothing overrides it.

> 🔒 **Why SHA-256 only as the threat-DB key?** MD5 collisions are cheap to construct and the DB is small, so MD5 is more attack surface than signal. MD5 is still computed for downstream consumers but is not used for matching.

### Stage 2 — Static Signature Layer (Extension + Magic Bytes)

- **Extension check** against a curated list of **100+ ransomware-family extensions** (`lockbit`, `hive`, `blackcat`, `alphv`, `ryuk`, `conti`, `revil`, `sodinokibi`, `maze`, `phobos`, `dharma`, `darkside`, …).
- **Magic-byte detection** for PE (`MZ`), ELF (`\x7fELF`), Mach-O (32/64), Java class, PDF, ZIP, RAR, MSI, scripts.
- `EXE`/`DLL`/`PS1`/`VBS`/etc. get a `LOW / SUSPICIOUS_TYPE` tag because legitimate use exists.

### Stage 3 — Entropy Analysis (Shannon)

Entropy over the first 64KB is a strong signal of encryption or packing:

| Range | Interpretation | Severity |
|---|---|---|
| `H < 6.0` | Normal text / structured binary | clean |
| `6.0 ≤ H < 7.2` | Possible compression | clean |
| `7.2 ≤ H < 7.8` | Likely packed / obfuscated | `MEDIUM / OBFUSCATION` |
| `H ≥ 7.8` | Almost certainly encrypted | `HIGH / ENCRYPTION` |

Files smaller than 10KB are skipped to avoid noise (small files naturally have high entropy).

### Stage 4 — PE Deep Analysis (Windows EXE / DLL)

Powered by [`pefile`](https://github.com/erocarrera/pefile) (optional dependency — scanner degrades gracefully):

- **Import table lookups** against a curated list of ~15 suspicious APIs: `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`, `CryptEncrypt`, `CryptGenKey`, `AdjustTokenPrivileges`, `SetWindowsHookEx`, `keybd_event`, `BitBlt`, `GetClipboardData`, etc.
- **TLS callbacks** → anti-analysis technique → `MEDIUM / EVASION`.
- **Entry-point section** check — if `AddressOfEntryPoint` lives in a writable + executable section that's not `.text`/`.code`, it's flagged `HIGH / INJECTION` (classic process-hollowing / reflective-injection pattern).

Malformed PE files are common in the wild; failures are swallowed silently and the rest of the scan continues.

### Stage 5 — Pattern Matching (50+ Regex Rules)

All rules are **pre-compiled once at module load** — recompiling inside the scan loop is 2–5× slower on pattern-heavy files.

Categories covered:

| Category | Examples of what it catches |
|---|---|
| `RANSOMWARE` | Ransom-note keywords, crypto API references, family names |
| `BACKDOOR` | Reverse shell, meterpreter, Cobalt Strike, `nc -lvp` |
| `OBFUSCATION` | `eval()`, `exec()`, PowerShell `-EncodedCommand`, gzip/bz2 in code |
| `PRIVILEGE_ESC` | `SeDebugPrivilege`, UAC bypass, `sudo -s` |
| `EXFILTRATION` | `smtplib`, FTP upload, clipboard, `BitBlt` screen capture |
| `PERSISTENCE` | HKLM Run keys, `schtasks`, cron, systemd enable, startup folder |
| `DESTRUCTIVE` | `rm -rf /`, `format C:`, `dd if=/dev/zero`, `DeviceIoControl` |
| `INJECTION` | `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread` |
| `NETWORK` | Hardcoded IP:port, `requests.get`, `socket.connect` |
| `CREDENTIAL` | Mimikatz, `Invoke-Mimikatz`, LSASS access |

### Stage 6 — Correlation & Severity Engine

This is what keeps the false-positive rate low. For each file:

1. **Per-category hit counter** — how many distinct pattern categories matched.
2. **Severe-category bypass** — `RANSOMWARE`, `DESTRUCTIVE`, `KNOWN_MALWARE`, and `INJECTION` keep their high severity even on a single hit. These categories are rare in clean code.
3. **Multi-signal promotion** — if **≥ 2 distinct categories** match in the same file, single hits get promoted from `LOW` → `MEDIUM`.
4. **High-impact single hits** — `BACKDOOR`, `PRIVILEGE_ESC`, `CREDENTIAL`, `PERSISTENCE`, `EXFILTRATION` on a single hit go straight to `HIGH` (these patterns are rare in legitimate code).
5. **Deduplication** — if the same description surfaces from multiple stages (e.g. extension + pattern), it appears once in the report.

### Risk verdict

The final risk level is the max severity seen, mapped to:

`CLEAN` → `LOW` → `MEDIUM` → `HIGH` → `CRITICAL`

---

## Architecture

```
 ┌──────────────────────────────────────────────────────────┐
 │                    INPUT LAYER                           │
 │  file discovery  ·  safety caps  ·  stream chunks       │
 └────────────────────────┬─────────────────────────────────┘
                          ▼
 ┌──────────────────────────────────────────────────────────┐
 │  ① Identity         → SHA-256/MD5 → Threat DB lookup     │
 │  ② Static sigs      → ext + magic bytes                  │
 │  ③ Entropy          → Shannon H over 64KB sample         │
 │  ④ PE deep          → imports + TLS + entry-point sec    │
 │  ⑤ Pattern match    → 50+ pre-compiled regex rules       │
 │  ⑥ Correlation      → anti-FP severity engine           │
 └────────────────────────┬─────────────────────────────────┘
                          ▼
   CLEAN  ◉ LOW  ◆ MEDIUM  ▲ HIGH  ● CRITICAL  (exit + JSON)
```

---

## Configuration

### Threat feed

```bash
export SENTINEL_THREAT_FEED=/etc/sentinel/threats.json
sentinel scan /var/www
```

`threats.json` format:

```json
{
  "44d88612fea8a8f36de82e1278abb02f": "EICAR Test Signature",
  "abcdef0123456789...": "Custom internal IOC"
}
```

Malformed entries (wrong length, non-hex characters, non-string keys) are skipped with a warning — never crash the scan.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Clean — no threats detected |
| `1` | Threats detected |
| `130` | Interrupted by user (`Ctrl+C`) |

---

---

## Testing

Sentinel Shield ships with an [EICAR](https://www.eicar.org/?page_id=3950) test signature in its built-in DB:

```bash
# Generate the EICAR test file (NOT malware — it's a standard test string)
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > eicar.com
sentinel info eicar.com
# Expected: ● CRITICAL · ☠ KNOWN_MALWARE · EICAR Test Signature
```

> EICAR is a harmless file used universally to verify AV products. It is not malware. Detection of EICAR is the canonical smoke test.

---

## Contributing

PRs welcome. Please:

1. **Open an issue first** for non-trivial changes (new detection stages, severity-model tweaks) — let's align on approach before code.
2. **Add a test** for any new detection rule. A small synthetic file that should trigger your rule is enough.
3. **Keep false-positive suppression in mind.** New rules should default to `LOW` and rely on the correlation engine for promotion, unless the category is independently severe.
4. **Don't add network calls.** Sentinel Shield runs offline by design.

See [`CONTRIBUTING.md`](./CONTRIBUTING.md) for the full guide.

---

## License

Sentinel Shield is released under the **GNU General Public License v3.0**.

You are free to use, modify, and redistribute it under the terms of the GPLv3. See [`LICENSE`](./LICENSE) for the full text.

```
Sentinel Shield — Copyright (C) 2024
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License.
```

---

## ⚠️ Disclaimer

Sentinel Shield is a heuristic scanner. It is **not a replacement** for a maintained commercial antivirus or enterprise EDR. It is a **supplementary** layer, a triage tool, and a learning project. False positives and false negatives are possible. Do not rely on it as your only line of defense.

If you suspect your system has been compromised by ransomware, disconnect it from the network immediately and contact a professional incident-response team.

---

<div align="center">

Built with 🛡️ for defenders, by defenders.

</div>