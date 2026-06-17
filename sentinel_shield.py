#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║          SENTINEL SHIELD — Malware & Ransomware Scanner       ║
║                   Advanced Threat Detection CLI               ║
╚══════════════════════════════════════════════════════════════╝
"""

import os
import sys
import math
import hashlib
import struct
import re
import time
import json
import argparse
import datetime
import threading
from pathlib import Path
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass, field
from collections import defaultdict

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import (
    Progress, SpinnerColumn, BarColumn, TextColumn,
    TimeElapsedColumn, MofNCompleteColumn, TaskProgressColumn
)
from rich.text import Text
from rich.align import Align
from rich.columns import Columns
from rich.rule import Rule
from rich.tree import Tree
from rich.live import Live
from rich.layout import Layout
from rich import box
from rich.style import Style
from rich.markup import escape


console = Console()

# ─────────────────────────────────────────────
#  THREAT INTELLIGENCE DATABASE
# ─────────────────────────────────────────────

RANSOMWARE_EXTENSIONS = {
    ".locky", ".zepto", ".odin", ".aesir", ".thor", ".zzzzz",
    ".cerber", ".cerber2", ".cerber3", ".crypt", ".crypz", ".cry",
    ".cryptowall", ".encrypted", ".enc", ".locked", ".crypto",
    ".crypted", ".crinf", ".r5a", ".xrtn", ".xtbl", ".crypt12",
    ".breaking_bad", ".evil", ".herbst", ".1999", ".vault",
    ".petya", ".notpetya", ".wncry", ".wcry", ".wncrypt",
    ".wannacry", ".wncryt", ".ecc", ".exx", ".ezz", ".exy",
    ".abc", ".aaa", ".zzz", ".xyz", ".micro", ".cryptolocker",
    ".sage", ".globe", ".dharma", ".wallet", ".onion", ".matrix",
    ".phobos", ".makop", ".stop", ".djvu", ".pay2key", ".crysis",
    ".adobe", ".java", ".btc", ".bora", ".karla", ".harma",
    ".gamma", ".bip", ".combo", ".alco", ".java", ".725",
    ".id-{", ".club", ".mosk", ".nols", ".gero", ".boot",
    ".kuub", ".karl", ".CRAB", ".KRAB", ".locked", ".deadbolt",
    ".lockbit", ".lockbit2", ".hive", ".ryuk", ".conti", ".avos",
    ".maze", ".netwalker", ".revil", ".sodinokibi", ".clop",
    ".mespinoza", ".babuk", ".darkside", ".blackcat", ".alphv",
    ".blackmatter", ".egregor", ".doppelpaymer", ".grief", ".pay",
    ".wasted", ".exela", ".render", ".cuba", ".yanluowang",
}

DANGEROUS_EXTENSIONS = {
    ".exe", ".dll", ".bat", ".cmd", ".com", ".scr", ".pif",
    ".vbs", ".vbe", ".js", ".jse", ".ws", ".wsf", ".wsc",
    ".wsh", ".ps1", ".ps2", ".psc1", ".psc2", ".msi", ".msp",
    ".mst", ".reg", ".inf", ".lnk", ".hta", ".cpl", ".msc",
    ".jar", ".jnlp", ".appref-ms", ".application", ".gadget",
    ".xbap", ".xnk", ".ade", ".adp", ".bas", ".chm", ".crt",
    ".fxp", ".hlp", ".isp", ".its", ".mad", ".maf", ".mag",
    ".maq", ".mar", ".mas", ".mat", ".mau", ".mav", ".maw",
    ".mda", ".mdb", ".mde", ".mdt", ".mdw", ".mdz", ".msh",
    ".msh1", ".msh2", ".mshxml", ".msh1xml", ".msh2xml",
    ".mhtml", ".ops", ".pcd", ".prg", ".sct", ".shb", ".shs",
    ".url", ".vxd", ".xsl", ".py", ".rb", ".sh", ".bash",
    ".zsh", ".fish", ".elf", ".so", ".ko", ".dylib",
}

MAGIC_BYTES: Dict[str, Tuple[bytes, str]] = {
    "PE_EXE":     (b"MZ",                          "Windows Executable (PE/EXE/DLL)"),
    "ELF":        (b"\x7fELF",                     "Linux ELF Executable"),
    "MACH_O_32":  (b"\xfe\xed\xfa\xce",            "macOS Mach-O 32-bit"),
    "MACH_O_64":  (b"\xfe\xed\xfa\xcf",            "macOS Mach-O 64-bit"),
    "CLASS":      (b"\xca\xfe\xba\xbe",            "Java Class File"),
    "PDF":        (b"%PDF",                         "PDF Document"),
    "ZIP":        (b"PK\x03\x04",                  "ZIP Archive"),
    "RAR":        (b"Rar!\x1a\x07",                "RAR Archive"),
    "CAB":        (b"MSCF",                        "Cabinet Archive"),
    "MSI":        (b"\xd0\xcf\x11\xe0",            "OLE Compound (MSI/DOC/XLS)"),
    "POWERSHELL": (b"\xff\xfe",                    "UTF-16 Script (possible PowerShell)"),
    "PYTHON_PYC": (b"\x16\r\r\n",                  "Python Bytecode"),
    "SH_SCRIPT":  (b"#!/",                         "Shell Script"),
}

SUSPICIOUS_PATTERNS: List[Tuple[bytes, str, str]] = [
    # Ransomware indicators
    (rb"(?i)your\s+files\s+(have\s+been|are)\s+(encrypted|locked)", "RANSOMWARE", "Ransom note message detected"),
    (rb"(?i)bitcoin\s*address", "RANSOMWARE", "Bitcoin address solicitation"),
    (rb"(?i)tor\s*browser", "RANSOMWARE", "Tor payment reference"),
    (rb"(?i)\.onion", "RANSOMWARE", "Dark web .onion address"),
    (rb"(?i)decrypt(ion)?\s*tool", "RANSOMWARE", "Decryption tool reference"),
    (rb"(?i)ransom", "RANSOMWARE", "Explicit ransom keyword"),
    (rb"(?i)cryptolocker|wannacry|wannacrypt|petya|notpetya|locky|cerber|sodinokibi|revil|ryuk|conti|lockbit|hive|blackcat|alphv", "RANSOMWARE", "Known ransomware family name"),
    (rb"CryptEncrypt|CryptDecrypt|CryptImportKey|CryptGenKey", "RANSOMWARE", "Windows crypto API usage"),
    (rb"(?i)AES_encrypt|RSA_encrypt|chacha20|salsa20", "RANSOMWARE", "Encryption algorithm reference"),

    # Remote access / backdoor
    (rb"(?i)reverse\s+shell", "BACKDOOR", "Reverse shell code"),
    (rb"(?i)bind\s+shell", "BACKDOOR", "Bind shell code"),
    (rb"(?i)nc\s+-[elnvp]+\s+\d+", "BACKDOOR", "Netcat listener/reverse shell"),
    (rb"(?i)(meterpreter|metasploit|empire\s+payload|cobalt\s*strike)", "BACKDOOR", "Known C2 framework reference"),
    (rb"(?i)rootkit|keylogger|botnet|c2\s+server|command.and.control", "BACKDOOR", "Malware infrastructure keyword"),

    # Code obfuscation / evasion
    (rb"(?i)base64[_\s]*decode", "OBFUSCATION", "Base64 decode (payload delivery)"),
    (rb"(?i)fromcharcode|charCodeAt", "OBFUSCATION", "Character code obfuscation"),
    (rb"(?i)eval\s*\(", "OBFUSCATION", "Dynamic code evaluation (eval)"),
    (rb"(?i)exec\s*\(", "OBFUSCATION", "Dynamic code execution (exec)"),
    (rb"(?i)powershell.*-[Ee]nc", "OBFUSCATION", "PowerShell encoded command"),
    (rb"(?i)powershell.*-[Ww]indow[Ss]tyle\s+[Hh]idden", "OBFUSCATION", "Hidden PowerShell window"),
    (rb"(?i)iex\s*\(|invoke-expression", "OBFUSCATION", "PowerShell Invoke-Expression"),
    (rb"(?i)invoke-mimikatz|mimikatz", "CREDENTIAL", "Mimikatz credential dumper"),
    (rb"(?i)gzip.decompress|zlib.decompress", "OBFUSCATION", "Compressed payload in code"),

    # Privilege escalation
    (rb"(?i)seDebugPrivilege|AdjustTokenPrivileges", "PRIVILEGE_ESC", "Privilege escalation API"),
    (rb"(?i)uac\s*bypass|bypassuac", "PRIVILEGE_ESC", "UAC bypass attempt"),
    (rb"(?i)sudo\s*-[sS]|sudo\s+su\b", "PRIVILEGE_ESC", "Privilege escalation via sudo"),

    # Data exfiltration
    (rb"(?i)send\s*mail|smtplib|smtp\.(ehlo|starttls)", "EXFILTRATION", "Email exfiltration code"),
    (rb"(?i)ftp\.(connect|upload|stor)", "EXFILTRATION", "FTP upload/exfiltration"),
    (rb"(?i)clipboard|GetClipboardData|keylog", "EXFILTRATION", "Clipboard/keylogger access"),
    (rb"(?i)screenshot|BitBlt|GetDC\b", "EXFILTRATION", "Screen capture code"),

    # Persistence mechanisms
    (rb"(?i)HKEY_LOCAL_MACHINE\\.*\\Run\b", "PERSISTENCE", "Registry run key (persistence)"),
    (rb"(?i)schtask|SchTasks\.exe", "PERSISTENCE", "Scheduled task creation"),
    (rb"(?i)crontab\s+-[el]", "PERSISTENCE", "Cron job modification"),
    (rb"(?i)startup\s*folder|appdata.*startup", "PERSISTENCE", "Startup folder persistence"),
    (rb"(?i)systemctl\s+enable", "PERSISTENCE", "Systemd service persistence"),

    # System destruction
    (rb"(?i)rm\s+-[rf]+\s+/|shred\s+-[uzn]+", "DESTRUCTIVE", "Recursive file deletion"),
    (rb"(?i)format\s+[a-zA-Z]:\s*/[yqQ]", "DESTRUCTIVE", "Disk format command"),
    (rb"(?i)dd\s+if=/dev/zero|dd\s+if=/dev/urandom", "DESTRUCTIVE", "Disk wiping with dd"),
    (rb"(?i)DeviceIoControl|IOCTL_DISK_FORMAT", "DESTRUCTIVE", "Raw disk I/O (wiper)"),
    (rb"(?i)MBR|master\s+boot\s+record|VBR\b", "DESTRUCTIVE", "Boot record manipulation"),

    # Network indicators
    (rb"(?i)(socket\.connect|urllib|requests\.get|curl\s+[^-])", "NETWORK", "Network connection code"),
    (rb"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5}", "NETWORK", "Hardcoded IP:Port"),

    # Injection
    (rb"(?i)VirtualAllocEx|WriteProcessMemory|CreateRemoteThread", "INJECTION", "Process injection API"),
    (rb"(?i)NtUnmapViewOfSection|ZwUnmapViewOfSection", "INJECTION", "Process hollowing API"),
    (rb"(?i)SetWindowsHookEx|DLL\s+Injection", "INJECTION", "DLL injection technique"),
]

# Pre-compile regexes once at module load. Compiling inside the scan loop
# is 2-5x slower on pattern-heavy files.
_COMPILED_PATTERNS: List[Tuple["re.Pattern", str, str]] = [
    (re.compile(p, re.IGNORECASE | re.DOTALL), cat, desc)
    for p, cat, desc in SUSPICIOUS_PATTERNS
]

# SHA-256 only. MD5 was removed because collisions are cheap to construct and
# could trick the scanner into flagging a benign file as known malware.
# To refresh from a real feed, replace this dict by loading a JSON file at
# startup; see load_threat_db() below.
KNOWN_BAD_HASHES: Dict[str, str] = {
    "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa": "EICAR Test Signature",
    "e7c539e6d48d8c7f1d4d44d93ea8c7ef6a4f8e2b9c1d3a5f7e9c1d3a5f7e9c1d3": "Ryuk Ransomware (placeholder)",
}

# Optional: path to a JSON threat feed {"sha256": "label", ...}. When set, the
# feed is merged with KNOWN_BAD_HASHES on startup. The file must contain
# lowercase hex digests of length 64.
THREAT_FEED_PATH: Optional[str] = os.environ.get("SENTINEL_THREAT_FEED")


# ─────────────────────────────────────────────
#  DATA CLASSES
# ─────────────────────────────────────────────

@dataclass
class Threat:
    severity: str
    category: str
    description: str
    evidence: str = ""

@dataclass
class ScanResult:
    path: str
    size: int
    sha256: str
    md5: str
    entropy: float
    threats: List[Threat] = field(default_factory=list)
    file_type: str = "Unknown"
    scan_time: float = 0.0
    error: Optional[str] = None

    @property
    def risk_level(self) -> str:
        if self.error:
            return "ERROR"
        if not self.threats:
            return "CLEAN"
        severities = [t.severity for t in self.threats]
        if "CRITICAL" in severities:
            return "CRITICAL"
        if "HIGH" in severities:
            return "HIGH"
        if "MEDIUM" in severities:
            return "MEDIUM"
        return "LOW"

    @property
    def risk_color(self) -> str:
        colors = {
            "CLEAN": "bright_green",
            "LOW": "yellow",
            "MEDIUM": "orange1",
            "HIGH": "red",
            "CRITICAL": "bright_red",
            "ERROR": "dim",
        }
        return colors.get(self.risk_level, "white")


@dataclass
class ScanStats:
    total_files: int = 0
    scanned: int = 0
    clean: int = 0
    infected: int = 0
    errors: int = 0
    skipped: int = 0
    total_size: int = 0
    start_time: float = field(default_factory=time.time)
    threats_by_category: Dict[str, int] = field(default_factory=lambda: defaultdict(int))


def scan_patterns(filepath: str, file_size: int) -> List[Threat]:
    """Run SUSPICIOUS_PATTERNS against the file and return threats.

    Anti-FP design (2.2):
      * All regexes are pre-compiled once at module load.
      * Single-hit unigrams are reported at LOW. A threat is only promoted
        to MEDIUM or higher when there are >= 2 distinct category hits in
        the same file, or when the category is independently severe
        (RANSOMWARE / DESTRUCTIVE / KNOWN_MALWARE).
      * Cap on per-pattern evidence length to keep the table readable.
    """
    threats: List[Threat] = []
    max_read = min(file_size, 5 * 1024 * 1024)
    try:
        with open(filepath, "rb") as f:
            data = f.read(max_read)
    except Exception:
        return threats

    # Per-category hit counter, used to decide whether a single unigram
    # should be promoted out of LOW.
    category_hits: Dict[str, int] = defaultdict(int)
    # Per-description dedup, same as the original.
    raw_hits: List[Threat] = []

    for compiled, category, description in _COMPILED_PATTERNS:
        try:
            matches = compiled.findall(data)
        except Exception:
            continue
        if not matches:
            continue
        category_hits[category] += 1
        # matches can be a list of str/bytes (when the pattern has no
        # capture groups, or one outer group) OR a list of tuples (when
        # the pattern has >1 group). Normalize to a flat str for the
        # evidence field.
        first = matches[0]
        if isinstance(first, tuple):
            first = next((g for g in first if g), b"")
        if isinstance(first, bytes):
            first = first[:80].decode("utf-8", errors="replace")
        evidence = str(first)[:60]
        raw_hits.append(Threat(
            severity="LOW",
            category=category,
            description=description,
            evidence=evidence,
        ))

    if not raw_hits:
        return threats

    # Decide per-hit severity. Categories that are independently severe
    # keep their original severity even on a single hit.
    SEVERE_CATEGORIES = {"RANSOMWARE", "DESTRUCTIVE", "KNOWN_MALWARE", "INJECTION"}
    distinct_cats = sum(1 for v in category_hits.values() if v > 0)

    for hit in raw_hits:
        cat = hit.category
        if cat in SEVERE_CATEGORIES:
            sev = (
                "CRITICAL" if cat == "RANSOMWARE" else
                "HIGH" if cat in ("DESTRUCTIVE", "INJECTION") else
                "MEDIUM"
            )
        elif distinct_cats >= 2 or category_hits[cat] >= 2:
            # Multiple distinct signals in the same file -> MEDIUM.
            sev = "MEDIUM"
        elif cat in ("BACKDOOR", "PRIVILEGE_ESC", "CREDENTIAL", "PERSISTENCE", "EXFILTRATION"):
            # High-impact category on a single hit: still HIGH because the
            # category itself is rare in clean code.
            sev = "HIGH"
        else:
            sev = "LOW"
        hit.severity = sev
        threats.append(hit)

    return threats

def load_threat_db() -> Dict[str, str]:
    """Load known-bad SHA-256 hashes. Starts with KNOWN_BAD_HASHES and, if
    SENTINEL_THREAT_FEED is set, merges a JSON file of {"sha256": "label"}.
    Malformed entries are skipped with a warning rather than crashing.
    """
    db = dict(KNOWN_BAD_HASHES)
    if not THREAT_FEED_PATH:
        return db
    try:
        with open(THREAT_FEED_PATH, "r", encoding="utf-8") as f:
            feed = json.load(f)
    except FileNotFoundError:
        console.print(f"[yellow]⚠ Threat feed not found: {THREAT_FEED_PATH}[/yellow]")
        return db
    except json.JSONDecodeError as e:
        console.print(f"[yellow]⚠ Threat feed is not valid JSON ({e}); using built-in DB[/yellow]")
        return db

    added = 0
    for h, label in feed.items():
        if not isinstance(h, str) or len(h) != 64 or any(c not in "0123456789abcdef" for c in h.lower()):
            console.print(f"[yellow]⚠ Skipping malformed hash entry: {h[:16]}…[/yellow]")
            continue
        db[h.lower()] = str(label)
        added += 1
    if added:
        console.print(f"[dim]Threat feed loaded: {added} entries from {THREAT_FEED_PATH}[/dim]")
    return db


# Loaded at import time; may be enriched from a JSON feed file.
_THREAT_DB: Dict[str, str] = load_threat_db()


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = defaultdict(int)
    for byte in data:
        freq[byte] += 1
    length = len(data)
    entropy = -sum((count / length) * math.log2(count / length) for count in freq.values())
    return round(entropy, 4)

def compute_hashes(filepath: str) -> Tuple[str, str]:
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    try:
        with open(filepath, "rb") as f:
            while chunk := f.read(65536):
                sha256.update(chunk)
                md5.update(chunk)
    except Exception:
        return ("", "")
    return sha256.hexdigest(), md5.hexdigest()

def detect_file_type(data: bytes) -> str:
    for name, (magic, desc) in MAGIC_BYTES.items():
        if data.startswith(magic):
            return desc
    if data[:2] == b"MZ":
        return "Windows Executable"
    try:
        text = data[:512].decode("utf-8", errors="strict")
        if text.strip().startswith("#!"):
            return f"Script: {text.split()[0]}"
        return "Text/Script"
    except Exception:
        pass
    return "Binary/Unknown"

# Cache the pefile ImportError. The first time we try to import and it
# fails, we print a one-line warning per process and never try again.
_pefile_warned: bool = False

def scan_pe_file(filepath: str) -> List[Threat]:
    global _pefile_warned
    threats = []
    try:
        import pefile
    except ImportError:
        if not _pefile_warned:
            console.print(
                "[yellow]⚠ pefile is not installed — PE deep analysis disabled. "
                "Install with `pip install pefile` to enable EXE/DLL inspection.[/yellow]"
            )
            _pefile_warned = True
        return threats
    try:
        pe = pefile.PE(filepath, fast_load=True)
        pe.parse_data_directories()

        suspicious_imports = {
            "VirtualAllocEx": ("INJECTION", "HIGH", "Memory allocation in remote process"),
            "WriteProcessMemory": ("INJECTION", "HIGH", "Write to remote process memory"),
            "CreateRemoteThread": ("INJECTION", "HIGH", "Thread injection into remote process"),
            "NtUnmapViewOfSection": ("INJECTION", "HIGH", "Process hollowing technique"),
            "SetWindowsHookEx": ("INJECTION", "MEDIUM", "System-wide hook installation"),
            "CryptEncrypt": ("CRYPTO", "HIGH", "File encryption API"),
            "CryptDecrypt": ("CRYPTO", "MEDIUM", "File decryption API"),
            "RegSetValueEx": ("PERSISTENCE", "MEDIUM", "Registry modification"),
            "MoveFileEx": ("PERSISTENCE", "MEDIUM", "Pending file move on reboot"),
            "DeleteFile": ("DESTRUCTIVE", "LOW", "File deletion API"),
            "GetClipboardData": ("EXFILTRATION", "MEDIUM", "Clipboard data access"),
            "keybd_event": ("KEYLOGGER", "HIGH", "Keyboard event hook"),
            "BitBlt": ("EXFILTRATION", "MEDIUM", "Screen capture API"),
            "AdjustTokenPrivileges": ("PRIVILEGE_ESC", "HIGH", "Privilege escalation API"),
            "SeDebugPrivilege": ("PRIVILEGE_ESC", "HIGH", "Debug privilege escalation"),
        }

        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name:
                        name = imp.name.decode("utf-8", errors="ignore")
                        if name in suspicious_imports:
                            cat, sev, desc = suspicious_imports[name]
                            threats.append(Threat(
                                severity=sev,
                                category=cat,
                                description=desc,
                                evidence=f"Import: {name}"
                            ))

        if hasattr(pe, "DIRECTORY_ENTRY_TLS"):
            threats.append(Threat(
                severity="MEDIUM",
                category="EVASION",
                description="TLS callback found (anti-analysis technique)",
                evidence="PE TLS Directory"
            ))

        try:
            ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            for section in pe.sections:
                if (section.VirtualAddress <= ep <
                        section.VirtualAddress + section.Misc_VirtualSize):
                    name = section.Name.rstrip(b"\x00").decode("utf-8", errors="ignore")
                    chars = section.Characteristics
                    if chars & 0x20 and chars & 0x80000000 and name not in (".text", ".code"):
                        threats.append(Threat(
                            severity="HIGH",
                            category="INJECTION",
                            description=f"Entry point in unusual writable section: {name}",
                            evidence=f"Section: {name}, Chars: 0x{chars:08x}"
                        ))
        except Exception:
            pass

        pe.close()
    except Exception:
        # Malformed PE files are common; don't crash, just return what we have.
        pass
    return threats


def analyze_file(filepath: str, scan_pe: bool = True) -> ScanResult:
    start = time.time()
    path = Path(filepath)

    try:
        size = path.stat().st_size
    except Exception as e:
        return ScanResult(
            path=filepath, size=0, sha256="", md5="",
            entropy=0, error=str(e)
        )

    sha256, md5 = compute_hashes(filepath)
    threats: List[Threat] = []

    # Hash check — SHA-256 only. MD5 was removed: collisions are cheap to
    # construct and the threat DB is small, so MD5 is more risk than signal.
    if sha256 in _THREAT_DB:
        threats.append(Threat(
            severity="CRITICAL",
            category="KNOWN_MALWARE",
            description=_THREAT_DB[sha256],
            evidence=f"SHA256: {sha256}"
        ))

    # Ransomware extension
    ext = path.suffix.lower()
    if ext in RANSOMWARE_EXTENSIONS:
        threats.append(Threat(
            severity="CRITICAL",
            category="RANSOMWARE",
            description=f"File has known ransomware extension: {ext}",
            evidence=f"Extension: {ext}"
        ))
    elif ext in DANGEROUS_EXTENSIONS:
        threats.append(Threat(
            severity="LOW",
            category="SUSPICIOUS_TYPE",
            description=f"Potentially dangerous file type: {ext}",
            evidence=f"Extension: {ext}"
        ))

    # Read header + entropy sample
    try:
        with open(filepath, "rb") as f:
            header = f.read(512)
            f.seek(0)
            sample = f.read(min(size, 65536))
    except Exception as e:
        return ScanResult(
            path=filepath, size=size, sha256=sha256, md5=md5,
            entropy=0, error=str(e), threats=threats
        )

    file_type = detect_file_type(header)
    entropy = shannon_entropy(sample)

    # High entropy = possibly encrypted/packed (ransomware indicator)
    if entropy > 7.8 and size > 10240:
        threats.append(Threat(
            severity="HIGH",
            category="ENCRYPTION",
            description=f"Extremely high entropy ({entropy:.4f}/8.0) — file may be encrypted or ransomware payload",
            evidence=f"Entropy: {entropy:.4f}"
        ))
    elif entropy > 7.2 and size > 10240:
        threats.append(Threat(
            severity="MEDIUM",
            category="OBFUSCATION",
            description=f"High entropy ({entropy:.4f}/8.0) — file may be packed or obfuscated",
            evidence=f"Entropy: {entropy:.4f}"
        ))

    # PE analysis
    if header.startswith(b"MZ") and scan_pe:
        pe_threats = scan_pe_file(filepath)
        threats.extend(pe_threats)

    # Pattern scan
    pattern_threats = scan_patterns(filepath, size)
    # Deduplicate by description
    seen = {t.description for t in threats}
    for t in pattern_threats:
        if t.description not in seen:
            threats.append(t)
            seen.add(t.description)

    return ScanResult(
        path=filepath,
        size=size,
        sha256=sha256,
        md5=md5,
        entropy=entropy,
        threats=threats,
        file_type=file_type,
        scan_time=round(time.time() - start, 3),
    )


# ─────────────────────────────────────────────
#  FILE COLLECTION
# ─────────────────────────────────────────────

MAX_FILE_SIZE_DEFAULT = 50 * 1024 * 1024  # 50 MB

# Total budget cap for a single scan. Prevents a single `sentinel scan /`
# invocation from queuing millions of files (e.g. on a directory that
# symlinks into /proc or a backup mount).
MAX_TOTAL_FILES_DEFAULT = 200_000
MAX_TOTAL_BYTES_DEFAULT = 5 * 1024 * 1024 * 1024  # 5 GB


def collect_files(
    targets: List[str],
    recursive: bool = True,
    max_size: int = MAX_FILE_SIZE_DEFAULT,
    extensions: Optional[List[str]] = None,
    follow_symlinks: bool = False,
    max_total_files: int = MAX_TOTAL_FILES_DEFAULT,
    max_total_bytes: int = MAX_TOTAL_BYTES_DEFAULT,
) -> List[str]:
    """Walk targets and return a sorted, de-duplicated list of file paths.

    Safety properties (added in 2.2):
      * Symlinks are not followed by default; the resolved real path is
        de-duplicated so a symlink loop yields exactly one entry.
      * Total file count and total bytes scanned are bounded; the walk stops
        once either cap is hit and a warning is printed.
      * FIFO / device / socket entries are skipped (`is_file()` is False
        for them); broken symlinks are skipped silently.
    """
    files: List[str] = []
    seen_real: set = set()
    seen_dir_inodes: set = set()
    total_bytes = 0
    cap_hit = False

    def add_file(p: Path) -> bool:
        nonlocal total_bytes, cap_hit
        if cap_hit:
            return False
        try:
            real = str(p.resolve())
        except OSError:
            return False
        if real in seen_real:
            return False
        try:
            st = p.stat()
        except OSError:
            return False
        if st.st_size > max_size:
            return False
        if extensions and p.suffix.lower() not in extensions:
            return False
        seen_real.add(real)
        files.append(str(p))
        total_bytes += st.st_size
        if len(files) >= max_total_files or total_bytes >= max_total_bytes:
            cap_hit = True
        return True

    for target in targets:
        p = Path(target)
        if not p.exists() and not p.is_symlink():
            console.print(f"[yellow]⚠ Not found: {target}[/yellow]")
            continue
        if p.is_file() or p.is_symlink():
            try:
                add_file(p)
            except Exception:
                pass
            continue
        if not p.is_dir():
            continue

        # Walk without following symlinks; detect directory cycles by inode.
        for root, dirs, names in os.walk(str(p), followlinks=follow_symlinks, topdown=True):
            if cap_hit:
                break
            root_path = Path(root)
            try:
                root_inode = root_path.stat().st_ino
            except OSError:
                dirs[:] = []
                continue
            if root_inode in seen_dir_inodes:
                dirs[:] = []
                continue
            seen_dir_inodes.add(root_inode)

            if not follow_symlinks:
                # Prune symlinked directories to avoid cycles and surprises.
                dirs[:] = [d for d in dirs if not (root_path / d).is_symlink()]

            for name in names:
                if cap_hit:
                    break
                child = root_path / name
                try:
                    if child.is_file():
                        add_file(child)
                except Exception:
                    pass

    if cap_hit:
        console.print(
            f"[yellow]⚠ Scan cap reached "
            f"({len(files)} files / {bytes_human(total_bytes)}); "
            f"raise --max-total-files / --max-total-bytes to widen.[/yellow]"
        )
    return sorted(files)


# ─────────────────────────────────────────────
#  CLI RENDERING
# ─────────────────────────────────────────────

BANNER = """
[bold bright_red]  ╔═══════════════════════════════════════════════════════════════╗
  ║  ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗   ║
  ║  ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║   ║
  ║  ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║   ║
  ║  ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║   ║
  ║  ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗║
  ║  ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝║
  ║                                                                   ║
  ║         [white]S H I E L D[/white]  [dim white]—  Advanced Malware & Ransomware Scanner[/dim white]     [bold bright_red]║
  ╚═══════════════════════════════════════════════════════════════════╝[/bold bright_red]
"""

SEVERITY_STYLES = {
    "CRITICAL": ("[bold bright_red]● CRITICAL[/bold bright_red]", "bright_red"),
    "HIGH":     ("[bold red]▲ HIGH[/bold red]",                   "red"),
    "MEDIUM":   ("[bold yellow]◆ MEDIUM[/bold yellow]",           "yellow"),
    "LOW":      ("[bold cyan]◉ LOW[/bold cyan]",                  "cyan"),
    "CLEAN":    ("[bold bright_green]✓ CLEAN[/bold bright_green]","bright_green"),
}

CATEGORY_ICONS = {
    "RANSOMWARE":     "💀",
    "BACKDOOR":       "🚪",
    "INJECTION":      "💉",
    "OBFUSCATION":    "🎭",
    "EVASION":        "🦎",
    "PRIVILEGE_ESC":  "⬆",
    "EXFILTRATION":   "📤",
    "PERSISTENCE":    "🔗",
    "DESTRUCTIVE":    "💥",
    "ENCRYPTION":     "🔐",
    "KNOWN_MALWARE":  "☠",
    "CREDENTIAL":     "🔑",
    "CRYPTO":         "🔒",
    "NETWORK":        "🌐",
    "KEYLOGGER":      "⌨",
    "SUSPICIOUS_TYPE":"⚠",
}

def render_banner():
    console.print(BANNER)
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    console.print(Align.center(f"[dim]Version 2.1.0  ·  {now}  ·  Threat DB: 2024.12[/dim]\n"))

def bytes_human(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"

def entropy_bar(entropy: float) -> str:
    filled = int((entropy / 8.0) * 20)
    empty = 20 - filled
    color = "bright_green" if entropy < 6.0 else "yellow" if entropy < 7.2 else "red"
    return f"[{color}]{'█' * filled}[/{color}][dim]{'░' * empty}[/dim] [{color}]{entropy:.2f}[/{color}]"

def risk_badge(level: str) -> str:
    badges = {
        "CLEAN":    "[on bright_green black] ✓ CLEAN    [/on bright_green black]",
        "LOW":      "[on yellow black] ◉ LOW      [/on yellow black]",
        "MEDIUM":   "[on orange1 black] ◆ MEDIUM   [/on orange1 black]",
        "HIGH":     "[on red white] ▲ HIGH     [/on red white]",
        "CRITICAL": "[on bright_red white bold] ● CRITICAL [/on bright_red white bold]",
        "ERROR":    "[on dark_red white] ✗ ERROR    [/on dark_red white]",
    }
    return badges.get(level, level)


def print_file_result(result: ScanResult, verbose: bool = False):
    level = result.risk_level
    if level == "CLEAN" and not verbose:
        console.print(
            f"  [bright_green]✓[/bright_green] [dim]{escape(result.path[:70])}[/dim] "
            f"[dim]({bytes_human(result.size)})[/dim] "
            f"[bright_green]CLEAN[/bright_green]  "
            f"[dim]H:{result.entropy:.2f}[/dim]"
        )
        return

    if level == "ERROR":
        console.print(f"  [dim red]✗ {escape(result.path[:70])} — {result.error}[/dim red]")
        return

    color = result.risk_color
    console.print()
    console.print(Rule(f"[{color}]{risk_badge(level)}[/{color}] [bold]{escape(Path(result.path).name)}[/bold]", style=color))
    console.print(f"  [dim]Path:[/dim] {escape(result.path)}")
    console.print(f"  [dim]Type:[/dim] {result.file_type}   [dim]Size:[/dim] {bytes_human(result.size)}   [dim]Time:[/dim] {result.scan_time}s")
    console.print(f"  [dim]SHA256:[/dim] [dim]{result.sha256}[/dim]")
    console.print(f"  [dim]MD5:[/dim]    [dim]{result.md5}[/dim]")
    console.print(f"  [dim]Entropy:[/dim] {entropy_bar(result.entropy)}")

    if result.threats:
        console.print()
        table = Table(box=box.SIMPLE, show_header=True, header_style="bold dim",
                      show_lines=False, padding=(0, 1))
        table.add_column("Severity", width=16, no_wrap=True)
        table.add_column("Category", width=18, no_wrap=True)
        table.add_column("Description", min_width=35)
        table.add_column("Evidence", style="dim", min_width=20)

        for threat in sorted(result.threats, key=lambda t: (
            {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(t.severity, 9)
        )):
            icon = CATEGORY_ICONS.get(threat.category, "•")
            sev_label, sev_color = SEVERITY_STYLES.get(threat.severity, (threat.severity, "white"))[:2], "white"
            sev_txt, sev_color = SEVERITY_STYLES.get(threat.severity, (threat.severity, "white"))
            evidence = escape(threat.evidence[:60]) if threat.evidence else "[dim]—[/dim]"
            table.add_row(
                sev_txt,
                f"{icon} {threat.category}",
                escape(threat.description[:65]),
                evidence
            )
        console.print(table)


def print_summary(stats: ScanStats, results: List[ScanResult], output_file: Optional[str]):
    elapsed = time.time() - stats.start_time
    speed = stats.scanned / elapsed if elapsed > 0 else 0

    console.print()
    console.print(Rule("[bold]SCAN COMPLETE[/bold]", style="bright_white"))
    console.print()

    # Stats grid
    grid = Table.grid(expand=True, padding=(0, 4))
    grid.add_column(justify="center")
    grid.add_column(justify="center")
    grid.add_column(justify="center")
    grid.add_column(justify="center")
    grid.add_column(justify="center")

    def stat_panel(label, value, color="white"):
        return Panel(
            Align.center(f"[bold {color}]{value}[/bold {color}]\n[dim]{label}[/dim]"),
            border_style=color, padding=(0, 2)
        )

    grid.add_row(
        stat_panel("Total Files", stats.total_files, "white"),
        stat_panel("✓ Clean",    stats.clean,        "bright_green"),
        stat_panel("⚠ Infected", stats.infected,     "red" if stats.infected else "dim"),
        stat_panel("✗ Errors",   stats.errors,        "yellow" if stats.errors else "dim"),
        stat_panel("Size Scanned", bytes_human(stats.total_size), "cyan"),
    )
    console.print(grid)
    console.print()

    # Threat breakdown
    if stats.threats_by_category:
        console.print(Rule("[bold]Threat Breakdown[/bold]", style="dim"))
        cat_table = Table(box=box.SIMPLE_HEAD, show_header=True,
                          header_style="bold dim", padding=(0, 2))
        cat_table.add_column("Category", style="bold")
        cat_table.add_column("Count", justify="right")
        cat_table.add_column("Visual")

        max_count = max(stats.threats_by_category.values(), default=1)
        for cat, count in sorted(stats.threats_by_category.items(), key=lambda x: -x[1]):
            icon = CATEGORY_ICONS.get(cat, "•")
            bar_len = int((count / max_count) * 30)
            bar = "█" * bar_len
            color = "bright_red" if cat == "RANSOMWARE" else "red" if cat in ("BACKDOOR", "DESTRUCTIVE") else "yellow"
            cat_table.add_row(
                f"{icon} {cat}",
                str(count),
                f"[{color}]{bar}[/{color}]"
            )
        console.print(cat_table)
        console.print()

    # Infected files list
    infected = [r for r in results if r.risk_level not in ("CLEAN", "ERROR")]
    if infected:
        console.print(Rule("[bold red]Detected Threats[/bold red]", style="red"))
        threat_table = Table(box=box.ROUNDED, show_header=True,
                             header_style="bold red", padding=(0, 1))
        threat_table.add_column("Risk", width=12, no_wrap=True)
        threat_table.add_column("File", min_width=30)
        threat_table.add_column("Threats", justify="right", width=8)
        threat_table.add_column("Top Threat")
        threat_table.add_column("Entropy", width=8, justify="right")

        for r in sorted(infected, key=lambda x: (
            {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(x.risk_level, 9)
        )):
            top = sorted(r.threats, key=lambda t: (
                {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(t.severity, 9)
            ))[0] if r.threats else None
            top_desc = escape(top.description[:50]) if top else ""
            fname = escape(Path(r.path).name[:40])
            threat_table.add_row(
                risk_badge(r.risk_level),
                fname,
                str(len(r.threats)),
                top_desc,
                f"{r.entropy:.2f}",
            )
        console.print(threat_table)
        console.print()

    # Footer stats
    console.print(
        f"  [dim]Scan speed:[/dim] [bold]{speed:.0f}[/bold] [dim]files/sec  ·  "
        f"Elapsed: [bold]{elapsed:.1f}s[/bold][/dim]"
    )

    if output_file:
        save_json_report(results, stats, output_file)
        console.print(f"\n  [bright_green]✓ JSON report saved → {output_file}[/bright_green]")

    final_color = "bright_red" if stats.infected else "bright_green"
    verdict = "⚠  THREATS DETECTED — IMMEDIATE ACTION REQUIRED" if stats.infected else "✓  ALL CLEAR — No threats detected"
    console.print()
    console.print(Panel(
        Align.center(f"[bold {final_color}]{verdict}[/bold {final_color}]"),
        border_style=final_color, padding=(1, 4)
    ))
    console.print()


def save_json_report(results: List[ScanResult], stats: ScanStats, path: str):
    report = {
        "scan_info": {
            "timestamp": datetime.datetime.now().isoformat(),
            "version": "2.1.0",
            "total_files": stats.total_files,
            "clean": stats.clean,
            "infected": stats.infected,
            "errors": stats.errors,
            "total_size_bytes": stats.total_size,
            "elapsed_seconds": round(time.time() - stats.start_time, 2),
        },
        "threats": [
            {
                "path": r.path,
                "risk_level": r.risk_level,
                "size": r.size,
                "sha256": r.sha256,
                "md5": r.md5,
                "entropy": r.entropy,
                "file_type": r.file_type,
                "threats": [
                    {"severity": t.severity, "category": t.category,
                     "description": t.description, "evidence": t.evidence}
                    for t in r.threats
                ]
            }
            for r in results if r.risk_level not in ("CLEAN", "ERROR")
        ]
    }
    with open(path, "w") as f:
        json.dump(report, f, indent=2)


# ─────────────────────────────────────────────
#  MAIN SCANNER
# ─────────────────────────────────────────────

def run_scan(args):
    render_banner()

    targets = args.targets
    console.print(Panel(
        "\n".join([
            f"[dim]Targets    :[/dim] [bold]{', '.join(targets)}[/bold]",
            f"[dim]Recursive  :[/dim] {'Yes' if args.recursive else 'No'}",
            f"[dim]Max size   :[/dim] {bytes_human(args.max_size * 1024 * 1024)}",
            f"[dim]PE Analysis:[/dim] {'Enabled' if not args.no_pe else 'Disabled'}",
            f"[dim]Output     :[/dim] {args.output or 'None (console only)'}",
        ]),
        title="[bold]Scan Configuration[/bold]",
        border_style="blue", padding=(0, 2)
    ))
    console.print()

    # Collect files
    with console.status("[bold blue]Discovering files...[/bold blue]"):
        files = collect_files(
            targets,
            recursive=args.recursive,
            max_size=args.max_size * 1024 * 1024,
            follow_symlinks=args.follow_symlinks,
            max_total_files=args.max_total_files,
            max_total_bytes=args.max_total_bytes,
        )

    if not files:
        console.print("[yellow]No files found to scan.[/yellow]")
        return

    console.print(f"  [dim]Found[/dim] [bold]{len(files)}[/bold] [dim]files to scan[/dim]\n")

    stats = ScanStats(total_files=len(files))
    results: List[ScanResult] = []
    show_all = args.verbose or args.all
    workers = max(1, int(getattr(args, "workers", 4)))

    with Progress(
        SpinnerColumn(spinner_name="dots12", style="bold blue"),
        TextColumn("[bold blue]{task.description}"),
        BarColumn(bar_width=40, style="blue", complete_style="bright_blue"),
        TaskProgressColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=False,
    ) as progress:
        task = progress.add_task("[bold]Scanning...[/bold]", total=len(files))

        # Use a thread pool: most of the work is regex + small file reads
        # which release the GIL often enough to benefit from a few workers.
        # PE parsing is also mostly I/O. We keep a sane upper bound so a
        # 10k-file scan doesn't fork 10k threads.
        from concurrent.futures import ThreadPoolExecutor, as_completed

        def _scan_one(filepath: str) -> ScanResult:
            return analyze_file(filepath, scan_pe=not args.no_pe)

        if workers == 1 or len(files) <= 1:
            for filepath in files:
                progress.update(task, description=f"[dim]{Path(filepath).name[:40]}[/dim]")
                result = _scan_one(filepath)
                results.append(result)
                stats.scanned += 1
                try:
                    stats.total_size += result.size
                except Exception:
                    pass
                if result.error:
                    stats.errors += 1
                elif result.threats:
                    stats.infected += 1
                    for t in result.threats:
                        stats.threats_by_category[t.category] += 1
                else:
                    stats.clean += 1
                progress.advance(task)
        else:
            with ThreadPoolExecutor(max_workers=workers) as pool:
                future_to_path = {pool.submit(_scan_one, fp): fp for fp in files}
                done_count = 0
                for future in as_completed(future_to_path):
                    filepath = future_to_path[future]
                    try:
                        result = future.result()
                    except Exception as e:
                        # Should not normally happen — analyze_file swallows
                        # its own exceptions — but defend against bugs.
                        result = ScanResult(
                            path=filepath, size=0, sha256="", md5="",
                            entropy=0.0, error=f"worker crashed: {e}"
                        )
                    results.append(result)
                    stats.scanned += 1
                    try:
                        stats.total_size += result.size
                    except Exception:
                        pass
                    if result.error:
                        stats.errors += 1
                    elif result.threats:
                        stats.infected += 1
                        for t in result.threats:
                            stats.threats_by_category[t.category] += 1
                    else:
                        stats.clean += 1
                    done_count += 1
                    progress.update(task, description=f"[dim]{Path(filepath).name[:40]}[/dim]")
                    progress.advance(task)

    # Print results
    console.print()
    console.print(Rule("[bold]Scan Results[/bold]", style="dim"))
    console.print()

    for result in results:
        if show_all or result.risk_level not in ("CLEAN", "ERROR"):
            print_file_result(result, verbose=args.verbose)

    print_summary(stats, results, args.output)


def cmd_hash(args):
    render_banner()
    console.print(Panel("[bold]Hash Lookup Mode[/bold]", border_style="blue"))
    for h in args.hashes:
        h_lower = h.lower()
        if h_lower in KNOWN_BAD_HASHES:
            console.print(f"  [bold bright_red]☠ MATCH[/bold bright_red] [dim]{h}[/dim] → [red]{KNOWN_BAD_HASHES[h_lower]}[/red]")
        else:
            console.print(f"  [bright_green]✓ Not found[/bright_green] [dim]{h}[/dim]")


def cmd_info(args):
    render_banner()
    for filepath in args.files:
        result = analyze_file(filepath)
        console.print()
        print_file_result(result, verbose=True)
    console.print()


# ─────────────────────────────────────────────
#  ARGUMENT PARSER
# ─────────────────────────────────────────────

def build_parser():
    parser = argparse.ArgumentParser(
        prog="sentinel",
        description="SENTINEL SHIELD — Advanced Malware & Ransomware Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sentinel scan .                          Scan current directory
  sentinel scan /path/to/dir -r            Recursive scan
  sentinel scan file.exe -v                Verbose file analysis
  sentinel scan . --all -o report.json     Scan all, save JSON report
  sentinel info suspicious.exe             Deep file info
  sentinel hash <sha256>                   Check SHA-256 against threat DB
        """
    )
    sub = parser.add_subparsers(dest="command")

    # scan
    sp = sub.add_parser("scan", help="Scan files or directories for threats")
    sp.add_argument("targets", nargs="+", metavar="PATH", help="Files or directories to scan")
    sp.add_argument("-r", "--recursive", action="store_true", default=True, help="Recursive scan (default: on)")
    sp.add_argument("--no-recursive", dest="recursive", action="store_false")
    sp.add_argument("-v", "--verbose", action="store_true", help="Show detailed result for every file")
    sp.add_argument("-a", "--all", action="store_true", help="Show all files (including clean)")
    sp.add_argument("--no-pe", action="store_true", help="Skip PE (EXE/DLL) deep analysis")
    sp.add_argument("-o", "--output", metavar="FILE", help="Save JSON report to FILE")
    sp.add_argument("--max-size", type=int, default=50, metavar="MB",
                    help="Max file size to scan in MB (default: 50)")
    sp.add_argument("--max-total-files", type=int, default=MAX_TOTAL_FILES_DEFAULT,
                    metavar="N", help="Max total files queued in one scan (default: 200000)")
    sp.add_argument("--max-total-bytes", type=int, default=MAX_TOTAL_BYTES_DEFAULT,
                    metavar="BYTES", help="Max total bytes queued in one scan (default: 5 GB)")
    sp.add_argument("--follow-symlinks", action="store_true",
                    help="Follow symlinks during directory walk (OFF by default; cycles possible)")
    sp.add_argument("--workers", type=int, default=4, metavar="N",
                    help="Parallel scan workers (default: 4; 1 = serial)")

    # info
    ip = sub.add_parser("info", help="Deep analysis of specific file(s)")
    ip.add_argument("files", nargs="+", metavar="FILE")

    # hash
    hp = sub.add_parser("hash", help="Check hashes against threat database")
    hp.add_argument("hashes", nargs="+", metavar="HASH")

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        render_banner()
        parser.print_help()
        console.print()
        return

    try:
        if args.command == "scan":
            run_scan(args)
        elif args.command == "info":
            cmd_info(args)
        elif args.command == "hash":
            cmd_hash(args)
    except KeyboardInterrupt:
        console.print("\n\n[yellow]⚡ Scan interrupted by user.[/yellow]\n")
        sys.exit(130)


if __name__ == "__main__":
    main()