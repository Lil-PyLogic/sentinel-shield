# Contributing to Sentinel Shield

Thanks for your interest in making Sentinel Shield better! 🛡️

Sentinel Shield is a defensive threat-detection tool. Contributions that improve detection coverage, reduce false positives, harden the codebase, or improve the user experience are all welcome.

---

## 📋 Table of Contents

- [Code of Conduct](#-code-of-conduct)
- [How to Get Started](#-how-to-get-started)
- [Reporting Bugs](#-reporting-bugs)
- [Suggesting Enhancements](#-suggesting-enhancements)
- [Pull Requests](#-pull-requests)
- [Adding a New Detection Rule](#-adding-a-new-detection-rule)
- [Coding Style](#-coding-style)
- [Testing](#-testing)
- [Commit Messages](#-commit-messages)

---

## 📜 Code of Conduct

This project follows a simple rule: **be respectful, be constructive, assume good intent.** Disagreement about technical direction is fine — personal attacks are not. Help us keep the issue tracker and PR discussions welcoming for everyone.

---

## 🚀 How to Get Started

1. **Fork** the repository on GitHub.
2. **Clone** your fork locally:
   ```bash
   git clone https://github.com/<your-username>/sentinel-shield.git
   cd sentinel-shield
   ```
3. **Create a virtual environment** (recommended):
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate   # Windows: .venv\Scripts\activate
   ```
4. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
5. **Smoke-test** your install:
   ```bash
   python malware_scaner.py --help
   echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > eicar.com
   python malware_scaner.py info eicar.com
   # Expected: ● CRITICAL · ☠ KNOWN_MALWARE
   ```

If the EICAR test passes, you're ready to develop.

---

## 🐛 Reporting Bugs

Open a **GitHub Issue** with:

- A clear, descriptive title.
- Steps to reproduce (ideally with a minimal command line).
- Expected vs. actual behavior.
- Your environment: OS, Python version, `rich`/`pefile` versions.
- If applicable, the relevant JSON report (`sentinel scan … -o report.json`) with sensitive paths redacted.

> ⚠️ **Do not paste real malware samples** into issues. If you need to share a binary, describe the detection (filename, SHA-256, scan output) and coordinate a private channel with the maintainer.

---

## 💡 Suggesting Enhancements

For new **detection rules**, please open an issue first and include:

- The **category** it should fall under (RANSOMWARE, BACKDOOR, PERSISTENCE, etc.).
- The **severity** you think is appropriate, and why.
- An **example string** that should trigger it.
- A **counter-example** showing that legitimate code does *not* trigger it (or an argument for why false positives are acceptable here).

For larger changes (new detection stage, refactor of the severity engine, plugin system, etc.), please open an **issue for discussion first** before writing code. We'd rather align on approach than reject a polished-but-misaligned PR.

---

## 🔀 Pull Requests

1. **Branch off `main`** with a descriptive branch name:
   ```bash
   git checkout -b feature/persistence-cron-variants
   git checkout -b fix/entropy-threshold-edge-case
   ```
2. **Make focused commits** — one logical change per commit.
3. **Add or update tests** for any behavioral change (see [Testing](#-testing)).
4. **Update the README** if the change is user-visible (new flag, new output format, new dependency).
5. **Run the smoke test** before pushing (see above).
6. **Open a PR** with:
   - A clear summary of what changed and why.
   - Reference to any related issue (e.g. `Closes #42`).
   - Screenshots of the TUI output if you changed any rendering.
7. **Be patient and open to feedback.** Reviews may take a few days.

---

## 🧬 Adding a New Detection Rule

Detection rules live in two places in `malware_scaner.py`:

### A. Extension-based (ransomware family)

Add the extension string to the `RANSOMWARE_EXTENSIONS` set. Please include a comment with the family name and a citation (vendor report, news article, etc.) if possible. **One extension per family variant.**

### B. Pattern-based (regex)

Add an entry to `SUSPICIOUS_PATTERNS` as a tuple of `(pattern: bytes, category: str, description: str)`. Rules of thumb:

| Guideline | Why |
|---|---|
| Compile-time regex, not raw string literals in the scan loop. | Compiling inside the loop is 2–5× slower. |
| Default new rules to severity `LOW`. | Let the correlation engine promote them, instead of spamming `MEDIUM` everywhere. |
| Promote to `MEDIUM`/`HIGH` only if the category is independently severe (`RANSOMWARE`, `DESTRUCTIVE`, `INJECTION`) or the pattern is extremely rare in clean code. | False positives destroy trust in the tool. |
| Use `(?i)` for case-insensitive matching, `re.DOTALL` only when you need `.` to match newlines. | Avoid silent misses. |
| Add the category to the `CATEGORY_ICONS` dict if it's new. | Otherwise the table prints a default `•`. |
| Add a `Threat` with `evidence` set to a short excerpt of the match (≤ 80 chars). | Keeps the output table readable. |

After adding, regenerate `_COMPILED_PATTERNS` (it's rebuilt automatically at module load from `SUSPICIOUS_PATTERNS`), and **add a test case** under `tests/` that contains a synthetic string which should trigger the rule.

---

## 🎨 Coding Style

- **Python 3.8+** is the supported baseline. Don't use 3.9+-only syntax (walrus is fine, but no `dict[str, int]` annotations).
- **PEP 8** with sensible pragmatism. Match the surrounding code's style — the project values readability over dogma.
- **Type hints** on public functions and dataclasses.
- **Docstrings** on every non-trivial function. One-line summary first, then a blank line, then detail.
- **Avoid global state mutation.** The few globals that exist (e.g. `_THREAT_DB`) are intentional caches — please don't add more.
- **No network calls.** Sentinel Shield runs offline by design. This is non-negotiable.
- **No new heavy dependencies** without a discussion in an issue first. The point of the project is that you can `git clone` and run it.

---

## 🧪 Testing

We don't have a full test suite yet — contributions to add `pytest` coverage are very welcome. In the meantime, the minimum bar for a PR is:

1. **Manual smoke test** with the EICAR string (see [How to Get Started](#-how-to-get-started)).
2. **A test fixture** in `tests/` for any new detection rule. The simplest acceptable form is a small text file containing a synthetic malicious-looking string, plus a one-liner that runs the scanner and asserts the expected threat category is in the result.
3. **A non-regression test** for any bug fix — a small file that used to misbehave, plus an assertion that the new behavior is correct.

Example minimal test:

```python
# tests/test_pattern_destructive_rm.py
from pathlib import Path
from malware_scaner import analyze_file

def test_destructive_rm_rf_flagged(tmp_path: Path):
    p = tmp_path / "evil.sh"
    p.write_text("#!/bin/bash\nrm -rf / --no-preserve-root\n")
    result = analyze_file(str(p))
    categories = {t.category for t in result.threats}
    assert "DESTRUCTIVE" in categories
```

---

## 💬 Commit Messages

We use **Conventional Commits** (loosely):

- `feat: …` — new feature or detection rule
- `fix: …` — bug fix
- `docs: …` — README / docs / comments
- `refactor: …` — internal cleanup, no behavior change
- `test: …` — adding or improving tests
- `chore: …` — build, CI, dependency bumps

Examples:
- `feat: add DeadBolt and Lorenz ransomware extensions`
- `fix: entropy threshold promoted clean GZIP to MEDIUM`
- `docs: clarify why MD5 is not used in threat-DB matching`
- `refactor: pre-compile regexes once at module load`

Keep subject lines under ~72 characters. Body explains *why*, not *what*.

---

## 🙏 Thank You

Every contribution matters — from a typo fix in the README, to a new detection rule that catches a family nobody else is flagging yet. Defensive tooling is a community effort, and we're glad to have you here.

— Sentinel Shield maintainers 🛡️
