#!/usr/bin/env python3
"""Scan repository files (and optionally Git history) for credential-like strings.

The scanner never prints a full matched value. Every finding is masked to the
first four and last two characters. Deliberate placeholders containing
``REPLACE_WITH`` or ``REDACTED`` are ignored.

Usage:
    python scripts/secret_scan.py --root .
    python scripts/secret_scan.py --root . --history
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("slack_token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("discord_webhook", re.compile(
        r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+")),
    ("telegram_bot_token", re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{30,}\b")),
    ("github_token", re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}")),
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("private_key", re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("bearer_token", re.compile(r"Bearer\s+[A-Za-z0-9._\-]{20,}")),
    ("long_hex_secret", re.compile(r"\b[0-9a-fA-F]{64}\b")),
]

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".pytest_cache", "dist", "build"}
SKIP_FILES = {".env", ".env.local"}
SKIP_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".pdf", ".zip", ".7z",
                 ".gz", ".ico", ".woff", ".woff2", ".ttf", ".pyc", ".exe", ".dll"}
# Digest values in the sanitisation report are hashes, not secrets.
HEX_SKIP_FILES = {"sanitization-report.json"}
PLACEHOLDER_MARKERS = ("REPLACE_WITH", "REDACTED")


def mask(value: str) -> str:
    if len(value) <= 8:
        return "*" * len(value)
    return value[:4] + "..." + value[-2:]


def is_placeholder(value: str) -> bool:
    return any(marker in value for marker in PLACEHOLDER_MARKERS)


def scan_text(text: str, label: str, *, skip_hex: bool = False) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        for name, pattern in PATTERNS:
            if skip_hex and name == "long_hex_secret":
                continue
            for match in pattern.finditer(line):
                value = match.group(0)
                if is_placeholder(value):
                    continue
                findings.append({
                    "file": label,
                    "line": str(line_number),
                    "type": name,
                    "masked": mask(value),
                })
    return findings


def iter_files(root: Path):
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(root)
        if any(part in SKIP_DIRS for part in relative.parts):
            continue
        if path.name in SKIP_FILES or path.suffix.lower() in SKIP_SUFFIXES:
            continue
        if path.name.startswith(".env.") and path.name != ".env.example":
            continue
        yield path, relative.as_posix()


def scan_worktree(root: Path) -> tuple[list[dict[str, str]], int]:
    findings: list[dict[str, str]] = []
    scanned = 0
    for path, label in iter_files(root):
        data = path.read_bytes()
        if b"\x00" in data[:4096]:
            continue
        text = data.decode("utf-8", errors="ignore")
        scanned += 1
        findings.extend(scan_text(text, label, skip_hex=path.name in HEX_SKIP_FILES))
    return findings, scanned


def scan_history(root: Path) -> tuple[list[dict[str, str]], int]:
    try:
        result = subprocess.run(
            ["git", "log", "-p", "--all", "--", "."],
            cwd=root,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired):
        return [], 0
    if result.returncode != 0:
        return [], 0
    output = result.stdout or ""
    # Split the diff into per-file blocks so digest values in the sanitisation
    # report can be excluded from the 64-hex check, exactly as in the worktree scan.
    findings: list[dict[str, str]] = []
    for block in re.split(r"(?=^diff --git )", output, flags=re.MULTILINE):
        if not block.strip():
            continue
        header = block.splitlines()[0] if block.splitlines() else ""
        skip_hex = any(name in header for name in HEX_SKIP_FILES)
        findings.extend(scan_text(block, "git-history", skip_hex=skip_hex))
    return findings, 1 if output else 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".", type=Path)
    parser.add_argument("--history", action="store_true")
    args = parser.parse_args()
    root = args.root.resolve()

    findings, scanned = scan_worktree(root)
    print(f"files_scanned={scanned}")

    history_count = 0
    if args.history:
        history_findings, history_count = scan_history(root)
        findings.extend(history_findings)
        print(f"git_history_scanned={'yes' if history_count else 'no-or-empty'}")

    print(f"findings={len(findings)}")
    for finding in findings:
        print(f"  {finding['file']}:{finding['line']} [{finding['type']}] {finding['masked']}")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
