#!/usr/bin/env python3
"""
Validate Wiz Custom Secret Detection regex rules against all synthetic test fixtures in the repository.
Usage: python3 scripts/validate_regex_rules.py [--help] [--json]
"""

import argparse
import json
import pathlib
import re
import sys

WIZ_CUSTOM_RULES = {
    "Broader JWT": re.compile(
        r"\b(?P<value>eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b"
    ),
    "NATS JWT": re.compile(
        r"\b(?P<value>eyJ0eXAiOiJKV1QiLCJhbGciOiJlZDI1NTE5LW5rZXkifQ\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{86})\b"
    ),
    "NATS NKey": re.compile(
        r"(?:NKEY SEED-----+\r?\n|(?:seed|Seed|SEED|nkey|NKey|NKEY)[_A-Za-z0-9]*\s*[:=]\s*[\"']?)(?P<value>S[OAU]A[A-Z2-7]{55})"
    ),
    "Okta SSWS Token": re.compile(
        r"(?:(?i:okta|ssws)[_A-Za-z0-9-]*\s*(?:[:=]|\s)\s*[\"']?)(?P<value>00[A-Za-z0-9_-]{40})\b"
    ),
}

RAW_OKTA_TOKEN_PATTERN = re.compile(r"\b(?P<value>00[A-Za-z0-9_-]{40})\b")

SKIP_DIRS = {".git", ".github", "bin", "reports", "__pycache__", ".venv", "venv"}
SKIP_FILES = {"README.md", "go.mod", ".gitignore", ".env", ".env.example"}


def scan_repository(repo_root: pathlib.Path) -> list[dict]:
    findings: list[dict] = []
    files = sorted(
        p
        for p in repo_root.rglob("*")
        if p.is_file()
        and not any(part in SKIP_DIRS for part in p.parts)
        and p.name not in SKIP_FILES
        and p.parent.name != "scripts"
    )

    for file_path in files:
        rel_path = file_path.relative_to(repo_root).as_posix()
        text = file_path.read_text(encoding="utf-8")
        lines = text.splitlines()

        okta_ssws_lines: set[int] = set()
        for rule_name, rx in WIZ_CUSTOM_RULES.items():
            for match in rx.finditer(text):
                line_no = text.count("\n", 0, match.start("value")) + 1
                if rule_name == "Okta SSWS Token":
                    okta_ssws_lines.add(line_no)
                val = match.group("value")
                findings.append({
                    "file": rel_path,
                    "line": line_no,
                    "rule": rule_name,
                    "status": "IGNORED_PATH" if rel_path.startswith("tests/ignored/") else (
                        "IGNORED_VALUE" if val == "SOAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" else "MATCHED"
                    ),
                    "value_preview": val if len(val) <= 44 else f"{val[:24]}...{val[-10:]}",
                    "context": lines[line_no - 1].strip()[:90],
                })

        for match in RAW_OKTA_TOKEN_PATTERN.finditer(text):
            line_no = text.count("\n", 0, match.start("value")) + 1
            if line_no not in okta_ssws_lines:
                val = match.group("value")
                findings.append({
                    "file": rel_path,
                    "line": line_no,
                    "rule": "Okta SSWS Token (Unlabeled/No-Keyword Gap)",
                    "status": "UNLABELED_GAP",
                    "value_preview": val,
                    "context": lines[line_no - 1].strip()[:90],
                })

    return findings


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Validate Wiz Custom Secret Detection regex rules against repository test fixtures."
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output validation findings as formatted JSON",
    )
    args = parser.parse_args()

    repo_root = pathlib.Path(__file__).resolve().parent.parent
    findings = scan_repository(repo_root)

    if args.json:
        print(json.dumps(findings, indent=2))
        sys.exit(0)

    print(f"{'File':<32} | {'Line':>4} | {'Rule':<42} | {'Status':<14} | {'Value Preview'}")
    print("-" * 145)
    for f in findings:
        print(
            f"{f['file']:<32} | {f['line']:>4} | {f['rule']:<42} | {f['status']:<14} | {f['value_preview']}"
        )


if __name__ == "__main__":
    main()
