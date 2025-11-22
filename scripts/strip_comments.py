#!/usr/bin/env python3
"""Strip full-line comments from selected source files.

Rules:
- For .py: remove lines where first non-whitespace char is '#'.
- For Dockerfile and files named Dockerfile* and files under docker/: remove lines starting with '#'.
- For .sql: remove lines starting with '--'.
- For .yaml/.yml: remove lines starting with '#'.
- For .sh: remove lines starting with '#' except keep shebang lines starting with '#!'.
- Do not touch Markdown (.md), templates (.j2), or other docs.

This script edits files in-place and prints a summary.
"""
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
patterns = [
    "**/*.py",
    "docker/**/Dockerfile*",
    "db/**/Dockerfile",
    "**/Dockerfile*",
    "**/*.sql",
    "**/*.yaml",
    "**/*.yml",
    "**/*.sh",
]

SKIP_DIRS = ["templates", "reports", ".git"]

modified = []

for pat in patterns:
    for p in ROOT.glob(pat):
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        if p.is_file():
            try:
                text = p.read_text(encoding="utf-8")
            except Exception:
                try:
                    text = p.read_text(encoding="latin-1")
                except Exception:
                    print(f"Skipping binary/unreadable: {p}")
                    continue

            lines = text.splitlines()
            new_lines = []
            changed = False
            suffix = p.suffix.lower()
            name = p.name
            for i, line in enumerate(lines):
                stripped = line.lstrip()
                if i == 0 and stripped.startswith("#!"):
                    new_lines.append(line)
                    continue
                if suffix == ".py":
                    if stripped.startswith("#"):
                        changed = True
                        continue
                elif suffix in {".yaml", ".yml"}:
                    if stripped.startswith("#"):
                        changed = True
                        continue
                elif suffix == ".sql":
                    if stripped.startswith("--"):
                        changed = True
                        continue
                elif suffix == ".sh":
                    if stripped.startswith("#"):
                        changed = True
                        continue
                else:
                    if name.startswith("Dockerfile") or "docker" in p.parts:
                        if stripped.startswith("#"):
                            changed = True
                            continue
                new_lines.append(line)
            if changed:
                p.write_text("\n".join(new_lines) + ("\n" if text.endswith("\n") else ""), encoding="utf-8")
                modified.append(str(p.relative_to(ROOT)))

print("Modified files (comments stripped):")
for m in modified:
    print(m)
print(f"Total modified: {len(modified)}")

if modified:
    sys.exit(0)
else:
    print("No files modified.")
    sys.exit(0)
