#!/usr/bin/env python3
"""
Validate Markdown links in the documentation.

- Scans docs/ recursively for .md files
- Ignores external URLs (http/https/mailto)
- Resolves relative links from each file location
- Detects broken targets and case-mismatch on files/dirs
- Exits non-zero if any broken links are found

Usage:
  python3 scripts/validate-doc-links.py [--root docs] [--verbose] [--ignore PATTERN ...]

Examples:
  python3 scripts/validate-doc-links.py --verbose
  python3 scripts/validate-doc-links.py --ignore docs/private/
"""
from __future__ import annotations

import argparse
import re
import sys
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

LINK_PATTERN = re.compile(r"!?(?:\[.*?\])\((.*?)\)")
CODE_FENCE_PATTERN = re.compile(r"^\s*```")
EXTERNAL_SCHEMES = ("http://", "https://", "mailto:", "tel:", "data:")

@dataclass
class LinkIssue:
    file: Path
    line_no: int
    link: str
    reason: str


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Validate Markdown links in docs/")
    p.add_argument("--root", default="docs", help="Root directory to scan (default: docs)")
    p.add_argument("--verbose", action="store_true", help="Verbose output")
    p.add_argument("--ignore", action="append", default=[], help="Ignore path prefix (can repeat)")
    return p.parse_args()


def has_unpublished_front_matter(path: Path) -> bool:
    """Detect Jekyll front matter with published: false."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return False
    if not text.startswith("---"):
        return False
    # Extract first front matter block
    end = text.find("\n---\n", 3)
    if end == -1:
        return False
    header = text[0 : end + 1]
    return "published:" in header and "published: false" in header


def iter_markdown_files(root: Path, ignore_prefixes: list[str]) -> Iterator[Path]:
    # Always ignore generated site and private docs
    default_ignores = [
        (root / "_site").as_posix(),
        (root / "private").as_posix(),
    ]
    prefixes = list(ignore_prefixes) + default_ignores
    for path in root.rglob("*.md"):
        rel = path.as_posix()
        if any(rel.startswith(prefix) for prefix in prefixes):
            continue
        if has_unpublished_front_matter(path):
            continue
        yield path


def is_external(link: str) -> bool:
    return link.startswith(EXTERNAL_SCHEMES)


def strip_anchor(link: str) -> str:
    # Remove fragment identifiers (e.g., README.md#section)
    return link.split("#", 1)[0]


def in_code_fence(state: dict, line: str) -> bool:
    if CODE_FENCE_PATTERN.match(line):
        state["code"] = not state.get("code", False)
    return state.get("code", False)


def exists_case_sensitive(path: Path) -> bool:
    # Validate existence with case sensitivity by checking each segment
    try:
        # Handle both absolute and relative paths
        if not path.exists():
            return False
        # Resolve to absolute for segment checks
        abs_path = path.resolve()
        parts = abs_path.parts
        # Start from filesystem root
        cur = Path(parts[0])
        for part in parts[1:]:
            try:
                names = {p.name for p in cur.iterdir()}
            except Exception:
                return False
            if part not in names:
                return False
            cur = cur / part
        return True
    except Exception:
        return False


def validate_file_links(file_path: Path, repo_root: Path) -> list[LinkIssue]:
    issues: list[LinkIssue] = []
    state = {"code": False}
    try:
        lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception as e:
        issues.append(LinkIssue(file=file_path, line_no=0, link="", reason=f"Failed to read file: {e}"))
        return issues

    for i, line in enumerate(lines, start=1):
        if in_code_fence(state, line):
            continue
        for match in LINK_PATTERN.finditer(line):
            raw_link = match.group(1).strip()
            if not raw_link or is_external(raw_link):
                continue
            target = strip_anchor(raw_link)
            # Ignore pure anchors
            if target == "":
                continue
            # Normalize and resolve relative to file path
            target_path = (file_path.parent / target).resolve()
            # Ensure target remains within repo
            try:
                target_path.relative_to(repo_root)
            except Exception:
                issues.append(LinkIssue(file=file_path, line_no=i, link=raw_link, reason="Link escapes repository root"))
                continue
            # Check existence and case sensitivity
            if not target_path.exists():
                issues.append(LinkIssue(file=file_path, line_no=i, link=raw_link, reason="Target does not exist"))
                continue
            if not exists_case_sensitive(target_path):
                issues.append(LinkIssue(file=file_path, line_no=i, link=raw_link, reason="Case mismatch on path"))
    return issues


def main() -> int:
    args = parse_args()
    repo_root = Path(__file__).resolve().parent.parent
    docs_root = (repo_root / args.root).resolve()
    if not docs_root.exists():
        print(f"Error: root '{docs_root}' not found", file=sys.stderr)
        return 2

    all_issues: list[LinkIssue] = []
    files = list(iter_markdown_files(docs_root, args.ignore))
    for md in files:
        issues = validate_file_links(md, repo_root)
        if args.verbose and issues:
            print(f"\n{md.relative_to(repo_root)}:")
            for iss in issues:
                print(f"  L{iss.line_no}: {iss.reason} → {iss.link}")
        all_issues.extend(issues)

    if all_issues:
        # Summary
        print(f"\nBroken links found: {len(all_issues)}")
        # Group by file
        by_file: dict[Path, list[LinkIssue]] = {}
        for iss in all_issues:
            by_file.setdefault(iss.file, []).append(iss)
        for f, items in sorted(by_file.items(), key=lambda kv: kv[0].as_posix()):
            print(f"- {f.relative_to(repo_root)}: {len(items)} issue(s)")
            for iss in items:
                print(f"    L{iss.line_no}: {iss.reason} → {iss.link}")
        return 1
    else:
        print("All links OK.")
        return 0


if __name__ == "__main__":
    sys.exit(main())
