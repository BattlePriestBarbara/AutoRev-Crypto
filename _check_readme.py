#!/usr/bin/env python3
"""README gate: internal anchors, code fences, and leakage scan.

Three questions this answers, all offline and from the file itself:

  1. Does every internal ``](#anchor)`` link resolve to a heading in this README?
     GitHub's slug rule is reproduced here exactly: lowercase, drop everything that
     is not alphanumeric/space/hyphen/underscore, then spaces -> hyphens. Numeric
     section prefixes are therefore KEPT (``## 5. Toolchain & Scripts`` becomes
     ``#5-toolchain--scripts``, not ``#toolchain--scripts``) - which is the single
     most common way a hand-written table of contents silently rots.

  2. Are the fenced code blocks balanced, and does every ``mermaid`` fence have a
     matching close? An unbalanced fence swallows the rest of the document.

  3. Does any text that must never reach a public README appear in it anyway?
     The patterns below are this publication's red lines: the target's real
     identifier, its original class names, absolute build paths, the real IV
     constant, and any literal 64-hex digest.

Pure standard library.

    python _check_readme.py README.md
    python _check_readme.py README.md --fail-on-leak

Exit codes: 0 = clean, 1 = at least one finding.
"""
from __future__ import annotations

import argparse
import os
import re
import sys

# ---------------------------------------------------------------- slug rules
HEADING_RE = re.compile(r"^(#{1,6})[ \t]+(.*?)[ \t]*$")
LINK_RE = re.compile(r"\]\(#([^)]+)\)")
KEEP = re.compile(r"[^a-z0-9 \-_]")


def slug(heading_text: str) -> str:
    """GitHub's heading->anchor rule, including any numeric prefix."""
    text = heading_text.replace("`", "").lower()
    text = KEEP.sub("", text)
    return text.replace(" ", "-")


# ------------------------------------------------------------------ red lines
# Patterns and their loader live in `_scan_leaks.py` + `_leak_patterns.txt`, NOT
# here. A redaction checker that hard-codes the identifiers it checks for leaks
# them the moment the checker is published, so the real values stay outside
# version control (see `_leak_patterns.example.txt` for the documented shapes).
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _scan_leaks import DEFAULT_PATTERNS, load_patterns  # noqa: E402



def outside_fences(lines: list[str]) -> list[tuple[int, str]]:
    """Line number plus content for every line that is NOT inside a fence."""
    result: list[tuple[int, str]] = []
    in_fence = False
    for number, line in enumerate(lines, start=1):
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
            continue
        if not in_fence:
            result.append((number, line))
    return result


def fence_report(lines: list[str]) -> tuple[list[str], int, int]:
    """Return findings, mermaid-fence count and total-fence count."""
    findings: list[str] = []
    fences = 0
    mermaid = 0
    for line in lines:
        if line.lstrip().startswith("```"):
            fences += 1
            if line.strip().lower().startswith("```mermaid"):
                mermaid += 1
    if fences % 2:
        findings.append(f"unbalanced code fences: {fences} markers (must be even)")
    if mermaid == 0:
        findings.append("no mermaid fence found (the pipeline diagrams are missing)")
    return findings, mermaid, fences


def anchor_report(lines: list[str]) -> tuple[list[str], int, int]:
    """Resolve every ``](#anchor)`` link against the headings outside code fences."""
    findings: list[str] = []

    headings: set[str] = set()
    for _, line in outside_fences(lines):
        match = HEADING_RE.match(line)
        if match:
            headings.add(slug(match.group(2)))

    links: list[str] = []
    for _, line in outside_fences(lines):
        links.extend(match.group(1) for match in LINK_RE.finditer(line))
    links = sorted(set(links))

    for link in links:
        if link not in headings:
            findings.append(f"unresolved anchor: #{link}")
    return findings, len(links), len(headings)


def leak_report(text: str, patterns: list) -> list[str]:
    findings: list[str] = []
    for label, pattern in patterns:
        hits = pattern.findall(text)
        if hits:
            findings.append(f"leak pattern {label!r} matched {len(hits)} time(s)")
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("path", help="README file to check")
    parser.add_argument("--patterns", default=DEFAULT_PATTERNS,
                        help="redaction pattern file (default: ./_leak_patterns.txt)")
    parser.add_argument("--fail-on-leak", action="store_true",
                        help="treat a leak finding as a failure (default: report only)")
    args = parser.parse_args(argv)

    with open(args.path, encoding="utf-8") as handle:
        text = handle.read()
    lines = text.splitlines()

    patterns = load_patterns(args.patterns)
    fence_findings, mermaid, fences = fence_report(lines)
    anchor_findings, links, headings = anchor_report(lines)
    leak_findings = leak_report(text, patterns)

    print(f"file     : {args.path}")
    print(f"lines    : {len(lines)}")
    print(f"headings : {headings}")
    print(f"anchors  : {links} internal links")
    print(f"fences   : {fences} markers, {mermaid} mermaid blocks")
    print(f"rules    : {len(patterns)} redaction rule(s) from {os.path.basename(args.patterns)}")
    print()
    if not patterns:
        print("NOTE  no redaction rules were available, so the leak scan did not run. "
              "That is a no-op, not a pass.")

    hard = anchor_findings + fence_findings
    for finding in hard:
        print(f"FAIL  {finding}")
    for finding in leak_findings:
        print(f"{'FAIL' if args.fail_on_leak else 'WARN'}  {finding}")
    if not hard and not leak_findings:
        print("PASS  anchors resolve, fences balanced, no leak pattern matched")

    return 1 if hard or (args.fail_on_leak and leak_findings) else 0


if __name__ == "__main__":
    sys.exit(main())

