"""aggregate_native_profile.py - turn the native-layer Frida evidence into the ARM64 profile JSON.

Input : the JSONL evidence written by frida-mcp (or dump_dex.py) while running
        D:\\frida\\hooks\\native_profile_arm64.js (and optionally root_bypass_arm64.js).
Output: D:\\Palantir_Research\\data\\processed\\apk_native_profile_arm64.json

The aggregator is deliberately read-only and stdlib-only: it never touches the device, and it
records what it could NOT read (malformed lines, script errors, capped event classes) instead
of silently reporting an empty section.

    python aggregate_native_profile.py --glob "D:\\frida\\out\\scripts\\*native_profile_arm64*.jsonl"
    python aggregate_native_profile.py --in D:\\frida\\out\\scripts --in D:\\frida\\out
"""

from __future__ import annotations

import argparse
import glob
import hashlib
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_IN = r"D:\frida\out\scripts"
DEFAULT_OUT = r"D:\Palantir_Research\data\processed\apk_native_profile_arm64.json"
DEFAULT_GLOB = "*native_profile_arm64*.jsonl"

GROUP_TYPES = (
    "profile_start", "module", "export_index", "jni_onload", "dlopen", "file", "prop",
    "socket", "socketpair", "connect", "net_io", "socket_close", "mmap", "mprotect",
    "heartbeat", "summary", "hooks_ready", "hook_fail",
)


def load_records(paths: list[Path]) -> tuple[list[dict], list[dict], list[dict], list[dict]]:
    """Return (records, malformed, script_errors, file_report)."""
    records: list[dict] = []
    malformed: list[dict] = []
    script_errors: list[dict] = []
    file_report: list[dict] = []

    for path in paths:
        raw = path.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        kept = 0
        try:
            text = raw.decode("utf-8", errors="replace")
        except Exception as exc:  # noqa: BLE001
            file_report.append({"path": str(path), "sha256_16": digest[:16], "error": str(exc)})
            continue
        for line_no, line in enumerate(text.splitlines(), 1):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                malformed.append({"path": path.name, "line": line_no, "text": line[:200]})
                continue
            kind = entry.get("kind")
            if kind == "script-error":
                script_errors.append({
                    "path": path.name, "description": entry.get("description"),
                    "stack": (entry.get("stack") or "")[:400],
                })
                continue
            payload = entry.get("payload")
            if not isinstance(payload, dict):
                continue
            record = dict(payload)
            record["_ts"] = entry.get("ts")
            record["_source"] = path.name
            records.append(record)
            kept += 1
        file_report.append({
            "path": str(path), "sha256_16": digest[:16], "bytes": len(raw), "records": kept,
        })
    return records, malformed, script_errors, file_report


def by_type(records: list[dict]) -> dict[str, list[dict]]:
    grouped: dict[str, list[dict]] = defaultdict(list)
    for record in records:
        grouped[str(record.get("type") or "unknown")].append(record)
    return dict(grouped)


def counter_from(groups: dict[str, list[dict]], key: str) -> dict[str, int]:
    """Merge counters from heartbeat/summary records.

    heartbeat carries a top-level "counters" map, summary nests the same data under
    "data.counts" - both shapes are accepted so a capture that produced only one of them
    still yields totals.
    """
    merged: Counter = Counter()
    for record in groups.get(key, []):
        for candidate in (record.get("counters"),
                          (record.get("data") or {}).get("counts") if isinstance(record.get("data"), dict) else None):
            if isinstance(candidate, dict):
                merged.update({str(k): int(v) for k, v in candidate.items() if isinstance(v, int)})
    return dict(sorted(merged.items(), key=lambda kv: -kv[1]))


def dropped_from(groups: dict[str, list[dict]]) -> dict[str, int]:
    merged: Counter = Counter()
    for record in groups.get("heartbeat", []) + groups.get("summary", []):
        for candidate in (record.get("dropped"),
                          (record.get("data") or {}).get("dropped") if isinstance(record.get("data"), dict) else None):
            if isinstance(candidate, dict):
                merged.update({str(k): int(v) for k, v in candidate.items() if isinstance(v, int)})
    return dict(sorted(merged.items(), key=lambda kv: -kv[1]))


def build_profile(records: list[dict], groups: dict[str, list[dict]],
                  file_report: list[dict], malformed: list[dict],
                  script_errors: list[dict]) -> dict:
    file_events = groups.get("file", [])
    connects = groups.get("connect", [])
    net_io = groups.get("net_io", [])
    mmaps = groups.get("mmap", [])
    mprotects = groups.get("mprotect", [])
    props = groups.get("prop", [])
    modules = groups.get("module", [])

    class_hist = Counter(str(e.get("cls")) for e in file_events)
    path_hist = Counter(str(e.get("path")) for e in file_events)
    op_hist = Counter(str(e.get("op")) for e in file_events)

    endpoints = Counter()
    unix_paths = Counter()
    for record in connects:
        peer = record.get("peer") or {}
        if peer.get("ip"):
            endpoints[f"{peer['ip']}:{peer.get('port')}"] += 1
        elif peer.get("path"):
            unix_paths[str(peer["path"])] += 1

    io_by_op = Counter(str(e.get("op")) for e in net_io)

    latest_summary = groups.get("summary", [])[-1] if groups.get("summary") else {}
    summary_data = latest_summary.get("data") if isinstance(latest_summary.get("data"), dict) else {}
    java_entry_hits = {}
    if isinstance(summary_data.get("java_entry_hits"), dict):
        java_entry_hits = summary_data["java_entry_hits"]

    timeline: list[dict] = []
    for record in records:
        rtype = record.get("type")
        if rtype == "connect":
            peer = record.get("peer") or {}
            timeline.append({
                "t_ms": record.get("t_ms"), "type": rtype,
                "key": peer.get("ip") or peer.get("path") or peer.get("af"),
                "port": peer.get("port"), "ret": record.get("ret"),
            })
        elif rtype == "file" and record.get("cls") in ("root", "proc", "frida", "app"):
            timeline.append({
                "t_ms": record.get("t_ms"), "type": rtype, "key": record.get("path"),
                "op": record.get("op"), "cls": record.get("cls"),
            })
        elif rtype in ("mmap", "mprotect", "jni_onload", "dlopen"):
            timeline.append({
                "t_ms": record.get("t_ms"), "type": rtype,
                "key": record.get("module") or record.get("path") or record.get("ret"),
                "prot": record.get("prot"), "len": record.get("len"),
            })
    timeline.sort(key=lambda item: (item.get("t_ms") if item.get("t_ms") is not None else -1))

    return {
        "environment": groups.get("profile_start", []),
        "hooks_ready": groups.get("hooks_ready", []),
        "hook_failures": groups.get("hook_fail", []),
        "counters": counter_from(groups, "heartbeat") or counter_from(groups, "summary"),
        "dropped_events": dropped_from(groups),
        "heartbeats": len(groups.get("heartbeat", [])),
        "packer": {
            "modules": modules,
            "export_index": groups.get("export_index", []),
            "jni_onload": groups.get("jni_onload", []),
            "dlopen": groups.get("dlopen", []),
            "java_entry_hits": dict(sorted(java_entry_hits.items(), key=lambda kv: -kv[1])[:120]),
        },
        "files": {
            "events": file_events,
            "by_class": dict(class_hist.most_common()),
            "by_op": dict(op_hist.most_common()),
            "top_paths": [{"path": p, "count": c} for p, c in path_hist.most_common(60)],
            "root_probes": [e for e in file_events if e.get("cls") == "root"],
            "proc_reads": [e for e in file_events if e.get("cls") == "proc"],
            "app_files": [e for e in file_events if e.get("cls") == "app"],
        },
        "network": {
            "sockets": groups.get("socket", []) + groups.get("socketpair", []),
            "connections": connects,
            "endpoints": dict(endpoints.most_common()),
            "unix_paths": dict(unix_paths.most_common()),
            "io_by_op": dict(io_by_op.most_common()),
            "io": net_io,
        },
        "memory": {
            "mmap_events": mmaps,
            "mprotect_events": mprotects,
            "mmap_total": len(mmaps),
            "mprotect_exec_total": len(mprotects),
        },
        "properties": props,
        "timeline": timeline[:400],
        "timeline_total": len(timeline),
        "evidence_files": file_report,
        "integrity": {
            "records": len(records),
            "malformed_lines": malformed,
            "script_errors": script_errors,
            "any_events": len(records) > 0,
            "warning": (None if records else
                        "no send() payload was captured: the hook never fired, the target was "
                        "not attached, or the JSONL glob matched the wrong file"),
        },
    }


def summarise(profile: dict) -> list[str]:
    integrity = profile["integrity"]
    counters = profile.get("counters") or {}
    packer = profile["packer"]
    lines = [
        "=== apk_native_profile_arm64 ===",
        f"records       : {integrity['records']} (malformed {len(integrity['malformed_lines'])}, "
        f"script errors {len(integrity['script_errors'])})",
        f"arch observed : {profile['profile'].get('arch_observed')}",
        f"app modules   : {len(packer['modules'])}",
        f"JNI_OnLoad    : {len(packer['jni_onload'])}",
        f"dlopen        : {len(packer['dlopen'])}",
        f"file events   : {sum(profile['files']['by_class'].values())} "
        f"by class {profile['files']['by_class']}",
        f"root probes   : {len(profile['files']['root_probes'])}",
        f"connections   : {len(profile['network']['connections'])} "
        f"endpoints {list(profile['network']['endpoints'])[:5]}",
        f"net I/O       : {profile['network']['io_by_op']}",
        f"mmap/mprotect : {profile['memory']['mmap_total']}/{profile['memory']['mprotect_exec_total']}",
        f"props read    : {len(profile['properties'])}",
        f"top counters  : {list(counters.items())[:8]}",
        f"dropped       : {profile['dropped_events']}",
    ]
    if "root_hiding" in profile:
        lines.append(f"root hiding   : {profile['root_hiding']['by_type']}")
    if integrity["warning"]:
        lines.append(f"WARNING       : {integrity['warning']}")
    return lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--glob", dest="patterns", action="append", default=[],
                        help=f"JSONL glob (default dir uses {DEFAULT_GLOB})")
    parser.add_argument("--in", dest="dirs", action="append", default=[],
                        help="directory to scan for the default JSONL pattern")
    parser.add_argument("--out", default=DEFAULT_OUT, help="profile JSON destination")
    args = parser.parse_args(argv)

    patterns = list(args.patterns)
    dirs = list(args.dirs) or ([DEFAULT_IN] if not patterns else [])

    paths: list[Path] = []
    for pattern in patterns:
        paths.extend(Path(p) for p in glob.glob(pattern))
    for directory in dirs:
        base = Path(directory)
        if not base.is_dir():
            print(f"[!] not a directory: {base}", file=sys.stderr)
            continue
        paths.extend(sorted(base.glob(DEFAULT_GLOB)))

    seen: set[str] = set()
    unique: list[Path] = []
    for path in paths:
        key = str(path.resolve())
        if key in seen or not path.is_file():
            continue
        seen.add(key)
        unique.append(path)

    if not unique:
        print("[!] no JSONL matched. Run the hook first (frida_run_hook / dump_dex.py), then "
              f"pass --glob or --in. Looked for '{DEFAULT_GLOB}' in {dirs or patterns}",
              file=sys.stderr)
        return 2

    records, malformed, script_errors, file_report = load_records(unique)
    groups = by_type(records)
    profile = build_profile(records, groups, file_report, malformed, script_errors)
    profile["profile"] = {
        "name": "apk_native_profile_arm64",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "generator": "aggregate_native_profile.py",
        "expects_arch": "arm64",
        "arch_observed": sorted({str(r.get("arch")) for r in groups.get("profile_start", [])}),
        "hook": r"D:\frida\hooks\native_profile_arm64.js",
        "sources": [str(p) for p in unique],
    }

    root_events = [r for r in records
                   if str(r.get("type", "")).startswith(("root_hide", "root_bypass"))]
    if root_events:
        profile["root_hiding"] = {
            "events": root_events,
            "by_type": dict(Counter(str(r.get("type")) for r in root_events).most_common()),
        }

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(profile, indent=2, ensure_ascii=False), encoding="utf-8")

    for line in summarise(profile):
        print(line)
    print(f"[=] written: {out} ({out.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
