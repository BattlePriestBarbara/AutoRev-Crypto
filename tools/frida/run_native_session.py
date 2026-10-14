"""run_native_session.py - attach ONCE and load several hook scripts into the same session.

Why this exists next to frida_mcp.py: the root-concealment hook and the native profiler must
run against the *same* live process at the same time. frida-mcp's frida_run_hook loads exactly
one script per session, and unloading the concealment script would let the app's next root
check through. So this runner creates N scripts on one attach and keeps them loaded for the
whole capture window.

The JSONL it writes is byte-compatible with frida-mcp's EventSink, so
aggregate_native_profile.py consumes either source:

    {"kind": "send", "payload": {...}, "ts": "2026-10-12T12:00:00"}

Usage (arm64 real device, both layers, 30 s):

    D:\\frida\\.venv\\Scripts\\python.exe run_native_session.py ^
        --target 12345 ^
        --js D:\\frida\\hooks\\root_bypass_arm64.js ^
        --js D:\\frida\\hooks\\native_profile_arm64.js ^
        --seconds 30 ^
        --label native_profile_arm64 ^
        --arg seconds=30
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import frida

DEFAULT_OUT = r"D:\frida\out\scripts"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", required=True, help="pid or frida process name")
    parser.add_argument("--js", action="append", default=[], help="hook script path (repeatable)")
    parser.add_argument("--seconds", type=float, default=30.0, help="capture window")
    parser.add_argument("--out", default=DEFAULT_OUT, help="JSONL output directory")
    parser.add_argument("--label", default="native_session",
                        help="JSONL filename label (used by the aggregator glob)")
    parser.add_argument("--device", default=None,
                        help="frida device id/address (default: USB device)")
    parser.add_argument("--arg", action="append", default=[],
                        help="k=v constant exported as FRIDA_MCP_ARGS (repeatable, v is JSON)")
    parser.add_argument("--resume", action="store_true",
                        help="resume the process after loading")
    return parser.parse_args(argv)


def make_sink(jsonl_path: Path, stats: dict):
    def sink(message: dict, data: object = None) -> None:
        stats["total"] += 1
        kind = str(message.get("type") or "send")
        if kind == "error":
            description = str(message.get("description") or "script error")
            entry = {
                "kind": "script-error",
                "description": description,
                "stack": str(message.get("stack") or "")[:1200],
                "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
            }
            stats["errors"].append(description)
            print(f"[!] script error: {description}", flush=True)
        else:
            payload = message.get("payload")
            entry = {
                "kind": kind,
                "payload": payload,
                "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
            }
            if isinstance(payload, dict):
                label = str(payload.get("type") or payload.get("tag") or "")
                if label:
                    stats["by_type"][label] = stats["by_type"].get(label, 0) + 1
        with jsonl_path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")
    return sink


def resolve_device(spec: str | None):
    if spec and (":" in spec or spec not in ("usb", "local")):
        return frida.get_device_manager().add_remote_device(spec)
    return frida.get_usb_device(timeout=10)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    script_paths = [Path(p) for p in args.js]
    if not script_paths:
        print("[!] no --js provided")
        return 2
    for path in script_paths:
        if not path.is_file():
            print(f"[!] hook script not found: {path}")
            return 2

    constants: dict[str, object] = {}
    for item in args.arg:
        key, _, value = item.partition("=")
        try:
            constants[key] = json.loads(value)
        except json.JSONDecodeError:
            constants[key] = value

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    jsonl_path = out_dir / f"{time.strftime('%Y%m%d-%H%M%S')}_{args.label}.jsonl"
    stats: dict = {"total": 0, "errors": [], "by_type": {}}

    device = resolve_device(args.device)
    print(f"[i] device: {device}")
    target: object = args.target
    if str(args.target).isdigit():
        target = int(str(args.target))

    session = None
    loaded: list[str] = []
    try:
        session = device.attach(target)
        print(f"[i] attached to {target} (pid {getattr(session, 'pid', '?')})")
        prefix = ""
        if constants:
            prefix = "const FRIDA_MCP_ARGS = " + json.dumps(constants, ensure_ascii=False) + ";\n"
        for path in script_paths:
            script = session.create_script(prefix + path.read_text(encoding="utf-8"),
                                           name=f"native-session:{path.stem}")
            script.on("message", make_sink(jsonl_path, stats))
            script.load()
            loaded.append(path.stem)
            print(f"[+] loaded {path.name}")

        if args.resume:
            try:
                device.resume(int(str(args.target)))
            except Exception as exc:  # noqa: BLE001
                print(f"[!] resume failed: {exc}")

        print(f"[i] capturing for {args.seconds}s -> {jsonl_path}")
        deadline = time.monotonic() + args.seconds
        while time.monotonic() < deadline:
            time.sleep(0.25)
    finally:
        if session is not None:
            try:
                session.detach()
            except Exception:  # noqa: BLE001
                pass

    print(f"[=] loaded scripts : {loaded}")
    print(f"[=] messages       : {stats['total']} (script errors {len(stats['errors'])})")
    print(f"[=] by type        : {json.dumps(stats['by_type'], ensure_ascii=False)}")
    print(f"[=] jsonl          : {jsonl_path}")
    return 0 if stats["total"] else 3


if __name__ == "__main__":
    raise SystemExit(main())
