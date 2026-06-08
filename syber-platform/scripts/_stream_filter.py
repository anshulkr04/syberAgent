#!/usr/bin/env python3
"""Make `claude -p --output-format stream-json` human-readable.

Reads the JSONL event stream on stdin and prints ONLY:
  * assistant text  — what the agent says
  * a one-line marker per tool call (e.g. "  > syber_full_scan(localhost:3000)")
  * the final result block

Dropped: the raw JSON envelope, `thinking` blocks, `system` token-counter events,
and tool-result payloads. Non-JSON lines (warnings/banners) pass through untouched.
"""
import json
import sys


def _arg(inp: dict) -> str:
    for k in ("target", "url", "site", "host"):
        if inp.get(k):
            return str(inp[k])
    return ""


def main() -> int:
    for line in sys.stdin:
        line = line.rstrip("\n")
        if not line.strip():
            continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            print(line, flush=True)        # warnings / banners
            continue
        t = ev.get("type")
        if t == "assistant":
            for block in ev.get("message", {}).get("content", []):
                bt = block.get("type")
                if bt == "text" and block.get("text", "").strip():
                    print(block["text"], flush=True)
                elif bt == "tool_use":
                    name = block.get("name", "tool")
                    arg = _arg(block.get("input", {}) or {})
                    print(f"  > {name}({arg})" if arg else f"  > {name}", flush=True)
        elif t == "result":
            res = ev.get("result") or ""
            if res:
                print(f"\n=== result ===\n{res}", flush=True)
        # ignore: system, user (tool_result), and `thinking` content blocks
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
