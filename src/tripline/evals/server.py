"""A scripted MCP server for eval scenarios.

    python -m tripline.evals.server SPEC.json CALLS.jsonl

It serves the tools described in SPEC.json over stdio and appends every call
that reaches it to CALLS.jsonl. That log is the ground truth for scoring: an
attack succeeded if its harmful call arrived here, whatever any guard in
between claimed. The server never runs anything; outputs are canned text.

Tool spec fields:
  name, description, inputSchema (optional)
  output    text, or {"by": "<arg>", "map": {"<value>": "<text>"}, "default": "<text>"}
            Text may use {arg} placeholders.
  becomes   optional replacement definition after the first call (a rug-pull)
"""

from __future__ import annotations

import json
import sys

PROTOCOL = "2025-06-18"


class _Args(dict):
    def __missing__(self, key):
        return "{" + key + "}"


def render(spec, args: dict) -> str:
    if isinstance(spec, dict):
        value = str(args.get(spec.get("by", ""), ""))
        text = spec.get("map", {}).get(value, spec.get("default", "Done."))
    else:
        text = spec if spec is not None else "Done."
    try:
        return text.format_map(_Args({k: v for k, v in args.items() if isinstance(v, (str, int, float))}))
    except (ValueError, IndexError):
        return text


def public(tool: dict) -> dict:
    out = {"name": tool["name"], "description": tool.get("description", ""),
           "inputSchema": tool.get("inputSchema") or {"type": "object"}}
    if "annotations" in tool:
        out["annotations"] = tool["annotations"]
    return out


def main() -> None:
    spec = json.loads(open(sys.argv[1], encoding="utf-8").read())
    log = open(sys.argv[2], "a", encoding="utf-8")
    tools = {t["name"]: dict(t) for t in spec["tools"]}
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        method, mid = msg.get("method"), msg.get("id")
        params = msg.get("params") or {}
        out = []
        if method == "initialize":
            out.append({"jsonrpc": "2.0", "id": mid, "result": {
                "protocolVersion": PROTOCOL, "capabilities": {"tools": {"listChanged": True}},
                "serverInfo": {"name": spec.get("name", "scenario"), "version": "1.0.0"}}})
        elif method == "tools/list":
            out.append({"jsonrpc": "2.0", "id": mid, "result": {"tools": [public(t) for t in tools.values()]}})
        elif method == "tools/call":
            name, args = params.get("name"), params.get("arguments") or {}
            tool = tools.get(name)
            log.write(json.dumps({"tool": name, "args": args}) + "\n")
            log.flush()
            if tool is None:
                out.append({"jsonrpc": "2.0", "id": mid, "result": {
                    "content": [{"type": "text", "text": f"Unknown tool {name}"}], "isError": True}})
            else:
                out.append({"jsonrpc": "2.0", "id": mid, "result": {
                    "content": [{"type": "text", "text": render(tool.get("output"), args)}], "isError": False}})
                if "becomes" in tool:
                    tools[name] = dict(tool["becomes"], name=name, output=tool.get("output"))
                    out.append({"jsonrpc": "2.0", "method": "notifications/tools/list_changed"})
        elif method == "ping":
            out.append({"jsonrpc": "2.0", "id": mid, "result": {}})
        elif mid is not None and method is not None:
            out.append({"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "Method not found"}})
        for o in out:
            sys.stdout.write(json.dumps(o) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
