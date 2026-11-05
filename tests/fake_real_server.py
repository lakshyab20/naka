"""Stand-in for the real servers in naka.evals.real, with real side effects
(files, HTTP, memory file, commands), for testing the harness offline."""

import json
import os
import subprocess
import sys
import urllib.request

kind = sys.argv[1]
root = sys.argv[2] if len(sys.argv) > 2 else "."
TOOLS = {
    "files": [{"name": "read_text_file", "description": "Read a file.", "inputSchema": {"type": "object"}},
              {"name": "write_file", "description": "Write a file.", "inputSchema": {"type": "object"}}],
    "fetch": [{"name": "fetch", "description": "Fetch a URL.", "inputSchema": {"type": "object"}}],
    "memory": [{"name": "create_entities", "description": "Create entities in the knowledge graph.",
                "inputSchema": {"type": "object"}}],
    "shell": [{"name": "start_process", "description": "Start a terminal process.", "inputSchema": {"type": "object"}}],
    "browser": [{"name": "puppeteer_navigate", "description": "Navigate to a URL.", "inputSchema": {"type": "object"}}],
}[kind]


def run(name, a):
    if name == "read_text_file":
        return open(a["path"]).read()
    if name == "write_file":
        open(a["path"], "w").write(a["content"])
        return "Successfully wrote to " + a["path"]
    if name == "fetch":
        return "Contents of " + a["url"] + ":\n" + urllib.request.urlopen(a["url"], timeout=10).read().decode()
    if name == "create_entities":
        with open(os.environ["MEMORY_FILE_PATH"], "a") as fh:
            for e in a["entities"]:
                fh.write(json.dumps(e) + "\n")
        return "created"
    if name == "start_process":
        return subprocess.run(a["command"], shell=True, capture_output=True, text=True, timeout=15).stdout
    if name == "puppeteer_navigate":
        exe = (a.get("launchOptions") or {}).get("executablePath")
        if exe:
            subprocess.run([exe])
        return "Navigated to " + a["url"]


for line in sys.stdin:
    m = json.loads(line)
    if "id" not in m:
        continue
    if m["method"] == "initialize":
        r = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}}, "serverInfo": {"name": kind, "version": "0"}}
    elif m["method"] == "tools/list":
        r = {"tools": TOOLS}
    else:
        p = m["params"]
        try:
            r = {"content": [{"type": "text", "text": run(p["name"], p.get("arguments") or {})}]}
        except Exception as exc:  # noqa: BLE001
            r = {"content": [{"type": "text", "text": f"error: {exc}"}], "isError": True}
    print(json.dumps({"jsonrpc": "2.0", "id": m["id"], "result": r}), flush=True)
