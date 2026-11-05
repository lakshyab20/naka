"""`naka audit`: reads a server's lists and reports what it finds."""

import json
import sys
from pathlib import Path

from naka import audit

FAKE = str(Path(__file__).with_name("fake_audit_server.py"))
CLEAN = """
import json, sys
for line in sys.stdin:
    m = json.loads(line)
    if "id" not in m: continue
    if m["method"] == "initialize":
        r = {"protocolVersion": "2025-11-25", "capabilities": {"tools": {}}, "serverInfo": {"name": "slack"}}
    elif m["method"] == "tools/list":
        r = {"tools": [{"name": "send_message", "description": "Post a message.", "inputSchema": {"type": "object"}}]}
    else:
        r = {}
    print(json.dumps({"jsonrpc": "2.0", "id": m["id"], "result": r}), flush=True)
"""


def test_poisoned_server_is_reported():
    rep = audit.run_one({"name": "evil", "command": [sys.executable, "-I", FAKE]}, timeout=20)
    assert rep.status == "ok"
    assert rep.poisoned
    assert {"hidden-instructions", "lethal-trifecta", "mislabelled-read-only"} <= set(rep.flags)
    flagged = {t.name for t in rep.tools if t.findings}
    assert flagged == {"add_numbers"}


def test_clean_server_and_cross_server_mentions(tmp_path):
    clean = tmp_path / "clean.py"
    clean.write_text(CLEAN)
    reps = audit.audit([{"name": "evil", "command": [sys.executable, "-I", FAKE]},
                        {"name": "slack", "command": [sys.executable, "-I", str(clean)]}], workers=2, timeout=20)
    evil, slack = reps
    assert not slack.poisoned and slack.flags == []
    assert "mentions-other-tools" in evil.flags
    md = audit.to_markdown(reps)
    assert "| slack | 1 |" in md and "send_message" in md
    json.dumps(audit.to_json(reps))


def test_servers_that_fail_or_hang_are_not_findings():
    reps = audit.audit([{"name": "broken", "command": [sys.executable, "-c", "import sys; sys.exit(3)"]},
                        {"name": "silent", "command": [sys.executable, "-c", "import time; time.sleep(30)"]}],
                       workers=2, timeout=3)
    assert [r.status for r in reps] == ["failed", "timeout"]
    assert not any(r.flags for r in reps)


def test_capabilities_from_names():
    caps = audit.tool_caps
    assert caps({"name": "fetch_url"}) >= {"reads-outside-content", "sends-out"}
    assert "runs-commands" in caps({"name": "execute_command"})
    assert "deletes" in caps({"name": "deleteRecord"})
    assert caps({"name": "get_time"}) == set()


def test_entries_get_shared_placeholders(tmp_path):
    f = tmp_path / "s.json"
    f.write_text(json.dumps({"env": {"A": "1"}, "servers": [
        {"package": "x-mcp", "args": ["--y"], "env": {"B": "2"}}, {"kind": "pypi", "package": "y-mcp"}]}))
    a, b = audit.load_entries(str(f))
    assert a["command"] == ["npx", "-y", "x-mcp", "--y"] and a["env"] == {"A": "1", "B": "2"}
    assert b["command"] == ["uvx", "y-mcp"]
