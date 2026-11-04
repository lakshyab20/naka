"""tripline install / uninstall on realistic config files."""

import json

import pytest

from tripline import install

DESKTOP = {"mcpServers": {
    "github": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"],
               "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_x"}},
    "remote": {"url": "https://mcp.example.com/mcp", "headers": {"Authorization": "Bearer abc"}},
    "legacy": {"url": "https://old.example.com/sse"},
    "off": {"command": "uvx", "args": ["thing"], "disabled": True},
}, "globalShortcut": "Ctrl+Space"}

CLAUDE_CODE = {"numStartups": 3, "mcpServers": {"fs": {"type": "stdio", "command": "npx", "args": ["fs"]}},
               "projects": {"/work/app": {"mcpServers": {"api": {"type": "http", "url": "https://api.example/mcp"}}},
                            "/work/empty": {"mcpServers": {}}}}

VSCODE = {"servers": {"git": {"type": "stdio", "command": "uvx", "args": ["mcp-server-git"]}}}


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("TRIPLINE_HOME", str(tmp_path / "th"))
    monkeypatch.setattr(install, "tripline_command", lambda: ["/opt/bin/tripline"])
    files = {}
    for name, data in (("desktop.json", DESKTOP), ("claude.json", CLAUDE_CODE), ("vscode.json", VSCODE)):
        p = tmp_path / name
        p.write_text(json.dumps(data, indent=2))
        files[name] = p
    return files


def test_wraps_local_and_remote_servers(env):
    p = env["desktop.json"]
    assert install.run(None, None, dry_run=False, yes=True, uninstall=False, config=str(p)) == 0
    cfg = json.loads(p.read_text())
    gh = cfg["mcpServers"]["github"]
    assert gh["command"] == "/opt/bin/tripline"
    assert gh["args"] == ["wrap", "--name", "github", "--", "npx", "-y", "@modelcontextprotocol/server-github"]
    assert gh["env"] == {"GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_x"}
    remote = cfg["mcpServers"]["remote"]
    assert remote["args"] == ["wrap", "--name", "remote", "--header", "Authorization: Bearer abc",
                              "--url", "https://mcp.example.com/mcp"] and "url" not in remote
    assert cfg["mcpServers"]["legacy"] == DESKTOP["mcpServers"]["legacy"]   # SSE: left alone
    assert cfg["mcpServers"]["off"] == DESKTOP["mcpServers"]["off"]         # disabled: left alone
    assert cfg["globalShortcut"] == "Ctrl+Space"                            # other settings untouched
    assert list(p.parent.glob("desktop.json.bak-tripline-*"))               # backup made


def test_uninstall_restores_exactly(env):
    p = env["desktop.json"]
    install.run(None, None, False, True, False, config=str(p))
    install.run(None, None, False, True, True, config=str(p))
    assert json.loads(p.read_text()) == DESKTOP


def test_install_is_idempotent(env):
    p = env["desktop.json"]
    install.run(None, None, False, True, False, config=str(p))
    once = p.read_text()
    install.run(None, None, False, True, False, config=str(p))
    assert p.read_text() == once


def test_claude_code_projects_and_types(env):
    p = env["claude.json"]
    install.run(None, None, False, True, False, config=str(p))
    cfg = json.loads(p.read_text())
    assert cfg["mcpServers"]["fs"]["type"] == "stdio" and cfg["mcpServers"]["fs"]["args"][-2:] == ["npx", "fs"]
    api = cfg["projects"]["/work/app"]["mcpServers"]["api"]
    assert api["type"] == "stdio" and api["args"][-2:] == ["--url", "https://api.example/mcp"]
    assert cfg["numStartups"] == 3
    install.run(None, None, False, True, True, config=str(p))
    assert json.loads(p.read_text()) == CLAUDE_CODE


def test_vscode_servers_key(env):
    p = env["vscode.json"]
    install.run(None, None, False, True, False, config=str(p))
    assert json.loads(p.read_text())["servers"]["git"]["command"] == "/opt/bin/tripline"


def test_dry_run_writes_nothing(env, capsys):
    p = env["desktop.json"]
    before = p.read_text()
    install.run(None, None, True, False, False, config=str(p))
    assert p.read_text() == before and "Dry run" in capsys.readouterr().out


def test_unwrap_without_saved_original(env):
    wrapped, _ = install.wrap_entry("x", {"url": "https://a.example/mcp", "headers": {"K": "v"}}, ["/t"])
    assert install._unwrap(wrapped) == {"url": "https://a.example/mcp", "headers": {"K": "v"}}
    wrapped, _ = install.wrap_entry("y", {"command": "node", "args": ["s.js", "--port", "1"]}, ["/t"])
    assert install._unwrap(wrapped) == {"command": "node", "args": ["s.js", "--port", "1"]}
