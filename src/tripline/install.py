"""`tripline install` / `tripline uninstall`: wrap every MCP server in your apps' configs.

    tripline install --dry-run      # show what would change
    tripline install                # wrap, after a backup of each file
    tripline uninstall              # put every config back the way it was

Each server entry is rewritten so the app starts `tripline wrap --name <name>
-- <original command>` (or `--url <original url>` for remote servers). The
original entry is saved, so uninstall restores it exactly. Close the apps
first: some of them rewrite their config while running.
"""

from __future__ import annotations

import copy
import difflib
import json
import os
import platform
import shutil
import sys
import time
from pathlib import Path

from .store import home


def client_configs(project: Path | None = None) -> dict[str, Path]:
    """Known config files for each app, for this OS."""
    h = Path.home()
    system = platform.system()
    if system == "Darwin":
        desktop = h / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
    elif system == "Windows":
        desktop = Path(os.environ.get("APPDATA", h / "AppData" / "Roaming")) / "Claude" / "claude_desktop_config.json"
    else:
        desktop = h / ".config" / "Claude" / "claude_desktop_config.json"
    paths = {
        "claude-desktop": desktop,
        "claude-code": h / ".claude.json",
        "cursor": h / ".cursor" / "mcp.json",
        "windsurf": h / ".codeium" / "windsurf" / "mcp_config.json",
    }
    if project:
        paths.update({"claude-code-project": project / ".mcp.json",
                      "cursor-project": project / ".cursor" / "mcp.json",
                      "vscode-project": project / ".vscode" / "mcp.json"})
    return paths


def tripline_command() -> list[str]:
    """How an app should start Tripline. Apps often have a minimal PATH, so be absolute."""
    exe = shutil.which("tripline")
    return [str(Path(exe).resolve())] if exe else [sys.executable, "-m", "tripline"]


def _server_maps(config: dict):
    """Yield every {name: server} map in a config (top level, and Claude Code projects)."""
    for key in ("mcpServers", "servers"):
        if isinstance(config.get(key), dict):
            yield key, config[key]
    projects = config.get("projects")
    if isinstance(projects, dict):
        for proj, data in projects.items():
            if isinstance(data, dict) and isinstance(data.get("mcpServers"), dict) and data["mcpServers"]:
                yield f"projects/{proj}", data["mcpServers"]


def is_wrapped(entry: dict) -> bool:
    cmd = entry.get("command")
    args = entry.get("args") or []
    if not isinstance(cmd, str) or not isinstance(args, list):
        return False
    base = Path(cmd).name.lower().removesuffix(".exe")
    return (base == "tripline" and args[:1] == ["wrap"]) or ("tripline" in args and "wrap" in args and "-m" in args)


def wrap_entry(name: str, entry: dict, tripline: list[str]) -> tuple[dict | None, str]:
    """(new entry or None to leave alone, explanation)."""
    if not isinstance(entry, dict):
        return None, "not a server entry"
    if is_wrapped(entry):
        return None, "already protected"
    if entry.get("disabled"):
        return None, "disabled"
    command, args = tripline[0], tripline[1:] + ["wrap", "--name", name]
    if isinstance(entry.get("command"), str):
        new = {k: v for k, v in entry.items() if k not in ("command", "args")}
        new["command"] = command
        new["args"] = args + ["--", entry["command"], *[str(a) for a in entry.get("args") or []]]
        return new, "local server"
    url = entry.get("url") or entry.get("serverUrl")
    if isinstance(url, str):
        if entry.get("type") == "sse" or url.rstrip("/").endswith("/sse"):
            return None, "legacy SSE transport isn't supported yet"
        for key, value in (entry.get("headers") or {}).items():
            args += ["--header", f"{key}: {value}"]
        new = {k: v for k, v in entry.items() if k not in ("url", "serverUrl", "headers", "type")}
        if "type" in entry:
            new["type"] = "stdio"
        new["command"], new["args"] = command, args + ["--url", url]
        return new, "remote server"
    return None, "unknown server format"


def _backup_store() -> Path:
    return home() / "install-originals.json"


def _load_originals() -> dict:
    p = _backup_store()
    return json.loads(p.read_text()) if p.exists() else {}


def _save_originals(data: dict) -> None:
    p = _backup_store()
    tmp = p.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)  # may hold auth headers
    with os.fdopen(fd, "w") as fh:
        json.dump(data, fh, indent=2)
    tmp.replace(p)


def plan(path: Path, tripline: list[str], uninstall: bool = False) -> tuple[dict, dict, list[str]]:
    """(old config, new config, notes) for one file. Nothing is written."""
    old = json.loads(path.read_text(encoding="utf-8"))
    new = copy.deepcopy(old)
    notes = []
    originals = _load_originals().get(str(path), {})
    for where, servers in _server_maps(new):
        for name, entry in list(servers.items()):
            key = f"{where}/{name}"
            if uninstall:
                if isinstance(entry, dict) and is_wrapped(entry):
                    servers[name] = originals.get(key) or _unwrap(entry)
                    notes.append(f"  restore  {name}")
                continue
            wrapped, why = wrap_entry(name, entry, tripline)
            if wrapped is None:
                notes.append(f"  skip     {name}: {why}")
            else:
                servers[name] = wrapped
                notes.append(f"  protect  {name} ({why})")
    return old, new, notes


def _unwrap(entry: dict) -> dict:
    """Rebuild an entry from Tripline's arguments when no saved original exists."""
    args = list(entry.get("args") or [])
    rest = args[args.index("wrap") + 1:] if "wrap" in args else []
    restored = {k: v for k, v in entry.items() if k not in ("command", "args")}
    if "--" in rest:
        cmd = rest[rest.index("--") + 1:]
        restored["command"], restored["args"] = cmd[0], cmd[1:]
    elif "--url" in rest:
        restored.pop("type", None)
        restored["url"] = rest[rest.index("--url") + 1]
        headers = {}
        for i, a in enumerate(rest):
            if a == "--header" and i + 1 < len(rest):
                k, _, v = rest[i + 1].partition(":")
                headers[k.strip()] = v.strip()
        if headers:
            restored["headers"] = headers
    return restored


def apply(path: Path, old: dict, new: dict) -> Path:
    stamp = time.strftime("%Y%m%d-%H%M%S")
    backup = path.with_name(f"{path.name}.bak-tripline-{stamp}")
    shutil.copy2(path, backup)
    originals = _load_originals()
    saved = originals.setdefault(str(path), {})
    for where, servers in _server_maps(old):
        for name, entry in servers.items():
            if isinstance(entry, dict) and not is_wrapped(entry):
                saved[f"{where}/{name}"] = entry
    _save_originals(originals)
    tmp = path.with_name(path.name + ".tripline-tmp")
    tmp.write_text(json.dumps(new, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    os.chmod(tmp, path.stat().st_mode & 0o777)
    tmp.replace(path)
    return backup


def run(apps: list[str] | None, project: str | None, dry_run: bool, yes: bool, uninstall: bool,
        config: str | None = None) -> int:
    targets = {"custom": Path(config).expanduser()} if config else client_configs(Path(project) if project else None)
    if apps:
        targets = {k: v for k, v in targets.items() if k in apps or k.split("-project")[0] in apps}
    tripline = tripline_command()
    changes = []
    for app, path in targets.items():
        if not path.exists():
            continue
        try:
            old, new, notes = plan(path, tripline, uninstall)
        except (ValueError, OSError) as exc:
            print(f"{app}: can't read {path}: {exc}")
            continue
        print(f"{app}: {path}")
        print("\n".join(notes) or "  no MCP servers")
        if new != old:
            changes.append((app, path, old, new))
    if not changes:
        print("\nNothing to change.")
        return 0
    if dry_run:
        for app, path, old, new in changes:
            diff = difflib.unified_diff(json.dumps(old, indent=2).splitlines(), json.dumps(new, indent=2).splitlines(),
                                        str(path), str(path) + " (after)", lineterm="", n=1)
            print("\n" + "\n".join(diff))
        print("\nDry run: nothing was written.")
        return 0
    if not yes:
        verb = "Restore" if uninstall else "Protect"
        if not sys.stdin.isatty() or input(f"\n{verb} these servers? Close the apps first. [y/N] ").strip().lower() != "y":
            print("Cancelled.")
            return 1
    for app, path, old, new in changes:
        backup = apply(path, old, new)
        print(f"updated {path} (backup: {backup.name})")
    print("Restart the apps to apply." if not uninstall else "Restored. Restart the apps to apply.")
    return 0
