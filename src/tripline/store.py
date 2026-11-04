"""On-disk state: tool pins (for rug-pull detection) and the audit log.

Everything lives under ``$TRIPLINE_HOME`` (default ``~/.tripline``).
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from pathlib import Path


def home() -> Path:
    root = Path(os.environ.get("TRIPLINE_HOME", Path.home() / ".tripline"))
    root.mkdir(parents=True, exist_ok=True)
    return root


def tool_fingerprint(tool: dict) -> str:
    """Hash the parts of a tool definition the model reads."""
    material = {
        "name": tool.get("name"),
        "description": tool.get("description", ""),
        "inputSchema": tool.get("inputSchema", {}),
        "annotations": tool.get("annotations", {}),
    }
    blob = json.dumps(material, sort_keys=True, ensure_ascii=False).encode()
    return hashlib.sha256(blob).hexdigest()


class PinStore:
    """Trust-on-first-use pins for each server's tool definitions."""

    def __init__(self, server: str):
        self.server = server
        self.path = home() / "pins" / f"{_safe(server)}.json"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        data = self._read()
        self.pins: dict[str, dict] = data.get("tools", {})
        # Definitions that changed or were held back, waiting for a human to
        # approve them with `tripline pins approve`.
        self.pending: dict[str, dict] = data.get("pending", {})

    def _read(self) -> dict:
        if self.path.exists():
            return json.loads(self.path.read_text())
        return {}

    def save(self) -> None:
        with self._lock:
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(
                {"server": self.server, "tools": self.pins, "pending": self.pending}, indent=2))
            tmp.replace(self.path)

    def hold(self, tool: dict, reason: str) -> None:
        self.pending[tool["name"]] = {"tool": tool, "reason": reason}

    def approve(self, name: str) -> bool:
        entry = self.pending.pop(name, None)
        if entry is None:
            return False
        self.pin(entry["tool"])
        return True

    @property
    def is_new_server(self) -> bool:
        return not self.pins

    def pin(self, tool: dict) -> None:
        self.pins[tool["name"]] = {
            "sha256": tool_fingerprint(tool),
            "description": tool.get("description", ""),
            "pinned_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }

    def check(self, tool: dict) -> str:
        """Return 'match', 'changed' or 'unknown'."""
        pinned = self.pins.get(tool.get("name", ""))
        if pinned is None:
            return "unknown"
        return "match" if pinned["sha256"] == tool_fingerprint(tool) else "changed"


def _safe(name: str) -> str:
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in name)[:80] or "default"


def server_id(name: str | None, command: list[str]) -> str:
    if name:
        return name
    return "cmd-" + hashlib.sha256(" ".join(command).encode()).hexdigest()[:12]


class AuditLog:
    """Append-only JSONL log of every decision. Never logs raw secret values."""

    def __init__(self, server: str, path: Path | None = None):
        self.server = server
        self.path = path or home() / "audit.jsonl"
        self._lock = threading.Lock()

    def write(self, event: str, **fields) -> dict:
        record = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "server": self.server,
            "event": event,
            **fields,
        }
        with self._lock, open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        return record
