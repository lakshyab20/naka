"""Policy: what Tripline does when a rule fires.

Loaded from a TOML file (``--config``) or defaults. Every action is either
``block`` (stop it and tell the agent why) or ``warn`` (let it through, log it).
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

ACTIONS = {"block", "warn"}

# Tool names that look like they move data out of the machine. Used for
# lockdown after untrusted content has reached the model.
DEFAULT_EGRESS_HINTS = (
    "send", "post", "email", "mail", "upload", "webhook", "http", "request",
    "publish", "share", "comment", "create_issue", "message", "tweet", "slack",
    "write_remote", "push", "fetch", "browse", "open_url", "url", "download",
    "curl", "wget", "web", "search", "query", "graphql", "api", "dns", "resolve",
    "sync", "backup", "export", "notify", "submit", "invite", "reply", "forward",
)


@dataclass
class Policy:
    on_poisoned_tool: str = "block"       # suspicious instructions in a tool definition
    on_rug_pull: str = "block"            # tool definition changed after it was pinned
    on_new_tool: str = "warn"             # tool appeared after first pin (warn = pin it)
    on_injected_response: str = "block"   # tool output contains instructions for the model
    on_secret_in_args: str = "block"      # agent sends a credential in tool arguments
    on_secret_in_response: str = "warn"   # tool output contains a credential
    on_pii_in_args: str = "warn"
    on_tainted_flow: str = "block"        # value read from tool A is sent out via tool B
    on_egress_after_injection: str = "block"
    threshold: int = 3
    # Text larger than this in one message is blocked rather than scanned, to
    # bound the work a hostile server can force (scanning is ~1 s per MB).
    max_scan_bytes: int = 8_000_000
    # After an injection attempt: "egress" blocks tools that can send data out
    # (by name, or any call carrying a URL, host, IP or email); "all" blocks
    # every tool call that isn't allow-listed until the session restarts.
    lockdown_scope: str = "egress"
    egress_tools: list[str] = field(default_factory=list)
    egress_hints: list[str] = field(default_factory=lambda: list(DEFAULT_EGRESS_HINTS))
    allow_tools: list[str] = field(default_factory=list)  # never inspected
    deny_tools: list[str] = field(default_factory=list)   # always blocked

    def is_egress(self, tool: str) -> bool:
        if tool in self.egress_tools:
            return True
        lowered = tool.lower()
        return any(h in lowered for h in self.egress_hints)

    @classmethod
    def load(cls, path: str | os.PathLike | None) -> "Policy":
        policy = cls()
        if not path:
            return policy
        data = tomllib.loads(Path(path).read_text())
        section = data.get("policy", data)
        for key, value in section.items():
            if not hasattr(policy, key):
                raise ValueError(f"Unknown policy key: {key}")
            if key == "lockdown_scope" and value not in ("egress", "all"):
                raise ValueError("lockdown_scope must be 'egress' or 'all'")
            if key.startswith("on_") and value not in ACTIONS:
                raise ValueError(f"{key} must be one of {sorted(ACTIONS)}, got {value!r}")
            setattr(policy, key, value)
        return policy
