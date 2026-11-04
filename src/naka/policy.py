"""Policy: what Naka does when a rule fires.

Loaded from a TOML file (``--config``) or defaults. Every action is either
``block`` (stop it and tell the agent why) or ``warn`` (let it through, log it).
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

ACTIONS = {"block", "warn"}
# Rules where asking the user is a valid action (needs MCP elicitation support).
CONFIRMABLE = {"on_egress_after_injection", "on_untrusted_destination", "on_tainted_flow", "on_spread",
               "on_memory_poisoning", "on_memory_write"}

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
    on_egress_after_injection: str = "confirm"
    on_untrusted_destination: str = "confirm"  # an address/URL/ID from untrusted output used to change something
    on_spread: str = "block"              # a note from untrusted output, asking to be passed on, copied into a message
    on_memory_poisoning: str = "block"    # text from untrusted output written into the AI's memory or instructions
    on_memory_write: str = "confirm"      # memory/instructions changed after untrusted content (links, configs...)
    # When the app can't show confirmation prompts: "block" or "warn".
    confirm_fallback: str = "block"
    # Strict mode (CaMeL-like): any tool that changes something needs
    # confirmation once untrusted content has been read this session.
    confirm_after_untrusted: bool = False
    # Balanced default: only high-impact actions (payments, access, deletion,
    # execution...) need confirmation after untrusted content.
    confirm_sensitive_after_untrusted: bool = True
    # "trust": pin tools the first time a server lists them (trust on first
    # use). "confirm": list them, but ask the user before each tool's first call.
    on_first_use: str = "trust"
    trusted_tools: list[str] = field(default_factory=list)    # outputs never mark values as untrusted
    read_only_tools: list[str] = field(default_factory=list)  # never treated as changing something
    memory_tools: list[str] = field(default_factory=list)     # extra tools that write the AI's long-term memory
    # Second-opinion ML classifier: "off", "builtin", or a path to a model file.
    classifier: str = "off"
    classifier_action: str = "warn"    # "warn": label + lockdown; "block": withhold the output
    classifier_threshold: float | None = None   # None: the model's own (1% false alarms on validation)
    # Share data-flow state with the other servers started by the same app.
    shared_session: bool = True
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
            if key == "on_first_use" and value not in ("trust", "confirm"):
                raise ValueError("on_first_use must be 'trust' or 'confirm'")
            elif key in ("confirm_fallback", "classifier_action") and value not in ACTIONS:
                raise ValueError(f"{key} must be one of {sorted(ACTIONS)}, got {value!r}")
            elif key.startswith("on_") and key != "on_first_use":
                allowed = ACTIONS | ({"confirm"} if key in CONFIRMABLE else set())
                if value not in allowed:
                    raise ValueError(f"{key} must be one of {sorted(allowed)}, got {value!r}")
            setattr(policy, key, value)
        return policy
