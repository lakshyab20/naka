"""`naka audit`: check MCP servers before you trust them.

    naka audit -- npx -y @modelcontextprotocol/server-filesystem /tmp
    naka audit --servers servers.json --json out.json --md out.md

Starts each server, asks only for its lists (tools, prompts, resources and the
handshake's instructions), and never calls a tool. Then it reports:

- hidden instructions for the AI in any definition (tool poisoning), using the
  same detectors as the firewall
- tools that mention another server's tools (cross-server shadowing)
- what the server can do: read outsider-written content, read private data,
  send data out, run commands, change or delete things
- "lethal trifecta" servers: outsider content, private data and a way out in
  one install, so one injected message can steal data with no other server
- tools whose read-only label contradicts their name
- how much of the AI's context the definitions use up

Capabilities are inferred from tool names and descriptions, so they're a
rough guide, not a verdict. Servers run with an empty home folder and no real
credentials; run untrusted ones in a throwaway machine (the public scan uses
GitHub Actions).
"""

from __future__ import annotations

import json
import os
import queue
import re
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from pathlib import Path

from . import __version__
from . import detectors as d
from .firewall import collect_strings
from .policy import Policy

PROTOCOL = "2025-11-25"
THRESHOLD = Policy().threshold

# Words in a tool's name (split on _ - . and camelCase) that suggest what it does.
UNTRUSTED_IN = {"fetch", "browse", "browser", "navigate", "scrape", "crawl", "search", "web", "url",
                "page", "webpage", "website", "screenshot", "snapshot", "email", "emails", "inbox", "mail",
                "gmail", "message", "messages", "issue", "issues", "comment", "comments", "pull", "pr",
                "ticket", "tickets", "feed", "rss", "transcript", "tweet", "tweets", "history",
                "conversation", "conversations", "thread", "threads", "notification", "notifications",
                "event", "events", "error", "errors", "review", "reviews", "post", "posts", "chat",
                "channel", "dm", "replies", "html", "markdown", "scrape", "extract", "youtube", "reddit"}
PRIVATE = {"file", "files", "directory", "directories", "dir", "folder", "database", "query", "sql",
           "table", "tables", "db", "drive", "doc", "docs", "document", "documents", "note", "notes",
           "calendar", "contact", "contacts", "repo", "repository", "repositories", "secret", "secrets",
           "env", "customer", "customers", "payment", "payments", "invoice", "invoices", "balance",
           "account", "accounts", "memory", "memories", "entities", "bucket", "buckets", "object",
           "objects", "log", "logs", "credential", "credentials", "key", "keys", "vault", "user", "users",
           "record", "records", "collection", "collections", "spreadsheet", "sheet", "sheets", "code"}
EXEC = {"exec", "execute", "shell", "command", "commands", "terminal", "bash", "eval", "evaluate",
        "script", "spawn", "process", "powershell", "cmd", "sandbox", "interpreter", "repl"}
DESTRUCTIVE = {"delete", "remove", "drop", "destroy", "truncate", "purge", "kill", "terminate", "wipe",
               "rm", "uninstall", "revoke", "cancel", "refund", "archive", "reset", "erase", "clear"}
WRITE = {"write", "create", "update", "edit", "set", "put", "insert", "add", "move", "rename", "modify",
         "patch", "upsert", "merge", "commit", "push", "deploy", "upload", "save", "append", "replace",
         "apply", "install"} | DESTRUCTIVE
SEND = {"send", "post", "email", "mail", "upload", "webhook", "publish", "share", "comment", "reply",
        "forward", "message", "notify", "invite", "tweet", "push", "submit", "http", "request", "fetch",
        "navigate", "browse", "open", "url", "curl", "wget", "create_issue", "dm", "chat"}

_SPLIT = re.compile(r"[^a-z0-9]+")
_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")


def words(name: str) -> set[str]:
    return {w for w in _SPLIT.split(_CAMEL.sub("_", name).lower()) if w}


def tool_caps(tool: dict) -> set[str]:
    """Rough capabilities of one tool, from its name and annotations."""
    name = str(tool.get("name", ""))
    w = words(name)
    caps = set()
    if w & UNTRUSTED_IN:
        caps.add("reads-outside-content")
    if w & PRIVATE:
        caps.add("reads-private-data")
    if w & SEND or Policy().is_egress(name):
        caps.add("sends-out")
    if w & EXEC or ("run" in w and w & {"code", "script", "shell", "command", "python", "js"}):
        caps.add("runs-commands")
    ann = tool.get("annotations") if isinstance(tool.get("annotations"), dict) else {}
    if w & DESTRUCTIVE or ann.get("destructiveHint") is True and ann.get("readOnlyHint") is not True:
        caps.add("deletes")
    if w & WRITE:
        caps.add("changes-things")
    if ann.get("openWorldHint") is True:
        caps.add("reads-outside-content")
    return caps


@dataclass
class ToolReport:
    name: str
    caps: list[str]
    findings: list[dict] = field(default_factory=list)   # scored at or above the firewall threshold
    notes: list[str] = field(default_factory=list)
    chars: int = 0
    description: str = ""


@dataclass
class ServerReport:
    name: str
    command: list[str]
    status: str = "not run"           # ok, failed, timeout
    error: str = ""
    server_info: dict = field(default_factory=dict)
    instructions_findings: list[dict] = field(default_factory=list)
    tools: list[ToolReport] = field(default_factory=list)
    prompts: int = 0
    resources: int = 0
    flags: list[str] = field(default_factory=list)
    caps: list[str] = field(default_factory=list)
    context_tokens: int = 0
    annotated: int = 0
    seconds: float = 0.0

    @property
    def poisoned(self) -> bool:
        return bool(self.instructions_findings or any(t.findings for t in self.tools))


class Client:
    """Just enough of an MCP stdio client to read a server's lists."""

    def __init__(self, cmd: list[str], env: dict, cwd: str, timeout: float):
        self.timeout = timeout
        self.err = tempfile.TemporaryFile(mode="w+")
        self.p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.err,
                                  env=env, cwd=cwd, text=True, bufsize=1,
                                  start_new_session=(os.name != "nt"))
        self.q: queue.Queue = queue.Queue()
        self.next_id = 1
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self):
        for line in self.p.stdout:
            try:
                self.q.put(json.loads(line))
            except ValueError:
                continue
        self.q.put(None)

    def _write(self, msg: dict):
        self.p.stdin.write(json.dumps(msg) + "\n")
        self.p.stdin.flush()

    def request(self, method: str, params: dict | None = None, timeout: float | None = None) -> dict:
        mid = self.next_id
        self.next_id += 1
        self._write({"jsonrpc": "2.0", "id": mid, "method": method, "params": params or {}})
        deadline = time.monotonic() + (timeout or self.timeout)
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                raise TimeoutError(f"no reply to {method}")
            try:
                msg = self.q.get(timeout=left)
            except queue.Empty:
                raise TimeoutError(f"no reply to {method}") from None
            if msg is None:
                raise ConnectionError("server exited")
            if not isinstance(msg, dict):
                continue
            if msg.get("id") == mid and "method" not in msg:
                if "error" in msg:
                    raise RuntimeError(str(msg["error"].get("message", msg["error"]))[:200])
                return msg.get("result") or {}
            if "method" in msg and "id" in msg:  # a request from the server: decline politely
                self._write({"jsonrpc": "2.0", "id": msg["id"],
                             "error": {"code": -32601, "message": "not supported by naka audit"}})

    def list_all(self, method: str, key: str) -> list:
        items, cursor = [], None
        for _ in range(50):
            result = self.request(method, {"cursor": cursor} if cursor else {}, timeout=30)
            page = result.get(key)
            if isinstance(page, list):
                items += page
            cursor = result.get("nextCursor")
            if not cursor:
                break
        return items

    def stderr_tail(self) -> str:
        try:
            self.err.seek(0)
            return d.safe_text(self.err.read()[-400:], 300)
        except OSError:
            return ""

    def close(self):
        try:
            self.p.stdin.close()
        except OSError:
            pass
        try:
            self.p.wait(timeout=3)
        except subprocess.TimeoutExpired:
            try:
                if os.name != "nt":
                    os.killpg(self.p.pid, 9)
                else:
                    self.p.kill()
            except OSError:
                pass


def _findings(obj) -> list[dict]:
    text = "\n".join(collect_strings(obj, skip_binary=False))
    found = d.scan_injection(text)
    return [f.to_dict() for f in found] if d.score(found) >= THRESHOLD else []


def analyse(rep: ServerReport, init: dict, tools: list, prompts: list, resources: list) -> None:
    rep.server_info = {k: init.get("serverInfo", {}).get(k) for k in ("name", "version")
                       if isinstance(init.get("serverInfo"), dict)}
    if isinstance(init.get("instructions"), str):
        rep.instructions_findings = _findings(init["instructions"])
    rep.prompts, rep.resources = len(prompts), len(resources)
    for p in prompts:  # a prompt template is text the AI will read, too
        if isinstance(p, dict) and _findings(p):
            rep.instructions_findings += [dict(f, where=f"prompt {p.get('name')}") for f in _findings(p)]
    caps: set[str] = set()
    for tool in tools:
        if not isinstance(tool, dict) or not isinstance(tool.get("name"), str):
            continue
        tr = ToolReport(name=tool["name"], caps=sorted(tool_caps(tool)),
                        findings=_findings(tool), chars=len(json.dumps(tool, ensure_ascii=False)),
                        description=d.strip_hidden(str(tool.get("description") or ""))[:2000])
        ann = tool.get("annotations") if isinstance(tool.get("annotations"), dict) else None
        if ann:
            rep.annotated += 1
            if ann.get("readOnlyHint") is True and words(tool["name"]) & WRITE:
                tr.notes.append("labelled read-only, but its name says it changes things")
        hidden = d.HIDDEN_UNICODE.findall(json.dumps(tool, ensure_ascii=False))
        if [c for c in hidden if c not in d.BENIGN_INVISIBLE]:
            tr.notes.append("contains invisible characters")
        caps |= set(tr.caps)
        rep.tools.append(tr)
    rep.caps = sorted(caps)
    rep.context_tokens = sum(t.chars for t in rep.tools) // 4
    flags = []
    if rep.poisoned:
        flags.append("hidden-instructions")
    if {"reads-outside-content", "reads-private-data", "sends-out"} <= caps:
        flags.append("lethal-trifecta")
    if {"reads-outside-content", "runs-commands"} <= caps:
        flags.append("injection-to-command")
    if any("read-only" in n for t in rep.tools for n in t.notes):
        flags.append("mislabelled-read-only")
    if any("invisible" in n for t in rep.tools for n in t.notes):
        flags.append("invisible-characters")
    rep.flags = flags


def run_one(entry: dict, timeout: float = 90) -> ServerReport:
    cmd = entry["command"]
    rep = ServerReport(name=entry.get("name") or " ".join(cmd)[:60], command=cmd)
    start = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="naka-audit-") as home:
        env = {k: os.environ[k] for k in ("PATH", "LANG", "TERM", "TZ", "SYSTEMROOT", "COMSPEC",
                                          "npm_config_cache", "UV_CACHE_DIR", "UV_PYTHON") if k in os.environ}
        env.update({"HOME": home, "USERPROFILE": home, "TMPDIR": home, "npm_config_yes": "true",
                    "npm_config_update_notifier": "false", "NO_UPDATE_NOTIFIER": "1"})
        env.update({k: str(v) for k, v in (entry.get("env") or {}).items()})
        args = [a.replace("{tmp}", home) for a in cmd]
        try:
            c = Client(args, env, entry.get("cwd") or home, timeout)
        except OSError as exc:
            rep.status, rep.error = "failed", f"could not start: {exc}"
            return rep
        try:
            init = c.request("initialize", {"protocolVersion": PROTOCOL, "capabilities": {},
                                            "clientInfo": {"name": "naka-audit", "version": __version__}})
            c._write({"jsonrpc": "2.0", "method": "notifications/initialized"})
            caps = init.get("capabilities") or {}
            tools = c.list_all("tools/list", "tools") if "tools" in caps else []
            prompts = c.list_all("prompts/list", "prompts") if "prompts" in caps else []
            resources = []
            if "resources" in caps:
                try:
                    resources = c.list_all("resources/list", "resources")
                except (RuntimeError, TimeoutError):
                    resources = []
            analyse(rep, init, tools, prompts, resources)
            rep.status = "ok"
        except TimeoutError as exc:
            rep.status, rep.error = "timeout", f"{exc}. {c.stderr_tail()}".strip()
        except (ConnectionError, RuntimeError, OSError, ValueError) as exc:
            rep.status, rep.error = "failed", f"{exc}. {c.stderr_tail()}".strip()
        finally:
            c.close()
    rep.seconds = round(time.monotonic() - start, 1)
    return rep


def cross_shadowing(reports: list[ServerReport]) -> None:
    """Flag tools whose description names a tool that belongs to another server."""
    owners: dict[str, set[str]] = {}
    for rep in reports:
        for t in rep.tools:
            if len(t.name) >= 6 and ("_" in t.name or "-" in t.name):
                owners.setdefault(t.name, set()).add(rep.name)
    for rep in reports:
        own = {t.name for t in rep.tools}
        for t in rep.tools:
            others = sorted(n for n, who in owners.items()
                            if n not in own and rep.name not in who
                            and re.search(rf"(?<![\w-]){re.escape(n)}(?![\w-])", t.description))
            if others:
                t.notes.append("mentions other servers' tools: " + ", ".join(others[:3]))
                if "mentions-other-tools" not in rep.flags:
                    rep.flags.append("mentions-other-tools")


def audit(entries: list[dict], workers: int = 4, timeout: float = 90, progress=None) -> list[ServerReport]:
    lock = threading.Lock()

    def one(entry):
        rep = run_one(entry, timeout)
        if progress:
            with lock:
                progress(rep)
        return rep

    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        reports = list(pool.map(one, entries))
    cross_shadowing(reports)
    return reports


SUMMARY_FLAGS = [
    ("hidden-instructions", "Hidden instructions for the AI"),
    ("invisible-characters", "Invisible characters in definitions"),
    ("mentions-other-tools", "Mentions another server's tools"),
    ("lethal-trifecta", "Lethal trifecta in one install"),
    ("injection-to-command", "Outside content + runs commands"),
    ("mislabelled-read-only", "Mislabelled as read-only"),
]


def to_json(reports: list[ServerReport]) -> dict:
    return {"naka": __version__, "date": time.strftime("%Y-%m-%d"),
            "servers": [dict(asdict(r), poisoned=r.poisoned) for r in reports]}


def to_markdown(reports: list[ServerReport]) -> str:
    ok = [r for r in reports if r.status == "ok"]
    lines = [f"# MCP server audit ({time.strftime('%Y-%m-%d')}, naka {__version__})", "",
             f"{len(reports)} servers tried, {len(ok)} started and listed their tools.", "",
             "| Finding | Servers |", "|---|---|"]
    for flag, label in SUMMARY_FLAGS:
        lines.append(f"| {label} | {sum(flag in r.flags for r in ok)} / {len(ok)} |")
    lines += ["", "| Server | Tools | Context (tokens) | Annotated | Findings |", "|---|---|---|---|---|"]
    for r in sorted(ok, key=lambda r: (-len(r.flags), r.name)):
        lines.append(f"| {r.name} | {len(r.tools)} | {r.context_tokens:,} | {r.annotated}/{len(r.tools)} | "
                     f"{', '.join(r.flags) or 'none'} |")
    bad = [r for r in reports if r.status != "ok"]
    if bad:
        lines += ["", "## Didn't start", "", "Usually because they need a real account or service. "
                  "These aren't findings.", ""]
        lines += [f"- {r.name}: {r.status} ({d.safe_text(r.error, 120)})" for r in bad]
    detail = [r for r in ok if r.poisoned or any(t.notes for t in r.tools)]
    if detail:
        lines += ["", "## Details", ""]
        for r in detail:
            lines.append(f"### {r.name}")
            for f in r.instructions_findings:
                lines.append(f"- server instructions/prompts: `{f['rule']}`: {d.safe_text(f.get('excerpt', ''), 120)}")
            for t in r.tools:
                for f in t.findings:
                    lines.append(f"- `{t.name}`: `{f['rule']}`: {d.safe_text(f.get('excerpt', ''), 120)}")
                for n in t.notes:
                    lines.append(f"- `{t.name}`: {n}")
            lines.append("")
    return "\n".join(lines) + "\n"


def print_report(rep: ServerReport) -> None:
    if rep.status != "ok":
        print(f"{rep.name}: {rep.status}. {d.safe_text(rep.error, 200)}")
        return
    print(f"{rep.name} ({rep.server_info.get('name', '?')} {rep.server_info.get('version', '')}): "
          f"{len(rep.tools)} tools, {rep.prompts} prompts, {rep.resources} resources, "
          f"~{rep.context_tokens:,} tokens of context")
    print(f"  can: {', '.join(rep.caps) or 'nothing detected'}")
    labels = dict(SUMMARY_FLAGS)
    for flag in rep.flags:
        print(f"  ! {labels.get(flag, flag)}")
    for f in rep.instructions_findings:
        print(f"  ! instructions: {f['rule']}: {d.safe_text(f.get('excerpt', ''), 100)}")
    for t in rep.tools:
        for f in t.findings:
            print(f"  ! {t.name}: {f['rule']}: {d.safe_text(f.get('excerpt', ''), 100)}")
        for n in t.notes:
            print(f"  - {t.name}: {n}")
    if not rep.flags:
        print("  no findings")


def load_entries(path: str) -> list[dict]:
    """Servers to audit. A file may set shared placeholder settings ("env") for every server."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    entries = data["servers"] if isinstance(data, dict) else data
    shared = data.get("env", {}) if isinstance(data, dict) else {}
    out = []
    for e in entries:
        e = dict(e)
        if "command" not in e:
            pkg = e["package"]
            if e.get("kind", "npm") == "npm":
                e["command"] = ["npx", "-y", pkg, *e.get("args", [])]
            else:
                e["command"] = ["uvx", pkg, *e.get("args", [])]
        e["env"] = {**shared, **(e.get("env") or {})}
        e.setdefault("name", e.get("package") or " ".join(e["command"]))
        out.append(e)
    return out


def main(args) -> int:
    if args.servers:
        entries = load_entries(args.servers)
    elif args.command:
        cmd = args.command[1:] if args.command[:1] == ["--"] else args.command
        entries = [{"name": " ".join(cmd)[:60], "command": cmd, "cwd": os.getcwd()}]
    else:
        print("give a server command after --, or --servers FILE", file=sys.stderr)
        return 2
    if args.only:
        entries = [e for e in entries if any(o in e["name"] for o in args.only)]
    quiet = bool(args.servers)
    done = [0]

    def progress(rep):
        done[0] += 1
        if quiet:
            print(f"[{done[0]}/{len(entries)}] {rep.name}: {rep.status}"
                  f"{' ' + ', '.join(rep.flags) if rep.flags else ''}", flush=True)

    reports = audit(entries, workers=args.workers, timeout=args.timeout, progress=progress)
    if not quiet:
        for r in reports:
            print_report(r)
    if args.json:
        Path(args.json).write_text(json.dumps(to_json(reports), indent=2) + "\n", encoding="utf-8")
    if args.md:
        Path(args.md).write_text(to_markdown(reports), encoding="utf-8")
    return 1 if any(r.poisoned for r in reports) else 0
