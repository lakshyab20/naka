"""Command-line interface.

    naka wrap [--name NAME] [--config FILE] [--sandbox auto] -- <server command...>
    naka wrap [--name NAME] --url https://server/mcp [--header "K: V"]
    naka pins list|approve|reset --name NAME [TOOL ...] [--all]
    naka scan [FILE]           scan text (or stdin) for injection and secrets
    naka log [-n N]            show recent decisions
    naka install [--dry-run]   protect every MCP server in Claude, Cursor...
    naka uninstall             put the original configs back
    naka bench [--agent]       measure every layer on public datasets
    naka demo [--unprotected]  run the attack demo
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from . import __version__
from . import detectors as d
from .firewall import Firewall
from .policy import Policy
from .proxy import StdioProxy, stderr_reporter
from .store import AuditLog, PinStore, home, server_id


def cmd_wrap(args) -> int:
    from .upstream import HttpUpstream, ProcessUpstream
    command = args.command
    if command and command[0] == "--":
        command = command[1:]
    if bool(command) == bool(args.url):
        print("naka wrap: give either a server command after --, or --url", file=sys.stderr)
        return 2
    if args.url:
        headers = {}
        for h in args.header or []:
            key, sep, value = h.partition(":")
            if not sep:
                print(f"naka wrap: --header must look like 'Name: value', got {h!r}", file=sys.stderr)
                return 2
            headers[key.strip()] = os.path.expandvars(value.strip())
        upstream = HttpUpstream(args.url, headers)
        sid = server_id(args.name, [args.url])
    else:
        env = cwd = None
        if args.sandbox:
            from .sandbox import SandboxUnavailable, start_dir, wrap_command
            try:
                cwd = start_dir(args.allow_path or [])
                command, env = wrap_command(command, args.sandbox, allow=args.allow_path or [],
                                            network=not args.no_network, image=args.image,
                                            env_names=args.env or [])
            except SandboxUnavailable as exc:
                # Never fall back to running the server unsandboxed.
                print(f"naka wrap: sandbox not started: {exc}", file=sys.stderr)
                return 2
        upstream = ProcessUpstream(command, env, cwd)
        sid = server_id(args.name, command)
    fw = Firewall(Policy.load(args.config), PinStore(sid), AuditLog(sid),
                  on_event=stderr_reporter(args.quiet))
    return StdioProxy(upstream, fw).run()


def cmd_pins(args) -> int:
    if args.action == "list":
        root = home() / "pins"
        files = sorted(root.glob("*.json")) if root.exists() else []
        if args.name:
            files = [f for f in files if f.stem == PinStore(args.name).path.stem]
        for f in files:
            data = json.loads(f.read_text())
            print(f"{data.get('server', f.stem)}")
            for name, pin in data.get("tools", {}).items():
                print(f"  pinned   {d.safe_text(name, 60):28} {pin['sha256'][:12]}  {pin['pinned_at']}")
            for name, entry in data.get("pending", {}).items():
                print(f"  PENDING  {d.safe_text(name, 60):28} {d.safe_text(entry['reason'])}")
        if not files:
            print("No pinned servers yet.")
        return 0

    if not args.name:
        print("--name is required", file=sys.stderr)
        return 2
    store = PinStore(args.name)
    if args.action == "reset":
        store.pins.clear()
        store.pending.clear()
        store.save()
        print(f"Cleared pins for {args.name}. The next tool list will be trusted and pinned.")
        return 0
    if args.action == "approve":
        names = list(store.pending) if args.all else args.tools
        if not names:
            print("Name the tools to approve, or pass --all.", file=sys.stderr)
            return 2
        for n in names:
            entry = store.pending.get(n)
            if entry:
                # Show the full new definition, made safe for the terminal, so the
                # person approving sees exactly what they are trusting.
                print(f"Approving {d.safe_text(n, 80)} ({d.safe_text(entry['reason'])}). New definition:\n  "
                      f"{d.safe_text(json.dumps(entry['tool'], ensure_ascii=False), 2000)}")
            print(("  approved " if store.approve(n) else "  nothing pending for ") + n)
        store.save()
        return 0
    return 2


def cmd_scan(args) -> int:
    text = open(args.file, encoding="utf-8").read() if args.file else sys.stdin.read()
    findings = d.scan_injection(text)
    findings += [f for f, _ in d.find_secrets(text)] + [f for f, _ in d.find_pii(text)]
    for f in findings:
        print(f"{f.category:15} {f.rule:28} sev={f.severity}  {d.safe_text(f.excerpt)}")
    total = d.score([f for f in findings if f.category in ("injection", "hidden_unicode")])
    verdict = "FLAGGED" if total >= args.threshold else "clean"
    print(f"\ninjection score {total} (threshold {args.threshold}): {verdict}")
    return 1 if total >= args.threshold or any(f.category == "secret" for f in findings) else 0


def cmd_log(args) -> int:
    path = home() / "audit.jsonl"
    if not path.exists():
        print("No audit log yet.")
        return 0
    # Split on \n only: str.splitlines() also splits on U+2028 and friends.
    lines = [l for l in path.read_text(encoding="utf-8", errors="replace").split("\n") if l.strip()][-args.n:]
    for line in lines:
        try:
            r = json.loads(line)
        except ValueError:
            print(f"(unreadable log line: {d.safe_text(line, 60)})")
            continue
        print(f"{r.get('ts', '?')}  {d.safe_text(r.get('server', ''), 14):14} {d.safe_text(r.get('event', ''), 8):8} "
              f"{d.safe_text(r.get('rule', ''), 18):18} {d.safe_text(r.get('tool', ''), 16):16} "
              f"{d.safe_text(r.get('detail', ''), 90)}")
    return 0


def cmd_bench(args) -> int:
    from . import bench
    rc = 0
    if not args.agent_only:
        rc |= bench.main(args.json)
    if args.agent or args.agent_only:
        print()
        report = bench.agent_eval(bench.fetch(["InjecAgent"]))
        print(bench.render_agent(report))
        if args.json:
            import pathlib
            path = pathlib.Path(args.json)
            data = json.loads(path.read_text()) if path.exists() else {}
            data["agent"] = report
            path.write_text(json.dumps(data, indent=2))
    return rc


def cmd_install(args, uninstall=False) -> int:
    from . import install
    return install.run(args.app, args.project, args.dry_run, args.yes, uninstall, args.config)


def cmd_demo(args) -> int:
    from .demo.run_demo import main as demo_main
    return demo_main(unprotected=args.unprotected)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="naka", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--version", action="version", version=f"naka {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    w = sub.add_parser("wrap", help="run an MCP server behind the firewall")
    w.add_argument("--name", help="stable name for this server (used for pins)")
    w.add_argument("--config", help="policy TOML file")
    w.add_argument("--quiet", action="store_true", help="only log blocks and warnings")
    w.add_argument("--url", help="remote MCP server (Streamable HTTP) instead of a command")
    w.add_argument("--header", action="append", help="HTTP header for --url, e.g. 'Authorization: Bearer $TOKEN'")
    w.add_argument("--sandbox", choices=["auto", "bwrap", "macos", "docker"],
                   help="run the server isolated from your home folder (Linux and Docker modes are experimental)")
    w.add_argument("--allow-path", action="append", help="folder the sandboxed server may use (repeatable)")
    w.add_argument("--no-network", action="store_true", help="sandbox: no network access")
    w.add_argument("--image", help="sandbox docker: container image (default chosen from the command)")
    w.add_argument("--env", action="append", help="sandbox: pass this environment variable to the server (repeatable)")
    w.add_argument("command", nargs=argparse.REMAINDER)
    w.set_defaults(func=cmd_wrap)

    p = sub.add_parser("pins", help="list, approve or reset pinned tool definitions")
    p.add_argument("action", choices=["list", "approve", "reset"])
    p.add_argument("tools", nargs="*")
    p.add_argument("--name")
    p.add_argument("--all", action="store_true")
    p.set_defaults(func=cmd_pins)

    s = sub.add_parser("scan", help="scan text for injection, secrets and PII")
    s.add_argument("file", nargs="?")
    s.add_argument("--threshold", type=int, default=3)
    s.set_defaults(func=cmd_scan)

    lg = sub.add_parser("log", help="show recent firewall decisions")
    lg.add_argument("-n", type=int, default=20)
    lg.set_defaults(func=cmd_log)

    for name, helptext, un in (("install", "wrap every MCP server in your apps' configs", False),
                               ("uninstall", "restore your apps' original MCP configs", True)):
        ins = sub.add_parser(name, help=helptext)
        ins.add_argument("--app", action="append",
                         choices=["claude-desktop", "claude-code", "cursor", "windsurf", "vscode"],
                         help="only this app (repeatable); default: every app found")
        ins.add_argument("--project", help="also handle this project folder's .mcp.json, .cursor/ and .vscode/")
        ins.add_argument("--config", help="a specific config file instead")
        ins.add_argument("--dry-run", action="store_true", help="show the changes without writing")
        ins.add_argument("--yes", action="store_true", help="don't ask for confirmation")
        ins.set_defaults(func=lambda a, _un=un: cmd_install(a, _un))

    b = sub.add_parser("bench", help="measure detection and data-flow rules on public datasets")
    b.add_argument("--agent", action="store_true", help="also replay InjecAgent attacks end to end")
    b.add_argument("--agent-only", action="store_true", help="only the end-to-end replay")
    b.add_argument("--json", help="also write the results to this file")
    b.set_defaults(func=cmd_bench)

    ev = sub.add_parser("eval", help="run attack and everyday-task scenarios through any MCP guard")
    ev.add_argument("--suite", action="append", help="mcp-attacks, contagion, injecagent (repeatable; "
                    "default: mcp-attacks and contagion)")
    ev.add_argument("--guard", action="append", help="'no guard', naka, 'naka strict', pipelock, or "
                    "NAME='command ... {cmd}' (repeatable; default: no guard and naka)")
    ev.add_argument("--only", action="append", help="only scenarios whose id contains this text")
    ev.add_argument("--limit", type=int, help="only the first N scenarios")
    ev.add_argument("--workers", type=int, default=8)
    ev.add_argument("--list", action="store_true", help="list the scenarios and exit")
    ev.add_argument("--verbose", "-v", action="store_true", help="show each attack that got through")
    ev.add_argument("--json", help="also write full results to this file")
    ev.add_argument("--keep", help="save every run (messages, guard log, tool calls) in this folder")
    ev.set_defaults(func=lambda a: __import__("naka.evals.cli", fromlist=["main"]).main(a))

    au = sub.add_parser("audit", help="check MCP servers' definitions before you trust them")
    au.add_argument("--servers", help="JSON list of servers to audit (see scan/servers.json)")
    au.add_argument("--only", action="append", help="only servers whose name contains this text")
    au.add_argument("--workers", type=int, default=4)
    au.add_argument("--timeout", type=float, default=90, help="seconds to wait for each server")
    au.add_argument("--json", help="write full results to this file")
    au.add_argument("--md", help="write a markdown report to this file")
    au.add_argument("command", nargs=argparse.REMAINDER, help="-- the server command to audit")
    au.set_defaults(func=lambda a: __import__("naka.audit", fromlist=["main"]).main(a))

    dm = sub.add_parser("demo", help="run the attack demo")
    dm.add_argument("--unprotected", action="store_true", help="run the same attack without naka")
    dm.set_defaults(func=cmd_demo)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
