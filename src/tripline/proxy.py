"""Stdio transport: run the real MCP server as a child process and sit in the middle.

    MCP client (Claude, Cursor, ...)                    real MCP server
          stdout/stdin  <-->  tripline  <-->  stdin/stdout (child process)

MCP over stdio sends one JSON-RPC message per line. We read a line from one
side, ask the Firewall what to do, and write the result to the other side (or
answer the sender directly when we block). Our own logs go to stderr, because
stdout belongs to the protocol: printing anything else there would corrupt it.
"""

from __future__ import annotations

import json
import signal
import subprocess
import sys
import threading
from typing import IO

from .firewall import Event, Firewall

COLORS = {"blocked": "\033[31m", "warned": "\033[33m", "pinned": "\033[36m", "info": "\033[2m"}
RESET = "\033[0m"


def stderr_reporter(quiet: bool = False):
    use_color = sys.stderr.isatty()

    def report(e: Event) -> None:
        if quiet and e.action not in ("blocked", "warned"):
            return
        label = e.action.upper()
        if use_color:
            label = COLORS.get(e.action, "") + label + RESET
        tool = f" {e.tool}" if e.tool else ""
        print(f"tripline ▸ {label} {e.rule}{tool}: {e.detail}", file=sys.stderr, flush=True)

    return report


class StdioProxy:
    def __init__(self, command: list[str], firewall: Firewall,
                 client_in: IO[bytes] | None = None, client_out: IO[bytes] | None = None):
        self.command = command
        self.fw = firewall
        self.client_in = client_in or sys.stdin.buffer
        self.client_out = client_out or sys.stdout.buffer
        self._out_lock = threading.Lock()
        self._in_lock = threading.Lock()
        self.child: subprocess.Popen | None = None

    # Writing ----------------------------------------------------------------
    def _write(self, stream: IO[bytes], lock: threading.Lock, msgs: list) -> None:
        if not msgs:
            return
        with lock:
            for m in msgs:
                data = m if isinstance(m, bytes) else json.dumps(m, ensure_ascii=False).encode()
                stream.write(data + b"\n")
            stream.flush()

    def to_client(self, msgs: list) -> None:
        self._write(self.client_out, self._out_lock, msgs)

    def to_server(self, msgs: list) -> None:
        try:
            self._write(self.child.stdin, self._in_lock, msgs)
        except (BrokenPipeError, ValueError):
            pass

    # Pumps ------------------------------------------------------------------
    def _pump(self, source: IO[bytes], handler, forward, reply) -> None:
        for raw in iter(source.readline, b""):
            line = raw.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                forward([line])  # not ours to judge; pass it on unchanged
                continue
            # JSON-RPC batches (arrays) were allowed in older MCP versions.
            messages = payload if isinstance(payload, list) else [payload]
            fwd, rep = [], []
            for m in messages:
                if not isinstance(m, dict):
                    fwd.append(m)
                    continue
                try:
                    decision = handler(m)
                except Exception as exc:  # never let a bug take the agent down
                    print(f"tripline ▸ internal error, passing message through: {exc!r}",
                          file=sys.stderr, flush=True)
                    fwd.append(m)
                    continue
                fwd.extend(decision.forward)
                rep.extend(decision.reply)
            forward(fwd)
            reply(rep)

    def run(self) -> int:
        self.child = subprocess.Popen(self.command, stdin=subprocess.PIPE,
                                      stdout=subprocess.PIPE, stderr=None, bufsize=0)

        def client_loop():
            self._pump(self.client_in, self.fw.from_client, self.to_server, self.to_client)
            # Client hung up: close the server's stdin so it can exit cleanly.
            try:
                self.child.stdin.close()
            except Exception:
                pass

        def server_loop():
            self._pump(self.child.stdout, self.fw.from_server, self.to_client, self.to_server)

        t_client = threading.Thread(target=client_loop, daemon=True)
        t_server = threading.Thread(target=server_loop, daemon=True)
        t_client.start()
        t_server.start()

        def _terminate(signum, frame):
            if self.child and self.child.poll() is None:
                self.child.terminate()

        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                signal.signal(sig, _terminate)
            except ValueError:
                pass  # not in main thread (tests)

        code = self.child.wait()
        t_server.join(timeout=2)
        return code
