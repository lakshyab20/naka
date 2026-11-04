"""Stdio transport: run the real MCP server as a child process and sit in the middle.

    MCP client (Claude, Cursor, ...)                    real MCP server
          stdout/stdin  <-->  naka  <-->  stdin/stdout (child process)

MCP over stdio sends one JSON-RPC message per line. We read a line from one
side, ask the Firewall what to do, and write the result to the other side (or
answer the sender directly when we block). Our own logs go to stderr, because
stdout belongs to the protocol: printing anything else there would corrupt it.
"""

from __future__ import annotations

import json
import signal
import sys
import threading
from typing import IO

from . import detectors as d
from .firewall import Event, Firewall
from .upstream import ProcessUpstream

# One message larger than this is dropped. Stops a server from exhausting
# memory with a never-ending line. Generous: real tool results are far smaller.
MAX_LINE = 16 * 1024 * 1024

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
        # Tool names and details come from the server: escape control codes so a
        # malicious server can't clear the screen or fake our log lines.
        tool = f" {d.safe_text(e.tool, 80)}" if e.tool else ""
        print(f"naka ▸ {label} {e.rule}{tool}: {d.safe_text(e.detail)}", file=sys.stderr, flush=True)

    return report


def _log(text: str) -> None:
    print(f"naka ▸ {text}", file=sys.stderr, flush=True)


class StdioProxy:
    """Relays between the client (our stdin/stdout) and an upstream server."""

    def __init__(self, upstream, firewall: Firewall,
                 client_in: IO[bytes] | None = None, client_out: IO[bytes] | None = None):
        if isinstance(upstream, list):  # backwards compatible: a command line
            upstream = ProcessUpstream(upstream)
        self.upstream = upstream
        self.fw = firewall
        self.client_in = client_in or sys.stdin.buffer
        self.client_out = client_out or sys.stdout.buffer
        self._out_lock = threading.Lock()

    @staticmethod
    def _encode(msgs: list) -> list[bytes]:
        return [m if isinstance(m, bytes) else json.dumps(m, ensure_ascii=False).encode() for m in msgs]

    def to_client(self, msgs: list) -> None:
        if not msgs:
            return
        with self._out_lock:
            for line in self._encode(msgs):
                self.client_out.write(line + b"\n")
            self.client_out.flush()

    def to_server(self, msgs: list) -> None:
        if msgs:
            self.upstream.send(self._encode(msgs))

    # Pumps ------------------------------------------------------------------
    @staticmethod
    def _lines(source: IO[bytes]):
        """Yield complete lines, dropping any longer than MAX_LINE."""
        while True:
            raw = source.readline(MAX_LINE + 1)
            if not raw:
                return
            if len(raw) > MAX_LINE and not raw.endswith(b"\n"):
                _log(f"dropped a message larger than {MAX_LINE // (1024 * 1024)} MB")
                while raw and not raw.endswith(b"\n"):  # skip the rest of it
                    raw = source.readline(MAX_LINE + 1)
                continue
            yield raw

    def _pump(self, source: IO[bytes], handler, forward, reply) -> None:
        for raw in self._lines(source):
            line = raw.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except (ValueError, RecursionError) as exc:
                # Invalid JSON, bad UTF-8, or absurd nesting. We never forward
                # what we could not read: another parser might read it differently.
                _log(f"dropped a message that is not valid JSON ({type(exc).__name__})")
                continue
            # JSON-RPC batches (arrays) were allowed in older MCP versions.
            messages = payload if isinstance(payload, list) else [payload]
            fwd, rep = [], []
            for m in messages:
                if not isinstance(m, dict):
                    _log("dropped a message that is not a JSON object")
                    continue
                try:
                    decision = handler(m)
                except Exception as exc:  # the firewall fails closed itself; this is a last guard
                    _log(f"internal error, message dropped: {exc!r}")
                    continue
                fwd.extend(decision.forward)
                rep.extend(decision.reply)
            forward(fwd)
            reply(rep)

    def run(self) -> int:
        self.upstream.start()

        def client_loop():
            self._pump(self.client_in, self.fw.from_client, self.to_server, self.to_client)
            # Client hung up: let the server finish and exit cleanly.
            self.upstream.close()

        def server_loop():
            self._pump(self.upstream.reader, self.fw.from_server, self.to_client, self.to_server)

        t_client = threading.Thread(target=client_loop, daemon=True)
        t_server = threading.Thread(target=server_loop, daemon=True)
        t_client.start()
        t_server.start()

        def _terminate(signum, frame):
            self.upstream.terminate()

        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                signal.signal(sig, _terminate)
            except ValueError:
                pass  # not in main thread (tests)

        code = self.upstream.wait()
        t_server.join(timeout=2)
        return code
