"""Where the real MCP server lives: a local process, or a remote URL.

The proxy reads server messages as lines from `reader` and sends client
messages with `send`. A local server is a child process (stdio). A remote
server speaks MCP's Streamable HTTP transport: each client message is POSTed,
and the server answers with JSON or a stream of server-sent events (SSE).

For HTTP, every message we receive is decoded and re-encoded as one line on an
internal pipe, so remote traffic goes through exactly the same reader as local
traffic: the same size limit, the same "drop what we can't parse" rule, and
the same firewall.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from typing import IO

PROTOCOL_HEADER = "MCP-Protocol-Version"
SESSION_HEADER = "Mcp-Session-Id"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow redirects: a malicious server could point us at another host
    (or a cloud metadata address) and our auth headers would go along."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, f"redirect to {newurl} not followed", headers, fp)


def _log(text: str) -> None:
    print(f"naka ▸ {text}", file=sys.stderr, flush=True)


class ProcessUpstream:
    def __init__(self, command: list[str], env: dict[str, str] | None = None, cwd: str | None = None):
        self.command = command
        self.env = env
        self.cwd = cwd
        self.child: subprocess.Popen | None = None
        self._lock = threading.Lock()

    def start(self) -> None:
        self.child = subprocess.Popen(self.command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                      stderr=None, bufsize=0, env=self.env, cwd=self.cwd)

    @property
    def reader(self) -> IO[bytes]:
        return self.child.stdout

    def send(self, lines: list[bytes]) -> None:
        try:
            with self._lock:
                for line in lines:
                    self.child.stdin.write(line + b"\n")
                self.child.stdin.flush()
        except (BrokenPipeError, ValueError, OSError):
            pass

    def close(self) -> None:
        try:
            self.child.stdin.close()
        except Exception:
            pass

    def terminate(self) -> None:
        if self.child and self.child.poll() is None:
            self.child.terminate()

    def wait(self) -> int:
        return self.child.wait()


class HttpUpstream:
    """A remote MCP server over Streamable HTTP."""

    def __init__(self, url: str, headers: dict[str, str] | None = None, timeout: float = 600):
        if not url.startswith(("https://", "http://")):
            raise ValueError("remote server URL must start with https:// or http://")
        if url.startswith("http://") and not url.startswith(("http://127.0.0.1", "http://localhost", "http://[::1]")):
            _log("warning: plain http:// to a non-local server; traffic and tokens are not encrypted")
        self.url = url
        self.headers = dict(headers or {})
        self.timeout = timeout
        self.session_id: str | None = None
        self.protocol: str | None = None
        self._pipe_lock = threading.Lock()
        self._done = threading.Event()
        self._inflight = 0
        self._inflight_lock = threading.Condition()
        self._opener = urllib.request.build_opener(_NoRedirect())

    def start(self) -> None:
        r, w = os.pipe()
        self._reader = os.fdopen(r, "rb")
        self._writer = os.fdopen(w, "wb")

    @property
    def reader(self) -> IO[bytes]:
        return self._reader

    # ---------------------------------------------------------------- output
    def _emit(self, payload: bytes) -> None:
        """Re-encode one server message as a single line for the proxy's reader."""
        try:
            msg = json.loads(payload)
        except (ValueError, RecursionError):
            _log("dropped a message from the remote server that is not valid JSON")
            return
        line = json.dumps(msg, ensure_ascii=False, separators=(",", ":")).encode()
        with self._pipe_lock:
            if not self._writer.closed:
                self._writer.write(line + b"\n")
                self._writer.flush()

    def _error_for(self, msg: dict, text: str) -> None:
        if isinstance(msg, dict) and "id" in msg and "method" in msg:
            self._emit(json.dumps({"jsonrpc": "2.0", "id": msg["id"],
                                   "error": {"code": -32000, "message": text}}).encode())

    def _sse(self, resp) -> None:
        data: list[bytes] = []
        for raw in resp:
            line = raw.rstrip(b"\r\n")
            if not line:
                if data:
                    self._emit(b"\n".join(data))
                    data = []
            elif line.startswith(b"data:"):
                data.append(line[5:].lstrip(b" "))
            # event:, id:, retry: and comments carry no message content
        if data:
            self._emit(b"\n".join(data))

    # --------------------------------------------------------------- requests
    def _request(self, method: str, body: bytes | None, accept: str):
        headers = dict(self.headers)
        headers["Accept"] = accept
        if body is not None:
            headers["Content-Type"] = "application/json"
        if self.session_id:
            headers[SESSION_HEADER] = self.session_id
        if self.protocol:
            headers[PROTOCOL_HEADER] = self.protocol
        req = urllib.request.Request(self.url, data=body, method=method, headers=headers)
        return self._opener.open(req, timeout=self.timeout)

    def _post(self, msg: dict) -> None:
        try:
            with self._request("POST", json.dumps(msg).encode(), "application/json, text/event-stream") as resp:
                if msg.get("method") == "initialize":
                    self.session_id = resp.headers.get(SESSION_HEADER) or self.session_id
                if resp.status == 202:
                    return
                ctype = (resp.headers.get("Content-Type") or "").split(";")[0].strip().lower()
                if ctype == "text/event-stream":
                    self._sse(resp)
                else:
                    body = resp.read()
                    if body.strip():
                        if msg.get("method") == "initialize":
                            try:
                                self.protocol = json.loads(body)["result"]["protocolVersion"]
                            except (ValueError, KeyError, TypeError):
                                pass
                        self._emit(body)
        except urllib.error.HTTPError as exc:
            reason = f": {exc.reason}" if 300 <= exc.code < 400 else ""
            self._error_for(msg, f"remote server returned HTTP {exc.code}{reason}")
        except (urllib.error.URLError, OSError, ValueError) as exc:
            self._error_for(msg, f"could not reach the remote server: {exc}")

    def _listen(self) -> None:
        """Optional GET stream for messages the server starts (notifications, requests)."""
        for attempt in range(3):
            if self._done.is_set():
                return
            try:
                with self._request("GET", None, "text/event-stream") as resp:
                    self._sse(resp)
            except urllib.error.HTTPError as exc:
                if exc.code in (404, 405):
                    return  # this server doesn't offer a GET stream
            except (urllib.error.URLError, OSError):
                pass
            time.sleep(1 + attempt)

    def send(self, lines: list[bytes]) -> None:
        for line in lines:
            try:
                msg = json.loads(line)
            except ValueError:
                continue
            if isinstance(msg, dict) and msg.get("method") == "initialize":
                self._post(msg)  # in order: the session id must exist before anything else
                if self.protocol and self.protocol < "2025-03-26":
                    _log("remote server negotiated an old protocol; Streamable HTTP may not work")
                continue
            if isinstance(msg, dict) and msg.get("method") == "notifications/initialized":
                self._post(msg)
                threading.Thread(target=self._listen, daemon=True).start()
                continue
            with self._inflight_lock:
                self._inflight += 1
            threading.Thread(target=self._post_tracked, args=(msg,), daemon=True).start()

    def _post_tracked(self, msg: dict) -> None:
        try:
            self._post(msg)
        finally:
            with self._inflight_lock:
                self._inflight -= 1
                self._inflight_lock.notify_all()

    def close(self) -> None:
        """The client hung up: let in-flight replies finish, end the session, close."""
        with self._inflight_lock:
            self._inflight_lock.wait_for(lambda: self._inflight == 0, timeout=10)
        if self.session_id:
            try:
                self._request("DELETE", None, "application/json").close()
            except (urllib.error.URLError, OSError, ValueError):
                pass
        self._done.set()
        with self._pipe_lock:
            self._writer.close()

    def terminate(self) -> None:
        self.close()

    def wait(self) -> int:
        self._done.wait()
        return 0
