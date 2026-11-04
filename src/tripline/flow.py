"""Data-flow tracking: where did a value come from, and where is it going?

Detection asks "does this text look like an attack?" and can always be fooled
by new wording. Data-flow rules ask a question wording can't change: is a
value that came out of an untrusted tool now being used to send data, or to
decide where it goes? This is the idea behind capability-based defences such
as Google DeepMind's CaMeL, applied at the MCP traffic layer.

Two kinds of values are tracked from tool output:
- Sensitive values (credentials, PAN, Aadhaar, card numbers). They must not
  leave through another tool, even re-encoded (base64, hex, reversed, case or
  separators changed) or split into pieces of CHUNK characters or more.
- Destinations (email addresses, URLs, hosts, IPs, phone numbers, account
  numbers, IDs). If one of these came from untrusted output and is then used
  as an argument of a tool that changes something, a person should confirm:
  "send to x@attacker.example" because a web page said so is the classic
  injection payoff.

Values are stored only as keyed hashes. With a shared session (the default),
every Tripline process started by the same app (Claude Desktop, Cursor...)
appends to one file, so data read through one server and sent through another
is still caught.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import secrets
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

from . import detectors as d
from .store import home

SHINGLE = 8                 # runs of this many words copied from untrusted text are recognised
MAX_SHINGLES = 50_000       # per tool output, to bound the work a huge page can force
TOKEN = re.compile(r"\w+")
CHUNK = 12                  # contiguous pieces this long are recognised in one call
FRAG_MIN = 6                # shorter pieces are tracked across calls...
REASSEMBLE = 0.75           # ...and blocked once they cover this share of a secret
SESSION_TTL = 12 * 3600     # forget sessions older than this

DESTINATIONS = [
    ("email", re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")),
    ("url", re.compile(r"\b(?:https?|ftp|wss?)://[^\s'\"<>)\]}]+", re.I)),
    ("host", re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,24}\b(?=[/:?#]|\s|$|['\"),.;])", re.I)),
    ("ip", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("phone", re.compile(r"(?<![\w.])\+?\d[\d ()-]{8,}\d(?![\w.])")),
    ("iban", re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b")),
    ("account", re.compile(r"(?<![\w.-])\d{8,18}(?![\w.-])")),
    ("handle", re.compile(r"(?<![\w@])@[A-Za-z0-9_]{3,30}\b")),
    ("id", re.compile(r"\b(?=[A-Za-z0-9_-]*\d)(?=[A-Za-z0-9_-]*[A-Za-z])[A-Za-z0-9]+(?:[_-][A-Za-z0-9]+)+\b")),
]
# Common words that look like IDs but carry no meaning as a destination.
BORING_HOSTS = {"example.com", "e.g", "i.e", "a.m", "p.m"}


def canonical(text: str) -> str:
    """Lowercase letters and digits only: undoes case, spacing and separators."""
    return re.sub(r"[^a-z0-9]", "", d.normalize(text).lower())


def variants(value: str) -> set[str]:
    """Forms a model might send a secret in, all reduced to canonical text."""
    raw = value.encode("utf-8", "ignore")
    forms = {value, value[::-1],
             base64.b64encode(raw).decode(), base64.urlsafe_b64encode(raw).decode(),
             binascii.hexlify(raw).decode(), base64.b32encode(raw).decode()}
    return {c for c in (canonical(f) for f in forms) if c}


def tokens(text: str) -> list[tuple[int, int, str]]:
    """Words with their positions, normalised so look-alike letters and case don't matter."""
    return [(m.start(), m.end(), d.normalize(m.group(0)).lower()) for m in TOKEN.finditer(text)]


def destinations(text: str) -> set[tuple[str, str]]:
    found = set()
    for kind, rx in DESTINATIONS:
        for m in rx.finditer(text):
            value = m.group(0).strip().rstrip(".,;")
            if kind == "host" and value.lower() in BORING_HOSTS:
                continue
            c = canonical(value)
            if len(c) >= 5:
                found.add((kind, c))
    return found


class SessionState:
    """Taint and provenance for one agent session, optionally shared across processes."""

    def __init__(self, server: str, shared: bool = True, session: str | None = None):
        self.server = server
        self._lock = threading.Lock()
        self.secret_chunks: dict[bytes, str] = {}   # hashed piece -> "server/tool"
        self.secret_whole: dict[bytes, str] = {}    # hashed short value -> source
        self.whole_sizes: set[int] = set()
        # Fragment hash -> list of (secret id, offset, length), for reassembly.
        self.fragments: dict[bytes, list[tuple[str, int, int]]] = {}
        self.secret_len: dict[str, tuple[int, str]] = {}   # secret id -> (length, source)
        self.covered: dict[str, set[int]] = {}  # secret id -> positions already sent out, any tool
        self.dest: dict[bytes, tuple[str, str]] = {}  # hashed destination -> (kind, source)
        self.text: dict[bytes, str] = {}  # hashed run of SHINGLE words from untrusted output -> source
        self.injection_from: str | None = None
        self.untrusted_from: str | None = None
        self.path: Path | None = None
        self._offset = 0
        if shared:
            group = session or os.environ.get("TRIPLINE_SESSION") or f"ppid-{os.getppid()}"
            root = home() / "sessions"
            root.mkdir(parents=True, exist_ok=True)
            os.chmod(root, 0o700)
            self._expire(root)
            self.path = root / f"{re.sub(r'[^A-Za-z0-9_.-]', '_', group)}.jsonl"
            self._key = self._load_or_create_key()
        else:
            self._key = secrets.token_bytes(16)

    # -------------------------------------------------------------- storage
    @staticmethod
    def _expire(root: Path) -> None:
        cutoff = time.time() - SESSION_TTL
        for f in root.glob("*.jsonl"):
            try:
                if f.stat().st_mtime < cutoff:
                    f.unlink()
            except OSError:
                pass

    def _load_or_create_key(self) -> bytes:
        """The first process in a session creates the file and its hashing key."""
        assert self.path is not None
        try:
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_APPEND, 0o600)
            with os.fdopen(fd, "a", encoding="ascii") as fh:
                fh.write(json.dumps({"t": "key", "k": secrets.token_hex(16)}) + "\n")
        except FileExistsError:
            pass
        for _ in range(50):  # another process may be mid-write of the first line
            first = self.path.read_text(encoding="ascii").split("\n", 1)[0]
            if first.endswith("}"):
                return bytes.fromhex(json.loads(first)["k"])
            time.sleep(0.01)
        raise RuntimeError("session file has no key")

    def _h(self, text: str) -> bytes:
        return hashlib.blake2b(text.encode(), digest_size=12, key=self._key).digest()

    def _h8(self, text: str) -> bytes:
        return hashlib.blake2b(text.encode(), digest_size=8, key=self._key).digest()

    def _append(self, record: dict) -> None:
        self._apply(record)
        if self.path:
            with self._lock, open(self.path, "a", encoding="ascii") as fh:
                fh.write(json.dumps(record) + "\n")

    def _apply(self, r: dict) -> None:
        t = r.get("t")
        if t == "sc":
            for h in r["h"]:
                self.secret_chunks.setdefault(bytes.fromhex(h), r["src"])
        elif t == "sw":
            for h in r["h"]:
                self.secret_whole.setdefault(bytes.fromhex(h), r["src"])
            self.whole_sizes.update(r.get("n", []))
        elif t == "fr":
            self.secret_len[r["sid"]] = (r["n"], r["src"])
            for h, off, ln in r["f"]:
                self.fragments.setdefault(bytes.fromhex(h), []).append((r["sid"], off, ln))
        elif t == "dst":
            self.dest.setdefault(bytes.fromhex(r["h"]), (r["kind"], r["src"]))
        elif t == "tx":
            for h in r["h"]:
                self.text.setdefault(bytes.fromhex(h), r["src"])
        elif t == "inj":
            self.injection_from = self.injection_from or r["src"]
        elif t == "unt":
            self.untrusted_from = self.untrusted_from or r["src"]

    def refresh(self) -> None:
        """Pick up records other Tripline processes in this session wrote."""
        if not self.path:
            return
        with self._lock:
            try:
                with open(self.path, "r", encoding="ascii") as fh:
                    fh.seek(self._offset)
                    data = fh.read()
                    self._offset = fh.tell()
            except OSError:
                return
        for line in data.split("\n"):
            if line.strip():
                try:
                    self._apply(json.loads(line))
                except (ValueError, KeyError):
                    continue

    # ------------------------------------------------------------- recording
    def record_output(self, text: str, tool: str, trusted: bool) -> None:
        src = f"{self.server}/{tool}"
        whole, chunks, sizes = set(), set(), set()
        for finding, value in d.find_secrets(text) + d.find_pii(text):
            if finding.rule == "email-address":
                continue
            base = canonical(value)
            if len(base) > CHUNK:
                sid = secrets.token_hex(6)
                frags = [[self._h(base[i:i + ln]).hex(), i, ln]
                         for ln in range(FRAG_MIN, CHUNK) for i in range(len(base) - ln + 1)]
                self._append({"t": "fr", "sid": sid, "n": len(base), "src": src, "f": frags})
            for c in variants(value):
                if len(c) <= CHUNK:
                    if len(c) >= 8:
                        whole.add(self._h(c).hex())
                        sizes.add(len(c))
                else:
                    chunks.update(self._h(c[i:i + CHUNK]).hex() for i in range(len(c) - CHUNK + 1))
        if chunks:
            self._append({"t": "sc", "h": sorted(chunks), "src": src})
        if whole:
            self._append({"t": "sw", "h": sorted(whole), "n": sorted(sizes), "src": src})
        if not trusted and not self.untrusted_from and text.strip():
            self._append({"t": "unt", "src": src})
        if not trusted:
            for kind, c in destinations(text):
                self._append({"t": "dst", "h": self._h(c).hex(), "kind": kind, "src": src})
            # Remember the wording itself (as hashed runs of words), so we can
            # tell later when the AI copies this text into something it sends
            # or into its own memory: how an injected note spreads or persists.
            words = [w for _, _, w in tokens(text)]
            runs = {self._h8(" ".join(words[i:i + SHINGLE]))
                    for i in range(min(len(words) - SHINGLE + 1, MAX_SHINGLES))}
            if runs:
                self._append({"t": "tx", "h": sorted(h.hex() for h in runs), "src": src})

    def record_injection(self, source: str) -> None:
        if not self.injection_from:
            self._append({"t": "inj", "src": f"{self.server}/{source}"})

    # --------------------------------------------------------------- checking
    def secret_source(self, text: str, tool: str) -> str | None:
        """Source of a tracked sensitive value found in text, if any (other tools only)."""
        self.refresh()
        here = f"{self.server}/{tool}"
        c = canonical(text)
        if self.secret_whole:
            # Short values (PAN, Aadhaar) in any disguise: check each stored length.
            for size in sorted(self.whole_sizes):
                for i in range(len(c) - size + 1):
                    src = self.secret_whole.get(self._h(c[i:i + size]))
                    if src and src != here:
                        return src
        if self.secret_chunks:
            for i in range(len(c) - CHUNK + 1):
                src = self.secret_chunks.get(self._h(c[i:i + CHUNK]))
                if src and src != here:
                    return src
        if self.fragments:
            # Pieces too short to recognise alone: remember which parts of each
            # secret this tool has been sent, across calls, and stop the call
            # that would complete most of it.
            hits: dict[str, set[int]] = {}
            for ln in range(CHUNK - 1, FRAG_MIN - 1, -1):
                for i in range(len(c) - ln + 1):
                    for sid, off, flen in self.fragments.get(self._h(c[i:i + ln]), ()):
                        hits.setdefault(sid, set()).update(range(off, off + flen))
            for sid, positions in hits.items():
                total, src = self.secret_len[sid]
                if src == here:
                    continue
                # Counted across all tools: the attacker controls where pieces
                # go and can reassemble them anywhere.
                seen = self.covered.setdefault(sid, set())
                if len(seen | positions) >= REASSEMBLE * total:
                    return src
                seen |= positions
        return None

    def untrusted_host_with_data(self, text: str) -> tuple[str, str, str] | None:
        """A URL to a host from untrusted output, carrying data that output didn't contain.

        Following a link exactly as it appeared, with nothing else, is normal
        browsing. The same host with a query or fragment added, or with other
        arguments alongside (a body, a payload), is how data gets smuggled out.
        Used for tools named like readers, since a name proves nothing.
        """
        self.refresh()
        if not self.dest:
            return None
        urls = [m.group(0).rstrip(".,;") for m in DESTINATIONS[1][1].finditer(text)]
        rest = text
        for url in urls:
            rest = rest.replace(url, "")
        other = len(canonical(rest))
        for url in urls:
            parts = urlsplit(url)
            host = parts.hostname or ""
            hit = self.dest.get(self._h(canonical(host))) if host else None
            if not hit:
                continue
            exact = self._h(canonical(url)) in self.dest
            extra = len(canonical(parts.query + parts.fragment))
            if (not exact and extra >= 16) or other >= 24:
                return "url", url, hit[1]
        return None

    def untrusted_destination(self, text: str) -> tuple[str, str, str] | None:
        """(kind, value, source) for a destination in text that came from untrusted output."""
        self.refresh()
        if not self.dest:
            return None
        for kind, rx in DESTINATIONS:
            for m in rx.finditer(text):
                value = m.group(0).strip().rstrip(".,;")
                hit = self.dest.get(self._h(canonical(value)))
                if hit:
                    return hit[0], value, hit[1]
        return None

    def copied_untrusted(self, text: str) -> list[tuple[str, str]]:
        """Passages of text copied from untrusted tool output: [(passage, source)].

        A passage is a run of at least SHINGLE words that appeared, in order, in
        something an untrusted tool returned. Small edits (a changed word, a
        sign-off added, re-flowed lines) still leave most runs intact.
        """
        self.refresh()
        if not self.text:
            return []
        toks = tokens(text)
        hits: list[tuple[int, str]] = []
        for i in range(len(toks) - SHINGLE + 1):
            src = self.text.get(self._h8(" ".join(w for _, _, w in toks[i:i + SHINGLE])))
            if src:
                hits.append((i, src))
        spans: list[list] = []
        for i, src in hits:
            if spans and i <= spans[-1][1]:
                spans[-1][1] = i + SHINGLE
            else:
                spans.append([i, i + SHINGLE, src])
        return [(text[toks[a][0]:toks[b - 1][1]], src) for a, b, src in spans]

    def untrusted_seen(self) -> str | None:
        self.refresh()
        return self.untrusted_from

    def injection_source(self) -> str | None:
        self.refresh()
        return self.injection_from
