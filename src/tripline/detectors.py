"""Content detectors: prompt injection, tool poisoning, hidden unicode, secrets and PII.

All detectors are pure functions over text so they can be reused by the proxy,
the CLI scanner and tests. They return a list of Finding objects; an empty list
means nothing suspicious was found.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass, field

# Severity weights. A text is considered "flagged" when its total score reaches
# the threshold passed by the caller (default 3).
LOW, MEDIUM, HIGH = 1, 2, 3


@dataclass(frozen=True)
class Finding:
    rule: str
    category: str  # injection | hidden_unicode | secret | pii
    severity: int
    excerpt: str = field(default="", compare=False)

    def to_dict(self) -> dict:
        return {
            "rule": self.rule,
            "category": self.category,
            "severity": self.severity,
            "excerpt": self.excerpt,
        }


def _rx(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE | re.DOTALL)


# --- Prompt injection / tool poisoning -------------------------------------
# These target instructions aimed at the model rather than the user. Tool
# descriptions and tool responses are both untrusted input for an agent.
INJECTION_RULES: list[tuple[str, int, re.Pattern[str]]] = [
    ("override-instructions", HIGH, _rx(
        r"\b(ignore|disregard|forget|override)\b.{0,40}\b(previous|prior|above|earlier|all|system|original)\b.{0,20}\b(instructions?|prompts?|rules|guidelines|directives)")),
    ("fake-system-tag", HIGH, _rx(
        r"<\s*/?\s*(important|system|admin|instructions?|secret|assistant)\s*>|\[\s*(system|admin|important)\s*\]|^\s*#{1,6}\s*system\b")),
    ("conceal-from-user", HIGH, _rx(
        r"\b(do\s*n[o']?t|never|without)\b.{0,30}\b(tell|inform|mention|reveal|show|notify|alert|let)\w*\b.{0,30}\b(the\s+)?(user|human|operator)")),
    ("new-role", MEDIUM, _rx(
        r"\byou\s+are\s+now\b|\bfrom\s+now\s+on\b.{0,40}\b(you|assistant)\b|\bact\s+as\s+(an?\s+)?(admin|root|developer\s+mode)")),
    ("pre-call-hijack", MEDIUM, _rx(
        r"\bbefore\s+(using|calling|invoking|running)\b.{0,40}\b(tool|function)\b.{0,80}\b(read|send|call|include|pass|fetch)\b")),
    ("sensitive-path", MEDIUM, _rx(
        r"(~|\$HOME|/home/\w+|/Users/\w+)?/?\.(ssh|aws|gnupg|kube|docker)/|\bid_(rsa|ed25519|ecdsa)\b|\.env\b|credentials\.json|mcp\.json|\.npmrc|\.netrc|/etc/(passwd|shadow)")),
    ("exfil-instruction", HIGH, _rx(
        r"\b(send|post|upload|forward|exfiltrate|transmit|leak|copy)\b.{0,60}\b(to|into)\b.{0,40}(https?://|webhook|\b(the\s+)?(sidenote|notes?|comment|parameter|argument|field)\b)")),
    ("cross-tool-shadowing", MEDIUM, _rx(
        r"\b(when|whenever|if)\b.{0,30}\b(the\s+)?(user|assistant|agent)\b.{0,30}\b(uses?|calls?|invokes?)\b.{0,40}\b(other|another|any)\b.{0,20}\b(tool|server|function)")),
    ("urgent-imperative", LOW, _rx(
        r"\b(you\s+must|it\s+is\s+(critical|mandatory|essential)|this\s+is\s+(very\s+)?important)\b")),
    ("tool-call-request", MEDIUM, _rx(
        r"\b(call|invoke|use|run)\s+(the\s+)?[`'\"]?[a-z0-9]+(_[a-z0-9]+)+[`'\"]?\s+(tool|function)\b")),
]

# Characters that are invisible to humans but read by models.
HIDDEN_UNICODE = re.compile(
    "[​-‏‪-‮⁠-⁤⁦-⁩﻿\U000e0000-\U000e007f]"
)

# --- Secrets ----------------------------------------------------------------
SECRET_RULES: list[tuple[str, re.Pattern[str]]] = [
    ("aws-access-key", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b")),
    ("anthropic-key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}")),
    ("openai-key", re.compile(r"\bsk-(proj-|svcacct-)?[A-Za-z0-9_\-]{20,}")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("stripe-live-key", re.compile(r"\b(sk|rk)_live_[0-9A-Za-z]{20,}\b")),
    ("private-key", re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY( BLOCK)?-----")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")),
    ("password-assignment", re.compile(r"(?i)\b(password|passwd|pwd|secret|api[_-]?key)\s*[:=]\s*['\"]?[^\s'\"]{8,}")),
]

# --- PII (India-aware) --------------------------------------------------------
PII_RULES: list[tuple[str, re.Pattern[str]]] = [
    ("email-address", re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")),
    ("india-pan", re.compile(r"\b[A-Z]{3}[ABCFGHLJPT][A-Z][0-9]{4}[A-Z]\b")),
    ("india-aadhaar", re.compile(r"\b[2-9][0-9]{3}[ \-]?[0-9]{4}[ \-]?[0-9]{4}\b")),
    ("credit-card", re.compile(r"\b(?:4[0-9]{3}|5[1-5][0-9]{2}|3[47][0-9]{2})[ \-]?[0-9]{4}[ \-]?[0-9]{4}[ \-]?[0-9]{1,4}\b")),
]


def _excerpt(text: str, m: re.Match[str], width: int = 60) -> str:
    start = max(0, m.start() - 10)
    snippet = text[start:start + width].replace("\n", " ")
    return snippet


def _redact(value: str) -> str:
    if len(value) <= 8:
        return "****"
    return value[:4] + "…" + value[-2:]


def _decoded_variants(text: str) -> list[str]:
    """Decode base64 blobs once so encoded payloads get scanned too."""
    out = []
    for blob in re.findall(r"[A-Za-z0-9+/=_\-]{24,}", text):
        padded = blob + "=" * (-len(blob) % 4)
        for decoder in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                raw = decoder(padded)
            except (binascii.Error, ValueError):
                continue
            try:
                decoded = raw.decode("utf-8")
            except UnicodeDecodeError:
                continue
            if decoded.isprintable() or "\n" in decoded:
                out.append(decoded)
                break
    return out


def scan_injection(text: str) -> list[Finding]:
    """Look for instructions aimed at the model, including hidden and encoded ones."""
    if not text:
        return []
    findings: list[Finding] = []
    hidden = HIDDEN_UNICODE.findall(text)
    if hidden:
        findings.append(Finding("hidden-unicode", "hidden_unicode", HIGH,
                                f"{len(hidden)} invisible character(s)"))
        # Unicode tag characters can smuggle ASCII; decode them for scanning.
        smuggled = "".join(chr(ord(c) - 0xE0000) for c in hidden if 0xE0000 <= ord(c) <= 0xE007F)
        text = HIDDEN_UNICODE.sub("", text) + ("\n" + smuggled if smuggled else "")

    variants = [text] + _decoded_variants(text)
    seen: set[str] = set()
    for i, variant in enumerate(variants):
        for rule, severity, rx in INJECTION_RULES:
            if rule in seen:
                continue
            m = rx.search(variant)
            if m:
                seen.add(rule)
                name = rule if i == 0 else f"{rule}(base64)"
                findings.append(Finding(name, "injection", severity, _excerpt(variant, m)))
    return findings


def find_secrets(text: str) -> list[tuple[Finding, str]]:
    """Return (finding, raw_value) pairs. Raw values stay in memory only."""
    results = []
    for rule, rx in SECRET_RULES:
        for m in rx.finditer(text or ""):
            value = m.group(0)
            results.append((Finding(rule, "secret", HIGH, _redact(value)), value))
    return results


def _luhn_ok(digits: str) -> bool:
    nums = [int(d) for d in digits if d.isdigit()]
    total = 0
    for i, n in enumerate(reversed(nums)):
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def find_pii(text: str) -> list[tuple[Finding, str]]:
    results = []
    for rule, rx in PII_RULES:
        for m in rx.finditer(text or ""):
            value = m.group(0)
            if rule == "credit-card" and not _luhn_ok(value):
                continue
            results.append((Finding(rule, "pii", MEDIUM, _redact(value)), value))
    return results


def score(findings: list[Finding]) -> int:
    return sum(f.severity for f in findings)


def strip_hidden(text: str) -> str:
    return HIDDEN_UNICODE.sub("", text)
