"""Content detectors: prompt injection, tool poisoning, hidden unicode, secrets and PII.

All detectors are pure functions over text so they can be reused by the proxy,
the CLI scanner and tests. They return a list of Finding objects; an empty list
means nothing suspicious was found.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
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
    # Imperative only: "Ignore all previous instructions" or "...: ignore your
    # rules", not a description like "the agent would ignore all previous
    # instructions" in a changelog or a security article.
    ("override-instructions", HIGH, _rx(
        r"(?:^|[.!?:;,>\-–—\n(*]\s*|\b(?:please|now|then|and|so|just|simply|kindly|must|should)\s+|"
        r"\byou\s+(?:must|should|need\s+to|have\s+to|will)\s+)"
        r"(?:(?:\w+ly|now|then|also|just|simply|instead)\s+){0,3}"   # "please carefully ignore"
        r"(?:ignore|disregard|forget|override|bypass)\b.{0,40}?"
        r"\b(?:previous|prior|above|earlier|all|system|original|your|any)\b.{0,20}?"
        r"\b(?:instructions?|prompts?|rules|guidelines|guidance|directives|guardrails|policies|constraints)")),
    ("fake-system-tag", HIGH, _rx(
        r"<\s*/?\s*(important|system|admin|instructions?|secret|assistant)\s*>|\[\s*(system|admin)\s*\]|^\s*#{1,6}\s*system\b")),
    # "[IMPORTANT]" on its own is ordinary emphasis in real tool descriptions
    # (Vercel's next-devtools-mcp uses it), so it only counts with other signals.
    ("bracket-important", MEDIUM, _rx(r"\[\s*important\s*\]")),
    # "Do not mention this to the user." but not "do not tell the user their
    # password over chat", which is ordinary security advice.
    ("conceal-from-user", HIGH, _rx(
        r"\b(?:do\s*n[o']?t|never|without)\s+(?:\w+\s+){0,2}?(?:tell|inform|mention|reveal|notify|alert|warn|show)\w*\s+"
        r"(?:(?:this|that|it|anything|any\s+of\s+this)\s+)?(?:to\s+)?(?:the\s+)?(?:user|human|operator)s?"
        r"(?=\s*[.,;:!?)\n]|\s*$|\s+(?:about|that|of|this|it|what|why|how|in|during|while|when|until|before|"
        r"after|unless|because|since|either|yet|anything)\b)"
        r"|\b(?:do\s*n[o']?t|never)\s+let\s+(?:the\s+)?(?:user|human)\s+(?:know|see|notice)"
        r"|\bkeep\s+(?:the\s+)?(?:user|human)\s+(?:unaware|uninformed|in\s+the\s+dark)"
        r"|\bwithout\s+the\s+user(?:'s)?\s+(?:knowing|knowledge|noticing|seeing|consent|approval|permission)"
        r"|\bhide\s+(?:this|it|that|these|the\s+\w+)\s+from\s+(?:the\s+)?user")),
    ("new-role", MEDIUM, _rx(
        r"\byou\s+are\s+now\b|\bfrom\s+now\s+on\b.{0,40}\b(you|assistant)\b|\bact\s+as\s+(an?\s+)?(admin|root|developer\s+mode)")),
    ("pre-call-hijack", MEDIUM, _rx(
        r"\bbefore\s+(using|calling|invoking|running)\b.{0,40}\b(tool|function)\b.{0,80}\b(read|send|call|include|pass|fetch)\b")),
    ("sensitive-path", MEDIUM, _rx(
        r"(~|\$HOME|/home/\w+|/Users/\w+)?/?\.(ssh|aws|gnupg|kube|docker)/|\bid_(rsa|ed25519|ecdsa)\b|\.env\b|credentials\.json|mcp\.json|\.npmrc|\.netrc|/etc/(passwd|shadow)")),
    ("exfil-instruction", HIGH, _rx(
        r"\b(send|post|upload|forward|exfiltrate|transmit|leak|copy)\b.{0,60}\b(to|into)\b.{0,40}(https?://|webhook|\b(the\s+)?(sidenote|notes?|comment|parameter|argument|field)\b)")),
    # Reworded exfiltration: get a secret, put it somewhere the model writes.
    ("secret-exfil-intent", HIGH, _rx(
        r"\b(?:append|include|add|insert|put|place|attach|embed|copy|paste|send|pass|forward|leak|write|encode|open|read|cat|load)\b"
        r".{0,80}?(?:\b(?:environment\s+variables?|env\s+vars?|api[\s_-]?(?:keys?|tokens?)|access\s+tokens?|secrets?|passwords?|"
        r"credentials?|private\s+keys?|ssh\s+keys?|session\s+cookies?|cookies)\b|id_(?:rsa|ed25519|ecdsa)|\.ssh/|\.aws/|\.env\b|"
        r"\b(?-i:[A-Z][A-Z0-9]*_(?:TOKEN|KEY|SECRET|PASSWORD|PASS))\b)"
        r".{0,80}?\b(?:to|into|in|as|inside|within)\s+(?:the\s+|your\s+|its\s+|a\s+|an\s+)?(?:\w+\s+){0,2}?"
        r"(?:summary|response|reply|answer|output|sidenote|notes?|comment|argument)\b")),
    # Same, but the destination is a URL or parameter: common in honest API docs
    # too, so it only counts together with another signal.
    ("secret-to-url", MEDIUM, _rx(
        r"\b(?:append|include|add|insert|put|place|attach|embed|pass|encode)\b.{0,60}?"
        r"\b(?:api[\s_-]?(?:keys?|tokens?)|access\s+tokens?|secrets?|passwords?|credentials?|environment\s+variables?)\b"
        r".{0,60}?\b(?:to|into|in|as)\s+(?:the\s+|a\s+)?(?:\w+\s+){0,2}?(?:url|link|query(?:\s+string)?|parameter)\b")),
    # A markdown image whose URL carries a placeholder for the model to fill in:
    # when the client renders it, the data leaves in the request.
    ("markdown-beacon", HIGH, _rx(
        r"!\[[^\]\n]{0,100}\]\(\s*https?://[^)\s]{1,300}?[?&#][^)\s=]{0,40}=?"
        r"(?:[^)\s&]*(?:\{|<|%7b|%3c|\$\{)|(?-i:[A-Z0-9]*[A-Z]{2,}_[A-Z_]{3,})|[^)\s&]*(?:_here|insert_|placeholder))")),
    ("stealth-action", MEDIUM, _rx(
        r"\b(?:quietly|silently|secretly|covertly|discreetly)\s+(?:\w+\s+){0,2}?"
        r"(?:copy|send|include|add|forward|upload|read|call|run|exfiltrate|post|email|share)")),
    ("financial-action", MEDIUM, _rx(
        r"\b(?:transfer|wire|send|pay|move|withdraw)\b.{0,40}?\b(?:balance|funds|money|amount|payment|rs\.?|inr|usd|btc|crypto)\b"
        r".{0,40}?\b(?:to|into)\s+(?:the\s+|this\s+|a\s+)?(?:account|wallet|iban|upi|address|beneficiary)"
        r"|(?:mark|set)\s+(?:the\s+)?invoice\b.{0,30}?\bas\s+(?:fully\s+)?paid")),
    ("approval-bypass", MEDIUM, _rx(
        r"\b(?:clear|skip|bypass|disable|auto-?approve|dismiss|turn\s+off)\b.{0,30}?"
        r"\b(?:approvals?|approval\s+queue|confirmations?|2fa|mfa|verification|security\s+checks?|alerts?|review\s+step)\b")),
    ("destructive-action", MEDIUM, _rx(
        r"\b(?:delete|remove|wipe|erase|destroy|drop|truncate|purge|rm\s+-rf)\b\s+(?:\w+\s+){0,3}?(?:every|all|entire|whole)\b.{0,40}?"
        r"\b(?:files?|folders?|director(?:y|ies)|repos?|repositor(?:y|ies)|databases?|tables?|branch(?:es)?|records|backups?|emails?|messages)")),
    ("deceive-user", MEDIUM, _rx(
        r"\b(?:tell|inform|assure|reassure|report\s+to|reply\s+to|let)\s+the\s+user\s+(?:know\s+)?(?:that\s+)?"
        r"(?:the\s+\w+\s+|everything\s+|it\s+|all\s+)?(?:succeeded|worked|went\s+(?:well|fine|smoothly)|"
        r"was\s+(?:successful|fine|ok|completed)|is\s+(?:fine|ok|done|complete)|completed\s+successfully)")),
    ("cross-tool-shadowing", MEDIUM, _rx(
        r"\b(when|whenever|if)\b.{0,30}\b(the\s+)?(user|assistant|agent)\b.{0,30}\b(uses?|calls?|invokes?)\b.{0,40}\b(other|another|any)\b.{0,20}\b(tool|server|function)")),
    ("urgent-imperative", LOW, _rx(
        r"\b(you\s+must|it\s+is\s+(critical|mandatory|essential)|this\s+is\s+(very\s+)?important)\b")),
    ("tool-call-request", MEDIUM, _rx(
        r"\b(call|invoke|use|run)\s+(the\s+)?[`'\"]?[a-z0-9]+(_[a-z0-9]+)+[`'\"]?\s+(tool|function)\b")),
    # Other languages. Patterns, like the English ones, catch the common
    # phrasings only; a classifier is on the roadmap.
    ("override-instructions-hi", HIGH, _rx(  # Hindi and Hinglish
        r"(?:पिछले|पहले\s+के|ऊपर\s+के|सभी|पूर्व)\s+(?:\S+\s+){0,2}?निर्देश\S*\s+(?:\S+\s+){0,2}?(?:भूल|अनदेखा|नज़रअंदाज़|नजरअंदाज|छोड़)"
        r"|pichl[ei]\s+(?:sab(?:hi)?\s+)?(?:instructions?|nirdesh)\s+(?:\S+\s+)?(?:bhool|bhul|ignore)")),
    ("conceal-from-user-hi", HIGH, _rx(
        r"(?:उपयोगकर्ता|यूज़र|यूजर)\s+को\s+(?:बताए\s+बिना|(?:मत|न|ना)\s+बता|कुछ\s+(?:मत|न)\s+बता)"
        r"|user\s+ko\s+(?:bina\s+bataye|(?:mat|na|mt)\s+bata)")),
    ("secret-exfil-hi", HIGH, _rx(
        r"(?:गुप्त\s+कुंजी|पासवर्ड|टोकन|क्रेडेंशियल|एपीआई\s+की|कुंजी)\S*\s+(?:\S+\s+){0,4}?(?:भेज|ईमेल|मेल|पोस्ट|अपलोड)")),
    ("override-instructions-intl", HIGH, _rx(
        r"\bignora\w*\s+(?:todas\s+)?(?:las\s+)?instrucciones\s+(?:anteriores|previas)"            # es
        r"|\bignore[zr]?\s+(?:toutes\s+)?(?:les\s+)?instructions\s+(?:pr[ée]c[ée]dentes|ant[ée]rieures)"  # fr
        r"|\bignorier\w*\s+(?:alle\s+)?(?:vorherigen|bisherigen|früheren|obigen)\s+anweisungen"     # de
        r"|\bignor[ea]\w*\s+(?:todas\s+)?(?:as\s+)?instru[çc][õo]es\s+anteriores")),                # pt
    ("conceal-from-user-intl", HIGH, _rx(
        r"\bno\s+(?:se\s+lo\s+|le\s+)?(?:digas|menciones|informes|cuentes)\s+(?:nada\s+)?al\s+usuario"
        r"|\bne\s+(?:le\s+)?(?:dis|dites|mentionne\w*)\s+(?:rien\s+)?(?:pas\s+)?(?:à|a)\s+l'utilisateur"
        r"|\b(?:sag|erwähn)\w*\s+(?:es\s+|das\s+)?(?:dem\s+)?(?:benutzer|nutzer)\s+nicht"
        r"|\bn[ãa]o\s+(?:conte|diga|mencione)\s+(?:nada\s+)?ao\s+usu[áa]rio")),
    ("secret-exfil-intl", HIGH, _rx(
        r"\b(?:incluye|env[ií]a|adjunta|copia|inclu[ia]|envoie|copie|joins?|füge|sende|kopiere)\w*\s+.{0,60}?"
        r"(?:contraseñ|credencial|clave|token|secreto|archivo\s+de\s+configuraci|mot\s+de\s+passe|identifiant|fichier\s+de\s+config|"
        r"passwort|zugangsdaten|schlüssel|konfigurationsdatei|senha|chave)"
        r".{0,60}?(?:mensaje|correo|respuesta|resumen|comentario|argumento|message|courriel|r[ée]ponse|r[ée]sum[ée]|commentaire|"
        r"nachricht|antwort|zusammenfassung|kommentar|mensagem|resposta|resumo)")),
]

# Characters that are invisible to humans but read by models.
#   U+00AD soft hyphen, U+034F grapheme joiner, U+061C Arabic letter mark,
#   U+115F/1160/3164/FFA0 Hangul fillers, U+17B4/17B5 Khmer vowels,
#   U+180B-180F Mongolian selectors, U+200B-200F zero-width and direction marks,
#   U+202A-202E and U+2066-2069 bidi controls, U+2060-206F invisible operators,
#   U+FE00-FE0F and U+E0100-E01EF variation selectors, U+FEFF BOM,
#   U+E0000-E007F tag characters (can spell out whole ASCII sentences).
HIDDEN_UNICODE = re.compile(
    "[­͏؜ᅟᅠ឴឵᠋-᠏​-‏‪-‮"
    "⁠-⁯ㅤ︀-️﻿ﾠ\U000e0000-\U000e007f\U000e0100-\U000e01ef]"
)
# These appear in normal text: ZWNJ/ZWJ shape Devanagari conjuncts and emoji
# sequences, FE0E/FE0F pick text or emoji style. Only flag them in long runs,
# which is what smuggling looks like.
BENIGN_INVISIBLE = set("‌‍︎️")
SUSPICIOUS_RUN = re.compile("[‌‍︎️]{4,}")

# Common Cyrillic/Greek look-alikes, mapped to Latin for scanning only.
CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i",
    "ј": "j", "ѕ": "s", "ԁ": "d", "һ": "h", "ӏ": "l", "ɡ": "g", "ο": "o", "ι": "i",
    "α": "a", "ν": "v", "ρ": "p", "τ": "t", "κ": "k", "Α": "A", "Β": "B", "Ε": "E",
    "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Χ": "X",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P",
    "С": "C", "Т": "T", "Х": "X",
})

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
    return redact_secrets(snippet)


def _redact(value: str) -> str:
    if len(value) <= 8:
        return "****"
    return value[:4] + "…" + value[-2:]


def redact_secrets(text: str) -> str:
    """Mask credentials inside any text we are about to log or show."""
    for _, rx in SECRET_RULES:
        text = rx.sub(lambda m: _redact(m.group(0)), text)
    return text


def safe_text(text: str, limit: int = 300) -> str:
    """Make attacker-controlled text safe to print to a terminal.

    Escapes control characters (which can clear the screen or fake output),
    bidi controls and other invisible characters, and caps the length.
    """
    out = []
    for ch in str(text)[:limit]:
        o = ord(ch)
        if o < 0x20 or 0x7f <= o < 0xa0 or o in (0x2028, 0x2029) or HIDDEN_UNICODE.match(ch):
            out.append(f"\\u{o:04x}" if o > 0xff else f"\\x{o:02x}")
        else:
            out.append(ch)
    if len(str(text)) > limit:
        out.append("…")
    return "".join(out)


MAX_DECODE_BLOBS = 50
MAX_DECODED_BYTES = 256 * 1024


def _decoded_variants(text: str) -> list[str]:
    """Decode base64 blobs so encoded payloads get scanned too.

    Bounded: an attacker can pack a message with blobs to make scanning slow,
    so we decode at most MAX_DECODE_BLOBS blobs and MAX_DECODED_BYTES in total,
    with one decoder per blob, chosen from its alphabet.
    """
    out: list[str] = []
    budget = MAX_DECODED_BYTES
    for blob in re.findall(r"[A-Za-z0-9+/=_\-]{24,}", text)[:MAX_DECODE_BLOBS]:
        if budget <= 0:
            break
        blob = blob[: budget * 4 // 3 + 4]
        decoder = base64.urlsafe_b64decode if ("-" in blob or "_" in blob) else base64.b64decode
        try:
            raw = decoder(blob + "=" * (-len(blob) % 4))
        except (binascii.Error, ValueError):
            continue
        budget -= len(raw)
        try:
            decoded = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if decoded.isprintable() or "\n" in decoded:
            out.append(decoded)
    return out


def _decode_smuggled(chars: list[str]) -> str:
    """Recover text hidden in tag characters or variation selectors."""
    tags = "".join(chr(ord(c) - 0xE0000) for c in chars if 0xE0000 <= ord(c) <= 0xE007F)
    data = bytearray()
    for c in chars:
        o = ord(c)
        if 0xFE00 <= o <= 0xFE0F:
            data.append(o - 0xFE00)
        elif 0xE0100 <= o <= 0xE01EF:
            data.append(o - 0xE0100 + 16)
    vs = data.decode("utf-8", errors="ignore") if len(data) >= 4 else ""
    return "\n".join(t for t in (tags, vs) if t)


GREEK_NAMES = {"ALPHA": "a", "BETA": "b", "EPSILON": "e", "ETA": "n", "IOTA": "i", "KAPPA": "k",
               "MU": "m", "NU": "v", "OMICRON": "o", "RHO": "p", "TAU": "t", "UPSILON": "u",
               "CHI": "x", "ZETA": "z", "GAMMA": "y", "DELTA": "d", "OMEGA": "w"}
CYRILLIC_NAMES = {"IE": "e", "ES": "c", "ER": "p", "HA": "x", "DZE": "s", "JE": "j", "SHHA": "h",
                  "PALOCHKA": "l", "KOMI DE": "d", "BYELORUSSIAN-UKRAINIAN I": "i", "U": "y", "EL": "l"}


def _fold_char(ch: str) -> str:
    """Best-effort Latin look-alike for one character, from its Unicode name."""
    if ch.isascii():
        return ch
    try:
        name = unicodedata.name(ch)
    except ValueError:
        return ""
    for script, table in (("CYRILLIC", CYRILLIC_NAMES), ("GREEK", GREEK_NAMES)):
        if script in name:
            for key, val in table.items():
                if name.endswith(" LETTER " + key) or name.endswith(" " + key):
                    return val
    if "LETTER" in name:
        last = name.rsplit(" ", 1)[-1]
        if len(last) == 1:                       # "... LETTER A", "... SMALL CAPITAL A"
            return last.lower()
        if last in GREEK_NAMES:                  # "LATIN SMALL LETTER ALPHA" (ɑ)
            return GREEK_NAMES[last]
        if "DOTLESS I" in name:
            return "i"
        if "DOTLESS J" in name:
            return "j"
    return ch


def skeleton(text: str) -> str:
    """Collapse look-alike names to one form: 'Send‑Emɑil', 'send_email\u200b' -> 'sendemail'."""
    text = unicodedata.normalize("NFKD", strip_hidden(text))
    text = "".join(c for c in text if not unicodedata.combining(c))
    text = "".join(_fold_char(c) for c in text.translate(CONFUSABLES))
    return re.sub(r"[^a-z0-9]", "", text.casefold())


def normalize(text: str) -> str:
    """Undo common disguises before pattern matching."""
    text = unicodedata.normalize("NFKC", text)  # fullwidth and styled letters
    return text.translate(CONFUSABLES)


def scan_injection(text: str) -> list[Finding]:
    """Look for instructions aimed at the model, including hidden and encoded ones."""
    if not text:
        return []
    findings: list[Finding] = []
    hidden = HIDDEN_UNICODE.findall(text)
    suspicious = [c for c in hidden if c not in BENIGN_INVISIBLE]
    if suspicious or SUSPICIOUS_RUN.search(text):
        findings.append(Finding("hidden-unicode", "hidden_unicode", HIGH,
                                f"{len(hidden)} invisible character(s)"))
    if hidden:
        smuggled = _decode_smuggled(hidden)
        text = HIDDEN_UNICODE.sub("", text) + ("\n" + smuggled if smuggled else "")

    base = normalize(text)
    variants = [base] + [normalize(v) for v in _decoded_variants(text)]
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
