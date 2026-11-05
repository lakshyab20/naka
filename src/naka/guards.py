"""Three newer protections, kept apart from the core firewall rules.

Canary keys
    Fake credentials Naka generates and you leave where an attacker would look
    (`naka canary plant .env.backup`). Nothing legitimate ever sends them
    anywhere, so if one shows up in a tool call, in any encoding, the agent is
    working for someone else: the call is blocked and the session locked down.

Elicitation phishing
    MCP lets a server pop up a form in your app. A malicious or hijacked
    server can use that to ask for a password, a one-time code, an API key or
    a card number. Naka declines those forms before you see them.

Agentjacking (installs steered by outside content)
    Injected text in an issue, error report or web page tells a coding agent
    to install a package or pipe a script into a shell (the 2026 "agentjacking"
    attacks on Claude Code, Cursor and Codex). Naka spots install and
    download-and-run commands, asks you first when the session has read
    outside content, blocks them when the package or URL itself came from
    that content, and flags package names one letter off a popular one.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import string
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit

from . import detectors as d
from .flow import canonical, variants
from .store import home

# ------------------------------------------------------------------ canaries


def canary_path() -> Path:
    return home() / "canaries.json"


def _rand(alphabet: str, n: int) -> str:
    return "".join(secrets.choice(alphabet) for _ in range(n))


def make_canaries() -> list[dict]:
    """Realistic-looking fake credentials. No marker in them says they're fake."""
    up = string.ascii_uppercase
    alnum = string.ascii_letters + string.digits
    host = f"vault-{_rand(string.ascii_lowercase + string.digits, 6)}.corp.internal"  # never resolves
    return [
        {"name": "AWS_ACCESS_KEY_ID", "value": "AKIA" + _rand(up + "234567", 16)},
        {"name": "AWS_SECRET_ACCESS_KEY", "value": _rand(alnum + "+/", 40)},
        {"name": "GITHUB_TOKEN", "value": "ghp_" + _rand(alnum, 36)},
        {"name": "STRIPE_SECRET_KEY", "value": "sk_live_" + _rand(alnum, 24)},
        {"name": "DB_PASSWORD", "value": _rand(alnum, 10) + "!" + _rand(string.digits, 3)},
        {"name": "VAULT_ADDR", "value": f"https://{host}:8200"},
    ]


def load_canaries(create: bool = False) -> list[dict]:
    path = canary_path()
    if path.exists():
        try:
            data = json.loads(path.read_text())
            if isinstance(data, list):
                return [c for c in data if isinstance(c, dict) and isinstance(c.get("value"), str)]
        except (OSError, ValueError):
            return []
    if not create:
        return []
    data = make_canaries()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(data, fh, indent=2)
    _forms.cache_clear()
    return data


@lru_cache(maxsize=4)
def _forms(key: str) -> tuple[tuple[str, str], ...]:
    out = []
    for c in json.loads(key):
        value = c["value"]
        forms = set(variants(value))
        if value.startswith("https://"):
            forms.add(canonical(urlsplit(value).hostname or ""))
        out += [(f, c["name"]) for f in forms if len(f) >= 10]
    return tuple(out)


def canary_hit(text: str, canaries: list[dict] | None = None) -> str | None:
    """Name of the canary found in text (plain, reversed, base64, hex...), if any."""
    canaries = load_canaries() if canaries is None else canaries
    if not canaries or not text:
        return None
    c = canonical(text)
    for form, name in _forms(json.dumps(canaries, sort_keys=True)):
        if form in c:
            return name
    return None


def decoy_file(canaries: list[dict]) -> str:
    """A file that looks like credentials someone forgot to delete."""
    lines = ["# production credentials (old backup, rotate before use)"]
    lines += [f"{c['name']}={c['value']}" for c in canaries]
    return "\n".join(lines) + "\n"


def plant(path: str) -> Path:
    target = Path(path).expanduser()
    if target.exists():
        raise FileExistsError(f"{target} already exists; pick a new file name")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(decoy_file(load_canaries(create=True)))
    os.chmod(target, 0o600)
    return target


# ------------------------------------------------------- elicitation phishing

ASKS_FOR_SECRET = re.compile(
    r"\b(?:pass(?:word|code|phrase)s?|pwd|otp|one[- ]?time (?:code|password|pin)|2fa|mfa|totp|"
    r"verification code|auth(?:entication|orization)? code|security code|sms code|"
    r"api[ _-]?(?:key|token|secret)|access[ _-]?(?:key|token)|secret(?:[ _-]?key)?|bearer token|"
    r"private[ _-]?key|ssh key|seed(?:[ _-]?phrase)?|recovery (?:phrase|code|key)|mnemonic|wallet key|"
    r"card[ _-]?number|credit card|debit card|cvv|cvc|card expiry|expiry date|"
    r"ssn|social security(?: number)?|aadhaar|pan (?:card|number)|upi pin|atm pin|(?:enter|your) pin|"
    r"bank account(?: number)?|routing number|iban|sort code|login credentials|credentials)\b",
    re.I)


def phishing(params) -> str | None:
    """Why an elicitation/create request looks like it's fishing for a secret, or None."""
    if not isinstance(params, dict):
        return None
    if params.get("mode") == "url" or isinstance(params.get("url"), str):
        url = str(params.get("url") or "")
        parts = urlsplit(url)
        host = parts.hostname or ""
        if parts.scheme != "https":
            return f"it sends you to a page that isn't https ({d.safe_text(url, 60)})"
        if re.fullmatch(r"[\d.]+|\[?[0-9a-f:]+\]?", host) or "xn--" in host:
            return f"it sends you to a disguised address ({d.safe_text(host, 60)})"
    message = str(params.get("message") or "")
    if re.search(r"\bnaka\b", d.normalize(message), re.I):
        return "it pretends to be one of Naka's own prompts"
    texts = [message]
    schema = params.get("requestedSchema")
    props = schema.get("properties") if isinstance(schema, dict) else None
    if isinstance(props, dict):
        for key, spec in props.items():
            texts.append(str(key).replace("_", " "))
            if isinstance(spec, dict):
                if spec.get("format") == "password" or spec.get("writeOnly") is True:
                    return f"it asks for a hidden field ('{d.safe_text(str(key), 40)}')"
                texts += [str(spec.get(k) or "") for k in ("title", "description")]
    m = ASKS_FOR_SECRET.search(d.normalize("\n".join(texts)))
    if m:
        return f"it asks you for {m.group(0).lower()}"
    return None


# --------------------------------------------------------------- agentjacking

_SEP = r"(?:^|[\s;&|`(]|\$\()"
_PKG = r"((?:[^\s;&|`)]+\s*)+)"
# (ecosystem, runs only its first package, pattern). Runners like npx and uvx
# run one package; the words after it are that program's own arguments.
INSTALLS = [
    ("npm", False, re.compile(_SEP + r"(?:sudo\s+)?(?:npm|pnpm|yarn|bun)\s+(?:i|install|add|global\s+add)\s"
                              + _PKG, re.I)),
    ("npm", True, re.compile(_SEP + r"(?:npx|bunx|pnpx)\s+" + _PKG, re.I)),
    ("npm", True, re.compile(_SEP + r"(?:pnpm|yarn|bun)\s+(?:dlx|x)\s+" + _PKG, re.I)),
    ("pypi", False, re.compile(_SEP + r"(?:sudo\s+)?(?:python3?\s+-m\s+)?(?:(?:pip3?|uv\s+pip)\s+install|uv\s+add|"
                               r"pipx\s+install)\s+" + _PKG, re.I)),
    ("pypi", True, re.compile(_SEP + r"(?:uvx|pipx\s+run)\s+" + _PKG, re.I)),
    ("other", False, re.compile(_SEP + r"(?:sudo\s+)?(?:gem|cargo|go|brew|apt|apt-get|dnf|yum|choco|winget)\s+"
                                r"(?:install|get)\s+" + _PKG, re.I)),
]
PIPE_TO_SHELL = re.compile(
    r"(?:curl|wget|iwr|invoke-webrequest|irm|invoke-restmethod)\b[^|;&\n]*?(https?://[^\s'\"|;&)]+)[^|;&\n]*"
    r"\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b|"
    r"(?:ba|z)?sh\s+(?:-c\s+)?[\"']?\$?\(?\s*<?\(?\s*(?:curl|wget)\b[^)\n]*?(https?://[^\s'\"|;&)]+)|"
    r"(?:iex|invoke-expression)\b[^\n]*?(https?://[^\s'\"|;&)]+)|"
    r"(?:curl|wget)\b[^|;&\n]*?(https?://[^\s'\"|;&)]+)[^|;&\n]*\|\s*(?:python3?|node|perl|ruby)\b", re.I)
COMMAND_KEYS = {"command", "cmd", "commands", "script", "shell", "code", "args", "input", "run", "line"}
_SKIP = re.compile(r"^(?:-.*|install|add|i|run|-r|--requirement|\.|\.\.?/.*|/.*|[\w.-]+\.txt)$")


def _packages(blob: str) -> list[str]:
    out = []
    for tok in blob.split():
        tok = tok.strip("'\"")
        if not tok or _SKIP.match(tok):
            if tok in ("-r", "--requirement"):
                break
            continue
        if tok.startswith(("&", "|", ";", ">", "<", "#")):
            break
        out.append(tok)
        if len(out) >= 10:
            break
    return out


def bare_name(spec: str) -> str:
    """Package name without version: lodash@4 -> lodash, @a/b@1 -> @a/b, requests==2 -> requests."""
    s = spec.strip()
    if s.startswith("@"):
        scope, _, rest = s[1:].partition("/")
        return "@" + scope + "/" + rest.split("@", 1)[0] if rest else s
    return re.split(r"[@=<>!~\[;]", s, maxsplit=1)[0]


def installs(text: str) -> list[tuple[str, str]]:
    """(ecosystem, package or URL) for install and download-and-run commands in text."""
    found: list[tuple[str, str]] = []
    for eco, first_only, rx in INSTALLS:
        for m in rx.finditer(text):
            specs = _packages(m.group(1))
            for spec in specs[:1] if first_only else specs:
                if re.match(r"https?://|git\+|github:", spec):
                    found.append(("url", spec))
                else:
                    found.append((eco, bare_name(spec)))
    for m in PIPE_TO_SHELL.finditer(text):
        url = next((g for g in m.groups() if g), "")
        found.append(("script", url))
    seen, out = set(), []
    for item in found:
        if item not in seen and item[1]:
            seen.add(item)
            out.append(item)
    return out


@lru_cache(maxsize=1)
def popular() -> dict[str, set[str]]:
    path = Path(__file__).with_name("data") / "popular_packages.txt"
    eco, out = "npm", {"npm": set(), "pypi": set()}
    for line in path.read_text().splitlines():
        line = line.strip()
        if line.startswith("[") and line.endswith("]"):
            eco = line[1:-1]
        elif line and not line.startswith("#"):
            out.setdefault(eco, set()).add(line.lower())
    return out


def _one_edit(a: str, b: str) -> bool:
    """True if a and b differ by one insert, delete, substitution or swap of neighbours."""
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        diff = [i for i in range(len(a)) if a[i] != b[i]]
        return len(diff) == 1 or (len(diff) == 2 and diff[1] == diff[0] + 1
                                  and a[diff[0]] == b[diff[1]] and a[diff[1]] == b[diff[0]])
    if len(a) > len(b):
        a, b = b, a
    i = 0
    while i < len(a) and a[i] == b[i]:
        i += 1
    return a[i:] == b[i + 1:]


def lookalike(eco: str, name: str) -> str | None:
    """The popular package this name imitates, if it's one letter off or a look-alike."""
    if eco not in ("npm", "pypi"):
        return None
    names = popular().get(eco, set())
    n = name.lower()
    if eco == "pypi":  # PyPI treats -, _ and . as the same character
        n = re.sub(r"[-_.]+", "-", n)
        names = {re.sub(r"[-_.]+", "-", p) for p in names}
    if n in names or len(n) < 4:
        return None
    flat = re.sub(r"[-_.]", "", n)
    skel = d.skeleton(n)
    for p in sorted(names):
        if len(p) < 4:
            continue
        if _one_edit(n, p) or d.skeleton(p) == skel:
            return p
        if eco == "npm" and flat == re.sub(r"[-_.]", "", p):
            return p
    return None


# ------------------------------------------------------ archived MCP servers
# MCPhantom (Glow Labs, Nov 2026): coding agents install the archived
# @modelcontextprotocol reference servers from training data. They get no
# security fixes (the Puppeteer one lets a web page start any program).
ARCHIVED_SERVERS = {
    "@modelcontextprotocol/server-github": "GitHub's own server (github/github-mcp-server)",
    "@modelcontextprotocol/server-gitlab": "GitLab's own MCP server",
    "@modelcontextprotocol/server-slack": "a maintained Slack server",
    "@modelcontextprotocol/server-puppeteer": "@playwright/mcp",
    "@modelcontextprotocol/server-brave-search": "@brave/brave-search-mcp-server",
    "@modelcontextprotocol/server-google-maps": "a maintained Google Maps server",
    "@modelcontextprotocol/server-postgres": "a maintained Postgres server",
    "@modelcontextprotocol/server-redis": "a maintained Redis server",
    "@modelcontextprotocol/server-gdrive": "a maintained Google Drive server",
    "@modelcontextprotocol/server-aws-kb-retrieval": "AWS's own MCP servers (awslabs)",
    "@modelcontextprotocol/server-everart": "a maintained server",
    "@modelcontextprotocol/create-server": "the MCP SDK's current docs",
    "mcp-server-sentry": "Sentry's own MCP server",
    "mcp-server-sqlite": "a maintained SQLite server",
}
_ARCHIVED = re.compile(r"(?<![\w@/.-])(" + "|".join(re.escape(k) for k in ARCHIVED_SERVERS) + r")(?![\w/-])", re.I)


def archived_servers(text: str) -> list[str]:
    """Archived, unpatched MCP reference servers named in text (a command or a config)."""
    out: list[str] = []
    for m in _ARCHIVED.finditer(text):
        name = m.group(1).lower()
        if name not in out:
            out.append(name)
    return out


# ------------------------------------------------------ browser launch hijack
# Browser tools that pass model-chosen launch options to Chrome (the archived
# Puppeteer server's launchOptions) can be told to start any program, or to
# run a command for every renderer. Real browsers only.
BROWSER_EXE = re.compile(r"(?:^|[/\\])(?:google[ -]chrome[\w-]*|chrome(?:-headless-shell|_headless_shell)?|"
                         r"chromium(?:-browser)?|headless_shell|msedge|microsoft[ -]edge[\w-]*|brave(?:-browser)?|"
                         r"brave browser|firefox|thorium|vivaldi|opera)(?:\.exe|\.app(?:/.*)?)?$", re.I)
EXE_KEYS = {"executablepath", "executable_path", "executable", "browserpath", "browser_path", "chromepath",
            "chrome_path", "binary", "binarypath", "browserexecutable"}
LAUNCH_FLAGS = re.compile(r"--(?:renderer|utility|gpu|ppapi|plugin|nacl|zygote)-(?:cmd-prefix|launcher)|"
                          r"--browser-subprocess-path|--(?:renderer|gpu)-startup-dialog-cmd", re.I)


BROWSER_WORDS = {"browser", "puppeteer", "playwright", "chrome", "chromium", "launch", "headless", "navigate",
                 "selenium", "webdriver", "page", "screenshot"}


def browser_launch(pairs: list[tuple[str, str]], tool: str = "") -> str | None:
    """Why these (key, value) arguments would make a browser tool start another program.

    The program-path check only applies to browser tools (named like one, or
    passing launch options): a debugger's or runner's "executable" is normal.
    The Chrome flags that run a command are suspicious anywhere.
    """
    words = set(re.split(r"[^a-z0-9]+", re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", tool).lower()))
    keys = {re.sub(r"[^a-z]", "", k.lower()) for k, _ in pairs}
    browser = bool(words & BROWSER_WORDS) or any(
        w in k for k in keys for w in ("launch", "headless", "browser", "puppeteer", "chrome"))
    for key, value in pairs:
        k = re.sub(r"[\s-]", "", key).lower()
        v = value.strip()
        if browser and k in EXE_KEYS and v and not BROWSER_EXE.search(v.rstrip("/\\")):
            return f"it sets the browser program to {d.safe_text(v, 60)}, which isn't a browser"
        m = LAUNCH_FLAGS.search(v)
        if m:
            return f"it passes {m.group(0)}, a Chrome flag that runs a command"
    return None
