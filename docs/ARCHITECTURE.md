# Architecture

## The problem in one paragraph

An AI agent treats everything it reads as possible instructions. With MCP, it reads three kinds of text from third parties: tool **definitions** (names, descriptions, schemas), tool **results** (web pages, issues, emails, files), and the instructions it gets from those. Any of them can be written by an attacker. The model can't reliably tell data from instructions, so the defence has to live outside the model, in the traffic.

## Where Tripline sits

```
 ┌──────────────┐  stdin/stdout  ┌───────────────────────────────┐  stdio (child process,
 │  MCP client  │ ─────────────▶ │           tripline            │  optionally sandboxed)
 │ Claude/Cursor│ ◀───────────── │ proxy.py → firewall.py        │ ─────────▶ local MCP server
 └──────┬───────┘   elicitation  │              ↕ flow.py        │
        │ ◀── "allow this?" ──── │ upstream.py                   │  Streamable HTTP
        ▼                        └──────────────┬────────────────┘ ─────────▶ remote MCP server
     the user                                   │
                       ~/.tripline/pins/*.json     tool pins
                       ~/.tripline/audit.jsonl     every decision
                       ~/.tripline/sessions/*.jsonl  data-flow state shared by the app's servers
```

The client launches `tripline wrap -- <server command>` (or `--url`) as if it were the server. Tripline starts or connects to the real server and relays messages both ways. Neither side has to know it's there, so it works with any MCP client and server. `tripline install` does that rewrite in the apps' config files for you.

## Modules

| File | Role | I/O? |
|---|---|---|
| `proxy.py` | Transport. Two threads pump lines client→server and server→client, and ask the firewall about each message. | yes |
| `firewall.py` | Decision engine. One message in, a `Decision(forward, reply)` out. Holds session state. | no (audit writes only) |
| `detectors.py` | Pure text functions: injection, hidden Unicode, base64, secrets, PII. | no |
| `store.py` | Tool pins (trust on first use) and the JSONL audit log. | disk |
| `policy.py` | Which rules block and which only warn. TOML. | reads config |
| `flow.py` | Data-flow state: hashed secrets and destinations seen in tool output, shared through a session file by every Tripline process the same app started. | disk |
| `classifier.py` | Optional built-in ML classifier (logistic regression over hashed word n-grams, sliding windows). | no |
| `upstream.py` | Where the server lives: a child process, or a remote URL over Streamable HTTP. | yes |
| `sandbox.py` | Builds bwrap / sandbox-exec / docker commands that hide the home folder from a server. | no |
| `install.py` | Rewrites Claude/Cursor/Windsurf/VS Code configs to wrap every server, and restores them. | disk |
| `bench.py` | Detection benchmark and end-to-end InjecAgent replay. | network (datasets), disk |
| `cli.py` | `wrap`, `install`, `uninstall`, `pins`, `scan`, `log`, `bench`, `demo`. | yes |
| `demo/` | A deliberately malicious MCP server and a scripted hijacked agent. | yes |

Transport and decisions are separate, so the same engine serves local and remote servers, and every rule can be unit-tested without processes.

## Message flow

MCP over stdio is newline-delimited JSON-RPC 2.0. A response carries only the request's `id`, not its method, so the firewall keeps `pending[id] = (method, params)` for every request it forwards. That's how it knows a response is a `tools/list` or `tools/call` result.

Three main checkpoints, plus resources, prompts, error messages and server-initiated sampling requests, which get the same injection scan. Everything else passes through untouched:

1. **`tools/list` result (server → client)**
   - Scan each description and schema for injection. If it scores at or above the threshold → **poisoned-tool**: removed from the list, quarantined, held in `pending` for review.
   - Compare the definition's SHA-256 with its pin. If it differs → **rug-pull**: removed, quarantined, held.
   - If the tool is unknown: on the server's first listing ever, pin it (trust on first use). Later, `on_new_tool` decides between pinning it with a warning and holding it.
   - Strip invisible characters from descriptions that are kept.

2. **`tools/call` request (client → server)**, checked in order:
   - deny list, then quarantine
   - **tainted-flow**: does the argument JSON contain a sensitive value that an *earlier result from a different tool* produced?
   - **secret-in-args**: credentials anywhere in the arguments
   - **egress-lockdown**: has injected content reached the model in this session, and is this tool an egress tool (by config or name hint)?
   - PII in arguments

   If a rule blocks, the request is never forwarded. Tripline answers the client itself with `result.isError = true` and a message the model can read.

3. **`tools/call` result (server → client)**
   - Record secrets and PII (except email addresses) as tainted values, keyed to the source tool. These are kept in memory only.
   - Scan for injection. In block mode, replace the result with a "withheld" message. In warn mode, prepend a warning label ("spotlighting"), strip hidden characters, and set `injection_seen_from`, which turns on egress lockdown.

## Data flow and confirmations

Detection asks "does this text look like an attack?", which wording can always defeat. The data-flow rules ask questions wording can't change:

- **Did this value come from a tool's output?** `flow.py` records the secrets (credentials, PAN, Aadhaar, cards) and destinations (emails, URLs, hosts, IPs, phone, account numbers, IDs) in every result, as keyed hashes. Secrets are also recorded in their base64, hex, base32, reversed and canonical (lowercase, no separators) forms, and as 12-character pieces, so re-encoding or splitting doesn't hide them.
- **Is it now deciding where something goes?** `destination_text()` reads only destination-like arguments (`to`, `recipient`, `url`, `account`, `guest`...), not payloads like an email body. If a destination there came from untrusted output, and the tool changes something (`changes_something()`), the user is asked.
- **Is this a high-impact action after untrusted content?** Payments, unlocking, access grants, deletion and execution ask first. Strict mode asks before every change.

The state is shared across servers: every Tripline process started by the same app (same parent process, or the same `TRIPLINE_SESSION`) appends to one file, so a key read through the GitHub server is recognised when the Gmail server tries to send it.

**Confirmations** use MCP elicitation. When a rule's action is `confirm` and the client declared the elicitation capability, the firewall holds the `tools/call`, sends the client an `elicitation/create` request with a random id (`tripline-confirm-<hex>`), and forwards the held call only if the answer is accept with `allow: true`. The model can't answer it: only the client produces JSON-RPC responses, and the id is unguessable and single-use. Without elicitation, `confirm_fallback` decides.

## Why these choices

- **Proxy over SDK plug-in.** A wrapper works with every client and server in every language today. A library would only protect apps that adopt it.
- **Blocks as tool results, not JSON-RPC errors.** An error can make clients abort or retry. A tool result with `isError` reaches the model as text, so it can tell the user what happened.
- **Pinning and data flow, not only detection.** Pattern matching can be evaded by rewording. A hash doesn't care about wording. "A secret from tool A is leaving through tool B" doesn't depend on how the attacker phrased the instructions. Detection catches the obvious cases cheaply; structure catches the rest.
- **Trust on first use.** It's the SSH `known_hosts` model: no setup, and it makes the rug-pull, the hardest attack to see, the easiest to catch.
- **Fail closed.** Every message comes from an untrusted party, so if Tripline can't fully inspect one (malformed shape, bad JSON, extreme nesting, oversized), it stops it: requests get an error reply, responses are replaced with an error. An earlier version passed such messages through to avoid breaking the agent. That let a malicious server bypass every check by adding one malformed item, so it was changed. Well-formed traffic is never affected.
- **Scan every string.** Inspection walks the whole message (titles, output schemas, resource links, structured content, error text), so unexpected fields can't carry instructions past the scanner.
- **Never log secrets.** Findings carry redacted excerpts. Raw tainted values exist only in memory for the session.
- **Zero dependencies.** `pip install` and done. Nothing to audit but this repo, which matters for a security tool. Even the classifier is pure Python.
- **Measure before trusting.** `tripline bench` showed regex catching ~1% of realistic embedded attacks, and a prompt-trained classifier flagging 96% of harmless tool output. Both findings changed the design: structure first, detection second, every layer scored on held-out data.
- **Ask, don't guess.** Replying to an address you just read and an injected "send it to attacker@..." look identical structurally. A confirmation turns an unsolvable classification problem into a one-click decision for the person who knows.

## Extending

- **New detector:** add a pattern to `INJECTION_RULES` / `SECRET_RULES` / `PII_RULES` in `detectors.py`, with positive and negative tests in `tests/test_detectors.py`.
- **New rule:** add a check in `Firewall._check_call` or `_inspect_result`, an `on_*` option in `Policy`, and a test in `tests/test_firewall.py`.
- **New transport:** reuse `Firewall.from_client` / `from_server`. Only the I/O changes.
