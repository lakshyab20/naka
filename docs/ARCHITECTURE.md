# Architecture

## The problem in one paragraph

An AI agent treats everything it reads as possible instructions. With MCP, it reads three kinds of text from third parties: tool **definitions** (names, descriptions, schemas), tool **results** (web pages, issues, emails, files), and the instructions it gets from those. Any of them can be written by an attacker. The model can't reliably tell data from instructions, so the defence has to live outside the model, in the traffic.

## Where Tripline sits

```
 ┌──────────────┐  stdin/stdout  ┌─────────────────────────────┐  stdin/stdout  ┌──────────────┐
 │  MCP client  │ ─────────────▶ │          tripline           │ ─────────────▶ │  MCP server  │
 │ Claude/Cursor│ ◀───────────── │  proxy.py  →  firewall.py   │ ◀───────────── │ (child proc) │
 └──────────────┘                └──────────────┬──────────────┘                └──────────────┘
                                                │ stderr: live log
                                                ▼
                                   ~/.tripline/pins/*.json  (tool pins)
                                   ~/.tripline/audit.jsonl  (every decision)
```

The client launches `tripline wrap -- <server command>` as if it were the server. Tripline launches the real server as a child process and relays messages both ways. Neither side knows it's there, so it works with any MCP client and any stdio MCP server without changes to either.

## Modules

| File | Role | I/O? |
|---|---|---|
| `proxy.py` | Transport. Two threads pump lines client→server and server→client, and ask the firewall about each message. | yes |
| `firewall.py` | Decision engine. One message in, a `Decision(forward, reply)` out. Holds session state. | no (audit writes only) |
| `detectors.py` | Pure text functions: injection, hidden Unicode, base64, secrets, PII. | no |
| `store.py` | Tool pins (trust on first use) and the JSONL audit log. | disk |
| `policy.py` | Which rules block and which only warn. TOML. | reads config |
| `cli.py` | `wrap`, `pins`, `scan`, `log`, `demo`. | yes |
| `demo/` | A deliberately malicious MCP server and a scripted hijacked agent. | yes |

Transport and decisions are separate so the same engine can sit behind Streamable HTTP later, and so every rule can be unit-tested without processes.

## Message flow

MCP over stdio is newline-delimited JSON-RPC 2.0. A response carries only the request's `id`, not its method, so the firewall keeps `pending[id] = (method, params)` for every request it forwards. That's how it knows a response is a `tools/list` or `tools/call` result.

Three checkpoints, and everything else passes through untouched:

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

## Why these choices

- **Proxy over SDK plug-in.** A wrapper works with every client and server in every language today. A library would only protect apps that adopt it.
- **Blocks as tool results, not JSON-RPC errors.** An error can make clients abort or retry. A tool result with `isError` reaches the model as text, so it can tell the user what happened.
- **Pinning and data flow, not only detection.** Pattern matching can be evaded by rewording. A hash doesn't care about wording. "A secret from tool A is leaving through tool B" doesn't depend on how the attacker phrased the instructions. Detection catches the obvious cases cheaply; structure catches the rest.
- **Trust on first use.** It's the SSH `known_hosts` model: no setup, and it makes the rug-pull, the hardest attack to see, the easiest to catch.
- **Fail open on internal errors.** If Tripline itself crashes on a message, it passes the message through and logs it. A security tool that breaks the agent gets uninstalled. Policy decisions still fail closed.
- **Never log secrets.** Findings carry redacted excerpts. Raw tainted values exist only in memory for the session.
- **Zero dependencies.** `pip install` and done. Nothing to audit but this repo, which matters for a security tool.

## Extending

- **New detector:** add a pattern to `INJECTION_RULES` / `SECRET_RULES` / `PII_RULES` in `detectors.py`, with positive and negative tests in `tests/test_detectors.py`.
- **New rule:** add a check in `Firewall._check_call` or `_inspect_result`, an `on_*` option in `Policy`, and a test in `tests/test_firewall.py`.
- **New transport:** reuse `Firewall.from_client` / `from_server`. Only the I/O changes.
