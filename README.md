# Tripline

**The open-source, vendor-neutral runtime firewall for AI agents.**
Tripline sits between your agent (Claude, Cursor, any MCP client) and its MCP servers. It stops poisoned tools, rug-pulls, prompt injection in tool output, and data leaving through tool calls, while the agent is running. When a call is risky but might be legitimate, it asks you in the app instead of guessing.

```
 MCP client  ⇄  tripline  ⇄  MCP server
 (Claude,        checks         (GitHub, Slack, files,
  Cursor...)     every message   or a remote https:// server)
```

Scanners check a tool before you install it. Red-teaming tools test an agent before you ship it. Tripline guards what happens **after**: the live traffic between the agent and its tools.

## Get started

```bash
pip install git+https://github.com/lakshyab20/tripline   # PyPI release coming
tripline install --dry-run      # see which servers in Claude/Cursor/... would be protected
tripline install                # protect them (backs up each config; `tripline uninstall` restores)
```

Restart the apps. Every server now runs through Tripline.

## See it

![A hijacked agent vs. a malicious MCP server: 4 attacks succeed without Tripline, all are stopped with it](docs/demo.gif)

```bash
tripline demo --unprotected   # a hijacked agent vs. a malicious server: 4 attacks succeed
tripline demo                 # same attack through tripline: every one is stopped
```

## What it stops

| Attack | What happens | Tripline's rule |
|---|---|---|
| **Tool poisoning** | A tool's description hides instructions for the model, often in invisible Unicode | `poisoned-tool`: hidden from the agent, calls refused |
| **Rug-pull** | A tool is harmless when you approve it, then changes later | `rug-pull`: every definition is pinned by SHA-256; a change is quarantined |
| **Indirect prompt injection** | Tool output (a page, an issue, an email) tells the model what to do | `injected-response`: withheld, or labelled as untrusted in warn mode |
| **Injected destinations** | The output says "email this to attacker@…" or "transfer to account …" and the agent does it | `untrusted-destination`: an address, URL, account or ID that came from tool output can't decide where data goes without your OK |
| **Data theft** | A secret read through one server leaves through another | `tainted-flow`: tracked across every server in the app, even base64-encoded, reversed, reformatted or split up |
| **High-impact actions** | After reading untrusted content, the agent pays, unlocks, grants access or deletes | `after-untrusted`: asks you first |
| **Credential leaks** | API keys, tokens or private keys in tool-call arguments | `secret-in-args` |
| **Look-alike tools** | A new tool named `send_emaіl` (Cyrillic і) shadows `send_email` | `shadow-tool` |

Detection covers hidden Unicode, base64, look-alike letters, English plus Hindi/Hinglish, Spanish, French, German and Portuguese phrasings, common credentials, and India-aware PII (PAN, Aadhaar, Luhn-checked card numbers).

## Measured, not claimed

`tripline bench` scores every layer on public datasets (InjecAgent, BIPIA, NotInject) that the built-in classifier never saw in training. Run it yourself; numbers below are v0.2.

**Replaying 1,054 InjecAgent attacks end to end** (a fully hijacked agent tries to complete each attack):

| Configuration | Direct harm stopped | Data theft stopped | Legitimate runs interrupted |
|---|---:|---:|---:|
| Detection only (regex) | 0% | 1.7% | 0% |
| Data-flow rules, destinations only | 36.7% | **100%** | 1.7% |
| **Default** (+ ask before high-impact actions) | **63.3%** | **100%** | 24.3%¹ |
| Strict (ask before every change after untrusted content) | 96.7% | 100% | 98.4% |

¹ Every one of these is a high-impact action (payment, unlock, access grant…) right after reading outside content: a confirmation click, not a block, in apps that support prompts.

**Detection alone, on attacks hidden in realistic tool output:**

| | Regex | + built-in classifier |
|---|---:|---:|
| Attacks caught (avg of 3 sets) | 24.7% | 39.8% |
| False alarms (avg of 4 harmless sets) | 0.0% | 3.5% |

The lesson behind the design: **detection can't be the main defence.** Attackers can always reword, and InjecAgent's polite "Please unlock my front door" doesn't look like an attack. What stops attacks is structure: pinning, data flow, and asking a person before risky actions. Detection is a cheap first filter.

## Confirmation prompts

Some calls aren't clearly wrong, only risky: replying to an address the agent just read, a payment after browsing, a tool's first use. If your app supports MCP elicitation, Tripline asks you in the app:

```
Tripline: allow 'send_email' on inbox?
- The email amy.watson@gmail.com came from the output of 'inbox/read_page', not from you.
Arguments: {"to": "amy.watson@gmail.com", "body": "..."}
```

Apps without prompts get `confirm_fallback` (block by default, with a message explaining how to adjust).

## Use it manually

```bash
# Local server
claude mcp add github -- tripline wrap --name github -- npx -y @modelcontextprotocol/server-github

# Remote server (Streamable HTTP); $VARS in headers are read from the environment
tripline wrap --name linear --url https://mcp.linear.app/mcp --header "Authorization: Bearer $LINEAR_TOKEN"

# Untrusted server: hide your home folder from it (experimental)
tripline wrap --name sketchy --sandbox auto --allow-path ~/projects/app -- npx -y some-server
```

```bash
tripline pins list                       # what is pinned, what is waiting for review
tripline pins approve --name github add  # accept a changed definition after reading it
tripline log                             # recent decisions
tripline scan suspicious.txt             # scan any text; exit code 1 if flagged (CI-friendly)
tripline bench --agent                   # reproduce the numbers above
```

## Policy

Defaults are safe; override with `--config tripline.toml`:

```toml
[policy]
on_first_use = "confirm"            # ask before each tool's first call, instead of trust-on-first-use
confirm_after_untrusted = true      # strict mode
classifier = "builtin"              # second-opinion ML classifier (warn mode by default)
trusted_tools = ["get_contact"]     # outputs that may decide destinations
deny_tools = ["delete_repo"]
```

See [`tripline.example.toml`](tripline.example.toml) for every option.

## How it works

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md). In short: Tripline relays MCP's JSON-RPC between the app and the server, local (stdio) or remote (Streamable HTTP). A pure decision engine (`firewall.py`) inspects every message, and a shared data-flow store (`flow.py`) remembers where sensitive values and destinations came from, across all servers one app runs. It fails closed: a message that can't be fully inspected is stopped, never passed through.

Zero runtime dependencies. Python 3.11+. 173 tests, including attacks on Tripline itself from four rounds of security review. Tested against the official MCP Python SDK (stdio and Streamable HTTP, protocol 2025-11-25, elicitation).

## Honest limitations

- **Detection is bypassable.** Rewording gets past regex; the built-in classifier is a bag-of-words model and misses polite, attack-shaped requests. That's why structural rules carry the weight.
- **Action-only injections** ("unlock the door") with no injected destination are stopped by default only for high-impact actions (63% in the replay). Strict mode stops 97% at the cost of a prompt on almost every change.
- **Data leaving in plain prose** isn't caught unless it contains tracked secrets or goes to an injected destination. Secrets split into pieces shorter than 12 characters aren't recognised.
- **The sandbox is experimental:** the commands are tested, but run them on your OS before relying on it.
- **Malicious local server code** can act without the model. Use `--sandbox` for servers you don't trust.

See [SECURITY.md](SECURITY.md) for the threat model, review history and how to report a vulnerability.

## Roadmap

- Transformer classifier backend (Prompt Guard 2 / PIGuard via ONNX), measured with `tripline bench`
- Per-tool policies and argument schemas (CaMeL-style capabilities)
- Team dashboard, central policies and alerts (Slack, SIEM)

## License

Apache-2.0. Copyright 2026 Lakshya Bhardwaj. The built-in classifier's training data is described in [`MODEL_CARD.md`](src/tripline/models/MODEL_CARD.md).
