# Tripline

**The open-source, vendor-neutral runtime firewall for AI agents.**
Tripline sits between your agent (Claude, Cursor, any MCP client) and its MCP servers, and stops poisoned tools, rug-pulls, prompt injection in tool output, and data leaving through tool calls, while the agent is running.

```
 MCP client  ⇄  tripline  ⇄  MCP server
 (Claude,        checks         (GitHub, Slack,
  Cursor...)     every message   filesystem...)
```

Scanners check a tool before you install it. Red-teaming tools test an agent before you ship it. Tripline guards what happens **after**: the live traffic between the agent and its tools.

## See it

![A hijacked agent vs. a malicious MCP server: 4 attacks succeed without Tripline, all are stopped with it](docs/demo.gif)

```bash
pip install -e .
tripline demo --unprotected   # a hijacked agent vs. a malicious server: 4 attacks succeed
tripline demo                 # same attack through tripline: every one is stopped
```

```
1. Agent connects and lists the server's tools
    tripline ▸ BLOCKED poisoned-tool fact_of_the_day: hidden-unicode, conceal-from-user, sensitive-path
2. Agent reads GitHub issue #42 (the body hides instructions for the AI)
    tripline ▸ BLOCKED injected-response read_issue: override-instructions, conceal-from-user
4. Hijacked agent emails the config to the attacker
    tripline ▸ BLOCKED tainted-flow send_email: value read from 'get_config' is being sent to 'send_email'
5. ...the server quietly swaps the tool's description (rug-pull)
    tripline ▸ BLOCKED rug-pull add: definition changed since it was pinned
```

## What it stops

| Attack | What happens | Tripline's rule |
|---|---|---|
| **Tool poisoning** | A tool's description hides instructions for the model, often in invisible Unicode | `poisoned-tool`: definition is hidden from the agent and calls are refused |
| **Rug-pull** | A tool is harmless when you approve it, then changes later | `rug-pull`: every definition is pinned by SHA-256; a change is quarantined until you approve it |
| **Indirect prompt injection** | Tool output (a web page, an issue, an email) tells the model what to do | `injected-response`: output is withheld (or, in warn mode, labelled as untrusted data) |
| **Data exfiltration** | A value read from one tool is sent out through another | `tainted-flow`: sensitive values from tool output are tracked and blocked from leaving via a different tool |
| **Credential leaks** | API keys, tokens or private keys in tool-call arguments | `secret-in-args` |
| **Hijacked-agent egress** | After untrusted instructions reach the model, it calls a tool that sends data out | `egress-lockdown` |

Detectors cover hidden Unicode (including tag-character smuggling), base64-encoded payloads, common cloud and API credentials, and India-aware PII (PAN, Aadhaar, card numbers with a Luhn check).

## Use it with your agent

Put `tripline wrap --name <name> --` in front of the server command you already use.

**Claude Code**
```bash
claude mcp add github -- tripline wrap --name github -- npx -y @modelcontextprotocol/server-github
```

**Claude Desktop / Cursor** (`claude_desktop_config.json` / `.cursor/mcp.json`)
```json
{
  "mcpServers": {
    "github": {
      "command": "tripline",
      "args": ["wrap", "--name", "github", "--", "npx", "-y", "@modelcontextprotocol/server-github"],
      "env": { "GITHUB_PERSONAL_ACCESS_TOKEN": "..." }
    }
  }
}
```

The first time a server lists its tools, Tripline pins them (trust on first use). After that:

```bash
tripline pins list                       # what is pinned, what is waiting for review
tripline pins approve --name github add  # accept a changed definition after reading it
tripline log                             # recent decisions
tripline scan suspicious.txt             # scan any text; exit code 1 if flagged (CI-friendly)
```

## Policy

Every rule is `block` or `warn`. Defaults are safe; override with `--config tripline.toml`:

```toml
[policy]
on_injected_response = "warn"    # let it through, label it, and lock down egress tools
on_new_tool = "block"            # hold tools added after first approval
egress_tools = ["create_comment"]
allow_tools = ["read_docs"]      # trusted, not inspected
deny_tools = ["delete_repo"]
```

See [`tripline.example.toml`](tripline.example.toml) for every option.

## How it works

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md). In short: Tripline launches the real server as a child process and relays MCP's line-delimited JSON-RPC in both directions. A pure decision engine (`firewall.py`) inspects tool definitions, tool-call arguments and results, resources, prompts, error messages and sampling requests from the server. It fails closed: a message that can't be fully inspected is stopped, never passed through. Blocked calls come back to the model as a normal tool result with `isError: true`, so the agent can tell the user what happened instead of crashing.

Zero dependencies. Python 3.11+. 123 tests, including 98 attacks on Tripline itself from three rounds of security review (`tests/test_security.py`). Tested against the official MCP Python SDK (client and server, protocol 2025-11-25).

## Honest limitations (v0.1)

- Detection is pattern-based. A determined attacker can paraphrase, translate or encode around it. Pinning and data-flow rules don't depend on wording, which is why they exist.
- Data-flow tracking matches exact values. A secret that is re-encoded or summarised before leaving is not caught yet.
- Trust on first use: a subtly malicious tool that passes the scan on day one gets pinned.
- It guards the traffic, not the server's own code. A malicious local server is a program with your permissions and can act without the model. Run untrusted servers in a sandbox.
- stdio transport only. Streamable HTTP is next.

See [SECURITY.md](SECURITY.md) for the full threat model and how to report a vulnerability.

## Roadmap

- Streamable HTTP transport and a remote gateway mode
- `tripline install` to wrap every server in your Claude/Cursor config in one command
- ML classifier alongside the rules; multilingual injection detection
- Import red-team findings (e.g. from promptfoo) as runtime rules
- Team dashboard, central policies and alerts (Slack, SIEM)

## License

Apache-2.0. Copyright 2026 Lakshya Bhardwaj.
