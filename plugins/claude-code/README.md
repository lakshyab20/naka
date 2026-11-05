# Naka for Claude Code

Naka's firewall for Claude Code's own tools. MCP servers are protected by `naka install`; this plugin covers what doesn't go through MCP: Bash, file writes and edits, web fetch and web search.

```
/plugin marketplace add lakshyab20/naka
/plugin install naka@naka
```

It needs Naka (`pip install naka`) or [uv](https://docs.astral.sh/uv/) on your PATH.

What it does:

- **Before a tool runs**, the call is checked with Naka's rules. A secret read earlier leaving through `curl`, a decoy key from `naka canary plant` being used, a page's instructions copied into `CLAUDE.md`, or `npx some-package` right after reading an issue: blocked, or Claude Code asks you first with Naka's reason.
- **After a tool runs**, its output is remembered and scanned. Instructions aimed at the AI in a fetched page are flagged to Claude, and data-leaving calls ask first for the rest of the session.

Settings: the plugin reads `~/.naka/policy.toml` if it exists (every option is in [naka.example.toml](../../naka.example.toml)). Decisions go to `naka log`.
