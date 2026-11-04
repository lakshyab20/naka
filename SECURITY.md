# Security

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub: **Security → Report a vulnerability** on this repository. Don't open a public issue for a security problem.

You'll get an acknowledgement within 3 days. Fixes for confirmed issues ship with a regression test in `tests/test_security.py` and credit to the reporter unless you'd rather stay anonymous.

## Threat model

Tripline assumes the **MCP server is malicious** and the **model may already be under an attacker's control**. Either can send anything, including deliberately malformed messages.

### What Tripline is designed to stop

- Instructions hidden in anything the server sends that reaches the model: tool definitions (every field), tool results (every content type, structured content, error messages), resources, prompts, their listings, sampling or elicitation requests, and notifications such as log and progress messages. Common phrasings are detected in English, Hindi (including Hinglish), Spanish, French, German and Portuguese.
- New tools whose names look like an existing tool (look-alike letters, case, separators, invisible characters).
- Tool definitions that change after they were approved (rug-pulls), detected by a SHA-256 of the entire definition.
- Credentials, and sensitive values read from one tool, leaving through another tool's arguments.
- Attempts to break Tripline itself: malformed messages, invalid JSON or UTF-8, extreme nesting, oversized messages, and terminal control codes in names or descriptions.

### Design rules that keep it that way

- **Fail closed.** If a message can't be fully inspected, for any reason, it is stopped, never passed through unchecked.
- **Never forward what we couldn't parse.** Another parser might read it differently.
- **Scan every string**, not just the fields we expect, so new or unusual fields can't carry hidden instructions.
- **Never print or log raw attacker text or secrets.** Terminal output is escaped; credentials are redacted; the audit log is ASCII-only on disk.
- **Answer only what was asked.** A response must match a request Tripline forwarded, by exact id and type. Anything else is dropped.
- **Bounded work.** Text over `max_scan_bytes` (8 MB by default) in one message is blocked rather than scanned, and base64 decoding has a fixed budget.
- **No dependencies.** The only code you have to trust is in this repository.

### What Tripline does NOT protect against

Be clear about these before relying on it:

- **A malicious server's own code.** A stdio MCP server is a program running on your computer with your permissions. It can read your files or open network connections directly, without going through the model, and it can edit Tripline's pin files in `~/.tripline`. Tripline guards what flows between the server and the model. To contain the server process itself, run it in a sandbox (a container or VM); built-in sandboxing is on the roadmap.
- **Instructions that don't look like instructions.** Detection is pattern-based. Rewording, other languages or novel encodings can get past it. Pinning and data-flow rules don't depend on wording, which is why they exist.
- **Transformed secrets.** Data-flow checks match exact values. A secret the model re-encodes or paraphrases before sending is not caught.
- **A tool that is malicious on day one** and subtle enough to pass the scan gets pinned as trusted.
- **Remote servers** over HTTP aren't supported yet.

## Review history

- **Round 1 (internal):** 26 attacks on Tripline itself, including a full bypass through malformed messages. All fixed; see `tests/test_security.py`.
- **Round 2 (independent red team):** 8 confirmed findings, including a full bypass through fields named `data` or `blob`, uninspected notifications, unmatched response ids, egress-lockdown gaps, a scanning slowdown and audit-log corruption. All fixed, each with a regression test.

## Supported versions

Only the latest release receives security fixes during the 0.x series.
