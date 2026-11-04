# Security

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub: **Security → Report a vulnerability** on this repository. Don't open a public issue for a security problem.

You'll get an acknowledgement within 3 days. Fixes for confirmed issues ship with a regression test in `tests/test_security.py` and credit to the reporter unless you'd rather stay anonymous.

## Threat model

Naka assumes the **MCP server is malicious** and the **model may already be under an attacker's control**. Either can send anything, including deliberately malformed messages.

### What Naka is designed to stop

- Instructions hidden in anything the server sends that reaches the model, including the handshake's `instructions` (which clients may put in the system prompt): tool definitions (every field), tool results (every content type, structured content, error messages), resources, prompts, their listings, sampling or elicitation requests, and notifications such as log and progress messages. Common phrasings are detected in English, Hindi (including Hinglish), Spanish, French, German and Portuguese.
- New tools whose names look like an existing tool (look-alike letters, case, separators, invisible characters).
- Tool definitions that change after they were approved (rug-pulls), detected by a SHA-256 of the entire definition.
- Credentials, and sensitive values read from one tool, leaving through another tool's arguments, on the same or any other server the app runs, including base64/hex/base32-encoded, reversed, reformatted or split (12+ character pieces).
- Addresses, URLs, accounts and IDs from untrusted tool output deciding where a state-changing tool sends or acts (asks the user).
- High-impact actions (payments, access, deletion, execution) right after untrusted content (asks the user).
- Injected notes spreading or persisting: text from untrusted output copied into outgoing messages, comments, chat or code when it asks to be passed on (AI worms), or into the AI's memory, instruction files, skills or program-starting configs (memory poisoning). Tracked as keyed hashes of 8-word runs, across every server in the session.
- Attempts to break Naka itself: malformed messages, invalid JSON or UTF-8, extreme nesting, oversized messages, and terminal control codes in names or descriptions.

### Design rules that keep it that way

- **Fail closed.** If a message can't be fully inspected, for any reason, it is stopped, never passed through unchecked.
- **Never forward what we couldn't parse.** Another parser might read it differently.
- **Scan every string**, not just the fields we expect, so new or unusual fields can't carry hidden instructions.
- **Never print or log raw attacker text or secrets.** Terminal output is escaped; credentials are redacted; the audit log is ASCII-only on disk.
- **Answer only what was asked.** A response must match a request Naka forwarded, by exact id and type. Anything else is dropped.
- **Bounded work.** Text over `max_scan_bytes` (8 MB by default) in one message is blocked rather than scanned, and base64 decoding has a fixed budget.
- **No dependencies.** The only code you have to trust is in this repository.

### New surfaces in v0.2, and how they're protected

- **Confirmation prompts.** Ids are random (128 bits) and single-use; a held call is forwarded only on an explicit accept with `allow: true`. The prompt shows the complete arguments that will be forwarded; a call too large to show in full is blocked instead of asked about. At most 20 prompts can wait at once, each for 10 minutes. The model can't answer a prompt (only the client sends responses).
- **Shared session file** (`~/.naka/sessions/`). Holds keyed hashes, never raw values; mode 0600 in a 0700 folder; expires after 12 hours. Anything that can write to it is already local code running as you (see below).
- **Remote servers.** Remote messages go through the same reader and firewall as local ones. Redirects are never followed (a redirect could send your auth headers to another host). Plain `http://` to a non-local host is warned about.
- **`naka install`.** Backs up every file it changes; originals (which may include auth headers) are saved with mode 0600.
- **Sandbox.** Refuses to start the server if the requested sandbox isn't available; never exposes credential folders even inside allowed paths; passes the server only a minimal environment plus the variables you name with `--env`, so API keys in your environment stay out.

### What Naka does NOT protect against

Be clear about these before relying on it:

- **A malicious server's own code, outside a sandbox.** A stdio MCP server is a program running with your permissions. It can read your files, open network connections, or edit Naka's state files directly, without going through the model. `--sandbox` hides your home folder from it. The macOS sandbox has been verified on a real Mac (21 checks, including home-folder, credential, environment and network isolation). The Linux (bubblewrap) and Docker modes are still experimental: their commands are tested, but verify them on your system.
- **Rewording.** Detection is pattern-based (plus an optional bag-of-words classifier). Rewording, unusual languages or novel encodings can get past it. Pinning, data-flow rules and confirmations don't depend on wording, which is why they carry the weight.
- **Action-only injections** with no injected destination ("unlock the door") are stopped by default only when the action is high-impact (63% of InjecAgent's direct-harm cases in `naka bench --agent`). Strict mode (`confirm_after_untrusted`) stops 97%, at the cost of a prompt for nearly every change.
- **Data leaving in plain prose.** Secrets are tracked, and so are destinations. Ordinary text (a summary of your emails) sent to a destination you supplied isn't blocked. Secrets split into pieces are caught once the pieces sent (6+ characters each, across any tools) cover 75% of the secret; smaller pieces aren't recognised.
- **Following an untrusted link exactly.** A reader tool may open a URL exactly as it appeared in untrusted output, with nothing else sent along: that's normal browsing and carries none of your data. Adding a query, or sending any other data alongside, needs confirmation.
- **A tool that is malicious on day one** and subtle enough to pass the scan gets pinned as trusted, unless you use `on_first_use = "confirm"`.
- **Reworded worms and rules.** Spread and memory rules recognise copied text (runs of 8+ words, so small edits still match). A note the model fully rewrites in its own words isn't recognised as copied: it's caught only if it asks to be passed on in wording the rules know, carries a link or command into memory or instructions after outside content was read, or goes through another rule. Encoded payloads (a base64 blob passed on unchanged) aren't recognised as notes.
- **Your own project files are trusted for memory.** Plain text copied from workspace files (a README line into CLAUDE.md) is allowed, so a poisoned repository's plain-text rule without a link or command can be copied into instructions.
- **Apps without elicitation** can't show confirmation prompts; there `confirm_fallback` decides (block by default).
- **Large results are slow to scan** (about 1 second per MB with the classifier on). Only that server's own messages wait; results over `max_scan_bytes` are blocked, not passed through.
- **Legacy SSE remote servers** (the transport MCP replaced in 2025) aren't supported.

## Review history

- **Round 1 (internal):** 26 attacks on Naka itself, including a full bypass through malformed messages. All fixed; see `tests/test_security.py`.
- **Round 2 (independent red team):** 8 confirmed findings, including a full bypass through fields named `data` or `blob`, uninspected notifications, unmatched response ids, egress-lockdown gaps, a scanning slowdown and audit-log corruption. All fixed, each with a regression test.
- **Round 3 (same red team, attacking the fixes):** 6 confirmed findings, including a full bypass through the handshake's `instructions` field, rewordings around the tightened rules, text disguised as binary payloads, look-alike tool names outside the confusables table, and lockdown gaps for IPs and scheme-less hosts. All fixed, each with a regression test. Every response type is now scanned by default.

- **Round 4 (red team on v0.2):** 6 confirmed findings in the new features: a confirmation prompt that truncated the arguments it then forwarded in full, the Docker sandbox passing every environment secret to the server, HTTP redirects that carried auth headers to another host, destination checks skipped for tools named like readers or for URLs in content fields, secrets split into short pieces across tools, and unbounded pending prompts. All fixed, each with a regression test. Confirmations couldn't be forged or replayed, the macOS sandbox profile resisted injection, and every earlier fix held.

- **Round 5 (red team on spread and memory protection):** 8 bypasses and 6 false alarms in the first version. Bypasses: worm notes worded around the keyword lists ("agent", "P.S.", "snippet", German); 50,000 filler words pushing a note out of the stored wording; writing a rule to a draft and moving it onto CLAUDE.md, importing it with `@file`, or appending it through a shell tool; instruction and start-up files missing from the lists (CLAUDE.local.md, .clinerules/, Zed, Junie, Trae, CI workflows, .envrc, git config...); `curl ... | sh` and `npx` rules without a link; memory and edit tools with unrecognised names (`write_note`, `search_replace`); text in error messages not remembered; a base64 payload. False alarms: CLAUDE.md written from the project's own README, "remember this email", forwarding company news about AI tools, code in a `memory/` package, code names like `logger.info` read as links. All fixed except the base64 payload (documented above); every case is now a regression scenario in `naka eval --suite contagion`.

- **macOS sandbox test (real hardware):** 21 checks on macOS 26 (Apple silicon). Found one bug: a sandboxed server started in the caller's folder, which the sandbox hides, so npm and npx crashed. Fixed by starting servers in an allowed folder or the temp folder. All 21 checks pass.

## Supported versions

Only the latest release receives security fixes during the 0.x series.
