# Changelog

All notable changes to Naka. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- The MCP server scan is now a website, [lakshyab20.github.io/naka](https://lakshyab20.github.io/naka/), rebuilt every Monday by GitHub Actions with no commits: each server's last few releases are compared tool by tool (added, removed and changed tools, new reach such as sending data out, new findings), and each week is compared with the previous one.
- `naka eval-real`: real attacks on real MCP servers (filesystem, fetch, memory, Desktop Commander, the archived Puppeteer server), judged by what actually happened. Run weekly and published: unprotected, all 7 attacks happened; Naka stopped 7/7 and interrupted 0 of 6 everyday tasks.
- `naka audit --through-naka`: every scanned server run behind Naka's firewall, to count tools Naka would hide by mistake (first run: 0 of 75 servers).
- A bare `[IMPORTANT]` in a tool description no longer quarantines the tool on its own (it is ordinary emphasis in Vercel's next-devtools-mcp); with other signals it still does.
- `naka audit` records a fingerprint of every tool definition and accepts pinned versions in server lists.
- MCPhantom ([Glow Labs](https://www.glow.io/blogs/mcphantom-ai-coding-agents-are-installing-vulnerable-deprecated-mcp-servers-from-training-data), Nov 2026): installing an archived, unpatched `@modelcontextprotocol` reference server (server-github, server-puppeteer, server-slack...) from a command or an MCP config asks first and names the maintained replacement (`archived-server`); browser launch options that start another program, such as a non-browser `executablePath` or `--renderer-cmd-prefix`, are blocked (`browser-launch`). Two attacks and two everyday twins added to the `agentjacking` eval suite. The browser check applies to browser tools only, so a debugger's or script runner's `executable` stays allowed. The scan page labels archived servers and names their replacements.

## [0.4.0] - 2026-11-05

### Added
- `naka audit`: start an MCP server, read only its lists, and report hidden instructions, cross-server mentions, "lethal trifecta" capability mixes, mislabelled read-only tools and context cost. Useful before installing any server.
- The public MCP server scan (`.github/workflows/mcp-scan.yml`): `naka audit` run weekly on the most downloaded MCP servers, in a throwaway GitHub Actions machine with placeholder settings only.
- The first public scan (docs/MCP-SCAN.md): 119 popular MCP servers, 75 started; no hidden instructions, 12 "lethal trifecta" servers, 8 that go from outside content to running code.
- Canary keys: `naka canary plant` leaves decoy credentials; sending one anywhere blocks the call and locks the session (`canary`, `hijacked-session`).
- Elicitation phishing: server pop-up forms asking for passwords, codes, keys or cards, or impersonating Naka, are declined (`elicitation-phishing`).
- Agentjacking: install and download-and-run commands after outside content ask first (`install-after-untrusted`), script links from that content are blocked (`untrusted-install`), and typo-squatted package names ask first (`lookalike-package`).
- Claude Code plugin (`/plugin install naka@naka`) and `naka hook claude-code`: Naka's rules for Claude Code's built-in tools. Calls are denied, or Claude Code asks with Naka's reason, before Bash, file writes and web fetches run; outputs are remembered and scanned after.
- `agentjacking` eval suite: 4 attacks modelled on the 2026 Sentry agentjacking reports, plus 3 everyday installs.

## [0.3.0] - 2026-11-04

### Added
- **AI worm protection** (`spread`): Naka remembers the wording of everything untrusted tools return, and stops an injected note being copied into email replies, forwards, issue comments, code comments or team chat, where it would hijack the next AI. Works in several languages, and on edited or padded copies.
- **Memory poisoning protection** (`memory-poisoning`, `memory-write`): outside text can't be written into CLAUDE.md, AGENTS.md, Cursor/Cline/Windsurf rules, skills, memory servers, MCP configs, git hooks or CI workflows without your OK. Text from your own project files is fine.
- **`naka eval`**: runs attack scenarios and everyday tasks through any MCP guard over real stdio, and scores what actually reached the tools. Suites: `mcp-attacks`, `contagion` (the first open test set for AI worms and memory poisoning) and `injecagent`. `--keep` saves every run for inspection.
- [Scoreboard](docs/SCOREBOARD.md) comparing no guard, Naka and Pipelock.
- [Naka explained simply](docs/EXPLAINED.md), with six pictures.
- New logo, contributing guide, code of conduct, issue templates and release workflow.

### Changed
- Renamed from Tripline (its working name) to **Naka**, Hindi for a checkpoint. The command is now `naka`, the state folder `~/.naka`, and `naka uninstall` still recognises apps set up under the old name.
- Error messages from tools are now treated as tool output (an attacker can hide instructions in them).
- Sandboxed servers start in an allowed folder. The macOS sandbox is verified on a real Mac.

### Fixed
- Red-team round 5: 8 bypasses and 6 false alarms in the first version of spread and memory protection (see [SECURITY.md](SECURITY.md)).
- `naka eval` scoring: payloads are compared with what honest tools would return, so a guard that refuses to read a secret file gets credit.

## [0.2.0] - 2026-11-04

### Added
- Cross-server data flow: a secret read through one server can't leave through another, even encoded, reversed or split.
- Confirmation prompts in the app (MCP elicitation) for risky but possibly legitimate calls.
- Remote servers (Streamable HTTP), `naka install` / `uninstall` for Claude, Cursor, VS Code and more, and sandboxing (macOS, Linux bubblewrap, Docker).
- `naka bench` on InjecAgent, BIPIA and NotInject, and an optional built-in classifier.

### Fixed
- Red-team round 4 findings.

## [0.1.0] - 2026-11-04

### Added
- First release: an MCP proxy with tool pinning (rug-pull detection), poisoned-tool detection, prompt-injection detection in tool output, secret detection in arguments, look-alike tool names, and fail-closed handling.
- Red-team rounds 1 to 3: fixes for handshake bypasses, rewording and disguised payloads.

[0.3.0]: https://github.com/lakshyab20/naka/releases/tag/v0.3.0
[0.2.0]: https://github.com/lakshyab20/naka/compare/e4381dd...d10066a
[0.1.0]: https://github.com/lakshyab20/naka/commit/e4381dd
