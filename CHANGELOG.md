# Changelog

All notable changes to Tripline. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## [0.3.0] - 2026-11-04

### Added
- **AI worm protection** (`spread`): Tripline remembers the wording of everything untrusted tools return, and stops an injected note being copied into email replies, forwards, issue comments, code comments or team chat, where it would hijack the next AI. Works in several languages, and on edited or padded copies.
- **Memory poisoning protection** (`memory-poisoning`, `memory-write`): outside text can't be written into CLAUDE.md, AGENTS.md, Cursor/Cline/Windsurf rules, skills, memory servers, MCP configs, git hooks or CI workflows without your OK. Text from your own project files is fine.
- **`tripline eval`**: runs attack scenarios and everyday tasks through any MCP guard over real stdio, and scores what actually reached the tools. Suites: `mcp-attacks`, `contagion` (the first open test set for AI worms and memory poisoning) and `injecagent`. `--keep` saves every run for inspection.
- [Scoreboard](docs/SCOREBOARD.md) comparing no guard, Tripline and Pipelock.
- [Tripline explained simply](docs/EXPLAINED.md), with six pictures.
- New logo, contributing guide, code of conduct, issue templates and release workflow.

### Changed
- Error messages from tools are now treated as tool output (an attacker can hide instructions in them).
- Sandboxed servers start in an allowed folder. The macOS sandbox is verified on a real Mac.

### Fixed
- Red-team round 5: 8 bypasses and 6 false alarms in the first version of spread and memory protection (see [SECURITY.md](SECURITY.md)).
- `tripline eval` scoring: payloads are compared with what honest tools would return, so a guard that refuses to read a secret file gets credit.

## [0.2.0] - 2026-11-04

### Added
- Cross-server data flow: a secret read through one server can't leave through another, even encoded, reversed or split.
- Confirmation prompts in the app (MCP elicitation) for risky but possibly legitimate calls.
- Remote servers (Streamable HTTP), `tripline install` / `uninstall` for Claude, Cursor, VS Code and more, and sandboxing (macOS, Linux bubblewrap, Docker).
- `tripline bench` on InjecAgent, BIPIA and NotInject, and an optional built-in classifier.

### Fixed
- Red-team round 4 findings.

## [0.1.0] - 2026-11-04

### Added
- First release: an MCP proxy with tool pinning (rug-pull detection), poisoned-tool detection, prompt-injection detection in tool output, secret detection in arguments, look-alike tool names, and fail-closed handling.
- Red-team rounds 1 to 3: fixes for handshake bypasses, rewording and disguised payloads.

[0.3.0]: https://github.com/lakshyab20/tripline/releases/tag/v0.3.0
[0.2.0]: https://github.com/lakshyab20/tripline/compare/e4381dd...d10066a
[0.1.0]: https://github.com/lakshyab20/tripline/commit/e4381dd
