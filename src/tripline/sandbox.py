"""Run an MCP server sandboxed from your home folder (experimental).

Tripline inspects what a server *says*. A local server is also a program
running with your permissions: a malicious one could read ~/.ssh directly, or
edit Tripline's own pin files, without saying anything. The sandbox closes
that gap by starting the server with your home folder hidden:

    tripline wrap --sandbox auto --allow-path ~/projects/app -- npx some-server

- Linux: bubblewrap (bwrap). The filesystem is read-only, /home and /root are
  empty, /tmp is private. Toolchains under your home (nvm, uv, cargo...) are
  mounted read-only so `npx`/`uvx` still work, and their package caches
  read-write.
- macOS: sandbox-exec with a profile that denies your home folder except the
  same toolchains/caches and the paths you allow.
- Docker: any OS with Docker. The server runs in a throwaway container that
  sees only the paths you allow.

Network stays on unless --no-network (most servers call an API). If the
requested sandbox isn't available, Tripline refuses to start rather than
silently running the server unsandboxed.
"""

from __future__ import annotations

import os
import platform
import shutil
from pathlib import Path

# Under $HOME: needed to *run* common servers. Read-only.
TOOLCHAINS = [".nvm", ".volta", ".bun", ".deno", ".local/bin", ".local/share/uv", ".local/share/pnpm",
              ".cargo/bin", ".pyenv", ".rbenv", ".asdf", ".local/share/mise", "go/bin"]
# Under $HOME: package caches, written during installs. Read-write.
CACHES = [".npm", ".cache/uv", ".cache/pip", ".cache/pnpm", ".cache/node", "Library/Caches/uv",
          "Library/Caches/pip", "Library/Caches/pnpm"]
# Never exposed, even if a broader allow-path includes them.
NEVER = [".ssh", ".aws", ".gnupg", ".kube", ".docker", ".tripline", ".config/gh", ".netrc", ".npmrc",
         ".pypirc", ".git-credentials", "Library/Keychains", ".password-store"]

ENV_SKIP = {"PATH", "HOME", "PWD", "OLDPWD", "SHELL", "TMPDIR", "USER", "LOGNAME", "SHLVL", "_", "TERM",
            "SSH_AUTH_SOCK", "SSH_AGENT_PID", "GPG_AGENT_INFO", "DISPLAY", "XAUTHORITY", "DBUS_SESSION_BUS_ADDRESS"}


class SandboxUnavailable(RuntimeError):
    pass


def _existing(home: Path, rel: list[str]) -> list[Path]:
    return [home / r for r in rel if (home / r).exists()]


def _allowed(allow: list[str], home: Path) -> list[Path]:
    """Resolve allowed folders, refusing ones that would defeat the sandbox."""
    paths = []
    for a in allow:
        p = Path(os.path.expanduser(a)).resolve()
        if p == home or home.is_relative_to(p):
            raise SandboxUnavailable(f"refusing to allow {p}: it would expose your whole home folder")
        if any(p.is_relative_to(home / n) for n in NEVER):
            raise SandboxUnavailable(f"refusing to allow {p}: it's a credentials folder")
        paths.append(p)
    return paths


def pick(mode: str) -> str:
    if mode != "auto":
        return mode
    system = platform.system()
    if system == "Linux" and shutil.which("bwrap"):
        return "bwrap"
    if system == "Darwin" and Path("/usr/bin/sandbox-exec").exists():
        return "macos"
    if shutil.which("docker"):
        return "docker"
    raise SandboxUnavailable("no sandbox available: install bubblewrap (Linux) or Docker, or use macOS")


def bwrap_args(command: list[str], allow: list[Path], network: bool, home: Path) -> list[str]:
    if not shutil.which("bwrap"):
        raise SandboxUnavailable("bubblewrap (bwrap) is not installed")
    args = ["bwrap", "--die-with-parent", "--new-session", "--unshare-all"]
    if network:
        args.append("--share-net")
    args += ["--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc", "--tmpfs", "/tmp",
             "--tmpfs", "/home", "--tmpfs", "/root", "--dir", str(home)]
    for p in _existing(home, TOOLCHAINS):
        args += ["--ro-bind", str(p), str(p)]
    for p in _existing(home, CACHES):
        args += ["--bind", str(p), str(p)]
    for p in allow:
        args += ["--bind", str(p), str(p)]
    args += ["--setenv", "HOME", str(home), "--chdir", str(allow[0] if allow else "/tmp"), "--", *command]
    return args


def macos_profile(allow: list[Path], network: bool, home: Path) -> str:
    def q(p: Path) -> str:
        return '"' + str(p).replace("\\", "\\\\").replace('"', '\\"') + '"'
    rules = ["(version 1)", "(allow default)",
             f"(deny file-read* file-write* (subpath {q(home)}))",
             # Metadata of the home folder itself (not its contents) is needed to resolve paths.
             f"(allow file-read-metadata (literal {q(home)}))"]
    rules += [f"(allow file-read* (subpath {q(p)}))" for p in _existing(home, TOOLCHAINS)]
    rules += [f"(allow file-read* file-write* (subpath {q(p)}))" for p in _existing(home, CACHES) + allow]
    # Later rules win in SBPL: credentials stay denied even inside allowed paths.
    rules += [f"(deny file-read* file-write* (subpath {q(home / n)}))" for n in NEVER]
    if not network:
        rules.append("(deny network*)")
    return "\n".join(rules)


def macos_args(command: list[str], allow: list[Path], network: bool, home: Path) -> list[str]:
    if not Path("/usr/bin/sandbox-exec").exists():
        raise SandboxUnavailable("sandbox-exec is not available on this system")
    return ["/usr/bin/sandbox-exec", "-p", macos_profile(allow, network, home), *command]


def default_image(command: list[str]) -> str:
    tool = Path(command[0]).name
    if tool in ("npx", "node", "npm", "pnpm", "yarn"):
        return "node:22-slim"
    if tool in ("uvx", "uv"):
        return "ghcr.io/astral-sh/uv:python3.12-bookworm-slim"
    if tool.startswith("python") or tool == "pip":
        return "python:3.12-slim"
    raise SandboxUnavailable(f"no default container image for '{tool}'; pass --image")


def docker_args(command: list[str], allow: list[Path], network: bool, image: str | None,
                env: dict[str, str]) -> list[str]:
    if not shutil.which("docker"):
        raise SandboxUnavailable("docker is not installed")
    args = ["docker", "run", "--rm", "-i", "--network", "bridge" if network else "none",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges"]
    for key in sorted(env):
        if key not in ENV_SKIP and not key.startswith(("TRIPLINE_", "LC_")):
            args += ["-e", key]
    for p in allow:
        args += ["-v", f"{p}:{p}"]
    if allow:
        args += ["-w", str(allow[0])]
    return args + [image or default_image(command), *command]


def wrap_command(command: list[str], mode: str, allow: list[str], network: bool = True,
                 image: str | None = None, home: Path | None = None) -> list[str]:
    home = (home or Path.home()).resolve()
    paths = _allowed(allow, home)
    chosen = pick(mode)
    if chosen == "bwrap":
        return bwrap_args(command, paths, network, home)
    if chosen == "macos":
        return macos_args(command, paths, network, home)
    if chosen == "docker":
        return docker_args(command, paths, network, image, dict(os.environ))
    raise SandboxUnavailable(f"unknown sandbox '{mode}'")
