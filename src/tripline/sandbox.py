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

Only a minimal environment reaches the server (PATH, locale...) plus the
variables you name with --env (for example --env GITHUB_TOKEN). Network stays
on unless --no-network (most servers call an API). If the
requested sandbox isn't available, Tripline refuses to start rather than
silently running the server unsandboxed.
"""

from __future__ import annotations

import os
import platform
import shutil
import tempfile
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

# A sandboxed server gets only these environment variables, plus the ones you
# name with --env. Everything else (API keys, tokens, database URLs that the
# app or your shell happens to have) stays out: the server is untrusted.
BASE_ENV = ("PATH", "LANG", "LC_ALL", "LC_CTYPE", "TERM", "TZ", "TMPDIR", "USER", "LOGNAME")


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


def sandbox_env(env: dict[str, str], names: list[str], home: Path) -> dict[str, str]:
    out = {k: env[k] for k in BASE_ENV if k in env}
    out.update({k: env[k] for k in names if k in env})
    out["HOME"] = str(home)
    return out


def docker_args(command: list[str], allow: list[Path], network: bool, image: str | None,
                names: list[str]) -> list[str]:
    if not shutil.which("docker"):
        raise SandboxUnavailable("docker is not installed")
    args = ["docker", "run", "--rm", "-i", "--network", "bridge" if network else "none",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges"]
    for key in sorted(set(names)):
        args += ["-e", key]  # value is copied from Tripline's environment by docker
    for p in allow:
        args += ["-v", f"{p}:{p}"]
    if allow:
        args += ["-w", str(allow[0])]
    return args + [image or default_image(command), *command]


def start_dir(allow: list[str], home: Path | None = None) -> str:
    """Where a sandboxed server starts. Not the caller's folder: that's usually
    inside home, which the sandbox hides, and tools like npm crash when they
    can't read their own working directory."""
    home = (home or Path.home()).resolve()
    paths = _allowed(allow, home)
    return str(paths[0]) if paths else tempfile.gettempdir()


def wrap_command(command: list[str], mode: str, allow: list[str], network: bool = True,
                 image: str | None = None, home: Path | None = None,
                 env_names: list[str] | None = None) -> tuple[list[str], dict[str, str] | None]:
    """(command line, environment for it). None means: inherit (docker's own CLI)."""
    home = (home or Path.home()).resolve()
    paths = _allowed(allow, home)
    names = list(env_names or [])
    chosen = pick(mode)
    if chosen == "bwrap":
        return bwrap_args(command, paths, network, home), sandbox_env(dict(os.environ), names, home)
    if chosen == "macos":
        return macos_args(command, paths, network, home), sandbox_env(dict(os.environ), names, home)
    if chosen == "docker":
        return docker_args(command, paths, network, image, names), None
    raise SandboxUnavailable(f"unknown sandbox '{mode}'")
