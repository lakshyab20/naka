"""Sandbox command construction. The sandboxes themselves need bwrap, macOS or Docker."""

import shutil
from pathlib import Path

import pytest

from tripline import sandbox as sb


@pytest.fixture
def home(tmp_path, monkeypatch):
    h = tmp_path / "home" / "me"
    for d in (".nvm/versions", ".npm", ".ssh", "projects/app"):
        (h / d).mkdir(parents=True)
    # Pretend the sandbox tools are installed; these tests check the commands we build.
    monkeypatch.setattr(sb.shutil, "which", lambda name: f"/usr/bin/{name}")
    real_exists = Path.exists
    monkeypatch.setattr(sb.Path, "exists", lambda self: str(self) == "/usr/bin/sandbox-exec" or real_exists(self))
    return h


def test_bwrap_hides_home_and_keeps_toolchains(home):
    argv, _ = sb.wrap_command(["npx", "-y", "server"], "bwrap", [str(home / "projects/app")], home=home)
    joined = " ".join(argv)
    assert argv[0] == "bwrap" and "--tmpfs /home" in joined and "--share-net" in joined
    assert f"--ro-bind {home}/.nvm {home}/.nvm" in joined          # toolchain, read-only
    assert f"--bind {home}/.npm {home}/.npm" in joined             # cache, writable
    assert f"--bind {home}/projects/app {home}/projects/app" in joined
    assert ".ssh" not in joined
    assert argv[-3:] == ["npx", "-y", "server"]


def test_no_network(home):
    assert "--share-net" not in sb.wrap_command(["node", "s.js"], "bwrap", [], network=False, home=home)[0]


def test_refuses_to_expose_home_or_credentials(home):
    for bad in (str(home), str(home / ".ssh"), str(home.parent), "/"):
        with pytest.raises(sb.SandboxUnavailable):
            sb.wrap_command(["node"], "bwrap", [bad], home=home)


def test_macos_profile_denies_home_but_keeps_credentials_denied_in_allowed_paths(home):
    profile = sb.macos_profile([home / "projects/app"], True, home)
    assert f'(deny file-read* file-write* (subpath "{home}"))' in profile
    assert f'(allow file-read* file-write* (subpath "{home}/projects/app"))' in profile
    # The deny for credentials comes after the allows, so it wins.
    assert profile.index(f'(subpath "{home}/.ssh")') > profile.index("projects/app")
    assert "(deny network*)" in sb.macos_profile([], False, home)


def test_docker_passes_only_named_env(home, monkeypatch):
    for k in ("GITHUB_TOKEN", "AWS_SECRET_ACCESS_KEY", "OPENAI_API_KEY", "DATABASE_URL"):
        monkeypatch.setenv(k, "secret")
    argv, env = sb.wrap_command(["npx", "server"], "docker", [str(home / "projects/app")], home=home,
                                env_names=["GITHUB_TOKEN"])
    assert argv[:3] == ["docker", "run", "--rm"] and "node:22-slim" in argv
    assert argv[argv.index("-e") + 1] == "GITHUB_TOKEN" and argv.count("-e") == 1
    for leaked in ("AWS_SECRET_ACCESS_KEY", "OPENAI_API_KEY", "DATABASE_URL", "HOME"):
        assert leaked not in argv
    assert f"{home}/projects/app:{home}/projects/app" in argv and "--cap-drop" in argv


def test_bwrap_and_macos_get_minimal_env(home, monkeypatch):
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
    monkeypatch.setenv("GITHUB_TOKEN", "t")
    for mode in ("bwrap", "macos"):
        _, env = sb.wrap_command(["node"], mode, [], home=home, env_names=["GITHUB_TOKEN"])
        assert "AWS_SECRET_ACCESS_KEY" not in env and env["GITHUB_TOKEN"] == "t" and env["HOME"] == str(home)
        assert "PATH" in env


def test_unavailable_sandbox_refuses_to_run(monkeypatch, tmp_path):
    monkeypatch.setattr(sb.shutil, "which", lambda name: None)
    with pytest.raises(sb.SandboxUnavailable):
        sb.wrap_command(["node"], "bwrap", [], home=tmp_path)


@pytest.mark.skipif(not shutil.which("bwrap"), reason="bubblewrap not installed")
def test_bwrap_really_hides_files(tmp_path):
    import subprocess
    secret = Path.home() / ".tripline-sandbox-test"
    secret.write_text("secret")
    try:
        argv, env = sb.wrap_command(["cat", str(secret)], "bwrap", [])
        assert subprocess.run(argv, capture_output=True, env=env).returncode != 0
    finally:
        secret.unlink()


def test_server_starts_outside_the_hidden_home(home):
    # npm crashes if it can't read its working directory, so never start in the caller's folder.
    assert sb.start_dir([str(home / "projects/app")], home=home) == str((home / "projects/app").resolve())
    assert not Path(sb.start_dir([], home=home)).is_relative_to(home)
