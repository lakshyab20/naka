"""naka eval-real's harness, with stand-ins for the real servers (the real run needs npx, uvx and network)."""

import sys
from pathlib import Path

import pytest

from naka.evals import core, real

FAKE = str(Path(__file__).with_name("fake_real_server.py"))


@pytest.fixture
def stand_ins(monkeypatch):
    servers = {name: dict(spec, command=[sys.executable, "-I", FAKE, name, "{dir}"]) for name, spec in real.SERVERS.items()}
    monkeypatch.setattr(real, "SERVERS", servers)


def test_attacks_work_unguarded_and_naka_stops_them(stand_ins):
    g = core.builtin_guards()
    results = real.run([g["no guard"], g["naka"]])
    by = {(r.guard, r.scenario): r for r in results}
    attacks = [s.id for s in real.scenarios() if s.kind == "attack"]
    everyday = [s.id for s in real.scenarios() if s.kind == "everyday"]
    for a in attacks:
        assert by[("no guard", a)].outcome == "succeeded", by[("no guard", a)]
        assert by[("naka", a)].outcome == "stopped", by[("naka", a)]
    for e in everyday:
        assert by[("no guard", e)].outcome == "passed", by[("no guard", e)]
    interrupted = [e for e in everyday if by[("naka", e)].outcome == "interrupted"]
    assert len(interrupted) <= 1, interrupted
