"""Pick earlier releases of every server that started, to compare what each
release tells the AI.

    python scan/history.py results/scan.json scan-servers.json --versions 3 --out history-servers.json

For each server: the version `latest` points to now, and the few stable
releases before it (npm and PyPI). Runs in GitHub Actions.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.parse
import urllib.request

STABLE = re.compile(r"^\d+(\.\d+)*$")


def get(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "naka-scan", "Accept": "application/json"})
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                return json.load(resp)
        except Exception as exc:  # noqa: BLE001 - retried, then reported
            if attempt == 2:
                print(f"  failed: {url}: {exc}", file=sys.stderr)
                return {}
            time.sleep(2 * (attempt + 1))
    return {}


def _key(v: str) -> tuple:
    return tuple(int(x) for x in v.split("."))


def npm_versions(pkg: str) -> tuple[str | None, list[tuple[str, str]]]:
    data = get("https://registry.npmjs.org/" + urllib.parse.quote(pkg, safe="@"))
    latest = (data.get("dist-tags") or {}).get("latest")
    times = data.get("time") or {}
    out = [(v, times.get(v, "")) for v in (data.get("versions") or {}) if STABLE.match(v)]
    return latest, out


def pypi_versions(pkg: str) -> tuple[str | None, list[tuple[str, str]]]:
    data = get(f"https://pypi.org/pypi/{urllib.parse.quote(pkg)}/json")
    latest = (data.get("info") or {}).get("version")
    out = []
    for v, files in (data.get("releases") or {}).items():
        if STABLE.match(v) and files and not all(f.get("yanked") for f in files):
            out.append((v, min(f.get("upload_time_iso_8601", "") for f in files)))
    return latest, out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("scan")
    ap.add_argument("servers")
    ap.add_argument("--versions", type=int, default=3, help="earlier releases to compare per server")
    ap.add_argument("--out", required=True)
    ap.add_argument("--map", required=True, help="where to write {package: {latest, releases}}")
    args = ap.parse_args()

    scan = json.load(open(args.scan))
    picked = json.load(open(args.servers))
    by_name = {e.get("name") or e["package"]: e for e in picked["servers"] if "package" in e}
    entries, vmap = [], {}
    for s in scan["servers"]:
        entry = by_name.get(s["name"])
        if s["status"] != "ok" or not entry:
            continue
        kind = entry.get("kind", "npm")
        pkg = entry["package"]
        latest, versions = (npm_versions if kind == "npm" else pypi_versions)(pkg)
        if not latest or not STABLE.match(latest):
            continue
        dates = dict(versions)
        earlier = sorted((v for v, _ in versions if _key(v) < _key(latest)), key=_key)[-args.versions:]
        vmap[pkg] = {"latest": latest, "kind": kind,
                     "releases": [{"version": v, "date": dates.get(v, "")[:10]} for v in earlier + [latest]]}
        for v in earlier:
            e = {k: entry[k] for k in ("package", "kind", "args", "env") if k in entry}
            entries.append(dict(e, name=f"{pkg}@{v}", version=v, of=pkg))
    json.dump({"env": picked.get("env", {}), "servers": entries}, open(args.out, "w"), indent=1)
    json.dump(vmap, open(args.map, "w"), indent=1)
    print(f"{len(entries)} earlier releases of {len(vmap)} servers", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
