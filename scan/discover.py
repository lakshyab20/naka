"""Build the list of servers for the public scan: the most downloaded MCP
servers on npm, plus popular Python servers from scan/servers.json.

    python scan/discover.py --top 100 --out scan-servers.json

Runs in GitHub Actions (it needs registry.npmjs.org and api.npmjs.org).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

HERE = Path(__file__).parent
SEARCHES = ["keywords:mcp-server", "keywords:mcp", "keywords:modelcontextprotocol",
            "keywords:model-context-protocol", "mcp server"]
# Libraries, clients and tools around MCP rather than servers you'd install.
NOT_SERVERS = re.compile(
    r"(^@modelcontextprotocol/(sdk|inspector|create-server|ext-apps)$|sdk|inspector|^mcp-remote$|"
    r"framework|^fastmcp$|client|types?$|eslint|typescript|-cli$|^create-|gateway|proxy|"
    r"^@smithery/|^@mastra/|^ai$|langchain|^@ai-sdk/|^@vercel/mcp-adapter|^use-mcp|^mcp-handler|"
    r"bridge|test(ing)?-|^@types/)", re.I)


def get(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "naka-scan"})
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.load(resp)
        except Exception as exc:  # noqa: BLE001 - retried, then reported
            if attempt == 2:
                print(f"  failed: {url}: {exc}", file=sys.stderr)
                return {}
            time.sleep(2 * (attempt + 1))
    return {}


def candidates() -> dict[str, dict]:
    found: dict[str, dict] = {}
    for text in SEARCHES:
        for start in range(0, 1000, 250):
            q = urllib.parse.urlencode({"text": text, "size": 250, "from": start, "popularity": 1.0})
            objs = get(f"https://registry.npmjs.org/-/v1/search?{q}").get("objects", [])
            for o in objs:
                pkg = o.get("package", {})
                name = pkg.get("name", "")
                if "mcp" not in name.lower() and "modelcontextprotocol" not in name.lower():
                    continue
                if NOT_SERVERS.search(name):
                    continue
                score = (o.get("score") or {}).get("final", 0)
                found.setdefault(name, {"weekly": (o.get("downloads") or {}).get("weekly"), "score": score})
            if len(objs) < 250:
                break
    return found


def weekly(name: str) -> int:
    data = get("https://api.npmjs.org/downloads/point/last-week/" + urllib.parse.quote(name, safe="@"))
    return int(data.get("downloads") or 0)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--top", type=int, default=100)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    settings = json.loads((HERE / "servers.json").read_text())
    curated = [e for e in settings["servers"] if "package" in e]
    overrides = {e["package"]: e for e in curated if e.get("kind", "npm") == "npm"}
    found = candidates()
    print(f"{len(found)} npm candidates", file=sys.stderr)
    # Look up downloads for the most popular few hundred by npm's own score.
    shortlist = sorted(found, key=lambda n: -(found[n].get("score") or 0))[: max(400, args.top * 4)]
    found = {n: found[n] for n in shortlist}
    for name, info in found.items():
        if not info.get("weekly"):
            info["weekly"] = weekly(name)
    ranked = sorted(found, key=lambda n: -found[n]["weekly"])[: args.top]
    servers = []
    for rank, name in enumerate(ranked, 1):
        entry = dict(overrides.get(name, {"package": name}), kind="npm",
                     weekly_downloads=found[name]["weekly"], rank=rank)
        servers.append(entry)
    servers += [e for e in curated if e.get("kind") == "pypi"]
    Path(args.out).write_text(json.dumps({"generated": time.strftime("%Y-%m-%d"),
                                          "env": settings.get("env", {}), "servers": servers},
                                         indent=2) + "\n")
    print(f"wrote {len(servers)} servers ({len(ranked)} npm by weekly downloads)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
