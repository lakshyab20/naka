"""Print which servers changed between releases as one compressed annotation (for checking a run)."""

import base64
import gzip
import json
import sys

data = json.load(open(sys.argv[1]))
rows = []
for s in data["servers"]:
    for r in s.get("releases", []):
        if r.get("added") or r.get("removed") or r.get("changed") or r.get("gained") or r.get("new_findings"):
            rows.append([s["name"], r["version"], r.get("added", [])[:5], r.get("removed", [])[:5],
                         [c["tool"] for c in r.get("changed", [])][:5], r.get("gained", []),
                         [[f["tool"], f["rule"]] for f in r.get("new_findings", [])][:3]])
    if s.get("releases"):
        rows.append([s["name"], "versions", [r["version"] for r in s["releases"]], [r.get("started") for r in s["releases"]]])
if len(sys.argv) > 2:  # how the earlier releases went, to spot a broken run
    import collections, os
    if os.path.exists(sys.argv[2]):
        hist = json.load(open(sys.argv[2]))["servers"]
        print("::notice title=naka-history::" + json.dumps({"statuses": collections.Counter(h["status"] for h in hist),
              "errors": [[h["name"], h["error"][:160]] for h in hist if h["status"] != "ok"][:6]}).replace("\n", " "))
    else:
        print("::notice title=naka-history::no history.json")
blob = base64.b64encode(gzip.compress(json.dumps(rows).encode())).decode()
for i in range(0, min(len(blob), 40000), 4000):
    print(f"::warning title=naka-changes {i // 4000 + 1}::{blob[i:i + 4000]}")
