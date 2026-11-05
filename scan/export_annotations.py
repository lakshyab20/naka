"""Print the scan's results as GitHub annotations, compressed and split, so
they can be read through the checks API (artifact downloads need a browser).

    python scan/export_annotations.py results/scan.json results/scan-servers.json
"""

import base64
import gzip
import json
import sys

CHUNK = 8000

scan = json.load(open(sys.argv[1]))
picked = {s["package"]: s for s in json.load(open(sys.argv[2]))["servers"]} if len(sys.argv) > 2 else {}
rows = []
for s in scan["servers"]:
    meta = picked.get(s["name"], {})
    rows.append({
        "n": s["name"], "st": s["status"], "e": s["error"][:160] if s["status"] != "ok" else "",
        "rank": meta.get("rank"), "dl": meta.get("weekly_downloads"), "kind": meta.get("kind", "npm"),
        "info": s.get("server_info"), "fl": s["flags"], "caps": s["caps"], "tools": len(s["tools"]),
        "tok": s["context_tokens"], "ann": s["annotated"], "pr": s["prompts"], "res": s["resources"],
        "inst": [[f["rule"], f.get("excerpt", "")[:160]] for f in s["instructions_findings"]],
        "tf": [[t["name"], f["rule"], f.get("excerpt", "")[:160]] for t in s["tools"] for f in t["findings"]],
        "notes": [[t["name"], n] for t in s["tools"] for n in t["notes"]],
        "tc": {t["name"]: t["caps"] for t in s["tools"]},
    })
blob = base64.b64encode(gzip.compress(json.dumps({"date": scan["date"], "naka": scan["naka"], "rows": rows}).encode())).decode()
parts = [blob[i:i + CHUNK] for i in range(0, len(blob), CHUNK)]
if len(parts) > 10:
    print(f"::warning::scan export is {len(blob)} characters, too large for annotations")
    parts = parts[:10]
for i, part in enumerate(parts, 1):
    print(f"::notice title=naka-scan {i}/{len(parts)}::{part}")
