"""Turn scan results into the data behind the public page.

    python scan/compare.py --latest results/scan.json --history results/history.json \
        --versions results/versions.json --picked results/scan-servers.json \
        [--previous previous/data.json] --out site/data.json

For each server: what it can do now, and what changed in what it tells the
AI between its recent releases and since the previous weekly scan.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE.parent / "src"))
try:
    from naka.guards import ARCHIVED_SERVERS
except ImportError:  # pragma: no cover - the page still builds without the label
    ARCHIVED_SERVERS = {}
LEGS = ("reads-outside-content", "reads-private-data", "sends-out", "runs-commands")


def load(path: str | None, default):
    if path and os.path.exists(path):
        try:
            return json.load(open(path))
        except ValueError:
            return default
    return default


def tools_of(server: dict) -> dict[str, dict]:
    return {t["name"]: t for t in server.get("tools", [])}


def caps_of(server: dict) -> set[str]:
    return {c for t in server.get("tools", []) for c in t.get("caps", [])}


def findings_of(server: dict) -> list[dict]:
    out = [dict(f, tool="(server instructions or prompts)") for f in server.get("instructions_findings", [])]
    out += [dict(f, tool=t["name"]) for t in server.get("tools", []) for f in t.get("findings", [])]
    return [{"tool": f["tool"], "rule": f.get("rule"), "excerpt": str(f.get("excerpt", ""))[:200]} for f in out]


def diff(old: dict, new: dict) -> dict:
    a, b = tools_of(old), tools_of(new)
    changed = []
    for name in sorted(set(a) & set(b)):
        if a[name].get("fingerprint") != b[name].get("fingerprint"):
            entry = {"tool": name}
            if a[name].get("description") != b[name].get("description"):
                entry["was"] = a[name].get("description", "")[:300]
                entry["now"] = b[name].get("description", "")[:300]
            changed.append(entry)
    old_f = {(f["tool"], f["rule"]) for f in findings_of(old)}
    return {
        "added": sorted(set(b) - set(a)), "removed": sorted(set(a) - set(b)), "changed": changed,
        "gained": sorted((caps_of(new) - caps_of(old)) & set(LEGS)),
        "new_findings": [f for f in findings_of(new) if (f["tool"], f["rule"]) not in old_f],
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--latest", required=True)
    ap.add_argument("--history")
    ap.add_argument("--versions")
    ap.add_argument("--picked")
    ap.add_argument("--previous")
    ap.add_argument("--wrapped", help="the same servers audited through Naka (naka audit --through-naka)")
    ap.add_argument("--real", help="naka eval-real results")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    latest = load(args.latest, {"servers": []})
    history = load(args.history, {"servers": []})
    versions = load(args.versions, {})
    picked = {e["package"]: e for e in load(args.picked, {"servers": []}).get("servers", []) if "package" in e}
    previous = load(args.previous, {})
    prev_by_name = {s["name"]: s for s in previous.get("servers", [])}
    reviewed = load(str(HERE / "reviewed.json"), {})
    old_releases: dict[str, dict[str, dict]] = {}
    for s in history.get("servers", []):
        meta = s.get("meta") or {}
        if meta.get("of") and s.get("status") == "ok":
            old_releases.setdefault(meta["of"], {})[meta.get("version")] = s

    wrapped = {w["name"]: w for w in load(args.wrapped, {"servers": []}).get("servers", [])}
    servers = []
    for s in latest.get("servers", []):
        meta = picked.get(s["name"], {})
        vinfo = versions.get(s["name"], {})
        rec = {
            "name": s["name"], "kind": meta.get("kind", "npm"), "rank": meta.get("rank"),
            "downloads": meta.get("weekly_downloads"), "status": s["status"],
            "version": vinfo.get("latest") or (s.get("server_info") or {}).get("version"),
            "error": s.get("error", "")[:160] if s["status"] != "ok" else "",
            "archived": ARCHIVED_SERVERS.get(s["name"].lower()),
        }
        if s["status"] == "ok":
            caps = caps_of(s)
            legs = {c: [t["name"] for t in s["tools"] if c in t.get("caps", [])][:6] for c in LEGS}
            findings = findings_of(s)
            review = reviewed.get(s["name"]) if "hidden-instructions" in s.get("flags", []) else None
            rec.update({
                "tools": len(s["tools"]), "tokens": s.get("context_tokens", 0), "annotated": s.get("annotated", 0),
                "flags": [f for f in s.get("flags", []) if f != "mentions-other-tools"
                          and not (f == "hidden-instructions" and review)],
                "legs": {c: v for c, v in legs.items() if v}, "findings": findings, "review": review,
                "tool_index": {t["name"]: {"fingerprint": t.get("fingerprint"), "description": t.get("description", "")[:300],
                                           "caps": t.get("caps", [])} for t in s["tools"]},
            })
            # Releases, oldest first, each compared with the one before it.
            releases = []
            prev = None
            for r in vinfo.get("releases", []):
                srv = s if r["version"] == vinfo.get("latest") else old_releases.get(s["name"], {}).get(r["version"])
                item = {"version": r["version"], "date": r.get("date", ""), "started": srv is not None}
                if srv is not None:
                    item["tools"] = len(srv.get("tools", []))
                    if prev is not None:
                        item.update(diff(prev, srv))
                    prev = srv
                releases.append(item)
            rec["releases"] = releases
            # The same server behind Naka: which tools would the AI no longer see?
            w = wrapped.get(s["name"])
            if w is not None:
                if w.get("status") != "ok":
                    rec["naka"] = {"status": "failed", "error": str(w.get("error", ""))[:160]}
                else:
                    seen = {t["name"] for t in w.get("tools", [])}
                    hidden = sorted(t["name"] for t in s["tools"] if t["name"] not in seen)
                    rec["naka"] = {"status": "hid" if hidden else "clean", "hidden": hidden}
            # Since the previous weekly scan.
            before = prev_by_name.get(s["name"])
            if before and before.get("status") == "ok" and before.get("tool_index"):
                old = {"tools": [dict(v, name=k, findings=[]) for k, v in before["tool_index"].items()]}
                old_find = {(f["tool"], f["rule"]) for f in before.get("findings", [])}
                d = diff(old, s)
                d["new_findings"] = [f for f in findings if (f["tool"], f["rule"]) not in old_find]
                d["from"] = before.get("version")
                if any(d[k] for k in ("added", "removed", "changed", "gained", "new_findings")):
                    rec["since_last_scan"] = d
        servers.append(rec)

    ok = [r for r in servers if r["status"] == "ok"]
    compared = [r for r in ok if sum(1 for x in r.get("releases", []) if x.get("started")) >= 2]
    def any_rel(r, key):
        return any(x.get(key) for x in r.get("releases", []))
    stats = {
        "tried": len(servers), "started": len(ok),
        "hidden_instructions": sum("hidden-instructions" in r["flags"] for r in ok),
        "false_alarms": sum(bool(r.get("review")) for r in ok),
        "lethal_trifecta": sum("lethal-trifecta" in r["flags"] for r in ok),
        "injection_to_command": sum("injection-to-command" in r["flags"] for r in ok),
        "annotated": sum(r["annotated"] > 0 for r in ok),
        "archived": sum(bool(r.get("archived")) for r in servers),
        "compared": len(compared),
        "releases_compared": sum(sum(1 for x in r["releases"] if x.get("started")) for r in compared),
        "changed_descriptions": sum(any(x.get("changed") for x in r["releases"]) for r in compared),
        "gained_reach": sum(any_rel(r, "gained") for r in compared),
        "new_findings_in_release": sum(any_rel(r, "new_findings") for r in compared),
        "changed_since_last_scan": sum(bool(r.get("since_last_scan")) for r in ok),
        "previous_scan": previous.get("date"),
        "naka_checked": sum("naka" in r for r in ok),
        "naka_clean": sum(r.get("naka", {}).get("status") == "clean" for r in ok),
        "naka_hid": sum(r.get("naka", {}).get("status") == "hid" for r in ok),
        "naka_failed": sum(r.get("naka", {}).get("status") == "failed" for r in ok),
    }
    data = {"date": time.strftime("%Y-%m-%d"), "naka": latest.get("naka"), "stats": stats, "servers": servers}
    realres = load(args.real, None)
    if realres:
        sc = {x["id"]: x for x in realres.get("scenarios", [])}
        rows: dict[str, dict] = {}
        for r in realres.get("results", []):
            row = rows.setdefault(r["scenario"], {"id": r["scenario"], "kind": r["kind"], "category": r["category"],
                                                  "title": sc.get(r["scenario"], {}).get("title", ""),
                                                  "servers": sc.get(r["scenario"], {}).get("servers", []),
                                                  "twin": sc.get(r["scenario"], {}).get("twin", ""), "guards": {}})
            row["guards"][r["guard"]] = {"outcome": r["outcome"], "detail": r.get("detail", "")[:160]}
            row.setdefault("versions", {}).update(r.get("versions") or {})
        data["real"] = {"date": realres.get("date"), "summary": realres.get("summary", {}), "scenarios": list(rows.values())}
        nk = realres.get("summary", {}).get("naka", {})
        stats.update(real_attacks=nk.get("attacks", 0), real_stopped=nk.get("stopped", 0),
                     real_everyday=nk.get("everyday", 0), real_interrupted=nk.get("interrupted", 0))
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    json.dump(data, open(args.out, "w"), indent=1)
    print(json.dumps(stats))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
