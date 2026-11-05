"""Build the public scan page from scan/compare.py's data.

    python scan/site/build.py site/data.json site/index.html
"""

from __future__ import annotations

import json
import sys
from html import escape

REPO = "https://github.com/lakshyab20/naka"
CAP_LABEL = {"reads-outside-content": "Reads outside content", "reads-private-data": "Reads private data",
             "sends-out": "Sends data out", "runs-commands": "Runs code"}


def e(x) -> str:
    return escape(str(x), quote=True)


def code(names, n=2) -> str:
    return ", ".join(f"<code>{e(t)}</code>" for t in list(names)[:n]) or "—"


def dl(r) -> str:
    return f"{r['downloads']:,}" if r.get("downloads") else ("PyPI" if r.get("kind") == "pypi" else "—")


def pkg_link(r) -> str:
    name = r["name"]
    url = (f"https://www.npmjs.com/package/{name}" if r.get("kind", "npm") == "npm"
           else f"https://pypi.org/project/{name}/")
    tag = (f' <span class="pill bad" title="Archived: gets no security fixes. Use {e(r["archived"])} instead.">'
           f'archived</span>' if r.get("archived") else "")
    return f'<a href="{e(url)}" rel="noopener">{e(name)}</a>{tag}'


def table(head: list[str], rows: list[list[str]], cls: str = "") -> str:
    th = "".join(f"<th>{h}</th>" for h in head)
    body = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in row) + "</tr>" for row in rows)
    return f'<div class="tw"><table class="{cls}"><thead><tr>{th}</tr></thead><tbody>{body}</tbody></table></div>'


def release_rows(ok: list[dict]) -> tuple[list[list[str]], str]:
    rows, details = [], []
    for r in sorted(ok, key=lambda r: -(r.get("downloads") or 0)):
        rel = [x for x in r.get("releases", []) if x.get("started")]
        if len(rel) < 2:
            continue
        added = sum(len(x.get("added", [])) for x in rel)
        removed = sum(len(x.get("removed", [])) for x in rel)
        changed = sum(len(x.get("changed", [])) for x in rel)
        gained = sorted({c for x in rel for c in x.get("gained", [])})
        new_f = [f for x in rel for f in x.get("new_findings", [])]
        if not (added or removed or changed or gained or new_f):
            continue
        span = f"{e(rel[0]['version'])} → {e(rel[-1]['version'])}"
        reach = " ".join(f'<span class="pill warn">{e(CAP_LABEL[c])}</span>' for c in gained) or "—"
        rows.append([pkg_link(r), span, str(added), str(removed), str(changed), reach,
                     f'<span class="pill bad">{len(new_f)}</span>' if new_f else "0"])
        items = []
        for x in rel:
            bits = []
            if x.get("added"):
                bits.append("added " + code(x["added"], 6))
            if x.get("removed"):
                bits.append("removed " + code(x["removed"], 6))
            if x.get("gained"):
                bits.append("can now: " + ", ".join(e(CAP_LABEL[c]).lower() for c in x["gained"]))
            for f in x.get("new_findings", []):
                bits.append(f'<span class="pill bad">{e(f["rule"])}</span> in <code>{e(f["tool"])}</code>: {e(f["excerpt"])}')
            changes = "".join(
                f'<li><code>{e(c["tool"])}</code>' + (f'<div class="was">was: {e(c["was"])}</div><div class="now">now: {e(c["now"])}</div>'
                                                      if "was" in c else " (schema or labels changed)") + "</li>"
                for c in x.get("changed", [])[:8])
            if bits or changes:
                items.append(f'<li><b>{e(x["version"])}</b> <span class="muted">{e(x.get("date", ""))}</span>'
                             f'{"<div>" + "; ".join(bits) + "</div>" if bits else ""}'
                             f'{"<ul>" + changes + "</ul>" if changes else ""}</li>')
        details.append(f'<details><summary>{e(r["name"])}: {span}</summary><ul class="rel">{"".join(items)}</ul></details>')
    return rows, "".join(details)


def build(data: dict) -> str:
    st = data["stats"]
    servers = data["servers"]
    ok = [r for r in servers if r["status"] == "ok"]
    tri = sorted([r for r in ok if "lethal-trifecta" in r["flags"]], key=lambda r: -(r.get("downloads") or 0))
    cmd = sorted([r for r in ok if "injection-to-command" in r["flags"]], key=lambda r: -(r.get("downloads") or 0))
    lead = (f"None of the {st['started']} servers that started hid instructions for the AI. "
            if st["hidden_instructions"] == 0 else
            f"{st['hidden_instructions']} of the {st['started']} servers that started hide instructions for the AI. ")
    lead += (f"But {st['lethal_trifecta']} give one injected message everything it needs to read your private data "
             f"and send it out, with no other server involved.")
    tiles = [
        (f"{st['started']}", f"servers started, of {st['tried']} tried"),
        (f"{st['hidden_instructions']}", "hide instructions for the AI"),
        (f"{st['lethal_trifecta']}", "can leak data from one injected message"),
        (f"{st['injection_to_command']}", "go from outside content to running code"),
        (f"{st['changed_descriptions']}", f"changed what they tell the AI across their last releases (of {st['compared']} compared)"),
        (f"{st['gained_reach']}", "gained new reach in a recent release"),
    ]
    if st.get("real_attacks"):
        tiles = [(f"{st['real_stopped']}/{st['real_attacks']}", "real attacks on real servers stopped by Naka"),
                 (f"{st.get('naka_hid', 0)}", f"popular servers where Naka hid a tool by mistake (of {st.get('naka_checked', 0)} run through it)")
                 ] + tiles[:4]
    tiles_html = "".join(f'<div class="tile"><div class="n">{e(n)}</div><div class="l">{e(l)}</div></div>' for n, l in tiles)

    tri_rows = [[pkg_link(r), dl(r), code(r["legs"].get("reads-outside-content", [])),
                 code(r["legs"].get("reads-private-data", [])), code(r["legs"].get("sends-out", []))] for r in tri]
    cmd_rows = [[pkg_link(r), dl(r), code(r["legs"].get("reads-outside-content", [])),
                 code(r["legs"].get("runs-commands", []))] for r in cmd]
    rel_rows, rel_details = release_rows(ok)
    week = [r for r in ok if r.get("since_last_scan")]
    week_rows = [[pkg_link(r), f'{e(r["since_last_scan"].get("from") or "?")} → {e(r.get("version") or "?")}',
                  code(r["since_last_scan"]["added"], 4), code(r["since_last_scan"]["removed"], 4),
                  code([c["tool"] for c in r["since_last_scan"]["changed"]], 4),
                  ", ".join(e(CAP_LABEL[c]) for c in r["since_last_scan"]["gained"]) or "—"] for r in week]
    reviewed = [r for r in ok if r.get("review")]
    arch = sorted([r for r in servers if r.get("archived")], key=lambda r: -(r.get("downloads") or 0))
    archived_html = ("" if not arch else
        "<h2>Still popular, no longer maintained</h2><p>These official reference servers were archived in 2025 and get no "
        "security fixes, yet AI coding agents still install them from memory "
        "(<a href=\"https://www.glow.io/blogs/mcphantom-ai-coding-agents-are-installing-vulnerable-deprecated-mcp-servers-from-training-data\">MCPhantom</a>). "
        "Naka asks before an agent installs one.</p>"
        + table(["Server", "Weekly downloads", "Use instead"], [[pkg_link(r), dl(r), e(r["archived"])] for r in arch]))

    all_rows = []
    for r in sorted(servers, key=lambda r: (r.get("rank") or 999, r["name"])):
        if r["status"] != "ok":
            continue
        flags = " ".join(f'<span class="pill {"bad" if f == "hidden-instructions" else "warn"}">{e(f)}</span>'
                         for f in r["flags"]) or '<span class="muted">none</span>'
        nk = r.get("naka") or {}
        naka_cell = {"clean": '<span class="pill ok">all tools shown</span>',
                     "hid": f'<span class="pill bad">hid {e(", ".join(nk.get("hidden", [])[:3]))}</span>',
                     "failed": f'<span class="pill bad" title="{e(nk.get("error", ""))}">didn\'t start</span>'}.get(nk.get("status"), "—")
        tags = " ".join(r["flags"]) + (" changed" if any(x.get("changed") or x.get("added") for x in r.get("releases", [])) else "")
        all_rows.append(f'<tr data-tags="{e(tags)}" data-name="{e(r["name"].lower())}"><td>{pkg_link(r)}</td>'
                        f'<td>{e(r.get("version") or "")}</td><td class="r">{dl(r)}</td><td class="r">{r["tools"]}</td>'
                        f'<td class="r">{r["tokens"]:,}</td><td class="r">{r["annotated"]}/{r["tools"]}</td><td>{flags}</td><td>{naka_cell}</td></tr>')
    failed = [r for r in servers if r["status"] != "ok"]
    real_html = ""
    real = data.get("real")
    if real:
        label = {"succeeded": '<span class="pill bad">happened</span>', "stopped": '<span class="pill ok">stopped</span>',
                 "passed": '<span class="pill ok">worked</span>', "interrupted": '<span class="pill warn">interrupted</span>',
                 "not run": '<span class="muted">couldn\'t run</span>', "error": '<span class="muted">error</span>'}
        def cell(row, g):
            x = row["guards"].get(g)
            if not x:
                return "—"
            why = (f' <span class="muted">({e(x["detail"])})</span>' if x["detail"] and g != "no guard" else "")
            return label.get(x["outcome"], e(x["outcome"])) + why
        guards = [g for g in real.get("summary", {}) if g != "no guard"]
        att = [x for x in real["scenarios"] if x["kind"] == "attack"]
        day = [x for x in real["scenarios"] if x["kind"] == "everyday"]
        head = ["Attack", "Servers", "No protection"] + [e(g.capitalize() if g == "naka" else g) for g in guards]
        att_rows = [[e(x["title"]), e(", ".join(x["servers"])), cell(x, "no guard")] + [cell(x, g) for g in guards] for x in att]
        day_head = ["Task"] + head[1:]
        day_rows = [[e(x["title"]), e(", ".join(x["servers"])), cell(x, "no guard")] + [cell(x, g) for g in guards] for x in day]
        versions = sorted({v for x in real["scenarios"] for v in (x.get("versions") or {}).values()})
        real_html = (
            "<h2>Real servers, real attacks</h2><p>These attacks run on the servers people actually install, as they ship today, "
            "and are judged by what really happened: did a fake secret reach an attacker's web server, did a note land in the AI's "
            "memory or in CLAUDE.md, did the attacker's program run. The agent is scripted and already fooled, so this measures the "
            "firewall, not the model. Each attack has an everyday task on the same servers that must keep working.</p>"
            + table(head, att_rows) + "<h3>Everyday tasks on the same servers</h3>" + table(day_head, day_rows)
            + f"<p class='muted'>Servers: {e(', '.join(versions))}. Run on {e(real.get('date', ''))} in GitHub Actions. "
            f"The pages and the attacker run on the test machine, so the fetch server is started with "
            f"<code>--allow-private-ips</code> (by default it refuses local addresses, a protection of its own). "
            f"Reproduce with <code>naka eval-real</code> on a throwaway machine.</p>")

    since = (f"Compared with the scan of {e(st['previous_scan'])}." if st.get("previous_scan")
             else "This is the first weekly scan; from next week this section shows what changed since the last one.")
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>MCP Server Scan</title>
<meta name="description" content="{e(lead)}">
<meta property="og:title" content="MCP Server Scan by Naka">
<meta property="og:description" content="{e(lead)}">
<meta property="og:image" content="https://raw.githubusercontent.com/lakshyab20/naka/main/docs/img/brand/social-preview.png">
<meta name="twitter:card" content="summary_large_image">
<style>
:root{{--ink:#0B1220;--paper:#F7F9FC;--card:#FFFFFF;--line:#DCE3EE;--muted:#5B6678;--signal:#FF6B35;--signal-bg:#FFF0E9;--bad:#C62828;--bad-bg:#FDECEC;--warn:#8A5A00;--warn-bg:#FFF4D6;--link:#1F5FD1;--ok:#2E7D32}}
@media (prefers-color-scheme:dark){{:root{{--ink:#E6EDF7;--paper:#0B1220;--card:#121B2E;--line:#24314A;--muted:#93A0B5;--signal-bg:#3A2116;--bad:#FF8A80;--bad-bg:#3A1717;--warn:#FFD27A;--warn-bg:#3A2E10;--link:#8AB4FF;--ok:#81C784}}}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--paper);color:var(--ink);font:16px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Inter,Roboto,sans-serif}}
main{{max-width:1080px;margin:0 auto;padding:24px 16px 64px}}a{{color:var(--link)}}code{{font:13px ui-monospace,SFMono-Regular,Menlo,monospace;background:color-mix(in srgb,var(--line) 45%,transparent);padding:1px 5px;border-radius:4px;word-break:break-word}}
header{{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap}}.brand{{font-weight:700;font-size:22px;letter-spacing:-.02em;text-decoration:none;color:var(--ink)}}.brand b{{color:var(--signal)}}
h1{{font-size:clamp(28px,5vw,44px);line-height:1.15;margin:28px 0 12px;letter-spacing:-.02em}}h2{{font-size:22px;margin:44px 0 8px}}.lead{{font-size:19px;max-width:820px}}.muted{{color:var(--muted)}}
.tiles{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:24px 0}}.tile{{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px}}.tile .n{{font-size:32px;font-weight:700;color:var(--signal)}}.tile .l{{font-size:14px;color:var(--muted)}}
.tw{{overflow-x:auto;border:1px solid var(--line);border-radius:12px;background:var(--card)}}table{{border-collapse:collapse;width:100%;font-size:14px}}th,td{{padding:8px 10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}}th{{font-size:13px;color:var(--muted);font-weight:600;white-space:nowrap}}tr:last-child td{{border-bottom:0}}td code{{white-space:nowrap}}td.r{{text-align:right;white-space:nowrap}}
.pill{{display:inline-block;font-size:12px;padding:1px 8px;border-radius:999px;margin:1px 2px 1px 0;white-space:nowrap}}.pill.bad{{background:var(--bad-bg);color:var(--bad)}}.pill.warn{{background:var(--warn-bg);color:var(--warn)}}.pill.ok{{background:color-mix(in srgb,var(--ok) 16%,transparent);color:var(--ok)}}h3{{font-size:17px;margin:22px 0 8px}}
.cta{{background:var(--signal-bg);border:1px solid var(--signal);border-radius:12px;padding:16px;margin:28px 0}}pre{{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px;overflow-x:auto;font-size:13px}}
details{{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:8px 12px;margin:6px 0}}summary{{cursor:pointer;font-weight:600}}.rel li{{margin:6px 0}}.was{{color:var(--bad);font-size:13px}}.now{{color:var(--muted);font-size:13px}}
.filters{{display:flex;gap:8px;flex-wrap:wrap;margin:10px 0}}.filters button,.filters input{{font:inherit;font-size:14px;border:1px solid var(--line);background:var(--card);color:var(--ink);border-radius:999px;padding:4px 12px;cursor:pointer}}.filters input{{border-radius:8px;cursor:text;min-width:200px}}.filters button[aria-pressed=true]{{background:var(--ink);color:var(--paper)}}
footer{{margin-top:56px;font-size:14px;color:var(--muted)}}
</style></head><body><main>
<header><a class="brand" href="{REPO}">naka<b>.</b></a><span class="muted">MCP server scan · {e(data['date'])} · updated every Monday</span></header>
<h1>One injected message is enough for {st['lethal_trifecta']} popular MCP servers</h1>
<p class="lead">{e(lead)}</p>
<div class="tiles">{tiles_html}</div>
<p class="muted">We start each server with placeholder settings, read only what it tells the AI about itself (its tools, prompts and instructions) and never call a tool. Capabilities are read from tool names as verb + object, so treat them as a guide and check the tools listed.</p>

{real_html}
{archived_html}
<h2>One message is enough: the lethal trifecta</h2>
<p>An agent that reads content strangers wrote, can reach your private data and can send data out can be made to leak that data by anyone who can write to what it reads (<a href="https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/">the lethal trifecta</a>). These servers have all three in one install. None of this is a bug: reading issues and posting comments is what a GitHub server is for. It's why a firewall has to sit between the agent and its tools.</p>
{table(["Server", "Weekly downloads", "Reads outside content", "Reads private data", "Sends data out"], tri_rows)}

<h2>From a web page to running code</h2>
<p>An injected page, issue or error report can lead straight to code running in a browser the agent controls or on your system.</p>
{table(["Server", "Weekly downloads", "Reads outside content", "Runs code"], cmd_rows)}

<h2>What changed between releases</h2>
<p>Each server's last few releases, compared tool by tool. A tool that changes what it tells the AI after you approved it is how a rug-pull works; most changes here are ordinary updates, and the ones worth a look are new reach (a release that can now send data out or run code) and new findings.</p>
{table(["Server", "Releases", "Tools added", "Removed", "Changed", "New reach", "New findings"], rel_rows) if rel_rows else "<p class='muted'>No changes between releases in this scan.</p>"}
{rel_details}

<h2>Since last week</h2>
<p class="muted">{since}</p>
{table(["Server", "Version", "Added", "Removed", "Changed", "New reach"], week_rows) if week_rows else ""}

<h2>Every server that started</h2>
<div class="filters"><input id="q" type="search" placeholder="Search servers" aria-label="Search servers">
<button data-f="" aria-pressed="true">All</button><button data-f="lethal-trifecta" aria-pressed="false">Lethal trifecta</button>
<button data-f="injection-to-command" aria-pressed="false">Outside → code</button><button data-f="changed" aria-pressed="false">Changed between releases</button></div>
<div class="tw"><table id="all"><thead><tr><th>Server</th><th>Version</th><th>Weekly downloads</th><th>Tools</th><th>Context (tokens)</th><th>Safety labels</th><th>Findings</th><th>Through Naka</th></tr></thead><tbody>{"".join(all_rows)}</tbody></table></div>

<h2>Reviewed by hand</h2>
{"".join(f"<p><code>{e(r['name'])}</code>: {e(r['review'].get('verdict', ''))}. {e(r['review'].get('note', ''))}</p>" for r in reviewed) or "<p class='muted'>Nothing needed review.</p>"}

<h2>Didn't start ({len(failed)})</h2>
<p class="muted">Most need a real account, database or cloud login before they list their tools. These aren't findings: {", ".join(e(r["name"]) for r in failed)}.</p>

<div class="cta"><b>Check a server yourself.</b> <code>naka audit</code> reads a server's lists and never calls a tool, but it does start the server, so run unknown ones somewhere disposable.
<pre>pip install naka
naka audit -- npx -y @modelcontextprotocol/server-github</pre>
<b>Stop the attacks, not just spot the risk:</b> <code>naka install</code> puts every MCP server in Claude, Cursor and VS Code behind Naka's firewall. <a href="{REPO}">Naka on GitHub</a></div>

<footer>Scan by <a href="{REPO}">Naka</a>, the open-source runtime firewall for AI agents. Method and code: <a href="{REPO}/blob/main/scan">scan/</a>. Raw data: <a href="data.json">data.json</a>. Weekly downloads from npm at scan time; the 100 most downloaded MCP servers on npm plus popular Python servers.</footer>
</main>
<script>
(function(){{var q=document.getElementById('q'),f='',rows=[].slice.call(document.querySelectorAll('#all tbody tr'));
function apply(){{var t=(q.value||'').toLowerCase();rows.forEach(function(r){{var ok=(!t||r.dataset.name.indexOf(t)>=0)&&(!f||(' '+r.dataset.tags+' ').indexOf(' '+f+' ')>=0);r.style.display=ok?'':'none';}});}}
q.addEventListener('input',apply);[].slice.call(document.querySelectorAll('.filters button')).forEach(function(b){{b.addEventListener('click',function(){{f=b.dataset.f;[].slice.call(document.querySelectorAll('.filters button')).forEach(function(x){{x.setAttribute('aria-pressed',x===b?'true':'false');}});apply();}});}});}})();
</script></body></html>
"""


def main() -> int:
    data = json.load(open(sys.argv[1]))
    open(sys.argv[2], "w").write(build(data))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
