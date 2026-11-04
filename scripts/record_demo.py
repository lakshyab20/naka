"""Record the before/after demo as docs/demo.gif and docs/demo.mp4.

Runs the real `tripline demo` (unprotected, then protected), replays its exact
output in a terminal-style frame with Playwright, and encodes it with ffmpeg.

    pip install playwright && playwright install chromium   # once
    python scripts/record_demo.py
"""

from __future__ import annotations

import html
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs"
W, H = 1200, 760

PAGE = """<!doctype html><html><head><meta charset="utf-8"><style>
html,body{margin:0;background:#0b0d10}
.win{position:absolute;inset:16px;background:#111419;border-radius:12px;overflow:hidden;
     box-shadow:0 0 0 1px #262b33;display:flex;flex-direction:column}
.bar{height:38px;flex:none;display:flex;align-items:center;gap:8px;padding:0 14px;background:#1a1e24;
     font:600 14px "DejaVu Sans",sans-serif;color:#9aa4b0}
.bar i{width:12px;height:12px;border-radius:50%;display:inline-block}
.bar .t{margin-left:14px}.bar .tag{margin-left:auto;padding:4px 10px;border-radius:999px;font-size:13px}
.tag.off{background:#3d1f1c;color:#ff8a7a}.tag.on{background:#163330;color:#5fd0c3}
.term{flex:1;overflow:hidden;display:flex;flex-direction:column;justify-content:flex-end;padding:14px 18px}
pre{margin:0;font:15px/1.5 "DejaVu Sans Mono",monospace;color:#d6dde6;white-space:pre-wrap;word-break:break-word}
.b{font-weight:bold}.d{color:#7d8792}.r{color:#ff6b6b}.g{color:#5fd38d}.y{color:#f2c14e}.c{color:#56c8d8}
.p{color:#5fd0c3}.cur{background:#d6dde6;color:#111419}
</style></head><body><div class="win"><div class="bar"><i style="background:#ff5f57"></i>
<i style="background:#febc2e"></i><i style="background:#28c840"></i><span class="t">~/tripline</span>
<span class="tag" id="tag"></span></div><div class="term"><pre id="out"></pre></div></div>
<script>
function show(h, tag, cls){document.getElementById('out').innerHTML=h;
 const t=document.getElementById('tag');t.textContent=tag;t.className='tag '+cls;}
</script></body></html>"""

SGR = {"1": "b", "2": "d", "31": "r", "32": "g", "33": "y", "36": "c"}


def ansi_to_html(line: str) -> str:
    out, classes = [], set()
    for part in re.split(r"(\x1b\[[0-9;]*m)", line):
        m = re.fullmatch(r"\x1b\[([0-9;]*)m", part)
        if m:
            for code in (m.group(1) or "0").split(";"):
                if code == "0":
                    classes.clear()
                elif code in SGR:
                    classes.add(SGR[code])
            continue
        if part:
            text = html.escape(part)
            out.append(f'<span class="{" ".join(sorted(classes))}">{text}</span>' if classes else text)
    return "".join(out)


def capture(args: list[str]) -> list[str]:
    env = dict(os.environ, FORCE_COLOR="1")
    r = subprocess.run([sys.executable, "-m", "tripline", "demo", *args],
                       capture_output=True, text=True, env=env, check=True)
    return r.stdout.rstrip("\n").split("\n")


def timeline():
    """Yield (html, tag, tag_class, seconds) frames."""
    runs = [("tripline demo --unprotected", capture(["--unprotected"]), "without tripline", "off"),
            ("tripline demo", capture([]), "with tripline", "on")]
    for cmd, lines, tag, cls in runs:
        prompt = '<span class="p">❯</span> '
        for i in range(0, len(cmd) + 1, 2):
            yield prompt + html.escape(cmd[:i]) + '<span class="cur"> </span>', tag, cls, 0.05
        shown = [prompt + html.escape(cmd)]
        yield "\n".join(shown), tag, cls, 0.4
        for line in lines:
            shown.append(ansi_to_html(line))
            plain = re.sub(r"\x1b\[[0-9;]*m", "", line)
            if re.match(r"\d\. ", plain):
                pause = 0.9                       # step headings: give viewers time to read
            elif "app asks you" in plain:
                pause = 1.6                       # let viewers read the confirmation prompt
            elif "you click" in plain:
                pause = 1.0
            elif "BLOCKED" in plain or "Result" in plain:
                pause = 0.7
            else:
                pause = 0.12
            yield "\n".join(shown), tag, cls, pause
        yield "\n".join(shown), tag, cls, 3.5          # hold on the result


def main() -> int:
    if not shutil.which("ffmpeg"):
        print("ffmpeg is required", file=sys.stderr)
        return 1
    OUT.mkdir(exist_ok=True)
    tmp = Path(tempfile.mkdtemp(prefix="tripline-rec-"))
    concat = []
    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        page = browser.new_page(viewport={"width": W, "height": H}, device_scale_factor=1)
        page.set_content(PAGE)
        for n, (body, tag, cls, secs) in enumerate(timeline()):
            page.evaluate("([h,t,c]) => show(h,t,c)", [body, tag, cls])
            frame = tmp / f"f{n:04d}.png"
            page.screenshot(path=str(frame))
            concat.append(f"file '{frame}'\nduration {secs}")
        browser.close()
    concat.append(f"file '{frame}'")  # ffmpeg concat needs the last file repeated
    listfile = tmp / "frames.txt"
    listfile.write_text("\n".join(concat))

    mp4 = OUT / "demo.mp4"
    subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-f", "concat", "-safe", "0", "-i", str(listfile),
                    "-vf", "fps=30,format=yuv420p", "-c:v", "libx264", "-preset", "veryfast", "-crf", "20",
                    "-movflags", "+faststart", str(mp4)], check=True)
    gif = OUT / "demo.gif"
    subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-f", "concat", "-safe", "0", "-i", str(listfile),
                    "-vf", "fps=12,scale=960:-1:flags=lanczos,split[a][b];[a]palettegen=max_colors=64:stats_mode=diff[p];"
                           "[b][p]paletteuse=dither=bayer:bayer_scale=4:diff_mode=rectangle",
                    str(gif)], check=True)
    shutil.rmtree(tmp, ignore_errors=True)
    for f in (gif, mp4):
        print(f"{f.relative_to(ROOT)}  {f.stat().st_size / 1e6:.1f} MB")
    return 0


if __name__ == "__main__":
    sys.exit(main())
