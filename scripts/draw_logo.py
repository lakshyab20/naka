"""Draw Naka's logo files into docs/img/brand/.

The mark: a line (the connection between an AI agent and its tools) with a checkpoint on it.
The wordmark is Inter Display SemiBold (SIL Open Font License), converted to outlines so it
looks the same everywhere. Needs fontTools and the Inter Display font installed.

    python scripts/draw_logo.py
"""
from __future__ import annotations

import pathlib
import sys

from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.pens.transformPen import TransformPen
from fontTools.ttLib import TTFont

OUT = pathlib.Path(__file__).resolve().parent.parent / "docs" / "img" / "brand"
FONT = "/usr/share/fonts/opentype/inter/InterDisplay-SemiBold.otf"

INK = "#0B1220"       # tile and dark text
PAPER = "#E6EDF7"     # line and light text
SIGNAL = "#FF6B35"    # the checkpoint


def mark(x: float = 0, y: float = 0, size: float = 64, tile: bool = True) -> str:
    s = size / 64
    parts = []
    if tile:
        parts.append(f'<rect x="{x}" y="{y}" width="{size}" height="{size}" rx="{15 * s:.2f}" fill="{INK}"/>')
    line = PAPER if tile else INK
    w = 4.5 * s
    parts.append(f'<line x1="{x + 10 * s:.2f}" y1="{y + 32 * s:.2f}" x2="{x + 24 * s:.2f}" y2="{y + 32 * s:.2f}" '
                 f'stroke="{line}" stroke-width="{w:.2f}" stroke-linecap="round"/>')
    parts.append(f'<line x1="{x + 40 * s:.2f}" y1="{y + 32 * s:.2f}" x2="{x + 54 * s:.2f}" y2="{y + 32 * s:.2f}" '
                 f'stroke="{line}" stroke-width="{w:.2f}" stroke-linecap="round"/>')
    c, r = 32 * s, 3 * s
    parts.append(f'<rect x="{x + c - 6.5 * s:.2f}" y="{y + c - 6.5 * s:.2f}" width="{13 * s:.2f}" height="{13 * s:.2f}" '
                 f'rx="{r:.2f}" transform="rotate(45 {x + c:.2f} {y + c:.2f})" fill="{SIGNAL}"/>')
    return "\n  ".join(parts)


def text_path(text: str, x: float, baseline: float, size: float, color: str) -> tuple[str, float]:
    font = TTFont(FONT)
    glyphs = font.getGlyphSet()
    cmap = font.getBestCmap()
    upm = font["head"].unitsPerEm
    scale = size / upm
    hmtx = font["hmtx"]
    pen = SVGPathPen(glyphs)
    cursor = 0.0
    tracking = -0.02 * upm   # slightly tight, as display type usually is
    for ch in text:
        name = cmap[ord(ch)]
        glyphs[name].draw(TransformPen(pen, (scale, 0, 0, -scale, x + cursor * scale, baseline)))
        cursor += hmtx[name][0] + tracking
    return f'<path d="{pen.getCommands()}" fill="{color}"/>', (cursor - tracking) * scale


def svg(w: float, h: float, body: str, label: str) -> str:
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{w:.0f}" height="{h:.0f}" viewBox="0 0 {w:.0f} {h:.0f}" '
            f'role="img" aria-label="{label}">\n  <title>{label}</title>\n  {body}\n</svg>\n')


def wordmark(color: str) -> str:
    h, size = 64, 44
    word, width = text_path("naka", 84, 47, size, color)
    return svg(84 + width + 4, h, mark() + "\n  " + word, "Naka")


def social() -> str:
    w, h = 1280, 640
    body = [f'<rect width="{w}" height="{h}" fill="{INK}"/>',
            # the connection: agent ... checkpoint ... tools
            f'<line x1="120" y1="420" x2="560" y2="420" stroke="#2A3550" stroke-width="6" stroke-linecap="round"/>',
            f'<line x1="720" y1="420" x2="1160" y2="420" stroke="#2A3550" stroke-width="6" stroke-linecap="round"/>',
            f'<rect x="604" y="384" width="72" height="72" rx="14" transform="rotate(45 640 420)" fill="{SIGNAL}"/>']
    title, tw = text_path("naka", 0, 0, 120, PAPER)
    body.append(title.replace("<path ", f'<path transform="translate({(w - tw) / 2:.1f} 250)" '))
    tag = "The runtime firewall for AI agents"
    sub, sw = text_path(tag, 0, 0, 40, "#9AA8C0")
    body.append(sub.replace("<path ", f'<path transform="translate({(w - sw) / 2:.1f} 320)" '))
    for label, cx in (("AI agent", 340), ("its tools", 940)):
        p, lw = text_path(label, 0, 0, 30, "#6B7A96")
        body.append(p.replace("<path ", f'<path transform="translate({cx - lw / 2:.1f} 490)" '))
    return svg(w, h, "\n  ".join(body), "Naka: the runtime firewall for AI agents")


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    files = {
        "mark.svg": svg(64, 64, mark(), "Naka"),
        "wordmark-light.svg": wordmark(INK),     # for light backgrounds
        "wordmark-dark.svg": wordmark(PAPER),    # for dark backgrounds
        "social-preview.svg": social(),
    }
    for name, text in files.items():
        (OUT / name).write_text(text)
        print(OUT / name)
    return 0


if __name__ == "__main__":
    sys.exit(main())
