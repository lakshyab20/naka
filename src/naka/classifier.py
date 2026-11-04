"""A small built-in machine-learning classifier for injected instructions.

Why it exists: the regex rules in detectors.py catch known phrasings and miss
rewordings and other languages. A learned model generalises from tens of
thousands of labelled examples instead of a hand-written list.

Why this design:
- Zero dependencies at runtime. It is a logistic regression over hashed word
  n-grams (1 to 3 words), trained offline by scripts/train_classifier.py.
  Scoring is a few hash lookups per word, in pure Python.
- Windows, not whole documents. An injection is usually a sentence or two
  inside a long, harmless tool result. Averaging over the whole text would
  dilute it, so we slide a window over the text and keep the worst score.
- Same normalisation as the regex layer, so invisible characters, look-alike
  letters and fullwidth text are undone before scoring.

It is a second opinion, not a replacement: regex is fast and explainable,
this catches what regex misses, and the structural rules (pinning, data flow)
don't depend on either.
"""

from __future__ import annotations

import gzip
import json
import math
import re
import struct
import zlib
from array import array
from dataclasses import dataclass
from importlib import resources

from . import detectors as d

# Words, plus a few symbols that mark fake system tags ("<", "#", "!").
# JSON punctuation is left out so structured data doesn't look suspicious.
TOKEN = re.compile(r"[a-z0-9\u0900-\u097f\u00c0-\u024f\u0400-\u04ff]+|[<>#!?]")
DEFAULT_MODEL = "injection-v1.bin.gz"


def tokens(text: str) -> list[str]:
    text = d.normalize(d.strip_hidden(text)).lower()
    return TOKEN.findall(text)


def features(toks: list[str], n_max: int, buckets: int) -> list[int]:
    """Hashed word n-grams. crc32 is used because Python's hash() is randomised."""
    out = []
    for n in range(1, n_max + 1):
        for i in range(len(toks) - n + 1):
            gram = "\x1f".join(toks[i:i + n]).encode("utf-8")
            out.append(zlib.crc32(gram) % buckets)
    return out


@dataclass
class Score:
    probability: float
    excerpt: str


class Classifier:
    def __init__(self, weights: array, bias: float, meta: dict):
        self.weights = weights
        self.bias = bias
        self.meta = meta
        self.buckets = meta["buckets"]
        self.n_max = meta["ngram_max"]
        self.window = meta["window"]
        self.stride = meta["stride"]
        self.threshold = meta["threshold"]

    # ------------------------------------------------------------ persistence
    @classmethod
    def load(cls, path: str | None = None) -> "Classifier":
        if path:
            blob = open(path, "rb").read()
        else:
            blob = resources.files("naka.models").joinpath(DEFAULT_MODEL).read_bytes()
        raw = gzip.decompress(blob)
        (header_len,) = struct.unpack("<I", raw[:4])
        meta = json.loads(raw[4:4 + header_len])
        body = raw[4 + header_len:]
        count = meta["nonzero"]
        idx = array("I")
        idx.frombytes(body[: 4 * count])
        val = array("f")
        val.frombytes(body[4 * count: 8 * count])
        weights = array("f", bytes(4 * meta["buckets"]))
        for i, w in zip(idx, val):
            weights[i] = w
        return cls(weights, meta["bias"], meta)

    @staticmethod
    def save(path: str, nonzero: list[tuple[int, float]], bias: float, meta: dict) -> None:
        meta = dict(meta, bias=bias, nonzero=len(nonzero))
        header = json.dumps(meta, sort_keys=True).encode()
        idx = array("I", [i for i, _ in nonzero])
        val = array("f", [w for _, w in nonzero])
        raw = struct.pack("<I", len(header)) + header + idx.tobytes() + val.tobytes()
        with open(path, "wb") as fh:
            fh.write(gzip.compress(raw, 9))

    # ---------------------------------------------------------------- scoring
    def _prob(self, toks: list[str]) -> float:
        z = self.bias + sum(self.weights[f] for f in features(toks, self.n_max, self.buckets))
        if z < -40:
            return 0.0
        return 1.0 / (1.0 + math.exp(-z))

    def score(self, text: str) -> Score:
        """Worst (highest) injection probability over sliding windows of the text."""
        toks = tokens(text)
        if not toks:
            return Score(0.0, "")
        if len(toks) <= self.window:
            return Score(self._prob(toks), " ".join(toks)[:120])
        best, best_at = 0.0, 0
        for start in range(0, len(toks) - self.stride, self.stride):
            p = self._prob(toks[start:start + self.window])
            if p > best:
                best, best_at = p, start
        return Score(best, " ".join(toks[best_at:best_at + self.window])[:120])


_default: Classifier | None = None


def default() -> Classifier:
    global _default
    if _default is None:
        _default = Classifier.load()
    return _default
