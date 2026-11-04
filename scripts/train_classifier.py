"""Train the built-in injection classifier (src/naka/models/injection-v1.bin.gz).

    pip install scikit-learn   # training only; Naka itself needs nothing
    python scripts/train_classifier.py

Data: the PIGuard training collection (github.com/leolee99/PIGuard, MIT),
which aggregates many public prompt-injection and benign-prompt datasets.

Excluded, and why:
- Alpaca, no_robots: licensed for non-commercial use only.
- BIPIA, InjecAgent: held out, so `naka bench` measures the model on
  attacks it has never seen.

The decision threshold is chosen on a validation split (never on the
benchmark) as the lowest score that keeps false alarms at or below 1%.
"""

from __future__ import annotations

import ast
import json
import random
import re
import sys
import sysconfig
import time
from pathlib import Path

import numpy as np
from scipy.sparse import csr_matrix
from sklearn.linear_model import LogisticRegression

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from naka import bench  # noqa: E402
from naka.classifier import Classifier, features, tokens  # noqa: E402

BUCKETS = 1 << 20
NGRAM_MAX = 3
WINDOW, STRIDE = 64, 32
MAX_TOKENS = 512          # long training docs are truncated
KEEP = 250_000            # largest weights kept in the shipped model
EXCLUDE = {"Alpaca", "no_robots", "BIPIA", "InjecAgent"}
TARGET_FPR = 0.01
SYNTH = 18_000            # synthetic harmless + injected tool outputs (each)
OUT = Path(__file__).resolve().parent.parent / "src" / "naka" / "models"


def matrix(texts):
    rows, cols = [], []
    for r, t in enumerate(texts):
        feats = set(features(tokens(t)[:MAX_TOKENS], NGRAM_MAX, BUCKETS))
        rows.extend([r] * len(feats))
        cols.extend(feats)
    data = np.ones(len(rows), dtype=np.float32)
    return csr_matrix((data, (rows, cols)), shape=(len(texts), BUCKETS))


# ---------------------------------------------------------------- synthetic data
# Naka scans tool output (JSON, code, emails, tables, logs), not chat
# prompts. A model trained only on prompts flags anything that looks like tool
# output. So we also train on realistic tool outputs: harmless ones, and the
# same documents with one injection hidden inside. Sources: Python's standard
# library (code and docstrings, PSF license) and the PIGuard training rows.
# Nothing from the benchmark sets (BIPIA, InjecAgent) is used.
KEYS = ["id", "name", "title", "description", "status", "price", "created_at", "updated_at", "email",
        "author", "comment", "message", "content", "summary", "notes", "review_content", "reviewer_name",
        "subject", "body", "location", "category", "tags", "url", "rating", "quantity", "owner", "event",
        "details", "text", "snippet", "label", "assignee", "due_date", "amount", "currency", "phone"]
FIRST = ["Asha", "Ravi", "Maria", "John", "Wei", "Fatima", "Liam", "Priya", "Kenji", "Sara", "Omar", "Ana"]
WORDS = ["alpha", "invoice", "report", "draft", "ready", "pending", "shipped", "closed", "open", "blue",
         "quarterly", "budget", "server", "ticket", "release", "north", "meeting", "laptop", "garden"]


def stdlib_text():
    """Docstring sentences and code chunks from the standard library."""
    root = Path(sysconfig.get_paths()["stdlib"])
    files = sorted(p for p in root.glob("*.py"))[:400]
    sentences, chunks = [], []
    for f in files:
        try:
            src = f.read_text(encoding="utf-8")
            tree = ast.parse(src)
        except (SyntaxError, UnicodeDecodeError, ValueError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.ClassDef, ast.Module)):
                doc = ast.get_docstring(node)
                if doc:
                    sentences += [x.strip() for x in re.split(r"(?<=[.!?])\s+", doc) if 30 < len(x.strip()) < 240]
        lines = src.splitlines()
        for i in range(0, max(1, len(lines) - 40), 120):
            chunks.append(lines[i:i + 40])
    return sentences, chunks


def synth(n, inj_pool, benign_pool, sentences, chunks, rng):
    """n harmless documents and n with one injection each, in the same formats."""
    def sent():
        return rng.choice(sentences) if rng.random() < 0.7 else rng.choice(benign_pool)[:300]

    def value(key):
        r = rng.random()
        if key in ("id", "quantity", "rating"):
            return rng.randint(1, 99999)
        if key in ("price", "amount"):
            return round(rng.uniform(1, 5000), 2)
        if key in ("created_at", "updated_at", "due_date"):
            return f"2026-{rng.randint(1, 12):02d}-{rng.randint(1, 28):02d}T{rng.randint(0, 23):02d}:00:00Z"
        if key in ("email", "owner", "assignee"):
            return f"{rng.choice(FIRST).lower()}.{rng.choice(WORDS)}@example.com"
        if key in ("name", "author", "reviewer_name"):
            return rng.choice(FIRST) + " " + rng.choice(WORDS).title()
        if key == "url":
            return f"https://example.com/{rng.choice(WORDS)}/{rng.randint(1, 999)}"
        return sent() if r < 0.7 else " ".join(rng.choice(WORDS) for _ in range(rng.randint(1, 4)))

    def json_doc(insert):
        def obj(depth):
            keys = rng.sample(KEYS, rng.randint(3, 7))
            o = {k: value(k) for k in keys}
            if depth < 2 and rng.random() < 0.5:
                o[rng.choice(["items", "reviews", "results", "messages", "events"])] = [obj(depth + 1) for _ in range(rng.randint(1, 3))]
            return o
        o = obj(0)
        if insert:
            targets, stack = [], [o]
            while stack:
                cur = stack.pop()
                for k, v in cur.items():
                    if isinstance(v, str):
                        targets.append((cur, k))
                    elif isinstance(v, list):
                        stack += [x for x in v if isinstance(x, dict)]
            if targets:
                cur, k = rng.choice(targets)
                cur[k] = insert
            else:
                o["note"] = insert
        return repr(o) if rng.random() < 0.4 else json.dumps(o, indent=rng.choice([None, 2]))

    def code_doc(insert):
        lines = list(rng.choice(chunks))
        if insert:
            at = rng.randint(0, len(lines))
            style = rng.random()
            line = f"# {insert}" if style < 0.5 else (f'    """{insert}"""' if style < 0.8 else f"MESSAGE = {insert!r}")
            lines.insert(at, line)
        return "\n".join(lines)

    def email_doc(insert):
        paras = [" ".join(sent() for _ in range(rng.randint(1, 4))) for _ in range(rng.randint(1, 4))]
        if insert:
            paras.insert(rng.randint(0, len(paras)), insert)
        who = rng.choice(FIRST)
        head = (f"SUBJECT: {rng.choice(WORDS).title()} {rng.choice(WORDS)}|EMAIL_FROM: {who} <{who.lower()}@example.com>|"
                f"RECEIVED DATE: Mon, {rng.randint(1, 28)} Mar 2026|CONTENT: " if rng.random() < 0.5 else
                f"From: {who} <{who.lower()}@example.com>\nSubject: {rng.choice(WORDS).title()}\n\n")
        return head + "\n\n".join(paras)

    def table_doc(insert):
        cols = rng.sample(["Name", "Region", "Q1", "Q2", "Status", "Owner", "Notes", "Total", "Date"], rng.randint(3, 6))
        rows = [[str(value(c.lower()) if c not in ("Q1", "Q2", "Total") else rng.randint(10, 9999))[:60] for c in cols]
                for _ in range(rng.randint(3, 10))]
        if insert:
            rows[rng.randrange(len(rows))][rng.randrange(len(cols))] = insert
        sep = " | " if rng.random() < 0.5 else ","
        return "\n".join([sep.join(cols)] + [sep.join(r) for r in rows])

    def log_doc(insert):
        lines = [f"2026-03-{rng.randint(1, 28):02d} {rng.randint(0, 23):02d}:{rng.randint(0, 59):02d} "
                 f"{rng.choice(['INFO', 'WARN', 'DEBUG', 'ERROR'])} {sent()[:120]}" for _ in range(rng.randint(4, 15))]
        if insert:
            lines.insert(rng.randint(0, len(lines)), f"2026-03-02 10:00 INFO {insert}")
        return "\n".join(lines)

    makers = [json_doc, json_doc, code_doc, email_doc, table_doc, log_doc]
    out = []
    for _ in range(n):
        out.append({"prompt": rng.choice(makers)(None), "label": 0, "source": "synthetic"})
        out.append({"prompt": rng.choice(makers)(rng.choice(inj_pool)[:1500]), "label": 1, "source": "synthetic"})
    return out


def main() -> int:
    paths = bench.fetch(["PIGuard"])
    rows = json.loads((paths["PIGuard"] / "datasets" / "train.json").read_text())
    rows = [r for r in rows if r["source"] not in EXCLUDE and r["prompt"].strip()]
    rows += [dict(r, label=r["label"]) for r in json.loads((paths["PIGuard"] / "datasets" / "valid.json").read_text())]
    rng = random.Random(13)
    rng.shuffle(rows)
    n_val = len(rows) // 10
    val, train = rows[:n_val], rows[n_val:]
    sentences, chunks = stdlib_text()
    print(f"stdlib: {len(sentences)} sentences, {len(chunks)} code chunks")
    for split, n in ((train, SYNTH), (val, SYNTH // 9)):
        inj = [r["prompt"] for r in split if r["label"] == 1]
        ben = [r["prompt"] for r in split if r["label"] == 0]
        split += synth(n, inj, ben, sentences, chunks, rng)
    print(f"train {len(train)}  validation {len(val)}  (positives {sum(r['label'] for r in train)})")

    t = time.time()
    X, y = matrix([r["prompt"] for r in train]), np.array([r["label"] for r in train])
    Xv, yv = matrix([r["prompt"] for r in val]), np.array([r["label"] for r in val])
    print(f"features in {time.time() - t:.0f}s")

    model = LogisticRegression(C=4.0, max_iter=2000, solver="liblinear", class_weight="balanced")
    model.fit(X, y)
    w, b = model.coef_[0], float(model.intercept_[0])

    # Prune to the largest weights, then score validation exactly as shipped.
    keep = np.argsort(-np.abs(w))[:KEEP]
    pruned = [(int(i), float(w[i])) for i in sorted(keep) if w[i] != 0]
    meta = {"buckets": BUCKETS, "ngram_max": NGRAM_MAX, "window": WINDOW, "stride": STRIDE,
            "threshold": 0.5, "version": "injection-v1",
            "trained_on": "PIGuard collection minus " + ", ".join(sorted(EXCLUDE)) +
                          "; synthetic tool outputs built from Python stdlib text and PIGuard rows",
            "created": time.strftime("%Y-%m-%d")}
    tmp = OUT / "_tmp.bin.gz"
    Classifier.save(str(tmp), pruned, b, meta)
    clf = Classifier.load(str(tmp))
    scores = np.array([clf.score(r["prompt"]).probability for r in val])
    neg = np.sort(scores[yv == 0])
    threshold = float(neg[int(len(neg) * (1 - TARGET_FPR))]) + 1e-6
    threshold = max(threshold, 0.5)
    tpr = float((scores[yv == 1] >= threshold).mean())
    fpr = float((scores[yv == 0] >= threshold).mean())
    print(f"validation: threshold {threshold:.3f}  detection {tpr:.1%}  false alarms {fpr:.1%}")

    meta.update(threshold=round(threshold, 4), validation={"detection": round(tpr, 4), "false_alarm": round(fpr, 4),
                                                           "n": len(val)})
    Classifier.save(str(OUT / "injection-v1.bin.gz"), pruned, b, meta)
    tmp.unlink()
    print("saved", OUT / "injection-v1.bin.gz", f"{(OUT / 'injection-v1.bin.gz').stat().st_size / 1e6:.1f} MB")
    return 0


if __name__ == "__main__":
    sys.exit(main())
