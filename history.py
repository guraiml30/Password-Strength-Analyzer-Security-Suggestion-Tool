"""Optional local history. Stores ONLY safe aggregate metadata: time, score, label, length,
bit estimate and finding categories. NEVER the password, a hash, or any part of it."""
import json
import os
import time
from collections import Counter

PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "history.jsonl")
ALLOWED = ("score", "label", "length", "bits_adjusted")


def record(result, path=PATH):
    row = {"ts": int(time.time()), **{k: result[k] for k in ALLOWED},
           "flags": sorted({f["kind"] for f in result["findings"]})}
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(row) + "\n")


def load(path=PATH):
    if not os.path.isfile(path):
        return []
    with open(path, encoding="utf-8") as fh:
        return [json.loads(l) for l in fh if l.strip()]


def summary(path=PATH):
    rows = load(path)
    return {"count": len(rows),
            "labels": dict(Counter(r["label"] for r in rows)),
            "flags": dict(Counter(f for r in rows for f in r["flags"])),
            "avg_score": round(sum(r["score"] for r in rows) / len(rows), 1) if rows else 0}


def clear(path=PATH):
    if os.path.isfile(path):
        os.remove(path)
