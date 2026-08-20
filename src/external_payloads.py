"""External payload holdout: score the shipped detector on payloads we did not write.

Limitation 2 is that the same group authored the 98 attack templates and the gate
that judges them, so a reviewer can read the retention figure as a design
specification rather than a finding. Nothing in a self-written gate answers that.

This module answers it with a holdout. PayloadsAllTheThings (`data/patt/`, MIT,
credited in NOTICE) is a third-party payload corpus that the shipped release was
built *without* -- `data/patt/` is gitignored and was absent at build time. We

  1. load the shipped pool and record every payload group it contains,
  2. load PATT and keep only payloads whose `group_key` is absent from that set,
     so the holdout is genuinely unseen,
  3. sample a stratified 250 across the 14 families at seed 42,
  4. wrap each one in a counterfactual pair using `build._paired_records`, the
     same function that built the corpus, so length parity, carrier-word parity
     and the twin all hold by construction rather than by reimplementation, and
     the carriers come from cores pre-assigned to the *test* cell,
  5. score the shipped reference model -- char 3-5 gram tf-idf + logistic
     regression, fitted on the payload-disjoint TRAIN split and not retrained.

The corpus is never rebuilt. `src/build.py` warns that a rebuild with
`data/patt/` present folds those payloads into training and will not reproduce
the published CSV; that would both break byte-reproducibility and answer the
objection more weakly, because the point is that the detector never saw them.

    python -m src.external_payloads            # -> data/external_payloads.json
"""

import argparse
import datetime
import json
import os
import random
import subprocess
import sys

import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_curve

from src import build as B
from src import config as C
from src import payloads as P
from src import checksums as S

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "data")
SEED = 42
N_SAMPLE = 250
BIG_CAP = 100000          # lift the per-family cap so PATT is not truncated away


def _external_pool(patt_root):
    """PATT payloads whose group_key does not occur in the shipped pool."""
    shipped = P.load_pool()                       # no patt_root: what was released
    seen = {P.group_key(raw) for items in shipped.values() for raw, _ in items}
    patt = P._load_patt(patt_root)
    out, dropped = {}, 0
    for fam, lines in patt.items():
        keep = []
        for line in lines:
            g = P.group_key(line)
            if g in seen:
                dropped += 1
                continue
            keep.append(line)
        if keep:
            out[fam] = keep
    return out, seen, dropped


def _patt_provenance(patt_root):
    """Pin the upstream commit.

    The corpus rebuilds byte-identically at seed 42; this holdout would not,
    because PayloadsAllTheThings is a moving target. Recording the commit the
    clone sits on -- and the selected group keys below -- is what makes the 229
    reconstructible without re-resolving upstream.
    """
    out = {"patt_root": os.path.relpath(patt_root, ROOT)}
    try:
        sha = subprocess.check_output(["git", "-C", patt_root, "rev-parse", "HEAD"],
                                      stderr=subprocess.DEVNULL).decode().strip()
        when = subprocess.check_output(
            ["git", "-C", patt_root, "log", "-1", "--format=%cI"],
            stderr=subprocess.DEVNULL).decode().strip()
        out["patt_commit"] = sha
        out["patt_commit_date"] = when
    except Exception:
        out["patt_commit"] = None
        out["patt_commit_date"] = None
    try:
        out["patt_checkout_mtime"] = datetime.datetime.fromtimestamp(
            os.path.getmtime(patt_root)).isoformat(timespec="seconds")
    except OSError:
        pass
    return out


def _tpr_at_fpr(y, s, budget):
    fpr, tpr, _ = roc_curve(y, s)
    ok = fpr <= budget
    return float(tpr[ok].max()) if ok.any() else 0.0


def build_holdout(patt_root, n_sample=N_SAMPLE, seed=SEED):
    ext, seen, dropped = _external_pool(patt_root)
    if not ext:
        raise SystemExit("no external payloads left after subtracting the shipped pool")

    rng = random.Random(seed)
    fams = sorted(ext)
    per = max(1, n_sample // len(fams))
    chosen = []
    for fam in fams:
        pool = sorted(set(ext[fam]))
        rng.shuffle(pool)
        for raw in pool[:per]:
            chosen.append((fam, raw))
    rng.shuffle(chosen)
    chosen = chosen[:n_sample]

    # Cell pool shaped exactly as _preassign produces: {fam: [(raw, template, group)]}
    cell = ("test", "test")
    ext_cell = {}
    for fam, raw in chosen:
        ext_cell.setdefault(fam, []).append(
            (raw, P._struct_signature(raw), P.group_key(raw)))

    # Cores pre-assigned to the test cell, so carriers are test-split benign text.
    shipped = P.load_pool()
    _, cores_by_cell, _, _ = B._preassign(shipped, random.Random(seed))
    cores = cores_by_cell.get(cell) or []

    endpoints = C.endpoints()
    inject_eps = [(app, ep) for app, ep in endpoints if ep["inject"]]

    grng = random.Random(seed)
    rows, made, i = [], 0, 0
    while made < len(chosen) and i < len(chosen) * 40:
        i += 1
        app, ep = grng.choice(inject_eps)
        core_idx = cores[made % len(cores)] if cores else None
        fam_pool = {f: v for f, v in ext_cell.items() if f in ep["families"]}
        if not fam_pool:
            continue
        b, a = B._paired_records(app, ep, shipped, grng, (made, cell, fam_pool, core_idx))
        if b is None:
            continue
        for r in (b, a):
            r["split"], r["split_struct"] = cell
            # Exactly the text a detector inspects, via the corpus's own
            # normaliser -- not a reimplementation.
            r["payload"] = B.normalise(r)
        if len(b["payload"]) < 3 or len(a["payload"]) < 3:
            continue
        rows.extend([b, a])
        made += 1
    keys = sorted({P.group_key(raw) for _, raw in chosen})
    return pd.DataFrame(rows), dropped, len(chosen), keys, len(fams), per


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--patt", default=os.path.join(DATA, "patt"))
    ap.add_argument("--csv", default=os.path.join(DATA, "webinject2026.csv"))
    ap.add_argument("--json", default=os.path.join(DATA, "external_payloads.json"))
    ap.add_argument("--n", type=int, default=N_SAMPLE)
    a = ap.parse_args()

    if not os.path.isdir(a.patt):
        raise SystemExit("PayloadsAllTheThings not found at %s" % a.patt)

    ext_df, dropped, n_chosen, sel_keys, n_fams, per_fam = build_holdout(a.patt, a.n)
    atk = ext_df[ext_df.label == 1]
    print("external holdout: %d payloads sampled, %d pairs built, %d PATT payloads "
          "dropped as already in the shipped pool" % (n_chosen, len(atk), dropped))

    # The shipped reference model, fitted on the payload-disjoint TRAIN split only.
    df = pd.read_csv(a.csv, keep_default_na=False).reset_index(drop=True)
    tr = df[df.split == "train"]
    v = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=3,
                        max_features=200000)
    X = v.fit_transform(tr.payload.astype(str))
    m = LogisticRegression(max_iter=2000, C=4.0).fit(X, tr.label)

    # Benign half of the corpus test split gives the operating threshold its
    # false-positive side; the external attacks supply the positive side.
    ben = df[(df.split == "test") & (df.label == 0)]
    y = np.concatenate([np.ones(len(atk)), np.zeros(len(ben))])
    s = np.concatenate([
        m.predict_proba(v.transform(atk.payload.astype(str)))[:, 1],
        m.predict_proba(v.transform(ben.payload.astype(str)))[:, 1]])

    recall = float((s[:len(atk)] >= 0.5).mean())
    out = {
        "n_external_attacks": int(len(atk)),
        "n_benign_reference": int(len(ben)),
        "n_patt_dropped_as_seen": int(dropped),
        "recall_at_0.5": recall,
        "tpr_at_1pct_fpr": _tpr_at_fpr(y, s, 0.01),
        "tpr_at_0.1pct_fpr": _tpr_at_fpr(y, s, 0.001),
        "by_family": {},
        "_corpus": S.corpus_fingerprint(csv_path=a.csv),
        "negatives": "full payload-disjoint test split benign rows",
        "selection": {
            "seed": SEED,
            "rule": "stratified: up to floor(n/families) unique payloads per "
                    "family, shuffled at seed %d, truncated to n" % SEED,
            "n_requested": a.n,
            "n_families": n_fams,
            "per_family_cap": per_fam,
            "group_keys": sel_keys,
        },
    }
    out.update(_patt_provenance(a.patt))

    piv = ext_df[ext_df.pair_id.astype(str) != ""].pivot_table(
        index="pair_id", columns="label", values="payload", aggfunc="first").dropna()
    if not piv.empty and 0 in piv.columns and 1 in piv.columns:
        sa = m.predict_proba(v.transform(piv[1].astype(str)))[:, 1]
        sb = m.predict_proba(v.transform(piv[0].astype(str)))[:, 1]
        out["paired_accuracy"] = float((sa > sb).mean())
        out["n_pairs"] = int(len(piv))

    for fam, g in atk.groupby("attack_type"):
        sc = m.predict_proba(v.transform(g.payload.astype(str)))[:, 1]
        out["by_family"][fam] = {"n": int(len(g)),
                                 "recall": float((sc >= 0.5).mean())}

    with open(a.json, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)
    print("  recall %.3f | TPR@1%%FPR %.3f | TPR@0.1%%FPR %.3f | paired %.3f"
          % (out["recall_at_0.5"], out["tpr_at_1pct_fpr"], out["tpr_at_0.1pct_fpr"],
             out.get("paired_accuracy", float("nan"))))
    print("  wrote %s" % a.json)
    S.refresh(a.json)


if __name__ == "__main__":
    main()
