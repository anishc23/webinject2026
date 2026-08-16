"""Panel C of Table 1: the deletion ablation under one split protocol for all
three corpora.

Why this exists
---------------
``src.syntax_ablation`` gives WebInject2026 its shipped payload-disjoint group
split, and gives CSIC-2010 and ECML/PKDD-2007 a stratified random 80/20,
because neither ships grouping information. That is the protocol their own
published results use and the one that flatters them most, so the comparison is
conservative in their favour -- but the paper cannot then claim "the same split
protocol", and a reader is entitled to ask what happens when the protocols are
actually matched.

The question is sharper than it looks, because **64.4% of CSIC-2010's payload
strings are exact duplicates** (34,552 unique of 97,065 rows). Under a random
split most of its test rows have an identical copy in training, so a memorising
model scores as a generalising one. ECML/PKDD-2007 is 2.3% duplicated;
WebInject2026 is 0% by construction (``duplicates`` is a blocking check).

This module applies one protocol to all three:

  1. drop exact-duplicate payloads,
  2. group by digit-masked skeleton, so near-duplicates travel together,
  3. split 80/20 over *groups*, never over rows,
  4. run the identical three conditions with the identical model.

Everything except the split is imported from ``src.syntax_ablation``, so the
two panels cannot drift apart.

    python -m src.protocol_matched                  # -> data/protocol_matched.json
    python -m src.protocol_matched --fast           # subsample, for a smoke test
"""

import argparse
import json
import os
import re
import sys

import numpy as np
import pandas as pd
from sklearn.model_selection import GroupShuffleSplit

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.syntax_ablation import (CORPORA, DATA, _fit, _load, derive_vocab,
                                 pool_words, strip_syntax, strip_vocab)

DIGITS = re.compile(r"\d+")
OUT = os.path.join(DATA, "protocol_matched.json")
SEED = 42


def skeleton(s):
    """Digit-masked form. ``id=1414`` and ``id=9`` share a skeleton, so a split
    that separates them would leak a template across the boundary."""
    return DIGITS.sub("#", str(s))


def matched_split(payloads, y, seed=SEED, test_size=0.2):
    """Deduplicate, group by skeleton, split over groups.

    Returns (keep_index, train_mask, test_mask) where the masks are over the
    deduplicated frame, not the original.
    """
    ser = pd.Series([str(p) for p in payloads])
    keep = ~ser.duplicated(keep="first")
    keep_idx = np.flatnonzero(keep.to_numpy())

    kept = ser[keep].reset_index(drop=True)
    groups = kept.map(skeleton).to_numpy()
    yk = np.asarray(y)[keep_idx]

    gss = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=seed)
    itr, ite = next(gss.split(np.zeros(len(kept)), yk, groups))
    tr = np.zeros(len(kept), bool); tr[itr] = True
    te = np.zeros(len(kept), bool); te[ite] = True
    return keep_idx, tr, te


def _retained(full_auc, deleted_auc):
    """Separation above chance as a share of the full model's. Can go negative:
    an AUC below 0.5 means the deleted text is anti-correlated with the label,
    which is a stronger statement than 'nothing survived'."""
    denom = full_auc - 0.5
    if abs(denom) < 1e-9:
        return None
    return float((deleted_auc - 0.5) / denom)


def run(fast=False):
    pool = pool_words()
    rows = []

    for key, label in CORPORA:
        d, _, _ = _load(key)
        if d is None:
            print(f"  {label}: source CSV absent, skipped")
            continue

        raw_n = len(d)
        text_col = "payload"
        payloads = d[text_col].astype(str).to_numpy()
        y = d["label"].astype(int).to_numpy()

        keep_idx, tr, te = matched_split(payloads, y)
        text = payloads[keep_idx]
        y = y[keep_idx]

        # Capture the deduplication figures BEFORE any --fast subsampling,
        # otherwise the two reductions are conflated and dup_share is nonsense.
        dedup_n = len(text)
        dedup_share = 1.0 - dedup_n / raw_n if raw_n else 0.0
        dedup_groups = len(pd.Series(text).map(skeleton).unique())

        if fast and len(text) > 12000:
            rs = np.random.RandomState(SEED)
            sel = rs.choice(len(text), 12000, replace=False)
            keepmask = np.zeros(len(text), bool); keepmask[sel] = True
            text, y, tr, te = text[keepmask], y[keepmask], tr[keepmask], te[keepmask]

        rec = {
            "corpus": label,
            "panel": "protocol_matched",
            "n_raw": int(raw_n),
            "n_dedup": int(dedup_n),
            "dup_share": float(dedup_share),
            "n_groups": int(dedup_groups),
            "n_fitted": int(len(text)),
            "n_train": int(tr.sum()),
            "n_test": int(te.sum()),
            "base_rate": float(y.mean()),
            "subsampled": bool(fast and dedup_n != len(text)),
        }

        full, _ = _fit(text[tr], y[tr], text[te], y[te])
        rec["full"] = full

        syn = np.array([strip_syntax(s) for s in text])
        r, _ = _fit(syn[tr], y[tr], syn[te], y[te])
        r["auc_retained"] = _retained(full["roc_auc"], r["roc_auc"])
        rec["syntax_deleted"] = r

        sv = np.array([strip_vocab(s, pool) for s in text])
        r2, _ = _fit(sv[tr], y[tr], sv[te], y[te])
        r2["auc_retained"] = _retained(full["roc_auc"], r2["roc_auc"])
        rec["syntax_and_vocab_deleted"] = r2

        rows.append(rec)
        print(f"  {label:16s} raw {raw_n:>6,} -> dedup {dedup_n:>6,} "
              f"({dedup_share*100:4.1f}% dup, {dedup_groups:,} groups)  "
              f"full AUC {full['roc_auc']:.3f}  "
              f"-syn-vocab AUC {r2['roc_auc']:.3f}  "
              f"kept {r2['auc_retained']*100:6.1f}%")

    return rows


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--fast", action="store_true",
                    help="subsample to 12k rows per corpus")
    ap.add_argument("--json", default=OUT)
    a = ap.parse_args()

    print("Protocol-matched ablation: dedup -> skeleton groups -> 80/20 over "
          "groups, all three corpora.\n")
    rows = run(fast=a.fast)

    with open(a.json, "w", encoding="utf-8") as fh:
        json.dump({"protocol_matched": rows, "seed": SEED,
                   "note": "Exact payload duplicates dropped; grouped by "
                           "digit-masked skeleton; 80/20 GroupShuffleSplit. "
                           "Applied identically to all three corpora."},
                  fh, indent=1)
    print(f"\nwrote {a.json}")


if __name__ == "__main__":
    main()
