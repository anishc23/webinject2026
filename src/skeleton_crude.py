"""How much of each corpus's skeleton separability is crude?

Section 5.3 reports that this corpus is more skeleton-separable than the two it
criticises (0.991 against 0.906 and 0.910), which read alone looks like a worse
shortcut. That reading treats skeleton AUC as one quantity. It is not: a
punctuation skeleton still carries its own length and its own punctuation
density, and either can separate a corpus without any attack shape being
learned at all.

This module measures the crude part. For each corpus it scores two single
features on the skeletonised text -- the length of the skeleton, and the share
of its characters that are punctuation rather than the `#` standing in for an
alphanumeric run -- under the same train/test split and the same AUC as
`src.separability.skeleton_auc`, so the numbers are directly comparable to the
skeleton AUC they decompose.

A corpus whose skeleton AUC is high while both crude features sit at chance is
separable on the arrangement of punctuation, which is what an injection is. A
corpus whose crude features are already most of the way to its skeleton AUC is
separable on how long its attacks are and how much punctuation they contain,
which is the length and character-class shortcut this corpus was built to
remove.

  python -m src.skeleton_crude
"""

import argparse
import json
import os
import re

import numpy as np
from sklearn.metrics import roc_auc_score

from . import checksums as S
from .syntax_ablation import _load

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "data")
OUT = os.path.join(DATA, "skeleton_crude.json")

_ALNUM = re.compile(r"[A-Za-z0-9]+")
# Same corpora, same labels and the same split column as src.separability.
CORPORA = (("webinject2026", "WebInject2026", "split"),
           ("csic_parsed", "CSIC-2010", None),
           ("ecml_parsed", "ECML/PKDD-2007", None))
SEED = 42


def skeletonise(s):
    """Identical to `src.separability` and `src.skeleton_transfer`."""
    return _ALNUM.sub("#", str(s))


def _test_mask(df, split_col):
    """The same held-out rows `skeleton_auc` scores on: the shipped test split
    where the corpus has one, otherwise a fixed 70/30 draw."""
    if split_col and split_col in df.columns:
        return (df[split_col] == "test").to_numpy()
    rng = np.random.RandomState(SEED)
    idx = rng.permutation(len(df))
    te = np.ones(len(df), bool)
    te[idx[:int(0.7 * len(df))]] = False
    return te


def run():
    out = {}
    for key, label, split_col in CORPORA:
        d, _, _ = _load(key)
        if d is None:
            continue
        skel = d["payload"].astype(str).map(skeletonise)
        y = d["label"].to_numpy().astype(int)
        te = _test_mask(d, split_col)

        # Two crude features. Neither is fitted: a single feature's AUC is a
        # rank statistic, so there is nothing to train and nothing to tune.
        length = skel.str.len().to_numpy().astype(float)
        density = skel.map(
            lambda s: 0.0 if not s else sum(1 for c in s if c != "#") / len(s)
        ).to_numpy()

        out[label] = {
            "corpus": label,
            "n_test": int(te.sum()),
            "length_auc": float(roc_auc_score(y[te], length[te])),
            "density_auc": float(roc_auc_score(y[te], density[te])),
            "split": split_col or "random 70/30 at seed %d" % SEED,
        }
    out["_corpus"] = S.corpus_fingerprint()
    out["_note"] = ("Single-feature AUC on the punctuation skeleton, on the same "
                    "test rows as src.separability.skeleton_auc. Compare against "
                    "the skeleton_auc in separability.json.")
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--json", default=OUT)
    a = ap.parse_args()

    res = run()
    with open(a.json, "w", encoding="utf-8") as fh:
        json.dump(res, fh, indent=2)

    sep = json.load(open(os.path.join(DATA, "separability.json")))["skeleton"]
    print("  How much of the skeleton signal is length or density alone?\n")
    print(f"    {'corpus':<18}{'skeleton':>10}{'length':>9}{'density':>9}")
    for k, v in res.items():
        if k.startswith("_"):
            continue
        print(f"    {k:<18}{sep[k]['skeleton_auc']:>10.3f}"
              f"{v['length_auc']:>9.3f}{v['density_auc']:>9.3f}")
    print("\n  Crude features at chance mean the skeleton signal is arrangement,")
    print("  not size. Crude features near the skeleton AUC mean the opposite.")
    print(f"\n  wrote {a.json}")
    S.refresh(a.json)


if __name__ == "__main__":
    main()
