"""A third control on the skeleton result: does the shape transfer off-corpus?

    python -m src.skeleton_transfer
    python -m src.skeleton_transfer --json data/skeleton_transfer.json

`src.separability` reports that this corpus is more skeleton-separable than the
two it criticises: collapsing every alphanumeric run to `#` leaves punctuation
shape alone, and on that representation WebInject2026 scores AUC 0.991 against
0.906 and 0.910. Read on its own that looks like a worse shortcut than the ones
being complained about, and the paper says so before explaining it.

Two controls already ship, and both are internal to this corpus: the skeleton
model scores 0.996 within matched pairs, and it survives the template-disjoint
split at 0.976. A reader can reasonably answer that both controls are computed
on data from the same generator, so neither can distinguish "the model reads
injection shape" from "the model reads our generator's fingerprint".

This is the external control. Fit the skeleton model here, then score it on
CSIC-2010 and ECML/PKDD-2007 without refitting.

  - If punctuation shape is a property of injection, a skeleton model trained on
    our attacks should separate somebody else's attacks too, because their
    injections have the same syntax.
  - If it is a property of our generator, the model has learned motifs that only
    exist here, and it should collapse to chance on both.

The comparison that matters is against full-text transfer, which
`src.baselines` already measures and which is poor: ROC-AUC 0.60 against
CSIC-2010. Skeleton transfer holding up *better* than full-text transfer would
be the informative outcome, because the skeleton representation discards
exactly the corpus-specific vocabulary that full text carries.

This control is reported whichever way it comes out. A weak result here does not
invalidate the two internal controls, but it does bound what they establish, and
Section 5.3 is written to say so.
"""

import argparse
import json
import os
import re

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score

from . import checksums as S
from .syntax_ablation import _load

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "data")

_ALNUM = re.compile(r"[A-Za-z0-9]+")


def skeletonise(s):
    """Every alphanumeric run becomes a single `#`. Punctuation shape survives,
    every word and number does not. Identical to `src.separability`."""
    return _ALNUM.sub("#", str(s))


def _fit(train_text, train_y):
    v = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=3,
                        sublinear_tf=True, max_features=200_000)
    X = v.fit_transform(train_text)
    m = LogisticRegression(max_iter=2000, C=8).fit(X, train_y)
    return v, m


def _score(v, m, text):
    return m.predict_proba(v.transform(text))[:, 1]


def run():
    out = {}

    d, tr, te = _load("webinject2026")
    text = d["payload"].astype(str).to_numpy()
    y = d["label"].to_numpy().astype(int)

    skel = np.array([skeletonise(s) for s in text])

    # Two models on our training rows: skeleton-only, and full text as the
    # reference the skeleton is being compared against.
    v_sk, m_sk = _fit(skel[tr], y[tr])
    v_full, m_full = _fit(text[tr], y[tr])

    out["source"] = {
        "corpus": "WebInject2026",
        "skeleton_auc_in_domain": float(
            roc_auc_score(y[te], _score(v_sk, m_sk, skel[te]))),
        "full_auc_in_domain": float(
            roc_auc_score(y[te], _score(v_full, m_full, text[te]))),
        "n_train": int(tr.sum()),
    }

    for key, label in (("csic_parsed", "CSIC-2010"),
                       ("ecml_parsed", "ECML/PKDD-2007")):
        d2, _, _ = _load(key)
        if d2 is None:
            continue
        # Transfer is scored on the whole target corpus: no fitting happens
        # here, so there is no train/test split to respect.
        t2 = d2["payload"].astype(str).to_numpy()
        y2 = d2["label"].to_numpy().astype(int)
        s2 = np.array([skeletonise(s) for s in t2])

        out[key] = {
            "corpus": label,
            "n": int(len(d2)),
            "base_rate": float(y2.mean()),
            "skeleton_transfer_auc": float(
                roc_auc_score(y2, _score(v_sk, m_sk, s2))),
            "full_transfer_auc": float(
                roc_auc_score(y2, _score(v_full, m_full, t2))),
        }
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", default=os.path.join(DATA,
                                                   "skeleton_transfer.json"))
    a = ap.parse_args()

    res = run()
    res["_corpus"] = S.corpus_fingerprint()
    with open(a.json, "w", encoding="utf-8") as fh:
        json.dump(res, fh, indent=2)
    S.refresh(a.json)

    src = res["source"]
    print("\nfit on WebInject2026 train (%d rows)" % src["n_train"])
    print("  in-domain   skeleton %.3f   full %.3f"
          % (src["skeleton_auc_in_domain"], src["full_auc_in_domain"]))
    print("\n%-18s %10s %10s" % ("transferred to", "skeleton", "full text"))
    for k, v in res.items():
        if k == "source" or k.startswith("_"):
            continue
        print("%-18s %10.3f %10.3f"
              % (v["corpus"], v["skeleton_transfer_auc"],
                 v["full_transfer_auc"]))
    print("\nwrote %s" % a.json)


if __name__ == "__main__":
    main()
