"""The third control on the skeleton result: injections we did not write.

Section 5.3 reports that this corpus is more skeleton-separable than the two it
criticises, and offers two controls. Both use rows from our own generator, so
neither separates "the model reads injection shape" from "the model reads our
generator's fingerprint". The cross-corpus control (`src.skeleton_transfer`)
answers a different question and answers it badly: CSIC-2010 and ECML/PKDD-2007
differ from us in carrier text as well as in payload, so a poor transfer there
is not attributable to the skeleton.

This module holds the carrier fixed and changes only the payload. It takes the
PayloadsAllTheThings holdout of `src.external_payloads` -- payloads the corpus
never saw, wrapped in our own pair machinery so length and carrier parity hold
-- skeletonises it, and scores it with a skeleton model fitted on our train
split. Because each external attack has a benign twin differing only in the
injected span, paired accuracy isolates the injection's punctuation shape from
everything else.

Read it this way:

  paired accuracy well above chance   punctuation shape transfers to injections
                                      we did not write, so what the skeleton
                                      model reads is a property of injection
  paired accuracy at or near chance   the skeleton signal is our generator's
                                      fingerprint, and Section 5.3's open
                                      defect is confirmed rather than open

One run, reported either way. There is nothing to tune here: the vectoriser,
the classifier and the holdout are all imported.

  python -m src.skeleton_external
"""

import argparse
import json
import os

import numpy as np

from . import checksums as S
from .external_payloads import build_holdout, N_SAMPLE, SEED
from .skeleton_transfer import _fit, _score, skeletonise
from .syntax_ablation import _load

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "data")
OUT = os.path.join(DATA, "skeleton_external.json")
# Same default as src.external_payloads; the clone is gitignored.
PATT_DEFAULT = os.path.join(DATA, "patt")


def _auc(y, s):
    """ROC-AUC by rank, so a degenerate score vector cannot raise."""
    y = np.asarray(y, dtype=int)
    s = np.asarray(s, dtype=float)
    pos, neg = (y == 1).sum(), (y == 0).sum()
    if pos == 0 or neg == 0:
        return float("nan")
    order = np.argsort(s, kind="mergesort")
    ranks = np.empty(len(s), dtype=float)
    ranks[order] = np.arange(1, len(s) + 1)
    # Average ranks within ties, or every tie would count as a win.
    _, inv, counts = np.unique(s, return_inverse=True, return_counts=True)
    sums = np.zeros(len(counts))
    np.add.at(sums, inv, ranks)
    ranks = (sums / counts)[inv]
    return float((ranks[y == 1].sum() - pos * (pos + 1) / 2) / (pos * neg))


def run(patt_root=PATT_DEFAULT, n_sample=N_SAMPLE, seed=SEED):
    # Fit the skeleton model on our own training split, exactly as
    # skeleton_transfer does: same vectoriser, same C, same skeletonisation.
    d, tr, te = _load("webinject2026")
    train = d[d.split == "train"] if "split" in d.columns else d.iloc[tr]
    v, m = _fit([skeletonise(x) for x in train["payload"].astype(str)],
                train["label"].to_numpy().astype(int))

    ext_df, dropped, n_chosen, keys, n_fams, per_fam = build_holdout(
        patt_root, n_sample=n_sample, seed=seed)

    atk = ext_df[ext_df.label == 1]
    ben = ext_df[ext_df.label == 0]

    # Negatives are the benign rows of the payload-disjoint test split, the same
    # reference external_payloads.py scores against, so the two are comparable.
    test_ben = d[(d.split == "test") & (d.label == 0)]["payload"].astype(str)

    s_atk = _score(v, m, [skeletonise(x) for x in atk["payload"].astype(str)])
    s_ben = _score(v, m, [skeletonise(x) for x in test_ben])

    y = np.r_[np.ones(len(s_atk), dtype=int), np.zeros(len(s_ben), dtype=int)]
    out = {
        "n_external_attacks": int(len(atk)),
        "n_benign_reference": int(len(s_ben)),
        "n_patt_dropped_as_seen": int(dropped),
        "skeleton_auc_vs_test_benign": _auc(y, np.r_[s_atk, s_ben]),
        "negatives": "full payload-disjoint test split benign rows, skeletonised",
        "_corpus": S.corpus_fingerprint(),
    }

    # The control that matters: attack against its own twin, carrier identical,
    # both skeletonised, so only the injected span's punctuation shape differs.
    piv = ext_df[ext_df.pair_id.astype(str) != ""].pivot_table(
        index="pair_id", columns="label", values="payload", aggfunc="first").dropna()
    if not piv.empty and 0 in piv.columns and 1 in piv.columns:
        sa = _score(v, m, [skeletonise(x) for x in piv[1].astype(str)])
        sb = _score(v, m, [skeletonise(x) for x in piv[0].astype(str)])
        wins = float((sa > sb).mean())
        ties = float((sa == sb).mean())
        out["n_pairs"] = int(len(piv))
        out["paired_wins"] = wins
        out["paired_ties"] = ties
        # Ties count half, as everywhere else in the paper.
        out["paired_accuracy"] = wins + 0.5 * ties
        out["skeleton_auc_within_pair"] = _auc(
            np.r_[np.ones(len(sa), dtype=int), np.zeros(len(sb), dtype=int)],
            np.r_[sa, sb])

    # In-corpus paired figure under the same model, as the comparison point.
    tst = d[(d.split == "test") & (d.pair_id.astype(str) != "")]
    ipiv = tst.pivot_table(index="pair_id", columns="label", values="payload",
                           aggfunc="first").dropna()
    if not ipiv.empty and 0 in ipiv.columns and 1 in ipiv.columns:
        ia = _score(v, m, [skeletonise(x) for x in ipiv[1].astype(str)])
        ib = _score(v, m, [skeletonise(x) for x in ipiv[0].astype(str)])
        out["in_corpus_paired_accuracy"] = (float((ia > ib).mean())
                                            + 0.5 * float((ia == ib).mean()))
        out["in_corpus_n_pairs"] = int(len(ipiv))
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--patt", default=PATT_DEFAULT)
    ap.add_argument("--n", type=int, default=N_SAMPLE)
    ap.add_argument("--json", default=OUT)
    a = ap.parse_args()

    out = run(a.patt, a.n)
    with open(a.json, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)

    print("skeleton model fitted on WebInject2026 train, scored on external "
          "payloads\n")
    print("  external attacks      %d (dropped %d already in the pool)"
          % (out["n_external_attacks"], out["n_patt_dropped_as_seen"]))
    print("  AUC vs test benign    %.3f" % out["skeleton_auc_vs_test_benign"])
    if "paired_accuracy" in out:
        print("  paired accuracy       %.3f over %d pairs (%.1f%% ties)"
              % (out["paired_accuracy"], out["n_pairs"],
                 out["paired_ties"] * 100))
        print("  within-pair AUC       %.3f" % out["skeleton_auc_within_pair"])
    if "in_corpus_paired_accuracy" in out:
        print("  in-corpus paired      %.3f over %d pairs"
              % (out["in_corpus_paired_accuracy"], out["in_corpus_n_pairs"]))
    print("\nwrote %s" % a.json)
    S.refresh(a.json)


if __name__ == "__main__":
    main()
