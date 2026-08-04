"""Known gaps: four properties the 25-check gate does not currently enforce.

    python -m src.audit_gaps

These are written in the style of `src.validate` and are intended to become
gate checks 26-29 once the construction changes that fix them land. They are
deliberately NOT part of the CI gate today, because on v3.0.0 all four FAIL.
Shipping them failing is the point: the gaps are published rather than left for
a reviewer to find, and the file doubles as the acceptance test for the fixes.

  lexical_register_leak  attack and benign carriers are drawn from different
                         vocabularies, so the label is recoverable from ordinary
                         words after every trace of injection syntax is deleted
  struct_split_balance   `split_balance` inspects `split` only; `split_struct`
                         is template-disjoint but neither family-complete nor
                         prevalence-matched
  session_signal         `session` carries no within-session correlation, so the
                         column cannot support the sequence modelling the
                         datasheet advertises
  transfer_ranking       cross-corpus transfer reported as F1 at a fixed
                         threshold hides threshold collapse; measure AUC/PR-AUC
                         and show the predicted-positive rate

Origin: these were found by an external audit of v3.0.0 and independently
reproduced. See DATASHEET.md > Limitations and CHANGELOG.md.
"""

import json
import os
import re
import sys
from collections import Counter

import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, f1_score, roc_auc_score

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "data")

WORD = re.compile(r"[A-Za-z]{2,}")

# Ceilings/floors chosen to be the value the corpus should reach once fixed,
# not the value it currently has.
REGISTER_AUC_CEILING = 0.75
STRUCT_SPREAD_MAX = 0.05
SESSION_RATIO_FLOOR = 1.15
TRANSFER_AUC_FLOOR = 0.75

_results = []


def report(name, ok, msg):
    _results.append((name, ok, msg))
    print(f"  {'PASS' if ok else 'FAIL'}  {name:<22s} {msg}")


def load():
    pq = os.path.join(DATA, "webinject2026.parquet")
    if os.path.exists(pq):
        try:
            return pd.read_parquet(pq)
        except Exception:
            pass
    return pd.read_csv(os.path.join(DATA, "webinject2026.csv"),
                       keep_default_na=False, dtype=str).astype({"label": int})


def _carrier_tokens(df):
    """Every alphabetic token of `payload`, minus every token that occurs in the
    seed payload pool. What remains is carrier vocabulary."""
    pool = json.load(open(os.path.join(ROOT, "corpus", "payloads.json")))
    atk = set()
    for payloads in pool.values():
        for p in payloads:
            atk |= {w.lower() for w in WORD.findall(p)}
    return df["payload"].map(
        lambda s: [w for w in (t.lower() for t in WORD.findall(str(s))) if w not in atk])


def _fit_auc(text_train, y_train, text_test, y_test):
    vec = TfidfVectorizer(min_df=3, sublinear_tf=True)
    X = vec.fit_transform(text_train)
    clf = LogisticRegression(max_iter=3000, C=4).fit(X, y_train)
    p = clf.predict_proba(vec.transform(text_test))[:, 1]
    return roc_auc_score(y_test, p), f1_score(y_test, (p > 0.5).astype(int))


def check_lexical_register_leak(df):
    """Delete all punctuation, digits and every token found in the payload pool,
    then try to predict the label from what is left.

    Reported twice. The first number is the raw carrier signal. The second
    restricts the vocabulary to tokens that occur in BOTH classes in training,
    which removes attack-exclusive residue left by encoding evasions (`%3Cimg`
    -> `cimg`) as well as benign-exclusive prose; it is the conservative figure
    and the one to quote, because it cannot be dismissed as leftover syntax.
    """
    toks = _carrier_tokens(df)
    tr, te = df["split"] == "train", df["split"] == "test"

    auc, f1 = _fit_auc(toks[tr].map(" ".join), df.loc[tr, "label"],
                       toks[te].map(" ".join), df.loc[te, "label"])

    ca, cb = Counter(), Counter()
    for t, lab in zip(toks[tr], df.loc[tr, "label"]):
        (ca if lab == 1 else cb).update(set(t))
    shared = {w for w in ca if ca[w] >= 3 and cb.get(w, 0) >= 3}
    sh = toks.map(lambda ws: " ".join(w for w in ws if w in shared))
    auc_shared, _ = _fit_auc(sh[tr], df.loc[tr, "label"], sh[te], df.loc[te, "label"])

    # the tier the corpus claims as its hard case
    hn = df[(df["label"] == 1) | (df["tier"] == "hard_negative")]
    hs = sh.loc[hn.index]
    h_tr, h_te = hn["split"] == "train", hn["split"] == "test"
    auc_hn, _ = _fit_auc(hs[h_tr.values], hn.loc[h_tr, "label"],
                         hs[h_te.values], hn.loc[h_te, "label"])

    report("lexical_register_leak", auc_shared < REGISTER_AUC_CEILING,
           f"carrier AUC {auc:.3f} (F1 {f1:.3f}); shared-vocab only {auc_shared:.3f}; "
           f"vs hard_negative {auc_hn:.3f} (ceiling {REGISTER_AUC_CEILING})")


def check_struct_split_balance(df):
    """Apply the `split_balance` contract to `split_struct` as well."""
    ratios = df.groupby("split_struct")["label"].mean()
    spread = float(ratios.max() - ratios.min())
    atk = df[df["label"] == 1]
    ct = pd.crosstab(atk["attack_type"], atk["split_struct"])
    for s in ("train", "val", "test"):
        if s not in ct.columns:
            ct[s] = 0
    missing = sorted(ct.index[(ct[["train", "val", "test"]] == 0).any(axis=1)].tolist())
    report("struct_split_balance", spread <= STRUCT_SPREAD_MAX and not missing,
           f"attack-ratio spread {spread:.3f} (max {STRUCT_SPREAD_MAX}); "
           f"{len(missing)} families absent from a split: {missing}")


def check_session_signal(df):
    """A session column advertised for sequence modelling must carry some
    within-session correlation. Compare the observed variance of the per-session
    attack rate against the i.i.d. binomial expectation."""
    g = df.groupby("session")["label"].agg(["count", "sum"])
    n, k = g["count"].to_numpy(), g["sum"].to_numpy()
    p = float(df["label"].mean())
    obs = float(np.mean((k / n - p) ** 2))
    exp = float(np.mean(p * (1 - p) / n))
    ratio = obs / exp
    report("session_signal", ratio >= SESSION_RATIO_FLOOR,
           f"per-session attack-rate variance / i.i.d. expectation = {ratio:.3f} "
           f"(floor {SESSION_RATIO_FLOOR}); {len(g):,} sessions")


def check_transfer_ranking(df):
    """Cross-corpus F1 at a fixed threshold hides threshold collapse: an
    all-positive classifier scores 2b/(1+b) at base rate b, which is ~41 at
    b=0.26. Report AUC, PR-AUC and the predicted-positive rate instead."""
    tr = df["split"] == "train"
    vec = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=3,
                          sublinear_tf=True, max_features=200_000)
    X = vec.fit_transform(df.loc[tr, "payload"])
    clf = LogisticRegression(max_iter=1500, C=8).fit(X, df.loc[tr, "label"])

    lines, worst = [], 1.0
    for name in ("csic_parsed", "ecml_parsed"):
        path = os.path.join(DATA, f"{name}.csv")
        if not os.path.exists(path):
            continue
        d = pd.read_csv(path, engine="python", on_bad_lines="skip").dropna(subset=["payload"])
        q = clf.predict_proba(vec.transform(d["payload"].astype(str)))[:, 1]
        auc = roc_auc_score(d["label"], q)
        ap = average_precision_score(d["label"], q)
        ppr = float((q > 0.5).mean())
        worst = min(worst, auc)
        lines.append(f"{name.split('_')[0]}: AUC {auc:.3f} PR-AUC {ap:.3f} pred-pos {ppr:.2f}")
    report("transfer_ranking", worst >= TRANSFER_AUC_FLOOR,
           f"{'; '.join(lines)} (floor AUC {TRANSFER_AUC_FLOOR})")


def main():
    df = load()
    print(f"loaded {len(df):,} rows\n")
    print("=" * 76)
    print("WebInject2026 - known gaps (not yet enforced by the 25-check gate)")
    print("=" * 76)
    check_lexical_register_leak(df)
    check_struct_split_balance(df)
    check_session_signal(df)
    check_transfer_ranking(df)
    print("=" * 76)
    failed = [n for n, ok, _ in _results if not ok]
    print(f"RESULT: {len(_results) - len(failed)}/{len(_results)} pass"
          + (f" - OPEN: {failed}" if failed else ""))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
