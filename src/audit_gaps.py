"""Construction checks: four properties `src.validate` does not test.

    python -m src.audit_gaps

Four properties the 25-check gate does not test, found by an external audit of
v3.0.0, where all four FAILED. v4.0.0 fixes them by construction and this module
is now a blocking CI step alongside `src.validate` -- so the gate is effectively
29 checks, and a regression in any of these fails the build.

  lexical_register_leak  attack and benign carriers are drawn from different
                         vocabularies, so the label is recoverable from ordinary
                         words after every trace of injection syntax is deleted
  struct_split_balance   `split_balance` inspects `split` only; `split_struct`
                         is template-disjoint but neither family-complete nor
                         prevalence-matched
  session_signal         `session` carries no within-session correlation, so the
                         column cannot support the sequence modelling the
                         datasheet advertises
  pair_integrity         every counterfactual pair is complete, sits wholly in
                         one split, and matches its twin on length
  transfer_ranking       cross-corpus transfer reported as F1 at a fixed
                         threshold hides threshold collapse; measure AUC/PR-AUC
                         and show the predicted-positive rate

Origin: these were found by an external audit of v3.0.0 and independently
reproduced. See DATASHEET.md > Limitations and CHANGELOG.md.
"""

import argparse
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

# Thresholds are the values v4.0.0 must hold, not the values v3.0.0 had.
REGISTER_AUC_CEILING = 0.75
STRUCT_SPREAD_MAX = 0.05
SESSION_RATIO_FLOOR = 1.15
PAIR_LEN_PARITY_FLOOR = 0.75

_results = []


def report(name, ok, msg):
    _results.append((name, ok, msg))
    print(f"  {'PASS' if ok else 'FAIL'}  {name:<22s} {msg}")


def load(csv_path=None):
    if csv_path:
        return pd.read_csv(csv_path, keep_default_na=False,
                           dtype=str).astype({"label": int})
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
    """Apply the `split_balance` contract to `split_struct` as well.

    Train and test coverage is required of every family: those are the two sets
    the structural generalisation gap is measured across, and a family missing
    from either makes that gap a family-composition artefact. Validation
    coverage is required only where the family owns at least three templates --
    a family with two cannot occupy three disjoint splits, and that is an
    inventory limit of the payload grammar, not a splitting bug. Families in
    that position are named in the message rather than silently excused.
    """
    ratios = df.groupby("split_struct")["label"].mean()
    spread = float(ratios.max() - ratios.min())
    atk = df[df["label"] == 1]
    ct = pd.crosstab(atk["attack_type"], atk["split_struct"])
    for s in ("train", "val", "test"):
        if s not in ct.columns:
            ct[s] = 0
    n_tmpl = atk.groupby("attack_type")["template"].nunique()

    missing_core = sorted(ct.index[(ct[["train", "test"]] == 0).any(axis=1)].tolist())
    missing_val = sorted(f for f in ct.index
                         if ct.loc[f, "val"] == 0 and n_tmpl.get(f, 0) >= 3)
    thin = sorted(f for f in ct.index if n_tmpl.get(f, 0) < 3)
    ok = spread <= STRUCT_SPREAD_MAX and not missing_core and not missing_val
    report("struct_split_balance", ok,
           f"attack-ratio spread {spread:.3f} (max {STRUCT_SPREAD_MAX}); "
           f"missing from train/test: {missing_core or 'none'}; "
           f"missing from val despite >=3 templates: {missing_val or 'none'}; "
           f"inventory-limited (<3 templates): {thin or 'none'}")


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



def check_pair_integrity(df):
    """The counterfactual guarantee, asserted rather than assumed.

    Pairing only buys anything if the pairs are actually intact: both halves
    present, on the same side of both splits, and matched on length. That last
    one is not cosmetic. Appending a payload makes an attack longer than its own
    twin, and length is the oldest shortcut in this corpus's history -- v1 was
    solvable from character class, and a length gap is the same kind of defect.
    The benign twin therefore receives a benign span of the same length in the
    same slot, so the pair differs only in whether the span is injective.

    The corpus-wide length gap does not go to zero, and should not: only 16,000
    of 45,400 benign rows can be twins, so attack rows carry an extra span that
    most benign rows do not. That is a real property of injection, not an
    artefact. What must hold is parity *within* a pair.
    """
    pr = df[df["pair_id"].astype(str) != ""]
    if pr.empty:
        report("pair_integrity", False, "no pair_id column populated")
        return
    sizes = pr.groupby("pair_id").size()
    complete = int((sizes == 2).sum())
    orphans = int((sizes != 2).sum())
    spanning = int((pr.groupby("pair_id")["split"].nunique() > 1).sum())
    spanning += int((pr.groupby("pair_id")["split_struct"].nunique() > 1).sum())

    ln = pr.assign(_n=pr["payload"].astype(str).str.len())
    piv = ln.pivot_table(index="pair_id", columns="label", values="_n",
                         aggfunc="first").dropna()
    # Parity within one character. Exact equality is the goal, but the guard
    # repair that keeps a seam from forming `--` can shave a character, and a
    # one-character difference is not a signal any model can use.
    equal = float(((piv[1] - piv[0]).abs() <= 1).mean()) if not piv.empty else 0.0
    ok = orphans == 0 and spanning == 0 and equal >= PAIR_LEN_PARITY_FLOOR
    report("pair_integrity", ok,
           f"{complete:,} complete pairs, {orphans} orphaned, {spanning} spanning a split; "
           f"within-pair length parity (+/-1 char) {equal*100:.1f}% (floor {PAIR_LEN_PARITY_FLOOR*100:.0f}%)")


def check_transfer_ranking(df):
    """Cross-corpus transfer must be *reported* threshold-free.

    The defect this guards against is a reporting one, not a property of the
    corpus. F1 ~41 against CSIC-2010 reads as graded degradation but is exactly
    what an all-positive classifier scores at that base rate, and the shipped
    numbers had recall ~100% with precision equal to the base rate.

    So the assertion is that `data/baselines.json` carries `roc_auc` and
    `pred_pos_rate` for every cross-dataset pair, not that transfer clears some
    floor. A floor would be the wrong contract: low transfer AUC against a
    16-year-old corpus is a finding about external validity that the paper
    should report, and forcing it upward would mean making this corpus resemble
    CSIC-2010, which is not the goal. The measured values are printed for
    reference.
    """
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
    bj = os.path.join(DATA, "baselines.json")
    reported = False
    if os.path.exists(bj):
        cd = json.load(open(bj)).get("cross_dataset", {})
        pairs = [m for tgts in cd.values() for m in tgts.values()]
        reported = bool(pairs) and all(
            "roc_auc" in m and "pred_pos_rate" in m for m in pairs)
    report("transfer_ranking", reported,
           f"{'; '.join(lines)}; baselines.json reports roc_auc + pred_pos_rate: "
           f"{'yes' if reported else 'NO -- collapsed F1 would be quoted alone'}")


def main():
    ap = argparse.ArgumentParser(description="Known gaps not enforced by the gate.")
    ap.add_argument("--csv", default=None, help="corpus to audit (default: the shipped one)")
    args = ap.parse_args()
    df = load(args.csv)
    print(f"loaded {len(df):,} rows\n")
    print("=" * 76)
    print("WebInject2026 - construction checks (blocking, alongside src.validate)")
    print("=" * 76)
    check_lexical_register_leak(df)
    check_struct_split_balance(df)
    check_session_signal(df)
    check_pair_integrity(df)
    check_transfer_ranking(df)
    print("=" * 76)
    failed = [n for n, ok, _ in _results if not ok]
    print(f"RESULT: {len(_results) - len(failed)}/{len(_results)} pass"
          + (f" - OPEN: {failed}" if failed else ""))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
