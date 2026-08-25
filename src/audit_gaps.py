"""Construction checks: seven properties `src.validate` does not test.

    python -m src.audit_gaps

Seven properties the 25-check gate does not test. Four came from an external
audit of v3.0.0, where all four FAILED, and were fixed by construction in
v4.0.0; `pair_integrity` was added in v4.1.0 alongside the pairing it checks,
and `skeleton_generalises` in v4.5.0 to keep the skeleton finding honest. This
module is a blocking CI step beside `src.validate`, so the gate is effectively
32 checks (25 + 7) and a regression in any of these fails the build.

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
                         one split, and matches its twin on both length and
                         carrier vocabulary
  skeleton_generalises   the punctuation-skeleton signal must survive attack
                         shapes held out of training, or it is memorisation of
                         the generator's own motifs rather than injection grammar
  results_match_corpus   every shipped result JSON carries the fingerprint of
                         the corpus it was computed against, and it matches
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

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src import checksums as S  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "data")

WORD = re.compile(r"[A-Za-z]{2,}")

# Thresholds are the values v4.0.0 must hold, not the values v3.0.0 had.
REGISTER_AUC_CEILING = 0.75
MATCHED_AUC_CEILING = 0.55
STRUCT_SPREAD_MAX = 0.05
SESSION_RATIO_FLOOR = 1.15
PAIR_LEN_PARITY_FLOOR = 0.75
PAIR_WORD_PARITY_FLOOR = 0.95
SKELETON_GAP_MAX = 0.10

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

    def _sub(mask):
        s = df[mask]
        t = sh.loc[s.index]
        a, b = s["split"] == "train", s["split"] == "test"
        return _fit_auc(t[a.values], s.loc[a, "label"],
                        t[b.values], s.loc[b, "label"])[0]

    # The tier the corpus claims as its hard case, measured two ways.
    #
    # Unmatched -- every attack against every hard negative -- has run at 0.82-0.84
    # since v4.0.0, above the ceiling, and was printed but not gated. An external
    # review fairly called that a check reporting its own failure. It is neither a
    # pass nor a leak: it is confounded by composition. Only 40% of attacks are
    # twinned with a hard negative; the other 60% are twinned with routine rows
    # and carry routine carrier text. So the comparison is largely prose against
    # non-prose, and a model separating those has learned the tier mixture, not
    # the label.
    #
    # Matched -- each hard-negative attack against *its own twin* -- removes that
    # confound by construction, because both rows carry the identical carrier
    # text. That is the number the counterfactual claim rests on, so that is the
    # number now gated, and it is gated far tighter than 0.75.
    hn_unmatched = _sub((df["label"] == 1) | (df["tier"] == "hard_negative"))
    twin_tier = df["pair_id"].map(
        df[(df["label"] == 0) & (df["pair_id"].astype(str) != "")]
        .set_index("pair_id")["tier"])
    hn_matched = _sub((df["pair_id"].astype(str) != "") &
                      (twin_tier == "hard_negative"))

    ok = auc_shared < REGISTER_AUC_CEILING and hn_matched < MATCHED_AUC_CEILING
    report("lexical_register_leak", ok,
           f"carrier AUC {auc:.3f} (F1 {f1:.3f}); shared-vocab only {auc_shared:.3f} "
           f"(ceiling {REGISTER_AUC_CEILING}); hard_negative matched pairs "
           f"{hn_matched:.3f} (ceiling {MATCHED_AUC_CEILING}), unmatched "
           f"{hn_unmatched:.3f} -- confounded by tier mixture, see docstring")


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

    # Length parity alone is not the counterfactual claim. v4.2.0 held 80% length
    # parity while the benign twin carried a median of two more carrier words
    # than its attack -- so a carrier-only model still ranked the attack above
    # its own twin in only 73.0% of pairs, and "the only difference within a pair
    # is the injected span" was falsifiable in ten lines. Vocabulary parity is
    # the check that closes that, and it is gated, not merely printed.
    wd = pr.assign(_w=_carrier_tokens(pr).map(len))
    wpiv = wd.pivot_table(index="pair_id", columns="label", values="_w",
                          aggfunc="first").dropna()
    dw = (wpiv[1] - wpiv[0]) if not wpiv.empty else pd.Series(dtype=float)
    zero = float((dw == 0).mean()) if not dw.empty else 0.0
    fewer = float((dw < 0).mean()) if not dw.empty else 0.0

    ok = (orphans == 0 and spanning == 0 and equal >= PAIR_LEN_PARITY_FLOOR
          and zero >= PAIR_WORD_PARITY_FLOOR)
    report("pair_integrity", ok,
           f"{complete:,} complete pairs, {orphans} orphaned, {spanning} spanning a split; "
           f"length parity (+/-1 char) {equal*100:.1f}% (floor {PAIR_LEN_PARITY_FLOOR*100:.0f}%); "
           f"carrier-word delta zero {zero*100:.1f}% (floor {PAIR_WORD_PARITY_FLOOR*100:.0f}%), "
           f"attack word-poorer in {fewer*100:.1f}%")



def check_skeleton_generalises(df):
    """Does the punctuation-skeleton signal survive unseen attack shapes?

    This corpus is the most skeleton-separable of the three (0.99, against 0.91
    for CSIC-2010 and ECML/PKDD-2007), and read alone that looks like the worse
    shortcut. It is the opposite, but only a control can show it: injection IS a
    punctuation phenomenon, so separability living in punctuation structure is
    the right profile -- provided the structure is injection grammar and not
    this generator's own benign mirror motifs (`%25`, `/**/`, `[1]`, `1|2`).

    Refit the skeleton model on template-disjoint train and score
    template-disjoint test, where every attack shape is one the model never saw.
    Memorised motifs collapse there; learned grammar does not. Gated against the
    full-payload model on the identical split, so the bar is relative rather
    than absolute: the skeleton must stay within SKELETON_GAP_MAX of it.
    """
    skel = df["payload"].astype(str).map(lambda t: re.sub(r"[A-Za-z0-9]+", "#", t))
    y = df["label"].to_numpy().astype(int)
    tr = (df["split_struct"] == "train").to_numpy()
    te = (df["split_struct"] == "test").to_numpy()
    if not (tr.any() and te.any()) or len(set(y[te])) < 2:
        report("skeleton_generalises", False, "no usable structural split")
        return

    def _auc(texts):
        v = TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 5), min_df=3,
                            max_features=200000)
        A = v.fit_transform(texts[tr])
        m = LogisticRegression(max_iter=2000, C=4.0).fit(A, y[tr])
        return float(roc_auc_score(y[te], m.predict_proba(v.transform(texts[te]))[:, 1]))

    sk = _auc(skel.to_numpy())
    full = _auc(df["payload"].astype(str).to_numpy())
    gap = full - sk
    report("skeleton_generalises", gap <= SKELETON_GAP_MAX,
           f"template-disjoint skeleton AUC {sk:.3f} vs full payload {full:.3f} "
           f"on the same split; gap {gap:.3f} (max {SKELETON_GAP_MAX})")



# Every result JSON the paper cites. This list was previously seven names and
# excluded the four files that had no fingerprint to check -- so the check
# passed precisely because it did not look at them.
RESULT_FILES = ("baselines.json", "evaluation.json", "shortcut_stats.json",
                "separability.json", "syntax_ablation.json",
                "model_zoo.json", "model_zoo_capped.json",
                "ablation_models.json", "protocol_matched.json",
                "skeleton_transfer.json", "external_payloads.json",
                "skeleton_external.json")


def check_results_match_corpus(df):
    """Every shipped result must have been computed against the shipped corpus.

    This is the defect that keeps recurring -- v4.0.0, v4.3.0, and v4.4.0 twice.
    Each time the results were regenerated, the corpus was rebuilt afterwards,
    and nothing noticed. SHA256SUMS cannot notice: a result file regenerated from
    an older build is internally consistent and hashes correctly, so the manifest
    passes while the numbers describe a corpus that is no longer shipped. The
    drift is small -- v4.4.0's disjoint recall was 0.87822 against an actual
    0.87853 -- which is precisely why review never catches it.

    So each writer stamps `_corpus` into its JSON and this check compares the
    stamps. A file with no stamp predates the scheme and is reported as unknown
    provenance rather than waved through.
    """
    want = S.corpus_fingerprint(df)
    bad, unstamped = [], []
    for name in RESULT_FILES:
        path = os.path.join(DATA, name)
        if not os.path.exists(path):
            continue
        try:
            got = json.load(open(path)).get("_corpus")
        except Exception:
            bad.append(f"{name}(unreadable)")
            continue
        if got is None:
            unstamped.append(name)
        elif got != want:
            bad.append(f"{name}({got})")
    report("results_match_corpus", not bad and not unstamped,
           f"corpus {want}; mismatched: {bad or 'none'}; unstamped: "
           f"{unstamped or 'none'}")


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
    check_skeleton_generalises(df)
    check_results_match_corpus(df)
    check_transfer_ranking(df)
    print("=" * 76)
    failed = [n for n, ok, _ in _results if not ok]
    print(f"RESULT: {len(_results) - len(failed)}/{len(_results)} pass"
          + (f" - OPEN: {failed}" if failed else ""))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
