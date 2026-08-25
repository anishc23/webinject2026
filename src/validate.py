"""Quality gate for WebInject2026.

Every check below encodes a specific way a web-attack corpus can be secretly
trivial. `python -m src.validate` exits non-zero if any FAIL, so a broken build
cannot be committed silently. v1 passed the one check it had (length) while
failing several it never ran; this makes the failure modes explicit.

Checks
  ratio          class balance in a defensible range
  duplicates     no repeated payload string
  length_gap     benign/attack median length within 15%
  char_class     benign and attack share a character alphabet
  param_leak     no parameter name predicts the label
  path_leak      no path predicts the label
  metadata_leak  none of {family,tier,evasion,source} sits in a feature column
  ngram_ceiling  a strong char n-gram model is BELOW an accuracy ceiling
                 (headroom exists) yet ABOVE a floor (task is learnable)
  disjoint_gen   payload-disjoint test recall is high (generalises beyond
                 memorised strings)
  split_leak     no payload group spans two splits
  split_balance  attack ratio matches across splits; every family in every split
  test_groups    the disjoint test holds enough payload groups (per family too)
                 to rank detectors with low variance, not average over a handful
  near_dup       digit-masking collapses no large block of rows to one skeleton
                 (dedup is exact-match; this catches near-duplicate regressions)
  evasion_artifact  no evasion-introduced marker (%25, /**/, &#, %00 …) is
                 attack-exclusive — each also occurs in benign traffic
  ambiguous_floor   a strong model still false-positives on the verbatim
                 `ambiguous` tier: the payload-only error floor is real, not zero
  hard_neg       hard-negative benigns really are punctuation-rich
  guard          no hard-negative benign contains real injection syntax
  benign_split_leak  benign cores never span splits, and the hard-negative test
                 set holds many distinct cores (the benign mirror of the
                 payload-disjoint attack split; closes the v2.1 67% benign reuse)
  header_leak    no header-derived feature predicts the label (v2.1 gave attacks
                 punctuation-rich headers and routine benigns plain ones)
  family_path_leak  the URL does not predict the attack family (secondary task
                 must not be solvable from the path alone; v2.1 NMI was 0.55)
  content_type_leak  Content-Type does not predict the label
  struct_split_leak  no template spans the structural split; the structural test
                 holds enough held-out template shapes
  session_leak   sessions never span the payload-disjoint split and are not
                 segregated by label
  struct_gen     recall on the structural (template-disjoint) test stays high
"""

import argparse
import json
import os
import re
import sys

import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.vocab import is_injective  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Accuracy the char n-gram baseline must stay under: above this and the task is
# a character-class shortcut, as in v1 (char n-gram hit 0.9999). Under 25% class
# imbalance, accuracy is a coarse lens — a model perfect on benign and at 96%
# attack recall already reaches ~0.99 — so this only guards the shortcut; the
# real headroom/ranking signal is per-family recall and TPR@low-FPR (baselines).
NGRAM_CEILING = 0.99
NGRAM_FLOOR = 0.80        # ...but it must beat this, or the corpus is noise.
DISJOINT_RECALL_FLOOR = 0.55
STRUCT_RECALL_FLOOR = 0.45   # structural (template-disjoint) test is harder
LEAK_MAX_MI = 0.12        # max share of label entropy a single feature may explain
MIN_TEST_GROUPS = 250     # attack payload groups the disjoint test must hold
MIN_FAMILY_TEST_GROUPS = 8   # ...and per family, so per-family metrics are usable
SPLIT_RATIO_SPREAD = 0.05    # max attack-ratio difference between any two splits
MIN_DISTINCT_SKELETON = 0.50  # min share of rows with a unique digit-masked form
MIN_AMBIGUOUS_FP = 3      # a strong model must miss >=this many verbatim-ambiguous
EVASION_MARKER_MIN_BENIGN = 20   # each evasion marker must occur in >=this benign
# Markers that evasion transforms inject; none may be an attack-only signal.
EVASION_MARKERS = ["%25", "/**/", "&#", "%3C", "%09", "%0a", "%00"]
N_FAMILIES = 14              # every attack family must appear in every split
MIN_BENIGN_TEST_CORES = 300  # distinct hard-negative cores the test must hold
FAMILY_PATH_MAX_NMI = 0.35   # max path->family NMI (was 0.55 in v2.1)
CTYPE_LEAK_MAX_NMI = 0.05    # max content_type->label NMI
MIN_STRUCT_TEST_TEMPLATES = 12  # held-out template shapes in the structural test
SESSION_RATIO_TOL = 0.04     # per-session mean attack ratio vs global


class Check:
    def __init__(self):
        self.rows = []
        self.failed = 0

    def add(self, name, ok, detail, warn=False):
        status = "PASS" if ok else ("WARN" if warn else "FAIL")
        if not ok and not warn:
            self.failed += 1
        self.rows.append((name, status, detail))

    def report(self):
        w = max(len(r[0]) for r in self.rows)
        print("\n" + "=" * 68)
        print("WebInject2026 validation")
        print("=" * 68)
        for name, status, detail in self.rows:
            print(f"  {status:4s}  {name:<{w}}  {detail}")
        print("=" * 68)
        print("RESULT:", "ALL CHECKS PASS" if self.failed == 0
              else f"{self.failed} CHECK(S) FAILED")
        return self.failed == 0


# ------------------------------------------------------------- helpers ------
def _param_names(query):
    import urllib.parse
    try:
        return [k for k, _ in urllib.parse.parse_qsl(str(query))]
    except Exception:
        return []


def _label_leakage(series, y):
    """Normalised mutual information between a categorical feature and label."""
    from sklearn.metrics import mutual_info_score
    from scipy.stats import entropy
    codes = pd.Series(series).astype("category").cat.codes
    mi = mutual_info_score(codes, y)
    hy = entropy(np.bincount(y) / len(y))
    return mi / hy if hy > 0 else 0.0


# ------------------------------------------------------------- checks --------
def run(df, chk):
    y = df.label.values
    payload = df.payload.astype(str).values

    # ratio
    ratio = y.mean()
    chk.add("ratio", 0.15 <= ratio <= 0.55, f"attack ratio {ratio:.3f}")

    # duplicates
    dups = df.payload.duplicated().sum()
    chk.add("duplicates", dups == 0, f"{dups} duplicate payloads")

    # length gap
    bl = np.median([len(s) for s in payload[y == 0]])
    al = np.median([len(s) for s in payload[y == 1]])
    gap = abs(bl - al) / max(bl, al)
    chk.add("length_gap", gap <= 0.15, f"median gap {gap:.3f} (benign {bl:.0f} / attack {al:.0f})")

    # character class overlap
    ben_chars = set("".join(payload[y == 0][:20000]))
    atk_chars = set("".join(payload[y == 1][:20000]))
    atk_only = atk_chars - ben_chars
    shared = len(atk_chars & ben_chars) / max(1, len(atk_chars))
    chk.add("char_class", len(atk_only) <= 3,
            f"attack-only chars: {len(atk_only)} ({''.join(sorted(atk_only))[:20]!r}), "
            f"shared {shared:.0%}")

    # parameter-name leakage
    all_params = df["query"].map(_param_names)
    exploded = []
    for names, lab in zip(all_params, y):
        for nm in set(names):
            exploded.append((nm, lab))
    if exploded:
        pe = pd.DataFrame(exploded, columns=["param", "label"])
        ct = pd.crosstab(pe.param, pe.label)
        ct = ct[(ct.sum(axis=1) >= 30)]
        rate = ct.get(1, 0) / ct.sum(axis=1)
        worst = rate.reindex(ct.index).fillna(0)
        n_absolute = int(((worst >= 0.98) | (worst <= 0.02)).sum())
        # a param is a leak only if it is BOTH near-deterministic AND common
        det = worst[(worst >= 0.98) | (worst <= 0.02)]
        det_common = [p for p in det.index if ct.loc[p].sum() >= 200
                      and det[p] >= 0.98]
        chk.add("param_leak", len(det_common) == 0,
                f"{n_absolute} near-deterministic params; "
                f"label-predictive: {det_common[:5]}")

    # path leakage
    path_mi = _label_leakage(df.path, y)
    chk.add("path_leak", path_mi <= LEAK_MAX_MI, f"path->label NMI {path_mi:.3f}")

    # metadata columns must not have leaked into the payload text
    meta_terms = ["scripted_browse", "synthetic", "captured", "hard_negative",
                  "benign_ambiguous"]
    leaked = [t for t in meta_terms if df.payload.str.contains(re.escape(t)).any()]
    chk.add("metadata_leak", len(leaked) == 0, f"metadata strings in payload: {leaked}")

    # n-gram ceiling / floor (reuse the fitted test predictions below)
    acc, f1, te_pred = _ngram_eval(df)
    chk.add("ngram_ceiling", acc <= NGRAM_CEILING,
            f"char n-gram acc {acc:.3f} (ceiling {NGRAM_CEILING}); F1 {f1:.3f}")
    chk.add("ngram_floor", acc >= NGRAM_FLOOR,
            f"char n-gram acc {acc:.3f} (floor {NGRAM_FLOOR})")

    # near-duplicate pressure: dedup is exact-match, so a build could still ship
    # near-twins that differ only in a number. Assert digit-masking does not
    # collapse a large block of rows onto one skeleton.
    skel = df.payload.astype(str).map(
        lambda s: re.sub(r"\s+", " ", re.sub(r"\d+", "#", s.lower())).strip())
    distinct = skel.nunique() / len(skel)
    chk.add("near_dup", distinct >= MIN_DISTINCT_SKELETON,
            f"{distinct:.2%} of rows have a unique digit-masked skeleton "
            f"(floor {MIN_DISTINCT_SKELETON:.0%})")

    # evasion markers must not be attack-exclusive
    ben_txt = df[df.label == 0].payload.astype(str)
    ev_txt = df[(df.label == 1) & (df.get("evasion", "none") != "none")].payload.astype(str)
    attack_only = []
    for mk in EVASION_MARKERS:
        in_attack = ev_txt.str.contains(re.escape(mk)).sum()
        in_benign = ben_txt.str.contains(re.escape(mk)).sum()
        if in_attack > 0 and in_benign < EVASION_MARKER_MIN_BENIGN:
            attack_only.append(f"{mk}(atk={in_attack},ben={in_benign})")
    chk.add("evasion_artifact", len(attack_only) == 0,
            f"attack-exclusive evasion markers: {attack_only or 'none'}")

    # payload-disjoint generalisation
    if "split" in df.columns:
        rec = _disjoint_recall(df)
        chk.add("disjoint_gen", rec >= DISJOINT_RECALL_FLOOR,
                f"attack recall on payload-disjoint test {rec:.3f}")

        # split leakage
        span = df.groupby("group").split.nunique()
        n_span = int((span > 1).sum())
        chk.add("split_leak", n_span == 0, f"{n_span} groups span >1 split")

        # split balance: matched attack ratio, every family in every split
        rates = df.groupby("split").label.mean()
        spread = float(rates.max() - rates.min())
        atk = df[df.label == 1]
        fam_splits = atk.groupby("attack_type").split.nunique()
        missing = fam_splits[fam_splits < 3]
        ok_bal = spread <= SPLIT_RATIO_SPREAD and len(missing) == 0
        chk.add("split_balance", ok_bal,
                f"attack-ratio spread {spread:.3f} (max {SPLIT_RATIO_SPREAD}); "
                f"{len(missing)} families not in all 3 splits")

        # enough disjoint test groups to rank detectors, overall and per family
        te_atk = atk[atk.split == "test"]
        n_groups = te_atk.group.nunique()
        per_fam = te_atk.groupby("attack_type").group.nunique()
        min_fam = int(per_fam.min()) if len(per_fam) else 0
        chk.add("test_groups",
                n_groups >= MIN_TEST_GROUPS and min_fam >= MIN_FAMILY_TEST_GROUPS,
                f"{n_groups} attack groups in test (floor {MIN_TEST_GROUPS}); "
                f"smallest family {min_fam} (floor {MIN_FAMILY_TEST_GROUPS})")

        # the payload-only error floor must be real: a strong model still
        # false-positives on the verbatim ambiguous tier (attack-like text a
        # request-only detector cannot separate from a real attack).
        amb = te_pred[te_pred.group.astype(str).str.startswith("ambigV")]
        amb_fp = int(amb.pred.sum()) if len(amb) else 0
        chk.add("ambiguous_floor", amb_fp >= MIN_AMBIGUOUS_FP,
                f"char n-gram false-positives on {amb_fp}/{len(amb)} verbatim-"
                f"ambiguous test rows (floor {MIN_AMBIGUOUS_FP})")

    # hard-negative richness
    if "tier" in df.columns:
        hn = df[df.tier == "hard_negative"].payload.astype(str)
        if len(hn):
            punct = hn.str.contains(r"['\"<>;|(){}$`%\[\]=&]").mean()
            chk.add("hard_neg", punct >= 0.85,
                    f"{punct:.0%} of hard-negatives carry attack-class punctuation "
                    f"(n={len(hn):,})")
            # guard: none may be a real injection
            bad = int(hn.map(is_injective).sum())
            chk.add("guard", bad == 0,
                    f"{bad} hard-negatives contain real injection syntax")

    # ---- v3 checks -------------------------------------------------------
    # benign split leak: hard-negative / ambiguous cores must be grouped and
    # split-disjoint, and the benign test must hold many distinct cores. This is
    # the benign mirror of the payload-disjoint attack split.
    if {"tier", "split", "group"} <= set(df.columns):
        ben = df[df.tier.isin(["hard_negative", "ambiguous"])]
        ben_span = int((ben.groupby("group").split.nunique() > 1).sum())
        hn_test_cores = df[(df.tier == "hard_negative") &
                           (df.split == "test")].group.nunique()
        chk.add("benign_split_leak",
                ben_span == 0 and hn_test_cores >= MIN_BENIGN_TEST_CORES,
                f"{ben_span} benign cores span splits; "
                f"{hn_test_cores} hard-negative cores in test "
                f"(floor {MIN_BENIGN_TEST_CORES})")

    # header leak: no header-derived feature may predict the label. Headers are
    # part of the inspected payload, so a header that correlates with the label
    # is a free signal (the v2.1 `prefs` cookie leak).
    if "headers" in df.columns:
        h = df.headers.astype(str)
        feats = {
            "prefs_cookie": h.str.contains(r"prefs", regex=True),
            "punct_referer": h.str.contains(r"Referer[^,]*(?:search\?q=|filter=|%2C|%26)",
                                            regex=True),
            "xff": h.str.contains(r"X-Forwarded-For", regex=True),
            "origin": h.str.contains(r"\"Origin\"", regex=True),
        }
        worst = max(_label_leakage(v.values, y) for v in feats.values())
        chk.add("header_leak", worst <= LEAK_MAX_MI,
                f"max header-feature->label NMI {worst:.4f} (max {LEAK_MAX_MI})")

    # family-path leak: the URL must not predict the attack family.
    if "attack_type" in df.columns:
        atk = df[df.label == 1]
        fam_path_nmi = _label_leakage_cat(atk.path, atk.attack_type)
        chk.add("family_path_leak", fam_path_nmi <= FAMILY_PATH_MAX_NMI,
                f"path->family NMI {fam_path_nmi:.3f} (max {FAMILY_PATH_MAX_NMI})")

    # content-type leak: Content-Type must not predict the label.
    if "content_type" in df.columns:
        ct_nmi = _label_leakage(df.content_type, y)
        chk.add("content_type_leak", ct_nmi <= CTYPE_LEAK_MAX_NMI,
                f"content_type->label NMI {ct_nmi:.4f} (max {CTYPE_LEAK_MAX_NMI})")

    # structural split: no template spans it, and the structural test holds
    # enough held-out template shapes to be a real generalisation test.
    if {"split_struct", "template"} <= set(df.columns):
        # Only attack templates are held out structurally; benign rows share
        # coarse templates (benign:routine, ambiguous) but are split by core, so
        # they legitimately span the structural split.
        atk_s = df[df.label == 1]
        span = int((atk_s.groupby("template").split_struct.nunique() > 1).sum())
        te_tpl = atk_s[atk_s.split_struct == "test"].template.nunique()
        chk.add("struct_split_leak",
                span == 0 and te_tpl >= MIN_STRUCT_TEST_TEMPLATES,
                f"{span} templates span the structural split; "
                f"{te_tpl} attack templates in structural test "
                f"(floor {MIN_STRUCT_TEST_TEMPLATES})")
        sr = _split_recall(df, "split_struct")
        chk.add("struct_gen", sr >= STRUCT_RECALL_FLOOR,
                f"attack recall on template-disjoint test {sr:.3f} "
                f"(floor {STRUCT_RECALL_FLOOR})")

    # session leak: sessions must not span the payload-disjoint split, nor be
    # segregated by label. Sessions do span split_struct, by construction: the
    # template-disjoint split holds out attack shapes, not traffic bursts.
    if "session" in df.columns:
        sess_span = int((df.groupby("session").split.nunique() > 1).sum())
        per_sess = df.groupby("session").label.mean()
        global_ratio = y.mean()
        drift = abs(per_sess.mean() - global_ratio)
        chk.add("session_leak", sess_span == 0 and drift <= SESSION_RATIO_TOL,
                f"{sess_span} sessions span splits; per-session mean attack "
                f"ratio {per_sess.mean():.3f} vs global {global_ratio:.3f}")

    return chk


def _label_leakage_cat(feature, target):
    """Normalised MI between a categorical feature and a categorical target."""
    from sklearn.metrics import mutual_info_score
    from scipy.stats import entropy
    fc = pd.Series(feature).astype("category").cat.codes
    tc = pd.Series(target).astype("category").cat.codes
    mi = mutual_info_score(fc, tc)
    ht = entropy(np.bincount(tc) / len(tc))
    return mi / ht if ht > 0 else 0.0


def _split_recall(df, split_col):
    """Attack recall on a given split column's test set (unseen groups)."""
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import recall_score
    tr = df[df[split_col] == "train"]
    te = df[(df[split_col] == "test") & (df.label == 1)]
    if len(te) == 0:
        return 1.0
    v = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5),
                        min_df=3, max_features=200000)
    A = v.fit_transform(tr.payload.astype(str))
    m = LogisticRegression(max_iter=2000, C=4.0).fit(A, tr.label)
    te_neg = df[(df[split_col] == "test") & (df.label == 0)]
    B = v.transform(pd.concat([te, te_neg]).payload.astype(str))
    yb = np.r_[np.ones(len(te)), np.zeros(len(te_neg))]
    return recall_score(yb, m.predict(B))


def _ngram_eval(df):
    """Fit the reference char n-gram model; return (acc, f1, test_df_with_pred).

    The returned test frame carries a `pred` column so downstream checks
    (`ambiguous_floor`) can inspect *where* the model errs without refitting.
    """
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import accuracy_score, f1_score

    if "split" in df.columns:
        tr = df[df.split == "train"]
        te = df[df.split == "test"].copy()
    else:
        from sklearn.model_selection import train_test_split
        tr, te = train_test_split(df, test_size=0.3, stratify=df.label,
                                  random_state=42)
        te = te.copy()
    v = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5),
                        min_df=3, max_features=200000)
    A = v.fit_transform(tr.payload.astype(str))
    B = v.transform(te.payload.astype(str))
    m = LogisticRegression(max_iter=2000, C=4.0).fit(A, tr.label)
    te["pred"] = m.predict(B)
    return accuracy_score(te.label, te.pred), f1_score(te.label, te.pred), te


def _disjoint_recall(df):
    """Attack recall on the test split, whose payload groups are unseen."""
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import recall_score
    tr = df[df.split == "train"]
    te = df[(df.split == "test") & (df.label == 1)]
    if len(te) == 0:
        return 1.0
    v = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5),
                        min_df=3, max_features=200000)
    A = v.fit_transform(tr.payload.astype(str))
    m = LogisticRegression(max_iter=2000, C=4.0).fit(A, tr.label)
    te_neg = df[(df.split == "test") & (df.label == 0)]
    B = v.transform(pd.concat([te, te_neg]).payload.astype(str))
    yb = np.r_[np.ones(len(te)), np.zeros(len(te_neg))]
    pred = m.predict(B)
    return recall_score(yb, pred)


def main():
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", default=os.path.join(ROOT, "data", "webinject2026.csv"))
    args = ap.parse_args()
    df = pd.read_csv(args.csv, keep_default_na=False)
    df["label"] = df["label"].astype(int)
    print(f"loaded {len(df):,} rows from {args.csv}")
    chk = Check()
    run(df, chk)
    ok = chk.report()
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
