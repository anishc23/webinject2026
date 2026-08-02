"""Reference baselines for WebInject2026.

Reports the numbers a paper should quote, and reports them the way an injection
detector is actually judged — not accuracy at threshold 0.5, but detection at a
low false-positive budget, per attack family, and across corpora.

    python -m src.baselines                 # full report to stdout
    python -m src.baselines --json out.json  # machine-readable metrics
    python -m src.baselines --fast           # skip bootstrap + cross-dataset

Sections
  1. Baseline table   several feature/model pairs, each on the random split and
                      the payload-disjoint split. Columns: F1, PR-AUC, and
                      TPR@FPR=1% / 0.1% (the operating points a WAF cares about).
                      Includes a rule/signature baseline — the reference point a
                      reviewer looks for first — alongside the ML models.
  2. Slice breakdown  the char n-gram's recall per family and per evasion on the
                      disjoint test. This is where the headroom is: some families
                      and evasions are far from solved.
  3. Group bootstrap  95% CI for the headline metrics, resampling *payload
                      groups* (not rows). With ~100 correlated rows per group a
                      row-level CI is ~10x too narrow; this one is honest.
  4. Cross-dataset    train here, test on CSIC-2010 / ECML-PKDD-2007 (and the
                      reverse). The external-validity gap: synthetic detection
                      numbers do not transfer unchanged to real corpora.
"""

import argparse
import json
import os
import re
import sys
import warnings

import numpy as np
import pandas as pd

warnings.filterwarnings("ignore")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, average_precision_score, f1_score,
                             precision_score, recall_score, roc_curve)
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier

from src import checksums as S  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "data")
SPECIAL = set("<>'\";()|&%$`{}[]=*/\\!:")
RNG = np.random.default_rng(42)


# ---------------------------------------------------------------- metrics ----
def _tpr_at_fpr(y, score, budget):
    """Highest TPR achievable without exceeding a false-positive rate budget."""
    fpr, tpr, _ = roc_curve(y, score)
    ok = fpr <= budget
    return float(tpr[ok].max()) if ok.any() else 0.0


def _metrics(y, pred, score):
    y = np.asarray(y)
    return {
        "accuracy": float(accuracy_score(y, pred)),
        "precision": float(precision_score(y, pred, zero_division=0)),
        "recall": float(recall_score(y, pred, zero_division=0)),
        "f1": float(f1_score(y, pred, zero_division=0)),
        "pr_auc": float(average_precision_score(y, score)) if len(set(y)) > 1 else 0.0,
        "tpr_at_1pct_fpr": _tpr_at_fpr(y, score, 0.01),
        "tpr_at_0.1pct_fpr": _tpr_at_fpr(y, score, 0.001),
    }


# ------------------------------------------------------- rule / signature ----
# A compact CRS-style rule set: one regex per common injection shape across the
# ten families. Not exhaustive — a reference floor for "what a hand-written
# signature catches", the baseline every ML model should beat on recall while
# not collapsing on the punctuation-rich benign side.
SIGNATURE_RULES = [
    r"(?i)\bunion\b[\s/*]+\bselect\b",
    r"(?i)\bor\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+",
    r"(?i)'\s*or\s*'[^']*'\s*=\s*'",
    r"(?i)\b(sleep|pg_sleep|benchmark|waitfor\s+delay)\s*\(",
    r"(?i);\s*(drop|insert|update|delete|truncate|exec)\b",
    r"(?i)<\s*script\b|onerror\s*=|onload\s*=|<svg\b|javascript:",
    r"(?i)\.\./|\.\.\\|%2e%2e(%2f|%5c)|%c0%af",
    r"(?i)(;|\||\|\||&&|`|\$\()\s*(cat|whoami|id|uname|nc|curl|wget|ping|ls|dir|sleep)\b",
    r"\{\{.*?\}\}|\$\{.*?\}|<%.*?%>",
    r"(?i)\$(ne|gt|lt|gte|where|regex|exists|nin)\b",
    r"(?i)(169\.254\.169\.254|metadata\.(google|azure)|gopher://|dict://|file:///)",
    r"(?i)%0d%0a|%0a|\\r\\n|%e5%98%8a",
    r"\*\)\(|\)\(\||\)\(uid=|\)\(cn=",
    r"(?i)<!entity|<!doctype[^>]*entity",
]
_SIG = [re.compile(r) for r in SIGNATURE_RULES]


def _signature_score(texts):
    """Number of distinct rules that fire on each string (0 = predicted benign)."""
    return np.array([sum(bool(rx.search(t)) for rx in _SIG) for t in texts])


# ---------------------------------------------------------------- models -----
def _char_vec():
    return TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=3,
                           max_features=200000)


def _fit_char(tr):
    v = _char_vec()
    A = v.fit_transform(tr.payload.astype(str))
    m = LogisticRegression(max_iter=2000, C=4.0).fit(A, tr.label)
    return v, m


def _char_ngram(df, tr, te):
    v, m = _fit_char(df.loc[tr])
    score = m.predict_proba(v.transform(df.loc[te].payload.astype(str)))[:, 1]
    return _metrics(df.loc[te].label, (score >= 0.5).astype(int), score)


def _word_ngram(df, tr, te):
    v = TfidfVectorizer(analyzer="word", ngram_range=(1, 2), min_df=3,
                        max_features=100000, token_pattern=r"(?u)\S+")
    A = v.fit_transform(df.loc[tr].payload.astype(str))
    m = LogisticRegression(max_iter=2000).fit(A, df.loc[tr].label)
    score = m.predict_proba(v.transform(df.loc[te].payload.astype(str)))[:, 1]
    return _metrics(df.loc[te].label, (score >= 0.5).astype(int), score)


def _length_only(df, tr, te):
    L = df.payload.astype(str).str.len().values.reshape(-1, 1)
    m = DecisionTreeClassifier(max_depth=3, random_state=42).fit(
        L[df.index.get_indexer(tr)], df.loc[tr].label)
    Lte = L[df.index.get_indexer(te)]
    score = m.predict_proba(Lte)[:, 1]
    return _metrics(df.loc[te].label, m.predict(Lte), score)


def _special_count(df, tr, te):
    f = df.payload.astype(str).map(
        lambda s: sum(c in SPECIAL for c in s)).values.reshape(-1, 1)
    m = DecisionTreeClassifier(max_depth=5, random_state=42).fit(
        f[df.index.get_indexer(tr)], df.loc[tr].label)
    fte = f[df.index.get_indexer(te)]
    score = m.predict_proba(fte)[:, 1]
    return _metrics(df.loc[te].label, m.predict(fte), score)


def _rule_signature(df, tr, te):
    """Signature detector: fit-free; score = number of rules that fire."""
    score = _signature_score(df.loc[te].payload.astype(str).tolist())
    return _metrics(df.loc[te].label, (score >= 1).astype(int), score)


BASELINES = {
    "length only (1 feature)": _length_only,
    "special-char count (1 feature)": _special_count,
    "rule signature (14 regex)": _rule_signature,
    "word n-gram (1-2) + LogReg": _word_ngram,
    "char n-gram (3-5) + LogReg": _char_ngram,
}


# ---------------------------------------------------------------- splits -----
def _splits(df):
    dis = (df[df.split == "train"].index, df[df.split == "test"].index)
    tr, te = train_test_split(df.index, test_size=0.2, stratify=df.label,
                              random_state=42)
    out = {"random": (tr, te), "payload-disjoint": dis}
    if "split_struct" in df.columns:
        out["structural"] = (df[df.split_struct == "train"].index,
                             df[df.split_struct == "test"].index)
    return out


TARGET_PREVALENCES = [0.005, 0.01, 0.05, 0.254]


def _ppv_at_prevalence(tpr, fpr, prev):
    num = prev * tpr
    den = num + (1 - prev) * fpr
    return float(num / den) if den > 0 else 0.0


# ---------------------------------------------------- slice + bootstrap ------
def _char_scores_disjoint(df):
    tr = df[df.split == "train"]
    te = df[df.split == "test"].copy()
    v, m = _fit_char(tr)
    te["score"] = m.predict_proba(v.transform(te.payload.astype(str)))[:, 1]
    te["pred"] = (te.score >= 0.5).astype(int)
    return te


def _slice_recall(te):
    a = te[te.label == 1]
    fam = a.groupby("attack_type").pred.agg(["mean", "count"]).sort_values("mean")
    eva = a.groupby("evasion").pred.agg(["mean", "count"]).sort_values("mean")
    return fam, eva


def _group_bootstrap(te, n=300):
    """95% CI for F1 / recall / TPR@0.1%FPR, resampling payload GROUPS."""
    groups = te.group.values
    uniq = np.unique(groups)
    idx_by_group = {g: np.where(groups == g)[0] for g in uniq}
    y = te.label.values
    score = te.score.values
    f1s, recs, tprs = [], [], []
    for _ in range(n):
        pick = RNG.choice(uniq, size=len(uniq), replace=True)
        rows = np.concatenate([idx_by_group[g] for g in pick])
        yy, ss = y[rows], score[rows]
        pp = (ss >= 0.5).astype(int)
        if yy.sum() == 0 or yy.sum() == len(yy):
            continue
        f1s.append(f1_score(yy, pp, zero_division=0))
        recs.append(recall_score(yy, pp, zero_division=0))
        tprs.append(_tpr_at_fpr(yy, ss, 0.001))
    pct = lambda a: (float(np.percentile(a, 2.5)), float(np.percentile(a, 97.5)))
    return {"f1": pct(f1s), "recall": pct(recs), "tpr_at_0.1pct_fpr": pct(tprs)}


# ------------------------------------------------------- cross-dataset -------
def _load_external(name):
    path = os.path.join(DATA, f"{name}_parsed.csv")
    if not os.path.exists(path):
        return None
    d = pd.read_csv(path, keep_default_na=False)
    if "payload" not in d.columns or "label" not in d.columns:
        return None
    return d[["payload", "label"]].dropna()


def _cross_dataset(df):
    """Train char n-gram on each corpus, test on the others."""
    corpora = {"webinject": df[["payload", "label"]].copy()}
    for name in ("csic", "ecml"):
        ext = _load_external(name)
        if ext is not None:
            corpora[name] = ext
    out = {}
    fitted = {}
    for tn, tr in corpora.items():
        v = _char_vec()
        A = v.fit_transform(tr.payload.astype(str))
        m = LogisticRegression(max_iter=2000, C=4.0).fit(A, tr.label)
        fitted[tn] = (v, m)
    for tn, (v, m) in fitted.items():
        out[tn] = {}
        for en, te in corpora.items():
            if en == tn:
                continue
            score = m.predict_proba(v.transform(te.payload.astype(str)))[:, 1]
            out[tn][en] = _metrics(te.label, (score >= 0.5).astype(int), score)
    return out


# ---------------------------------------------------------------- report -----
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", default=os.path.join(DATA, "webinject2026.csv"))
    ap.add_argument("--json", default=None)
    ap.add_argument("--fast", action="store_true",
                    help="skip the bootstrap and cross-dataset sections")
    args = ap.parse_args()
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    df = pd.read_csv(args.csv, keep_default_na=False).reset_index(drop=True)
    splits = _splits(df)
    results = {"baselines": {}}

    # 1. baseline table
    print("=" * 92)
    print("1. BASELINES  (F1 / PR-AUC / TPR@FPR=1% / TPR@FPR=0.1%)")
    print("=" * 92)
    hdr = f"{'baseline':<32}" + "".join(f"{s:>28}" for s in splits)
    print(hdr)
    print("-" * len(hdr))
    for name, fn in BASELINES.items():
        row = f"{name:<32}"
        results["baselines"][name] = {}
        for sname, (tr, te) in splits.items():
            m = fn(df, tr, te)
            results["baselines"][name][sname] = m
            row += (f"  {m['f1']*100:5.1f} {m['pr_auc']*100:5.1f} "
                    f"{m['tpr_at_1pct_fpr']*100:5.1f} {m['tpr_at_0.1pct_fpr']*100:5.1f}")
        print(row)
    print("\ncols per split: F1  PR-AUC  TPR@1%FPR  TPR@0.1%FPR   (all %)")

    # 2. slice breakdown (char n-gram, disjoint)
    te = _char_scores_disjoint(df)
    fam, eva = _slice_recall(te)
    print("\n" + "=" * 92)
    print("2. CHAR N-GRAM RECALL BY SLICE  (payload-disjoint test) — where the headroom is")
    print("=" * 92)
    print("  by family:   " +
          "  ".join(f"{k}={v['mean']*100:.0f}%(n={int(v['count'])})"
                    for k, v in fam.iterrows()))
    print("  by evasion:  " +
          "  ".join(f"{k}={v['mean']*100:.0f}%(n={int(v['count'])})"
                    for k, v in eva.iterrows()))
    results["char_ngram_recall_by_family"] = {
        k: {"recall": float(v["mean"]), "n": int(v["count"])} for k, v in fam.iterrows()}
    results["char_ngram_recall_by_evasion"] = {
        k: {"recall": float(v["mean"]), "n": int(v["count"])} for k, v in eva.iterrows()}

    # 2b. prevalence-corrected precision. The corpus is ~26% attack; production
    # is far lower, and precision is prevalence-dependent. Convert the disjoint
    # char n-gram's operating points to the precision they would have at
    # realistic attack prevalences — the number that decides deployability.
    fpr_c, tpr_c, _ = roc_curve(te.label, te.score)
    prev_tbl = {}
    for budget in (0.01, 0.001):
        ok = fpr_c <= budget
        t = float(tpr_c[ok].max()) if ok.any() else 0.0
        prev_tbl[f"{budget}"] = {f"{p}": _ppv_at_prevalence(t, budget, p)
                                 for p in TARGET_PREVALENCES}
    results["char_ngram_ppv_by_prevalence"] = prev_tbl
    print("\n" + "=" * 92)
    print("2b. PREVALENCE-CORRECTED PRECISION  (char n-gram, disjoint)")
    print("=" * 92)
    print(f"  {'FPR budget':<14}" +
          "".join(f"{'prev='+format(p, 'g'):>14}" for p in TARGET_PREVALENCES))
    for budget, row in prev_tbl.items():
        print(f"  {'<='+budget:<14}" +
              "".join(f"{row[str(p)]*100:13.1f}%" for p in TARGET_PREVALENCES))
    print("  precision collapses as prevalence drops even at a fixed FPR budget;")
    print("  report the operating prevalence your deployment actually sees.")

    if not args.fast:
        # 3. group bootstrap
        ci = _group_bootstrap(te)
        results["char_ngram_group_bootstrap_ci95"] = ci
        print("\n" + "=" * 92)
        print("3. GROUP-BOOTSTRAP 95% CI  (char n-gram, disjoint; resampling payload groups)")
        print("=" * 92)
        for k, (lo, hi) in ci.items():
            print(f"  {k:<20} [{lo*100:5.1f}, {hi*100:5.1f}] %")

        # 4. cross-dataset
        cross = _cross_dataset(df)
        results["cross_dataset"] = cross
        print("\n" + "=" * 92)
        print("4. CROSS-DATASET TRANSFER  (char n-gram; F1 / recall, train-row -> test-col)")
        print("=" * 92)
        names = ["webinject", "csic", "ecml"]
        present = [n for n in names if n in cross or any(n in v for v in cross.values())]
        print(f"  {'train \\\\ test':<14}" + "".join(f"{n:>16}" for n in present))
        for tn in present:
            if tn not in cross:
                continue
            row = f"  {tn:<14}"
            for en in present:
                if en == tn:
                    row += f"{'—':>16}"
                elif en in cross[tn]:
                    m = cross[tn][en]
                    row += f"{m['f1']*100:7.1f}/{m['recall']*100:.0f}".rjust(16)
                else:
                    row += f"{'n/a':>16}"
            print(row)
        print("\n  in-corpus F1 is high; cross-corpus F1 is far lower — the synthetic")
        print("  distribution does not transfer unchanged. Report both.")

    if args.json:
        json.dump(results, open(args.json, "w"), indent=2)
        print(f"\nwrote {args.json}")
        if S.refresh(args.json):
            print(f"refreshed {S.SUMS}")


if __name__ == "__main__":
    main()
