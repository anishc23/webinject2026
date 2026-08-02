"""Evaluation protocols and a submission scorer for WebInject2026.

`baselines.py` reports the reference numbers for the built-in models. This module
is the *protocol* layer: it defines the harder generalisation splits a paper
should report, corrects detection numbers to a realistic attack prevalence, and
scores an external predictions file so results are comparable across methods.

    python -m src.evaluate                       # all protocols, reference model
    python -m src.evaluate --json out.json       # machine-readable
    python -m src.evaluate --predictions p.csv   # score your own scores
    python -m src.evaluate --protocol lofo       # just one protocol

Protocols
  disjoint    payload-disjoint split (the shipped default; use this to rank).
  structural  template-disjoint split: whole payload *shapes* held out. Harder;
              the gap to `disjoint` is the systematicity of the grammar.
  lofo        leave-one-family-out: train on 13 families, test zero-shot on the
              14th. Measures generalisation to an unseen attack class.
  evasion     train on plain attacks only, test on evaded attacks. Measures
              robustness to obfuscation the model never saw.

Prevalence correction
  The corpus is ~26% attack; production traffic is far lower. F1 and precision
  are prevalence-dependent, so the report converts each operating point to the
  precision (PPV) it would have at 0.5% / 1% / 5% attack prevalence — the number
  that actually decides whether a WAF is deployable.

Submission scoring
  `--predictions file.(csv|parquet|npy)` must give one score per test row, in the
  order of `df[df.split=='test']` (or provide `id`/`row` + `score` columns). The
  scorer prints the standard table and, with `--protocol`, the chosen split.
"""

import argparse
import json
import os
import sys
import warnings

import numpy as np
import pandas as pd

warnings.filterwarnings("ignore")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (average_precision_score, f1_score, precision_score,
                             recall_score, roc_curve)

from src import checksums as S  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "data")
TARGET_PREVALENCES = [0.005, 0.01, 0.05, 0.254]


# ---------------------------------------------------------------- model ------
def _fit_char(train_text, train_y):
    v = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=3,
                        max_features=200000)
    A = v.fit_transform(train_text)
    m = LogisticRegression(max_iter=2000, C=4.0).fit(A, train_y)
    return v, m


def _score(v, m, text):
    return m.predict_proba(v.transform(text))[:, 1]


# --------------------------------------------------------------- metrics -----
def _tpr_at_fpr(y, score, budget):
    fpr, tpr, _ = roc_curve(y, score)
    ok = fpr <= budget
    return float(tpr[ok].max()) if ok.any() else 0.0


def _ppv_at_prevalence(tpr, fpr, prev):
    """Precision a detector with (tpr, fpr) would have at a given prevalence."""
    num = prev * tpr
    den = num + (1 - prev) * fpr
    return float(num / den) if den > 0 else 0.0


def _full_metrics(y, score):
    y = np.asarray(y)
    pred = (score >= 0.5).astype(int)
    fpr, tpr, _ = roc_curve(y, score)
    out = {
        "n": int(len(y)), "n_attack": int(y.sum()),
        "f1": float(f1_score(y, pred, zero_division=0)),
        "precision": float(precision_score(y, pred, zero_division=0)),
        "recall": float(recall_score(y, pred, zero_division=0)),
        "pr_auc": float(average_precision_score(y, score)) if y.sum() else 0.0,
        "tpr_at_1pct_fpr": _tpr_at_fpr(y, score, 0.01),
        "tpr_at_0.1pct_fpr": _tpr_at_fpr(y, score, 0.001),
    }
    # prevalence-corrected precision at the 1% FPR operating point
    t1 = out["tpr_at_1pct_fpr"]
    out["ppv_at_prevalence@1pctFPR"] = {
        f"{p:.3f}": _ppv_at_prevalence(t1, 0.01, p) for p in TARGET_PREVALENCES}
    return out


# -------------------------------------------------------------- protocols ----
def protocol_split(df, split_col):
    tr = df[df[split_col] == "train"]
    te = df[df[split_col] == "test"]
    v, m = _fit_char(tr.payload.astype(str), tr.label)
    score = _score(v, m, te.payload.astype(str))
    return _full_metrics(te.label.values, score)


def protocol_lofo(df):
    """Leave-one-family-out zero-shot recall, per family.

    Train on all benign train rows plus every attack family except one; test the
    held-out family's attacks against the benign test set. Reveals which attack
    classes a char model can and cannot recognise without having seen them.
    """
    fams = sorted(df[df.label == 1].attack_type.unique())
    ben_tr = df[(df.label == 0) & (df.split == "train")]
    ben_te = df[(df.label == 0) & (df.split == "test")]
    out = {}
    for fam in fams:
        atk_tr = df[(df.label == 1) & (df.attack_type != fam) &
                    (df.split == "train")]
        atk_te = df[(df.label == 1) & (df.attack_type == fam) &
                    (df.split == "test")]
        if len(atk_te) == 0:
            continue
        tr_text = pd.concat([ben_tr.payload, atk_tr.payload]).astype(str)
        tr_y = np.r_[np.zeros(len(ben_tr)), np.ones(len(atk_tr))]
        v, m = _fit_char(tr_text, tr_y)
        te_text = pd.concat([atk_te.payload, ben_te.payload]).astype(str)
        te_y = np.r_[np.ones(len(atk_te)), np.zeros(len(ben_te))]
        score = _score(v, m, te_text)
        out[fam] = {
            "n_test": int(len(atk_te)),
            "zeroshot_recall": float(recall_score(
                te_y, (score >= 0.5).astype(int), zero_division=0)),
            "tpr_at_1pct_fpr": _tpr_at_fpr(te_y, score, 0.01),
        }
    return out


def protocol_evasion(df):
    """Train on plain attacks only; test recall on evaded attacks, per evasion."""
    ben_tr = df[(df.label == 0) & (df.split == "train")]
    ben_te = df[(df.label == 0) & (df.split == "test")]
    atk_tr = df[(df.label == 1) & (df.split == "train") & (df.evasion == "none")]
    atk_te = df[(df.label == 1) & (df.split == "test") & (df.evasion != "none")]
    tr_text = pd.concat([ben_tr.payload, atk_tr.payload]).astype(str)
    tr_y = np.r_[np.zeros(len(ben_tr)), np.ones(len(atk_tr))]
    v, m = _fit_char(tr_text, tr_y)

    out = {"_train_note": "trained on plain (evasion=none) attacks only"}
    # overall on all evaded test attacks vs benign test
    te_text = pd.concat([atk_te.payload, ben_te.payload]).astype(str)
    te_y = np.r_[np.ones(len(atk_te)), np.zeros(len(ben_te))]
    sc = _score(v, m, te_text)
    out["all_evaded"] = {"n": int(len(atk_te)),
                         "recall": float(recall_score(
                             te_y, (sc >= 0.5).astype(int), zero_division=0)),
                         "tpr_at_1pct_fpr": _tpr_at_fpr(te_y, sc, 0.01)}
    # chained vs single-transform
    for label, mask in (("single", ~atk_te.evasion.str.contains(r"\+")),
                        ("chained", atk_te.evasion.str.contains(r"\+"))):
        sub = atk_te[mask]
        if len(sub) == 0:
            continue
        s = _score(v, m, sub.payload.astype(str))
        out[label] = {"n": int(len(sub)),
                      "recall": float((s >= 0.5).mean())}
    return out


# ------------------------------------------------------ submission scoring ---
def score_predictions(df, pred_path, split_col="split"):
    te = df[df[split_col] == "test"].reset_index(drop=True)
    ext = os.path.splitext(pred_path)[1].lower()
    if ext == ".npy":
        scores = np.load(pred_path)
        if len(scores) != len(te):
            raise ValueError(f"{len(scores)} scores for {len(te)} test rows")
    else:
        p = (pd.read_parquet(pred_path) if ext == ".parquet"
             else pd.read_csv(pred_path))
        col = "score" if "score" in p.columns else p.columns[-1]
        if len(p) != len(te):
            raise ValueError(f"{len(p)} scores for {len(te)} test rows")
        scores = p[col].values
    return _full_metrics(te.label.values, np.asarray(scores, dtype=float))


# ---------------------------------------------------------------- report -----
def _print_metrics(name, m):
    print(f"\n{name}  (n={m['n']:,}, attacks={m['n_attack']:,})")
    print(f"  F1 {m['f1']*100:5.1f}   PR-AUC {m['pr_auc']*100:5.1f}   "
          f"recall {m['recall']*100:5.1f}   "
          f"TPR@1%FPR {m['tpr_at_1pct_fpr']*100:5.1f}   "
          f"TPR@0.1%FPR {m['tpr_at_0.1pct_fpr']*100:5.1f}")
    ppv = m["ppv_at_prevalence@1pctFPR"]
    cells = "  ".join(f"{float(k)*100:g}%->{v*100:4.1f}" for k, v in ppv.items())
    print(f"  precision at 1% FPR by attack prevalence:  {cells}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", default=os.path.join(DATA, "webinject2026.csv"))
    ap.add_argument("--json", default=None)
    ap.add_argument("--predictions", default=None,
                    help="score an external predictions file on the test split")
    ap.add_argument("--protocol", default="all",
                    choices=["all", "disjoint", "structural", "lofo", "evasion"])
    args = ap.parse_args()
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    df = pd.read_csv(args.csv, keep_default_na=False).reset_index(drop=True)
    df["label"] = df["label"].astype(int)
    results = {}

    if args.predictions:
        split_col = "split_struct" if args.protocol == "structural" else "split"
        m = score_predictions(df, args.predictions, split_col)
        _print_metrics(f"submission [{args.predictions}] on {split_col}", m)
        results["submission"] = m
        if args.json:
            json.dump(results, open(args.json, "w"), indent=2)
            S.refresh(args.json)
        return

    print("=" * 78)
    print("WebInject2026 evaluation protocols (reference char n-gram model)")
    print("=" * 78)

    if args.protocol in ("all", "disjoint"):
        results["disjoint"] = protocol_split(df, "split")
        _print_metrics("1. payload-disjoint", results["disjoint"])

    if args.protocol in ("all", "structural"):
        results["structural"] = protocol_split(df, "split_struct")
        _print_metrics("2. structural (template-disjoint)", results["structural"])
        if "disjoint" in results:
            d = results["disjoint"]["tpr_at_0.1pct_fpr"]
            s = results["structural"]["tpr_at_0.1pct_fpr"]
            print(f"  -> systematicity gap at 0.1% FPR: "
                  f"{d*100:.1f} - {s*100:.1f} = {(d-s)*100:+.1f} pts")

    if args.protocol in ("all", "lofo"):
        lofo = protocol_lofo(df)
        results["lofo"] = lofo
        print("\n3. LEAVE-ONE-FAMILY-OUT  (zero-shot recall on the unseen family)")
        for fam, v in sorted(lofo.items(), key=lambda kv: kv[1]["zeroshot_recall"]):
            print(f"     {fam:14s} recall {v['zeroshot_recall']*100:5.1f}  "
                  f"TPR@1%FPR {v['tpr_at_1pct_fpr']*100:5.1f}  (n={v['n_test']})")

    if args.protocol in ("all", "evasion"):
        ev = protocol_evasion(df)
        results["evasion"] = ev
        print("\n4. EVASION HOLD-OUT  (trained on plain attacks, tested on evaded)")
        for k in ("all_evaded", "single", "chained"):
            if k in ev:
                print(f"     {k:12s} recall {ev[k]['recall']*100:5.1f}  "
                      f"(n={ev[k]['n']})")

    if args.json:
        json.dump(results, open(args.json, "w"), indent=2)
        print(f"\nwrote {args.json}")
        if S.refresh(args.json):
            print(f"refreshed {S.SUMS}")


if __name__ == "__main__":
    main()
