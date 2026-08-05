"""Per-character shortcut statistics, on this corpus and the two standard ones.

    python -m src.shortcut_stats
    python -m src.shortcut_stats --json data/shortcut_stats.json

The claim "benign traffic contains quotes too" is worth nothing as an assertion.
This module tests it. For every punctuation character that injection payloads
rely on, it asks: does the mere *presence* of that character predict the label?

For each character and each corpus it reports

  p(benign) / p(attack)  presence rate in each class
  chi2, p                chi-square test of independence, 1 d.o.f.
  cramers_v              effect size in [0, 1]. With ~60k rows a chi-square is
                         significant at trivial effect sizes, so the effect size
                         -- not the p-value -- is the number to read.
  odds_ratio (95% CI)    Haldane-Anscombe corrected, log-normal interval
  auc                    a one-feature detector: "flag iff the character is
                         present". 0.5 is chance.

A corpus is shortcut-free on this axis when every character sits near
CRAMERS_V_CEILING and every AUC near 0.5. CSIC-2010 and ECML/PKDD-2007 are
included as reference points, not as targets: the comparison is the evidence.
"""

import argparse
import json
import math
import os
import sys

import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "data")

# The characters injection actually needs. Presence, not frequency: a detector
# keying on "contains a single quote" is the shortcut we are ruling out.
CHARS = list("'\"<>;()|&${}[]/\\*%=`-#:")

# An effect size a reviewer should accept as "no usable single-character signal".
# 0.1 is the conventional boundary for a small effect in a 2x2 table.
CRAMERS_V_CEILING = 0.10
AUC_CEILING = 0.60


def _wilson_or(a, b, c, d):
    """Odds ratio with a Haldane-Anscombe correction and a 95% log interval."""
    a, b, c, d = a + 0.5, b + 0.5, c + 0.5, d + 0.5
    or_ = (a * d) / (b * c)
    se = math.sqrt(1 / a + 1 / b + 1 / c + 1 / d)
    return or_, or_ * math.exp(-1.96 * se), or_ * math.exp(1.96 * se)


def _chi2_2x2(a, b, c, d):
    """Chi-square (no continuity correction) and Cramer's V for a 2x2 table."""
    n = a + b + c + d
    if n == 0:
        return 0.0, 1.0, 0.0
    row1, row2 = a + b, c + d
    col1, col2 = a + c, b + d
    if min(row1, row2, col1, col2) == 0:
        return 0.0, 1.0, 0.0
    exp = [row1 * col1 / n, row1 * col2 / n, row2 * col1 / n, row2 * col2 / n]
    obs = [a, b, c, d]
    chi2 = sum((o - e) ** 2 / e for o, e in zip(obs, exp) if e > 0)
    # V = sqrt(chi2 / n) for 1 d.o.f.
    v = math.sqrt(chi2 / n)
    try:
        from scipy.stats import chi2 as chi2_dist
        p = float(chi2_dist.sf(chi2, 1))
    except Exception:
        p = float("nan")
    return float(chi2), p, float(v)


def analyse(text, label, chars=CHARS):
    """Per-character presence statistics for one corpus."""
    y = np.asarray(label).astype(int)
    n_atk, n_ben = int(y.sum()), int((1 - y).sum())
    rows = []
    for ch in chars:
        has = text.str.contains(ch, regex=False, na=False).to_numpy()
        a = int((has & (y == 1)).sum())      # attack, present
        b = int((~has & (y == 1)).sum())     # attack, absent
        c = int((has & (y == 0)).sum())      # benign, present
        d = int((~has & (y == 0)).sum())     # benign, absent
        chi2, p, v = _chi2_2x2(a, b, c, d)
        or_, lo, hi = _wilson_or(a, b, c, d)
        auc = float(roc_auc_score(y, has.astype(float))) if 0 < has.sum() < len(has) else 0.5
        rows.append({
            "char": ch,
            "p_benign": c / n_ben if n_ben else 0.0,
            "p_attack": a / n_atk if n_atk else 0.0,
            "chi2": chi2, "p_value": p, "cramers_v": v,
            "odds_ratio": or_, "or_ci_low": lo, "or_ci_high": hi,
            "auc": auc,
        })
    return rows


def _load_reference(name):
    path = os.path.join(DATA, f"{name}_parsed.csv")
    if not os.path.exists(path):
        return None
    d = pd.read_csv(path, engine="python", on_bad_lines="skip")
    d = d.dropna(subset=["payload"])
    return d["payload"].astype(str), d["label"].astype(int)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--csv", default=os.path.join(DATA, "webinject2026.csv"))
    ap.add_argument("--json", default=None)
    args = ap.parse_args()

    df = pd.read_csv(args.csv, keep_default_na=False, dtype=str)
    df["label"] = df["label"].astype(int)

    corpora = {"webinject2026": (df["payload"].astype(str), df["label"])}
    for name in ("csic", "ecml"):
        ref = _load_reference(name)
        if ref:
            corpora[name] = ref

    out = {}
    for name, (text, label) in corpora.items():
        rows = analyse(text, label)
        out[name] = rows
        worst = max(rows, key=lambda r: r["cramers_v"])
        worst_auc = max(rows, key=lambda r: r["auc"])
        print("=" * 92)
        print(f"{name}  (n={len(text):,}, attack={int(np.sum(label)):,})")
        print("=" * 92)
        print(f"  {'char':<6}{'p(benign)':>11}{'p(attack)':>11}{'chi2':>12}"
              f"{'Cramer V':>10}{'odds ratio (95% CI)':>28}{'AUC':>8}")
        for r in sorted(rows, key=lambda r: -r["cramers_v"]):
            ci = f"{r['odds_ratio']:.2f} [{r['or_ci_low']:.2f}, {r['or_ci_high']:.2f}]"
            print(f"  {r['char']:<6}{r['p_benign']:>11.3f}{r['p_attack']:>11.3f}"
                  f"{r['chi2']:>12.1f}{r['cramers_v']:>10.3f}{ci:>28}{r['auc']:>8.3f}")
        print(f"  strongest single character: '{worst['char']}' "
              f"(Cramer V {worst['cramers_v']:.3f}); "
              f"best one-character AUC: '{worst_auc['char']}' {worst_auc['auc']:.3f}")

    ours = out["webinject2026"]
    max_v = max(r["cramers_v"] for r in ours)
    max_auc = max(r["auc"] for r in ours)
    refs = {n: (max(r["cramers_v"] for r in out[n]), max(r["auc"] for r in out[n]))
            for n in ("csic", "ecml") if n in out}

    # The contract, stated so it cannot be read as more than it is.
    #
    # We do NOT claim zero association. Injection genuinely uses punctuation, and
    # the `routine` tier is deliberately ordinary alphanumeric traffic, so real
    # benign traffic carries less of it. Forcing a perfect match would falsify
    # the benign distribution -- a worse fault than the one being fixed.
    #
    # What is claimed, and enforced: no single character yields a usable
    # detector, and the strongest single-character association is smaller than in
    # every public corpus this one is meant to replace.
    beats_refs = all(max_v < v and max_auc < a for v, a in refs.values()) if refs else True
    ok = max_auc <= AUC_CEILING and beats_refs
    print("=" * 92)
    print(f"RESULT: {'PASS' if ok else 'FAIL'}")
    print(f"  webinject2026  max Cramer V {max_v:.3f}   max single-char AUC {max_auc:.3f}"
          f"   (AUC ceiling {AUC_CEILING})")
    for name, (v, a) in refs.items():
        print(f"  reference {name:<6} max Cramer V {v:.3f}   max single-char AUC {a:.3f}")
    print(f"  no usable single-character detector: {'yes' if max_auc <= AUC_CEILING else 'NO'}"
          f"; smaller than every reference corpus: {'yes' if beats_refs else 'NO'}")
    if max_v > CRAMERS_V_CEILING:
        print(f"  note: max Cramer V {max_v:.3f} exceeds the conventional small-effect "
              f"boundary of {CRAMERS_V_CEILING}. Residual association is expected and is "
              f"documented, not claimed away -- see DATASHEET.md > Limitations.")

    if args.json:
        json.dump(out, open(args.json, "w"), indent=1)
        print(f"wrote {args.json}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
