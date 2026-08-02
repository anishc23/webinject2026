"""Publication figures for WebInject2026.

Reads data/baselines.json and data/evaluation.json — never recomputes — so the
figures always match the reported numbers.

    python -m src.figures
    python -m src.figures --outdir figures --format pdf
"""

import argparse
import json
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "data")

plt.rcParams.update({
    "font.size": 11, "font.family": "serif",
    "axes.grid": True, "grid.alpha": 0.3,
    "savefig.dpi": 300, "savefig.bbox": "tight",
})

C_BLUE, C_RED, C_GREEN, C_PURPLE, C_ORANGE = (
    "#2E75B6", "#C0392B", "#27AE60", "#8E44AD", "#E67E22")


def _save(fig, outdir, name, fmt):
    path = os.path.join(outdir, f"{name}.{fmt}")
    fig.savefig(path)
    plt.close(fig)
    print(f"  wrote {path}")


# --------------------------------------------------------------- figures ----
def fig_composition(man, outdir, fmt):
    """Corpus composition: applications, families, tiers."""
    fig, axes = plt.subplots(1, 3, figsize=(15, 4.2))

    apps = pd.Series(man["app"]).sort_values(ascending=False)
    axes[0].bar(apps.index, apps.values, color=C_BLUE, edgecolor="black")
    axes[0].set_title("Requests per application", fontweight="bold")
    axes[0].set_ylabel("Requests")

    fam = {k: v for k, v in man["attack_type"].items() if k != "benign"}
    fam = pd.Series(fam).sort_values()
    axes[1].barh(fam.index, fam.values, color=C_RED, edgecolor="black")
    axes[1].set_title("Attack families (14)", fontweight="bold")

    tier = pd.Series(man["tier"])[["routine", "hard_negative", "ambiguous", "attack"]]
    axes[2].bar(tier.index, tier.values, color=C_GREEN, edgecolor="black")
    axes[2].set_title("Requests by tier", fontweight="bold")
    axes[2].tick_params(axis="x", rotation=20)

    fig.tight_layout()
    _save(fig, outdir, "fig1_composition", fmt)


def fig_baseline_ladder(base, outdir, fmt):
    """Baseline capability ladder on the payload-disjoint split."""
    order = ["length only (1 feature)", "special-char count (1 feature)",
             "rule signature (14 regex)", "word n-gram (1-2) + LogReg",
             "char n-gram (3-5) + LogReg"]
    labels = ["Length only", "Special-char count", "Rule signature (14 regex)",
              "Word n-gram + LogReg", "Char n-gram + LogReg"]
    f1 = [base["baselines"][k]["payload-disjoint"]["f1"] * 100 for k in order]

    fig, ax = plt.subplots(figsize=(9, 5))
    cols = [C_RED, C_RED, C_ORANGE, C_BLUE, C_GREEN]
    ax.barh(labels, f1, color=cols, edgecolor="black")
    for i, v in enumerate(f1):
        ax.text(v + 1.5, i, f"{v:.2f}", va="center", fontsize=10)
    ax.set_xlim(0, 105)
    ax.set_xlabel("F1 (%)")
    ax.set_title("Baseline ladder: the corpus is neither trivial nor unlearnable",
                 fontweight="bold")
    fig.tight_layout()
    _save(fig, outdir, "fig2_baseline_ladder", fmt)


def fig_systematicity(ev, outdir, fmt):
    """Payload-disjoint vs template-disjoint (structural) split."""
    keys = ["f1", "recall", "tpr_at_1pct_fpr", "tpr_at_0.1pct_fpr"]
    labels = ["F1", "Recall", "TPR@1%FPR", "TPR@0.1%FPR"]
    d = [ev["disjoint"][k] * 100 for k in keys]
    s = [ev["structural"][k] * 100 for k in keys]

    x = np.arange(len(keys)); w = 0.38
    fig, ax = plt.subplots(figsize=(9, 5))
    ax.bar(x - w/2, d, w, label="payload-disjoint", color=C_BLUE, edgecolor="black")
    ax.bar(x + w/2, s, w, label="structural (template-disjoint)", color=C_RED,
           edgecolor="black")
    for i, (a, b) in enumerate(zip(d, s)):
        ax.text(i - w/2, a + 1, f"{a:.1f}", ha="center", fontsize=9)
        ax.text(i + w/2, b + 1, f"{b:.1f}", ha="center", fontsize=9)
    ax.set_xticks(x); ax.set_xticklabels(labels)
    ax.set_ylabel("%"); ax.set_ylim(0, 108); ax.legend()
    gap = (ev["disjoint"]["tpr_at_0.1pct_fpr"] -
           ev["structural"]["tpr_at_0.1pct_fpr"]) * 100
    ax.set_title(f"Systematicity gap: {gap:+.1f} pts at 0.1% FPR", fontweight="bold")
    fig.tight_layout()
    _save(fig, outdir, "fig3_systematicity", fmt)


def fig_lofo(ev, outdir, fmt):
    """Leave-one-family-out zero-shot recall."""
    rows = [(k, v["zeroshot_recall"] * 100, v["n_test"])
            for k, v in ev["lofo"].items()]
    rows.sort(key=lambda r: r[1])
    names = [r[0] for r in rows]; vals = [r[1] for r in rows]

    fig, ax = plt.subplots(figsize=(9, 6))
    cols = [C_RED if v < 40 else (C_ORANGE if v < 70 else C_GREEN) for v in vals]
    ax.barh(names, vals, color=cols, edgecolor="black")
    for i, (v, n) in enumerate(zip(vals, [r[2] for r in rows])):
        ax.text(v + 1.5, i, f"{v:.1f}  (n={n})", va="center", fontsize=9)
    ax.set_xlim(0, 105); ax.set_xlabel("Zero-shot recall (%)")
    ax.set_title("Leave-one-family-out: detecting an unseen attack class",
                 fontweight="bold")
    fig.tight_layout()
    _save(fig, outdir, "fig4_lofo", fmt)


def fig_prevalence(ev, outdir, fmt):
    """Precision at 1% FPR as a function of attack prevalence."""
    ppv = ev["disjoint"]["ppv_at_prevalence@1pctFPR"]
    prev = [float(k) * 100 for k in ppv]
    vals = [v * 100 for v in ppv.values()]

    fig, ax = plt.subplots(figsize=(8, 5))
    ax.plot(prev, vals, "o-", color=C_PURPLE, lw=2.5, ms=9)
    for p, v in zip(prev, vals):
        ax.annotate(f"{v:.1f}%", (p, v), textcoords="offset points",
                    xytext=(0, 11), ha="center", fontsize=10)
    ax.set_xscale("log")
    ax.set_xlabel("Attack prevalence (%, log scale)")
    ax.set_ylabel("Precision at 1% FPR (%)")
    ax.set_ylim(0, 108)
    ax.set_title("Deployability: precision collapses at realistic prevalence",
                 fontweight="bold")
    fig.tight_layout()
    _save(fig, outdir, "fig5_prevalence", fmt)


def fig_family_recall(base, outdir, fmt):
    """Per-family recall of the reference char n-gram model."""
    d = base["char_ngram_recall_by_family"]
    rows = sorted(((k, v["recall"] * 100, v["n"]) for k, v in d.items()),
                  key=lambda r: r[1])
    names = [r[0] for r in rows]; vals = [r[1] for r in rows]

    fig, ax = plt.subplots(figsize=(9, 6))
    cols = [C_RED if v < 70 else (C_ORANGE if v < 90 else C_GREEN) for v in vals]
    ax.barh(names, vals, color=cols, edgecolor="black")
    for i, (v, n) in enumerate(zip(vals, [r[2] for r in rows])):
        ax.text(v + 1, i, f"{v:.1f}  (n={n})", va="center", fontsize=9)
    ax.set_xlim(0, 112); ax.set_xlabel("Recall (%)")
    ax.set_title("Per-family recall, payload-disjoint test", fontweight="bold")
    fig.tight_layout()
    _save(fig, outdir, "fig6_family_recall", fmt)


def fig_evasion(base, ev, outdir, fmt):
    """Recall by evasion transform (single transforms, n>=25)."""
    d = base["char_ngram_recall_by_evasion"]
    rows = [(k, v["recall"] * 100, v["n"]) for k, v in d.items()
            if "+" not in k and v["n"] >= 25]
    rows.sort(key=lambda r: r[1])
    names = [r[0] for r in rows]; vals = [r[1] for r in rows]

    fig, ax = plt.subplots(figsize=(9, 5))
    cols = [C_RED if v < 85 else (C_ORANGE if v < 95 else C_GREEN) for v in vals]
    ax.barh(names, vals, color=cols, edgecolor="black")
    for i, (v, n) in enumerate(zip(vals, [r[2] for r in rows])):
        ax.text(v + 0.8, i, f"{v:.1f}  (n={n})", va="center", fontsize=9)
    base_r = ev["evasion"]["all_evaded"]["recall"] * 100
    ax.axvline(base_r, color="black", ls="--", lw=1.2,
               label=f"evasion hold-out: {base_r:.1f}%")
    ax.set_xlim(0, 112); ax.set_xlabel("Recall (%)"); ax.legend(loc="lower right")
    ax.set_title("Recall by evasion transform", fontweight="bold")
    fig.tight_layout()
    _save(fig, outdir, "fig7_evasion", fmt)


def fig_cross_dataset(base, outdir, fmt):
    """Cross-corpus transfer: PR-AUC, which exposes lost discrimination."""
    cd = base["cross_dataset"]
    corpora = ["webinject", "csic", "ecml"]
    mat = np.full((3, 3), np.nan)
    for i, src in enumerate(corpora):
        for j, tgt in enumerate(corpora):
            if src != tgt and tgt in cd.get(src, {}):
                mat[i, j] = cd[src][tgt]["pr_auc"] * 100

    fig, ax = plt.subplots(figsize=(7, 5.5))
    im = ax.imshow(mat, cmap="RdYlGn", vmin=20, vmax=100)
    ax.set_xticks(range(3)); ax.set_xticklabels(corpora)
    ax.set_yticks(range(3)); ax.set_yticklabels(corpora)
    ax.set_xlabel("tested on"); ax.set_ylabel("trained on")
    for i in range(3):
        for j in range(3):
            txt = "—" if np.isnan(mat[i, j]) else f"{mat[i, j]:.1f}"
            ax.text(j, i, txt, ha="center", va="center", fontweight="bold")
    ax.grid(False)
    fig.colorbar(im, ax=ax, label="PR-AUC (%)")
    ax.set_title("Cross-corpus transfer: discrimination is lost entirely",
                 fontweight="bold")
    fig.tight_layout()
    _save(fig, outdir, "fig8_cross_dataset", fmt)


# ------------------------------------------------------------------ main ----
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--outdir", default=os.path.join(ROOT, "figures"))
    ap.add_argument("--format", default="png", choices=["png", "pdf", "svg"])
    args = ap.parse_args()
    os.makedirs(args.outdir, exist_ok=True)

    man = json.load(open(os.path.join(DATA, "manifest.json")))
    base = json.load(open(os.path.join(DATA, "baselines.json")))
    ev = json.load(open(os.path.join(DATA, "evaluation.json")))

    print(f"writing figures to {args.outdir}")
    fig_composition(man, args.outdir, args.format)
    fig_baseline_ladder(base, args.outdir, args.format)
    fig_systematicity(ev, args.outdir, args.format)
    fig_lofo(ev, args.outdir, args.format)
    fig_prevalence(ev, args.outdir, args.format)
    fig_family_recall(base, args.outdir, args.format)
    fig_evasion(base, ev, args.outdir, args.format)
    fig_cross_dataset(base, args.outdir, args.format)
    print("done — 8 figures")


if __name__ == "__main__":
    main()