"""The deletion ablation as a figure: what survives, across all three panels.

    python -m src.fig_ablation
    python -m src.fig_ablation --outdir figures --format pdf

Reads data/syntax_ablation.json and data/protocol_matched.json -- never
recomputes -- so the figure always matches the tables.

This is the paper's central result and it was the one measurement with no
figure. Three tables carry it (pool, symmetric, deduplicated), each with the
same shape, and asking a reader to hold three tables in their head to see one
comparison is the wrong way round.

The quantity plotted is AUC kept, (AUC_deleted - 0.5) / (AUC_full - 0.5): the
share of a detector's above-chance separation that survives deleting every
injection character and every injection word. **Lower is better**, which is
inverted with respect to every other score in the paper, so the axis is labelled
with the direction and a chance line is drawn at zero.

Colour is categorical over the three panels and is never the only encoding: each
bar carries its value, and the palette is checked for CVD separation
(worst adjacent pair dE 11.4 protan / 24.2 normal vision).
"""

import argparse
import json
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "data")

plt.rcParams.update({
    "font.size": 11, "font.family": "serif",
    "axes.grid": True, "grid.alpha": 0.3,
    "savefig.dpi": 300, "savefig.bbox": "tight",
})

# Okabe-Ito steps. Fixed order, assigned per panel and never cycled.
PANEL_COLOURS = ("#0072B2", "#E69F00", "#009E73")
ORDER = ("CSIC-2010", "ECML/PKDD-2007", "WebInject2026")


def _load(name):
    with open(os.path.join(DATA, name), encoding="utf-8") as fh:
        return json.load(fh)


def _kept(rows):
    return {r["corpus"]: 100.0 * r["syntax_and_vocab_deleted"]["auc_retained"]
            for r in rows}


def build(outdir, fmt):
    abl = _load("syntax_ablation.json")
    panels = [("pool vocabulary", _kept(abl["pool"])),
              ("per-corpus vocabulary", _kept(abl["symmetric"]))]

    pm_path = os.path.join(DATA, "protocol_matched.json")
    if os.path.exists(pm_path):
        panels.append(("deduplicated, group-disjoint",
                       _kept(_load("protocol_matched.json")["protocol_matched"])))

    fig, ax = plt.subplots(figsize=(7.2, 3.6))
    x = np.arange(len(ORDER))
    width = 0.8 / len(panels)

    for i, ((label, vals), colour) in enumerate(zip(panels, PANEL_COLOURS)):
        offs = x + (i - (len(panels) - 1) / 2) * width
        heights = [vals.get(c, np.nan) for c in ORDER]
        # A 2px surface gap between adjacent fills, per the mark spec.
        ax.bar(offs, heights, width * 0.92, label=label, color=colour,
               edgecolor="white", linewidth=1.0, zorder=3)
        for xi, h in zip(offs, heights):
            if np.isnan(h):
                continue
            va = "bottom" if h >= 0 else "top"
            ax.annotate("%.0f%%" % h, (xi, h), textcoords="offset points",
                        xytext=(0, 3 if h >= 0 else -4), ha="center", va=va,
                        fontsize=9, color="#333333", zorder=4)

    ax.axhline(0, color="#666666", linewidth=1.0, zorder=2)
    ax.set_xticks(x)
    ax.set_xticklabels(ORDER)
    ax.set_ylabel("AUC kept (%)\n$\\leftarrow$ lower is better")
    ax.set_title("What survives deleting the injection")
    ax.legend(frameon=False, fontsize=9, loc="upper right")
    ax.set_axisbelow(True)
    ax.grid(axis="x", visible=False)

    # Headroom for the value labels, and enough floor to show a negative bar.
    lo = min(v for _, vals in panels for v in vals.values())
    ax.set_ylim(min(-20, lo - 10), 110)

    os.makedirs(outdir, exist_ok=True)
    path = os.path.join(outdir, "fig9_ablation.%s" % fmt)
    fig.savefig(path)
    plt.close(fig)
    print("  wrote %s" % path)
    return path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--outdir", default=os.path.join(ROOT, "figures"))
    ap.add_argument("--format", default="png")
    a = ap.parse_args()
    build(a.outdir, a.format)


if __name__ == "__main__":
    main()
