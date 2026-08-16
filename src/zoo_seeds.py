"""How much of the model zoo's ordering is seed noise?

!! DOES NOT WORK YET. NOT WIRED INTO THE PAPER. !!

Running this produces a standard deviation of exactly 0.0 for every model,
which is an artefact and not a result. `src.model_zoo` pins its randomness
internally in two places -- `_cap()` passes `random_state=42` to both `.sample()`
calls, and `_deep()` calls `torch.manual_seed(42)` -- so seeding at this call
site changes nothing and all repeats are the same computation. The numbers this
module reports also do not reproduce `model_zoo`'s own (CNN disjoint
TPR@0.1%FPR 13.7 here against 64.5 there), so they could not annotate those
tables even if the seeds did vary.

Making this real means threading a seed parameter through `_cap` and `_deep`
in `src/model_zoo.py` and rerunning the sweep. Until then the paper says
plainly that it has no run-to-run variance estimate.

    python -m src.zoo_seeds
    python -m src.zoo_seeds --seeds 42,43,44 --cap 8000

`src.model_zoo` reports one run per model at seed 42. The paper reads an
ordering off those columns -- which architecture generalises best on the
template-disjoint protocol -- and an ordering read off single point estimates is
only meaningful if the spread between repeated runs is smaller than the gaps
being compared.

This module repeats the classical tier and the character CNN across several
seeds at the capped training budget and reports mean and standard deviation for
the two columns the paper actually ranks on: TPR@0.1%FPR on the payload-disjoint
split, and F1 on the template-disjoint ("structural") split.

What actually moves per seed differs by model, and the module does not pretend
otherwise. For every model the training subsample moves. For the CNN so do
weight initialisation and batch order. RandomForest and XGBoost pin their own
`random_state` inside `src.model_zoo`, so their spread here reflects the
subsample alone and is a floor on their true run-to-run variance rather than an
estimate of it. LogisticRegression and LinearSVM are deterministic given their
input, so their spread is subsample variance exactly.

The splits themselves are fixed and shipped, so this measures estimator variance
and not split variance -- the right quantity, because the splits are part of the
corpus rather than part of the experiment.

The transformers are excluded: at three seeds each they are hours of GPU for a
variance estimate, and the paper already declines to compare them across
budgets.
"""

import argparse
import json
import os
import statistics

import numpy as np
import pandas as pd

from .model_zoo import _cap, _classical, _deep, _metrics, splits

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "data")

MODELS = ["LogisticRegression", "RandomForest", "LinearSVM", "XGBoost", "CNN"]
PROTOCOLS = ["disjoint", "structural"]


def _build(name, seed):
    """A fresh, seeded instance of one model."""
    if name == "CNN":
        return _deep("cnn")
    return _classical(name)


def run(df, seeds, cap, models=None):
    out = {}
    for name in (models or MODELS):
        per_protocol = {p: {"tpr": [], "f1": []} for p in PROTOCOLS}
        for seed in seeds:
            np.random.seed(seed)
            try:
                import torch
                torch.manual_seed(seed)
            except ImportError:
                pass
            fn = _build(name, seed)
            for proto in PROTOCOLS:
                tr, te = splits(df, proto, seed=seed)
                if cap:
                    tr = _cap(tr, cap)
                score = fn(tr, te)
                m = _metrics(te.label.values, score)
                per_protocol[proto]["tpr"].append(m["tpr_at_0.1pct_fpr"])
                per_protocol[proto]["f1"].append(m["f1"])
            print("    %-20s seed %d done" % (name, seed))

        row = {"seeds": list(seeds), "n_seeds": len(seeds)}
        for proto in PROTOCOLS:
            for metric in ("tpr", "f1"):
                vals = [100 * v for v in per_protocol[proto][metric]]
                row["%s_%s_mean" % (proto, metric)] = round(
                    statistics.mean(vals), 2)
                row["%s_%s_sd" % (proto, metric)] = round(
                    statistics.pstdev(vals) if len(vals) > 1 else 0.0, 2)
                row["%s_%s_runs" % (proto, metric)] = [round(v, 2)
                                                       for v in vals]
        out[name] = row
        print("  %-20s structural F1 %.1f +/- %.1f" %
              (name, row["structural_f1_mean"], row["structural_f1_sd"]))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", default=os.path.join(DATA, "webinject2026.csv"))
    ap.add_argument("--seeds", default="42,43,44")
    ap.add_argument("--cap", type=int, default=8000)
    ap.add_argument("--models", default=None,
                    help="comma-separated subset; the CNN needs the GPU, the "
                         "rest are CPU-only, so they can be run separately")
    ap.add_argument("--json", default=os.path.join(DATA, "zoo_seeds.json"))
    a = ap.parse_args()

    seeds = [int(s) for s in a.seeds.split(",")]
    models = a.models.split(",") if a.models else None
    df = pd.read_csv(a.csv, low_memory=False)
    print("loaded %s rows; seeds %s; cap %s" % (len(df), seeds, a.cap))

    res = run(df, seeds, a.cap, models)
    # Merge rather than overwrite, so a CPU-only subset and a later GPU subset
    # accumulate into one file instead of clobbering each other.
    if os.path.exists(a.json):
        with open(a.json, encoding="utf-8") as fh:
            res = {**json.load(fh).get("models", {}), **res}
    with open(a.json, "w", encoding="utf-8") as fh:
        json.dump({"cap": a.cap, "seeds": seeds, "models": res}, fh, indent=2)
    print("\nwrote %s" % a.json)

    print("\n%-20s %22s %22s" % ("model", "TPR@0.1%FPR (disjoint)",
                                 "F1 (structural)"))
    for name, r in res.items():
        print("%-20s %15.1f +/-%-5.1f %15.1f +/-%-5.1f"
              % (name, r["disjoint_tpr_mean"], r["disjoint_tpr_sd"],
                 r["structural_f1_mean"], r["structural_f1_sd"]))


if __name__ == "__main__":
    main()
