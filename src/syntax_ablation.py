"""Table 1: how much detection performance survives deleting injection syntax?

    python -m src.syntax_ablation
    python -m src.syntax_ablation --json data/syntax_ablation.json
    python -m src.syntax_ablation --fast          # skip the paired section

The load-bearing claim of this corpus is that the ~99% detection scores reported
against existing web-attack corpora are largely driven by dataset artefacts
rather than by the injection itself. `src.separability` argues that one character
at a time: a single quote is a better detector on CSIC-2010 (Cramer's V 0.316)
and on ECML/PKDD-2007 (0.411) than any character is here (0.139).

This argues it with the whole model, which is the stronger form: delete the
injection from the corpus, retrain from scratch, and measure what is left. Three
conditions, each a strict superset of the last.

  full            the payload as shipped
  -syntax         every character that is not a letter or a space, deleted.
                  Every quote, angle bracket, semicolon, percent-escape, every
                  `1=1` and every `../`.
  -syntax -vocab  additionally, every word in `corpus/payloads.json` -- `script`,
                  `select`, `union`, `passwd`, `etc`, `alert`, `onerror` and 385
                  others. Nothing recognisable as an injection survives this.

The second condition alone is not the experiment, and reporting it alone would
be misleading: deleting punctuation from `<script>alert(1)</script>` leaves
`script alert script`, which is still the attack. Both corpora keep ~90% of
their AUC there, and that number says only that punctuation was never the sole
carrier. The third condition is the one that means something, because after it
the injected span holds no information at all.

The reading is then direct. A corpus still separable at condition three is
separable by something that is not the attack -- and whatever that something is,
a detector trained on it has learned the corpus, not the threat. A corpus that
falls to chance was carrying its signal in the injection.

The deleted vocabulary is one fixed list applied identically to all three
corpora, so the comparison is like-for-like. It is derived from this corpus's
payload pool, which if anything understates the effect on the others: it deletes
every attack word this corpus knows about, and CSIC-2010 or ECML/PKDD-2007 may
use attack vocabulary it does not contain.

All conditions use the same model, features and split. Splits: WebInject2026
uses its own payload-disjoint `split` column; CSIC-2010 and ECML/PKDD-2007 ship
no grouping, so they get a stratified random 80/20 -- the protocol their
published results use, and the one that flatters them most.
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
from sklearn.metrics import f1_score, roc_auc_score
from sklearn.model_selection import train_test_split

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "data")

# Everything that is not a letter or a space. Digits included: `1=1`, `admin'--`
# and `../../etc/passwd` are as much injection syntax as the punctuation holding
# them together, and leaving digits in would understate the deletion.
SYNTAX = re.compile(r"[^A-Za-z ]+")
WORD = re.compile(r"[A-Za-z]{2,}")


def strip_syntax(s):
    return re.sub(r"\s+", " ", SYNTAX.sub(" ", str(s))).strip()


def pool_words():
    """Every alphabetic token appearing anywhere in the payload pool. One list,
    applied to every corpus, so the deletion is identical across the table."""
    path = os.path.join(ROOT, "corpus", "payloads.json")
    pool = json.load(open(path, encoding="utf-8"))
    return {w.lower() for ps in pool.values() for p in ps
            for w in WORD.findall(p)}


def strip_vocab(s, vocab):
    """`strip_syntax`, then delete every payload-pool word. What remains is
    carrier text: ordinary language with no trace of an injection in it."""
    return " ".join(w for w in strip_syntax(s).split(" ")
                    if w and w.lower() not in vocab)


def _fit(tr_text, tr_y, te_text, te_y):
    """One detector, trained and scored. char_wb 3-5 grams is the standard
    strong baseline for this task and the one `src.baselines` reports."""
    v = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=3,
                        sublinear_tf=True, max_features=200_000)
    X = v.fit_transform(tr_text)
    m = LogisticRegression(max_iter=2000, C=8).fit(X, tr_y)
    p = m.predict_proba(v.transform(te_text))[:, 1]
    return {"f1": float(f1_score(te_y, (p >= 0.5).astype(int), zero_division=0)),
            "roc_auc": float(roc_auc_score(te_y, p))}, p


def _load(name):
    """(dataframe, train_mask, test_mask) for one corpus."""
    if name == "webinject2026":
        pq = os.path.join(DATA, "webinject2026.parquet")
        d = (pd.read_parquet(pq) if os.path.exists(pq) else
             pd.read_csv(os.path.join(DATA, "webinject2026.csv"),
                         keep_default_na=False, dtype=str).astype({"label": int}))
        return d, (d.split == "train").to_numpy(), (d.split == "test").to_numpy()

    path = os.path.join(DATA, f"{name}.csv")
    if not os.path.exists(path):
        return None, None, None
    d = pd.read_csv(path, engine="python", on_bad_lines="skip")
    d = d.dropna(subset=["payload"]).reset_index(drop=True)
    itr, ite = train_test_split(np.arange(len(d)), test_size=0.2,
                                random_state=42, stratify=d["label"])
    tr = np.zeros(len(d), bool); tr[itr] = True
    te = np.zeros(len(d), bool); te[ite] = True
    return d, tr, te


CORPORA = [("csic_parsed", "CSIC-2010"),
           ("ecml_parsed", "ECML/PKDD-2007"),
           ("webinject2026", "WebInject2026")]


def run(fast=False):
    vocab = pool_words()
    rows = []
    for key, label in CORPORA:
        d, tr, te = _load(key)
        if d is None:
            print(f"  {label}: not present, skipped")
            continue
        text = d["payload"].astype(str)
        y = d["label"].to_numpy()
        conds = {"full": text,
                 "syntax_deleted": text.map(strip_syntax),
                 "syntax_and_vocab_deleted": text.map(lambda s: strip_vocab(s, vocab))}

        rec = {"corpus": label, "n": int(len(d)), "base_rate": float(y.mean()),
               "vocab_size": len(vocab)}
        scores = {}
        for cond, t in conds.items():
            rec[cond], scores[cond] = _fit(t[tr], y[tr], t[te], y[te])
            rec[cond]["chars_deleted"] = float(
                1 - t.str.len().sum() / max(1, text.str.len().sum()))

        # How much of the *achieved* separation survives, measured above chance
        # rather than above zero: an AUC of 0.5 is what a coin scores, so the
        # honest denominator for "how much is left" is (AUC - 0.5).
        base = rec["full"]["roc_auc"] - 0.5
        for cond in ("syntax_deleted", "syntax_and_vocab_deleted"):
            rec[cond]["auc_retained"] = (float((rec[cond]["roc_auc"] - 0.5) / base)
                                         if base > 0 else float("nan"))
            rec[cond]["f1_retained"] = (float(rec[cond]["f1"] / rec["full"]["f1"])
                                        if rec["full"]["f1"] else float("nan"))

        # For this corpus only, the counterfactual version: within a matched
        # pair, both rows carry identical carrier text, so a model with the
        # injection deleted has nothing left to read and must score at chance.
        # No other corpus can be measured this way, which is the point.
        if key == "webinject2026" and not fast:
            for cond in ("syntax_deleted", "syntax_and_vocab_deleted"):
                sub = d[te].assign(_s=scores[cond])
                sub = sub[sub.pair_id.astype(str) != ""]
                piv = sub.pivot_table(index="pair_id", columns="label",
                                      values="_s", aggfunc="first").dropna()
                if piv.empty:
                    continue
                w = float((piv[1] > piv[0]).mean())
                t = float((piv[1] == piv[0]).mean())
                rec[cond]["paired_accuracy"] = w + 0.5 * t
                rec[cond]["paired_ties"] = t
        rows.append(rec)
    return rows


def _table(rows):
    w = max(len(r["corpus"]) for r in rows) + 2
    head = (f"{'corpus':<{w}}{'rows':>8} | {'F1':>6}{'AUC':>7} | "
            f"{'F1':>6}{'AUC':>7}{'kept':>7} | {'F1':>6}{'AUC':>7}{'kept':>7}")
    sub = (f"{'':<{w}}{'':>8} | {'full':>13} | {'-syntax':>20} | "
           f"{'-syntax -vocab':>20}")
    out = [sub, head, "-" * len(head)]
    for r in rows:
        a, b = r["syntax_deleted"], r["syntax_and_vocab_deleted"]
        out.append(
            f"{r['corpus']:<{w}}{r['n']:>8,} | {r['full']['f1']:>6.3f}"
            f"{r['full']['roc_auc']:>7.3f} | {a['f1']:>6.3f}{a['roc_auc']:>7.3f}"
            f"{a['auc_retained']*100:>6.0f}% | {b['f1']:>6.3f}{b['roc_auc']:>7.3f}"
            f"{b['auc_retained']*100:>6.0f}%")
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--json", default=None)
    ap.add_argument("--fast", action="store_true")
    args = ap.parse_args()

    print("=" * 78)
    print("Table 1 - detection performance after deleting the injection")
    print("  -syntax        every character that is not a letter or a space")
    print("  -syntax -vocab  ... and every word in the payload pool")
    print("'kept' is AUC above chance, as a share of the full model's")
    print("=" * 78)
    rows = run(fast=args.fast)
    print(_table(rows))
    print()
    for r in rows:
        b = r["syntax_and_vocab_deleted"]
        print(f"  {r['corpus']:<16} base rate {r['base_rate']:.3f}; "
              f"{b['chars_deleted']*100:.0f}% of characters deleted at -syntax -vocab")
        if "paired_accuracy" in b:
            print(f"  {'':<16} matched-pair accuracy with the injection deleted "
                  f"{b['paired_accuracy']*100:.1f}% ({b['paired_ties']*100:.1f}% "
                  f"ties) -- chance is 50%")
    if args.json:
        json.dump(rows, open(args.json, "w"), indent=1)
        print(f"\nwrote {args.json}")


if __name__ == "__main__":
    main()
