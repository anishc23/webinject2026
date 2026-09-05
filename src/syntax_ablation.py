"""Table 4: how much detection performance survives deleting injection syntax?

    python -m src.syntax_ablation
    python -m src.syntax_ablation --json data/syntax_ablation.json
    python -m src.syntax_ablation --fast          # skip the paired section

The load-bearing claim of this corpus is that the ~99% detection scores reported
against existing web-attack corpora are largely driven by dataset artefacts
rather than by the injection itself. `src.separability` argues that one character
at a time: the strongest single character is a better detector on CSIC-2010 (Cramer's V
0.300) and on ECML/PKDD-2007 (0.411) than any character is here (0.147).

This argues it with the whole model, which is the stronger form: delete the
injection from the corpus, retrain from scratch, and measure what is left. Three
conditions, each a strict superset of the last.

  full            the payload as shipped
  -syntax         every character that is not a letter or a space, deleted.
                  Every quote, angle bracket, semicolon, percent-escape, every
                  `1=1` and every `../`.
  -syntax -vocab  additionally, every word in `corpus/payloads.json` -- `script`,
                  `select`, `union`, `passwd`, `etc`, `alert`, `onerror` and 397
                  others. Nothing recognisable as an injection survives this.

The second condition alone is not the experiment, and reporting it alone would
be misleading: deleting punctuation from `<script>alert(1)</script>` leaves
`script alert script`, which is still the attack. The reference corpora keep 96% and 88% of their
above-chance separation there, and that number says only that punctuation was
never the sole carrier. The third condition is the one that means something, because after it
the injected span holds no information at all.

The reading is then direct. A corpus still separable at condition three is
separable by something that is not the attack -- and whatever that something is,
a detector trained on it has learned the corpus, not the threat. A corpus that
falls to chance was carrying its signal in the injection.

Two panels ship, and neither is "the real one". They answer different
questions and the honest reading needs both.

  pool       the deletion vocabulary is one fixed list -- every alphabetic token
             in `corpus/payloads.json` -- applied identically to all three
             corpora. It is exhaustive on this corpus by construction and only
             partial on the others, because it can only delete attack words this
             corpus happens to know. It therefore measures the UPPER BOUND on
             what a complete deletion removes, and it flatters our conclusion:
             it deletes 44% of our characters and 20%/15% of CSIC's and ECML's.

  symmetric  the deletion vocabulary is derived independently for each corpus
             from its OWN training attack rows -- a token is deleted when it is
             at least 5x more likely to appear in an attack row than a benign
             one. Deletion aggression is then matched across corpora rather than
             assumed, which is the control a reviewer builds first.

The symmetric panel is less favourable to this corpus, and that is reported
rather than buried: under it WebInject2026 retains more of its separation than
ECML/PKDD-2007 does. The defensible claim spans both panels -- CSIC-2010 retains
the most under either, and this corpus retains between a fifth and two thirds
depending on how completely the injection can be removed.

One caveat is measurable here and nowhere else, and it matters for reading the
symmetric panel. Matched deletion *aggression* is not matched deletion
*completeness*: a 5x-lift rule is a statistic, not ground truth, so it leaves
injection residue behind. On this corpus that residue can be quantified, because
each attack has a twin identical but for the injected span. With the pool
vocabulary deleted, a model scores an attack above its own twin 51% of the time
-- chance, so nothing of the injection survives. With the symmetric vocabulary
deleted it still manages 80%, so a fifth to a third of the injection is still
there. Part of the higher retention under the symmetric panel is therefore
incomplete deletion rather than non-injection signal. Neither corpus without
pairs can be checked this way, which is why both panels ship rather than one.

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
from collections import Counter
import warnings

import numpy as np
import pandas as pd

warnings.filterwarnings("ignore")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import f1_score, roc_auc_score
from sklearn.model_selection import train_test_split

from src import checksums as S  # noqa: E402
from src.vocab import is_injective  # noqa: E402

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



VOCAB_LIFT = 5.0


def derive_vocab(text, y, tr, lift=None, guard=True):
    """Tokens a corpus's own training attacks over-use, relative to its benigns.

    Presence per row, not frequency: a token counts once however often it occurs
    in a row, so a single repeated word cannot dominate. A token is deleted when

        P(token | attack row) >= VOCAB_LIFT * P(token | benign row)

    with add-one smoothing on the benign side so a token absent from every benign
    row is not automatically admitted on a single attack occurrence.

    Derived from TRAIN rows only, then applied to train and test alike, so the
    deletion cannot leak test-set information into the fit.

    Benign rows containing literal injection syntax are excluded from the benign
    denominator: such a row is not evidence that a token is non-injective. This
    corpus ships an `ambiguous` benign tier built to carry real attack syntax and
    the comparison corpora do not, so without this exclusion the estimator
    declines to delete this corpus's own injection vocabulary while harvesting
    theirs, and the panel penalises the corpus for the property it was built to
    have. The guard is `vocab.is_injective` and it is applied identically to all
    three corpora -- there is no corpus-specific branch. See
    `docs/panel-b-correction.md` for the specification and the measured defect.
    """
    lift = VOCAB_LIFT if lift is None else lift
    tt, ty = text[tr], y[tr]
    if guard:
        injective = np.fromiter((is_injective(s) for s in tt), bool, len(tt))
        use = (ty == 1) | ~injective
        tt, ty = tt[use], ty[use]
    na = max(1, int(ty.sum()))
    nb = max(1, int((1 - ty).sum()))
    ca, cb = Counter(), Counter()
    for s, lab in zip(tt, ty):
        toks = {w.lower() for w in WORD.findall(s)}
        (ca if lab == 1 else cb).update(toks)
    return {w for w, n in ca.items()
            if n / na >= lift * ((cb.get(w, 0) + 1) / nb)}


def vocab_recall(vocab, text, pool):
    """Deletion completeness: share of the injection vocabulary actually deleted.

    Ground truth is the payload pool restricted to terms the corpus actually
    contains. For WebInject2026 that is exact -- the pool is where its payloads
    came from. For CSIC-2010 and ECML/PKDD-2007 it is a proxy that can only name
    attack words this corpus happens to know, so their true vocabularies are
    larger than the denominator and the real recall is lower than reported.
    """
    present = {w.lower() for s in text for w in WORD.findall(str(s))}
    gt = pool & present
    if not gt:
        return None, 0
    return len(vocab & gt) / len(gt), len(gt)


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


def lift_sweep(lifts=(2.0, 5.0, 10.0, 20.0)):
    """Panel B under a range of lift thresholds, per `docs/panel-b-correction.md`.

    Reported so that the headline threshold is visibly not a tuned choice. The
    rule was fixed before this was run; the sweep is a sensitivity report, not a
    selection procedure.
    """
    pool = pool_words()
    out = []
    for key, label in CORPORA:
        d, tr, te = _load(key)
        if d is None:
            continue
        text = d["payload"].astype(str)
        y = d["label"].to_numpy()
        full, _ = _fit(text[tr], y[tr], text[te], y[te])
        base = full["roc_auc"] - 0.5
        for lift in lifts:
            vocab = derive_vocab(text, y, tr, lift=lift)
            deleted = text.map(lambda s: strip_vocab(s, vocab))
            m, _ = _fit(deleted[tr], y[tr], deleted[te], y[te])
            recall, _ = vocab_recall(vocab, text, pool)
            out.append({"corpus": label, "lift": float(lift),
                        "vocab_size": len(vocab),
                        "vocab_recall": recall,
                        "roc_auc": m["roc_auc"],
                        "auc_retained": (float((m["roc_auc"] - 0.5) / base)
                                         if base > 0 else float("nan"))})
    return out


def run(fast=False, panel="pool"):
    """One panel of Table 4. `panel` selects where the deleted vocabulary comes
    from: the fixed payload pool, or each corpus's own training attacks."""
    pool = pool_words()
    rows = []
    for key, label in CORPORA:
        d, tr, te = _load(key)
        if d is None:
            print(f"  {label}: not present, skipped")
            continue
        text = d["payload"].astype(str)
        y = d["label"].to_numpy()
        vocab = pool if panel == "pool" else derive_vocab(text, y, tr)
        conds = {"full": text,
                 "syntax_deleted": text.map(strip_syntax),
                 "syntax_and_vocab_deleted": text.map(lambda s: strip_vocab(s, vocab))}

        recall, gt_n = vocab_recall(vocab, text, pool)
        rec = {"corpus": label, "panel": panel, "n": int(len(d)),
               "base_rate": float(y.mean()), "vocab_size": len(vocab),
               "vocab_recall": recall, "vocab_gt_n": gt_n,
               "vocab_gt_exact": key == "webinject2026"}

        # The superseded Panel B estimator, kept so that Section 6.3 can state
        # what the old rule produced without anyone typing the number in. See
        # docs/panel-b-correction.md.
        if panel == "symmetric":
            old_vocab = derive_vocab(text, y, tr, guard=False)
            old_recall, _ = vocab_recall(old_vocab, text, pool)
            old_text = text.map(lambda s: strip_vocab(s, old_vocab))
            old_m, _ = _fit(old_text[tr], y[tr], old_text[te], y[te])
            rec["superseded"] = {
                "rule": "no injection guard on the benign denominator",
                "vocab_size": len(old_vocab),
                "vocab_recall": old_recall,
                "roc_auc": old_m["roc_auc"],
                "f1": old_m["f1"],
            }
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
    ap.add_argument("--panel", default="both",
                    choices=["pool", "symmetric", "both"])
    ap.add_argument("--sweep", action="store_true",
                    help="also run the VOCAB_LIFT sensitivity sweep")
    args = ap.parse_args()

    panels = (["pool", "symmetric"] if args.panel == "both" else [args.panel])
    out = {}
    for panel in panels:
        blurb = ("one fixed list from corpus/payloads.json, applied to all three"
                 if panel == "pool" else
                 "derived per corpus from its own training attacks (>=5x lift)")
        print("=" * 78)
        print(f"Table 4 [{panel}] - performance after deleting the injection")
        print(f"  deleted vocabulary: {blurb}")
        print("  -syntax        every character that is not a letter or a space")
        print("  -syntax -vocab  ... and every word in that vocabulary")
        print("'kept' is AUC above chance, as a share of the full model's")
        print("=" * 78)
        rows = run(fast=args.fast, panel=panel)
        out[panel] = rows
        print(_table(rows))
        print()
        for r in rows:
            b = r["syntax_and_vocab_deleted"]
            print(f"  {r['corpus']:<16} base rate {r['base_rate']:.3f}; vocab "
                  f"{r['vocab_size']:,}; {b['chars_deleted']*100:.0f}% of "
                  f"characters deleted at -syntax -vocab")
            if "paired_accuracy" in b:
                print(f"  {'':<16} matched-pair accuracy with the injection "
                      f"deleted {b['paired_accuracy']*100:.1f}% "
                      f"({b['paired_ties']*100:.1f}% ties) -- chance is 50%")
        print()

    if len(out) > 1:
        print("=" * 78)
        print("Both panels, AUC above chance retained at -syntax -vocab")
        print("=" * 78)
        names = [r["corpus"] for r in out["pool"]]
        print(f"  {'corpus':<18}{'pool':>10}{'symmetric':>12}{'chars del':>22}")
        for name in names:
            p = next(r for r in out["pool"] if r["corpus"] == name)
            q = next(r for r in out["symmetric"] if r["corpus"] == name)
            pk = p["syntax_and_vocab_deleted"]["auc_retained"] * 100
            qk = q["syntax_and_vocab_deleted"]["auc_retained"] * 100
            pc_ = p["syntax_and_vocab_deleted"]["chars_deleted"] * 100
            qc = q["syntax_and_vocab_deleted"]["chars_deleted"] * 100
            print(f"  {name:<18}{pk:>9.0f}%{qk:>11.0f}%"
                  f"{f'{pc_:.0f}% / {qc:.0f}%':>22}")
        print("  The pool panel is the upper bound on what a complete deletion")
        print("  removes; the symmetric panel matches deletion aggression across")
        print("  corpora. Neither alone is the result.")
        # Completeness, not just aggression -- measurable only where pairs exist.
        for pname in ("pool", "symmetric"):
            w = next((r for r in out[pname]
                      if r["corpus"] == "WebInject2026"), None)
            pa = w and w["syntax_and_vocab_deleted"].get("paired_accuracy")
            if pa is not None:
                print(f"  {pname:<10} injection residue check: attack still beats its "
                      f"own twin {pa*100:.0f}% of the time (chance 50%)")
        print("  Matched aggression is not matched completeness: the symmetric rule")
        print("  is a statistic, so it leaves injection behind. Only a paired corpus")
        print("  can measure that, which is part of why both panels ship.")

    if args.sweep:
        print("=" * 78)
        print("VOCAB_LIFT sensitivity, Panel B rule (docs/panel-b-correction.md)")
        print("=" * 78)
        sweep = lift_sweep()
        out["lift_sweep"] = sweep
        print(f"  {'corpus':<18}{'lift':>6}{'vocab':>8}{'recall':>9}{'AUC kept':>10}")
        for r in sweep:
            rc = "n/a" if r["vocab_recall"] is None else f"{r['vocab_recall']*100:.0f}%"
            print(f"  {r['corpus']:<18}{r['lift']:>6.0f}{r['vocab_size']:>8}"
                  f"{rc:>9}{r['auc_retained']*100:>9.0f}%")
        print()

    if args.json:
        payload = out if len(out) > 1 else out[panels[0]]
        if isinstance(payload, dict):
            payload["_corpus"] = S.corpus_fingerprint()
        json.dump(payload, open(args.json, "w"), indent=1)
        print(f"\nwrote {args.json}")


if __name__ == "__main__":
    main()
