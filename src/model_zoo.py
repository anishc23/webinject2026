"""Ten reference detectors across three model families, on the same splits.

    python -m src.model_zoo --tier classical          # 4 models, minutes
    python -m src.model_zoo --tier deep               # 3 models, needs torch
    python -m src.model_zoo --tier transformer        # 3 models, needs a GPU/MPS
    python -m src.model_zoo --tier all --json data/model_zoo.json

Run the tiers as separate processes. XGBoost's OpenMP pool and torch's MPS
backend deadlock when initialised in the same interpreter -- `--tier all` will
hang after the classical tier on Apple silicon.

A benchmark that only reports one model cannot tell a reader whether a result is
a property of the corpus or of the model. This runs the same protocol over

  classical    logistic regression, random forest, linear SVM, XGBoost
               (char 3-5 gram TF-IDF features)
  deep         char-CNN, LSTM, BiLSTM (learned character embeddings)
  transformer  DistilBERT, RoBERTa, DeBERTa-v3 (fine-tuned)

and, for every one of them, repeats the two ablations that matter:

  carrier_auc      the register test -- delete all punctuation and every word
                   occurring in the payload pool, then try to predict the label
                   from the ordinary words left. Near 0.5 means the model cannot
                   be reading benign register instead of the injection.
  paired_accuracy  share of matched pairs where the model scores the attack
                   above its own benign twin, which differ only by the injected
                   span. Near 1.0 means the decision tracks the injection.

Reporting a strong headline number without those two is what this corpus exists
to make unnecessary.
"""

import argparse
import json
import os
import re
import sys
import time
import warnings
from collections import Counter

import numpy as np
import pandas as pd

warnings.filterwarnings("ignore")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (average_precision_score, f1_score, precision_score,
                             recall_score, roc_auc_score, roc_curve)
from sklearn.svm import LinearSVC

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "data")
WORD = re.compile(r"[A-Za-z]{2,}")

PROTOCOLS = ("random", "payload-disjoint", "structural")


# ------------------------------------------------------------------ metrics --
def _tpr_at_fpr(y, score, budget):
    fpr, tpr, _ = roc_curve(y, score)
    ok = fpr <= budget
    return float(tpr[ok].max()) if ok.any() else 0.0


def _metrics(y, score):
    y = np.asarray(y)
    pred = (score >= 0.5).astype(int)
    return {
        "f1": float(f1_score(y, pred, zero_division=0)),
        "precision": float(precision_score(y, pred, zero_division=0)),
        "recall": float(recall_score(y, pred, zero_division=0)),
        "roc_auc": float(roc_auc_score(y, score)),
        "pr_auc": float(average_precision_score(y, score)),
        "tpr_at_1pct_fpr": _tpr_at_fpr(y, score, 0.01),
        "tpr_at_0.1pct_fpr": _tpr_at_fpr(y, score, 0.001),
    }


def _paired_accuracy(te, score):
    """Share of matched pairs scored in the right order."""
    t = te.assign(_s=score)
    t = t[t.pair_id.astype(str) != ""]
    if t.empty:
        return None
    piv = t.pivot_table(index="pair_id", columns="label", values="_s",
                        aggfunc="first").dropna()
    if piv.empty or 0 not in piv.columns or 1 not in piv.columns:
        return None
    return float((piv[1] > piv[0]).mean())


# ------------------------------------------------------------------- splits --
def splits(df, protocol, seed=42):
    if protocol == "random":
        rng = np.random.default_rng(seed)
        idx = rng.permutation(len(df))
        cut = int(0.8 * len(df))
        tr = df.iloc[idx[:cut]]
        te = df.iloc[idx[cut:]]
        return tr, te
    col = "split_struct" if protocol == "structural" else "split"
    return df[df[col] == "train"], df[df[col] == "test"]


def carrier_text(df):
    """Payload with all punctuation and all payload-pool words removed."""
    pool = json.load(open(os.path.join(ROOT, "corpus", "payloads.json")))
    atk = set()
    for payloads in pool.values():
        for p in payloads:
            atk |= {w.lower() for w in WORD.findall(p)}
    return df["payload"].map(
        lambda s: " ".join(w for w in (t.lower() for t in WORD.findall(str(s)))
                           if w not in atk))


# ------------------------------------------------------- classical models ----
def _tfidf(tr_text, te_text):
    v = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=3,
                        max_features=200000)
    return v.fit_transform(tr_text), v.transform(te_text), v


def _classical(name):
    def run(tr, te):
        Xtr, Xte, _ = _tfidf(tr.payload.astype(str), te.payload.astype(str))
        if name == "LogisticRegression":
            m = LogisticRegression(max_iter=2000, C=4.0)
        elif name == "RandomForest":
            m = RandomForestClassifier(n_estimators=300, n_jobs=-1,
                                       random_state=42, min_samples_leaf=2)
        elif name == "LinearSVM":
            m = LinearSVC(C=0.5)
        else:
            from xgboost import XGBClassifier
            m = XGBClassifier(n_estimators=400, max_depth=8, learning_rate=0.2,
                              n_jobs=-1, tree_method="hist", eval_metric="logloss")
        m.fit(Xtr, tr.label)
        if hasattr(m, "predict_proba"):
            return m.predict_proba(Xte)[:, 1]
        d = m.decision_function(Xte)          # LinearSVM: map to (0,1)
        return 1.0 / (1.0 + np.exp(-d))
    return run


# ------------------------------------------------------------ deep models ----
def _deep(kind, epochs=3, max_len=256, batch=128):
    """Character-level CNN / LSTM / BiLSTM."""
    def run(tr, te):
        import torch
        import torch.nn as nn
        dev = ("mps" if torch.backends.mps.is_available()
               else "cuda" if torch.cuda.is_available() else "cpu")

        chars = Counter()
        for s in tr.payload.astype(str):
            chars.update(s[:max_len])
        vocab = {c: i + 2 for i, (c, _) in enumerate(chars.most_common(200))}

        def enc(series):
            out = np.zeros((len(series), max_len), dtype=np.int64)
            for i, s in enumerate(series.astype(str)):
                for j, c in enumerate(s[:max_len]):
                    out[i, j] = vocab.get(c, 1)
            return torch.from_numpy(out)

        Xtr, Xte = enc(tr.payload), enc(te.payload)
        ytr = torch.tensor(tr.label.to_numpy(), dtype=torch.float32)

        class Net(nn.Module):
            def __init__(self):
                super().__init__()
                self.emb = nn.Embedding(len(vocab) + 2, 64, padding_idx=0)
                if kind == "CNN":
                    self.enc = nn.Sequential(
                        nn.Conv1d(64, 128, 5, padding=2), nn.ReLU(),
                        nn.AdaptiveMaxPool1d(1))
                    self.head = nn.Linear(128, 1)
                else:
                    self.rnn = nn.LSTM(64, 96, batch_first=True,
                                       bidirectional=(kind == "BiLSTM"))
                    self.head = nn.Linear(96 * (2 if kind == "BiLSTM" else 1), 1)

            def forward(self, x):
                e = self.emb(x)
                if kind == "CNN":
                    h = self.enc(e.transpose(1, 2)).squeeze(-1)
                else:
                    o, _ = self.rnn(e)
                    h = o.max(dim=1).values
                return self.head(h).squeeze(-1)

        torch.manual_seed(42)
        net = Net().to(dev)
        opt = torch.optim.AdamW(net.parameters(), lr=2e-3)
        lossf = nn.BCEWithLogitsLoss()
        n = len(Xtr)
        for _ in range(epochs):
            net.train()
            perm = torch.randperm(n)
            for i in range(0, n, batch):
                sel = perm[i:i + batch]
                xb, yb = Xtr[sel].to(dev), ytr[sel].to(dev)
                opt.zero_grad()
                loss = lossf(net(xb), yb)
                loss.backward()
                opt.step()
        net.eval()
        outs = []
        with torch.no_grad():
            for i in range(0, len(Xte), 512):
                outs.append(torch.sigmoid(net(Xte[i:i + 512].to(dev))).cpu().numpy())
        return np.concatenate(outs)
    return run


# ----------------------------------------------------- transformer models ----
HF_IDS = {
    "DistilBERT": "distilbert-base-uncased",
    "RoBERTa": "roberta-base",
    "DeBERTa": "microsoft/deberta-v3-base",
}


def _transformer(name, epochs=1, max_len=128, batch=32, lr=3e-5, clip=1.0):
    def run(tr, te):
        import torch
        from torch.utils.data import DataLoader, TensorDataset
        from transformers import (AutoModelForSequenceClassification,
                                  AutoTokenizer)
        dev = ("mps" if torch.backends.mps.is_available()
               else "cuda" if torch.cuda.is_available() else "cpu")
        tok = AutoTokenizer.from_pretrained(HF_IDS[name])
        model = AutoModelForSequenceClassification.from_pretrained(
            HF_IDS[name], num_labels=2).to(dev)

        def batches(texts, labels=None, shuffle=False):
            e = tok(list(texts), truncation=True, max_length=max_len,
                    padding="max_length", return_tensors="pt")
            parts = [e["input_ids"], e["attention_mask"]]
            if labels is not None:
                parts.append(torch.tensor(np.asarray(labels), dtype=torch.long))
            return DataLoader(TensorDataset(*parts), batch_size=batch,
                              shuffle=shuffle)

        opt = torch.optim.AdamW(model.parameters(), lr=lr)
        model.train()
        for _ in range(epochs):
            for b in batches(tr.payload.astype(str), tr.label.to_numpy(), True):
                ids, am, y = (t.to(dev) for t in b)
                opt.zero_grad()
                out = model(input_ids=ids, attention_mask=am, labels=y)
                out.loss.backward()
                # DeBERTa-v3's disentangled attention diverges to NaN in fp32 on
                # the Metal backend without this; harmless for the others.
                torch.nn.utils.clip_grad_norm_(model.parameters(), clip)
                opt.step()
        model.eval()
        outs = []
        with torch.no_grad():
            for b in batches(te.payload.astype(str)):
                ids, am = (t.to(dev) for t in b)
                logits = model(input_ids=ids, attention_mask=am).logits
                outs.append(torch.softmax(logits, -1)[:, 1].cpu().numpy())
        out = np.concatenate(outs)
        if not np.isfinite(out).all():
            raise RuntimeError(
                f"{name} produced non-finite scores on {dev}; this is a known "
                f"DeBERTa-v3/Metal fp32 issue. Re-run this model on CUDA or CPU.")
        return out
    return run


TIERS = {
    "classical": [(n, _classical(n)) for n in
                  ("LogisticRegression", "RandomForest", "LinearSVM", "XGBoost")],
    "deep": [(n, _deep(n)) for n in ("CNN", "LSTM", "BiLSTM")],
    "transformer": [(n, _transformer(n, lr=1e-5 if n == "DeBERTa" else 3e-5))
                    for n in HF_IDS],
}


# ------------------------------------------------------------------- driver --
def _cap(tr, n):
    """Class-stratified subsample of the training split.

    Fine-tuning a transformer on the full 43k rows costs ~44 min per epoch on
    Apple MPS, so a ten-model sweep is ~9 hours. Capping the training set makes
    the sweep tractable -- and every tier is run at the same cap, so the
    comparison stays like-for-like. Uncapped numbers for the classical and deep
    tiers are reported separately; a full-data transformer sweep wants CUDA.
    """
    if not n or n >= len(tr):
        return tr
    frac = n / len(tr)
    parts = [g.sample(n=max(1, int(round(len(g) * frac))), random_state=42)
             for _, g in tr.groupby("label")]
    return pd.concat(parts).sample(frac=1.0, random_state=42)



def evaluate(df, name, fn, protocols=PROTOCOLS, ablate=True, train_cap=None):
    out = {}
    if train_cap:
        out["_train_cap"] = int(train_cap)
    for proto in protocols:
        tr, te = splits(df, proto)
        tr = _cap(tr, train_cap)
        t0 = time.time()
        score = fn(tr, te)
        rec = _metrics(te.label.values, score)
        rec["seconds"] = round(time.time() - t0, 1)
        pa = _paired_accuracy(te, score)
        if pa is not None:
            rec["paired_accuracy"] = pa
        out[proto] = rec
        print(f"  {name:<20}{proto:<18}F1 {rec['f1']*100:5.1f}  "
              f"PR-AUC {rec['pr_auc']*100:5.1f}  TPR@1% {rec['tpr_at_1pct_fpr']*100:5.1f}  "
              f"TPR@0.1% {rec['tpr_at_0.1pct_fpr']*100:5.1f}"
              + (f"  paired {pa*100:5.1f}" if pa is not None else "")
              + f"  [{rec['seconds']}s]")

    if ablate:
        # the cheating check: can this model still separate the classes with
        # every trace of injection syntax deleted?
        c = carrier_text(df)
        tr, te = splits(df, "payload-disjoint")
        tr = _cap(tr, train_cap)
        sub_tr = tr.assign(payload=c.loc[tr.index])
        sub_te = te.assign(payload=c.loc[te.index])
        try:
            s = fn(sub_tr, sub_te)
            out["ablation_carrier_only"] = {
                "roc_auc": float(roc_auc_score(te.label.values, s)),
                "f1": float(f1_score(te.label.values, (s >= 0.5).astype(int),
                                     zero_division=0)),
            }
            print(f"  {name:<20}{'carrier-only ablation':<18}"
                  f"AUC {out['ablation_carrier_only']['roc_auc']:.3f}  "
                  f"F1 {out['ablation_carrier_only']['f1']*100:5.1f}")
        except Exception as e:                       # pragma: no cover
            print(f"  {name:<20}carrier ablation failed: {e}")
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--csv", default=os.path.join(DATA, "webinject2026.csv"))
    ap.add_argument("--tier", default="classical",
                    choices=["classical", "deep", "transformer", "all"])
    ap.add_argument("--models", default=None,
                    help="comma-separated subset of model names")
    ap.add_argument("--protocols", default=",".join(PROTOCOLS))
    ap.add_argument("--no-ablation", action="store_true")
    ap.add_argument("--train-cap", type=int, default=None,
                    help="cap the training split (stratified) for a tractable sweep")
    ap.add_argument("--json", default=None)
    args = ap.parse_args()

    df = pd.read_csv(args.csv, keep_default_na=False, dtype=str)
    df["label"] = df["label"].astype(int)
    protos = tuple(p.strip() for p in args.protocols.split(",") if p.strip())

    tiers = list(TIERS) if args.tier == "all" else [args.tier]
    wanted = set(args.models.split(",")) if args.models else None

    results = {}
    if args.json and os.path.exists(args.json):
        results = json.load(open(args.json))       # accumulate across tiers

    for tier in tiers:
        print("=" * 100)
        print(f"{tier.upper()} TIER")
        print("=" * 100)
        for name, fn in TIERS[tier]:
            if wanted and name not in wanted:
                continue
            try:
                results.setdefault(tier, {})[name] = evaluate(
                    df, name, fn, protos, ablate=not args.no_ablation,
                    train_cap=args.train_cap)
            except Exception as e:
                print(f"  {name:<20}FAILED: {type(e).__name__}: {e}")
                results.setdefault(tier, {})[name] = {"error": str(e)}
            if args.json:
                json.dump(results, open(args.json, "w"), indent=1)

    if args.json:
        json.dump(results, open(args.json, "w"), indent=1)
        print(f"\nwrote {args.json}")


if __name__ == "__main__":
    main()
