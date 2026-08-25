"""Does the deletion ablation survive a stronger model than logistic regression?

    python -m src.ablation_models --model cnn
    python -m src.ablation_models --model bert
    python -m src.ablation_models --model cnn --json data/ablation_models.json

`src.syntax_ablation` runs the paper's central experiment with one model: char
3-5 grams into logistic regression. That invites an obvious objection. If
CSIC-2010 keeps 94% of its above-chance separation after every injection
character and word is deleted, perhaps that says something about linear models
on tf-idf rather than about the corpus -- and, symmetrically, perhaps this
corpus's fall to 21% is a weak model failing rather than a corpus with nothing
left to find.

This module answers that by rerunning the identical three conditions with two
non-linear models: a character CNN and a fine-tuned transformer encoder. The
deletion functions are imported from `src.syntax_ablation` rather than
reimplemented, so the text each model sees is byte-identical to the text the
logistic regression saw. Only the classifier changes.

The conditions, unchanged:

  full            the payload as shipped
  -syntax         every character that is not a letter or a space, deleted
  -syntax -vocab  additionally every word in the payload pool

and the reported quantity is the same AUC-kept ratio, (AUC - 0.5) / (AUC_full -
0.5), so the numbers drop straight into Table 1's frame. A lower value is
better: it means less of the detector survived losing the attack.

Budgets. The CNN trains on the full split for every corpus. The transformer is
capped at TRANSFORMER_CAP training rows because nine fine-tunes at full data is
hours of compute for a control, and the question here is whether the label is
recoverable at all rather than how well. A cap can only understate recovery, so
it is the conservative direction for the claim being tested.
"""

import argparse
import json
import os
import time

import numpy as np
import torch
import torch.nn as nn
from sklearn.metrics import f1_score, roc_auc_score

from . import checksums as S
from .syntax_ablation import (CORPORA, _load, derive_vocab, pool_words,
                              strip_syntax, strip_vocab)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "data")

SEED = 42
DEVICE = "cuda" if torch.cuda.is_available() else "cpu"

MAX_CHARS = 400
TRANSFORMER_CAP = 20_000
TRANSFORMER_MODEL = "distilbert-base-uncased"


def _seed_everything(seed=SEED):
    import random
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    torch.cuda.manual_seed_all(seed)


# ------------------------------------------------------------------- CNN -----
class CharCNN(nn.Module):
    """Character CNN in the shape the applied literature uses for this task.

    Byte-level embedding, parallel convolutions at three widths, max-over-time
    pooling, dropout, linear. Deliberately ordinary: the point is to test the
    corpora with a non-linear model, not to win a benchmark with a novel one.
    """

    def __init__(self, vocab=257, emb=32, filters=128, widths=(3, 4, 5)):
        super().__init__()
        self.emb = nn.Embedding(vocab, emb, padding_idx=0)
        self.convs = nn.ModuleList(
            [nn.Conv1d(emb, filters, w, padding=w // 2) for w in widths])
        self.drop = nn.Dropout(0.3)
        self.fc = nn.Linear(filters * len(widths), 1)

    def forward(self, x):
        h = self.emb(x).transpose(1, 2)
        h = torch.cat([torch.relu(c(h)).max(dim=2).values for c in self.convs], 1)
        return self.fc(self.drop(h)).squeeze(1)


def _encode_bytes(texts, max_chars=MAX_CHARS):
    """UTF-8 bytes, offset by one so that 0 stays free as the padding index."""
    out = np.zeros((len(texts), max_chars), dtype=np.int64)
    for i, t in enumerate(texts):
        b = str(t).encode("utf-8", "ignore")[:max_chars]
        out[i, :len(b)] = np.frombuffer(b, dtype=np.uint8) + 1
    return out


def _fit_cnn(tr_text, tr_y, te_text, te_y, epochs=4, bs=256):
    _seed_everything()
    Xtr = torch.from_numpy(_encode_bytes(tr_text))
    ytr = torch.tensor(np.asarray(tr_y), dtype=torch.float32)
    Xte = torch.from_numpy(_encode_bytes(te_text))

    model = CharCNN().to(DEVICE)
    opt = torch.optim.AdamW(model.parameters(), lr=1e-3)
    lossf = nn.BCEWithLogitsLoss()

    n = len(Xtr)
    for _ in range(epochs):
        model.train()
        perm = torch.randperm(n)
        for i in range(0, n, bs):
            idx = perm[i:i + bs]
            opt.zero_grad()
            loss = lossf(model(Xtr[idx].to(DEVICE)), ytr[idx].to(DEVICE))
            loss.backward()
            opt.step()

    model.eval()
    scores = []
    with torch.no_grad():
        for i in range(0, len(Xte), 512):
            scores.append(torch.sigmoid(
                model(Xte[i:i + 512].to(DEVICE))).cpu().numpy())
    return np.concatenate(scores)


# ----------------------------------------------------------- transformer -----
def _fit_bert(tr_text, tr_y, te_text, te_y, epochs=2, bs=32, max_len=128):
    from transformers import (AutoModelForSequenceClassification,
                              AutoTokenizer)
    _seed_everything()
    tok = AutoTokenizer.from_pretrained(TRANSFORMER_MODEL)
    model = AutoModelForSequenceClassification.from_pretrained(
        TRANSFORMER_MODEL, num_labels=2).to(DEVICE)

    def batches(texts, labels, shuffle):
        idx = np.arange(len(texts))
        if shuffle:
            rng = np.random.default_rng(SEED)
            rng.shuffle(idx)
        for i in range(0, len(idx), bs):
            j = idx[i:i + bs]
            enc = tok([str(texts[k]) for k in j], truncation=True,
                      max_length=max_len, padding=True, return_tensors="pt")
            yield ({k: v.to(DEVICE) for k, v in enc.items()},
                   torch.tensor([labels[k] for k in j]).to(DEVICE)
                   if labels is not None else None)

    opt = torch.optim.AdamW(model.parameters(), lr=3e-5)
    tr_text = list(tr_text)
    tr_y = list(tr_y)
    for _ in range(epochs):
        model.train()
        for enc, y in batches(tr_text, tr_y, True):
            opt.zero_grad()
            out = model(**enc, labels=y)
            out.loss.backward()
            opt.step()

    model.eval()
    scores = []
    te_text = list(te_text)
    with torch.no_grad():
        for enc, _ in batches(te_text, None, False):
            logits = model(**enc).logits
            scores.append(torch.softmax(logits, -1)[:, 1].cpu().numpy())
    return np.concatenate(scores)


# ------------------------------------------------------------------ run ------
def _metrics(y, p):
    return {"f1": float(f1_score(y, (p >= 0.5).astype(int), zero_division=0)),
            "roc_auc": float(roc_auc_score(y, p))}


def _kept(auc_del, auc_full):
    denom = auc_full - 0.5
    return float((auc_del - 0.5) / denom) if denom > 1e-9 else float("nan")


def run(model_name="cnn", panel="pool", only=None, on_corpus=None,
        conditions=None, cap_override=None):
    pool = pool_words()
    fit = _fit_cnn if model_name == "cnn" else _fit_bert
    cap = None if model_name == "cnn" else (cap_override or TRANSFORMER_CAP)

    # Our own corpus first. A transformer sweep is long enough that it may not
    # survive the session, and this is the row the paper cannot do without.
    corpora = sorted(CORPORA, key=lambda kv: kv[0] != "webinject2026")
    if only:
        corpora = [(k, l) for k, l in corpora if l in only or k in only]

    results = []
    for key, label in corpora:
        d, tr, te = _load(key)
        if d is None:
            print("  skip %s (not present)" % label)
            continue

        text = d["payload"].astype(str).to_numpy()
        y = d["label"].to_numpy().astype(int)

        if cap is not None and tr.sum() > cap:
            # Stratified cap. Subsampling can only lower recovery, so it is the
            # conservative direction for a control that asks whether the label
            # survives deletion at all.
            rng = np.random.default_rng(SEED)
            idx = np.flatnonzero(tr)
            pos = idx[y[idx] == 1]
            neg = idx[y[idx] == 0]
            share = cap / len(idx)
            keep = np.concatenate([
                rng.choice(pos, max(1, int(len(pos) * share)), replace=False),
                rng.choice(neg, max(1, int(len(neg) * share)), replace=False)])
            tr = np.zeros(len(d), bool)
            tr[keep] = True

        vocab = (pool if panel == "pool"
                 else derive_vocab(text, y, tr))

        all_conditions = {
            "full": text,
            "syntax_deleted": np.array([strip_syntax(s) for s in text]),
            "syntax_and_vocab_deleted": np.array(
                [strip_vocab(s, vocab) for s in text]),
        }
        # `syntax_deleted` is the expensive one to skip: the paper reports AUC
        # kept under `syntax_and_vocab_deleted` against the `full` denominator,
        # and never quotes the middle condition for these models.
        wanted = {c: t for c, t in all_conditions.items()
                  if not conditions or c in conditions}

        row = {"corpus": label, "model": model_name, "panel": panel,
               "n": int(len(d)), "n_train": int(tr.sum()),
               "vocab_size": len(vocab)}
        for cond, txt in wanted.items():
            t0 = time.time()
            p = fit(txt[tr], y[tr], txt[te], y[te])
            row[cond] = _metrics(y[te], p)
            row[cond]["seconds"] = round(time.time() - t0, 1)
            print("    %-24s %-24s AUC %.4f  F1 %.4f  (%ds)"
                  % (label, cond, row[cond]["roc_auc"], row[cond]["f1"],
                     row[cond]["seconds"]))

        full_auc = row["full"]["roc_auc"]
        for cond in ("syntax_deleted", "syntax_and_vocab_deleted"):
            if cond in row:
                row[cond]["auc_retained"] = _kept(row[cond]["roc_auc"],
                                                  full_auc)
        results.append(row)

        # Checkpoint after every corpus. A transformer run is long, and losing
        # a completed corpus because a later one died is avoidable.
        if on_corpus:
            on_corpus(results)

    return results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="cnn", choices=["cnn", "bert"])
    ap.add_argument("--panel", default="pool", choices=["pool", "symmetric"])
    ap.add_argument("--corpus", default=None,
                    help="comma-separated subset, e.g. WebInject2026")
    ap.add_argument("--conditions", default=None,
                    help="comma-separated subset of full,syntax_deleted,"
                         "syntax_and_vocab_deleted")
    ap.add_argument("--cap", type=int, default=None,
                    help="override TRANSFORMER_CAP training rows")
    ap.add_argument("--json", default=os.path.join(DATA,
                                                   "ablation_models.json"))
    a = ap.parse_args()

    def save(rows):
        """Merge this model's finished corpora into the file, by corpus name,
        so a partial run adds to what is there instead of replacing it."""
        existing = {}
        if os.path.exists(a.json):
            with open(a.json, encoding="utf-8") as fh:
                existing = json.load(fh)
        by_corpus = {r["corpus"]: r for r in existing.get(a.model, [])}
        by_corpus.update({r["corpus"]: r for r in rows})
        existing[a.model] = list(by_corpus.values())
        existing["_corpus"] = S.corpus_fingerprint()
        with open(a.json, "w", encoding="utf-8") as fh:
            json.dump(existing, fh, indent=2)
        S.refresh(a.json)
        print("      checkpointed %d corpus/corpora -> %s"
              % (len(by_corpus), os.path.basename(a.json)))

    print("device: %s   model: %s   panel: %s" % (DEVICE, a.model, a.panel))
    only = a.corpus.split(",") if a.corpus else None
    conds = a.conditions.split(",") if a.conditions else None
    rows = run(a.model, a.panel, only=only, on_corpus=save,
               conditions=conds, cap_override=a.cap)

    save(rows)
    print("\nwrote %s" % a.json)

    print("\n%-16s %-8s %10s %10s %10s" % ("corpus", "model", "full", "-syn-voc",
                                           "AUC kept"))
    for r in rows:
        sv = r["syntax_and_vocab_deleted"]
        print("%-16s %-8s %10.3f %10.3f %9.0f%%"
              % (r["corpus"], r["model"], r["full"]["roc_auc"], sv["roc_auc"],
                 100 * sv["auc_retained"]))


if __name__ == "__main__":
    main()
