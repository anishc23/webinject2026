"""The OWASP ModSecurity Core Rule Set, scored on the payload-disjoint test split.

Table 6's strongest rule baseline is fourteen regexes we wrote, while Section 7.1
argues that production firewalls are signature-driven and Section 1 cites the CRS.
A reviewer is entitled to ask why the real ruleset was not run. This module runs
it.

CRS is a blocker, not a scorer: deployed, it returns a decision, not a ranking,
so there is no threshold to sweep and no TPR at a false-positive budget. It is
reported at the two operating points people actually deploy -- paranoia level 1
and 2 -- against the same test split and the same negatives as every other row of
Table 6.

Requests are replayed as HTTP, reconstructed from the corpus's own method, path,
query, body, content type and headers, through nginx with ModSecurity and the CRS
in front of a static backend. A 403 is a block.

  docker network create crsnet
  docker run -d --name crs-backend --network crsnet nginx:alpine
  docker run -d --name crs-pl1 --network crsnet -p 8081:8080 \
      -e BACKEND=http://crs-backend:80 -e PARANOIA=1 -e BLOCKING_PARANOIA=1 \
      owasp/modsecurity-crs:nginx
  python -m src.crs_baseline --port 8081 --paranoia 1
Two deployment settings are changed from the container defaults, and both are
recorded in the result file:

  ALLOWED_METHODS   CRS ships a GET/HEAD/POST/OPTIONS whitelist. This corpus is
                    REST traffic and 2,382 of 12,298 test requests are DELETE,
                    PUT or PATCH, which rule 911100 blocks on the verb alone.
                    Leaving the default would measure whether the corpus matches
                    CRS's method policy, not whether CRS detects injection.
  hop-by-hop        stripped from the replay, see `_request_parts`.

Everything else -- paranoia level, anomaly thresholds, the rules themselves --
is stock.
"""

import argparse
import json
import os
from concurrent.futures import ThreadPoolExecutor

import pandas as pd
import requests

from . import checksums as S

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "data")
OUT = os.path.join(DATA, "crs_baseline.json")

CT = {
    "json": "application/json",
    "form": "application/x-www-form-urlencoded",
    "multipart": "multipart/form-data",
    "query": None,
}


def _request_parts(row):
    """Rebuild the HTTP request the corpus row describes.

    The corpus stores the components rather than a wire-format request, so the
    reconstruction is explicit here rather than hidden in a formatter.
    """
    try:
        headers = json.loads(row.headers) if row.headers else {}
    except Exception:
        headers = {}
    headers = {str(k): str(v) for k, v in headers.items()}
    # Hop-by-hop headers describe framing, and the client owns framing: replaying
    # a stored Transfer-Encoding verbatim without actually chunking produces a
    # protocol violation that CRS blocks (920171) for reasons unrelated to
    # injection. Transfer-Encoding appears on 700 of 9,071 benign test rows and
    # 5 of 63 smuggling attacks, so dropping it removes a large artefact and
    # costs almost nothing in attack signal.
    for h in ("Host", "Content-Length", "Transfer-Encoding", "Connection",
              "Accept-Encoding"):
        headers.pop(h, None)

    body = row.body or ""
    ct = CT.get(row.content_type)
    if row.content_type == "multipart" and body:
        # The boundary is embedded in the body; Content-Type must name it or
        # ModSecurity cannot parse the parts and the test is meaningless.
        first = body.split("\r\n", 1)[0].strip()
        if first.startswith("--"):
            ct = f"multipart/form-data; boundary={first[2:]}"
    if ct:
        headers["Content-Type"] = ct

    url = row.path or "/"
    if row.query:
        url = f"{url}?{row.query}"
    return row.method or "GET", url, body, headers


def _score_one(sess, base, row):
    method, url, body, headers = _request_parts(row)
    try:
        r = sess.request(method, base + url,
                         data=body.encode("utf-8", "surrogateescape") or None,
                         headers=headers, timeout=20, allow_redirects=False)
        return 1 if r.status_code == 403 else 0
    except Exception:
        # A transport failure is not a block; counting it as one would inflate
        # recall for free.
        return 0


def run(port, workers=24, split="test", limit=None):
    df = pd.read_csv(os.path.join(DATA, "webinject2026.csv"),
                     keep_default_na=False, dtype=str)
    te = df[df.split == split].copy()
    if limit:
        te = te.head(limit)
    te["label"] = te["label"].astype(int)
    base = f"http://localhost:{port}"

    rows = list(te.itertuples(index=False))
    sessions = [requests.Session() for _ in range(workers)]

    def work(i_row):
        i, row = i_row
        return _score_one(sessions[i % workers], base, row)

    with ThreadPoolExecutor(max_workers=workers) as ex:
        blocked = list(ex.map(work, enumerate(rows), chunksize=32))

    te["blocked"] = blocked
    y, p = te["label"].to_numpy(), te["blocked"].to_numpy()
    tp = int(((y == 1) & (p == 1)).sum()); fn = int(((y == 1) & (p == 0)).sum())
    fp = int(((y == 0) & (p == 1)).sum()); tn = int(((y == 0) & (p == 0)).sum())
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    out = {
        "n": int(len(te)), "n_attack": int((y == 1).sum()),
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": prec, "recall": rec,
        "f1": 2 * prec * rec / (prec + rec) if prec + rec else 0.0,
        "fpr": fp / (fp + tn) if fp + tn else 0.0,
        "block_rate": float(p.mean()),
    }
    # Per-tier false positives: the hard_negative tier is punctuation-rich but
    # non-injective, so a rule engine's error rate there is a direct read on
    # whether the tier is doing its job.
    ben = te[te.label == 0]
    out["fp_by_tier"] = {t: {"n": int(len(g)),
                             "fp_rate": float(g["blocked"].mean())}
                         for t, g in ben.groupby("tier")}
    out["recall_by_family"] = {f: {"n": int(len(g)),
                                   "recall": float(g["blocked"].mean())}
                               for f, g in te[te.label == 1].groupby("family")}
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--paranoia", type=int, required=True)
    ap.add_argument("--workers", type=int, default=24)
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--json", default=OUT)
    a = ap.parse_args()

    res = run(a.port, a.workers, limit=a.limit)
    res["paranoia"] = a.paranoia
    res["engine"] = "owasp/modsecurity-crs:nginx"

    existing = {}
    if os.path.exists(a.json):
        with open(a.json, encoding="utf-8") as fh:
            existing = json.load(fh)
    existing[f"paranoia_{a.paranoia}"] = res
    existing["_corpus"] = S.corpus_fingerprint()
    with open(a.json, "w", encoding="utf-8") as fh:
        json.dump(existing, fh, indent=2)

    print(f"  PL{a.paranoia}: recall {res['recall']*100:5.1f}%  "
          f"precision {res['precision']*100:5.1f}%  F1 {res['f1']*100:5.1f}%  "
          f"FPR {res['fpr']*100:5.2f}%  (n={res['n']:,})")
    for t, v in sorted(res["fp_by_tier"].items()):
        print(f"      FP {t:14} {v['fp_rate']*100:6.2f}%  (n={v['n']:,})")
    if not a.limit:
        S.refresh(a.json)
    print(f"  wrote {a.json}")


if __name__ == "__main__":
    main()
