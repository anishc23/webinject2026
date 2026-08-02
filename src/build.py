"""Assemble the WebInject2026 corpus.

    python -m src.build                 # offline synthesis (default, reproducible)
    python -m src.build --capture       # replay against live containers, keep 200s
    python -m src.build --n-attack 8000 # override any VOLUME key from the CLI

Pipeline: synthesise records -> (optional) live capture -> normalise -> dedupe on
exact payload -> two grouped splits (payload-disjoint + structural) -> session
assignment -> write CSV + Parquet + manifest.

Difficulty is not decided here; it is measured afterward by `validate.py` (the
gate) and `baselines.py`/`evaluate.py` (the numbers).

What changed in v3
  * Benign traffic is groupable and split-disjoint. Every hard-negative row has
    exactly one *carrier* field holding an enumerated benign core; the core id is
    the row's split group, so a benign phrase never spans train/test. This closes
    the v2.1 leak where 67% of hard-negative test values were seen in training.
  * Headers are drawn INDEPENDENTLY of the label. v2.1 gave every attack
    hard-negative headers and routine benigns plain ones, so header punctuation
    was a free label signal. Now a coin flip (HEADER_PUNCT_RATE) decides, for
    every row regardless of label.
  * A second split column, `split_struct`, holds out whole payload *templates*,
    not just strings — a harder generalisation test.
  * New columns: `content_type`, `template`, `split_struct`, `session`, `status`.
"""

import argparse
import csv
import hashlib
import json
import os
import random
import re
import sys
import time
import urllib.parse
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src import config as C
from src import payloads as P
from src import vocab as V

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "data")
CORPUS = os.path.join(ROOT, "corpus")
PATT_ROOT = os.path.join(DATA, "patt")


# ------------------------------------------------------- record synthesis ---
def _query_string(params):
    return "&".join(f"{k}={urllib.parse.quote_plus(str(v))}" for k, v in params)


def _json_body(params):
    """Serialise body params as a JSON object (values kept as raw strings)."""
    obj = {k: v for k, v in params}
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)


def _graphql_body(params):
    """A GraphQL query whose variables carry the params (search is injectable)."""
    d = {k: v for k, v in params}
    q = ('query($q:String,$first:Int,$orderBy:String){search(q:$q,first:$first,'
         'orderBy:$orderBy){id name}}')
    return json.dumps({"query": q, "variables": d},
                      separators=(",", ":"), ensure_ascii=False)


def _multipart_body(params, boundary):
    """A multipart/form-data body; keeps values raw so injections survive."""
    lines = []
    for k, v in params:
        lines.append(f"--{boundary}")
        if k in ("file",):
            lines.append(f'Content-Disposition: form-data; name="{k}"; '
                         f'filename="{v}"')
            lines.append("Content-Type: application/octet-stream")
            lines.append("")
            lines.append("<<binary>>")
        else:
            lines.append(f'Content-Disposition: form-data; name="{k}"')
            lines.append("")
            lines.append(str(v))
    lines.append(f"--{boundary}--")
    return "\r\n".join(lines)


def _encode_body(ep, params, rng):
    """Return (body_string, content_type_label, boundary)."""
    ct = C.content_type(ep)
    if ct == "json":
        return _json_body(params), "json", None
    if ct == "graphql":
        return _graphql_body(params), "graphql", None
    if ct == "multipart":
        b = "----WebKitFormBoundary" + "".join(
            rng.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=16))
        return _multipart_body(params, b), "multipart", b
    return _query_string(params), "form", None


def _split_qb(ep, params):
    """Partition (name, value) pairs into (query_list, body_list)."""
    body_names = set(ep.get("body", []))
    query, body = [], []
    for name, val in params:
        (body if name in body_names else query).append((name, val))
    return query, body


def _assemble(app, ep, values, rng, extra):
    """Build the transport-level fields shared by every record kind."""
    query, body = _split_qb(ep, values)
    body_str, ct_label, boundary = ("", "query", None)
    if body:
        body_str, ct_label, boundary = _encode_body(ep, body, rng)
    rec = {
        "app": app, "method": ep["method"], "path": ep["path"],
        "query": _query_string(query), "body": body_str,
        "content_type": ct_label,
        "headers": _hdr_json(_headers(app, ep, rng, extra, boundary)),
        "source": "synthetic", "status": "",
    }
    return rec


def _benign_record(app, ep, tier, rng):
    """One benign request. Hard negatives carry exactly one groupable core."""
    carrier = None
    core_id = None
    if tier == "hard_negative":
        text_params = [n for n, t in ep["params"] if t in C.TEXT_TYPES]
        carrier = rng.choice(text_params)
        core_text, core_id = V.core_value(rng)

    values = []
    for name, ftype in ep["params"]:
        if name == carrier:
            values.append((name, core_text))
        else:
            # Non-carrier fields use the (unbounded) tier generator, so only the
            # carrier core can repeat across rows.
            values.append((name, V.value_for(ftype, rng, tier)))

    # Header punctuation is drawn i.i.d. (extra=None) for every row, so it never
    # correlates with tier or label. The tier's difficulty lives in the
    # parameter values, not the headers.
    rec = _assemble(app, ep, values, rng, extra=None)
    rec.update({
        "label": 0, "attack_type": "benign", "family": "benign",
        "tier": tier, "evasion": "none", "placement": "",
        "template": f"benign:{tier}",
        "group": core_id or f"benR-{rng.getrandbits(48):x}",
    })
    return rec


def _ambiguous_record(app, ep, rng):
    """Benign traffic carrying literal attack syntax in a free-text field."""
    text_params = [n for n, t in ep["params"] if t in C.TEXT_TYPES] or ep["inject"]
    target = rng.choice(text_params)
    amb_text, core_id = V.ambiguous_value(rng)
    values = []
    for name, ftype in ep["params"]:
        values.append((name, amb_text if name == target
                       else V.value_for(ftype, rng, "routine")))
    rec = _assemble(app, ep, values, rng, extra=None)
    rec.update({
        "label": 0, "attack_type": "benign", "family": "benign_ambiguous",
        "tier": "ambiguous", "evasion": "none", "placement": "",
        "template": "ambiguous", "group": core_id,
    })
    return rec


def _attack_record(app, ep, pool, rng):
    """One attack request placed at a declared injection point."""
    fams = [f for f in ep["families"] if pool.get(f)]
    # weight the family choice so prevalence roughly matches FAMILY_WEIGHTS
    weights = [C.FAMILY_WEIGHTS.get(f, 1.0) for f in fams]
    fam = rng.choices(fams, weights=weights, k=1)[0]
    raw, template = rng.choice(pool[fam])
    group = P.group_key(raw)

    if rng.random() < C.EVASION_RATE:
        payload, evasion = P.apply_evasion(raw, fam, rng, C.EVASION_CHAIN_RATE)
    else:
        payload, evasion = raw, "none"

    target = rng.choice(ep["inject"])
    body_names = set(ep.get("body", []))
    in_body = target in body_names and rng.random() < 0.9
    in_header = (not in_body) and rng.random() < C.HEADER_INJECTION_RATE \
        and fam in C.HEADER_FAMILIES

    values = []
    for name, ftype in ep["params"]:
        if name == target and not in_header:
            values.append((name, payload))
        else:
            values.append((name, V.value_for(
                ftype, rng, rng.choice(["routine", "hard_negative"]))))

    header_inject = None
    if in_header:
        header_inject = payload
    rec = _assemble(app, ep, values, rng, extra=None, )
    # `extra=None` above means "decide header punctuation by the global coin
    # flip" (see _headers); attacks get no special header treatment — that was
    # the v2.1 leak.
    if in_header:
        hdr = json.loads(rec["headers"])
        if rng.random() < 0.5:
            hdr["User-Agent"] = payload
        else:
            hdr["Referer"] = C.APPS[app]["base"] + "/" + urllib.parse.quote_plus(payload)
        rec["headers"] = _hdr_json(hdr)

    placement = "header" if in_header else ("body" if in_body else "query")
    rec.update({
        "label": 1, "attack_type": fam, "family": fam,
        "tier": "attack", "evasion": evasion, "group": group,
        "template": template, "placement": placement,
    })
    return rec


def _headers(app, ep, rng, extra, boundary=None):
    """Header dict for a record. `extra` selects the header tier:

        True  -> always punctuation-rich (used by ambiguous rows)
        False -> always plain            (used by routine benign rows)
        None  -> decide by the global HEADER_PUNCT_RATE coin flip, INDEPENDENT
                 of the label (used by attacks and hard negatives)

    The `None` path is the v3 fix: header punctuation must not correlate with the
    label, because headers are part of the inspected payload.
    """
    if extra is None:
        punct = rng.random() < C.HEADER_PUNCT_RATE
    else:
        punct = bool(extra)
    tier = "hard_negative" if punct else "routine"

    h = {
        "User-Agent": rng.choice(V.UA_POOL),
        "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
        "Accept-Language": rng.choice(["en-US,en;q=0.9", "es-ES,es;q=0.8",
                                       "de-DE,de;q=0.7", "fr-FR,fr;q=0.6"]),
        "Referer": V.referer(rng, C.APPS[app]["base"], tier),
        "Cookie": V.cookie(rng, tier),
    }
    ct = C.content_type(ep)
    if ct in V.CONTENT_TYPES and V.CONTENT_TYPES[ct]:
        val = V.CONTENT_TYPES[ct]
        h["Content-Type"] = val.format(b=boundary) if boundary else val
    h.update(V.extra_headers(rng, tier))
    return h


def _hdr_json(h):
    return json.dumps(h, separators=(",", ":"), ensure_ascii=False)


def synthesise(pool, volume, rng):
    """Produce the full record list before capture/dedup."""
    endpoints = C.endpoints()
    inject_eps = [(app, ep) for app, ep in endpoints if ep["inject"]]
    recs = []

    def spread(n, gen, pick_from):
        for _ in range(n):
            app, ep = rng.choice(pick_from)
            recs.append(gen(app, ep))

    spread(volume["routine"],
           lambda a, e: _benign_record(a, e, "routine", rng), endpoints)
    spread(volume["hard_negative"],
           lambda a, e: _benign_record(a, e, "hard_negative", rng), endpoints)
    spread(volume["ambiguous"],
           lambda a, e: _ambiguous_record(a, e, rng), inject_eps)
    spread(volume["attack"],
           lambda a, e: _attack_record(a, e, pool, rng), inject_eps)

    rng.shuffle(recs)
    return recs


# --------------------------------------------------------- live capture -----
def capture(recs, drop_5xx=True, pause=0.01):
    """Replay records against live containers; keep those that return 2xx/4xx."""
    import requests
    sessions = _login_sessions(requests)
    kept, redirected = [], 0
    for i, r in enumerate(recs):
        base = C.APPS[r["app"]]["base"]
        url = base + r["path"]
        if r["query"]:
            url += "?" + r["query"]
        hdrs = r["headers"] if isinstance(r["headers"], dict) else json.loads(r["headers"])
        try:
            sess = sessions[r["app"]]
            if r["method"] in C.BODY_METHODS:
                data = dict(urllib.parse.parse_qsl(r["body"])) if r["content_type"] == "form" else None
                fn = getattr(sess, r["method"].lower())
                resp = fn(url, data=data, headers=hdrs, timeout=5,
                          allow_redirects=False)
            else:
                fn = sess.get if r["method"] == "GET" else sess.delete
                resp = fn(url, headers=hdrs, timeout=5, allow_redirects=False)
            r["status"] = resp.status_code
            if resp.status_code == 302:
                redirected += 1
                continue
            if drop_5xx and resp.status_code >= 500:
                continue
            kept.append(r)
        except Exception:
            continue
        if pause:
            time.sleep(pause)
        if (i + 1) % 2000 == 0:
            print(f"    captured {i + 1:,}/{len(recs):,}")
    if redirected:
        print(f"    WARNING: {redirected:,} requests redirected (session lost?)")
    return kept


def _login_sessions(requests):
    import re as _re
    sessions = {}
    for app, cfg in C.APPS.items():
        s = requests.Session()
        login = cfg.get("login")
        if login:
            r = s.get(cfg["base"] + login["url"], timeout=10)
            data = dict(login["data"])
            if login.get("token_re"):
                m = _re.search(login["token_re"], r.text)
                if m:
                    data[login["token_field"]] = m.group(1)
            s.post(cfg["base"] + login["url"], data=data, timeout=10)
            for path, pdata in login.get("post_login", []):
                s.post(cfg["base"] + path, data=pdata, timeout=10)
        sessions[app] = s
    return sessions


# ----------------------------------------------------- normalise + split ----
INSPECTED_HEADERS = ("User-Agent", "Referer", "Cookie", "X-Forwarded-Host",
                     "X-Forwarded-For", "Transfer-Encoding", "Content-Type")


def normalise(rec):
    """Decoded text a detector inspects: request line, body, and key headers."""
    try:
        hdr = json.loads(rec.get("headers") or "{}")
    except Exception:
        hdr = {}
    hdr_text = " ".join(f"{k}: {hdr[k]}" for k in INSPECTED_HEADERS if hdr.get(k))
    parts = [rec["path"], rec["query"], rec.get("body", ""), hdr_text]
    text = urllib.parse.unquote_plus(" ".join(p for p in parts if p).strip())
    text = re.sub(r"[\x00-\x1f\x7f]+", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def finalize(recs, seed):
    rng = random.Random(seed)
    for r in recs:
        r["payload"] = normalise(r)
        r["payload_raw"] = " ".join(x for x in [r["path"], r["query"],
                                                r.get("body", "")] if x).strip()

    recs = [r for r in recs if len(r["payload"]) >= 3]

    # Exact-payload dedup (keep first occurrence).
    seen, uniq = set(), []
    for r in recs:
        fp = hashlib.md5(r["payload"].encode("utf-8", "ignore")).hexdigest()
        if fp not in seen:
            seen.add(fp)
            uniq.append(r)
    dropped = len(recs) - len(uniq)
    recs = uniq

    _assign_split(recs, rng, key="group", col="split")
    _assign_split(recs, rng, key=_struct_key, col="split_struct")
    _assign_sessions(recs, rng)
    return recs, dropped


def _stratum(rec):
    """Splitting stratum: attacks by family, benigns by tier."""
    if rec["label"] == 1:
        return ("attack", rec["attack_type"])
    return ("benign", rec["tier"])


def _struct_key(rec):
    """Grouping key for the structural split.

    Attacks group by template (whole shapes held out); benign rows group exactly
    as in the payload split so benign balance and disjointness are preserved.
    """
    if rec["label"] == 1:
        return rec["template"]
    return rec["group"]


def _assign_split(recs, rng, key, col):
    """Group-disjoint, family/tier-stratified split into `rec[col]`.

    `key` is either a record field name or a callable rec -> group key. Every
    group lives wholly in one split, and each stratum is split ~70/10/20, so the
    attack ratio matches across splits and every family/tier appears in each.
    """
    key_fn = key if callable(key) else (lambda r: r[key])
    strata = {}
    for r in recs:
        strata.setdefault(_stratum(r), {}).setdefault(key_fn(r), []).append(r)

    f = C.SPLIT_FRACTIONS
    for _strat, groups in sorted(strata.items(), key=lambda kv: str(kv[0])):
        keys = sorted(groups, key=str)
        rng.shuffle(keys)
        n = sum(len(groups[k]) for k in keys)
        want = {s: f[s] * n for s in f}
        got = {s: 0 for s in f}
        for k in keys:
            split = max(("train", "val", "test"),
                        key=lambda s: want[s] - got[s])
            for r in groups[k]:
                r[col] = split
            got[split] += len(groups[k])


def _assign_sessions(recs, rng):
    """Chunk rows into synthetic sessions that never span a split.

    Sessions are label-agnostic (a real session may mix normal and malicious
    requests), and are grouped within the payload-disjoint `split` so a session
    id can be used for sequence modelling without leaking across the split. The
    `session_leak` gate asserts session does not predict the label and no session
    spans splits.
    """
    lo, hi = C.SESSION_LEN
    by_split = {}
    for r in recs:
        by_split.setdefault(r["split"], []).append(r)
    sess_no = 0
    for split, rows in sorted(by_split.items()):
        idx = list(range(len(rows)))
        rng.shuffle(idx)
        i = 0
        while i < len(idx):
            n = rng.randint(lo, hi)
            sid = f"s{split[0]}-{sess_no:06d}"
            for j in idx[i:i + n]:
                rows[j]["session"] = sid
            sess_no += 1
            i += n


# ---------------------------------------------------------------- write -----
COLUMNS = ["app", "method", "path", "query", "body", "content_type", "headers",
           "payload", "payload_raw", "label", "attack_type", "family",
           "placement", "tier", "evasion", "source", "status", "session",
           "split", "split_struct", "template", "group"]


def write_csv(recs, path):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=COLUMNS, extrasaction="ignore")
        w.writeheader()
        for r in recs:
            w.writerow({c: r.get(c, "") for c in COLUMNS})


def write_parquet(csv_path, pq_path):
    """Ship a Parquet copy alongside the CSV (smaller, typed, HF-friendly)."""
    try:
        import pandas as pd
    except Exception:
        print("    pandas unavailable; skipping Parquet")
        return False
    try:
        df = pd.read_csv(csv_path, keep_default_na=False, dtype=str)
        df["label"] = df["label"].astype("int8")
        df.to_parquet(pq_path, index=False)
        return True
    except Exception as e:
        print(f"    Parquet write skipped ({e})")
        return False


def write_manifest(recs, dropped, args, path):
    import collections
    man = {
        "name": "WebInject2026",
        "version": C.VERSION,
        "built_utc": datetime.now(timezone.utc).isoformat(),
        "seed": args.seed,
        "capture": args.capture,
        "rows": len(recs),
        "duplicates_removed": dropped,
        "label": dict(collections.Counter(r["label"] for r in recs)),
        "attack_type": dict(collections.Counter(r["attack_type"] for r in recs)),
        "family": dict(collections.Counter(r["family"] for r in recs)),
        "tier": dict(collections.Counter(r["tier"] for r in recs)),
        "content_type": dict(collections.Counter(r["content_type"] for r in recs)),
        "placement": dict(collections.Counter(
            r.get("placement", "") for r in recs if r["label"] == 1)),
        "evasion_used": sum(1 for r in recs if r.get("evasion", "none") != "none"),
        "evasion_chained": sum(1 for r in recs
                               if "+" in str(r.get("evasion", ""))),
        "split": dict(collections.Counter(r["split"] for r in recs)),
        "split_struct": dict(collections.Counter(r["split_struct"] for r in recs)),
        "app": dict(collections.Counter(r["app"] for r in recs)),
        "sessions": len({r["session"] for r in recs}),
    }
    for col in ("split", "split_struct"):
        by_group = {}
        for r in recs:
            gk = r["group"] if col == "split" else _struct_key(r)
            by_group.setdefault((col, gk), set()).add(r[col])
        man[f"groups_spanning_{col}"] = sum(1 for s in by_group.values() if len(s) > 1)

    atk = [r for r in recs if r["label"] == 1]
    test_atk = [r for r in atk if r.get("split") == "test"]
    fam_groups = {}
    for r in test_atk:
        fam_groups.setdefault(r["attack_type"], set()).add(r["group"])
    struct_test_atk = [r for r in atk if r.get("split_struct") == "test"]
    man["groups"] = {
        "attack_total": len({r["group"] for r in atk}),
        "attack_test": len({r["group"] for r in test_atk}),
        "attack_test_per_family_min": min((len(v) for v in fam_groups.values()),
                                          default=0),
        "attack_templates": len({r["template"] for r in atk}),
        "attack_templates_test": len({r["template"] for r in struct_test_atk}),
        "benign_cores": len({r["group"] for r in recs
                             if r["tier"] == "hard_negative"}),
        "ambiguous_cores": len({r["group"] for r in recs
                                if r["tier"] == "ambiguous"}),
        "ambiguous_verbatim_rows": sum(
            1 for r in recs if str(r["group"]).startswith("ambigV")),
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(man, f, indent=2)
    return man


# ---------------------------------------------------------------- main ------
def main():
    ap = argparse.ArgumentParser(description="Build the WebInject2026 corpus.")
    ap.add_argument("--capture", action="store_true",
                    help="replay against live containers instead of offline synthesis")
    ap.add_argument("--seed", type=int, default=C.SEED)
    ap.add_argument("--n-routine", type=int, default=C.VOLUME["routine"])
    ap.add_argument("--n-hard", type=int, default=C.VOLUME["hard_negative"])
    ap.add_argument("--n-ambiguous", type=int, default=C.VOLUME["ambiguous"])
    ap.add_argument("--n-attack", type=int, default=C.VOLUME["attack"])
    ap.add_argument("--out", default=os.path.join(DATA, "webinject2026.csv"))
    ap.add_argument("--no-parquet", action="store_true")
    args = ap.parse_args()

    C.validate_config()
    rng = random.Random(args.seed)

    volume = {"routine": args.n_routine, "hard_negative": args.n_hard,
              "ambiguous": args.n_ambiguous, "attack": args.n_attack}

    pool = P.load_pool(patt_root=PATT_ROOT)
    json.dump({k: [p for p, _ in v] for k, v in pool.items()},
              open(os.path.join(CORPUS, "payloads.json"), "w"), ensure_ascii=False)
    print("payload pool:", {k: len(v) for k, v in pool.items()},
          "total", sum(len(v) for v in pool.values()))

    print("synthesising", sum(volume.values()), "records...")
    recs = synthesise(pool, volume, rng)

    if args.capture:
        print("live capture enabled - replaying against containers")
        recs = capture(recs)
        for r in recs:
            r["source"] = "captured"

    recs, dropped = finalize(recs, args.seed)
    print(f"dedup removed {dropped:,}; final rows {len(recs):,}")

    write_csv(recs, args.out)
    if not args.no_parquet:
        pq = os.path.splitext(args.out)[0] + ".parquet"
        if write_parquet(args.out, pq):
            print(f"wrote {pq}")
    man = write_manifest(recs, dropped, args, os.path.join(DATA, "manifest.json"))
    print("\nlabel    ", man["label"])
    print("attack   ", man["attack_type"])
    print("tier     ", man["tier"])
    print("ctype    ", man["content_type"])
    print("split    ", man["split"])
    print("groups spanning split:", man["groups_spanning_split"],
          "| spanning split_struct:", man["groups_spanning_split_struct"])
    print("groups   ", man["groups"])
    print(f"\nwrote {args.out}")


if __name__ == "__main__":
    main()
