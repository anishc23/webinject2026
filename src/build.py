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

What changed in v4
  * **Counterfactual pairing.** Every attack row is the twin of a benign row: same
    endpoint, same carrier values, same headers, same multipart boundary, with a
    payload appended into one declared injection slot and nothing else altered.
    Both halves share a `pair_id`. v3 generated attacks independently and gave
    them routine-tier filler while hard negatives carried prose cores, so carrier
    vocabulary encoded the tier and the tier encoded the label -- the label was
    recoverable at AUC 0.904 from ordinary words with all injection syntax
    deleted. Pairing takes that to 0.539.
  * **Splits decided before generation.** Each payload group, template and benign
    core is assigned to a (split, split_struct) cell up front, and generation only
    ever pairs units from the same cell. A pair therefore cannot straddle a split,
    which post-hoc grouping could not guarantee.
  * **Bursty sessions.** A minority of attacker sessions carry a high
    within-session attack rate. v3's sessions were i.i.d. (variance ratio 0.989),
    so the column could not support the sequence modelling it advertised.
  * New column: `pair_id`.
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

from src import checksums as S
from src import config as C
from src import payloads as P
from src import vocab as V

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "data")
CORPUS = os.path.join(ROOT, "corpus")
PATT_ROOT = os.path.join(DATA, "patt")

# v4 construction: every attack is the counterfactual twin of a benign row, and
# every split membership is decided before generation. This is what v4.0.0 IS,
# so it is the default; set WEBINJECT_PAIRED=0 to build the v3-style corpus for
# a side-by-side comparison.
PAIRED = os.environ.get("WEBINJECT_PAIRED", "1") == "1"

# Within-session attack rates for a bursty (PAIRED) session layout: a minority
# of attacker sessions at SESS_HI, the rest mostly benign at SESS_LO.
SESS_HI, SESS_LO = 0.75, 0.10


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


def _encode_body(ep, params, rng, boundary=None):
    """Return (body_string, content_type_label, boundary).

    `boundary` is supplied when re-encoding the twin of an already-built record,
    so both halves of a counterfactual pair carry the same multipart boundary and
    therefore the same Content-Type header.
    """
    ct = C.content_type(ep)
    if ct == "json":
        return _json_body(params), "json", None
    if ct == "graphql":
        return _graphql_body(params), "graphql", None
    if ct == "multipart":
        b = boundary or ("----WebKitFormBoundary" + "".join(
            rng.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=16)))
        return _multipart_body(params, b), "multipart", b
    return _query_string(params), "form", None


def _split_qb(ep, params):
    """Partition (name, value) pairs into (query_list, body_list)."""
    body_names = set(ep.get("body", []))
    query, body = [], []
    for name, val in params:
        (body if name in body_names else query).append((name, val))
    return query, body


def _assemble(app, ep, values, rng, extra, reuse=None):
    """Build the transport-level fields shared by every record kind.

    `reuse` is the envelope of an already-built record, as returned in the
    "_envelope" key. Passing it makes this record transport-identical to that
    one -- same headers, same multipart boundary -- so the only difference
    between the two is the parameter value that was substituted. That is what
    makes a counterfactual pair counterfactual.
    """
    query, body = _split_qb(ep, values)
    body_str, ct_label, boundary = ("", "query", None)
    if body:
        body_str, ct_label, boundary = _encode_body(
            ep, body, rng, boundary=(reuse or {}).get("boundary"))
    hdrs = (reuse or {}).get("headers") or _headers(app, ep, rng, extra, boundary)
    rec = {
        "app": app, "method": ep["method"], "path": ep["path"],
        "query": _query_string(query), "body": body_str,
        "content_type": ct_label,
        "headers": _hdr_json(hdrs),
        "source": "synthetic", "status": "",
        "_envelope": {"headers": hdrs, "boundary": boundary},
    }
    return rec


def _benign_values(app, ep, tier, rng, core_idx=None):
    """The parameter values of one benign request, before assembly.

    Split out of `_benign_record` so a counterfactual attack twin can be built
    from exactly the same carrier values (see `_paired_records`). In v3 the
    attack side called `V.value_for` directly and never received a core, which
    made the ~2,340 prose cores benign-exclusive and the label recoverable from
    carrier vocabulary alone. Sharing this function is what closes that.
    """
    carrier = None
    core_id = None
    kind = ""
    if tier == "hard_negative":
        text_params = [n for n, t in ep["params"] if t in C.TEXT_TYPES]
        carrier = rng.choice(text_params)
        if core_idx is None:
            core_text, core_id = V.core_value(rng)
            core_idx = int(core_id.split("-")[1])
        else:
            # Pre-assigned core: its split cell was fixed before generation, so
            # the pair cannot straddle a split.
            core_text, core_id = V.BENIGN_CORES[core_idx], f"benH-{core_idx:05d}"
        kind = V.BENIGN_CORE_KINDS[core_idx] if core_idx is not None else ""

    values = []
    for name, ftype in ep["params"]:
        if name == carrier:
            values.append((name, core_text))
        else:
            values.append((name, V.value_for(ftype, rng, tier)))
    return values, carrier, core_id, (kind if tier == "hard_negative" else "")


def _benign_record(app, ep, tier, rng, core_idx=None):
    """One benign request. Hard negatives carry exactly one groupable core."""
    carrier = None
    core_id = None
    if tier == "hard_negative":
        text_params = [n for n, t in ep["params"] if t in C.TEXT_TYPES]
        carrier = rng.choice(text_params)
        if core_idx is None:
            core_text, core_id = V.core_value(rng)
        else:
            core_text, core_id = V.BENIGN_CORES[core_idx], f"benH-{core_idx:05d}"

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
    if tier == "hard_negative" and _MARKER_PROFILES and carrier:
        # Unpaired hard negatives carry an attack-shaped character profile too.
        # This tier exists to be punctuation-rich yet non-injective, so giving it
        # the same marker counts a real payload would have is squarely on-purpose
        # -- and without it only the 16,000 paired twins hold that punctuation,
        # leaving `%` at 6.8% of benign against 31.3% of attacks.
        prof = rng.choice(_MARKER_PROFILES)
        extra_tokens = _mirror_charset(prof, rng)
        if extra_tokens:
            def _mark(v):
                out = f"{v} {' '.join(extra_tokens)}".strip()
                return str(v) if V.is_injective(out) else out
            values = [(n, _mark(v) if n == carrier else v) for n, v in values]

    rec = _assemble(app, ep, values, rng, extra=None)
    rec.update({
        "label": 0, "attack_type": "benign", "family": "benign",
        "tier": tier, "evasion": "none", "placement": "",
        "template": f"benign:{tier}",
        "group": core_id or f"benR-{rng.getrandbits(48):x}",
        "benign_category": (V.BENIGN_CORE_KINDS[core_idx]
                            if tier == "hard_negative" and core_idx is not None else ""),
    })
    return rec


def _ambiguous_record(app, ep, rng, amb_idx=None):
    """Benign traffic carrying literal attack syntax in a free-text field."""
    text_params = [n for n, t in ep["params"] if t in C.TEXT_TYPES] or ep["inject"]
    target = rng.choice(text_params)
    if amb_idx is None:
        amb_text, core_id = V.ambiguous_value(rng)
    else:
        amb_text, core_id = V.ambiguous_value(rng, idx=amb_idx)
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



# Benign carriers for each character injection relies on. Used to give the
# benign twin of a pair the same character profile as the attack's payload, so
# that no single character separates the classes. Every entry is ordinary text a
# real user could type, and none matches vocab.INJECTION_GUARD.
_CHAR_CARRIERS = {
    "%": ["%25", "%20", "100%", "%%"],
    "*": ["/**/", "**", "2*3", "***"],
    "<": ["<3", "1<2", "<<"],
    ">": [">>", "2>1", "->"],
    "'": ["'12'", "''", "'9'"],
    '"': ['"12"', '""', '"7"'],
    "$": ["$19.99", "$0", "$$"],
    "(": ["(1)", "(2)", "(3)"],
    ")": ["(1)", "(2)", "(3)"],
    "{": ["{1}", "{}", "{2}"],
    "}": ["{1}", "{}", "{2}"],
    "[": ["[1]", "[]", "[2]"],
    "]": ["[1]", "[]", "[2]"],
    "|": ["1|2", "||", "3|4"],
    "\\": ["1\\2", "\\\\", "3\\4"],
    "#": ["#1", "#7", "#42"],
    "`": ["`1`", "``"],
    ";": ["1; 2", ";;"],
    "&": ["1&2", "&&"],
    "=": ["1=2", "=="],
    ":": ["10:30", "1:2"],
    # `--x` was the only carrier here holding a letter, which made `x` a
    # benign-exclusive token once syntax deletion stripped the dashes around it
    # (5,029 occurrences against none on the attack side). Digits carry the same
    # character profile and leak nothing.
    "-": ["1-2", "--7"],
    "/": ["1/2", "//"],
}

_MARKER_PROFILES = []
_MIRROR_CHARS = "%*<>'\"$(){}[]|\\#`"

# Word-free padding. Every token is digits and punctuation only, so padding a
# decoy span to its twin's length can never add an alphabetic token -- which is
# the whole point of `_decoy_span`.
_PAD_TOKENS = ["1", "12", "7", "42", "0", "99", "3", "2024", "1.5", "10:30",
               "1-2", "1/2", "(1)", "[2]", "{}", "==", "..", "--7", "+1", "0.0"]

_WORD_RE = re.compile(r"[A-Za-z]{2,}")   # what the register audits count
_ECHO_RE = re.compile(r"[A-Za-z]+")      # what a twin has to reproduce
_POOL_WORDS = set()


def _words(text):
    """Alphabetic tokens the register audit would count, minus payload-pool
    vocabulary. This is deliberately the same rule `audit_gaps._carrier_tokens`
    and `model_zoo.carrier_text` apply, so what the builder balances is exactly
    what the audit measures."""
    return [w for w in (t.lower() for t in _WORD_RE.findall(str(text)))
            if w not in _POOL_WORDS]



def _safe_trim(text, n):
    """Cut `text` to n characters without manufacturing an artefact.

    Two ways a naive slice bites. Cutting inside a percent-escape leaves a
    dangling `%` or `%X` that decodes to U+FFFD, which then shows up as an
    attack-only character. Cutting inside a token like `--x` leaves a trailing
    `--`, which is a real SQL comment terminator and makes a hard negative a
    mislabelled attack. Trim, then repair, then verify against the same guard
    the gate uses.
    """
    out = text[:n]
    out = re.sub(r"%[0-9A-Fa-f]?$", "", out)
    while out and V.is_injective(out):
        out = out[:-1].rstrip("-#/*%\\ ")
    return out.rstrip()


def _mirror_charset(payload, rng):
    """Benign tokens giving the same character profile as `payload`.

    A payload necessarily carries the punctuation injection is built from. If
    the benign twin does not, then a single character separates the classes and
    the corpus has a shortcut -- which is exactly what src.shortcut_stats
    measures. Presence parity is not enough either: the gate's evasion_artifact
    check only asks whether a marker occurs in both classes, and `%` still sat
    at 6.8% of benign against 31.3% of attacks (Cramer V 0.318, on par with
    CSIC-2010's worst character). Matching counts closes that.
    """
    out = []
    for ch in _MIRROR_CHARS:
        need = payload.count(ch)
        if not need:
            continue
        carriers = _CHAR_CARRIERS.get(ch)
        if not carriers:
            continue
        have = 0
        while have < need:
            tok = rng.choice(carriers)
            out.append(tok)
            have += tok.count(ch)
    rng.shuffle(out)
    return out


def _decoy_span(payload, rng, prefix=False, decoded=False):
    """The benign twin's span: same length, same character profile, same carrier
    vocabulary as `payload`, and nothing else.

    v4.2.0 built this as mirror punctuation followed by ordinary filler drawn
    from `V.value_for`, truncated to the payload's length. That matched length
    and character profile but not *vocabulary*: the filler contributed real
    words the payload did not, so within a pair the benign twin held a median of
    two more carrier words than its attack, a carrier-only model ranked the
    attack above its own twin in only 73.0% of pairs, and 77.5% of attacks were
    word-poorer than their twins. The pair's difference was therefore not the
    injected span alone, which is the one thing the paired protocol asserts.

    So the span echoes the payload's own non-pool alphabetic tokens instead of
    inventing new ones, and pads with `_PAD_TOKENS` -- digits and punctuation
    only -- to reach length. Two consequences, both wanted: the within-pair
    carrier-word delta is zero by construction, and no alphabetic token is
    class-exclusive, because whatever residue an encoding evasion leaves
    (`%3Cimg` -> `cimg`) now appears on the benign side of the same pair.
    """
    span_len = len(payload)

    # Echo first -- it is the part that makes the delta zero, so it gets the
    # budget ahead of decoration. Preserve multiplicity: two occurrences of a
    # token on the attack side need two on the benign side. These always fit:
    # each alphabetic run in the payload is separated by at least one non-alpha
    # character, so the joined echo is never longer than the payload itself.
    # Echo the payload as the *audit* will see it, not as it is written here.
    # `normalise` unquotes every record once before the payload column is
    # written. A query-placed span is quoted on assembly, so that decode is
    # exactly undone and the audit sees this string; a body- or header-placed
    # span is stored raw, so the audit sees it decoded, and `%3Csvg` arrives as
    # `<svg`. Echoing the wrong one is what left `csvg`/`cimg` on the benign side
    # of a pair with no counterpart on the attack side.
    seen = urllib.parse.unquote_plus(payload) if decoded else payload
    # Single letters count here even though the register audits tokenise at two
    # or more. Deleting punctuation and digits turns `%3A` into a bare `A` and
    # `%2F` into `F`, and those stray capitals were 99% of what still separated a
    # pair once the injection was deleted outright (see `src.syntax_ablation`).
    # Echoing them costs nothing and closes that.
    parts = list(_ECHO_RE.findall(seen))
    parts = [w for w in parts if w.lower() not in _POOL_WORDS]

    # The letter run that touches the carrier value. The span is appended with no
    # separator, so this run *fuses* with the carrier's adjacent word into one
    # token -- and a fused token is new, so it counts even when the run on its
    # own is payload-pool vocabulary the audit strips. `home.php` beside
    # `http://...` yields `phphttp`, which is why 618 of the last 647 mismatched
    # pairs were off by exactly one. Reproducing the run verbatim at the same
    # edge makes both sides fuse identically; `prefix` says which edge that is.
    at_start = not prefix
    m = (re.match(r"[A-Za-z]+", seen) if at_start
         else re.search(r"[A-Za-z]+$", seen))
    seam = m.group(0) if m else ""
    if seam in parts:
        parts.remove(seam)            # re-added at the edge below, not dropped

    # Character profile next, capped so echo + markers cannot crowd out the
    # length match, then word-free padding.
    budget = int(span_len * 0.6)
    used = sum(len(t) + 1 for t in parts) + len(seam)
    for tok in _mirror_charset(payload, rng):
        if used + len(tok) > budget:
            break
        parts.append(tok)
        used += len(tok) + 1
    rng.shuffle(parts)
    toks = ([seam] + parts) if at_start else (parts + [seam])
    toks = [t for t in toks if t]

    # Fit to length from the end *away* from the seam, so nothing displaces the
    # run that has to sit against the carrier. Whole tokens first, so a cut never
    # halves an echoed word into a benign-exclusive fragment (`cimg` -> `cim`).
    while len(" ".join(toks)) < span_len:
        pad = rng.choice(_PAD_TOKENS)
        toks = toks + [pad] if at_start else [pad] + toks
    while len(" ".join(toks)) > span_len and len(toks) > 1:
        toks = toks[:-1] if at_start else toks[1:]

    span = " ".join(toks)
    while len(span) < span_len:                  # exact length, word-free
        c = rng.choice("1234567")
        span = span + c if at_start else c + span
    if at_start:
        # `_safe_trim` repairs from the tail, which is the free end only when the
        # seam sits at the head. When it does not, `_safe_join` is the guard that
        # catches an injective join, and it does so without touching the span.
        span = _safe_trim(span, span_len)
        while len(span) < span_len:              # re-pad; digits form no marker
            span += "1"
    return span


def _greedy_partition(keys, weights, rng):
    """Assign keys to train/val/test hitting SPLIT_FRACTIONS by *weight*.

    Weighting by expected row count rather than key count matters: templates
    are wildly uneven (xss:tag_event holds 303 payloads, ssrf:http_host_port
    180), so partitioning by count alone leaves the structural test starved.
    """
    f = C.SPLIT_FRACTIONS
    keys = sorted(keys, key=str)
    rng.shuffle(keys)
    total = sum(weights[k] for k in keys)
    want = {s: f[s] * total for s in f}
    got = {s: 0.0 for s in f}
    out = {}

    # Seed train, then test, then val before greedy filling. Without this a
    # family holding only three templates puts all of them in train/test at a
    # 70/10/20 target, and the family vanishes from the structural val set --
    # which is how jndi, nosqli, ssrf and xss went missing in v3.0.0. A family
    # with fewer templates than splits still cannot cover them all; that is an
    # inventory limit, reported rather than papered over.
    ordered = sorted(keys, key=lambda k: -weights[k])
    for s, k in zip(("train", "test", "val"), ordered):
        out[k] = s
        got[s] += weights[k]
    for k in ordered:
        if k in out:
            continue
        s = max(("train", "val", "test"), key=lambda s: want[s] - got[s])
        out[k] = s
        got[s] += weights[k]
    return out


def _preassign(pool, rng):
    """Decide every split membership BEFORE any row is generated.

    A counterfactual pair links an attack payload to a benign core, so the two
    cannot be split independently after the fact -- that is what left 1,236
    groups spanning `split` in the first prototype. Union-find over pairs is not
    an option either: 16,000 pairs over ~1,961 groups and ~2,340 cores collapse
    into a single component.

    So each unit is assigned up front to a *cell* -- a (split, split_struct)
    pair -- and generation only ever pairs a payload with a core from the same
    cell. Both halves then inherit the cell, and no group, template or core can
    span either split by construction.

    Payload groups and templates are partitioned per family, which also gives
    `split_struct` the family coverage and prevalence balance it lacked in
    v3.0.0 (nosqli and ssrf had no structural val or test rows at all).
    """
    per_fam = {}
    for fam, items in pool.items():
        for raw, tmpl in items:
            per_fam.setdefault(fam, []).append((P.group_key(raw), tmpl, raw))

    group_split, template_split = {}, {}
    for fam in sorted(per_fam):
        gw, tw = {}, {}
        for g, t, _ in per_fam[fam]:
            gw[g] = gw.get(g, 0) + 1
            tw[t] = tw.get(t, 0) + 1
        group_split.update(_greedy_partition(list(gw), gw, rng))
        template_split.update(_greedy_partition(list(tw), tw, rng))

    # index payloads by cell and family
    cell_pool = {}
    for fam in sorted(per_fam):
        for g, t, raw in per_fam[fam]:
            cell = (group_split[g], template_split[t])
            cell_pool.setdefault(cell, {}).setdefault(fam, []).append((raw, t, g))

    weight = {c: sum(len(v) for v in fams.values()) for c, fams in cell_pool.items()}
    total = sum(weight.values())
    share = {c: weight[c] / total for c in weight}

    def _deal(n_units, prefix):
        """Split a pool of ungrouped units across cells in the same proportions."""
        cells = sorted(share, key=str)
        out = {c: [] for c in cells}
        idx = list(range(n_units))
        rng.shuffle(idx)
        i = 0
        for c in cells:
            k = int(round(share[c] * n_units))
            for j in idx[i:i + k]:
                out[c].append(j)
            i += k
        for j in idx[i:]:
            out[cells[0]].append(j)
        return out

    cores_by_cell = _deal(len(V.BENIGN_CORES), "benH")
    amb_by_cell = _deal(len(V.AMBIGUOUS_CORES), "amb")
    return cell_pool, cores_by_cell, amb_by_cell, share


def _paired_records(app, ep, pool, rng, pair_no):
    """A counterfactual pair: one benign row and its attack twin.

    The two rows are identical in every respect -- endpoint, method, every
    carrier value, headers, multipart boundary -- except that in the attack row
    a single declared injection slot holds a payload instead of its benign
    value. Both carry the same `pair_id`.

    This is the construction fix for the lexical register leak. Because the
    attack row inherits its carrier text from a benign row drawn from the same
    tier mixture, carrier vocabulary is identically distributed across labels
    and cannot predict the label. It also yields a matched-pair protocol: the
    score difference within a pair is attributable to the injected span alone.
    """
    cell, cell_pool, core_idx = pair_no[1], pair_no[2], pair_no[3]
    pair_no = pair_no[0]
    split, split_struct = cell

    fams = [f for f in ep["families"] if cell_pool.get(f)]
    if not fams:
        return None, None
    weights = [C.FAMILY_WEIGHTS.get(f, 1.0) for f in fams]
    fam = rng.choices(fams, weights=weights, k=1)[0]
    raw, template, group = rng.choice(cell_pool[fam])

    tier = "hard_negative" if core_idx is not None else "routine"
    values, carrier, core_id, bcat = _benign_values(app, ep, tier, rng, core_idx=core_idx)

    pair_id = f"pair-{pair_no:06d}"
    _twin_values = list(values)

    if rng.random() < C.EVASION_RATE:
        payload, evasion = P.apply_evasion(raw, fam, rng, C.EVASION_CHAIN_RATE)
    else:
        payload, evasion = raw, "none"

    target = rng.choice(ep["inject"])
    body_names = set(ep.get("body", []))
    in_body = target in body_names and rng.random() < 0.9
    # Header placement, restored for v4.1. The paired path originally dropped it,
    # taking header-placed attacks from 487 to 0 -- which silently removed the
    # placement CRLF and request smuggling are actually about. The pair stays a
    # counterfactual: both twins carry the same header, one with the payload
    # appended and one with an equal-length benign span.
    in_header = (not in_body) and fam in C.HEADER_FAMILIES \
        and rng.random() < C.HEADER_INJECTION_RATE

    # Append the payload to the target slot rather than replacing its value.
    # Replacing it removes that slot's benign prose from the attack row, so
    # attacks end up with systematically less carrier vocabulary than their own
    # twins -- a residual register signal measured at AUC 0.840. Appending keeps
    # the carrier identical and makes the injected span the only difference,
    # which is also how real injections arrive (?q=shoes' OR 1=1--).
    prefix = rng.random() < 0.15

    def _append(v, span):
        v = str(v)
        if not v:
            return span
        return f"{span}{v}" if prefix else f"{v}{span}"

    # The benign twin gets a span of the same length in the same slot, so the
    # pair differs only in whether the appended span is injective -- not in how
    # much text it carries. Without it, appending made every attack longer than
    # its own twin (100% of pairs, 11.3% median gap corpus-wide) and a
    # length-only model reached AUC 0.611. Length is the oldest shortcut in this
    # corpus's history; reintroducing it while closing the register leak would
    # trade one artefact for another.
    #
    # `_decoy_span` matches the payload on three axes at once -- length,
    # character profile, and carrier vocabulary. v4.2.0 matched only the first
    # two and paid for the third: see that function's docstring for the
    # measurements. Matching all three is what makes the paired protocol's score
    # delta attributable to the span's *content* rather than to its size, its
    # punctuation, or how many ordinary words sit beside it.
    # Which slots survive assembly un-quoted, and so reach the payload column one
    # decode lighter than they were written. Query strings and form bodies go
    # through `quote_plus`, which `normalise`'s single `unquote_plus` exactly
    # undoes; JSON, GraphQL, multipart and header slots are stored verbatim and
    # therefore arrive decoded.
    raw_slot = in_header or (in_body and C.content_type(ep) in
                             ("json", "graphql", "multipart"))
    decoy = _decoy_span(payload, rng, prefix, decoded=raw_slot)

    def _safe_join(v, span):
        """Append, then verify the *joined* value. Trimming the span alone is
        not enough: a carrier ending in `-` beside a span starting with `-`
        makes `--` at the seam, which is a real SQL comment terminator and would
        turn a hard negative into a mislabelled attack."""
        out = _append(v, span)
        if not V.is_injective(out):
            return out
        # A space at the seam separates the two halves without touching either.
        # It costs one character of length parity, which the +/-1 tolerance
        # absorbs, and -- unlike dropping the span -- it keeps the echoed
        # carrier tokens, so the pair's word delta stays zero. Try it first.
        spaced = _append(v, f" {span}") if not prefix else _append(v, f"{span} ")
        if not V.is_injective(spaced):
            return spaced
        # Trimming character by character can leave a dangling `#` or `--`
        # against a carrier that is itself a SQL snippet (the `code` category
        # holds real queries). Drop the span for this row instead: one row
        # without a mirrored profile costs nothing, a mislabelled hard negative
        # costs the corpus its guarantee. Both parity checks tolerate the
        # handful of rows this reaches; `audit_gaps` reports the share.
        return str(v)

    # Verify rather than assume. The three axes `_decoy_span` matches are
    # properties of the span in isolation; what the audit counts is the
    # assembled row after `normalise`, and the seam where a span meets its
    # carrier value can fuse two tokens into one on one side of a pair and not
    # the other (`report.pdf` + `/admin` -> `pdffadmin`). So assemble, count, and
    # redraw until the two sides agree. Cheap, because the disagreement is
    # essentially a coin flip on which token the shuffle left at the edge.
    hname = "User-Agent" if rng.random() < 0.5 else "Referer"

    def _make_benign(span, reuse):
        vals = (values if in_header else
                [(n, _safe_join(v, span) if n == target else v) for n, v in values])
        rec = _assemble(app, ep, vals, rng, extra=None, reuse=reuse)
        if in_header:
            hb = json.loads(rec["headers"])
            cand = _append(str(hb.get(hname, "")), span)
            if not V.is_injective(cand):
                hb[hname] = cand
                rec["headers"] = _hdr_json(hb)
        return rec

    benign = _make_benign(decoy, None)
    envelope = benign["_envelope"]
    benign.update({
        "label": 0, "attack_type": "benign", "family": "benign",
        "tier": tier, "evasion": "none", "placement": "",
        "template": f"benign:{tier}",
        "group": core_id or f"benR-{rng.getrandbits(48):x}",
        "pair_id": pair_id, "split": split, "split_struct": split_struct,
        # Shared with the twin, not handed to it. v4.1.0 set this on the attack
        # only, which left all 6,343 paired hard negatives uncategorised -- so
        # the error-analysis table bucketed a third of the tier, and every one of
        # the 13 false positives, into `(routine/ambiguous)`. The per-category
        # false-positive claim was computed over 63% of the tier.
        "benign_category": bcat,
    })

    atk_values = ([(n, v) for n, v in _twin_values] if in_header else
                  [(n, _append(v, payload) if n == target else v)
                   for n, v in _twin_values])
    attack = _assemble(app, ep, atk_values, rng, extra=None, reuse=envelope)
    if in_header:
        ha = json.loads(attack["headers"])
        ha[hname] = _append(str(ha.get(hname, "")), payload)
        attack["headers"] = _hdr_json(ha)

    # Redraw the benign span until its assembled carrier-word count matches the
    # attack's. Bounded: a handful of pairs never converge (the carrier is itself
    # a SQL snippet, so `_safe_join` keeps dropping the span), and `audit_gaps`
    # gates the share that does.
    n_atk = len(_words(normalise(attack)))
    for _ in range(8):
        if len(_words(normalise(benign))) == n_atk:
            break
        span = _decoy_span(payload, rng, prefix, decoded=raw_slot)
        retry = _make_benign(span, envelope)
        retry.update({k: v for k, v in benign.items() if k not in retry})
        benign = retry

    attack.update({
        "label": 1, "attack_type": fam, "family": fam, "tier": "attack",
        "evasion": evasion,
        "placement": "header" if in_header else ("body" if in_body else "query"),
        "template": template, "group": group, "payload_slot": target,
        "pair_id": pair_id, "split": split, "split_struct": split_struct,
        # The attack inherits its twin's carrier category, so a false negative
        # can be attributed to the benign register it was hiding in.
        "benign_category": bcat,
    })
    return benign, attack


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

    if PAIRED:
        # v4: every attack is the counterfactual twin of a benign row, and every
        # split membership was decided before generation, so no group, template
        # or benign core can span a split. Twins count against the benign
        # budget, so total volume is unchanged.
        cell_pool, cores_by_cell, amb_by_cell, share = _preassign(pool, rng)
        cells = sorted(share, key=str)
        cell_w = [share[c] for c in cells]

        made = {"routine": 0, "hard_negative": 0}
        hard_target = volume["hard_negative"] / (volume["routine"]
                                                 + volume["hard_negative"])
        cursor = {c: 0 for c in cells}

        def take_core(cell):
            """Next pre-assigned core for this cell, cycling if exhausted."""
            bucket = cores_by_cell[cell]
            if not bucket:
                return None
            i = bucket[cursor[cell] % len(bucket)]
            cursor[cell] += 1
            return i

        i = 0
        while i < volume["attack"]:
            cell = rng.choices(cells, weights=cell_w, k=1)[0]
            if not cell_pool.get(cell):
                continue
            app, ep = rng.choice(inject_eps)
            core_idx = take_core(cell) if rng.random() < hard_target else None
            b, a = _paired_records(app, ep, pool, rng,
                                   (i, cell, cell_pool[cell], core_idx))
            if b is None:
                continue
            made[b["tier"]] += 1
            recs.append(b)
            recs.append(a)
            i += 1

        # Unpaired benign rows: routine rows are ungrouped so they take a cell
        # by the same proportions; hard negatives and ambiguous rows follow the
        # cell their pre-assigned core already belongs to.
        for _ in range(max(0, volume["routine"] - made["routine"])):
            app, ep = rng.choice(endpoints)
            cell = rng.choices(cells, weights=cell_w, k=1)[0]
            r = _benign_record(app, ep, "routine", rng)
            r["split"], r["split_struct"] = cell
            recs.append(r)
        for _ in range(max(0, volume["hard_negative"] - made["hard_negative"])):
            app, ep = rng.choice(endpoints)
            cell = rng.choices(cells, weights=cell_w, k=1)[0]
            r = _benign_record(app, ep, "hard_negative", rng,
                               core_idx=take_core(cell))
            r["split"], r["split_struct"] = cell
            recs.append(r)
        amb_cursor = {c: 0 for c in cells}
        for _ in range(volume["ambiguous"]):
            app, ep = rng.choice(inject_eps)
            cell = rng.choices(cells, weights=cell_w, k=1)[0]
            bucket = amb_by_cell[cell]
            if not bucket:
                cell = cells[0]
                bucket = amb_by_cell[cell]
            idx = bucket[amb_cursor[cell] % len(bucket)]
            amb_cursor[cell] += 1
            r = _ambiguous_record(app, ep, rng, amb_idx=idx)
            r["split"], r["split_struct"] = cell
            recs.append(r)
    else:
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
                # Send the body the record actually carries. Sending only `form`
                # bodies left json/graphql/multipart rows (37% of the corpus,
                # including 5,272 attacks whose payload lives in the body) going
                # out empty while Content-Type still advertised a payload, so the
                # recorded `status` described a different request than the row.
                ctype = r["content_type"]
                kw = {}
                if ctype == "form":
                    kw["data"] = dict(urllib.parse.parse_qsl(r["body"]))
                elif r["body"]:
                    # json, graphql and multipart are sent verbatim: re-encoding
                    # would drop the multipart boundary that hdrs declares, and
                    # would normalise the exact bytes the payload depends on.
                    kw["data"] = r["body"].encode("utf-8")
                fn = getattr(sess, r["method"].lower())
                resp = fn(url, headers=hdrs, timeout=5,
                          allow_redirects=False, **kw)
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


_PAIR_GROUP = {}


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

    if PAIRED:
        # Dedup works per row, so it can drop one half of a pair and leave the
        # other as an unmatched orphan. A half-pair is worse than no pair: it
        # reintroduces exactly the asymmetry pairing exists to remove. Drop both.
        seen_pairs = {}
        for r in recs:
            pid = r.get("pair_id")
            if pid:
                seen_pairs[pid] = seen_pairs.get(pid, 0) + 1
        before = len(recs)
        recs = [r for r in recs
                if not r.get("pair_id") or seen_pairs[r["pair_id"]] == 2]
        dropped += before - len(recs)

    if not PAIRED:
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
        if PAIRED:
            # Bursty sessions. v3 chunked rows at random, so the per-session
            # attack rate varied exactly as an i.i.d. binomial would (measured
            # ratio 0.989) and no sequence model could beat a per-request one --
            # while the datasheet advertised sequence modelling. Here a minority
            # of sessions are attacker sessions with a high within-session rate
            # and the rest are mostly benign. `session_leak` constrains the MEAN
            # of the per-session rates, not the variance, so this keeps that
            # check satisfied while giving the column real signal.
            atk = [r for r in rows if r["label"] == 1]
            ben = [r for r in rows if r["label"] == 0]
            rng.shuffle(atk)
            rng.shuffle(ben)
            p = len(atk) / max(1, len(rows))
            q = min(0.9, max(0.05, (p - SESS_LO) / (SESS_HI - SESS_LO)))
            ai = bi = 0
            while ai < len(atk) or bi < len(ben):
                n = rng.randint(lo, hi)
                rate = SESS_HI if rng.random() < q else SESS_LO
                want_a = min(len(atk) - ai, int(round(n * rate)))
                want_b = min(len(ben) - bi, n - want_a)
                if want_a + want_b == 0:
                    # One pool is exhausted and this session's rate asked for
                    # none of the other. Take whatever is left rather than
                    # breaking, which previously stranded 411 rows with no
                    # session id at all -- and an empty id spans every split.
                    want_a = min(len(atk) - ai, n)
                    want_b = min(len(ben) - bi, n - want_a)
                    if want_a + want_b == 0:
                        break
                chunk = atk[ai:ai + want_a] + ben[bi:bi + want_b]
                ai += want_a
                bi += want_b
                sid = f"s{split[0]}-{sess_no:06d}"
                for r in chunk:
                    r["session"] = sid
                sess_no += 1
            continue
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
           "split", "split_struct", "template", "group", "pair_id", "benign_category"]


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

    # data/patt/ is gitignored, so whether it is on disk silently decides which
    # corpus you get. The release was built without it; a rebuild with it present
    # draws from a larger pool and will not reproduce the published CSV. Say so
    # loudly rather than letting the difference surface as a failed CI diff.
    if os.path.isdir(PATT_ROOT):
        print("WARNING: %s is present, so its payloads are being folded in."
              % os.path.relpath(PATT_ROOT, ROOT))
        print("         The released corpus was built WITHOUT it. This rebuild will")
        print("         NOT reproduce data/webinject2026.csv. Move the directory")
        print("         aside to rebuild the published corpus.")

    pool = P.load_pool(patt_root=PATT_ROOT)
    _MARKER_PROFILES.extend(p for v in pool.values() for p, _ in v)
    # The register audit strips every word occurring anywhere in the pool before
    # counting carrier vocabulary. Load the same set here so `_decoy_span` can
    # balance the pair against the measure that will judge it.
    _POOL_WORDS.update(w for v in pool.values() for p, _ in v
                       for w in (t.lower() for t in _WORD_RE.findall(p)))
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

    # The build rewrites four tracked artefacts; keep the release manifest in
    # step with them rather than updating it by hand at tag time.
    lines, missing = S.write()
    print(f"wrote {S.SUMS} ({len(lines)} files)")
    if missing:
        print("  not on disk, left out:", ", ".join(missing))


if __name__ == "__main__":
    main()
