"""Pytest wrapper around the quality gate.

`pytest -q` asserts the shipped CSV passes every check in src.validate, plus a
few structural invariants. This is the CI guard: a regenerated corpus that
reintroduces any leak or shortcut turns the suite red.
"""

import json
import os
import sys

import pandas as pd
import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from src import config as C          # noqa: E402
from src import validate as Vd       # noqa: E402
from src.vocab import is_injective   # noqa: E402

CSV = os.path.join(ROOT, "data", "webinject2026.csv")


@pytest.fixture(scope="module")
def df():
    d = pd.read_csv(CSV, keep_default_na=False)
    d["label"] = d["label"].astype(int)
    return d


def test_config_invariant():
    assert C.validate_config() is True


def test_gate_all_pass(df):
    chk = Vd.Check()
    Vd.run(df, chk)
    failed = [r for r in chk.rows if r[1] == "FAIL"]
    assert not failed, "failing checks: " + ", ".join(f"{r[0]} ({r[2]})" for r in failed)


def test_no_duplicate_payloads(df):
    assert df.payload.duplicated().sum() == 0


def test_split_disjoint_by_group(df):
    spans = df.groupby("group").split.nunique()
    assert int((spans > 1).sum()) == 0


def test_every_family_in_every_split(df):
    """The stratified split must place every attack family in train/val/test."""
    atk = df[df.label == 1]
    per_family = atk.groupby("attack_type").split.nunique()
    missing = per_family[per_family < 3]
    assert missing.empty, f"families absent from a split: {list(missing.index)}"


def test_split_ratio_balance(df):
    """Attack ratio must match across splits (no unusable low-signal val set)."""
    rates = df.groupby("split").label.mean()
    assert float(rates.max() - rates.min()) <= 0.05


def test_disjoint_test_has_enough_groups(df):
    """Enough held-out payload groups to rank detectors with low variance."""
    te_atk = df[(df.label == 1) & (df.split == "test")]
    assert te_atk.group.nunique() >= 250
    assert int(te_atk.groupby("attack_type").group.nunique().min()) >= 8


def test_benign_cores_are_split_disjoint(df):
    """Hard-negative / ambiguous benign cores never span splits (the v3 fix)."""
    ben = df[df.tier.isin(["hard_negative", "ambiguous"])]
    assert int((ben.groupby("group").split.nunique() > 1).sum()) == 0


def test_structural_split_holds_out_templates(df):
    """No attack template spans the structural split, and it holds enough."""
    atk = df[df.label == 1]
    assert int((atk.groupby("template").split_struct.nunique() > 1).sum()) == 0
    te = atk[atk.split_struct == "test"]
    assert te.template.nunique() >= 12


def test_sessions_never_span_splits(df):
    assert int((df.groupby("session").split.nunique() > 1).sum()) == 0


def test_content_type_present_for_body_methods(df):
    """Every request that carries a body declares a non-query content type."""
    body = df[df.method.isin(["POST", "PUT", "PATCH"])]
    assert (body.content_type != "query").all()


def test_all_fourteen_families_present(df):
    assert df[df.label == 1].attack_type.nunique() == 14


def test_ambiguous_cores_are_split_disjoint(df):
    """Ambiguous (frame, specimen) cores never span splits, and both the
    verbatim and discussion kinds reach the test set."""
    amb = df[df.tier == "ambiguous"]
    assert int(amb.groupby("group").split.nunique().gt(1).sum()) == 0
    te = amb[amb.split == "test"].group.astype(str)
    assert te.str.startswith("ambigV").any()
    assert te.str.startswith("ambigD").any()


def test_every_injectable_param_has_benign_traffic(df):
    """No injectable parameter may be attack-only (the v1 `comment` leak)."""
    import urllib.parse

    def params(q):
        try:
            return {k for k, _ in urllib.parse.parse_qsl(str(q))}
        except Exception:
            return set()

    injectable = {p for cfg in C.APPS.values() for ep in cfg["endpoints"]
                  for p in ep["inject"]}
    ben = set().union(*df[df.label == 0]["query"].map(params)) \
        if len(df[df.label == 0]) else set()
    ben |= set().union(*df[df.label == 0]["body"].fillna("").map(params))
    # every injectable param that appears at all in the query grammar must also
    # occur in benign traffic somewhere
    seen_atk = set().union(*df[df.label == 1]["query"].map(params))
    for p in injectable & seen_atk:
        assert p in ben, f"parameter '{p}' appears only in attack traffic"


def test_hard_negatives_are_not_injections(df):
    hn = df[df.tier == "hard_negative"].payload.astype(str)
    assert int(hn.map(is_injective).sum()) == 0


def test_manifest_matches_csv(df):
    man = json.load(open(os.path.join(ROOT, "data", "manifest.json")))
    assert man["rows"] == len(df)
    assert man["groups_spanning_split"] == 0
    assert man["groups_spanning_split_struct"] == 0
    assert man["label"][str(1)] == int((df.label == 1).sum())


def test_labels_binary(df):
    assert set(df.label.unique()) <= {0, 1}


# --------------------------------------------------- counterfactual pairing --
# The paired protocol asserts one thing: within a pair, the only difference is
# the injected span. Every claim in the attribution section rests on it, and an
# external review falsified it in ten lines against v4.2.0 -- the benign twin
# carried a median of two more carrier words than its own attack, because the
# decoy span was padded with ordinary filler. These are the regression guards.

def test_mirror_vocabularies_are_word_free(df):
    """The tokens a twin is padded with must contain no letters at all.

    v4.2.0's changelog claimed this ("digit/punctuation only") while the builder
    filled the remaining span with `V.value_for`, and both `--x` entries slipped
    a letter through. Assert it rather than claiming it.
    """
    import re

    from src import build as B
    for name, toks in (("_PAD_TOKENS", B._PAD_TOKENS),
                       ("_CHAR_CARRIERS", [t for v in B._CHAR_CARRIERS.values()
                                           for t in v])):
        bad = [t for t in toks if re.search(r"[A-Za-z]", t)]
        assert not bad, f"{name} carries letters: {bad}"


def test_pair_carrier_word_parity(df):
    """Within a pair, both rows must carry the same count of carrier words.

    Carrier words are alphabetic tokens that do not occur in the payload pool --
    the same definition `audit_gaps` and `model_zoo` use. A pair that fails this
    differs by something other than the injected span.
    """
    import re

    pool = json.load(open(os.path.join(ROOT, "corpus", "payloads.json")))
    word = re.compile(r"[A-Za-z]{2,}")
    atk = {w.lower() for ps in pool.values() for p in ps for w in word.findall(p)}

    pr = df[df.pair_id.astype(str) != ""]
    n = pr.payload.map(lambda s: len([w for w in (t.lower() for t in
                                                  word.findall(str(s)))
                                      if w not in atk]))
    piv = pr.assign(_n=n).pivot_table(index="pair_id", columns="label",
                                      values="_n", aggfunc="first").dropna()
    zero = float((piv[1] == piv[0]).mean())
    assert zero >= 0.95, f"carrier-word delta is zero in only {zero:.1%} of pairs"


def test_benign_category_is_shared_not_moved(df):
    """Both halves of a hard-negative pair carry the category, not just the
    attack. v4.1.0 set it on the attack alone, which left 6,343 hard negatives
    uncategorised and silently narrowed the error-analysis table to 63% of the
    tier."""
    hn = df[df.tier == "hard_negative"]
    blank = int((hn.benign_category.astype(str) == "").sum())
    assert blank == 0, f"{blank:,} hard negatives have no benign_category"
