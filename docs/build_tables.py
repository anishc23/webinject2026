"""Generate the paper's LaTeX numbers from the shipped result files.

The paper states that every number in it comes from `tables/macros.tex` or a
`tables/tab_*.tex` fragment, and that both are generated from the result JSONs
rather than typed. This script is what makes that true. It reads only
`data/*.json`, `data/manifest.json` and `CITATION.cff`, and writes:

    tables/macros.tex            203 \newcommand definitions
    tables/tab_ablation_pool.tex
    tables/tab_ablation_symmetric.tex
    tables/tab_baselines.tex
    tables/tab_lofo.tex
    tables/tab_zoo_capped.tex
    tables/tab_zoo_full.tex

  python docs/build_tables.py --paper ../paper       write the fragments
  python docs/build_tables.py --paper ../paper --check   fail if they would change

`--check` is the mode that matters: it regenerates into memory and diffs against
what is on disk, so CI fails if a result file was regenerated and the paper was
not. Run it after any result file changes.

Rounding is done once, here, in `_f`/`_pct`/`_int`. Nothing downstream rounds
again, so a number cannot drift between the table and the prose that quotes it.
"""

import argparse
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "data")

# Display names. The result files key families by their internal short name;
# these are what the paper prints.
FAMILY = {
    "sqli": "SQLi", "xss": "XSS", "cmdi": "Command inj.",
    "traversal": "Path traversal", "ssti": "SSTI", "nosqli": "NoSQLi",
    "ssrf": "SSRF", "crlf": "CRLF", "ldapi": "LDAP inj.", "xxe": "XXE",
    "jndi": "JNDI/Log4Shell", "deser": "Deserialization",
    "protopollute": "Prototype poll.", "smuggle": "Req. smuggling",
}
CORPORA = ("CSIC-2010", "ECML/PKDD-2007", "WebInject2026")
# Zoo tiers, in the order Table 6 prints them.
_TIERS = ("classical", "deep", "transformer")
# Macro infix per corpus, so \ablCsicKept and \pmCsicKept agree on "Csic".
TAG = {"CSIC-2010": "Csic", "ECML/PKDD-2007": "Ecml", "WebInject2026": "Wi"}


def _load(name):
    with open(os.path.join(DATA, name), encoding="utf-8") as f:
        return json.load(f)


def _f(x, nd=3):
    """Fixed-point, the form used for AUCs and other 0-1 scores."""
    return f"{x:.{nd}f}"


def _pct(x, nd=1):
    """A 0-1 rate rendered as a percentage. The `%` sign lives in the .tex."""
    return f"{x * 100:.{nd}f}" if nd else f"{round(x * 100):.0f}"


def _int(n):
    """Thousands-separated, matching the paper's typography."""
    return f"{n:,}"


def _by_corpus(rows):
    return {r["corpus"]: r for r in rows}


def _kept(row, cond="syntax_and_vocab_deleted"):
    """AUC kept, Equation 1: above-chance separation as a share of the full
    model's. Recomputed here from the two AUCs rather than read from
    `auc_retained`, so the published ratio and the published AUCs cannot
    disagree."""
    full, deleted = row["full"]["roc_auc"], row[cond]["roc_auc"]
    return (deleted - 0.5) / (full - 0.5)


def _delta(row, cond="syntax_and_vocab_deleted"):
    """Raw AUC difference. Reported alongside the ratio because the ratio is
    unstable where the denominator is small (Panel C, CSIC-2010)."""
    return row["full"]["roc_auc"] - row[cond]["roc_auc"]


def build_macros():
    """Return an ordered list of (name, value) pairs and the section comments.

    Order is: an alphabetical core, then the external-holdout block, then the
    delta block -- matching the order the shipped file was written in, so a
    regeneration produces no spurious diff.
    """
    ev = _load("evaluation.json")
    bl = _load("baselines.json")
    sep = _load("separability.json")
    sc = _load("shortcut_stats.json")
    sa = _load("syntax_ablation.json")
    am = _load("ablation_models.json")
    pm = _load("protocol_matched.json")
    skt = _load("skeleton_transfer.json")
    zoo = _load("model_zoo.json")
    zooc = _load("model_zoo_capped.json")
    ext = _load("external_payloads.json")
    sx = _load("skeleton_external.json")
    man = _load("manifest.json")

    m = {}

    # ---- corpus shape, from the build manifest -----------------------------
    m["wiRows"] = _int(man["rows"])
    m["wiAttack"] = _int(man["label"]["1"])
    m["wiBenign"] = _int(man["label"]["0"])
    m["wiAttackPct"] = _pct(man["label"]["1"] / man["rows"])
    m["wiRoutine"] = _int(man["tier"]["routine"])
    m["wiHardNeg"] = _int(man["tier"]["hard_negative"])
    m["wiAmbiguous"] = _int(man["tier"]["ambiguous"])
    m["wiFamilies"] = str(sum(1 for k in man["family"]
                              if not k.startswith("benign")))
    m["wiSessions"] = _int(man["sessions"])
    m["wiEvasion"] = _int(man["evasion_used"])
    m["wiEvasionChained"] = _int(man["evasion_chained"])
    m["wiSeed"] = str(man["seed"])
    m["wiVersion"] = man["version"]
    m["wiApps"] = str(len(man["app"]))
    m["wiTrain"] = _int(man["split"]["train"])
    m["wiVal"] = _int(man["split"]["val"])
    m["wiTest"] = _int(man["split"]["test"])
    g = man["groups"]
    m["wiGroups"] = _int(g["attack_total"])
    m["wiGroupsTest"] = _int(g["attack_test"])
    m["wiTemplates"] = str(g["attack_templates"])
    m["wiTemplatesTest"] = str(g["attack_templates_test"])
    m["wiBenignCores"] = _int(g["benign_cores"])
    m["wiAmbigCores"] = _int(g["ambiguous_cores"])

    # Release version is the citation metadata, not a result.
    with open(os.path.join(ROOT, "CITATION.cff"), encoding="utf-8") as f:
        for line in f:
            if line.startswith("version:"):
                m["wiRelease"] = line.split(":", 1)[1].strip()
                break

    # ---- headline detector, both protocols ---------------------------------
    dj, st = ev["disjoint"], ev["structural"]
    m["djFone"] = _pct(dj["f1"])
    m["djRecall"] = _pct(dj["recall"])
    m["djTPR"] = _pct(dj["tpr_at_0.1pct_fpr"])
    m["djTPRone"] = _pct(dj["tpr_at_1pct_fpr"])
    m["stFone"] = _pct(st["f1"])
    m["stTPR"] = _pct(st["tpr_at_0.1pct_fpr"])
    m["gapTPR"] = _pct(dj["tpr_at_0.1pct_fpr"] - st["tpr_at_0.1pct_fpr"])
    m["nTestPairs"] = _int(dj["n_attack"])
    m["testAttackPct"] = _pct(dj["n_attack"] / dj["n"])
    m["prevCorpus"] = _pct(ev["calibration"]["base_rate"])

    # Precision corrected to deployment prevalence, at both budgets.
    ppv1 = ev["disjoint"]["ppv_at_prevalence@1pctFPR"]
    ppvs = bl["char_ngram_ppv_by_prevalence"]
    m["ppvHalf"] = _pct(ppv1["0.005"])
    m["ppvOne"] = _pct(ppv1["0.010"])
    m["ppvFive"] = _pct(ppv1["0.050"])
    m["ppvCorpus"] = _pct(ppv1["0.262"])
    m["ppvStrictHalf"] = _pct(ppvs["0.001"]["0.005"])
    m["ppvStrictOne"] = _pct(ppvs["0.001"]["0.01"])
    m["ppvStrictFive"] = _pct(ppvs["0.001"]["0.05"])
    m["ppvStrictCorpus"] = _pct(ppvs["0.001"]["0.2624"])

    # ---- calibration, attribution, evasion ---------------------------------
    cal = ev["calibration"]
    m["calBrier"] = _f(cal["brier"])
    m["calECE"] = _f(cal["ece"])
    m["calMCE"] = _f(cal["mce"])
    m["calBaseRate"] = _f(cal["base_rate"])
    m["calMeanScore"] = _f(cal["mean_score"])

    at = ev["attribution"]
    m["attrN"] = _int(at["n"])
    m["attrAttack"] = _f(at["mean_score_attack"])
    m["attrSpanDel"] = _f(at["mean_score_span_removed"])
    m["attrTwin"] = _f(at["mean_score_twin"])
    m["attrShare"] = _pct(at["span_attribution_mean"])
    m["attrShareMed"] = _pct(at["span_attribution_median"])
    m["attrLocal"] = _pct(at["localisation_rate"])

    m["evAll"] = _pct(ev["evasion"]["all_evaded"]["recall"])
    m["evSingle"] = _pct(ev["evasion"]["single"]["recall"])
    m["evChained"] = _pct(ev["evasion"]["chained"]["recall"])

    # False positives by tier and by benign register.
    fp = ev["errors"]["false_positives_by_tier"]
    m["fpAmbig"] = _pct(fp["ambiguous"])
    m["fpRoutine"] = _pct(fp["routine"])
    reg = ev["errors"]["false_positives_by_benign_category"]
    named = {k: v for k, v in reg.items() if not k.startswith("(")}
    m["fpSearch"] = _pct(named["search"]["fp_rate"], 2)
    m["fpCleanRegisters"] = str(sum(1 for v in named.values()
                                    if v["false_positives"] == 0))

    # ---- leave-one-family-out ---------------------------------------------
    lofo = ev["lofo"]
    zs = {k: v["zeroshot_recall"] for k, v in lofo.items()}
    lo, hi = min(zs, key=zs.get), max(zs, key=zs.get)
    m["lofoMin"] = _pct(zs[lo])
    m["lofoMinFam"] = FAMILY[lo]
    m["lofoMax"] = _pct(zs[hi])
    m["lofoMaxFam"] = FAMILY[hi]

    fam = bl["char_ngram_recall_by_family"]
    others = [v["recall"] for k, v in fam.items() if k != "cmdi"]
    m["famRecallLo"] = _pct(min(others))
    m["famRecallHi"] = _pct(max(others))
    m["cmdiRecall"] = _pct(fam["cmdi"]["recall"])
    m["cmdiFNR"] = _pct(1 - fam["cmdi"]["recall"])

    # ---- baselines ---------------------------------------------------------
    b = bl["baselines"]
    m["ruleFone"] = _pct(b["rule signature (14 regex)"]["payload-disjoint"]["f1"])
    m["ruleTPR"] = _pct(b["rule signature (14 regex)"]["payload-disjoint"]["tpr_at_0.1pct_fpr"])
    m["wnFone"] = _pct(b["word n-gram (1-2) + LogReg"]["payload-disjoint"]["f1"])
    m["wnTPR"] = _pct(b["word n-gram (1-2) + LogReg"]["payload-disjoint"]["tpr_at_0.1pct_fpr"])
    m["cnFone"] = _pct(b["char n-gram (3-5) + LogReg"]["payload-disjoint"]["f1"])
    m["cnTPR"] = _pct(b["char n-gram (3-5) + LogReg"]["payload-disjoint"]["tpr_at_0.1pct_fpr"])

    ci = bl["char_ngram_group_bootstrap_ci95"]
    m["ciFoneLo"], m["ciFoneHi"] = _pct(ci["f1"][0]), _pct(ci["f1"][1])
    m["ciTPRLo"], m["ciTPRHi"] = (_pct(ci["tpr_at_0.1pct_fpr"][0]),
                                  _pct(ci["tpr_at_0.1pct_fpr"][1]))

    # ---- cross-corpus transfer --------------------------------------------
    xc = bl["cross_dataset"]["webinject"]
    m["xcCsicAuc"] = _f(xc["csic"]["roc_auc"], 2)
    m["xcCsicF"] = _pct(xc["csic"]["f1"])
    m["xcEcmlAuc"] = _f(xc["ecml"]["roc_auc"], 2)
    m["xcEcmlF"] = _pct(xc["ecml"]["f1"])
    m["xcRate"] = _pct(max(xc["csic"]["pred_pos_rate"],
                           xc["ecml"]["pred_pos_rate"]), 0)

    # ---- single-character separability ------------------------------------
    for key, tag in (("webinject2026", "Wi"), ("csic", "Csic"), ("ecml", "Ecml")):
        top = max(sc[key], key=lambda c: c["auc"])
        ch = top["char"]
        m[f"sc{tag}Char"] = "\\%" if ch == "%" else ch
        m[f"sc{tag}Auc"] = _f(top["auc"])
        m[f"sc{tag}V"] = _f(top["cramers_v"])

    # ---- skeleton ----------------------------------------------------------
    sk = sep["skeleton"]
    m["skWi"] = _f(sk["WebInject2026"]["skeleton_auc"])
    m["skCsic"] = _f(sk["CSIC-2010"]["skeleton_auc"])
    m["skEcml"] = _f(sk["ECML/PKDD-2007"]["skeleton_auc"])
    wp = sk["WebInject2026"]["within_pair"]
    m["skPair"] = _f(wp["skeleton_auc"])
    m["skPairRate"] = _pct(wp["attack_above_twin"])
    m["skPairs"] = _int(wp["n_pairs"])
    td = sk["WebInject2026"]["template_disjoint"]
    m["skStruct"] = _f(td["skeleton_auc"])
    m["skStructFull"] = _f(td["full_payload_auc"])

    m["sktSelfSkel"] = _f(skt["source"]["skeleton_auc_in_domain"])
    m["sktSelfFull"] = _f(skt["source"]["full_auc_in_domain"])
    m["sktCsicSkel"] = _f(skt["csic_parsed"]["skeleton_transfer_auc"])
    m["sktCsicFull"] = _f(skt["csic_parsed"]["full_transfer_auc"])
    m["sktEcmlSkel"] = _f(skt["ecml_parsed"]["skeleton_transfer_auc"])
    m["sktEcmlFull"] = _f(skt["ecml_parsed"]["full_transfer_auc"])

    # ---- Panel A (pooled vocabulary) and Panel B (per-corpus) --------------
    pool, sym = _by_corpus(sa["pool"]), _by_corpus(sa["symmetric"])
    for corpus in CORPORA:
        t, r = TAG[corpus], pool[corpus]
        if t != "Wi":
            m[f"abl{t}FullAuc"] = _f(r["full"]["roc_auc"])
        if t != "Ecml":
            m[f"abl{t}Auc"] = _f(r["syntax_and_vocab_deleted"]["roc_auc"])
        m[f"abl{t}Kept"] = _pct(_kept(r), 0)
        m[f"abl{t}Chars"] = _pct(r["syntax_and_vocab_deleted"]["chars_deleted"], 0)
        m[f"ablSyn{t}Kept"] = _pct(_kept(r, "syntax_deleted"), 0)
    m["ablWiFull"] = _f(pool["WebInject2026"]["full"]["roc_auc"])
    m["ablWiF"] = _f(pool["WebInject2026"]["syntax_and_vocab_deleted"]["f1"])

    wi_del = pool["WebInject2026"]["syntax_and_vocab_deleted"]
    m["ablPaired"] = _pct(wi_del["paired_accuracy"])
    m["ablPairedTies"] = _pct(wi_del["paired_ties"])

    for corpus in ("ECML/PKDD-2007", "WebInject2026"):
        t, r = TAG[corpus], sym[corpus]
        m[f"sym{t}Kept"] = _pct(_kept(r), 0)
        m[f"sym{t}Chars"] = _pct(r["syntax_and_vocab_deleted"]["chars_deleted"], 0)
    m["symPaired"] = _pct(
        sym["WebInject2026"]["syntax_and_vocab_deleted"]["paired_accuracy"], 0)

    # Carrier-only AUC range across the zoo, full-data tier.
    carr = [v["ablation_carrier_only"]["roc_auc"]
            for z in (zoo, zooc)
            for tier in _TIERS if tier in z
            for v in z[tier].values()
            if v.get("ablation_carrier_only")]
    m["carrierLo"], m["carrierHi"] = _f(min(carr)), _f(max(carr))

    # ---- Panel C (protocol matched) ---------------------------------------
    pmc = _by_corpus(pm["protocol_matched"])
    for corpus in CORPORA:
        t, r = TAG[corpus], pmc[corpus]
        m[f"pm{t}Raw"] = _int(r["n_raw"])
        m[f"pm{t}Dedup"] = _int(r["n_dedup"])
        m[f"pm{t}Groups"] = _int(r["n_groups"])
        m[f"pm{t}DupShare"] = _pct(r["dup_share"], 0)
        m[f"pm{t}Base"] = _pct(r["base_rate"], 0)
        m[f"pm{t}FullAuc"] = _f(r["full"]["roc_auc"])
        m[f"pm{t}Auc"] = _f(r["syntax_and_vocab_deleted"]["roc_auc"])
        m[f"pm{t}Kept"] = _pct(_kept(r), 0)

    # ---- the model zoo -----------------------------------------------------
    def _span(z, tiers, protocol, key):
        vals = [v[protocol][key] for t in tiers if t in z
                for v in z[t].values()
                if v.get(protocol, {}).get(key) is not None]
        return min(vals), max(vals)

    lo, hi = _span(zoo, ("classical",), "payload-disjoint", "f1")
    m["zooFoneLo"], m["zooFoneHi"] = _pct(lo), _pct(hi)
    lo, hi = _span(zoo, ("classical",), "payload-disjoint", "tpr_at_0.1pct_fpr")
    m["zooTPRLo"], m["zooTPRHi"] = _pct(lo), _pct(hi)
    lo, hi = _span(zoo, _TIERS, "structural", "tpr_at_0.1pct_fpr")
    m["zooStructLo"], m["zooStructHi"] = _pct(lo), _pct(hi)

    # ---- multi-architecture ablation --------------------------------------
    for model, tag in (("cnn", "Cnn"), ("bert", "Bert")):
        rows = _by_corpus(am[model])
        for corpus in CORPORA:
            t, r = TAG[corpus], rows[corpus]
            m[f"ablm{tag}{t}Full"] = _f(r["full"]["roc_auc"])
            m[f"ablm{tag}{t}Auc"] = _f(r["syntax_and_vocab_deleted"]["roc_auc"])
            m[f"ablm{tag}{t}Kept"] = _pct(_kept(r), 0)

    # ---- the audit gate ----------------------------------------------------
    # Counted from the source rather than hardcoded, so adding a check to the
    # gate updates the paper and cannot silently disagree with it.
    def _count(rel, needle):
        with open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
            return sum(1 for ln in fh if ln.lstrip().startswith(needle))

    n_val = _count("src/validate.py", "chk.add(")
    n_con = _count("src/audit_gaps.py", "def check_")
    m["gateValidation"] = str(n_val)
    m["gateConstruction"] = str(n_con)
    m["gateTotal"] = str(n_val + n_con)

    core = [(k, m[k]) for k in sorted(m)]

    # ---- appended blocks, in the order they were added ---------------------
    e = {}
    e["extN"] = str(ext["n_external_attacks"])
    e["extDropped"] = _int(ext["n_patt_dropped_as_seen"])
    e["extRecall"] = _pct(ext["recall_at_0.5"])
    e["extTPRone"] = _pct(ext["tpr_at_1pct_fpr"])
    e["extTPR"] = _pct(ext["tpr_at_0.1pct_fpr"])
    e["extPaired"] = _pct(ext["paired_accuracy"])
    bf = ext["by_family"]
    worst = min(bf, key=lambda k: bf[k]["recall"])
    best = max(bf, key=lambda k: bf[k]["recall"])
    e["extWorstFam"] = FAMILY[worst]
    e["extWorstRecall"] = _pct(bf[worst]["recall"], 0)
    e["extBestFam"] = FAMILY[best]
    e["extBestRecall"] = _pct(bf[best]["recall"], 0)
    e["extNeg"] = _int(ext["n_benign_reference"])

    d = {}
    for corpus in CORPORA:
        d[f"pm{TAG[corpus]}Delta"] = _f(_delta(pmc[corpus]))
    for corpus in CORPORA:
        d[f"abl{TAG[corpus]}Delta"] = _f(_delta(pool[corpus]))
    for corpus in CORPORA:
        d[f"abl{TAG[corpus]}SymDelta"] = _f(_delta(sym[corpus]))
    # Panel C's denominator, quoted in §6 to explain the ratio's instability.
    d["pmCsicDenom"] = _f(pmc["CSIC-2010"]["full"]["roc_auc"] - 0.5)

    # ---- seed spread on Panel C -------------------------------------------
    # Panel C draws its own split, so unlike Panels A and B its numbers move
    # with the seed. Reported as a range because one of the orderings flips.
    sp = pm.get("seed_spread", {})
    v = {}
    if sp:
        v["pmSeeds"] = str(len(sp["CSIC-2010"]["seeds"]))
        for corpus in CORPORA:
            t = TAG[corpus]
            v[f"pm{t}SeedLo"] = _pct(sp[corpus]["min"], 0)
            v[f"pm{t}SeedHi"] = _pct(sp[corpus]["max"], 0)

    # ---- the external skeleton control ------------------------------------
    v["sxN"] = str(sx["n_external_attacks"])
    v["sxPairs"] = _int(sx["n_pairs"])
    v["sxPaired"] = _pct(sx["paired_accuracy"])
    v["sxTies"] = _pct(sx["paired_ties"])
    v["sxAuc"] = _f(sx["skeleton_auc_vs_test_benign"])
    v["sxPairAuc"] = _f(sx["skeleton_auc_within_pair"])
    v["sxInCorpus"] = _pct(sx["in_corpus_paired_accuracy"])

    return core, list(e.items()), list(d.items()) + list(v.items())


HEAD = "%% GENERATED by build_tables.py -- do not edit by hand.\n"


def render_macros():
    core, ext, delta = build_macros()
    out = [HEAD]
    out += [f"\\newcommand{{\\{k}}}{{{v}}}\n" for k, v in core]
    out.append("\n%% GENERATED from data/external_payloads.json "
               "(external payload holdout).\n")
    out += [f"\\newcommand{{\\{k}}}{{{v}}}\n" for k, v in ext + delta]
    return "".join(out)


def _tabular(colspec, header, rows):
    out = [HEAD, f"\\begin{{tabular}}{{{colspec}}}\n", "\\hline\n",
           " & ".join(header) + " \\\\\n", "\\hline\n"]
    out += [" & ".join(r) + " \\\\\n" for r in rows]
    out += ["\\hline\n", "\\end{tabular}\n"]
    return "".join(out)


def render_ablation(panel):
    sa = _by_corpus(_load("syntax_ablation.json")[panel])
    rows = []
    for c in CORPORA:
        r = sa[c]
        d = r["syntax_and_vocab_deleted"]
        rows.append([c, _f(r["full"]["f1"]), _f(r["full"]["roc_auc"]),
                     _f(d["f1"]), _f(d["roc_auc"]), _f(_delta(r)),
                     _int(r["vocab_size"]),
                     _pct(d["chars_deleted"], 0) + "\\%",
                     _pct(_kept(r), 0) + "\\%"])
    return _tabular("|l|r|r|r|r|r|r|r|r|",
                    ["Corpus", "full F1", "full AUC", "F1", "AUC",
                     "$\\Delta$AUC", "vocab", "chars del.", "AUC kept"], rows)


def render_baselines():
    b = _load("baselines.json")["baselines"]
    label = {
        "length only (1 feature)": "Length only (1 feature)",
        "special-char count (1 feature)": "Special-char count (1 feature)",
        "rule signature (14 regex)": "Rule signature (14 regex)",
        "word n-gram (1-2) + LogReg": "Word $n$-gram (1--2) + LogReg",
        "char n-gram (3-5) + LogReg": "Char $n$-gram (3--5) + LogReg",
    }
    rows = []
    for key, name in label.items():
        r = b[key]["payload-disjoint"]
        rows.append([name, _pct(r["f1"]), _pct(r["pr_auc"]),
                     _pct(r["tpr_at_1pct_fpr"]),
                     _pct(r["tpr_at_0.1pct_fpr"])])
    return _tabular("|l|r|r|r|r|",
                    ["Baseline", "F1", "PR-AUC", "TPR@1\\%FPR",
                     "TPR@0.1\\%FPR"], rows)


def render_lofo():
    ev, bl = _load("evaluation.json"), _load("baselines.json")
    fam = bl["char_ngram_recall_by_family"]
    # Ascending by zero-shot recall: the table's argument is the ordering.
    order = sorted(ev["lofo"], key=lambda k: ev["lofo"][k]["zeroshot_recall"])
    rows = [[FAMILY[k], str(ev["lofo"][k]["n_test"]),
             _pct(fam[k]["recall"]),
             _pct(ev["lofo"][k]["zeroshot_recall"])] for k in order]
    return _tabular("|l|r|r|r|",
                    ["Held-out family", "$n$", "In-training", "Zero-shot"], rows)


def render_zoo(capped):
    z = _load("model_zoo_capped.json" if capped else "model_zoo.json")

    def cell(d, key, fn):
        """A model that failed to converge ships as an empty entry and prints
        as a rule, so a reader can tell a failed run from an omitted one."""
        if not d or d.get(key) is None:
            return "---"
        return fn(d[key])

    rows = []
    for tier in _TIERS:
        for name, r in z.get(tier, {}).items():
            rows.append([name, tier,
                         cell(r.get("payload-disjoint"), "f1", _pct),
                         cell(r.get("payload-disjoint"), "tpr_at_0.1pct_fpr", _pct),
                         cell(r.get("structural"), "tpr_at_0.1pct_fpr", _pct),
                         cell(r.get("payload-disjoint"), "paired_accuracy", _pct),
                         cell(r.get("ablation_carrier_only"), "roc_auc", _f)])
    return _tabular("|l|l|r|r|r|r|r|",
                    ["Model", "Family", "F1", "TPR@0.1\\%FPR", "structural",
                     "paired acc.", "carrier-only AUC"], rows)


TARGETS = {
    "macros.tex": render_macros,
    "tab_ablation_pool.tex": lambda: render_ablation("pool"),
    "tab_ablation_symmetric.tex": lambda: render_ablation("symmetric"),
    "tab_baselines.tex": render_baselines,
    "tab_lofo.tex": render_lofo,
    "tab_zoo_capped.tex": lambda: render_zoo(True),
    "tab_zoo_full.tex": lambda: render_zoo(False),
}


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--paper", required=True,
                    help="paper source directory (the one containing tables/)")
    ap.add_argument("--check", action="store_true",
                    help="do not write; exit 1 if any file would change")
    args = ap.parse_args()

    tables = os.path.join(args.paper, "tables")
    if not os.path.isdir(tables):
        sys.exit(f"no tables/ directory under {args.paper}")

    stale = []
    for name, render in TARGETS.items():
        new = render()
        path = os.path.join(tables, name)
        old = (open(path, encoding="utf-8").read()
               if os.path.exists(path) else None)
        if args.check:
            if old != new:
                stale.append(name)
                print(f"  WOULD CHANGE  {name}")
            else:
                print(f"  ok            {name}")
        else:
            with open(path, "w", encoding="utf-8") as f:
                f.write(new)
            print(f"  {'rewrote' if old != new else 'unchanged'}      {name}")

    if args.check:
        print("RESULT:", "STALE" if stale else "ALL FRAGMENTS CURRENT")
        sys.exit(1 if stale else 0)


if __name__ == "__main__":
    sys.path.insert(0, ROOT)
    main()
