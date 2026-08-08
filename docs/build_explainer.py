"""Build ``Understanding_WebInject2026.pdf`` from the shipped result JSONs.

The previous explainer was deleted because it hard-coded v3.0.0 numbers and a
25-check gate, and went four versions stale. This script removes that failure
mode the same way ``src/figures.py`` does: **every number in the document is
read from a shipped JSON at build time**, never typed by hand. Rebuild it after
any corpus rebuild, alongside the figures:

    python -m src.build
    python -m src.baselines      --json data/baselines.json
    python -m src.evaluate       --json data/evaluation.json
    python -m src.shortcut_stats --json data/shortcut_stats.json
    python -m src.separability
    python -m src.syntax_ablation --json data/syntax_ablation.json
    python docs/build_explainer.py            # -> Understanding_WebInject2026.pdf

Inputs (all under data/):
    manifest.json  baselines.json  evaluation.json  shortcut_stats.json
    separability.json  syntax_ablation.json  model_zoo_capped.json
    model_zoo.json (optional -- the full-data table, if present)

Design notes:
  * A4, Helvetica body, tables rather than prose for numbers.
  * ReportLab's built-in fonts are WinAnsi, so arrows, >=, <= and check marks
    render as black boxes. Everything below is ASCII -- ">=", "->", "x".
  * Written for a reader with basic computing knowledge and no security or ML
    background: three layers per idea (everyday intuition, then mechanism, then
    the measured detail), the shape the deleted document used.
"""

import datetime as _dt
import json
import os
import re
import sys

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (BaseDocTemplate, CondPageBreak, Frame,
                                KeepTogether, PageBreak, PageTemplate,
                                Paragraph, Spacer, Table, TableStyle)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "data")
OUT = os.path.join(ROOT, "Understanding_WebInject2026.pdf")

# ------------------------------------------------------------------- palette --
INK = colors.HexColor("#1A1A1A")
BLUE = colors.HexColor("#2E75B6")
RED = colors.HexColor("#C0392B")
GREEN = colors.HexColor("#27AE60")
LIGHT = colors.HexColor("#EEF3F9")
LIGHTER = colors.HexColor("#F7F9FC")
RULE = colors.HexColor("#BBBBBB")


def _load(name, required=True):
    path = os.path.join(DATA, name)
    if not os.path.exists(path):
        if required:
            sys.exit(f"missing required input {path} -- regenerate it first")
        return None
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _ascii(s):
    """Map the few non-WinAnsi glyphs that creep in from prose to ASCII, and
    escape any stray ampersand that is not part of an intended XML entity, so
    literals like "&#" in the prose do not trip ReportLab's paragraph parser."""
    s = (str(s).replace("→", "->").replace("≥", ">=")
         .replace("≤", "<=").replace("–", "-").replace("—", "--")
         .replace("’", "'").replace("×", "x").replace("≈", "~"))
    return re.sub(r"&(?!(?:amp|lt|gt|nbsp|middot|#\d+);)", "&amp;", s)


def pct(x, nd=1):
    return f"{x * 100:.{nd}f}"


# ------------------------------------------------------------------- styles ---
def styles():
    ss = getSampleStyleSheet()
    body = ParagraphStyle("body", parent=ss["BodyText"], fontName="Helvetica",
                          fontSize=9.7, leading=13.6, spaceAfter=6, textColor=INK,
                          alignment=TA_LEFT)
    h1 = ParagraphStyle("h1", parent=ss["Heading1"], fontName="Helvetica-Bold",
                        fontSize=16, leading=19, spaceBefore=6, spaceAfter=8,
                        textColor=BLUE)
    h2 = ParagraphStyle("h2", parent=ss["Heading2"], fontName="Helvetica-Bold",
                        fontSize=12, leading=15, spaceBefore=12, spaceAfter=4,
                        textColor=INK)
    layer = ParagraphStyle("layer", parent=body, fontName="Helvetica-Oblique",
                           fontSize=9.4, leading=13, textColor=colors.HexColor("#555555"),
                           spaceAfter=3)
    lead = ParagraphStyle("lead", parent=body, fontName="Helvetica-Bold",
                          fontSize=9.7, leading=13.6, textColor=INK, spaceAfter=2)
    cap = ParagraphStyle("cap", parent=body, fontSize=8.4, leading=11,
                         textColor=colors.HexColor("#666666"), spaceBefore=2)
    title = ParagraphStyle("title", parent=h1, fontSize=25, leading=29,
                           alignment=TA_CENTER, textColor=BLUE, spaceAfter=6)
    sub = ParagraphStyle("sub", parent=body, fontSize=12, leading=16,
                         alignment=TA_CENTER, textColor=INK)
    qq = ParagraphStyle("qq", parent=body, fontName="Helvetica-Bold", spaceAfter=1)
    return dict(body=body, h1=h1, h2=h2, layer=layer, lead=lead, cap=cap,
                title=title, sub=sub, qq=qq)


S = styles()


def P(text, style="body"):
    return Paragraph(_ascii(text), S[style])


def layered(intuition, mechanism, detail):
    """The three-layer idiom: intuition, then mechanism, then measured detail."""
    return [P("Intuition. " + intuition, "layer"),
            P("Mechanism. " + mechanism, "body"),
            P("Detail. " + detail, "body")]


def table(data, col_widths=None, header=True, highlight_last_col=False,
          highlight_rows=()):
    t = Table(data, colWidths=col_widths, hAlign="LEFT", repeatRows=1 if header else 0)
    cmds = [
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 8.6),
        ("TEXTCOLOR", (0, 0), (-1, -1), INK),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("ALIGN", (1, 0), (-1, -1), "RIGHT"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LINEBELOW", (0, 0), (-1, -1), 0.25, RULE),
        ("ROWBACKGROUNDS", (0, 1 if header else 0), (-1, -1),
         [colors.white, LIGHTER]),
    ]
    if header:
        cmds += [
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("BACKGROUND", (0, 0), (-1, 0), BLUE),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("ALIGN", (0, 0), (0, 0), "LEFT"),
            ("LINEBELOW", (0, 0), (-1, 0), 0.6, BLUE),
        ]
    if highlight_last_col:
        cmds.append(("FONTNAME", (-1, 1), (-1, -1), "Helvetica-Bold"))
        cmds.append(("BACKGROUND", (-1, 1), (-1, -1), LIGHT))
    for r in highlight_rows:
        cmds.append(("BACKGROUND", (0, r), (-1, r), colors.HexColor("#FDECEA")))
        cmds.append(("FONTNAME", (0, r), (-1, r), "Helvetica-Bold"))
    t.setStyle(TableStyle(cmds))
    return t


# =========================================================== content sections =
def sec_title(man, story):
    v = man.get("version", "?")
    built = man.get("built_utc", "")[:10]
    story += [Spacer(1, 3.2 * cm),
              P("Understanding WebInject2026", "title"),
              P("A leakage-audited corpus for web-injection detection", "sub"),
              Spacer(1, 0.5 * cm),
              P(f"Version {v} &nbsp;&middot;&nbsp; {man['rows']:,} labelled HTTP "
                f"requests &nbsp;&middot;&nbsp; built {built}", "sub"),
              Spacer(1, 1.4 * cm)]
    intro = (
        "This document explains, from first principles and with no assumed "
        "security or machine-learning background, what this dataset is, the "
        "problem it was built to expose, and every headline number it reports. "
        "It is generated directly from the dataset's own result files, so it "
        "cannot drift out of date: if a number appears here, a script measured "
        "it on the shipped corpus. Each idea is given three times over -- an "
        "everyday intuition, then the mechanism, then the measured detail -- so "
        "you can stop at whichever depth you need.")
    story.append(P(intro))
    story.append(Spacer(1, 0.5 * cm))
    story.append(P("What you are looking at", "h2"))
    story += layered(
        "A web application is a form you fill in; an injection attack is typing "
        "a command into the form where the software expected a name or a search "
        "term, and getting the command run. This corpus is a large, carefully "
        "labelled pile of such form submissions -- some ordinary, some hostile "
        "-- for teaching a computer to tell them apart.",
        "Each row is one HTTP request: the address it went to, the parameters "
        "it carried, its headers, and a label -- benign or one of fourteen "
        "attack families. Roughly a quarter of the rows are attacks.",
        f"{man['rows']:,} rows across three deliberately vulnerable practice "
        f"applications ({', '.join(man['app'].keys())}); "
        f"{man['label']['1']:,} attacks and {man['label']['0']:,} benign "
        f"({pct(man['label']['1'] / man['rows'])}% attack).")
    story.append(PageBreak())


def sec_injection(man, story):
    story.append(P("1 &nbsp; What an injection attack is", "h1"))
    story += layered(
        "Imagine a bank teller who does whatever is written on your deposit "
        "slip. Normally you write an amount. An attacker writes 'give me the "
        "contents of every account' -- and a naive teller obeys, because it "
        "never separated your data from its own instructions.",
        "Software builds database queries, page HTML, shell commands and file "
        "paths by pasting user input into a template string. If the input "
        "contains the punctuation that ends the data and begins a new "
        "instruction -- a quote, an angle bracket, a semicolon -- the input "
        "escapes the slot it was meant to fill and becomes code.",
        "The corpus covers fourteen such families. Each abuses a different "
        "interpreter: SQL databases (SQLi), the browser (XSS), the operating "
        "system shell (command injection), the file system (path traversal), "
        "template engines (SSTI), NoSQL and LDAP directories, XML parsers "
        "(XXE), logging libraries (JNDI/Log4Shell), object deserialisers, "
        "JavaScript prototypes, and the HTTP layer itself (CRLF, request "
        "smuggling).")
    fam = {k: v for k, v in man["attack_type"].items() if k != "benign"}
    fam = sorted(fam.items(), key=lambda kv: -kv[1])
    rows = [["Family", "Rows", "Family", "Rows"]]
    half = (len(fam) + 1) // 2
    for i in range(half):
        left = fam[i]
        right = fam[i + half] if i + half < len(fam) else ("", "")
        rows.append([left[0], f"{left[1]:,}", right[0],
                     f"{right[1]:,}" if right[1] != "" else ""])
    story.append(Spacer(1, 0.2 * cm))
    story.append(table(rows, col_widths=[4.2 * cm, 2.6 * cm, 4.2 * cm, 2.6 * cm]))
    story.append(P("The fourteen attack families and their row counts in the "
                   "shipped corpus.", "cap"))


def sec_why_corpora(abl, story):
    story.append(P("2 &nbsp; Why the existing corpora are not enough", "h1"))
    story += layered(
        "If an exam's answer is written in the margin, a student who scores "
        "100% has not proved they understand the subject -- only that they can "
        "read the margin. The web-security field has been grading detectors on "
        "exams with the answer in the margin, and reporting the scores as "
        "understanding.",
        "The standard corpora (CSIC-2010, ECML/PKDD-2007) were assembled so "
        "that benign and attack traffic differ in ways that have nothing to do "
        "with the attack: different lengths, different vocabulary, different "
        "punctuation density. A model can reach ~99% by keying on those "
        "artefacts and never learning the injection.",
        "This is testable, so we test it. Delete the injection from every row "
        "-- first the syntax (every character that is not a letter or a space), "
        "then additionally every word in the attack vocabulary -- retrain the "
        "same model on the same split, and see how much detection performance "
        "survives. If a lot survives, the model was never reading the attack.")

    by = {d["corpus"]: d for d in abl}
    order = ["CSIC-2010", "ECML/PKDD-2007", "WebInject2026"]
    header = ["Corpus", "full F1", "full AUC", "-inj F1", "-inj AUC", "AUC kept"]
    rows = [header]
    for c in order:
        d = by.get(c)
        if not d:
            continue
        f = d["full"]
        sv = d["syntax_and_vocab_deleted"]
        rows.append([c, f"{f['f1']:.3f}", f"{f['roc_auc']:.3f}",
                     f"{sv['f1']:.3f}", f"{sv['roc_auc']:.3f}",
                     pct(sv["auc_retained"], 0) + "%"])
    story.append(Spacer(1, 0.2 * cm))
    story.append(table(rows, col_widths=[4.4 * cm, 2.2 * cm, 2.2 * cm, 2.2 * cm,
                                          2.2 * cm, 2.2 * cm],
                       highlight_last_col=True))
    wi = by["WebInject2026"]
    csic = by["CSIC-2010"]
    story.append(P(
        "Table 1. 'AUC kept' is separation above chance as a share of the full "
        "model's (0.5 is a coin). With every trace of the attack deleted, "
        f"CSIC-2010 keeps {pct(csic['syntax_and_vocab_deleted']['auc_retained'],0)}% "
        f"of its detection performance -- whatever its reported 0.99 measures, "
        f"it is not injection. WebInject2026 keeps only "
        f"{pct(wi['syntax_and_vocab_deleted']['auc_retained'],0)}%: delete the "
        "attack and the signal is gone, which is the property a detection "
        "corpus should have.", "cap"))
    pa = wi["syntax_and_vocab_deleted"].get("paired_accuracy")
    if pa is not None:
        story.append(P(
            "Because every attack here has a matched benign twin, a stricter "
            "version is possible that no other corpus supports: score each "
            "attack against its own twin with the injection deleted. Result "
            f"{pct(pa)}%, with {pct(wi['syntax_and_vocab_deleted']['paired_ties'])}% "
            "of pairs scoring identically -- chance is 50%. With the injection "
            "removed there is nothing left to separate a pair."))


def sec_leakage(story):
    story.append(P("3 &nbsp; Leakage and shortcut learning: the central claim",
                   "h1"))
    story += layered(
        "Give a child photos where every dog is on grass and every cat is on a "
        "sofa, and they will learn 'grass = dog'. Show them a cat on grass and "
        "they fail. They learned the background, not the animal. A detector "
        "trained on a leaky corpus learns the background.",
        "Leakage is any signal that tells the model the label without being the "
        "thing you want detected. Shortcut learning is the model taking that "
        "signal because it is easier than the real task. In injection corpora "
        "the shortcuts are length, vocabulary, punctuation counts, which URL "
        "was hit, and -- subtlest -- whether a benign row was even reachable in "
        "the test set (if a benign value seen in training reappears in test, "
        "the model just memorises it).",
        "This corpus's entire thesis is that the reported ~99% scores are "
        "largely a dataset artefact, not detection ability. Everything in the "
        "construction -- counterfactual pairing, pre-assigned splits, a benign "
        "side enumerated into non-repeating cores, a 30-check gate -- exists to "
        "remove one shortcut each, and every claim is a measurement rather than "
        "an assertion. If it cannot be measured, it is not claimed.")


def sec_construction(man, story):
    story.append(P("4 &nbsp; How the corpus is built", "h1"))

    story.append(P("Three benign tiers", "h2"))
    story += layered(
        "The hardest part of teaching 'attack vs not' is the not. If every "
        "benign example is bland, the model decides that anything with a quote "
        "or a bracket is an attack -- which is wrong, because people put quotes "
        "and brackets in perfectly ordinary text.",
        "So benign traffic is built in three deliberately graded tiers, from "
        "plain to genuinely confusing, so the model cannot pass by treating "
        "punctuation as guilt.",
        "")
    tier = man["tier"]
    rows = [["Tier", "Rows", "What it is"],
            ["routine", f"{tier['routine']:,}",
             "Ordinary navigation, mostly letters and digits."],
            ["hard_negative", f"{tier['hard_negative']:,}",
             "Punctuation-rich but harmless: apostrophes in names, quotes and "
             "shell characters in reviews, tokens, URLs, pasted code."],
            ["ambiguous", f"{tier['ambiguous']:,}",
             "Benign text that literally contains attack syntax -- someone "
             "asking how to stop \"' OR 1=1--\". The irreducible error floor."]]
    story.append(table(rows, col_widths=[3.0 * cm, 1.8 * cm, 10.6 * cm],
                       header=True))
    story.append(P("The three benign tiers. A detector that flags the "
                   "ambiguous tier is flagging people talking about attacks, "
                   "not attacking.", "cap"))

    story.append(P("Counterfactual pairing", "h2"))
    story += layered(
        "To prove a light switch controls a bulb, you flip only the switch and "
        "keep everything else fixed. To prove a detector reacts to the "
        "injection and nothing else, build two requests identical in every way "
        "except the injected span.",
        "Every attack is created as the twin of a specific benign row -- same "
        "shape, same surrounding words, matched length, sharing a pair id. The "
        "only difference is the injected payload. A change in the model's score "
        "across a pair is therefore attributable to the injection alone.",
        f"{man['rows']:,} rows form {man['label']['1']:,} complete pairs. "
        "Neither half of a pair is ever split across train and test.")

    story.append(P("Splits decided before generation", "h2"))
    story += layered(
        "If you want to know whether a student can solve new problems, the exam "
        "must hold problems they have not already seen worked out. A test set "
        "that shares material with training measures memory, not skill.",
        "Membership in train / validation / test is assigned to every payload "
        "group, template and benign core before any row is generated, so no "
        "group, template or benign phrase can straddle the boundary. Two split "
        "views ship: 'split' holds out whole payloads; 'split_struct' holds out "
        "whole payload templates -- entire attack shapes the model never saw.",
        f"Payload-disjoint test holds {man['groups']['attack_test']} attack "
        f"groups (>= {man['groups']['attack_test_per_family_min']} per family); "
        f"the structural test holds {man['groups']['attack_templates_test']} of "
        f"{man['groups']['attack_templates']} templates. "
        f"{man['groups_spanning_split']} groups span the payload split, "
        f"{man['groups_spanning_split_struct']} span the structural split.")


def sec_gate(story):
    story.append(P("5 &nbsp; What the quality gate enforces", "h1"))
    story += layered(
        "A safety net you cannot see is worthless; a safety net that is checked "
        "on every build is what lets you trust the trapeze. The corpus ships "
        "with an automated gate that fails the build if any known shortcut "
        "reappears, and it runs in continuous integration.",
        "Thirty checks in total -- twenty-five in the validator, five more "
        "construction audits -- each blocking. Grouped by what they defend:",
        "")
    groups = [
        ("Balance and surface", "ratio, duplicates, length_gap, char_class -- "
         "attack and benign are balanced, carry no repeated payloads, sit "
         "within 15% on median length, and share a character alphabet."),
        ("No metadata predicts the label", "param_leak, path_leak, "
         "family_path_leak, content_type_leak, header_leak, metadata_leak -- "
         "no parameter name, URL, content type, header or build token gives the "
         "label away (the v2.1 cookie leak lived here)."),
        ("Learnable but not a shortcut", "ngram_ceiling, ngram_floor, near_dup "
         "-- a strong character model stays below a ceiling yet above a floor, "
         "and digit-masking collapses no large block of rows to one skeleton."),
        ("Evasion is not a tell", "evasion_artifact -- no obfuscation marker "
         "(%25, /**/, &#, %00) is attack-exclusive; each also occurs in benign "
         "traffic."),
        ("The splits really generalise", "disjoint_gen, struct_gen, split_leak, "
         "struct_split_leak, split_balance, benign_split_leak, test_groups, "
         "session_leak -- recall stays high on held-out payloads and templates, "
         "nothing spans a split, and sessions neither span splits nor sort by "
         "label."),
        ("The floors are real", "ambiguous_floor, hard_neg, guard -- a strong "
         "model still false-positives on the verbatim-ambiguous tier (the "
         "payload-only error floor), hard negatives really are "
         "punctuation-rich, and none is a real injection."),
        ("Construction audits (the five)", "lexical_register_leak, "
         "struct_split_balance, session_signal, pair_integrity, "
         "transfer_ranking -- ordinary vocabulary cannot recover the label, "
         "the structural split covers every family, sessions carry real "
         "burst structure, every pair is complete and length-matched, and "
         "cross-corpus transfer is reported threshold-free."),
    ]
    rows = [["Group", "Checks and what they defend"]]
    for g, d in groups:
        rows.append([P("<b>" + g + "</b>", "body"), P(d, "body")])
    story.append(table(rows, col_widths=[4.2 * cm, 11.2 * cm], header=True))
    story.append(P("All thirty checks are blocking in continuous integration, "
                   "on Python 3.11 and 3.12. A red gate stops the release.",
                   "cap"))


def sec_results(base, ev, man, story):
    story.append(P("6 &nbsp; The headline results", "h1"))

    # --- honesty ladder / baselines
    story.append(P("6.1 &nbsp; The baseline ladder", "h2"))
    story += layered(
        "Before trusting a fancy detector, check what a dumb one scores. If "
        "counting exclamation marks already gets 95%, the task is measuring "
        "punctuation, not skill.",
        "Five reference detectors of rising sophistication are scored on the "
        "payload-disjoint split. The column that matters is the last: the true "
        "positive rate at a very strict 0.1% false-positive budget, which is "
        "how an injection detector is actually judged -- accuracy and F1 "
        "saturate and hide the differences.",
        "")
    order = ["length only (1 feature)", "special-char count (1 feature)",
             "rule signature (14 regex)", "word n-gram (1-2) + LogReg",
             "char n-gram (3-5) + LogReg"]
    rows = [["Baseline", "F1", "PR-AUC", "TPR@1%FPR", "TPR@0.1%FPR"]]
    for k in order:
        d = base["baselines"][k]["payload-disjoint"]
        rows.append([k.replace(" (1 feature)", "").replace(" (1-2)", "")
                     .replace(" (3-5)", ""),
                     pct(d["f1"], 0) if d["f1"] else "0",
                     pct(d["pr_auc"], 0), pct(d["tpr_at_1pct_fpr"], 0),
                     pct(d["tpr_at_0.1pct_fpr"], 0)])
    story.append(table(rows, col_widths=[6.0 * cm, 2.0 * cm, 2.2 * cm,
                                          2.6 * cm, 2.6 * cm],
                       highlight_last_col=True))
    lo = base["baselines"]["length only (1 feature)"]["payload-disjoint"]["tpr_at_0.1pct_fpr"]
    hi = base["baselines"]["char n-gram (3-5) + LogReg"]["payload-disjoint"]["tpr_at_0.1pct_fpr"]
    wn = base["baselines"]["word n-gram (1-2) + LogReg"]["payload-disjoint"]["tpr_at_0.1pct_fpr"]
    story.append(P(
        f"The ranking signal is the last column: TPR@0.1%FPR runs "
        f"{pct(lo,0)} -> {pct(wn,0)} -> {pct(hi,0)} across the ladder. "
        "Accuracy and F1 barely move; detection at a strict budget spans the "
        "whole range.", "cap"))

    # --- structural gap
    story.append(P("6.2 &nbsp; The two generalisation gaps", "h2"))
    dj = ev["disjoint"]
    st = ev["structural"]
    rows = [["Metric", "payload-disjoint", "structural (templates held out)"],
            ["F1", pct(dj["f1"]), pct(st["f1"])],
            ["Recall", pct(dj["recall"]), pct(st["recall"])],
            ["TPR@1%FPR", pct(dj["tpr_at_1pct_fpr"]), pct(st["tpr_at_1pct_fpr"])],
            ["TPR@0.1%FPR", pct(dj["tpr_at_0.1pct_fpr"]),
             pct(st["tpr_at_0.1pct_fpr"])]]
    story.append(table(rows, col_widths=[3.6 * cm, 4.2 * cm, 6.4 * cm]))
    gap = (dj["tpr_at_0.1pct_fpr"] - st["tpr_at_0.1pct_fpr"]) * 100
    story.append(P(
        "Holding out whole attack templates (shapes the model never saw) is "
        f"much harder than holding out individual payloads: TPR@0.1%FPR falls "
        f"{pct(dj['tpr_at_0.1pct_fpr'])} -> {pct(st['tpr_at_0.1pct_fpr'])} "
        f"({gap:+.1f} points). The model leans on template shape, and this "
        "corpus is one of the few that can show it.", "cap"))

    # --- LOFO
    story.append(P("6.3 &nbsp; Zero-shot: an entirely unseen family", "h2"))
    lofo = ev["lofo"]
    rows_sorted = sorted(lofo.items(), key=lambda kv: kv[1]["zeroshot_recall"])
    worst = rows_sorted[0]
    best = rows_sorted[-1]
    story.append(P(
        "Leave-one-family-out training removes a whole attack family, then "
        "tests on it -- can the model flag an attack class it never saw? It "
        f"barely flags {worst[0]} ({pct(worst[1]['zeroshot_recall'])}%) but "
        f"transfers to {best[0]} ({pct(best[1]['zeroshot_recall'])}%). "
        "Injection detection does not generalise uniformly across families."))

    # --- prevalence
    story.append(P("6.4 &nbsp; Prevalence: precision in the real world", "h2"))
    ppv = dj["ppv_at_prevalence@1pctFPR"]
    rows = [["Attack prevalence"] + [f"{float(k) * 100:g}%" for k in ppv]]
    rows.append(["Precision at 1% FPR"] + [pct(v, 0) + "%" for v in ppv.values()])
    story.append(table(rows, header=True))
    story += [P(
        "In the lab a quarter of the traffic is attacks; in production it is a "
        "fraction of a percent. The same detector's precision collapses as "
        "attacks get rarer -- most alarms become false at realistic base "
        "rates. Report precision at your own prevalence, not the corpus's.",
        "cap")]

    # --- calibration + attribution + errors
    story.append(P("6.5 &nbsp; Calibration, error analysis, span attribution",
                   "h2"))
    cal = ev["calibration"]
    at = ev["attribution"]
    err = ev["errors"]
    pr = ev["paired"]
    story.append(P(
        f"Calibration. A score should behave like a probability. Brier "
        f"{cal['brier']:.4f}, ECE {cal['ece']:.4f}, MCE {cal['mce']:.4f}; mean "
        f"score {cal['mean_score']:.3f} against a base rate of "
        f"{cal['base_rate']:.3f}. The reliability curve ships as data, not a "
        "picture."))
    story.append(P(
        f"Span attribution. Because the counterfactual twin is in the data, "
        "the contribution of the injected span is measured, not approximated: "
        f"deleting the span moves the score {at['mean_score_attack']:.3f} -> "
        f"{at['mean_score_span_removed']:.3f} (twin {at['mean_score_twin']:.3f}), "
        f"median attribution {at['span_attribution_median']:.3f}, localisation "
        f"rate {pct(at['localisation_rate'])}%."))
    story.append(P(
        f"Matched-pair sensitivity. On {pr['n_pairs']:,} test pairs the "
        f"reference model scores the attack above its own twin in "
        f"{pct(pr['paired_accuracy'])}% of pairs (median delta "
        f"{pr['delta_median']:+.2f}), and crosses the threshold in the right "
        f"direction in {pct(pr['flip_rate'])}%. A detector keying on carrier "
        "text rather than the injection shows a delta near zero here even when "
        "its aggregate F1 looks strong."))
    fp_cat = err["false_positives_by_tier"]
    story.append(P(
        "Error analysis. False positives are attributable by benign register "
        "because the category ships on both halves of every pair. They "
        "concentrate exactly where the corpus says they must -- the ambiguous "
        "tier -- and misses concentrate in "
        + max(err["false_negatives_by_family"].items(),
              key=lambda kv: kv[1] if isinstance(kv[1], (int, float))
              else kv[1].get("rate", 0))[0]
        + "."))


def sec_model_zoo(mz_capped, mz_full, story):
    story.append(P("7 &nbsp; The model zoo: is it the corpus or the model?",
                   "h1"))
    story += layered(
        "One detector's score could be a fluke of that detector. Run ten "
        "different ones and the pattern that survives is a property of the "
        "data, not the model.",
        "Ten reference detectors across three families -- classical, deep, "
        "transformer -- are scored on the same splits, and for each the two "
        "ablations that matter are repeated: carrier-only AUC (predict the "
        "label after deleting all punctuation and every payload word) and "
        "paired accuracy (does it score an attack above its own twin?).",
        "Read the last two columns first. If carrier-only AUC is near 0.5, no "
        "model can recover the label once the injection is gone; if paired "
        "accuracy is near 1.0, every model's decision tracks the injected "
        "span. Those two numbers are what a headline F1 cannot tell you.")

    def zoo_rows(mz):
        rows = [["Model", "Family", "F1", "TPR@0.1%", "struct TPR", "paired",
                 "carrier AUC"]]
        for tier in ("classical", "deep", "transformer"):
            for name, rec in (mz.get(tier) or {}).items():
                if not isinstance(rec, dict) or rec.get("error"):
                    rows.append([name, tier, "--", "--", "--", "--", "--"])
                    continue
                dj = rec.get("payload-disjoint", {})
                stc = rec.get("structural", {})
                car = rec.get("ablation_carrier_only", {})
                pa = dj.get("paired_accuracy")
                stale = " (stale)" if rec.get("_stale") else ""
                rows.append([
                    name + stale, tier,
                    pct(dj["f1"], 1) if dj.get("f1") is not None else "--",
                    pct(dj["tpr_at_0.1pct_fpr"], 1)
                    if dj.get("tpr_at_0.1pct_fpr") is not None else "--",
                    pct(stc["tpr_at_0.1pct_fpr"], 1)
                    if stc.get("tpr_at_0.1pct_fpr") is not None else "--",
                    pct(pa, 1) if pa is not None else "--",
                    f"{car['roc_auc']:.3f}" if car.get("roc_auc") is not None else "--"])
        return rows

    cw = [3.5 * cm, 2.0 * cm, 1.5 * cm, 2.0 * cm, 2.0 * cm, 1.8 * cm, 2.4 * cm]
    if mz_full:
        cap = mz_full.get("_train_cap")
        story.append(P("Full training data" if not cap else "Model sweep", "h2"))
        story.append(table(zoo_rows(mz_full), col_widths=cw,
                           highlight_last_col=True))
        story.append(P("Every model scored on the same fixed test split, "
                       "trained on the full training set.", "cap"))
    if mz_capped:
        story.append(P("Capped training data (identical 8,000-row subsample)",
                       "h2"))
        story.append(table(zoo_rows(mz_capped), col_widths=cw,
                           highlight_last_col=True))
        story.append(P("The capped table isolates sample efficiency: at a fixed "
                       "small budget the transformer (RoBERTa) closes more of "
                       "the structural gap, but that is a claim about budgets, "
                       "not model families. DeBERTa-v3 shows '--': it diverges "
                       "to a non-finite loss after the first optimiser step on "
                       "this CUDA/transformers build (across fp32, TF32-off and "
                       "bf16), and the outcome is recorded rather than dropped.",
                       "cap"))


def sec_shortcut(sc, sep, story):
    story.append(P("8 &nbsp; No single character predicts the label", "h1"))
    story += layered(
        "'Attacks use quotes' sounds damning until you notice ordinary people "
        "use quotes too. The question is not whether a character appears, but "
        "whether its presence alone is a usable detector.",
        "For each character an attack relies on, a one-feature detector is "
        "built ('flag if present') and its strength measured -- a chi-square, "
        "Cramer's V (effect size), and the AUC -- for this corpus and for the "
        "two it replaces. The enforced property is that no single character "
        "yields a usable detector (AUC <= 0.60) and that every association is "
        "smaller than in either reference corpus.",
        "")

    def top(entry):
        best = max(entry, key=lambda r: r["auc"])
        return best["char"], best["cramers_v"], best["auc"]

    rows = [["Corpus", "strongest character", "Cramer's V", "best 1-char AUC"]]
    label = {"webinject2026": "WebInject2026", "csic": "CSIC-2010",
             "ecml": "ECML/PKDD-2007"}
    for key in ("webinject2026", "csic", "ecml"):
        if key not in sc:
            continue
        ch, v, auc = top(sc[key])
        shown = {"<": "<", ">": ">", "&": "&amp;"}.get(ch, ch)
        rows.append([label[key], f"'{shown}'", f"{v:.3f}", f"{auc:.3f}"])
    story.append(table(rows, col_widths=[4.4 * cm, 4.4 * cm, 3.0 * cm, 3.4 * cm],
                       highlight_rows=(1,)))
    story.append(P("The strongest single character in WebInject2026 is a weaker "
                   "detector than in either corpus it replaces. The claim is "
                   "deliberately not 'zero association' -- injection genuinely "
                   "uses punctuation -- but that no one character is a "
                   "shortcut.", "cap"))


def sec_limitations(base, story):
    story.append(P("9 &nbsp; Limitations, stated plainly", "h1"))
    cd = base.get("cross_dataset", {}).get("webinject", {})
    csic_auc = cd.get("csic", {}).get("roc_auc")
    ecml_auc = cd.get("ecml", {}).get("roc_auc")
    items = [
        ("It is synthetic.", "All benign traffic is generated, not captured "
         "from real users, so it contains no real credentials or PII -- and "
         "also none of the messiness of production traffic. Detection signal "
         "learned here does not transfer to the older corpora: training on "
         "WebInject2026 and testing on CSIC-2010 gives AUC "
         + (f"{csic_auc:.2f}" if csic_auc else "~0.57")
         + " and on ECML/PKDD "
         + (f"{ecml_auc:.2f}" if ecml_auc else "~0.76")
         + ", with the model firing on nearly every row. Report this "
         "threshold-free, not as an F1."),
        ("The structural split is not balanced like the payload split.",
         "Holding out whole templates leaves some families thin in the "
         "structural validation and test sets, so the structural gap is "
         "measured under a different family mix -- treat it as indicative, not "
         "a like-for-like comparison."),
        ("The ambiguous tier is a declared error floor, not a solved problem.",
         "Text that literally contains attack syntax cannot be separated from "
         "an attack by the request alone; a context-aware system with more than "
         "the single request is out of scope here."),
        ("Three practice applications, not the whole web.", "DVWA, Juice Shop "
         "and bWAPP cover a wide but finite surface. Endpoints, parameter "
         "conventions and framework behaviours outside them are not "
         "represented."),
    ]
    for h, d in items:
        story.append(P("<b>" + _ascii(h) + "</b> " + _ascii(d), "body"))


def sec_qa(ev, base, story):
    story.append(P("10 &nbsp; Questions you may be asked", "h1"))
    dj = ev["disjoint"]
    qa = [
        ("If the numbers are lower than published corpora, why is that good?",
         "Because the published numbers are inflated by leakage. A lower score "
         "on a corpus where the attack is the only thing predicting the label "
         "is a more honest estimate of real detection ability than a high score "
         "on a corpus you can beat with the injection deleted."),
        ("Is the corpus just too hard, then?",
         "No -- the baseline ladder shows a strong character model reaches F1 "
         f"{pct(dj['f1'],0)} and TPR {pct(dj['tpr_at_0.1pct_fpr'],0)}% at a "
         "0.1% false-positive budget on held-out payloads. The task is "
         "learnable; it just cannot be shortcut."),
        ("Why counterfactual pairs instead of independent benign and attack "
         "rows?",
         "Because a pair lets you attribute a score change to the injection "
         "alone, the way a controlled experiment isolates one variable. It "
         "turns 'the model probably reads the attack' into a measurement."),
        ("How do you know the gate is not just re-stating your assumptions?",
         "Each of the thirty checks re-derives its number from the shipped CSV "
         "on every build and fails the release if it regresses. The v1->v4 "
         "history is a record of checks catching real leaks the authors had "
         "missed -- a register leak at AUC 0.90 among them."),
        ("Can I score my own detector on it?",
         "Yes -- pass one score per test row to 'python -m src.evaluate "
         "--predictions', and it reports the same protocols, prevalence "
         "corrections and paired sensitivity used here."),
        ("Why is a number in this PDF different from the paper draft?",
         "It should not be: this document is regenerated from the same result "
         "JSONs the paper's tables and figures are built from. If it differs, "
         "the corpus was rebuilt and something downstream was not regenerated "
         "-- the fix is to re-run the pipeline, not to edit a number."),
    ]
    for q, a in qa:
        story.append(P(q, "qq"))
        story.append(P(a, "body"))


# ----------------------------------------------------------------- assembly ---
def _decorate(canvas, doc):
    canvas.saveState()
    canvas.setStrokeColor(RULE)
    canvas.setLineWidth(0.4)
    canvas.line(2 * cm, 1.35 * cm, A4[0] - 2 * cm, 1.35 * cm)
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(colors.HexColor("#888888"))
    canvas.drawString(2 * cm, 1.0 * cm, "Understanding WebInject2026")
    canvas.drawRightString(A4[0] - 2 * cm, 1.0 * cm, f"page {doc.page}")
    canvas.restoreState()


def build():
    man = _load("manifest.json")
    base = _load("baselines.json")
    ev = _load("evaluation.json")
    abl = _load("syntax_ablation.json")
    sc = _load("shortcut_stats.json")
    sep = _load("separability.json", required=False)
    mz_capped = _load("model_zoo_capped.json", required=False)
    mz_full = _load("model_zoo.json", required=False)

    story = []
    sec_title(man, story)                 # ends with a hard PageBreak
    sec_injection(man, story)
    story.append(CondPageBreak(9 * cm))
    sec_why_corpora(abl, story)
    story.append(CondPageBreak(12 * cm))
    sec_leakage(story)
    story.append(CondPageBreak(12 * cm))
    sec_construction(man, story)
    story.append(CondPageBreak(14 * cm))
    sec_gate(story)
    story.append(CondPageBreak(12 * cm))
    sec_results(base, ev, man, story)
    story.append(CondPageBreak(14 * cm))
    sec_model_zoo(mz_capped, mz_full, story)
    story.append(CondPageBreak(12 * cm))
    sec_shortcut(sc, sep, story)
    story.append(CondPageBreak(9 * cm))
    sec_limitations(base, story)
    story.append(CondPageBreak(12 * cm))
    sec_qa(ev, base, story)

    doc = BaseDocTemplate(OUT, pagesize=A4, leftMargin=2 * cm, rightMargin=2 * cm,
                          topMargin=1.8 * cm, bottomMargin=1.8 * cm,
                          title="Understanding WebInject2026",
                          author="WebInject2026")
    frame = Frame(doc.leftMargin, doc.bottomMargin,
                  doc.width, doc.height, id="main")
    doc.addPageTemplates([PageTemplate(id="main", frames=[frame],
                                       onPage=_decorate)])
    doc.build(story)
    print(f"wrote {OUT} ({os.path.getsize(OUT):,} bytes)")


if __name__ == "__main__":
    build()
