# WebInject2026

A contemporary, leakage-audited corpus for **web-application injection-attack
detection**. 61,400 labelled HTTP requests across three applications and fourteen
attack families, shipped with fixed payload-disjoint **and** template-disjoint
splits and an automated 31-check quality gate that fails the build if any known
shortcut or leak reappears.

> **v3.0 rebuild.** v2.1 made the *attack* side rigorous but left two measurable
> leaks on the *benign* side: 67% of hard-negative test values appeared verbatim
> in training (benign traffic was not split-disjoint), and attacks were given
> punctuation-rich headers while routine benigns got plain ones, so a cookie
> blob predicted the label. v3 fixes both — benign text is now enumerated into
> ~2,340 split-disjoint cores, and headers are drawn independently of the label
> (header→label NMI 0.000). It also adds four modern families (JNDI, insecure
> deserialization, prototype pollution, request smuggling), JSON/GraphQL/
> multipart bodies and PUT/PATCH/DELETE, a template-disjoint structural split,
> chained evasions, sessions, and harder evaluation protocols.
>
> **v4.0 rebuild.** An external audit found a *lexical register leak* v3 had
> installed while removing the character-class one: with all punctuation and
> all payload words deleted, the label was still recoverable from ordinary
> vocabulary at AUC 0.904. v4 builds every attack as the counterfactual twin of
> a benign row (shared `pair_id`), decides all split membership before
> generation, and gives sessions real burst structure. Carrier-only AUC is now
> 0.608 and the word n-gram baseline falls from F1 82.1 to 45.2. The gate is 31
> checks. See [CHANGELOG.md](CHANGELOG.md).

New to the problem, or preparing a talk on it?
[**Understanding_WebInject2026.pdf**](Understanding_WebInject2026.pdf) explains
the attacks, the leakage argument, the construction and every headline number
from first principles, in three layers per idea (intuition, mechanism, detail).

## Contents

| | |
|---|---|
| Rows | 61,400 |
| Benign / attack | 45,400 / 16,000 (26.1% attack) |
| Applications | DVWA, OWASP Juice Shop, bWAPP (35 endpoints) |
| Attack families | SQLi, XSS, command injection, path traversal, SSTI, NoSQLi, SSRF, CRLF, LDAP, XXE, **JNDI/Log4Shell, deserialization, prototype pollution, request smuggling** |
| Distinct attack payloads (groups) | 1,945 — **388 held out in test**, ≥10 per family |
| Attack templates | 84 — **24 held out in the structural test** |
| Methods | GET / POST / PUT / PATCH / DELETE |
| Content types | query 31,371 · json 15,692 · graphql 1,899 · form 6,953 · multipart 5,485 |
| Injection placement | query 8,511 · body 6,963 · header 526 |
| Evasion-transformed attacks | 5,531 (35%), of which 950 chained |
| Splits | `split` (payload-disjoint) · `split_struct` (template-disjoint); both family/tier-stratified 70/10/20 |

Benign traffic is deliberately built in three tiers so the task cannot collapse
to a punctuation test:

| Tier | Rows | What it is |
|---|---|---|
| `routine` | 26,000 | Ordinary navigation, alphanumeric-dominant |
| `hard_negative` | 17,000 | **Punctuation-rich but non-injective** — apostrophes in names, quotes and shell metacharacters in reviews, base64/JWT tokens, URLs and JSON in parameters, pasted code snippets, and the same encoding markers evasions use (`%25`, `/**/`, `&#`, `%00`) in benign contexts. Enumerated into **~2,340 split-disjoint cores**: each row carries one core, the core id is its split group, so no benign phrase spans train/test |
| `ambiguous` | 2,400 | Benign text that *contains literal attack syntax*, in 884 compositional (frame × specimen) cores across all 14 families, split-disjoint. `discussion` cores ("how do I stop `' OR 1=1--`?") are headroom a context-aware model wins; `verbatim` cores (the payload with minimal framing) are the **irreducible** payload-only error floor. The `group` id is prefixed `ambigD`/`ambigV` so the two are separable |

## Quick start

```bash
pip install -r requirements.txt

shasum -a 256 -c SHA256SUMS  # confirm the files you have are the files released
python -m src.shortcut_stats  # per-character chi2 / Cramer V / odds ratio vs CSIC + ECML
python -m src.build          # rebuild the corpus offline (reproducible, seed=42)
python -m src.validate       # 25-check quality gate; non-zero exit on any FAIL
python -m src.audit_gaps     # 5 construction checks (register, splits, sessions, pairs, transfer)
python -m src.baselines      # reference results table
python -m src.evaluate       # generalisation protocols + prevalence correction
python -m src.figures        # the eight paper figures, from the shipped result JSONs
python -m src.model_zoo --tier classical   # 10-model sweep; see also --tier deep|transformer
pytest -q                    # assert the shipped CSV passes every gate
```

> **Rebuilding reproduces the release only on a clean checkout.** The published
> corpus was built from the 1,979-payload seed + grammar pool, *without* a local
> PayloadsAllTheThings checkout. If `data/patt/` exists it is folded in, the pool
> grows to 2,048, and the rebuild will not match `data/webinject2026.csv` —
> `src.build` prints a warning when this applies. Move the directory aside to
> rebuild the published corpus.

Score your own model on the fixed test split (one score per test row, in
`df[df.split=='test']` order):

```bash
python -m src.evaluate --predictions my_scores.csv   # add --protocol structural
```

To capture against live containers instead of offline synthesis:

```bash
# start the three apps first (see DATASHEET.md > Collection)
python -m src.build --capture
```

## Reference baselines

An injection detector is judged at a **low false-positive budget**, not by
accuracy at threshold 0.5. `python -m src.baselines` reports F1, PR-AUC and
**TPR at FPR = 1% / 0.1%** on three split protocols, plus a rule-signature
reference, per-family/per-evasion recall, prevalence-corrected precision,
group-bootstrap CIs, and cross-dataset transfer. Payload-disjoint headline:

| Baseline | F1 | PR-AUC | TPR@1%FPR | TPR@0.1%FPR |
|---|--:|--:|--:|--:|
| length only (1 feature) | 0.0 | 29.3 | 0.0 | 0.0 |
| special-char count (1 feature) | **0.1** | 29.5 | 0.7 | **0.0** |
| rule signature (14 regex) | 59.9 | 51.6 | 1.2 | 0.0 |
| word n-gram (1–2) + LogReg | 45.2 | 69.8 | 24.0 | 16.1 |
| char n-gram (3–5) + LogReg | **93.1** | 99.3 | 96.8 | **86.9** |

The ranking signal is the last column: **TPR@0.1%FPR spans 0 → 16.1 → 86.9** across
baselines. Accuracy/F1 saturate; detection at a strict FP budget does not.

- **Two generalisation gaps.** The char n-gram's TPR@0.1%FPR is 91.2 on a random
  split, **86.9 on the payload-disjoint split, and 57.1 on the template-disjoint
  (`split_struct`) split** — a 29.8-point structural gap. Report all three.
- **Prevalence matters.** At the corpus's 26% attack rate the char n-gram's
  precision at 1% FPR is 97.1%; at a realistic **0.5% prevalence it is 32.7%** (81.4%
  if you can hold FPR to 0.1%). Report the precision at *your* operating
  prevalence — `evaluate.py` prints the table.
- **Group-bootstrap 95% CI** (char n-gram, disjoint, resampling payload groups —
  not rows): F1 [91.4, 94.5], recall [84.5, 90.0], TPR@0.1%FPR [81.4, 89.6].
- **Where the headroom is** (char n-gram recall, disjoint): **cmdi 30.7%** · deser 75.7% · ssti 76.1% … jndi 98.3% · xxe 100.0%.
- **External validity.** Train here, test on CSIC-2010 / ECML-PKDD-2007: F1 falls
  from ~96 in-corpus to ~41–46 cross-corpus. **Do not quote that F1 on its own —
  it is threshold collapse, not graded degradation.** Recall is ~100% and
  precision equals the base rate, i.e. the model fires on nearly every row; an
  all-positive classifier scores exactly 41.0 at CSIC's base rate. Threshold-free
  the picture is worse and more honest: **AUC 0.57 against CSIC-2010** and **0.76 against
  ECML/PKDD**, with the model firing on 100% of rows at threshold 0.5. Synthetic detection signal does not
  transfer; see [DATASHEET.md](DATASHEET.md) > Limitations.

## No single character predicts the label

Asserting that benign traffic "also contains quotes" is worth nothing. `python -m
src.shortcut_stats` tests it: for each character injection relies on it builds a
one-feature detector ("flag iff present") and reports a chi-square, Cramer's V,
a Haldane-Anscombe odds ratio with a 95% interval, and the AUC — for this corpus
and for both corpora it replaces.

| Corpus | strongest character | Cramer's V | best single-char AUC |
|---|---|--:|--:|
| **WebInject2026** | `%` | **0.139** | **0.565** |
| CSIC-2010 | `-` | 0.316 | 0.672 |
| ECML/PKDD-2007 | `)` | 0.411 | 0.662 |

The claim is deliberately not "zero association", which would be false and easy
to refute. Injection genuinely uses punctuation, and the `routine` tier is
deliberately ordinary alphanumeric traffic, so forcing an exact match would
falsify the benign distribution — a worse fault than the one being fixed. What
is enforced in CI is that **no single character yields a usable detector**
(AUC ≤ 0.60) and that every association is **smaller than in either reference
corpus**. The residual, which exceeds the conventional 0.10 small-effect
boundary, is reported rather than argued away.

Hard negatives are labelled by register in the shipped `benign_category` column
— review, search, code, qa, encoded, log, markup — so false positives can be
attributed to the kind of benign text that caused them, which no other
web-attack corpus supports.

## Ten reference detectors, one protocol

A benchmark that reports one model cannot tell a reader whether a result is a
property of the corpus or of the model. `python -m src.model_zoo` runs the same
splits over four classical models, three deep models and three transformers,
and — for every one of them — repeats the two ablations that matter:
**carrier-only AUC** (delete all punctuation and every payload-pool word, then
try to predict the label from the ordinary words left) and **paired accuracy**
(does it score an attack above its own benign twin?).

Trained on an identical 8,000-row stratified subsample so the comparison is
like-for-like; a full-data transformer sweep is ~9 hours on Apple MPS.

| Model | Family | F1 | TPR@0.1%FPR | structural | paired acc | carrier-only AUC |
|---|---|--:|--:|--:|--:|--:|
| LogisticRegression | classical | 84.9 | 61.0 | 38.0 | 99.6 | 0.612 |
| RandomForest | classical | 83.1 | 38.8 | 22.9 | 99.1 | 0.603 |
| LinearSVM | classical | 87.9 | 68.7 | 41.2 | 99.8 | 0.615 |
| XGBoost | classical | 92.0 | 75.3 | 41.3 | 99.6 | 0.590 |
| CNN | deep | 89.7 | 74.1 | 42.6 | 92.6 | 0.546 |
| LSTM | deep | 86.1 | 31.2 | 23.6 | 91.8 | 0.518 |
| BiLSTM | deep | 85.4 | 32.4 | 39.7 | 91.6 | 0.518 |
| DistilBERT | transformer | 90.4 | 63.3 | 38.4 | 96.5 | 0.512 |
| RoBERTa | transformer | 94.8 | 81.8 | 72.2 | 97.9 | 0.499 |
| DeBERTa | transformer | — | — | — | — | — |

Read the last two columns first. Carrier-only AUC runs **0.499–0.615** across all
nine — no model can recover the label once the injection syntax is gone, and the
transformers sit at chance. Paired accuracy is 91.6–99.8%: every model's decision
tracks the injected span rather than the surrounding text. Those two numbers are
what a headline F1 cannot tell you, and reporting them is the point of the corpus.

RoBERTa is the only model that substantially closes the structural gap
(72.2 against 22.9–42.6 for everything else) — evidence that template-disjoint
generalisation is a model limitation rather than a property of the task.

**DeBERTa-v3 did not run.** Its disentangled attention diverges to NaN in fp32 on
Apple's Metal backend, with and without gradient clipping at lr 1e-5, and CPU
managed fewer than five optimiser steps in ten minutes. The harness selects CUDA
automatically, so `--tier transformer --models DeBERTa` completes the set on a
CUDA machine. This is recorded in `data/model_zoo_capped.json` rather than
quietly dropped.

Uncapped numbers for the classical and deep tiers (43k training rows) are in
`data/model_zoo.json`: the ordering is unchanged, and carrier-only AUC rises only
to 0.569–0.662.

## Evaluation protocols

`python -m src.evaluate` runs four generalisation protocols and writes
`data/evaluation.json`:

| Protocol | Split | Measures |
|---|---|---|
| `disjoint` | `split` | payload-disjoint (the headline; use this to rank) |
| `structural` | `split_struct` | whole payload *templates* held out — harder |
| `lofo` | leave-one-family-out | zero-shot recall on an unseen attack family |
| `evasion` | plain→evaded | recall on obfuscations the model never trained on |
| `paired` | matched twins | does the score move *because of* the injected span? |
| `calibration` | test split | is the score a probability? Brier / ECE / MCE + reliability curve |
| `errors` | test split | false positives by benign register, misses by family |
| `attribution` | matched twins | how much of the score comes from the injected span |

Every protocol reports precision corrected to 0.5% / 1% / 5% / 26% attack
prevalence. Reference char n-gram, payload-disjoint test:

- **Structural gap.** TPR@0.1%FPR falls **86.9 → 57.1** from the payload-disjoint
  to the template-disjoint split (28.9 pts) — the model leans on template shape.
- **Zero-shot (LOFO) recall spans 6.9 → 84.6%.** A model that never saw the family
  barely flags protopollute (6.9%) or xss (7.5%), but transfers to smuggle (84.6%)
  and xxe (61.8%). Injection detection does **not** generalise uniformly across families.
- **Matched-pair sensitivity (new in v4).** Every attack is the counterfactual
  twin of a benign row, differing only by the injected span and matched on
  length, so a score difference is attributable to that span alone. On the
  3,236 test pairs the reference model scores the attack above its own twin in
  **99.9%** of pairs (median delta **+0.90**, 10th percentile
  +0.34), and cleanly crosses the 0.5 threshold in the right direction in
  **86.7%**. A detector keying on carrier text rather than the injection shows a
  delta near zero here even when its aggregate F1 looks strong — which no metric
  over independently drawn rows can reveal.
- **Calibration.** Brier 0.0252, ECE 0.0556, MCE 0.5294; mean score
  0.242 against a base rate of 0.261. The reliability curve ships as data
  in `data/evaluation.json`, not as a picture.
- **Error analysis.** Every hard-negative register sits at 0.00% false positives or
  below; misses concentrate in command injection. Attributable because
  `benign_category` ships with the data.
- **Span attribution.** Deleting the injected span moves the score
  0.817 → 0.057 (twin 0.025); median attribution
  0.966, localisation rate 87.3%. Because the counterfactual is in
  the data, this is measured rather than approximated as SHAP or integrated
  gradients would.
- **Evasion hold-out.** Trained on plain attacks only, recall on *evaded* test
  attacks is **54.4%** (58.8% on chained transforms).

To grade your own detector on the fixed test split, pass one score per test row
(in `df[df.split=='test']` order):

```bash
python -m src.evaluate --predictions my_scores.(csv|parquet|npy)
```

## What the quality gate enforces

`python -m src.validate` fails the build unless every one of 25 checks passes, and
`python -m src.audit_gaps` adds five construction checks that are equally blocking in CI:

- **ratio / duplicates / length_gap** — balance, no repeated payloads, benign vs attack median length within 15%
- **char_class** — benign and attack share a character alphabet (≤3 attack-only characters)
- **param_leak / path_leak** — no parameter name or path predicts the label
- **family_path_leak** — the URL does not predict the attack *family* (NMI ≤ 0.35; was 0.55 in v2.1)
- **content_type_leak** — `Content-Type` does not predict the label
- **header_leak** — no header-derived feature predicts the label (the v2.1 `prefs` cookie leak)
- **metadata_leak** — no metadata token (family, tier, source) leaked into the payload text
- **ngram_ceiling / ngram_floor** — a strong char-n-gram model stays *below* a ceiling (not a char-class shortcut) yet *above* a floor (task is learnable)
- **near_dup** — digit-masking collapses no large block of rows to one skeleton
- **evasion_artifact** — no evasion marker (`%25`, `/**/`, `&#`, `%00` …) is attack-exclusive; each also occurs in benign traffic
- **disjoint_gen / struct_gen** — attack recall stays high on the payload-disjoint *and* template-disjoint test sets
- **split_leak / struct_split_leak** — no group spans `split`, and no template spans `split_struct`
- **split_balance** — attack ratio matches across splits and every family appears in all three — **on `split` only**. `split_struct` is template-disjoint but *not* balanced: attack prevalence runs 28.6% train / 21.2% test / 15.3% val (spread 0.134, against 0.0005 for `split`), `nosqli` and `ssrf` have no rows in its val or test sets, and six families have no val rows. Treat the structural gap as measured under a different family mix, not a like-for-like comparison — see [DATASHEET.md](DATASHEET.md) > Limitations
- **benign_split_leak** — hard-negative/ambiguous benign cores never span splits, and the test holds ≥300 distinct benign cores (the benign mirror of the payload-disjoint attack split)
- **test_groups** — the disjoint test holds ≥250 attack payload groups overall and ≥8 per family
- **session_leak** — sessions never span a split and are not segregated by label
- **ambiguous_floor** — a strong model still false-positives on the verbatim `ambiguous` tier: the payload-only error floor is real, not zero
- **hard_neg / guard** — hard negatives really are punctuation-rich, and none is a real injection

## Layout

```
src/config.py      35 endpoints, 14 families, volumes, four anti-leak invariants
src/vocab.py       three-tier benign generators, ~2.3k groupable benign cores, ambiguous cores, guard
src/payloads.py    14 families: seed + grammar (templates, ~2k payloads) + chained evasions; widens from PayloadsAllTheThings
src/build.py       synthesise -> (optional capture) -> normalise -> dedup -> payload + structural splits -> sessions
src/validate.py    the 25-check quality gate
src/baselines.py   reference results: F1/PR-AUC/TPR@FPR, prevalence-corrected precision, slice recall, bootstrap CIs, cross-dataset
src/evaluate.py    protocols (disjoint/structural/LOFO/evasion), prevalence correction, submission scorer (--predictions)
src/checksums.py   writes/verifies SHA256SUMS; --check is a CI gate
src/audit_gaps.py  five construction checks (register/splits/sessions/pairs/transfer); blocking in CI
src/shortcut_stats.py  per-character shortcut statistics against CSIC-2010 and ECML/PKDD; blocking in CI
src/model_zoo.py   ten detectors across classical / deep / transformer, same splits, same ablations
src/figures.py     the eight paper figures; reads the result JSONs, never recomputes
data/webinject2026.csv       the corpus (22 columns; see DATASHEET.md > Schema)
data/webinject2026.parquet   same rows, typed columnar copy (NUL stripped in 25 rows; see DATASHEET.md > Limitations)
data/manifest.json           build provenance and distribution counts
data/baselines.json          machine-readable baseline metrics
data/evaluation.json         machine-readable protocol metrics
tests/             pytest wrapper around the gate
figures/           the eight figures, regenerated by `python -m src.figures`
DATASHEET.md       datasheet-for-datasets (motivation, composition, collection, uses, limitations)
Understanding_WebInject2026.pdf   plain-language explanation of the whole corpus (21 pp.)
Literature_Review_WebInject2026.xlsx   related-work matrix
```

`data/csic_parsed.csv` and `data/ecml_parsed.csv` are the classic CSIC-2010 and
ECML/PKDD-2007 corpora, parsed to a common schema for cross-dataset comparison.

## Licensing

Code under [MIT](LICENSE). Dataset under CC-BY-4.0. Attack payloads derive from
PayloadsAllTheThings (MIT); see [NOTICE](NOTICE). All benign traffic is
synthetic — it contains no real users, credentials, or PII.

## Citation

```bibtex
@misc{webinject2026,
  author = {Choudhury, Anish and Abhishek},
  title  = {WebInject2026: A Leakage-Audited Corpus for Web Injection Detection},
  year   = {2026},
  note   = {Version 3.0.0},
  howpublished = {\url{https://github.com/anishc23/webinject2026}}
}
```

Machine-readable metadata is in [CITATION.cff](CITATION.cff).
