# Changelog

## 4.5.1 - publication metadata; no change to the corpus or any result

The paper describing this corpus was accepted as a full paper at ICISSP 2027
(Valletta, 22-24 February 2027). This release records that and completes the
authorship metadata. The CSV, the Parquet copy and every result JSON are
byte-identical to 4.5.0, and `SHA256SUMS` is unchanged.

### Changed
- `CITATION.cff` now lists all three authors with family names and
  affiliations, and carries the ICISSP 2027 paper as `preferred-citation`.
  Earlier versions named two authors, one of them without a family name.
- `README.md` cites the paper first and the artefact second. The artefact
  BibTeX entry had named two authors and claimed version 4.4.0.
- `.gitignore` covers local agent and editor state, and the camera-ready
  deliverables built from the paper tree.

- The stale `data.backup-20260814-202539/` directory is no longer tracked. It
  held a 14 August working copy of `data/`: the corpus CSV, the Parquet copy
  and the two comparison CSVs byte-identical to the live ones, and six result
  JSONs that were **superseded** by later corrections. Shipping it in the
  release archive would have doubled the download and, worse, published a
  shadow set of pre-correction numbers beside the current ones. Nothing in
  `src/`, the CI workflow, the documentation or `SHA256SUMS` referenced it.
  It remains in the git history and on the authors' disks.

- `README.md` now carries the CI and licence badges, and names the ICISSP 2027
  paper in the opening section. Previously the paper appeared only in the
  citation block at the foot of a 475-line file. One stale phrase, "the shipped
  4.4.0 corpus", now reads "the shipped corpus, byte-identical since 4.4.0" --
  accurate before, but it read as a version the repository had left behind.
- `SECURITY.md` added: what the payloads are and are not, that they are not
  execution-validated, intended use, and separate routes for reporting a
  corpus defect (public issue) and a repository security issue (email).

### Still open
- ORCID iDs for all three authors, and the Zenodo DOI, are left as explicit
  TODOs in `CITATION.cff` rather than placeholders.

## 4.5.0 - a symmetric control for Table 1; the skeleton result gets its controls

Two audit findings closed, plus a third defect found while closing them. No
change to the corpus: this release is analysis, controls and provenance, and the
CSV is byte-identical to 4.4.0.

### Fixed
- **Table 1 was asymmetric, and the asymmetry favoured us.** The deletion
  vocabulary came from this corpus's payload pool and was applied unchanged to
  all three corpora, so it was exhaustive here and partial elsewhere: 44% of
  our characters deleted against 20% of CSIC-2010's and 15% of
  ECML/PKDD-2007's. The module printed that line itself, so any reviewer reading
  it would have built the control.

  A **symmetric panel** now derives the vocabulary independently for each corpus
  from its own training attack rows -- a token is deleted when it is at least 5x
  more likely in an attack row than a benign one, presence per row, train rows
  only. Deletion aggression is matched (23% / 21% / 15%).

  | corpus | chars del | full AUC | scrubbed AUC | AUC kept |
  |---|--:|--:|--:|--:|
  | CSIC-2010 | 21% | 0.996 | 0.939 | 89% |
  | WebInject2026 | 23% | 0.998 | 0.825 | 65% |
  | ECML/PKDD-2007 | 15% | 0.882 | 0.617 | 31% |

  **Under this control we rank behind ECML/PKDD-2007** (65% against
  31%). That is the honest result and it is reported, not buried. Both
  panels ship and neither is "the real one": the pool panel is the upper bound
  on what a complete deletion removes, the symmetric panel is the
  matched-aggression comparison. The claim the two jointly support is that
  CSIC-2010 retains 89-94% of its above-chance separation with no
  injection present, while this corpus retains 21-65% depending on how
  completely the injection can be removed.

  **Found while building it, and not in the brief:** matched deletion aggression
  is not matched deletion *completeness*. A 5x-lift rule is a statistic, not
  ground truth, so it leaves injection residue. The pairs make that measurable
  here and nowhere else -- with the pool vocabulary deleted a model scores an
  attack above its own twin 51% of the time (chance), but with the
  symmetric vocabulary deleted it still manages 80%. Part of our higher
  retention under the symmetric panel is therefore incomplete deletion rather
  than non-injection signal.

- **The skeleton result shipped without its controls.** A model given only the
  punctuation shape scores 0.991 here against 0.906 (CSIC-2010) and
  0.910 (ECML/PKDD-2007) -- read alone, that says we are the more
  shortcut-prone corpus. Two controls now ship beside it:
  - **within-pair** 0.996, attack above its own twin in
    99.4% of 3,227 pairs. Both halves carry identical carrier
    text, so this is the injection's shape and nothing else.
  - **template-disjoint** 0.976 against 0.983 for the full payload
    on the same split. Every attack shape at test time is unseen in training, so
    a model that had memorised this generator's benign mirror motifs (`%25`,
    `/**/`, `[1]`, `1|2`, `--7`) would collapse. It reaches 99% of
    full-payload performance instead.

  The reading, now in README and DATASHEET: injection is a punctuation
  phenomenon, so separability living in punctuation structure is the right
  profile. This corpus's lives in structure (skeleton 0.991,
  vocabulary-stripped 0.606); CSIC-2010's lives in vocabulary (skeleton
  0.906, vocabulary-stripped 0.966).

- **Stale results have shipped four times and nothing could catch it.** v4.4.0's
  `baselines.json` and `evaluation.json` do not match the corpus v4.4.0 shipped:
  disjoint recall 0.87822 against an actual 0.87853, and 84 and 116 other values.
  Confirmed rather than assumed -- two runs of each module on one corpus are
  byte-identical, so the drift is not nondeterminism. SHA256SUMS cannot catch
  this: a result regenerated from an older build is internally consistent and
  hashes correctly, so the manifest passes while the numbers describe a corpus
  that is no longer shipped, and the drift is small enough that review never
  notices.

### Added
- **`skeleton_generalises`** (6th construction check): the template-disjoint
  skeleton AUC must stay within 0.10 of the template-disjoint full-payload AUC,
  so the skeleton signal cannot become split-specific memorisation unnoticed.
  Currently a gap of 0.006.
- **`results_match_corpus`** (7th): every result JSON now carries a `_corpus`
  fingerprint of the corpus it was computed against, and the build fails if any
  disagrees or is unstamped. This is the systemic fix for the defect above --
  the mechanism `src.model_zoo` already had, extended to `baselines`,
  `evaluation`, `shortcut_stats`, `separability` and `syntax_ablation`.
  The gate is now 32 checks (25 validation + 7 construction).
- `--panel pool|symmetric|both` on `src.syntax_ablation`; both panels ship in
  `data/syntax_ablation.json` and in the explainer PDF as Table 1 and Table 1b.

### Changed
- Reference char n-gram, payload-disjoint: F1 93.4,
  TPR@0.1%FPR 87.9; structural
  50.8. Unchanged corpus, corrected numbers.
- `CITATION.cff` 4.5.0. The three unresolved author facts are now explicit
  `TODO(owner):` markers rather than commented-out fields, so they cannot be
  mistaken for filled in.

### Removed
- **`Understanding_WebInject2026.pdf` and `docs/build_explainer.py`.** The
  explainer was a reader's aid rather than part of the release, and nothing in
  the pipeline, the gate or CI depended on it. Its README entries are removed
  with it. The 4.4.0 entry recording that it was added stays: that release did
  add it, and the log records what happened.

## 4.4.0 - the structural protocol is no longer inventory-limited

The template-disjoint split is where the paper's most interesting generalisation
number comes from, and `struct_split_balance` was flagging it: four families held
too few templates to occupy three disjoint structural splits. Fixed by
construction, corpus rebuilt, everything downstream regenerated against the one
build.

### Fixed
- **Structural inventory limit.** `ssrf` held only two payload templates and
  `crlf`/`jndi`/`nosqli` only three, so those families could not reach the
  structural val (and `ssrf`'s pair could barely reach test). The cause was not
  only the grammar but the per-family cap: each generator enumerated its first
  template block past the cap and its later templates never survived. Generators
  for the four families now **interleave** their template blocks (`_roundrobin`)
  and carry 1-2 new templates each (`ssrf:userinfo`, `crlf:double_enc`/`log_forge`,
  `jndi:lower_bypass`/`char_bypass`/`env_bypass`/`nested_lookup`,
  `nosqli:regex`/`or_array`/`auth_bypass`). Every family now holds **>=4** (most
  5-7); the pool has **98 templates** (was 84), 26 held out structurally (was
  24), and `struct_split_balance` reports **no inventory-limited family**, every
  family in structural train/val/test, prevalence spread **0.002**.

  | | 4.3.0 | 4.4.0 |
  |---|--:|--:|
  | attack templates in pool | 84 | **98** |
  | templates held out structurally | 24 | **26** |
  | inventory-limited families (<3 templates) | ssrf | **none** |
  | structural attack-ratio spread | 0.003 | **0.002** |

- **The verbatim-`ambiguous` error floor leaned on one string.** On 4.3.0 the
  `ambiguous_floor` gate (a strong char n-gram must still false-positive on the
  verbatim tier) passed with 18 false positives -- but **12 of the 18** were the
  single specimen `http://169.254.169.254/latest/meta-data/`, which the model
  over-fired on only because 4.3.0's `ssrf` training was dominated by
  near-identical `http://169.254.169.254/...` strings. Diversifying `ssrf`
  removed that crutch and the floor fell to 2, below the gate's floor of 3 --
  not a corpus defect but a floor resting on an artefact. The verbatim specimen
  set was widened **26 -> 39** with recognisable, high-volume-family payloads
  (sqli/xss/cmdi/traversal/ssti), so the floor is now carried across the
  taxonomy: 9 false positives spread over sqli, xss, ssrf and prototype-pollution
  specimens. Ambiguous cores grow 884 -> **1,326** (858 discussion, 468
  verbatim).

### Changed (measured deltas -- the corpus is harder, as expected)
- Char n-gram TPR@0.1%FPR: payload-disjoint **83.9 -> 87.6**; template-disjoint
  (structural) **56.1 -> 52.5**. The structural gap widens **27.8 -> 35.1**
  points -- holding out whole shapes for the newly-templated families is exactly
  the harder test the split is meant to be.
- Table 1 (WebInject2026, -syntax -vocab): AUC kept **22% -> 21%**; within-pair
  matched accuracy with the injection deleted 51.8% -> **51.3%** (94.6% ties).
- Per-family recall (char n-gram, disjoint): cmdi 32 -> **26**, ssti 73 -> 76,
  ssrf 75 -> 77; LOFO zero-shot worst/best now cmdi 7.1% / smuggle 69.8%.
- Error analysis: false positives are still almost all in the `ambiguous` tier
  (2.01%); one `search` hard-negative now false-positives (0.16%), so the "all
  seven registers at 0.00%" line becomes "six of seven".

### Added
- **`docs/build_explainer.py`** rebuilds `Understanding_WebInject2026.pdf` from
  the shipped JSONs (`manifest`, `baselines`, `evaluation`, `shortcut_stats`,
  `separability`, `syntax_ablation`, `model_zoo_capped`) at build time -- no
  number typed by hand, the way `src/figures.py` works. The previous PDF was
  deleted for going four versions stale; this one cannot. A4, Helvetica,
  tables not prose, ASCII-only (ReportLab's built-in fonts are WinAnsi).

### Model zoo (regenerated against 4.4.0; all rows carry the 4.4.0 fingerprint)
- Classical and deep tiers regenerated (full and capped). **XGBoost full now
  completes** (F1 97.1) and fills the row 4.2.0 left empty -- the `bad_malloc`
  was a 15.3 GB-machine limit, not intrinsic.
- **Transformer tier run on GPU** (RTX 3050, 4 GB). DistilBERT (F1 89.4,
  carrier-only AUC 0.503) and RoBERTa (F1 91.1, structural 69.1, carrier-only
  0.520) train cleanly at a reduced batch. New `--batch` flag on
  `src.model_zoo` lets the transformer tier fit a small-VRAM card without
  changing `max_len` (so the models stay comparable).
- **DeBERTa-v3 is recorded non-convergent, and the "Metal-only" claim is
  corrected.** It diverges to a non-finite loss after the *first* optimiser step
  on **CUDA** -- reproduced across fp32, fp32 with TF32 disabled, and bf16, and
  independent of learning rate, warm-up and gradient clipping (the divergence is
  in the backward pass). The prior docs said the NaN was specific to Apple's
  Metal backend and "completes on CUDA"; it does not. `src.model_zoo` now
  fail-fasts on the first non-finite loss with an accurate message instead of
  training a doomed epoch, and the outcome is recorded in
  `model_zoo_capped.json` as `error` rather than dropped. Completing the row
  needs a DeBERTa-compatible transformers/torch build.

### Metadata
- `CITATION.cff` bumped to 4.4.0; the abstract's gate count corrected 31 -> 30
  (25 `validate` + 5 `audit_gaps`). Author affiliations/ORCIDs and the second
  author's family name remain author-supplied TODOs (git records only the handle
  `AbhiShrek07`); the Zenodo DOI is deferred until the repository is made public,
  which stays the owner's decision. ICISSP 2027 confirmed against the official
  site: 22-24 February 2027, Malta; regular-paper deadline 15 September 2026.

## 4.3.0 - the pair is a real counterfactual; Table 1 tests the headline claim

Three defects found by an external review of 4.2.0, all confirmed and all fixed
by construction. Corpus rebuilt.

### Fixed
- **The benign twin carried words its attack did not, so the pair was not a
  counterfactual.** 4.2.0's changelog said the mirror tokens were
  "digit/punctuation only (`%25`, `/**/`, `[1]`, `1|2`)". That was true of the
  token list and false of the span built from it: after the character-profile
  markers, `_decoy_span` padded the rest of the length budget with ordinary
  filler from `V.value_for`. Measured on the shipped 4.2.0 corpus:

  | | 4.2.0 | 4.3.0 |
  |---|--:|--:|
  | within-pair carrier-word delta is zero | 19.3% | **99.6%** |
  | attack word-poorer than its own twin | 77.5% | **0.2%** |
  | within-pair carrier-only AUC | 0.744 | **0.502** |
  | carrier-only model ranks attack above twin (tie-corrected) | 73.0% | **50.7%** |

  The span now echoes the payload's own non-pool alphabetic tokens rather than
  inventing new ones, and pads with digits and punctuation only. Three further
  causes of drift were found by measuring instead of assuming, and each is fixed
  at its root:

  - *Encoding.* `normalise` unquotes every record once. A query-placed span is
    quoted on assembly so that decode is undone, but a JSON, multipart or header
    span is stored raw and so reaches the payload column decoded -- `%3Csvg`
    arriving as `<svg`. The echo now matches whichever form the audit will see.
  - *Seam fusion.* A span is appended with no separator, so its edge run of
    letters fuses with the carrier's adjacent word into a new token, and a fused
    token counts even when the run alone is pool vocabulary the audit strips
    (`home.php` + `http://…` = `phphttp`). That was 618 of the last 647
    mismatches. The span now reproduces the payload's edge run verbatim.
  - *Single letters.* Deleting punctuation and digits turns `%3A` into a bare
    `A`. Those stray capitals were 99% of what still separated a pair once the
    injection was deleted outright. The echo now covers one-letter runs too.

  Two entries in the word-free vocabularies did contain a letter -- `--x`, in
  both `_PAD_TOKENS` and `_CHAR_CARRIERS` -- which made `x` benign-exclusive
  (5,061 occurrences against none). Now `--7`. A test asserts both lists are
  letter-free, so the 4.2.0 claim cannot become false again unnoticed.

  New blocking gate: `pair_integrity` requires the within-pair carrier-word
  delta to be zero for **>=95%** of pairs, alongside the existing length parity.

- **`benign_category` was moved to the attack twin, not copied.** All 6,343
  paired hard negatives shipped with a blank category: the attack inherited it
  and the benign row lost it. The error-analysis table therefore bucketed a
  third of the tier -- including every false positive -- into
  `(routine/ambiguous)`, so "every hard-negative category is at 0.00% false
  positives" was computed over 63% of the tier. Both halves now carry it; all
  17,000 hard negatives are categorised, and the test split holds 3,438 of them
  against roughly 1,247 before.

- **`lexical_register_leak` printed a sub-metric above its own ceiling and
  passed.** `vs hard_negative` ran 0.82-0.84 against a stated ceiling of 0.75
  and was not gated -- fairly described in review as a check reporting its own
  failure. It is neither a pass nor a leak but a confound: only 40% of attacks
  are twinned with a hard negative, so the comparison is largely prose against
  non-prose. The matched version -- each hard-negative attack against *its own
  twin* -- is **0.500**, and that is what is now gated, at a 0.55 ceiling. The
  unmatched figure is still printed, with its explanation.

### Added
- **`src/syntax_ablation.py` -- Table 1.** The corpus's load-bearing claim is
  that ~99% detection scores on existing corpora are driven by artefacts rather
  than by the injection. `src.shortcut_stats` argues that one character at a
  time; this argues it with the whole model. Delete the injection -- every
  non-letter character, then every word in the payload pool -- retrain, and see
  what is left. Same model, same features, same split, one deletion list applied
  to all three corpora.

  | | full F1 | full AUC | -syntax -vocab F1 | AUC | AUC kept |
  |---|--:|--:|--:|--:|--:|
  | CSIC-2010 | 0.971 | 0.995 | 0.873 | 0.965 | **94%** |
  | ECML/PKDD-2007 | 0.816 | 0.881 | 0.587 | 0.745 | 64% |
  | **WebInject2026** | 0.950 | 0.997 | **0.151** | **0.608** | **22%** |

  CSIC-2010 keeps 94% of its separation above chance with nothing recognisable
  as an attack left in the data. On the matched-pair version, which only this
  corpus supports, a model with the injection deleted scores **51.8% with 94.1%
  of pairs tied** -- chance is 50%.

  Deleting punctuation *alone* is reported but is not the experiment: it leaves
  `<script>alert(1)</script>` as `script alert script`, all three corpora keep
  ~90%, and quoting that number alone would mislead.

- **Corpus fingerprinting in `src/model_zoo.py`.** The tiers run as separate
  processes and accumulate into one JSON, so a row measured against an earlier
  build could sit in a published table with nothing looking wrong. Each run now
  records a corpus id and marks pre-existing rows `_stale` when it differs.

### Changed
- **The model zoo publishes both training budgets, and the structural claim is
  withdrawn.** 4.2.0 published one table, trained on an 8,000-row subsample --
  13% of the corpus -- and concluded from it that "RoBERTa is the only model
  that substantially closes the structural gap (72.2 against 22.9-42.6)". That
  compared a transformer against classical models given 13% of the data. Both
  tables now ship. At the cap, the best classical or deep model reaches 49.7 on
  structural TPR@0.1%FPR; at full data LinearSVM reaches **67.7** and the
  char-CNN **65.2** -- the same models, 18-20 points better, and within 5-7
  points of RoBERTa's capped 72.2.

  What the pair of tables supports is that the transformer was the most
  *sample-efficient* model at a fixed budget. It does not support the claim that
  structural generalisation is a model limitation rather than a property of the
  task, and that sentence is gone.

### Not done
- **XGBoost has no full-data row.** `bad_malloc`, needing 12.3 GB on a 15.3 GB
  machine (200k char n-gram features x 43k rows, `tree_method=hist`), reproduced
  with nothing else running. Lowering `max_features` for one model would break
  the like-for-like feature setup, so the row is reported missing. The capped
  run completes.
- **The transformer tier was not re-run against this build.** DistilBERT and
  RoBERTa were measured on the 4.2.0 corpus, and 4.3.0 rebuilt every benign
  twin, so those numbers are not comparable to the rows beside them. They are
  retained in `data/model_zoo_capped.json` flagged `_stale` and excluded from
  the published tables; completing them needs `transformers` and a CUDA device.
  This is the flagging mechanism above doing its job on its first real case.

## 4.2.0 - ten-model reference sweep

### Added
- **`src/model_zoo.py`**: four classical models (logistic regression, random
  forest, linear SVM, XGBoost), three deep models (char-CNN, LSTM, BiLSTM) and
  three transformers (DistilBERT, RoBERTa, DeBERTa-v3), all on the same splits,
  each with the two ablations that decide whether a headline number means
  anything -- carrier-only AUC and matched-pair accuracy. Blocking CI step for
  the classical tier.

  Nine of ten ran here. Trained on an identical 8,000-row stratified subsample
  so the comparison is like-for-like:

  | Model | Family | F1 | TPR@0.1%FPR | structural | paired | carrier AUC |
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

  Carrier-only AUC spans 0.499-0.615 across every family, with the transformers
  at chance: no model recovers the label once injection syntax is deleted. On
  v3.0.0 the same ablation gave 0.904. Paired accuracy is 91.6-99.8%, so every
  model's decision tracks the injected span.

  RoBERTa is the only model that substantially closes the structural gap (72.2
  against 22.9-42.6), which is evidence that template-disjoint generalisation is
  a model limitation rather than a property of the task.

### Not done
- **DeBERTa-v3 did not run.** Its disentangled attention diverges to NaN in fp32
  on Apple's Metal backend, with and without gradient clipping at lr 1e-5; CPU
  managed fewer than five optimiser steps in ten minutes. The harness selects
  CUDA when present, so one command completes the set on a CUDA machine. The
  blocker is recorded in `data/model_zoo_capped.json`, not dropped.
- Run the tiers as separate processes: XGBoost's OpenMP pool and torch's MPS
  backend deadlock in the same interpreter, so `--tier all` hangs on Apple
  silicon after the classical tier. Documented in the module.

## 4.1.0 - character-level shortcut statistics, benign taxonomy, calibration,
##         error analysis and span attribution

Answers five reviewer-facing questions the corpus could previously only assert.
Corpus rebuilt; schema gains `benign_category`.

### Fixed
- **Single characters still predicted the label, and the claim that they did not
  was false.** A per-character test (chi-square, Cramer's V, Haldane-Anscombe
  odds ratio with 95% CI, and a one-feature AUC) put `%` at 6.8% of benign rows
  against 31.3% of attacks -- Cramer's V 0.318, effectively identical to
  CSIC-2010's worst character (0.316). `%` and `*` come from double-URL-encoding
  and `/**/` comment evasions; `<`, `>`, `'`, `$` come from the payloads
  themselves. The gate's `evasion_artifact` check missed it because it asks only
  whether a marker occurs in both classes, never whether the rates match.

  The benign twin of a pair now mirrors its attack's **character profile**, not
  just its length, and unpaired hard negatives carry an attack-shaped profile
  too -- squarely the purpose of a tier defined as punctuation-rich but
  non-injective. Max Cramer's V falls **0.318 -> 0.139** and the best
  single-character AUC **0.622 -> 0.565**, against 0.316 for CSIC-2010 and
  0.411 for ECML/PKDD.

  The mirror tokens are digit/punctuation only (`%25`, `/**/`, `[1]`, `1|2`).
  Word-bearing carriers were tried first and reintroduced the register leak,
  because words present in benign rows and absent from payloads are exactly the
  signal pairing exists to remove.

  > **Corrected in 4.3.0.** That last paragraph was true of the token list and
  > false of the span built from it — the rest of the length budget was filled
  > with ordinary words from `V.value_for`, and two tokens (`--x`) carried a
  > letter. See the 4.3.0 entry for the measurements and the fix.

### Added
- **`src/shortcut_stats.py`**, a blocking CI step. Reports every statistic
  per character for this corpus and both reference corpora.

  The contract is deliberately not "zero association". Injection genuinely uses
  punctuation and the `routine` tier is deliberately ordinary alphanumeric
  traffic, so forcing a perfect match would falsify the benign distribution --
  a worse fault than the one being fixed. What is enforced: no single character
  yields a usable detector (AUC <= 0.60), and every association is smaller than
  in both corpora this one replaces. The residual, which exceeds the
  conventional 0.10 small-effect boundary, is reported rather than claimed away.
- **`benign_category` column** exposing the seven-way hard-negative taxonomy
  that already existed inside `vocab.py` but was never shipped: review, search,
  code, qa, encoded, log, markup. An attack inherits its twin's category, so a
  miss can be attributed to the benign register it was hiding in.
- **Calibration protocol** (`--protocol calibration`): Brier 0.0252,
  ECE 0.0556, MCE 0.5294, plus the reliability curve as data
  rather than a picture. Mean score 0.242 against a base rate
  of 0.261.
- **Error analysis** (`--protocol errors`): false positives by benign category
  and by tier, misses by family. On the reference model every hard-negative
  category is at 0.00% false positives; the misses concentrate in command
  injection. No other web-attack corpus can answer "what does my detector
  mistake for an attack?" beyond one aggregate number.
- **Span attribution** (`--protocol attribution`): because an attack is its twin
  plus one appended span, the ground-truth explanation is known exactly, so
  attribution is measured rather than approximated. Deleting the span moves the
  score 0.817 -> 0.057
  (twin 0.025); median span attribution
  0.966, localisation rate
  87.3%. This is what SHAP and integrated gradients
  approximate, without the approximation.

### Changed
- Reference char n-gram, payload-disjoint: F1 93.1,
  TPR@0.1%FPR 86.9. Structural TPR@0.1%FPR
  57.1. Matched-pair accuracy
  99.9% over 3,225 pairs.
- **Header placement restored.** The v4.0.0 paired path dropped it, taking
  header-placed attacks from 487 to **0** and silently removing the placement
  CRLF and request smuggling are actually about. Now 526, and the pair
  stays a counterfactual: both twins carry the same header, one with the payload
  appended and one with an equal-length benign span.
- The gate is now 25 validate checks + 5 construction checks + the
  character-statistics check, all blocking in CI.

## 4.0.0 - counterfactual pairing, pre-assigned splits, bursty sessions

An external audit of v3.0.0 found four properties the 25-check gate did not
test. All four reproduced. This release fixes them by construction and makes the
checks blocking in CI. Schema gains `pair_id`; distribution and splits changed,
so results are **not** comparable to a v3.0.0 run.

### Fixed (measured leaks v3.0.0 shipped)
- **Lexical register leak.** Delete every non-alphabetic character, then delete
  every word occurring in the seed payload pool, and v3.0.0's label was still
  recoverable from the ordinary words left behind at **AUC 0.904** (0.990 for
  attack versus the `hard_negative` tier). The cause was construction: attacks
  were synthesised independently and given routine-tier filler, while hard
  negatives carried prose cores, so carrier register encoded the tier and the
  tier encoded the label. `char_class` and `hard_neg` both passed, because
  neither looks at token-to-label association. This is the same *shape* of
  defect as the v2.1 header leak: a character-class shortcut was removed and a
  lexical one took its place.

  v4 builds every attack as the **counterfactual twin** of a benign row drawn
  from the same tier mixture -- same endpoint, same carrier values, same
  headers, same multipart boundary -- with the payload *appended* into one
  declared injection slot and nothing else changed. Both halves share a
  `pair_id`, and matched on length. Carrier-only AUC falls to **0.608**.

  Appending rather than substituting is what did it: substituting removes the
  target slot's prose, so attacks carry systematically less benign vocabulary
  than their own twins, which measured 0.840 on its own. Appending is also how
  real injections arrive (`?q=shoes' OR 1=1--`).
- **`split_struct` was neither family-complete nor prevalence-matched.**
  `split_balance` inspects `split` only. In v3.0.0 `nosqli` and `ssrf` had no
  rows in the structural val *or* test sets, six families had no val rows, and
  attack prevalence ran 28.6/21.2/15.3 percent (spread 0.134). The structural
  gap was therefore measured under a different family mix. v4 pre-assigns every
  payload group, template and benign core to a (split, split_struct) cell before
  generation and pairs only within a cell, seeding train/test/val in that order
  so thin families still cover the splits their inventory allows. Spread is now
  0.007, every family is in structural train and test, and only `ssrf` (2
  templates) cannot reach val -- an inventory limit, reported by the check.
- **`session` carried no sequential signal.** Per-session attack-rate variance
  was 0.989x the i.i.d. binomial expectation, so no sequence model could beat a
  per-request model on a column the datasheet advertised for sequence
  modelling. v4 gives a minority of sessions a high within-session attack rate;
  the ratio is now **2.87**. `session_leak` constrains the mean of per-session
  rates, not the variance, so both hold.
- **Cross-corpus transfer was reported with a collapsing metric.** F1 ~41
  against CSIC-2010 is exactly what an all-positive classifier scores at that
  base rate, and recall was ~100% with precision equal to the base rate.
  `baselines.json` now carries `roc_auc` and `pred_pos_rate` for every
  cross-dataset pair. Threshold-free, transfer is **AUC 0.61** against
  CSIC-2010 and **0.77** against ECML/PKDD.
- **`capture()` sent only `form` bodies**, so 37% of rows replayed bodyless
  while `Content-Type` advertised a payload. Bodies now go out verbatim per
  content type.

### Changed
- **The task is harder, and that is the result.** Same reference model, same
  protocol, v3.0.0 -> v4.0.0:

  | Metric (payload-disjoint) | v3.0.0 | v4.0.0 |
  |---|--:|--:|
  | char n-gram F1 | 95.6 | 92.4 |
  | char n-gram TPR@0.1%FPR | 87.1 | 81.9 |
  | **word n-gram F1** | **82.1** | **30.3** |
  | length-only F1 | 0.4 | 0.0 |
  | structural TPR@0.1%FPR | 77.2 | 53.0 |
  | carrier-only AUC (register) | 0.904 | 0.608 |

  The word n-gram collapse is the clearest single piece of evidence: a
  word-level model scored 82.1 F1 on v3.0.0 because carrier register was
  informative. With the register gone it scores 30.3. The structural gap widens
  from 9.8 to 28.9 points, because template shape is now the signal that is
  actually being held out.
- **Honesty ladder** (char n-gram TPR@0.1%FPR): random 88.8 -> payload-disjoint
  81.9 -> template-disjoint 53.0.
- Zero-shot LOFO recall now spans 6.9% (prototype pollution) to 80.8% (CRLF).
- Supported Python floor stays 3.11; CI matrix 3.11 / 3.12.

### Added
- **`src/audit_gaps.py` is a blocking CI step**, so the gate is effectively 30
  checks. It shipped failing 0/4 against v3.0.0 and passes 5/5 here, the fifth
  being `pair_integrity`.
- **`pair_id`** column and a **matched-pair evaluation protocol**
  (`python -m src.evaluate --protocol paired`). Within a pair the only
  difference is the injected span -- matched on length too -- so a score
  difference is attributable to it. The reference model scores the attack above
  its own twin in **99.9%** of 3,236 test pairs (median delta
  +0.90) and crosses 0.5 in the right direction in 86.7%. A detector
  reading carrier text rather than the injection shows a delta near zero here
  even at high aggregate F1, which no metric over independently drawn rows can
  reveal.
- **Within-pair length parity.** Appending a payload made every attack longer
  than its twin (100% of pairs, length-only AUC 0.611), so the benign twin now
  receives a benign span of equal length in the same slot: 80.3% of pairs match
  exactly and length-only AUC falls to 0.567. The trade is a carrier AUC of
  0.608 rather than 0.539, since the twin carries filler words the payload does
  not; both sit well under the 0.75 ceiling, and matched length is what makes
  the paired delta attributable to span *content*.

## Unreleased — release-integrity fix

No corpus change: `data/webinject2026.csv` and every other released file is
byte-identical to 3.0.0, and `src/config.VERSION` is unchanged.

### Fixed
- **`SHA256SUMS` shipped five stale hashes.** 3.0.0 published correct digests for
  the corpus CSV, Parquet and payload pool, but stale ones for `manifest.json`,
  `baselines.json`, `evaluation.json`, `csic_parsed.csv` and `ecml_parsed.csv`,
  so `shasum -a 256 -c SHA256SUMS` reported 5 FAILED against an intact release.
  The manifest was hand-maintained while its eight files are written by three
  entry points at three different times. Regenerated from the released files.

- **The package did not parse on Python 3.10 or 3.11.** `src/vocab.py` and
  `src/baselines.py` each held an f-string with a backslash in the *expression*
  part — a `SyntaxError` before PEP 701 landed in 3.12. `requirements.txt`
  advertises 3.10+, so a reviewer on the supported floor could not import the
  package at all, and CI (pinned to 3.11) failed at the rebuild step on every
  push. Both are hoisted into variables; output is unchanged and the corpus
  rebuilds byte-identical.

### Changed
- **Supported Python floor is now 3.11**, documented rather than assumed. 25 rows
  carry raw NUL bytes from the null-byte evasion, and 3.10's `csv` module rejects
  NUL on both read and write, so 3.10 cannot load the corpus at all. 3.11 lifted
  the restriction.

### Documented (no data change)
- **The 25 NUL-bearing rows**, and the fact that the CSV and Parquet copies
  disagree on exactly those rows: `write_parquet` re-reads the CSV through
  `pandas.read_csv`, whose C parser silently drops NUL, so the Parquet is
  NUL-free in `body` and `payload_raw` (50 cells). The CSV is authoritative.
  Also noted that the release was built without `data/patt/`, so a rebuild with
  a local PayloadsAllTheThings checkout will not reproduce the published CSV.

### Added
- **`src/audit_gaps.py`** — four properties the 25-check gate does not enforce,
  written as gate-style checks and shipped *failing* (0/4 on v3.0.0). Found by
  an external audit and independently reproduced. The headline one is a
  **lexical register leak**: with all punctuation and all payload-pool words
  deleted, the label is still recoverable from ordinary vocabulary at AUC 0.904
  overall and 0.990 against the `hard_negative` tier. The others are
  `split_struct` imbalance, a `session` column with no within-session
  correlation, and cross-corpus transfer reported via a collapsing F1 (recall
  ~100%, precision = base rate; threshold-free AUC is 0.53 against CSIC-2010).
  Full write-up in DATASHEET.md > Limitations.

### Fixed
- **`capture()` sent only `form` bodies.** `json`, `graphql` and `multipart`
  rows — 22,649 rows, 37% of the corpus, including 5,272 attacks whose payload
  sits in the body — were replayed with no body at all while the `Content-Type`
  header still advertised one, so the recorded `status` described a different
  request than the row it was stored on. Bodies are now sent verbatim per
  content type, preserving the multipart boundary the headers declare. Affects
  the opt-in `--capture` path only; the released corpus is offline-synthesised
  and unchanged.
- **README overstated `split_balance`.** It implied family coverage and
  prevalence matching held for both splits; the check inspects `split` only.
  The bullet now states the scope and gives the `split_struct` figures.

### Added
- **CI matrix over Python 3.11 / 3.12**, spanning the PEP 701 boundary.
  A single-version matrix is what let the f-strings above ship.
- **`src/checksums.py`** owns the manifest. `python -m src.checksums` rewrites it;
  `--check` verifies and exits non-zero. `src.build` refreshes it after every
  build, and `src.baselines` / `src.evaluate` refresh it when `--json` writes a
  tracked file, so the manifest can no longer drift behind the artefacts.
- **CI gate `Released files match SHA256SUMS`**, run against a fresh checkout
  before the rebuild, so a commit whose files and manifest disagree fails.

## 3.0.0 — leak-audited benign side, modern surface, harder protocols

v2.1 made the *attack* side rigorous (1,494 payload groups, payload-disjoint,
20-check gate) but left the *benign* side generated from ~150 hand-written
phrases with a per-row group, and gave every attack punctuation-rich headers
while routine benigns got plain ones. This release applies the attack-side
discipline to the benign side, modernises the request surface, and adds harder
evaluation protocols. Schema gained columns; distribution and splits changed, so
results are **not** comparable to a v2.1 run.

### Fixed (measured leaks v2.1 shipped)
- **Benign side was not split-disjoint.** Measured on the v2.1 CSV: **67.4% of
  hard-negative *test* parameter values appeared verbatim in training**, and
  35.2% of hard-negative test rows had every value seen in training. Since the
  headline metric is TPR at a 0.1% FP budget — driven entirely by the hardest
  negatives — a third of that budget was memorisation. v3 enumerates ~2,340
  groupable benign **cores**; each hard-negative row carries exactly one core and
  the core id is its split group, so a benign phrase never spans train/test
  (gate: `benign_split_leak`, 0 spanning). Every non-carrier field uses an
  unbounded procedural generator, so incidental verbatim reuse of punctuation-
  rich values fell from 67% to <10%.
- **Headers leaked the label.** v2.1 gave every attack hard-negative headers and
  routine benigns plain ones, so a `prefs=` cookie moved P(attack) from 17.6% to
  44.9%. Headers are part of the inspected payload. v3 draws header punctuation
  i.i.d. of the label for every row; header→label NMI is now 0.000 (gate:
  `header_leak`).
- **Family was partly readable from the URL.** v2.1 path→family NMI was 0.55 and
  all 204 XXE rows sat at one endpoint. v3 spreads every family across ≥7
  endpoints (XXE now on 12); path→family NMI is 0.197 (gate: `family_path_leak`).

### Added
- **Four attack families** (10 → 14): JNDI/Log4Shell, insecure deserialization,
  prototype pollution, and request smuggling / header injection — the shapes
  that dominate modern advisories and were entirely absent.
- **Modern request surface.** JSON, GraphQL and multipart bodies, and PUT / PATCH
  / DELETE methods (v2.1 was ~100% form-encoded GET/POST). A `content_type`
  column is shipped and gated non-predictive (`content_type_leak`).
- **Structural split (`split_struct`).** Holds out whole payload *templates*, not
  just strings — a harder generalisation test than the payload-disjoint split.
  84 attack templates, 26 held out in the structural test.
- **Chained evasions.** A transform can now be stacked (e.g. `case_mix+url_double`);
  835 attacks carry a composite evasion. `apply_evasion` takes a chain rate.
- **Sessions (`session` column).** Requests are chunked into ~8,200 synthetic
  sessions that never span a split, enabling sequence/behavioural models
  (`session_leak`).
- **`src/evaluate.py`** — evaluation protocols (payload-disjoint, structural,
  leave-one-family-out zero-shot, evasion hold-out), **prevalence-corrected
  precision** (0.5% / 1% / 5% / 26% attack), and a **submission scorer**
  (`--predictions`) so external models are graded on the fixed test split.
- **Parquet export** (`data/webinject2026.parquet`) alongside the CSV.
- **New gate checks**, bringing the gate to **25** in total:
  `benign_split_leak`, `header_leak`, `family_path_leak`, `content_type_leak`,
  `struct_split_leak`, `session_leak`, plus a `struct_gen` recall floor.

### Changed
- Rows 55,200 → **61,400** (benign 41,200 → 45,400; attack 14,000 → 16,000).
- 3 apps, **35 endpoints** (was 23), 77 injection points, 14 families.
- `MIN_TEST_GROUPS` 150 → 250; per-family test-group floor 5 → 8.

## 2.1.0 — payload breadth, stratified split, real error floor

v2.0 closed the character-class shortcut but left three problems that this
release fixes. Schema is unchanged; distribution and split changed, so results
are **not** comparable to a v2.0 run.

### Fixed (what made v2.0's headline number unreliable)
- **Thin attack side.** v2.0 shipped ~130 distinct payloads, so the
  payload-disjoint *test* set held **30 payload groups**; the reported 82 F1 was
  dominated by the variance of thirty strings and could not rank two detectors.
  A deterministic per-family grammar (`payloads._generate`) lifts the pool to
  **1,494 canonical payloads → 297 test groups, ≥10 per family**. Every payload
  keeps its group key, so the split stays leakage-free.
- **Unusable validation split.** v2.0's `val` was 14.9% attack and missing five
  of ten families, so a threshold or model chosen on it was meaningless. The
  split is now **family-stratified** (`build._stratum`): every family and tier is
  split ~70/10/20, so the attack ratio matches across splits (spread 0.000) and
  every family appears in every split.
- **`ambiguous` tier that leaked itself.** v2.0 had 12 fixed phrases reused in
  99.2% of test rows, and its "irreducible error floor" was empirically **zero**
  (a strong model false-positived on none of them). The tier is now **544
  compositional (frame × specimen) cores**, grouped and split-disjoint (0% test
  reuse), in two kinds: `discussion` (headroom a context model wins) and
  `verbatim` (the payload with minimal framing — the genuinely irreducible floor,
  where the char n-gram now false-positives as it must). `group` ids are prefixed
  `ambigD`/`ambigV` so the two are separable with no schema change.

### Added
- **Evasion no longer a free label signal.** Benign traffic now carries the same
  encoding markers the evasion transforms introduce (`%25`, `/**/`, `&#`, `%00`,
  percent-encoded punctuation); the new `evasion_artifact` gate fails if any
  marker is attack-exclusive. Effect: `whitespace_swap`/`null_byte` evasions are
  now *harder* than plain attacks, not easier.
- **Six new gate checks** (14 → 20): `near_dup`, `evasion_artifact`,
  `split_balance`, `test_groups`, `ambiguous_floor`, and per-family coverage in
  `test_groups`.
- **Detection-grade baselines.** `src/baselines.py` now reports PR-AUC and
  **TPR@FPR = 1% / 0.1%** (the metric a WAF is judged by), adds a
  **rule/signature** baseline, prints per-family and per-evasion recall,
  **group-level bootstrap 95% CIs**, and **cross-dataset transfer** to
  CSIC-2010 / ECML-PKDD-2007.
- Manifest now records group statistics (`groups.attack_test`,
  `attack_test_per_family_min`, `ambiguous_cores`, `ambiguous_verbatim_rows`).

### Changed
- Rows 54,200 → **55,200** (benign 40,200 → 41,200; `ambiguous` 1,200 → 2,200).
- `ngram_ceiling` raised 0.985 → 0.99: under 25% class imbalance, accuracy is a
  coarse lens (a benign-perfect, 96%-recall model already reaches ~0.99), so the
  check now only guards against a v1-style char-class shortcut; the real
  headroom/ranking signal moved to TPR@low-FPR and per-family recall in
  `baselines.py`.

## 2.0.0 — leakage-audited rebuild

Complete regeneration of the corpus and pipeline. **Not backward compatible**
with v1 (schema and distribution changed).

### Fixed (leaks that made v1 trivially separable)
- **Character-class shortcut.** In v1 no benign request contained a quote, angle
  bracket, semicolon, or parenthesis, so a one-line rule reached ~99% and a char
  n-gram model reached 99.99% F1. v2 adds a 15,000-row `hard_negative` tier of
  punctuation-rich but non-injective benign traffic. Char n-gram accuracy on the
  shipped split is now 90.7% (disjoint), with real headroom.
- **Parameter-name leak.** v1's `comment` parameter carried 2,187 attacks and
  zero benign requests. v2 enforces that every injectable parameter also has a
  benign generator on the same endpoint (`config.validate_config()`).
- **Evaluation leak.** v1 shipped no split; a random split lets payloads appear
  in both train and test. v2 ships a fixed **payload-disjoint** train/val/test
  split grouped on canonical payloads.

### Added
- Seven new attack families: path traversal, SSTI, NoSQLi, SSRF, CRLF, LDAP
  injection, XXE (v1 had SQLi, XSS, cmdi only).
- POST bodies (30% of traffic) and query/body/header injection placement.
- Evasion transforms (double-encoding, case mixing, comment insertion, null
  bytes, entity/percent encoding) on 28% of attacks.
- `ambiguous` benign tier: literal attack syntax in benign context, tagged.
- Request headers as an inspected feature surface.
- 14-check quality gate (`src/validate.py`) run in CI/tests; the build fails if
  any shortcut or leak reappears.
- Reference baselines on both split protocols (`src/baselines.py`).
- Datasheet, license, NOTICE, manifest, and per-file checksums.

### Changed
- Generation refactored from a single notebook into an importable, testable
  `src/` package with an offline default (no containers required) and live
  capture as an opt-in.

## 1.0.0 — initial corpus
- 52,696 requests; DVWA / Juice Shop / bWAPP; SQLi / XSS / cmdi. Validated only
  that payload length was not a shortcut.
