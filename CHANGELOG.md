# Changelog

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
