# Changelog

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
- **Six new gate checks** (20 → 26): `benign_split_leak`, `header_leak`,
  `family_path_leak`, `content_type_leak`, `struct_split_leak`, `session_leak`,
  plus a `struct_gen` recall floor.

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
