# WebInject2026

A contemporary, leakage-audited corpus for **web-application injection-attack
detection**. 61,400 labelled HTTP requests across three applications and fourteen
attack families, shipped with fixed payload-disjoint **and** template-disjoint
splits and an automated 25-check quality gate that fails the build if any known
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
> chained evasions, sessions, and harder evaluation protocols. The gate grew
> to 25 checks. See [CHANGELOG.md](CHANGELOG.md).

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
| Distinct attack payloads (groups) | 1,961 — **393 held out in test**, ≥11 per family |
| Attack templates | 84 — **26 held out in the structural test** |
| Methods | GET / POST / PUT / PATCH / DELETE |
| Content types | query 31,644 · json 15,607 · form 7,107 · multipart 5,234 · graphql 1,808 |
| Injection placement | query 8,673 · body 6,840 · header 487 |
| Evasion-transformed attacks | 5,538 (35%), of which 835 chained |
| Splits | `split` (payload-disjoint) · `split_struct` (template-disjoint); both family/tier-stratified 70/10/20 |

Benign traffic is deliberately built in three tiers so the task cannot collapse
to a punctuation test:

| Tier | Rows | What it is |
|---|---|---|
| `routine` | 26,000 | Ordinary navigation, alphanumeric-dominant |
| `hard_negative` | 17,000 | **Punctuation-rich but non-injective** — apostrophes in names, quotes and shell metacharacters in reviews, base64/JWT tokens, URLs and JSON in parameters, pasted code snippets, and the same encoding markers evasions use (`%25`, `/**/`, `&#`, `%00`) in benign contexts. Enumerated into **~2,340 split-disjoint cores**: each row carries one core, the core id is its split group, so no benign phrase spans train/test |
| `ambiguous` | 2,400 | Benign text that *contains literal attack syntax*, in 823 compositional (frame × specimen) cores across all 14 families (528 `discussion`, 295 `verbatim`), split-disjoint. `discussion` cores ("how do I stop `' OR 1=1--`?") are headroom a context-aware model wins; `verbatim` cores (the payload with minimal framing) are the **irreducible** payload-only error floor. The `group` id is prefixed `ambigD`/`ambigV` so the two are separable |

## Quick start

```bash
pip install -r requirements.txt

shasum -a 256 -c SHA256SUMS  # confirm the files you have are the files released
python -m src.build          # rebuild the corpus offline (reproducible, seed=42)
python -m src.validate       # 25-check quality gate; non-zero exit on any FAIL
python -m src.baselines      # reference results table
python -m src.evaluate       # generalisation protocols + prevalence correction
python -m src.figures        # the eight paper figures, from the shipped result JSONs
python -m src.audit_gaps     # four known, documented gaps; currently 0/4 (see DATASHEET)
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
| length only (1 feature) | 0.4 | 26.2 | 0.5 | 0.2 |
| special-char count (1 feature) | 8.3 | 35.8 | 1.3 | 0.7 |
| rule signature (14 regex) | 57.5 | 50.1 | 0.9 | 0.0 |
| word n-gram (1–2) + LogReg | 82.1 | 86.6 | 70.3 | 13.1 |
| char n-gram (3–5) + LogReg | **95.6** | 99.5 | 97.2 | **87.1** |

The ranking signal is the last column: **TPR@0.1%FPR spans 0 → 13 → 87** across
baselines. Accuracy/F1 saturate; detection at a strict FP budget does not.

- **Two generalisation gaps.** The char n-gram's TPR@0.1%FPR is 95.1 on a random
  split, **87.1 on the payload-disjoint split, and 77.2 on the template-disjoint
  (`split_struct`) split.** The drop from payload- to template-disjoint is the
  systematicity of the grammar — report both.
- **Prevalence matters.** At the corpus's 26% attack rate the char n-gram's
  precision at 1% FPR is 97%; at a realistic **0.5% prevalence it is 33%** (81%
  if you can hold FPR to 0.1%). Report the precision at *your* operating
  prevalence — `evaluate.py` prints the table.
- **Group-bootstrap 95% CI** (char n-gram, disjoint, resampling payload groups —
  not rows): F1 [94.6, 96.6], recall [90.4, 94.0], TPR@0.1%FPR [77.9, 91.3].
- **Where the headroom is** (char n-gram recall, disjoint): **cmdi 55%** ·
  ssrf 83% · crlf 88% · ssti 89% · smuggle 90% … xss 98% · xxe 100%; by evasion,
  chained transforms and `whitespace_swap` (81%) sit *below* plain (90%).
- **External validity.** Train here, test on CSIC-2010 / ECML-PKDD-2007: F1 falls
  from ~96 in-corpus to ~41–46 cross-corpus. **Do not quote that F1 on its own —
  it is threshold collapse, not graded degradation.** Recall is ~100% and
  precision equals the base rate, i.e. the model fires on nearly every row; an
  all-positive classifier scores exactly 41.0 at CSIC's base rate. Threshold-free
  the picture is worse and more honest: **AUC 0.53 against CSIC-2010** (near
  chance) and **0.72 against ECML/PKDD**. Synthetic detection signal does not
  transfer; see [DATASHEET.md](DATASHEET.md) > Limitations.

## Evaluation protocols

`python -m src.evaluate` runs four generalisation protocols and writes
`data/evaluation.json`:

| Protocol | Split | Measures |
|---|---|---|
| `disjoint` | `split` | payload-disjoint (the headline; use this to rank) |
| `structural` | `split_struct` | whole payload *templates* held out — harder |
| `lofo` | leave-one-family-out | zero-shot recall on an unseen attack family |
| `evasion` | plain→evaded | recall on obfuscations the model never trained on |

Every protocol reports precision corrected to 0.5% / 1% / 5% / 26% attack
prevalence. Reference char n-gram, payload-disjoint test:

- **Structural gap.** TPR@0.1%FPR falls **87.1 → 77.2** from the payload-disjoint
  to the template-disjoint split (+9.8 pts) — the model leans on template shape.
- **Zero-shot (LOFO) recall spans 14 → 88%.** A model that never saw the family
  barely flags xss (14%), sqli (18%) or prototype pollution (15%), but transfers
  to smuggle (88%) and crlf (76%). Injection detection does **not** generalise
  uniformly across families.
- **Evasion hold-out.** Trained on plain attacks only, recall on *evaded* test
  attacks is **58%** (55% on chained transforms) — obfuscation the model never
  saw roughly halves recall.

To grade your own detector on the fixed test split, pass one score per test row
(in `df[df.split=='test']` order):

```bash
python -m src.evaluate --predictions my_scores.(csv|parquet|npy)
```

## What the quality gate enforces

`python -m src.validate` fails the build unless every one of 25 checks passes:

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
src/audit_gaps.py  four known gaps NOT yet enforced by the gate; ships failing (0/4)
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
