# WebInject2026

A contemporary, leakage-audited corpus for **web-application injection-attack
detection**. 61,400 labelled HTTP requests across three applications and fourteen
attack families, shipped with fixed payload-disjoint **and** template-disjoint
splits and an automated 29-check quality gate that fails the build if any known
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
> 0.539 and the word n-gram baseline falls from F1 82.1 to 29.9. The gate is 29
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
| Distinct attack payloads (groups) | 1,942 — **386 held out in test**, ≥10 per family |
| Attack templates | 84 — **24 held out in the structural test** |
| Methods | GET / POST / PUT / PATCH / DELETE |
| Content types | query 31,551 · json 15,722 · form 7,095 · multipart 5,295 · graphql 1,737 |
| Injection placement | query 9,133 · body 6,867 · header 0 |
| Evasion-transformed attacks | 5,617 (35%), of which 885 chained |
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
python -m src.build          # rebuild the corpus offline (reproducible, seed=42)
python -m src.validate       # 25-check quality gate; non-zero exit on any FAIL
python -m src.audit_gaps     # 4 construction checks (register, splits, sessions, transfer)
python -m src.baselines      # reference results table
python -m src.evaluate       # generalisation protocols + prevalence correction
python -m src.figures        # the eight paper figures, from the shipped result JSONs
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
| length only (1 feature) | 0.0 | 32.9 | 0.0 | 0.0 |
| special-char count (1 feature) | 7.2 | 37.2 | 3.9 | 0.8 |
| rule signature (14 regex) | 59.4 | 51.0 | 0.9 | 0.0 |
| word n-gram (1–2) + LogReg | 29.9 | 59.1 | 26.6 | 20.9 |
| char n-gram (3–5) + LogReg | **91.0** | 98.9 | 94.3 | **85.7** |

The ranking signal is the last column: **TPR@0.1%FPR spans 0 → 21 → 85.7** across
baselines. Accuracy/F1 saturate; detection at a strict FP budget does not.

- **Two generalisation gaps.** The char n-gram's TPR@0.1%FPR is 90.0 on a random
  split, **85.7 on the payload-disjoint split, and 52.6 on the template-disjoint
  (`split_struct`) split** — a 33.1-point structural gap. Report all three.
- **Prevalence matters.** At the corpus's 26% attack rate the char n-gram's
  precision at 1% FPR is 97.0%; at a realistic **0.5% prevalence it is 32.2%** (81.2%
  if you can hold FPR to 0.1%). Report the precision at *your* operating
  prevalence — `evaluate.py` prints the table.
- **Group-bootstrap 95% CI** (char n-gram, disjoint, resampling payload groups —
  not rows): F1 [89.0, 92.8], recall [80.3, 86.6], TPR@0.1%FPR [82.0, 89.8].
- **Where the headroom is** (char n-gram recall, disjoint): **cmdi 24.9%** · ssrf 62.8% · ssti 73.4% … xxe 97.8% · jndi 99.0%.
- **External validity.** Train here, test on CSIC-2010 / ECML-PKDD-2007: F1 falls
  from ~96 in-corpus to ~41–46 cross-corpus. **Do not quote that F1 on its own —
  it is threshold collapse, not graded degradation.** Recall is ~100% and
  precision equals the base rate, i.e. the model fires on nearly every row; an
  all-positive classifier scores exactly 41.0 at CSIC's base rate. Threshold-free
  the picture is worse and more honest: **AUC 0.61 against CSIC-2010** and
  **0.77 against ECML/PKDD**, with the model firing on 100% of rows. Synthetic detection signal does not
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

- **Structural gap.** TPR@0.1%FPR falls **85.7 → 52.6** from the payload-disjoint
  to the template-disjoint split (33.1 pts) — the model leans on template shape.
- **Zero-shot (LOFO) recall spans 6.9 → 80.8%.** A model that never saw the family
  barely flags protopollute (6.9%), sqli (8.0%) or cmdi (9.6%), but transfers
  to crlf (80.8%) and smuggle (80.0%). Injection detection does **not** generalise
  uniformly across families.
- **Evasion hold-out.** Trained on plain attacks only, recall on *evaded* test
  attacks is **54.8%** (50.8% on chained transforms) — obfuscation the model
  never saw roughly halves recall.

To grade your own detector on the fixed test split, pass one score per test row
(in `df[df.split=='test']` order):

```bash
python -m src.evaluate --predictions my_scores.(csv|parquet|npy)
```

## What the quality gate enforces

`python -m src.validate` fails the build unless every one of 25 checks passes, and
`python -m src.audit_gaps` adds four construction checks that are equally blocking in CI:

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
src/audit_gaps.py  four construction checks (register/splits/sessions/transfer); blocking in CI
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
