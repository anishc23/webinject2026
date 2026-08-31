# Datasheet — WebInject2026 v4.5.0

Following Gebru et al., *Datasheets for Datasets* (2021). This document is the
authoritative description of what the corpus is, how it was made, and where it
should and should not be used.

---

## Motivation

**Why was the dataset created?**
To provide a modern, leakage-audited benchmark for detecting web-application
injection attacks at the level of the HTTP request. The widely used public
corpora (CSIC-2010, ECML/PKDD-2007) predate today's application frameworks,
encodings, and payload techniques, and several exhibit trivial shortcuts that
let naive models score highly without learning the task.

**What problem does it target?**
Binary classification (benign vs attack) of an HTTP request from its request
line, body, and key headers, with a secondary multi-class label over ten attack
families. It is designed so that success requires modelling attack *structure*,
not memorising payload strings or exploiting an artefact of generation.

---

## Composition

**What does each instance represent?**
One HTTP request. 61,400 instances: 45,400 benign, 16,000 attack. Every attack row is the counterfactual twin of a benign row (shared `pair_id`).

**Schema (24 columns).**

| Column | Description |
|---|---|
| `app` | Target application: `dvwa`, `juice`, `bwapp` |
| `method` | `GET`, `POST`, `PUT`, `PATCH`, `DELETE` |
| `path` | URL path |
| `query` | URL-encoded query string |
| `body` | Request body, encoded per `content_type` |
| `content_type` | Body encoding: `query` (no body), `form`, `json`, `graphql`, `multipart` |
| `headers` | JSON of request headers (User-Agent, Accept, Accept-Language, Referer, Cookie, and sometimes Content-Type, X-Forwarded-For/Host, Origin, Transfer-Encoding) |
| `payload` | **Primary feature.** Decoded, whitespace-normalised text of path + query + body + inspected headers |
| `payload_raw` | Encoded path + query + body, headers excluded (convenience) |
| `label` | `0` benign, `1` attack |
| `attack_type` | `benign` or family name |
| `family` | As `attack_type`, but benign is split into `benign` / `benign_ambiguous` |
| `placement` | Where the attack sits: `query`, `body`, `header` (empty for benign) |
| `tier` | `routine`, `hard_negative`, `ambiguous`, `attack` |
| `evasion` | Evasion transform(s) applied, or `none`. Composite = `a+b` (chained) |
| `source` | `synthetic` (offline) or `captured` (live replay) |
| `status` | HTTP status from live capture; empty for synthetic rows |
| `session` | Synthetic session id; a session never spans a split (for sequence models) |
| `split` | `train`/`val`/`test` — **payload-disjoint, family/tier-stratified** (primary) |
| `split_struct` | `train`/`val`/`test` — **template-disjoint** (structural generalisation) |
| `template` | Attack template the payload was generated from (`sqli:union`, …); `benign:*` / `ambiguous` for benign |
| `benign_category` | Register of the hard-negative carrier: `review`, `search`, `code`, `qa`, `encoded`, `log`, `markup`. Both halves of a pair carry it — the attack inherits its twin's, so a miss is attributable to the benign text it hid in, and the twin keeps its own so a false positive is too. Empty only for routine/ambiguous rows. (Before 4.3.0 it was *moved* to the attack, leaving all 6,343 paired hard negatives blank.) |
| `pair_id` | Counterfactual pair id. Each attack row and its benign twin share one: same endpoint, carrier values, headers and boundary, differing only by the injected span. Empty for unpaired benign rows |
| `group` | Split group; `split` never shares one. Attack = canonical-payload hash; ambiguous = `ambigD`/`ambigV` (frame × specimen) core; hard_negative = `benH` core; routine = per-row |

**Class / family distribution.**

- Benign 45,400 = routine 26,000 + hard_negative 17,000 + ambiguous 2,400
  (in 1,326 cores). Hard negatives draw from 2,344 groupable,
  split-disjoint cores.
- Attack 16,000 across: xss 3,697 · sqli 3,550 · ssti 1,498 · nosqli 1,227 · jndi 1,070 · traversal 873 · ssrf 865 · deser 771 · cmdi 725 · protopollute 616 · ldapi 456 · smuggle 267 · xxe 220 · crlf 165.
- Distinct attack payloads: 1,943 groups (387 held out in the test split,
  >=11 per family), across 98 templates (26 held out in the structural test).
  Placement: query 8,510 · body 6,983 · header 507. Content type: query 31,417 · json 15,662 · multipart 5,414 · form 7,138 · graphql 1,769.
  Evasion applied to 5,647 (901 chained). 8,239 sessions.

**Is anything missing?**
Header capture is limited to a fixed set of common headers. Server responses,
timing, and bodies are not included for synthetic rows (this is a
request-classification corpus; `status` is populated only under live capture).

**Does it contain confidential data or PII?**
No. All benign traffic is synthetic. Names, emails, addresses, tokens, and
sessions are randomly generated and reference no real person. Passwords are
random strings. No production traffic is included.

**Are there redundant instances?**
No. Exact-payload duplicates are removed at build time; the gate asserts zero.

---

## Collection

**How was the data acquired?**
Two interchangeable modes, both fully scripted in `src/build.py`:

1. **Offline synthesis (default, shipped).** Requests are generated directly
   from the endpoint configuration. Reproducible from `seed=42` with no network
   access. This is how the released CSV was produced.
2. **Live capture (`--build --capture`).** The same requests are replayed
   against locally running containers of DVWA (`:8080`), Juice Shop (`:3000`),
   and bWAPP (`:8081`). Requests that redirect to a login (302) or return 5xx are
   dropped, so retained traffic is confirmed to reach a live handler.

> **Honesty note.** Live capture validates that each request is *well-formed and
> routable*, not that its distribution matches production traffic. Benign
> traffic is engineered, not observed; the dataset should be read as a
> controlled benchmark, not a traffic sample. This is stated plainly so results
> are not over-interpreted.

**Benign construction.** Three tiers (see README). The `hard_negative` tier is
the core methodological contribution: it populates free-text, name, token, URL,
and code fields with values that are punctuation-dense yet provably
non-injective. In v3 this tier is **groupable and split-disjoint**: a
deterministic grammar (`vocab._build_cores`) enumerates ~2,340 distinct benign
*cores*, each hard-negative row carries exactly one core, and the core id is the
row's split group — so a benign phrase, like an attack payload, never spans
train/test. Every non-carrier field uses an unbounded procedural generator, so
only the (grouped) core can repeat. This closes the v2.1 leak where 67% of
hard-negative test values were seen verbatim in training. The `ambiguous` tier
places literal attack syntax in benign contexts, built compositionally from 34
frames × 39 attack-syntax specimens (1,326 possible combinations, all of which
appear in the shipped corpus — 858 `discussion`, 468 `verbatim` — across all 14
families; v4.4 widened the specimen set from 26 so the verbatim floor is carried
across the taxonomy rather than by one over-represented string). Its `verbatim`
cores (payload with minimal framing) are the *irreducible* payload-only floor — a
request-only detector cannot separate them from a real attack, and a strong char
n-gram false-positives on them as it must (gate: `ambiguous_floor`); its
`discussion` cores are headroom a context-aware model recovers. Cores are grouped
and split-disjoint, so the floor is measured on unseen frames/specimens.

**Attack construction.** Payloads come from a curated fourteen-family seed set
plus a deterministic per-family **grammar** (`payloads._generate`) that
enumerates template slots — comment terminators, sleep durations, target files,
event handlers, JNDI schemes, prototype keys, smuggling headers — in fixed order.
Every generated payload carries a `template` name (e.g. `sqli:union`); the pool
holds 1,943 distinct canonical payloads across 98 templates (no RNG, so the build
is reproducible). Payloads are deduplicated **globally across families** so no
string that is plausible for two families (e.g. `file:///etc/passwd`) can appear
in both train and test. The pool is optionally widened by PayloadsAllTheThings
under `data/patt/`. Each payload is embedded at a *declared injection point* of an
endpoint, alongside otherwise-benign parameters, and delivered via query, body
(form/json/graphql/multipart), or header. A configurable share is rewritten by an
evasion transform, which may be **chained** (e.g. `case_mix+url_double`); the same
encoding markers are seeded into benign traffic so an evasion marker is never a
free label signal (gate: `evasion_artifact`).

**The anti-leak invariants.** `config.validate_config()` enforces four: (1) every
injectable parameter also has a benign generator on the same endpoint (v1's
`comment` carried 2,187 attacks and zero benign requests); (2) every endpoint has
a free-text field to carry a benign core; (3) every family is reachable at ≥6
endpoints, so the URL cannot predict the family (v2.1 path→family NMI was 0.55,
now 0.200); (4) every content type carries both benign and attack traffic, so
`Content-Type` is not a label proxy. Headers are drawn independently of the label
(v2.1 gave attacks richer headers than routine benigns; header→label NMI is now
0.000).

---

## Preprocessing / labelling

- `payload` is produced by URL-decoding path+query+body+headers, collapsing C0
  control characters and whitespace runs to single spaces (keeps the record on
  one CSV-safe line while preserving injected tokens and header names).
- Deduplication is exact-match on `payload`.
- Labels are assigned at generation and are exact by construction (no annotation
  noise): a request is `1` iff a payload was injected at a declared point.
- The `hard_negative` tier passes an **injection guard** (`vocab.is_injective`):
  any generated benign value or core matching real injection syntax is dropped,
  and the gate asserts zero hard negatives slip through.

---

## Splits

Two fixed splits ship, both 70 / 10 / 20, assigned by **group** (not by row) and
**stratified by family/tier**, so the attack ratio matches across splits (spread
0.006) and **every family appears in every split**.

- **`split` — payload-disjoint (primary; report this).** A group is a canonical
  (evasion-stripped) attack payload and all its variants, a hard-negative benign
  core, an ambiguous (frame, specimen) core, or a single routine row. The test
  holds 387 attack payload groups (≥11 per family) and 469 hard-negative cores.
- **`split_struct` — template-disjoint (structural generalisation).** Attacks are
  grouped by `template`, so whole payload *shapes* are held out; 26 of 98 attack
  templates are in the structural test. Benign rows are grouped as in `split`. The
  gap between the two splits measures how much a model relies on the systematicity
  of the grammar.

The gate asserts `split_leak`, `struct_split_leak`, `split_balance`,
`test_groups`, and `benign_split_leak` (all zero spanning). Report on the provided
splits; a random re-split inflates scores via memorisation (quantified in
`data/baselines.json`).

---

## Uses

**Intended.** Training and *comparative* evaluation of request-level injection
detectors (signature, classical ML, deep learning); studying generalisation via
the random / payload-disjoint / structural / leave-one-family-out / evasion
protocols in `src/evaluate.py`; ablations over family, placement, content type,
and evasion using the metadata columns; sequence/behavioural modelling over the
`session` column.

**Not intended.** A drop-in model of any specific production application's
traffic; a source of realistic benign user behaviour; a network/packet-level IDS
dataset (this is application-layer, request-level). **Do not train on metadata
columns** (`family`, `attack_type`, `tier`, `evasion`, `source`, `status`,
`placement`, `content_type`, `session`, `group`, `template`, `split`,
`split_struct`) — they encode or partition the label. Train only on `payload` (or
the raw `path`/`query`/`body`/`headers`).

---

## Limitations

- **Synthetic benign distribution.** Engineered for coverage and difficulty, not
  sampled from production; absolute detection numbers will not transfer directly
  to a live deployment. Cross-dataset transfer (train here → test on CSIC/ECML)
  drops F1 from 93.4 in-corpus to 41–46 cross-corpus — report it, in
  `data/baselines.json`.
- **Prevalence.** The corpus is ~26% attack; production is far lower. Precision is
  prevalence-dependent, so `baselines.py`/`evaluate.py` report precision corrected
  to 0.5% / 1% / 5% attack — the number that decides deployability. Sub-sample the
  benign side for a realistic-prevalence evaluation.
- **Grammar-generated payloads are systematic.** A payload-disjoint test payload
  still shares its *template* with training payloads, so a char n-gram
  generalises well. v3 adds the **structural (template-disjoint) split** and the
  **leave-one-family-out** protocol to measure the harder generalisation the
  payload split hides; report the structural and LOFO numbers alongside the
  headline. Even so, the templates are a finite, hand-written set.
- **Offline release contains no server responses or timing**, so response-based
  detectors are out of scope for synthetic rows; the `status` column is populated
  only under live capture.
- **Family imbalance** (crlf 165 … xss 3,697) mirrors real-world prevalence but
  means small-family metrics have wider CIs; the disjoint test still holds ≥11
  payload groups per family, and `baselines.py` reports group-level bootstrap CIs.
- **Seed payload set is finite**; place PayloadsAllTheThings under `data/patt/`
  and rebuild to widen coverage and the number of held-out test groups. Note the
  released corpus was built *without* it (1,979 payloads); a rebuild with
  `data/patt/` present draws from a larger pool and will not reproduce the
  published CSV byte-for-byte.
- **The skeleton result, and why it is not a shortcut.** A model given only the
  punctuation shape (every alphanumeric run collapsed to `#`) scores
  0.991 here, against 0.906 on CSIC-2010 and 0.910 on
  ECML/PKDD-2007. Alone that reads as a worse shortcut than the corpora this one
  replaces. Two controls, both shipped in `data/separability.json`, say
  otherwise. Within a matched pair -- where both halves carry identical carrier
  text, so only the injected span differs -- the skeleton model scores
  0.996 and puts the attack above its own twin in
  99.4% of 3,227 pairs. Refit template-disjoint, where every
  attack shape at test time is unseen in training, it scores
  0.976 against 0.983 for the full payload on the identical
  split. A model that had memorised this generator's benign mirror motifs
  (`%25`, `/**/`, `[1]`, `1|2`, `--7`) would collapse there; it does not, and
  `skeleton_generalises` now fails the build if that stops being true.

  Injection is a punctuation phenomenon, so a corpus built around injection
  syntax *should* be skeleton-separable. The distinguishing fact is where the
  separability lives: in structure here (skeleton 0.991,
  vocabulary-stripped 0.606), in vocabulary for CSIC-2010
  (skeleton 0.906, vocabulary-stripped 0.966).
- **Table 1 ships two panels, and the second is less flattering.** The pool panel
  deletes one fixed vocabulary -- this corpus's payload pool -- from all three
  corpora, which is exhaustive here and partial elsewhere (44% of our
  characters against 20% and 15%). The symmetric panel derives the
  vocabulary per corpus from its own training attacks, matching deletion
  aggression (23% / 21% / 15%). Under it we retain
  65% of our above-chance separation against ECML/PKDD-2007's
  31% -- we rank behind ECML, and that is reported rather than buried.

  Matched aggression is not matched completeness, and the pairs let us show it:
  with the pool vocabulary deleted a model scores an attack above its own twin
  51% of the time (chance), but with the symmetric vocabulary deleted
  it still manages 80%, so injection residue survives that rule. Part of
  the higher retention under the symmetric panel is incomplete deletion rather
  than non-injection signal. No corpus without pairs can be checked this way,
  which is why both panels ship and neither is called the real one.
- **Single characters carry a residual, measured association.** `%` sits at
  17.5% of benign rows against
  31.2% of attacks (Cramer's V
  0.147). This is deliberately *not* driven to zero: injection genuinely uses
  punctuation and the `routine` tier is deliberately ordinary alphanumeric
  traffic, so an exact match would falsify the benign distribution. What is
  enforced by `src.shortcut_stats` in CI is that no single character yields a
  usable detector (best AUC 0.568, ceiling 0.60) and that every association is
  smaller than in CSIC-2010 (0.300) or ECML/PKDD (0.411). v4.0.0 had this at
  0.318 -- on par with CSIC -- and the claim that no character predicted the
  label was simply wrong until 4.1.0 measured it.
- **Closed in v4.0.0, and now enforced.** An external audit of v3.0.0 found four
  properties the 25-check gate did not test; all four reproduced. They are fixed
  by construction and `python -m src.audit_gaps` is a blocking CI step, so the
  gate is effectively 32 checks (25 validation + 7 construction). What was wrong, and what it is now:
  - **Lexical register leak.** With all punctuation and every payload-pool word
    deleted, v3.0.0's label was recoverable from ordinary vocabulary at AUC
    0.904 (0.990 against the `hard_negative` tier). Attacks were generated
    independently with routine-tier filler while hard negatives carried prose
    cores, so carrier register encoded the tier and the tier encoded the label.
    v4 builds each attack as the counterfactual twin of a benign row; carrier
    AUC is now **0.565**. The residual 0.823 against `hard_negative` alone is
    tier composition, not label signal: only 40% of attacks are twinned with a
    hard negative, so that comparison is largely prose against non-prose. Since
    4.3.0 the check gates the *matched* version instead -- each hard-negative
    attack against its own twin, where both rows carry identical carrier text --
    which is **0.500**. The unmatched figure is still printed beside it.
    Until 4.3.0 the unmatched figure was printed against a 0.75 ceiling it
    exceeded, and nothing failed; an external review rightly called that a check
    reporting its own failure.
  - **`split_struct` imbalance.** `nosqli` and `ssrf` had no structural val or
    test rows and prevalence spread was 0.134. Splits are now decided before
    generation; spread is **0.002** and every family is in structural train,
    val *and* test. v4.4 closed the last of this: `ssrf` held only 2 templates
    and `crlf`/`jndi`/`nosqli` only 3, so those families could not occupy three
    disjoint structural splits, which the `struct_split_balance` audit flagged.
    Templates were added so every family now holds at least 4-5 (98 in the pool,
    up from 84), the audit reports no inventory-limited family, and the
    structural gap widened as the harder split took effect (char n-gram
    TPR@0.1%FPR 87.9 on the payload split, 50.8 structural).
  - **`session` had no sequential signal** (variance 0.989x i.i.d.). Sessions
    are now bursty; the ratio is **2.87**.
  - **Cross-corpus transfer read as graded degradation when it was threshold
    collapse.** `baselines.json` now reports `roc_auc` and `pred_pos_rate`
    alongside F1. Threshold-free, transfer is AUC 0.60 against CSIC-2010 and
    0.76 against ECML/PKDD, with the model firing on 100% of rows at threshold
    0.5. Quote the AUC, not the F1.
  - **Length parity within a pair** (added with the fix, and now checked).
    Appending a payload makes an attack longer than its own twin -- 100% of
    pairs before the fix, with a length-only AUC of 0.611. Length was v1's
    original shortcut, so reintroducing it while closing the register leak would
    trade one artefact for another. The benign twin now receives a benign span
    of equal length in the same slot: 80.3% of pairs match exactly and
    length-only AUC falls to 0.567. The corpus-wide length gap does not reach
    zero (6.2%) and should not: only 16,000 of 45,400 benign rows can be twins,
    so attack rows carry an extra span most benign rows do not. That is a real
    property of injection. What is guaranteed, and enforced by `pair_integrity`,
    is parity *within* a pair.
- **The corpus is harder than v3.0.0, deliberately.** Char n-gram F1 falls 95.6
  -> 92.4 and the structural gap widens from 9.8 to 28.9 points. The word n-gram
  baseline falls from F1 82.1 to 30.3, which is the clearest evidence the
  register shortcut is gone: a word-level model had been reading carrier prose.
- **25 rows contain raw NUL bytes** in `body` and `payload_raw` (20 traversal,
  5 cmdi; 12 train / 10 test / 3 val). This is faithful — null-byte injection
  truncates strings in the C layer beneath PHP and Java, so the byte has to
  survive into the corpus to be worth detecting — but it constrains consumers:
  - **Python 3.10 and earlier cannot read the CSV** (`_csv.Error: line contains
    NUL`). 3.11 lifted the restriction; hence the 3.11 floor.
  - PostgreSQL `COPY`, R's `read.csv`, and some Excel imports also reject NUL.
  - The `payload` column carries no NUL, so payload-only models are unaffected;
    the byte survives in `body` and `payload_raw` only.
  - **The CSV and the Parquet copy disagree on exactly these 25 rows.**
    `write_parquet` re-reads the CSV with `pandas.read_csv`, whose C parser
    silently drops NUL, so `data/webinject2026.parquet` holds the same 61,400
    rows and is identical in all 22 columns *except* `body` and `payload_raw`
    on those rows, where the NUL is missing (50 cells in total). Treat the CSV
    as authoritative; use the Parquet copy if your loader is strict about NUL
    and losing that byte is acceptable for your task.

---

## Maintenance

- **Versioned and reproducible.** `src/config.VERSION`; every build writes
  `data/manifest.json` (seed, counts, leakage checks). Integrity via
  `SHA256SUMS` — verify a download with `shasum -a 256 -c SHA256SUMS` (or
  `python -m src.checksums --check`, which CI runs on every push). The build and
  the `--json` writers regenerate the manifest, so it is not maintained by hand.
- **Regenerate:** `python -m src.build && python -m src.validate`. A change that
  reintroduces any shortcut fails the gate, so the corpus cannot silently
  regress.
- **Provenance of comparison corpora:** `data/csic_parsed.csv` (CSIC-2010) and
  `data/ecml_parsed.csv` (ECML/PKDD-2007) are third-party datasets reparsed to a
  common schema; original terms apply to those files.
