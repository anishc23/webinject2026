# Datasheet — WebInject2026 v3.0.0

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
One HTTP request. 61,400 instances: 45,400 benign, 16,000 attack.

**Schema (22 columns).**

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
| `group` | Split group; `split` never shares one. Attack = canonical-payload hash; ambiguous = `ambigD`/`ambigV` (frame × specimen) core; hard_negative = `benH` core; routine = per-row |

**Class / family distribution.**

- Benign 45,400 = routine 26,000 + hard_negative 17,000 + ambiguous 2,400
  (verbatim 827 + discussion 1,573, in 823 cores). Hard negatives draw from
  2,340 groupable, split-disjoint cores.
- Attack 16,000 across: xss 3,601 · sqli 3,571 · ssti 1,527 · nosqli 1,264 ·
  jndi 981 · traversal 917 · ssrf 811 · deser 781 · cmdi 734 · protopollute 675 ·
  ldapi 478 · xxe 251 · smuggle 245 · crlf 164.
- Distinct attack payloads: 1,961 groups (393 held out in the test split, ≥11
  per family), across 84 templates (26 held out in the structural test).
  Placement: query 8,673 · body 6,840 · header 487. Content type: query 31,644 ·
  json 15,607 · form 7,107 · multipart 5,234 · graphql 1,808. Evasion applied to
  5,538 (835 chained). ~8,200 sessions.

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
frames × 26 attack-syntax specimens (884 possible combinations, of which **823
distinct cores** appear in the shipped corpus — 528 `discussion`, 295
`verbatim` — across all 14 families). Its `verbatim`
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
holds 1,961 distinct canonical payloads across 84 templates (no RNG, so the build
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
now 0.197); (4) every content type carries both benign and attack traffic, so
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
0.001) and **every family appears in every split**.

- **`split` — payload-disjoint (primary; report this).** A group is a canonical
  (evasion-stripped) attack payload and all its variants, a hard-negative benign
  core, an ambiguous (frame, specimen) core, or a single routine row. The test
  holds 393 attack payload groups (≥11 per family) and 471 hard-negative cores.
- **`split_struct` — template-disjoint (structural generalisation).** Attacks are
  grouped by `template`, so whole payload *shapes* are held out; 26 of 84 attack
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
  drops F1 from ~96 in-corpus to ~41–46 cross-corpus — report it, in
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
- **Family imbalance** (crlf 164 … xss 3,601) mirrors real-world prevalence but
  means small-family metrics have wider CIs; the disjoint test still holds ≥11
  payload groups per family, and `baselines.py` reports group-level bootstrap CIs.
- **Seed payload set is finite**; place PayloadsAllTheThings under `data/patt/`
  and rebuild to widen coverage and the number of held-out test groups. Note the
  released corpus was built *without* it (1,979 payloads); a rebuild with
  `data/patt/` present draws from a larger pool and will not reproduce the
  published CSV byte-for-byte.
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
