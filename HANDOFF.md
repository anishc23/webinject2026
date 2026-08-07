# Handoff — remaining work on WebInject2026

Paste everything below the line into Claude Code, from a clone of
`git@github.com:anishc23/webinject2026.git` at `main`.

---

You are working on WebInject2026, a leakage-audited corpus for web-injection
detection, targeted at ICISSP 2027. The repository is private, has a single
branch `main`, and CI must stay green on Python 3.11 and 3.12.

Read `README.md`, `CHANGELOG.md` (top entry first) and `DATASHEET.md` before
changing anything. The project's whole thesis is that reported detection
performance is largely a dataset artefact, so **every claim in this repository
must be a measurement, not an assertion**. If you cannot measure it, say so
rather than asserting it.

## Ground rules

1. **Never trust a result file that was not regenerated after the last corpus
   build.** This has now bitten the project three times. `src.baselines` is
   deterministic — two runs on the same corpus are byte-identical — so if a
   committed JSON disagrees with a fresh run, the JSON is stale, not noisy.
   After any rebuild, regenerate in this order and then run the checks:
   ```
   python -m src.build
   python -m src.baselines      --json data/baselines.json
   python -m src.evaluate       --json data/evaluation.json
   python -m src.shortcut_stats --json data/shortcut_stats.json
   python -m src.separability
   python -m src.syntax_ablation --json data/syntax_ablation.json
   python -m src.figures
   python -m src.checksums
   ```
2. **The gate is the safety net; keep it green.** `python -m src.validate`
   (25 checks), `python -m src.audit_gaps` (5 construction checks) and
   `python -m src.shortcut_stats` are all blocking in CI, plus `pytest -q`.
3. **A clean checkout must rebuild `data/webinject2026.csv` byte-identically.**
   If you have a local PayloadsAllTheThings checkout at `data/patt/`, move it
   aside before rebuilding — it is folded into the payload pool and will change
   the corpus. `src.build` warns when it applies.
4. **Do not commit large local files.** `Archive.zip` and `data/patt/` are
   gitignored. `git add -A` has already swept a 322 MB archive into a commit
   once; stage explicitly if you are unsure.
5. Report honestly. If a number gets worse, say so and explain why — the
   v1→v2.1→v3→v4 history of measured regressions is the strongest part of the
   methodology section.

## Task 1 — Regenerate the model zoo on the current corpus (you have the GPU)

`data/model_zoo.json` and `data/model_zoo_capped.json` were computed on the
v4.2.0 corpus. The corpus has since been rebuilt twice. Both files are stale and
must be regenerated against the shipped corpus.

**Run each tier as a separate process.** XGBoost's OpenMP pool and torch's MPS
backend deadlock in one interpreter; on CUDA this is less likely but keep them
separate anyway so a failure in one tier does not lose the others.

```
python -m src.model_zoo --tier classical --json data/model_zoo.json
python -m src.model_zoo --tier deep      --json data/model_zoo.json

python -m src.model_zoo --tier classical   --train-cap 8000 --protocols payload-disjoint,structural --json data/model_zoo_capped.json
python -m src.model_zoo --tier deep        --train-cap 8000 --protocols payload-disjoint,structural --json data/model_zoo_capped.json
python -m src.model_zoo --tier transformer --train-cap 8000 --protocols payload-disjoint,structural --json data/model_zoo_capped.json
```

Two things to fix while you are there, both of which need your hardware:

- **DeBERTa-v3 has never run.** It diverges to NaN in fp32 on Apple's Metal
  backend, with and without gradient clipping at lr 1e-5, and CPU managed fewer
  than five optimiser steps in ten minutes. On CUDA it should simply work — the
  harness selects CUDA automatically. This completes the ten-model table. If it
  still produces NaN, try fp32 with `TF32` disabled before giving up, and record
  the outcome in `data/model_zoo_capped.json` rather than dropping the model.
- **The `--train-cap 8000` subsample exists only because Apple MPS needed ~44
  min/epoch** for DistilBERT on the full 43k training rows (measured: 1.95
  s/step at batch 32, seq len 128). On a real GPU, run the transformers on the
  **full** training set and drop the cap. Then either re-run the classical and
  deep tiers uncapped too, so the comparison stays like-for-like, or keep both
  tables and label them clearly. Do not compare a full-data transformer against
  a capped classical model without saying so.

Afterwards, update the model-zoo table in `README.md`, the entry in
`CHANGELOG.md`, and regenerate checksums.

## Task 2 — Replace the explainer PDF

`Understanding_WebInject2026.pdf` was deleted because it documented v3.0.0
numbers and a 25-check gate, and was four versions stale. A replacement is
needed, built so it cannot go stale again.

Requirements:

- **Generate it from the shipped JSONs at build time**, the way `src/figures.py`
  does. Add `docs/build_explainer.py` that reads `data/manifest.json`,
  `data/baselines.json`, `data/evaluation.json`, `data/shortcut_stats.json`,
  `data/separability.json`, `data/syntax_ablation.json` and
  `data/model_zoo_capped.json`, and writes the PDF. No number typed by hand.
  `reportlab` is already an optional dependency and works well for this; render
  with A4, a serif or Helvetica body, and tables rather than prose for numbers.
- Written for a reader with basic computing knowledge and no security or ML
  background — the previous document used three layers per idea (everyday
  intuition, then mechanism, then detail) and that worked; keep that shape.
- It must cover, at minimum: what injection is; why existing corpora are
  inadequate; what leakage/shortcut learning is and why it is the paper's
  central claim; how the corpus is constructed (three benign tiers,
  counterfactual pairing, pre-assigned splits); what each of the 30 checks
  enforces, grouped; every headline result including Table 1, the model zoo, the
  honesty ladder, prevalence correction, calibration, error analysis and span
  attribution; the limitations, stated plainly; and a Q&A section for the
  conference.
- Verify the output before committing: render pages to images and actually look
  at them. ReportLab's built-in fonts are WinAnsi, so arrows, `>=`, `<=` and
  check marks render as black boxes — use ASCII equivalents. Check that no page
  is an orphaned near-empty page.

## Task 3 — Strengthen the structural protocol

`src.audit_gaps` reports `ssrf` as inventory-limited: it holds only 2 payload
templates, so it cannot occupy three disjoint structural splits. `crlf`, `jndi`
and `nosqli` have only 3 each. This weakens `split_struct`, which is where the
paper's most interesting generalisation number comes from.

Add templates for those four families in `src/payloads.py`, following the
existing per-family grammar style, so every family has at least 4-5 templates.
Then rebuild, regenerate everything, and confirm `struct_split_balance` reports
no inventory-limited families. Expect the structural numbers to move; that is
fine, report the delta.

## Task 4 — Pre-submission metadata

- `CITATION.cff` has a `TODO`: the second author's family name is a placeholder
  (git records only the handle `AbhiShrek07`), and neither author has an
  affiliation or ORCID. Fill these in.
- ICISSP artifact evaluation will want a public repository and ideally a Zenodo
  DOI so the citation points at something immutable. The repository is currently
  private by the owner's decision — do not change its visibility. Raise it with
  him and, once public, mint the DOI and add it to `CITATION.cff` and `README.md`.
- Confirm the ICISSP 2027 dates and deadlines against the official site. The
  figures circulating in our notes (22-24 February 2027, Valletta; regular-paper
  deadline 15 September 2026) have not been verified from source.

## What is already done — do not redo it

- Counterfactual pairing: every attack is the twin of a benign row, sharing a
  `pair_id`, matched on length and on carrier vocabulary.
- Splits decided before generation, so no group, template or benign core spans a
  split; 16,000 complete pairs, none split across train/val/test.
- Per-character shortcut statistics against CSIC-2010 and ECML/PKDD-2007.
- `benign_category` (review/search/code/qa/encoded/log/markup) shipped on both
  halves of every pair.
- Calibration, error analysis by benign register, and span attribution.
- Table 1 (`src.syntax_ablation`) and `src.separability`.
- Nine of ten models in the zoo, with per-model carrier-only and paired ablations.

## Sanity check before you push anything

```
python -m src.checksums --check && \
python -m src.validate && \
python -m src.audit_gaps && \
python -m src.shortcut_stats && \
pytest -q
```

Then confirm CI is green on both Python versions before telling anyone it is
done — CI was red for a day because a stale manifest failed the first step and
silently skipped every check after it.
