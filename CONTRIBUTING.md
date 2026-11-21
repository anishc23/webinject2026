# Contributing

This is a research artefact attached to a published paper, which shapes what
can and cannot be accepted. Issues and discussion are welcome; the constraints
below are about reproducibility, not gatekeeping.

## The corpus is frozen

`data/webinject2026.csv` and its Parquet copy are pinned by `SHA256SUMS`, cited
by the paper and archived under a DOI. A pull request that regenerates or edits
the corpus cannot be merged, because results already published against it would
silently stop reproducing.

If you believe a row is mislabelled or a family is misconstructed, open an issue
with the `pair_id` and what you think is wrong. That is the useful contribution,
and defects found this way are recorded in [CHANGELOG.md](CHANGELOG.md) — the
project has published several of its own.

## What is welcome

- **Defects in the audit gate.** A shortcut the 32 checks miss is the most
  valuable thing you can report. Include the measurement.
- **Results that do not reproduce** from the shipped seeds and result JSONs.
  Include your Python version and `pip freeze`.
- **New detectors for the model zoo**, provided they run under the existing
  splits and report the same two ablations every other row reports:
  carrier-only AUC and paired accuracy.
- **Documentation fixes**, including in the paper's description of the corpus.

## What will not be merged

- Changes to the corpus data, its splits, or `SHA256SUMS`.
- Hand-edited figures or result files. Everything under `data/*.json` and
  `figures/` regenerates from the pipeline; if a number changes, it changes
  because the code that produced it changed.
- Numbers typed into prose. The paper's figures come from generated macros for
  the same reason.

## Running the checks

```bash
pip install -r requirements.txt
python -m src.checksums --check   # the shipped data is unmodified
python -m src.validate            # the 25 corpus-validation checks
python -m src.audit_gaps          # the 7 construction-integrity checks
pytest -q                         # unit tests
```

CI runs all of these on every push and pull request against two Python
versions, and a red gate blocks the merge; that is the point of it. The full
workflow is [.github/workflows/ci.yml](.github/workflows/ci.yml).

## Reporting a security issue

See [SECURITY.md](SECURITY.md), which separates a scientific defect in the
corpus (public issue) from a security problem in this repository (email).
