# Security and responsible use

WebInject2026 ships synthetic attack payloads. This file says what that does
and does not amount to, and how to report a problem.

## What is in the corpus

Every attack row carries an injection payload built from public, long-documented
attack patterns — the same material found in OWASP documentation, in
PayloadsAllTheThings, and in the teaching applications the corpus models (DVWA,
OWASP Juice Shop, bWAPP). Nothing here is a novel technique, a working exploit
chain, or a zero-day.

The payloads are **not execution-validated**. They were synthesised against
endpoint inventories rather than fired at running instances, so a positive label
means "an injection payload occupies this slot", not "this request exploits this
endpoint". That distinction is deliberate and is discussed in the paper's
limitations.

All benign traffic is synthetic. The corpus contains no production traffic, no
real users, no credentials and no personal data.

## Intended use

Training and evaluating web-attack detectors, and auditing whether a detection
benchmark measures the attack or an artefact of how it was assembled. The
corpus exists to make that second question answerable.

Do not point this material at systems you do not own or have written permission
to test. The payloads confer no capability beyond a published payload list, but
sending them at third-party infrastructure is still unauthorised access in most
jurisdictions.

## Reporting a problem

Two different things, two different routes.

**A defect in the corpus or the pipeline** — a mislabelled row, a leak the
32-check gate failed to catch, a result that does not reproduce from the shipped
seeds: please open a public issue. These are scientific defects and are better
discussed in the open. The project has a history of finding and publishing its
own, recorded in [CHANGELOG.md](CHANGELOG.md).

**A security issue in this repository itself** — for instance something in
`src/` that is unsafe to run, or a file that should not have been published:
email anishc2301@gmail.com rather than opening an issue, and allow a reasonable
window for a fix before disclosing.

## Scope

This repository is a research artefact, not deployed software. It serves no
network traffic, runs no service and stores no user data. There is no supported
release line and no security backport policy: fixes land on `main`, and archived
versions stay as published so that results citing them remain reproducible.
