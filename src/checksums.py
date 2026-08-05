"""Integrity manifest for the released artefacts.

`SHA256SUMS` is what a reviewer runs to confirm the files they downloaded are
the files that were published. It was hand-maintained through v3.0.0 and drifted:
the release shipped five stale hashes, because the eight tracked files are
written by three different entry points at three different times, and nothing
recomputed the manifest afterwards.

So the producers now own it. `src.build`, `src.baselines` and `src.evaluate`
each call `refresh()` after writing a tracked file, and CI runs `--check`
against a fresh checkout, which fails if a commit and its manifest disagree.

  python -m src.checksums           rewrite SHA256SUMS from what is on disk
  python -m src.checksums --check   verify on-disk files against SHA256SUMS
"""

import argparse
import hashlib
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SUMS = os.path.join(ROOT, "SHA256SUMS")

# Repo-relative, in release order: the corpus first, then its provenance and
# reference metrics, then the third-party comparison corpora.
FILES = [
    "data/webinject2026.csv",
    "data/webinject2026.parquet",
    "data/manifest.json",
    "data/baselines.json",
    "data/evaluation.json",
    "data/shortcut_stats.json",
    "corpus/payloads.json",
    "data/csic_parsed.csv",
    "data/ecml_parsed.csv",
]


def sha256(path):
    """Hash a file in chunks — the corpus CSV is ~80 MB."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def write(root=ROOT):
    """Rewrite SHA256SUMS from the files currently on disk.

    A missing file is skipped rather than fatal: `--no-parquet` builds and
    partial working copies are legitimate, and `--check` is what enforces
    completeness at release time.
    """
    lines, missing = [], []
    for rel in FILES:
        path = os.path.join(root, rel)
        if os.path.exists(path):
            lines.append(f"{sha256(path)}  {rel}\n")
        else:
            missing.append(rel)
    with open(os.path.join(root, "SHA256SUMS"), "w", encoding="utf-8") as f:
        f.writelines(lines)
    return lines, missing


def refresh(written_path, root=ROOT):
    """Rewrite the manifest if `written_path` is one of the tracked files.

    Called by the producers. The guard keeps `--json /tmp/scratch.json` from
    touching the released manifest as a side effect.
    """
    try:
        rel = os.path.relpath(os.path.abspath(written_path), root)
    except ValueError:          # different drive on Windows
        return False
    if rel.replace(os.sep, "/") not in FILES:
        return False
    write(root)
    return True


def check(root=ROOT):
    """Compare on-disk files against SHA256SUMS. Returns (ok, results)."""
    sums_path = os.path.join(root, "SHA256SUMS")
    if not os.path.exists(sums_path):
        return False, [("SHA256SUMS", "MISSING MANIFEST")]

    expected = {}
    with open(sums_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            digest, _, rel = line.partition("  ")
            if rel:
                expected[rel.strip()] = digest.strip()

    results, ok = [], True
    for rel in FILES:
        path = os.path.join(root, rel)
        if rel not in expected:
            results.append((rel, "NOT LISTED"))
            ok = False
        elif not os.path.exists(path):
            results.append((rel, "MISSING FILE"))
            ok = False
        elif sha256(path) != expected[rel]:
            results.append((rel, "FAILED"))
            ok = False
        else:
            results.append((rel, "OK"))
    for rel in expected:
        if rel not in FILES:
            results.append((rel, "UNTRACKED ENTRY"))
            ok = False
    return ok, results


def main():
    ap = argparse.ArgumentParser(description="Write or verify SHA256SUMS.")
    ap.add_argument("--check", action="store_true",
                    help="verify instead of rewriting; exits 1 on any mismatch")
    args = ap.parse_args()

    if args.check:
        ok, results = check()
        width = max(len(r) for r, _ in results)
        for rel, status in results:
            print(f"  {status:<16} {rel:<{width}}")
        print("RESULT:", "ALL FILES MATCH" if ok else "MANIFEST OUT OF DATE")
        if not ok:
            print("  regenerate with: python -m src.checksums")
        sys.exit(0 if ok else 1)

    lines, missing = write()
    for line in lines:
        print("  " + line.rstrip())
    for rel in missing:
        print(f"  skipped (not on disk): {rel}")
    print(f"wrote {SUMS} ({len(lines)} files)")


if __name__ == "__main__":
    main()
