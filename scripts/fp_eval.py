#!/usr/bin/env python3
"""Run the masker over tracked files of git repos and report what it would mask.

Prints counts per kind and sample lines AFTER masking (values never shown), so
an unexpected real secret is reported without being revealed.
    scripts/fp_eval.py <repo> [<repo> ...] [--samples N] [--min-entropy X]
"""
import argparse
import collections
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from blindfold.mask import Masker  # noqa: E402

parser = argparse.ArgumentParser()
parser.add_argument("repos", nargs="+")
parser.add_argument("--samples", type=int, default=4)
parser.add_argument("--min-entropy", type=float, default=4.2)
args = parser.parse_args()
masker = Masker(key=b"eval" * 8, min_entropy=args.min_entropy)
by_kind = collections.Counter()
files_by_kind = collections.defaultdict(set)
samples = collections.defaultdict(list)
scanned = 0
for repo in args.repos:
    files = subprocess.run(["git", "-C", repo, "ls-files"], capture_output=True, text=True).stdout.splitlines()
    for rel in files:
        if os.path.basename(rel).startswith(".env"):
            continue
        path = os.path.join(repo, rel)
        try:
            if os.path.getsize(path) > 2_000_000:
                continue
            with open(path, encoding="utf-8") as handle:
                text = handle.read()
        except (OSError, UnicodeDecodeError):
            continue
        scanned += 1
        for line in text.splitlines():
            masked, findings = masker.mask(line)
            for f in findings:
                by_kind[f.kind] += 1
                files_by_kind[f.kind].add(f"{os.path.basename(repo)}/{rel}")
                if len(samples[f.kind]) < args.samples:
                    samples[f.kind].append(f"{os.path.basename(repo)}/{rel}: {masked.strip()[:150]}")
print(f"scanned {scanned} files")
for kind, n in by_kind.most_common():
    print(f"\n{kind}: {n} hits in {len(files_by_kind[kind])} files")
    for s in samples[kind]:
        print(f"   {s}")
