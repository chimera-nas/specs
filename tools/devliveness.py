#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 The Quint Specs Authors
#
# SPDX-License-Identifier: MIT

"""Fail when a cell enables a deviation its corpus never exercises.

A deviation is a claim: "this implementation gets X wrong, here, on purpose,
for now."  The claim decays.  Someone fixes X, the model's deviating branch
stops being taken, and the entry sits on in the config -- still forgiving the
same divergence anywhere else it appears, in every other cell that copied the
config.  That is the failure mode this repo has hit before: a fixed-but-kept
entry is not neutral, it is a blindfold.

The model now records what it actually did.  Every step whose expectation was
shaped by a deviation carries that deviation's id, so a corpus is a record of
which claims are still live.  This compares the ids a cell's config ENABLES
against the ids its corpus EXERCISES:

  * enabled and exercised   -- the claim still stands.
  * enabled, never exercised -- either the deviation is dead (fix it in the
    config, delete the branch) or the corpus stopped reaching it (a generator
    change quietly lost coverage).  Both need a human; both fail here.
  * exercised but not enabled -- impossible by construction (the model gates on
    the config), so it means the config and the corpus disagree about what was
    generated: a stale corpus.  Also fails.

Usage: devliveness.py <config.json> <corpus-dir>
"""

import json
import os
import re
import sys


def load_config(path):
    """Resolve `extends` the same way mkconfig.js does.

    HAZARDS are gated exactly as DEVS are, and for the same reason.  A hazard
    changes what the corpus CONTAINS rather than what it predicts -- it is the
    knob for a pattern the server cannot survive -- which makes an unexercised
    one worse than an unexercised deviation, not better: it would go on
    narrowing every corpus this cell generates, for a crash nobody has seen
    since.  So a dead hazard fails the build like a dead deviation, and both
    live in the same set here.
    """
    with open(path) as fh:
        text = re.sub(r"^\s*//.*$", "", fh.read(), flags=re.M)
    cfg = json.loads(text)
    enabled = set()
    if cfg.get("extends"):
        parent = os.path.join(os.path.dirname(os.path.abspath(path)),
                              cfg["extends"])
        enabled |= load_config(parent)
    enabled |= set(cfg.get("deviations", []))
    enabled |= set(cfg.get("hazards", []))
    enabled -= set(cfg.get("deviationsOff", []))
    enabled -= set(cfg.get("hazardsOff", []))
    return enabled


def exercised(corpus_dir):
    """Every deviation id any trace in the corpus records having taken."""
    hits = set()
    ntraces = 0
    for dirpath, _, files in os.walk(corpus_dir):
        for f in files:
            if not f.endswith(".itf.json"):
                continue
            ntraces += 1
            with open(os.path.join(dirpath, f)) as fh:
                doc = json.load(fh)
            for state in doc.get("states", []):
                for key, val in state.items():
                    # `devHits` is namespaced <instance>::<model>::devHits.
                    if key.rsplit("::", 1)[-1] != "devHits":
                        continue
                    # ITF renders a set as {"#set": [...]}.
                    items = val.get("#set", val) if isinstance(val, dict) else val
                    if isinstance(items, list):
                        hits.update(i for i in items if isinstance(i, str))
    return hits, ntraces


def main():
    if len(sys.argv) != 3:
        sys.stderr.write(__doc__)
        return 2
    cfg_path, corpus = sys.argv[1], sys.argv[2]

    enabled = load_config(cfg_path)
    hits, ntraces = exercised(corpus)

    if ntraces == 0:
        sys.stderr.write(f"devliveness: no traces under {corpus}\n")
        return 2

    dead = sorted(enabled - hits)
    unexpected = sorted(hits - enabled)

    print(f"devliveness: {os.path.basename(cfg_path)}: {ntraces} trace(s), "
          f"{len(enabled)} deviation(s) enabled, {len(hits)} exercised")
    for d in sorted(enabled & hits):
        print(f"  live     {d}")

    rc = 0
    for d in dead:
        print(f"  DEAD     {d}  -- enabled but never exercised")
        rc = 1
    for d in unexpected:
        print(f"  STRAY    {d}  -- exercised but not enabled by this config")
        rc = 1

    if rc:
        print("\nA deviation that is never exercised is either fixed -- retire it "
              "from the config and delete its branch in the model -- or no longer "
              "reachable, which means the corpus quietly lost the coverage that "
              "used to find it. Either way it stops being a claim anyone can "
              "trust, so it fails here rather than sitting on as a blindfold.")
    return rc


if __name__ == "__main__":
    sys.exit(main())
