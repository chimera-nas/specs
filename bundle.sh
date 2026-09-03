#!/bin/bash
# SPDX-FileCopyrightText: 2026 The Quint Specs Authors
# SPDX-License-Identifier: MIT
#
# Tar the generated trace tree + a manifest into the bundle a consuming project
# fetches, either by this repo's git hash or by a release version.
#
# Usage: bundle.sh <trace-dir> <out-dir>
set -euo pipefail
TRACE_DIR=$1
OUT_DIR=$2
QUINT_VERSION=${QUINT_VERSION:-unknown}

# Identity of the source these traces were generated from.
#
# A consumer pins this repo as a submodule and fetches the bundle for it.  The
# coordinate it fetches BY -- a commit hash or a release version -- says which
# bundle to get; source_sha says whether that bundle is actually the right one.
# The two can disagree: a release version names the last tagged commit, so a
# consumer pinned to a later commit could look up a version that resolves to an
# older corpus.  Recording the sha lets the consumer refuse it and regenerate
# locally instead of replaying traces against models they were not built from.
#
# From the environment when CI knows it (it does -- github.sha).  The git
# fallback carries safe.directory because bundling runs inside a container whose
# root does not own the bind-mounted checkout, and git otherwise refuses the
# repository for dubious ownership.
SPECS_SOURCE_SHA=${SPECS_SOURCE_SHA:-$(git -c safe.directory='*' rev-parse HEAD 2>/dev/null || echo unknown)}
# Declared release version.  Between releases this carries a -dev suffix, which
# never has a published bundle -- so a consumer that matches on version alone
# still cannot resolve a mid-release commit to a stale corpus.
SPECS_VERSION=${SPECS_VERSION:-$(tr -d '[:space:]' < "$(dirname "$0")/VERSION" 2>/dev/null || echo unknown)}

# manifest.json (inside the bundle): provenance + quint version + per-suite
# trace counts.
{
    printf '{\n  "source_sha": "%s",\n  "version": "%s",\n  "quint_version": "%s",\n  "suites": {\n' \
           "$SPECS_SOURCE_SHA" "$SPECS_VERSION" "$QUINT_VERSION"
    first=1
    for d in "$TRACE_DIR"/*/; do
        [ -d "$d" ] || continue
        name=$(basename "$d")
        n=$(find "$d" -name '*.itf.json' | wc -l | tr -d ' ')
        [ $first -eq 1 ] || printf ',\n'
        first=0
        printf '    "%s": %s' "$name" "$n"
    done
    printf '\n  }\n}\n'
} > "$TRACE_DIR/manifest.json"

tar czf "$OUT_DIR/specs-traces.tar.gz" -C "$TRACE_DIR" .
total=$(find "$TRACE_DIR" -name '*.itf.json' | wc -l | tr -d ' ')
echo "bundle: $OUT_DIR/specs-traces.tar.gz  ($total traces, $(du -h "$OUT_DIR/specs-traces.tar.gz" | cut -f1))"
