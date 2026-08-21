#!/bin/bash
# SPDX-FileCopyrightText: 2026 Chimera-NAS Project Contributors
# SPDX-License-Identifier: LGPL-2.1-only
#
# Tar the generated trace tree + a manifest into the bundle the chimera build
# consumes (fetched by the specs submodule's git hash).
#
# Usage: bundle.sh <trace-dir> <out-dir>
set -euo pipefail
TRACE_DIR=$1
OUT_DIR=$2
QUINT_VERSION=${QUINT_VERSION:-unknown}

# manifest.json (inside the bundle): quint version + per-suite trace counts.
{
    printf '{\n  "quint_version": "%s",\n  "suites": {\n' "$QUINT_VERSION"
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
