#!/bin/bash
# SPDX-FileCopyrightText: 2026 The Quint Specs Authors
#
# SPDX-License-Identifier: MIT

# Replay a batch of S3 model traces against a private MinIO server.
#
# Usage: run_minio_mbt.sh <trace-dir> [trace-glob]
#
#   <trace-dir>   a CELL's trace directory (build/specs-corpus/minio/s3/<cell>).
#                 One config is one cell is one ctest, and the cell replays ALL
#                 of its directory.
#   [trace-glob]  shell glob narrowing the run (default: *.itf.json).  For
#                 driving one trace by hand; CMake never passes it.
#
# A FRESH MinIO PER TRACE, on an empty data directory.  The model's bucket
# names are fixed (bk0, bk1), so anything one trace left behind -- an object,
# a bucket tag set, an in-flight multipart upload -- would be the next trace's
# initial state, and a cleanup pass that removed it would be code that could
# itself hide a leak.  An empty directory cannot.  MinIO is listening about a
# third of a second after exec, so the cost is noise.
#
# No network namespace and no root: MinIO needs no privileged port, so every
# instance takes a free loopback port of its own and the cells run concurrently
# under `ctest -j` with nothing to serialize.
#
# The instance is disposable and self-contained: single node, single drive,
# data, certs and HOME all inside a session directory, console and update check
# off, so it neither reads nor writes anything outside it and never calls home.
#
# Environment:
#   MINIO                    path to the minio server binary (default: PATH)
#   SPECS_S3_BLOCK_SIZE      bytes per model block (default 8192).  A multipart
#                            cell is replayed at 5242880, the minimum part size.
#   SPECS_MINIO_TIMEOUT      wall-clock cap for one trace's replay (default 600s)
#   SPECS_MINIO_KEEP=1       keep the session dir on exit (debugging)
#   SPECS_MINIO_SURVEY=1     pass --keep-going to the replayer: report every
#                            diverging step of a trace rather than stopping at
#                            the first
#   SPECS_MINIO_EXEC=<cmd>   run <cmd> against one live instance instead of the
#                            replayer, with SPECS_S3_{HOST,PORT,ACCESS_KEY,
#                            SECRET_KEY} exported.  For hand-probing a
#                            divergence.

set -u

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

TRACE_DIR=${1:?usage: run_minio_mbt.sh <trace-dir> [trace-glob]}
TRACE_GLOB=${2:-*.itf.json}

MINIO=${MINIO:-$(command -v minio 2>/dev/null || true)}
if [ -z "$MINIO" ] || [ ! -x "$MINIO" ]; then
    echo "minio not found (build it from chimera-nas/minio, or set MINIO)" >&2
    exit 77
fi

BLOCK_SIZE=${SPECS_S3_BLOCK_SIZE:-8192}
TIMEOUT=${SPECS_MINIO_TIMEOUT:-600}

# The root credential of this instance and of nothing else.  The model has no
# identity axis -- every request it describes is correctly signed by the owner
# -- so the one account MinIO is born with is the whole of it.
ACCESS_KEY=specsmodel
SECRET_KEY=Model01ReplayKey

SESSION_DIR=$(mktemp -d "${TMPDIR:-/tmp}/specs_minio_XXXXXX")
MINIO_PID=""
PORT=""

stop_minio() {
    if [ -n "$MINIO_PID" ]; then
        kill -TERM "$MINIO_PID" 2>/dev/null || true
        for _ in $(seq 1 50); do
            kill -0 "$MINIO_PID" 2>/dev/null || break
            sleep 0.1
        done
        kill -KILL "$MINIO_PID" 2>/dev/null || true
        wait "$MINIO_PID" 2>/dev/null || true
        MINIO_PID=""
    fi
}

cleanup() {
    stop_minio
    if [ "${SPECS_MINIO_KEEP:-0}" = "1" ]; then
        echo "session kept at ${SESSION_DIR}"
    else
        rm -rf "$SESSION_DIR"
    fi
}
# EXIT alone is not enough: ctest sends SIGTERM on timeout, and bash does not
# run an EXIT trap for an untrapped fatal signal -- which would leave a live
# server behind for every timed-out test.
trap cleanup EXIT
trap 'exit 143' INT TERM

# Start a MinIO on an empty data directory named for <tag> and wait until it
# answers.  The port is chosen by binding port 0 and releasing it, so another
# process can take it in between; that is what the retry is for.
start_minio() {
    local tag=$1 data="${SESSION_DIR}/data_$1" out="${SESSION_DIR}/minio_$1.out"
    local try
    for try in 1 2 3 4 5; do
        PORT=$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
        rm -rf "$data"
        mkdir -p "$data"
        # MINIO_CI_CD lets it use a directory on the root filesystem as its
        # drive, which a production MinIO refuses.
        HOME="$SESSION_DIR" \
        MINIO_ROOT_USER="$ACCESS_KEY" MINIO_ROOT_PASSWORD="$SECRET_KEY" \
        MINIO_BROWSER=off MINIO_UPDATE=off MINIO_CI_CD=1 \
            "$MINIO" server --quiet --address "127.0.0.1:${PORT}" \
                --certs-dir "${SESSION_DIR}/certs" "$data" > "$out" 2>&1 &
        MINIO_PID=$!
        for _ in $(seq 1 300); do
            if bash -c "echo > /dev/tcp/127.0.0.1/${PORT}" 2>/dev/null; then
                MINIO_OUT=$out
                return 0
            fi
            kill -0 "$MINIO_PID" 2>/dev/null || break
            sleep 0.05
        done
        stop_minio
        grep -q "address already in use" "$out" 2>/dev/null && continue
        break
    done
    echo "minio did not come up on 127.0.0.1:${PORT}"
    cat "$out"
    return 1
}

echo "=== $("$MINIO" --version 2>/dev/null | head -1) | traces ${TRACE_GLOB} | block ${BLOCK_SIZE} ==="

if [ -n "${SPECS_MINIO_EXEC:-}" ]; then
    start_minio exec || exit 1
    SPECS_S3_HOST=127.0.0.1 SPECS_S3_PORT=$PORT \
    SPECS_S3_ACCESS_KEY=$ACCESS_KEY SPECS_S3_SECRET_KEY=$SECRET_KEY \
        timeout "$TIMEOUT" bash -c "$SPECS_MINIO_EXEC"
    exit $?
fi

# shellcheck disable=SC2086  # TRACE_GLOB is a glob and must stay unquoted
TRACES=( $(compgen -G "${TRACE_DIR}/${TRACE_GLOB}" || true) )
if [ ${#TRACES[@]} -eq 0 ]; then
    echo "no traces matched ${TRACE_DIR}/${TRACE_GLOB}" >&2
    exit 77
fi

ARGS=()
[ "${SPECS_MINIO_SURVEY:-0}" = "1" ] && ARGS+=(--keep-going)

FAILED=0
N=0
for t in "${TRACES[@]}"; do
    N=$((N + 1))
    start_minio "$N" || exit 1

    timeout "$TIMEOUT" python3 "${HERE}/s3_replay.py" \
        --host 127.0.0.1 --port "$PORT" \
        --access-key "$ACCESS_KEY" --secret-key "$SECRET_KEY" \
        --block-size "$BLOCK_SIZE" "${ARGS[@]}" --trace "$t"
    RC=$?

    # 2 is a trace the replayer could not read: a harness or corpus fault, not
    # a divergence, and no later trace will fare better.
    if [ "$RC" = "2" ]; then
        exit 2
    fi
    if ! kill -0 "$MINIO_PID" 2>/dev/null; then
        echo "=== minio exited during ${t} ==="
        tail -60 "$MINIO_OUT" 2>/dev/null || true
        MINIO_PID=""
        [ "$RC" = "0" ] && RC=70
    fi
    if [ "$RC" != "0" ]; then
        FAILED=$((FAILED + 1))
        if [ "$RC" = "124" ]; then
            echo "=== replay of ${t} timed out after ${TIMEOUT}s ==="
        fi
    fi
    stop_minio
    [ "${SPECS_MINIO_KEEP:-0}" = "1" ] || rm -rf "${SESSION_DIR}/data_${N}"
done

echo "=== ${N} trace(s): $((N - FAILED)) matched, ${FAILED} diverged ==="
[ "$FAILED" = "0" ]
