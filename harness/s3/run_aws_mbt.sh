#!/bin/bash
# SPDX-FileCopyrightText: 2026 The Quint Specs Authors
#
# SPDX-License-Identifier: MIT

# Replay a batch of S3 model traces against Amazon S3 itself.
#
# Usage: run_aws_mbt.sh <trace-dir> [trace-glob]
#
#   <trace-dir>   a CELL's trace directory (build/specs-corpus/aws/s3/<cell>).
#   [trace-glob]  shell glob narrowing the run (default: *.itf.json).
#
# There is no server to start.  What there is instead is an account in which
# the credentials hold rights on ONE bucket that already exists, and nothing
# else -- so the cells are generated under the fixedBucket policy (the model
# starts with its one bucket live and never creates, deletes or lists
# buckets), and the replayer maps that bucket onto the real one.
#
# The bucket is SHARED: other pipelines, of this repository and of others, may
# be using it at the same moment.  So isolation is by KEY PREFIX, not by
# emptying anything: every trace's keys go under
# specs-mbt/<run>-<attempt>-<time>-<pid>/<trace>/, which no other run, no other
# cell of this run and no other trace of this cell shares.  A trace therefore
# starts on an empty namespace in a bucket that is not empty, and any number of
# these can run at once.  Nothing is deleted afterwards -- the bucket carries a
# lifecycle rule that expires objects and unfinished multipart uploads after a
# day.
#
# Nothing bucket-wide is touched: the one piece of modeled state a prefix
# cannot partition, the bucket's tag set, is not drawn under fixedBucket.
#
# Environment:
#   AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY   the credentials
#   AWS_S3_BUCKET            the bucket (must exist)
#   AWS_REGION               its region (default us-east-1)
#   SPECS_S3_BLOCK_SIZE      bytes per model block (default 8192).  A multipart
#                            cell is replayed at 5242880, the minimum part size.
#   SPECS_AWS_TIMEOUT        wall-clock cap for the whole replay (default 1500s)
#   SPECS_AWS_SURVEY=1       pass --keep-going to the replayer
#
# Exit status 77 (a ctest SKIP) when the credentials or the bucket name are not
# in the environment: a fork's pull request has neither, and that is not a
# failure of the fork.

set -u

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

TRACE_DIR=${1:?usage: run_aws_mbt.sh <trace-dir> [trace-glob]}
TRACE_GLOB=${2:-*.itf.json}

if [ -z "${AWS_ACCESS_KEY_ID:-}" ] || [ -z "${AWS_SECRET_ACCESS_KEY:-}" ] ||
   [ -z "${AWS_S3_BUCKET:-}" ]; then
    echo "no AWS credentials or bucket in the environment (AWS_ACCESS_KEY_ID," \
         "AWS_SECRET_ACCESS_KEY, AWS_S3_BUCKET); skipping" >&2
    exit 77
fi

REGION=${AWS_REGION:-us-east-1}
BLOCK_SIZE=${SPECS_S3_BLOCK_SIZE:-8192}
TIMEOUT=${SPECS_AWS_TIMEOUT:-1500}
# Unique per run AND per invocation: two cells of one run must not share it.
PREFIX="specs-mbt/${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-0}-$(date +%s)-$$"

# shellcheck disable=SC2086  # TRACE_GLOB is a glob and must stay unquoted
TRACES=( $(compgen -G "${TRACE_DIR}/${TRACE_GLOB}" || true) )
if [ ${#TRACES[@]} -eq 0 ]; then
    echo "no traces matched ${TRACE_DIR}/${TRACE_GLOB}" >&2
    exit 77
fi

ARGS=()
[ "${SPECS_AWS_SURVEY:-0}" = "1" ] && ARGS+=(--keep-going)
for t in "${TRACES[@]}"; do ARGS+=(--trace "$t"); done

echo "=== Amazon S3 ${REGION} | bucket ${AWS_S3_BUCKET} | prefix ${PREFIX}/ | ${#TRACES[@]} trace(s) | block ${BLOCK_SIZE} ==="

# The credentials reach the replayer through the environment, never the
# command line, where any process on the machine could read them.
timeout "$TIMEOUT" python3 "${HERE}/s3_replay.py" \
    --host "s3.${REGION}.amazonaws.com" --port 443 --tls --region "$REGION" \
    --bucket "bk0=${AWS_S3_BUCKET}" --key-prefix "$PREFIX" \
    --block-size "$BLOCK_SIZE" "${ARGS[@]}"
RC=$?
[ "$RC" = "124" ] && echo "=== replay timed out after ${TIMEOUT}s ==="
exit $RC
