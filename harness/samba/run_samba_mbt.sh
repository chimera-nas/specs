#!/bin/bash
# SPDX-FileCopyrightText: 2026 The Quint Specs Authors
#
# SPDX-License-Identifier: MIT

# Replay a batch of SMB2 model traces against a private Samba server.
#
# Usage: run_samba_mbt.sh <trace-dir> [trace-glob]
#
#   <trace-dir>   directory holding the generated *.itf.json corpus
#   [trace-glob]  shell glob selecting the batch (default: *.itf.json).
#                 One ctest per batch, so a divergence names the flavor that
#                 found it and the batches run in parallel.
#
# Everything -- smbd and the replay client -- runs inside a private network
# namespace, so every concurrent test gets its own 127.0.0.1:445 and the whole
# suite runs under `ctest -j` without a port broker.  Where `ip netns` is
# unavailable (no CAP_NET_ADMIN) the caller is expected to serialize instead;
# see SPECS_SAMBA_NO_NETNS below.
#
# The Samba instance is disposable and fully self-contained: a fresh smb.conf
# in a session directory, with every Samba path (private/lock/state/cache/pid/
# ncalrpc) pointed inside it, so concurrent smbds never share a TDB and nothing
# touches the system configuration.
#
# Environment:
#   SPECS_SAMBA_NO_NETNS=1   run on the host network (caller serializes)
#   SPECS_SAMBA_TIMEOUT      wall-clock cap for the replay (default 900s)
#   SPECS_SAMBA_KEEP=1       keep the session dir on exit (debugging)
#   SPECS_SAMBA_SURVEY=1     pass --keep-going to the replayer: report every
#                            divergence in a trace rather than stopping at the
#                            first unrecorded one
#   SPECS_SAMBA_EXEC=<cmd>   run <cmd> against the live instance instead of the
#                            replayer, with SPECS_SMB_{SERVER,PORT,SHARE,PATH,
#                            USER,PASS} exported.  For iterating on the harness
#                            or hand-probing a divergence.
#   SPECS_SAMBA_LOGLEVEL     smbd log level (default 1)
#   SMBD                     path to smbd (default: from PATH)

set -u

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

TRACE_DIR=${1:?usage: run_samba_mbt.sh <trace-dir> [trace-glob]}
TRACE_GLOB=${2:-*.itf.json}

# smbd lives in /usr/sbin, which is not on PATH for every caller, so fall back
# to the usual locations rather than depending on the invoking shell.  CMake
# passes SMBD explicitly from its own find_program, so the search here only
# matters when the script is run by hand.
SMBD=${SMBD:-}
if [ -z "$SMBD" ]; then
    for cand in "$(command -v smbd 2>/dev/null)" /usr/sbin/smbd \
                /usr/local/sbin/smbd /opt/samba/sbin/smbd; do
        if [ -n "$cand" ] && [ -x "$cand" ]; then
            SMBD=$cand
            break
        fi
    done
fi
if [ -z "$SMBD" ]; then
    echo "smbd not found (install samba, or set SMBD)" >&2
    exit 77
fi

TIMEOUT=${SPECS_SAMBA_TIMEOUT:-900}
LOGLEVEL=${SPECS_SAMBA_LOGLEVEL:-1}

# The SMB identity. root is deliberate: the model has no uid/gid axis at all
# (SMB2 arbitration is share modes and handle state, not POSIX permissions), so
# running the session as root keeps ordinary filesystem DAC -- which the model
# does not describe -- from injecting divergences that would be noise rather
# than findings.  The account is local to this instance's own passdb.
SMB_USER=root
SMB_PASS='Model01!Replay'

NETNS_NAME="specs_samba_$$_$(date +%s%N)"
SESSION_DIR=$(mktemp -d "${TMPDIR:-/tmp}/specs_samba_XXXXXX")
CONF="${SESSION_DIR}/smb.conf"
SHARE_PATH="${SESSION_DIR}/share"
SMBD_OUT="${SESSION_DIR}/smbd.out"
SMBD_LOG="${SESSION_DIR}/log/smbd.log"
SMBD_PID=""
SMBD_PGID=""
# Our own process group, so cleanup can refuse to signal it.  Under ctest this
# group holds ctest itself and every concurrently running test.
OUR_PGID=$(ps -o pgid= -p $$ 2>/dev/null | tr -d ' ' || true)
USE_NETNS=1
[ "${SPECS_SAMBA_NO_NETNS:-0}" = "1" ] && USE_NETNS=0

# Signal smbd's process group, never our own.  The guard is the invariant this
# script cannot get wrong twice: if setsid did not take -- an old util-linux, a
# kernel that refused, an `ip netns exec` that forked in between -- smbd is
# still sharing OUR group, and killing it would take ctest down.  Fall back to
# signalling the single pid in that case and let the strays be reaped by the
# namespace teardown below.
kill_smbd_group() {
    local sig=$1
    if [ -n "$SMBD_PGID" ] && [ "$SMBD_PGID" != "$OUR_PGID" ]; then
        kill "$sig" -- -"$SMBD_PGID" 2>/dev/null || true
    else
        kill "$sig" "$SMBD_PID" 2>/dev/null || true
    fi
}

cleanup() {
    if [ -n "$SMBD_PID" ]; then
        kill_smbd_group -TERM
        for _ in $(seq 1 20); do
            kill -0 "$SMBD_PID" 2>/dev/null || break
            sleep 0.1
        done
        kill_smbd_group -KILL
        wait "$SMBD_PID" 2>/dev/null || true
    fi
    if [ "$USE_NETNS" = "1" ]; then
        # smbd forks a child per connection; they must be gone before the
        # namespace will delete.
        for pid in $(ip netns pids "${NETNS_NAME}" 2>/dev/null); do
            kill "$pid" 2>/dev/null || true
        done
        sleep 0.1
        for pid in $(ip netns pids "${NETNS_NAME}" 2>/dev/null); do
            kill -9 "$pid" 2>/dev/null || true
        done
        timeout 2s ip netns delete "${NETNS_NAME}" 2>/dev/null || true
    else
        pkill -9 -f "smbd.*${SESSION_DIR}" 2>/dev/null || true
    fi
    if [ "${SPECS_SAMBA_KEEP:-0}" = "1" ]; then
        echo "session kept at ${SESSION_DIR}"
    else
        rm -rf "$SESSION_DIR"
    fi
}
# EXIT alone is not enough: ctest sends SIGTERM on timeout, and bash does not
# run an EXIT trap for an untrapped fatal signal -- which would leave the
# namespace and a live smbd behind for every timed-out test.
trap cleanup EXIT INT TERM

mkdir -p "${SESSION_DIR}"/{private,lock,state,cache,log,share} \
         "${SESSION_DIR}"/run/{ncalrpc,winbindd}
# The share must be traversable by the session user; mktemp -d gives 0700.
chmod 0755 "${SESSION_DIR}"
chmod 0777 "${SHARE_PATH}"

cat > "$CONF" <<EOF
# Generated by run_samba_mbt.sh -- disposable, one per test.
[global]
    workgroup = WORKGROUP
    server string = specs-model-sut
    security = user
    map to guest = never
    server min protocol = SMB2_02
    server max protocol = SMB3_11
    smb ports = 445
    interfaces = 127.0.0.1
    bind interfaces only = yes

    private dir = ${SESSION_DIR}/private
    lock directory = ${SESSION_DIR}/lock
    state directory = ${SESSION_DIR}/state
    cache directory = ${SESSION_DIR}/cache
    pid directory = ${SESSION_DIR}/run
    ncalrpc dir = ${SESSION_DIR}/run/ncalrpc
    winbindd socket directory = ${SESSION_DIR}/run/winbindd
    usershare path =
    log file = ${SMBD_LOG}
    log level = ${LOGLEVEL}
    passdb backend = tdbsam:${SESSION_DIR}/private/passdb.tdb

    disable spoolss = yes
    load printers = no
    printing = bsd
    printcap name = /dev/null
    smbd profiling level = off
    panic action = /bin/true

    # The model is a filesystem-and-handle model: it says nothing about
    # opportunistic caching, and the registered smb2Base corpus is generated
    # with oplocks and leases OFF.  Turning them off here too means a grant can
    # never silently change the timing of a conflicting open, which would show
    # up as a divergence the model could not have predicted.  (The harness also
    # skips any trace whose LInit says caching is on.)
    oplocks = no
    level2 oplocks = no
    kernel oplocks = no
    durable handles = no

    # Keep the server's answers about the filesystem literal: no name mangling
    # to alias the model's names, and no DOS-attribute mapping to reinterpret
    # the mode bits as hidden/system/archive.
    mangled names = no
    store dos attributes = no
    map archive = no
    map hidden = no
    map system = no
    map readonly = no

[share]
    path = ${SHARE_PATH}
    read only = no
    guest ok = no
    browseable = yes
    # strict allocate keeps EndOfFile and the on-disk size in step, so the
    # model's block accounting means the same thing on both sides.
    strict allocate = yes
EOF

# Seed the instance-local passdb.  -c pins it at THIS smb.conf, so the entry
# lands in the session's own tdbsam and concurrent tests never race on a
# shared one.
if ! (echo "$SMB_PASS"; echo "$SMB_PASS") | \
        smbpasswd -c "$CONF" -s -a "$SMB_USER" >/dev/null 2>&1; then
    echo "smbpasswd failed to seed the session passdb" >&2
    exit 1
fi

run_in_ns() {
    if [ "$USE_NETNS" = "1" ]; then
        ip netns exec "${NETNS_NAME}" "$@"
    else
        "$@"
    fi
}

if [ "$USE_NETNS" = "1" ]; then
    if ! ip netns add "${NETNS_NAME}" 2>/dev/null; then
        echo "cannot create a network namespace (need CAP_NET_ADMIN); " \
             "re-run with SPECS_SAMBA_NO_NETNS=1 and serialize the caller" >&2
        exit 77
    fi
    ip netns exec "${NETNS_NAME}" ip link set lo up
fi

# setsid is load-bearing, not tidiness.  smbd tears down its PROCESS GROUP when
# it is asked to stop -- that is how it reaps notifyd, cleanupd and the
# per-connection children.  --no-process-group leaves it in OUR group, so that
# teardown reaches the test script, ctest, and every sibling test: the first
# batch to finish killed ctest with SIGTERM 0.13s after it printed its result,
# and the whole suite died with it.  setsid gives smbd a session and group of
# its own, so the teardown stays inside it -- and lets cleanup take down the
# entire smbd tree with one negative-pid kill.
run_in_ns setsid "$SMBD" -F --configfile="$CONF" --no-process-group \
    > "$SMBD_OUT" 2>&1 &
SMBD_PID=$!
SMBD_PGID=$(ps -o pgid= -p "$SMBD_PID" 2>/dev/null | tr -d ' ' || true)

ready=0
for _ in $(seq 1 300); do
    if run_in_ns bash -c 'echo > /dev/tcp/127.0.0.1/445' 2>/dev/null; then
        ready=1
        break
    fi
    if ! kill -0 "$SMBD_PID" 2>/dev/null; then
        echo "smbd exited before it was ready"
        cat "$SMBD_OUT"
        tail -60 "$SMBD_LOG" 2>/dev/null
        exit 1
    fi
    sleep 0.1
done
if [ "$ready" != "1" ]; then
    echo "smbd never accepted a connection on 127.0.0.1:445"
    cat "$SMBD_OUT"
    tail -60 "$SMBD_LOG" 2>/dev/null
    exit 1
fi

echo "=== samba $("$SMBD" --version 2>/dev/null) | traces ${TRACE_GLOB} ==="

if [ -n "${SPECS_SAMBA_EXEC:-}" ]; then
    run_in_ns env \
        SPECS_SMB_SERVER=127.0.0.1 SPECS_SMB_PORT=445 \
        SPECS_SMB_SHARE=share SPECS_SMB_PATH="$SHARE_PATH" \
        SPECS_SMB_USER="$SMB_USER" SPECS_SMB_PASS="$SMB_PASS" \
        timeout "$TIMEOUT" bash -c "$SPECS_SAMBA_EXEC"
    RC=$?
else
    # shellcheck disable=SC2086  # TRACE_GLOB is a glob and must stay unquoted
    TRACES=( $(compgen -G "${TRACE_DIR}/${TRACE_GLOB}" || true) )
    if [ ${#TRACES[@]} -eq 0 ]; then
        echo "no traces matched ${TRACE_DIR}/${TRACE_GLOB}" >&2
        exit 77
    fi

    ARGS=()
    [ "${SPECS_SAMBA_SURVEY:-0}" = "1" ] && ARGS+=(--keep-going)
    for t in "${TRACES[@]}"; do ARGS+=(--trace "$t"); done

    run_in_ns timeout "$TIMEOUT" python3 "${HERE}/smb2_replay.py" \
        --server 127.0.0.1 --port 445 \
        --share share --share-path "$SHARE_PATH" \
        --user "$SMB_USER" --password "$SMB_PASS" \
        "${ARGS[@]}"
    RC=$?
fi

if [ "$RC" != "0" ]; then
    echo "=== smbd log (last 40 lines) ==="
    tail -40 "$SMBD_LOG" 2>/dev/null || true
fi
if ! kill -0 "$SMBD_PID" 2>/dev/null; then
    echo "=== smbd exited during the run ==="
    tail -60 "$SMBD_LOG" 2>/dev/null || true
    SMBD_PID=""
    [ "$RC" = "0" ] && RC=70
fi

exit $RC
