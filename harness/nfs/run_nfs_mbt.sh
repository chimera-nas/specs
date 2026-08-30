#!/bin/bash
# SPDX-FileCopyrightText: 2026 The Quint Specs Authors
#
# SPDX-License-Identifier: MIT

# Replay a batch of NFS model traces against a private third-party NFS
# server.
#
# Usage: run_nfs_mbt.sh <server> <suite> <trace-dir> [trace-glob]
#
#   <server>      ganesha | knfsd
#   <suite>       nfs4 | nfs3   (which replayer, and which corpus shape)
#   <trace-dir>   directory holding the generated *.itf.json corpus
#   [trace-glob]  shell glob selecting the batch (default: *.itf.json).
#                 One ctest per batch, so a divergence names the flavor that
#                 found it and the batches run in parallel.
#
# Everything -- the server, its portmapper and the replay client -- runs
# inside a private network namespace, so every concurrent test gets its own
# 127.0.0.1:2049 and the whole suite runs under `ctest -j` without a port
# broker.  Where `ip netns` is unavailable (no CAP_NET_ADMIN) the caller is
# expected to serialize instead; see SPECS_NFS_NO_NETNS below.
#
# Every trace gets a FRESH server.  A model trace starts from an empty root
# and no protocol state, and the cheapest way to give it exactly that is to
# start the server over: no leftover clientids, no orphaned opens pinning a
# file the model has forgotten, no stale directory cache.  Ganesha starts in
# well under a second, and the batches run concurrently, so the restart is
# not what the wall clock is made of.
#
# Environment:
#   SPECS_NFS_NO_NETNS=1     run on the host network (caller serializes)
#   SPECS_NFS_TIMEOUT        wall-clock cap for one trace's replay (600s)
#   SPECS_NFS_KEEP=1         keep the session dir on exit (debugging)
#   SPECS_NFS_SURVEY=1       pass --keep-going to the replayer: report every
#                            divergence in a trace rather than stopping at
#                            the first unrecorded one
#   SPECS_NFS_EXEC=<cmd>     run <cmd> against one live instance instead of
#                            the replayer, with SPECS_NFS_{SERVER,PORT,
#                            MOUNT_PORT,EXPORT,PATH} exported.  For iterating
#                            on the harness or hand-probing a divergence.
#   SPECS_NFS_DELEG=1        enable delegations (the *Deleg batches)
#   SPECS_NFS_LOGLEVEL       server log level (ganesha: EVENT, DEBUG, ...)
#   SPECS_NFS_SERVER_LOG=1   print the server log tail after a failed trace
#                            (always printed when the server dies)
#   SPECS_GANESHA_FSAL       vfs (default) | mem.  VFS exports an ext4
#                            filesystem the script builds in an image file
#                            and loop-mounts in the session dir -- a real
#                            filesystem with xattrs, holes and fallocate, and
#                            one that hands out file handles (overlayfs, the
#                            usual container root, does not; tmpfs does, but
#                            ganesha refuses to export it).  If the loop
#                            mount is refused the export falls back to the
#                            MEM FSAL, which needs no filesystem at all.
#   SPECS_GANESHA_FS_MB      size of that ext4 image (default 128)
#   GANESHA / RPCBIND        paths to ganesha.nfsd / rpcbind

set -u

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

SERVER=${1:?usage: run_nfs_mbt.sh <ganesha|knfsd> <nfs4|nfs3> <trace-dir> [trace-glob]}
SUITE=${2:?usage: run_nfs_mbt.sh <ganesha|knfsd> <nfs4|nfs3> <trace-dir> [trace-glob]}
TRACE_DIR=${3:?usage: run_nfs_mbt.sh <ganesha|knfsd> <nfs4|nfs3> <trace-dir> [trace-glob]}
TRACE_GLOB=${4:-*.itf.json}

case "$SERVER" in
    ganesha|knfsd) ;;
    *) echo "unknown server '$SERVER' (ganesha|knfsd)" >&2; exit 2 ;;
esac
case "$SUITE" in
    nfs4|nfs3) ;;
    *) echo "unknown suite '$SUITE' (nfs4|nfs3)" >&2; exit 2 ;;
esac

TIMEOUT=${SPECS_NFS_TIMEOUT:-600}
USE_NETNS=1
[ "${SPECS_NFS_NO_NETNS:-0}" = "1" ] && USE_NETNS=0

NFS_BASE_PORT=2049
MNT_BASE_PORT=20048
NLM_BASE_PORT=32803
# Set per trace by ganesha_start (base + rotating offset).
NFS_PORT=$NFS_BASE_PORT
MNT_PORT=$MNT_BASE_PORT
NLM_PORT=$NLM_BASE_PORT

NETNS_NAME="specs_nfs_$$_$(date +%s%N)"
SESSION_DIR=$(mktemp -d "${TMPDIR:-/tmp}/specs_nfs_XXXXXX")
SHARE_PATH="${SESSION_DIR}/share"
SHARE_MOUNTED=0
SERVER_PID=""
RPCBIND_PID=""
START_SEQ=0
OUR_PGID=$(ps -o pgid= -p $$ 2>/dev/null | tr -d ' ' || true)

run_in_ns() {
    if [ "$USE_NETNS" = "1" ]; then
        ip netns exec "${NETNS_NAME}" "$@"
    else
        "$@"
    fi
}

kill_tree() {
    # Signal a process and its group, never our own group (which under ctest
    # holds ctest itself and every sibling test).
    local pid=$1 sig=$2 pgid
    [ -n "$pid" ] || return 0
    pgid=$(ps -o pgid= -p "$pid" 2>/dev/null | tr -d ' ' || true)
    if [ -n "$pgid" ] && [ "$pgid" != "$OUR_PGID" ]; then
        kill "$sig" -- -"$pgid" 2>/dev/null || true
    else
        kill "$sig" "$pid" 2>/dev/null || true
    fi
}

stop_server() {
    if [ -n "$SERVER_PID" ]; then
        kill_tree "$SERVER_PID" -TERM
        for _ in $(seq 1 50); do
            kill -0 "$SERVER_PID" 2>/dev/null || break
            sleep 0.1
        done
        kill_tree "$SERVER_PID" -KILL
        wait "$SERVER_PID" 2>/dev/null || true
        SERVER_PID=""
    fi
}

cleanup() {
    stop_server
    if [ -n "$RPCBIND_PID" ]; then
        kill_tree "$RPCBIND_PID" -TERM
        wait "$RPCBIND_PID" 2>/dev/null || true
        RPCBIND_PID=""
    fi
    if [ "$USE_NETNS" = "1" ]; then
        for pid in $(ip netns pids "${NETNS_NAME}" 2>/dev/null); do
            kill "$pid" 2>/dev/null || true
        done
        sleep 0.1
        for pid in $(ip netns pids "${NETNS_NAME}" 2>/dev/null); do
            kill -9 "$pid" 2>/dev/null || true
        done
        timeout 2s ip netns delete "${NETNS_NAME}" 2>/dev/null || true
    fi
    if [ "$SHARE_MOUNTED" = "1" ]; then
        umount "$SHARE_PATH" 2>/dev/null || umount -l "$SHARE_PATH" 2>/dev/null || true
    fi
    if [ "${SPECS_NFS_KEEP:-0}" = "1" ]; then
        echo "session kept at ${SESSION_DIR}"
    else
        rm -rf "$SESSION_DIR"
    fi
}
# EXIT alone is not enough: ctest sends SIGTERM on timeout, and bash does not
# run an EXIT trap for an untrapped fatal signal.
trap cleanup EXIT INT TERM

mkdir -p "${SESSION_DIR}"/{log,run,recovery,share}
chmod 0755 "${SESSION_DIR}"

if [ "$USE_NETNS" = "1" ]; then
    if ! ip netns add "${NETNS_NAME}" 2>/dev/null; then
        echo "cannot create a network namespace (need CAP_NET_ADMIN); " \
             "re-run with SPECS_NFS_NO_NETNS=1 and serialize the caller" >&2
        exit 77
    fi
    ip netns exec "${NETNS_NAME}" ip link set lo up
fi

wait_port() {
    local port=$1 pid=$2 what=$3 i
    for i in $(seq 1 300); do
        if run_in_ns bash -c "echo > /dev/tcp/127.0.0.1/$port" 2>/dev/null; then
            return 0
        fi
        if [ -n "$pid" ] && ! kill -0 "$pid" 2>/dev/null; then
            echo "$what exited before it was ready" >&2
            return 1
        fi
        sleep 0.05
    done
    echo "$what never accepted a connection on 127.0.0.1:$port" >&2
    return 1
}

# ---------------------------------------------------------------------------
# ganesha
# ---------------------------------------------------------------------------

GANESHA=${GANESHA:-}
RPCBIND=${RPCBIND:-}
FSAL=${SPECS_GANESHA_FSAL:-vfs}
LOGLEVEL=${SPECS_NFS_LOGLEVEL:-EVENT}
GANESHA_CONF="${SESSION_DIR}/ganesha.conf"
GANESHA_LOG="${SESSION_DIR}/log/ganesha.log"
GANESHA_OUT="${SESSION_DIR}/ganesha.out"

find_bin() {
    local var=$1; shift
    local cand
    for cand in "$@"; do
        if [ -n "$cand" ] && [ -x "$cand" ]; then
            printf '%s' "$cand"
            return 0
        fi
    done
    return 1
}

ganesha_prepare() {
    GANESHA=$(find_bin GANESHA "$GANESHA" "$(command -v ganesha.nfsd 2>/dev/null)" \
              /usr/bin/ganesha.nfsd /usr/sbin/ganesha.nfsd /usr/local/bin/ganesha.nfsd) || {
        echo "ganesha.nfsd not found (install nfs-ganesha, or set GANESHA)" >&2
        exit 77
    }
    RPCBIND=$(find_bin RPCBIND "$RPCBIND" "$(command -v rpcbind 2>/dev/null)" \
              /sbin/rpcbind /usr/sbin/rpcbind) || {
        echo "rpcbind not found (install rpcbind, or set RPCBIND)" >&2
        exit 77
    }

    # The export: an ext4 filesystem of our own, loop-mounted from an image
    # file.  FSAL_VFS needs a filesystem that hands out file handles
    # (name_to_handle_at), which overlayfs -- the usual container root --
    # refuses, and ganesha declines to export tmpfs outright.  ext4 gives the
    # model what it assumes: user xattrs, holes, fallocate.
    if [ "$FSAL" = "vfs" ]; then
        local img="${SESSION_DIR}/export.ext4"
        if truncate -s "${SPECS_GANESHA_FS_MB:-128}M" "$img" 2>/dev/null && \
           mkfs.ext4 -q -F "$img" >/dev/null 2>&1 && \
           mount -o loop "$img" "$SHARE_PATH" 2>/dev/null; then
            SHARE_MOUNTED=1
        else
            echo "note: cannot loop-mount an ext4 image here; using the MEM FSAL"
            FSAL=mem
        fi
    fi

    # rpcbind: ganesha registers MOUNT/NLM/NSM with a portmapper and refuses
    # to serve NFSv3 without one.  -f keeps it in the foreground under our
    # control.  Its lock, socket and state files live under /run, which is
    # shared by every concurrent batch, so each instance gets a private
    # tmpfs over /run in a mount namespace of its own (`ip netns exec`
    # already unshares one; without a netns, unshare -m does).  ganesha then
    # enters the same namespaces (nsenter), so it finds rpcbind's socket
    # where libtirpc looks for it.
    local wrap
    if [ "$USE_NETNS" = "1" ]; then
        wrap=(ip netns exec "${NETNS_NAME}")
    else
        wrap=(unshare -m)
    fi
    "${wrap[@]}" bash -c \
        'mount -t tmpfs none /run && mkdir -p /run/rpcbind && exec setsid "$0" -f' \
        "$RPCBIND" > "${SESSION_DIR}/rpcbind.out" 2>&1 &
    RPCBIND_PID=$!
    wait_port 111 "$RPCBIND_PID" rpcbind || {
        cat "${SESSION_DIR}/rpcbind.out"
        exit 1
    }
}

# Run a command inside rpcbind's mount + network namespaces.
run_in_server_ns() {
    nsenter --mount="/proc/${RPCBIND_PID}/ns/mnt" \
            --net="/proc/${RPCBIND_PID}/ns/net" -- "$@"
}

ganesha_conf() {
    local deleg="none" deleg4="false"
    if [ "${SPECS_NFS_DELEG:-0}" = "1" ]; then
        deleg="readwrite"
        deleg4="true"
    fi
    local fsal_block
    if [ "$FSAL" = "mem" ]; then
        fsal_block='FSAL { Name = MEM; }'
    else
        fsal_block='FSAL { Name = VFS; }'
    fi
    cat > "$GANESHA_CONF" <<EOF
# Generated by run_nfs_mbt.sh -- disposable, one per trace.
NFS_CORE_PARAM {
    # No Bind_Addr: ganesha resolves it with AI_ADDRCONFIG, which refuses
    # every IPv4 literal in a namespace whose only interface is loopback.
    # Binding all addresses inside the namespace is the same thing.
    NFS_Port = ${NFS_PORT};
    MNT_Port = ${MNT_PORT};
    NLM_Port = ${NLM_PORT};
    Enable_RQUOTA = false;
    Enable_UDP = false;
    Protocols = 3, 4;
    Clustered = false;
}

NFS_KRB5 {
    Active_krb5 = false;
}

NFSv4 {
    Minor_Versions = 0, 1, 2;
    # Every trace starts on a fresh server with nothing to reclaim; the
    # model does not describe a grace period, so the server must not spend
    # its first seconds answering NFS4ERR_GRACE.
    Graceless = true;
    Lease_Lifetime = 30;
    Delegations = ${deleg4};
    # The harness identifies owners numerically ("0"): no idmapping.
    Allow_Numeric_Owners = true;
    Only_Numeric_Owners = true;
    # RFC 7530 12.7 / RFC 8881 14.4 let a server validate the UTF-8 of
    # component names and tags; the model asserts that validation (a name
    # that is not UTF-8 is NFS4ERR_INVAL).  Off by default in ganesha.
    Enforce_UTF8_Validation = true;
    RecoveryBackend = fs;
    RecoveryRoot = ${SESSION_DIR}/recovery;
}

EXPORT {
    Export_Id = 1;
    Path = ${SHARE_PATH};
    # The export IS the pseudo root: the model's PUTROOTFH lands on the
    # export itself and LOOKUPP at the root has no parent to find.
    Pseudo = /;
    Access_Type = RW;
    Squash = No_Root_Squash;
    Protocols = 3, 4;
    Transports = TCP;
    SecType = sys;
    Delegations = ${deleg};
    ${fsal_block}
}

$( [ "$FSAL" = "mem" ] && printf 'MEM {\n    Inode_Size = 1114112;\n}\n' )

LOG {
    Default_Log_Level = ${LOGLEVEL};
    Facility {
        name = FILE;
        destination = ${GANESHA_LOG};
        enable = active;
    }
}
EOF
}

ganesha_start() {
    START_SEQ=$((START_SEQ + 1))
    local off=$((START_SEQ % 50))
    NFS_PORT=$((NFS_BASE_PORT + off))
    MNT_PORT=$((MNT_BASE_PORT + off))
    NLM_PORT=$((NLM_BASE_PORT + off))
    GANESHA_PID_FILE="${SESSION_DIR}/run/ganesha.${START_SEQ}.pid"
    rm -f "$GANESHA_PID_FILE"
    ganesha_conf
    # Fresh export contents and recovery state for every trace.
    rm -rf "${SHARE_PATH:?}"/* "${SHARE_PATH:?}"/.[!.]* 2>/dev/null || true
    rm -rf "${SESSION_DIR}/recovery"
    if [ "${SPECS_NFS_DEBUG:-0}" = "1" ]; then
        echo "--- export before start:"; ls -la "$SHARE_PATH"
    fi
    mkdir -p "${SESSION_DIR}/recovery"
    # The model's root is 0777 (nfs4_fs: fsInit(511); the nfs3 model's
    # non-root credentials create straight into it).
    chmod 0777 "$SHARE_PATH"
    rm -f "$GANESHA_LOG"
    # -F foreground, -x fatal on config errors, -p a pidfile of our own so
    # concurrent instances never fight over /var/run/ganesha.
    run_in_server_ns setsid "$GANESHA" -F -x -f "$GANESHA_CONF" -L "$GANESHA_LOG" \
        -N "NIV_${LOGLEVEL}" -p "$GANESHA_PID_FILE" \
        > "$GANESHA_OUT" 2>&1 &
    SERVER_PID=$!
    if ! wait_port "$NFS_PORT" "$SERVER_PID" ganesha; then
        cat "$GANESHA_OUT"
        tail -60 "$GANESHA_LOG" 2>/dev/null
        return 1
    fi
    # The export is what the model talks to: refuse to run a batch against
    # a server that failed to bring it up (the FSAL could not export the
    # path, say), which would otherwise surface as a divergence on step 1.
    local i
    for i in $(seq 1 100); do
        if grep -q 'NFS SERVER INITIALIZED\|NFS STARTUP' "$GANESHA_LOG" 2>/dev/null; then
            break
        fi
        sleep 0.05
    done
    if grep -qi 'Could not create export\|Export .* not created\|export_commit.*fail' "$GANESHA_LOG" 2>/dev/null; then
        echo "ganesha did not bring up the export:" >&2
        grep -i 'export' "$GANESHA_LOG" | tail -10 >&2
        return 1
    fi
    return 0
}

server_version() {
    case "$SERVER" in
        ganesha) "$GANESHA" -v 2>/dev/null | head -1 ;;
        knfsd) echo "knfsd (guest kernel)" ;;
    esac
}

# ---------------------------------------------------------------------------
# knfsd (Linux kernel NFS server in a KVM guest): a later step of the
# conformance work; the batches report SKIP until it lands so the gap stays
# attributable to the harness.
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# knfsd: the Linux kernel NFS server, in a KVM guest.
#
# The guest (a chimera-nas/kvm-test-base image, >= v1.10.0, which carries
# nfs-kernel-server) boots as the SERVER; the replay client runs on the host
# side of a TAP link, in this test's network namespace, and drives the guest
# at 10.0.0.2.  This inverts the usual chimera KVM wrapper, where the guest is
# the client and chimera the host server.
#
# One guest per batch, not per trace: a VM boot is seconds and NFSv4 grace is
# entered once, so the per-trace reset is done in-guest instead.  A 9p share
# is the control channel -- the host drops a "go" marker, the guest clears its
# export and flushes the filehandle cache, then acks -- which needs neither an
# ssh key (the image's keys are guest-internal) nor an NFS-level walk (leftover
# open state would make that unreliable).  Distinct per-trace client owners
# (the replayer salts them) keep one trace's NFSv4 state from touching the
# next; whatever lingers expires with the short lease.
#
# Environment (beyond the common set):
#   KVM_VMLINUZ / KVM_ROOTFS   guest kernel + rootfs (CMake resolves them from
#                              the fetched image; required)
#   SPECS_KVM_GRACE            knfsd grace/lease seconds in the guest (default
#                              10; the replayer's GRACE retry covers the first
#                              trace's wait)
if [ "$SERVER" = "knfsd" ]; then
    VMLINUZ=${KVM_VMLINUZ:-}
    ROOTFS=${KVM_ROOTFS:-}
    if [ -z "$VMLINUZ" ] || [ -z "$ROOTFS" ] || [ ! -s "$VMLINUZ" ] \
            || [ ! -s "$ROOTFS" ]; then
        echo "knfsd: no guest image (set KVM_VMLINUZ / KVM_ROOTFS)" >&2
        exit 77
    fi
    if [ ! -e /dev/kvm ]; then
        echo "knfsd: /dev/kvm is not available" >&2
        exit 77
    fi
    if [ "$USE_NETNS" != "1" ]; then
        echo "knfsd: a network namespace is required (the guest needs a TAP)" >&2
        exit 77
    fi

    ARCH=$(uname -m)
    if [ "$ARCH" = "aarch64" ]; then
        QEMU_BIN=qemu-system-aarch64
        QEMU_MACHINE="-machine virt"
        QEMU_CONSOLE=ttyAMA0
        ROOT_DEV=/dev/vda
    else
        QEMU_BIN=qemu-system-x86_64
        QEMU_MACHINE="-M microvm,acpi=on,rtc=on,pit=on,pcie=on"
        QEMU_CONSOLE=ttyS0
        ROOT_DEV=/dev/vda
    fi
    if ! command -v "$QEMU_BIN" >/dev/null 2>&1; then
        echo "knfsd: $QEMU_BIN not found" >&2
        exit 77
    fi

    TAP_NAME="tapk$$"
    HOST_IP=10.0.0.1
    GUEST_IP=10.0.0.2
    GRACE=${SPECS_KVM_GRACE:-10}
    RESET_DIR="${SESSION_DIR}/reset"
    QEMU_LOG="${SESSION_DIR}/qemu-serial.log"
    QEMU_OUT="${SESSION_DIR}/qemu.out"
    QEMU_PID=""
    mkdir -p "$RESET_DIR"

    knfsd_cleanup() {
        if [ -n "$QEMU_PID" ]; then
            kill "$QEMU_PID" 2>/dev/null || true
            for _ in $(seq 1 30); do
                kill -0 "$QEMU_PID" 2>/dev/null || break
                sleep 0.1
            done
            kill -9 "$QEMU_PID" 2>/dev/null || true
            wait "$QEMU_PID" 2>/dev/null || true
        fi
    }
    # Chain onto the EXIT/INT/TERM trap already installed for the netns.
    trap 'knfsd_cleanup; cleanup' EXIT INT TERM

    # Host side of the TAP.
    ip netns exec "${NETNS_NAME}" ip tuntap add dev "$TAP_NAME" mode tap
    ip netns exec "${NETNS_NAME}" ip addr add "${HOST_IP}/24" dev "$TAP_NAME"
    ip netns exec "${NETNS_NAME}" ip link set "$TAP_NAME" up

    # The in-guest server bring-up + per-trace reset loop, passed on the kernel
    # command line.  NFSv4 grace/lease are lowered so the one grace window this
    # batch pays is short; the export is fsid=0 so PUTROOTFH lands on it (the
    # model's root), and `insecure` admits the replayer's high source ports.
    GUEST_CMD="\
set -x; \
mkdir -p /export /reset; chmod 0777 /export; \
modprobe 9pnet_virtio 2>/dev/null; modprobe 9p 2>/dev/null; \
mount -t 9p -o trans=virtio,version=9p2000.L resetshare /reset || true; \
modprobe nfsd 2>/dev/null; \
mount -t nfsd nfsd /proc/fs/nfsd 2>/dev/null || true; \
echo ${GRACE} > /proc/fs/nfsd/nfsv4leasetime 2>/dev/null || true; \
echo ${GRACE} > /proc/fs/nfsd/nfsv4gracetime 2>/dev/null || true; \
rpcbind || true; sleep 0.3; \
exportfs -o rw,no_root_squash,insecure,no_subtree_check,fsid=0,sync ${GUEST_IP%.*}.0/24:/export; \
rpc.nfsd 8; rpc.mountd; exportfs -a; \
touch /reset/ready; \
while true; do \
  if [ -f /reset/go ]; then \
    rm -rf /export/* /export/.[!.]* 2>/dev/null; chmod 0777 /export; \
    exportfs -f 2>/dev/null; sync; \
    rm -f /reset/go; touch /reset/done; \
  fi; \
  sleep 0.05; \
done"

    QEMU_INITRD=""
    # shellcheck disable=SC2086
    ip netns exec "${NETNS_NAME}" "$QEMU_BIN" \
        -enable-kvm -smp 4 -m 1G -cpu host \
        -kernel "$VMLINUZ" $QEMU_INITRD $QEMU_MACHINE -nodefaults \
        -drive file="$ROOTFS",if=virtio,format=qcow2,snapshot=on \
        -netdev tap,id=net0,ifname="$TAP_NAME",script=no,downscript=no \
        -device virtio-net-pci,netdev=net0,romfile="" \
        -fsdev local,id=resetfs,path="$RESET_DIR",security_model=none \
        -device virtio-9p-pci,fsdev=resetfs,mount_tag=resetshare \
        -serial file:"$QEMU_LOG" -nographic -no-reboot \
        -append "root=${ROOT_DEV} rw console=${QEMU_CONSOLE} net.ifnames=0 biosdevname=0 quiet mitigations=off tsc=reliable panic=-1 guest_ip=${GUEST_IP} test_cmd=\"${GUEST_CMD}\" init=/init.sh" \
        > "$QEMU_OUT" 2>&1 &
    QEMU_PID=$!

    # Ready when nfsd answers on :2049 (which means the whole bring-up ran).
    # The /reset/ready marker is not required here -- 9p write-visibility can
    # lag, and a live :2049 is the real signal -- but the reset round-trip
    # below does depend on the 9p channel working.
    ready=0
    for _ in $(seq 1 1200); do
        if ip netns exec "${NETNS_NAME}" bash -c \
               "exec 3<>/dev/tcp/${GUEST_IP}/2049" 2>/dev/null; then
            ready=1; break
        fi
        if ! kill -0 "$QEMU_PID" 2>/dev/null; then
            echo "knfsd: the guest exited before it was ready" >&2
            cat "$QEMU_OUT" 2>/dev/null || true
            tail -60 "$QEMU_LOG" 2>/dev/null || true
            exit 1
        fi
        sleep 0.1
    done
    if [ "$ready" != "1" ]; then
        echo "knfsd: the guest never served NFS on ${GUEST_IP}:2049" >&2
        cat "$QEMU_OUT" 2>/dev/null || true
        tail -80 "$QEMU_LOG" 2>/dev/null || true
        exit 1
    fi

    # Clear the export in-guest via the 9p control channel.
    knfsd_reset() {
        rm -f "${RESET_DIR}/done"
        touch "${RESET_DIR}/go"
        local i
        for i in $(seq 1 200); do
            [ -f "${RESET_DIR}/done" ] && return 0
            sleep 0.05
        done
        echo "knfsd: the guest did not acknowledge a reset" >&2
        return 1
    }

    echo "=== knfsd (guest $(basename "$ROOTFS")) | $SUITE | traces ${TRACE_GLOB} ==="

    if [ -n "${SPECS_NFS_EXEC:-}" ]; then
        knfsd_reset || true
        run_in_ns env \
            SPECS_NFS_SERVER="$GUEST_IP" SPECS_NFS_PORT=2049 \
            SPECS_NFS_MOUNT_PORT=0 SPECS_NFS_EXPORT=/export \
            SPECS_NFS_PATH=/export SPECS_NFS_HARNESS="$HERE" \
            timeout "$TIMEOUT" bash -c "$SPECS_NFS_EXEC"
        exit $?
    fi

    # shellcheck disable=SC2086
    TRACES=( $(compgen -G "${TRACE_DIR}/${TRACE_GLOB}" || true) )
    if [ ${#TRACES[@]} -eq 0 ]; then
        echo "no traces matched ${TRACE_DIR}/${TRACE_GLOB}" >&2
        exit 77
    fi

    K_ARGS=(--server "$GUEST_IP" --server-kind knfsd)
    [ "${SPECS_NFS_SURVEY:-0}" = "1" ] && K_ARGS+=(--keep-going)
    case "$SUITE" in
        nfs4) REPLAYER="${HERE}/nfs4_replay.py"; K_ARGS+=(--port 2049 --export /) ;;
        nfs3) REPLAYER="${HERE}/nfs3_replay.py"
              K_ARGS+=(--port 2049 --mount-port 0 --export /export) ;;
    esac

    n_ok=0; n_skip=0; n_fail=0
    EPOCH="$$-$(date +%s)"
    for t in "${TRACES[@]}"; do
        if ! knfsd_reset; then
            echo "$(basename "$t"): ERROR guest reset failed"
            n_fail=$((n_fail + 1)); continue
        fi
        run_in_ns timeout "$TIMEOUT" python3 "$REPLAYER" "${K_ARGS[@]}" \
            --owner-epoch "${EPOCH}" --trace "$t"
        rc=$?
        if [ "$rc" = "0" ]; then n_ok=$((n_ok + 1))
        elif [ "$rc" = "77" ]; then n_skip=$((n_skip + 1))
        else n_fail=$((n_fail + 1)); fi
        if ! kill -0 "$QEMU_PID" 2>/dev/null; then
            echo "=== knfsd guest died during $(basename "$t") ==="
            tail -60 "$QEMU_LOG" 2>/dev/null || true
            QEMU_PID=""
            break
        fi
    done

    echo "=== batch ${TRACE_GLOB}: ${#TRACES[@]} trace(s): ok ${n_ok}, skipped ${n_skip}, failed ${n_fail} ==="
    [ "$n_fail" != "0" ] && exit 1
    [ "$n_skip" = "${#TRACES[@]}" ] && exit 77
    exit 0
fi


ganesha_prepare

echo "=== $(server_version) | $SUITE | fsal ${FSAL} | traces ${TRACE_GLOB} ==="

if [ -n "${SPECS_NFS_EXEC:-}" ]; then
    ganesha_start || exit 1
    run_in_ns env \
        SPECS_NFS_SERVER=127.0.0.1 SPECS_NFS_PORT=$NFS_PORT \
        SPECS_NFS_MOUNT_PORT=$MNT_PORT SPECS_NFS_EXPORT="$SHARE_PATH" \
        SPECS_NFS_PATH="$SHARE_PATH" SPECS_NFS_HARNESS="$HERE" \
        timeout "$TIMEOUT" bash -c "$SPECS_NFS_EXEC"
    RC=$?
    stop_server
    exit $RC
fi

# shellcheck disable=SC2086  # TRACE_GLOB is a glob and must stay unquoted
TRACES=( $(compgen -G "${TRACE_DIR}/${TRACE_GLOB}" || true) )
if [ ${#TRACES[@]} -eq 0 ]; then
    echo "no traces matched ${TRACE_DIR}/${TRACE_GLOB}" >&2
    exit 77
fi

BASE_ARGS=(--server 127.0.0.1 --server-kind "$SERVER")
[ "${SPECS_NFS_SURVEY:-0}" = "1" ] && BASE_ARGS+=(--keep-going)
case "$SUITE" in
    nfs4) REPLAYER="${HERE}/nfs4_replay.py" ;;
    nfs3) REPLAYER="${HERE}/nfs3_replay.py" ;;
esac

# The per-trace port arguments (NFS_PORT etc. are set by ganesha_start).
replay_args() {
    case "$SUITE" in
        nfs4) echo --port "$NFS_PORT" --export / ;;
        nfs3) echo --port "$NFS_PORT" --mount-port "$MNT_PORT" \
                   --export "$SHARE_PATH" ;;
    esac
}

n_ok=0; n_skip=0; n_fail=0; n_other=0
EPOCH="$$-$(date +%s)"
for t in "${TRACES[@]}"; do
    if ! ganesha_start; then
        echo "$(basename "$t"): ERROR server failed to start"
        n_fail=$((n_fail + 1))
        continue
    fi
    # shellcheck disable=SC2046  # replay_args intentionally word-splits
    run_in_ns timeout "$TIMEOUT" python3 "$REPLAYER" "${BASE_ARGS[@]}" \
        $(replay_args) --owner-epoch "${EPOCH}" --trace "$t"
    rc=$?
    if [ "$rc" = "0" ]; then
        n_ok=$((n_ok + 1))
    elif [ "$rc" = "77" ]; then
        n_skip=$((n_skip + 1))
    else
        n_fail=$((n_fail + 1))
        if [ "${SPECS_NFS_SERVER_LOG:-0}" = "1" ]; then
            echo "=== ganesha log (last 40 lines) ==="
            tail -40 "$GANESHA_LOG" 2>/dev/null || true
        fi
    fi
    if [ -n "$SERVER_PID" ] && ! kill -0 "$SERVER_PID" 2>/dev/null; then
        echo "=== ganesha exited during $(basename "$t") ==="
        if [ "${SPECS_NFS_SERVER_LOG:-0}" = "1" ]; then
            cat "$GANESHA_OUT"
            tail -60 "$GANESHA_LOG" 2>/dev/null || true
        fi
        SERVER_PID=""
        [ "$rc" = "0" ] && { n_ok=$((n_ok - 1)); n_fail=$((n_fail + 1)); }
    fi
    stop_server
done

echo "=== batch ${TRACE_GLOB}: ${#TRACES[@]} trace(s): ok ${n_ok}, skipped ${n_skip}, failed ${n_fail} ==="
if [ "$n_fail" != "0" ]; then
    exit 1
fi
if [ "$n_skip" = "${#TRACES[@]}" ]; then
    exit 77
fi
exit 0
