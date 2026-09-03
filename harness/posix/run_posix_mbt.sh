#!/bin/bash
# SPDX-FileCopyrightText: 2026 The Quint Specs Authors
#
# SPDX-License-Identifier: MIT

# Replay a batch of POSIX model traces against a real ext4 filesystem inside
# a KVM guest.
#
# Usage: run_posix_mbt.sh <trace-dir> [trace-glob]
#
#   <trace-dir>   directory holding the generated *.itf.json corpus
#   [trace-glob]  shell glob selecting the batch (default: *.itf.json).
#                 One ctest per batch, so a divergence names the flavor that
#                 found it and the batches run in parallel.
#
# Why a guest, when the other conformance harnesses here just start a server:
# the POSIX corpus is not a protocol, it is syscalls.  Driving it needs a
# filesystem the harness may mount, a kernel it may set sysctls on, and root
# to fork the per-credential workers -- and it needs those to be *the same*
# on every runner, which the container the rest of this repo builds in is
# not: its root is overlayfs, its sysctls are the host's, and its kernel is
# whatever the CI machine happens to run.  A guest is the cheapest way to
# make the filesystem under test the thing being measured.
#
# The guest is a chimera-nas/kvm-test-base image, the same one the knfsd
# suite boots.  Unlike that suite there is no network at all: the ext4
# filesystem is a raw image the host mkfs'es and hands over as a second
# virtio disk, the harness and the batch's traces arrive on a 9p share, and
# the replay runs entirely in-guest.  One guest per batch; the per-trace
# filesystem reset is the driver's own `newfs`.
#
# Environment:
#   KVM_VMLINUZ / KVM_ROOTFS   guest kernel + rootfs (CMake resolves them
#                              from the fetched image; required)
#   SPECS_POSIX_TIMEOUT        wall-clock cap for the whole batch (1500s)
#   SPECS_POSIX_FS_MB          size of the ext4 image (default 512; big
#                              enough that mke2fs picks 4 KiB blocks, which
#                              is the block size the model's block symbols
#                              expand to)
#   SPECS_POSIX_KEEP=1         keep the session dir (and its serial log)
#   SPECS_POSIX_SURVEY=1       report every divergence in a trace rather
#                              than stopping at the first unreconciled one
#   SPECS_POSIX_VERBOSE=1      log every replayed step
#   SPECS_POSIX_LOCAL_ROOT=<d> skip the guest entirely and replay against
#                              the filesystem already mounted at <d>, as
#                              root, on this machine.  For harness
#                              development; CI always uses the guest.
#   SPECS_POSIX_CHECK_PROFILE=1  measure the live capability/policy profile
#                              and diff it against the one pinned in
#                              posix_replay.py, instead of replaying.  The
#                              pinned profile is what trace generation
#                              assumes (posix_run.qnt's posixExt4), so a
#                              drift is not a divergence, it is a corpus
#                              generated for a filesystem that no longer
#                              exists.

set -u

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

TRACE_DIR=${1:?usage: run_posix_mbt.sh <trace-dir> [trace-glob]}
TRACE_GLOB=${2:-*.itf.json}
CHECK_PROFILE=${SPECS_POSIX_CHECK_PROFILE:-0}

TIMEOUT=${SPECS_POSIX_TIMEOUT:-1500}
FS_MB=${SPECS_POSIX_FS_MB:-512}

# shellcheck disable=SC2086  # TRACE_GLOB is a glob and must stay unquoted
TRACES=( $(compgen -G "${TRACE_DIR}/${TRACE_GLOB}" || true) )
if [ ${#TRACES[@]} -eq 0 ] && [ "$CHECK_PROFILE" != "1" ]; then
    echo "no traces matched ${TRACE_DIR}/${TRACE_GLOB}" >&2
    exit 77
fi

REPLAY_ARGS=()
[ "$CHECK_PROFILE" = "1" ] && REPLAY_ARGS+=(--check-profile)
[ "${SPECS_POSIX_SURVEY:-0}" = "1" ] && REPLAY_ARGS+=(--keep-going)
[ "${SPECS_POSIX_VERBOSE:-0}" = "1" ] && REPLAY_ARGS+=(--verbose)

# --------------------------------------------------------------------------
# Development path: replay against a filesystem already mounted here.
# --------------------------------------------------------------------------
if [ -n "${SPECS_POSIX_LOCAL_ROOT:-}" ]; then
    if [ "$(id -u)" != "0" ]; then
        echo "SPECS_POSIX_LOCAL_ROOT needs root (the driver forks one worker "
        echo "per model pid and drops each to that pid's credentials)" >&2
        exit 77
    fi
    echo "=== ext4 (local ${SPECS_POSIX_LOCAL_ROOT}) | traces ${TRACE_GLOB} ==="
    if [ "$CHECK_PROFILE" = "1" ]; then
        exec python3 "${HERE}/posix_replay.py" \
             --root "${SPECS_POSIX_LOCAL_ROOT}" "${REPLAY_ARGS[@]}"
    fi
    exec python3 "${HERE}/posix_replay.py" --root "${SPECS_POSIX_LOCAL_ROOT}" \
         "${REPLAY_ARGS[@]}" "${TRACES[@]/#/--trace=}"
fi

# --------------------------------------------------------------------------
# The guest
# --------------------------------------------------------------------------
VMLINUZ=${KVM_VMLINUZ:-}
ROOTFS=${KVM_ROOTFS:-}
if [ -z "$VMLINUZ" ] || [ -z "$ROOTFS" ] || [ ! -s "$VMLINUZ" ] \
        || [ ! -s "$ROOTFS" ]; then
    echo "ext4: no guest image (set KVM_VMLINUZ / KVM_ROOTFS)" >&2
    exit 77
fi
if [ ! -e /dev/kvm ]; then
    echo "ext4: /dev/kvm is not available" >&2
    exit 77
fi
if ! command -v mkfs.ext4 >/dev/null 2>&1; then
    echo "ext4: mkfs.ext4 not found (e2fsprogs)" >&2
    exit 77
fi

ARCH=$(uname -m)
if [ "$ARCH" = "aarch64" ]; then
    QEMU_BIN=qemu-system-aarch64
    QEMU_MACHINE="-machine virt"
    QEMU_CONSOLE=ttyAMA0
else
    QEMU_BIN=qemu-system-x86_64
    QEMU_MACHINE="-M microvm,acpi=on,rtc=on,pit=on,pcie=on"
    QEMU_CONSOLE=ttyS0
fi
if ! command -v "$QEMU_BIN" >/dev/null 2>&1; then
    echo "ext4: $QEMU_BIN not found" >&2
    exit 77
fi

SESSION_DIR=$(mktemp -d "${TMPDIR:-/tmp}/specs_posix_XXXXXX")
SHARE_DIR="${SESSION_DIR}/share"
FS_IMG="${SESSION_DIR}/ext4.img"
QEMU_LOG="${SESSION_DIR}/serial.log"
QEMU_OUT="${SESSION_DIR}/qemu.out"

cleanup() {
    if [ "${SPECS_POSIX_KEEP:-0}" = "1" ]; then
        echo "session kept at ${SESSION_DIR}" >&2
    else
        rm -rf "${SESSION_DIR}"
    fi
}
trap cleanup EXIT INT TERM

mkdir -p "${SHARE_DIR}/harness" "${SHARE_DIR}/traces"
cp "${HERE}"/posix_replay.py "${HERE}"/posix_driver.py \
   "${HERE}"/deviations.py "${HERE}"/ext4_deviations.py \
   "${SHARE_DIR}/harness/"
if [ ${#TRACES[@]} -gt 0 ]; then
    cp "${TRACES[@]}" "${SHARE_DIR}/traces/"
fi

# The filesystem under test.  Built here rather than in the guest so the
# suite depends on the guest image for a kernel and nothing else, and so the
# block size is pinned: mke2fs picks 1 KiB blocks on a small volume, and the
# model's block symbols expand to 4 KiB.
truncate -s "${FS_MB}M" "$FS_IMG"
mkfs.ext4 -q -F -b 4096 -O ^has_journal "$FS_IMG"

# The in-guest half of the run.  A script on the share rather than a kernel
# command line: the cmdline has a length limit and quoting a program through
# it twice is how a batch fails for reasons that have nothing to do with the
# filesystem.
cat > "${SHARE_DIR}/guest_run.sh" <<'GUESTEOF'
#!/bin/sh
# Mount the filesystem under test, neutralize the sysctls that would answer
# for it, and replay the batch.
set -x
rc=77

# The guest's init script hands us an environment with no PATH at all, and
# a shell's built-in default is not one every program inherits -- Python
# resolves its own sys.executable through PATH, and comes back empty
# without it.
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

# The guest's init.sh runs this script, waits for it, and powers the VM off
# on its own (there is no poweroff(8) in the image).  So every path out of
# here prints exactly one SPECS_POSIX_EXIT marker -- which is what the host
# reads back -- and returns.
if ! command -v python3 >/dev/null 2>&1; then
    echo "ext4: the guest image has no python3"
    echo "SPECS_POSIX_EXIT=77"
    exit 77
fi

# Find the filesystem under test by the serial qemu gave it, not by
# guessing that it enumerated second: there is no udev under init=/init.sh
# to build /dev/disk/by-id, but virtio-blk publishes the serial in sysfs.
# The scan is the fallback, and mounting the wrong disk is not a risk it
# runs -- the root filesystem is already mounted, so mount(8) declines.
mkdir -p /mnt/fs
disk=""
for d in /sys/block/vd*; do
    [ -r "$d/serial" ] || continue
    if [ "$(cat "$d/serial" 2>/dev/null)" = "specsfs" ]; then
        disk="/dev/$(basename "$d")"; break
    fi
done
[ -n "$disk" ] || disk="/dev/vdb /dev/vdc /dev/vdd"

mounted=""
for d in $disk; do
    [ -b "$d" ] || continue
    if mount -t ext4 -o rw,strictatime "$d" /mnt/fs 2>/dev/null; then
        mounted="$d"; break
    fi
done
if [ -z "$mounted" ]; then
    echo "ext4: no ext4 disk to mount (tried $disk)"
    cat /proc/partitions
    echo "SPECS_POSIX_EXIT=1"
    exit 1
fi
echo "ext4: filesystem under test is $mounted"

# mke2fs always lays down lost+found; the model's root starts empty, mode
# 0777, owned by root (posix.qnt's fsInit(511, 0, 0)).  The driver's newfs
# restores that between traces; this is the first one.
rm -rf /mnt/fs/lost+found
chmod 0777 /mnt/fs
chown 0:0 /mnt/fs

# These four sysctls are Linux hardening policy, not filesystem behavior,
# and each one answers a call the model is asking ext4 about: refusing a
# hardlink to a file the caller does not own (protected_hardlinks), refusing
# to follow a symlink in a sticky directory (protected_symlinks), and
# refusing O_CREAT on someone else's file or FIFO in one (protected_regular,
# protected_fifos).  With them on, a whole class of traces measures the
# sysctl instead of the filesystem.
for k in protected_hardlinks protected_symlinks protected_regular \
         protected_fifos; do
    [ -w "/proc/sys/fs/$k" ] && echo 0 > "/proc/sys/fs/$k"
done

cd /specs/harness
if [ "${SPECS_POSIX_CHECK_PROFILE:-0}" = "1" ]; then
    python3 posix_replay.py --root /mnt/fs --check-profile
else
    python3 posix_replay.py --root /mnt/fs ${SPECS_POSIX_REPLAY_ARGS:-} \
            --trace-dir /specs/traces
fi
rc=$?

echo "SPECS_POSIX_EXIT=${rc}"
sync
exit "$rc"
GUESTEOF
chmod +x "${SHARE_DIR}/guest_run.sh"

GUEST_CMD="mkdir -p /specs; modprobe 9pnet_virtio 2>/dev/null; \
modprobe 9p 2>/dev/null; \
if mount -t 9p -o trans=virtio,version=9p2000.L specsshare /specs; then \
SPECS_POSIX_REPLAY_ARGS='${REPLAY_ARGS[*]}' \
SPECS_POSIX_CHECK_PROFILE=${CHECK_PROFILE} sh /specs/guest_run.sh; \
else echo SPECS_POSIX_EXIT=1; fi"

if [ "$CHECK_PROFILE" = "1" ]; then
    echo "=== ext4 (guest $(basename "$ROOTFS"), ${FS_MB}MB) | live profile ==="
else
    echo "=== ext4 (guest $(basename "$ROOTFS"), ${FS_MB}MB) | ${#TRACES[@]} trace(s) ${TRACE_GLOB} ==="
fi

# Both disks are spelled out as -device, root first, because qemu creates
# every explicit -device before it creates the implicit ones behind the
# `if=virtio` shorthand -- so a root disk left as `if=virtio` alongside an
# explicit second disk enumerates SECOND, root=/dev/vda names the filesystem
# under test, and the guest panics on a 512MB image with no /init.sh in it.
# shellcheck disable=SC2086
timeout "$TIMEOUT" "$QEMU_BIN" \
    -enable-kvm -smp 2 -m 1G -cpu host \
    -kernel "$VMLINUZ" $QEMU_MACHINE -nodefaults \
    -drive file="$ROOTFS",if=none,id=rootdisk,format=qcow2,snapshot=on \
    -device virtio-blk-pci,drive=rootdisk \
    -drive file="$FS_IMG",if=none,id=fsdisk,format=raw,cache=unsafe \
    -device virtio-blk-pci,drive=fsdisk,serial=specsfs \
    -fsdev local,id=sharefs,path="$SHARE_DIR",security_model=none \
    -device virtio-9p-pci,fsdev=sharefs,mount_tag=specsshare \
    -serial file:"$QEMU_LOG" -nographic -no-reboot \
    -append "root=/dev/vda rw console=${QEMU_CONSOLE} net.ifnames=0 biosdevname=0 quiet mitigations=off tsc=reliable panic=-1 test_cmd=\"${GUEST_CMD}\" init=/init.sh" \
    > "$QEMU_OUT" 2>&1
QEMU_RC=$?

# The serial log is the run: the replayer's output, the driver's stderr, and
# whatever the guest said on its way down.  The guest image's init.sh dumps
# every process in the VM every five seconds once a test has run for ten,
# which for a batch that takes minutes is most of the log and none of the
# information -- drop those blocks unless something went wrong, when a
# process list is exactly what a hang needs.
RC=$(grep -a -o 'SPECS_POSIX_EXIT=[0-9]*' "$QEMU_LOG" 2>/dev/null |
     tail -1 | cut -d= -f2)
if [ "${RC:-1}" = "0" ] && [ "${SPECS_POSIX_KEEP:-0}" != "1" ]; then
    # Buffer each block rather than deleting a sed range: the last dump is
    # cut off mid-way when the test finishes and the watchdog is killed, and
    # a range with no end deletes to end-of-file -- taking the replayer's
    # summary and the result marker with it.
    awk '
        /=== WATCHDOG:/          { inblk = 1; buf = "" }
        inblk                    { buf = buf $0 "\n"
                                   if ($0 ~ /=== END WATCHDOG ===/) {
                                       inblk = 0; buf = "" }
                                   next }
                                 { print }
        END                      { if (inblk) printf "%s", buf }
    ' "$QEMU_LOG" 2>/dev/null || true
else
    cat "$QEMU_LOG" 2>/dev/null || true
fi

if [ "$QEMU_RC" = "124" ]; then
    echo "=== the guest did not finish within ${TIMEOUT}s ===" >&2
    cat "$QEMU_OUT" 2>/dev/null >&2 || true
    exit 1
fi

if [ -z "$RC" ]; then
    echo "=== the guest never reported a result (qemu exited ${QEMU_RC}) ===" >&2
    cat "$QEMU_OUT" 2>/dev/null >&2 || true
    exit 1
fi
exit "$RC"
