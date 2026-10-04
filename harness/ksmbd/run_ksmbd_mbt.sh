#!/bin/bash
# SPDX-FileCopyrightText: 2026 The Quint Specs Authors
#
# SPDX-License-Identifier: MIT

# Replay a batch of SMB2 model traces against ksmbd, the Linux kernel's SMB
# server.
#
# Usage: run_ksmbd_mbt.sh <trace-dir> [trace-glob]
#
#   <trace-dir>   a CELL's trace directory (build/specs-corpus/ksmbd/smb2/<cell>).
#   [trace-glob]  shell glob narrowing the run (default: *.itf.json).
#
# ksmbd is a kernel module, so the server under test is a KVM guest: the same
# chimera-nas/kvm-test-base image the knfsd suite boots (harness/nfs).  This
# script is the HOST side of a TAP link in a network namespace of its own and
# drives the guest at 10.0.0.2 with the replayer the Samba suite uses
# (harness/samba/smb2_replay.py) -- one client, three servers.
#
# One guest per batch.  A 9p share is the control channel, as for knfsd: it
# carries the guest's bring-up script in, and between traces the host drops a
# "go" marker, the guest empties the share and answers "done".
#
# ksmbd's userspace half (ksmbd.mountd, ksmbd.adduser: the ksmbd-tools
# package) is in the guest image as of kvm-test-base v1.11.0.  For an older
# image, SPECS_KSMBD_DEBS names a directory of .deb files -- ksmbd-tools and
# whatever of its dependencies the image lacks -- which the guest installs at
# boot; with neither, the run is a SKIP.
#
# Environment:
#   KVM_VMLINUZ / KVM_ROOTFS   guest kernel + rootfs (CMake resolves them from
#                              KVM_IMAGE_DIR)
#   SPECS_KSMBD_DEBS           see above
#   SPECS_KSMBD_TIMEOUT        wall-clock cap for the whole replay (default 900s)
#   SPECS_KSMBD_KEEP=1         keep the session dir (and the guest's serial log)
#   SPECS_KSMBD_SURVEY=1       pass --keep-going to the replayer
#   SPECS_KSMBD_EXEC=<cmd>     run <cmd> against the live guest instead of the
#                              replayer, with SPECS_SMB_{SERVER,PORT,SHARE,
#                              USER,PASS,RESET_DIR} exported
#
# Exit status 77 (a ctest SKIP) when the machine cannot run a guest: no image,
# no /dev/kvm, no qemu, or no right to create a network namespace.

set -u

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
SAMBA_HARNESS="${HERE}/../samba"

TRACE_DIR=${1:?usage: run_ksmbd_mbt.sh <trace-dir> [trace-glob]}
TRACE_GLOB=${2:-*.itf.json}

VMLINUZ=${KVM_VMLINUZ:-}
ROOTFS=${KVM_ROOTFS:-}
if [ -z "$VMLINUZ" ] || [ -z "$ROOTFS" ] || [ ! -s "$VMLINUZ" ] \
        || [ ! -s "$ROOTFS" ]; then
    echo "ksmbd: no guest image (set KVM_VMLINUZ / KVM_ROOTFS)" >&2
    exit 77
fi
if [ ! -e /dev/kvm ]; then
    echo "ksmbd: /dev/kvm is not available" >&2
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
    echo "ksmbd: $QEMU_BIN not found" >&2
    exit 77
fi

TIMEOUT=${SPECS_KSMBD_TIMEOUT:-900}
SMB_USER=root
SMB_PASS='Model01-Replay'
HOST_IP=10.0.0.1
GUEST_IP=10.0.0.2

NETNS_NAME="specs_ksmbd_$$_$(date +%s%N)"
TAP_NAME="taps$$"
SESSION_DIR=$(mktemp -d "${TMPDIR:-/tmp}/specs_ksmbd_XXXXXX")
RESET_DIR="${SESSION_DIR}/reset"
QEMU_LOG="${SESSION_DIR}/qemu-serial.log"
QEMU_OUT="${SESSION_DIR}/qemu.out"
QEMU_PID=""

cleanup() {
    if [ -n "$QEMU_PID" ]; then
        kill "$QEMU_PID" 2>/dev/null || true
        for _ in $(seq 1 30); do
            kill -0 "$QEMU_PID" 2>/dev/null || break
            sleep 0.1
        done
        kill -9 "$QEMU_PID" 2>/dev/null || true
        wait "$QEMU_PID" 2>/dev/null || true
    fi
    for pid in $(ip netns pids "${NETNS_NAME}" 2>/dev/null); do
        kill -9 "$pid" 2>/dev/null || true
    done
    timeout 2s ip netns delete "${NETNS_NAME}" 2>/dev/null || true
    if [ "${SPECS_KSMBD_KEEP:-0}" = "1" ]; then
        echo "session kept at ${SESSION_DIR}"
    else
        rm -rf "$SESSION_DIR"
    fi
}
trap cleanup EXIT INT TERM

if ! ip netns add "${NETNS_NAME}" 2>/dev/null; then
    echo "ksmbd: cannot create a network namespace (need CAP_NET_ADMIN);" \
         "the guest needs a TAP" >&2
    exit 77
fi
ip netns exec "${NETNS_NAME}" ip link set lo up
ip netns exec "${NETNS_NAME}" ip tuntap add dev "$TAP_NAME" mode tap
ip netns exec "${NETNS_NAME}" ip addr add "${HOST_IP}/24" dev "$TAP_NAME"
ip netns exec "${NETNS_NAME}" ip link set "$TAP_NAME" up

mkdir -p "$RESET_DIR/debs"
if [ -n "${SPECS_KSMBD_DEBS:-}" ]; then
    cp "${SPECS_KSMBD_DEBS}"/*.deb "$RESET_DIR/debs/" 2>/dev/null || true
fi

# The guest's side: bring ksmbd up over an empty share, then serve resets.
#
# The settings are the counterpart of the smb.conf the Samba suite writes --
# no leases, no durable handles: the caching-off profile the cells are
# generated for -- with one exception.  "oplocks = no" is NOT set on the
# share.  With it an open carries no oplock state at all, and a kernel without
# the fix for CVE-2026-43379 dereferences that missing state on CLOSE and
# oopses; Ubuntu's 6.8 GA kernel is one.  Left on, ksmbd grants an oplock only
# to an open that asks for one, which the cells replayed here do not.
cat > "$RESET_DIR/guest.sh" <<GUEST
#!/bin/sh
set -x
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export DEBIAN_FRONTEND=noninteractive
mkdir -p /export /etc/ksmbd
chmod 0777 /export
if ! command -v ksmbd.mountd >/dev/null 2>&1; then
    ls /reset/debs/*.deb >/dev/null 2>&1 || { touch /reset/notools; exit 0; }
    # Unpacked into a directory of their own, not installed: the guest is a
    # throwaway snapshot with no init system for a package's maintainer
    # scripts to talk to, and unpacking onto / would replace the /lib symlink
    # of a merged-usr root with a real directory.
    mkdir -p /opt/ksmbd-tools
    for d in /reset/debs/*.deb; do
        dpkg-deb -x "\$d" /opt/ksmbd-tools || { touch /reset/notools; exit 0; }
    done
    export PATH=/opt/ksmbd-tools/usr/sbin:/opt/ksmbd-tools/sbin:\$PATH
    export LD_LIBRARY_PATH=/opt/ksmbd-tools/usr/lib/x86_64-linux-gnu:/opt/ksmbd-tools/lib/x86_64-linux-gnu:/opt/ksmbd-tools/usr/lib/aarch64-linux-gnu:/opt/ksmbd-tools/lib/aarch64-linux-gnu
    command -v ksmbd.mountd >/dev/null 2>&1 || { touch /reset/notools; exit 0; }
fi
modprobe ksmbd || { touch /reset/nomodule; exit 0; }
cat > /etc/ksmbd/ksmbd.conf <<CONF
[global]
    netbios name = SPECS
    server string = specs-model-sut
    workgroup = WORKGROUP
    map to guest = never
    server min protocol = SMB2_10
    server max protocol = SMB3_11
    smb2 leases = no
    durable handles = no
    bind interfaces only = no
[share]
    path = /export
    read only = no
    guest ok = no
    browseable = yes
    force user = root
CONF
ksmbd.adduser -a -p '${SMB_PASS}' ${SMB_USER} || ksmbd.adduser -a ${SMB_USER} -p '${SMB_PASS}'
ksmbd.mountd || { touch /reset/failed; exit 0; }
( ksmbd.mountd --version 2>/dev/null || ksmbd.mountd -V 2>/dev/null; uname -r ) > /reset/version 2>&1
touch /reset/ready
while true; do
    if [ -f /reset/go ]; then
        rm -rf /export/* /export/.[!.]* 2>/dev/null
        chmod 0777 /export
        sync
        rm -f /reset/go
        touch /reset/done
    fi
    sleep 0.02
done
GUEST
chmod +x "$RESET_DIR/guest.sh"

GUEST_CMD="mkdir -p /reset; modprobe 9pnet_virtio 2>/dev/null; modprobe 9p 2>/dev/null; mount -t 9p -o trans=virtio,version=9p2000.L resetshare /reset && sh /reset/guest.sh"

# shellcheck disable=SC2086
ip netns exec "${NETNS_NAME}" "$QEMU_BIN" \
    -enable-kvm -smp 4 -m 1G -cpu host \
    -kernel "$VMLINUZ" $QEMU_MACHINE -nodefaults \
    -drive file="$ROOTFS",if=virtio,format=qcow2,snapshot=on \
    -netdev tap,id=net0,ifname="$TAP_NAME",script=no,downscript=no \
    -device virtio-net-pci,netdev=net0,romfile="" \
    -fsdev local,id=resetfs,path="$RESET_DIR",security_model=none \
    -device virtio-9p-pci,fsdev=resetfs,mount_tag=resetshare \
    -serial file:"$QEMU_LOG" -nographic -no-reboot \
    -append "root=/dev/vda rw console=${QEMU_CONSOLE} net.ifnames=0 biosdevname=0 quiet mitigations=off tsc=reliable panic=-1 guest_ip=${GUEST_IP} test_cmd=\"${GUEST_CMD}\" init=/init.sh" \
    > "$QEMU_OUT" 2>&1 &
QEMU_PID=$!

guest_log() {
    cat "$QEMU_OUT" 2>/dev/null || true
    tail -80 "$QEMU_LOG" 2>/dev/null || true
}

# Ready when ksmbd answers on :445, which means the whole bring-up ran.
ready=0
for _ in $(seq 1 1200); do
    if ip netns exec "${NETNS_NAME}" bash -c \
           "exec 3<>/dev/tcp/${GUEST_IP}/445" 2>/dev/null; then
        ready=1; break
    fi
    if [ -f "$RESET_DIR/notools" ]; then
        echo "ksmbd: the guest image has no ksmbd-tools (kvm-test-base" \
             ">= v1.11.0 carries it; or set SPECS_KSMBD_DEBS)" >&2
        exit 77
    fi
    if [ -f "$RESET_DIR/failed" ]; then
        echo "ksmbd: ksmbd.mountd did not start in the guest" >&2
        guest_log
        exit 1
    fi
    if [ -f "$RESET_DIR/nomodule" ]; then
        echo "ksmbd: the guest kernel has no ksmbd module" >&2
        exit 77
    fi
    if ! kill -0 "$QEMU_PID" 2>/dev/null; then
        echo "ksmbd: the guest exited before it was ready" >&2
        guest_log
        exit 1
    fi
    sleep 0.1
done
if [ "$ready" != "1" ]; then
    echo "ksmbd: the guest never served SMB on ${GUEST_IP}:445" >&2
    guest_log
    exit 1
fi

echo "=== ksmbd ($(tr '\n' ' ' < "$RESET_DIR/version" 2>/dev/null)) | traces ${TRACE_GLOB} ==="

# The replayer finds ksmbd_deviations.py through the module search path.
export PYTHONPATH="${HERE}${PYTHONPATH:+:$PYTHONPATH}"

if [ -n "${SPECS_KSMBD_EXEC:-}" ]; then
    ip netns exec "${NETNS_NAME}" env \
        SPECS_SMB_SERVER="$GUEST_IP" SPECS_SMB_PORT=445 SPECS_SMB_SHARE=share \
        SPECS_SMB_USER="$SMB_USER" SPECS_SMB_PASS="$SMB_PASS" \
        SPECS_SMB_RESET_DIR="$RESET_DIR" \
        timeout "$TIMEOUT" bash -c "$SPECS_KSMBD_EXEC"
    exit $?
fi

# shellcheck disable=SC2086  # TRACE_GLOB is a glob and must stay unquoted
TRACES=( $(compgen -G "${TRACE_DIR}/${TRACE_GLOB}" || true) )
if [ ${#TRACES[@]} -eq 0 ]; then
    echo "no traces matched ${TRACE_DIR}/${TRACE_GLOB}" >&2
    exit 77
fi

ARGS=()
[ "${SPECS_KSMBD_SURVEY:-0}" = "1" ] && ARGS+=(--keep-going)
for t in "${TRACES[@]}"; do ARGS+=(--trace "$t"); done

ip netns exec "${NETNS_NAME}" timeout "$TIMEOUT" \
    python3 "${SAMBA_HARNESS}/smb2_replay.py" \
    --server "$GUEST_IP" --port 445 --share share --reset-dir "$RESET_DIR" \
    --user "$SMB_USER" --password "$SMB_PASS" --server-kind ksmbd \
    --no-signing \
    "${ARGS[@]}"
RC=$?

if [ "$RC" != "0" ]; then
    echo "=== guest console (last 40 lines) ==="
    tail -40 "$QEMU_LOG" 2>/dev/null || true
fi
if ! kill -0 "$QEMU_PID" 2>/dev/null; then
    echo "=== the ksmbd guest died during the run ==="
    guest_log
    QEMU_PID=""
    [ "$RC" = "0" ] && RC=70
fi
exit $RC
