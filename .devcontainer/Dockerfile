# SPDX-FileCopyrightText: 2026 The Quint Specs Authors
#
# SPDX-License-Identifier: MIT

# Development container for the quint specs repo.
#
# Two jobs:
#   1. Build the corpus -- cmake + a pinned quint + python3, which is the whole
#      dependency set of `cmake -B build && cmake --build build && ctest`.
#   2. Run the corpus against a REAL SMB server -- Samba's smbd, driven by the
#      replay harness in harness/samba.  That is what makes the SMB2 model
#      falsifiable against something other than the implementation it was
#      written alongside: where the model and Samba disagree, one of them is
#      wrong, and the disagreement is either a model bug or a recorded
#      deviation (harness/samba/samba_deviations.py).
#
# The image is Ubuntu 26.04 to match the chimera devcontainer, so the Samba
# build under test is the same one chimera's smbtorture suites run against.

ARG DOCKER_MIRROR=""
FROM ${DOCKER_MIRROR}ubuntu:26.04
ARG APT_MIRROR=""
ARG ENABLE_CLAUDE=1

ENV DEBIAN_FRONTEND=noninteractive

# CI points these at an internal registry and apt mirror; both default empty so
# a plain "docker build" of this devcontainer still pulls from upstream.
RUN if [ -n "$APT_MIRROR" ]; then \
    echo "deb $APT_MIRROR resolute main universe" > /etc/apt/sources.list.d/local-mirror.list && \
    echo "deb $APT_MIRROR resolute-updates main universe" >> /etc/apt/sources.list.d/local-mirror.list && \
    echo "deb $APT_MIRROR resolute-security main universe" >> /etc/apt/sources.list.d/local-mirror.list && \
    rm -f /etc/apt/sources.list.d/ubuntu.sources; \
    fi

# cmake/ninja/make/py3   -- the corpus build and the coverage gates.  make is
#                           here only so a bare `cmake -B build` (no -G) works:
#                           without a default generator cmake fails outright.
# nodejs/npm             -- quint itself
# samba/smbclient        -- the server under test for the samba MBT suite
# nfs-ganesha + FSALs    -- the server under test for the NFS conformance
#                           suite (harness/nfs): a userspace NFSv3/v4.0/4.1/
#                           4.2 server nobody consulted while writing the NFS
#                           models.  The VFS FSAL exports a real directory
#                           (xattrs, holes and fallocate behave as the model
#                           expects); MEM is the fallback when the container's
#                           filesystem cannot hand out file handles.
# rpcbind                -- ganesha registers its NFSv3 side programs (MOUNT,
#                           NLM) with a portmapper; one runs per test netns.
# iproute2               -- `ip netns`, which is how the samba and ganesha
#                           tests get to run in parallel (each server binds its
#                           ports in its own network namespace)
# qemu-system-x86/utils  -- the KVM guest that runs the Linux kernel NFS server
#                           (knfsd) for the NFS conformance suite.  x86 only, as
#                           in the chimera devcontainer: KVM acceleration needs
#                           a matching host, so the knfsd tests run on amd64.
# python3-pip            -- the replay harness's SMB2 client (see below)
# reuse                  -- the SPDX lint this repo's CI enforces
RUN apt-get -y update && \
    apt-get -y --no-install-recommends upgrade && \
    apt-get -y --no-install-recommends install apt-utils && \
    apt-get -y --no-install-recommends install \
        cmake ninja-build make git curl ca-certificates less vim psmisc jq \
        python3 python3-pip python3-venv nodejs npm reuse \
        iproute2 net-tools tshark tcpdump procps \
        samba smbclient samba-common-bin libsmbclient \
        nfs-ganesha nfs-ganesha-vfs nfs-ganesha-mem rpcbind \
        qemu-system-x86 qemu-utils && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# The replay harness speaks SMB2 through `smbprotocol`, a pure-Python SMB2/3
# client.  It is used at its RAW layer -- the harness hand-builds each
# SMB2CreateRequest / SMB2SetInfoRequest / ... and reads the reply status
# itself, rather than going through the library's file-like API -- because a
# model replay has to put exact DesiredAccess / ShareAccess / CreateDisposition
# combinations on the wire and compare the exact NTSTATUS that comes back.
# Pinned: the harness depends on the raw structure field names, which are not
# part of a stability contract -- and on classes that came later.  1.15.0 has
# no smbprotocol.open.SMB2LockElement, so every batch that takes a byte-range
# lock dies with an AttributeError; the harness is developed and tested against
# 1.17.0, and that is what this must track.
ARG SMBPROTOCOL_VERSION=1.17.0
RUN pip3 install --break-system-packages --no-cache-dir \
        "smbprotocol==${SMBPROTOCOL_VERSION}"

RUN if [ "$ENABLE_CLAUDE" = "1" ] ; then \
    npm install -g @anthropic-ai/claude-code ; \
    fi

# Trace generation is deterministic only against the quint release recorded in
# .quint-version, so the image installs exactly that one rather than a floating
# `@latest`.  Copying the file in (build context is the repo root -- see
# devcontainer.json) keeps the pin in ONE place: bumping .quint-version rebuilds
# the image with the matching quint, and there is no second constant to forget.
COPY .quint-version /tmp/.quint-version
RUN npm install -g "@informalsystems/quint@$(cat /tmp/.quint-version)" && \
    quint --version && \
    rm -f /tmp/.quint-version

# quint downloads its Rust evaluator the first time it simulates, into ~/.quint.
# CI runners reach the network through internal mirrors only, so that download
# arrives truncated and every trace generation fails.  Warm the cache here,
# where the network is available and the result is baked into the image.
# Double quotes, so quint's prime operator (n') needs no escaping: inside single
# quotes a backslash is literal and would end the string early.
#
# The closing ls is the check: if the evaluator did not land, fail here where it
# is fixable rather than in every generation job downstream.
RUN printf "module warm {\n  var n: int\n  action init = n' = 0\n  action step = n' = n + 1\n}\n" \
        > /tmp/warm.qnt && \
    { quint run /tmp/warm.qnt --max-steps=1 --max-samples=1 > /dev/null 2>&1 || true ; } && \
    rm -f /tmp/warm.qnt && \
    ls -d /root/.quint/rust-evaluator-*/quint_evaluator

# Samba ships a system-wide default smb.conf and a set of state directories
# under /var/lib/samba.  The harness never uses them: every test writes a
# private smb.conf into its own session directory and points every Samba path
# (private/lock/state/cache/pid/ncalrpc) inside it, so concurrent smbds in
# different namespaces cannot share a TDB.  Disabling the packaged services
# keeps a stray system smbd from ever competing for :445.
RUN systemctl disable smbd nmbd winbind 2>/dev/null || true; \
    rm -f /etc/samba/smb.conf

# Likewise for ganesha and rpcbind: the NFS harness writes a private
# ganesha.conf per test and runs its own rpcbind inside the test's namespace.
# The packaged units must never come up on their own and compete for :2049 /
# :111 on the host network.
RUN systemctl disable nfs-ganesha rpcbind rpcbind.socket 2>/dev/null || true; \
    [ -e /etc/mtab ] || ln -s /proc/self/mounts /etc/mtab

ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8
