<!--
SPDX-FileCopyrightText: 2026 The Quint Specs Authors
SPDX-License-Identifier: MIT
-->
# ext4 conformance harness

Replays the generated POSIX corpus (`quint/posix`) against a real ext4
filesystem, in a KVM guest, and compares every syscall's outcome to the
result the model baked into the trace.

The point is not to test ext4. It is to test the **model**. A model
developed alongside one implementation drifts toward it: the traces keep
passing, and the passing keeps meaning less, because the model and that
implementation can agree on something POSIX never said. The POSIX model was
written against in-memory backends; Linux's ext4 was consulted by nobody who
wrote it, and it is the filesystem everything else in the world is measured
against. Every disagreement is informative -- either the model is wrong, or
ext4 is.

| target | how it runs | suite |
|--------|-------------|-------|
| Linux ext4 | a `kvm-test-base` guest booted per batch, the filesystem a raw image handed over as a second virtio disk; needs `/dev/kvm` and qemu, and SKIPs without them | `posix` (the `ext4_` profile) |

Both outcomes of a disagreement are recorded, and the suite distinguishes
them:

| verdict | meaning |
|---------|---------|
| `model`  | the model diverges from POSIX, or asserts something POSIX leaves to the implementation; ext4 is right |
| `server` | ext4 (or the Linux VFS above it) diverges from POSIX; the model is right |
| `both`   | each is wrong, differently, in the same result |

An unrecorded divergence fails the run. A recorded one does not -- it has a
citation, a root cause, and something that would retire it. The records live
in [`ext4_deviations.py`](ext4_deviations.py); see
[`deviations.py`](deviations.py) for the contract.

## Why a guest

The other conformance harnesses here start a server and speak a protocol at
it. This corpus is not a protocol, it is syscalls, and driving it needs
three things the container the rest of this repo builds in cannot give
reproducibly: a filesystem the harness may mount, a kernel whose sysctls it
may set, and root to fork one process per model credential. A guest makes
the filesystem under test the thing being measured rather than whatever the
CI machine's root filesystem happens to be.

There is no network at all -- unlike the knfsd suite, which boots the same
guest image and drives it over a TAP -- so these tests need no network
namespace and never collide with each other.

## Running

```
ctest --test-dir build -L ext4          # one test per generated batch
```

The suite boots a `chimera-nas/kvm-test-base` guest (the image is fetched by
CI and pointed at with `-DKVM_IMAGE_DIR`). The host builds the filesystem
under test -- `mkfs.ext4 -b 4096` over a 512 MB image, so the block size is
the 4 KiB the model's block symbols expand to -- and hands it to the guest as
a second virtio disk; the harness and the batch's traces arrive on a 9p
share, and the replay runs entirely in-guest. One guest per batch; the
per-trace filesystem reset is the driver's own `newfs`.

Or by hand, against a filesystem already mounted here (as root):

```
harness/posix/run_posix_mbt.sh build/traces/posix 'ext4_stepPerms_*.itf.json'
SPECS_POSIX_LOCAL_ROOT=/mnt/ext4 harness/posix/run_posix_mbt.sh \
    build/traces/posix 'ext4_stepLocks_*.itf.json'
```

Useful environment variables (see the script header for the full list):
`SPECS_POSIX_KEEP=1` keeps the session directory and its serial log,
`SPECS_POSIX_SURVEY=1` reports every divergence in a trace instead of
stopping at the first unreconciled one, `SPECS_POSIX_VERBOSE=1` logs every
replayed step, and `SPECS_POSIX_CHECK_PROFILE=1` measures the live profile
instead of replaying.

## How it runs

**One worker process per model credential.** POSIX ties three things to a
process rather than to a call -- the descriptor table, the umask, and
record-lock ownership -- so a driver that switched credentials per call with
`seteuid` would get the credentials right and all three of those wrong.
`posix_driver.py` forks a real process per model pid, permanently dropped to
that pid's uid/gid/supplementary groups, and routes each request to the
worker its `pid` names.

**Chrooted into the filesystem under test.** The model's root is *the* root:
`/..` is the root itself, and an absolute symlink target names a path from
it. A mount point does not behave that way, so a trace would be resolved
against the host's namespace from the first `..` onward -- silently, and
with the power to create objects outside the filesystem being measured.

**Two mount-time decisions, both to measure the filesystem rather than the
policy above it.** The image is mounted `strictatime`, because under
relatime whether an access is recorded depends on how the previous mtime
compares -- a mount policy, not a filesystem one. And the four
`fs.protected_*` sysctls are turned off in the guest: each of them answers a
call the model is asking ext4 about (a hardlink to a file the caller does not
own, a symlink followed in a sticky directory, an `O_CREAT` over someone
else's file or FIFO in one), and with them on a whole class of traces
measures the sysctl.

## What is checked

Per syscall: the errno, and then the observables the model predicts -- the
descriptor a successful open returns (as a mapping, not a number), file
offsets, read and write counts, `F_GETFL` access mode and `O_APPEND`,
`F_GETLK` conflicts, directory listings, `readlink` targets, and the full
stat: type, mode, owner, link count, size, and identity. Then, at the end of
every trace, a sweep of the whole final tree as root, comparing every
reachable object's attributes, directory contents, link target and *content*
against the model -- which is what catches the state drift no single
operation observed.

Four things a naive replay would get wrong:

* **Identity.** The model's inode numbers are symbolic; `st_ino` is the
  filesystem's. The harness learns each binding from the stat that reveals
  it and checks that the mapping is a *bijection*: two results the model
  calls the same object must land on the same `(st_dev, st_ino)`, two it
  calls different must not.
* **Content.** The model abstracts a file's bytes to a block map, so exact
  content is verified against a byte-accurate shadow instead. A write stamps
  offset-derived, always-nonzero bytes, so a hole (zero) is distinguishable
  from data and any off-by-N is caught. The shadow is keyed by the model's
  inode, which is never reused, so dup, hard link, rename and
  unlink-with-an-open-descriptor all share content for free.
* **Timestamps.** Never predicted. What is checked is *consistency*: for one
  object, an unchanged model instant must observe an unchanged wire value,
  and an advancing one must not go backwards. Explicit `utimensat` values are
  the exception -- those map to fixed instants and are checked exactly.
* **The capability profile.** POSIX leaves a long list of choices to the
  implementation, and the model draws one profile per trace. The pinned
  profile in `posix_replay.py` is a *measurement* (`--check-profile`
  re-measures it), and `posix_run.qnt`'s `posixExt4` instance pins the same
  values, so generation and replay agree and no trace is skipped for a
  mismatch. `ctest -R ext4/profile` is what fails if that stops being true.

## What it found

Replaying 76 traces -- roughly 10,000 syscalls -- found 15 disagreements.

Two were plain model bugs with no defensible other side, and are fixed here:

* `lockf(F_TEST)` and `lockf(F_ULOCK)` do not need a descriptor open for
  writing. XSH `lockf`'s EBADF condition names `F_LOCK` and `F_TLOCK` only,
  and the model applied it to all four commands.
* On the create path an existing final component is `EEXIST` whatever the
  trailing slash says. The model let the trailing-slash rule of pathname
  resolution answer first, so `mkdir("f/")` over an existing file was
  `ENOTDIR` where Linux says `EEXIST` -- as it does for `mkdir("dangling/")`
  and `symlink(t, "f/")` too.

The other thirteen are in [`ext4_deviations.py`](ext4_deviations.py), nine of
them the model's and four ext4's. The largest group is *order of checks*:
POSIX lists a call's error conditions without ordering them, and Linux
consistently judges the destination and its permissions before the source
and its type, where the model does the reverse (`EXT4-6` unlink/rmdir,
`EXT4-7` rename, `EXT4-8` link). The rest are single facts worth having
written down -- `mkdir` does not take the set-id bits from its mode
(`EXT4-1`), an allocated-but-unwritten extent reads as a hole (`EXT4-5`), a
mixed `UTIME_NOW`/`UTIME_OMIT` pair takes the owner-only tier (`EXT4-9`),
`lockf(F_TEST)` probes with a read lock (`EXT4-13`).

None of the thirteen has been patched into the model. Each entry names the
change that would retire it, and says why it is a choice rather than a bug:
the corpus has other consumers, a model change regenerates all of it, and
several of these are cases where both readings conform.
