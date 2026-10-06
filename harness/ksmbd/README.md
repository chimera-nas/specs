<!--
SPDX-FileCopyrightText: 2026 The Quint Specs Authors
SPDX-License-Identifier: MIT
-->
# ksmbd conformance harness

Replays the generated SMB2 corpus (`quint/smb2`) against **ksmbd**, the Linux
kernel's SMB server, and compares every reply to the result the model baked
into the trace. It is the third SMB server the corpus is replayed against,
after Samba ([`../samba/`](../samba/)) and Windows ([`../windows/`](../windows/)),
and it uses the same replayer.

As with the others, the point is to test the **model**. ksmbd is an
implementation nobody consulted while writing it, and shares no code with
Samba.

## Running

```
ctest --test-dir build -L ksmbd
```

ksmbd is a kernel module, so the server is a KVM guest: the
`chimera-nas/kvm-test-base` image the knfsd suite boots. Configure with
`-DKVM_IMAGE_DIR=<dir with vmlinuz and rootfs.qcow2>`. Without an image,
`/dev/kvm`, qemu or the right to create a network namespace, the tests report
a SKIP.

`run_ksmbd_mbt.sh` is the host side of a TAP link in a network namespace of
its own, which is what lets the cells run concurrently. One guest per cell. A
9p share carries the guest's bring-up script in, and between traces the host
drops a `go` marker, the guest empties the share and answers `done`.

ksmbd's userspace half (`ksmbd.mountd`, `ksmbd.adduser`: the `ksmbd-tools`
package) is in the guest image as of kvm-test-base v1.11.0. For an older
image, `SPECS_KSMBD_DEBS` names a directory of `.deb` files — `ksmbd-tools`
and whatever of its dependencies the image lacks — which the guest unpacks at
boot.

`SPECS_KSMBD_EXEC=<cmd>` runs `<cmd>` against the live guest instead of the
replayer, which is the fastest way to hand-probe a divergence; see the script
header for the rest.

## Three things about this server that are not in the model

**A kernel that oopses.** With `oplocks = no` on the share, an open carries no
oplock state, and a kernel without the fix for CVE-2026-43379 dereferences
that missing state on CLOSE. Ubuntu's 6.8 GA kernel (6.8.0-138) is one: the
first CLOSE of a replay takes the guest down. So the share leaves oplocks at
ksmbd's default, under which an oplock is granted only to an open that asks
for one — which the cells here never do.

**A signature that does not verify.** ksmbd's reply to a READ at end of file
(`STATUS_END_OF_FILE`) carries a signature the client library cannot verify,
and the library drops the connection on one. The runner therefore passes
`--no-signing`, and signatures are **not checked at all** against this server.
That is a hole in what is tested, kept open by a defect in the server.

**No CHANGE_NOTIFY.** ksmbd answers the request inline instead of parking it,
so there is no notify cell.

## What ksmbd does differently

Each is a branch in `quint/smb2/smb2_ops.qnt`, declared with its measurement
in `quint/smb2/corpus.schema.json`. Measured on Linux 6.8.0-138 with
ksmbd-tools 3.5.1.

| id | what ksmbd does | cells |
|----|-----------------|-------|
| KD-1 | a truncating CREATE (supersede, overwrite, overwrite-if) that asks for no write access is not refused by a holder that denies write-sharing: the truncate's write is not arbitrated | core, dir, ns |
| KD-2 | an attribute-only truncating CREATE answers success and leaves the contents untouched; with read or delete access it truncates | core, dir, ns |
| KD-3 | FLUSH does not check the handle's access: success through a read-only or delete-only handle, `STATUS_INVALID_HANDLE` through an attribute-only one | info |

KD-1 and KD-2 change state, and the model follows them: it lets the open
through, and truncates or does not, as ksmbd does.

One policy: `lockAccessCheck` is `false`, as on Windows — a handle with no
data access may take and release byte-range locks.

## The cells

| cell | config | traces | status |
|------|--------|--------|--------|
| `stepCore` | `core.json` | 8 | gates; strict twin in the extended tier |
| `stepDir` | `dir.json` | 8 | gates; strict twin in the extended tier |
| `stepNs` | `ns.json` | 8 | gates; strict twin in the extended tier |
| `stepInfo` | `info.json` | 8 | **reporting only**, extended tier |

### Byte-range locks: reported, not gated

`stepInfo` draws byte-range locks, and ksmbd's differ from the model in more
ways than are modelled yet. A lock the two sides disagree about changes what
every later read, write and truncate over that range does, so the cell
reports rather than gates. Measured directly:

* an exclusive lock on `[64,128)` refuses another handle's exclusive lock on
  the **adjacent** range `[0,64)`;
* a handle may take a shared lock over its own exclusive lock;
* SET_END_OF_FILE is refused `STATUS_FILE_LOCK_CONFLICT` in cases the model
  allows, including a truncate through the handle that holds a shared lock.

Each is a candidate for a modelled deviation, and the first looks like an
off-by-one in the overlap test.

## Scope

The caching-off profile only, as for Samba: no oplock or lease break
lifecycle and no durable handles. The cells that need them are not registered
here.
