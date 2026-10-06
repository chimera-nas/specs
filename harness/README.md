<!--
SPDX-FileCopyrightText: 2026 The Quint Specs Authors
SPDX-License-Identifier: MIT
-->
# Replay harnesses

A consuming project normally brings its own replay harness and drives the
generated corpus at its own server (see the top-level README). What lives here
is different, and serves this repo rather than a consumer:

**a harness that replays the corpus against a third-party server, to test the
models themselves.**

A model written alongside one implementation drifts toward that
implementation. The traces still pass, and the passing means less and less:
the model and the server can agree on something the standard never said.
Replaying the same corpus against an unrelated server is the cheapest way to
find out. Every disagreement is a finding — a model bug, or a genuine
divergence in that server — and both are worth having written down.

| harness | server under test | suite |
|---------|-------------------|-------|
| [`samba/`](samba/) | Samba `smbd` | `quint/smb2` |
| [`nfs/`](nfs/) | NFS-Ganesha `ganesha.nfsd`; the Linux kernel NFS server (knfsd) in a KVM guest | `quint/nfs` (nfs3, nfs4) |
| [`windows/`](windows/) | the Windows SMB server, on Windows Server 2025 and Windows 11 | `quint/smb2` |
| [`ksmbd/`](ksmbd/) | ksmbd, the Linux kernel SMB server, in a KVM guest | `quint/smb2` |
| [`s3/`](s3/) | MinIO (the last AGPLv3 community release, built from `chimera-nas/minio`) | `quint/s3` |

Only the third-party servers' records live here. A consuming project's own
divergences belong in that project, next to the code that has to change --
and because the corpus is generated unconditionally, nothing about one
server's behavior is encoded in what gets generated for everyone.

## samba

`ctest -L samba` replays the generated SMB2 corpus against a private Samba
instance. See [`samba/README.md`](samba/README.md) for how it runs, what it
checks, and the divergences found so far.

## nfs

`ctest -L ganesha` replays the generated NFSv3 and NFSv4 corpora against a
private NFS-Ganesha instance per trace; `ctest -L knfsd` replays the same corpus
against the Linux kernel NFS server booted in a KVM guest. See
[`nfs/README.md`](nfs/README.md).

## ksmbd

`ctest -L ksmbd` replays the SMB2 flavours against the Linux kernel's SMB
server, in the KVM guest the knfsd suite boots. See
[`ksmbd/README.md`](ksmbd/README.md).

## windows

The same SMB2 flavours the samba suite replays, against the Windows SMB server
itself. It runs on a Windows machine rather than through ctest; see
[`windows/README.md`](windows/README.md).

## s3

`ctest -L minio` replays the generated S3 corpus against a private MinIO, a
fresh one per trace. See [`s3/README.md`](s3/README.md) for how it runs, what
it checks, and the divergences found so far.
