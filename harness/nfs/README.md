<!--
SPDX-FileCopyrightText: 2026 The Quint Specs Authors
SPDX-License-Identifier: MIT
-->
# NFS conformance harness

Replays the generated NFSv3 corpus (`quint/nfs/nfs3.qnt`) and NFSv4 corpus
(`quint/nfs/nfs4*.qnt`) against a real third-party NFS server and compares
every reply to the result the model baked into the trace.

The point is not to test the server. It is to test the **models**. A model
developed alongside one implementation drifts toward it: the traces keep
passing, and the passing keeps meaning less, because the model and that
server can agree on something the RFCs never said. The servers driven here
were consulted by nobody who wrote the NFS models, so every disagreement is
informative — either the model is wrong, or the server is.

| server | how it runs | suites |
|--------|-------------|--------|
| NFS-Ganesha (`ganesha.nfsd`, userspace) | in the devcontainer, one fresh instance per trace in a private network namespace, exporting a loop-mounted ext4 image through the VFS FSAL | `nfs3`, `nfs4`, `nfs4pnfs` |
| Linux knfsd | a `kvm-test-base` guest booted per batch (needs `/dev/kvm`) — *not wired yet; the batches report SKIP* | `nfs3`, `nfs4` |

Both outcomes of a disagreement are recorded, and the suite distinguishes
them:

| verdict | meaning |
|---------|---------|
| `model`  | the model diverges from the RFC; the server is right |
| `server` | the server diverges from the RFC; the model is right |
| `both`   | each is wrong, differently, in the same reply |

An unrecorded divergence fails the run. A recorded one does not — it has a
citation, a root cause, and something that would retire it. The records live
next to the harness: [`ganesha_deviations.py`](ganesha_deviations.py) and
[`knfsd_deviations.py`](knfsd_deviations.py); see
[`deviations.py`](deviations.py) for the contract.

## Running

```
ctest --test-dir build -L ganesha         # one test per generated batch
```

Or by hand:

```
harness/nfs/run_nfs_mbt.sh ganesha nfs4 build/traces/nfs4 'nfs4Memfs40_step_*.itf.json'
harness/nfs/run_nfs_mbt.sh ganesha nfs3 build/traces/nfs3 'stepExcl_*.itf.json'
```

Every trace gets a **fresh server**: a model trace starts from an empty root
and no protocol state, and starting the server over is the only way to give
it exactly that — no leftover clientids, no orphaned opens pinning a file the
model has forgotten, no stale directory cache. Ganesha starts in well under a
second and the batches run concurrently, so the restarts are not what the
wall clock is made of.

Useful environment variables (see the script header for the full list):
`SPECS_NFS_KEEP=1` keeps the session directory, `SPECS_NFS_SURVEY=1` reports
every divergence in a trace instead of stopping at the first unrecorded one,
`SPECS_NFS_SERVER_LOG=1` prints the server log after a failed trace, and
`SPECS_NFS_EXEC=<cmd>` runs `<cmd>` against one live instance instead of the
replayer — the fastest way to hand-probe a divergence.

## What is checked

**NFSv4** — per operation: the status, and then the observables the model
predicts: stateid seqids, `OPEN4_RESULT_CONFIRM`, delegation type, read
payloads and `eof`, write and copy counts, `SEEK` results, `READ_PLUS`
segment classification (as a legal prefix of the model's answer), directory
listings, `ACCESS` masks, xattr values and lists, layout coverage. Then the
compound status and result count.

**NFSv3** — per procedure: the status, then the post-op attributes against
the model's post-state (type, mode, link count, size), read payloads,
write/commit verifiers, listings, `ACCESS` masks. `FSSTAT`, `FSINFO` and
`PATHCONF` are held to the RFC's ordering invariants only, never to a
server's constants.

Three things a naive replay would get wrong:

* **Identity.** The model's inode numbers, clientids, sessionids and
  stateids are symbolic; the wire values are whatever the server hands out.
  The harness learns each binding from the reply that creates it (GETFH,
  EXCHANGE_ID, CREATE_SESSION, OPEN, LOCK…) and checks that the mapping is a
  *bijection*: two results the model calls the same object must land on the
  same wire value, two it calls different must not.
* **The change attribute.** Never predicted. What is checked is
  *consistency*: for one object, equal abstract change values must observe
  equal wire values and distinct ones distinct — and `change_info4` lives in
  the same domain (RFC 7530 §2.2.6: its values *are* the change attribute).
* **Capabilities.** A third-party server owes the model nothing about which
  optional features it implements. The first divergence that matches a
  capability pattern (NOTSUPP for a 4.2 op family, a delegation granted or
  withheld, DELAY-vs-block on a recall conflict, CLOSE frees-locks vs
  LOCKS_HELD, the EXCHANGE_ID pNFS flag) marks the trace not applicable and
  it is reported as a SKIP, never a failure.

Two things the standards leave open are deliberately **not** asserted: a
symlink's permission bits, and the mode of an EXCLUSIVE-created file before
its follow-up SETATTR.

## Divergences found

*(filled in as the suite is triaged — see the registries)*
