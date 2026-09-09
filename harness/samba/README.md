<!--
SPDX-FileCopyrightText: 2026 The Quint Specs Authors
SPDX-License-Identifier: MIT
-->
# Samba conformance harness

Replays the generated SMB2 corpus (`quint/smb2`) against a real Samba `smbd`
and compares every reply to the result the model baked into the trace.

The point is not to test Samba. It is to test the **model**. A model developed
alongside one implementation drifts toward it: the traces keep passing, and the
passing keeps meaning less, because the model and that server can agree on
something the standard never said. Samba is an implementation nobody consulted
while writing these models, so every disagreement is informative — either the
model is wrong, or Samba is.

A model bug is fixed in the model. A **Samba** divergence is written into the
model as a branch guarded on the cell's config, so the model predicts what this
smbd actually does, the trace's expectation is already the truth, and replay is
an exact match. Every such branch is declared with its measurement and citation
in `quint/smb2/corpus.schema.json`, switched on per cell by
`harness/samba/configs/*.json`, and kept honest by `tools/devliveness.py`,
which fails a cell that claims a deviation its own corpus never reaches — so an
entry cannot outlive its fix.

The harness therefore has **no notion of a forgivable difference**, with one
exception: three CHANGE_NOTIFY divergences (SD-10, SD-11, SD-12) cannot be
expressed in the model and are still forgiven from
`samba_deviations.py`, which explains why. Everything else that differs fails.

## Running

```
ctest --test-dir build -L samba            # one test per cell
ctest --test-dir build -C extended -L strict   # ... plus the strict twins
```

A **cell** is one config in `configs/`: it binds every constant the smb2 model
declares — which capabilities this smbd advertises, which of its known
divergences the model is told to predict — and carries the one batch it
replays. The cell then replays its whole trace directory: no filename carving,
no per-trace skipping. Four cells also get a *strict* twin, the same profile
with every deviation forced off; that one is reporting rather than gating (it
is exactly Samba's conformance debt, re-measured every run) and lives in the
extended tier.

Or by hand:

```
harness/samba/run_samba_mbt.sh build/specs-corpus/samba/smb2/stepCore
```

Each run stands up its own throwaway `smbd` — a private `smb.conf` in a session
directory with every Samba path (private/lock/state/cache/pid/ncalrpc) pointed
inside it, so concurrent instances share no TDB and nothing touches the system
configuration. Server and client both run inside a private network namespace,
which is what lets the cells run concurrently: each instance binds
`127.0.0.1:445` in its own namespace, so there is no port to broker. Without
`CAP_NET_ADMIN` the tests still run, serialized by CMake under one
`RESOURCE_LOCK`.

Useful environment variables (see the script header for the full list):
`SPECS_SAMBA_KEEP=1` keeps the session directory, `SPECS_SAMBA_SURVEY=1` reports
every divergence in a trace instead of stopping at the first unrecorded one, and
`SPECS_SAMBA_EXEC=<cmd>` runs `<cmd>` against the live instance instead of the
replayer — the fastest way to hand-probe a divergence.

## What is checked

Per command: the NTSTATUS, and then the observables the model predicts —
`CreateAction`, that a caching-off profile granted no oplock, read byte counts
and the actual block contents, write counts, and the `FileStandardInformation`
quadruple (size, link count, delete-pending, directory).

Two things are checked that a naive replay would miss:

* **Handle identity.** The model's inode numbers are symbolic and Samba's are
  whatever the backing filesystem hands out, so they are not compared for
  equality. What is compared is that the mapping between them is a *bijection*:
  two opens the model calls the same object must land on the same on-disk id,
  and two it calls different must not. That is what catches a disposition arm
  that silently reuses an object's identity, or silently replaces it. The id
  arrives in the CREATE reply itself (the `QFid` create context), so it costs no
  extra round trip and cannot race the CLOSE that so often follows a CREATE in
  the same compound chain.
* **Compound chains.** A related compound is sent as one message with the
  all-`0xFF` FileId threading, exactly as the model describes it. The model
  truncates its result list at a chain's first error; the harness sends the
  prefix that has results, so every request is one the model expects an answer
  for.

The model's `change` counter is deliberately **not** asserted: no wire field
carries a comparable value (`ChangeTime` is a timestamp, not a monotonic count).

## Divergences found

This suite has found twelve. **Five were model bugs**, and that is the result
that justifies the exercise: they were invisible while the corpus only ever ran
against the implementation the models grew up with, and each one was a place
where the model and that implementation had quietly agreed on something the
standard never said.

All five are fixed in the model. Chimera shared all five and has fixed four of
them; the fifth, SD-7, is a data-loss bug whose fix is an async-chain
restructure, so chimera records it as CD-3 in its own cell configs
(`src/server/smb/tests/quint/configs/*.json`) rather than carrying a half-done
fix. What the models now assert is the standard, and what remains
here is Samba.

### Fixed in the model — retired

| id | what the model had wrong |
|----|--------------------------|
| SD-1 | FLUSH succeeded on a handle with no write access |
| SD-3 | an attribute-only CREATE with a *truncating* disposition skipped share arbitration, discarding the write `wantOf()` had just added |
| SD-6 | the lease-key-to-file binding was enforced on a profile advertising no leasing |
| SD-7 | a truncating CREATE refused with a sharing violation still truncated the file — a failed open with a side effect |
| SD-2 (model half) | LOCK was granted on a handle with neither read nor write access |

SD-7 is worth singling out. Both sides answered `STATUS_SHARING_VIOLATION`, so
the status comparison saw nothing — the divergence was silent, and surfaced
dozens of steps later as a read that should have returned data. The oracle that
caught it compares the model's own post-state against the server and is still
armed; with nothing left that could excuse it, a recurrence is now a hard
failure.

### Live — Samba deviates, and the model predicts it

Each of these is a guarded branch in `quint/smb2/smb2_ops.qnt`, switched on by
the cells named below. Their measurements and citations are in
`quint/smb2/corpus.schema.json`.

| id | what Samba does | model | cells |
|----|-----------------|-------|-------|
| SD-2 | refuses a LOCK on a handle with no data access with `STATUS_INVALID_HANDLE` instead of `STATUS_ACCESS_DENIED` | `devLockRefuseSt` | `stepInfo` |
| SD-4 | checks the rename destination for a collision *before* checking the handle holds DELETE, so a rename failing both ways reports the collision | `devRenameSd4` | `stepNs` |
| SD-5 | `FILE_CREATE` onto an existing *directory* opened `FILE_NON_DIRECTORY_FILE` reports `FILE_IS_A_DIRECTORY` instead of the collision — and asymmetrically, since the mirror case reports the collision | `devCreateSd5` | `stepDir`, `notify` |
| SD-8 | a handle whose CREATE actually created or overwrote the file may take byte-range locks with no data access: the lock path consults the descriptor Samba opened for write, not the SMB GrantedAccess | `devLockSd8`, via `Open.createAct` | `stepInfo` |
| SD-9 | the LOCK access check is applied to a lock request but not to an unlock request | `devLockSd9` | `stepInfo` |

SD-2, SD-8 and SD-9 are three distinct faults in one code path — the wrong
status from the check, the wrong thing consulted by the check, and the check not
running at all — which is why they are three entries rather than one.

A deviation is enabled only in the cells whose flavour can actually *reach* it:
locks are drawn only by `stepInfo` and SET_INFO renames only by `stepNs`, so
the other cells switch it off with `deviationsOff`. That is a statement about
coverage, not about the server — a branch a corpus never takes changes not one
byte of it — and it is what lets the liveness gate mean something.

### Live — Samba deviates, and the model CANNOT predict it

| id | what Samba does |
|----|-----------------|
| SD-10 | raises a different set of change classes than MS-FSA for writes, closes and creates |
| SD-11 | treats the CompletionFilter of the FIRST CHANGE_NOTIFY on a handle as binding for the life of the handle |
| SD-12 | reports the old name of an intra-directory rename as `FILE_ACTION_REMOVED` as well as the `RENAMED_OLD_NAME`/`RENAMED_NEW_NAME` pair |

These three stay in `samba_deviations.py`. All three are blocked by the same
thing: Samba delivers one model-level mutation as *several* completions, and
the model buffers events through a message and drains each watch once at the
end of it, identifying a completion by (handle, queue position). SD-10's write
and create faces additionally turn on DOS-attribute state the model does not
carry. Guessing at either would make every `stepNotify` trace wrong, so they
are left enumerable instead — which is also why the `stepNotifyNs` flavour,
the namespace subset the two sides agree on exactly, still exists.

### The cells

A cell is registered for every flavour the model generates, including the four
whose profile turns a caching capability on and which this harness cannot
drive. Those report a ctest SKIP naming the capability, which keeps the gap
attributable to the harness rather than hidden in traces nobody generated.

| cell | config | traces | deviations enabled | strict twin |
|------|--------|--------|--------------------|-------------|
| `stepCore` | `core.json` | 8 | none | it *is* the strict corpus |
| `stepReq`  | `req.json` | 8 | none | it *is* the strict corpus |
| `stepDir`  | `dir.json` | 8 | SD-5 | yes |
| `stepInfo` | `info.json` | 8 | SD-2, SD-8, SD-9 | yes |
| `stepNs`   | `ns.json` | 8 | SD-4 | yes |
| `notify`   | `notify.json` | 8 | SD-5 | yes |
| `notifyNs` | `notify_ns.json` | 6 | none | it *is* the strict corpus |
| `leases`   | `leases.json` | 8 | — | SKIP: needs the oplock/lease break lifecycle |
| `forceL2`  | `force_l2.json` | 8 | — | SKIP: needs the oplock/lease break lifecycle |
| `durable`  | `durable.json` | 8 | — | SKIP: needs durable handles |
| `replay`   | `replay.json` | 8 | — | SKIP: needs durable handles |

The four SKIPped cells enable no deviation and get no strict twin: nothing
replays them, so there would be no claim to check and the twin would be a
byte-identical second corpus. The three driveable cells that reach no deviation
need no twin either — their own corpus already states the standard, so they
*gate* on conformance rather than reporting it.

The four skipped cells are the harness's own limit, not a finding about Samba:
the break-and-acknowledge lifecycle and the durable reconnect are not
implemented here. Implementing them is what would retire those SKIPs.

### A note on coverage

`stepInfo` used to abandon every trace on SD-8's non-reconcilable arm: Samba
granted a lock the model had refused, so it held a range the model knew nothing
about and every later read and write over that range would report the
consequence rather than a finding. Modelled, the model takes the same lock, and
the trace keeps testing — which is the point of moving a deviation out of a
registry and into the model: a *state-mutating* divergence becomes expressible,
where a registry could only abandon it.

`notify` still abandons on SD-10 or SD-11 within a few dozen steps of a
400-step trace, for the reason given above. The run summary always reports how
many traces reached the end, so that figure stays visible rather than implied.

## Scope

The cells this harness actually drives are the caching-off profile
(`configs/_smbd.json`, which the seven flavour configs extend): no oplock/lease
grant, break or acknowledgment lifecycle, and no durable handles — matching the
`oplocks = no` / `durable handles = no` smb.conf the runner generates. The
harness sends the oplock and lease *request* contexts as written (the lease-key
binding rule is enforced on the request, not on the grant), but the break/ack
and durable-reconnect commands are not implemented, so the four cells whose
profile needs them SKIP. They raise a clearly-labelled harness limit rather
than silently passing.

The corpus's namespace is flat: every CREATE targets the share root and the
names are `a`, `b`, `c`. The harness asserts that rather than ignoring the
model's `dir`, so a future nested corpus turns into a loud harness limit instead
of a wrong path on the wire.
