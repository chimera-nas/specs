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

Both outcomes are recorded, and the suite distinguishes them:

| verdict | meaning |
|---------|---------|
| `model` | the model diverges from the standard; Samba is right |
| `samba` | Samba diverges from the standard; the model is right |
| `both`  | each is wrong, differently, in the same reply |

An unrecorded divergence fails the run. A recorded one does not — it has a
citation, a root cause, and something that would retire it.

## Running

```
ctest --test-dir build -L samba            # one test per generated batch
```

Or by hand:

```
harness/samba/run_samba_mbt.sh build/traces/smb2 'smb2Base_stepCore_*.itf.json'
```

Each run stands up its own throwaway `smbd` — a private `smb.conf` in a session
directory with every Samba path (private/lock/state/cache/pid/ncalrpc) pointed
inside it, so concurrent instances share no TDB and nothing touches the system
configuration. Server and client both run inside a private network namespace,
which is what lets the batches run concurrently: each instance binds
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

This suite has found nine. **Five were model bugs**, and that is the result
that justifies the exercise: they were invisible while the corpus only ever ran
against the implementation the models grew up with, and each one was a place
where the model and that implementation had quietly agreed on something the
standard never said.

All five are fixed in the model. Chimera shared all five and has fixed four of
them; the fifth, SD-7, is a data-loss bug whose fix is an async-chain
restructure, so chimera records it as CD-3 in
`src/server/smb/tests/quint/smb2_mbt_deviations.h` rather than carrying a
half-done fix. What the models now assert is the standard, and what remains
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
armed; with no registry entry to excuse it, a recurrence is now a hard failure.

### Live — Samba deviates

| id | what Samba does |
|----|-----------------|
| SD-2 | refuses a LOCK on a handle with no data access with `STATUS_INVALID_HANDLE` instead of `STATUS_ACCESS_DENIED` |
| SD-4 | checks the rename destination for a collision *before* checking the handle holds DELETE, so a rename failing both ways reports the collision |
| SD-5 | `FILE_CREATE` onto an existing *directory* opened `FILE_NON_DIRECTORY_FILE` reports `FILE_IS_A_DIRECTORY` instead of the collision — and asymmetrically, since the mirror case reports the collision |
| SD-8 | a handle whose CREATE actually created or overwrote the file may take byte-range locks with no data access: the lock path consults the descriptor Samba opened for write, not the SMB GrantedAccess |
| SD-9 | the LOCK access check is applied to a lock request but not to an unlock request |

SD-2, SD-8 and SD-9 are three distinct faults in one code path — the wrong
status from the check, the wrong thing consulted by the check, and the check not
running at all — which is why they are three entries rather than one.

### The run as it stands

The corpus is generated unconditionally -- every instance and flavor -- so it
contains batches this harness cannot drive. Those report a ctest SKIP naming
the capability, which keeps the gap attributable to the harness rather than
hidden in traces nobody generated.

| batch | traces | reached the end | recorded divergences |
|-------|--------|-----------------|----------------------|
| `stepCore` | 8 | 8 | none |
| `stepReq`  | 8 | 8 | none |
| `stepDir`  | 8 | 8 | SD-5 ×87 |
| `stepInfo` | 8 | 0 | SD-2, SD-8, SD-9 |
| `stepNs`   | 8 | 8 | SD-4 ×192 |
| `leases`   | 8 | — | SKIP: needs the oplock/lease break lifecycle |
| `forceL2`  | 8 | — | SKIP: needs the oplock/lease break lifecycle |
| `durable`  | 8 | — | SKIP: needs durable handles |
| `replay`   | 8 | — | SKIP: needs durable handles |

Before the model fixes, **no** batch ran a single trace to the end. Four now
run all eight, which is the clearest measure of what those bugs were costing:
the suite was stopping in the first tens of steps of a 500-step trace.

The four skipped batches are the harness's own limit, not a finding about
Samba: the break-and-acknowledge lifecycle and the durable reconnect are not
implemented here. Implementing them is what would retire those SKIPs.

### A note on coverage

`stepInfo` still abandons every trace, on SD-8's non-reconcilable arm: when
Samba grants a lock the model refused, it holds a range the model knows nothing
about, and every later read and write over that range would report the
consequence rather than a finding. The run summary always reports how many
traces reached the end, so this figure stays visible rather than implied.

It is deliberately not worked around in the harness. Reconciling would mean
either fabricating server state or teaching the harness to track which ranges
and files the two sides disagree about — both of which trade the harness's
trustworthiness for a coverage number.

## Scope

The registered corpus is the `smb2Base` instance: caching off, so no
oplock/lease grant, break or acknowledgment lifecycle, and no durable handles.
The harness sends the oplock and lease *request* contexts as written (the
lease-key binding rule is enforced on the request, not on the grant), but the
break/ack and durable-reconnect commands are not implemented — they occur only
in instances that are not generated. They raise a clearly-labelled harness limit
rather than silently passing.

The corpus's namespace is flat: every CREATE targets the share root and the
names are `a`, `b`, `c`. The harness asserts that rather than ignoring the
model's `dir`, so a future nested corpus turns into a loud harness limit instead
of a wrong path on the wire.
