<!--
SPDX-FileCopyrightText: 2026 The Quint Specs Authors

SPDX-License-Identifier: MIT
-->

# The auxiliary NFS protocols

A model of the four RPC protocols that surround NFSv3 and make it usable:

| program | version | protocol | source |
|---------|---------|----------|--------|
| 100000  | 2, 3, 4 | portmap / rpcbind | RFC 1833 |
| 100005  | 3       | MOUNT | RFC 1813 Appendix I |
| 100021  | 4       | NLM, the network lock manager | RFC 1813 Appendix II / X/Open NFS |
| 100024  | 1       | NSM, the network status monitor ("sm_inter") | the de-facto `rpc.statd` interface |

## Why one model and not four

They are not independent, and the interesting behaviour is in the seams:

* a granted NLM lock puts its holder on the NSM monitor list, so the server
  can tell it to reclaim after a restart;
* an `SM_NOTIFY` says a peer rebooted, which makes every lock that peer held
  stale — and dropping those locks can let queued blocking requests through;
* `NLMPROC4_FREE_ALL` does both at once;
* and the portmapper is how a client finds the lock manager to begin with.

A trace that can move between the four exercises those seams. Each protocol's
own semantics still live in its own file — `aux_portmap.qnt`, `aux_mount.qnt`,
`aux_nlm.qnt`, `aux_nsm.qnt` — each complete with respect to its RFC. The
composing module `nfsaux.qnt` holds the state, the transition relation, and the
configuration.

## Full protocols, gated profiles

Servers implement subsets. A server that embeds a minimal portmapper registers
`GETPORT`, `DUMP` and `GETADDR` and nothing that would let a client rewrite the
service table; `PMAPPROC_SET`, `CALLIT`, `GETTIME` and the rest are simply not
there.

Unimplemented does not mean untested. The `IMPLEMENTED` configuration names the
procedures a server registers, and a procedure outside it is **still called by
the traces** — the expected reply just becomes the RPC layer's `PROC_UNAVAIL`
(RFC 5531 `accept_stat` 3) instead of the protocol's own result. Nothing is
dropped from the corpus for being unimplemented; the refusal is under test too,
and so is the dispatcher path that produces it.

The remaining configuration constants are choices where more than one answer is
legitimate. Each is documented at its declaration in `nfsaux.qnt`; the ones that
bite hardest:

* `NLM_UPGRADE_IS_NOOP` — whether a `LOCK` naming a range its own owner already
  holds is answered as an idempotent retry without re-evaluating the mode, so a
  shared-to-exclusive upgrade silently does not happen.
* `NSM_ADDRS_DISTINCT` — whether monitored peers are distinguishable by source
  address. When they are not, `SM_NOTIFY`'s fallback match is indiscriminate and
  one peer's reboot drops everyone's locks.
* `NLM_SHARE_ENFORCED` — whether DOS share reservations are honoured or merely
  accepted.
* `NLM_IN_GRACE` — whether the server is inside its post-restart reclaim window.

A trace generated under one profile must only be replayed against a server
matching it. `nfsaux_run.qnt` holds the profiles: `nfsauxRef` is the one the
corpus is generated from, `nfsauxFull` registers everything so the RFC semantics
of the refused procedures stay under test, and `nfsauxGrace` is the reference
profile inside its grace window.

## Running

```sh
quint test --main=nfsauxTestRef   nfsauxTest.qnt
quint test --main=nfsauxTestFull  nfsauxTest.qnt
quint test --main=nfsauxTestGrace nfsauxTest.qnt

quint run nfsaux_run.qnt --main=nfsauxRef --step=step --invariant=inv
```

`--step` selects a flavour: `stepPortmap`, `stepMount`, `stepLocks`,
`stepAsync`, `stepBlocking`, `stepRecovery`, `stepShare`, or the mixed `step`.
The per-protocol flavours keep a divergence legible; the mixed one reaches the
seams. `coverage.py` gates the generated corpus on the behaviour buckets the
model is meant to cover, so a starved corner goes red rather than passing
vacuously.

## Things the model pins that are easy to get wrong

Each of these is a scenario test in `nfsauxTest.qnt`, and several were only
settled by measuring a live server:

* `GETPORT` matches the exact `(prog, vers, prot)` triple or returns 0 — no
  fallback to a sibling version, which is where RFC 1833 and classic BSD
  portmap part company.
* An export name must match at a **path-component boundary**: `/shareXX` does
  not resolve under the export `/share`.
* `MNT` records its mount-table row as soon as an export matches, **before**
  the resolved path is looked up — so a `MNT` that ends in `NOENT` still leaves
  a row behind. And `MNT` does not type-check the object: mounting a regular
  file succeeds.
* An NLM owner is the triple `(caller_name, oh, svid)`. Two processes on one
  client with one owner handle are two owners.
* RFC 1813 gives to-EOF two wire spellings, `l_len = 0` and
  `l_len = 0xffffffffffffffff`. A lock taken with one is released by the other.
* `UNLOCK` answers `GRANTED` whether or not it found anything.
* A client's table entry outlives its locks, which changes which path a later
  `SM_NOTIFY` for that name takes.
* Releasing a client's locks is **not atomic** with respect to the wait queue:
  the locks go one at a time with a pump after each, so a waiter whose range is
  satisfied by a partial release is granted ahead of a wider waiter that is
  still blocked — and the wider one then finds the narrow one in its way.
