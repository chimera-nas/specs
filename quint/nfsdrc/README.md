<!--
SPDX-FileCopyrightText: 2026 The Quint Specs Authors

SPDX-License-Identifier: MIT
-->

# nfsdrc — the NFSv3 and NFSv4.0 duplicate-request caches

A server that executes a non-idempotent request twice has corrupted the
client's view of the filesystem. The second CREATE of a name the first one made
answers EXIST; the second REMOVE answers NOENT; and the client — which cannot
tell a lost reply from a lost request — concludes its operation failed when it
succeeded. Neither NFSv3 nor NFSv4.0 has in-protocol sequencing to prevent
that, so both rely on the server remembering its recent replies and re-sending
one instead of re-executing. That memory is the duplicate-request cache, and
this suite is about whether it remembers the right things.

## Why one model for two caches

They exist for the same reason and are told apart by one decision: what an
entry belongs to.

| | NFSv3 | NFSv4.0 |
|---|---|---|
| scope | source address | connection |
| survives a reconnect | yes, and must | no, and must not |
| shared by two users behind one address | yes | only if they share a connection |
| lifetime | none — entries are evicted by size | the connection's |

The interesting traces are the ones that move between them: the same reconnect
that makes an address-scoped entry answer makes a connection-scoped one
disappear, and a suite that could only do one of those would be asserting half
of each rule. That is why `reconnect` is a step and not a fixture.

## What the model says a cache must do

Everything follows from what counts as "the same request":

1. A retransmit — the same requester, re-presenting the same call under the
   same identity — MUST be answered with the reply the original produced, and
   MUST NOT execute.
2. Anything else MUST NOT be answered from the cache.

Rule 2 is where the work is, because the cache has to decide identity from what
the wire carries. `drc_cache.qnt` breaks the key into the three clauses of that
rule — **scope** (who), **call** (which request, procedure and argument digest
separately), **cred** (on whose behalf) — and every one of them is a place a
real server has got it wrong. The suite's negative steps are one per clause:
the same bytes at a different XID, under a different procedure, from a
different connection, under a different credential.

The credential clause deserves a note because the RFCs are silent on it for
these two protocols. RFC 8881 Section 2.10.6.1.3.1 spells it out for the
NFSv4.1 reply cache — a retry "that uses a different principal in the RPC
request's credential field that translates to a different user" is a false
retry, and the replier MUST NOT answer it from the cache. Nothing says
otherwise for v3 or v4.0; the hazard is identical, and the RFCs simply do not
discuss a reply cache at all. The model requires it, and
`nfsdrcCredBlind` keeps the other answer under test so that what it costs stays
written down.

## Files

| file | what is in it |
|---|---|
| `drc_cache.qnt` | what a cache is: keys, entries, lookup, insert, eviction, and the connection-close rule |
| `drc_ops.qnt` | the filesystem the requests act on, and each operation's semantics |
| `nfsdrc.qnt` | state, transitions, configuration |
| `nfsdrc_run.qnt` | the four profiles |
| `nfsdrcTest.qnt` | deterministic self-checks, one per property |
| `coverage.py` | the corpus gate |

## Profiles

* **`nfsdrcRef`** — the reference: the NFSv3 cache on, one address for every
  connection, credentials in the key. The corpus.
* **`nfsdrcNoV3`** — the same server with the NFSv3 cache off, which is the
  shipped default. Its whole job is to show the switch is real.
* **`nfsdrcTwoAddr`** — two connections from two addresses, so an
  address-scoped entry has something not to cross. No loopback or in-process
  transport can produce this, so it is `quint test` only.
* **`nfsdrcCredBlind`** — a server that checksums only the procedure arguments
  and so cannot tell two users' identical requests apart. Also `quint test`
  only.

## The filesystem is as small as it can be

Two requirements, and nothing else:

* every cacheable operation must have a state in which running it twice answers
  differently. Otherwise the cache is invisible — a re-executed idempotent
  request and a replayed one are the same reply, and no trace could tell a
  working cache from an absent one. Each operation is used in exactly that
  state, which is also why every creating request is exclusive (GUARDED CREATE,
  MKDIR, SYMLINK) rather than UNCHECKED.
* the directory's contents after every step must be predictable, because
  comparing them is what catches a cache that returned the right status from
  the wrong entry. The replay harness re-reads it after every step under
  `--paranoid`.

Objects have identities, not just names. A filehandle names an object: a hard
link shares one, a rename carries one, and a name created again after a removal
gets a different one. A model that identified objects by name would call two
different requests the same one.

## What is deliberately not here

* **A fresh request on a filehandle whose object is gone.** The model answers
  it (NFS3ERR_STALE, RFC 1813 Section 3.3) but the traces never ask, because
  what a live server answers depends on whether the handle is still in its own
  handle cache — a timing question, and a corpus that walked into it would be
  flaky for a reason unrelated to a cache. The property that matters, that a
  *retransmit* carrying such a handle replays rather than re-resolving, is
  asserted in the harness's ground-truth probe where it is deterministic.
* **The NFSv4.1 session reply cache.** A different mechanism — a slot table
  with sequence numbers rather than a key over transport identity — and it
  belongs with the sessions, in the nfs4 model.
* **Persistence.** Both caches can be written through to a KV store so that a
  retransmit survives a server restart. That needs a persistent backend and a
  restart, neither of which an in-process replay has.
