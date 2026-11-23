<!--
SPDX-FileCopyrightText: 2026 The Quint Specs Authors

SPDX-License-Identifier: MIT
-->

# The models

Seven models live under this directory. Each one is an oracle for a protocol:
given a request and the state the earlier requests left behind, it says what a
conformant server must answer. Nothing here talks to a server. The build
random-walks each model to produce traces, and a replay harness sends those
traces to a real server and compares every reply with what the model predicted.

This page is the map: what each model covers, the shape they all share, and how
a model becomes a trace. The detail lives in the header comments of the `.qnt`
files, which are long on purpose and are the place to go next.

| directory | model | what one step is | encodes |
|---|---|---|---|
| [`nfs/`](nfs/) | `nfs3` | one NFSv3 RPC | RFC 1813 |
| [`nfs/`](nfs/) | `nfs4` | one COMPOUND | RFC 7530, RFC 8881, RFC 7862, RFC 8276 |
| [`smb2/`](smb2/) | `smb2` | one SMB2 message, single or compound | MS-SMB2, MS-FSA |
| [`posix/`](posix/) | `posix` | one system call by one process | POSIX.1-2024, with Linux extensions |
| [`s3/`](s3/) | `s3` | one HTTP request | AWS S3 API Reference, RFC 9110 |
| [`nfsaux/`](nfsaux/) | `nfsaux` | one RPC to one of four programs | RFC 1833, RFC 1813 Appendices I and II |
| [`nfsdrc/`](nfsdrc/) | `nfsdrc` | one RPC, a retransmit, or a transport event | RFC 1813, RFC 7530, RFC 8881 Section 2.10.6 |

`nfs3/` and `nfs4/` hold only a `corpus.schema.json` each. The two NFS models
are separate families for the build but share the `nfs/` directory.

## Reading Quint, briefly

A Quint specification is a state machine: some variables, an action that sets
their first values, an action that says which changes are legal, and properties
that must hold in every state that can be reached.

| you will see | it means |
|---|---|
| `pure def`, `pure val` | an ordinary function or constant, with no access to state |
| `def`, `val` | reads the state, does not change it |
| `var x: T` | a state variable |
| `x' = e` | in the next state `x` equals `e` |
| `action` | a boolean formula over the current and next state: a transition |
| `all { a, b }` | both hold; a plain boolean among them is a guard |
| `any { a, b }` | exactly one is taken, chosen at random by the simulator |
| `nondet v = S.oneOf()` | pick an arbitrary element of the set `S` |
| `const C: T` | a parameter, bound when the module is instantiated |
| `run t = init.then(a).expect(p)` | a scripted sequence, executed by `quint test` |

Values are immutable. Data is built from integers, strings, booleans, sets,
lists, maps (`K -> V`), records and tagged unions taken apart with `match`.

## The shape every model shares

**The reply is in the state.** Every step writes the request it made and the
reply the standard requires into a variable called `lastOp`. A trace is the
sequence of states, so it is also the sequence of requests and expected replies,
and `lastOp` is the only thing a replay harness has to read.

**A pure evaluator and a thin generator.** What the server does is a
deterministic pure function of the state and the request: `evalCompound` in
nfs4, `evalMsg` in smb2, `dispatch` in posix. The actions only draw arguments
and apply it. That is why the larger models are split the same way:

| file | holds |
|---|---|
| `*_fs.qnt` | the filesystem, with no protocol in it |
| `*_state.qnt` | the protocol's own state: sessions, opens, locks, grants |
| `*_ops.qnt` | the evaluator: one pure handler per operation |
| `<model>.qnt` | the constants, the variables, the generating actions, the invariants |

The smb2 model has no filesystem of its own. It imports `nfs/nfs4_fs.qnt`, and
nothing else from NFS.

**Step flavours.** Each model has a mixed `step` and a set of narrower ones
(`stepLease`, `stepNamespace`, `stepNotify`, and so on). A flavour is a
different mix of the same actions, chosen with `--step`, so that a walk of a few
dozen steps stays in one area long enough to reach its deep states. An action
listed twice inside an `any` is drawn twice as often; that is the weighting
mechanism, not a mistake.

Changing which actions a flavour contains reshuffles every seeded draw made
through it, and so rewrites that flavour's whole corpus. This is why some
flavours that look redundant are kept apart.

**Small universes.** Three or four names, two clients, a handful of offsets.
The interesting behaviour is in collisions, two requests on one name or one
lock range, and a random walk only finds collisions when there is little room
to miss.

**Abstract where the value does not matter.** File content is a list or set of
block symbols, not bytes. Timestamps are not wall-clock values; a harness
checks that one moved or did not. Handles, state ids and client ids are small
integers the harness maps onto whatever the server issued.

**Invariants.** Each model ends with a `val inv` that the simulator checks at
every state: the filesystem is well formed, no two grants conflict, state never
outlives what it belongs to. An invariant failure is a model bug, found before
any trace is written.

**Self-tests.** `<model>Test.qnt` holds `run` definitions: scripted scenarios
that pin one rule each, and random walks that check `inv` along the way. The
build runs them before it generates anything, and a failure stops it.

## Constants

A model states the standard, and a standard leaves room. Each family's
`corpus.schema.json` declares the constants that fill that room and sorts them
into kinds:

| kind | prefix | says |
|---|---|---|
| feature | `F_` | whether the server has an optional capability |
| policy | `P_` | which of several permitted behaviours it chose |
| tolerance | `T_` | that either of two answers is to be accepted |
| deviation | `DEVS` | a known divergence the model should predict instead of flag |
| hazard | `HAZARDS` | a request pattern the server does not survive, so none is generated |

In nfs4, smb2 and posix a feature is one of `FeatOff`, `FeatMandatory` or
`FeatIfAdvertised`. The last lets `init` draw either value, and the draw is
kept in the `caps` variable for the rest of the trace.

A deviation is a named, cited claim that one server answers differently, kept
in the schema with its measurement. When a config enables one, the model takes
the divergent branch and records the id in the `devHits` variable for that
step. `tools/devliveness.py` then fails any config that enables a deviation its
traces never took, so an entry cannot outlive the bug it describes.

The schema is the authoritative list of constants, deviations and self-test
modules for a family. This page does not repeat them.

## From a model to a trace

1. A **config** is a JSON file that binds every constant of one family and
   lists the batches to generate: a flavour, a depth, a trace count and a seed.
   One config is one **cell**. The configs in this repo are under
   `harness/*/configs/`; a consuming project keeps its own.
2. `tools/mkconfig.js` checks the config against the family's schema and
   renders it into an instance module, in a staging copy of this directory.
3. `tools/gen.js` loads and typechecks the family once, runs its self-tests,
   then simulates every batch and writes the traces as ITF JSON.
4. A harness replays each trace. Those under [`harness/`](../harness/README.md)
   do so against third-party servers, to test the models themselves.

Two kinds of file here predate that arrangement or sit beside it:

* `*_run.qnt` holds hand-written instances, the profiles a person names with
  `--main` when running a model directly. The corpus is not generated from
  them. Some also carry the shared constant sets a config refers to by name.
* `*_all.qnt` names one module from the run file and one from the test file so
  that a single load brings in both. The build writes its own equivalent
  covering every cell.

`coverage.py`, where a suite has one, reads a generated corpus and reports
which behaviours it reached, so that a corner the walks stopped visiting is
noticed.

## The suites

### nfs3

Every procedure of RFC 1813 except NULL: lookup and attributes, the create
family including exclusive create and its verifier, READ, WRITE and COMMIT,
REMOVE, RMDIR, RENAME, LINK, READDIR and READDIRPLUS, and the three filesystem
information calls. Permission checks follow POSIX over AUTH_SYS credentials,
though only a few procedures are issued as anyone but root.

Left out: time and fileid values, device nodes, and a READDIR that spans more
than one request.

The whole model is `nfs/nfs3.qnt`.

### nfs4

Minor versions 0, 1 and 2, selected by the `MINOR` constant.

* the filehandle and namespace operations, attributes, VERIFY and NVERIFY
* NFSv4.0 client state: SETCLIENTID, open and lock owner sequence ids,
  OPEN_CONFIRM, RENEW, and lease loss as an explicit event
* NFSv4.1 sessions: EXCHANGE_ID, CREATE_SESSION, the SEQUENCE slot discipline,
  RECLAIM_COMPLETE and the grace gate, FREE_STATEID
* OPEN in its create modes with share access and deny, OPEN_DOWNGRADE, CLOSE
* byte-range locks
* read and write delegations, and the recall a conflicting request causes
* pNFS layouts
* the NFSv4.2 data operations: ALLOCATE, DEALLOCATE, SEEK, COPY, CLONE,
  READ_PLUS, WRITE_SAME, IO_ADVISE
* extended attributes

Left out: ACLs, more than one principal, a clock, the callback channel beyond
the fact of a recall, and state reclaim after a server restart.

Start with `nfs/nfs4_fs.qnt`, then `nfs4_state.qnt`, then `nfs4_ops.qnt`;
`nfs4.qnt` is the generator on top.

### smb2

* session and tree connect, and what a disconnect tears down
* CREATE: the dispositions and the order their checks run in, the file and
  directory matrix, share arbitration, delete-on-close
* oplocks and leases as one caching model, with the break a conflicting open
  causes and the acknowledgements a client may send back
* durable handles: the grant, surviving a disconnect, and the reclaim
* exactly-once: the CREATE replay cache and the ChannelSequence window
* READ, WRITE, FLUSH, CLOSE, and byte-range locks
* SET_INFO for end-of-file, disposition and rename; QUERY_INFO
* CHANGE_NOTIFY and CANCEL
* related and unrelated compounds

Left out: authentication and cryptography, NEGOTIATE beyond recording the
dialect, IOCTLs, QUERY_DIRECTORY, persistent handles, and rename onto an
existing name.

Start with `smb2/smb2_state.qnt`, then `smb2_ops.qnt`. CHANGE_NOTIFY is
self-contained in `smb2_notify.qnt`.

### posix

Two processes, with pathname resolution through symlinks and directory
descriptors.

* `open` and its flags, `close`, `dup`, `fcntl`, `lseek` including holes
* `read` and `write` in their positional and vectored forms, truncation,
  `fallocate`, `copy_file_range` and clone
* `stat`, `chmod`, `chown`, `utimensat`, `access`, `umask`
* `mkdir`, `mknod`, `symlink`, `link`, `unlink`, `rmdir`, `rename`, `readlink`
* directory streams
* record locks through `fcntl` and `lockf`

Where POSIX permits two answers, a policy constant picks one, so that a trace
can predict a single errno.

Left out: file bytes, `fork` and a working directory, extended attributes and
ACLs, and anything that needs a crash.

Start with `posix/posix_fs.qnt`, then `posix_state.qnt`, then `posix_ops.qnt`.

### s3

The S3 REST API as a gateway in front of a filesystem serves it. The defaults
are what AWS was measured to do, which is not always what the reference says.

* bucket create, head, delete, list and location
* object PUT, GET, HEAD and DELETE, ranged reads, batch delete, CopyObject
* conditional requests
* the three listing calls, with prefix, delimiter and continuation
* object and bucket tagging
* versioning, including delete markers
* bucket policy and anonymous reads
* presigned and checksummed requests, and malformed ones
* multipart upload from create to complete, with listing of parts and uploads

Left out: ETag and date values, byte-granular ranges, and the cases where a
flat object namespace and a directory tree disagree.

The whole model is `s3/s3.qnt`. It has no run file; its instances come from
configs alone.

### nfsaux

portmap and rpcbind, MOUNT, NLM and NSM in one state machine, because the
behaviour worth testing is between them. See
[`nfsaux/README.md`](nfsaux/README.md).

### nfsdrc

The duplicate-request caches of NFSv3 and NFSv4.0: a retransmit must be
answered from the cache and nothing else may be. See
[`nfsdrc/README.md`](nfsdrc/README.md), which is also the gentlest
introduction to how a model here is put together.

## Running a model by hand

The pinned version is in [`.quint-version`](../.quint-version). From the
repository root:

```sh
npm i -g @informalsystems/quint@$(cat .quint-version)
```

Then, from a suite's directory:

```sh
quint typecheck nfsdrc.qnt
quint test nfsdrcTest.qnt --main=nfsdrcTestRef
quint run  nfsdrc_run.qnt --main=nfsdrcRef --step=step --invariant=inv
```

`quint test` runs the scripted scenarios. `quint run` is the simulator: add
`--max-steps` for depth, `--seed` to reproduce a walk, and `--out-itf` to keep
the trace. Each family's schema lists its test modules under `selfTests`.

## A reading order

1. [`nfsdrc/README.md`](nfsdrc/README.md), then `nfsdrc/drc_cache.qnt`: types
   and pure functions only.
2. `nfsdrc/nfsdrc.qnt`: a complete state machine in one file.
3. `nfsdrc/nfsdrcTest.qnt`: what a scenario looks like.
4. `nfs/nfs3.qnt`: a full protocol, still in one file.
5. Any of the layered models, filesystem file first.