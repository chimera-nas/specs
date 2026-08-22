<!--
SPDX-FileCopyrightText: 2026 The Quint Specs Authors

SPDX-License-Identifier: MIT
-->

# Quint model-based conformance test for the portmap server

This directory is a case study in model-based testing: a formal
[Quint](https://quint-lang.org) model of a portmap/rpcbind server
acts as the test oracle, and a consuming project replays traces generated
from that model against a live server, diffing every RPC reply against the
reply the model predicted.

## Pieces

- `portmap.qnt` — the model.  The modeled portmapper is a static registry
  (no `PMAPPROC_SET`/`UNSET`), so each procedure is modeled as a pure
  request → reply function over the `SERVICES` table; the only state is
  the last `(call, reply)` event.  Covers PMAP v2 NULL/GETPORT/DUMP and
  rpcbind v3/v4 GETADDR.  The `repliesExact` invariant and the scenario
  tests pin the semantics the reference implementation deliberately chose:
  GETPORT/GETADDR match the *exact* `(prog, vers, prot)` triple or return
  0 — unlike classic BSD portmap, which falls back to the port of some
  other registered version of the program on a version mismatch.
- `traces/*.itf.json` — pre-generated random traces (Informal Trace
  Format), checked in so the replay is hermetic: a consumer needs only
  python3, not quint or node.
- `regen_traces.sh` — regenerates the checked-in traces from the model.

The replay driver and its test wrapper live in the consuming project: a
pure-stdlib ONC RPC client replays a trace's calls over TCP and compares
replies, driven by a wrapper that boots a server (in-memory backend) in a
private network namespace and runs the replayer against it.

## Running

Model-only checks (no server involved):

```sh
quint test portmap.qnt
quint run portmap.qnt --invariant=repliesExact
```

Regenerate the checked-in traces after a model change:

```sh
./regen_traces.sh
```

The consuming project's replay harness drives the checked-in traces against
a live server; refer to that project for how to invoke it.

## Keeping the model in sync

`SERVICES` in `portmap.qnt` must mirror the table the server builds with
`external_portmap=false` and the default `lockmgr_port` (32803) and NSM
port (32765).  If you add a service, change a port, or change lookup
semantics, update the model accordingly and regenerate the traces:

```sh
./regen_traces.sh
```

A failing replay means the implementation and the model disagree; decide
which one is right before "fixing" either side.  The divergence report
names the trace state, the call arguments, and both replies.
