<!--
SPDX-FileCopyrightText: 2026 Chimera-NAS Project Contributors
SPDX-License-Identifier: LGPL-2.1-only
-->
# chimera specs

Quint model-based-test specifications for [chimera](https://github.com/chimera-nas/chimera).

Each suite under `quint/` is a spec-first model of a protocol/filesystem
surface; the build turns the models into a corpus of ITF traces plus model
self-tests and coverage gates:

| suite | what it models |
|-------|----------------|
| `quint/posix`   | the POSIX filesystem API (memfs/diskfs/cairn + nfs3/nfs4 loopback profiles) |
| `quint/nfs`     | NFSv3 and NFSv4 (RFC-first) |
| `quint/smb2`    | SMB2 (shares the nfs4 filesystem substrate) |
| `quint/portmap` | the RPC portmapper |

## Building

```
cmake -B build
cmake --build build          # generate every trace + run the model self-tests
ctest --test-dir build       # coverage gates
cmake --build build --target bundle   # -> build/specs-traces.tar.gz (+ manifest.json)
```

Trace generation is deterministic only against the quint version in
`.quint-version` (install with `npm i -g @informalsystems/quint@<ver>`).

## Consumption

The C/Python replay harness lives in the chimera repo. Chimera consumes this
repo as a submodule at `ext/specs`: when the submodule is clean it fetches the
prebuilt trace bundle for that commit from `ghcr.io/chimera-nas/specs:<sha>`;
otherwise (spec development) it builds the corpus locally from these sources.
CI publishes the `<sha>`-tagged bundle on every push to `main`.
