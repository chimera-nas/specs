<!--
SPDX-FileCopyrightText: 2026 The Quint Specs Authors
SPDX-License-Identifier: MIT
-->
# Quint protocol & filesystem specifications

Spec-first [Quint](https://quint-lang.org) model-based-test specifications for
common storage protocol and filesystem surfaces, derived from their standards
documents (RFC 1833, RFC 1813, RFC 7530/8881, MS-SMB2/MS-FSA, POSIX). The build turns each
model into a corpus of ITF traces plus model self-tests and coverage gates; a
separate replay harness drives those traces against a server under test.

Each suite under `quint/` is an independent model:

| suite | what it models | source |
|-------|----------------|--------|
| `quint/posix`   | the POSIX filesystem API | POSIX.1 / Linux |
| `quint/nfs`     | NFSv3 and NFSv4 | RFC 1813, RFC 7530/8881 |
| `quint/smb2`    | SMB2 (shares the nfs4 filesystem substrate) | MS-SMB2, MS-FSA |
| `quint/nfsaux`  | the four protocols around NFSv3: portmap/rpcbind, MOUNT, NLM, NSM | RFC 1833, RFC 1813 App. I+II |

> These specifications were originally created to facilitate model-based testing
> of the [Chimera](https://github.com/chimera-nas/chimera) NAS project, but the
> models encode the standards, not any one implementation, and stand on their own.

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

A consuming project embeds this repo as a submodule and drives the generated
traces against its server with its own replay harness. When the submodule is
clean it can fetch the prebuilt trace bundle for that exact commit from
`ghcr.io/chimera-nas/specs:<sha>` instead of building it; otherwise (spec
development) it builds the corpus locally from these sources. CI publishes the
`<sha>`-tagged bundle on every push to `main`.
