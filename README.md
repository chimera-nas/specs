<!--
SPDX-FileCopyrightText: 2026 The Quint Specs Authors
SPDX-License-Identifier: MIT
-->
# Quint protocol & filesystem specifications

Spec-first [Quint](https://quint-lang.org) model-based-test specifications for
common storage protocol and filesystem surfaces, derived from their standards
documents (RFC 1833, RFC 1813, RFC 7530/8881, MS-SMB2/MS-FSA, POSIX, the AWS
S3 API Reference). The build turns each
model into a corpus of ITF traces plus model self-tests and coverage gates; a
separate replay harness drives those traces against a server under test.

Each suite under `quint/` is an independent model:

| suite | what it models | source |
|-------|----------------|--------|
| `quint/posix`   | the POSIX filesystem API | POSIX.1 / Linux |
| `quint/nfs`     | NFSv3 and NFSv4 | RFC 1813, RFC 7530/8881 |
| `quint/smb2`    | SMB2 (shares the nfs4 filesystem substrate) | MS-SMB2, MS-FSA |
| `quint/nfsaux`  | the four protocols around NFSv3: portmap/rpcbind, MOUNT, NLM, NSM | RFC 1833, RFC 1813 App. I+II |
| `quint/s3`      | the Amazon S3 REST API, scoped to a filesystem-backed gateway | AWS S3 API Reference (2006-03-01) |
| `quint/nfsdrc`  | the duplicate-request caches of NFSv3 and NFSv4.0 | RFC 1813, RFC 7530, RFC 8881 §2.10.6 |

> These specifications were originally created to facilitate model-based testing
> of the [Chimera](https://github.com/chimera-nas/chimera) NAS project, but the
> models encode the standards, not any one implementation, and stand on their own.

## Building

```
cmake -B build
cmake --build build          # generate every trace + run the model self-tests
ctest --test-dir build       # coverage gates + the samba conformance suite
cmake --build build --target bundle   # -> build/specs-traces.tar.gz (+ manifest.json)
```

`.devcontainer/` builds an image with everything the above needs: the pinned
quint, cmake/ninja/python, and Samba plus the replay client's dependencies for
the conformance suite below. It runs privileged, because those tests isolate
themselves with network namespaces.

Trace generation is deterministic only against the quint version in
`.quint-version` (install with `npm i -g @informalsystems/quint@<ver>`).

## Generation is unconditional

Every batch this repo defines is generated, always. No trace is withheld, and
no depth clipped, because some server fails it. A corpus that omits the cases
an implementation gets wrong cannot report them, and the omission has to be
remembered rather than measured.

Divergence is therefore a **harness** concern, never a generation one, and each
harness owns the record for the server it drives:

* Samba's divergences live here, in
  [`harness/samba/samba_deviations.py`](harness/samba/samba_deviations.py) --
  the server is not this project's, but the harness that drives it is.
* A consuming project's divergences live in that project, next to the code that
  has to change. Chimera keeps its own registry in
  `src/server/smb/tests/quint/smb2_mbt_deviations.h`.

A harness that cannot drive part of the corpus says so per batch and reports a
SKIP, which keeps the gap visible and attributable to the harness rather than
hiding it in what was never generated.

## Testing the models against a real server

`ctest -L samba` replays the generated SMB2 corpus against a real Samba `smbd`
and fails on any divergence that is not already recorded and analyzed.

This exists because a model developed alongside one implementation drifts
toward it: the traces keep passing, and the passing keeps meaning less, because
the model and that server can agree on something the standard never said.
Replaying the same corpus at an unrelated server is the cheapest way to find
out. It has already found nine divergences: five were the model's and are fixed
here (chimera shared all five and has fixed four of them, recording the fifth --
a refused truncating create that truncates anyway -- as a known data-loss bug),
and five are Samba's, each recorded with a citation in
[`harness/samba/samba_deviations.py`](harness/samba/samba_deviations.py). The
counts overlap by one: SD-2 is a case where both sides were wrong, differently.

See [`harness/README.md`](harness/README.md).

## Consumption

A consuming project embeds this repo as a submodule and drives the generated
traces against its server with its own replay harness. When the submodule is
clean it can fetch the prebuilt trace bundle for that exact commit from
`ghcr.io/chimera-nas/specs:<sha>` instead of building it; otherwise (spec
development) it builds the corpus locally from these sources. CI publishes the
`<sha>`-tagged bundle on every push to `main`.
