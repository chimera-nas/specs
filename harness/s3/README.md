<!--
SPDX-FileCopyrightText: 2026 The Quint Specs Authors
SPDX-License-Identifier: MIT
-->
# S3 conformance harness

Replays the generated S3 corpus (`quint/s3`) against a real MinIO server and
compares every reply to the result the model baked into the trace.

The point is not to test MinIO. It is to test the **model**. The s3 model was
written alongside one filesystem-backed gateway, and a model developed that way
drifts toward its implementation: the traces keep passing, and the passing
keeps meaning less. MinIO is an object store nobody consulted while writing the
model — a flat namespace of its own, no filesystem underneath the keys — so
every disagreement is informative: either the model is wrong, or MinIO is.

A model bug is fixed in the model. A **MinIO** divergence is written into the
model as a branch guarded on the cell's config, so the model predicts what this
server actually does, the trace's expectation is already the truth, and replay
is an exact match. Every such branch is declared with its measurement and
citation in `quint/s3/corpus.schema.json` (the `M-*` ids), switched on by
`harness/s3/configs/*.json`, and kept honest by `tools/devliveness.py`, which
fails a cell that claims a deviation its own corpus never reaches.

Not every difference is a fault. Where S3 itself has more than one right answer
and a service picks one, the choice is a **policy** — a named constant of the
model that each implementation's config sets — and not a deviation: it records
no hit and a strict twin leaves it alone. Either way the branch is in the model
and the setting is in the config, so `configs/_minio.json` is the whole
statement of how this server differs. The harness has **no notion of a
forgivable difference**.

## The server

MinIO's community edition is no longer released: upstream stopped publishing
binaries in October 2025 and archived the repository in April 2026. The server
under test is the head of that final AGPLv3 tree, built from source out of
[`chimera-nas/minio`](https://github.com/chimera-nas/minio) at a pinned commit
(`MINIO_COMMIT` in `.devcontainer/Dockerfile`). It runs as a single node on a
single drive. Because the target no longer moves, the deviations below are
MinIO's for good unless the pin is moved to a tree that fixes them.

## Running

```
ctest --test-dir build -L minio                 # one test per cell
ctest --test-dir build -C extended -L strict    # ... plus the strict twins
```

Or by hand:

```
harness/s3/run_minio_mbt.sh build/specs-corpus/minio/s3/base
SPECS_S3_BLOCK_SIZE=5242880 \
    harness/s3/run_minio_mbt.sh build/specs-corpus/minio/s3/multipart
```

Each run starts a **fresh MinIO per trace** on an empty data directory. The
model's bucket names are fixed, so anything a trace left behind would be the
next trace's initial state; an empty directory cannot leak, where a cleanup
pass could. MinIO is listening about a third of a second after exec.

There is no network namespace and no root: MinIO needs no privileged port, so
every instance takes a free loopback port and the cells run concurrently under
`ctest -j` with nothing to serialize.

Useful environment variables (see the script header for the full list):
`SPECS_MINIO_KEEP=1` keeps the session directory, `SPECS_MINIO_SURVEY=1`
reports every diverging step of a trace instead of stopping at the first, and
`SPECS_MINIO_EXEC=<cmd>` runs `<cmd>` against a live instance instead of the
replayer — the fastest way to hand-probe a divergence.

The client (`s3_wire.py`) is the standard library and nothing else: HTTP/1.1
and a SigV4 signer. An SDK would retry, rewrite and reinterpret exactly the
status lines, headers and error bodies a replay has to compare.

## What is checked

Per request: the HTTP status and the `<Code>` of the XML error body, and then
the observables the model predicts — body bytes and `Content-Length`,
`Content-Range` on a 206 and a 416, the `Content-Type` and `x-amz-meta` echo,
`x-amz-tagging-count`, listing keys, common prefixes, `IsTruncated` and
`KeyCount`, tag sets, part lists, in-flight uploads, and the per-key
`<Deleted>` report of a batch delete.

ETags are not predicted but are held **consistent**: the value an object
reports at its last write is the value every later GET, HEAD, listing,
GetObjectAttributes and CompleteMultipartUpload must report until it is
rewritten.

Two things here are choices, and are stated rather than left implicit:

* **It is a correct client.** DeleteObjects and the tagging PUTs carry
  `Content-MD5` and GetObjectAttributes carries `x-amz-object-attributes`,
  because the S3 API requires them and MinIO enforces it. Not sending them
  would measure the harness.
* **The default Content-Type is `binary/octet-stream`.** That is what S3
  reports for an object stored with no Content-Type, and what MinIO reports.

## Divergences found

The first replay of the strict corpus diverged in all 34 traces. Sixteen
distinct causes came out of it: one of the model's own, two places where S3
allows either answer, and thirteen MinIO faults.

### The model — one, and it is the harness-facing half

| what was wrong |
|----------------|
| the model's convention for an object stored with no Content-Type was `application/octet-stream`; S3's is `binary/octet-stream` |

The value is not a field of the trace label — the model carries only the
`mtag` that selects a Content-Type — so the fix is the convention stated in
`s3.qnt` and applied by this harness. A consumer whose own harness expects
`application/octet-stream` is asserting its server's default, not S3's.

### S3 allows either — policies

| policy | default | MinIO |
|--------|---------|-------|
| `createOwnedBucketConflict` | `false`: CreateBucket on a bucket you own answers 200, as us-east-1 does | `true`: 409 `BucketAlreadyOwnedByYou`, as every other AWS region does |
| `copySourceFirst` | `false`: a CopyObject of a missing key into a missing bucket reports `NoSuchBucket` | `true`: it reports `NoSuchKey` — the source is resolved first |

### MinIO deviates, and the model predicts it

| id | what MinIO does | cell |
|----|-----------------|------|
| `M-list-marker-outside-prefix-501` | a V1 `marker` or Versions `key-marker` that does not begin with the prefix is refused with 501 `NotImplemented`, before the bucket is even looked up | both |
| `M-list-marker-inside-prefix-skipped` | with a delimiter, a common prefix the start key lies inside is never returned, though later keys still roll up into it | base |
| `M-416-no-content-range` | a 416 carries no `Content-Range: bytes */<length>` | base |
| `M-suffix-range-empty-206` | `bytes=-N` on a zero-length object answers 206 with `Content-Range: bytes 0--1/0` instead of 416 | base |
| `M-get-bucket-tagging-no-bucket-check` | GetBucketTagging on a missing bucket answers `NoSuchTagSet`, not `NoSuchBucket` | base |
| `M-delete-bucket-tagging-no-bucket-check` | DeleteBucketTagging on a missing bucket answers 204 | base |
| `M-delete-objects-dup-empty` | a key named twice in one DeleteObjects comes back once with its key and once as an empty `<Deleted/>` | base |
| `M-getattrs-zero-size-omitted` | GetObjectAttributes omits `<ObjectSize>` when the size is 0 | base |
| `M-getattrs-root-lowercase` | the GetObjectAttributes document's root element is `getObjectAttributesResponse`, lower-case g | base |
| `M-part-zero-invalidpart` | `partNumber=0` is `InvalidPart`, not `InvalidArgument` | multipart |
| `M-complete-empty-manifest-invalidrequest` | an empty Complete manifest is `InvalidRequest`, not `MalformedXML` | multipart |
| `M-complete-duplicate-part-accepted` | a manifest repeating a part number in place (1,2,2) is **accepted**, and the part is assembled once per occurrence | multipart |
| `M-abort-unknown-upload-204` | AbortMultipartUpload of an upload that does not exist answers 204, not `NoSuchUpload` | multipart |

`M-complete-duplicate-part-accepted` is worth singling out, because it is the
one that changes state: AWS refuses the request and the upload stays open,
MinIO completes it and an object the client never described exists — one part
longer than the manifest's distinct parts. A registry could only have abandoned
the trace there. Modelled, the model completes the upload too and concatenates
the repeat, and the trace keeps testing.

Four of the thirteen change no field of the trace label, only something the
harness derives: the missing 416 header, the empty `<Deleted/>`, the omitted
`<ObjectSize>`, the root element's name. For those the model records the hit in `devHits` and the
harness reads it from the trace, so the expectation still comes from the model
and never from the harness knowing which server it is talking to.

### The cells

| cell | config | traces | block size | strict twin |
|------|--------|--------|------------|-------------|
| `base` | `base.json` | 29 | 8 KiB | yes |
| `multipart` | `multipart.json` | 5 | 5 MiB | yes |

Both extend `configs/_minio.json`, which carries the server's two policies
and thirteen deviations; each cell switches off the ones its own flavours cannot reach. The
batch lists are the ones the consuming project replays against its own server,
unchanged: the corpus is protocol-level, so what distinguishes these cells is
only which divergences the model is told to predict.

The strict twins are the same batches with every deviation forced off and the
policies left as set. They
fail, by design: their failures are exactly MinIO's conformance debt,
re-measured on every extended run rather than remembered.

## Scope

The model is S3 as a filesystem-backed gateway can serve it: keys are path
components and no object is ever stored at both `d` and `d/a`. MinIO has no
such limit, and nothing here probes past it. Authentication failures,
virtual-host addressing, versioning proper, continuation tokens and
`aws-chunked` framing are not modelled and so not replayed.
