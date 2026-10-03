<!--
SPDX-FileCopyrightText: 2026 The Quint Specs Authors
SPDX-License-Identifier: MIT
-->
# S3 conformance harness

Replays the generated S3 corpus (`quint/s3`) against two real services and
compares every reply to the result the model baked into the trace:

* **Amazon S3 itself** — the service the model claims to state, and the only
  one that can say whether the model read it correctly;
* **MinIO** — an object store nobody consulted while writing the model, which
  can say whether an independent implementation agrees.

The point is to test the **model**. It was written alongside one
filesystem-backed gateway, and a model developed that way drifts toward its
implementation: the traces keep passing, and the passing keeps meaning less.

## AWS is the default; everything else is said out loud

The model's defaults are **Amazon S3 as measured**. S3 is a protocol whose
implementations routinely decline exact parity, on purpose, so what has to be
explicit is not what AWS does but what is *accepted that AWS does not do*.
There are three kinds of setting, all of them in a config and none in the
harness:

* A **relaxation** is a policy that is `false` on AWS. Switching one on in a
  config is a statement that the implementation departs from AWS there and that
  the departure is accepted. It is the only way the model will predict it.
* A **deviation** (`M-*` for MinIO) is a fault: the implementation gets
  something wrong that no one would defend. It has an id, a measurement, and a
  strict twin that turns it off, and `tools/devliveness.py` fails a cell that
  claims one its corpus never reaches.
* A **setup policy** describes the test arrangement rather than the service:
  `fixedBucket`, and the two policies AWS's answer to which could not be
  measured with one bucket.

Every branch is in the model and every setting is in
`configs/_aws.json` or `configs/_minio.json`, each of which is therefore the
whole statement of how that service differs. Each is declared, with what was
measured, in `quint/s3/corpus.schema.json`. The harness has **no notion of a
forgivable difference**.

## Amazon S3

```
AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... \
AWS_S3_BUCKET=<bucket> AWS_REGION=<region> \
    ctest --test-dir build -L aws
```

Without those in the environment the tests report a SKIP, so a machine with no
credentials — or a fork's pull request, which gets no secrets — is not a
failure. In CI they are repository secrets and variables, and the `aws` job
fails outright if they are missing in this repository itself.

There is no server to start and no bucket to create. The credentials are an
IAM user's with rights on **one existing bucket**, which other pipelines share
at the same moment. Two things follow.

**The corpus is generated under `fixedBucket`.** The model starts with its one
bucket live and empty; never draws CreateBucket, DeleteBucket or ListBuckets;
never names another bucket; and never touches the bucket's own tag set, the one
piece of modelled state nothing can partition. This narrows what the corpus
*contains* and changes nothing the model predicts.

**Isolation is by key prefix.** The replayer maps the model's bucket onto the
real one and puts every key under
`specs-mbt/<run>-<attempt>-<time>-<pid>/<trace>/`, unique to the run, the cell
and the trace. A trace starts on an empty namespace in a bucket that is not
empty, any number of runs can share the bucket, and nothing is deleted
afterwards: the bucket carries a lifecycle rule that expires objects and
unfinished multipart uploads after a day. Listings are asked for under the
prefix and the prefix is stripped from what comes back; a key from outside it
would show up as the mismatch it is.

A run is about 3,900 requests, and the multipart cell uploads 5 MiB parts.

### What AWS taught the model

The first replay diverged in 21 of 25 traces. None of it was AWS being wrong.
Five things the model predicted are things AWS does not do, and each is now a
relaxation:

| relaxation | what it accepts | what AWS does |
|------------|-----------------|---------------|
| `rangeErrorContentRange` | a 416 carries `Content-Range: bytes */<length>` | sends no such header |
| `emptySuffixRangeUnsatisfiable` | `bytes=-N` against a zero-length object is 416 | ignores the range: 200, empty body |
| `listReturnsMarkerPrefix` | with a delimiter, a common prefix the start key lies inside is returned | never returns it |
| `copySelfRejected` | a copy of an object onto itself is 400 `InvalidRequest` | performs it: 200 |
| `deleteReportsDuplicates` | a key named twice in DeleteObjects is reported twice | reports it once |

`copySelfRejected` is the one to read twice. 400 is what the S3 API Reference
describes, and it is not what AWS answered — measured in us-east-2, on a bucket
with the default SSE-S3 encryption every bucket now has. The model follows the
service.

One more was not a relaxation but a comparison the harness made that the API
never promised: DeleteObjects reports its entries in no particular order. The
model now predicts the entries and the harness compares them as a multiset.

With those in place both cells replay against AWS with **no deviation and no
relaxation**: 25 of 25 and 5 of 5.

### What could not be measured

One bucket and no right to create another leaves these unexercised against
AWS: the bucket lifecycle, bucket tagging, every `NoSuchBucket` path, and
cross-bucket copies. Two policies keep the defaults they had for that reason
— `createOwnedBucketConflict` (200, the documented us-east-1 answer) and
`copySourceFirst` — and MinIO's two bucket-tagging deviations are filed
against the API Reference rather than against a measurement.

## MinIO

### The server

MinIO's community edition is no longer released: upstream stopped publishing
binaries in October 2025 and archived the repository in April 2026. The server
under test is the head of that final AGPLv3 tree, built from source out of
[`chimera-nas/minio`](https://github.com/chimera-nas/minio) at a pinned commit
(`MINIO_COMMIT` in `.devcontainer/Dockerfile`). It runs as a single node on a
single drive. Because the target no longer moves, the deviations below are
MinIO's for good unless the pin is moved to a tree that fixes them.

### Running

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
`Content-Range` on a 206 and its absence or presence on a 416, the
`Content-Type` and `x-amz-meta` echo, `x-amz-tagging-count`, listing keys,
common prefixes, `IsTruncated` and `KeyCount`, tag sets, part lists, in-flight
uploads, the `<Deleted>` report of a batch delete, and the name of each
response document's root element.

ETags are not predicted but are held **consistent**: the value an object
reports at its last write is the value every later GET, HEAD, listing,
GetObjectAttributes and CompleteMultipartUpload must report until it is
rewritten.

Two things here are choices, and are stated rather than left implicit:

* **It is a correct client.** DeleteObjects and the tagging PUTs carry
  `Content-MD5`, GetObjectAttributes carries `x-amz-object-attributes`, and a
  large body is offered with `Expect: 100-continue`, because that is what the
  S3 API requires and the AWS SDKs do. Not doing so would measure the harness.
* **The default Content-Type is `binary/octet-stream`.** That is what AWS and
  MinIO report for an object stored with no Content-Type. It is the one
  AWS-versus-implementation difference still asserted by a harness rather than
  set in a config: the trace carries only the `mtag` that selects a
  Content-Type. A consumer whose own harness expects
  `application/octet-stream` is asserting its server's default, not S3's.

## What MinIO does differently

### Relaxations and setup policies

| policy | MinIO | AWS |
|--------|-------|-----|
| `copySelfRejected` | `true`: a copy of an object onto itself is 400, as the API Reference describes | performs it |
| `createOwnedBucketConflict` | `true`: CreateBucket on a bucket you own answers 409 `BucketAlreadyOwnedByYou` | 200 in us-east-1, 409 elsewhere (documented; not measured here) |
| `copySourceFirst` | `true`: a CopyObject of a missing key into a missing bucket reports `NoSuchKey` | not measured |

On the other four relaxations MinIO does what AWS does. Two of them — the 416
with no `Content-Range`, and the common prefix that is not returned — were
first filed here as MinIO faults, and were withdrawn when AWS turned out to do
the same.

### Deviations

| id | what MinIO does | cell |
|----|-----------------|------|
| `M-list-marker-outside-prefix-501` | a V1 `marker` or Versions `key-marker` that does not begin with the prefix is refused with 501 `NotImplemented`, before the bucket is even looked up | both |
| `M-suffix-range-empty-206` | `bytes=-N` on a zero-length object answers 206 with `Content-Range: bytes 0--1/0` | base |
| `M-get-bucket-tagging-no-bucket-check` | GetBucketTagging on a missing bucket answers `NoSuchTagSet`, not `NoSuchBucket` | base |
| `M-delete-bucket-tagging-no-bucket-check` | DeleteBucketTagging on a missing bucket answers 204 | base |
| `M-delete-objects-dup-empty` | a key named twice in one DeleteObjects comes back once with its key and once as an empty `<Deleted/>` | base |
| `M-getattrs-zero-size-omitted` | GetObjectAttributes omits `<ObjectSize>` when the size is 0 | base |
| `M-getattrs-root-lowercase` | the GetObjectAttributes document's root element is `getObjectAttributesResponse`, lower-case g | base |
| `M-part-zero-invalidpart` | `partNumber=0` is `InvalidPart`, not `InvalidArgument` | multipart |
| `M-complete-empty-manifest-invalidrequest` | an empty Complete manifest is `InvalidRequest`, not `MalformedXML` | multipart |
| `M-complete-duplicate-part-accepted` | a manifest repeating a part number in place (1,2,2) is **accepted**, and the part is assembled once per occurrence | multipart |
| `M-abort-unknown-upload-204` | AbortMultipartUpload of an upload that does not exist answers 204, not `NoSuchUpload` | multipart |

Nine of the eleven are now confirmed against AWS rather than only against the
documentation: the AWS cells reach the same requests with every deviation off
and AWS answers as the model says. The two bucket-tagging ones are the
exception, for the reason given above.

`M-complete-duplicate-part-accepted` is worth singling out, because it is the
one that changes state: AWS refuses the request and the upload stays open,
MinIO completes it and an object the client never described exists — one part
longer than the manifest's distinct parts. A registry could only have abandoned
the trace there. Modelled, the model completes the upload too and concatenates
the repeat, and the trace keeps testing.

Two of the eleven change no field of the trace label, only something the
harness derives — the omitted `<ObjectSize>` and the root element's name. For
those the model records the hit in `devHits` and the harness reads it from the
trace, so the expectation still comes from the model and never from the harness
knowing which server it is talking to.

## The cells

| cell | config | traces | block size | strict twin |
|------|--------|--------|------------|-------------|
| `aws/s3/base` | `aws_base.json` | 25 | 8 KiB | it *is* the strict corpus |
| `aws/s3/multipart` | `aws_multipart.json` | 5 | 5 MiB | it *is* the strict corpus |
| `minio/s3/base` | `base.json` | 29 | 8 KiB | yes |
| `minio/s3/multipart` | `multipart.json` | 5 | 5 MiB | yes |

The MinIO batch lists are the ones the consuming project replays against its
own server, unchanged; the AWS base cell is the same list without `stepBucket`,
which is the bucket lifecycle. Each MinIO cell switches off the deviations its
own flavours cannot reach.

The MinIO strict twins are the same batches with every deviation forced off
and the policies left as set. They fail, by design: their failures are exactly
MinIO's conformance debt, re-measured on every extended run rather than
remembered.

## Scope

The model is S3 as a filesystem-backed gateway can serve it: keys are path
components and no object is ever stored at both `d` and `d/a`. MinIO has no
such limit, and nothing here probes past it. Authentication failures,
virtual-host addressing, versioning proper, continuation tokens and
`aws-chunked` framing are not modelled and so not replayed.
