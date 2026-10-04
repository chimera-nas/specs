// SPDX-FileCopyrightText: 2026 The Quint Specs Authors
//
// SPDX-License-Identifier: MIT

// Quint model of the Amazon S3 REST API, restricted to the operation set a
// filesystem-backed S3 gateway serves, used for model-based testing at the
// HTTP request/response level.
//
// The model tracks a flat object store (bucket -> key -> object) plus the
// bucket/object tag sets and the in-flight multipart uploads, and, on every
// step, records the HTTP request issued and the response the service is
// expected to produce in the state variable `lastOp`.  Traces generated
// with `quint run --out-itf` are replayed against an in-process S3 server by
// the replay harness, which issues each request over HTTP and compares the
// server's actual response -- status line, S3 error code, headers, and body
// -- against `lastOp` step by step.
//
// Modeling conventions:
//  - The model's defaults are Amazon S3 AS MEASURED (harness/s3 replays the
//    corpus against AWS itself), which is not always what the API Reference
//    says.  Three kinds of knob tell it about another implementation, all
//    bound by the cell's config.  A FEATURE (F_*) is an optional capability:
//    switched off, the requests that need it are never drawn.  A RELAXATION
//    (a P_* that is false on AWS) accepts a different answer to a request
//    that is still sent.  A DEVIATION (the DEVS set) is a fault.  None of
//    them is ever the default.
//  - Object keys are lists of path components (e.g. ["d", "a"] is the key
//    "d/a").  Component names are single distinct lowercase letters, so the
//    byte order AWS sorts keys by coincides with component-list order and
//    every prefix/delimiter computation is structural.  Components used as
//    key "directories" (d, e) are disjoint from leaf components (a, b, c),
//    so a generated key set is always realizable on a POSIX filesystem --
//    the model deliberately never asks for the flat-namespace cases (an
//    object at both "d" and "d/a") that no filesystem-backed gateway can
//    represent.  That is the scope: S3-on-a-POSIX-filesystem, not full S3.
//  - Object content is a list of block symbols (small ints).  The harness
//    expands block symbol s at index i into a full block of identical bytes
//    at offset i * block-size, so real offsets and sizes are exercised
//    while the model state stays tiny.  Range requests are block-granular.
//  - Multipart uploads are named by an abstract integer id; the harness
//    learns the real 32-hex UploadId from the Initiate response, the way it
//    learns ETags.  The multipart actions are generated only by the
//    stepMultipart flavor, whose traces the harness replays with a block
//    size of at least 5 MiB (the AWS minimum part size): a non-empty part
//    is then always large enough, so EntityTooSmall is the fate of EMPTY
//    non-final manifest parts, exactly as encoded here.  DeleteBucket with
//    in-flight uploads (officially 409) is deliberately never generated:
//    whether a gateway can even see an in-flight upload as bucket content
//    is backend-dependent.
//  - Object metadata is abstracted to one small enum `mtag` driving a
//    Content-Type + x-amz-meta header pair (0 = neither: the response
//    Content-Type falls back to the service default, which on AWS is
//    binary/octet-stream).  Tag sets are
//    sets of small tag ids; the harness maps id i to the ("tk<i>","tv<i>")
//    pair.  A completed multipart object has no metadata and no tags (none
//    are supplied at Initiate).
//  - ETag, Last-Modified, Owner and Date are not modeled; the harness
//    checks ETag *consistency* (an object reports the same ETag from PUT,
//    GET, HEAD and List until it is rewritten) without predicting values.
//  - Statuses are HTTP status codes, numerically identical to the wire, so
//    the harness compares raw status with no decode step.  The `err` field
//    carries the S3 <Code> of the XML error body ("" when the response has
//    no error body -- success, or a HEAD response, which has no body).
//  - Authentication is not modeled: every request the harness sends is
//    correctly signed (V4, or V2 in the harness's --sigv2 mode).
//    ListObjects is modeled once with a `mode` selector (1 = V1 with
//    marker, 2 = V2 with start-after, 3 = ListObjectVersions with
//    key-marker); the walk is identical, only the wire dressing differs.
//    Continuation tokens are opaque and unmodeled.

module s3 {

    type Comp = str
    // An object key, as its slash-separated path components.
    type Key = List[Comp]
    // Object content: a list of block symbols, expanded by the harness.
    type Blocks = List[int]

    // One stored object: content, metadata tag (see MTAGS), object tags.
    // `parts` is the size in blocks of each part of an object assembled by a
    // multipart upload, in order; [] for an object written any other way.
    type Obj = { data: Blocks, mtag: int, tags: Set[int], parts: List[int] }

    // One in-flight multipart upload: target key and the uploaded parts.
    // The metadata and tags given at Initiate are what the completed object
    // carries.
    type Mpu = { key: Key, parts: int -> Blocks, mtag: int, tags: Set[int] }

    // One version of a key: an object, or a delete marker (dm; `obj` is then
    // a placeholder).  vid is abstract -- the harness learns the wire id from
    // the reply that minted it -- except 0, which is the "null" version: an
    // object written before versioning was enabled, or while it is suspended.
    type Ver = { vid: int, dm: bool, obj: Obj }

    // One bucket: objects, bucket tag set, in-flight uploads by id.
    //
    // `objs` is always what a plain GET sees.  A bucket whose versioning has
    // ever been configured (ver: 1 Enabled, 2 Suspended; 0 never) also keeps
    // `hist`: every version of every key, oldest first, so the last entry is
    // the latest -- and objs holds a key exactly when that entry is not a
    // delete marker.  nvid is the next version id to mint.
    //
    // pol is the bucket policy: 0 none, 1 anyone may GetObject (a PUBLIC
    // policy), 2 no one may GetObjectTagging (a Deny that binds the owner
    // too).
    type Bkt = { objs: Key -> Obj, btags: Set[int], mpu: int -> Mpu,
                 ver: int, nvid: int, hist: Key -> List[Ver], pol: int }

    // A listing prefix: component prefix plus whether it ends in "/".
    // { comps: ["d"], slash: true } is the prefix "d/";
    // { comps: ["d"], slash: false } is the bare prefix "d";
    // { comps: [], slash: false } is the empty prefix.
    type Prefix = { comps: List[Comp], slash: bool }

    // An HTTP Range header, in block units (the harness scales by the block
    // size): RClosed = "bytes=f-l", RFrom = "bytes=f-", RSuffix = "bytes=-n".
    type Range = RNone | RClosed({ first: int, last: int }) | RFrom(int) | RSuffix(int)

    // ------------------------------------------------------------------
    // Universes
    // ------------------------------------------------------------------

    pure val BUCKETS = Set("bk0", "bk1")

    // Leaf components (never key "directories") and directory chains.
    pure val LEAVES = Set("a", "b", "c")
    pure val DIRCHAINS: Set[List[Comp]] = Set([], ["d"], ["e"], ["d", "e"])
    // Every generated object key is a directory chain plus a leaf.
    pure val KEYS: Set[Key] =
        DIRCHAINS.map(ch => LEAVES.map(l => ch.append(l))).flatten()

    // Sentinel for "no start-after" (the empty component list is never a key).
    pure val NO_KEY: Key = []

    pure val PREFIXES: Set[Prefix] = Set(
        { comps: [], slash: false },        // ""    every object
        { comps: ["d"], slash: true },      // "d/"
        { comps: ["e"], slash: true },      // "e/"
        { comps: ["d", "e"], slash: true }, // "d/e/"
        { comps: ["d"], slash: false },     // "d"   bare prefix over a subtree
        { comps: ["a"], slash: false }      // "a"   bare prefix hitting one object
    )

    pure val MAXKEYS_CHOICES = Set(1, 2, 3, 1000)
    // The edges: nothing asked for, and more than the service will return in
    // one page (it answers as if 1000 had been asked, and says so).
    pure val MAXKEYS_EDGES = Set(0, 2000)
    pure val MAXKEYS_CAP = 1000
    // ListObjects request dressing: 1 = V1/marker, 2 = V2/start-after,
    // 3 = ListObjectVersions/key-marker.  Same walk, different XML.
    pure val LIST_MODES = Set(1, 2, 3)

    // Content block symbols; 0 is reserved (S3 has no holes).
    pure val BLOCK_SYMS = 1.to(3)
    pure val MAX_BLOCKS = 3
    // Every content the generator can PUT: 0..3 blocks over BLOCK_SYMS.
    pure val DATAS: Set[Blocks] =
        Set(List())
            .union(BLOCK_SYMS.map(a => [a]))
            .union(tuples(BLOCK_SYMS, BLOCK_SYMS).map(t => [t._1, t._2]))
            .union(tuples(BLOCK_SYMS, BLOCK_SYMS, BLOCK_SYMS).map(t => [t._1, t._2, t._3]))

    // Metadata tags: 0 = no Content-Type / x-amz-meta header on the PUT;
    // 1..2 select a fixed (Content-Type, x-amz-meta-m) pair in the harness.
    pure val MTAGS = Set(0, 1, 2)

    // Object/bucket tag ids; the harness maps id i to ("tk<i>", "tv<i>").
    pure val TAG_IDS = Set(1, 2)
    pure val TAGSETS: Set[Set[int]] = Set(Set(1), Set(2), Set(1, 2))

    // Multipart: part numbers, per-part contents (0..2 blocks -- an empty
    // part is the EntityTooSmall trigger), live-upload cap, and the
    // never-minted upload id / part number used for the not-found paths.
    pure val PART_NUMS = Set(1, 2, 3)
    pure val PART_DATAS: Set[Blocks] =
        Set(List())
            .union(BLOCK_SYMS.map(a => [a]))
            .union(tuples(BLOCK_SYMS, BLOCK_SYMS).map(t => [t._1, t._2]))
    pure val MAX_UPLOADS = 2
    pure val UNKNOWN_UPLOAD = 999
    pure val BOGUS_PART = 9

    // Cap on live objects across all buckets, keeping traces small.
    pure val MAX_OBJECTS = 8
    // A completed multipart object may concatenate several parts.
    pure val MAX_OBJ_BLOCKS = 8

    // DeleteObjects batch key lists (dup keys are legal and exercised).
    pure val DELETE_BATCHES: Set[List[Key]] =
        KEYS.map(k => [k])
            .union(tuples(KEYS, KEYS).map(t => [t._1, t._2]))

    // ------------------------------------------------------------------
    // HTTP statuses (wire values) and S3 error codes
    // ------------------------------------------------------------------

    pure val HTTP_OK = 200
    pure val HTTP_NO_CONTENT = 204
    pure val HTTP_PARTIAL = 206
    pure val HTTP_NOT_MODIFIED = 304
    pure val HTTP_BAD_REQUEST = 400
    pure val HTTP_FORBIDDEN = 403
    pure val HTTP_NOT_FOUND = 404
    pure val HTTP_METHOD_NOT_ALLOWED = 405
    pure val HTTP_CONFLICT = 409
    pure val HTTP_PRECOND = 412
    pure val HTTP_RANGE_ERR = 416
    pure val HTTP_INTERNAL = 500
    pure val HTTP_NOT_IMPL = 501

    // ------------------------------------------------------------------
    // The trace-visible request/response label
    // ------------------------------------------------------------------

    // Each variant is one HTTP request and its expected response, flat:
    // request fields first, then `status` (HTTP status), `err` (S3 <Code>
    // of the XML error body, "" if the response carries none), then any
    // response payload observables.  Sentinels on error paths: data/keys
    // lists are empty, sizeBlocks/first/total/uplid are -1.
    type Op =
        | OInit
        | OCreateBucket({ bucket: str, status: int })
        | OHeadBucket({ bucket: str, status: int })
        | ODeleteBucket({ bucket: str, status: int, err: str })
        | OListBuckets({ buckets: Set[str], status: int })
        // tags: sent in the x-amz-tagging header; empty sends none.
        | OPutObject({ bucket: str, key: Key, data: Blocks, mtag: int,
                       tags: Set[int], status: int, err: str })
        // ctype: the Content-Type the reply must carry ("" on an error).
        | OGetObject({ bucket: str, key: Key, range: Range, status: int, err: str,
                       data: Blocks, first: int, total: int, ctype: str })
        | OHeadObject({ bucket: str, key: Key, status: int, sizeBlocks: int,
                        ctype: str })
        // GET or HEAD with ?partNumber=N.  partsCount is what
        // x-amz-mp-parts-count must say; 0 means the header is absent.
        | OGetObjectPart({ bucket: str, key: Key, partNum: int, head: bool,
                           status: int, err: str, data: Blocks, first: int,
                           total: int, partsCount: int })
        | ODeleteObject({ bucket: str, key: Key, status: int, err: str })
        | ODeleteObjects({ bucket: str, keys: List[Key], quiet: bool,
                           status: int, err: str, deleted: List[Key] })
        // mdir: -1 is x-amz-metadata-directive COPY (the default, no header);
        // otherwise REPLACE, with that mtag's headers.  treplace: is
        // x-amz-tagging-directive REPLACE, with `tags` in x-amz-tagging.
        | OCopyObject({ srcBucket: str, srcKey: Key, dstBucket: str, dstKey: Key,
                        mdir: int, treplace: bool, tags: Set[int],
                        status: int, err: str })
        | OGetAttrs({ bucket: str, key: Key, status: int, err: str,
                      sizeBlocks: int })
        // Conditional requests.  `cond` names the precondition the request
        // carries; the harness supplies the object's current ETag, or one
        // that is not it.
        //   OCondGet   1 If-Match: current        2 If-Match: other
        //              3 If-None-Match: current   4 If-None-Match: other
        //              5 If-Modified-Since: a date long past
        //              6 If-Unmodified-Since: a date long past
        //              7 If-Unmodified-Since: a date far ahead
        //   OCondPut   1 If-None-Match: *   2 If-Match: current
        //              3 If-Match: other
        //   OCondCopy  the same four as OCondGet 1-4, on the SOURCE
        //              (x-amz-copy-source-if-match / -if-none-match)
        | OCondGet({ bucket: str, key: Key, head: bool, cond: int,
                     status: int, err: str, data: Blocks })
        | OCondPut({ bucket: str, key: Key, data: Blocks, cond: int,
                     status: int, err: str })
        | OCondCopy({ srcBucket: str, srcKey: Key, dstBucket: str, dstKey: Key,
                      cond: int, status: int, err: str })
        // Versioning.  state: 0 never configured, 1 Enabled, 2 Suspended.
        | OPutBktVersioning({ bucket: str, state: int, status: int, err: str })
        | OGetBktVersioning({ bucket: str, status: int, err: str, state: int })
        // GET or HEAD of one version (?versionId=).  dm: the version is a
        // delete marker, which the reply says in x-amz-delete-marker.
        | OGetVersion({ bucket: str, key: Key, vid: int, head: bool,
                        status: int, err: str, data: Blocks, dm: bool })
        // DELETE of one version: it is gone for good.
        | ODeleteVersion({ bucket: str, key: Key, vid: int, status: int,
                           err: str, dm: bool })
        // The whole history, in listing order: by key, newest first.
        | OListVersions({ bucket: str, status: int, err: str,
                          versions: List[{ key: Key, vid: int, dm: bool,
                                           latest: bool }] })
        // Bucket policy.  pol: 1 public read, 2 deny GetObjectTagging (see
        // Bkt); 0 in a Get reply that found none.
        | OPutBktPolicy({ bucket: str, pol: int, status: int, err: str })
        | OGetBktPolicy({ bucket: str, status: int, err: str, pol: int })
        | ODelBktPolicy({ bucket: str, status: int, err: str })
        // public: what <IsPublic> must say.
        | OGetPolicyStatus({ bucket: str, status: int, err: str, public: bool })
        // An UNSIGNED GetObject: no credentials at all.
        | OAnonGet({ bucket: str, key: Key, status: int, err: str, data: Blocks })
        // The same PutObject / GetObject by another route to the wire.
        //   OPutVia  "presigned"         a presigned URL, nothing in headers
        //            "trailer-crc32"     aws-chunked body, CRC32 in a trailer
        //            "header-crc32"      x-amz-checksum-crc32 of the body
        //            "header-crc32-bad"  ... of some other body
        //   OGetVia  "presigned"
        //            "bad-signature"     signed with the wrong secret
        //            "unknown-key"       an access key id nobody has
        | OPutVia({ bucket: str, key: Key, data: Blocks, via: str,
                    status: int, err: str })
        | OGetVia({ bucket: str, key: Key, via: str, status: int, err: str,
                    data: Blocks })
        | OGetBktLocation({ bucket: str, status: int, err: str })
        // The ACL of a bucket (key: NO_KEY) or an object.  A 200 names one
        // grant: FULL_CONTROL to the owner.
        | OGetAcl({ bucket: str, key: Key, status: int, err: str })
        // A request that is wrong in itself.  `kind` names how (see
        // invalidReply); nothing changes.
        | OInvalid({ bucket: str, key: Key, kind: str, status: int, err: str })
        // cont: the request carries the continuation token the PREVIOUS step's
        // reply returned (V2 only), and no start-after.  maxKeysEcho: what
        // <MaxKeys> must say -- on AWS the number asked for, even when that is
        // more than a page will hold.  last/lastIsPfx: the last entry of the page in
        // listing order ([] when the page is empty) -- what NextMarker and
        // NextKeyMarker name when the page is truncated.
        | OListObjects({ bucket: str, prefix: Prefix, delim: bool, startAfter: Key,
                         maxKeys: int, mode: int, cont: bool,
                         status: int, err: str,
                         keys: List[Key], prefixes: List[Key], truncated: bool,
                         maxKeysEcho: int, last: List[Comp], lastIsPfx: bool })
        | OPutObjTagging({ bucket: str, key: Key, tags: Set[int],
                           status: int, err: str })
        | OGetObjTagging({ bucket: str, key: Key, status: int, err: str,
                           tags: Set[int] })
        | ODelObjTagging({ bucket: str, key: Key, status: int, err: str })
        | OPutBktTagging({ bucket: str, tags: Set[int], status: int, err: str })
        | OGetBktTagging({ bucket: str, status: int, err: str, tags: Set[int] })
        | ODelBktTagging({ bucket: str, status: int, err: str })
        | OCreateMpu({ bucket: str, key: Key, uplid: int, mtag: int,
                       tags: Set[int], status: int, err: str })
        | OUploadPart({ bucket: str, key: Key, uplid: int, partNum: int,
                        data: Blocks, status: int, err: str })
        | OUploadPartCopy({ bucket: str, key: Key, uplid: int, partNum: int,
                            srcBucket: str, srcKey: Key, range: Range,
                            data: Blocks, status: int, err: str })
        | OCompleteMpu({ bucket: str, key: Key, uplid: int, manifest: List[int],
                         status: int, err: str })
        | OAbortMpu({ bucket: str, key: Key, uplid: int, status: int, err: str })
        // maxParts / marker: max-parts and part-number-marker (1000 and 0 are
        // sent as no parameter at all).
        | OListParts({ bucket: str, key: Key, uplid: int, maxParts: int,
                       marker: int, status: int, err: str,
                       partNums: List[int], truncated: bool })
        // prefix / maxUploads: the same for prefix and max-uploads.
        | OListMpu({ bucket: str, prefix: Prefix, maxUploads: int,
                     status: int, err: str,
                     uploads: Set[{ key: Key, uplid: int }], truncated: bool })

    // ------------------------------------------------------------------
    // State
    // ------------------------------------------------------------------

    // ------------------------------------------------------------------
    // Known implementation deviations.
    //
    // The model states S3 as AWS documents it.  Where the implementation under
    // test knowingly diverges, the divergence is DESCRIBED HERE, gated on the
    // consumer's config, rather than forgiven by the replay harness after the
    // fact.  A harness that forgives cannot say what it forgave; a model that
    // describes produces a trace whose expectation already IS the implementation's
    // behaviour, so replay is an exact match and the harness needs no registry.
    //
    // One Set constant, not a constant per deviation: adding a deviation then
    // costs no schema signature change, and a config names only what it enables.
    // Every id here must be declared, with a citation, in the family's
    // corpus.schema.json before a config may switch it on.
    const DEVS: Set[str]

    // ------------------------------------------------------------------
    // Policies: places where S3 itself has more than one right answer, and an
    // implementation picks.  Unlike a deviation, neither value is a fault, so
    // these carry no devHits record and no strict twin turns them off.
    // ------------------------------------------------------------------

    // CreateBucket on a bucket the caller already owns.  false: the legacy
    // us-east-1 answer, 200 OK.  true: what every other AWS region answers,
    // 409 BucketAlreadyOwnedByYou (S3 API Reference, CreateBucket).
    const P_CREATE_OWNED_CONFLICT: bool

    // CopyObject when the destination bucket AND the source key are both
    // missing.  S3 documents no precedence between the two 404s.  false: the
    // destination bucket is resolved first (NoSuchBucket), which is what AWS
    // does, measured.  true: the source is resolved first (NoSuchKey) -- a
    // relaxation.
    const P_COPY_SOURCE_FIRST: bool

    // The service under test is handed ONE bucket that already exists, which
    // the tester may neither create nor delete and may be SHARING with other
    // runs -- an account in which the tester holds rights on a single bucket
    // and nothing else.  true: the model starts with that bucket ("bk0") live
    // and empty, never draws CreateBucket, DeleteBucket or ListBuckets, never
    // names another bucket (so the NoSuchBucket paths and cross-bucket copies
    // are not generated), and never touches the bucket's own tag set, the one
    // piece of modeled state a key prefix cannot keep apart.  It narrows what
    // a corpus CONTAINS; it changes nothing the model predicts.
    const P_FIXED_BUCKET: bool

    // ---- features: optional capabilities ----
    //
    // AWS has every one of them, so the default is true.  A config switches
    // one off for a server that does not have it, and the requests that need
    // it are then never drawn: a feature narrows what a corpus contains.

    // Conditional requests: If-Match / If-None-Match / If-Modified-Since /
    // If-Unmodified-Since on GET and HEAD, If-None-Match: * and If-Match on
    // PUT, x-amz-copy-source-if-* on a copy.
    const F_CONDITIONAL: bool

    // Presigned URLs: the signature in the query string.
    const F_PRESIGNED: bool

    // Flexible checksums: x-amz-checksum-crc32 as a header, and as the
    // trailer of an aws-chunked body -- how current AWS SDKs upload.
    const F_CHECKSUMS: bool

    // GetBucketAcl / GetObjectAcl.
    const F_ACL: bool

    // Object versioning: PutBucketVersioning / GetBucketVersioning, versionId
    // on GET, HEAD and DELETE, delete markers, ListObjectVersions over a
    // history.  Off: no bucket's versioning is ever configured, so every
    // bucket stays as it was created.
    const F_VERSIONING: bool

    // Bucket policy: Put / Get / DeleteBucketPolicy, GetBucketPolicyStatus,
    // and the policy being enforced.
    const F_BUCKET_POLICY: bool

    // ---- relaxations: what AWS does NOT do, and an implementation may ----
    //
    // The defaults above and below are Amazon S3's own behaviour, measured.
    // Each of these is FALSE on AWS.  Setting one true is an explicit
    // statement that the implementation under test departs from AWS there and
    // that the departure is accepted -- which is the only way the model will
    // predict it.

    // A 416 InvalidRange carries "Content-Range: bytes */<length>", as RFC
    // 9110 15.5.17 says a server SHOULD.  AWS sends none: false, and the
    // label's `total` is -1 on a 416 -- the header must be ABSENT.  true: the
    // header is sent and `total` says what length it must name.
    const P_RANGE_ERR_CONTENT_RANGE: bool

    // A suffix range (bytes=-N) against a zero-length object.  AWS ignores
    // the range and answers as an unranged GET would, 200 with an empty body:
    // false.  true: it is unsatisfiable like every other range against an
    // empty object, 416 InvalidRange.
    const P_EMPTY_SUFFIX_RANGE_UNSATISFIABLE: bool

    // Listing with a delimiter from a start key (marker / start-after /
    // key-marker) that lies INSIDE a common prefix, "d/" for a start key
    // "d/a".  AWS takes the prefix to sort before the start key and never
    // returns it: false.  true: keys after the start key still roll up into
    // the prefix and it is returned.
    const P_LIST_RETURNS_MARKER_PREFIX: bool

    // CopyObject of an object onto itself with nothing changed.  In a bucket
    // as AWS creates it this is 400 InvalidRequest, as the API Reference
    // says: false.  true: the copy is performed and answers 200 -- which one
    // long-lived AWS bucket was also measured to do, for a reason in its
    // configuration that was not established.
    const P_COPY_SELF_ACCEPTED: bool

    // DeleteObjects naming the same key more than once.  AWS reports that key
    // ONCE, however many times the request named it: false.  true: one
    // <Deleted> entry per occurrence.
    const P_DELETE_REPORTS_DUPLICATES: bool

    // A successful PutBucketTagging.  AWS answers 204 No Content: false.
    // true: 200 OK, which is what PutObjectTagging answers and what an
    // implementation sharing one code path between the two tends to give.
    const P_PUT_BUCKET_TAGGING_OK: bool

    // The Content-Type reported for an object stored with none.  AWS says
    // binary/octet-stream: false.  true: application/octet-stream, the
    // registered type an implementation built on an HTTP library tends to
    // give.
    const P_DEFAULT_CTYPE_APP_OCTET: bool

    // PutBucketPolicy with a policy that makes the bucket PUBLIC.  A bucket
    // on AWS is created with Block Public Access on, which refuses it: false,
    // 403 AccessDenied, and the bucket's policy is unchanged.  true: the
    // policy is accepted, and an unsigned GetObject is then served.
    const P_PUBLIC_POLICY_ALLOWED: bool

    // The bucket names a request may carry.
    val BKT_UNIVERSE = if (P_FIXED_BUCKET) Set("bk0") else BUCKETS

    pure def dev(id: str): bool = DEVS.contains(id)

    // The store: bucket name -> bucket.  Bucket existence is membership.
    var bkts: str -> Bkt

    // Which deviations shaped the step just taken.  This is what makes a
    // deviation falsifiable: tools/devliveness.py fails the build when a config
    // enables one that no trace in its corpus ever records here, so a deviation
    // that has been fixed cannot sit on quietly forgiving the same divergence
    // elsewhere.
    var devHits: Set[str]
    // Next multipart upload id (abstract; the harness maps to wire ids).
    var nextUpl: int
    var lastOp: Op

    pure val EMPTY_BKT: Bkt = { objs: Map(), btags: Set(), mpu: Map(),
                                ver: 0, nvid: 1, hist: Map(), pol: 0 }

    pure def mkObj(d: Blocks, mt: int): Obj =
        { data: d, mtag: mt, tags: Set(), parts: [] }

    // The Content-Type a reply for an object with metadata tag mt carries.
    // The harness sends these for mtag 1 and 2; they are named here because
    // the fallback for mtag 0 is the service's choice.
    val defaultCtype = if (P_DEFAULT_CTYPE_APP_OCTET) "application/octet-stream"
                       else "binary/octet-stream"
    def ctypeOf(mt: int): str =
        if (mt == 1) "text/plain"
        else if (mt == 2) "application/json"
        else defaultCtype

    // ---- writes, deletes and retags, versioning included ----
    //
    // Every action that changes an object goes through these three, so a
    // bucket's history is kept in one place.

    pure val NO_OBJ: Obj = { data: [], mtag: 0, tags: Set(), parts: [] }

    pure def histOf(bk: Bkt, k: Key): List[Ver] =
        if (bk.hist.keys().contains(k)) bk.hist.get(k) else []

    // The id a write takes: a new one while versioning is Enabled, the null
    // version -- replacing whatever null version there was -- while Suspended.
    pure def bkAppend(bk: Bkt, k: Key, dm: bool, o: Obj): Bkt =
        val vid = if (bk.ver == 1) bk.nvid else 0
        bk.with("hist", bk.hist.put(k,
                    histOf(bk, k).select(v => v.vid != vid)
                        .append({ vid: vid, dm: dm, obj: o })))
          .with("nvid", if (bk.ver == 1) bk.nvid + 1 else bk.nvid)

    pure def bkPut(bk: Bkt, k: Key, o: Obj): Bkt =
        val b2 = bk.with("objs", bk.objs.put(k, o))
        if (bk.ver == 0) b2 else bkAppend(b2, k, false, o)

    // A DELETE that names no version.  In a versioned bucket nothing is
    // removed: a delete marker becomes the latest version, whether or not the
    // key ever existed.
    pure def bkDel(bk: Bkt, k: Key): Bkt =
        val b2 = bk.with("objs", mapDrop(bk.objs, k))
        if (bk.ver == 0) b2 else bkAppend(b2, k, true, NO_OBJ)

    // New tags on the CURRENT version; no version is created.
    pure def bkRetag(bk: Bkt, k: Key, ts: Set[int]): Bkt =
        val o = bk.objs.get(k).with("tags", ts)
        val b2 = bk.with("objs", bk.objs.put(k, o))
        if (bk.ver == 0) b2
        else
            val h = bk.hist.get(k)
            b2.with("hist", bk.hist.put(k,
                h.replaceAt(h.length() - 1, h[h.length() - 1].with("obj", o))))

    // Remove one version for good; what a plain GET sees is whatever is then
    // the latest.
    pure def bkDropVer(bk: Bkt, k: Key, vid: int): Bkt =
        val h = histOf(bk, k).select(v => v.vid != vid)
        val b2 = bk.with("hist", if (h.length() == 0) mapDrop(bk.hist, k)
                                 else bk.hist.put(k, h))
        if (h.length() > 0 and not(h[h.length() - 1].dm))
            b2.with("objs", bk.objs.put(k, h[h.length() - 1].obj))
        else
            b2.with("objs", mapDrop(bk.objs, k))

    // A key whose latest version is a delete marker: there is no object, but
    // there is something, and a tagging call says so -- 405, where a key
    // with no history at all is 404.
    pure def tagOnMarker(bk: Bkt, k: Key): bool =
        val h = histOf(bk, k)
        h.length() > 0 and h[h.length() - 1].dm

    val liveBuckets = bkts.keys()
    val totalObjs = liveBuckets.fold(0, (n, b) => n + bkts.get(b).objs.keys().size())
    // Every live (bucket, key) pair, for hit-biased generators.
    val objPairs = liveBuckets.map(b => bkts.get(b).objs.keys().map(k => (b, k))).flatten()
    val totalUploads = liveBuckets.fold(0, (n, b) => n + bkts.get(b).mpu.keys().size())
    // Every live (bucket, uploadId) pair.
    val uploadPairs = liveBuckets.map(b => bkts.get(b).mpu.keys().map(u => (b, u))).flatten()

    pure def imin(a: int, b: int): int = if (a < b) a else b
    pure def imax(a: int, b: int): int = if (a > b) a else b
    // Quint has no builtin to delete a map key.
    pure def mapDrop(m, k) = m.keys().exclude(Set(k)).mapBy(x => m.get(x))

    // ------------------------------------------------------------------
    // Listing (the ListObjects walk, AWS API Reference)
    // ------------------------------------------------------------------

    // A listing result entry: an object key (<Contents>) or a rolled-up
    // common prefix (<CommonPrefixes>; the comps carry an implied trailing
    // slash on the wire).
    type Entry = EKey(Key) | EPfx(List[Comp])

    // The canonical byte order of every key and common-prefix string this
    // model can produce.  With single-letter components ordered a < b < c
    // < d < e, the byte order of the slash-joined strings is exactly this
    // interleaving ("d" < "d/" < "d/a", since "/" sorts below lowercase
    // letters).  All sorting and start-after comparisons walk this list.
    pure val ENT_ORDER: List[Entry] = [
        EKey(["a"]),
        EKey(["b"]),
        EKey(["c"]),
        EPfx(["d"]),
        EKey(["d", "a"]),
        EKey(["d", "b"]),
        EKey(["d", "c"]),
        EPfx(["d", "e"]),
        EKey(["d", "e", "a"]),
        EKey(["d", "e", "b"]),
        EKey(["d", "e", "c"]),
        EPfx(["e"]),
        EKey(["e", "a"]),
        EKey(["e", "b"]),
        EKey(["e", "c"])
    ]

    pure def entRank(e: Entry): int =
        ENT_ORDER.indices().fold(-1, (acc, i) =>
            if (ENT_ORDER[i] == e) i else acc)

    pure def keyRank(k: Key): int = entRank(EKey(k))

    pure def isStrictPrefix(p: List[Comp], k: List[Comp]): bool =
        p.length() < k.length() and p.indices().forall(i => p[i] == k[i])

    // Does key k match listing prefix p (string-prefix semantics)?
    pure def keyMatches(k: Key, p: Prefix): bool =
        if (p.slash)
            isStrictPrefix(p.comps, k)
        else if (p.comps.length() == 0)
            true
        else
            // Bare prefix: exact key, or the prefix components followed by
            // more (the "/" after them makes the string a prefix match).
            k == p.comps or isStrictPrefix(p.comps, k)

    // With delimiter "/": the entry key k contributes to the listing --
    // itself, or the common prefix it rolls up into (the key truncated
    // just past the first "/" after the request prefix).
    pure def rollup(k: Key, p: Prefix): Entry =
        if (p.slash)
            if (k.length() == p.comps.length() + 1)
                EKey(k)
            else
                EPfx(p.comps.append(k[p.comps.length()]))
        else if (p.comps.length() == 0)
            if (k.length() == 1) EKey(k) else EPfx([k[0]])
        else
            // Bare prefix "c": the exact object is a Contents entry; any
            // deeper key's first "/" is right after the first component.
            if (k == p.comps) EKey(k) else EPfx([k[0]])

    // Tracking the last emitted entry, to absorb keys that roll up into an
    // already-emitted common prefix.
    type LastE = LNone | LSome(Entry)

    type ListOut = { keys: List[Key], prefixes: List[Key], truncated: bool,
                     last: List[Comp], lastIsPfx: bool }

    // Where a continuation token resumes: after the last entry of the page
    // that returned it.  After a key, that is the key itself.  After a common
    // prefix, it is everything the prefix rolled up -- every key under it.
    type Resume = { key: Key, pfx: List[Comp] }
    pure val NO_RESUME: Resume = { key: [], pfx: [] }

    pure def resumeSkips(r: Resume, k: Key): bool =
        (r.key != NO_KEY and keyRank(k) <= keyRank(r.key))
        or (r.pfx.length() > 0 and
            (isStrictPrefix(r.pfx, k) or keyRank(k) < entRank(EPfx(r.pfx))))

    // The ListObjects walk (shared by V1, V2 and ListObjectVersions --
    // marker / start-after / key-marker are all the same exclusive start
    // key): object keys in byte order, those at or below the start key
    // skipped, each emitting itself (no delimiter) or its rollup
    // (delimiter "/"); consecutive keys sharing a rollup collapse into one
    // <CommonPrefixes> entry; the page closes after maxKeys emissions and
    // IsTruncated reports whether any further key would have emitted a new
    // entry.  AWS returns an empty, non-truncated result for max-keys=0.
    //
    // skipIn is AWS's behaviour, relaxed by P_LIST_RETURNS_MARKER_PREFIX: a
    // common prefix the start key lies INSIDE ("d/" for a start key "d/a") is never emitted,
    // although keys past the start key still roll up into it.
    pure def listWalk(objs: Set[Key], p: Prefix, delim: bool, sa: Key, maxKeys: int,
                      skipIn: bool, res: Resume): ListOut =
        if (maxKeys == 0)
            { keys: [], prefixes: [], truncated: false, last: [], lastIsPfx: false }
        else
            val w = ENT_ORDER.foldl(
                { keys: [], prefixes: [], truncated: false, done: false, last: LNone },
                (st, e) =>
                match e {
                    | EPfx(x) => st
                    | EKey(k) =>
                        if (not(objs.contains(k))
                                or not(keyMatches(k, p))
                                or (sa != NO_KEY and keyRank(k) <= keyRank(sa))
                                or resumeSkips(res, k))
                            st
                        else
                            val em = if (delim) rollup(k, p) else EKey(k)
                            val inside = match em {
                                | EKey(kk) => false
                                | EPfx(pc) => skipIn and isStrictPrefix(pc, sa)
                            }
                            if (inside)
                                st
                            else if (st.last == LSome(em))
                                // Absorbed into the already-emitted prefix.
                                st
                            else if (st.done)
                                st.with("truncated", true)
                            else
                                val st2 = match em {
                                    | EKey(kk) => st.with("keys", st.keys.append(kk))
                                    | EPfx(pc) => st.with("prefixes", st.prefixes.append(pc))
                                }
                                val n = st2.keys.length() + st2.prefixes.length()
                                st2.with("last", LSome(em)).with("done", n >= maxKeys)
                })
            { keys: w.keys, prefixes: w.prefixes, truncated: w.truncated,
              last: match w.last {
                        | LNone => []
                        | LSome(e) => match e {
                            | EKey(kk) => kk
                            | EPfx(pc) => pc
                        }
                    },
              lastIsPfx: match w.last {
                        | LNone => false
                        | LSome(e) => match e {
                            | EKey(kk) => false
                            | EPfx(pc) => true
                        }
                    } }

    // ------------------------------------------------------------------
    // Range resolution (RFC 9110 14.4 as AWS applies it)
    // ------------------------------------------------------------------

    type RangeOut = { status: int, err: str, out: Blocks, first: int }

    // AWS returns 206 for every satisfiable Range request -- including one
    // that resolves to the whole object (bytes=0- on a 2-block object) --
    // and 416 InvalidRange when the start is at or past EOF, or for any
    // range against a zero-length object.  A last-position past EOF is
    // clamped, not rejected.
    pure def rangeApply(data: Blocks, r: Range): RangeOut =
        val sz = data.length()
        match r {
            | RNone => { status: HTTP_OK, err: "", out: data, first: 0 }
            | RClosed(c) =>
                if (c.first >= sz)
                    { status: HTTP_RANGE_ERR, err: "InvalidRange", out: [], first: -1 }
                else
                    { status: HTTP_PARTIAL, err: "",
                      out: data.slice(c.first, imin(c.last + 1, sz)), first: c.first }
            | RFrom(f) =>
                if (f >= sz)
                    { status: HTTP_RANGE_ERR, err: "InvalidRange", out: [], first: -1 }
                else
                    { status: HTTP_PARTIAL, err: "", out: data.slice(f, sz), first: f }
            | RSuffix(n) =>
                if (sz == 0)
                    { status: HTTP_RANGE_ERR, err: "InvalidRange", out: [], first: -1 }
                else
                    { status: HTTP_PARTIAL, err: "",
                      out: data.slice(imax(0, sz - n), sz), first: imax(0, sz - n) }
        }

    // ------------------------------------------------------------------
    // Multipart manifest validation (verified against AWS semantics; the
    // reference implementation applies the same per-index precedence)
    // ------------------------------------------------------------------

    // Sorted (ascending) part numbers of an upload.
    pure def sortedParts(parts: int -> Blocks): List[int] =
        [1, 2, 3].foldl([], (acc, n) =>
            if (parts.keys().contains(n)) acc.append(n) else acc)

    pure def rev(l: List[int]): List[int] =
        l.foldl([], (acc, x) => [x].concat(acc))

    // CompleteMultipartUpload validation: an empty manifest is
    // MalformedXML; otherwise the manifest is walked once, index by index,
    // and the FIRST offending index decides the error -- within one index
    // the precedence is out-of-order (non-increasing, duplicates included)
    // -> unknown part -> undersized (empty, i.e. below the 5 MiB part
    // minimum) non-final part.
    //
    // Two MinIO deviations live here, as parameters so the action can ask
    // whether either one changed the answer: emptyReq reports the empty
    // manifest as InvalidRequest, and dupOk accepts a part number repeated in
    // place (1,2,2) -- its order check is "not descending", not "ascending" --
    // and then assembles the part once per occurrence.
    pure def completeCheckWith(parts: int -> Blocks, manifest: List[int], dupOk: bool,
                               emptyReq: bool): { status: int, err: str } =
        if (manifest.length() == 0)
            { status: HTTP_BAD_REQUEST,
              err: if (emptyReq) "InvalidRequest" else "MalformedXML" }
        else
            val w = manifest.foldl(
                { i: 0, prev: 0, status: 0, err: "" },
                (acc, pn) =>
                if (acc.status != 0)
                    acc.with("i", acc.i + 1)
                else if (pn < acc.prev or (pn == acc.prev and not(dupOk)))
                    acc.with("status", HTTP_BAD_REQUEST).with("err", "InvalidPartOrder")
                else if (not(parts.keys().contains(pn)))
                    acc.with("status", HTTP_BAD_REQUEST).with("err", "InvalidPart")
                else if (acc.i < manifest.length() - 1 and parts.get(pn).length() == 0)
                    acc.with("status", HTTP_BAD_REQUEST).with("err", "EntityTooSmall")
                else
                    { i: acc.i + 1, prev: pn, status: 0, err: "" })
            if (w.status != 0) { status: w.status, err: w.err }
            else { status: HTTP_OK, err: "" }

    // MinIO's order of checks (M-complete-checks-by-kind): not index by
    // index, but kind by kind over the whole manifest -- every part's order,
    // then every part's existence, then every part's size.  So a manifest
    // with an undersized part AHEAD of an unknown one reports the unknown
    // one.
    pure def completeCheckByKind(parts: int -> Blocks, manifest: List[int], dupOk: bool,
                                 emptyReq: bool): { status: int, err: str } =
        val first = completeCheckWith(parts, manifest, dupOk, emptyReq)
        val unknown = manifest.select(pn => not(parts.keys().contains(pn))).length() > 0
        val w = manifest.foldl({ prev: 0, bad: false }, (acc, pn) =>
            { prev: pn, bad: acc.bad or pn < acc.prev or (pn == acc.prev and not(dupOk)) })
        if (manifest.length() == 0 or first.status == HTTP_OK) first
        else if (w.bad) { status: HTTP_BAD_REQUEST, err: "InvalidPartOrder" }
        else if (unknown) { status: HTTP_BAD_REQUEST, err: "InvalidPart" }
        else first

    // Is the manifest exactly parts 1..N?
    pure def manifestContiguous(manifest: List[int]): bool =
        manifest.foldl({ i: 1, ok: true }, (acc, pn) =>
            { i: acc.i + 1, ok: acc.ok and pn == acc.i }).ok

    def completeCheck(parts: int -> Blocks, manifest: List[int]): { status: int, err: str } =
        if (dev("M-complete-checks-by-kind"))
            completeCheckByKind(parts, manifest, dev("M-complete-duplicate-part-accepted"),
                                dev("M-complete-empty-manifest-invalidrequest"))
        else
            completeCheckWith(parts, manifest, dev("M-complete-duplicate-part-accepted"),
                              dev("M-complete-empty-manifest-invalidrequest"))

    // The assembled object: manifest parts concatenated in manifest order
    // (empty parts contribute nothing).
    pure def assembleParts(parts: int -> Blocks, manifest: List[int]): Blocks =
        manifest.foldl([], (acc, pn) => acc.concat(parts.get(pn)))

    // Manifest candidates the generator draws from: the full ascending
    // manifest (success), a proper ascending subset (success; orphans the
    // dropped part), the reverse (InvalidPartOrder), a duplicated tail
    // (InvalidPartOrder), a never-uploaded part appended (InvalidPart),
    // and the empty manifest (MalformedXML).
    pure def manifestChoices(parts: int -> Blocks): Set[List[int]] =
        val pns = sortedParts(parts)
        Set(pns, List(), pns.append(BOGUS_PART))
            .union(if (pns.length() >= 2)
                       Set(rev(pns),
                           pns.slice(0, pns.length() - 1),
                           pns.append(pns[pns.length() - 1]))
                   else Set())

    // ------------------------------------------------------------------
    // Initialization
    // ------------------------------------------------------------------

    // The service starts with no buckets; traces create what they use
    // (CreateBucket is part of the modeled surface).  Under P_FIXED_BUCKET it
    // starts with the one bucket it will ever have.
    action init = all {
        bkts' = if (P_FIXED_BUCKET) Map("bk0" -> EMPTY_BKT) else Map(),
        nextUpl' = 1,
        devHits' = Set(),
        lastOp' = OInit,
    }

    // ------------------------------------------------------------------
    // CreateBucket (PUT /{bucket})
    // ------------------------------------------------------------------

    // Creating a bucket that already exists and is yours: us-east-1 answers an
    // idempotent 200, every other AWS region 409 BucketAlreadyOwnedByYou.
    // Which one the service under test gives is P_CREATE_OWNED_CONFLICT.
    action applyCreateBucket(b: str): bool = all {
        bkts' = if (liveBuckets.contains(b)) bkts else bkts.put(b, EMPTY_BKT),
        nextUpl' = nextUpl,
        devHits' = Set(),
        // Both answers are S3's own: which one a service gives is the
        // P_CREATE_OWNED_CONFLICT policy, not a deviation.  The bucket is left
        // as it was either way.
        lastOp' = OCreateBucket({
            bucket: b,
            status: if (liveBuckets.contains(b) and P_CREATE_OWNED_CONFLICT)
                        HTTP_CONFLICT
                    else HTTP_OK }),
    }

    action createBucket = all {
        not(P_FIXED_BUCKET),
        {
            nondet b = oneOf(BKT_UNIVERSE)
            applyCreateBucket(b)
        },
    }

    // ------------------------------------------------------------------
    // HeadBucket (HEAD /{bucket})
    // ------------------------------------------------------------------

    action applyHeadBucket(b: str): bool = all {
        bkts' = bkts,
        nextUpl' = nextUpl,
        devHits' = Set(),
        lastOp' = OHeadBucket({
            bucket: b,
            status: if (liveBuckets.contains(b)) HTTP_OK else HTTP_NOT_FOUND }),
    }

    action headBucket = {
        nondet b = oneOf(BKT_UNIVERSE)
        applyHeadBucket(b)
    }

    // ------------------------------------------------------------------
    // DeleteBucket (DELETE /{bucket})
    // ------------------------------------------------------------------

    // A bucket must hold no objects AND no in-progress multipart uploads
    // to be deletable.  (The in-flight-upload 409 is never generated; see
    // the module comment.)

    // Is this DELETE the non-empty-bucket refusal?  Named so the deviating
    // status and the deviation record can ask the same question of the same
    // state, instead of the harness reconstructing it from the trace.
    pure def delBktNonEmptyIn(bs: str -> Bkt, b: str): bool =
        bs.keys().contains(b) and
        (bs.get(b).objs.keys().size() > 0 or bs.get(b).mpu.keys().size() > 0
            // a version or a delete marker is content too
            or bs.get(b).hist.keys().size() > 0)

    action applyDeleteBucket(b: str): bool = all {
        bkts' =
            if (liveBuckets.contains(b) and not(delBktNonEmptyIn(bkts, b)))
                mapDrop(bkts, b)
            else bkts,
        nextUpl' = nextUpl,
        // AWS answers 409 BucketNotEmpty here (S3 API Reference, DeleteBucket).
        // chimera has no mapping for its internal BUCKET_NOT_EMPTY, so the
        // refusal falls through the gateway's default arm and comes back as
        // 500 InternalError -- the right decision, reported as a server fault.
        devHits' =
            if (delBktNonEmptyIn(bkts, b) and dev("delete-bucket-nonempty-500"))
                Set("delete-bucket-nonempty-500")
            else Set(),
        lastOp' =
            if (not(liveBuckets.contains(b)))
                ODeleteBucket({ bucket: b, status: HTTP_NOT_FOUND, err: "NoSuchBucket" })
            else if (delBktNonEmptyIn(bkts, b))
                if (dev("delete-bucket-nonempty-500"))
                    ODeleteBucket({ bucket: b, status: HTTP_INTERNAL,
                                    err: "InternalError" })
                else
                    ODeleteBucket({ bucket: b, status: HTTP_CONFLICT,
                                    err: "BucketNotEmpty" })
            else
                ODeleteBucket({ bucket: b, status: HTTP_NO_CONTENT, err: "" }),
    }

    action deleteBucket = all {
        not(P_FIXED_BUCKET),
        {
            nondet b = oneOf(BKT_UNIVERSE)
            applyDeleteBucket(b)
        },
    }

    // ------------------------------------------------------------------
    // ListBuckets (GET /)
    // ------------------------------------------------------------------

    // The response bucket list is compared as a set: AWS documents no
    // contractual ordering for ListBuckets.
    action listBuckets = all {
        not(P_FIXED_BUCKET),
        bkts' = bkts,
        nextUpl' = nextUpl,
        devHits' = Set(),
        lastOp' = OListBuckets({ buckets: liveBuckets, status: HTTP_OK }),
    }

    // ------------------------------------------------------------------
    // PutObject (PUT /{bucket}/{key})
    // ------------------------------------------------------------------

    // A PUT into a live bucket creates or replaces the object -- content,
    // metadata and (implicitly empty) tag set alike.  Keys with slashes
    // need no parents: the namespace is flat.
    action applyPutObject(b: str, k: Key, d: Blocks, mt: int): bool =
        applyPutObjectTagged(b, k, d, mt, Set())

    // ... with a tag set of its own when the request carries x-amz-tagging.
    action applyPutObjectTagged(b: str, k: Key, d: Blocks, mt: int, ts: Set[int]): bool = all {
        bkts' =
            if (liveBuckets.contains(b))
                bkts.setBy(b, bk => bkPut(bk, k, mkObj(d, mt).with("tags", ts)))
            else bkts,
        nextUpl' = nextUpl,
        devHits' = Set(),
        lastOp' =
            if (liveBuckets.contains(b))
                OPutObject({ bucket: b, key: k, data: d, mtag: mt, tags: ts,
                             status: HTTP_OK, err: "" })
            else
                OPutObject({ bucket: b, key: k, data: d, mtag: mt, tags: ts,
                             status: HTTP_NOT_FOUND, err: "NoSuchBucket" }),
    }

    action putObjectTagged = all {
        liveBuckets.size() > 0,
        totalObjs < MAX_OBJECTS,
        {
            nondet b = oneOf(liveBuckets)
            nondet k = oneOf(KEYS)
            nondet d = oneOf(DATAS)
            nondet mt = oneOf(MTAGS)
            nondet ts = oneOf(TAGSETS)
            applyPutObjectTagged(b, k, d, mt, ts)
        },
    }

    action putObject = all {
        liveBuckets.size() > 0,
        totalObjs < MAX_OBJECTS,
        {
            nondet b = oneOf(liveBuckets)
            nondet k = oneOf(KEYS)
            nondet d = oneOf(DATAS)
            nondet mt = oneOf(MTAGS)
            applyPutObject(b, k, d, mt)
        },
    }

    // PUT against any bucket name, live or not (NoSuchBucket coverage).
    action putObjectAny = all {
        totalObjs < MAX_OBJECTS,
        {
            nondet b = oneOf(BKT_UNIVERSE)
            nondet k = oneOf(KEYS)
            nondet d = oneOf(DATAS)
            applyPutObject(b, k, d, 0)
        },
    }

    // ------------------------------------------------------------------
    // GetObject (GET /{bucket}/{key}), optionally ranged
    // ------------------------------------------------------------------

    // A satisfiable Range whose result happens to span the whole object.
    // RFC 7233 4.1: a 206 is the answer to a satisfiable Range request, and
    // nothing there makes an exception for one that covers everything.
    pure def rangeIsFull(d: Blocks, r: Range): bool =
        val ro = rangeApply(d, r)
        ro.status == HTTP_PARTIAL and ro.first == 0 and ro.out.length() == d.length()

    pure def getIsFullRange(bs: str -> Bkt, b: str, k: Key, r: Range): bool =
        if (bs.keys().contains(b) and bs.get(b).objs.keys().contains(k))
            rangeIsFull(bs.get(b).objs.get(k).data, r)
        else false

    pure def isSuffixRange(r: Range): bool =
        match r {
            | RSuffix(n) => true
            | _ => false
        }

    // A suffix range against a zero-length object: unsatisfiable on AWS (416),
    // but MinIO answers 206 with an empty body and the impossible
    // "Content-Range: bytes 0--1/0".
    pure def getIsEmptySuffix(bs: str -> Bkt, b: str, k: Key, r: Range): bool =
        bs.keys().contains(b) and bs.get(b).objs.keys().contains(k)
            and bs.get(b).objs.get(k).data.length() == 0 and isSuffixRange(r)

    action applyGetObject(b: str, k: Key, r: Range): bool = all {
        bkts' = bkts,
        nextUpl' = nextUpl,
        // chimera collapses a whole-object range to a plain 200 (and then
        // sends no Content-Range, which is consistent with the 200 it chose).
        // RNone is untouched: an unranged GET is 200 on AWS too, so only a
        // request that carried a Range header can take this branch.
        devHits' =
            (if (getIsFullRange(bkts, b, k, r) and dev("range-full-200"))
                Set("range-full-200")
            else Set())
            .union(if (getIsEmptySuffix(bkts, b, k, r) and dev("M-suffix-range-empty-206"))
                Set("M-suffix-range-empty-206")
            else Set()),
        lastOp' =
            if (not(liveBuckets.contains(b)))
                OGetObject({ bucket: b, key: k, range: r, status: HTTP_NOT_FOUND,
                             err: "NoSuchBucket", data: [], first: -1, total: -1,
                             ctype: "" })
            else if (not(bkts.get(b).objs.keys().contains(k)))
                OGetObject({ bucket: b, key: k, range: r, status: HTTP_NOT_FOUND,
                             err: "NoSuchKey", data: [], first: -1, total: -1,
                             ctype: "" })
            else if (getIsEmptySuffix(bkts, b, k, r) and dev("M-suffix-range-empty-206"))
                OGetObject({ bucket: b, key: k, range: r, status: HTTP_PARTIAL,
                             err: "", data: [], first: 0, total: 0,
                             ctype: ctypeOf(bkts.get(b).objs.get(k).mtag) })
            else if (getIsEmptySuffix(bkts, b, k, r)
                    and not(P_EMPTY_SUFFIX_RANGE_UNSATISFIABLE))
                OGetObject({ bucket: b, key: k, range: r, status: HTTP_OK,
                             err: "", data: [], first: 0, total: 0,
                             ctype: ctypeOf(bkts.get(b).objs.get(k).mtag) })
            else
                val d = bkts.get(b).objs.get(k).data
                val ro = rangeApply(d, r)
                OGetObject({ bucket: b, key: k, range: r,
                             status: if (rangeIsFull(d, r) and dev("range-full-200"))
                                         HTTP_OK
                                     else ro.status,
                             err: ro.err, data: ro.out, first: ro.first,
                             // -1 on a 416 that carries no Content-Range
                             total: if (ro.status == HTTP_RANGE_ERR and
                                        not(P_RANGE_ERR_CONTENT_RANGE)) -1
                                    else d.length(),
                             ctype: if (ro.status == HTTP_RANGE_ERR) ""
                                    else ctypeOf(bkts.get(b).objs.get(k).mtag) }),
    }

    // Unranged GET over live buckets: both hits and misses (k spans KEYS).
    action getObject = all {
        liveBuckets.size() > 0,
        {
            nondet b = oneOf(liveBuckets)
            nondet k = oneOf(KEYS)
            applyGetObject(b, k, RNone)
        },
    }

    // GET against any bucket name (NoSuchBucket coverage).
    action getObjectAny = {
        nondet b = oneOf(BKT_UNIVERSE)
        nondet k = oneOf(KEYS)
        applyGetObject(b, k, RNone)
    }

    // Ranged GET on a live object: closed, open-ended and suffix ranges,
    // including starts at/past EOF (416) and lasts past EOF (clamped).
    action getObjectRange = all {
        objPairs.size() > 0,
        {
            nondet p = oneOf(objPairs)
            nondet f = oneOf(0.to(MAX_BLOCKS))
            nondet l = oneOf(0.to(MAX_BLOCKS))
            nondet n = oneOf(1.to(MAX_BLOCKS + 1))
            nondet r = oneOf(Set(RClosed({ first: imin(f, l), last: imax(f, l) }),
                                 RFrom(f), RSuffix(n)))
            applyGetObject(p._1, p._2, r)
        },
    }

    // ------------------------------------------------------------------
    // HeadObject (HEAD /{bucket}/{key})
    // ------------------------------------------------------------------

    // A HEAD response has no body, so `err` is not modeled (there is no
    // XML <Code> to compare); the harness checks status, Content-Length,
    // Content-Type/x-amz-meta echo and the x-amz-tagging-count header
    // (from the post-state object's mtag and tag set).
    action applyHeadObject(b: str, k: Key): bool = all {
        bkts' = bkts,
        nextUpl' = nextUpl,
        devHits' = Set(),
        lastOp' =
            if (liveBuckets.contains(b) and bkts.get(b).objs.keys().contains(k))
                OHeadObject({ bucket: b, key: k, status: HTTP_OK,
                              sizeBlocks: bkts.get(b).objs.get(k).data.length(),
                              ctype: ctypeOf(bkts.get(b).objs.get(k).mtag) })
            else
                OHeadObject({ bucket: b, key: k, status: HTTP_NOT_FOUND,
                              sizeBlocks: -1, ctype: "" }),
    }

    action headObject = all {
        liveBuckets.size() > 0,
        {
            nondet b = oneOf(liveBuckets)
            nondet k = oneOf(KEYS)
            applyHeadObject(b, k)
        },
    }

    // ------------------------------------------------------------------
    // DeleteObject (DELETE /{bucket}/{key})
    // ------------------------------------------------------------------

    // AWS DeleteObject is idempotent: 204 whether or not the key exists
    // (only a missing *bucket* is an error).
    // Does this key exist right now?  The harness used to answer questions like
    // this from the trace's op record; the model can just look.
    pure def delObjHasKeyIn(bs: str -> Bkt, b: str, k: Key): bool =
        bs.keys().contains(b) and bs.get(b).objs.keys().contains(k)

    action applyDeleteObject(b: str, k: Key): bool = all {
        bkts' =
            if (liveBuckets.contains(b))
                bkts.setBy(b, bk => bkDel(bk, k))
            else bkts,
        nextUpl' = nextUpl,
        // AWS is idempotent here: 204 whether or not the key existed, and only
        // a missing BUCKET is an error.  chimera answers 200 for a key it
        // deleted and 404 NoSuchKey for one that was not there, so both halves
        // are separate claims that can be retired separately.
        devHits' =
            if (not(liveBuckets.contains(b))) Set()
            else if (delObjHasKeyIn(bkts, b, k) and dev("delete-object-200"))
                Set("delete-object-200")
            else if (not(delObjHasKeyIn(bkts, b, k)) and dev("delete-object-missing-404"))
                Set("delete-object-missing-404")
            else Set(),
        lastOp' =
            if (not(liveBuckets.contains(b)))
                ODeleteObject({ bucket: b, key: k, status: HTTP_NOT_FOUND,
                                err: "NoSuchBucket" })
            else if (delObjHasKeyIn(bkts, b, k) and dev("delete-object-200"))
                ODeleteObject({ bucket: b, key: k, status: HTTP_OK, err: "" })
            else if (not(delObjHasKeyIn(bkts, b, k)) and dev("delete-object-missing-404"))
                ODeleteObject({ bucket: b, key: k, status: HTTP_NOT_FOUND,
                                err: "NoSuchKey" })
            else
                ODeleteObject({ bucket: b, key: k, status: HTTP_NO_CONTENT, err: "" }),
    }

    action deleteObject = all {
        liveBuckets.size() > 0,
        {
            nondet b = oneOf(liveBuckets)
            nondet k = oneOf(KEYS)
            applyDeleteObject(b, k)
        },
    }

    // Delete against any bucket name (NoSuchBucket coverage).
    action deleteObjectAny = {
        nondet b = oneOf(BKT_UNIVERSE)
        nondet k = oneOf(KEYS)
        applyDeleteObject(b, k)
    }

    // Delete biased to live objects (churn for listing flavors).
    action deleteObjectHit = all {
        objPairs.size() > 0,
        {
            nondet p = oneOf(objPairs)
            applyDeleteObject(p._1, p._2)
        },
    }

    // ------------------------------------------------------------------
    // DeleteObjects batch (POST /{bucket}?delete)
    // ------------------------------------------------------------------

    // Every named key is reported <Deleted>, present or not (idempotent,
    // matching single DeleteObject); Quiet suppresses the <Deleted>
    // entries.  Duplicate keys in one request are legal; see deletedReport
    // for how they are reported.
    // The <Deleted> entries of the reply, as a list of keys.  The ORDER is not
    // part of the contract -- AWS does not keep the request's -- so a harness
    // compares it as a multiset.  Quiet reports nothing.  A key named more
    // than once is reported once (AWS), once per occurrence
    // (P_DELETE_REPORTS_DUPLICATES), or once by name and then as an entry
    // naming no key at all, NO_KEY (MinIO, M-delete-objects-dup-empty).
    pure def deletedReport(ks: List[Key], quiet: bool): List[Key] =
        if (quiet) []
        else ks.foldl([], (acc, k) =>
            if (not(acc.select(x => x == k).length() > 0)) acc.append(k)
            else if (dev("M-delete-objects-dup-empty")) acc.append(NO_KEY)
            else if (P_DELETE_REPORTS_DUPLICATES) acc.append(k)
            else acc)

    action applyDeleteObjects(b: str, ks: List[Key], quiet: bool): bool = all {
        bkts' =
            if (liveBuckets.contains(b))
                // a key named twice is deleted once
                bkts.setBy(b, bk =>
                    ks.foldl([], (u, k) =>
                            if (u.select(x => x == k).length() > 0) u else u.append(k))
                      .foldl(bk, (acc, k) => bkDel(acc, k)))
            else bkts,
        nextUpl' = nextUpl,
        // MinIO deletes the key and reports its FIRST occurrence, then answers
        // every repeat with an empty <Deleted/> element that names no key
        // (M-delete-objects-dup-empty; NO_KEY in `deleted`).  Quiet mode
        // reports nothing for anyone, so only a verbose request can take it.
        devHits' =
            if (liveBuckets.contains(b) and not(quiet) and ks.length() == 2
                    and ks[0] == ks[1] and dev("M-delete-objects-dup-empty"))
                Set("M-delete-objects-dup-empty")
            else Set(),
        lastOp' =
            if (not(liveBuckets.contains(b)))
                ODeleteObjects({ bucket: b, keys: ks, quiet: quiet,
                                 status: HTTP_NOT_FOUND, err: "NoSuchBucket",
                                 deleted: [] })
            else
                ODeleteObjects({ bucket: b, keys: ks, quiet: quiet,
                                 status: HTTP_OK, err: "",
                                 deleted: deletedReport(ks, quiet) }),
    }

    action deleteObjects = all {
        liveBuckets.size() > 0,
        {
            nondet b = oneOf(liveBuckets)
            nondet ks = oneOf(DELETE_BATCHES)
            nondet q = oneOf(Set(false, true))
            applyDeleteObjects(b, ks, q)
        },
    }

    action deleteObjectsAny = {
        nondet b = oneOf(BKT_UNIVERSE)
        nondet ks = oneOf(DELETE_BATCHES)
        nondet q = oneOf(Set(false, true))
        applyDeleteObjects(b, ks, q)
    }

    // ------------------------------------------------------------------
    // CopyObject (PUT /{dstBucket}/{dstKey} + x-amz-copy-source)
    // ------------------------------------------------------------------

    // The request URI names the destination, so a missing destination
    // bucket reports before the source is looked at.  A copy onto itself
    // with no metadata directive is 400 InvalidRequest.  A copy replicates
    // the whole object: content, metadata, and (x-amz-tagging-directive
    // COPY being the default) the tag set.
    //
    // AWS documents no precedence between the two failures, so which is
    // resolved first is the P_COPY_SOURCE_FIRST policy: source first, and a
    // copy of a missing key into a missing bucket reports NoSuchKey.  (With
    // both buckets missing the two orders give the same NoSuchBucket.)
    pure def copySrcKeyFirstIn(bs: str -> Bkt, sb: str, sk: Key, db: str): bool =
        not(bs.keys().contains(db)) and bs.keys().contains(sb)
            and not(bs.get(sb).objs.keys().contains(sk))

    action applyCopyObject(sb: str, sk: Key, db: str, dk: Key): bool =
        applyCopyObjectDir(sb, sk, db, dk, -1, false, Set())

    // The copy is one part whatever the source was.  A REPLACE directive
    // substitutes the request's own metadata (mdir) or tags (ts) for the
    // source's, and makes a copy onto itself legal: something changes.
    action applyCopyObjectDir(sb: str, sk: Key, db: str, dk: Key, mdir: int,
                              treplace: bool, ts: Set[int]): bool = all {
        bkts' =
            if (liveBuckets.contains(db) and liveBuckets.contains(sb)
                    and bkts.get(sb).objs.keys().contains(sk)
                    and (not(sb == db and sk == dk) or mdir >= 0 or treplace))
                val src = bkts.get(sb).objs.get(sk)
                bkts.setBy(db, bk =>
                    bkPut(bk, dk,
                        { data: src.data,
                          mtag: if (mdir >= 0) mdir else src.mtag,
                          tags: if (treplace) ts else src.tags,
                          parts: if (sb == db and sk == dk and mdir < 0 and not(treplace))
                                     src.parts else [] }))
            else bkts,
        nextUpl' = nextUpl,
        // AWS rejects a copy of an object onto itself when nothing about it
        // would change -- no x-amz-metadata-directive REPLACE -- with 400
        // InvalidRequest (S3 API Reference, CopyObject, "This copy request is
        // illegal because it is trying to copy an object to itself").  chimera
        // does not special-case the self-copy and just performs it, answering
        // 200.  The predicate is exactly `sb == db and sk == dk`, which the
        // model can ask directly; the harness used to rebuild it from the
        // trace's four name fields.
        //
        // Note bkts' above: the self-copy is excluded from the write, and that
        // stays right under the deviation too -- rewriting an object with its
        // own content and metadata yields the identical map, so chimera's
        // performing the copy is invisible in the modeled state.
        devHits' =
            if (liveBuckets.contains(db) and liveBuckets.contains(sb)
                    and bkts.get(sb).objs.keys().contains(sk)
                    and sb == db and sk == dk and mdir < 0 and not(treplace)
                    and dev("copy-self-200"))
                Set("copy-self-200")
            else Set(),
        lastOp' =
            if (copySrcKeyFirstIn(bkts, sb, sk, db) and P_COPY_SOURCE_FIRST)
                OCopyObject({ srcBucket: sb, srcKey: sk, dstBucket: db, dstKey: dk,
                              mdir: mdir, treplace: treplace, tags: ts,
                              status: HTTP_NOT_FOUND, err: "NoSuchKey" })
            else if (not(liveBuckets.contains(db)))
                OCopyObject({ srcBucket: sb, srcKey: sk, dstBucket: db, dstKey: dk,
                              mdir: mdir, treplace: treplace, tags: ts,
                              status: HTTP_NOT_FOUND, err: "NoSuchBucket" })
            else if (not(liveBuckets.contains(sb)))
                OCopyObject({ srcBucket: sb, srcKey: sk, dstBucket: db, dstKey: dk,
                              mdir: mdir, treplace: treplace, tags: ts,
                              status: HTTP_NOT_FOUND, err: "NoSuchBucket" })
            else if (not(bkts.get(sb).objs.keys().contains(sk)))
                OCopyObject({ srcBucket: sb, srcKey: sk, dstBucket: db, dstKey: dk,
                              mdir: mdir, treplace: treplace, tags: ts,
                              status: HTTP_NOT_FOUND, err: "NoSuchKey" })
            else if (sb == db and sk == dk and mdir < 0 and not(treplace)
                    and not(dev("copy-self-200")) and not(P_COPY_SELF_ACCEPTED))
                OCopyObject({ srcBucket: sb, srcKey: sk, dstBucket: db, dstKey: dk,
                              mdir: mdir, treplace: treplace, tags: ts,
                              status: HTTP_BAD_REQUEST, err: "InvalidRequest" })
            else
                OCopyObject({ srcBucket: sb, srcKey: sk, dstBucket: db, dstKey: dk,
                              mdir: mdir, treplace: treplace, tags: ts,
                              status: HTTP_OK, err: "" }),
    }

    // Copy from a live object into a live bucket (the productive path,
    // including self-copy -> 400).
    action copyObject = all {
        objPairs.size() > 0,
        totalObjs < MAX_OBJECTS,
        {
            nondet p = oneOf(objPairs)
            nondet db = oneOf(liveBuckets)
            nondet dk = oneOf(KEYS)
            applyCopyObject(p._1, p._2, db, dk)
        },
    }

    // Copy under a REPLACE directive: new metadata, new tags, or both --
    // including onto itself, which is how S3 changes an object's metadata.
    action copyObjectReplace = all {
        objPairs.size() > 0,
        totalObjs < MAX_OBJECTS,
        {
            nondet p = oneOf(objPairs)
            nondet db = oneOf(liveBuckets)
            nondet dk = oneOf(KEYS)
            nondet self = oneOf(Set(false, true))
            nondet mdir = oneOf(Set(-1, 0, 1, 2))
            nondet treplace = oneOf(Set(false, true))
            nondet ts = oneOf(TAGSETS)
            all {
                mdir >= 0 or treplace,
                applyCopyObjectDir(p._1, p._2, if (self) p._1 else db,
                                   if (self) p._2 else dk, mdir, treplace,
                                   if (treplace) ts else Set()),
            }
        },
    }

    // Copy with unconstrained names (NoSuchBucket / NoSuchKey coverage).
    action copyObjectAny = all {
        totalObjs < MAX_OBJECTS,
        {
            nondet sb = oneOf(BKT_UNIVERSE)
            nondet sk = oneOf(KEYS)
            nondet db = oneOf(BKT_UNIVERSE)
            nondet dk = oneOf(KEYS)
            applyCopyObject(sb, sk, db, dk)
        },
    }

    // ------------------------------------------------------------------
    // Conditional requests (RFC 9110 13, as S3 applies it)
    // ------------------------------------------------------------------

    // Does the precondition `c` of a conditional GET hold for an object that
    // exists?  And what does S3 answer when it does not: a failed If-Match or
    // If-Unmodified-Since is 412, a failed If-None-Match is 304.
    pure def condGetStatus(c: int): int =
        if (c == 2 or c == 6) HTTP_PRECOND
        else if (c == 3) HTTP_NOT_MODIFIED
        else HTTP_OK

    action applyCondGet(b: str, k: Key, hd: bool, c: int): bool = all {
        bkts' = bkts,
        nextUpl' = nextUpl,
        devHits' = Set(),
        lastOp' =
            if (not(liveBuckets.contains(b)))
                OCondGet({ bucket: b, key: k, head: hd, cond: c,
                           status: HTTP_NOT_FOUND,
                           err: if (hd) "" else "NoSuchBucket", data: [] })
            else if (not(bkts.get(b).objs.keys().contains(k)))
                OCondGet({ bucket: b, key: k, head: hd, cond: c,
                           status: HTTP_NOT_FOUND,
                           err: if (hd) "" else "NoSuchKey", data: [] })
            else
                val st = condGetStatus(c)
                OCondGet({ bucket: b, key: k, head: hd, cond: c, status: st,
                           // a 304 has no body, and neither has a HEAD
                           err: if (st == HTTP_PRECOND and not(hd))
                                    "PreconditionFailed" else "",
                           data: if (st == HTTP_OK and not(hd))
                                     bkts.get(b).objs.get(k).data else [] }),
    }

    action condGet = all {
        F_CONDITIONAL,
        liveBuckets.size() > 0,
        {
            nondet b = oneOf(liveBuckets)
            nondet k = oneOf(KEYS)
            nondet hd = oneOf(Set(false, true))
            nondet c = oneOf(1.to(7))
            applyCondGet(b, k, hd, c)
        },
    }

    // A conditional GET biased to objects that exist.
    action condGetHit = all {
        F_CONDITIONAL,
        objPairs.size() > 0,
        {
            nondet p = oneOf(objPairs)
            nondet hd = oneOf(Set(false, true))
            nondet c = oneOf(1.to(7))
            applyCondGet(p._1, p._2, hd, c)
        },
    }

    // If-None-Match: * writes only where nothing is; If-Match writes only
    // over the object it names, and names one that must exist.
    action applyCondPut(b: str, k: Key, d: Blocks, c: int): bool = all {
        val live = liveBuckets.contains(b)
        val has = live and bkts.get(b).objs.keys().contains(k)
        val st = if (not(live)) HTTP_NOT_FOUND
                 else if (c == 1) (if (has) HTTP_PRECOND else HTTP_OK)
                 else if (not(has)) HTTP_NOT_FOUND
                 else if (c == 2) HTTP_OK
                 else HTTP_PRECOND
        all {
            bkts' =
                if (st == HTTP_OK)
                    bkts.setBy(b, bk => bkPut(bk, k, mkObj(d, 0)))
                else bkts,
            nextUpl' = nextUpl,
            devHits' = Set(),
            lastOp' = OCondPut({ bucket: b, key: k, data: d, cond: c, status: st,
                                 err: if (st == HTTP_OK) ""
                                      else if (st == HTTP_PRECOND) "PreconditionFailed"
                                      else if (not(live)) "NoSuchBucket"
                                      else "NoSuchKey" }),
        }
    }

    action condPut = all {
        F_CONDITIONAL,
        liveBuckets.size() > 0,
        totalObjs < MAX_OBJECTS,
        {
            nondet b = oneOf(liveBuckets)
            nondet k = oneOf(KEYS)
            nondet d = oneOf(DATAS)
            nondet c = oneOf(1.to(3))
            applyCondPut(b, k, d, c)
        },
    }

    // A copy conditional on its SOURCE.  Either failure is 412 here: there
    // is no 304 for a request that is not a read.
    action applyCondCopy(sb: str, sk: Key, db: str, dk: Key, c: int): bool = all {
        val ok = c == 1 or c == 4
        all {
            bkts' =
                if (ok)
                    bkts.setBy(db, bk => bkPut(bk, dk,
                        bkts.get(sb).objs.get(sk).with("parts", [])))
                else bkts,
            nextUpl' = nextUpl,
            devHits' = Set(),
            lastOp' = OCondCopy({ srcBucket: sb, srcKey: sk, dstBucket: db,
                                  dstKey: dk, cond: c,
                                  status: if (ok) HTTP_OK else HTTP_PRECOND,
                                  err: if (ok) "" else "PreconditionFailed" }),
        }
    }

    // From a live object to a different key of a live bucket.
    action condCopy = all {
        F_CONDITIONAL,
        objPairs.size() > 0,
        totalObjs < MAX_OBJECTS,
        {
            nondet p = oneOf(objPairs)
            nondet db = oneOf(liveBuckets)
            nondet dk = oneOf(KEYS)
            nondet c = oneOf(1.to(4))
            all {
                not(p._1 == db and p._2 == dk),
                applyCondCopy(p._1, p._2, db, dk, c),
            }
        },
    }

    // ------------------------------------------------------------------
    // Other routes to the wire
    // ------------------------------------------------------------------

    // The route changes nothing about what a PutObject does -- except the
    // one that names a checksum of bytes it did not send, which is refused
    // and writes nothing.
    action applyPutVia(b: str, k: Key, d: Blocks, via: str): bool = all {
        bkts' =
            if (via != "header-crc32-bad")
                bkts.setBy(b, bk => bkPut(bk, k, mkObj(d, 0)))
            else bkts,
        nextUpl' = nextUpl,
        devHits' =
            if (via == "header-crc32-bad" and dev("M-checksum-mismatch-code"))
                Set("M-checksum-mismatch-code")
            else Set(),
        lastOp' =
            if (via == "header-crc32-bad")
                OPutVia({ bucket: b, key: k, data: d, via: via,
                          status: HTTP_BAD_REQUEST,
                          err: if (dev("M-checksum-mismatch-code"))
                                   "XAmzContentChecksumMismatch"
                               else "BadDigest" })
            else
                OPutVia({ bucket: b, key: k, data: d, via: via,
                          status: HTTP_OK, err: "" }),
    }

    val putVias =
        (if (F_PRESIGNED) Set("presigned") else Set())
        .union(if (F_CHECKSUMS)
                   Set("trailer-crc32", "header-crc32", "header-crc32-bad")
               else Set())

    action putVia = all {
        liveBuckets.size() > 0,
        totalObjs < MAX_OBJECTS,
        putVias.size() > 0,
        {
            nondet b = oneOf(liveBuckets)
            nondet k = oneOf(KEYS)
            nondet d = oneOf(DATAS)
            nondet via = oneOf(putVias)
            applyPutVia(b, k, d, via)
        },
    }

    // A request whose credentials are wrong is refused before anything about
    // the object is looked at.
    action applyGetVia(b: str, k: Key, via: str): bool = all {
        bkts' = bkts,
        nextUpl' = nextUpl,
        devHits' = Set(),
        lastOp' =
            if (via == "bad-signature")
                OGetVia({ bucket: b, key: k, via: via, status: HTTP_FORBIDDEN,
                          err: "SignatureDoesNotMatch", data: [] })
            else if (via == "unknown-key")
                OGetVia({ bucket: b, key: k, via: via, status: HTTP_FORBIDDEN,
                          err: "InvalidAccessKeyId", data: [] })
            else if (not(bkts.get(b).objs.keys().contains(k)))
                OGetVia({ bucket: b, key: k, via: via, status: HTTP_NOT_FOUND,
                          err: "NoSuchKey", data: [] })
            else
                OGetVia({ bucket: b, key: k, via: via, status: HTTP_OK, err: "",
                          data: bkts.get(b).objs.get(k).data }),
    }

    action getVia = all {
        liveBuckets.size() > 0,
        {
            nondet b = oneOf(liveBuckets)
            nondet k = oneOf(KEYS)
            nondet via = oneOf(Set("bad-signature", "unknown-key").union(
                if (F_PRESIGNED) Set("presigned") else Set()))
            applyGetVia(b, k, via)
        },
    }

    action getViaHit = all {
        F_PRESIGNED,
        objPairs.size() > 0,
        {
            nondet p = oneOf(objPairs)
            applyGetVia(p._1, p._2, "presigned")
        },
    }

    // ------------------------------------------------------------------
    // Bucket location and ACLs
    // ------------------------------------------------------------------

    action applyGetBktLocation(b: str): bool = all {
        bkts' = bkts,
        nextUpl' = nextUpl,
        devHits' = Set(),
        lastOp' =
            if (liveBuckets.contains(b))
                OGetBktLocation({ bucket: b, status: HTTP_OK, err: "" })
            else
                OGetBktLocation({ bucket: b, status: HTTP_NOT_FOUND,
                                  err: "NoSuchBucket" }),
    }

    action getBktLocation = {
        nondet b = oneOf(BKT_UNIVERSE)
        applyGetBktLocation(b)
    }

    action applyGetAcl(b: str, k: Key): bool = all {
        bkts' = bkts,
        nextUpl' = nextUpl,
        devHits' = Set(),
        lastOp' =
            if (not(liveBuckets.contains(b)))
                OGetAcl({ bucket: b, key: k, status: HTTP_NOT_FOUND,
                          err: "NoSuchBucket" })
            else if (k != NO_KEY and not(bkts.get(b).objs.keys().contains(k)))
                OGetAcl({ bucket: b, key: k, status: HTTP_NOT_FOUND,
                          err: "NoSuchKey" })
            else
                OGetAcl({ bucket: b, key: k, status: HTTP_OK, err: "" }),
    }

    action getAcl = all {
        F_ACL,
        {
            nondet b = oneOf(BKT_UNIVERSE)
            nondet k = oneOf(KEYS.union(Set(NO_KEY)))
            applyGetAcl(b, k)
        },
    }

    // ------------------------------------------------------------------
    // Versioning
    // ------------------------------------------------------------------

    // The first time versioning is configured, what the bucket already holds
    // becomes its history: each object is the null version of its key.
    action applyPutBktVersioning(b: str, st: int): bool = all {
        bkts' =
            if (liveBuckets.contains(b))
                bkts.setBy(b, bk =>
                    (if (bk.ver == 0)
                        bk.with("hist", bk.objs.keys().mapBy(k =>
                            [{ vid: 0, dm: false, obj: bk.objs.get(k) }]))
                     else bk).with("ver", st))
            else bkts,
        nextUpl' = nextUpl,
        devHits' = Set(),
        lastOp' =
            if (liveBuckets.contains(b))
                OPutBktVersioning({ bucket: b, state: st, status: HTTP_OK, err: "" })
            else
                OPutBktVersioning({ bucket: b, state: st, status: HTTP_NOT_FOUND,
                                    err: "NoSuchBucket" }),
    }

    // Not under P_FIXED_BUCKET: versioning is one setting for the whole
    // bucket, and a bucket the tester was handed is not the tester's to
    // reconfigure.
    action putBktVersioning = all {
        F_VERSIONING,
        not(P_FIXED_BUCKET),
        {
            nondet b = oneOf(BKT_UNIVERSE)
            nondet st = oneOf(Set(1, 1, 2))
            applyPutBktVersioning(b, st)
        },
    }

    action applyGetBktVersioning(b: str): bool = all {
        bkts' = bkts,
        nextUpl' = nextUpl,
        devHits' = Set(),
        lastOp' =
            if (liveBuckets.contains(b))
                OGetBktVersioning({ bucket: b, status: HTTP_OK, err: "",
                                    state: bkts.get(b).ver })
            else
                OGetBktVersioning({ bucket: b, status: HTTP_NOT_FOUND,
                                    err: "NoSuchBucket", state: 0 }),
    }

    action getBktVersioning = all {
        F_VERSIONING,
        not(P_FIXED_BUCKET),
        {
            nondet b = oneOf(BKT_UNIVERSE)
            applyGetBktVersioning(b)
        },
    }

    // Every (bucket, key, version id) there is.
    val verTriples = liveBuckets.map(b =>
        bkts.get(b).hist.keys().map(k =>
            bkts.get(b).hist.get(k).foldl(Set(), (acc, v) =>
                acc.union(Set((b, k, v.vid))))).flatten()).flatten()

    pure def verOf(bk: Bkt, k: Key, vid: int): Ver =
        bk.hist.get(k).select(v => v.vid == vid)[0]

    // One version, by id.  A delete marker has nothing to return: 405, and
    // the reply says what it is.
    action applyGetVersion(b: str, k: Key, vid: int, hd: bool): bool = all {
        bkts' = bkts,
        nextUpl' = nextUpl,
        devHits' = Set(),
        lastOp' =
            val v = verOf(bkts.get(b), k, vid)
            if (v.dm)
                OGetVersion({ bucket: b, key: k, vid: vid, head: hd,
                              status: HTTP_METHOD_NOT_ALLOWED,
                              err: if (hd) "" else "MethodNotAllowed",
                              data: [], dm: true })
            else
                OGetVersion({ bucket: b, key: k, vid: vid, head: hd,
                              status: HTTP_OK, err: "",
                              data: if (hd) [] else v.obj.data, dm: false }),
    }

    action getVersion = all {
        verTriples.size() > 0,
        {
            nondet t = oneOf(verTriples)
            nondet hd = oneOf(Set(false, true))
            applyGetVersion(t._1, t._2, t._3, hd)
        },
    }

    action applyDeleteVersion(b: str, k: Key, vid: int): bool = all {
        bkts' = bkts.setBy(b, bk => bkDropVer(bk, k, vid)),
        nextUpl' = nextUpl,
        devHits' = Set(),
        lastOp' = ODeleteVersion({ bucket: b, key: k, vid: vid,
                                   status: HTTP_NO_CONTENT, err: "",
                                   dm: verOf(bkts.get(b), k, vid).dm }),
    }

    action deleteVersion = all {
        verTriples.size() > 0,
        {
            nondet t = oneOf(verTriples)
            applyDeleteVersion(t._1, t._2, t._3)
        },
    }

    // The history of every key: keys in byte order, and for one key the
    // newest version first.
    action applyListVersions(b: str): bool = all {
        bkts' = bkts,
        nextUpl' = nextUpl,
        devHits' = Set(),
        lastOp' =
            val bk = bkts.get(b)
            OListVersions({ bucket: b, status: HTTP_OK, err: "",
                versions: ENT_ORDER.foldl([], (acc, e) =>
                    match e {
                        | EPfx(x) => acc
                        | EKey(k) =>
                            val h = histOf(bk, k)
                            acc.concat(h.foldl([], (a2, v) =>
                                [{ key: k, vid: v.vid, dm: v.dm,
                                   latest: v.vid == h[h.length() - 1].vid }].concat(a2)))
                    }) }),
    }

    action listVersions = all {
        {
            val vb = liveBuckets.filter(b => bkts.get(b).ver != 0)
            all {
                vb.size() > 0,
                {
                    nondet b = oneOf(vb)
                    applyListVersions(b)
                },
            }
        },
    }

    // ------------------------------------------------------------------
    // Bucket policy
    // ------------------------------------------------------------------

    // AWS answers every successful policy write with 204.
    action applyPutBktPolicy(b: str, pol: int): bool = all {
        val refused = pol == 1 and not(P_PUBLIC_POLICY_ALLOWED)
        all {
            bkts' =
                if (liveBuckets.contains(b) and not(refused))
                    bkts.setBy(b, bk => bk.with("pol", pol))
                else bkts,
            nextUpl' = nextUpl,
            devHits' = Set(),
            lastOp' =
                if (not(liveBuckets.contains(b)))
                    OPutBktPolicy({ bucket: b, pol: pol, status: HTTP_NOT_FOUND,
                                    err: "NoSuchBucket" })
                else if (refused)
                    OPutBktPolicy({ bucket: b, pol: pol, status: HTTP_FORBIDDEN,
                                    err: "AccessDenied" })
                else
                    OPutBktPolicy({ bucket: b, pol: pol, status: HTTP_NO_CONTENT,
                                    err: "" }),
        }
    }

    // Not under P_FIXED_BUCKET, for the reason versioning is not.
    action putBktPolicy = all {
        F_BUCKET_POLICY,
        not(P_FIXED_BUCKET),
        {
            nondet b = oneOf(BKT_UNIVERSE)
            nondet pol = oneOf(Set(1, 2))
            applyPutBktPolicy(b, pol)
        },
    }

    action applyGetBktPolicy(b: str): bool = all {
        bkts' = bkts,
        nextUpl' = nextUpl,
        devHits' = Set(),
        lastOp' =
            if (not(liveBuckets.contains(b)))
                OGetBktPolicy({ bucket: b, status: HTTP_NOT_FOUND,
                                err: "NoSuchBucket", pol: 0 })
            else if (bkts.get(b).pol == 0)
                OGetBktPolicy({ bucket: b, status: HTTP_NOT_FOUND,
                                err: "NoSuchBucketPolicy", pol: 0 })
            else
                OGetBktPolicy({ bucket: b, status: HTTP_OK, err: "",
                                pol: bkts.get(b).pol }),
    }

    action getBktPolicy = all {
        F_BUCKET_POLICY,
        not(P_FIXED_BUCKET),
        {
            nondet b = oneOf(BKT_UNIVERSE)
            applyGetBktPolicy(b)
        },
    }

    action applyDelBktPolicy(b: str): bool = all {
        bkts' =
            if (liveBuckets.contains(b)) bkts.setBy(b, bk => bk.with("pol", 0))
            else bkts,
        nextUpl' = nextUpl,
        devHits' = Set(),
        lastOp' =
            if (liveBuckets.contains(b))
                ODelBktPolicy({ bucket: b, status: HTTP_NO_CONTENT, err: "" })
            else
                ODelBktPolicy({ bucket: b, status: HTTP_NOT_FOUND,
                                err: "NoSuchBucket" }),
    }

    action delBktPolicy = all {
        F_BUCKET_POLICY,
        not(P_FIXED_BUCKET),
        {
            nondet b = oneOf(BKT_UNIVERSE)
            applyDelBktPolicy(b)
        },
    }

    // Is the bucket public?  Asked only of a bucket that has a policy: with
    // none the call is NoSuchBucketPolicy, like the Get.
    action applyGetPolicyStatus(b: str): bool = all {
        bkts' = bkts,
        nextUpl' = nextUpl,
        devHits' = Set(),
        lastOp' =
            if (bkts.get(b).pol == 0)
                OGetPolicyStatus({ bucket: b, status: HTTP_NOT_FOUND,
                                   err: "NoSuchBucketPolicy", public: false })
            else
                OGetPolicyStatus({ bucket: b, status: HTTP_OK, err: "",
                                   public: bkts.get(b).pol == 1 }),
    }

    action getPolicyStatus = all {
        F_BUCKET_POLICY,
        not(P_FIXED_BUCKET),
        liveBuckets.size() > 0,
        {
            nondet b = oneOf(liveBuckets)
            applyGetPolicyStatus(b)
        },
    }

    // A GetObject with no credentials.  Served only from a bucket whose
    // policy grants it; the public policy grants GetObject and nothing else,
    // so a key that is not there is refused like everything else -- telling
    // the caller it is missing would take ListBucket.
    action applyAnonGet(b: str, k: Key): bool = all {
        bkts' = bkts,
        nextUpl' = nextUpl,
        devHits' = Set(),
        lastOp' =
            if (bkts.get(b).pol == 1 and bkts.get(b).objs.keys().contains(k))
                OAnonGet({ bucket: b, key: k, status: HTTP_OK, err: "",
                           data: bkts.get(b).objs.get(k).data })
            else
                OAnonGet({ bucket: b, key: k, status: HTTP_FORBIDDEN,
                           err: "AccessDenied", data: [] }),
    }

    action anonGet = all {
        F_BUCKET_POLICY,
        not(P_FIXED_BUCKET),
        liveBuckets.size() > 0,
        {
            nondet b = oneOf(liveBuckets)
            nondet k = oneOf(KEYS)
            applyAnonGet(b, k)
        },
    }

    // ------------------------------------------------------------------
    // Requests that are wrong in themselves
    // ------------------------------------------------------------------

    // Each kind is one malformed or out-of-limits request against a bucket
    // that exists (and, for the tagging kinds, an object that exists), so the
    // answer is about the request and not about what was missing.
    //
    //   bucket-name-upper    CreateBucket, an upper-case letter in the name
    //   bucket-name-long     CreateBucket, a name of more than 63 characters
    //   key-too-long         PutObject, a key of 1025 bytes
    //   max-keys-negative    ListObjectsV2, max-keys=-1
    //   max-keys-text        ListObjectsV2, max-keys=abc
    //   tagging-11           PutObjectTagging, eleven tags
    //   tagging-dup-key      PutObjectTagging, one tag key twice
    //   tagging-malformed    PutObjectTagging, a body that is not XML
    //   delete-empty         DeleteObjects, no <Object> at all
    //   delete-1001          DeleteObjects, 1001 keys
    //   put-bad-digest       PutObject, a Content-MD5 of other bytes
    //   put-invalid-digest   PutObject, a Content-MD5 that is not base64
    pure val INVALID_BUCKET_KINDS = Set("bucket-name-upper", "bucket-name-long")
    pure val INVALID_OBJECT_KINDS = Set("tagging-11", "tagging-dup-key",
                                        "tagging-malformed")
    pure val INVALID_KINDS = Set("key-too-long", "max-keys-negative",
        "max-keys-text", "delete-empty", "delete-1001", "put-bad-digest",
        "put-invalid-digest")

    pure def invalidReply(kind: str): { status: int, err: str } =
        if (kind == "bucket-name-upper" or kind == "bucket-name-long")
            { status: HTTP_BAD_REQUEST, err: "InvalidBucketName" }
        else if (kind == "key-too-long")
            { status: HTTP_BAD_REQUEST, err: "KeyTooLongError" }
        else if (kind == "max-keys-negative" or kind == "max-keys-text")
            { status: HTTP_BAD_REQUEST, err: "InvalidArgument" }
        else if (kind == "tagging-11")
            { status: HTTP_BAD_REQUEST, err: "BadRequest" }
        else if (kind == "tagging-dup-key")
            { status: HTTP_BAD_REQUEST, err: "InvalidTag" }
        else if (kind == "put-bad-digest")
            { status: HTTP_BAD_REQUEST, err: "BadDigest" }
        else if (kind == "put-invalid-digest")
            { status: HTTP_BAD_REQUEST, err: "InvalidDigest" }
        else
            { status: HTTP_BAD_REQUEST, err: "MalformedXML" }

    action applyInvalid(b: str, k: Key, kind: str): bool = all {
        bkts' = bkts,
        nextUpl' = nextUpl,
        devHits' = Set(),
        lastOp' = OInvalid({ bucket: b, key: k, kind: kind,
                             status: invalidReply(kind).status,
                             err: invalidReply(kind).err }),
    }

    action invalidRequest = all {
        liveBuckets.size() > 0,
        {
            nondet b = oneOf(liveBuckets)
            nondet k = oneOf(KEYS)
            nondet kind = oneOf(INVALID_KINDS.union(
                if (P_FIXED_BUCKET) Set() else INVALID_BUCKET_KINDS))
            applyInvalid(b, k, kind)
        },
    }

    action invalidObjectRequest = all {
        objPairs.size() > 0,
        {
            nondet p = oneOf(objPairs)
            nondet kind = oneOf(INVALID_OBJECT_KINDS)
            applyInvalid(p._1, p._2, kind)
        },
    }

    // ------------------------------------------------------------------
    // GetObjectAttributes (GET /{bucket}/{key}?attributes)
    // ------------------------------------------------------------------

    // The harness requests ETag, StorageClass and ObjectSize (the
    // filesystem-suppliable set); the response reports the object size and
    // an unquoted ETag the harness checks for consistency.
    //
    // M-getattrs-zero-size-omitted changes no field of the label: MinIO leaves
    // <ObjectSize> out of the document altogether when the size is 0, and the
    // recorded hit tells the harness to expect it absent.
    action applyGetAttrs(b: str, k: Key): bool = all {
        bkts' = bkts,
        nextUpl' = nextUpl,
        //
        // M-getattrs-root-lowercase is the same kind: the document's root
        // element is named getObjectAttributesResponse, with a lower-case g,
        // where the API Reference names it GetObjectAttributesResponse.  Every
        // successful reply takes it.
        devHits' =
            if (liveBuckets.contains(b) and bkts.get(b).objs.keys().contains(k))
                (if (dev("M-getattrs-root-lowercase"))
                    Set("M-getattrs-root-lowercase") else Set())
                .union(if (bkts.get(b).objs.get(k).data.length() == 0
                           and dev("M-getattrs-zero-size-omitted"))
                    Set("M-getattrs-zero-size-omitted") else Set())
            else Set(),
        lastOp' =
            if (not(liveBuckets.contains(b)))
                OGetAttrs({ bucket: b, key: k, status: HTTP_NOT_FOUND,
                            err: "NoSuchBucket", sizeBlocks: -1 })
            else if (not(bkts.get(b).objs.keys().contains(k)))
                OGetAttrs({ bucket: b, key: k, status: HTTP_NOT_FOUND,
                            err: "NoSuchKey", sizeBlocks: -1 })
            else
                OGetAttrs({ bucket: b, key: k, status: HTTP_OK, err: "",
                            sizeBlocks: bkts.get(b).objs.get(k).data.length() }),
    }

    action getAttrs = all {
        liveBuckets.size() > 0,
        {
            nondet b = oneOf(liveBuckets)
            nondet k = oneOf(KEYS)
            applyGetAttrs(b, k)
        },
    }

    // ------------------------------------------------------------------
    // ListObjects (GET /{bucket}, V1 / V2 / Versions)
    // ------------------------------------------------------------------

    // A marker (V1) or key-marker (Versions) that does not itself begin with
    // the request prefix.  On AWS that is an ordinary start key: the listing is
    // whatever matches the prefix and sorts after it.  MinIO refuses the request
    // outright with 501 NotImplemented -- before it looks at the bucket, so a
    // missing bucket reports 501 too -- and only for those two spellings: V2's
    // start-after is served.  keyMatches is string-prefix matching, which is
    // exactly "the marker begins with the prefix".
    pure def listMarkerOutside(p: Prefix, sa: Key, mode: int): bool =
        mode != 2 and sa != NO_KEY and not(keyMatches(sa, p))

    // Mode 3 dresses the walk as ListObjectVersions, which is the same walk
    // only while every key has exactly one version.  In a bucket with a
    // history it is asked as V2; listVersions is what reads the history.
    action applyListObjects(b: str, p: Prefix, delim: bool, sa: Key, mk: int, mode: int): bool =
        applyListObjectsFrom(b, p, delim, sa, mk,
            if (mode == 3 and liveBuckets.contains(b) and bkts.get(b).ver != 0) 2
            else mode,
            false, NO_RESUME)

    action applyListObjectsFrom(b: str, p: Prefix, delim: bool, sa: Key, mk: int,
                                mode: int, cont: bool, res: Resume): bool = all {
        bkts' = bkts,
        nextUpl' = nextUpl,
        // M-list-next-marker-cache-suffix changes no field of the label: on a
        // truncated V1 or Versions page MinIO names the next marker with a
        // suffix of its own, and names one for V1 whether or not a delimiter
        // was given.  The recorded hit tells the harness what to expect.
        devHits' =
            if (listMarkerOutside(p, sa, mode) and dev("M-list-marker-outside-prefix-501"))
                Set("M-list-marker-outside-prefix-501")
            else if (liveBuckets.contains(b) and mode != 2
                    and dev("M-list-next-marker-cache-suffix")
                    and listWalk(bkts.get(b).objs.keys(), p, delim, sa,
                                 imin(mk, MAXKEYS_CAP),
                                 not(P_LIST_RETURNS_MARKER_PREFIX), res).truncated)
                Set("M-list-next-marker-cache-suffix")
            else Set(),
        lastOp' =
            if (listMarkerOutside(p, sa, mode) and dev("M-list-marker-outside-prefix-501"))
                OListObjects({ bucket: b, prefix: p, delim: delim, startAfter: sa,
                               maxKeys: mk, mode: mode, cont: cont,
                               status: HTTP_NOT_IMPL, err: "NotImplemented",
                               keys: [], prefixes: [], truncated: false,
                               maxKeysEcho: -1, last: [], lastIsPfx: false })
            else if (not(liveBuckets.contains(b)))
                OListObjects({ bucket: b, prefix: p, delim: delim, startAfter: sa,
                               maxKeys: mk, mode: mode, cont: cont,
                               status: HTTP_NOT_FOUND, err: "NoSuchBucket",
                               keys: [], prefixes: [], truncated: false,
                               maxKeysEcho: -1, last: [], lastIsPfx: false })
            else
                val w = listWalk(bkts.get(b).objs.keys(), p, delim, sa,
                                 imin(mk, MAXKEYS_CAP),
                                 not(P_LIST_RETURNS_MARKER_PREFIX), res)
                OListObjects({ bucket: b, prefix: p, delim: delim, startAfter: sa,
                               maxKeys: mk, mode: mode, cont: cont,
                               status: HTTP_OK, err: "",
                               keys: w.keys, prefixes: w.prefixes,
                               truncated: w.truncated,
                               maxKeysEcho: mk,
                               last: w.last, lastIsPfx: w.lastIsPfx }),
    }

    // The next page of a truncated V2 listing: the same request again with
    // the continuation token its reply returned.  Enabled only on the step
    // right after that reply, so nothing has changed in between and the page
    // is exactly the rest of the walk.
    val lastPage = match lastOp {
        | OListObjects(o) =>
            { more: o.status == HTTP_OK and o.mode == 2 and o.truncated,
              bucket: o.bucket, prefix: o.prefix, delim: o.delim,
              maxKeys: o.maxKeys, last: o.last, lastIsPfx: o.lastIsPfx }
        | _ =>
            { more: false, bucket: "", prefix: { comps: [], slash: false },
              delim: false, maxKeys: 0, last: [], lastIsPfx: false }
    }

    action listContinue = all {
        lastPage.more,
        applyListObjectsFrom(lastPage.bucket, lastPage.prefix, lastPage.delim,
            NO_KEY, lastPage.maxKeys, 2, true,
            if (lastPage.lastIsPfx) { key: NO_KEY, pfx: lastPage.last }
            else { key: lastPage.last, pfx: [] }),
    }

    // The max-keys edges.
    action listObjectsEdge = all {
        liveBuckets.size() > 0,
        {
            nondet b = oneOf(liveBuckets)
            nondet p = oneOf(PREFIXES)
            nondet delim = oneOf(Set(false, true))
            nondet mk = oneOf(MAXKEYS_EDGES)
            nondet mode = oneOf(LIST_MODES)
            applyListObjects(b, p, delim, NO_KEY, mk, mode)
        },
    }

    action listObjects = all {
        liveBuckets.size() > 0,
        {
            nondet b = oneOf(liveBuckets)
            nondet p = oneOf(PREFIXES)
            nondet delim = oneOf(Set(false, true))
            nondet sa = oneOf(KEYS.union(Set(NO_KEY)))
            nondet mk = oneOf(MAXKEYS_CHOICES)
            nondet mode = oneOf(LIST_MODES)
            applyListObjects(b, p, delim, sa, mk, mode)
        },
    }

    // ------------------------------------------------------------------
    // Object tagging (?tagging on an object)
    // ------------------------------------------------------------------

    action applyPutObjTagging(b: str, k: Key, ts: Set[int]): bool = all {
        bkts' =
            if (liveBuckets.contains(b) and bkts.get(b).objs.keys().contains(k))
                bkts.setBy(b, bk => bkRetag(bk, k, ts))
            else bkts,
        nextUpl' = nextUpl,
        devHits' = Set(),
        lastOp' =
            if (not(liveBuckets.contains(b)))
                OPutObjTagging({ bucket: b, key: k, tags: ts,
                                 status: HTTP_NOT_FOUND, err: "NoSuchBucket" })
            else if (tagOnMarker(bkts.get(b), k))
                OPutObjTagging({ bucket: b, key: k, tags: ts,
                                 status: HTTP_METHOD_NOT_ALLOWED,
                                 err: "MethodNotAllowed" })
            else if (not(bkts.get(b).objs.keys().contains(k)))
                OPutObjTagging({ bucket: b, key: k, tags: ts,
                                 status: HTTP_NOT_FOUND, err: "NoSuchKey" })
            else
                OPutObjTagging({ bucket: b, key: k, tags: ts,
                                 status: HTTP_OK, err: "" }),
    }

    action putObjTagging = all {
        liveBuckets.size() > 0,
        {
            nondet b = oneOf(liveBuckets)
            nondet k = oneOf(KEYS)
            nondet ts = oneOf(TAGSETS)
            applyPutObjTagging(b, k, ts)
        },
    }

    // GetObjectTagging with no tags stored is an empty 200 tag set (unlike
    // the bucket-level call).
    action applyGetObjTagging(b: str, k: Key): bool = all {
        bkts' = bkts,
        nextUpl' = nextUpl,
        devHits' = Set(),
        lastOp' =
            if (not(liveBuckets.contains(b)))
                OGetObjTagging({ bucket: b, key: k, status: HTTP_NOT_FOUND,
                                 err: "NoSuchBucket", tags: Set() })
            // a Deny in the bucket policy is decided before the key is looked
            // at, and binds the bucket's owner like anyone else
            else if (tagOnMarker(bkts.get(b), k))
                OGetObjTagging({ bucket: b, key: k, status: HTTP_METHOD_NOT_ALLOWED,
                                 err: "MethodNotAllowed", tags: Set() })
            // The owner may list the bucket, so a key that is not there is
            // reported as missing; the Deny answers for one that is.
            else if (bkts.get(b).pol == 2 and bkts.get(b).objs.keys().contains(k))
                OGetObjTagging({ bucket: b, key: k, status: HTTP_FORBIDDEN,
                                 err: "AccessDenied", tags: Set() })
            else if (not(bkts.get(b).objs.keys().contains(k)))
                OGetObjTagging({ bucket: b, key: k, status: HTTP_NOT_FOUND,
                                 err: "NoSuchKey", tags: Set() })
            else
                OGetObjTagging({ bucket: b, key: k, status: HTTP_OK, err: "",
                                 tags: bkts.get(b).objs.get(k).tags }),
    }

    action getObjTagging = all {
        liveBuckets.size() > 0,
        {
            nondet b = oneOf(liveBuckets)
            nondet k = oneOf(KEYS)
            applyGetObjTagging(b, k)
        },
    }

    action applyDelObjTagging(b: str, k: Key): bool = all {
        bkts' =
            if (liveBuckets.contains(b) and bkts.get(b).objs.keys().contains(k))
                bkts.setBy(b, bk => bkRetag(bk, k, Set()))
            else bkts,
        nextUpl' = nextUpl,
        devHits' = Set(),
        lastOp' =
            if (not(liveBuckets.contains(b)))
                ODelObjTagging({ bucket: b, key: k, status: HTTP_NOT_FOUND,
                                 err: "NoSuchBucket" })
            else if (tagOnMarker(bkts.get(b), k))
                ODelObjTagging({ bucket: b, key: k,
                                 status: HTTP_METHOD_NOT_ALLOWED,
                                 err: "MethodNotAllowed" })
            else if (not(bkts.get(b).objs.keys().contains(k)))
                ODelObjTagging({ bucket: b, key: k, status: HTTP_NOT_FOUND,
                                 err: "NoSuchKey" })
            else
                ODelObjTagging({ bucket: b, key: k, status: HTTP_NO_CONTENT,
                                 err: "" }),
    }

    action delObjTagging = all {
        liveBuckets.size() > 0,
        {
            nondet b = oneOf(liveBuckets)
            nondet k = oneOf(KEYS)
            applyDelObjTagging(b, k)
        },
    }

    // ------------------------------------------------------------------
    // Bucket tagging (?tagging on a bucket)
    // ------------------------------------------------------------------

    action applyPutBktTagging(b: str, ts: Set[int]): bool = all {
        bkts' =
            if (liveBuckets.contains(b))
                bkts.setBy(b, bk => bk.with("btags", ts))
            else bkts,
        nextUpl' = nextUpl,
        devHits' = Set(),
        lastOp' =
            if (not(liveBuckets.contains(b)))
                OPutBktTagging({ bucket: b, tags: ts, status: HTTP_NOT_FOUND,
                                 err: "NoSuchBucket" })
            else
                OPutBktTagging({ bucket: b, tags: ts,
                                 status: if (P_PUT_BUCKET_TAGGING_OK) HTTP_OK
                                         else HTTP_NO_CONTENT,
                                 err: "" }),
    }

    // Not drawn under P_FIXED_BUCKET: a bucket's tag set is one value for the
    // whole bucket, and a bucket the tester was handed may be shared with
    // other runs at the same moment.  A key prefix partitions objects; nothing
    // partitions this.
    action putBktTagging = all {
        not(P_FIXED_BUCKET),
        {
            nondet b = oneOf(BKT_UNIVERSE)
            nondet ts = oneOf(TAGSETS)
            applyPutBktTagging(b, ts)
        },
    }

    // GetBucketTagging with no tags stored is 404 NoSuchTagSet (unlike the
    // object-level call).
    //
    // MinIO's GET and DELETE never ask whether the bucket exists: a missing
    // bucket reads as a bucket with no tags (NoSuchTagSet) and its tag set
    // deletes successfully.  PutBucketTagging does check.
    action applyGetBktTagging(b: str): bool = all {
        bkts' = bkts,
        nextUpl' = nextUpl,
        devHits' =
            if (not(liveBuckets.contains(b)) and dev("M-get-bucket-tagging-no-bucket-check"))
                Set("M-get-bucket-tagging-no-bucket-check")
            else Set(),
        lastOp' =
            if (not(liveBuckets.contains(b)))
                OGetBktTagging({ bucket: b, status: HTTP_NOT_FOUND,
                                 err: if (dev("M-get-bucket-tagging-no-bucket-check"))
                                          "NoSuchTagSet"
                                      else "NoSuchBucket",
                                 tags: Set() })
            else if (bkts.get(b).btags.size() == 0)
                OGetBktTagging({ bucket: b, status: HTTP_NOT_FOUND,
                                 err: "NoSuchTagSet", tags: Set() })
            else
                OGetBktTagging({ bucket: b, status: HTTP_OK, err: "",
                                 tags: bkts.get(b).btags }),
    }

    action getBktTagging = all {
        not(P_FIXED_BUCKET),
        {
            nondet b = oneOf(BKT_UNIVERSE)
            applyGetBktTagging(b)
        },
    }

    action applyDelBktTagging(b: str): bool = all {
        bkts' =
            if (liveBuckets.contains(b))
                bkts.setBy(b, bk => bk.with("btags", Set()))
            else bkts,
        nextUpl' = nextUpl,
        devHits' =
            if (not(liveBuckets.contains(b)) and dev("M-delete-bucket-tagging-no-bucket-check"))
                Set("M-delete-bucket-tagging-no-bucket-check")
            else Set(),
        lastOp' =
            if (not(liveBuckets.contains(b)) and dev("M-delete-bucket-tagging-no-bucket-check"))
                ODelBktTagging({ bucket: b, status: HTTP_NO_CONTENT, err: "" })
            else if (not(liveBuckets.contains(b)))
                ODelBktTagging({ bucket: b, status: HTTP_NOT_FOUND,
                                 err: "NoSuchBucket" })
            else
                ODelBktTagging({ bucket: b, status: HTTP_NO_CONTENT, err: "" }),
    }

    action delBktTagging = all {
        not(P_FIXED_BUCKET),
        {
            nondet b = oneOf(BKT_UNIVERSE)
            applyDelBktTagging(b)
        },
    }

    // ------------------------------------------------------------------
    // Multipart upload (generated only by stepMultipart; see the module
    // comment for the block-size contract)
    // ------------------------------------------------------------------

    action applyCreateMpu(b: str, k: Key): bool =
        applyCreateMpuMeta(b, k, 0, Set())

    action applyCreateMpuMeta(b: str, k: Key, mt: int, ts: Set[int]): bool = all {
        bkts' =
            if (liveBuckets.contains(b))
                bkts.setBy(b, bk =>
                    bk.with("mpu", bk.mpu.put(nextUpl,
                        { key: k, parts: Map(), mtag: mt, tags: ts })))
            else bkts,
        nextUpl' = if (liveBuckets.contains(b)) nextUpl + 1 else nextUpl,
        devHits' = Set(),
        lastOp' =
            if (liveBuckets.contains(b))
                OCreateMpu({ bucket: b, key: k, uplid: nextUpl, mtag: mt, tags: ts,
                             status: HTTP_OK, err: "" })
            else
                OCreateMpu({ bucket: b, key: k, uplid: -1, mtag: mt, tags: ts,
                             status: HTTP_NOT_FOUND, err: "NoSuchBucket" }),
    }

    action createMpuMeta = all {
        liveBuckets.size() > 0,
        totalUploads < MAX_UPLOADS,
        {
            nondet b = oneOf(liveBuckets)
            nondet k = oneOf(KEYS)
            nondet mt = oneOf(MTAGS)
            nondet ts = oneOf(TAGSETS.union(Set(Set())))
            applyCreateMpuMeta(b, k, mt, ts)
        },
    }

    action createMpu = all {
        liveBuckets.size() > 0,
        totalUploads < MAX_UPLOADS,
        {
            nondet b = oneOf(liveBuckets)
            nondet k = oneOf(KEYS)
            applyCreateMpu(b, k)
        },
    }

    // UploadPart: the part number is validated (1..10000) before the
    // upload id is looked up; re-uploading a part number replaces it.
    // The URL key is always the upload's own key (the gateway does not
    // check it; the model does not exercise the mismatch).
    action applyUploadPart(b: str, k: Key, u: int, n: int, d: Blocks): bool = all {
        bkts' =
            if (liveBuckets.contains(b) and n != 0
                    and bkts.get(b).mpu.keys().contains(u))
                bkts.setBy(b, bk =>
                    bk.with("mpu", bk.mpu.setBy(u, m =>
                        m.with("parts", m.parts.put(n, d)))))
            else bkts,
        nextUpl' = nextUpl,
        // AWS: "Part number must be an integer between 1 and 10000,
        // inclusive" -- InvalidArgument.  MinIO says exactly that for 10001,
        // but reports part number 0 as InvalidPart, the CompleteMultipartUpload
        // error for a part that was never uploaded.
        devHits' =
            if (liveBuckets.contains(b) and n == 0 and dev("M-part-zero-invalidpart"))
                Set("M-part-zero-invalidpart")
            else Set(),
        lastOp' =
            if (not(liveBuckets.contains(b)))
                OUploadPart({ bucket: b, key: k, uplid: u, partNum: n, data: d,
                              status: HTTP_NOT_FOUND, err: "NoSuchBucket" })
            else if (n == 0)
                OUploadPart({ bucket: b, key: k, uplid: u, partNum: n, data: d,
                              status: HTTP_BAD_REQUEST,
                              err: if (dev("M-part-zero-invalidpart")) "InvalidPart"
                                   else "InvalidArgument" })
            else if (not(bkts.get(b).mpu.keys().contains(u)))
                OUploadPart({ bucket: b, key: k, uplid: u, partNum: n, data: d,
                              status: HTTP_NOT_FOUND, err: "NoSuchUpload" })
            else
                OUploadPart({ bucket: b, key: k, uplid: u, partNum: n, data: d,
                              status: HTTP_OK, err: "" }),
    }

    action uploadPart = all {
        uploadPairs.size() > 0,
        {
            nondet p = oneOf(uploadPairs)
            nondet n = oneOf(PART_NUMS)
            nondet d = oneOf(PART_DATAS)
            applyUploadPart(p._1, bkts.get(p._1).mpu.get(p._2).key, p._2, n, d)
        },
    }

    // partNumber outside 1..10000 (the harness sends 0).
    action uploadPartZero = all {
        uploadPairs.size() > 0,
        {
            nondet p = oneOf(uploadPairs)
            nondet d = oneOf(PART_DATAS)
            applyUploadPart(p._1, bkts.get(p._1).mpu.get(p._2).key, p._2, 0, d)
        },
    }

    action uploadPartUnknown = all {
        liveBuckets.size() > 0,
        {
            nondet b = oneOf(liveBuckets)
            nondet k = oneOf(KEYS)
            nondet n = oneOf(PART_NUMS)
            applyUploadPart(b, k, UNKNOWN_UPLOAD, n, [1])
        },
    }

    // UploadPartCopy: the part's content is the source object (or the
    // in-bounds closed range of it).  The generator only draws satisfiable
    // ranges; the not-found paths mirror UploadPart/CopyObject.
    action applyUploadPartCopy(b: str, k: Key, u: int, n: int, sb: str, sk: Key, r: Range): bool = all {
        val known = liveBuckets.contains(b) and n != 0
            and bkts.get(b).mpu.keys().contains(u)
            and liveBuckets.contains(sb)
            and bkts.get(sb).objs.keys().contains(sk)
        val pdata =
            if (not(known)) []
            else
                val sd = bkts.get(sb).objs.get(sk).data
                match r {
                    | RClosed(c) => sd.slice(c.first, c.last + 1)
                    | _ => sd
                }
        all {
            bkts' =
                if (known)
                    bkts.setBy(b, bk =>
                        bk.with("mpu", bk.mpu.setBy(u, m =>
                            m.with("parts", m.parts.put(n, pdata)))))
                else bkts,
            nextUpl' = nextUpl,
            devHits' =
                if (liveBuckets.contains(b) and n == 0 and dev("M-part-zero-invalidpart"))
                    Set("M-part-zero-invalidpart")
                else Set(),
            lastOp' =
                if (not(liveBuckets.contains(b)))
                    OUploadPartCopy({ bucket: b, key: k, uplid: u, partNum: n,
                                      srcBucket: sb, srcKey: sk, range: r, data: [],
                                      status: HTTP_NOT_FOUND, err: "NoSuchBucket" })
                else if (n == 0)
                    OUploadPartCopy({ bucket: b, key: k, uplid: u, partNum: n,
                                      srcBucket: sb, srcKey: sk, range: r, data: [],
                                      status: HTTP_BAD_REQUEST,
                                      err: if (dev("M-part-zero-invalidpart")) "InvalidPart"
                                           else "InvalidArgument" })
                else if (not(bkts.get(b).mpu.keys().contains(u)))
                    OUploadPartCopy({ bucket: b, key: k, uplid: u, partNum: n,
                                      srcBucket: sb, srcKey: sk, range: r, data: [],
                                      status: HTTP_NOT_FOUND, err: "NoSuchUpload" })
                else if (not(liveBuckets.contains(sb)))
                    OUploadPartCopy({ bucket: b, key: k, uplid: u, partNum: n,
                                      srcBucket: sb, srcKey: sk, range: r, data: [],
                                      status: HTTP_NOT_FOUND, err: "NoSuchBucket" })
                else if (not(bkts.get(sb).objs.keys().contains(sk)))
                    OUploadPartCopy({ bucket: b, key: k, uplid: u, partNum: n,
                                      srcBucket: sb, srcKey: sk, range: r, data: [],
                                      status: HTTP_NOT_FOUND, err: "NoSuchKey" })
                else
                    OUploadPartCopy({ bucket: b, key: k, uplid: u, partNum: n,
                                      srcBucket: sb, srcKey: sk, range: r,
                                      data: pdata, status: HTTP_OK, err: "" }),
        },
    }

    action uploadPartCopy = all {
        uploadPairs.size() > 0,
        objPairs.size() > 0,
        {
            nondet p = oneOf(uploadPairs)
            nondet src = oneOf(objPairs)
            nondet n = oneOf(PART_NUMS)
            nondet f = oneOf(0.to(MAX_OBJ_BLOCKS - 1))
            nondet span = oneOf(0.to(1))
            nondet whole = oneOf(Set(false, true))
            // The copied part must respect the 2-block part-content cap: a
            // whole-object copy only when the source fits it (multipart-
            // assembled sources can be larger), else an in-bounds closed
            // range of at most 2 blocks.
            val sz = bkts.get(src._1).objs.get(src._2).data.length()
            val fc = imin(f, imax(sz - 1, 0))
            val r = if (sz == 0 or (whole and sz <= 2))
                        RNone
                    else
                        RClosed({ first: fc, last: imin(fc + span, sz - 1) })
            applyUploadPartCopy(p._1, bkts.get(p._1).mpu.get(p._2).key, p._2, n,
                                src._1, src._2, r)
        },
    }

    action uploadPartCopyMissing = all {
        uploadPairs.size() > 0,
        {
            nondet p = oneOf(uploadPairs)
            nondet sb = oneOf(BKT_UNIVERSE)
            // a genuinely absent source (bucket dead, or key not present),
            // so the copy always fails and never mints an oversized part
            nondet sk = oneOf(KEYS.filter(kk =>
                not(liveBuckets.contains(sb)
                    and bkts.get(sb).objs.keys().contains(kk))))
            nondet n = oneOf(PART_NUMS)
            applyUploadPartCopy(p._1, bkts.get(p._1).mpu.get(p._2).key, p._2, n,
                                sb, sk, RNone)
        },
    }

    // CompleteMultipartUpload: on success the assembled object replaces
    // any object at the upload's key (with no metadata and no tags -- none
    // are supplied at Initiate) and the upload is consumed; on any
    // validation error the upload survives untouched.
    action applyCompleteMpu(b: str, k: Key, u: int, manifest: List[int]): bool = all {
        val live = liveBuckets.contains(b) and bkts.get(b).mpu.keys().contains(u)
        val chk = if (live) completeCheck(bkts.get(b).mpu.get(u).parts, manifest)
                  else { status: 0, err: "" }
        all {
            bkts' =
                if (live and chk.status == HTTP_OK)
                    bkts.setBy(b, bk =>
                        bkPut(bk, k,
                            { data: assembleParts(bk.mpu.get(u).parts, manifest),
                              mtag: bk.mpu.get(u).mtag,
                              tags: bk.mpu.get(u).tags,
                              // MinIO keeps the numbers the parts were
                              // uploaded under (M-part-numbers-kept), so an
                              // object completed from parts 1 and 3 has no
                              // part 2.  The model does not follow it there:
                              // [-1] marks such an object, and no read by
                              // part number is drawn against it.
                              parts: if (dev("M-part-numbers-kept")
                                         and not(manifestContiguous(manifest)))
                                         [-1]
                                     else manifest.foldl([], (acc, pn) =>
                                  acc.append(bk.mpu.get(u).parts.get(pn).length())) })
                          .with("mpu", mapDrop(bk.mpu, u)))
                else bkts,
            nextUpl' = nextUpl,
            // Recorded only where the deviation decided the answer: the empty
            // manifest, and a manifest the standard refuses for a repeated
            // part that MinIO goes on to judge (and usually complete) instead.
            devHits' =
                if (live and manifest.length() == 0
                        and dev("M-complete-empty-manifest-invalidrequest"))
                    Set("M-complete-empty-manifest-invalidrequest")
                else if (live and dev("M-complete-duplicate-part-accepted")
                        and completeCheckWith(bkts.get(b).mpu.get(u).parts, manifest,
                                              true, false) !=
                            completeCheckWith(bkts.get(b).mpu.get(u).parts, manifest,
                                              false, false))
                    Set("M-complete-duplicate-part-accepted")
                else if (live and chk.status == HTTP_OK
                        and dev("M-part-numbers-kept")
                        and not(manifestContiguous(manifest)))
                    Set("M-part-numbers-kept")
                else if (live and dev("M-complete-checks-by-kind")
                        and chk != completeCheckWith(bkts.get(b).mpu.get(u).parts,
                                manifest, dev("M-complete-duplicate-part-accepted"),
                                dev("M-complete-empty-manifest-invalidrequest")))
                    Set("M-complete-checks-by-kind")
                else Set(),
            lastOp' =
                if (not(liveBuckets.contains(b)))
                    OCompleteMpu({ bucket: b, key: k, uplid: u, manifest: manifest,
                                   status: HTTP_NOT_FOUND, err: "NoSuchBucket" })
                else if (not(bkts.get(b).mpu.keys().contains(u)))
                    OCompleteMpu({ bucket: b, key: k, uplid: u, manifest: manifest,
                                   status: HTTP_NOT_FOUND, err: "NoSuchUpload" })
                else
                    OCompleteMpu({ bucket: b, key: k, uplid: u, manifest: manifest,
                                   status: chk.status, err: chk.err }),
        },
    }

    action completeMpu = all {
        uploadPairs.size() > 0,
        totalObjs < MAX_OBJECTS,
        {
            nondet p = oneOf(uploadPairs)
            nondet manifest = oneOf(manifestChoices(bkts.get(p._1).mpu.get(p._2).parts))
            applyCompleteMpu(p._1, bkts.get(p._1).mpu.get(p._2).key, p._2, manifest)
        },
    }

    // Complete against an unknown upload id: the key is constrained to a
    // key with NO object, so the gateway's replayed-success idempotency
    // probe (which looks the key up) cannot fire and the official 404
    // NoSuchUpload is the one true answer.
    action completeMpuUnknown = all {
        liveBuckets.size() > 0,
        {
            nondet b = oneOf(liveBuckets)
            nondet k = oneOf(KEYS.filter(kk => not(bkts.get(b).objs.keys().contains(kk))))
            applyCompleteMpu(b, k, UNKNOWN_UPLOAD, [1])
        },
    }

    action applyAbortMpu(b: str, k: Key, u: int): bool = all {
        bkts' =
            if (liveBuckets.contains(b) and bkts.get(b).mpu.keys().contains(u))
                bkts.setBy(b, bk => bk.with("mpu", mapDrop(bk.mpu, u)))
            else bkts,
        nextUpl' = nextUpl,
        // MinIO's abort is idempotent: an upload that never existed, or was
        // already aborted or completed, aborts successfully.  The bucket is
        // still checked.
        devHits' =
            if (liveBuckets.contains(b) and not(bkts.get(b).mpu.keys().contains(u))
                    and dev("M-abort-unknown-upload-204"))
                Set("M-abort-unknown-upload-204")
            else Set(),
        lastOp' =
            if (not(liveBuckets.contains(b)))
                OAbortMpu({ bucket: b, key: k, uplid: u,
                            status: HTTP_NOT_FOUND, err: "NoSuchBucket" })
            else if (not(bkts.get(b).mpu.keys().contains(u))
                    and dev("M-abort-unknown-upload-204"))
                OAbortMpu({ bucket: b, key: k, uplid: u,
                            status: HTTP_NO_CONTENT, err: "" })
            else if (not(bkts.get(b).mpu.keys().contains(u)))
                OAbortMpu({ bucket: b, key: k, uplid: u,
                            status: HTTP_NOT_FOUND, err: "NoSuchUpload" })
            else
                OAbortMpu({ bucket: b, key: k, uplid: u,
                            status: HTTP_NO_CONTENT, err: "" }),
    }

    action abortMpu = all {
        uploadPairs.size() > 0,
        {
            nondet p = oneOf(uploadPairs)
            applyAbortMpu(p._1, bkts.get(p._1).mpu.get(p._2).key, p._2)
        },
    }

    action abortMpuUnknown = all {
        liveBuckets.size() > 0,
        {
            nondet b = oneOf(liveBuckets)
            nondet k = oneOf(KEYS)
            applyAbortMpu(b, k, UNKNOWN_UPLOAD)
        },
    }

    action applyListParts(b: str, k: Key, u: int): bool =
        applyListPartsPaged(b, k, u, 1000, 0)

    // The parts numbered above the marker, the first maxParts of them.
    action applyListPartsPaged(b: str, k: Key, u: int, mp: int, marker: int): bool = all {
        bkts' = bkts,
        nextUpl' = nextUpl,
        devHits' = Set(),
        lastOp' =
            if (not(liveBuckets.contains(b)))
                OListParts({ bucket: b, key: k, uplid: u, maxParts: mp,
                             marker: marker, status: HTTP_NOT_FOUND,
                             err: "NoSuchBucket", partNums: [], truncated: false })
            else if (not(bkts.get(b).mpu.keys().contains(u)))
                OListParts({ bucket: b, key: k, uplid: u, maxParts: mp,
                             marker: marker, status: HTTP_NOT_FOUND,
                             err: "NoSuchUpload", partNums: [], truncated: false })
            else
                val after = sortedParts(bkts.get(b).mpu.get(u).parts)
                                .select(pn => pn > marker)
                OListParts({ bucket: b, key: k, uplid: u, maxParts: mp,
                             marker: marker, status: HTTP_OK, err: "",
                             partNums: after.slice(0, imin(mp, after.length())),
                             truncated: after.length() > mp }),
    }

    action listPartsPaged = all {
        uploadPairs.size() > 0,
        {
            nondet p = oneOf(uploadPairs)
            nondet mp = oneOf(Set(1, 2))
            nondet marker = oneOf(Set(0, 1, 2))
            applyListPartsPaged(p._1, bkts.get(p._1).mpu.get(p._2).key, p._2,
                                mp, marker)
        },
    }

    action listParts = all {
        uploadPairs.size() > 0,
        {
            nondet p = oneOf(uploadPairs)
            applyListParts(p._1, bkts.get(p._1).mpu.get(p._2).key, p._2)
        },
    }

    action listPartsUnknown = all {
        liveBuckets.size() > 0,
        {
            nondet b = oneOf(liveBuckets)
            nondet k = oneOf(KEYS)
            applyListParts(b, k, UNKNOWN_UPLOAD)
        },
    }

    // ListMultipartUploads: compared as a set -- the wire orders rows by
    // (key, 32-hex upload id) and the ids are unpredictable.
    action applyListMpu(b: str): bool =
        applyListMpuFiltered(b, { comps: [], slash: false }, 1000)

    // Ascending, for a set this small.
    pure def sortedIds(ids: Set[int]): List[int] =
        ids.fold([], (acc, x) =>
            acc.select(y => y < x).concat([x]).concat(acc.select(y => y > x)))

    // The uploads of a bucket in listing order: by key, and for one key in
    // the order they were initiated -- which is the order their ids were
    // minted in.
    pure def uploadOrder(mpu: int -> Mpu): List[int] =
        sortedIds(mpu.keys()).foldl([], (acc, u) =>
            acc.select(v => keyRank(mpu.get(v).key) <= keyRank(mpu.get(u).key))
               .concat([u])
               .concat(acc.select(v => keyRank(mpu.get(v).key) > keyRank(mpu.get(u).key))))

    // The uploads whose key matches the prefix, the first maxUploads of them.
    // MinIO (M-list-uploads-exact-prefix) treats the prefix as a whole key:
    // it lists the uploads of the object so named and no others, and lists
    // uploads in the order they were initiated, not by key.
    pure def listMpuPage(m: int -> Mpu, p: Prefix, mu: int, exact: bool): { page: List[int], more: bool } =
        val hits =
            if (exact)
                sortedIds(m.keys()).select(u =>
                    (p.comps.length() == 0 and not(p.slash))
                    or (m.get(u).key == p.comps and not(p.slash)))
            else uploadOrder(m).select(u => keyMatches(m.get(u).key, p))
        { page: hits.slice(0, imin(mu, hits.length())), more: hits.length() > mu }

    action applyListMpuFiltered(b: str, p: Prefix, mu: int): bool = all {
        bkts' = bkts,
        nextUpl' = nextUpl,
        devHits' =
            if (liveBuckets.contains(b) and dev("M-list-uploads-exact-prefix")
                    and listMpuPage(bkts.get(b).mpu, p, mu, true) !=
                        listMpuPage(bkts.get(b).mpu, p, mu, false))
                Set("M-list-uploads-exact-prefix")
            else Set(),
        lastOp' =
            if (not(liveBuckets.contains(b)))
                OListMpu({ bucket: b, prefix: p, maxUploads: mu,
                           status: HTTP_NOT_FOUND, err: "NoSuchBucket",
                           uploads: Set(), truncated: false })
            else
                val m = bkts.get(b).mpu
                val r = listMpuPage(m, p, mu, dev("M-list-uploads-exact-prefix"))
                OListMpu({ bucket: b, prefix: p, maxUploads: mu,
                           status: HTTP_OK, err: "",
                           uploads: r.page.foldl(Set(), (acc, u) =>
                               acc.union(Set({ key: m.get(u).key, uplid: u }))),
                           truncated: r.more }),
    }

    action listMpuFiltered = all {
        liveBuckets.size() > 0,
        {
            nondet b = oneOf(liveBuckets)
            nondet p = oneOf(PREFIXES)
            nondet mu = oneOf(Set(1, 1000))
            applyListMpuFiltered(b, p, mu)
        },
    }

    // An UploadPartCopy whose source is in ANOTHER bucket than the upload.
    action uploadPartCopyCross = all {
        uploadPairs.size() > 0,
        {
            nondet p = oneOf(uploadPairs)
            val others = objPairs.filter(o => o._1 != p._1)
            all {
                others.size() > 0,
                {
                    nondet src = oneOf(others)
                    nondet n = oneOf(PART_NUMS)
                    val sz = bkts.get(src._1).objs.get(src._2).data.length()
                    applyUploadPartCopy(p._1, bkts.get(p._1).mpu.get(p._2).key,
                                        p._2, n, src._1, src._2,
                                        // a part is at most two blocks
                                        if (sz <= 2) RNone
                                        else RClosed({ first: 0, last: 1 }))
                },
            }
        },
    }

    // ------------------------------------------------------------------
    // GET / HEAD of one part (?partNumber=N)
    // ------------------------------------------------------------------

    // An object assembled from N parts answers for each of them: 206, that
    // part's bytes, a Content-Range placing it in the whole, and
    // x-amz-mp-parts-count: N.  An object written in one piece is its own
    // part 1, with no parts count.  Any other part number is 416
    // InvalidPartNumber.
    pure def partFirst(parts: List[int], n: int): int =
        parts.slice(0, n - 1).foldl(0, (acc, x) => acc + x)

    action applyGetObjectPart(b: str, k: Key, n: int, hd: bool): bool = all {
        bkts' = bkts,
        nextUpl' = nextUpl,
        devHits' = Set(),
        lastOp' =
            if (not(liveBuckets.contains(b)))
                OGetObjectPart({ bucket: b, key: k, partNum: n, head: hd,
                                 status: HTTP_NOT_FOUND,
                                 err: if (hd) "" else "NoSuchBucket",
                                 data: [], first: -1, total: -1, partsCount: 0 })
            else if (not(bkts.get(b).objs.keys().contains(k)))
                OGetObjectPart({ bucket: b, key: k, partNum: n, head: hd,
                                 status: HTTP_NOT_FOUND,
                                 err: if (hd) "" else "NoSuchKey",
                                 data: [], first: -1, total: -1, partsCount: 0 })
            else
                val o = bkts.get(b).objs.get(k)
                val np = imax(o.parts.length(), 1)
                if (n > np)
                    OGetObjectPart({ bucket: b, key: k, partNum: n, head: hd,
                                     status: HTTP_RANGE_ERR,
                                     err: if (hd) "" else "InvalidPartNumber",
                                     data: [], first: -1, total: -1, partsCount: 0 })
                else if (o.parts.length() == 0)
                    OGetObjectPart({ bucket: b, key: k, partNum: n, head: hd,
                                     status: HTTP_PARTIAL, err: "",
                                     data: o.data, first: 0, total: o.data.length(),
                                     partsCount: 0 })
                else
                    val f = partFirst(o.parts, n)
                    OGetObjectPart({ bucket: b, key: k, partNum: n, head: hd,
                                     status: HTTP_PARTIAL, err: "",
                                     data: o.data.slice(f, f + o.parts[n - 1]),
                                     first: f, total: o.data.length(),
                                     partsCount: o.parts.length() }),
    }

    // Over objects every part of which has bytes: what a zero-length part's
    // Content-Range would be is not something worth predicting.
    action getObjectPart = all {
        {
            val cands = objPairs.filter(p =>
                val o = bkts.get(p._1).objs.get(p._2)
                o.data.length() > 0 and o.parts.indices().forall(i => o.parts[i] > 0))
            all {
                cands.size() > 0,
                {
                    nondet p = oneOf(cands)
                    nondet n = oneOf(1.to(4))
                    nondet hd = oneOf(Set(false, true))
                    applyGetObjectPart(p._1, p._2, n, hd)
                },
            }
        },
    }

    action listMpu = all {
        liveBuckets.size() > 0,
        {
            nondet b = oneOf(liveBuckets)
            applyListMpu(b)
        },
    }

    // ------------------------------------------------------------------
    // Step distributions
    // ------------------------------------------------------------------

    // Uniform-ish mix.  createBucket / headBucket / listBuckets /
    // deleteBucket are always enabled and act as the liveness fallback;
    // the object actions gate on a live bucket (or object) existing.
    // Tagging and multipart have their own flavors.
    action step = any {
        createBucket,
        headBucket,
        deleteBucket,
        listBuckets,
        putObject, putObject, putObject,
        getObject, getObject,
        getObjectRange,
        headObject,
        deleteObject,
        deleteObjects,
        copyObject,
        getAttrs,
        listObjects, listObjects,
    }

    // Data-path heavy: puts, ranged gets, overwrites; minimal namespace
    // churn.
    action stepData = any {
        putObject, putObject, putObject, putObject,
        getObject, getObject,
        getObjectRange, getObjectRange, getObjectRange,
        headObject,
        getAttrs,
        deleteObjectHit,
        copyObject,
        createBucket,
        listBuckets,
    }

    // Listing-heavy: build and churn a keyspace, list it from every angle.
    action stepList = any {
        putObject, putObject, putObject,
        deleteObject, deleteObjectHit,
        deleteObjects,
        listObjects, listObjects, listObjects, listObjects, listObjects,
        copyObject,
        createBucket,
        headBucket,
    }

    // Bucket-lifecycle heavy, including object ops aimed at missing
    // buckets.
    action stepBucket = any {
        createBucket, createBucket,
        deleteBucket, deleteBucket, deleteBucket,
        headBucket, headBucket,
        listBuckets,
        putObjectAny, putObjectAny,
        getObjectAny,
        copyObjectAny,
        deleteObjectAny,
        deleteObjectsAny,
    }

    // Tagging-heavy: object and bucket tag sets, metadata-carrying puts,
    // HEADs for the x-amz-tagging-count echo.  Deliberately no copyObject:
    // whether a gateway replicates tag xattrs on copy is untested here.
    action stepTag = any {
        createBucket,
        putObject, putObject,
        headObject, headObject,
        getObject,
        putObjTagging, putObjTagging, putObjTagging,
        getObjTagging, getObjTagging, getObjTagging,
        delObjTagging, delObjTagging,
        putBktTagging, putBktTagging,
        getBktTagging, getBktTagging,
        delBktTagging,
        deleteObject,
        listBuckets,
    }

    // Paging: listings cut into pages and resumed, and the max-keys edges.
    action stepPage = any {
        createBucket,
        putObject, putObject, putObject, putObject,
        deleteObjectHit,
        listObjects, listObjects, listObjects,
        listObjectsEdge,
        listContinue, listContinue, listContinue, listContinue, listContinue,
        listContinue,
    }

    // Metadata and tags by every route an object can acquire them: on the
    // PUT, by a copy under a REPLACE directive, and read back.
    action stepMeta = any {
        createBucket,
        putObject, putObject,
        putObjectTagged, putObjectTagged,
        copyObject,
        copyObjectReplace, copyObjectReplace, copyObjectReplace,
        getObject, getObject,
        headObject, headObject,
        getObjTagging, getObjTagging, getObjTagging,
        putObjTagging,
        getObjectPart,
        deleteObjectHit,
    }

    // Conditional requests, over a keyspace that keeps changing under them.
    // A server without them (F_CONDITIONAL off) gets only the plain calls.
    action stepCond = any {
        createBucket,
        putObject, putObject, putObject,
        condGet, condGetHit, condGetHit, condGetHit, condGetHit,
        condPut, condPut, condPut, condPut,
        condCopy, condCopy,
        getObject,
        headObject,
        deleteObjectHit, deleteObjectHit,
    }

    // Versioning: buckets switched between Enabled and Suspended under a
    // keyspace of a few keys, so histories grow deep; every version read,
    // deleted and listed.
    action stepVersion = any {
        createBucket,
        putBktVersioning, putBktVersioning,
        getBktVersioning,
        putObject, putObject, putObject, putObject,
        deleteObject, deleteObjectHit, deleteObjectHit,
        deleteObjects,
        copyObject,
        getObject, getObject,
        headObject,
        getVersion, getVersion, getVersion,
        deleteVersion, deleteVersion,
        listVersions, listVersions,
        listObjects,
        putObjTagging, getObjTagging,
        deleteBucket,
    }

    // Bucket policy: set, read, removed, and enforced.
    action stepPolicy = any {
        createBucket,
        putObject, putObject, putObject,
        putObjTagging,
        putBktPolicy, putBktPolicy, putBktPolicy,
        getBktPolicy, getBktPolicy,
        delBktPolicy,
        getPolicyStatus, getPolicyStatus,
        anonGet, anonGet, anonGet,
        getObjTagging, getObjTagging, getObjTagging,
        getObject,
        deleteBucket,
    }

    // The same calls by other routes to the wire, the credentials that are
    // wrong, and the two read-only bucket calls every client makes.
    action stepWire = any {
        createBucket,
        putObject, putObject,
        putVia, putVia, putVia, putVia,
        getVia, getVia, getViaHit, getViaHit,
        getObject, getObject,
        headObject,
        getBktLocation, getBktLocation,
        getAcl, getAcl, getAcl,
        deleteObjectHit,
    }

    // Requests that are wrong in themselves, among enough ordinary ones to
    // show that a refusal changed nothing.
    action stepInvalid = any {
        createBucket,
        putObject, putObject,
        invalidRequest, invalidRequest, invalidRequest, invalidRequest,
        invalidObjectRequest, invalidObjectRequest,
        getObject,
        getObjTagging,
        listObjects,
        listBuckets,
    }

    // Multipart beyond the upload itself: metadata and tags given at
    // Initiate, the listings paged and filtered, parts copied across buckets,
    // and the completed object read back part by part.  Replayed, like
    // stepMultipart, with a >= 5 MiB block size.
    action stepMultipartDeep = any {
        createBucket, createBucket,
        createMpuMeta, createMpuMeta,
        uploadPart, uploadPart, uploadPart, uploadPart, uploadPart,
        uploadPartCopyCross,
        completeMpu, completeMpu, completeMpu,
        listParts,
        listPartsPaged, listPartsPaged,
        listMpuFiltered, listMpuFiltered,
        putObject,
        copyObject,
        getObject,
        headObject,
        getObjTagging,
        getObjectPart, getObjectPart, getObjectPart, getObjectPart,
    }

    // Multipart-heavy.  Replayed with a >= 5 MiB block size; no
    // deleteBucket (in-flight uploads officially block deletion, and the
    // visibility of an in-flight upload as bucket content is
    // backend-dependent).
    action stepMultipart = any {
        createBucket,
        createMpu, createMpu,
        uploadPart, uploadPart, uploadPart, uploadPart,
        uploadPartCopy, uploadPartCopy,
        completeMpu, completeMpu,
        abortMpu,
        listParts, listParts,
        listMpu,
        uploadPartZero,
        uploadPartUnknown,
        uploadPartCopyMissing,
        completeMpuUnknown,
        abortMpuUnknown,
        listPartsUnknown,
        putObject,
        getObject,
        headObject,
        deleteObject,
        listObjects,
    }

    // ------------------------------------------------------------------
    // Invariants (structural sanity of the model itself)
    // ------------------------------------------------------------------

    pure def validBlocks(d: Blocks, maxb: int): bool =
        d.length() <= maxb and d.indices().forall(i => BLOCK_SYMS.contains(d[i]))

    val bucketsInUniverse = liveBuckets.subseteq(BUCKETS)

    val objectsValid = liveBuckets.forall(b =>
        bkts.get(b).objs.keys().forall(k =>
            val o = bkts.get(b).objs.get(k)
            KEYS.contains(k) and validBlocks(o.data, MAX_OBJ_BLOCKS)
                and MTAGS.contains(o.mtag) and o.tags.subseteq(TAG_IDS)
                and (o.parts.length() == 0 or o.parts == [-1] or
                     o.parts.foldl(0, (acc, x) => acc + x) == o.data.length())))

    val bucketTagsValid = liveBuckets.forall(b =>
        bkts.get(b).btags.subseteq(TAG_IDS))

    val uploadsValid = liveBuckets.forall(b =>
        bkts.get(b).mpu.keys().forall(u =>
            val m = bkts.get(b).mpu.get(u)
            KEYS.contains(m.key) and u < nextUpl
                and m.parts.keys().forall(pn =>
                    PART_NUMS.contains(pn) and validBlocks(m.parts.get(pn), 2))))

    val objectsBounded = totalObjs <= MAX_OBJECTS

    val uploadsBounded = totalUploads <= MAX_UPLOADS

    // What a plain GET sees is the latest version, unless that is a delete
    // marker.
    val historyConsistent = liveBuckets.forall(b =>
        val bk = bkts.get(b)
        bk.ver == 0 or KEYS.forall(k =>
            val h = histOf(bk, k)
            if (h.length() > 0 and not(h[h.length() - 1].dm))
                bk.objs.keys().contains(k) and bk.objs.get(k) == h[h.length() - 1].obj
            else not(bk.objs.keys().contains(k))))

    val inv = historyConsistent and bucketsInUniverse and objectsValid and bucketTagsValid
        and uploadsValid and objectsBounded and uploadsBounded
}
