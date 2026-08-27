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
//  - The model is spec-first: it encodes the documented AWS S3 behavior
//    (API Reference, 2006-03-01), not any one implementation's.  Known
//    divergences of the server under test are reconciled by the harness's
//    deviation registry, NOT encoded here.  Where AWS behavior is
//    region-dependent the model follows us-east-1 (the legacy region every
//    filesystem gateway emulates): CreateBucket on a bucket you already own
//    returns 200, not 409 BucketAlreadyOwnedByYou.
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
//    Content-Type falls back to application/octet-stream).  Tag sets are
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
    type Obj = { data: Blocks, mtag: int, tags: Set[int] }

    // One in-flight multipart upload: target key and the uploaded parts.
    type Mpu = { key: Key, parts: int -> Blocks }

    // One bucket: objects, bucket tag set, in-flight uploads by id.
    type Bkt = { objs: Key -> Obj, btags: Set[int], mpu: int -> Mpu }

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
    pure val MAX_OBJ_BLOCKS = 6

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
    pure val HTTP_BAD_REQUEST = 400
    pure val HTTP_NOT_FOUND = 404
    pure val HTTP_CONFLICT = 409
    pure val HTTP_RANGE_ERR = 416

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
        | OPutObject({ bucket: str, key: Key, data: Blocks, mtag: int,
                       status: int, err: str })
        | OGetObject({ bucket: str, key: Key, range: Range, status: int, err: str,
                       data: Blocks, first: int, total: int })
        | OHeadObject({ bucket: str, key: Key, status: int, sizeBlocks: int })
        | ODeleteObject({ bucket: str, key: Key, status: int, err: str })
        | ODeleteObjects({ bucket: str, keys: List[Key], quiet: bool,
                           status: int, err: str })
        | OCopyObject({ srcBucket: str, srcKey: Key, dstBucket: str, dstKey: Key,
                        status: int, err: str })
        | OGetAttrs({ bucket: str, key: Key, status: int, err: str,
                      sizeBlocks: int })
        | OListObjects({ bucket: str, prefix: Prefix, delim: bool, startAfter: Key,
                         maxKeys: int, mode: int, status: int, err: str,
                         keys: List[Key], prefixes: List[Key], truncated: bool })
        | OPutObjTagging({ bucket: str, key: Key, tags: Set[int],
                           status: int, err: str })
        | OGetObjTagging({ bucket: str, key: Key, status: int, err: str,
                           tags: Set[int] })
        | ODelObjTagging({ bucket: str, key: Key, status: int, err: str })
        | OPutBktTagging({ bucket: str, tags: Set[int], status: int, err: str })
        | OGetBktTagging({ bucket: str, status: int, err: str, tags: Set[int] })
        | ODelBktTagging({ bucket: str, status: int, err: str })
        | OCreateMpu({ bucket: str, key: Key, uplid: int, status: int, err: str })
        | OUploadPart({ bucket: str, key: Key, uplid: int, partNum: int,
                        data: Blocks, status: int, err: str })
        | OUploadPartCopy({ bucket: str, key: Key, uplid: int, partNum: int,
                            srcBucket: str, srcKey: Key, range: Range,
                            data: Blocks, status: int, err: str })
        | OCompleteMpu({ bucket: str, key: Key, uplid: int, manifest: List[int],
                         status: int, err: str })
        | OAbortMpu({ bucket: str, key: Key, uplid: int, status: int, err: str })
        | OListParts({ bucket: str, key: Key, uplid: int, status: int, err: str,
                       partNums: List[int] })
        | OListMpu({ bucket: str, status: int, err: str,
                     uploads: Set[{ key: Key, uplid: int }] })

    // ------------------------------------------------------------------
    // State
    // ------------------------------------------------------------------

    // The store: bucket name -> bucket.  Bucket existence is membership.
    var bkts: str -> Bkt
    // Next multipart upload id (abstract; the harness maps to wire ids).
    var nextUpl: int
    var lastOp: Op

    pure val EMPTY_BKT: Bkt = { objs: Map(), btags: Set(), mpu: Map() }

    pure def mkObj(d: Blocks, mt: int): Obj = { data: d, mtag: mt, tags: Set() }

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

    type ListOut = { keys: List[Key], prefixes: List[Key], truncated: bool }

    // The ListObjects walk (shared by V1, V2 and ListObjectVersions --
    // marker / start-after / key-marker are all the same exclusive start
    // key): object keys in byte order, those at or below the start key
    // skipped, each emitting itself (no delimiter) or its rollup
    // (delimiter "/"); consecutive keys sharing a rollup collapse into one
    // <CommonPrefixes> entry; the page closes after maxKeys emissions and
    // IsTruncated reports whether any further key would have emitted a new
    // entry.  AWS returns an empty, non-truncated result for max-keys=0.
    pure def listWalk(objs: Set[Key], p: Prefix, delim: bool, sa: Key, maxKeys: int): ListOut =
        if (maxKeys == 0)
            { keys: [], prefixes: [], truncated: false }
        else
            val w = ENT_ORDER.foldl(
                { keys: [], prefixes: [], truncated: false, done: false, last: LNone },
                (st, e) =>
                match e {
                    | EPfx(x) => st
                    | EKey(k) =>
                        if (not(objs.contains(k))
                                or not(keyMatches(k, p))
                                or (sa != NO_KEY and keyRank(k) <= keyRank(sa)))
                            st
                        else
                            val em = if (delim) rollup(k, p) else EKey(k)
                            if (st.last == LSome(em))
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
            { keys: w.keys, prefixes: w.prefixes, truncated: w.truncated }

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
    pure def completeCheck(parts: int -> Blocks, manifest: List[int]): { status: int, err: str } =
        if (manifest.length() == 0)
            { status: HTTP_BAD_REQUEST, err: "MalformedXML" }
        else
            val w = manifest.foldl(
                { i: 0, prev: 0, status: 0, err: "" },
                (acc, pn) =>
                if (acc.status != 0)
                    acc.with("i", acc.i + 1)
                else if (pn <= acc.prev)
                    acc.with("status", HTTP_BAD_REQUEST).with("err", "InvalidPartOrder")
                else if (not(parts.keys().contains(pn)))
                    acc.with("status", HTTP_BAD_REQUEST).with("err", "InvalidPart")
                else if (acc.i < manifest.length() - 1 and parts.get(pn).length() == 0)
                    acc.with("status", HTTP_BAD_REQUEST).with("err", "EntityTooSmall")
                else
                    { i: acc.i + 1, prev: pn, status: 0, err: "" })
            if (w.status != 0) { status: w.status, err: w.err }
            else { status: HTTP_OK, err: "" }

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
    // (CreateBucket is part of the modeled surface).
    action init = all {
        bkts' = Map(),
        nextUpl' = 1,
        lastOp' = OInit,
    }

    // ------------------------------------------------------------------
    // CreateBucket (PUT /{bucket})
    // ------------------------------------------------------------------

    // us-east-1 semantics: creating a bucket that already exists and is
    // yours is idempotent 200 (elsewhere AWS returns 409
    // BucketAlreadyOwnedByYou; a single-tenant gateway is "us-east-1").
    action applyCreateBucket(b: str): bool = all {
        bkts' = if (liveBuckets.contains(b)) bkts else bkts.put(b, EMPTY_BKT),
        nextUpl' = nextUpl,
        lastOp' = OCreateBucket({ bucket: b, status: HTTP_OK }),
    }

    action createBucket = {
        nondet b = oneOf(BUCKETS)
        applyCreateBucket(b)
    }

    // ------------------------------------------------------------------
    // HeadBucket (HEAD /{bucket})
    // ------------------------------------------------------------------

    action applyHeadBucket(b: str): bool = all {
        bkts' = bkts,
        nextUpl' = nextUpl,
        lastOp' = OHeadBucket({
            bucket: b,
            status: if (liveBuckets.contains(b)) HTTP_OK else HTTP_NOT_FOUND }),
    }

    action headBucket = {
        nondet b = oneOf(BUCKETS)
        applyHeadBucket(b)
    }

    // ------------------------------------------------------------------
    // DeleteBucket (DELETE /{bucket})
    // ------------------------------------------------------------------

    // A bucket must hold no objects AND no in-progress multipart uploads
    // to be deletable.  (The in-flight-upload 409 is never generated; see
    // the module comment.)
    action applyDeleteBucket(b: str): bool = all {
        bkts' =
            if (liveBuckets.contains(b) and bkts.get(b).objs.keys().size() == 0
                    and bkts.get(b).mpu.keys().size() == 0)
                mapDrop(bkts, b)
            else bkts,
        nextUpl' = nextUpl,
        lastOp' =
            if (not(liveBuckets.contains(b)))
                ODeleteBucket({ bucket: b, status: HTTP_NOT_FOUND, err: "NoSuchBucket" })
            else if (bkts.get(b).objs.keys().size() > 0
                     or bkts.get(b).mpu.keys().size() > 0)
                ODeleteBucket({ bucket: b, status: HTTP_CONFLICT, err: "BucketNotEmpty" })
            else
                ODeleteBucket({ bucket: b, status: HTTP_NO_CONTENT, err: "" }),
    }

    action deleteBucket = {
        nondet b = oneOf(BUCKETS)
        applyDeleteBucket(b)
    }

    // ------------------------------------------------------------------
    // ListBuckets (GET /)
    // ------------------------------------------------------------------

    // The response bucket list is compared as a set: AWS documents no
    // contractual ordering for ListBuckets.
    action listBuckets = all {
        bkts' = bkts,
        nextUpl' = nextUpl,
        lastOp' = OListBuckets({ buckets: liveBuckets, status: HTTP_OK }),
    }

    // ------------------------------------------------------------------
    // PutObject (PUT /{bucket}/{key})
    // ------------------------------------------------------------------

    // A PUT into a live bucket creates or replaces the object -- content,
    // metadata and (implicitly empty) tag set alike.  Keys with slashes
    // need no parents: the namespace is flat.
    action applyPutObject(b: str, k: Key, d: Blocks, mt: int): bool = all {
        bkts' =
            if (liveBuckets.contains(b))
                bkts.setBy(b, bk => bk.with("objs", bk.objs.put(k, mkObj(d, mt))))
            else bkts,
        nextUpl' = nextUpl,
        lastOp' =
            if (liveBuckets.contains(b))
                OPutObject({ bucket: b, key: k, data: d, mtag: mt,
                             status: HTTP_OK, err: "" })
            else
                OPutObject({ bucket: b, key: k, data: d, mtag: mt,
                             status: HTTP_NOT_FOUND, err: "NoSuchBucket" }),
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
            nondet b = oneOf(BUCKETS)
            nondet k = oneOf(KEYS)
            nondet d = oneOf(DATAS)
            applyPutObject(b, k, d, 0)
        },
    }

    // ------------------------------------------------------------------
    // GetObject (GET /{bucket}/{key}), optionally ranged
    // ------------------------------------------------------------------

    action applyGetObject(b: str, k: Key, r: Range): bool = all {
        bkts' = bkts,
        nextUpl' = nextUpl,
        lastOp' =
            if (not(liveBuckets.contains(b)))
                OGetObject({ bucket: b, key: k, range: r, status: HTTP_NOT_FOUND,
                             err: "NoSuchBucket", data: [], first: -1, total: -1 })
            else if (not(bkts.get(b).objs.keys().contains(k)))
                OGetObject({ bucket: b, key: k, range: r, status: HTTP_NOT_FOUND,
                             err: "NoSuchKey", data: [], first: -1, total: -1 })
            else
                val d = bkts.get(b).objs.get(k).data
                val ro = rangeApply(d, r)
                OGetObject({ bucket: b, key: k, range: r, status: ro.status,
                             err: ro.err, data: ro.out, first: ro.first,
                             total: d.length() }),
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
        nondet b = oneOf(BUCKETS)
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
        lastOp' =
            if (liveBuckets.contains(b) and bkts.get(b).objs.keys().contains(k))
                OHeadObject({ bucket: b, key: k, status: HTTP_OK,
                              sizeBlocks: bkts.get(b).objs.get(k).data.length() })
            else
                OHeadObject({ bucket: b, key: k, status: HTTP_NOT_FOUND,
                              sizeBlocks: -1 }),
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
    action applyDeleteObject(b: str, k: Key): bool = all {
        bkts' =
            if (liveBuckets.contains(b))
                bkts.setBy(b, bk => bk.with("objs", mapDrop(bk.objs, k)))
            else bkts,
        nextUpl' = nextUpl,
        lastOp' =
            if (not(liveBuckets.contains(b)))
                ODeleteObject({ bucket: b, key: k, status: HTTP_NOT_FOUND,
                                err: "NoSuchBucket" })
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
        nondet b = oneOf(BUCKETS)
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
    // entries.  Duplicate keys in one request are legal and each occurrence
    // is reported.
    action applyDeleteObjects(b: str, ks: List[Key], quiet: bool): bool = all {
        bkts' =
            if (liveBuckets.contains(b))
                bkts.setBy(b, bk =>
                    bk.with("objs", ks.foldl(bk.objs, (m, k) => mapDrop(m, k))))
            else bkts,
        nextUpl' = nextUpl,
        lastOp' =
            if (not(liveBuckets.contains(b)))
                ODeleteObjects({ bucket: b, keys: ks, quiet: quiet,
                                 status: HTTP_NOT_FOUND, err: "NoSuchBucket" })
            else
                ODeleteObjects({ bucket: b, keys: ks, quiet: quiet,
                                 status: HTTP_OK, err: "" }),
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
        nondet b = oneOf(BUCKETS)
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
    action applyCopyObject(sb: str, sk: Key, db: str, dk: Key): bool = all {
        bkts' =
            if (liveBuckets.contains(db) and liveBuckets.contains(sb)
                    and bkts.get(sb).objs.keys().contains(sk)
                    and not(sb == db and sk == dk))
                bkts.setBy(db, bk =>
                    bk.with("objs", bk.objs.put(dk, bkts.get(sb).objs.get(sk))))
            else bkts,
        nextUpl' = nextUpl,
        lastOp' =
            if (not(liveBuckets.contains(db)))
                OCopyObject({ srcBucket: sb, srcKey: sk, dstBucket: db, dstKey: dk,
                              status: HTTP_NOT_FOUND, err: "NoSuchBucket" })
            else if (not(liveBuckets.contains(sb)))
                OCopyObject({ srcBucket: sb, srcKey: sk, dstBucket: db, dstKey: dk,
                              status: HTTP_NOT_FOUND, err: "NoSuchBucket" })
            else if (not(bkts.get(sb).objs.keys().contains(sk)))
                OCopyObject({ srcBucket: sb, srcKey: sk, dstBucket: db, dstKey: dk,
                              status: HTTP_NOT_FOUND, err: "NoSuchKey" })
            else if (sb == db and sk == dk)
                OCopyObject({ srcBucket: sb, srcKey: sk, dstBucket: db, dstKey: dk,
                              status: HTTP_BAD_REQUEST, err: "InvalidRequest" })
            else
                OCopyObject({ srcBucket: sb, srcKey: sk, dstBucket: db, dstKey: dk,
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

    // Copy with unconstrained names (NoSuchBucket / NoSuchKey coverage).
    action copyObjectAny = all {
        totalObjs < MAX_OBJECTS,
        {
            nondet sb = oneOf(BUCKETS)
            nondet sk = oneOf(KEYS)
            nondet db = oneOf(BUCKETS)
            nondet dk = oneOf(KEYS)
            applyCopyObject(sb, sk, db, dk)
        },
    }

    // ------------------------------------------------------------------
    // GetObjectAttributes (GET /{bucket}/{key}?attributes)
    // ------------------------------------------------------------------

    // The harness requests ETag, StorageClass and ObjectSize (the
    // filesystem-suppliable set); the response reports the object size and
    // an unquoted ETag the harness checks for consistency.
    action applyGetAttrs(b: str, k: Key): bool = all {
        bkts' = bkts,
        nextUpl' = nextUpl,
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

    action applyListObjects(b: str, p: Prefix, delim: bool, sa: Key, mk: int, mode: int): bool = all {
        bkts' = bkts,
        nextUpl' = nextUpl,
        lastOp' =
            if (not(liveBuckets.contains(b)))
                OListObjects({ bucket: b, prefix: p, delim: delim, startAfter: sa,
                               maxKeys: mk, mode: mode, status: HTTP_NOT_FOUND,
                               err: "NoSuchBucket",
                               keys: [], prefixes: [], truncated: false })
            else
                val w = listWalk(bkts.get(b).objs.keys(), p, delim, sa, mk)
                OListObjects({ bucket: b, prefix: p, delim: delim, startAfter: sa,
                               maxKeys: mk, mode: mode, status: HTTP_OK, err: "",
                               keys: w.keys, prefixes: w.prefixes,
                               truncated: w.truncated }),
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
                bkts.setBy(b, bk =>
                    bk.with("objs", bk.objs.setBy(k, o => o.with("tags", ts))))
            else bkts,
        nextUpl' = nextUpl,
        lastOp' =
            if (not(liveBuckets.contains(b)))
                OPutObjTagging({ bucket: b, key: k, tags: ts,
                                 status: HTTP_NOT_FOUND, err: "NoSuchBucket" })
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
        lastOp' =
            if (not(liveBuckets.contains(b)))
                OGetObjTagging({ bucket: b, key: k, status: HTTP_NOT_FOUND,
                                 err: "NoSuchBucket", tags: Set() })
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
                bkts.setBy(b, bk =>
                    bk.with("objs", bk.objs.setBy(k, o => o.with("tags", Set()))))
            else bkts,
        nextUpl' = nextUpl,
        lastOp' =
            if (not(liveBuckets.contains(b)))
                ODelObjTagging({ bucket: b, key: k, status: HTTP_NOT_FOUND,
                                 err: "NoSuchBucket" })
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
        lastOp' =
            if (not(liveBuckets.contains(b)))
                OPutBktTagging({ bucket: b, tags: ts, status: HTTP_NOT_FOUND,
                                 err: "NoSuchBucket" })
            else
                OPutBktTagging({ bucket: b, tags: ts, status: HTTP_OK, err: "" }),
    }

    action putBktTagging = {
        nondet b = oneOf(BUCKETS)
        nondet ts = oneOf(TAGSETS)
        applyPutBktTagging(b, ts)
    }

    // GetBucketTagging with no tags stored is 404 NoSuchTagSet (unlike the
    // object-level call).
    action applyGetBktTagging(b: str): bool = all {
        bkts' = bkts,
        nextUpl' = nextUpl,
        lastOp' =
            if (not(liveBuckets.contains(b)))
                OGetBktTagging({ bucket: b, status: HTTP_NOT_FOUND,
                                 err: "NoSuchBucket", tags: Set() })
            else if (bkts.get(b).btags.size() == 0)
                OGetBktTagging({ bucket: b, status: HTTP_NOT_FOUND,
                                 err: "NoSuchTagSet", tags: Set() })
            else
                OGetBktTagging({ bucket: b, status: HTTP_OK, err: "",
                                 tags: bkts.get(b).btags }),
    }

    action getBktTagging = {
        nondet b = oneOf(BUCKETS)
        applyGetBktTagging(b)
    }

    action applyDelBktTagging(b: str): bool = all {
        bkts' =
            if (liveBuckets.contains(b))
                bkts.setBy(b, bk => bk.with("btags", Set()))
            else bkts,
        nextUpl' = nextUpl,
        lastOp' =
            if (not(liveBuckets.contains(b)))
                ODelBktTagging({ bucket: b, status: HTTP_NOT_FOUND,
                                 err: "NoSuchBucket" })
            else
                ODelBktTagging({ bucket: b, status: HTTP_NO_CONTENT, err: "" }),
    }

    action delBktTagging = {
        nondet b = oneOf(BUCKETS)
        applyDelBktTagging(b)
    }

    // ------------------------------------------------------------------
    // Multipart upload (generated only by stepMultipart; see the module
    // comment for the block-size contract)
    // ------------------------------------------------------------------

    action applyCreateMpu(b: str, k: Key): bool = all {
        bkts' =
            if (liveBuckets.contains(b))
                bkts.setBy(b, bk =>
                    bk.with("mpu", bk.mpu.put(nextUpl, { key: k, parts: Map() })))
            else bkts,
        nextUpl' = if (liveBuckets.contains(b)) nextUpl + 1 else nextUpl,
        lastOp' =
            if (liveBuckets.contains(b))
                OCreateMpu({ bucket: b, key: k, uplid: nextUpl,
                             status: HTTP_OK, err: "" })
            else
                OCreateMpu({ bucket: b, key: k, uplid: -1,
                             status: HTTP_NOT_FOUND, err: "NoSuchBucket" }),
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
        lastOp' =
            if (not(liveBuckets.contains(b)))
                OUploadPart({ bucket: b, key: k, uplid: u, partNum: n, data: d,
                              status: HTTP_NOT_FOUND, err: "NoSuchBucket" })
            else if (n == 0)
                OUploadPart({ bucket: b, key: k, uplid: u, partNum: n, data: d,
                              status: HTTP_BAD_REQUEST, err: "InvalidArgument" })
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
            lastOp' =
                if (not(liveBuckets.contains(b)))
                    OUploadPartCopy({ bucket: b, key: k, uplid: u, partNum: n,
                                      srcBucket: sb, srcKey: sk, range: r, data: [],
                                      status: HTTP_NOT_FOUND, err: "NoSuchBucket" })
                else if (n == 0)
                    OUploadPartCopy({ bucket: b, key: k, uplid: u, partNum: n,
                                      srcBucket: sb, srcKey: sk, range: r, data: [],
                                      status: HTTP_BAD_REQUEST, err: "InvalidArgument" })
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
            nondet sb = oneOf(BUCKETS)
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
                        bk.with("objs", bk.objs.put(k,
                            mkObj(assembleParts(bk.mpu.get(u).parts, manifest), 0)))
                          .with("mpu", mapDrop(bk.mpu, u)))
                else bkts,
            nextUpl' = nextUpl,
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
        lastOp' =
            if (not(liveBuckets.contains(b)))
                OAbortMpu({ bucket: b, key: k, uplid: u,
                            status: HTTP_NOT_FOUND, err: "NoSuchBucket" })
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

    action applyListParts(b: str, k: Key, u: int): bool = all {
        bkts' = bkts,
        nextUpl' = nextUpl,
        lastOp' =
            if (not(liveBuckets.contains(b)))
                OListParts({ bucket: b, key: k, uplid: u, status: HTTP_NOT_FOUND,
                             err: "NoSuchBucket", partNums: [] })
            else if (not(bkts.get(b).mpu.keys().contains(u)))
                OListParts({ bucket: b, key: k, uplid: u, status: HTTP_NOT_FOUND,
                             err: "NoSuchUpload", partNums: [] })
            else
                OListParts({ bucket: b, key: k, uplid: u, status: HTTP_OK, err: "",
                             partNums: sortedParts(bkts.get(b).mpu.get(u).parts) }),
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
    action applyListMpu(b: str): bool = all {
        bkts' = bkts,
        nextUpl' = nextUpl,
        lastOp' =
            if (not(liveBuckets.contains(b)))
                OListMpu({ bucket: b, status: HTTP_NOT_FOUND, err: "NoSuchBucket",
                           uploads: Set() })
            else
                OListMpu({ bucket: b, status: HTTP_OK, err: "",
                           uploads: bkts.get(b).mpu.keys().map(u =>
                               { key: bkts.get(b).mpu.get(u).key, uplid: u }) }),
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
                and MTAGS.contains(o.mtag) and o.tags.subseteq(TAG_IDS)))

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

    val inv = bucketsInUniverse and objectsValid and bucketTagsValid
        and uploadsValid and objectsBounded and uploadsBounded
}
