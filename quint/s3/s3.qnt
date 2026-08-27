// SPDX-FileCopyrightText: 2026 The Quint Specs Authors
//
// SPDX-License-Identifier: MIT

// Quint model of the Amazon S3 REST API, restricted to the operation set a
// filesystem-backed S3 gateway serves, used for model-based testing at the
// HTTP request/response level.
//
// The model tracks a flat object store (bucket -> key -> content) and, on
// every step, records the HTTP request issued and the response the service
// is expected to produce in the state variable `lastOp`.  Traces generated
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
//  - ETag, Last-Modified, Owner and Date are not modeled; the harness
//    checks ETag *consistency* (an object reports the same ETag from PUT,
//    GET, HEAD and List until it is rewritten) without predicting values.
//  - Statuses are HTTP status codes, numerically identical to the wire, so
//    the harness compares raw status with no decode step.  The `err` field
//    carries the S3 <Code> of the XML error body ("" when the response has
//    no error body -- success, or a HEAD response, which has no body).
//  - Authentication is not modeled: every request the harness sends is
//    correctly SigV4-signed.  ListObjects is modeled as ListObjectsV2
//    (list-type=2) with start-after; continuation tokens are opaque and
//    unmodeled.

module s3 {

    type Comp = str
    // An object key, as its slash-separated path components.
    type Key = List[Comp]
    // Object content: a list of block symbols, expanded by the harness.
    type Blocks = List[int]

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

    // Content block symbols; 0 is reserved (S3 has no holes).
    pure val BLOCK_SYMS = 1.to(3)
    pure val MAX_BLOCKS = 3
    // Every content the generator can PUT: 0..3 blocks over BLOCK_SYMS.
    pure val DATAS: Set[Blocks] =
        Set(List())
            .union(BLOCK_SYMS.map(a => [a]))
            .union(tuples(BLOCK_SYMS, BLOCK_SYMS).map(t => [t._1, t._2]))
            .union(tuples(BLOCK_SYMS, BLOCK_SYMS, BLOCK_SYMS).map(t => [t._1, t._2, t._3]))

    // Cap on live objects across all buckets, keeping traces small.
    pure val MAX_OBJECTS = 8

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
    // lists are empty, sizeBlocks/first/total are -1.
    type Op =
        | OInit
        | OCreateBucket({ bucket: str, status: int })
        | OHeadBucket({ bucket: str, status: int })
        | ODeleteBucket({ bucket: str, status: int, err: str })
        | OListBuckets({ buckets: Set[str], status: int })
        | OPutObject({ bucket: str, key: Key, data: Blocks, status: int, err: str })
        | OGetObject({ bucket: str, key: Key, range: Range, status: int, err: str,
                       data: Blocks, first: int, total: int })
        | OHeadObject({ bucket: str, key: Key, status: int, sizeBlocks: int })
        | ODeleteObject({ bucket: str, key: Key, status: int, err: str })
        | OCopyObject({ srcBucket: str, srcKey: Key, dstBucket: str, dstKey: Key,
                        status: int, err: str })
        | OListObjects({ bucket: str, prefix: Prefix, delim: bool, startAfter: Key,
                         maxKeys: int, status: int, err: str,
                         keys: List[Key], prefixes: List[Key], truncated: bool })

    // ------------------------------------------------------------------
    // State
    // ------------------------------------------------------------------

    // The object store: bucket name -> (key -> content).  Bucket existence
    // is membership in the outer map.
    var bkts: str -> (Key -> Blocks)
    var lastOp: Op

    val liveBuckets = bkts.keys()
    val totalObjs = liveBuckets.fold(0, (n, b) => n + bkts.get(b).keys().size())
    // Every live (bucket, key) pair, for hit-biased generators.
    val objPairs = liveBuckets.map(b => bkts.get(b).keys().map(k => (b, k))).flatten()

    pure def imin(a: int, b: int): int = if (a < b) a else b
    pure def imax(a: int, b: int): int = if (a > b) a else b
    // Quint has no builtin to delete a map key.
    pure def mapDrop(m: Key -> Blocks, k: Key): Key -> Blocks =
        m.keys().exclude(Set(k)).mapBy(x => m.get(x))
    pure def bktsDrop(m: str -> (Key -> Blocks), b: str): str -> (Key -> Blocks) =
        m.keys().exclude(Set(b)).mapBy(x => m.get(x))

    // ------------------------------------------------------------------
    // Listing (the ListObjectsV2 algorithm, AWS API Reference)
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

    // The ListObjectsV2 walk: object keys in byte order, those at or below
    // start-after skipped, each emitting itself (no delimiter) or its
    // rollup (delimiter "/"); consecutive keys sharing a rollup collapse
    // into one <CommonPrefixes> entry; the page closes after maxKeys
    // emissions and IsTruncated reports whether any further key would have
    // emitted a new entry.  AWS returns an empty, non-truncated result for
    // max-keys=0.
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
    // Initialization
    // ------------------------------------------------------------------

    // The service starts with no buckets; traces create what they use
    // (CreateBucket is part of the modeled surface).
    action init = all {
        bkts' = Map(),
        lastOp' = OInit,
    }

    // ------------------------------------------------------------------
    // CreateBucket (PUT /{bucket})
    // ------------------------------------------------------------------

    // us-east-1 semantics: creating a bucket that already exists and is
    // yours is idempotent 200 (elsewhere AWS returns 409
    // BucketAlreadyOwnedByYou; a single-tenant gateway is "us-east-1").
    action applyCreateBucket(b: str): bool = all {
        bkts' = if (liveBuckets.contains(b)) bkts else bkts.put(b, Map()),
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

    action applyDeleteBucket(b: str): bool = all {
        bkts' =
            if (liveBuckets.contains(b) and bkts.get(b).keys().size() == 0)
                bktsDrop(bkts, b)
            else bkts,
        lastOp' =
            if (not(liveBuckets.contains(b)))
                ODeleteBucket({ bucket: b, status: HTTP_NOT_FOUND, err: "NoSuchBucket" })
            else if (bkts.get(b).keys().size() > 0)
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
        lastOp' = OListBuckets({ buckets: liveBuckets, status: HTTP_OK }),
    }

    // ------------------------------------------------------------------
    // PutObject (PUT /{bucket}/{key})
    // ------------------------------------------------------------------

    // A PUT into a live bucket creates or replaces the object.  Keys with
    // slashes need no parents: the namespace is flat (the gateway under
    // test materializes intermediate directories; that is invisible at the
    // API and stays invisible while dir and leaf components are disjoint).
    action applyPutObject(b: str, k: Key, d: Blocks): bool = all {
        bkts' =
            if (liveBuckets.contains(b))
                bkts.setBy(b, objs => objs.put(k, d))
            else bkts,
        lastOp' =
            if (liveBuckets.contains(b))
                OPutObject({ bucket: b, key: k, data: d, status: HTTP_OK, err: "" })
            else
                OPutObject({ bucket: b, key: k, data: d,
                             status: HTTP_NOT_FOUND, err: "NoSuchBucket" }),
    }

    action putObject = all {
        liveBuckets.size() > 0,
        totalObjs < MAX_OBJECTS,
        {
            nondet b = oneOf(liveBuckets)
            nondet k = oneOf(KEYS)
            nondet d = oneOf(DATAS)
            applyPutObject(b, k, d)
        },
    }

    // PUT against any bucket name, live or not (NoSuchBucket coverage).
    action putObjectAny = all {
        totalObjs < MAX_OBJECTS,
        {
            nondet b = oneOf(BUCKETS)
            nondet k = oneOf(KEYS)
            nondet d = oneOf(DATAS)
            applyPutObject(b, k, d)
        },
    }

    // ------------------------------------------------------------------
    // GetObject (GET /{bucket}/{key}), optionally ranged
    // ------------------------------------------------------------------

    action applyGetObject(b: str, k: Key, r: Range): bool = all {
        bkts' = bkts,
        lastOp' =
            if (not(liveBuckets.contains(b)))
                OGetObject({ bucket: b, key: k, range: r, status: HTTP_NOT_FOUND,
                             err: "NoSuchBucket", data: [], first: -1, total: -1 })
            else if (not(bkts.get(b).keys().contains(k)))
                OGetObject({ bucket: b, key: k, range: r, status: HTTP_NOT_FOUND,
                             err: "NoSuchKey", data: [], first: -1, total: -1 })
            else
                val d = bkts.get(b).get(k)
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
    // XML <Code> to compare); the harness checks status and Content-Length.
    action applyHeadObject(b: str, k: Key): bool = all {
        bkts' = bkts,
        lastOp' =
            if (liveBuckets.contains(b) and bkts.get(b).keys().contains(k))
                OHeadObject({ bucket: b, key: k, status: HTTP_OK,
                              sizeBlocks: bkts.get(b).get(k).length() })
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
                bkts.setBy(b, objs => mapDrop(objs, k))
            else bkts,
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
    // CopyObject (PUT /{dstBucket}/{dstKey} + x-amz-copy-source)
    // ------------------------------------------------------------------

    // The request URI names the destination, so a missing destination
    // bucket reports before the source is looked at.  A copy onto itself
    // with no metadata directive is 400 InvalidRequest ("This copy request
    // is illegal because it is trying to copy an object to itself...").
    action applyCopyObject(sb: str, sk: Key, db: str, dk: Key): bool = all {
        bkts' =
            if (liveBuckets.contains(db) and liveBuckets.contains(sb)
                    and bkts.get(sb).keys().contains(sk)
                    and not(sb == db and sk == dk))
                bkts.setBy(db, objs => objs.put(dk, bkts.get(sb).get(sk)))
            else bkts,
        lastOp' =
            if (not(liveBuckets.contains(db)))
                OCopyObject({ srcBucket: sb, srcKey: sk, dstBucket: db, dstKey: dk,
                              status: HTTP_NOT_FOUND, err: "NoSuchBucket" })
            else if (not(liveBuckets.contains(sb)))
                OCopyObject({ srcBucket: sb, srcKey: sk, dstBucket: db, dstKey: dk,
                              status: HTTP_NOT_FOUND, err: "NoSuchBucket" })
            else if (not(bkts.get(sb).keys().contains(sk)))
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
    // ListObjectsV2 (GET /{bucket}?list-type=2)
    // ------------------------------------------------------------------

    action applyListObjects(b: str, p: Prefix, delim: bool, sa: Key, mk: int): bool = all {
        bkts' = bkts,
        lastOp' =
            if (not(liveBuckets.contains(b)))
                OListObjects({ bucket: b, prefix: p, delim: delim, startAfter: sa,
                               maxKeys: mk, status: HTTP_NOT_FOUND, err: "NoSuchBucket",
                               keys: [], prefixes: [], truncated: false })
            else
                val w = listWalk(bkts.get(b).keys(), p, delim, sa, mk)
                OListObjects({ bucket: b, prefix: p, delim: delim, startAfter: sa,
                               maxKeys: mk, status: HTTP_OK, err: "",
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
            applyListObjects(b, p, delim, sa, mk)
        },
    }

    // ------------------------------------------------------------------
    // Step distributions
    // ------------------------------------------------------------------

    // Uniform-ish mix.  createBucket / headBucket / listBuckets /
    // deleteBucket are always enabled and act as the liveness fallback;
    // the object actions gate on a live bucket (or object) existing.
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
        copyObject,
        listObjects, listObjects,
    }

    // Data-path heavy: puts, ranged gets, overwrites; minimal namespace
    // churn.
    action stepData = any {
        putObject, putObject, putObject, putObject,
        getObject, getObject,
        getObjectRange, getObjectRange, getObjectRange,
        headObject,
        deleteObjectHit,
        copyObject,
        createBucket,
        listBuckets,
    }

    // Listing-heavy: build and churn a keyspace, list it from every angle.
    action stepList = any {
        putObject, putObject, putObject,
        deleteObject, deleteObjectHit,
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
    }

    // ------------------------------------------------------------------
    // Invariants (structural sanity of the model itself)
    // ------------------------------------------------------------------

    val bucketsInUniverse = liveBuckets.subseteq(BUCKETS)

    val keysInUniverse = liveBuckets.forall(b =>
        bkts.get(b).keys().forall(k => KEYS.contains(k)))

    val contentsValid = liveBuckets.forall(b =>
        bkts.get(b).keys().forall(k =>
            val d = bkts.get(b).get(k)
            d.length() <= MAX_BLOCKS and d.indices().forall(i => BLOCK_SYMS.contains(d[i]))))

    val objectsBounded = totalObjs <= MAX_OBJECTS

    val inv = bucketsInUniverse and keysInUniverse and contentsValid and objectsBounded
}
