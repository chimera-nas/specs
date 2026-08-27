// SPDX-FileCopyrightText: 2026 The Quint Specs Authors
//
// SPDX-License-Identifier: MIT

// Deterministic self-checks for the S3 model, executed with `quint test`.
// These validate the model's own transition logic without a server, so a
// model regression is caught before it can invalidate generated traces.

module s3Test {
    import s3.* from "./s3"

    // Key shorthands (component lists).
    pure val kA: Key = ["a"]
    pure val kB: Key = ["b"]
    pure val kDA: Key = ["d", "a"]
    pure val kDB: Key = ["d", "b"]
    pure val kDEA: Key = ["d", "e", "a"]
    pure val kEA: Key = ["e", "a"]

    // Prefix shorthands.
    pure val pAll: Prefix = { comps: [], slash: false }
    pure val pD: Prefix = { comps: ["d"], slash: true }
    pure val pDE: Prefix = { comps: ["d", "e"], slash: true }
    pure val pE: Prefix = { comps: ["e"], slash: true }
    pure val pBareD: Prefix = { comps: ["d"], slash: false }
    pure val pBareA: Prefix = { comps: ["a"], slash: false }

    run bucketLifecycleTest =
        init
            .then(applyCreateBucket("bk0"))
            .expect(lastOp == OCreateBucket({ bucket: "bk0", status: HTTP_OK }))
            .then(applyHeadBucket("bk0"))
            .expect(lastOp == OHeadBucket({ bucket: "bk0", status: HTTP_OK }))
            .then(applyHeadBucket("bk1"))
            .expect(lastOp == OHeadBucket({ bucket: "bk1", status: HTTP_NOT_FOUND }))
            .then(applyDeleteBucket("bk1"))
            .expect(lastOp == ODeleteBucket({ bucket: "bk1", status: HTTP_NOT_FOUND,
                                              err: "NoSuchBucket" }))
            // creating an existing bucket is idempotent 200 (us-east-1)
            .then(applyCreateBucket("bk0"))
            .expect(lastOp == OCreateBucket({ bucket: "bk0", status: HTTP_OK }))
            .then(applyDeleteBucket("bk0"))
            .expect(lastOp == ODeleteBucket({ bucket: "bk0", status: HTTP_NO_CONTENT,
                                              err: "" }))
            .then(applyHeadBucket("bk0"))
            .expect(lastOp == OHeadBucket({ bucket: "bk0", status: HTTP_NOT_FOUND }))

    run bucketNotEmptyTest =
        init
            .then(applyCreateBucket("bk0"))
            .then(applyPutObject("bk0", kA, [1]))
            .then(applyDeleteBucket("bk0"))
            .expect(lastOp == ODeleteBucket({ bucket: "bk0", status: HTTP_CONFLICT,
                                              err: "BucketNotEmpty" }))
            .expect(bkts.keys().contains("bk0"))
            .then(applyDeleteObject("bk0", kA))
            .expect(lastOp == ODeleteObject({ bucket: "bk0", key: kA,
                                              status: HTTP_NO_CONTENT, err: "" }))
            .then(applyDeleteBucket("bk0"))
            .expect(lastOp == ODeleteBucket({ bucket: "bk0", status: HTTP_NO_CONTENT,
                                              err: "" }))

    run listBucketsTest =
        init
            .then(listBuckets)
            .expect(lastOp == OListBuckets({ buckets: Set(), status: HTTP_OK }))
            .then(applyCreateBucket("bk0"))
            .then(applyCreateBucket("bk1"))
            .then(listBuckets)
            .expect(lastOp == OListBuckets({ buckets: Set("bk0", "bk1"),
                                             status: HTTP_OK }))

    run putGetHeadTest =
        init
            .then(applyCreateBucket("bk0"))
            .then(applyPutObject("bk0", kDA, [1, 2]))
            .expect(lastOp == OPutObject({ bucket: "bk0", key: kDA, data: [1, 2],
                                           status: HTTP_OK, err: "" }))
            .expect(bkts.get("bk0").get(kDA) == [1, 2])
            .then(applyGetObject("bk0", kDA, RNone))
            .expect(lastOp == OGetObject({ bucket: "bk0", key: kDA, range: RNone,
                                           status: HTTP_OK, err: "", data: [1, 2],
                                           first: 0, total: 2 }))
            .then(applyHeadObject("bk0", kDA))
            .expect(lastOp == OHeadObject({ bucket: "bk0", key: kDA,
                                            status: HTTP_OK, sizeBlocks: 2 }))
            .then(applyGetObject("bk0", kB, RNone))
            .expect(lastOp == OGetObject({ bucket: "bk0", key: kB, range: RNone,
                                           status: HTTP_NOT_FOUND, err: "NoSuchKey",
                                           data: [], first: -1, total: -1 }))
            .then(applyPutObject("bk1", kA, [1]))
            .expect(lastOp == OPutObject({ bucket: "bk1", key: kA, data: [1],
                                           status: HTTP_NOT_FOUND,
                                           err: "NoSuchBucket" }))
            .then(applyHeadObject("bk1", kA))
            .expect(lastOp == OHeadObject({ bucket: "bk1", key: kA,
                                            status: HTTP_NOT_FOUND, sizeBlocks: -1 }))

    run overwriteTest =
        init
            .then(applyCreateBucket("bk0"))
            .then(applyPutObject("bk0", kA, [1]))
            .then(applyPutObject("bk0", kA, [2, 3]))
            .expect(bkts.get("bk0").get(kA) == [2, 3])
            .then(applyGetObject("bk0", kA, RNone))
            .expect(lastOp == OGetObject({ bucket: "bk0", key: kA, range: RNone,
                                           status: HTTP_OK, err: "", data: [2, 3],
                                           first: 0, total: 2 }))

    run emptyObjectTest =
        init
            .then(applyCreateBucket("bk0"))
            .then(applyPutObject("bk0", kA, []))
            .then(applyGetObject("bk0", kA, RNone))
            .expect(lastOp == OGetObject({ bucket: "bk0", key: kA, range: RNone,
                                           status: HTTP_OK, err: "", data: [],
                                           first: 0, total: 0 }))
            .then(applyHeadObject("bk0", kA))
            .expect(lastOp == OHeadObject({ bucket: "bk0", key: kA,
                                            status: HTTP_OK, sizeBlocks: 0 }))
            // any range against a zero-length object is unsatisfiable
            .then(applyGetObject("bk0", kA, RSuffix(1)))
            .expect(lastOp == OGetObject({ bucket: "bk0", key: kA, range: RSuffix(1),
                                           status: HTTP_RANGE_ERR, err: "InvalidRange",
                                           data: [], first: -1, total: 0 }))

    // AWS DeleteObject is idempotent: 204 whether or not the key exists.
    run deleteIdempotentTest =
        init
            .then(applyCreateBucket("bk0"))
            .then(applyDeleteObject("bk0", kA))
            .expect(lastOp == ODeleteObject({ bucket: "bk0", key: kA,
                                              status: HTTP_NO_CONTENT, err: "" }))
            .then(applyPutObject("bk0", kA, [1]))
            .then(applyDeleteObject("bk0", kA))
            .expect(lastOp == ODeleteObject({ bucket: "bk0", key: kA,
                                              status: HTTP_NO_CONTENT, err: "" }))
            .then(applyGetObject("bk0", kA, RNone))
            .expect(lastOp == OGetObject({ bucket: "bk0", key: kA, range: RNone,
                                           status: HTTP_NOT_FOUND, err: "NoSuchKey",
                                           data: [], first: -1, total: -1 }))
            .then(applyDeleteObject("bk1", kA))
            .expect(lastOp == ODeleteObject({ bucket: "bk1", key: kA,
                                              status: HTTP_NOT_FOUND,
                                              err: "NoSuchBucket" }))

    run copyTest =
        init
            .then(applyCreateBucket("bk0"))
            // destination bucket is resolved first (it names the request URI)
            .then(applyCopyObject("bk0", kA, "bk1", kB))
            .expect(lastOp == OCopyObject({ srcBucket: "bk0", srcKey: kA,
                                            dstBucket: "bk1", dstKey: kB,
                                            status: HTTP_NOT_FOUND,
                                            err: "NoSuchBucket" }))
            .then(applyCreateBucket("bk1"))
            .then(applyPutObject("bk0", kA, [1, 2]))
            .then(applyCopyObject("bk0", kA, "bk1", kDA))
            .expect(lastOp == OCopyObject({ srcBucket: "bk0", srcKey: kA,
                                            dstBucket: "bk1", dstKey: kDA,
                                            status: HTTP_OK, err: "" }))
            .expect(bkts.get("bk1").get(kDA) == [1, 2])
            .then(applyGetObject("bk1", kDA, RNone))
            .expect(lastOp == OGetObject({ bucket: "bk1", key: kDA, range: RNone,
                                           status: HTTP_OK, err: "", data: [1, 2],
                                           first: 0, total: 2 }))
            // missing source key
            .then(applyCopyObject("bk0", kB, "bk1", kB))
            .expect(lastOp == OCopyObject({ srcBucket: "bk0", srcKey: kB,
                                            dstBucket: "bk1", dstKey: kB,
                                            status: HTTP_NOT_FOUND,
                                            err: "NoSuchKey" }))
            // copy onto itself without a metadata directive
            .then(applyCopyObject("bk0", kA, "bk0", kA))
            .expect(lastOp == OCopyObject({ srcBucket: "bk0", srcKey: kA,
                                            dstBucket: "bk0", dstKey: kA,
                                            status: HTTP_BAD_REQUEST,
                                            err: "InvalidRequest" }))
            .expect(bkts.get("bk0").get(kA) == [1, 2])

    run rangeTest =
        init
            .then(applyCreateBucket("bk0"))
            .then(applyPutObject("bk0", kA, [1, 2, 3]))
            .then(applyGetObject("bk0", kA, RClosed({ first: 0, last: 0 })))
            .expect(lastOp == OGetObject({ bucket: "bk0", key: kA,
                                           range: RClosed({ first: 0, last: 0 }),
                                           status: HTTP_PARTIAL, err: "", data: [1],
                                           first: 0, total: 3 }))
            // last past EOF is clamped, not rejected
            .then(applyGetObject("bk0", kA, RClosed({ first: 1, last: 9 })))
            .expect(lastOp == OGetObject({ bucket: "bk0", key: kA,
                                           range: RClosed({ first: 1, last: 9 }),
                                           status: HTTP_PARTIAL, err: "",
                                           data: [2, 3], first: 1, total: 3 }))
            .then(applyGetObject("bk0", kA, RFrom(2)))
            .expect(lastOp == OGetObject({ bucket: "bk0", key: kA, range: RFrom(2),
                                           status: HTTP_PARTIAL, err: "", data: [3],
                                           first: 2, total: 3 }))
            // a satisfiable range covering the whole object is still 206
            .then(applyGetObject("bk0", kA, RFrom(0)))
            .expect(lastOp == OGetObject({ bucket: "bk0", key: kA, range: RFrom(0),
                                           status: HTTP_PARTIAL, err: "",
                                           data: [1, 2, 3], first: 0, total: 3 }))
            .then(applyGetObject("bk0", kA, RSuffix(2)))
            .expect(lastOp == OGetObject({ bucket: "bk0", key: kA, range: RSuffix(2),
                                           status: HTTP_PARTIAL, err: "",
                                           data: [2, 3], first: 1, total: 3 }))
            .then(applyGetObject("bk0", kA, RSuffix(9)))
            .expect(lastOp == OGetObject({ bucket: "bk0", key: kA, range: RSuffix(9),
                                           status: HTTP_PARTIAL, err: "",
                                           data: [1, 2, 3], first: 0, total: 3 }))
            // start at EOF is unsatisfiable
            .then(applyGetObject("bk0", kA, RClosed({ first: 3, last: 3 })))
            .expect(lastOp == OGetObject({ bucket: "bk0", key: kA,
                                           range: RClosed({ first: 3, last: 3 }),
                                           status: HTTP_RANGE_ERR, err: "InvalidRange",
                                           data: [], first: -1, total: 3 }))
            .then(applyGetObject("bk0", kA, RFrom(3)))
            .expect(lastOp == OGetObject({ bucket: "bk0", key: kA, range: RFrom(3),
                                           status: HTTP_RANGE_ERR, err: "InvalidRange",
                                           data: [], first: -1, total: 3 }))

    run listFlatTest =
        init
            .then(applyCreateBucket("bk0"))
            .then(applyPutObject("bk0", kA, [1]))
            .then(applyPutObject("bk0", kB, [1]))
            .then(applyPutObject("bk0", kDA, [1]))
            .then(applyPutObject("bk0", kDEA, [1]))
            .then(applyListObjects("bk0", pAll, false, NO_KEY, 1000))
            .expect(lastOp == OListObjects({ bucket: "bk0", prefix: pAll, delim: false,
                                             startAfter: NO_KEY, maxKeys: 1000,
                                             status: HTTP_OK, err: "",
                                             keys: [kA, kB, kDA, kDEA],
                                             prefixes: [], truncated: false }))
            // flat listing under a "d/" prefix
            .then(applyListObjects("bk0", pD, false, NO_KEY, 1000))
            .expect(lastOp == OListObjects({ bucket: "bk0", prefix: pD, delim: false,
                                             startAfter: NO_KEY, maxKeys: 1000,
                                             status: HTTP_OK, err: "",
                                             keys: [kDA, kDEA],
                                             prefixes: [], truncated: false }))

    run listDelimTest =
        init
            .then(applyCreateBucket("bk0"))
            .then(applyPutObject("bk0", kA, [1]))
            .then(applyPutObject("bk0", kB, [1]))
            .then(applyPutObject("bk0", kDA, [1]))
            .then(applyPutObject("bk0", kDEA, [1]))
            .then(applyListObjects("bk0", pAll, true, NO_KEY, 1000))
            .expect(lastOp == OListObjects({ bucket: "bk0", prefix: pAll, delim: true,
                                             startAfter: NO_KEY, maxKeys: 1000,
                                             status: HTTP_OK, err: "",
                                             keys: [kA, kB], prefixes: [["d"]],
                                             truncated: false }))
            .then(applyListObjects("bk0", pD, true, NO_KEY, 1000))
            .expect(lastOp == OListObjects({ bucket: "bk0", prefix: pD, delim: true,
                                             startAfter: NO_KEY, maxKeys: 1000,
                                             status: HTTP_OK, err: "",
                                             keys: [kDA], prefixes: [["d", "e"]],
                                             truncated: false }))
            .then(applyListObjects("bk0", pDE, true, NO_KEY, 1000))
            .expect(lastOp == OListObjects({ bucket: "bk0", prefix: pDE, delim: true,
                                             startAfter: NO_KEY, maxKeys: 1000,
                                             status: HTTP_OK, err: "",
                                             keys: [kDEA], prefixes: [],
                                             truncated: false }))
            // bare prefix "d": every d/... key rolls up into "d/"
            .then(applyListObjects("bk0", pBareD, true, NO_KEY, 1000))
            .expect(lastOp == OListObjects({ bucket: "bk0", prefix: pBareD, delim: true,
                                             startAfter: NO_KEY, maxKeys: 1000,
                                             status: HTTP_OK, err: "",
                                             keys: [], prefixes: [["d"]],
                                             truncated: false }))
            // bare prefix "a": exactly the object "a"
            .then(applyListObjects("bk0", pBareA, true, NO_KEY, 1000))
            .expect(lastOp == OListObjects({ bucket: "bk0", prefix: pBareA, delim: true,
                                             startAfter: NO_KEY, maxKeys: 1000,
                                             status: HTTP_OK, err: "",
                                             keys: [kA], prefixes: [],
                                             truncated: false }))

    run listPagingTest =
        init
            .then(applyCreateBucket("bk0"))
            .then(applyPutObject("bk0", kA, [1]))
            .then(applyPutObject("bk0", kB, [1]))
            .then(applyPutObject("bk0", kDA, [1]))
            .then(applyPutObject("bk0", kEA, [1]))
            // entries under "" + delimiter: a, b, d/, e/
            .then(applyListObjects("bk0", pAll, true, NO_KEY, 2))
            .expect(lastOp == OListObjects({ bucket: "bk0", prefix: pAll, delim: true,
                                             startAfter: NO_KEY, maxKeys: 2,
                                             status: HTTP_OK, err: "",
                                             keys: [kA, kB], prefixes: [],
                                             truncated: true }))
            .then(applyListObjects("bk0", pAll, true, NO_KEY, 3))
            .expect(lastOp == OListObjects({ bucket: "bk0", prefix: pAll, delim: true,
                                             startAfter: NO_KEY, maxKeys: 3,
                                             status: HTTP_OK, err: "",
                                             keys: [kA, kB], prefixes: [["d"]],
                                             truncated: true }))
            .then(applyListObjects("bk0", pAll, true, kB, 2))
            .expect(lastOp == OListObjects({ bucket: "bk0", prefix: pAll, delim: true,
                                             startAfter: kB, maxKeys: 2,
                                             status: HTTP_OK, err: "",
                                             keys: [], prefixes: [["d"], ["e"]],
                                             truncated: false }))
            // max-keys=0: empty page, not truncated
            .then(applyListObjects("bk0", pAll, true, NO_KEY, 0))
            .expect(lastOp == OListObjects({ bucket: "bk0", prefix: pAll, delim: true,
                                             startAfter: NO_KEY, maxKeys: 0,
                                             status: HTTP_OK, err: "",
                                             keys: [], prefixes: [],
                                             truncated: false }))

    // start-after inside a rolled-up group: keys past start-after still
    // surface their common prefix, even though the prefix string itself
    // sorts at or below start-after.
    run listStartAfterInGroupTest =
        init
            .then(applyCreateBucket("bk0"))
            .then(applyPutObject("bk0", kDA, [1]))
            .then(applyPutObject("bk0", kDB, [1]))
            .then(applyListObjects("bk0", pAll, true, kDA, 1000))
            .expect(lastOp == OListObjects({ bucket: "bk0", prefix: pAll, delim: true,
                                             startAfter: kDA, maxKeys: 1000,
                                             status: HTTP_OK, err: "",
                                             keys: [], prefixes: [["d"]],
                                             truncated: false }))
            // start-after past the whole group
            .then(applyListObjects("bk0", pAll, true, kDB, 1000))
            .expect(lastOp == OListObjects({ bucket: "bk0", prefix: pAll, delim: true,
                                             startAfter: kDB, maxKeys: 1000,
                                             status: HTTP_OK, err: "",
                                             keys: [], prefixes: [],
                                             truncated: false }))

    run listMissingBucketTest =
        init
            .then(applyListObjects("bk0", pAll, false, NO_KEY, 1000))
            .expect(lastOp == OListObjects({ bucket: "bk0", prefix: pAll, delim: false,
                                             startAfter: NO_KEY, maxKeys: 1000,
                                             status: HTTP_NOT_FOUND, err: "NoSuchBucket",
                                             keys: [], prefixes: [],
                                             truncated: false }))

    // Long random walks preserve the structural invariants under every
    // step flavor the trace batches use.
    run randomWalkTest =
        init.then(150.reps(_ => all { inv, step }))

    run randomDataWalkTest =
        init.then(150.reps(_ => all { inv, stepData }))

    run randomListWalkTest =
        init.then(150.reps(_ => all { inv, stepList }))

    run randomBucketWalkTest =
        init.then(150.reps(_ => all { inv, stepBucket }))
}
