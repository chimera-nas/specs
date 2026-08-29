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
    pure val kC: Key = ["c"]
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
            .then(applyPutObject("bk0", kA, [1], 0))
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
            .then(applyPutObject("bk0", kDA, [1, 2], 0))
            .expect(lastOp == OPutObject({ bucket: "bk0", key: kDA, data: [1, 2], mtag: 0,
                                           status: HTTP_OK, err: "" }))
            .expect(bkts.get("bk0").objs.get(kDA).data == [1, 2])
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
            .then(applyPutObject("bk1", kA, [1], 0))
            .expect(lastOp == OPutObject({ bucket: "bk1", key: kA, data: [1], mtag: 0,
                                           status: HTTP_NOT_FOUND,
                                           err: "NoSuchBucket" }))
            .then(applyHeadObject("bk1", kA))
            .expect(lastOp == OHeadObject({ bucket: "bk1", key: kA,
                                            status: HTTP_NOT_FOUND, sizeBlocks: -1 }))

    run overwriteTest =
        init
            .then(applyCreateBucket("bk0"))
            .then(applyPutObject("bk0", kA, [1], 0))
            .then(applyPutObject("bk0", kA, [2, 3], 0))
            .expect(bkts.get("bk0").objs.get(kA).data == [2, 3])
            .then(applyGetObject("bk0", kA, RNone))
            .expect(lastOp == OGetObject({ bucket: "bk0", key: kA, range: RNone,
                                           status: HTTP_OK, err: "", data: [2, 3],
                                           first: 0, total: 2 }))

    run emptyObjectTest =
        init
            .then(applyCreateBucket("bk0"))
            .then(applyPutObject("bk0", kA, [], 0))
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
            .then(applyPutObject("bk0", kA, [1], 0))
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
            .then(applyPutObject("bk0", kA, [1, 2], 0))
            .then(applyCopyObject("bk0", kA, "bk1", kDA))
            .expect(lastOp == OCopyObject({ srcBucket: "bk0", srcKey: kA,
                                            dstBucket: "bk1", dstKey: kDA,
                                            status: HTTP_OK, err: "" }))
            .expect(bkts.get("bk1").objs.get(kDA).data == [1, 2])
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
            .expect(bkts.get("bk0").objs.get(kA).data == [1, 2])

    run rangeTest =
        init
            .then(applyCreateBucket("bk0"))
            .then(applyPutObject("bk0", kA, [1, 2, 3], 0))
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
            .then(applyPutObject("bk0", kA, [1], 0))
            .then(applyPutObject("bk0", kB, [1], 0))
            .then(applyPutObject("bk0", kDA, [1], 0))
            .then(applyPutObject("bk0", kDEA, [1], 0))
            .then(applyListObjects("bk0", pAll, false, NO_KEY, 1000, 2))
            .expect(lastOp == OListObjects({ bucket: "bk0", prefix: pAll, delim: false,
                                             startAfter: NO_KEY, maxKeys: 1000, mode: 2,
                                             status: HTTP_OK, err: "",
                                             keys: [kA, kB, kDA, kDEA],
                                             prefixes: [], truncated: false }))
            // flat listing under a "d/" prefix
            .then(applyListObjects("bk0", pD, false, NO_KEY, 1000, 2))
            .expect(lastOp == OListObjects({ bucket: "bk0", prefix: pD, delim: false,
                                             startAfter: NO_KEY, maxKeys: 1000, mode: 2,
                                             status: HTTP_OK, err: "",
                                             keys: [kDA, kDEA],
                                             prefixes: [], truncated: false }))

    run listDelimTest =
        init
            .then(applyCreateBucket("bk0"))
            .then(applyPutObject("bk0", kA, [1], 0))
            .then(applyPutObject("bk0", kB, [1], 0))
            .then(applyPutObject("bk0", kDA, [1], 0))
            .then(applyPutObject("bk0", kDEA, [1], 0))
            .then(applyListObjects("bk0", pAll, true, NO_KEY, 1000, 2))
            .expect(lastOp == OListObjects({ bucket: "bk0", prefix: pAll, delim: true,
                                             startAfter: NO_KEY, maxKeys: 1000, mode: 2,
                                             status: HTTP_OK, err: "",
                                             keys: [kA, kB], prefixes: [["d"]],
                                             truncated: false }))
            .then(applyListObjects("bk0", pD, true, NO_KEY, 1000, 2))
            .expect(lastOp == OListObjects({ bucket: "bk0", prefix: pD, delim: true,
                                             startAfter: NO_KEY, maxKeys: 1000, mode: 2,
                                             status: HTTP_OK, err: "",
                                             keys: [kDA], prefixes: [["d", "e"]],
                                             truncated: false }))
            .then(applyListObjects("bk0", pDE, true, NO_KEY, 1000, 2))
            .expect(lastOp == OListObjects({ bucket: "bk0", prefix: pDE, delim: true,
                                             startAfter: NO_KEY, maxKeys: 1000, mode: 2,
                                             status: HTTP_OK, err: "",
                                             keys: [kDEA], prefixes: [],
                                             truncated: false }))
            // bare prefix "d": every d/... key rolls up into "d/"
            .then(applyListObjects("bk0", pBareD, true, NO_KEY, 1000, 2))
            .expect(lastOp == OListObjects({ bucket: "bk0", prefix: pBareD, delim: true,
                                             startAfter: NO_KEY, maxKeys: 1000, mode: 2,
                                             status: HTTP_OK, err: "",
                                             keys: [], prefixes: [["d"]],
                                             truncated: false }))
            // bare prefix "a": exactly the object "a"
            .then(applyListObjects("bk0", pBareA, true, NO_KEY, 1000, 2))
            .expect(lastOp == OListObjects({ bucket: "bk0", prefix: pBareA, delim: true,
                                             startAfter: NO_KEY, maxKeys: 1000, mode: 2,
                                             status: HTTP_OK, err: "",
                                             keys: [kA], prefixes: [],
                                             truncated: false }))

    run listPagingTest =
        init
            .then(applyCreateBucket("bk0"))
            .then(applyPutObject("bk0", kA, [1], 0))
            .then(applyPutObject("bk0", kB, [1], 0))
            .then(applyPutObject("bk0", kDA, [1], 0))
            .then(applyPutObject("bk0", kEA, [1], 0))
            // entries under "" + delimiter: a, b, d/, e/
            .then(applyListObjects("bk0", pAll, true, NO_KEY, 2, 2))
            .expect(lastOp == OListObjects({ bucket: "bk0", prefix: pAll, delim: true,
                                             startAfter: NO_KEY, maxKeys: 2, mode: 2,
                                             status: HTTP_OK, err: "",
                                             keys: [kA, kB], prefixes: [],
                                             truncated: true }))
            .then(applyListObjects("bk0", pAll, true, NO_KEY, 3, 2))
            .expect(lastOp == OListObjects({ bucket: "bk0", prefix: pAll, delim: true,
                                             startAfter: NO_KEY, maxKeys: 3, mode: 2,
                                             status: HTTP_OK, err: "",
                                             keys: [kA, kB], prefixes: [["d"]],
                                             truncated: true }))
            .then(applyListObjects("bk0", pAll, true, kB, 2, 2))
            .expect(lastOp == OListObjects({ bucket: "bk0", prefix: pAll, delim: true,
                                             startAfter: kB, maxKeys: 2, mode: 2,
                                             status: HTTP_OK, err: "",
                                             keys: [], prefixes: [["d"], ["e"]],
                                             truncated: false }))
            // max-keys=0: empty page, not truncated
            .then(applyListObjects("bk0", pAll, true, NO_KEY, 0, 2))
            .expect(lastOp == OListObjects({ bucket: "bk0", prefix: pAll, delim: true,
                                             startAfter: NO_KEY, maxKeys: 0, mode: 2,
                                             status: HTTP_OK, err: "",
                                             keys: [], prefixes: [],
                                             truncated: false }))

    // start-after inside a rolled-up group: keys past start-after still
    // surface their common prefix, even though the prefix string itself
    // sorts at or below start-after.
    run listStartAfterInGroupTest =
        init
            .then(applyCreateBucket("bk0"))
            .then(applyPutObject("bk0", kDA, [1], 0))
            .then(applyPutObject("bk0", kDB, [1], 0))
            .then(applyListObjects("bk0", pAll, true, kDA, 1000, 2))
            .expect(lastOp == OListObjects({ bucket: "bk0", prefix: pAll, delim: true,
                                             startAfter: kDA, maxKeys: 1000, mode: 2,
                                             status: HTTP_OK, err: "",
                                             keys: [], prefixes: [["d"]],
                                             truncated: false }))
            // start-after past the whole group
            .then(applyListObjects("bk0", pAll, true, kDB, 1000, 2))
            .expect(lastOp == OListObjects({ bucket: "bk0", prefix: pAll, delim: true,
                                             startAfter: kDB, maxKeys: 1000, mode: 2,
                                             status: HTTP_OK, err: "",
                                             keys: [], prefixes: [],
                                             truncated: false }))

    run listMissingBucketTest =
        init
            .then(applyListObjects("bk0", pAll, false, NO_KEY, 1000, 2))
            .expect(lastOp == OListObjects({ bucket: "bk0", prefix: pAll, delim: false,
                                             startAfter: NO_KEY, maxKeys: 1000, mode: 2,
                                             status: HTTP_NOT_FOUND, err: "NoSuchBucket",
                                             keys: [], prefixes: [],
                                             truncated: false }))

    run putMetadataTest =
        init
            .then(applyCreateBucket("bk0"))
            .then(applyPutObject("bk0", kA, [1], 2))
            .expect(lastOp == OPutObject({ bucket: "bk0", key: kA, data: [1],
                                           mtag: 2, status: HTTP_OK, err: "" }))
            .expect(bkts.get("bk0").objs.get(kA).mtag == 2)
            // overwrite replaces metadata (and clears tags)
            .then(applyPutObjTagging("bk0", kA, Set(1)))
            .then(applyPutObject("bk0", kA, [1], 0))
            .expect(bkts.get("bk0").objs.get(kA).mtag == 0)
            .expect(bkts.get("bk0").objs.get(kA).tags == Set())
            // copy replicates content, metadata and tags
            .then(applyPutObject("bk0", kB, [2], 1))
            .then(applyPutObjTagging("bk0", kB, Set(1, 2)))
            .then(applyCopyObject("bk0", kB, "bk0", kDA))
            .expect(bkts.get("bk0").objs.get(kDA).mtag == 1)
            .expect(bkts.get("bk0").objs.get(kDA).tags == Set(1, 2))

    run tagObjectTest =
        init
            .then(applyCreateBucket("bk0"))
            .then(applyPutObject("bk0", kA, [1], 0))
            // no tags stored: object-level GET is an empty 200 tag set
            .then(applyGetObjTagging("bk0", kA))
            .expect(lastOp == OGetObjTagging({ bucket: "bk0", key: kA,
                                               status: HTTP_OK, err: "",
                                               tags: Set() }))
            .then(applyPutObjTagging("bk0", kA, Set(1, 2)))
            .expect(lastOp == OPutObjTagging({ bucket: "bk0", key: kA,
                                               tags: Set(1, 2),
                                               status: HTTP_OK, err: "" }))
            .then(applyGetObjTagging("bk0", kA))
            .expect(lastOp == OGetObjTagging({ bucket: "bk0", key: kA,
                                               status: HTTP_OK, err: "",
                                               tags: Set(1, 2) }))
            .then(applyDelObjTagging("bk0", kA))
            .expect(lastOp == ODelObjTagging({ bucket: "bk0", key: kA,
                                               status: HTTP_NO_CONTENT, err: "" }))
            .expect(bkts.get("bk0").objs.get(kA).tags == Set())
            // tagging a missing object
            .then(applyPutObjTagging("bk0", kB, Set(1)))
            .expect(lastOp == OPutObjTagging({ bucket: "bk0", key: kB,
                                               tags: Set(1),
                                               status: HTTP_NOT_FOUND,
                                               err: "NoSuchKey" }))

    run tagBucketTest =
        init
            .then(applyCreateBucket("bk0"))
            // no tags stored: bucket-level GET is 404 NoSuchTagSet
            .then(applyGetBktTagging("bk0"))
            .expect(lastOp == OGetBktTagging({ bucket: "bk0",
                                               status: HTTP_NOT_FOUND,
                                               err: "NoSuchTagSet", tags: Set() }))
            .then(applyPutBktTagging("bk0", Set(2)))
            .then(applyGetBktTagging("bk0"))
            .expect(lastOp == OGetBktTagging({ bucket: "bk0", status: HTTP_OK,
                                               err: "", tags: Set(2) }))
            .then(applyDelBktTagging("bk0"))
            .expect(lastOp == ODelBktTagging({ bucket: "bk0",
                                               status: HTTP_NO_CONTENT, err: "" }))
            .then(applyGetBktTagging("bk1"))
            .expect(lastOp == OGetBktTagging({ bucket: "bk1",
                                               status: HTTP_NOT_FOUND,
                                               err: "NoSuchBucket", tags: Set() }))

    run deleteObjectsTest =
        init
            .then(applyCreateBucket("bk0"))
            .then(applyPutObject("bk0", kA, [1], 0))
            .then(applyPutObject("bk0", kDA, [1], 0))
            // present, missing and duplicate keys all report Deleted
            .then(applyDeleteObjects("bk0", [kA, kA], false))
            .expect(lastOp == ODeleteObjects({ bucket: "bk0", keys: [kA, kA],
                                               quiet: false, status: HTTP_OK,
                                               err: "" }))
            .expect(not(bkts.get("bk0").objs.keys().contains(kA)))
            .then(applyDeleteObjects("bk0", [kB, kDA], true))
            .expect(lastOp == ODeleteObjects({ bucket: "bk0", keys: [kB, kDA],
                                               quiet: true, status: HTTP_OK,
                                               err: "" }))
            .expect(bkts.get("bk0").objs.keys().size() == 0)
            .then(applyDeleteObjects("bk1", [kA], false))
            .expect(lastOp == ODeleteObjects({ bucket: "bk1", keys: [kA],
                                               quiet: false,
                                               status: HTTP_NOT_FOUND,
                                               err: "NoSuchBucket" }))

    run getAttrsTest =
        init
            .then(applyCreateBucket("bk0"))
            .then(applyPutObject("bk0", kA, [1, 2], 0))
            .then(applyGetAttrs("bk0", kA))
            .expect(lastOp == OGetAttrs({ bucket: "bk0", key: kA,
                                          status: HTTP_OK, err: "",
                                          sizeBlocks: 2 }))
            .then(applyGetAttrs("bk0", kB))
            .expect(lastOp == OGetAttrs({ bucket: "bk0", key: kB,
                                          status: HTTP_NOT_FOUND,
                                          err: "NoSuchKey", sizeBlocks: -1 }))

    // V1 marker / Versions key-marker use the same walk as V2 start-after.
    run listModesTest =
        init
            .then(applyCreateBucket("bk0"))
            .then(applyPutObject("bk0", kA, [1], 0))
            .then(applyPutObject("bk0", kDA, [1], 0))
            .then(applyListObjects("bk0", pAll, true, NO_KEY, 1000, 1))
            .expect(lastOp == OListObjects({ bucket: "bk0", prefix: pAll,
                                             delim: true, startAfter: NO_KEY,
                                             maxKeys: 1000, mode: 1,
                                             status: HTTP_OK, err: "",
                                             keys: [kA], prefixes: [["d"]],
                                             truncated: false }))
            .then(applyListObjects("bk0", pAll, false, kA, 1000, 3))
            .expect(lastOp == OListObjects({ bucket: "bk0", prefix: pAll,
                                             delim: false, startAfter: kA,
                                             maxKeys: 1000, mode: 3,
                                             status: HTTP_OK, err: "",
                                             keys: [kDA], prefixes: [],
                                             truncated: false }))

    run mpuLifecycleTest =
        init
            .then(applyCreateBucket("bk0"))
            .then(applyCreateMpu("bk0", kDA))
            .expect(lastOp == OCreateMpu({ bucket: "bk0", key: kDA, uplid: 1,
                                           status: HTTP_OK, err: "" }))
            .then(applyUploadPart("bk0", kDA, 1, 1, [1]))
            .expect(lastOp == OUploadPart({ bucket: "bk0", key: kDA, uplid: 1,
                                            partNum: 1, data: [1],
                                            status: HTTP_OK, err: "" }))
            .then(applyUploadPart("bk0", kDA, 1, 2, [2, 3]))
            // re-upload replaces
            .then(applyUploadPart("bk0", kDA, 1, 1, [3]))
            .expect(bkts.get("bk0").mpu.get(1).parts.get(1) == [3])
            .then(applyListParts("bk0", kDA, 1))
            .expect(lastOp == OListParts({ bucket: "bk0", key: kDA, uplid: 1,
                                           status: HTTP_OK, err: "",
                                           partNums: [1, 2] }))
            .then(applyListMpu("bk0"))
            .expect(lastOp == OListMpu({ bucket: "bk0", status: HTTP_OK, err: "",
                                         uploads: Set({ key: kDA, uplid: 1 }) }))
            .then(applyCompleteMpu("bk0", kDA, 1, [1, 2]))
            .expect(lastOp == OCompleteMpu({ bucket: "bk0", key: kDA, uplid: 1,
                                             manifest: [1, 2],
                                             status: HTTP_OK, err: "" }))
            .expect(bkts.get("bk0").objs.get(kDA).data == [3, 2, 3])
            .expect(bkts.get("bk0").mpu.keys().size() == 0)
            // the upload is consumed
            .then(applyCompleteMpu("bk0", kDA, 1, [1]))
            .expect(lastOp == OCompleteMpu({ bucket: "bk0", key: kDA, uplid: 1,
                                             manifest: [1],
                                             status: HTTP_NOT_FOUND,
                                             err: "NoSuchUpload" }))

    run mpuErrorsTest =
        init
            .then(applyCreateBucket("bk0"))
            .then(applyCreateMpu("bk0", kA))
            .then(applyUploadPart("bk0", kA, 1, 1, [1]))
            .then(applyUploadPart("bk0", kA, 1, 2, []))
            .then(applyUploadPart("bk0", kA, 1, 3, [2]))
            // partNumber outside 1..10000
            .then(applyUploadPart("bk0", kA, 1, 0, [1]))
            .expect(lastOp == OUploadPart({ bucket: "bk0", key: kA, uplid: 1,
                                            partNum: 0, data: [1],
                                            status: HTTP_BAD_REQUEST,
                                            err: "InvalidArgument" }))
            // empty manifest
            .then(applyCompleteMpu("bk0", kA, 1, []))
            .expect(lastOp == OCompleteMpu({ bucket: "bk0", key: kA, uplid: 1,
                                             manifest: [],
                                             status: HTTP_BAD_REQUEST,
                                             err: "MalformedXML" }))
            // non-ascending: index 1 fires order (index 0's part 3 is
            // non-empty, so its size check passes first)
            .then(applyCompleteMpu("bk0", kA, 1, [3, 1]))
            .expect(lastOp == OCompleteMpu({ bucket: "bk0", key: kA, uplid: 1,
                                             manifest: [3, 1],
                                             status: HTTP_BAD_REQUEST,
                                             err: "InvalidPartOrder" }))
            // unknown part
            .then(applyCompleteMpu("bk0", kA, 1, [1, 9]))
            .expect(lastOp == OCompleteMpu({ bucket: "bk0", key: kA, uplid: 1,
                                             manifest: [1, 9],
                                             status: HTTP_BAD_REQUEST,
                                             err: "InvalidPart" }))
            // empty NON-final part: index 1 (part 2, empty) fires the size
            // check before index 2 is examined
            .then(applyCompleteMpu("bk0", kA, 1, [1, 2, 3]))
            .expect(lastOp == OCompleteMpu({ bucket: "bk0", key: kA, uplid: 1,
                                             manifest: [1, 2, 3],
                                             status: HTTP_BAD_REQUEST,
                                             err: "EntityTooSmall" }))
            // empty FINAL part is fine; ascending subset is fine
            .then(applyCompleteMpu("bk0", kA, 1, [1, 2]))
            .expect(lastOp == OCompleteMpu({ bucket: "bk0", key: kA, uplid: 1,
                                             manifest: [1, 2],
                                             status: HTTP_OK, err: "" }))
            .expect(bkts.get("bk0").objs.get(kA).data == [1])
            // abort of an unknown id
            .then(applyAbortMpu("bk0", kA, 7))
            .expect(lastOp == OAbortMpu({ bucket: "bk0", key: kA, uplid: 7,
                                          status: HTTP_NOT_FOUND,
                                          err: "NoSuchUpload" }))

    run mpuPartCopyTest =
        init
            .then(applyCreateBucket("bk0"))
            .then(applyPutObject("bk0", kA, [1, 2, 3], 0))
            .then(applyCreateMpu("bk0", kB))
            .then(applyUploadPartCopy("bk0", kB, 1, 1, "bk0", kA, RNone))
            .expect(lastOp == OUploadPartCopy({ bucket: "bk0", key: kB, uplid: 1,
                                                partNum: 1, srcBucket: "bk0",
                                                srcKey: kA, range: RNone,
                                                data: [1, 2, 3],
                                                status: HTTP_OK, err: "" }))
            .then(applyUploadPartCopy("bk0", kB, 1, 2, "bk0", kA,
                                      RClosed({ first: 1, last: 2 })))
            .expect(bkts.get("bk0").mpu.get(1).parts.get(2) == [2, 3])
            .then(applyUploadPartCopy("bk0", kB, 1, 3, "bk0", kC, RNone))
            .expect(lastOp == OUploadPartCopy({ bucket: "bk0", key: kB, uplid: 1,
                                                partNum: 3, srcBucket: "bk0",
                                                srcKey: kC, range: RNone,
                                                data: [],
                                                status: HTTP_NOT_FOUND,
                                                err: "NoSuchKey" }))
            .then(applyCompleteMpu("bk0", kB, 1, [1, 2]))
            .expect(bkts.get("bk0").objs.get(kB).data == [1, 2, 3, 2, 3])

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

    run randomTagWalkTest =
        init.then(150.reps(_ => all { inv, stepTag }))

    run randomMultipartWalkTest =
        init.then(150.reps(_ => all { inv, stepMultipart }))
}
