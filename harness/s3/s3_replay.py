#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 The Quint Specs Authors
#
# SPDX-License-Identifier: MIT

"""Replay Quint-generated S3 traces (ITF JSON) against a live S3 server over
HTTP, comparing every response against the model's expectation.

Model-to-wire mapping:
  - model bucket names are wire bucket names (path-style addressing);
  - a model key (a list of path components) joins with '/' into the wire key;
  - content block symbol s at index i is block-size bytes of 0x40+s at offset
    i * block-size; range requests scale block units by the block size;
  - the model's `status` is the HTTP status line, its `err` the <Code> of the
    XML error body;
  - mtag 1/2 select a fixed (Content-Type, x-amz-meta-m) pair, mtag 0 sends
    neither; tag id i is the ("tk<i>", "tv<i>") pair;
  - a multipart upload's abstract id maps to the wire UploadId learned from
    the Initiate response; an id the model never minted goes out as an
    UploadId no server ever issued;
  - ETag values are not predicted.  The harness learns an object's ETag at its
    last write and requires every later read (Get, Head, List, GetAttrs) to
    report the same value until the object is rewritten or deleted.

Divergence policy: there is none.  Expected and actual must be equal.  A known
divergence of the server under test belongs in the MODEL (quint/s3/s3.qnt,
gated on the DEVS set the cell's config binds, declared with its citation in
quint/s3/corpus.schema.json), so a trace generated for that cell already
predicts the answer the server gives.  Anything unexpected here fails the
trace with a report of the step, the mismatches and the recent history.

Exit status: 0 every trace matched, 1 a divergence, 2 a malformed trace.
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from s3_wire import S3Client  # noqa: E402

HIST = 10

# An UploadId no Initiate ever minted, for the model's unknown-upload requests.
UNKNOWN_UPLOAD_ID = "ffffffffffffffffffffffffffffffff"

# mtag -> (Content-Type, x-amz-meta-m); mtag 0 sends neither.
MTAG = {1: ("text/plain", "v1"), 2: ("application/json", "v2")}
# What S3 reports for an object stored with no Content-Type.
DEFAULT_CONTENT_TYPE = "binary/octet-stream"


class TraceFormatError(Exception):
    pass


# ---- ITF decoding ---------------------------------------------------------

def _hashable(v):
    return tuple(_hashable(x) for x in v) if isinstance(v, list) else v


def itf_decode(v):
    """Quint's ITF encodings as plain Python data.  A map keyed by a list (the
    object store is keyed by Key = List[str]) becomes a dict keyed by a tuple;
    anything unrecognised fails loudly, so a quint format change is a visible
    error rather than a silently skipped check."""
    if isinstance(v, dict):
        special = [k for k in v if k.startswith("#")]
        if special == ["#bigint"]:
            return int(v["#bigint"])
        if special == ["#map"]:
            return {_hashable(itf_decode(k)): itf_decode(val)
                    for k, val in v["#map"]}
        if special == ["#set"]:
            return [itf_decode(x) for x in v["#set"]]
        if special == ["#tup"]:
            return tuple(itf_decode(x) for x in v["#tup"])
        if special:
            raise TraceFormatError(f"unrecognized ITF encoding {special}")
        return {k: itf_decode(val) for k, val in v.items()}
    if isinstance(v, list):
        return [itf_decode(x) for x in v]
    if isinstance(v, (str, bool, int)):
        return v
    raise TraceFormatError(f"unrecognized ITF value {v!r}")


def load_states(path):
    """Every state of the trace as {var: value}.  A trace generated from a
    config cell names its variables "<cell>::<model>::<var>"; the qualifiers
    are stripped."""
    with open(path) as f:
        raw = json.load(f)
    if "states" not in raw or "vars" not in raw:
        raise TraceFormatError(f"{path}: not an ITF trace")
    states = []
    for i, st in enumerate(raw["states"]):
        d = {k.split("::")[-1]: itf_decode(v) for k, v in st.items()
             if k != "#meta" and not k.startswith("mbt::")}
        for need in ("lastOp", "bkts"):
            if need not in d:
                raise TraceFormatError(f"{path}: state {i} lacks {need}")
        states.append(d)
    return states


# ---- model-to-wire helpers ------------------------------------------------

def key_str(key):
    return "/".join(key)


def prefix_str(pfx):
    s = "".join(c + "/" for c in pfx["comps"])
    return s if pfx["slash"] else s[:-1]


def quoted(etag):
    """An ETag in its quoted wire form.  Headers and most XML bodies carry the
    quotes; GetObjectAttributes does not."""
    return etag if etag.startswith('"') else f'"{etag}"'


def tagging_body(ids):
    return ("<Tagging><TagSet>" +
            "".join(f"<Tag><Key>tk{i}</Key><Value>tv{i}</Value></Tag>"
                    for i in sorted(ids)) +
            "</TagSet></Tagging>").encode()


# ---- oracle ---------------------------------------------------------------

class Oracle:
    """One trace's replay state: what the harness has learned from the server
    that the model does not predict (ETags, wire upload ids), plus the
    mismatches of the step in hand."""

    def __init__(self, client, block_size):
        self.c = client
        self.bs = block_size
        self.etags = {}      # (bucket, key) -> ETag at the last write
        self.upls = {}       # model uplid -> wire UploadId
        self.petags = {}     # (uplid, partNum) -> part ETag
        self.m = []          # mismatches of the current step
        self.hits = ()       # deviations the model took at the current step
        self.status = 0      # status of the current step's reply

    # -- plumbing --

    def call(self, *args, **kw):
        res = self.c.call(*args, **kw)
        self.status = res.status
        return res

    def mism(self, msg):
        self.m.append(msg)

    def check_status(self, op, res):
        if op["status"] == res.status:
            return True
        code = res.error_code()
        self.mism(f"status: expected {op['status']}, got {res.status}" +
                  (f" ({code})" if code else ""))
        return False

    def check_error_code(self, op, res):
        """Only called once the status matched: on a status mismatch the body
        is some other response's body entirely."""
        got = res.error_code()
        if op["err"] != got:
            self.mism(f"error <Code>: expected '{op['err']}', got '{got}'")

    def xml(self, res, root_tag, what):
        root = res.xml()
        if root is None or root.tag != root_tag:
            self.mism(f"{what}: response is not a <{root_tag}> document"
                      + ("" if root is None else f" (got <{root.tag}>)"))
            return None
        return root

    def hit(self, dev):
        """Did the model take deviation `dev` at this step?  Most deviations
        change a field of the label and need no help here.  A few change only
        something the harness derives -- a header, the shape of a body -- and
        for those the model records the hit and this asks for it, so the
        expectation still comes from the trace and never from the harness
        knowing which server it is talking to."""
        return dev in self.hits

    def blocks(self, data):
        return b"".join(bytes([0x40 + s]) * self.bs for s in data)

    def range_header(self, rng):
        tag, val = rng["tag"], rng["value"]
        if tag == "RClosed":
            return (f"bytes={val['first'] * self.bs}-"
                    f"{(val['last'] + 1) * self.bs - 1}")
        if tag == "RFrom":
            return f"bytes={val * self.bs}-"
        if tag == "RSuffix":
            return f"bytes=-{val * self.bs}"
        return None

    def wire_upload(self, uplid):
        return self.upls.get(uplid, UNKNOWN_UPLOAD_ID)

    # -- ETag consistency --

    def etag_check(self, bucket, key, etag, what):
        """An ETag reported for (bucket, key) must be a quoted string and match
        the one learned at the object's last write."""
        if len(etag) < 2 or etag[0] != '"' or etag[-1] != '"':
            self.mism(f"{what}: ETag '{etag}' for {bucket}/{key} is not a "
                      "quoted string")
            return
        have = self.etags.setdefault((bucket, key), etag)
        if have != etag:
            self.mism(f"{what}: ETag for {bucket}/{key} changed without a "
                      f"write: learned {have}, got {etag}")

    def etag_forget(self, bucket, key):
        self.etags.pop((bucket, key), None)

    # -- body and metadata --

    def expect_body(self, res, data, what):
        want = self.blocks(data)
        if len(res.body) != len(want):
            self.mism(f"{what}: body length {len(res.body)}, expected "
                      f"{len(want)}")
        elif res.body != want:
            i = next(i for i in range(len(want)) if res.body[i] != want[i])
            self.mism(f"{what}: body differs at offset {i} (got "
                      f"{res.body[i]:#04x}, expected {want[i]:#04x})")
        return len(want)

    def check_meta_echo(self, res, post, bucket, key, what):
        """GET/HEAD echo the stored Content-Type (or the fallback) and the
        x-amz-meta-m value, both from the post-state object's mtag."""
        obj = post.get(bucket, {}).get("objs", {}).get(tuple(key.split("/")))
        if obj is None:
            self.mism(f"{what}: {bucket}/{key} missing from model post-state")
            return
        want_ct, want_meta = MTAG.get(obj["mtag"], (DEFAULT_CONTENT_TYPE, ""))
        if res.header("content-type") != want_ct:
            self.mism(f"{what}: Content-Type '{res.header('content-type')}', "
                      f"expected '{want_ct}'")
        if res.header("x-amz-meta-m") != want_meta:
            self.mism(f"{what}: x-amz-meta-m '{res.header('x-amz-meta-m')}', "
                      f"expected '{want_meta}'")

    # ---- buckets ----

    def OCreateBucket(self, op, post):
        path = f"/{op['bucket']}"
        res = self.call("PUT", path)
        if not self.check_status(op, res):
            return
        if op["status"] == 409:
            # the label carries no err: the model predicts one 409 only
            if res.error_code() != "BucketAlreadyOwnedByYou":
                self.mism("error <Code>: expected 'BucketAlreadyOwnedByYou', "
                          f"got '{res.error_code()}'")
        elif res.header("location") != path:
            self.mism(f"CreateBucket Location: expected '{path}', got "
                      f"'{res.header('location')}'")

    def OHeadBucket(self, op, post):
        res = self.call("HEAD", f"/{op['bucket']}")
        self.check_status(op, res)
        if res.body:
            self.mism(f"HeadBucket returned a body ({len(res.body)} bytes)")

    def ODeleteBucket(self, op, post):
        res = self.call("DELETE", f"/{op['bucket']}")
        if self.check_status(op, res) and op["status"] != 204:
            self.check_error_code(op, res)

    def OListBuckets(self, op, post):
        res = self.call("GET", "/")
        if not self.check_status(op, res):
            return
        root = self.xml(res, "ListAllMyBucketsResult", "ListBuckets")
        if root is None:
            return
        # Compared as a set: AWS documents no ordering contract here.
        got = sorted(b.findtext("Name", "") for b in root.iter("Bucket"))
        if got != sorted(op["buckets"]):
            self.mism(f"ListBuckets: got {got}, expected "
                      f"{sorted(op['buckets'])}")

    # ---- objects ----

    def OPutObject(self, op, post):
        bucket, key = op["bucket"], key_str(op["key"])
        headers = {}
        if op["mtag"] in MTAG:
            headers["content-type"], headers["x-amz-meta-m"] = MTAG[op["mtag"]]
        res = self.call("PUT", f"/{bucket}/{key}", headers=headers,
                        body=self.blocks(op["data"]))
        ok = self.check_status(op, res)
        if ok and op["status"] == 200:
            # a successful write re-keys the ETag
            self.etag_forget(bucket, key)
            self.etag_check(bucket, key, res.header("etag"), "PutObject")
        if ok and op["status"] == 404:
            self.check_error_code(op, res)

    def OGetObject(self, op, post):
        bucket, key = op["bucket"], key_str(op["key"])
        headers = {}
        rng = self.range_header(op["range"])
        if rng:
            headers["range"] = rng
        res = self.call("GET", f"/{bucket}/{key}", headers=headers)
        if not self.check_status(op, res):
            return
        expected = op["status"]
        if expected in (200, 206):
            n = self.expect_body(res, op["data"], "GetObject")
            if res.header("content-length") != str(n):
                self.mism("GetObject Content-Length "
                          f"'{res.header('content-length')}', body {n}")
            self.etag_check(bucket, key, res.header("etag"), "GetObject")
            self.check_meta_echo(res, post, bucket, key, "GetObject")
            if expected == 206:
                first = op["first"] * self.bs
                want = f"bytes {first}-{first + n - 1}/{op['total'] * self.bs}"
                if res.header("content-range") != want:
                    self.mism(f"GetObject Content-Range: expected '{want}', "
                              f"got '{res.header('content-range')}'")
        elif expected == 416:
            want = ("" if self.hit("M-416-no-content-range")
                    else f"bytes */{op['total'] * self.bs}")
            if res.header("content-range") != want:
                self.mism(f"416 Content-Range: expected '{want}', got "
                          f"'{res.header('content-range')}'")
            self.check_error_code(op, res)
        elif expected == 404:
            self.check_error_code(op, res)

    def OHeadObject(self, op, post):
        bucket, key = op["bucket"], key_str(op["key"])
        res = self.call("HEAD", f"/{bucket}/{key}")
        if not self.check_status(op, res):
            return
        if res.body:
            self.mism(f"HeadObject returned a body ({len(res.body)} bytes)")
        if op["status"] != 200:
            return
        want = str(op["sizeBlocks"] * self.bs)
        if res.header("content-length") != want:
            self.mism(f"HeadObject Content-Length: expected {want}, got "
                      f"'{res.header('content-length')}'")
        self.etag_check(bucket, key, res.header("etag"), "HeadObject")
        self.check_meta_echo(res, post, bucket, key, "HeadObject")
        # x-amz-tagging-count reports the object's tag count; with no tags AWS
        # omits the header, so the zero case accepts absent or "0".
        obj = post.get(bucket, {}).get("objs", {}).get(tuple(op["key"]))
        if obj is not None:
            ntags = len(obj["tags"])
            got = res.header("x-amz-tagging-count")
            if (got or "0") != str(ntags):
                self.mism(f"HeadObject x-amz-tagging-count '{got}', expected "
                          f"{ntags}")

    def ODeleteObject(self, op, post):
        bucket, key = op["bucket"], key_str(op["key"])
        res = self.call("DELETE", f"/{bucket}/{key}")
        ok = self.check_status(op, res)
        # The object is gone (or never was) whenever the bucket existed.
        if op["err"] != "NoSuchBucket":
            self.etag_forget(bucket, key)
        if ok and op["status"] == 404:
            self.check_error_code(op, res)

    def ODeleteObjects(self, op, post):
        bucket = op["bucket"]
        keys = [key_str(k) for k in op["keys"]]
        body = ("<Delete>" +
                ("<Quiet>true</Quiet>" if op["quiet"] else "") +
                "".join(f"<Object><Key>{k}</Key></Object>" for k in keys) +
                "</Delete>").encode()
        res = self.call("POST", f"/{bucket}", query=[("delete", "")],
                        body=body, xml_body=True)
        if not self.check_status(op, res):
            return
        if op["status"] != 200:
            self.check_error_code(op, res)
            return
        for k in keys:
            self.etag_forget(bucket, k)
        root = self.xml(res, "DeleteResult", "DeleteObjects")
        if root is None:
            return
        # non-quiet: one <Deleted><Key> per named key, in request order;
        # quiet: none.  Never an <Error>: every key is deletable.
        got = [d.findtext("Key", "") for d in root.findall("Deleted")]
        want = [] if op["quiet"] else keys
        if self.hit("M-delete-objects-dup-empty"):
            # a repeated key comes back as an empty <Deleted/>
            want = [k if k not in keys[:i] else "" for i, k in enumerate(keys)]
        if got != want:
            self.mism(f"DeleteObjects: <Deleted> keys {got}, expected {want}")
        if root.find("Error") is not None:
            self.mism("DeleteObjects: unexpected <Error> entry")

    def OCopyObject(self, op, post):
        sb, sk = op["srcBucket"], key_str(op["srcKey"])
        db, dk = op["dstBucket"], key_str(op["dstKey"])
        res = self.call("PUT", f"/{db}/{dk}",
                        headers={"x-amz-copy-source": f"/{sb}/{sk}"})
        ok = self.check_status(op, res)
        if ok and op["status"] == 200:
            # the destination was (re)written: its ETag is whatever
            # <CopyObjectResult><ETag> reports
            self.etag_forget(db, dk)
            root = self.xml(res, "CopyObjectResult", "CopyObject")
            if root is None:
                return
            etag = root.findtext("ETag")
            if etag is None:
                self.mism("CopyObject: response lacks <ETag>")
            else:
                self.etag_check(db, dk, etag, "CopyObject")
        if ok and op["status"] in (400, 404):
            self.check_error_code(op, res)

    def OGetAttrs(self, op, post):
        bucket, key = op["bucket"], key_str(op["key"])
        # x-amz-object-attributes is required by the API; ask for the fixed
        # set a filesystem-backed gateway can supply, which is what is checked.
        res = self.call(
            "GET", f"/{bucket}/{key}", query=[("attributes", "")],
            headers={"x-amz-object-attributes": "ETag,StorageClass,ObjectSize"})
        if not self.check_status(op, res):
            return
        if op["status"] != 200:
            self.check_error_code(op, res)
            return
        # The root element's NAME is not checked.  The API Reference calls it
        # GetObjectAttributesResponse, the service model calls the same shape
        # GetObjectAttributesOutput, servers are found using either (and
        # MinIO a third, getObjectAttributesResponse), and no REST-XML client
        # reads it.  That it is not an <Error> is what matters.
        root = res.xml()
        if root is None or root.tag == "Error":
            self.mism("GetAttrs: response is not an attributes document")
            return
        want = (None if self.hit("M-getattrs-zero-size-omitted")
                else str(op["sizeBlocks"] * self.bs))
        if root.findtext("ObjectSize") != want:
            self.mism(f"GetAttrs: ObjectSize {root.findtext('ObjectSize')}, "
                      f"expected {want}")
        if root.findtext("StorageClass") != "STANDARD":
            self.mism("GetAttrs: StorageClass "
                      f"{root.findtext('StorageClass')!r}, expected STANDARD")
        etag = root.findtext("ETag")
        if etag is None:
            self.mism("GetAttrs: response lacks <ETag>")
        else:
            # the same value GET/HEAD report, here without the quotes
            self.etag_check(bucket, key, quoted(etag), "GetAttrs")

    # ---- listing ----

    def OListObjects(self, op, post):
        bucket, mode = op["bucket"], op["mode"]
        pfx = prefix_str(op["prefix"])
        sa = key_str(op["startAfter"])
        # The three modes dress the same walk differently: V1 uses marker, V2
        # list-type=2 + start-after, Versions the versions subresource +
        # key-marker.
        query = [("max-keys", str(op["maxKeys"]))]
        if op["delim"]:
            query.append(("delimiter", "/"))
        if pfx:
            query.append(("prefix", pfx))
        if mode == 2:
            query.append(("list-type", "2"))
        if mode == 3:
            query.append(("versions", ""))
        if sa:
            query.append(({1: "marker", 2: "start-after",
                           3: "key-marker"}[mode], sa))
        res = self.call("GET", f"/{bucket}", query=query)
        if not self.check_status(op, res):
            return
        if op["status"] != 200:
            self.check_error_code(op, res)
            return
        root = self.xml(res, {1: "ListBucketResult", 2: "ListBucketResult",
                              3: "ListVersionsResult"}[mode], "ListObjects")
        if root is None:
            return

        objs = post.get(bucket, {}).get("objs", {})
        got_keys = []
        for ent in root.findall("Version" if mode == 3 else "Contents"):
            k = ent.findtext("Key", "")
            got_keys.append(k)
            # every listed object's Size and ETag must agree with the model
            # post-state / the ETag learned at its last write
            obj = objs.get(tuple(k.split("/")))
            size = ent.findtext("Size")
            if obj is not None and size is not None and \
                    size != str(len(obj["data"]) * self.bs):
                self.mism(f"ListObjects: {k} Size {size}, model "
                          f"{len(obj['data'])} blocks")
            etag = ent.findtext("ETag")
            if etag is not None:
                self.etag_check(bucket, k, etag, "ListObjects")
        want_keys = [key_str(k) for k in op["keys"]]
        if got_keys != want_keys:
            self.mism(f"ListObjects: keys {got_keys}, expected {want_keys}")

        got_pfx = [p.findtext("Prefix", "")
                   for p in root.findall("CommonPrefixes")]
        # a common prefix always renders with a trailing slash
        want_pfx = [key_str(p) + "/" for p in op["prefixes"]]
        if got_pfx != want_pfx:
            self.mism(f"ListObjects: common prefixes {got_pfx}, expected "
                      f"{want_pfx}")

        want_trunc = "true" if op["truncated"] else "false"
        if root.findtext("IsTruncated") != want_trunc:
            self.mism(f"ListObjects: IsTruncated "
                      f"{root.findtext('IsTruncated')!r}, expected "
                      f"'{want_trunc}'")
        if mode == 2:   # KeyCount is a V2-only element; it counts both lists
            want = str(len(want_keys) + len(want_pfx))
            if root.findtext("KeyCount") != want:
                self.mism(f"ListObjects: KeyCount "
                          f"{root.findtext('KeyCount')!r}, expected {want}")

    # ---- tagging ----

    def _tagging(self, op, what, method, has_key, send_tags):
        path = f"/{op['bucket']}" + (f"/{key_str(op['key'])}" if has_key
                                     else "")
        if send_tags:
            res = self.call(method, path, query=[("tagging", "")],
                            body=tagging_body(op["tags"]), xml_body=True)
        else:
            res = self.call(method, path, query=[("tagging", "")])
        if not self.check_status(op, res):
            return
        if op["status"] not in (200, 204):
            self.check_error_code(op, res)
            return
        if method != "GET":
            return
        root = self.xml(res, "Tagging", what)
        if root is None:
            return
        got = sorted((t.findtext("Key", ""), t.findtext("Value", ""))
                     for t in root.iter("Tag"))
        want = sorted((f"tk{i}", f"tv{i}") for i in op["tags"])
        if got != want:
            self.mism(f"{what}: tags {got}, expected {want}")

    def OPutObjTagging(self, op, post):
        self._tagging(op, "PutObjectTagging", "PUT", True, True)

    def OGetObjTagging(self, op, post):
        self._tagging(op, "GetObjectTagging", "GET", True, False)

    def ODelObjTagging(self, op, post):
        self._tagging(op, "DeleteObjectTagging", "DELETE", True, False)

    def OPutBktTagging(self, op, post):
        self._tagging(op, "PutBucketTagging", "PUT", False, True)

    def OGetBktTagging(self, op, post):
        self._tagging(op, "GetBucketTagging", "GET", False, False)

    def ODelBktTagging(self, op, post):
        self._tagging(op, "DeleteBucketTagging", "DELETE", False, False)

    # ---- multipart ----

    def OCreateMpu(self, op, post):
        bucket, key = op["bucket"], key_str(op["key"])
        res = self.call("POST", f"/{bucket}/{key}", query=[("uploads", "")])
        if not self.check_status(op, res):
            return
        if op["status"] != 200:
            self.check_error_code(op, res)
            return
        root = self.xml(res, "InitiateMultipartUploadResult", "CreateMpu")
        if root is None:
            return
        wire = root.findtext("UploadId", "")
        if not wire:
            self.mism("CreateMpu: missing <UploadId>")
            return
        self.upls[op["uplid"]] = wire
        if root.findtext("Key") != key:
            self.mism(f"CreateMpu: <Key> {root.findtext('Key')!r}, expected "
                      f"'{key}'")

    def _part_query(self, op):
        return [("partNumber", str(op["partNum"])),
                ("uploadId", self.wire_upload(op["uplid"]))]

    def OUploadPart(self, op, post):
        res = self.call("PUT", f"/{op['bucket']}/{key_str(op['key'])}",
                        query=self._part_query(op),
                        body=self.blocks(op["data"]))
        if not self.check_status(op, res):
            return
        if op["status"] != 200:
            self.check_error_code(op, res)
            return
        etag = res.header("etag")
        if not etag.startswith('"'):
            self.mism(f"UploadPart: ETag missing/unquoted ('{etag}')")
            return
        self.petags[(op["uplid"], op["partNum"])] = etag

    def OUploadPartCopy(self, op, post):
        headers = {"x-amz-copy-source":
                   f"/{op['srcBucket']}/{key_str(op['srcKey'])}"}
        if op["range"]["tag"] == "RClosed":
            headers["x-amz-copy-source-range"] = self.range_header(op["range"])
        res = self.call("PUT", f"/{op['bucket']}/{key_str(op['key'])}",
                        query=self._part_query(op), headers=headers)
        if not self.check_status(op, res):
            return
        if op["status"] != 200:
            self.check_error_code(op, res)
            return
        # the part's ETag arrives in the <CopyPartResult> body, not a header
        root = self.xml(res, "CopyPartResult", "UploadPartCopy")
        if root is None:
            return
        etag = root.findtext("ETag")
        if etag is None:
            self.mism("UploadPartCopy: response lacks <ETag>")
            return
        self.petags[(op["uplid"], op["partNum"])] = quoted(etag)

    def OCompleteMpu(self, op, post):
        bucket, key, uplid = op["bucket"], key_str(op["key"]), op["uplid"]
        # a never-uploaded part still needs a syntactically valid ETag
        body = ("<CompleteMultipartUpload>" + "".join(
            f"<Part><PartNumber>{pn}</PartNumber><ETag>" +
            self.petags.get((uplid, pn), '"' + "0" * 32 + '"') +
            "</ETag></Part>" for pn in op["manifest"]) +
            "</CompleteMultipartUpload>").encode()
        res = self.call("POST", f"/{bucket}/{key}",
                        query=[("uploadId", self.wire_upload(uplid))],
                        body=body, xml_body=True)
        if not self.check_status(op, res):
            return
        if op["status"] != 200:
            self.check_error_code(op, res)
            return
        # The upload is consumed and the key holds the assembled object.  A
        # 200 here can still carry an <Error> body (the API keeps the
        # connection alive with whitespace and reports late), so the document
        # type is part of the check.
        self.upls.pop(uplid, None)
        self.petags = {k: v for k, v in self.petags.items() if k[0] != uplid}
        self.etag_forget(bucket, key)
        root = self.xml(res, "CompleteMultipartUploadResult", "CompleteMpu")
        if root is None:
            return
        etag = root.findtext("ETag")
        if etag is None:
            self.mism("CompleteMpu: response lacks <ETag>")
            return
        # a multipart ETag is "<hex>-<N>", N the number of parts assembled
        if not quoted(etag).endswith(f'-{len(op["manifest"])}"'):
            self.mism(f"CompleteMpu: ETag '{etag}' lacks part-count suffix "
                      f"-{len(op['manifest'])}")
        self.etag_check(bucket, key, quoted(etag), "CompleteMpu")

    def OAbortMpu(self, op, post):
        res = self.call("DELETE", f"/{op['bucket']}/{key_str(op['key'])}",
                        query=[("uploadId", self.wire_upload(op["uplid"]))])
        if not self.check_status(op, res):
            return
        if op["status"] == 204:
            self.upls.pop(op["uplid"], None)
            self.petags = {k: v for k, v in self.petags.items()
                           if k[0] != op["uplid"]}
        else:
            self.check_error_code(op, res)

    def OListParts(self, op, post):
        bucket, uplid = op["bucket"], op["uplid"]
        res = self.call("GET", f"/{bucket}/{key_str(op['key'])}",
                        query=[("uploadId", self.wire_upload(uplid))])
        if not self.check_status(op, res):
            return
        if op["status"] != 200:
            self.check_error_code(op, res)
            return
        root = self.xml(res, "ListPartsResult", "ListParts")
        if root is None:
            return
        parts = post.get(bucket, {}).get("mpu", {}).get(uplid, {}) \
                    .get("parts", {})
        got = []
        for p in root.findall("Part"):
            pn = int(p.findtext("PartNumber", "-1"))
            got.append(pn)
            size = p.findtext("Size")
            if pn in parts and size is not None and \
                    size != str(len(parts[pn]) * self.bs):
                self.mism(f"ListParts: part {pn} Size {size}, model "
                          f"{len(parts[pn])} blocks")
            etag = p.findtext("ETag")
            have = self.petags.get((uplid, pn))
            if etag is not None and have and quoted(etag) != have:
                self.mism(f"ListParts: part {pn} ETag '{etag}', learned "
                          f"'{have}'")
        if got != op["partNums"]:
            self.mism(f"ListParts: parts {got}, expected {op['partNums']}")

    def OListMpu(self, op, post):
        res = self.call("GET", f"/{op['bucket']}", query=[("uploads", "")])
        if not self.check_status(op, res):
            return
        if op["status"] != 200:
            self.check_error_code(op, res)
            return
        root = self.xml(res, "ListMultipartUploadsResult", "ListMpu")
        if root is None:
            return
        # Compared as a set: each row's UploadId must map (via the learned
        # wire ids) to a model upload whose {key, uplid} the label carries.
        by_wire = {w: u for u, w in self.upls.items()}
        got = []
        for u in root.findall("Upload"):
            wire = u.findtext("UploadId", "")
            if wire not in by_wire:
                self.mism(f"ListMpu: unknown UploadId '{wire}' (key "
                          f"'{u.findtext('Key', '')}')")
                return
            got.append((u.findtext("Key", ""), by_wire[wire]))
        want = sorted((key_str(u["key"]), u["uplid"]) for u in op["uploads"])
        if sorted(got) != want:
            self.mism(f"ListMpu: uploads {sorted(got)}, expected {want}")


# ---- trace driver ---------------------------------------------------------

def run_trace(path, args, tally):
    """Replay one trace.  Returns the number of diverging steps."""
    states = load_states(path)
    name = os.path.basename(path)
    if args.dry_run or args.verbose:
        print(f"{name}: {len(states) - 1} steps")
    if args.dry_run:
        return 0

    client = S3Client(args.host, args.port, args.access_key, args.secret_key,
                      timeout=args.timeout)
    o = Oracle(client, args.block_size)
    history = []
    diverged = 0
    try:
        for idx, st in enumerate(states[1:], 1):
            tag, op = st["lastOp"]["tag"], st["lastOp"]["value"]
            fn = getattr(o, tag, None)
            if fn is None:
                raise TraceFormatError(f"{path}: state {idx} has unknown op "
                                       f"'{tag}'")
            o.m = []
            o.hits = st.get("devHits", ())
            fn(op, st["bkts"])
            dump = json.dumps(op, sort_keys=True, separators=(",", ":"))
            history = (history + [(idx, tag, o.status, dump)])[-HIST:]
            if not o.m:
                continue
            diverged += 1
            for msg in o.m:
                tally[f"{tag}: {msg}"] = tally.get(f"{tag}: {msg}", 0) + 1
            print(f"\n=== DIVERGENCE in {path} ===\nstep {idx}: {tag} {dump}")
            for msg in o.m:
                print(f"  MISMATCH: {msg}")
            print(f"last {len(history)} ops:")
            for h in history:
                print(f"  [{h[0]}] {h[1]} -> {h[2]}  {h[3]}")
            if not args.keep_going:
                break
    finally:
        client.close()
    return diverged


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--trace", action="append", required=True)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--access-key", required=True)
    ap.add_argument("--secret-key", required=True)
    ap.add_argument("--block-size", type=int, default=8192,
                    help="bytes per model block (multipart traces need the "
                         "5 MiB minimum part size)")
    ap.add_argument("--timeout", type=float, default=60.0,
                    help="per-request timeout in seconds")
    ap.add_argument("--keep-going", action="store_true",
                    help="report every diverging step of a trace instead of "
                         "stopping at the first (survey mode: once the server "
                         "and the model disagree about state, later reports "
                         "may be follow-on noise)")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    tally = {}
    failed = 0
    for t in args.trace:
        try:
            failed += 1 if run_trace(t, args, tally) else 0
        except TraceFormatError as e:
            print(e, file=sys.stderr)
            return 2
    if args.keep_going and tally:
        print("\n=== divergence summary ===")
        for msg, n in sorted(tally.items(), key=lambda kv: -kv[1]):
            print(f"  x{n}  {msg}")
    if failed:
        print(f"{failed} trace(s) diverged")
        return 1
    print(f"{len(args.trace)} trace(s) replayed with no divergence")
    return 0


if __name__ == "__main__":
    sys.exit(main())
