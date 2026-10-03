# SPDX-FileCopyrightText: 2026 The Quint Specs Authors
#
# SPDX-License-Identifier: MIT

"""A raw S3 client for the conformance replayer: HTTP/1.1 plus SigV4, nothing
else.

Deliberately not an SDK.  A model replay has to put one exact request on the
wire and read back the exact status line, headers and body the server chose --
and an SDK is built to stop a caller seeing those: it retries, follows
redirects, rewrites a 404 into an exception that has already thrown the body
away, and adds checksum headers and addressing styles of its own.  This is the
S3 counterpart of using smbprotocol at its raw layer in harness/samba.

Standard library only (http.client, hashlib, hmac, xml.etree), so the suite
needs nothing installed beyond the server under test.

What it does send is what a correct client sends: every request is signed
(AWS Signature Version 4, path-style addressing, the payload hash in
x-amz-content-sha256), and a request whose body is an XML document carries
Content-MD5, which the S3 API requires on DeleteObjects and the tagging PUTs.
A large body is offered with "Expect: 100-continue", as the AWS SDKs offer
theirs: a server that can refuse a request from its headers alone -- an upload
id that does not exist -- then answers without the body ever being sent,
instead of answering, closing the connection, and leaving the client writing
megabytes into a reset.
"""

import base64
import datetime
import hashlib
import hmac
import http.client
import select
import sys
import time
import urllib.parse
import zlib
import xml.etree.ElementTree as ET

SERVICE = "s3"

# A body at least this large is offered with "Expect: 100-continue".
EXPECT_THRESHOLD = 1 << 20
# How long to wait for the server's verdict on the headers before sending the
# body regardless (RFC 9110 10.1.1: a client need not wait indefinitely).
EXPECT_WAIT = 5.0


def _enc(s, safe=""):
    """RFC 3986 percent-encoding as SigV4 defines it: everything but the
    unreserved set, and '/' only where the caller says so."""
    return urllib.parse.quote(s, safe=safe + "-_.~")


def _hmac(key, msg):
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


class Response:
    """One reply, as the server sent it."""

    def __init__(self, status, headers, body):
        self.status = status
        self.headers = headers          # lower-cased name -> value
        self.body = body
        self._xml = None

    def header(self, name):
        """A header's value, "" when the server did not send it."""
        return self.headers.get(name.lower(), "")

    def xml(self):
        """The body as an element tree with namespaces stripped, or None when
        it is not XML.  S3 documents live in one namespace that some servers
        declare and some do not, and no check here turns on which."""
        if self._xml is None:
            try:
                root = ET.fromstring(self.body)
            except ET.ParseError:
                return None
            for el in root.iter():
                if "}" in el.tag:
                    el.tag = el.tag.split("}", 1)[1]
            self._xml = root
        return self._xml

    def error_code(self):
        """The <Code> of an XML error body, "" when there is none (a success,
        or a HEAD reply, which has no body)."""
        root = self.xml()
        if root is None or root.tag != "Error":
            return ""
        return root.findtext("Code", "")


class S3Client:
    def __init__(self, host, port, access_key, secret_key, timeout=60.0,
                 region="us-east-1", tls=False):
        self.host = host
        self.port = port
        self.region = region
        self.tls = tls
        self.access_key = access_key
        self.secret_key = secret_key
        self.timeout = timeout
        self.conn = None

    def close(self):
        if self.conn is not None:
            self.conn.close()
            self.conn = None

    def _key(self, date, secret=None):
        key = _hmac(("AWS4" + (secret or self.secret_key)).encode(), date)
        for part in (self.region, SERVICE, "aws4_request"):
            key = _hmac(key, part)
        return key

    def presign(self, method, path, query=(), expires=300):
        """The query of a presigned URL for this request: the signature goes
        in the query string, and the request then carries no credentials in
        its headers at all."""
        now = datetime.datetime.now(datetime.timezone.utc)
        amz_date = now.strftime("%Y%m%dT%H%M%SZ")
        date = amz_date[:8]
        scope = f"{date}/{self.region}/{SERVICE}/aws4_request"
        default = 443 if self.tls else 80
        host = (self.host if self.port == default
                else f"{self.host}:{self.port}")
        query = list(query) + [
            ("X-Amz-Algorithm", "AWS4-HMAC-SHA256"),
            ("X-Amz-Credential", f"{self.access_key}/{scope}"),
            ("X-Amz-Date", amz_date),
            ("X-Amz-Expires", str(expires)),
            ("X-Amz-SignedHeaders", "host"),
        ]
        canonical = "\n".join([
            method,
            _enc(path, safe="/"),
            "&".join(f"{_enc(k)}={_enc(v)}" for k, v in sorted(query)),
            f"host:{host}\n",
            "host",
            "UNSIGNED-PAYLOAD",
        ])
        to_sign = "\n".join([
            "AWS4-HMAC-SHA256", amz_date, scope,
            hashlib.sha256(canonical.encode()).hexdigest(),
        ])
        sig = hmac.new(self._key(date), to_sign.encode(),
                       hashlib.sha256).hexdigest()
        return query + [("X-Amz-Signature", sig)]

    def _sign(self, method, path, query, headers, payload_hash, creds=None):
        access_key, secret_key = creds or (self.access_key, self.secret_key)
        now = datetime.datetime.now(datetime.timezone.utc)
        amz_date = now.strftime("%Y%m%dT%H%M%SZ")
        date = amz_date[:8]
        # A default port is left out of Host, as every HTTP client leaves it
        # out; the signature covers the header exactly as sent.
        default = 443 if self.tls else 80
        headers["host"] = (self.host if self.port == default
                           else f"{self.host}:{self.port}")
        headers["x-amz-date"] = amz_date
        headers["x-amz-content-sha256"] = payload_hash

        signed = sorted(h for h in headers
                        if h == "host" or h == "content-md5"
                        or h.startswith("x-amz-"))
        canonical = "\n".join([
            method,
            _enc(path, safe="/"),
            "&".join(f"{_enc(k)}={_enc(v)}" for k, v in sorted(query)),
            "".join(f"{h}:{headers[h].strip()}\n" for h in signed),
            ";".join(signed),
            payload_hash,
        ])
        scope = f"{date}/{self.region}/{SERVICE}/aws4_request"
        to_sign = "\n".join([
            "AWS4-HMAC-SHA256", amz_date, scope,
            hashlib.sha256(canonical.encode()).hexdigest(),
        ])
        key = self._key(date, secret_key)
        sig = hmac.new(key, to_sign.encode(), hashlib.sha256).hexdigest()
        headers["authorization"] = (
            f"AWS4-HMAC-SHA256 Credential={access_key}/{scope}, "
            f"SignedHeaders={';'.join(signed)}, Signature={sig}")

    def call(self, method, path, query=(), headers=None, body=b"",
             xml_body=False, anonymous=False, creds=None,
             payload_hash=None):
        """Issue one request.  `anonymous` sends it with no credentials at
        all: unsigned, as a stranger would (a presigned URL is sent this way:
        its credentials are in `query`).  `creds` signs it as (access key,
        secret) instead of the client's own.  `payload_hash` replaces the
        body's SHA-256 in x-amz-content-sha256, for a body that is not the
        payload itself.

        `query` is a sequence of (name, value) pairs; a bare subresource such
        as ?uploads is the pair ("uploads", "").  `headers` are extra request
        headers, lower-case names.  `xml_body` marks the body as an XML
        document, which adds Content-MD5.
        """
        query = list(query)
        headers = dict(headers or {})
        if xml_body:
            headers["content-md5"] = base64.b64encode(
                hashlib.md5(body).digest()).decode()
        if not anonymous:
            self._sign(method, path, query, headers,
                       payload_hash or hashlib.sha256(body).hexdigest(),
                       creds)

        target = _enc(path, safe="/")
        if query:
            target += "?" + "&".join(f"{_enc(k)}={_enc(v)}" for k, v in query)

        # One reconnect: the server is entitled to drop an idle keep-alive
        # connection, and that is not a divergence.  A request that fails on
        # a fresh connection is.
        for attempt in (0, 1):
            if self.conn is None:
                self.conn = (http.client.HTTPSConnection if self.tls
                             else http.client.HTTPConnection)(
                    self.host, self.port, timeout=self.timeout)
            try:
                if len(body) >= EXPECT_THRESHOLD:
                    r = self._request_expect(method, target, headers, body)
                else:
                    self.conn.request(method, target, body=body,
                                      headers=headers)
                    r = self.conn.getresponse()
                data = r.read()
                break
            except (http.client.RemoteDisconnected, ConnectionResetError,
                    BrokenPipeError):
                self.close()
                if attempt:
                    raise
        resp = Response(r.status,
                        {k.lower(): v for k, v in r.getheaders()}, data)
        if r.will_close:
            self.close()
        return resp

    def _request_expect(self, method, target, headers, body):
        """Send the headers with Expect: 100-continue, and the body only if
        the server asks for it (or says nothing for EXPECT_WAIT seconds).

        http.client cannot do this: its response parser swallows an interim
        100 and blocks for the final status, which never comes while the body
        is unsent.  So the first status line is read here, through the same
        response object that then parses whatever follows it.  The connection
        is not reused afterwards.
        """
        c = self.conn
        # skip_host: the signed headers already carry Host, and a second one
        # is a 400.
        c.putrequest(method, target, skip_host=True)
        for k, v in headers.items():
            c.putheader(k, v)
        c.putheader("content-length", str(len(body)))
        c.putheader("expect", "100-continue")
        c.endheaders()

        r = _ExpectResponse(c.sock, method=method)
        send_body = True
        if select.select([c.sock], [], [], EXPECT_WAIT)[0]:
            first = http.client.HTTPResponse._read_status(r)
            if first[1] == http.client.CONTINUE:
                # the rest of the interim response: any headers, a blank line
                while r.fp.readline(65537).strip():
                    pass
            else:
                # The final answer, given on the headers alone.  Hand its
                # status line back to the parser; the body is never sent.
                r.first_status = first
                send_body = False
        if send_body:
            c.send(body)
        r.begin()
        r.will_close = True
        return r


class _ExpectResponse(http.client.HTTPResponse):
    """A response whose first status line may already have been read."""

    first_status = None

    def _read_status(self):
        if self.first_status is not None:
            first, self.first_status = self.first_status, None
            return first
        return super()._read_status()


def crc32_b64(data):
    """A body's CRC32 as S3 carries it: the four bytes, big-endian, base64."""
    return base64.b64encode(zlib.crc32(data).to_bytes(4, "big")).decode()


def trailer_body(data, chunk=1 << 16):
    """`data` framed as aws-chunked with its CRC32 in a trailer, unsigned
    (x-amz-content-sha256: STREAMING-UNSIGNED-PAYLOAD-TRAILER) -- the framing
    current AWS SDKs upload with by default."""
    out = []
    for i in range(0, len(data), chunk):
        piece = data[i:i + chunk]
        out.append(f"{len(piece):x}\r\n".encode() + piece + b"\r\n")
    out.append(b"0\r\n" + f"x-amz-checksum-crc32:{crc32_b64(data)}\r\n"
               .encode() + b"\r\n")
    return b"".join(out)


# The rule every bucket this suite creates carries from the moment it exists:
# whatever is still in it after a day expires, and so does an upload nobody
# finished.  A bucket has no lifetime of its own in S3 -- only its contents can
# be given one -- so this bounds what a leaked bucket can cost until a sweep
# (s3_sweep.py) removes the bucket itself.
EXPIRE_LIFECYCLE = (
    b"<LifecycleConfiguration><Rule><ID>specs-mbt-expire</ID>"
    b"<Filter><Prefix></Prefix></Filter><Status>Enabled</Status>"
    b"<Expiration><Days>1</Days></Expiration>"
    b"<AbortIncompleteMultipartUpload><DaysAfterInitiation>1"
    b"</DaysAfterInitiation></AbortIncompleteMultipartUpload>"
    b"</Rule></LifecycleConfiguration>")


def location_constraint(region):
    """The CreateBucket body a region demands: every region but us-east-1
    refuses a create that does not name it."""
    if region == "us-east-1":
        return b""
    return ("<CreateBucketConfiguration><LocationConstraint>" + region +
            "</LocationConstraint></CreateBucketConfiguration>").encode()


def list_buckets(client, prefix=""):
    """[(name, CreationDate)] of the caller's buckets whose name starts with
    `prefix`, following the listing's continuation tokens.  The prefix is
    applied here as well as asked of the server: a server that ignores the
    parameter must not widen what a caller goes on to delete."""
    out, token = [], None
    while True:
        query = [("prefix", prefix)] if prefix else []
        if token:
            query.append(("continuation-token", token))
        res = client.call("GET", "/", query=query)
        root = res.xml()
        if res.status != 200 or root is None:
            raise OSError(f"ListBuckets: {res.status} {res.error_code()}")
        for b in root.iter("Bucket"):
            name = b.findtext("Name", "")
            if name.startswith(prefix):
                out.append((name, b.findtext("CreationDate", "")))
        token = root.findtext("ContinuationToken")
        if not token:
            return out


def purge_bucket(client, name):
    """Abort every upload in bucket `name`, delete every object, delete the
    bucket.  Returns "" on success (a bucket already gone is a success), else
    what stopped it."""
    path = f"/{name}"
    for _ in range(1000):
        res = client.call("GET", path, query=[("uploads", "")])
        if res.status == 404:
            return ""
        root = res.xml()
        if res.status != 200 or root is None:
            return f"ListMultipartUploads: {res.status} {res.error_code()}"
        ups = [(u.findtext("Key", ""), u.findtext("UploadId", ""))
               for u in root.findall("Upload")]
        for key, upl in ups:
            client.call("DELETE", f"{path}/{key}", query=[("uploadId", upl)])
        if root.findtext("IsTruncated") != "true":
            break
    # every version and delete marker: in a bucket with a history, deleting a
    # key by name removes nothing
    for _ in range(1000):
        res = client.call("GET", path, query=[("versions", "")])
        if res.status == 404:
            return ""
        root = res.xml()
        if res.status != 200 or root is None:
            break       # a server without the call has no history to remove
        vers = [(v.findtext("Key", ""), v.findtext("VersionId", ""))
                for v in root if v.tag in ("Version", "DeleteMarker")]
        if not vers:
            break
        for key, vid in vers:
            client.call("DELETE", f"{path}/{key}",
                        query=[("versionId", vid)] if vid else [])
    for _ in range(1000):
        res = client.call("GET", path, query=[("list-type", "2")])
        if res.status == 404:
            return ""
        root = res.xml()
        if res.status != 200 or root is None:
            return f"ListObjectsV2: {res.status} {res.error_code()}"
        keys = [c.findtext("Key", "") for c in root.findall("Contents")]
        if not keys:
            break
        for key in keys:
            client.call("DELETE", f"{path}/{key}")
    res = client.call("DELETE", path)
    if res.status in (204, 404):
        return ""
    return f"DeleteBucket: {res.status} {res.error_code()}"


def wait_ready(host, port, access_key, secret_key, timeout=60.0, **kw):
    """Wait until the server answers S3, not merely until it listens.

    A server can accept connections before it can serve: MinIO opens its port
    and answers 503 XMinioServerNotInitialized until its object layer is up.
    The only test that cannot be wrong about that is the thing itself -- a
    signed ListBuckets that comes back 200.  Returns whether it did.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        c = S3Client(host, port, access_key, secret_key, timeout=5.0, **kw)
        try:
            if c.call("GET", "/").status == 200:
                return True
        except OSError:
            pass
        finally:
            c.close()
        time.sleep(0.05)
    return False


if __name__ == "__main__":
    # s3_wire.py wait-ready <host> <port> <access-key> <secret-key> [seconds]
    if len(sys.argv) < 6 or sys.argv[1] != "wait-ready":
        sys.exit("usage: s3_wire.py wait-ready <host> <port> <access-key> "
                 "<secret-key> [seconds]")
    sys.exit(0 if wait_ready(sys.argv[2], int(sys.argv[3]), sys.argv[4],
                             sys.argv[5],
                             float(sys.argv[6]) if len(sys.argv) > 6 else 60.0)
             else 1)
