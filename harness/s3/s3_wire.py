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
"""

import base64
import datetime
import hashlib
import hmac
import http.client
import urllib.parse
import xml.etree.ElementTree as ET

REGION = "us-east-1"
SERVICE = "s3"


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
    def __init__(self, host, port, access_key, secret_key, timeout=60.0):
        self.host = host
        self.port = port
        self.access_key = access_key
        self.secret_key = secret_key
        self.timeout = timeout
        self.conn = None

    def close(self):
        if self.conn is not None:
            self.conn.close()
            self.conn = None

    def _sign(self, method, path, query, headers, payload_hash):
        now = datetime.datetime.now(datetime.timezone.utc)
        amz_date = now.strftime("%Y%m%dT%H%M%SZ")
        date = amz_date[:8]
        headers["host"] = f"{self.host}:{self.port}"
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
        scope = f"{date}/{REGION}/{SERVICE}/aws4_request"
        to_sign = "\n".join([
            "AWS4-HMAC-SHA256", amz_date, scope,
            hashlib.sha256(canonical.encode()).hexdigest(),
        ])
        key = _hmac(("AWS4" + self.secret_key).encode(), date)
        for part in (REGION, SERVICE, "aws4_request"):
            key = _hmac(key, part)
        sig = hmac.new(key, to_sign.encode(), hashlib.sha256).hexdigest()
        headers["authorization"] = (
            f"AWS4-HMAC-SHA256 Credential={self.access_key}/{scope}, "
            f"SignedHeaders={';'.join(signed)}, Signature={sig}")

    def call(self, method, path, query=(), headers=None, body=b"",
             xml_body=False):
        """Issue one request.

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
        self._sign(method, path, query, headers,
                   hashlib.sha256(body).hexdigest())

        target = _enc(path, safe="/")
        if query:
            target += "?" + "&".join(f"{_enc(k)}={_enc(v)}" for k, v in query)

        # One reconnect: the server is entitled to drop an idle keep-alive
        # connection, and that is not a divergence.  A request that fails on
        # a fresh connection is.
        for attempt in (0, 1):
            if self.conn is None:
                self.conn = http.client.HTTPConnection(
                    self.host, self.port, timeout=self.timeout)
            try:
                self.conn.request(method, target, body=body, headers=headers)
                r = self.conn.getresponse()
                data = r.read()
                break
            except (http.client.RemoteDisconnected, ConnectionResetError,
                    BrokenPipeError):
                self.close()
                if attempt:
                    raise
        return Response(r.status,
                        {k.lower(): v for k, v in r.getheaders()}, data)
