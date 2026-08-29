# SPDX-FileCopyrightText: 2026 The Quint Specs Authors
#
# SPDX-License-Identifier: MIT

"""Raw SMB2 wire layer for the model replay harness.

`smbprotocol` is used at its RAW layer only: this module hand-builds each
SMB2 request structure, sends it, and reports the exact NTSTATUS that came
back.  The library's file-like `Open` API is deliberately NOT used -- it
normalizes away precisely what the model is about (which DesiredAccess bits
were asked for, which CreateDisposition, which ShareAccess, and what the
server answered), and it raises on a non-success status where the harness
needs that status as data.

Everything here is about SMB2 mechanics.  The model vocabulary and the
comparisons live in smb2_replay.py.
"""

import struct
import uuid

from smbprotocol.connection import Connection, Dialects
from smbprotocol.session import Session
from smbprotocol.tree import TreeConnect
from smbprotocol.exceptions import SMBResponseException
import smbprotocol.open as O
import smbprotocol.create_contexts as CC


# ---------------------------------------------------------------------------
# Wire constants (MS-SMB2 2.2.13, MS-FSCC 2.4)
# ---------------------------------------------------------------------------

# CreateDisposition
FILE_SUPERSEDE, FILE_OPEN, FILE_CREATE = 0, 1, 2
FILE_OPEN_IF, FILE_OVERWRITE, FILE_OVERWRITE_IF = 3, 4, 5

# CreateOptions
FILE_DIRECTORY_FILE = 0x00000001
FILE_NON_DIRECTORY_FILE = 0x00000040
FILE_DELETE_ON_CLOSE = 0x00001000

# DesiredAccess (file access mask)
FILE_READ_DATA = 0x00000001
FILE_WRITE_DATA = 0x00000002
FILE_READ_ATTRIBUTES = 0x00000080
DELETE = 0x00010000

# ShareAccess
FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_SHARE_DELETE = 0x1, 0x2, 0x4

# FileInformationClass (MS-FSCC 2.4)
FILE_BASIC_INFORMATION = 4
FILE_STANDARD_INFORMATION = 5
FILE_INTERNAL_INFORMATION = 6
FILE_RENAME_INFORMATION = 10
FILE_DISPOSITION_INFORMATION = 13
FILE_END_OF_FILE_INFORMATION = 20

SMB2_0_INFO_FILE = 0x01

# Requested oplock levels (MS-SMB2 2.2.13).
OPLOCK_NONE = 0x00
OPLOCK_LEVEL_II = 0x01
OPLOCK_EXCLUSIVE = 0x08
OPLOCK_BATCH = 0x09
OPLOCK_LEASE = 0xFF

# Lease state bits (MS-SMB2 2.2.13.2.8).
LEASE_NONE = 0x00
LEASE_READ = 0x01
LEASE_HANDLE = 0x02
LEASE_WRITE = 0x04

# The all-0xFF FileId that means "the handle the previous command in this
# compound chain produced" (MS-SMB2 3.2.4.1.6).
RELATED_FID = b"\xff" * 16

# NTSTATUS values the harness itself needs to reason about.
ST_SUCCESS = 0x00000000
ST_PENDING = 0x00000103

# No modeled request may legitimately take this long: every lock in the
# generated corpus carries FAIL_IMMEDIATELY, and nothing else blocks.  A reply
# that never comes is a wedged server or a harness bug, and it has to surface
# as a diagnosable failure rather than hanging the ctest until its timeout
# kills the whole batch with no output at all.
RECV_TIMEOUT = 60


class WireError(Exception):
    """A harness-level failure: the transport broke, not the server disagreed."""


def _status_of(exc):
    """NTSTATUS from an smbprotocol SMBResponseException."""
    return exc.status & 0xFFFFFFFF


class Conn:
    """One TCP connection carrying one SMB2 session.

    The model's session and connection are one-to-one (`CDisconnect` takes a
    session's trees down with it, and `CReconnect` is defined as a *fresh
    connection* presenting the same ClientGuid), so binding them together here
    keeps the mapping honest instead of multiplexing sessions the model
    believes are independent.
    """

    def __init__(self, server, port, share, user, password, client_guid,
                 dialect=Dialects.SMB_3_0_0):
        self.server = server
        self.port = port
        self.share = share
        self.client_guid = client_guid
        self.conn = Connection(client_guid, server, port, require_signing=True)
        self.conn.connect(dialect)
        self.session = Session(self.conn, user, password,
                               require_encryption=False)
        self.session.connect()
        self.sid = self.session.session_id
        self.trees = {}          # wire tree id -> TreeConnect
        self.dead = False

    # -- lifecycle ---------------------------------------------------------

    def tree_connect(self):
        t = TreeConnect(self.session, r"\\%s\%s" % (self.server, self.share))
        t.connect()
        self.trees[t.tree_connect_id] = t
        return ST_SUCCESS, t.tree_connect_id

    def tree_disconnect(self, tid):
        t = self.trees.pop(tid, None)
        if t is None:
            raise WireError("tree_disconnect on unknown tid %r" % (tid,))
        try:
            t.disconnect()
        except SMBResponseException as e:
            return _status_of(e)
        return ST_SUCCESS

    def logoff(self):
        try:
            self.session.disconnect(close=True)
        except SMBResponseException as e:
            return _status_of(e)
        finally:
            self.trees.clear()
        return ST_SUCCESS

    def close(self):
        """Drop the transport.  Never raises: used on teardown paths."""
        if self.dead:
            return
        self.dead = True
        try:
            self.conn.disconnect(close=True)
        except Exception:
            pass

    # -- raw request plumbing ---------------------------------------------

    def _send1(self, req, tid, parse=None):
        """Send one request, return (status, parsed-or-None)."""
        try:
            hdr = self.conn.send(req, sid=self.sid, tid=tid)
            resp = self.conn.receive(hdr, timeout=RECV_TIMEOUT)
        except SMBResponseException as e:
            return _status_of(e), None
        if parse is None:
            return ST_SUCCESS, resp
        out = parse()
        out.unpack(resp['data'].get_value())
        return ST_SUCCESS, out

    def send_chain(self, reqs, tid, related, parsers):
        """Send `reqs` as one compound message; return [(status, parsed), ...].

        With related=True the server threads the previous command's FileId
        through the chain, which is what the model's `FidRelated` selector
        means.  The caller has already put RELATED_FID in those requests.

        A related chain stops at the first error server-side; the model
        truncates its result list at the same point, and the caller only ever
        hands us the prefix that has results, so every request here is one the
        model expects an answer for.
        """
        if len(reqs) == 1:
            return [self._send1(reqs[0], tid, parsers[0])]
        try:
            hdrs = self.conn.send_compound(reqs, sid=self.sid, tid=tid,
                                           related=related)
        except SMBResponseException as e:
            # A failure raised by send_compound is a framing problem, not a
            # per-command status: report it against the first command.
            return [(_status_of(e), None)] * len(reqs)
        out = []
        for hdr, parse in zip(hdrs, parsers):
            try:
                resp = self.conn.receive(hdr, timeout=RECV_TIMEOUT)
            except SMBResponseException as e:
                out.append((_status_of(e), None))
                continue
            if parse is None:
                out.append((ST_SUCCESS, resp))
            else:
                p = parse()
                p.unpack(resp['data'].get_value())
                out.append((ST_SUCCESS, p))
        return out


# ---------------------------------------------------------------------------
# Request builders.  Each returns (request, parser) so a command can be sent
# alone or spliced into a compound chain without a second code path.
# ---------------------------------------------------------------------------

def lease_key_bytes(model_key):
    """A 16-byte LeaseKey for the model's small integer key.

    The key must be stable within a trace and distinct between model keys: the
    server binds a lease key to exactly one file per client, and the model
    generates deliberate rebinding conflicts to exercise that rule.
    """
    return b"LK" + struct.pack("<I", model_key) + b"\x00" * 10


def req_create(name, disposition, access, share_access, options,
               oplock_level=OPLOCK_NONE, lease=None, want_disk_id=True):
    r = O.SMB2CreateRequest()
    r['impersonation_level'] = O.ImpersonationLevel.Impersonation
    r['desired_access'] = access
    r['file_attributes'] = 0
    r['share_access'] = share_access
    r['create_disposition'] = disposition
    r['create_options'] = options
    r['requested_oplock_level'] = oplock_level
    r['buffer_path'] = name.encode('utf-16-le')
    contexts = []
    if lease is not None:
        # RqLs (MS-SMB2 2.2.13.2.8 / 2.2.13.2.10).  The request goes on the
        # wire even against a server that grants no caching: the lease KEY
        # binding is a server-side rule in its own right (a key may name only
        # one file per client), and it is only exercised if the context is
        # actually sent.
        state = 0
        if lease.get("r"):
            state |= LEASE_READ
        if lease.get("h"):
            state |= LEASE_HANDLE
        if lease.get("w"):
            state |= LEASE_WRITE
        if lease.get("v2"):
            lc = CC.SMB2CreateRequestLeaseV2()
            lc['lease_key'] = lease_key_bytes(lease["key"])
            lc['lease_state'] = state
            lc['lease_flags'] = 0
            lc['lease_duration'] = 0
            # Fixed-width fields with no default: the V2 context does not pack
            # unless every one of them is set, and a model lease has no parent.
            lc['parent_lease_key'] = b"\x00" * 16
            lc['epoch'] = lease.get("epoch", 0)
            lc['reserved'] = 0
        else:
            lc = CC.SMB2CreateRequestLease()
            lc['lease_key'] = lease_key_bytes(lease["key"])
            lc['lease_state'] = state
            lc['lease_flags'] = 0
            lc['lease_duration'] = 0
        ctx = CC.SMB2CreateContextRequest()
        ctx['buffer_name'] = (CC.CreateContextName.SMB2_CREATE_REQUEST_LEASE_V2
                              if lease.get("v2")
                              else CC.CreateContextName.SMB2_CREATE_REQUEST_LEASE)
        ctx['buffer_data'] = lc
        contexts.append(ctx)
    if want_disk_id:
        # SMB2_CREATE_QUERY_ON_DISK_ID (MS-SMB2 2.2.13.2.9): the server returns
        # the object's on-disk identity in the CREATE reply itself.  The
        # harness needs that identity to check the model's Ino bijection, and
        # asking for it here costs no extra round trip -- which matters, since
        # a separate QUERY_INFO would race the CLOSE that frequently follows a
        # CREATE in the same compound chain, and is impossible to splice into a
        # RELATED chain without breaking the FileId threading the model relies
        # on.  It is a purely informational context: it grants nothing and
        # changes no state.
        q = CC.SMB2CreateContextRequest()
        q['buffer_name'] = CC.CreateContextName.SMB2_CREATE_QUERY_ON_DISK_ID
        q['buffer_data'] = b""
        contexts.append(q)
    if contexts:
        r['buffer_contexts'] = CC.SMB2CreateContextRequest.pack_multiple(
            contexts)
    return r, O.SMB2CreateResponse


def req_close(fid):
    r = O.SMB2CloseRequest()
    r['file_id'] = fid
    r['flags'] = 0
    return r, O.SMB2CloseResponse


def req_read(fid, offset, length):
    r = O.SMB2ReadRequest()
    r['length'] = length
    r['offset'] = offset
    r['file_id'] = fid
    r['minimum_count'] = 0
    r['padding'] = 80
    r['remaining_bytes'] = 0
    return r, O.SMB2ReadResponse


def req_write(fid, offset, data):
    r = O.SMB2WriteRequest()
    r['offset'] = offset
    r['file_id'] = fid
    r['buffer'] = data
    r['channel'] = 0
    r['remaining_bytes'] = 0
    r['flags'] = 0
    return r, O.SMB2WriteResponse


def req_flush(fid):
    r = O.SMB2FlushRequest()
    r['file_id'] = fid
    return r, O.SMB2FlushResponse


def req_lock(fid, offset, length, exclusive, unlock, fail_immediately):
    el = O.SMB2LockElement()
    el['offset'] = offset
    el['length'] = length
    if unlock:
        flags = O.LockFlags.SMB2_LOCKFLAG_UNLOCK
    else:
        flags = (O.LockFlags.SMB2_LOCKFLAG_EXCLUSIVE_LOCK if exclusive
                 else O.LockFlags.SMB2_LOCKFLAG_SHARED_LOCK)
        if fail_immediately:
            flags |= O.LockFlags.SMB2_LOCKFLAG_FAIL_IMMEDIATELY
    el['flags'] = flags
    r = O.SMB2LockRequest()
    r['file_id'] = fid
    r['lock_count'] = 1
    r['locks'] = [el]
    r['lock_sequence'] = 0
    return r, None


def _req_query(fid, info_class, outlen=4096):
    r = O.SMB2QueryInfoRequest()
    r['info_type'] = SMB2_0_INFO_FILE
    r['file_info_class'] = info_class
    r['output_buffer_length'] = outlen
    r['file_id'] = fid
    r['flags'] = 0
    r['additional_information'] = 0
    return r, O.SMB2QueryInfoResponse


def req_query_standard(fid):
    return _req_query(fid, FILE_STANDARD_INFORMATION)


def req_query_internal(fid):
    return _req_query(fid, FILE_INTERNAL_INFORMATION)


def _req_set(fid, info_class, buf):
    r = O.SMB2SetInfoRequest()
    r['info_type'] = SMB2_0_INFO_FILE
    r['file_info_class'] = info_class
    r['file_id'] = fid
    r['buffer'] = buf
    r['additional_information'] = 0
    return r, None


def req_set_eof(fid, size_bytes):
    return _req_set(fid, FILE_END_OF_FILE_INFORMATION,
                    struct.pack("<q", size_bytes))


def req_set_disposition(fid, delete_pending):
    return _req_set(fid, FILE_DISPOSITION_INFORMATION,
                    struct.pack("<B", 1 if delete_pending else 0))


def req_set_rename(fid, new_name, replace_if_exists=False):
    """FILE_RENAME_INFORMATION (MS-FSCC 2.4.37, SMB2 form).

    ReplaceIfExists is false: the model answers a rename onto an existing
    name with a collision, which is the ReplaceIfExists=0 arm.
    """
    name = new_name.encode('utf-16-le')
    buf = struct.pack("<BxxxxxxxQI",
                      1 if replace_if_exists else 0,
                      0,                      # RootDirectory
                      len(name))
    return _req_set(fid, FILE_RENAME_INFORMATION, buf + name)


# ---------------------------------------------------------------------------
# Reply decoding
# ---------------------------------------------------------------------------

def parse_standard_info(resp):
    """FileStandardInformation -> dict (MS-FSCC 2.4.41)."""
    b = resp['buffer'].get_value()
    alloc, eof, nlink, delete_pending, directory = struct.unpack("<qqIBB",
                                                                 b[:22])
    return {"alloc": alloc, "eof": eof, "nlink": nlink,
            "delete_pending": bool(delete_pending),
            "directory": bool(directory)}


def parse_internal_info(resp):
    """FileInternalInformation -> the server's IndexNumber (MS-FSCC 2.4.24)."""
    return struct.unpack("<Q", resp['buffer'].get_value()[:8])[0]


def parse_disk_id(create_response):
    """DiskFileId from the QFid create context, or None if absent.

    MS-SMB2 2.2.14.2.9.  When the reply carries create contexts, smbprotocol
    parses the CREATE response `buffer` into a list of context structures, and
    each one decodes itself through get_context_data().
    """
    if create_response['create_contexts_length'].get_value() <= 0:
        return None
    for ctx in create_response['buffer'].get_value():
        try:
            data = ctx.get_context_data()
        except Exception:
            continue
        if isinstance(data, CC.SMB2CreateQueryOnDiskIDResponse):
            return data['disk_file_id'].get_value()
    return None


def new_client_guid(client_symbol):
    """A stable ClientGuid per model client symbol.

    Stable within a trace and distinct between symbols: a durable/lease
    reclaim is adjudicated on ClientGuid equality, so two model clients must
    never collide onto one guid.
    """
    return uuid.UUID(int=(0x51C0 << 112) | client_symbol)
