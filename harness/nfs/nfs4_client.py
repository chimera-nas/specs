# SPDX-FileCopyrightText: 2026 The Quint Specs Authors
#
# SPDX-License-Identifier: MIT

"""Minimal standalone NFSv4.0/4.1/4.2 COMPOUND client used by the NFS
conformance harness (nfs4_replay.py).

Like nfs3_client.py this is a deliberately independent implementation of
the wire protocol (RFC 7530/8881/7862/8276 + RFC 7531/7863 XDR): it shares
no code with any server's generated marshalling, so an encoding bug on
either side surfaces as a divergence instead of cancelling itself out.

Structure:
  - encode_* functions build one nfs_argop4 each, returning packed bytes
    (opnum included); the replay layer composes them into compounds.
  - DECODERS maps opnum -> result decoder; compound() returns one plain
    dict per executed op plus the raw COMPOUND4res bytes (the 4.1 SEQUENCE
    replay contract compares raw bytes).
  - The receive path understands RPC CALLs arriving on the same TCP
    connection (the 4.1 backchannel): CB_COMPOUND is answered minimally
    (CB_SEQUENCE + CB_RECALL/CB_LAYOUTRECALL accepted) and every recalled
    stateid/layout is recorded for the harness to reconcile.

Only what the Quint model exercises is implemented.
"""

import socket
import struct

from nfs3_client import Packer, Unpacker, RpcClient, RpcError, XdrError

NFS_PROGRAM = 100003
NFS_V4 = 4
NFSPROC4_COMPOUND = 1

NFS4_OK = 0

# Operation numbers (RFC 7530 16.2 / 8881 18 / 7862 15 / 8276 8)
OP_ACCESS = 3
OP_CLOSE = 4
OP_COMMIT = 5
OP_CREATE = 6
OP_DELEGPURGE = 7
OP_DELEGRETURN = 8
OP_GETATTR = 9
OP_GETFH = 10
OP_LINK = 11
OP_LOCK = 12
OP_LOCKT = 13
OP_LOCKU = 14
OP_LOOKUP = 15
OP_LOOKUPP = 16
OP_NVERIFY = 17
OP_OPEN = 18
OP_OPEN_CONFIRM = 20
OP_OPEN_DOWNGRADE = 21
OP_PUTFH = 22
OP_PUTROOTFH = 24
OP_READ = 25
OP_READDIR = 26
OP_READLINK = 27
OP_REMOVE = 28
OP_RENAME = 29
OP_RENEW = 30
OP_RESTOREFH = 31
OP_SAVEFH = 32
OP_SECINFO = 33
OP_SETATTR = 34
OP_SETCLIENTID = 35
OP_SETCLIENTID_CONFIRM = 36
OP_VERIFY = 37
OP_WRITE = 38
OP_RELEASE_LOCKOWNER = 39
OP_BIND_CONN_TO_SESSION = 41
OP_EXCHANGE_ID = 42
OP_CREATE_SESSION = 43
OP_DESTROY_SESSION = 44
OP_FREE_STATEID = 45
OP_GETDEVICEINFO = 47
OP_LAYOUTCOMMIT = 49
OP_LAYOUTGET = 50
OP_LAYOUTRETURN = 51
OP_SEQUENCE = 53
OP_DESTROY_CLIENTID = 57
OP_RECLAIM_COMPLETE = 58
OP_ALLOCATE = 59
OP_COPY = 60
OP_DEALLOCATE = 62
OP_IO_ADVISE = 63
OP_READ_PLUS = 68
OP_SEEK = 69
OP_WRITE_SAME = 70
OP_CLONE = 71
OP_GETXATTR = 72
OP_SETXATTR = 73
OP_LISTXATTRS = 74
OP_REMOVEXATTR = 75
OP_ILLEGAL = 10044

# Callback ops (RFC 8881 20)
OP_CB_GETATTR = 3
OP_CB_RECALL = 4
OP_CB_LAYOUTRECALL = 5
OP_CB_SEQUENCE = 11

# ftype4
NF4REG, NF4DIR, NF4BLK, NF4CHR, NF4LNK, NF4SOCK, NF4FIFO = 1, 2, 3, 4, 5, 6, 7

# Attribute numbers
# Attribute numbers (RFC 7530 5.8 / RFC 8881 5.8 / RFC 7862 12 / RFC 8276 8).
FATTR4_SUPPORTED_ATTRS = 0
FATTR4_TYPE = 1
FATTR4_FH_EXPIRE_TYPE = 2
FATTR4_CHANGE = 3
FATTR4_SIZE = 4
FATTR4_LINK_SUPPORT = 5
FATTR4_SYMLINK_SUPPORT = 6
FATTR4_NAMED_ATTR = 7
FATTR4_FSID = 8
FATTR4_UNIQUE_HANDLES = 9
FATTR4_LEASE_TIME = 10
FATTR4_RDATTR_ERROR = 11
FATTR4_ACL = 12
FATTR4_ACLSUPPORT = 13
FATTR4_ARCHIVE = 14
FATTR4_CANSETTIME = 15
FATTR4_CASE_INSENSITIVE = 16
FATTR4_CASE_PRESERVING = 17
FATTR4_CHOWN_RESTRICTED = 18
FATTR4_FILEHANDLE = 19
FATTR4_FILEID = 20
FATTR4_FILES_AVAIL = 21
FATTR4_FILES_FREE = 22
FATTR4_FILES_TOTAL = 23
FATTR4_FS_LOCATIONS = 24
FATTR4_HIDDEN = 25
FATTR4_HOMOGENEOUS = 26
FATTR4_MAXFILESIZE = 27
FATTR4_MAXLINK = 28
FATTR4_MAXNAME = 29
FATTR4_MAXREAD = 30
FATTR4_MAXWRITE = 31
FATTR4_MIMETYPE = 32
FATTR4_MODE = 33
FATTR4_NO_TRUNC = 34
FATTR4_NUMLINKS = 35
FATTR4_OWNER = 36
FATTR4_OWNER_GROUP = 37
FATTR4_QUOTA_AVAIL_HARD = 38
FATTR4_QUOTA_AVAIL_SOFT = 39
FATTR4_QUOTA_USED = 40
FATTR4_RAWDEV = 41
FATTR4_SPACE_AVAIL = 42
FATTR4_SPACE_FREE = 43
FATTR4_SPACE_TOTAL = 44
FATTR4_SPACE_USED = 45
FATTR4_SYSTEM = 46
FATTR4_TIME_ACCESS = 47
FATTR4_TIME_ACCESS_SET = 48
FATTR4_TIME_BACKUP = 49
FATTR4_TIME_CREATE = 50
FATTR4_TIME_DELTA = 51
FATTR4_TIME_METADATA = 52
FATTR4_TIME_MODIFY = 53
FATTR4_TIME_MODIFY_SET = 54
FATTR4_MOUNTED_ON_FILEID = 55
FATTR4_DIR_NOTIF_DELAY = 56
FATTR4_DIRENT_NOTIF_DELAY = 57
FATTR4_DACL = 58
FATTR4_SACL = 59
FATTR4_CHANGE_POLICY = 60
FATTR4_FS_STATUS = 61
FATTR4_FS_LAYOUT_TYPES = 62
FATTR4_LAYOUT_HINT = 63
FATTR4_LAYOUT_TYPES = 64
FATTR4_LAYOUT_BLKSIZE = 65
FATTR4_LAYOUT_ALIGNMENT = 66
FATTR4_FS_LOCATIONS_INFO = 67
FATTR4_MDSTHRESHOLD = 68
FATTR4_RETENTION_GET = 69
FATTR4_RETENTION_SET = 70
FATTR4_RETENTEVT_GET = 71
FATTR4_RETENTEVT_SET = 72
FATTR4_RETENTION_HOLD = 73
FATTR4_MODE_SET_MASKED = 74
FATTR4_SUPPATTR_EXCLCREAT = 75
FATTR4_FS_CHARSET_CAP = 76
FATTR4_CLONE_BLKSIZE = 77
FATTR4_SPACE_FREED = 78
FATTR4_CHANGE_ATTR_TYPE = 79
FATTR4_SEC_LABEL = 80
FATTR4_MODE_UMASK = 81
FATTR4_XATTR_SUPPORT = 82

# NFS4_CONTENT_DATA / NFS4_CONTENT_HOLE (RFC 7862 15.10).
NFS4_CONTENT_DATA = 0
NFS4_CONTENT_HOLE = 1
NFS4_UINT64_MAX = 0xffffffffffffffff

OPEN4_RESULT_CONFIRM = 2

CREATE_SESSION4_FLAG_CONN_BACK_CHAN = 1
EXCHGID4_FLAG_USE_PNFS_MDS = 0x20000

ANON_STATEID = (0, b"\0" * 12)
BYPASS_STATEID = (0xffffffff, b"\xff" * 12)


def pack_stateid(p, sid):
    seq, other = sid
    p.uint32(seq)
    p.opaque_fixed(other)


def unpack_stateid(u):
    return (u.uint32(), u.opaque_fixed(12))


def pack_bitmap(p, attrs):
    words = []
    for a in attrs:
        w = a // 32
        while len(words) <= w:
            words.append(0)
        words[w] |= 1 << (a % 32)
    p.uint32(len(words))
    for w in words:
        p.uint32(w)


def unpack_bitmap(u):
    n = u.uint32()
    attrs = []
    for w in range(n):
        word = u.uint32()
        for b in range(32):
            if word & (1 << b):
                attrs.append(w * 32 + b)
    return attrs


def pack_fattr(p, mode=None, size=None):
    """fattr4 restricted to what the model sets (mode and/or size)."""
    attrs = []
    ap = Packer()
    # Attribute data must be packed in ascending attribute order.
    if size is not None:
        attrs.append(FATTR4_SIZE)
        ap.uint64(size)
    if mode is not None:
        attrs.append(FATTR4_MODE)
        ap.uint32(mode)
    pack_bitmap(p, attrs)
    p.opaque_var(bytes(ap.buf))


def _u_time(u):
    return (u.uint64(), u.uint32())      # nfstime4: seconds (int64) + nseconds


def _u_ace_list(u):
    aces = []
    for _ in range(u.uint32()):
        aces.append({"type": u.uint32(), "flag": u.uint32(),
                     "mask": u.uint32(), "who": u.opaque_var()})
    return aces


def _u_acl41(u):
    return {"flag": u.uint32(), "aces": _u_ace_list(u)}


def _u_u32_list(u):
    return [u.uint32() for _ in range(u.uint32())]


# Decoders for every attribute the harness may request.  The wide GETATTR
# (RGetattrWide) asks for the intersection of the server's supported_attrs and
# this table, so a reply never carries an attribute the harness cannot walk
# past.  Attributes with a complex body nobody here needs (fs_locations,
# fs_status, layout_hint, fs_locations_info, mdsthreshold, the retention set,
# sec_label) are deliberately absent, as are the set-only ones (the *_SET
# times, mode_set_masked, mode_umask) and rdattr_error, which only READDIR
# may return.
_ATTR_DECODERS = {
    FATTR4_SUPPORTED_ATTRS: unpack_bitmap,
    FATTR4_TYPE: lambda u: u.uint32(),
    FATTR4_FH_EXPIRE_TYPE: lambda u: u.uint32(),
    FATTR4_CHANGE: lambda u: u.uint64(),
    FATTR4_SIZE: lambda u: u.uint64(),
    FATTR4_LINK_SUPPORT: lambda u: u.boolean(),
    FATTR4_SYMLINK_SUPPORT: lambda u: u.boolean(),
    FATTR4_NAMED_ATTR: lambda u: u.boolean(),
    FATTR4_FSID: lambda u: (u.uint64(), u.uint64()),
    FATTR4_UNIQUE_HANDLES: lambda u: u.boolean(),
    FATTR4_LEASE_TIME: lambda u: u.uint32(),
    FATTR4_ACL: _u_ace_list,
    FATTR4_ACLSUPPORT: lambda u: u.uint32(),
    FATTR4_ARCHIVE: lambda u: u.boolean(),
    FATTR4_CANSETTIME: lambda u: u.boolean(),
    FATTR4_CASE_INSENSITIVE: lambda u: u.boolean(),
    FATTR4_CASE_PRESERVING: lambda u: u.boolean(),
    FATTR4_CHOWN_RESTRICTED: lambda u: u.boolean(),
    FATTR4_FILEHANDLE: lambda u: u.opaque_var(),
    FATTR4_FILEID: lambda u: u.uint64(),
    FATTR4_FILES_AVAIL: lambda u: u.uint64(),
    FATTR4_FILES_FREE: lambda u: u.uint64(),
    FATTR4_FILES_TOTAL: lambda u: u.uint64(),
    FATTR4_HIDDEN: lambda u: u.boolean(),
    FATTR4_HOMOGENEOUS: lambda u: u.boolean(),
    FATTR4_MAXFILESIZE: lambda u: u.uint64(),
    FATTR4_MAXLINK: lambda u: u.uint32(),
    FATTR4_MAXNAME: lambda u: u.uint32(),
    FATTR4_MAXREAD: lambda u: u.uint64(),
    FATTR4_MAXWRITE: lambda u: u.uint64(),
    FATTR4_MIMETYPE: lambda u: u.opaque_var(),
    FATTR4_MODE: lambda u: u.uint32(),
    FATTR4_NO_TRUNC: lambda u: u.boolean(),
    FATTR4_NUMLINKS: lambda u: u.uint32(),
    FATTR4_OWNER: lambda u: u.opaque_var(),
    FATTR4_OWNER_GROUP: lambda u: u.opaque_var(),
    FATTR4_QUOTA_AVAIL_HARD: lambda u: u.uint64(),
    FATTR4_QUOTA_AVAIL_SOFT: lambda u: u.uint64(),
    FATTR4_QUOTA_USED: lambda u: u.uint64(),
    FATTR4_RAWDEV: lambda u: (u.uint32(), u.uint32()),
    FATTR4_SPACE_AVAIL: lambda u: u.uint64(),
    FATTR4_SPACE_FREE: lambda u: u.uint64(),
    FATTR4_SPACE_TOTAL: lambda u: u.uint64(),
    FATTR4_SPACE_USED: lambda u: u.uint64(),
    FATTR4_SYSTEM: lambda u: u.boolean(),
    FATTR4_TIME_ACCESS: _u_time,
    FATTR4_TIME_BACKUP: _u_time,
    FATTR4_TIME_CREATE: _u_time,
    FATTR4_TIME_DELTA: _u_time,
    FATTR4_TIME_METADATA: _u_time,
    FATTR4_TIME_MODIFY: _u_time,
    FATTR4_MOUNTED_ON_FILEID: lambda u: u.uint64(),
    FATTR4_DIR_NOTIF_DELAY: _u_time,
    FATTR4_DIRENT_NOTIF_DELAY: _u_time,
    FATTR4_DACL: _u_acl41,
    FATTR4_SACL: _u_acl41,
    FATTR4_CHANGE_POLICY: lambda u: u.uint64(),
    FATTR4_FS_LAYOUT_TYPES: _u_u32_list,
    FATTR4_LAYOUT_TYPES: _u_u32_list,
    FATTR4_LAYOUT_BLKSIZE: lambda u: u.uint32(),
    FATTR4_LAYOUT_ALIGNMENT: lambda u: u.uint32(),
    FATTR4_RETENTION_HOLD: lambda u: u.uint64(),
    FATTR4_SUPPATTR_EXCLCREAT: unpack_bitmap,
    FATTR4_FS_CHARSET_CAP: lambda u: u.uint32(),
    FATTR4_CLONE_BLKSIZE: lambda u: u.uint32(),
    FATTR4_SPACE_FREED: lambda u: u.uint64(),
    FATTR4_CHANGE_ATTR_TYPE: lambda u: u.uint32(),
    FATTR4_XATTR_SUPPORT: lambda u: u.boolean(),
}

# What a wide request may ask for: everything decodable above.
WIDE_ATTRS = sorted(_ATTR_DECODERS)


def unpack_fattr(u):
    """Decode a fattr4 into {attr number: value}.

    The value blob is positional in ascending attribute order, so an
    attribute without a decoder ends the walk: whatever follows is kept
    under the key "raw" rather than misread as the next attribute.  A reply
    can only carry attributes the request asked for, and every request here
    is built from _ATTR_DECODERS, so "raw" is a server-side surprise worth
    seeing rather than a crash.
    """
    attrs = unpack_bitmap(u)
    au = Unpacker(u.opaque_var())
    out = {}
    for a in attrs:
        dec = _ATTR_DECODERS.get(a)
        if dec is None:
            out["raw"] = au.data[au.pos:]
            out["undecoded"] = a
            return out
        out[a] = dec(au)
    au.done()
    return out


def unpack_cinfo(u):
    return {"atomic": u.boolean(), "before": u.uint64(), "after": u.uint64()}


# ---------------------------------------------------------------------------
# Per-op argument encoders: each returns the fully packed nfs_argop4.
# ---------------------------------------------------------------------------

def _op(opnum):
    p = Packer()
    p.uint32(opnum)
    return p


def _done(p):
    return bytes(p.buf)


def enc_putrootfh():
    return _done(_op(OP_PUTROOTFH))


def enc_putfh(fh):
    p = _op(OP_PUTFH)
    p.opaque_var(fh)
    return _done(p)


def enc_getfh():
    return _done(_op(OP_GETFH))


def enc_savefh():
    return _done(_op(OP_SAVEFH))


def enc_restorefh():
    return _done(_op(OP_RESTOREFH))


def enc_lookup(name):
    p = _op(OP_LOOKUP)
    p.string(name)
    return _done(p)


def enc_lookupp():
    return _done(_op(OP_LOOKUPP))


def enc_getattr(attrs):
    p = _op(OP_GETATTR)
    pack_bitmap(p, attrs)
    return _done(p)


def enc_readlink():
    return _done(_op(OP_READLINK))


def enc_access(mask):
    p = _op(OP_ACCESS)
    p.uint32(mask)
    return _done(p)


def enc_readdir(dircount=65536, maxcount=1048576, attrs=()):
    p = _op(OP_READDIR)
    p.uint64(0)                       # cookie
    p.opaque_fixed(b"\0" * 8)         # cookieverf
    p.uint32(dircount)
    p.uint32(maxcount)
    pack_bitmap(p, list(attrs))
    return _done(p)


def enc_create(ftype, name, mode=None, linkdata=None):
    p = _op(OP_CREATE)
    p.uint32(ftype)
    if ftype == NF4LNK:
        p.string(linkdata)
    elif ftype in (NF4BLK, NF4CHR):
        p.uint32(0)
        p.uint32(0)
    p.string(name)
    pack_fattr(p, mode=mode)
    return _done(p)


def enc_remove(name):
    p = _op(OP_REMOVE)
    p.string(name)
    return _done(p)


def enc_rename(oldname, newname):
    p = _op(OP_RENAME)
    p.string(oldname)
    p.string(newname)
    return _done(p)


def enc_link(name):
    p = _op(OP_LINK)
    p.string(name)
    return _done(p)


def enc_setattr(sid, mode=None, size=None):
    p = _op(OP_SETATTR)
    pack_stateid(p, sid)
    pack_fattr(p, mode=mode, size=size)
    return _done(p)


def enc_verify_size(size, nverify=False):
    p = _op(OP_NVERIFY if nverify else OP_VERIFY)
    pack_fattr(p, size=size)
    return _done(p)


def enc_setclientid(verf, ident, cb_program=0x40000000,
                    netid="tcp", addr="0.0.0.0.0.0", cb_ident=1):
    p = _op(OP_SETCLIENTID)
    p.opaque_fixed(verf)
    p.opaque_var(ident)
    p.uint32(cb_program)
    p.string(netid)
    p.string(addr)
    p.uint32(cb_ident)
    return _done(p)


def enc_setclientid_confirm(clientid, confirm_verf):
    p = _op(OP_SETCLIENTID_CONFIRM)
    p.uint64(clientid)
    p.opaque_fixed(confirm_verf)
    return _done(p)


def enc_renew(clientid):
    p = _op(OP_RENEW)
    p.uint64(clientid)
    return _done(p)


def enc_release_lockowner(clientid, owner):
    p = _op(OP_RELEASE_LOCKOWNER)
    p.uint64(clientid)
    p.opaque_var(owner)
    return _done(p)


def enc_exchange_id(verf, ownerid, flags=0):
    p = _op(OP_EXCHANGE_ID)
    p.opaque_fixed(verf)
    p.opaque_var(ownerid)
    p.uint32(flags)
    p.uint32(0)                       # SP4_NONE
    p.uint32(0)                       # no client impl id
    return _done(p)


def enc_create_session(clientid, seq, back_chan, cb_program=0x40000000):
    p = _op(OP_CREATE_SESSION)
    p.uint64(clientid)
    p.uint32(seq)
    p.uint32(CREATE_SESSION4_FLAG_CONN_BACK_CHAN if back_chan else 0)
    for _ in range(2):                # fore and back channel attrs
        p.uint32(0)                   # headerpadsize
        p.uint32(1048576)             # maxrequestsize
        p.uint32(1048576)             # maxresponsesize
        p.uint32(65536)               # maxresponsesize_cached
        p.uint32(16)                  # maxoperations
        p.uint32(32)                  # maxrequests
        p.uint32(0)                   # no rdma_ird
    p.uint32(cb_program)
    p.uint32(1)                       # one callback sec_parms entry
    p.uint32(0)                       # AUTH_NONE
    return _done(p)


def enc_sequence(sessionid, slot, seq, cachethis, highest_slot=31):
    p = _op(OP_SEQUENCE)
    p.opaque_fixed(sessionid)
    p.uint32(seq)
    p.uint32(slot)
    p.uint32(highest_slot)
    p.boolean(cachethis)
    return _done(p)


def enc_destroy_session(sessionid):
    p = _op(OP_DESTROY_SESSION)
    p.opaque_fixed(sessionid)
    return _done(p)


def enc_destroy_clientid(clientid):
    p = _op(OP_DESTROY_CLIENTID)
    p.uint64(clientid)
    return _done(p)


def enc_reclaim_complete(one_fs=False):
    p = _op(OP_RECLAIM_COMPLETE)
    p.boolean(one_fs)
    return _done(p)


def enc_free_stateid(sid):
    p = _op(OP_FREE_STATEID)
    pack_stateid(p, sid)
    return _done(p)


def enc_open(seqid, access, deny, clientid, owner, openhow, claim):
    """openhow: None | ("UNCHECKED", mode, truncate) | ("GUARDED", mode)
               | ("EXCLUSIVE", verf8)
    claim:     ("NULL", name) | ("FH",)"""
    p = _op(OP_OPEN)
    p.uint32(seqid)
    p.uint32(access)
    p.uint32(deny)
    p.uint64(clientid)
    p.opaque_var(owner)
    if openhow is None:
        p.uint32(0)                   # OPEN4_NOCREATE
    else:
        p.uint32(1)                   # OPEN4_CREATE
        kind = openhow[0]
        if kind == "UNCHECKED":
            p.uint32(0)
            pack_fattr(p, mode=openhow[1],
                       size=0 if openhow[2] else None)
        elif kind == "GUARDED":
            p.uint32(1)
            pack_fattr(p, mode=openhow[1])
        else:
            p.uint32(2)               # EXCLUSIVE4
            p.opaque_fixed(openhow[1])
    if claim[0] == "NULL":
        p.uint32(0)                   # CLAIM_NULL
        p.string(claim[1])
    else:
        p.uint32(4)                   # CLAIM_FH
    return _done(p)


def enc_open_confirm(sid, seqid):
    p = _op(OP_OPEN_CONFIRM)
    pack_stateid(p, sid)
    p.uint32(seqid)
    return _done(p)


def enc_open_downgrade(sid, seqid, access, deny):
    p = _op(OP_OPEN_DOWNGRADE)
    pack_stateid(p, sid)
    p.uint32(seqid)
    p.uint32(access)
    p.uint32(deny)
    return _done(p)


def enc_close(seqid, sid):
    p = _op(OP_CLOSE)
    p.uint32(seqid)
    pack_stateid(p, sid)
    return _done(p)


def enc_read(sid, offset, count):
    p = _op(OP_READ)
    pack_stateid(p, sid)
    p.uint64(offset)
    p.uint32(count)
    return _done(p)


def enc_write(sid, offset, stable, data):
    p = _op(OP_WRITE)
    pack_stateid(p, sid)
    p.uint64(offset)
    p.uint32(stable)
    p.opaque_var(data)
    return _done(p)


def enc_commit(offset=0, count=0):
    p = _op(OP_COMMIT)
    p.uint64(offset)
    p.uint32(count)
    return _done(p)


def enc_lock(write_lock, reclaim, offset, length, new_owner,
             open_seqid=0, open_sid=None, lock_seqid=0,
             clientid=0, owner=b"", lock_sid=None):
    p = _op(OP_LOCK)
    p.uint32(2 if write_lock else 1)  # WRITE_LT / READ_LT
    p.boolean(reclaim)
    p.uint64(offset)
    p.uint64(length)
    p.boolean(new_owner)
    if new_owner:
        p.uint32(open_seqid)
        pack_stateid(p, open_sid)
        p.uint32(lock_seqid)
        p.uint64(clientid)
        p.opaque_var(owner)
    else:
        pack_stateid(p, lock_sid)
        p.uint32(lock_seqid)
    return _done(p)


def enc_lockt(write_lock, offset, length, clientid, owner):
    p = _op(OP_LOCKT)
    p.uint32(2 if write_lock else 1)
    p.uint64(offset)
    p.uint64(length)
    p.uint64(clientid)
    p.opaque_var(owner)
    return _done(p)


def enc_locku(seqid, sid, offset, length, write_lock=True):
    p = _op(OP_LOCKU)
    p.uint32(2 if write_lock else 1)
    p.uint32(seqid)
    pack_stateid(p, sid)
    p.uint64(offset)
    p.uint64(length)
    return _done(p)


def enc_delegreturn(sid):
    p = _op(OP_DELEGRETURN)
    pack_stateid(p, sid)
    return _done(p)


def enc_layoutget(iomode_rw, offset, length, sid, minlength=1,
                  maxcount=1048576):
    p = _op(OP_LAYOUTGET)
    p.boolean(False)                  # signal_layout_avail
    p.uint32(1)                       # LAYOUT4_NFSV4_1_FILES
    p.uint32(2 if iomode_rw else 1)   # LAYOUTIOMODE4_RW / READ
    p.uint64(offset)
    p.uint64(length)
    p.uint64(minlength)
    pack_stateid(p, sid)
    p.uint32(maxcount)
    return _done(p)


def enc_layoutreturn(sid, offset, length):
    p = _op(OP_LAYOUTRETURN)
    p.boolean(False)                  # reclaim
    p.uint32(1)                       # LAYOUT4_NFSV4_1_FILES
    p.uint32(3)                       # LAYOUTIOMODE4_ANY
    p.uint32(1)                       # LAYOUTRETURN4_FILE
    p.uint64(offset)
    p.uint64(length)
    pack_stateid(p, sid)
    p.opaque_var(b"")                 # lrf_body
    return _done(p)


def enc_layoutcommit(sid, offset, length, last_write_offset):
    p = _op(OP_LAYOUTCOMMIT)
    p.uint64(offset)
    p.uint64(length)
    p.boolean(False)                  # reclaim
    pack_stateid(p, sid)
    p.boolean(True)                   # newoffset: yes
    p.uint64(last_write_offset)
    p.uint32(0)                       # time_modify: server time
    p.uint32(1)                       # LAYOUT4_NFSV4_1_FILES (layoutupdate)
    p.opaque_var(b"")
    return _done(p)


def enc_getdeviceinfo(deviceid, maxcount=1048576):
    p = _op(OP_GETDEVICEINFO)
    p.opaque_fixed(deviceid)
    p.uint32(1)                       # LAYOUT4_NFSV4_1_FILES
    p.uint32(maxcount)
    p.uint32(0)                       # no notifications (empty bitmap)
    return _done(p)


def enc_allocate(sid, offset, length, deallocate=False):
    p = _op(OP_DEALLOCATE if deallocate else OP_ALLOCATE)
    pack_stateid(p, sid)
    p.uint64(offset)
    p.uint64(length)
    return _done(p)


def enc_seek(sid, offset, what_data):
    p = _op(OP_SEEK)
    pack_stateid(p, sid)
    p.uint64(offset)
    p.uint32(0 if what_data else 1)   # NFS4_CONTENT_DATA / _HOLE
    return _done(p)


def enc_copy(src_sid, dst_sid, src_off, dst_off, count):
    p = _op(OP_COPY)
    pack_stateid(p, src_sid)
    pack_stateid(p, dst_sid)
    p.uint64(src_off)
    p.uint64(dst_off)
    p.uint64(count)
    p.boolean(True)                   # ca_consecutive
    p.boolean(True)                   # ca_synchronous
    p.uint32(0)                       # no source servers (intra-server)
    return _done(p)


def enc_getxattr(name):
    p = _op(OP_GETXATTR)
    p.string(name)
    return _done(p)


def enc_setxattr(option, name, value):
    p = _op(OP_SETXATTR)
    p.uint32(option)                  # 0 EITHER / 1 CREATE / 2 REPLACE
    p.string(name)
    p.opaque_var(value)
    return _done(p)


def enc_listxattrs(maxcount=1048576):
    p = _op(OP_LISTXATTRS)
    p.uint64(0)                       # cookie
    p.uint32(maxcount)
    return _done(p)


def enc_removexattr(name):
    p = _op(OP_REMOVEXATTR)
    p.string(name)
    return _done(p)


def enc_secinfo(name):
    p = _op(OP_SECINFO)
    p.string(name)
    return _done(p)


def enc_bind_conn_to_session(sessionid, direction, rdma=False):
    p = _op(OP_BIND_CONN_TO_SESSION)
    p.opaque_fixed(sessionid)
    p.uint32(direction)
    p.boolean(rdma)
    return _done(p)


def enc_setattr_wide(sid, mode, owner=b"0", group=b"0"):
    """SETATTR carrying mode, owner, owner_group and both settable times
    (SET_TO_SERVER_TIME4), in ascending attribute order (RFC 7530 5):
    MODE(33), OWNER(36), OWNER_GROUP(37), TIME_ACCESS_SET(48),
    TIME_MODIFY_SET(54).  The model treats it as a mode-only SETATTR, so the
    owner and group name the identity the harness already runs as."""
    p = _op(OP_SETATTR)
    pack_stateid(p, sid)
    ap = Packer()
    ap.uint32(mode)
    ap.opaque_var(owner)
    ap.opaque_var(group)
    ap.uint32(0)                      # settime4: SET_TO_SERVER_TIME4
    ap.uint32(0)
    pack_bitmap(p, [FATTR4_MODE, FATTR4_OWNER, FATTR4_OWNER_GROUP,
                    FATTR4_TIME_ACCESS_SET, FATTR4_TIME_MODIFY_SET])
    p.opaque_var(bytes(ap.buf))
    return _done(p)


def enc_verify_wide(attrs, nverify=False):
    """VERIFY / NVERIFY with a wide attribute mask and an EMPTY value blob:
    the attributes cannot all be equal to nothing, so the answer is decided
    without predicting a single value (see opVerifyWide in the model)."""
    p = _op(OP_NVERIFY if nverify else OP_VERIFY)
    pack_bitmap(p, list(attrs))
    p.opaque_var(b"")
    return _done(p)


def enc_read_plus(sid, offset, count):
    p = _op(OP_READ_PLUS)
    pack_stateid(p, sid)
    p.uint64(offset)
    p.uint32(count)
    return _done(p)


def enc_io_advise(sid, offset, count, hints):
    p = _op(OP_IO_ADVISE)
    pack_stateid(p, sid)
    p.uint64(offset)
    p.uint64(count)
    pack_bitmap(p, list(hints))
    return _done(p)


def enc_write_same(sid, offset, block_size, block_count, pattern,
                   blocknum=False, stable=2):
    """WRITE_SAME (RFC 7862 15.13).  One ADB block is one pattern; the
    per-block-number stamping arm (adb_reloff_blocknum != NFS4_UINT64_MAX)
    is selected by `blocknum` and is the unsupported union arm."""
    p = _op(OP_WRITE_SAME)
    pack_stateid(p, sid)
    p.uint32(stable)
    p.uint64(offset)                  # adb_offset
    p.uint64(block_size)              # adb_block_size
    p.uint64(block_count)             # adb_block_count
    p.uint64(0 if blocknum else NFS4_UINT64_MAX)   # adb_reloff_blocknum
    p.uint64(0)                       # adb_block_num
    p.uint64(0)                       # adb_reloff_pattern
    p.opaque_var(pattern)             # adb_pattern
    return _done(p)


def enc_clone(src_sid, dst_sid, src_off, dst_off, count):
    p = _op(OP_CLONE)
    pack_stateid(p, src_sid)
    pack_stateid(p, dst_sid)
    p.uint64(src_off)
    p.uint64(dst_off)
    p.uint64(count)
    return _done(p)


def enc_illegal():
    return _done(_op(OP_ILLEGAL))


# ---------------------------------------------------------------------------
# Per-op result decoders: fn(u, status) -> dict of fields beyond "status".
# Only OK-path bodies are decoded unless the op defines an error body.
# ---------------------------------------------------------------------------

def _dec_void(u, st):
    return {}


def _dec_getfh(u, st):
    return {"fh": u.opaque_var()} if st == NFS4_OK else {}


def _dec_getattr(u, st):
    return {"attrs": unpack_fattr(u)} if st == NFS4_OK else {}


def _dec_readlink(u, st):
    return {"target": u.opaque_var().decode()} if st == NFS4_OK else {}


def _dec_access(u, st):
    if st != NFS4_OK:
        return {}
    return {"supported": u.uint32(), "access": u.uint32()}


def _dec_readdir(u, st):
    if st != NFS4_OK:
        return {}
    out = {"cookieverf": u.opaque_fixed(8), "entries": []}
    while u.boolean():
        e = {"cookie": u.uint64(), "name": u.opaque_var(),
             "attrs": unpack_fattr(u)}
        out["entries"].append(e)
    out["eof"] = u.boolean()
    return out


def _dec_create(u, st):
    if st != NFS4_OK:
        return {}
    return {"cinfo": unpack_cinfo(u), "attrset": unpack_bitmap(u)}


def _dec_remove(u, st):
    return {"cinfo": unpack_cinfo(u)} if st == NFS4_OK else {}


def _dec_rename(u, st):
    if st != NFS4_OK:
        return {}
    return {"source_cinfo": unpack_cinfo(u), "target_cinfo": unpack_cinfo(u)}


def _dec_link(u, st):
    return {"cinfo": unpack_cinfo(u)} if st == NFS4_OK else {}


def _dec_setattr(u, st):
    # attrsset follows in BOTH success and failure cases (RFC 7530 16.32).
    return {"attrsset": unpack_bitmap(u)}


def _dec_setclientid(u, st):
    if st == NFS4_OK:
        return {"clientid": u.uint64(), "confirm": u.opaque_fixed(8)}
    if st == 10017:                   # NFS4ERR_CLID_INUSE
        return {"netid": u.opaque_var(), "addr": u.opaque_var()}
    return {}


def _dec_exchange_id(u, st):
    if st != NFS4_OK:
        return {}
    out = {"clientid": u.uint64(), "sequenceid": u.uint32(),
           "flags": u.uint32()}
    sp = u.uint32()                   # state_protect4_r
    if sp != 0:
        raise XdrError(f"unexpected state protection {sp}")
    out["server_owner_minor"] = u.uint64()
    out["server_owner_major"] = u.opaque_var()
    out["server_scope"] = u.opaque_var()
    n = u.uint32()                    # impl id array
    for _ in range(n):
        u.opaque_var()                # domain
        u.opaque_var()                # name
        u.uint64()                    # date seconds
        u.uint32()                    # date nseconds
    return out


def _dec_create_session(u, st):
    if st != NFS4_OK:
        return {}
    out = {"sessionid": u.opaque_fixed(16), "sequenceid": u.uint32(),
           "flags": u.uint32()}
    for chan in ("fore", "back"):
        attrs = {"headerpad": u.uint32(), "maxreq": u.uint32(),
                 "maxresp": u.uint32(), "maxresp_cached": u.uint32(),
                 "maxops": u.uint32(), "maxreqs": u.uint32()}
        n = u.uint32()
        for _ in range(n):
            u.uint32()
        out[chan] = attrs
    return out


def _dec_sequence(u, st):
    if st != NFS4_OK:
        return {}
    return {"sessionid": u.opaque_fixed(16), "seq": u.uint32(),
            "slot": u.uint32(), "highest": u.uint32(),
            "target_highest": u.uint32(), "status_flags": u.uint32()}


def _dec_open(u, st):
    if st != NFS4_OK:
        return {}
    out = {"stateid": unpack_stateid(u), "cinfo": unpack_cinfo(u),
           "rflags": u.uint32(), "attrset": unpack_bitmap(u)}
    dt = u.uint32()
    out["deleg_type"] = dt
    if dt in (1, 2):                  # READ / WRITE
        out["deleg_stateid"] = unpack_stateid(u)
        out["deleg_recall"] = u.boolean()
        if dt == 2:
            limit = u.uint32()        # nfs_space_limit4
            if limit == 1:
                u.uint64()            # filesize
            else:
                u.uint32()            # num_blocks
                u.uint32()            # bytes_per_block
        # nfsace4
        u.uint32()
        u.uint32()
        u.uint32()
        u.opaque_var()
    elif dt != 0:
        raise XdrError(f"unexpected delegation type {dt}")
    return out


def _dec_open_confirm(u, st):
    return {"stateid": unpack_stateid(u)} if st == NFS4_OK else {}


def _dec_close(u, st):
    return {"stateid": unpack_stateid(u)} if st == NFS4_OK else {}


def _dec_read(u, st):
    if st != NFS4_OK:
        return {}
    return {"eof": u.boolean(), "data": u.opaque_var()}


def _dec_write(u, st):
    if st != NFS4_OK:
        return {}
    return {"count": u.uint32(), "committed": u.uint32(),
            "verf": u.opaque_fixed(8)}


def _dec_commit(u, st):
    return {"verf": u.opaque_fixed(8)} if st == NFS4_OK else {}


def _dec_denied(u):
    d = {"offset": u.uint64(), "length": u.uint64(),
         "locktype": u.uint32(), "clientid": u.uint64(),
         "owner": u.opaque_var()}
    return d


def _dec_lock(u, st):
    if st == NFS4_OK:
        return {"stateid": unpack_stateid(u)}
    if st == 10010:                   # NFS4ERR_DENIED
        return {"denied": _dec_denied(u)}
    return {}


def _dec_lockt(u, st):
    if st == 10010:
        return {"denied": _dec_denied(u)}
    return {}


def _dec_locku(u, st):
    return {"stateid": unpack_stateid(u)} if st == NFS4_OK else {}


def _dec_layoutget(u, st):
    if st == 10058:                   # LAYOUTTRYLATER carries a bool
        return {"signal": u.boolean()}
    if st != NFS4_OK:
        return {}
    out = {"return_on_close": u.boolean(), "stateid": unpack_stateid(u),
           "segments": []}
    n = u.uint32()
    for _ in range(n):
        seg = {"offset": u.uint64(), "length": u.uint64(),
               "iomode": u.uint32(), "type": u.uint32()}
        body = Unpacker(u.opaque_var())
        if seg["type"] == 1:          # files layout: extract the deviceid
            seg["deviceid"] = body.opaque_fixed(16)
            seg["nfl_util"] = body.uint32()
            body.uint32()             # first_stripe_index
            body.uint64()             # pattern_offset
            fhn = body.uint32()
            seg["fhs"] = [body.opaque_var() for _ in range(fhn)]
        out["segments"].append(seg)
    return out


def _dec_layoutreturn(u, st):
    if st != NFS4_OK:
        return {}
    present = u.boolean()
    out = {"present": present}
    if present:
        out["stateid"] = unpack_stateid(u)
    return out


def _dec_layoutcommit(u, st):
    if st != NFS4_OK:
        return {}
    has = u.boolean()
    return {"newsize": u.uint64() if has else None}


def _dec_getdeviceinfo(u, st):
    if st != NFS4_OK:
        return {}
    out = {"type": u.uint32(), "body": u.opaque_var()}
    unpack_bitmap(u)                  # notification bitmap
    return out


def _dec_seek(u, st):
    if st != NFS4_OK:
        return {}
    return {"eof": u.boolean(), "offset": u.uint64()}


def _dec_write_response(u):
    """write_response4 (RFC 7862 15.2.3): optional callback stateid, then
    the count (a length4, 64 bits), stable_how4 and the verifier."""
    n = u.uint32()                    # wr_callback_id<1> (async only)
    for _ in range(n):
        unpack_stateid(u)
    return {"count": u.uint64(), "committed": u.uint32(),
            "verf": u.opaque_fixed(8)}


def _dec_copy(u, st):
    if st != NFS4_OK:
        return {"bytes_copied": u.uint64()}
    out = _dec_write_response(u)
    out["consecutive"] = u.boolean()
    out["synchronous"] = u.boolean()
    return out


def _dec_write_same(u, st):
    return _dec_write_response(u) if st == NFS4_OK else {}


def _dec_read_plus(u, st):
    """read_plus_res4: eof + a list of DATA/HOLE segments."""
    if st != NFS4_OK:
        return {}
    out = {"eof": u.boolean(), "segments": []}
    for _ in range(u.uint32()):
        kind = u.uint32()
        if kind == NFS4_CONTENT_DATA:
            off = u.uint64()
            data = u.opaque_var()
            out["segments"].append({"is_data": True, "offset": off,
                                    "length": len(data), "data": data})
        elif kind == NFS4_CONTENT_HOLE:
            out["segments"].append({"is_data": False, "offset": u.uint64(),
                                    "length": u.uint64(), "data": None})
        else:
            raise XdrError(f"read_plus: unknown content type {kind}")
    return out


def _dec_io_advise(u, st):
    return {"hints": unpack_bitmap(u)} if st == NFS4_OK else {}


def _dec_secinfo(u, st):
    if st != NFS4_OK:
        return {}
    flavors = []
    for _ in range(u.uint32()):
        flavor = u.uint32()
        if flavor == 6:               # RPCSEC_GSS
            flavors.append({"flavor": flavor, "oid": u.opaque_var(),
                            "qop": u.uint32(), "service": u.uint32()})
        else:
            flavors.append({"flavor": flavor})
    return {"flavors": flavors}


def _dec_bind_conn_to_session(u, st):
    if st != NFS4_OK:
        return {}
    return {"sessionid": u.opaque_fixed(16), "dir": u.uint32(),
            "rdma": u.boolean()}


def _dec_getxattr(u, st):
    return {"value": u.opaque_var()} if st == NFS4_OK else {}


def _dec_setxattr(u, st):
    return {"cinfo": unpack_cinfo(u)} if st == NFS4_OK else {}


def _dec_listxattrs(u, st):
    if st != NFS4_OK:
        return {}
    out = {"cookie": u.uint64(), "names": []}
    n = u.uint32()
    for _ in range(n):
        out["names"].append(u.opaque_var().decode())
    out["eof"] = u.boolean()
    return out


DECODERS = {
    OP_ACCESS: _dec_access,
    OP_CLOSE: _dec_close,
    OP_COMMIT: _dec_commit,
    OP_CREATE: _dec_create,
    OP_DELEGRETURN: _dec_void,
    OP_GETATTR: _dec_getattr,
    OP_GETFH: _dec_getfh,
    OP_LINK: _dec_link,
    OP_LOCK: _dec_lock,
    OP_LOCKT: _dec_lockt,
    OP_LOCKU: _dec_locku,
    OP_LOOKUP: _dec_void,
    OP_LOOKUPP: _dec_void,
    OP_NVERIFY: _dec_void,
    OP_OPEN: _dec_open,
    OP_OPEN_CONFIRM: _dec_open_confirm,
    OP_OPEN_DOWNGRADE: _dec_open_confirm,
    OP_PUTFH: _dec_void,
    OP_PUTROOTFH: _dec_void,
    OP_READ: _dec_read,
    OP_READDIR: _dec_readdir,
    OP_READLINK: _dec_readlink,
    OP_REMOVE: _dec_remove,
    OP_RENAME: _dec_rename,
    OP_RENEW: _dec_void,
    OP_RESTOREFH: _dec_void,
    OP_SAVEFH: _dec_void,
    OP_SETATTR: _dec_setattr,
    OP_SETCLIENTID: _dec_setclientid,
    OP_SETCLIENTID_CONFIRM: _dec_void,
    OP_VERIFY: _dec_void,
    OP_WRITE: _dec_write,
    OP_RELEASE_LOCKOWNER: _dec_void,
    OP_EXCHANGE_ID: _dec_exchange_id,
    OP_CREATE_SESSION: _dec_create_session,
    OP_DESTROY_SESSION: _dec_void,
    OP_FREE_STATEID: _dec_void,
    OP_GETDEVICEINFO: _dec_getdeviceinfo,
    OP_LAYOUTCOMMIT: _dec_layoutcommit,
    OP_LAYOUTGET: _dec_layoutget,
    OP_LAYOUTRETURN: _dec_layoutreturn,
    OP_SEQUENCE: _dec_sequence,
    OP_DESTROY_CLIENTID: _dec_void,
    OP_RECLAIM_COMPLETE: _dec_void,
    OP_ALLOCATE: _dec_void,
    OP_COPY: _dec_copy,
    OP_DEALLOCATE: _dec_void,
    OP_SEEK: _dec_seek,
    OP_GETXATTR: _dec_getxattr,
    OP_SETXATTR: _dec_setxattr,
    OP_LISTXATTRS: _dec_listxattrs,
    OP_REMOVEXATTR: _dec_setxattr,
    OP_SECINFO: _dec_secinfo,
    OP_BIND_CONN_TO_SESSION: _dec_bind_conn_to_session,
    OP_READ_PLUS: _dec_read_plus,
    OP_IO_ADVISE: _dec_io_advise,
    OP_WRITE_SAME: _dec_write_same,
    OP_CLONE: _dec_void,
    OP_ILLEGAL: _dec_void,
}


class Nfs4Client:
    """NFSv4 COMPOUND transport with backchannel awareness.

    Incoming RPC CALLs on this connection (the 4.1 backchannel) are
    answered inline: CB_SEQUENCE and CB_RECALL/CB_LAYOUTRECALL succeed and
    the recalled stateids are appended to self.recalls; other callback ops
    get NFS4ERR_NOTSUPP.  The harness drains self.recalls to satisfy the
    model's SOpen.recalls contract.
    """

    def __init__(self, host, port=2049, **kw):
        self.rpc = RpcClient(host, port, NFS_PROGRAM, NFS_V4, **kw)
        self.recalls = []             # [(op, stateid-or-range-info)]
        self.cb_slots = {}            # backchannel slot -> seqid
        self.cb_calls = 0             # backchannel CALLs answered (any proc)

    def drain_backchannel(self, wait=0.0):
        """Answer backchannel CALLs that arrived while no request was in
        flight (a CB_NULL probe after CREATE_SESSION, a CB_RECALL raised by
        another client's conflicting OPEN).  Returns how many were answered.
        `wait` is how long to sit on an idle socket before giving up."""
        n = 0
        sock = self.rpc.sock
        old = sock.gettimeout()
        try:
            sock.settimeout(wait if wait > 0 else 0.0)
            while True:
                try:
                    record = self.rpc._recv_record()
                except (socket.timeout, BlockingIOError):
                    break
                u = Unpacker(record)
                u.uint32()            # xid
                if u.uint32() != 0:   # not a CALL: a stray reply
                    raise RpcError("unsolicited RPC reply on the connection")
                self._answer_cb(record)
                n += 1
                sock.settimeout(0.0)
        finally:
            sock.settimeout(old)
        return n

    def close(self):
        self.rpc.close()

    def null(self):
        self.rpc.call(0).done()

    # -- backchannel ------------------------------------------------------

    def _cb_reply_body(self, u):
        """Decode one CB_COMPOUND call body, produce the reply results."""
        u.opaque_var()                # utf8 tag
        u.uint32()                    # minorversion
        u.uint32()                    # callback_ident
        nops = u.uint32()
        rp = Packer()
        results = 0
        status = NFS4_OK
        for _ in range(nops):
            op = u.uint32()
            if op == OP_CB_SEQUENCE:
                sessionid = u.opaque_fixed(16)
                seq = u.uint32()
                slot = u.uint32()
                high = u.uint32()
                u.boolean()           # cachethis
                nrefs = u.uint32()
                for _ in range(nrefs):
                    u.opaque_fixed(16)
                    nlist = u.uint32()
                    for _ in range(nlist):
                        u.uint32()
                        u.uint32()
                self.cb_slots[slot] = seq
                rp.uint32(op)
                rp.uint32(NFS4_OK)
                rp.opaque_fixed(sessionid)
                rp.uint32(seq)
                rp.uint32(slot)
                rp.uint32(high)
                rp.uint32(high)
                results += 1
            elif op == OP_CB_RECALL:
                sid = unpack_stateid(u)
                u.boolean()           # truncate
                u.opaque_var()        # fh
                self.recalls.append(("CB_RECALL", sid))
                rp.uint32(op)
                rp.uint32(NFS4_OK)
                results += 1
            elif op == OP_CB_LAYOUTRECALL:
                u.uint32()            # layout type
                u.uint32()            # iomode
                u.boolean()           # changed
                rtype = u.uint32()
                if rtype == 1:        # LAYOUTRECALL4_FILE
                    fh = u.opaque_var()
                    u.uint64()        # offset
                    u.uint64()        # length
                    sid = unpack_stateid(u)
                    self.recalls.append(("CB_LAYOUTRECALL", sid))
                else:
                    self.recalls.append(("CB_LAYOUTRECALL", None))
                rp.uint32(op)
                rp.uint32(NFS4_OK)
                results += 1
            else:
                rp.uint32(op)
                rp.uint32(10004)      # NFS4ERR_NOTSUPP
                results += 1
                status = 10004
                break
        body = Packer()
        body.uint32(status)
        body.opaque_var(b"")          # tag
        body.uint32(results)
        body.buf += rp.buf
        return bytes(body.buf)


    def _answer_cb(self, record):
        u = Unpacker(record)
        xid = u.uint32()
        mtype = u.uint32()
        assert mtype == 0             # CALL
        u.uint32()                    # rpcvers
        u.uint32()                    # prog (the cb_program we registered)
        u.uint32()                    # vers
        proc = u.uint32()
        for _ in range(2):            # cred, verf
            u.uint32()
            u.opaque_var()
        self.cb_calls += 1
        rep = Packer()
        rep.uint32(xid)
        rep.uint32(1)                 # REPLY
        rep.uint32(0)                 # MSG_ACCEPTED
        rep.uint32(0)                 # verf AUTH_NONE
        rep.uint32(0)
        rep.uint32(0)                 # SUCCESS
        if proc == 1:                 # CB_COMPOUND
            rep.buf += self._cb_reply_body(u)
        self.rpc._send_record(bytes(rep.buf))

    def _call_v4(self, args):
        """Like RpcClient.call but services backchannel CALLs that arrive
        while waiting for the reply."""
        rpc = self.rpc
        rpc.xid += 1
        p = Packer()
        p.uint32(rpc.xid)
        p.uint32(0)                   # CALL
        p.uint32(2)
        p.uint32(rpc.prog)
        p.uint32(rpc.vers)
        p.uint32(NFSPROC4_COMPOUND)
        p.uint32(1)                   # AUTH_SYS
        p.opaque_var(rpc._cred_auth_sys())
        p.uint32(0)
        p.uint32(0)
        p.buf += args
        rpc._send_record(bytes(p.buf))

        while True:
            record = rpc._recv_record()
            u = Unpacker(record)
            xid = u.uint32()
            mtype = u.uint32()
            if mtype == 0:            # backchannel CALL
                self._answer_cb(record)
                continue
            if xid != rpc.xid:
                raise RpcError(f"xid mismatch: sent {rpc.xid:#x}, "
                               f"got {xid:#x}")
            if u.uint32() != 0:       # MSG_ACCEPTED
                raise RpcError("RPC call denied")
            u.uint32()
            u.opaque_var()
            accept = u.uint32()
            if accept != 0:
                raise RpcError(f"RPC accept_stat {accept}")
            return u

    # -- compound ---------------------------------------------------------

    def compound(self, minorversion, encoded_ops, tag=b""):
        """Send one COMPOUND.  Returns {status, tag, results, raw} where
        results is one {op, status, ...fields} per executed op and raw is
        the undecoded COMPOUND4res (for the SEQUENCE replay-cache
        contract)."""
        p = Packer()
        p.opaque_var(tag)
        p.uint32(minorversion)
        p.uint32(len(encoded_ops))
        for op in encoded_ops:
            p.buf += op
        u = self._call_v4(bytes(p.buf))
        raw = u.data[u.pos:]

        status = u.uint32()
        rtag = u.opaque_var()
        nres = u.uint32()
        results = []
        for _ in range(nres):
            opnum = u.uint32()
            opstatus = u.uint32()
            dec = DECODERS.get(opnum)
            if dec is None:
                raise XdrError(f"no decoder for op {opnum}")
            fields = dec(u, opstatus)
            fields["op"] = opnum
            fields["status"] = opstatus
            results.append(fields)
        u.done()
        return {"status": status, "tag": rtag, "results": results,
                "raw": raw}
