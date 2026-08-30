# SPDX-FileCopyrightText: 2026 The Quint Specs Authors
#
# SPDX-License-Identifier: MIT

"""Minimal standalone NFSv3 + MOUNTv3 (+ PORTMAP GETPORT) client used by the
NFS conformance harness (nfs3_replay.py; nfs4_client.py builds on the RPC
layer here).

This is a deliberately independent implementation of ONC RPC (RFC 5531),
XDR (RFC 4506) and the NFSv3 wire protocol (RFC 1813): it shares no code
with any server's generated marshalling, so an encoding bug on either side
shows up as a divergence instead of cancelling itself out.  The pynfs
project's rpc layer was used as a reference, but nothing here imports it.

Only the procedures the Quint model exercises are implemented; extend
per-procedure as the model grows.
"""

import socket
import struct

# nfsstat3 (RFC 1813 2.6)
NFS3_OK = 0
NFS3ERR_NOENT = 2
NFS3ERR_NOTDIR = 20
NFS3ERR_EXIST = 17
NFS3ERR_NOTEMPTY = 66
NFS3ERR_STALE = 70

# ftype3
NF3REG = 1
NF3DIR = 2
NF3BLK = 3
NF3CHR = 4
NF3LNK = 5
NF3SOCK = 6
NF3FIFO = 7

# ACCESS3 bits
ACCESS3_READ = 0x0001
ACCESS3_LOOKUP = 0x0002
ACCESS3_MODIFY = 0x0004
ACCESS3_EXTEND = 0x0008
ACCESS3_DELETE = 0x0010
ACCESS3_EXECUTE = 0x0020

# stable_how
UNSTABLE = 0
DATA_SYNC = 1
FILE_SYNC = 2

# createmode3
UNCHECKED = 0
GUARDED = 1
EXCLUSIVE = 2

NFS_PROGRAM = 100003
MOUNT_PROGRAM = 100005

NFSPROC3_NULL = 0
NFSPROC3_GETATTR = 1
NFSPROC3_SETATTR = 2
NFSPROC3_LOOKUP = 3
NFSPROC3_ACCESS = 4
NFSPROC3_READLINK = 5
NFSPROC3_READ = 6
NFSPROC3_WRITE = 7
NFSPROC3_CREATE = 8
NFSPROC3_MKDIR = 9
NFSPROC3_SYMLINK = 10
NFSPROC3_MKNOD = 11
NFSPROC3_REMOVE = 12
NFSPROC3_RMDIR = 13
NFSPROC3_RENAME = 14
NFSPROC3_LINK = 15
NFSPROC3_READDIR = 16
NFSPROC3_READDIRPLUS = 17
NFSPROC3_FSSTAT = 18
NFSPROC3_FSINFO = 19
NFSPROC3_PATHCONF = 20
NFSPROC3_COMMIT = 21

MOUNTPROC3_NULL = 0
MOUNTPROC3_MNT = 1


class XdrError(Exception):
    pass


class RpcError(Exception):
    pass


class Packer:
    def __init__(self):
        self.buf = bytearray()

    def uint32(self, v):
        self.buf += struct.pack(">I", v & 0xffffffff)

    def uint64(self, v):
        self.buf += struct.pack(">Q", v & 0xffffffffffffffff)

    def boolean(self, v):
        self.uint32(1 if v else 0)

    def opaque_fixed(self, b):
        self.buf += b
        self.buf += b"\0" * ((4 - len(b) % 4) % 4)

    def opaque_var(self, b):
        self.uint32(len(b))
        self.opaque_fixed(b)

    def string(self, s):
        self.opaque_var(s.encode() if isinstance(s, str) else s)


class Unpacker:
    def __init__(self, data):
        self.data = data
        self.pos = 0

    def _take(self, n):
        if self.pos + n > len(self.data):
            raise XdrError(f"XDR underrun: need {n} bytes at offset {self.pos}, "
                           f"have {len(self.data)}")
        b = self.data[self.pos:self.pos + n]
        self.pos += n
        return b

    def uint32(self):
        return struct.unpack(">I", self._take(4))[0]

    def uint64(self):
        return struct.unpack(">Q", self._take(8))[0]

    def boolean(self):
        v = self.uint32()
        if v not in (0, 1):
            raise XdrError(f"bad XDR bool {v}")
        return bool(v)

    def opaque_fixed(self, n):
        b = self._take(n)
        self._take((4 - n % 4) % 4)
        return b

    def opaque_var(self):
        return self.opaque_fixed(self.uint32())

    def done(self):
        if self.pos != len(self.data):
            raise XdrError(f"{len(self.data) - self.pos} trailing reply bytes")


class RpcClient:
    """ONC RPC v2 over TCP with record marking; AUTH_SYS credentials."""

    def __init__(self, host, port, prog, vers, timeout=30.0,
                 uid=0, gid=0, gids=(), machine=b"quintmbt"):
        self.prog = prog
        self.vers = vers
        self.xid = 0x71b00000
        self.uid = uid
        self.gid = gid
        self.gids = list(gids)
        self.machine = machine
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    def close(self):
        self.sock.close()

    def set_cred(self, uid=0, gid=0, gids=()):
        """AUTH_SYS identity for subsequent calls (the nfs3 model drives
        every DAC-relevant operation under a credential of its choosing)."""
        self.uid = uid
        self.gid = gid
        self.gids = list(gids)

    def _cred_auth_sys(self):
        p = Packer()
        p.uint32(0)                  # stamp
        p.string(self.machine)
        p.uint32(self.uid)
        p.uint32(self.gid)
        p.uint32(len(self.gids))
        for g in self.gids:
            p.uint32(g)
        return bytes(p.buf)

    def _send_record(self, payload):
        self.sock.sendall(struct.pack(">I", 0x80000000 | len(payload)) + payload)

    def _recv_exact(self, n):
        chunks = []
        while n:
            c = self.sock.recv(n)
            if not c:
                raise RpcError("connection closed by server")
            chunks.append(c)
            n -= len(c)
        return b"".join(chunks)

    def _recv_record(self):
        frags = []
        while True:
            hdr = struct.unpack(">I", self._recv_exact(4))[0]
            frags.append(self._recv_exact(hdr & 0x7fffffff))
            if hdr & 0x80000000:
                return b"".join(frags)

    def call(self, proc, args=b""):
        """Send one call, return an Unpacker positioned at the results."""
        self.xid += 1
        p = Packer()
        p.uint32(self.xid)
        p.uint32(0)                  # CALL
        p.uint32(2)                  # RPC version
        p.uint32(self.prog)
        p.uint32(self.vers)
        p.uint32(proc)
        p.uint32(1)                  # cred flavor AUTH_SYS
        p.opaque_var(self._cred_auth_sys())
        p.uint32(0)                  # verf flavor AUTH_NONE
        p.uint32(0)
        p.buf += args
        self._send_record(bytes(p.buf))

        u = Unpacker(self._recv_record())
        xid = u.uint32()
        if xid != self.xid:
            raise RpcError(f"xid mismatch: sent {self.xid:#x}, got {xid:#x}")
        if u.uint32() != 1:
            raise RpcError("not an RPC reply")
        if u.uint32() != 0:          # reply_stat MSG_ACCEPTED
            raise RpcError("RPC call denied")
        u.uint32()                   # verf flavor
        u.opaque_var()               # verf body
        accept = u.uint32()
        if accept != 0:              # accept_stat SUCCESS
            raise RpcError(f"RPC accept_stat {accept}")
        return u


# ---------------------------------------------------------------------------
# NFS3 data types
# ---------------------------------------------------------------------------

def _unpack_time(u):
    return (u.uint32(), u.uint32())


def _unpack_fattr3(u):
    return {
        "type": u.uint32(),
        "mode": u.uint32(),
        "nlink": u.uint32(),
        "uid": u.uint32(),
        "gid": u.uint32(),
        "size": u.uint64(),
        "used": u.uint64(),
        "rdev": (u.uint32(), u.uint32()),
        "fsid": u.uint64(),
        "fileid": u.uint64(),
        "atime": _unpack_time(u),
        "mtime": _unpack_time(u),
        "ctime": _unpack_time(u),
    }


def _unpack_post_op_attr(u):
    return _unpack_fattr3(u) if u.boolean() else None


def _unpack_pre_op_attr(u):
    if not u.boolean():
        return None
    return {"size": u.uint64(), "mtime": _unpack_time(u), "ctime": _unpack_time(u)}


def _unpack_wcc_data(u):
    return {"before": _unpack_pre_op_attr(u), "after": _unpack_post_op_attr(u)}


def _unpack_post_op_fh3(u):
    return u.opaque_var() if u.boolean() else None


def _pack_diropargs3(p, fh, name):
    p.opaque_var(fh)
    p.string(name)


def _pack_sattr3(p, mode=None, uid=None, gid=None, size=None):
    for v in (mode, uid, gid):
        if v is None:
            p.boolean(False)
        else:
            p.boolean(True)
            p.uint32(v)
    if size is None:
        p.boolean(False)
    else:
        p.boolean(True)
        p.uint64(size)
    p.uint32(0)                      # atime DONT_CHANGE
    p.uint32(0)                      # mtime DONT_CHANGE


class Nfs3Client:
    """Typed NFSv3 procedure wrappers returning plain dicts."""

    def __init__(self, host, port=2049, **kw):
        self.rpc = RpcClient(host, port, NFS_PROGRAM, 3, **kw)

    def close(self):
        self.rpc.close()

    def null(self):
        self.rpc.call(NFSPROC3_NULL).done()

    def getattr(self, fh):
        p = Packer()
        p.opaque_var(fh)
        u = self.rpc.call(NFSPROC3_GETATTR, bytes(p.buf))
        status = u.uint32()
        res = {"status": status,
               "attrs": _unpack_fattr3(u) if status == NFS3_OK else None}
        u.done()
        return res

    def lookup(self, dir_fh, name):
        p = Packer()
        _pack_diropargs3(p, dir_fh, name)
        u = self.rpc.call(NFSPROC3_LOOKUP, bytes(p.buf))
        status = u.uint32()
        if status == NFS3_OK:
            res = {"status": status,
                   "obj_fh": u.opaque_var(),
                   "obj_attrs": _unpack_post_op_attr(u),
                   "dir_attrs": _unpack_post_op_attr(u)}
        else:
            res = {"status": status, "obj_fh": None, "obj_attrs": None,
                   "dir_attrs": _unpack_post_op_attr(u)}
        u.done()
        return res

    def create(self, dir_fh, name, createmode=UNCHECKED, mode=None, verf=None):
        p = Packer()
        _pack_diropargs3(p, dir_fh, name)
        p.uint32(createmode)
        if createmode == EXCLUSIVE:
            p.opaque_fixed(verf)
        else:
            _pack_sattr3(p, mode=mode)
        return self._create_reply(self.rpc.call(NFSPROC3_CREATE, bytes(p.buf)))

    def mkdir(self, dir_fh, name, mode=None):
        p = Packer()
        _pack_diropargs3(p, dir_fh, name)
        _pack_sattr3(p, mode=mode)
        return self._create_reply(self.rpc.call(NFSPROC3_MKDIR, bytes(p.buf)))

    @staticmethod
    def _create_reply(u):
        status = u.uint32()
        if status == NFS3_OK:
            res = {"status": status,
                   "obj_fh": _unpack_post_op_fh3(u),
                   "obj_attrs": _unpack_post_op_attr(u),
                   "wcc": _unpack_wcc_data(u)}
        else:
            res = {"status": status, "obj_fh": None, "obj_attrs": None,
                   "wcc": _unpack_wcc_data(u)}
        u.done()
        return res

    def write(self, fh, offset, data, stable=FILE_SYNC):
        p = Packer()
        p.opaque_var(fh)
        p.uint64(offset)
        p.uint32(len(data))
        p.uint32(stable)
        p.opaque_var(data)
        u = self.rpc.call(NFSPROC3_WRITE, bytes(p.buf))
        status = u.uint32()
        res = {"status": status, "wcc": _unpack_wcc_data(u)}
        if status == NFS3_OK:
            res["count"] = u.uint32()
            res["committed"] = u.uint32()
            res["verf"] = u.opaque_fixed(8)
        u.done()
        return res

    def read(self, fh, offset, count):
        p = Packer()
        p.opaque_var(fh)
        p.uint64(offset)
        p.uint32(count)
        u = self.rpc.call(NFSPROC3_READ, bytes(p.buf))
        status = u.uint32()
        res = {"status": status, "attrs": _unpack_post_op_attr(u)}
        if status == NFS3_OK:
            res["count"] = u.uint32()
            res["eof"] = u.boolean()
            res["data"] = u.opaque_var()
        u.done()
        return res

    def remove(self, dir_fh, name):
        return self._wcc_only_reply(NFSPROC3_REMOVE, dir_fh, name)

    def rmdir(self, dir_fh, name):
        return self._wcc_only_reply(NFSPROC3_RMDIR, dir_fh, name)

    def _wcc_only_reply(self, proc, dir_fh, name):
        p = Packer()
        _pack_diropargs3(p, dir_fh, name)
        u = self.rpc.call(proc, bytes(p.buf))
        res = {"status": u.uint32(), "wcc": _unpack_wcc_data(u)}
        u.done()
        return res

    def setattr(self, fh, mode=None, uid=None, gid=None, size=None,
                guard_ctime=None):
        p = Packer()
        p.opaque_var(fh)
        _pack_sattr3(p, mode=mode, uid=uid, gid=gid, size=size)
        if guard_ctime is None:
            p.boolean(False)
        else:
            p.boolean(True)
            p.uint32(guard_ctime[0])
            p.uint32(guard_ctime[1])
        u = self.rpc.call(NFSPROC3_SETATTR, bytes(p.buf))
        res = {"status": u.uint32(), "wcc": _unpack_wcc_data(u)}
        u.done()
        return res

    def access(self, fh, mask):
        p = Packer()
        p.opaque_var(fh)
        p.uint32(mask)
        u = self.rpc.call(NFSPROC3_ACCESS, bytes(p.buf))
        status = u.uint32()
        res = {"status": status, "attrs": _unpack_post_op_attr(u)}
        if status == NFS3_OK:
            res["access"] = u.uint32()
        u.done()
        return res

    def readlink(self, fh):
        p = Packer()
        p.opaque_var(fh)
        u = self.rpc.call(NFSPROC3_READLINK, bytes(p.buf))
        status = u.uint32()
        res = {"status": status, "attrs": _unpack_post_op_attr(u)}
        if status == NFS3_OK:
            res["target"] = u.opaque_var().decode()
        u.done()
        return res

    def symlink(self, dir_fh, name, target, mode=None):
        p = Packer()
        _pack_diropargs3(p, dir_fh, name)
        _pack_sattr3(p, mode=mode)
        p.string(target)
        return self._create_reply(self.rpc.call(NFSPROC3_SYMLINK, bytes(p.buf)))

    def mknod(self, dir_fh, name, ftype, mode=None):
        if ftype not in (NF3SOCK, NF3FIFO):
            raise ValueError("only NF3SOCK/NF3FIFO supported")
        p = Packer()
        _pack_diropargs3(p, dir_fh, name)
        p.uint32(ftype)
        _pack_sattr3(p, mode=mode)
        return self._create_reply(self.rpc.call(NFSPROC3_MKNOD, bytes(p.buf)))

    def rename(self, from_fh, from_name, to_fh, to_name):
        p = Packer()
        _pack_diropargs3(p, from_fh, from_name)
        _pack_diropargs3(p, to_fh, to_name)
        u = self.rpc.call(NFSPROC3_RENAME, bytes(p.buf))
        res = {"status": u.uint32(),
               "fromdir_wcc": _unpack_wcc_data(u),
               "todir_wcc": _unpack_wcc_data(u)}
        u.done()
        return res

    def link(self, fh, dir_fh, name):
        p = Packer()
        p.opaque_var(fh)
        _pack_diropargs3(p, dir_fh, name)
        u = self.rpc.call(NFSPROC3_LINK, bytes(p.buf))
        res = {"status": u.uint32(),
               "attrs": _unpack_post_op_attr(u),
               "linkdir_wcc": _unpack_wcc_data(u)}
        u.done()
        return res

    def readdir(self, dir_fh, cookie=0, cookieverf=b"\0" * 8, count=65536):
        p = Packer()
        p.opaque_var(dir_fh)
        p.uint64(cookie)
        p.opaque_fixed(cookieverf)
        p.uint32(count)
        u = self.rpc.call(NFSPROC3_READDIR, bytes(p.buf))
        status = u.uint32()
        res = {"status": status, "dir_attrs": _unpack_post_op_attr(u)}
        if status == NFS3_OK:
            res["cookieverf"] = u.opaque_fixed(8)
            entries = []
            while u.boolean():
                e = {"fileid": u.uint64(),
                     "name": u.opaque_var().decode(),
                     "cookie": u.uint64()}
                entries.append(e)
            res["entries"] = entries
            res["eof"] = u.boolean()
        u.done()
        return res

    def readdirplus(self, dir_fh, cookie=0, cookieverf=b"\0" * 8,
                    dircount=65536, maxcount=1048576):
        p = Packer()
        p.opaque_var(dir_fh)
        p.uint64(cookie)
        p.opaque_fixed(cookieverf)
        p.uint32(dircount)
        p.uint32(maxcount)
        u = self.rpc.call(NFSPROC3_READDIRPLUS, bytes(p.buf))
        status = u.uint32()
        res = {"status": status, "dir_attrs": _unpack_post_op_attr(u)}
        if status == NFS3_OK:
            res["cookieverf"] = u.opaque_fixed(8)
            entries = []
            while u.boolean():
                e = {"fileid": u.uint64(),
                     "name": u.opaque_var().decode(),
                     "cookie": u.uint64(),
                     "attrs": _unpack_post_op_attr(u),
                     "fh": _unpack_post_op_fh3(u)}
                entries.append(e)
            res["entries"] = entries
            res["eof"] = u.boolean()
        u.done()
        return res

    def fsstat(self, fh):
        p = Packer()
        p.opaque_var(fh)
        u = self.rpc.call(NFSPROC3_FSSTAT, bytes(p.buf))
        status = u.uint32()
        res = {"status": status, "attrs": _unpack_post_op_attr(u)}
        if status == NFS3_OK:
            for f in ("tbytes", "fbytes", "abytes",
                      "tfiles", "ffiles", "afiles"):
                res[f] = u.uint64()
            res["invarsec"] = u.uint32()
        u.done()
        return res

    def fsinfo(self, fh):
        p = Packer()
        p.opaque_var(fh)
        u = self.rpc.call(NFSPROC3_FSINFO, bytes(p.buf))
        status = u.uint32()
        res = {"status": status, "attrs": _unpack_post_op_attr(u)}
        if status == NFS3_OK:
            for f in ("rtmax", "rtpref", "rtmult",
                      "wtmax", "wtpref", "wtmult", "dtpref"):
                res[f] = u.uint32()
            res["maxfilesize"] = u.uint64()
            res["time_delta"] = _unpack_time(u)
            res["properties"] = u.uint32()
        u.done()
        return res

    def pathconf(self, fh):
        p = Packer()
        p.opaque_var(fh)
        u = self.rpc.call(NFSPROC3_PATHCONF, bytes(p.buf))
        status = u.uint32()
        res = {"status": status, "attrs": _unpack_post_op_attr(u)}
        if status == NFS3_OK:
            res["linkmax"] = u.uint32()
            res["name_max"] = u.uint32()
            for f in ("no_trunc", "chown_restricted",
                      "case_insensitive", "case_preserving"):
                res[f] = u.boolean()
        u.done()
        return res

    def commit(self, fh, offset=0, count=0):
        p = Packer()
        p.opaque_var(fh)
        p.uint64(offset)
        p.uint32(count)
        u = self.rpc.call(NFSPROC3_COMMIT, bytes(p.buf))
        status = u.uint32()
        res = {"status": status, "wcc": _unpack_wcc_data(u)}
        if status == NFS3_OK:
            res["verf"] = u.opaque_fixed(8)
        u.done()
        return res


PMAP_PROGRAM = 100000
PMAPPROC_GETPORT = 3
IPPROTO_TCP = 6
IPPROTO_UDP = 17


def pmap_getport(host, prog, vers, proto=IPPROTO_TCP, port=111, **kw):
    """PMAPPROC_GETPORT over TCP: the port `prog`/`vers` is registered on,
    or 0 when it is not registered (RFC 1833 3.2)."""
    rpc = RpcClient(host, port, PMAP_PROGRAM, 2, **kw)
    try:
        p = Packer()
        p.uint32(prog)
        p.uint32(vers)
        p.uint32(proto)
        p.uint32(0)
        u = rpc.call(PMAPPROC_GETPORT, bytes(p.buf))
        got = u.uint32()
        u.done()
        return got
    finally:
        rpc.close()


class Mount3Client:
    """MOUNTv3, only what is needed to obtain a root file handle."""

    def __init__(self, host, port=20048, **kw):
        self.rpc = RpcClient(host, port, MOUNT_PROGRAM, 3, **kw)

    def close(self):
        self.rpc.close()

    def null(self):
        self.rpc.call(MOUNTPROC3_NULL).done()

    def mnt(self, dirpath):
        p = Packer()
        p.string(dirpath)
        u = self.rpc.call(MOUNTPROC3_MNT, bytes(p.buf))
        status = u.uint32()
        if status != 0:
            raise RpcError(f"MNT {dirpath!r} failed: mountstat3 {status}")
        fh = u.opaque_var()
        nflavors = u.uint32()
        for _ in range(nflavors):
            u.uint32()
        u.done()
        return fh
