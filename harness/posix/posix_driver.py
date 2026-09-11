#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 The Quint Specs Authors
#
# SPDX-License-Identifier: MIT

"""Real-syscall driver for the POSIX conformance harness.

Speaks one JSON request per line on stdin and answers one JSON reply per
line on stdout, executing every request as an actual syscall against a real
filesystem rooted at --root.  posix_replay.py drives it; nothing here knows
anything about the model.

Credentials
-----------
The POSIX model has processes with distinct uid/gid/supplementary groups,
and POSIX ties three things to a process rather than to a call: the
descriptor table, the umask, and record-lock ownership.  A driver that
switched credentials per call with seteuid would get the credentials right
and all three of those wrong.

So each model pid gets a real WORKER PROCESS, forked at `setcred` and
permanently dropped to that pid's credentials.  Descriptors, umask and
fcntl locks are then per-pid because they are per-process, which is what
the model says they are.  The main process is a router: it holds a
socketpair per worker, forwards each request to the worker its `pid` names,
and relays the reply.

Everything the driver returns is the raw syscall outcome: `err` is errno (0
on success), `ret` the return value, plus per-op payload fields.  No
interpretation, no model vocabulary.
"""

import argparse
import base64
import ctypes
import errno
import fcntl
import json
import os
import shutil
import signal
import socket
import stat
import struct
import sys

# Wall-clock cap on one syscall in a worker; see Worker.handle.
REQUEST_TIMEOUT = int(os.environ.get("SPECS_POSIX_CALL_TIMEOUT", "20"))

libc = ctypes.CDLL(None, use_errno=True)

# --------------------------------------------------------------------------
# libc entry points Python does not expose
# --------------------------------------------------------------------------

UTIME_NOW = (1 << 30) - 1
UTIME_OMIT = (1 << 30) - 2

FALLOC_FL_KEEP_SIZE = 0x01
FALLOC_FL_PUNCH_HOLE = 0x02

# FICLONERANGE = _IOW(0x94, 13, struct file_clone_range) -- 32-byte struct of
# { __s64 src_fd; __u64 src_offset; __u64 src_length; __u64 dest_offset; }
FICLONERANGE = (1 << 30) | (32 << 16) | (0x94 << 8) | 13


class Timespec(ctypes.Structure):
    _fields_ = [("tv_sec", ctypes.c_int64), ("tv_nsec", ctypes.c_int64)]


class Dirent(ctypes.Structure):
    """struct dirent64 on Linux (glibc's readdir is readdir64 on LP64)."""
    _fields_ = [("d_ino", ctypes.c_uint64),
                ("d_off", ctypes.c_int64),
                ("d_reclen", ctypes.c_uint16),
                ("d_type", ctypes.c_uint8),
                ("d_name", ctypes.c_char * 256)]


libc.utimensat.argtypes = [ctypes.c_int, ctypes.c_char_p,
                           ctypes.POINTER(Timespec), ctypes.c_int]
libc.futimens.argtypes = [ctypes.c_int, ctypes.POINTER(Timespec)]
libc.fallocate.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_int64,
                           ctypes.c_int64]
libc.opendir.argtypes = [ctypes.c_char_p]
libc.opendir.restype = ctypes.c_void_p
libc.readdir.argtypes = [ctypes.c_void_p]
libc.readdir.restype = ctypes.POINTER(Dirent)
libc.closedir.argtypes = [ctypes.c_void_p]
libc.telldir.argtypes = [ctypes.c_void_p]
libc.telldir.restype = ctypes.c_long
libc.seekdir.argtypes = [ctypes.c_void_p, ctypes.c_long]
libc.seekdir.restype = None
libc.rewinddir.argtypes = [ctypes.c_void_p]
libc.rewinddir.restype = None
libc.access.argtypes = [ctypes.c_char_p, ctypes.c_int]
libc.faccessat.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                           ctypes.c_int]
# os.link(follow_symlinks=True) is link(2) on Linux, which does NOT follow;
# the model asks for both behaviours, so go through linkat directly.
libc.linkat.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                        ctypes.c_char_p, ctypes.c_int]
libc.renameat.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                          ctypes.c_char_p]
libc.lockf.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_int64]

AT_FDCWD = -100
AT_EACCESS = 0x200
AT_SYMLINK_NOFOLLOW = 0x100
AT_SYMLINK_FOLLOW = 0x400


class SyscallError(Exception):
    def __init__(self, err):
        self.err = err
        super().__init__(os.strerror(err))


def _check(rc):
    if rc < 0:
        raise SyscallError(ctypes.get_errno())
    return rc


def _timespec_pair(a, m):
    arr = (Timespec * 2)()
    arr[0].tv_sec, arr[0].tv_nsec = a
    arr[1].tv_sec, arr[1].tv_nsec = m
    return arr


# --------------------------------------------------------------------------
# The worker: one process per model pid, running as that pid's credentials
# --------------------------------------------------------------------------

class Worker:
    """Executes requests as one fixed credential.  Runs in a forked child."""

    def __init__(self, root):
        self.root = root
        self.dirs = {}        # stream id -> DIR*
        self.next_sid = 1

    # -- helpers ----------------------------------------------------------

    def _dir(self, sid):
        d = self.dirs.get(sid)
        if d is None:
            raise SyscallError(errno.EBADF)
        return d

    @staticmethod
    def _ftype(mode):
        if stat.S_ISREG(mode):
            return "reg"
        if stat.S_ISDIR(mode):
            return "dir"
        if stat.S_ISLNK(mode):
            return "lnk"
        if stat.S_ISFIFO(mode):
            return "fifo"
        if stat.S_ISSOCK(mode):
            return "sock"
        if stat.S_ISBLK(mode):
            return "blk"
        if stat.S_ISCHR(mode):
            return "chr"
        return "unknown"

    @classmethod
    def _stat_reply(cls, st):
        return {
            "err": 0, "ret": 0,
            "ftype": cls._ftype(st.st_mode),
            "mode": stat.S_IMODE(st.st_mode),
            "uid": st.st_uid, "gid": st.st_gid, "nlink": st.st_nlink,
            "size": st.st_size, "dev": st.st_dev, "ino": st.st_ino,
            "atime": [st.st_atime_ns // 10**9, st.st_atime_ns % 10**9],
            "mtime": [st.st_mtime_ns // 10**9, st.st_mtime_ns % 10**9],
            "ctime": [st.st_ctime_ns // 10**9, st.st_ctime_ns % 10**9],
        }

    @staticmethod
    def _iovecs(data, nvec=3):
        """Split a buffer across iovecs so the vectored entry points are
        genuinely vectored; POSIX makes the result identical to the scalar
        call, which is exactly what the model asserts."""
        if len(data) < nvec:
            return [data] if data else [b""]
        step = len(data) // nvec
        out = [data[i * step:(i + 1) * step] for i in range(nvec - 1)]
        out.append(data[(nvec - 1) * step:])
        return out

    @staticmethod
    def _readv_bufs(length, nvec=3):
        if length < nvec:
            return [bytearray(length)] if length else [bytearray(0)]
        step = length // nvec
        bufs = [bytearray(step) for _ in range(nvec - 1)]
        bufs.append(bytearray(length - step * (nvec - 1)))
        return bufs

    def _ts(self, req, prefix):
        kind = req[prefix + "type"]
        if kind == "now":
            return (0, UTIME_NOW)
        if kind == "omit":
            return (0, UTIME_OMIT)
        return (req[prefix + "sec"], req[prefix + "nsec"])

    # -- dispatch ---------------------------------------------------------

    def handle(self, req):
        op = req["op"]
        fn = getattr(self, "do_" + op, None)
        if fn is None:
            return {"err": errno.ENOSYS, "ret": -1,
                    "detail": f"no driver op {op!r}"}
        # Some of these calls can block for as long as the model likes: a
        # FIFO opened for reading waits for a writer, an F_SETLKW waits for
        # the holder.  The model only ever issues the forms that do not
        # block, but "only ever" is a property of the generator, and one
        # blocked worker would take the whole batch down with it rather than
        # reporting anything.  The alarm turns that into an errno the
        # replayer can compare and the registry can reconcile.
        signal.alarm(REQUEST_TIMEOUT)
        try:
            return fn(req)
        except SyscallError as e:
            return {"err": e.err, "ret": -1}
        except OSError as e:
            return {"err": e.errno or errno.EIO, "ret": -1}
        finally:
            signal.alarm(0)

    # -- descriptors ------------------------------------------------------

    def do_open(self, r):
        fd = os.open(r["path"], r["flags"], r.get("mode", 0))
        return {"err": 0, "ret": fd}

    def do_openat(self, r):
        fd = os.open(r["path"], r["flags"], r.get("mode", 0),
                     dir_fd=r["dirfd"])
        return {"err": 0, "ret": fd}

    def do_close(self, r):
        os.close(r["fd"])
        return {"err": 0, "ret": 0}

    def do_dup(self, r):
        return {"err": 0, "ret": os.dup(r["fd"])}

    def do_dup2(self, r):
        return {"err": 0, "ret": os.dup2(r["fd"], r["nfd"])}

    def do_fcntl_dupfd(self, r):
        return {"err": 0,
                "ret": fcntl.fcntl(r["fd"], fcntl.F_DUPFD, r["atleast"])}

    def do_fcntl_getfl(self, r):
        return {"err": 0, "ret": fcntl.fcntl(r["fd"], fcntl.F_GETFL)}

    def do_fcntl_setfl(self, r):
        cur = fcntl.fcntl(r["fd"], fcntl.F_GETFL)
        new = (cur & ~os.O_APPEND) | (r["flags"] & os.O_APPEND)
        fcntl.fcntl(r["fd"], fcntl.F_SETFL, new)
        return {"err": 0, "ret": 0}

    # -- data -------------------------------------------------------------

    def do_lseek(self, r):
        whence = {"set": os.SEEK_SET, "cur": os.SEEK_CUR,
                  "end": os.SEEK_END, "data": os.SEEK_DATA,
                  "hole": os.SEEK_HOLE}[r["whence"]]
        return {"err": 0, "ret": os.lseek(r["fd"], r["off"], whence)}

    def do_read(self, r):
        data = os.read(r["fd"], r["len"])
        return {"err": 0, "ret": len(data),
                "data": base64.b64encode(data).decode()}

    def do_pread(self, r):
        data = os.pread(r["fd"], r["len"], r["off"])
        return {"err": 0, "ret": len(data),
                "data": base64.b64encode(data).decode()}

    def do_readv(self, r):
        bufs = self._readv_bufs(r["len"])
        n = os.readv(r["fd"], bufs)
        return {"err": 0, "ret": n,
                "data": base64.b64encode(b"".join(bufs)[:n]).decode()}

    def do_preadv(self, r):
        bufs = self._readv_bufs(r["len"])
        n = os.preadv(r["fd"], bufs, r["off"])
        return {"err": 0, "ret": n,
                "data": base64.b64encode(b"".join(bufs)[:n]).decode()}

    def do_write(self, r):
        data = base64.b64decode(r["data"])
        return {"err": 0, "ret": os.write(r["fd"], data)}

    def do_pwrite(self, r):
        data = base64.b64decode(r["data"])
        return {"err": 0, "ret": os.pwrite(r["fd"], data, r["off"])}

    def do_writev(self, r):
        data = base64.b64decode(r["data"])
        return {"err": 0, "ret": os.writev(r["fd"], self._iovecs(data))}

    def do_pwritev(self, r):
        data = base64.b64decode(r["data"])
        return {"err": 0,
                "ret": os.pwritev(r["fd"], self._iovecs(data), r["off"])}

    def do_truncate(self, r):
        os.truncate(r["path"], r["len"])
        return {"err": 0, "ret": 0}

    def do_ftruncate(self, r):
        os.ftruncate(r["fd"], r["len"])
        return {"err": 0, "ret": 0}

    def do_fsync(self, r):
        os.fsync(r["fd"])
        return {"err": 0, "ret": 0}

    def do_fdatasync(self, r):
        os.fdatasync(r["fd"])
        return {"err": 0, "ret": 0}

    def do_fallocate(self, r):
        mode = FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE if r["mode"] else 0
        _check(libc.fallocate(r["fd"], mode, r["off"], r["len"]))
        return {"err": 0, "ret": 0}

    def do_copy_range(self, r):
        n = os.copy_file_range(r["fd_in"], r["fd_out"], r["len"],
                               r["off_in"], r["off_out"])
        return {"err": 0, "ret": n}

    def do_clone_range(self, r):
        arg = struct.pack("=qQQQ", r["src_fd"], r["src_off"], r["len"],
                          r["dst_off"])
        fcntl.ioctl(r["dst_fd"], FICLONERANGE, arg)
        return {"err": 0, "ret": 0}

    # -- metadata ---------------------------------------------------------

    def do_stat(self, r):
        return self._stat_reply(os.stat(r["path"],
                                        follow_symlinks=r["follow"]))

    def do_fstatat(self, r):
        return self._stat_reply(os.stat(r["path"], dir_fd=r["dirfd"],
                                        follow_symlinks=r["follow"]))

    def do_fstat(self, r):
        return self._stat_reply(os.fstat(r["fd"]))

    def do_statfs(self, r):
        os.statvfs(r["path"])
        return {"err": 0, "ret": 0}

    do_statvfs = do_statfs

    def do_fstatfs(self, r):
        os.statvfs(r["fd"])
        return {"err": 0, "ret": 0}

    do_fstatvfs = do_fstatfs

    def do_chmod(self, r):
        os.chmod(r["path"], r["mode"])
        return {"err": 0, "ret": 0}

    def do_fchmod(self, r):
        os.fchmod(r["fd"], r["mode"])
        return {"err": 0, "ret": 0}

    def do_chown(self, r):
        os.chown(r["path"], r["uid"], r["gid"],
                 follow_symlinks=r["follow"])
        return {"err": 0, "ret": 0}

    def do_fchown(self, r):
        os.fchown(r["fd"], r["uid"], r["gid"])
        return {"err": 0, "ret": 0}

    def do_utimens(self, r):
        times = _timespec_pair(self._ts(r, "a"), self._ts(r, "m"))
        flags = 0 if r.get("follow", True) else AT_SYMLINK_NOFOLLOW
        _check(libc.utimensat(AT_FDCWD, r["path"].encode(), times, flags))
        return {"err": 0, "ret": 0}

    def do_utimensat(self, r):
        times = _timespec_pair(self._ts(r, "a"), self._ts(r, "m"))
        _check(libc.utimensat(r["dirfd"], r["path"].encode(), times, 0))
        return {"err": 0, "ret": 0}

    def do_futimens(self, r):
        times = _timespec_pair(self._ts(r, "a"), self._ts(r, "m"))
        _check(libc.futimens(r["fd"], times))
        return {"err": 0, "ret": 0}

    def do_access(self, r):
        mode = os.F_OK
        if r["r"]:
            mode |= os.R_OK
        if r["w"]:
            mode |= os.W_OK
        if r["x"]:
            mode |= os.X_OK
        # os.access reports a bool; the model wants the errno, so ask the
        # syscall directly.  faccessat is also the only spelling that can
        # take a dirfd or the real-id form.
        ctypes.set_errno(0)
        if "dirfd" in r or r["eff"]:
            rc = libc.faccessat(r.get("dirfd", AT_FDCWD), r["path"].encode(),
                                mode, AT_EACCESS if r["eff"] else 0)
        else:
            rc = libc.access(r["path"].encode(), mode)
        if rc < 0:
            return {"err": ctypes.get_errno(), "ret": -1}
        return {"err": 0, "ret": 0}

    def do_umask(self, r):
        return {"err": 0, "ret": os.umask(r["mask"])}

    # -- namespace --------------------------------------------------------

    def do_mkdir(self, r):
        os.mkdir(r["path"], r["mode"])
        return {"err": 0, "ret": 0}

    def do_mkdirat(self, r):
        os.mkdir(r["path"], r["mode"], dir_fd=r["dirfd"])
        return {"err": 0, "ret": 0}

    def do_mknod(self, r):
        kind = {"reg": stat.S_IFREG, "fifo": stat.S_IFIFO,
                "sock": stat.S_IFSOCK, "blk": stat.S_IFBLK,
                "chr": stat.S_IFCHR}[r["ftype"]]
        dev = 0
        if kind in (stat.S_IFBLK, stat.S_IFCHR):
            # Major 240 is the LOCAL/EXPERIMENTAL range (Documentation/
            # admin-guide/devices.txt) and nothing registers it, so opening
            # the node fails ENXIO -- which is what the model predicts for a
            # device node with no driver behind it.  A real major (1,3 or
            # 7,0) would open /dev/null or a loop device instead and the
            # trace would diverge on the harness's choice of number rather
            # than on anything the filesystem did.
            dev = os.makedev(240, 0)
        os.mknod(r["path"], r["mode"] | kind, dev)
        return {"err": 0, "ret": 0}

    def do_symlink(self, r):
        os.symlink(r["target"], r["path"])
        return {"err": 0, "ret": 0}

    def do_link(self, r):
        ctypes.set_errno(0)
        rc = libc.linkat(r.get("olddirfd", AT_FDCWD), r["old"].encode(),
                         r.get("newdirfd", AT_FDCWD), r["new"].encode(),
                         AT_SYMLINK_FOLLOW if r["follow"] else 0)
        if rc < 0:
            return {"err": ctypes.get_errno(), "ret": -1}
        return {"err": 0, "ret": 0}

    def do_unlink(self, r):
        os.unlink(r["path"])
        return {"err": 0, "ret": 0}

    def do_rmdir(self, r):
        os.rmdir(r["path"])
        return {"err": 0, "ret": 0}

    def do_unlinkat(self, r):
        if r["rmdir"]:
            os.rmdir(r["path"], dir_fd=r["dirfd"])
        else:
            os.unlink(r["path"], dir_fd=r["dirfd"])
        return {"err": 0, "ret": 0}

    def do_rename(self, r):
        if "olddirfd" not in r and "newdirfd" not in r:
            os.rename(r["old"], r["new"])
            return {"err": 0, "ret": 0}
        ctypes.set_errno(0)
        rc = libc.renameat(r.get("olddirfd", AT_FDCWD), r["old"].encode(),
                           r.get("newdirfd", AT_FDCWD), r["new"].encode())
        if rc < 0:
            return {"err": ctypes.get_errno(), "ret": -1}
        return {"err": 0, "ret": 0}

    def do_readlink(self, r):
        return {"err": 0, "ret": 0, "target": os.readlink(r["path"])}

    # -- directory streams ------------------------------------------------

    def do_opendir(self, r):
        ctypes.set_errno(0)
        d = libc.opendir(r["path"].encode())
        if not d:
            return {"err": ctypes.get_errno() or errno.EIO, "ret": -1}
        sid = self.next_sid
        self.next_sid += 1
        self.dirs[sid] = d
        return {"err": 0, "ret": sid}

    def do_readdir(self, r):
        """One full sweep from the top, which is what the model's readdir
        is: an atomic snapshot of the directory (posix_ops.qnt models
        telldir/seekdir on the premise that "the harness rewinds before
        each readdir").  Without the rewind the second sweep of a stream
        would return nothing, because a real DIR* is left at EOF."""
        d = self._dir(r["sid"])
        libc.rewinddir(d)
        names = []
        while True:
            ctypes.set_errno(0)
            ent = libc.readdir(d)
            if not ent:
                e = ctypes.get_errno()
                if e:
                    return {"err": e, "ret": -1}
                break
            names.append(
                ent.contents.d_name.decode("utf-8", "surrogateescape"))
        return {"err": 0, "ret": len(names), "names": names}

    def do_rewinddir(self, r):
        libc.rewinddir(self._dir(r["sid"]))
        return {"err": 0, "ret": 0}

    def do_telldir(self, r):
        ctypes.set_errno(0)
        loc = libc.telldir(self._dir(r["sid"]))
        if loc < 0 and ctypes.get_errno():
            return {"err": ctypes.get_errno(), "ret": -1}
        return {"err": 0, "ret": loc}

    def do_seekdir(self, r):
        libc.seekdir(self._dir(r["sid"]), r["loc"])
        return {"err": 0, "ret": 0}

    def do_closedir(self, r):
        d = self._dir(r["sid"])
        rc = libc.closedir(d)
        del self.dirs[r["sid"]]
        if rc < 0:
            return {"err": ctypes.get_errno(), "ret": -1}
        return {"err": 0, "ret": 0}

    # -- record locks -----------------------------------------------------

    def do_fcntl_lock(self, r):
        cmd = {"setlk": fcntl.F_SETLK, "setlkw": fcntl.F_SETLKW,
               "getlk": fcntl.F_GETLK}[r["cmd"]]
        ltype = {"rd": fcntl.F_RDLCK, "wr": fcntl.F_WRLCK,
                 "un": fcntl.F_UNLCK}[r["type"]]
        # struct flock on Linux: short l_type, short l_whence, off_t l_start,
        # off_t l_len, pid_t l_pid.
        arg = struct.pack("@hhqqi", ltype, os.SEEK_SET, r["start"],
                          r["len"], 0)
        out = fcntl.fcntl(r["fd"], cmd, arg)
        got, _, start, length, pid = struct.unpack("@hhqqi", out)
        name = {fcntl.F_RDLCK: "rd", fcntl.F_WRLCK: "wr",
                fcntl.F_UNLCK: "un"}.get(got, "?")
        return {"err": 0, "ret": 0, "l_type": name, "l_start": start,
                "l_len": length, "l_pid": pid}

    def do_lockf(self, r):
        # F_ULOCK/F_LOCK/F_TLOCK/F_TEST (unistd.h); fcntl.lockf remaps its
        # operations onto the flock names and cannot spell F_TEST.
        cmd = {"ulock": 0, "lock": 1, "tlock": 2, "test": 3}[r["cmd"]]
        ctypes.set_errno(0)
        if libc.lockf(r["fd"], cmd, r["len"]) < 0:
            return {"err": ctypes.get_errno(), "ret": -1}
        return {"err": 0, "ret": 0}


def worker_main(sock, root, uid, gid, gids):
    """Enter the filesystem under test, drop to (uid, gid, gids), and serve
    requests forever.

    The chroot is not isolation, it is fidelity.  The model's root is *the*
    root: `/..` is the root itself, and an absolute symlink target names a
    path from it.  A mount point does not behave that way -- `..` there
    escapes into whatever directory the filesystem happens to be mounted
    under -- so the trace would be resolved against the host's namespace
    from the first `..` onward, silently, and could create objects outside
    the filesystem it is meant to be testing.  Inside the chroot every path
    in the trace means exactly what the model says it means.
    """
    try:
        os.chroot(root)
        os.chdir("/")
        os.setgroups(sorted(set(gids)))
        os.setresgid(gid, gid, gid)
        os.setresuid(uid, uid, uid)
    except OSError as e:
        sock.sendall(json.dumps({"err": e.errno, "ret": -1,
                                 "detail": "setcred"}).encode() + b"\n")
        os._exit(1)
    os.umask(0)

    def on_alarm(sig, frame):
        raise SyscallError(errno.EINTR)

    signal.signal(signal.SIGALRM, on_alarm)
    w = Worker(root)
    f = sock.makefile("rwb", buffering=0)
    while True:
        line = f.readline()
        if not line:
            break
        try:
            req = json.loads(line)
        except ValueError:
            break
        if req.get("op") == "exit":
            break
        try:
            resp = w.handle(req)
        except Exception as e:                       # noqa: BLE001
            resp = {"err": errno.EIO, "ret": -1,
                    "detail": f"driver exception: {e!r}"}
        f.write(json.dumps(resp).encode() + b"\n")
    os._exit(0)


# --------------------------------------------------------------------------
# The router
# --------------------------------------------------------------------------

class Router:
    def __init__(self, root, root_mode):
        self.root = root
        self.root_mode = root_mode
        self.workers = {}     # pid -> (child pid, socket file)

    def spawn(self, pid, uid, gid, gids):
        self.kill(pid)
        parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        cpid = os.fork()
        if cpid == 0:
            parent.close()
            worker_main(child, self.root, uid, gid, gids)
            os._exit(0)                              # unreachable
        child.close()
        self.workers[pid] = (cpid, parent.makefile("rwb", buffering=0),
                             parent)
        return {"err": 0, "ret": 0}

    def kill(self, pid):
        ent = self.workers.pop(pid, None)
        if ent is None:
            return
        cpid, f, sock = ent
        try:
            f.write(json.dumps({"op": "exit"}).encode() + b"\n")
        except OSError:
            pass
        try:
            sock.close()
        except OSError:
            pass
        try:
            os.waitpid(cpid, 0)
        except ChildProcessError:
            pass

    def kill_all(self):
        for pid in list(self.workers):
            self.kill(pid)

    def forward(self, req):
        ent = self.workers.get(req.get("pid"))
        if ent is None:
            return {"err": errno.EINVAL, "ret": -1,
                    "detail": f"no worker for pid {req.get('pid')!r}"}
        _, f, _ = ent
        f.write(json.dumps(req).encode() + b"\n")
        line = f.readline()
        if not line:
            return {"err": errno.EIO, "ret": -1, "detail": "worker died"}
        return json.loads(line)

    def newfs(self):
        """A pristine tree: no workers (so no descriptors and no locks
        survive), an empty root, and the root's own attributes back to what
        the model's fsInit says they are."""
        self.kill_all()
        for name in os.listdir(self.root):
            p = os.path.join(self.root, name)
            if os.path.isdir(p) and not os.path.islink(p):
                shutil.rmtree(p)
            else:
                os.unlink(p)
        os.chown(self.root, 0, 0)
        os.chmod(self.root, self.root_mode)
        return {"err": 0, "ret": 0}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", required=True,
                    help="mount point of the filesystem under test")
    ap.add_argument("--block-size", type=int, default=4096,
                    help="block size the model's block symbols expand to")
    ap.add_argument("--root-mode", type=lambda s: int(s, 8), default=0o777,
                    help="mode newfs restores on the root (octal)")
    args = ap.parse_args()

    if os.geteuid() != 0:
        print(json.dumps({"ready": False,
                          "detail": "the driver must run as root: it forks "
                                    "one worker per model pid and drops "
                                    "each to that pid's credentials"}),
              flush=True)
        return 1

    router = Router(args.root, args.root_mode)
    router.newfs()
    print(json.dumps({"ready": True, "blocksize": args.block_size,
                      "root": args.root}), flush=True)

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        req = json.loads(line)
        op = req.get("op")
        if op == "shutdown":
            router.kill_all()
            return 0
        if op == "setcred":
            resp = router.spawn(req["pid"], req["uid"], req["gid"],
                                req.get("gids", []))
        elif op == "newfs":
            resp = router.newfs()
        else:
            resp = router.forward(req)
        sys.stdout.write(json.dumps(resp) + "\n")
        sys.stdout.flush()
    router.kill_all()
    return 0


if __name__ == "__main__":
    sys.exit(main())
