#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 The Quint Specs Authors
#
# SPDX-License-Identifier: MIT

"""Replay the generated POSIX corpus against a real filesystem.

Each state of a `quint/posix` trace carries a `lastOp` label naming the
syscall the model issued and the result POSIX requires (see posix.qnt).
This harness drives posix_driver.py -- which makes those calls for real,
one worker process per model pid -- and compares every outcome against the
model's expectation.

The point is not to test the filesystem.  It is to test the **model**.  A
model developed alongside one implementation drifts toward it: the traces
keep passing, and the passing keeps meaning less, because the model and
that implementation can agree on something POSIX never said.  Linux's ext4
was consulted by nobody who wrote this model, so every disagreement is
informative -- either the model is wrong, or ext4 is.  Both verdicts are
recorded, in ext4_deviations.py; an unrecorded one fails the run.

Model-to-real mapping maintained here:
  - model pid      -> a driver worker process with that pid's credentials
  - model (pid,fd) -> real fd, learned from the open/dup replies
  - model sid      -> driver directory-stream id
  - model Ino      -> real (st_dev, st_ino), learned from stat replies
  - block symbols  -> a byte-accurate shadow; a write stamps offset-derived
                      nonzero bytes so a hole (zero) is distinguishable and
                      any off-by-N is caught
  - timestamps     -> abstract instants checked for monotone consistency,
                      never predicted; explicit utimensat values map to
                      fixed wall-clock times (XTIME) and are checked exactly
"""

import argparse
import base64
import collections
import json
import os
import signal
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from deviations import Finding                                  # noqa: E402
import ext4_deviations                                          # noqa: E402

REGISTRIES = {"ext4": ext4_deviations.REGISTRY}

# The model no longer carries a per-target policy profile -- see the header
# of quint/posix/posix_run.qnt.  What a trace can still depend on is whether
# an optional interface exists, and a trace that meets one the target does
# not have is reported as NOT APPLICABLE rather than replayed against a
# capability nobody claimed.  These are the ops that can raise that.
CAPABILITY_OPS = {
    "RCopyRange": "copy_file_range",
    "RCloneRange": "clone_file_range (reflink)",
    "RLseek": "SEEK_DATA/SEEK_HOLE",
}

# What a filesystem answers for an interface it does not implement.  Only
# EOPNOTSUPP: a target that answers EINVAL for an absent SEEK_DATA/SEEK_HOLE
# shows up as a divergence to triage rather than a silent skip, which is the
# safer way round -- EINVAL is a legitimate answer for these ops too, and
# treating it as "absent" would mask real disagreements.
NOT_IMPLEMENTED = (95,)         # EOPNOTSUPP / ENOTSUP

# What the model now asserts unconditionally, where it used to carry a knob.
# `--check-profile` measures the target and reports every one it does not
# satisfy: each of those has to be a recorded deviation, so this is really a
# check that the registry is complete rather than a profile comparison.
# None means "the harness chooses" or "not measurable".
MODEL_ASSUMES = {
    "gidFromParent": False,     # egid, unless a S_ISGID parent forces it
    "sgidInherit": True,        # a new subdir of a setgid dir inherits it
    "writeClearsSets": True,    # write by an unprivileged owner clears setid
    "pwriteAppends": False,     # XSH pwrite: at the offset, O_APPEND or not
    "renameCtime": True,        # rename marks the moved object's ctime
    "stickyWriteArm": False,    # sticky is not exempted by write permission
    "chownSuppGroup": True,     # chgrp to any group the caller belongs to
}

# Departures already written down, per target: measuring one of these is the
# expected outcome, not a finding.  Anything else this probe turns up is a
# deviation that has not been recorded yet.
RECORDED_DEPARTURES = {
    "ext4": {"pwriteAppends"},  # EXT4-14; pwrite(2) lists it under BUGS
}

BADFD = 999999

# Explicit utimensat instants: model reserved value -> (sec, nsec).  Kept in
# the past so a later "mark to now" still satisfies the monotone check.
XTIME = {-1: (1000000, 0), -2: (2000000, 0)}

FTYPE_MAP = {"FReg": "reg", "FDir": "dir", "FLnk": "lnk", "FFifo": "fifo",
             "FSock": "sock", "FBlk": "blk", "FChr": "chr"}

ACC_FLAGS = {"AccR": os.O_RDONLY, "AccW": os.O_WRONLY, "AccRW": os.O_RDWR}

WHENCE_MAP = {"WSet": "set", "WCur": "cur", "WEnd": "end",
              "WData": "data", "WHole": "hole"}

LOCK_CMD = {"CSetlk": "setlk", "CSetlkw": "setlkw", "CGetlk": "getlk"}
LOCK_TYPE = {"LkRd": "rd", "LkWr": "wr", "LkUn": "un"}
LOCKF_CMD = {"LfLock": "lock", "LfTlock": "tlock", "LfUlock": "ulock",
             "LfTst": "test"}

# Over-long component sentinels (posix_ops NLONG/PLONG) materialized to real
# strings that exceed NAME_MAX (255) / PATH_MAX (4096).
_NLONG = "@nlong"
_PLONG = "@plong"


class TraceFormatError(Exception):
    pass


class NotApplicable(Exception):
    """The target lacks an optional interface this trace exercises.

    Not a divergence and not a pass: the trace asked for copy_file_range or
    reflink or SEEK_HOLE, the filesystem does not implement it, and every
    step after the refusal would be comparing against a state the model did
    not predict.  Reported as a SKIP so the gap stays visible and
    attributable to the interface rather than hidden in a corpus generated
    per implementation."""

    def __init__(self, step, op, what):
        self.step = step
        self.op = op
        self.what = what
        super().__init__(f"step {step}: {op} needs {what}")


class Divergence(Exception):
    def __init__(self, step, op, findings):
        self.step = step
        self.op = op
        self.findings = findings
        super().__init__(f"step {step}: " +
                         "; ".join(str(f) for f in findings))


# --------------------------------------------------------------------------
# ITF decoding
# --------------------------------------------------------------------------

def itf_decode(v):
    if isinstance(v, dict):
        special = [k for k in v if k.startswith("#")]
        if special == ["#bigint"]:
            return int(v["#bigint"])
        if special == ["#map"]:
            return {itf_decode(k): itf_decode(val) for k, val in v["#map"]}
        if special == ["#set"]:
            return [itf_decode(x) for x in v["#set"]]
        if special == ["#tup"]:
            return tuple(itf_decode(x) for x in v["#tup"])
        if special:
            raise TraceFormatError(f"unrecognized ITF encoding {special}")
        if set(v.keys()) == {"tag", "value"}:
            return {"tag": v["tag"], "value": itf_decode(v["value"])}
        return {k: itf_decode(val) for k, val in v.items()}
    if isinstance(v, list):
        return [itf_decode(x) for x in v]
    if isinstance(v, (str, bool, int)):
        return v
    raise TraceFormatError(f"unrecognized ITF value {v!r}")


def load_trace(path):
    with open(path) as f:
        raw = json.load(f)
    if "states" not in raw:
        raise TraceFormatError(f"{path}: not an ITF trace")
    states = []
    for st in raw["states"]:
        states.append({k.split("::")[-1]: itf_decode(v)
                       for k, v in st.items()
                       if k != "#meta" and not k.startswith("mbt::")})
    for st in states:
        if "lastOp" not in st or "fs" not in st:
            raise TraceFormatError(f"{path}: state missing lastOp/fs")
    return states


# --------------------------------------------------------------------------
# The driver process
# --------------------------------------------------------------------------

class Driver:
    """posix_driver.py wrapper: one JSON request line per call."""

    def __init__(self, driver_path, root, block_size=4096, root_mode=0o777):
        # sys.executable, not "python3" -- except when it is empty, which
        # it is when the interpreter cannot work out its own path.  In the
        # guest the harness runs from an init script with no PATH in the
        # environment, and Python resolves argv[0] through PATH.
        argv = [sys.executable or "python3", driver_path, "--root", root,
                "--block-size", str(block_size),
                "--root-mode", oct(root_mode)[2:]]
        self.stderr_path = os.path.join(
            os.environ.get("TMPDIR", "/tmp"),
            f"posix_driver_{os.getpid()}.stderr")
        self.stderr_file = open(self.stderr_path, "w+")
        self.proc = subprocess.Popen(argv, stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE,
                                     stderr=self.stderr_file, text=True)
        ready = self.proc.stdout.readline()
        try:
            obj = json.loads(ready)
        except ValueError:
            raise RuntimeError(f"driver failed to start: {ready!r}\n"
                               f"{self.stderr_tail()}")
        if not obj.get("ready"):
            raise RuntimeError(f"driver not ready: {obj}")
        self.block_size = obj["blocksize"]
        self.root = obj["root"]

    def request(self, **req):
        self.proc.stdin.write(json.dumps(req) + "\n")
        self.proc.stdin.flush()
        line = self.proc.stdout.readline()
        if not line:
            raise RuntimeError(f"driver died on request {req}\n"
                               f"{self.stderr_tail()}")
        return json.loads(line)

    def stderr_tail(self, lines=40):
        try:
            self.stderr_file.flush()
            with open(self.stderr_path, errors="replace") as f:
                return "".join(f.readlines()[-lines:])
        except OSError:
            return "<no driver stderr>"

    def close(self):
        try:
            if self.proc.poll() is None:
                self.proc.stdin.write(json.dumps({"op": "shutdown"}) + "\n")
                self.proc.stdin.flush()
                self.proc.wait(timeout=15)
        except (OSError, ValueError, subprocess.TimeoutExpired):
            self.proc.kill()
            self.proc.wait()
        finally:
            self.stderr_file.close()
            try:
                os.unlink(self.stderr_path)
            except OSError:
                pass


# --------------------------------------------------------------------------
# Path materialization
# --------------------------------------------------------------------------

def _expand(c):
    if c == _NLONG:
        return "n" * 300      # one component over NAME_MAX (255)
    if c == _PLONG:
        return "p" * 5000     # makes the whole path exceed PATH_MAX (4096)
    return c


def creds_for(with_root):
    """posix.qnt's credsFor: process 0 is root or uid 100, process 1 is
    uid 200; group 30 is shared so the group class is exercised both ways."""
    return {
        0: {"uid": 0 if with_root else 100, "gid": 10, "gids": [10, 30]},
        1: {"uid": 200, "gid": 20, "gids": [20, 30]},
    }


class Replayer:
    AUDIT_PID = 3          # an out-of-band root worker for the final sweep

    def __init__(self, driver, caps, registry, keep_going=False,
                 verbose=False, strict_atime=True):
        self.drv = driver
        self.bs = driver.block_size
        self.caps = caps
        # Whether to hold the target to the atime marks the model predicts.
        # A mount option, not a filesystem property: under relatime whether
        # an access is recorded depends on how the previous mtime compares,
        # so the runner mounts strictatime and this stays on.
        self.strict_atime = strict_atime
        self.registry = registry
        self.keep_going = keep_going
        self.verbose = verbose
        self.fdmap = {}       # (pid, model fd) -> real fd
        self.sidmap = {}      # model sid -> driver stream id
        self.inomap = {}      # model ino -> (st_dev, st_ino)
        self.shadow = {}      # model ino -> bytearray
        self.timemap = {}     # (model ino, field) -> (abstract, (sec, ns))
        self.history = []
        self.deviations_hit = collections.Counter()
        # (op, canonical, chosen) -> count, for the permitted alternates this
        # implementation took.  Reported, because "which of the allowed
        # answers does it give" is worth knowing even though it is not a
        # divergence.
        self.alts_taken = collections.Counter()
        self.findings = []
        self.abandoned = None    # (step, deviation id) once state diverges
        self._ctx = {}

        for pid, cred in creds_for(caps["withRoot"]).items():
            r = self.drv.request(op="setcred", pid=pid, **cred)
            if r.get("err"):
                raise RuntimeError(f"setcred pid {pid} {cred}: {r}")

    # -- paths ------------------------------------------------------------

    def real_path(self, pth):
        # The driver's workers are chrooted into the filesystem under test,
        # so a model path is already a real one: no mount prefix to add,
        # and ".." at the root stays at the root as the model says.
        comps = [_expand(c) for c in pth["comps"]]
        if pth["abs"]:
            p = "/" + "/".join(comps)
            if pth["slash"] and comps:
                p += "/"
            return p
        p = "/".join(comps)
        if pth["slash"] and comps:
            p += "/"
        return p

    def real_target(self, tgt):
        comps = [_expand(c) for c in tgt["comps"]]
        if tgt["abs"]:
            return "/" + "/".join(comps)
        return "/".join(comps)

    def at_args(self, pid, dfd, pth, key="dirfd"):
        """The dirfd half of an *at call.

        The model's dfd == -1 means "the plain call".  For an absolute path
        that is exactly the *at call with any dirfd, so the plain entry
        point is used and genuinely exercised.  For a relative path there is
        no plain call that could work -- POSIX resolves it against the
        process CWD, which the model does not have -- and the model predicts
        EBADF, so the *at form is issued with an invalid descriptor, which
        is the same answer for the same reason.
        """
        if dfd == -1:
            if pth["abs"]:
                return None
            return {key: -1}
        return {key: self.rfd(pid, dfd)}

    # -- byte shadow ------------------------------------------------------

    @staticmethod
    def pat_byte(pat, pos):
        return 1 + ((31 * pat + pos) % 255)

    def write_bytes(self, pat, off, length):
        return bytes(self.pat_byte(pat, off + i) for i in range(length))

    def shadow_apply(self, ino, off, data):
        sh = self.shadow.setdefault(ino, bytearray())
        end = off + len(data)
        if len(sh) < end:
            sh.extend(b"\0" * (end - len(sh)))
        sh[off:end] = data

    def shadow_read(self, ino, off, count):
        sh = self.shadow.get(ino, b"")
        chunk = bytes(sh[off:off + count])
        if len(chunk) < count:
            chunk += b"\0" * (count - len(chunk))
        return chunk

    def shadow_resize(self, ino, n):
        sh = self.shadow.setdefault(ino, bytearray())
        if n < len(sh):
            del sh[n:]
        else:
            sh.extend(b"\0" * (n - len(sh)))

    def shadow_punch(self, ino, off, length):
        sh = self.shadow.get(ino)
        if sh is None:
            return
        hi = min(off + length, len(sh))
        if hi > off:
            sh[off:hi] = b"\0" * (hi - off)

    # -- model-state queries ----------------------------------------------

    def model_ino_of_fd(self, pid, mfd):
        ps = self._ctx.get("ps")
        if ps is None:
            return None
        ofd = ps["fds"].get((pid, mfd))
        if ofd is None:
            return None
        return ps["ofds"][ofd]["ino"]

    def path_ino(self, fs, comps):
        ino = 0
        for name in comps:
            node = fs["inodes"].get(ino)
            if node is None:
                return None
            ino = node["ents"].get(name)
            if ino is None:
                return None
        return ino

    def rfd(self, pid, mfd):
        return self.fdmap.get((pid, mfd), BADFD)

    def rsid(self, msid):
        return self.sidmap.get(msid, -1)

    # -- finding bookkeeping ----------------------------------------------

    def note(self, kind, expected, actual, detail=""):
        """Record a disagreement.  True if the registry reconciles it."""
        f = Finding(self._ctx.get("tag", "?"), kind, expected, actual, detail)
        dev = self.registry.lookup(f, self._ctx) if self.registry else None
        if dev is None:
            self.findings.append(f)
            return False
        self.deviations_hit[dev.id] += 1
        if not dev.is_reconcilable(f, self._ctx) and self.abandoned is None:
            self.abandoned = (self._ctx.get("step"), dev.id, str(f))
        return True

    def check_status(self, expected, actual, detail=""):
        """True if the errno matches (proceed with success-path checks).

        The model may name more than one acceptable errno: where POSIX gives
        a condition two spellings -- rmdir on a non-empty directory is
        {ENOTEMPTY, EEXIST}, a sticky refusal is {EPERM, EACCES} -- the trace
        carries the alternates alongside the canonical answer and any of them
        conforms.  An implementation that picks a permitted alternate is not
        deviating from anything, so this is not a deviation-registry matter
        and no entry is written for it."""
        if actual == expected:
            return True
        if actual in self._ctx.get("alt", ()):
            self.alts_taken[(self._ctx.get("tag"), expected, actual)] += 1
            return False
        # An absent interface refuses every call, whatever the model
        # expected of the arguments -- ext4 answers FICLONERANGE with
        # EOPNOTSUPP before it looks at the ranges at all -- so this does not
        # test `expected`.
        tag = self._ctx.get("tag")
        if (actual in NOT_IMPLEMENTED and expected not in NOT_IMPLEMENTED
                and tag in CAPABILITY_OPS
                and self._ctx.get("capability_op")):
            raise NotApplicable(self._ctx.get("step"), tag,
                                CAPABILITY_OPS[tag])
        self.note("status", expected, actual, detail)
        return False

    # -- attribute checks -------------------------------------------------

    def check_time(self, mino, field, abstract, wire):
        if field == "atime" and not self.strict_atime:
            return
        wire = tuple(wire)
        if abstract < 0:
            want = XTIME.get(abstract)
            if want is None:
                self.note(field, abstract, wire, "unmapped explicit instant")
            elif wire != want:
                self.note(field, want, wire,
                          f"explicit instant {abstract}")
            self.timemap[(mino, field)] = (abstract, wire)
            return
        key = (mino, field)
        prev = self.timemap.get(key)
        if prev is None or prev[0] < 0:
            self.timemap[key] = (abstract, wire)
        elif abstract == prev[0]:
            if wire != prev[1]:
                self.note(field, prev[1], wire,
                          f"model instant unchanged ({abstract}) but the "
                          f"wire value moved")
        elif abstract > prev[0]:
            if wire < prev[1]:
                self.note(field, f">= {prev[1]}", wire,
                          f"model instant advanced {prev[0]} -> {abstract} "
                          f"but the wire value went backwards")
            self.timemap[key] = (abstract, wire)
        else:
            self.note(field, prev[0], abstract,
                      "model instant went backwards (harness bug?)")

    def check_identity(self, mino, res, fs):
        ident = (res.get("dev"), res.get("ino"))
        known = self.inomap.get(mino)
        if known is None:
            for other, oident in self.inomap.items():
                if oident == ident and other != mino and \
                        other in fs["inodes"]:
                    self.note("identity", f"!= {ident}", ident,
                              f"st_ino of model ino {mino} collides with "
                              f"live model ino {other}")
            self.inomap[mino] = ident
        elif known != ident:
            self.note("identity", known, ident,
                      f"model ino {mino} changed identity")

    def check_statres(self, rv, res, fs):
        want_ftype = FTYPE_MAP[rv["ftype"]["tag"]]
        if res.get("ftype") != want_ftype:
            self.note("ftype", want_ftype, res.get("ftype"))
        if rv["ftype"]["tag"] == "FLnk":
            # POSIX leaves a symlink's permission bits unspecified and no
            # call consults them; deliberately not asserted.
            pass
        elif res.get("mode") != rv["mode"]:
            self.note("mode", oct(rv["mode"]), oct(res.get("mode", 0)))
        if res.get("uid") != rv["uid"]:
            self.note("uid", rv["uid"], res.get("uid"))
        if res.get("gid") != rv["gid"]:
            self.note("gid", rv["gid"], res.get("gid"))
        if res.get("nlink") != rv["nlink"]:
            self.note("nlink", rv["nlink"], res.get("nlink"))
        if rv["ftype"]["tag"] == "FReg":
            if res.get("size") != rv["sizeB"]:
                self.note("size", rv["sizeB"], res.get("size"))
        elif rv["ftype"]["tag"] == "FLnk":
            node = fs["inodes"].get(rv["ino"])
            if node is not None:
                want = len(self.real_target(node["target"]))
                if res.get("size") != want:
                    self.note("size", want, res.get("size"),
                              "symlink target length")
        self.check_identity(rv["ino"], res, fs)
        self.check_time(rv["ino"], "atime", rv["atime"], res["atime"])
        self.check_time(rv["ino"], "mtime", rv["mtime"], res["mtime"])
        self.check_time(rv["ino"], "ctime", rv["ctime"], res["ctime"])

    # -- descriptor ops ---------------------------------------------------

    def op_open(self, pid, rv, res, fs):
        fl = rv["fl"]
        flags = ACC_FLAGS[fl["acc"]["tag"]]
        for name, bit in (("creat", os.O_CREAT), ("excl", os.O_EXCL),
                          ("trunc", os.O_TRUNC), ("appendF", os.O_APPEND),
                          ("directory", os.O_DIRECTORY),
                          ("nofollow", os.O_NOFOLLOW)):
            if fl[name]:
                flags |= bit
        at = self.at_args(pid, rv["dfd"], rv["pth"])
        op = "open" if at is None else "openat"
        r = self.drv.request(op=op, pid=pid, path=self.real_path(rv["pth"]),
                             flags=flags, mode=fl["mode"], **(at or {}))
        if self.check_status(res["e"], r["err"]) and res["e"] == 0:
            self.fdmap[(pid, res["fd"])] = r["ret"]
            if fl["trunc"]:
                ino = self.model_ino_of_fd(pid, res["fd"])
                if ino is not None:
                    self.shadow_resize(ino, 0)
        elif res["e"] != 0 and r["err"] == 0 and r["ret"] >= 0:
            # The model refused and the filesystem did not: the descriptor
            # is real and belongs to no model fd, so close it before it
            # outlives the trace.  An O_CREAT may also have minted a file
            # the model does not have, and that residue is not inert -- a
            # later step meets an object the model never heard of and
            # diverges for reasons that have nothing to do with the refusal.
            # Remove it, but only when the model really lacks the path: an
            # O_CREAT over a file that already existed created nothing.
            self.drv.request(op="close", pid=pid, fd=r["ret"])
            if fl["creat"] and self.path_ino(fs, rv["pth"]["comps"]) is None:
                self.drv.request(op="unlink", pid=pid,
                                 path=self.real_path(rv["pth"]))
        return r

    def op_close(self, pid, rv, res, fs):
        r = self.drv.request(op="close", pid=pid, fd=self.rfd(pid, rv["fd"]))
        if self.check_status(res["e"], r["err"]) and res["e"] == 0:
            self.fdmap.pop((pid, rv["fd"]), None)
        return r

    def op_dup(self, pid, rv, res, fs):
        r = self.drv.request(op="dup", pid=pid, fd=self.rfd(pid, rv["fd"]))
        if self.check_status(res["e"], r["err"]) and res["e"] == 0:
            self.fdmap[(pid, res["fd"])] = r["ret"]
        elif res["e"] != 0 and r["err"] == 0 and r["ret"] >= 0:
            self.drv.request(op="close", pid=pid, fd=r["ret"])
        return r

    def op_dup2(self, pid, rv, res, fs):
        target = self.fdmap.get((pid, rv["nfd"]))
        if rv["fd"] == rv["nfd"] or target is not None:
            # A live target (or a self-dup): the real dup2 exercises the
            # implicit close of the old description.
            r = self.drv.request(op="dup2", pid=pid,
                                 fd=self.rfd(pid, rv["fd"]),
                                 nfd=self.rfd(pid, rv["nfd"]))
        else:
            # The model's nfd names a free slot.  Real descriptor numbers
            # are the kernel's, not the model's, and the number is never
            # asserted, so plain dup() is observationally identical.
            r = self.drv.request(op="dup", pid=pid,
                                 fd=self.rfd(pid, rv["fd"]))
        if self.check_status(res["e"], r["err"]) and res["e"] == 0:
            self.fdmap[(pid, rv["nfd"])] = r["ret"]
        elif res["e"] != 0 and r["err"] == 0 and r["ret"] >= 0:
            self.drv.request(op="close", pid=pid, fd=r["ret"])
        return r

    def op_fcntl_dupfd(self, pid, rv, res, fs):
        r = self.drv.request(op="fcntl_dupfd", pid=pid,
                             fd=self.rfd(pid, rv["fd"]),
                             atleast=rv["atLeast"])
        if self.check_status(res["e"], r["err"]) and res["e"] == 0:
            self.fdmap[(pid, res["fd"])] = r["ret"]
        elif res["e"] != 0 and r["err"] == 0 and r["ret"] >= 0:
            self.drv.request(op="close", pid=pid, fd=r["ret"])
        return r

    def op_fcntl_getfl(self, pid, rv, res, fs):
        r = self.drv.request(op="fcntl_getfl", pid=pid,
                             fd=self.rfd(pid, rv["fd"]))
        if self.check_status(res["e"], r["err"]) and res["e"] == 0:
            want = ACC_FLAGS[res["acc"]["tag"]]
            if (r["ret"] & os.O_ACCMODE) != want:
                self.note("accmode", want, r["ret"] & os.O_ACCMODE)
            if bool(r["ret"] & os.O_APPEND) != res["appendF"]:
                self.note("appendF", res["appendF"],
                          bool(r["ret"] & os.O_APPEND))
        return r

    def op_fcntl_setfl(self, pid, rv, res, fs):
        r = self.drv.request(op="fcntl_setfl", pid=pid,
                             fd=self.rfd(pid, rv["fd"]),
                             flags=os.O_APPEND if rv["appendF"] else 0)
        self.check_status(res["e"], r["err"])
        return r

    # -- data ops ---------------------------------------------------------

    def op_lseek(self, pid, rv, res, fs):
        ino = self.model_ino_of_fd(pid, rv["fd"])
        node = fs["inodes"].get(ino) if ino is not None else None
        self._ctx["whence"] = rv["wh"]["tag"]
        self._ctx["capability_op"] = rv["wh"]["tag"] in ("WData", "WHole")
        self._ctx["on_dir"] = node is not None and \
            node["ftype"]["tag"] == "FDir"
        # Whether any byte at or after the queried offset was ever WRITTEN,
        # as opposed to merely reserved by fallocate or spanned by a
        # truncate.  ext4 cannot tell an allocated-but-unwritten extent from
        # a hole (see EXT4-5), and the shadow is the only thing that knows.
        self._ctx["written_after"] = self.written_after(ino, rv["off"])
        r = self.drv.request(op="lseek", pid=pid, fd=self.rfd(pid, rv["fd"]),
                             off=rv["off"],
                             whence=WHENCE_MAP[rv["wh"]["tag"]])
        diverged = r["err"] != res["e"] or (res["e"] == 0 and
                                            r["ret"] != res["off"])
        if self.check_status(res["e"], r["err"]) and res["e"] == 0:
            if r["ret"] != res["off"]:
                self.note("offset", res["off"], r["ret"])
        if diverged:
            # An lseek that disagrees leaves the descriptor at a different
            # place than the model believes, and every later read, write or
            # relative seek through it would then disagree for that one
            # reason -- one of them spectacularly, because ext4 answers
            # SEEK_HOLE on a directory with the maximum file size and a
            # subsequent readv is EINVAL on the overflow rather than EISDIR
            # on the directory.  Put the offset back where the model says it
            # is.  The repair is exact: the trace's post-state names the
            # offset, and nothing else about an lseek is state.
            self.resync_offset(pid, rv["fd"])
        return r

    def resync_offset(self, pid, mfd):
        ps = self._ctx.get("ps")
        real = self.fdmap.get((pid, mfd))
        if ps is None or real is None:
            return
        ofd = ps["fds"].get((pid, mfd))
        if ofd is None:
            return
        self.drv.request(op="lseek", pid=pid, fd=real,
                         off=ps["ofds"][ofd]["offset"], whence="set")

    def written_after(self, ino, off):
        """True when the byte shadow holds a written (nonzero) byte at or
        after `off`.  A zero byte is either a hole or a fallocate-reserved
        block; either way nothing put data there."""
        if ino is None:
            return False
        sh = self.shadow.get(ino)
        if not sh:
            return False
        return any(sh[max(off, 0):])

    def _check_read(self, r, res):
        if self.check_status(res["e"], r["err"]) and res["e"] == 0:
            if r["ret"] != res["n"]:
                self.note("count", res["n"], r["ret"])
                return
            data = base64.b64decode(r.get("data", ""))
            expect = self.shadow_read(res["ino"], res["off"], res["n"])
            if data != expect:
                self.note("data", f"{len(expect)}B shadow",
                          f"{len(data)}B read",
                          first_diff(expect, data, self.bs))

    def _check_write(self, r, res):
        if self.check_status(res["e"], r["err"]) and res["e"] == 0:
            if r["ret"] != res["n"]:
                self.note("count", res["n"], r["ret"])

    def _write_and_shadow(self, op, pid, rv, res, **kw):
        # Stamp offset-derived bytes at the model's landing offset, issue
        # the write, and (on success) record them in the shadow.
        data = self.write_bytes(rv["pat"], res.get("off", 0), rv["len"])
        r = self.drv.request(op=op, pid=pid, fd=self.rfd(pid, rv["fd"]),
                             data=base64.b64encode(data).decode(), **kw)
        if res["e"] == 0:
            self.shadow_apply(res["ino"], res["off"], data)
        return r

    def op_read(self, pid, rv, res, fs):
        r = self.drv.request(op="read", pid=pid, fd=self.rfd(pid, rv["fd"]),
                             len=rv["len"])
        self._check_read(r, res)
        return r

    def op_pread(self, pid, rv, res, fs):
        r = self.drv.request(op="pread", pid=pid, fd=self.rfd(pid, rv["fd"]),
                             off=rv["off"], len=rv["len"])
        self._check_read(r, res)
        return r

    def op_readv(self, pid, rv, res, fs):
        r = self.drv.request(op="readv", pid=pid, fd=self.rfd(pid, rv["fd"]),
                             len=rv["len"])
        self._check_read(r, res)
        return r

    def op_preadv(self, pid, rv, res, fs):
        r = self.drv.request(op="preadv", pid=pid,
                             fd=self.rfd(pid, rv["fd"]),
                             off=rv["off"], len=rv["len"])
        self._check_read(r, res)
        return r

    def op_write(self, pid, rv, res, fs):
        r = self._write_and_shadow("write", pid, rv, res)
        self._check_write(r, res)
        return r

    def op_pwrite(self, pid, rv, res, fs):
        r = self._write_and_shadow("pwrite", pid, rv, res, off=rv["off"])
        self._check_write(r, res)
        self._check_pwrite_landed(pid, rv, res, fs)
        return r

    def _check_pwrite_landed(self, pid, rv, res, fs):
        """Did the write land where POSIX says it should?

        XSH pwrite writes at the given offset "regardless of whether
        O_APPEND is set"; Linux appends instead (pwrite(2), BUGS).  Nothing
        in the reply says where the bytes went, so the size afterwards is
        what tells them apart -- and it has to be caught here, because by
        the time the difference shows up as a surprising file offset several
        steps later there is nothing left to attribute it to."""
        if res["e"] != 0 or res.get("ino", -1) < 0:
            return
        ofd = (self._ctx.get("ps") or {}).get("fds", {}).get((pid, rv["fd"]))
        ps = self._ctx.get("ps") or {}
        if ofd is None or not ps.get("ofds", {}).get(ofd, {}).get("appendF"):
            return
        node = fs["inodes"].get(res["ino"])
        if node is None:
            return
        st = self.drv.request(op="fstat", pid=pid, fd=self.rfd(pid, rv["fd"]))
        if st.get("err") or st.get("size") == node["size"]:
            return
        self.note("size", node["size"], st.get("size"),
                  "pwrite through an O_APPEND descriptor did not land at "
                  "the offset it was given")

    def op_writev(self, pid, rv, res, fs):
        r = self._write_and_shadow("writev", pid, rv, res)
        self._check_write(r, res)
        return r

    def op_pwritev(self, pid, rv, res, fs):
        r = self._write_and_shadow("pwritev", pid, rv, res, off=rv["off"])
        self._check_write(r, res)
        return r

    def op_truncate(self, pid, rv, res, fs):
        r = self.drv.request(op="truncate", pid=pid,
                             path=self.real_path(rv["pth"]), len=rv["len"])
        if self.check_status(res["e"], r["err"]) and res["e"] == 0:
            ino = self.path_ino(fs, rv["pth"]["comps"])
            if ino is not None:
                self.shadow_resize(ino, rv["len"])
        return r

    def op_ftruncate(self, pid, rv, res, fs):
        r = self.drv.request(op="ftruncate", pid=pid,
                             fd=self.rfd(pid, rv["fd"]), len=rv["len"])
        if self.check_status(res["e"], r["err"]) and res["e"] == 0:
            ino = self.model_ino_of_fd(pid, rv["fd"])
            if ino is not None:
                self.shadow_resize(ino, rv["len"])
        return r

    def op_fsync(self, pid, rv, res, fs):
        r = self.drv.request(op="fdatasync" if rv["dataOnly"] else "fsync",
                             pid=pid, fd=self.rfd(pid, rv["fd"]))
        self.check_status(res["e"], r["err"])
        return r

    def op_fallocate(self, pid, rv, res, fs):
        r = self.drv.request(op="fallocate", pid=pid,
                             fd=self.rfd(pid, rv["fd"]), mode=rv["mode"],
                             off=rv["off"], len=rv["len"])
        if self.check_status(res["e"], r["err"]) and res["e"] == 0:
            ino = self.model_ino_of_fd(pid, rv["fd"])
            if ino is not None:
                if rv["mode"] == 0:
                    end = rv["off"] + rv["len"]
                    if len(self.shadow.setdefault(ino, bytearray())) < end:
                        self.shadow_resize(ino, end)
                else:
                    self.shadow_punch(ino, rv["off"], rv["len"])
        return r

    def op_copy_range(self, pid, rv, res, fs):
        self._ctx["capability_op"] = True
        r = self.drv.request(op="copy_range", pid=pid,
                             fd_in=self.rfd(pid, rv["fdIn"]),
                             off_in=rv["offIn"],
                             fd_out=self.rfd(pid, rv["fdOut"]),
                             off_out=rv["offOut"], len=rv["len"])
        if self.check_status(res["e"], r["err"]) and res["e"] == 0:
            if r["ret"] != res["n"]:
                self.note("count", res["n"], r["ret"])
            elif res["n"] > 0:
                si = self.model_ino_of_fd(pid, rv["fdIn"])
                di = self.model_ino_of_fd(pid, rv["fdOut"])
                if si is not None and di is not None:
                    self.shadow_apply(di, rv["offOut"],
                                      self.shadow_read(si, rv["offIn"],
                                                       res["n"]))
        return r

    def op_clone_range(self, pid, rv, res, fs):
        self._ctx["capability_op"] = True
        r = self.drv.request(op="clone_range", pid=pid,
                             dst_fd=self.rfd(pid, rv["fdDst"]),
                             dst_off=rv["offDst"],
                             src_fd=self.rfd(pid, rv["fdSrc"]),
                             src_off=rv["offSrc"], len=rv["len"])
        if self.check_status(res["e"], r["err"]) and res["e"] == 0:
            si = self.model_ino_of_fd(pid, rv["fdSrc"])
            di = self.model_ino_of_fd(pid, rv["fdDst"])
            if si is not None and di is not None:
                self.shadow_apply(di, rv["offDst"],
                                  self.shadow_read(si, rv["offSrc"],
                                                   rv["len"]))
        return r

    # -- metadata ops -----------------------------------------------------

    def op_stat(self, pid, rv, res, fs):
        at = self.at_args(pid, rv["dfd"], rv["pth"])
        op = "stat" if at is None else "fstatat"
        r = self.drv.request(op=op, pid=pid, path=self.real_path(rv["pth"]),
                             follow=rv["follow"], **(at or {}))
        if self.check_status(res["e"], r["err"]) and res["e"] == 0:
            self.check_statres(res, r, fs)
        return r

    def op_fstat(self, pid, rv, res, fs):
        r = self.drv.request(op="fstat", pid=pid, fd=self.rfd(pid, rv["fd"]))
        if self.check_status(res["e"], r["err"]) and res["e"] == 0:
            self.check_statres(res, r, fs)
        return r

    def op_statfs(self, pid, rv, res, fs):
        r = self.drv.request(op="statfs", pid=pid,
                             path=self.real_path(rv["pth"]))
        self.check_status(res["e"], r["err"])
        return r

    def op_statvfs(self, pid, rv, res, fs):
        r = self.drv.request(op="statvfs", pid=pid,
                             path=self.real_path(rv["pth"]))
        self.check_status(res["e"], r["err"])
        return r

    def op_fstatfs(self, pid, rv, res, fs):
        r = self.drv.request(op="fstatfs", pid=pid,
                             fd=self.rfd(pid, rv["fd"]))
        self.check_status(res["e"], r["err"])
        return r

    def op_fstatvfs(self, pid, rv, res, fs):
        r = self.drv.request(op="fstatvfs", pid=pid,
                             fd=self.rfd(pid, rv["fd"]))
        self.check_status(res["e"], r["err"])
        return r

    def op_chmod(self, pid, rv, res, fs):
        at = self.at_args(pid, rv["dfd"], rv["pth"])
        r = self.drv.request(op="chmod", pid=pid,
                             path=self.real_path(rv["pth"]),
                             mode=rv["mode"], **(at or {}))
        self.check_status(res["e"], r["err"])
        return r

    def op_fchmod(self, pid, rv, res, fs):
        r = self.drv.request(op="fchmod", pid=pid,
                             fd=self.rfd(pid, rv["fd"]), mode=rv["mode"])
        self.check_status(res["e"], r["err"])
        return r

    def op_chown(self, pid, rv, res, fs):
        r = self.drv.request(op="chown", pid=pid,
                             path=self.real_path(rv["pth"]),
                             uid=rv["u"], gid=rv["g"], follow=rv["follow"])
        self.check_status(res["e"], r["err"])
        return r

    def op_fchown(self, pid, rv, res, fs):
        r = self.drv.request(op="fchown", pid=pid,
                             fd=self.rfd(pid, rv["fd"]),
                             uid=rv["u"], gid=rv["g"])
        self.check_status(res["e"], r["err"])
        return r

    @staticmethod
    def _ts_args(prefix, ts):
        tag = ts["tag"]
        if tag == "TsNow":
            return {prefix + "type": "now"}
        if tag == "TsOmit":
            return {prefix + "type": "omit"}
        sec, nsec = XTIME[ts["value"]]
        return {prefix + "type": "val", prefix + "sec": sec,
                prefix + "nsec": nsec}

    def op_utimens(self, pid, rv, res, fs):
        args = {}
        args.update(self._ts_args("a", rv["ta"]))
        args.update(self._ts_args("m", rv["tm"]))
        at = self.at_args(pid, rv["dfd"], rv["pth"])
        op = "utimens" if at is None else "utimensat"
        r = self.drv.request(op=op, pid=pid,
                             path=self.real_path(rv["pth"]),
                             **args, **(at or {}))
        self.check_status(res["e"], r["err"])
        return r

    def op_futimens(self, pid, rv, res, fs):
        args = {}
        args.update(self._ts_args("a", rv["ta"]))
        args.update(self._ts_args("m", rv["tm"]))
        r = self.drv.request(op="futimens", pid=pid,
                             fd=self.rfd(pid, rv["fd"]), **args)
        self.check_status(res["e"], r["err"])
        return r

    def op_access(self, pid, rv, res, fs):
        at = self.at_args(pid, rv["dfd"], rv["pth"])
        r = self.drv.request(op="access", pid=pid,
                             path=self.real_path(rv["pth"]),
                             r=rv["r"], w=rv["w"], x=rv["x"], eff=rv["eff"],
                             **(at or {}))
        self.check_status(res["e"], r["err"])
        return r

    def op_umask(self, pid, rv, res, fs):
        r = self.drv.request(op="umask", pid=pid, mask=rv["mask"])
        if r["ret"] != res["old"]:
            self.note("umask", res["old"], r["ret"],
                      "the driver's per-worker umask disagrees with the "
                      "model's (harness bug)")
        return r

    # -- namespace ops ----------------------------------------------------

    def op_mkdir(self, pid, rv, res, fs):
        at = self.at_args(pid, rv["dfd"], rv["pth"])
        op = "mkdir" if at is None else "mkdirat"
        r = self.drv.request(op=op, pid=pid, path=self.real_path(rv["pth"]),
                             mode=rv["mode"], **(at or {}))
        self.check_status(res["e"], r["err"])
        return r

    def op_mknod(self, pid, rv, res, fs):
        r = self.drv.request(op="mknod", pid=pid,
                             path=self.real_path(rv["pth"]),
                             mode=rv["mode"],
                             ftype=FTYPE_MAP.get(rv["ft"]["tag"], "reg"))
        self.check_status(res["e"], r["err"])
        return r

    def op_symlink(self, pid, rv, res, fs):
        r = self.drv.request(op="symlink", pid=pid,
                             target=self.real_target(rv["tgt"]),
                             path=self.real_path(rv["pth"]))
        self.check_status(res["e"], r["err"])
        return r

    def op_link(self, pid, rv, res, fs):
        args = {}
        old_at = self.at_args(pid, rv["dfdOld"], rv["pthOld"], "olddirfd")
        new_at = self.at_args(pid, rv["dfdNew"], rv["pthNew"], "newdirfd")
        args.update(old_at or {})
        args.update(new_at or {})
        r = self.drv.request(op="link", pid=pid,
                             old=self.real_path(rv["pthOld"]),
                             new=self.real_path(rv["pthNew"]),
                             follow=rv["followOld"], **args)
        self.check_status(res["e"], r["err"])
        return r

    def op_unlink(self, pid, rv, res, fs):
        at = self.at_args(pid, rv["dfd"], rv["pth"])
        if at is None:
            r = self.drv.request(op="unlink", pid=pid,
                                 path=self.real_path(rv["pth"]))
        else:
            r = self.drv.request(op="unlinkat", pid=pid,
                                 path=self.real_path(rv["pth"]),
                                 rmdir=False, **at)
        self.check_status(res["e"], r["err"])
        return r

    def op_rmdir(self, pid, rv, res, fs):
        at = self.at_args(pid, rv["dfd"], rv["pth"])
        if at is None:
            r = self.drv.request(op="rmdir", pid=pid,
                                 path=self.real_path(rv["pth"]))
        else:
            r = self.drv.request(op="unlinkat", pid=pid,
                                 path=self.real_path(rv["pth"]),
                                 rmdir=True, **at)
        self.check_status(res["e"], r["err"])
        return r

    def op_rename(self, pid, rv, res, fs):
        args = {}
        args.update(self.at_args(pid, rv["dfdOld"], rv["pthOld"],
                                 "olddirfd") or {})
        args.update(self.at_args(pid, rv["dfdNew"], rv["pthNew"],
                                 "newdirfd") or {})
        r = self.drv.request(op="rename", pid=pid,
                             old=self.real_path(rv["pthOld"]),
                             new=self.real_path(rv["pthNew"]), **args)
        self.check_status(res["e"], r["err"])
        return r

    def op_readlink(self, pid, rv, res, fs):
        at = self.at_args(pid, rv["dfd"], rv["pth"])
        r = self.drv.request(op="readlink", pid=pid,
                             path=self.real_path(rv["pth"]), **(at or {}))
        if self.check_status(res["e"], r["err"]) and res["e"] == 0:
            want = self.real_target(res["tgt"])
            if r.get("target") != want:
                self.note("target", want, r.get("target"))
        return r

    # -- directory streams ------------------------------------------------

    def op_opendir(self, pid, rv, res, fs):
        r = self.drv.request(op="opendir", pid=pid,
                             path=self.real_path(rv["pth"]))
        if self.check_status(res["e"], r["err"]) and res["e"] == 0:
            self.sidmap[res["sid"]] = r["ret"]
        elif res["e"] != 0 and r["err"] == 0 and r["ret"] >= 0:
            self.drv.request(op="closedir", pid=pid, sid=r["ret"])
        return r

    def op_readdir(self, pid, rv, res, fs):
        r = self.drv.request(op="readdir", pid=pid, sid=self.rsid(rv["sid"]))
        if self.check_status(res["e"], r["err"]) and res["e"] == 0:
            names = r.get("names", [])
            if len(names) != len(set(names)):
                self.note("names", "no duplicates", sorted(names))
            got = set(names) - {".", ".."}
            want = set(res["names"])
            if got != want:
                self.note("names", sorted(want), sorted(got))
        return r

    def op_rewinddir(self, pid, rv, res, fs):
        r = self.drv.request(op="rewinddir", pid=pid,
                             sid=self.rsid(rv["sid"]))
        self.check_status(res["e"], r["err"])
        return r

    def op_telldir(self, pid, rv, res, fs):
        r = self.drv.request(op="telldir", pid=pid, sid=self.rsid(rv["sid"]))
        self.check_status(res["e"], r["err"])
        return r

    def op_seekdir(self, pid, rv, res, fs):
        r = self.drv.request(op="seekdir", pid=pid, sid=self.rsid(rv["sid"]),
                             loc=rv["loc"])
        self.check_status(res["e"], r["err"])
        return r

    def op_closedir(self, pid, rv, res, fs):
        r = self.drv.request(op="closedir", pid=pid,
                             sid=self.rsid(rv["sid"]))
        if self.check_status(res["e"], r["err"]) and res["e"] == 0:
            self.sidmap.pop(rv["sid"], None)
        return r

    # -- record locks -----------------------------------------------------

    def op_fcntl_lock(self, pid, rv, res, fs):
        cmd = LOCK_CMD[rv["cmd"]["tag"]]
        r = self.drv.request(op="fcntl_lock", pid=pid,
                             fd=self.rfd(pid, rv["fd"]), cmd=cmd,
                             type=LOCK_TYPE[rv["lk"]["tag"]],
                             start=rv["lo"], len=rv["hi"] - rv["lo"])
        if self.check_status(res["e"], r["err"]) and res["e"] == 0 \
                and cmd == "getlk":
            conflict = r.get("l_type", "un") != "un"
            if conflict != res["conflict"]:
                self.note("conflict", res["conflict"], conflict,
                          f"l_type {r.get('l_type')}")
            elif conflict:
                # POSIX lets the kernel name ANY of the blocking locks, so
                # what is checkable is that the one it named is in the
                # model's conflict set, with a type the model says that
                # owner blocks with.
                want = {"wr": set(res["cwowners"]),
                        "rd": set(res["crowners"])}.get(r["l_type"], set())
                if not want:
                    self.note("l_type", "a blocking lock type", r["l_type"])
        return r

    def op_lockf(self, pid, rv, res, fs):
        r = self.drv.request(op="lockf", pid=pid, fd=self.rfd(pid, rv["fd"]),
                             cmd=LOCKF_CMD[rv["cmd"]["tag"]], len=rv["len"])
        self.check_status(res["e"], r["err"])
        return r

    HANDLERS = {
        "ROpen": op_open, "RClose": op_close, "RDup": op_dup,
        "RDup2": op_dup2, "RLseek": op_lseek, "RRead": op_read,
        "RWrite": op_write, "RPread": op_pread, "RPwrite": op_pwrite,
        "RReadv": op_readv, "RWritev": op_writev, "RPreadv": op_preadv,
        "RPwritev": op_pwritev, "RStatfs": op_statfs,
        "RStatvfs": op_statvfs, "RFstatfs": op_fstatfs,
        "RFstatvfs": op_fstatvfs, "RTruncate": op_truncate,
        "RFtruncate": op_ftruncate, "RStat": op_stat, "RFstat": op_fstat,
        "RChmod": op_chmod, "RFchmod": op_fchmod, "RChown": op_chown,
        "RFchown": op_fchown, "RUtimens": op_utimens,
        "RFutimens": op_futimens, "RAccess": op_access, "RUmask": op_umask,
        "RMkdir": op_mkdir, "RMknod": op_mknod, "RSymlink": op_symlink,
        "RLink": op_link, "RUnlink": op_unlink, "RRmdir": op_rmdir,
        "RRename": op_rename, "RReadlink": op_readlink,
        "ROpendir": op_opendir, "RReaddir": op_readdir,
        "RRewinddir": op_rewinddir, "RTelldir": op_telldir,
        "RSeekdir": op_seekdir, "RClosedir": op_closedir,
        "RFcntlDupfd": op_fcntl_dupfd, "RFcntlGetfl": op_fcntl_getfl,
        "RFcntlSetfl": op_fcntl_setfl, "RFcntlLock": op_fcntl_lock,
        "RLockf": op_lockf, "RFsync": op_fsync,
        "RCopyRange": op_copy_range, "RCloneRange": op_clone_range,
        "RFallocate": op_fallocate,
    }

    # -- the replay loop --------------------------------------------------

    def replay(self, states):
        for idx, state in enumerate(states[1:], start=1):
            label = state["lastOp"]
            if label["tag"] != "LCall":
                raise TraceFormatError(
                    f"step {idx}: unexpected label {label['tag']}")
            pid = label["value"]["pid"]
            req = label["value"]["req"]
            res = label["value"]["res"]
            tag = req["tag"]
            handler = self.HANDLERS.get(tag)
            if handler is None:
                raise TraceFormatError(f"step {idx}: no handler for {tag}")
            self.findings = []
            self._ctx = {"tag": tag, "req": req["value"], "res": res["value"],
                         "pid": pid, "fs": state["fs"], "ps": state.get("ps"),
                         "caps": self.caps, "step": idx,
                         "alt": set(label["value"].get("alt", []))}
            signal.alarm(120)
            r = handler(self, pid, req["value"], res["value"], state["fs"])
            signal.alarm(0)
            self.history.append((idx, pid, tag, req["value"], res["value"],
                                 r))
            if self.verbose:
                print(f"  [{idx:4d}] pid{pid} {tag} {req['value']} -> {r}")
            if self.findings and not self.keep_going:
                raise Divergence(idx, (tag, req["value"], res["value"]),
                                 self.findings)
            if self.findings:
                report_findings(idx, tag, req["value"], res["value"],
                                self.findings)
                self.all_findings = getattr(self, "all_findings", [])
                self.all_findings.extend(self.findings)
            if self.abandoned is not None:
                # An analyzed deviation that leaves the filesystem in a
                # state the model does not predict.  Every later step would
                # disagree for that one reason, so stop here rather than
                # emit the cascade -- the deviation is reported, and the
                # steps that did run still counted.
                return idx
        return len(states) - 1

    # -- end-of-trace sweep ------------------------------------------------

    def final_audit(self, final_state, nsteps):
        """Walk the final model tree and verify every reachable object's
        identity, attributes, directory contents, data and link target
        against the live filesystem.  Catches silent state drift the
        per-operation checks never observed.  Runs as an out-of-band root
        worker so permission bits cannot mask the comparison."""
        fs = final_state["fs"]
        self.findings = []
        self._ctx = {"tag": "final-audit", "req": {}, "res": {}, "pid": 3,
                     "fs": fs, "ps": None, "caps": self.caps,
                     "step": nsteps}
        audited = 0
        p = self.AUDIT_PID
        self.drv.request(op="setcred", pid=p, uid=0, gid=0, gids=[0])

        stack = [(0, "")]
        while stack and len(self.findings) < 20 and self.abandoned is None:
            ino, rpath = stack.pop()
            node = fs["inodes"][ino]

            r = self.drv.request(op="opendir", pid=p, path=(rpath or "/"))
            if r["err"] != 0:
                self.note("audit", 0, r["err"], f"opendir {rpath or '/'}")
                continue
            sid = r["ret"]
            names = set(self.drv.request(op="readdir", pid=p,
                                         sid=sid).get("names", []))
            self.drv.request(op="closedir", pid=p, sid=sid)
            names -= {".", ".."}

            want_names = set(node["ents"].keys())
            if names != want_names:
                self.note("audit", sorted(want_names), sorted(names),
                          f"entries of {rpath or '/'}")

            for name in sorted(want_names & names):
                cino = node["ents"][name]
                cnode = fs["inodes"][cino]
                cpath = rpath + "/" + name
                ftag = cnode["ftype"]["tag"]
                audited += 1

                st = self.drv.request(op="stat", pid=p,
                                      path=cpath, follow=False)
                if st["err"] != 0:
                    self.note("audit", 0, st["err"], f"lstat {cpath}")
                    continue
                if st.get("ftype") != FTYPE_MAP[ftag]:
                    self.note("audit", FTYPE_MAP[ftag], st.get("ftype"),
                              f"{cpath} ftype")
                    continue
                if ftag != "FLnk" and st.get("mode") != cnode["mode"]:
                    self.note("audit", oct(cnode["mode"]),
                              oct(st.get("mode", 0)), f"{cpath} mode")
                if st.get("uid") != cnode["uid"] or \
                        st.get("gid") != cnode["gid"]:
                    self.note("audit",
                              f"{cnode['uid']}:{cnode['gid']}",
                              f"{st.get('uid')}:{st.get('gid')}",
                              f"{cpath} owner")
                if st.get("nlink") != cnode["nlink"]:
                    self.note("audit", cnode["nlink"], st.get("nlink"),
                              f"{cpath} nlink")
                known = self.inomap.get(cino)
                ident = (st.get("dev"), st.get("ino"))
                if known is not None and known != ident:
                    self.note("audit", known, ident, f"{cpath} identity")

                if ftag == "FDir":
                    stack.append((cino, cpath))
                elif ftag == "FLnk":
                    rl = self.drv.request(op="readlink", pid=p,
                                          path=cpath)
                    want = self.real_target(cnode["target"])
                    if rl["err"] != 0 or rl.get("target") != want:
                        self.note("audit", want, rl.get("target"),
                                  f"readlink {cpath}")
                elif ftag == "FReg":
                    want_size = cnode["size"]
                    if st.get("size") != want_size:
                        self.note("audit", want_size, st.get("size"),
                                  f"{cpath} size")
                        continue
                    if want_size == 0:
                        continue
                    fd = self.drv.request(op="open", pid=p,
                                          path=cpath,
                                          flags=os.O_RDONLY, mode=0)
                    if fd["err"] != 0:
                        self.note("audit", 0, fd["err"], f"open {cpath}")
                        continue
                    chunk = 65536
                    for off in range(0, want_size, chunk):
                        n = min(chunk, want_size - off)
                        rr = self.drv.request(op="pread", pid=p,
                                              fd=fd["ret"], off=off, len=n)
                        data = base64.b64decode(rr.get("data", ""))
                        expect = self.shadow_read(cino, off, n)
                        if data != expect:
                            self.note("audit", f"{n}B shadow",
                                      f"{len(data)}B read",
                                      f"{cpath} content at +{off}" +
                                      first_diff(expect, data, self.bs))
                            break
                    self.drv.request(op="close", pid=p, fd=fd["ret"])

        if self.findings:
            raise Divergence(nsteps, ("final-audit", {}), self.findings)
        return audited

    def cleanup(self):
        """Close everything still open so the next trace's newfs starts
        from a filesystem nothing is holding."""
        try:
            for pid, sid in list(self.sidmap.items()):
                self.drv.request(op="closedir", pid=0, sid=sid)
            for (pid, _), real in list(self.fdmap.items()):
                self.drv.request(op="close", pid=pid, fd=real)
        except (RuntimeError, OSError, ValueError):
            pass


def first_diff(expect, actual, block_size):
    n = min(len(expect), len(actual))
    for i in range(0, n, block_size):
        if expect[i:i + block_size] != actual[i:i + block_size]:
            return (f"; first differing block {i // block_size}: expected "
                    f"byte {expect[i]:#x}, got byte {actual[i]:#x}")
    return "; lengths differ only"


def report_findings(step, tag, req, res, findings):
    print(f"  step {step}: {tag} {req}", file=sys.stderr)
    print(f"    model expectation: {res}", file=sys.stderr)
    for f in findings:
        print(f"    MISMATCH: {f}", file=sys.stderr)


def report_divergence(trace_path, div, replayer):
    print(f"\n=== DIVERGENCE in {trace_path} ===", file=sys.stderr)
    print(f"step {div.step}: {div.op[0]} req: {div.op[1]}", file=sys.stderr)
    if len(div.op) > 2:
        print(f"  model expectation: {div.op[2]}", file=sys.stderr)
    for f in div.findings:
        print(f"  MISMATCH: {f}", file=sys.stderr)
    print("\nlast operations before the failure:", file=sys.stderr)
    for idx, pid, tag, req, res, r in replayer.history[-10:]:
        print(f"  [{idx:4d}] pid{pid} {tag} {req} expect {res} -> {r}",
              file=sys.stderr)
    print("\n(pid, model fd) -> real fd:", file=sys.stderr)
    for k, v in sorted(replayer.fdmap.items()):
        print(f"  {k}: {v}", file=sys.stderr)


# --------------------------------------------------------------------------
# Live-profile probe
#
# Measures the capability/policy knobs POSIX leaves to the implementation,
# so the pinned EXT4_PROFILE above -- and posix_run.qnt's posixExt4 instance,
# which must agree with it -- are a measurement rather than a guess.
# --------------------------------------------------------------------------

def probe(driver_path, root):
    # `root` mounts the filesystem for the driver, which chroots its workers
    # into it; every path below is therefore absolute *within* the
    # filesystem under test, exactly as a model path is.
    drv = Driver(driver_path, root)
    bs = drv.block_size
    out = {}
    root_cred = {"uid": 0, "gid": 10, "gids": [10, 30]}
    user1 = {"uid": 100, "gid": 10, "gids": [10, 30]}
    user2 = {"uid": 200, "gid": 20, "gids": [20, 30]}
    drv.request(op="setcred", pid=0, **root_cred)
    drv.request(op="setcred", pid=1, **user2)
    drv.request(op="setcred", pid=2, **user1)
    blk = base64.b64encode(b"A" * bs).decode()

    def mk(path, pid=0, mode=0o777):
        drv.request(op="mkdir", pid=pid, path=path, mode=mode)

    def touch(path, pid=0, mode=0o666, data=None):
        r = drv.request(op="open", pid=pid, path=path,
                        flags=os.O_CREAT | os.O_WRONLY, mode=mode)
        if data:
            drv.request(op="write", pid=pid, fd=r["ret"], data=data)
        drv.request(op="close", pid=pid, fd=r["ret"])

    def st(path, pid=0):
        return drv.request(op="stat", pid=pid, path=path, follow=True)

    # copy_file_range / FICLONERANGE / SEEK_HOLE
    touch("/p_src", data=blk)
    touch("/p_dst")
    fin = drv.request(op="open", pid=0, path="/p_src",
                      flags=os.O_RDONLY, mode=0)["ret"]
    fout = drv.request(op="open", pid=0, path="/p_dst",
                       flags=os.O_WRONLY, mode=0)["ret"]
    r = drv.request(op="copy_range", pid=0, fd_in=fin, off_in=0,
                    fd_out=fout, off_out=0, len=bs)
    out["copyRange"] = r["ret"] >= 0
    r = drv.request(op="clone_range", pid=0, dst_fd=fout, dst_off=0,
                    src_fd=fin, src_off=0, len=bs)
    out["cloneRange"] = r["err"] == 0
    out["cloneRangeErrno"] = r["err"]
    drv.request(op="ftruncate", pid=0, fd=fout, len=0)
    drv.request(op="pwrite", pid=0, fd=fout, off=0, data=blk)
    drv.request(op="ftruncate", pid=0, fd=fout, len=3 * bs)
    drv.request(op="fsync", pid=0, fd=fout)
    r = drv.request(op="lseek", pid=0, fd=fout, off=0, whence="hole")
    out["seekHole"] = r["ret"] == bs
    out["seekHoleRaw"] = r["ret"]
    drv.request(op="close", pid=0, fd=fin)
    drv.request(op="close", pid=0, fd=fout)

    # gidFromParent: a plain (non-setgid) directory with gid 77; does a file
    # created in it by egid 10 take 77 or 10?
    mk("/p_gid")
    drv.request(op="chown", pid=0, path="/p_gid", uid=0, gid=77,
                follow=True)
    touch("/p_gid/f")
    out["gidFromParent"] = st("/p_gid/f").get("gid") == 77
    out["gidFromParentRaw"] = st("/p_gid/f").get("gid")

    # sgidInherit: a subdirectory of a setgid directory
    mk("/p_sgid")
    drv.request(op="chmod", pid=0, path="/p_sgid", mode=0o2777)
    mk("/p_sgid/sub", mode=0o755)
    out["sgidInherit"] = bool(st("/p_sgid/sub").get("mode", 0) & 0o2000)

    # writeClearsSets: an unprivileged owner writes their setuid file
    touch("/p_setid", pid=1, mode=0o700)
    drv.request(op="chmod", pid=1, path="/p_setid", mode=0o4755)
    fd = drv.request(op="open", pid=1, path="/p_setid",
                     flags=os.O_WRONLY, mode=0)["ret"]
    drv.request(op="write", pid=1, fd=fd, data=blk)
    drv.request(op="close", pid=1, fd=fd)
    out["writeClearsSets"] = not (st("/p_setid", pid=1).get("mode", 0)
                                  & 0o4000)

    # pwriteAppends: pwrite at 0 through an O_APPEND descriptor
    touch("/p_app", data=blk)
    fd = drv.request(op="open", pid=0, path="/p_app",
                     flags=os.O_WRONLY | os.O_APPEND, mode=0)["ret"]
    drv.request(op="pwrite", pid=0, fd=fd, off=0,
                data=base64.b64encode(b"B" * bs).decode())
    drv.request(op="close", pid=0, fd=fd)
    out["pwriteAppends"] = st("/p_app").get("size") == 2 * bs

    # renameCtime
    touch("/p_ren")
    t1 = st("/p_ren")["ctime"]
    time.sleep(0.02)
    drv.request(op="rename", pid=0, old="/p_ren", new="/p_ren2")
    out["renameCtime"] = tuple(st("/p_ren2")["ctime"]) > tuple(t1)

    # strictAtime: does a read mark atime?
    touch("/p_at", data=blk)
    t1 = st("/p_at")["atime"]
    time.sleep(0.02)
    fd = drv.request(op="open", pid=0, path="/p_at",
                     flags=os.O_RDONLY, mode=0)["ret"]
    drv.request(op="read", pid=0, fd=fd, len=bs)
    drv.request(op="close", pid=0, fd=fd)
    out["strictAtime"] = tuple(st("/p_at")["atime"]) > tuple(t1)

    # sticky arm + its errno: a sticky directory holding another user's file
    mk("/p_sticky")
    drv.request(op="chmod", pid=0, path="/p_sticky", mode=0o1777)
    touch("/p_sticky/w", mode=0o666)
    drv.request(op="chown", pid=0, path="/p_sticky/w", uid=100,
                gid=10, follow=True)
    r = drv.request(op="unlink", pid=1, path="/p_sticky/w")
    out["stickyWriteArm"] = r["err"] == 0
    touch("/p_sticky/s", mode=0o600)
    drv.request(op="chown", pid=0, path="/p_sticky/s", uid=100,
                gid=10, follow=True)
    r = drv.request(op="unlink", pid=1, path="/p_sticky/s")
    out["stickyDenyErrno"] = r["err"]
    out["errStickyAcces"] = (r["err"] == 13) if r["err"] else None

    # chownSuppGroup: an owner chgrps their file to a supplementary group
    touch("/p_chgrp", pid=1, mode=0o600)
    r = drv.request(op="chown", pid=1, path="/p_chgrp", uid=-1,
                    gid=30, follow=True)
    out["chownSuppGroup"] = r["err"] == 0
    out["chownSuppGroupErrno"] = r["err"]

    # errNotempty / errUnlinkDirIsdir
    mk("/p_ne")
    mk("/p_ne/x")
    r = drv.request(op="rmdir", pid=0, path="/p_ne")
    out["errNotempty"] = r["err"] == 39
    out["rmdirNonemptyErrno"] = r["err"]
    r = drv.request(op="unlink", pid=0, path="/p_ne")
    out["errUnlinkDirIsdir"] = r["err"] == 21
    out["unlinkDirErrno"] = r["err"]

    # errLockAgain: a conflicting F_SETLK between two processes
    fd0 = drv.request(op="open", pid=0, path="/p_src",
                      flags=os.O_RDWR, mode=0)["ret"]
    drv.request(op="chmod", pid=0, path="/p_src", mode=0o666)
    fd1 = drv.request(op="open", pid=1, path="/p_src",
                      flags=os.O_RDWR, mode=0)["ret"]
    drv.request(op="fcntl_lock", pid=0, fd=fd0, cmd="setlk", type="wr",
                start=0, len=4)
    r = drv.request(op="fcntl_lock", pid=1, fd=fd1, cmd="setlk", type="wr",
                    start=0, len=4)
    out["lockConflictErrno"] = r["err"]
    out["errLockAgain"] = (r["err"] == 11) if r["err"] else None
    drv.request(op="close", pid=0, fd=fd0)
    drv.request(op="close", pid=1, fd=fd1)

    out["withRoot"] = None
    drv.close()
    return out


# --------------------------------------------------------------------------
# Per-trace driving
# --------------------------------------------------------------------------

def replay_one(driver, trace_path, args, registry):
    """Replay one trace against an already-running driver.

    Returns "ok", "skip" or "fail".  The caller resets the filesystem
    between traces: a model trace starts from an empty root, and a `newfs`
    is the only thing that gives it exactly that."""
    states = load_trace(trace_path)
    init = states[0]["lastOp"]
    if init["tag"] != "LInit":
        raise TraceFormatError(f"{trace_path}: first label is not LInit")
    caps = init["value"]["caps"]

    rp = Replayer(driver, caps, registry, keep_going=args.keep_going,
                  verbose=args.verbose,
                  strict_atime=not args.no_strict_atime)
    audited = 0
    steps = 0
    stopped = None       # a deviation that ended the replay before the end
    try:
        steps = rp.replay(states)
        stopped = rp.abandoned
        if stopped is None:
            audited = rp.final_audit(states[-1], len(states) - 1)
    except NotApplicable as na:
        print(f"{trace_path}: SKIP: needs {na.what}, which this filesystem "
              f"does not implement (step {na.step}, {na.op})")
        rp.cleanup()
        return "skip"
    except Divergence as div:
        report_divergence(trace_path, div, rp)
        rp.cleanup()
        return "fail"
    finally:
        signal.alarm(0)
    rp.cleanup()

    if getattr(rp, "all_findings", None):
        print(f"{trace_path}: {len(rp.all_findings)} unreconciled "
              f"finding(s) (survey mode)", file=sys.stderr)
        return "fail"

    alts = ""
    if rp.alts_taken:
        alts = "; permitted alternates: " + ", ".join(
            f"{op} {a} for {e}" for (op, e, a), _ in
            sorted(rp.alts_taken.items()))
    devs = ""
    if rp.deviations_hit:
        devs = "; known deviations: " + ", ".join(
            f"{k}x{v}" for k, v in sorted(rp.deviations_hit.items()))
    devs += alts
    if stopped is not None:
        step, dev_id, what = stopped
        print(f"{trace_path}: {steps} of {len(states) - 1} steps replayed, "
              f"abandoned at step {step} by {dev_id} ({what}){devs}")
    elif rp.abandoned is not None:
        # The replay ran to the end; it was the closing sweep that met a
        # deviation it cannot see past.  Every object after it would report
        # the same thing, so the sweep stops -- but nothing was abandoned.
        _, dev_id, what = rp.abandoned
        print(f"{trace_path}: {steps} steps replayed, {audited} objects "
              f"audited, audit stopped by {dev_id} ({what}){devs}")
    else:
        print(f"{trace_path}: {steps} steps replayed, "
              f"{audited} objects audited{devs}")
    return "ok"


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", required=True,
                    help="mount point of the filesystem under test")
    ap.add_argument("--target", default="ext4", choices=sorted(REGISTRIES),
                    help="which deviation registry and pinned profile to "
                         "use (default: ext4)")
    ap.add_argument("--driver",
                    default=os.path.join(os.path.dirname(
                        os.path.abspath(__file__)), "posix_driver.py"),
                    help="path to posix_driver.py")
    ap.add_argument("--trace", action="append", default=[],
                    help="ITF trace file (repeatable)")
    ap.add_argument("--trace-dir", action="append", default=[],
                    help="directory of ITF traces (repeatable)")
    ap.add_argument("--include-prefix", action="append", default=[],
                    help="with --trace-dir, take only these basenames")
    ap.add_argument("--exclude-prefix", action="append", default=[],
                    help="with --trace-dir, drop these basenames")
    ap.add_argument("--probe", action="store_true",
                    help="measure the live capability/policy profile")
    ap.add_argument("--check-profile", action="store_true",
                    help="measure the live profile and diff it against the "
                         "pinned one")
    ap.add_argument("--no-strict-atime", action="store_true",
                    help="do not hold the target to the atime marks the "
                         "model predicts (for a relatime mount, where "
                         "whether an access is recorded depends on the "
                         "previous mtime)")
    ap.add_argument("--keep-going", action="store_true",
                    help="report every divergence in a trace instead of "
                         "stopping at the first unreconciled one")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    root = os.path.abspath(args.root)
    if not os.path.isdir(root):
        print(f"{root}: not a directory", file=sys.stderr)
        return 2

    def on_alarm(sig, frame):
        print("FATAL: a driver request timed out (a blocked syscall?)",
              file=sys.stderr)
        sys.exit(1)

    signal.signal(signal.SIGALRM, on_alarm)

    if args.probe or args.check_profile:
        measured = probe(args.driver, root)
        print(json.dumps(measured, indent=2, sort_keys=True))
        if args.check_profile:
            recorded = RECORDED_DEPARTURES.get(args.target, set())
            unrecorded, expected = [], []
            for key, assumed in MODEL_ASSUMES.items():
                if assumed is None or measured.get(key) == assumed:
                    continue
                (expected if key in recorded else unrecorded).append(
                    f"{key}: model assumes {assumed}, measured "
                    f"{measured.get(key)}")
            for line in expected:
                print(f"recorded departure -- {line}")
            if unrecorded:
                print("\nUNRECORDED departures from what the model assumes:",
                      file=sys.stderr)
                for line in unrecorded:
                    print(f"  {line}", file=sys.stderr)
                print("Each needs an entry in this target's deviation "
                      "registry, or the model's assumption is wrong.",
                      file=sys.stderr)
                return 1
        return 0

    for d in args.trace_dir:
        for name in sorted(os.listdir(d)):
            if not name.endswith(".itf.json"):
                continue
            if args.include_prefix and \
                    not any(name.startswith(p) for p in args.include_prefix):
                continue
            if any(name.startswith(p) for p in args.exclude_prefix):
                continue
            args.trace.append(os.path.join(d, name))

    if not args.trace:
        print("no traces selected", file=sys.stderr)
        return 77

    registry = REGISTRIES[args.target]
    driver = Driver(args.driver, root)
    replayed = skipped = failures = ran = 0
    try:
        for trace in args.trace:
            if ran > 0:
                reset = driver.request(op="newfs")
                if reset.get("err"):
                    print(f"FATAL: newfs failed before {trace}: {reset}\n"
                          f"{driver.stderr_tail()}", file=sys.stderr)
                    return 1
            status = replay_one(driver, trace, args, registry)
            if status == "ok":
                replayed += 1
                ran += 1
            elif status == "fail":
                failures += 1
                ran += 1
            else:
                skipped += 1
                # A capability skip happens PART WAY THROUGH a trace -- the
                # filesystem has been written to by everything before the
                # call that turned out to need an absent interface -- so the
                # next trace still needs a fresh one.  (A skip used to mean
                # "never touched the filesystem", which is why the reset was
                # keyed on having run.)
                ran += 1
    finally:
        driver.close()

    print(f"batch: {replayed} replayed, {skipped} skipped, {failures} failed "
          f"of {len(args.trace)} trace(s)")
    if failures:
        return 1
    if replayed == 0:
        return 77          # every trace skipped -> the batch is a SKIP
    return 0


if __name__ == "__main__":
    sys.exit(main())
