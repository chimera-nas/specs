#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 The Quint Specs Authors
#
# SPDX-License-Identifier: MIT

"""Replay the generated NFSv3 corpus (quint/nfs/nfs3.qnt) against a live
NFSv3 server and compare every reply to what the model baked into the
trace.

Each state of the trace carries a `lastOp` record naming the RPC the model
issued and the reply the server must produce, plus the model's whole
post-state filesystem (`fs`), which is what the returned attributes are
compared against.  The harness obtains the export root file handle via
MOUNTv3 and replays every step through the standalone client in
nfs3_client.py.

Model-to-wire mapping maintained here:
  - model Fid        -> real nfs_fh3, learned from LOOKUP/CREATE/MKDIR/
                        SYMLINK/MKNOD/READDIRPLUS replies (byte-compared
                        once known)
  - model block i    -> BLOCK_SIZE bytes at offset i * BLOCK_SIZE; block
                        symbol 0 is a hole (zero bytes), symbol s > 0 is
                        BLOCK_SIZE repetitions of byte 0x40 + s
  - fileid           -> not predicted; checked for consistency (a fid must
                        always report the same fileid; live fids distinct)
  - cred             -> AUTH_SYS uid/gid/gids from the op's `cred` (root
                        for ops the model does not drive under a credential)

Two attributes the standard leaves open are not asserted: a symlink's
permission bits (Linux forces 0777, other servers keep what was asked), and
the mode of an EXCLUSIVE-created file before the client's follow-up SETATTR
(RFC 1813 3.3.8 leaves it undefined).  FSSTAT/FSINFO/PATHCONF replies are
checked for the RFC's ordering invariants only, never for a particular
server's constants.

Every divergence is a Finding looked up in the server's deviation
registry (see deviations.py and nfs4_replay.py for the contract).
"""

import argparse
import importlib
import os
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nfs3_client  # noqa: E402
from nfs3_client import (  # noqa: E402
    NFS3_OK, NF3REG, NF3DIR, NF3LNK, NF3SOCK, NF3FIFO,
    UNCHECKED, GUARDED, EXCLUSIVE)
from itf import load_states, Divergence, TraceFormatError, diff_bytes  # noqa: E402
from deviations import Finding  # noqa: E402

BLOCK_SIZE = 8192

FTYPE_WIRE = {"TReg": NF3REG, "TDir": NF3DIR, "TLnk": NF3LNK,
              "TFifo": NF3FIFO, "TSock": NF3SOCK}
CREATE_WIRE = {"Unchecked": UNCHECKED, "Guarded": GUARDED,
               "Exclusive": EXCLUSIVE}

NFS3ERR_JUKEBOX = 10008


class Abandon(Exception):
    def __init__(self, step, dev, finding):
        self.step = step
        self.dev = dev
        self.finding = finding
        super().__init__(f"step {step}: {dev.id}: {finding}")


def load_trace(path):
    states = load_states(path, need=("lastOp", "fs"))
    if states[0]["lastOp"]["tag"] != "OInit":
        raise TraceFormatError(f"{path}: first state is not OInit")
    return states


class Replayer:
    RETRY_JUKEBOX_MAX = 40

    def __init__(self, client, root_fh, registry, keep_going=False,
                 verbose=False):
        self.client = client
        self.registry = registry
        self.keep_going = keep_going
        self.verbose = verbose
        self.fh = {0: root_fh}
        self.fileid = {}
        self.write_verf = None
        self.attr_checks = 0
        self.attr_skips = 0
        self.history = []
        self.deviations_hit = {}
        self.unmatched = []
        self.rpcs = 0
        self._cur = None              # (step, tag, op, post_fs)

    # -- helpers ----------------------------------------------------------

    def hit(self, dev):
        self.deviations_hit[dev.id] = self.deviations_hit.get(dev.id, 0) + 1

    def fnd(self, mism, kind, expected, actual, detail=""):
        mism.append(Finding(self._cur[1], kind, expected, actual, detail))

    @staticmethod
    def block_bytes(sym):
        if sym == 0:
            return b"\0" * BLOCK_SIZE
        return bytes([0x40 + sym]) * BLOCK_SIZE

    def expand(self, syms):
        return b"".join(self.block_bytes(s) for s in syms)

    def real_fh(self, fid):
        fh = self.fh.get(fid)
        if fh is None:
            raise TraceFormatError(f"model fid {fid} has no learned file "
                                   f"handle (earlier divergence?)")
        return fh

    def learn_fh(self, fid, fh, mism):
        if fh is None:
            # post_op_fh3 with handle_follows = FALSE: RFC 1813 lets a server
            # withhold the handle, though every real one returns it.
            self.fnd(mism, "fh", "<handle>", None,
                     f"no file handle returned for fid {fid}")
            return
        known = self.fh.get(fid)
        if known is None:
            self.fh[fid] = fh
        elif known != fh:
            self.fnd(mism, "fh_identity", known.hex(), fh.hex(),
                     f"fid {fid}: file handle changed")

    def set_cred(self, op):
        cred = op.get("cred")
        if cred is None:
            self.client.rpc.set_cred(0, 0, ())
        else:
            self.client.rpc.set_cred(cred["uid"], cred["gid"],
                                     cred.get("gids", ()))

    def check_attrs(self, fid, attrs, post_fs, mism, what="obj_attrs"):
        """Compare a returned fattr3 against the model's post-state node."""
        if attrs is None:
            self.attr_skips += 1
            return
        self.attr_checks += 1
        node = post_fs.get(fid)
        if node is None:
            self.fnd(mism, what, f"fid {fid} in post-state", "absent")
            return
        ftype = node["ftype"]["tag"]
        if attrs["type"] != FTYPE_WIRE[ftype]:
            self.fnd(mism, f"{what}.type", FTYPE_WIRE[ftype], attrs["type"],
                     ftype)
        # Two modes the standard leaves unspecified, so conformant servers
        # legitimately differ: a symlink's bits, and an EXCLUSIVE-created
        # file's before its SETATTR (marked by a non-zero xverf).
        if ftype != "TLnk" and node.get("xverf", 0) == 0 and \
                attrs["mode"] & 0o7777 != node["mode"]:
            self.fnd(mism, f"{what}.mode", f"{node['mode']:#o}",
                     f"{attrs['mode'] & 0o7777:#o}")
        if ftype != "TDir" and attrs["nlink"] != node["nlink"]:
            self.fnd(mism, f"{what}.nlink", node["nlink"], attrs["nlink"])
        if ftype == "TReg":
            expect_size = len(node["data"]) * BLOCK_SIZE
            if attrs["size"] != expect_size:
                self.fnd(mism, f"{what}.size", expect_size, attrs["size"])
        elif ftype == "TLnk":
            if attrs["size"] != len(node["target"]):
                self.fnd(mism, f"{what}.size", len(node["target"]),
                         attrs["size"], "symlink size")
        known = self.fileid.get(fid)
        if known is None:
            for other, other_id in self.fileid.items():
                if other_id == attrs["fileid"] and other in post_fs:
                    self.fnd(mism, f"{what}.fileid", f"!= {other_id}",
                             attrs["fileid"],
                             f"fid {fid} collides with live fid {other}")
            self.fileid[fid] = attrs["fileid"]
        elif known != attrs["fileid"]:
            self.fnd(mism, f"{what}.fileid", known, attrs["fileid"],
                     f"fid {fid} changed fileid")

    def check_status(self, expected, actual, mism):
        """True if the reply status matches (proceed with OK-path checks)."""
        if actual == expected:
            return True
        self.fnd(mism, "status", expected, actual)
        return False

    def call(self, fn, *a, **kw):
        """Issue one RPC, retrying an NFS3ERR_JUKEBOX the model did not
        predict (a transient the RFC tells clients to retry)."""
        expected = self._cur[2].get("status")
        for _ in range(self.RETRY_JUKEBOX_MAX):
            res = fn(*a, **kw)
            self.rpcs += 1
            if res["status"] != NFS3ERR_JUKEBOX or expected == NFS3ERR_JUKEBOX:
                return res
            time.sleep(0.1)
        return res

    # -- per-procedure handlers -------------------------------------------

    def op_lookup(self, op, post_fs, mism):
        res = self.call(self.client.lookup, self.real_fh(op["dir"]),
                        op["name"])
        if self.check_status(op["status"], res["status"], mism) \
                and op["status"] == NFS3_OK:
            self.learn_fh(op["child"], res["obj_fh"], mism)
            self.check_attrs(op["child"], res["obj_attrs"], post_fs, mism)
        return res

    def op_getattr(self, op, post_fs, mism):
        res = self.call(self.client.getattr, self.real_fh(op["obj"]))
        if self.check_status(op["status"], res["status"], mism) \
                and op["status"] == NFS3_OK:
            self.check_attrs(op["obj"], res["attrs"], post_fs, mism,
                             what="attrs")
        return res

    def op_create(self, op, post_fs, mism):
        cmode = CREATE_WIRE[op["cmode"]["tag"]]
        if cmode == EXCLUSIVE:
            res = self.call(self.client.create, self.real_fh(op["dir"]),
                            op["name"], createmode=EXCLUSIVE,
                            verf=struct.pack(">Q", op["verf"]))
        else:
            res = self.call(self.client.create, self.real_fh(op["dir"]),
                            op["name"], createmode=cmode, mode=op["mode"])
        if self.check_status(op["status"], res["status"], mism) \
                and op["status"] == NFS3_OK:
            self.learn_fh(op["obj"], res["obj_fh"], mism)
            self.check_attrs(op["obj"], res["obj_attrs"], post_fs, mism)
        return res

    def op_setattr(self, op, post_fs, mism):
        fh = self.real_fh(op["obj"])
        guard = None
        if op["guard"] == 1:
            # A matching guard needs the object's live ctime; fetch it with
            # an auxiliary GETATTR (not part of the modeled sequence).
            pre = self.client.getattr(fh)
            if pre["status"] != NFS3_OK:
                self.fnd(mism, "guard", NFS3_OK, pre["status"],
                         "pre-guard GETATTR failed")
                return pre
            guard = tuple(pre["attrs"]["ctime"])
        elif op["guard"] == 2:
            guard = (1, 1)
        res = self.call(
            self.client.setattr, fh,
            mode=None if op["mode"] < 0 else op["mode"],
            size=None if op["sizeBlocks"] < 0
                 else op["sizeBlocks"] * BLOCK_SIZE,
            guard_ctime=guard)
        if self.check_status(op["status"], res["status"], mism) \
                and op["status"] == NFS3_OK:
            self.check_attrs(op["obj"], res["wcc"]["after"], post_fs, mism,
                             what="wcc.after")
        return res

    def op_access(self, op, post_fs, mism):
        res = self.call(self.client.access, self.real_fh(op["obj"]),
                        op["mask"])
        if self.check_status(op["status"], res["status"], mism) \
                and op["status"] == NFS3_OK:
            if res["access"] != op["access"]:
                self.fnd(mism, "access", f"{op['access']:#x}",
                         f"{res['access']:#x}")
            self.check_attrs(op["obj"], res["attrs"], post_fs, mism)
        return res

    def op_symlink(self, op, post_fs, mism):
        res = self.call(self.client.symlink, self.real_fh(op["dir"]),
                        op["name"], op["target"], mode=0o777)
        if self.check_status(op["status"], res["status"], mism) \
                and op["status"] == NFS3_OK:
            self.learn_fh(op["obj"], res["obj_fh"], mism)
            self.check_attrs(op["obj"], res["obj_attrs"], post_fs, mism)
        return res

    def op_readlink(self, op, post_fs, mism):
        res = self.call(self.client.readlink, self.real_fh(op["obj"]))
        if self.check_status(op["status"], res["status"], mism) \
                and op["status"] == NFS3_OK:
            if res["target"] != op["target"]:
                self.fnd(mism, "target", op["target"], res["target"])
            self.check_attrs(op["obj"], res["attrs"], post_fs, mism)
        return res

    def op_mknod(self, op, post_fs, mism):
        res = self.call(self.client.mknod, self.real_fh(op["dir"]),
                        op["name"], FTYPE_WIRE[op["ftype"]["tag"]],
                        mode=op["mode"])
        if self.check_status(op["status"], res["status"], mism) \
                and op["status"] == NFS3_OK:
            self.learn_fh(op["obj"], res["obj_fh"], mism)
            self.check_attrs(op["obj"], res["obj_attrs"], post_fs, mism)
        return res

    def op_rename(self, op, post_fs, mism):
        res = self.call(self.client.rename, self.real_fh(op["fromDir"]),
                        op["fromName"], self.real_fh(op["toDir"]),
                        op["toName"])
        self.check_status(op["status"], res["status"], mism)
        return res

    def op_link(self, op, post_fs, mism):
        res = self.call(self.client.link, self.real_fh(op["obj"]),
                        self.real_fh(op["dir"]), op["name"])
        if self.check_status(op["status"], res["status"], mism) \
                and op["status"] == NFS3_OK:
            self.check_attrs(op["obj"], res["attrs"], post_fs, mism,
                             what="file_attributes")
        return res

    def op_readdir(self, op, post_fs, mism):
        fh = self.real_fh(op["dir"])
        if op["plus"]:
            res = self.call(self.client.readdirplus, fh)
        else:
            res = self.call(self.client.readdir, fh)
        if not self.check_status(op["status"], res["status"], mism) \
                or op["status"] != NFS3_OK:
            return res
        names = [e["name"] for e in res["entries"]]
        if len(names) != len(set(names)):
            self.fnd(mism, "names", sorted(set(names)), sorted(names),
                     "duplicate entries")
        # "." and ".." are conventional in a listing (RFC 1813 3.3.16 does
        # not require them); accept a listing with or without them.
        got = set(names) - {".", ".."}
        expect = set(op["names"])
        if got != expect:
            self.fnd(mism, "names", sorted(expect), sorted(got))
        if not res["eof"]:
            self.fnd(mism, "eof", True, False,
                     "eof not set on a single-shot full listing")
        ents = post_fs[op["dir"]]["ents"]
        for e in res["entries"]:
            if e["name"] == ".":
                fid = op["dir"]
            elif e["name"] == ".." or e["name"] not in ents:
                continue
            else:
                fid = ents[e["name"]]
            known = self.fileid.get(fid)
            if known is None:
                self.fileid[fid] = e["fileid"]
            elif known != e["fileid"]:
                self.fnd(mism, f"entry[{e['name']}].fileid", known,
                         e["fileid"], f"fid {fid}")
            if op["plus"] and e["name"] not in (".", ".."):
                if e.get("fh") is not None:
                    self.learn_fh(fid, e["fh"], mism)
                self.check_attrs(fid, e.get("attrs"), post_fs, mism,
                                 what=f"readdirplus[{e['name']}]")
        return res

    def op_commit(self, op, post_fs, mism):
        res = self.call(self.client.commit, self.real_fh(op["file"]))
        if self.check_status(op["status"], res["status"], mism) \
                and op["status"] == NFS3_OK:
            if self.write_verf is None:
                self.write_verf = res["verf"]
            elif res["verf"] != self.write_verf:
                self.fnd(mism, "verf", self.write_verf.hex(),
                         res["verf"].hex(),
                         "commit verifier differs from write verifier")
        return res

    def op_fsstat(self, op, post_fs, mism):
        res = self.call(self.client.fsstat, self.fh[0])
        if self.check_status(op["status"], res["status"], mism) \
                and op["status"] == NFS3_OK:
            # RFC 1813 3.3.18 ordering only: free <= total, avail <= free
            # for bytes; total > 0.  Files may all be 0 ("unknown").
            # RFC 1813 3.3.18 ordering only: avail <= free <= total (bytes
            # and files).  A total of 0 is permitted -- it means "unknown" --
            # so it is not asserted to be positive.
            if not (res["abytes"] <= res["fbytes"] <= res["tbytes"]):
                self.fnd(mism, "bytes", "abytes <= fbytes <= tbytes",
                         (res["abytes"], res["fbytes"], res["tbytes"]))
            if not (res["afiles"] <= res["ffiles"] <= res["tfiles"]):
                self.fnd(mism, "files", "afiles <= ffiles <= tfiles",
                         (res["afiles"], res["ffiles"], res["tfiles"]))
        return res

    def op_fsinfo(self, op, post_fs, mism):
        res = self.call(self.client.fsinfo, self.fh[0])
        if self.check_status(op["status"], res["status"], mism) \
                and op["status"] == NFS3_OK:
            # RFC 1813 3.3.19: preferred sizes never exceed the maxima; the
            # transfer sizes must be able to carry a model block.
            for pref, mx in (("rtpref", "rtmax"), ("wtpref", "wtmax")):
                if res[pref] > res[mx]:
                    self.fnd(mism, pref, f"<= {mx} ({res[mx]})", res[pref])
            for k in ("rtmax", "wtmax"):
                if res[k] < BLOCK_SIZE:
                    self.fnd(mism, k, f">= {BLOCK_SIZE}", res[k])
            if res["maxfilesize"] < BLOCK_SIZE * 64:
                self.fnd(mism, "maxfilesize", f">= {BLOCK_SIZE * 64}",
                         res["maxfilesize"])
        return res

    def op_pathconf(self, op, post_fs, mism):
        res = self.call(self.client.pathconf, self.real_fh(op["obj"]))
        if self.check_status(op["status"], res["status"], mism) \
                and op["status"] == NFS3_OK:
            if res["name_max"] < 4:
                self.fnd(mism, "name_max", ">= 4", res["name_max"])
            if not res["case_preserving"]:
                self.fnd(mism, "case_preserving", True, False)
        return res

    def op_stalegetattr(self, op, post_fs, mism):
        res = self.call(self.client.getattr, self.real_fh(op["obj"]))
        self.check_status(op["status"], res["status"], mism)
        return res

    def op_mkdir(self, op, post_fs, mism):
        res = self.call(self.client.mkdir, self.real_fh(op["dir"]),
                        op["name"], mode=op["mode"])
        if self.check_status(op["status"], res["status"], mism) \
                and op["status"] == NFS3_OK:
            self.learn_fh(op["obj"], res["obj_fh"], mism)
            self.check_attrs(op["obj"], res["obj_attrs"], post_fs, mism)
        return res

    def op_write(self, op, post_fs, mism):
        data = self.block_bytes(op["pat"]) * op["count"]
        res = self.call(self.client.write, self.real_fh(op["file"]),
                        op["offset"] * BLOCK_SIZE, data,
                        stable=op["stable"])
        if self.check_status(op["status"], res["status"], mism) \
                and op["status"] == NFS3_OK:
            if res["count"] != len(data):
                self.fnd(mism, "count", len(data), res["count"])
            if res["committed"] < op["stable"]:
                self.fnd(mism, "committed", f">= {op['stable']}",
                         res["committed"],
                         "weaker than the requested stability")
            if self.write_verf is None:
                self.write_verf = res["verf"]
            elif res["verf"] != self.write_verf:
                self.fnd(mism, "verf", self.write_verf.hex(),
                         res["verf"].hex(), "write verifier changed")
            self.check_attrs(op["file"], res["wcc"]["after"], post_fs, mism,
                             what="wcc.after")
        return res

    def op_read(self, op, post_fs, mism):
        res = self.call(self.client.read, self.real_fh(op["file"]),
                        op["offset"] * BLOCK_SIZE, op["count"] * BLOCK_SIZE)
        if self.check_status(op["status"], res["status"], mism) \
                and op["status"] == NFS3_OK:
            expect = self.expand(op["blocks"])
            if res["count"] != len(expect):
                self.fnd(mism, "count", len(expect), res["count"])
            if bool(res["eof"]) != op["eof"]:
                self.fnd(mism, "eof", op["eof"], bool(res["eof"]))
            if res["data"] != expect:
                self.fnd(mism, "data", f"blocks {op['blocks']}",
                         f"{len(res['data'])} bytes",
                         diff_bytes(expect, res["data"], BLOCK_SIZE))
            self.check_attrs(op["file"], res["attrs"], post_fs, mism,
                             what="file_attributes")
        return res

    def op_remove(self, op, post_fs, mism):
        res = self.call(self.client.remove, self.real_fh(op["dir"]),
                        op["name"])
        self.check_status(op["status"], res["status"], mism)
        return res

    def op_rmdir(self, op, post_fs, mism):
        res = self.call(self.client.rmdir, self.real_fh(op["dir"]),
                        op["name"])
        self.check_status(op["status"], res["status"], mism)
        return res

    HANDLERS = {
        "OLookup": op_lookup,
        "OGetattr": op_getattr,
        "OStaleGetattr": op_stalegetattr,
        "OSetattr": op_setattr,
        "OAccess": op_access,
        "OCreate": op_create,
        "OMkdir": op_mkdir,
        "OSymlink": op_symlink,
        "OReadlink": op_readlink,
        "OMknod": op_mknod,
        "OWrite": op_write,
        "ORead": op_read,
        "ORemove": op_remove,
        "ORmdir": op_rmdir,
        "ORename": op_rename,
        "OLink": op_link,
        "OReaddir": op_readdir,
        "OCommit": op_commit,
        "OFsstat": op_fsstat,
        "OFsinfo": op_fsinfo,
        "OPathconf": op_pathconf,
    }

    def reconcile(self, idx, tag, op, findings):
        if not findings:
            return
        ctx = {"op": op, "tag": tag, "step": idx, "replayer": self,
               "post_fs": self._cur[3]}
        unmatched = []
        abandon = None
        for f in findings:
            dev = self.registry.lookup(f, ctx) if self.registry else None
            if dev is None:
                unmatched.append(f)
                continue
            self.hit(dev)
            if abandon is None and not dev.is_reconcilable(f, ctx):
                abandon = (dev, f)
        if unmatched:
            if self.keep_going:
                self.unmatched.append((idx, tag, unmatched))
                for f in unmatched:
                    print(f"  [{idx:4d}] MISMATCH {f}")
            else:
                raise Divergence(idx, (tag, op), unmatched)
        if abandon is not None:
            raise Abandon(idx, abandon[0], abandon[1])

    def replay(self, states):
        for idx, state in enumerate(states[1:], start=1):
            tag = state["lastOp"]["tag"]
            op = state["lastOp"]["value"]
            handler = self.HANDLERS.get(tag)
            if handler is None:
                raise TraceFormatError(f"step {idx}: no handler for {tag}")
            mism = []
            self._cur = (idx, tag, op, state["fs"])
            self.set_cred(op)
            res = handler(self, op, state["fs"], mism)
            self.history.append((idx, tag, op, res))
            if self.verbose:
                print(f"  [{idx:4d}] {tag} {op} -> {res.get('status')}")
            self.reconcile(idx, tag, op, mism)

    def attr_skip_rate(self):
        total = self.attr_checks + self.attr_skips
        return self.attr_skips / total if total else 0.0


def report_divergence(trace_path, div, replayer):
    print(f"\n=== DIVERGENCE in {trace_path} ===", file=sys.stderr)
    print(f"step {div.step}: {div.op[0]} args/expectation: {div.op[1]}",
          file=sys.stderr)
    for f in div.findings:
        print(f"  MISMATCH: {f}", file=sys.stderr)
    print("\nlast operations before failure:", file=sys.stderr)
    for idx, tag, op, res in replayer.history[-10:]:
        print(f"  [{idx:4d}] {tag} {op} -> {res}", file=sys.stderr)


class TraceOutcome:
    def __init__(self, path):
        self.path = path
        self.status = "ok"
        self.detail = ""
        self.deviations = {}
        self.steps = 0


def mount_root(args):
    port = args.mount_port
    if port == 0:
        port = nfs3_client.pmap_getport(args.server, nfs3_client.MOUNT_PROGRAM,
                                        3, port=args.portmap_port)
        if port == 0:
            raise RuntimeError("MOUNTv3 is not registered with the portmapper")
    mnt = nfs3_client.Mount3Client(args.server, port=port,
                                   timeout=args.rpc_timeout)
    try:
        return mnt.mnt(args.export)
    finally:
        mnt.close()


def run_trace(trace_path, args, registry):
    out = TraceOutcome(trace_path)
    states = load_trace(trace_path)
    out.steps = len(states) - 1
    if args.dry_run:
        print(f"{trace_path}: {len(states) - 1} steps, format OK")
        return out

    client = None
    replayer = None
    try:
        root_fh = mount_root(args)
        client = nfs3_client.Nfs3Client(args.server, port=args.port,
                                        timeout=args.rpc_timeout)
        client.null()
        replayer = Replayer(client, root_fh, registry,
                            keep_going=args.keep_going, verbose=args.verbose)
        try:
            replayer.replay(states)
        except Abandon as ab:
            out.status = "abandoned"
            out.detail = f"step {ab.step}: {ab.dev.id}: {ab.finding}"
        except Divergence as div:
            out.status = "mismatch"
            out.detail = f"step {div.step}"
            report_divergence(trace_path, div, replayer)
        if replayer.unmatched:
            out.status = "mismatch"
            out.detail = (f"{sum(len(u[2]) for u in replayer.unmatched)} "
                          f"unrecorded divergence(s) across "
                          f"{len(replayer.unmatched)} step(s)")
        rate = replayer.attr_skip_rate()
        if out.status == "ok" and rate > args.max_attr_skip_rate:
            out.status = "mismatch"
            out.detail = (f"attribute skip rate {rate:.0%} exceeds "
                          f"{args.max_attr_skip_rate:.0%} "
                          f"({replayer.attr_skips} of "
                          f"{replayer.attr_checks + replayer.attr_skips} "
                          f"replies had attributes_follow=0)")
        out.deviations = dict(replayer.deviations_hit)
    except (OSError, nfs3_client.RpcError, nfs3_client.XdrError,
            RuntimeError) as e:
        out.status = "error"
        out.detail = f"{type(e).__name__}: {e}"
        print(f"\n=== {trace_path}: {out.detail} ===", file=sys.stderr)
        if replayer is not None:
            for idx, tag, op, res in replayer.history[-6:]:
                print(f"  [{idx:4d}] {tag} {op} -> {res}", file=sys.stderr)
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass

    devs = ""
    if out.deviations:
        devs = "; deviations: " + ", ".join(
            f"{k} x{v}" for k, v in sorted(out.deviations.items()))
    name = os.path.basename(trace_path)
    if out.status == "ok":
        print(f"{name}: OK ({out.steps} steps, "
              f"{replayer.attr_checks} attribute checks, "
              f"{replayer.attr_skips} skipped{devs})")
    elif out.status == "abandoned":
        print(f"{name}: ABANDONED: {out.detail}{devs}")
    elif out.status == "mismatch":
        print(f"{name}: MISMATCH ({out.detail}){devs}")
    else:
        print(f"{name}: ERROR {out.detail}{devs}")
    return out


def load_registry(kind):
    if kind in (None, "", "none"):
        return None
    mod = importlib.import_module(f"{kind}_deviations")
    return getattr(mod, "NFS3")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--trace", action="append", required=True)
    ap.add_argument("--server", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=2049)
    ap.add_argument("--mount-port", type=int, default=0,
                    help="MOUNTv3 port; 0 = ask the portmapper")
    ap.add_argument("--portmap-port", type=int, default=111)
    ap.add_argument("--export", default="/",
                    help="the path MOUNTv3 exports (MNT argument)")
    ap.add_argument("--server-kind", default="none")
    ap.add_argument("--owner-epoch", default=None, help="(ignored: v3 has "
                    "no client identity)")
    ap.add_argument("--max-attr-skip-rate", type=float, default=0.5)
    ap.add_argument("--keep-going", action="store_true")
    ap.add_argument("--rpc-timeout", type=float, default=30.0)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    registry = load_registry(args.server_kind)
    outcomes = [run_trace(t, args, registry) for t in args.trace]
    n = len(outcomes)
    by = {}
    tally = {}
    for o in outcomes:
        by[o.status] = by.get(o.status, 0) + 1
        for k, v in o.deviations.items():
            tally[k] = tally.get(k, 0) + v
    print(f"\n=== {n} trace(s): " +
          ", ".join(f"{k} {v}" for k, v in sorted(by.items())) + " ===")
    if tally:
        print("deviations: " + ", ".join(f"{k} x{v}"
                                         for k, v in sorted(tally.items())))
    if by.get("mismatch") or by.get("error"):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
