# SPDX-FileCopyrightText: 2026 The Quint Specs Authors
#
# SPDX-License-Identifier: MIT

"""Replay the SMB2 model corpus against a live Samba server.

The models in quint/smb2 encode MS-SMB2 / MS-FSA, not any one implementation.
This harness is what makes that claim falsifiable against a server nobody
wrote the model alongside: it drives the generated ITF traces at a real smbd
and compares every reply to the result the model baked into the trace.

  * A disagreement the registry in samba_deviations.py covers is reported as
    a DEVIATION and does not fail the run -- Samba is allowed to deviate, but
    only enumerably, with a citation.
  * Any other disagreement is a MISMATCH and fails.  It is either a model bug
    or an unanalyzed Samba behavior, and both deserve to be looked at.

Usage:
    smb2_replay.py --server 127.0.0.1 --share share --share-path /srv/share \\
                   --user u --password p --trace-dir traces/smb2

Exit codes: 0 clean, 1 mismatches, 2 harness error, 77 nothing to do (skip).
"""

import argparse
import glob
import json
import os
import shutil
import sys
import traceback

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import samba_deviations as DEV
import smb2_wire as W


# One model block is 64 bytes of a single repeated byte; block symbol 0 is a
# hole and reads back as zeros.  This is the same encoding chimera's C
# replayer uses (BS 64), so a trace means the same thing in both harnesses.
BS = 64

# The model's namespace root.  Every CCreate in the registered corpus targets
# it (the model's NAMES are three flat names), and the harness asserts that
# rather than silently ignoring `dir`: if a future corpus nests directories,
# this turns into a loud harness limit instead of a wrong path on the wire.
ROOT_INO = 0


# ---------------------------------------------------------------------------
# ITF decoding
# ---------------------------------------------------------------------------

def jint(o):
    if isinstance(o, dict) and "#bigint" in o:
        return int(o["#bigint"])
    return o


def jtag(o):
    return o["tag"]


def jval(o):
    return o.get("value")


def jset(o):
    if isinstance(o, dict) and "#set" in o:
        return o["#set"]
    return o or []


def jmap(o):
    """An ITF map is {"#map": [[k, v], ...]}; return it as a dict."""
    if isinstance(o, dict) and "#map" in o:
        return {(jint(k) if isinstance(k, (dict, int)) else k): v
                for k, v in o["#map"]}
    return o or {}


def last_op_key(state):
    for k in state:
        if k.endswith("::lastOp"):
            return k
    raise RuntimeError("no ::lastOp variable in ITF state")


def sdb_key(state):
    for k in state:
        if k.endswith("::sdb"):
            return k
    return None


# ---------------------------------------------------------------------------
# Model -> wire translation
# ---------------------------------------------------------------------------

DISP_WIRE = {
    "DispSupersede": W.FILE_SUPERSEDE,
    "DispOpen": W.FILE_OPEN,
    "DispCreate": W.FILE_CREATE,
    "DispOpenIf": W.FILE_OPEN_IF,
    "DispOverwrite": W.FILE_OVERWRITE,
    "DispOverwriteIf": W.FILE_OVERWRITE_IF,
}


def access_wire(a):
    """DesiredAccess.  FILE_READ_ATTRIBUTES is unconditional: every modeled
    access profile sets `h`, and the harness needs it for the identity query."""
    m = W.FILE_READ_ATTRIBUTES
    if a.get("r"):
        m |= W.FILE_READ_DATA
    if a.get("w"):
        m |= W.FILE_WRITE_DATA
    if a.get("d"):
        m |= W.DELETE
    return m


def share_wire(s):
    m = 0
    if s.get("r"):
        m |= W.FILE_SHARE_READ
    if s.get("w"):
        m |= W.FILE_SHARE_WRITE
    if s.get("d"):
        m |= W.FILE_SHARE_DELETE
    return m


def oplock_wire(o):
    """Model OplockReq -> (RequestedOplockLevel, lease-context dict or None).

    The registered instance grants no caching, but the REQUEST still has to go
    on the wire as written: the lease-key binding rule (a key may name only one
    file per client) is enforced on the request, not on the grant, and the
    model generates deliberate rebinding conflicts to exercise it.
    """
    tag = jtag(o)
    if tag == "OrNone":
        return W.OPLOCK_NONE, None
    if tag == "OrLevelII":
        return W.OPLOCK_LEVEL_II, None
    if tag == "OrExclusive":
        return W.OPLOCK_EXCLUSIVE, None
    if tag == "OrBatch":
        return W.OPLOCK_BATCH, None
    if tag == "OrLease":
        v = jval(o)
        return W.OPLOCK_LEASE, {
            "key": jint(v["key"]), "r": v["r"], "w": v["w"], "h": v["h"],
            "v2": v["v2"], "epoch": jint(v["epoch"]),
        }
    raise RuntimeError("unknown OplockReq %s" % tag)


def block_bytes(symbol, nblocks):
    return bytes([symbol & 0xFF]) * (BS * nblocks)


# ---------------------------------------------------------------------------
# Replayer
# ---------------------------------------------------------------------------

class Abort(Exception):
    """Abandon this trace: state has desynced, later results are meaningless."""


class Replayer:

    def __init__(self, args):
        self.args = args
        self.nmismatch = 0
        self.ndeviation = 0
        self.deviations_seen = {}
        self.deviation_verdict = {}
        self.ncomplete = 0
        self.nabandoned = 0
        self.nskipped = 0
        self.skip_reasons = {}
        self.trace = "<none>"
        self.step = 0
        self.warned_no_qfid = False
        self.abort_cause = None
        self.abort_unrecorded = False
        self.post_sdb = None
        self.reset_trace_state()

    # -- per-trace state ---------------------------------------------------

    def reset_trace_state(self):
        self.sessions = {}      # model sess id -> Conn
        self.sess_client = {}   # model sess id -> client symbol
        self.trees = {}         # model tree id -> (Conn, wire tid)
        self.fids = {}          # model fid -> (Conn, wire fid bytes)
        # model fid -> how it was opened: the DesiredAccess profile and whether
        # the disposition truncated.  Several deviation entries turn on these,
        # and the per-command trace record does not repeat them.
        self.fid_access = {}
        self.fid_act = {}
        self.chain_fid = None   # model fid the current chain's CREATE made
        self.ino_of = {}        # model ino -> server IndexNumber
        self.model_of_ino = {}  # server IndexNumber -> model ino

    def drop_connections(self):
        for c in list(self.sessions.values()):
            c.close()
        self.reset_trace_state()

    # -- reporting ---------------------------------------------------------

    def where(self):
        return "%s:%d" % (self.trace, self.step)

    def mism(self, fmt, *a):
        print("MISMATCH [%s] %s" % (self.where(), fmt % a))
        self.nmismatch += 1
        # An unanalyzed divergence means the model and the server have parted
        # ways; everything after it in this trace is a consequence, not a
        # finding.  Stop, so the report is one line per trace instead of a
        # cascade -- unless the caller is surveying, where seeing every
        # distinct shape at once is the point.
        if not self.args.keep_going:
            self.abort_unrecorded = True
            raise Abort()

    def deviation(self, d, fmt, *a):
        print("DEVIATION %s (%s) [%s] %s"
              % (d.id, d.verdict, self.where(), fmt % a))
        self.ndeviation += 1
        self.deviations_seen[d.id] = self.deviations_seen.get(d.id, 0) + 1
        self.deviation_verdict[d.id] = d.verdict

    def cmd_ctx(self, cmd):
        """Harness-side facts a deviation entry may need.

        `access` is the DesiredAccess profile of the handle the command
        targets -- the trace records it on the CREATE, not on every later
        command against that handle.
        """
        tag = jtag(cmd)
        v = jval(cmd)
        if tag == "CCreate":
            return {"access": v["access"], "create_action": None}
        sel = v if tag in ("CClose", "CFlush", "CQueryBasic") else v.get("fid")
        if isinstance(sel, dict) and jtag(sel) == "FidRef":
            fid = jint(jval(sel))
            return {"access": self.fid_access.get(fid),
                    "create_action": self.fid_act.get(fid)}
        return {"access": None, "create_action": None}

    def check_status(self, op, exp, got, cmd, res, what, ctx=None):
        """Compare one status.  Returns True if replay may continue."""
        if exp == got:
            return True
        d = DEV.find(op, exp, got, None, None, None, cmd, res, ctx or {})
        if d is None:
            self.mism("%s status: model 0x%08x wire 0x%08x", what, exp, got)
            return False
        self.deviation(d, "%s status: model 0x%08x wire 0x%08x (%s)",
                       what, exp, got, d.summary)
        if not d.is_reconcilable(cmd, res, ctx or {}):
            self.abort_cause = d
            raise Abort()
        return False

    def check_field(self, op, name, exp, got, cmd, res, what, ctx=None):
        if exp == got:
            return True
        d = DEV.find(op, None, None, name, exp, got, cmd, res, ctx or {})
        if d is None:
            self.mism("%s %s: model %r wire %r", what, name, exp, got)
            return False
        self.deviation(d, "%s %s: model %r wire %r (%s)",
                       what, name, exp, got, d.summary)
        if not d.is_reconcilable(cmd, res, ctx or {}):
            self.abort_cause = d
            raise Abort()
        return False

    # -- handle resolution -------------------------------------------------

    def fid_wire(self, sel, chain_pos, related):
        """Resolve a model FidSel to a wire FileId.

        `FidRelated` is the compound chain's threaded handle, which is the
        all-0xFF FileId -- but only from the second command of a RELATED
        chain onward.  Anywhere else it has no meaning, and answering one
        would put a handle on the wire the model never named.
        """
        tag = jtag(sel)
        if tag == "FidRelated":
            if not related or chain_pos == 0:
                raise Abort()
            return W.RELATED_FID
        fid = jint(jval(sel))
        ent = self.fids.get(fid)
        if ent is None:
            # The model is referencing a handle this harness never learned --
            # it was opened by a command whose reply we could not bind.
            raise Abort()
        return ent[1]

    # -- command builders --------------------------------------------------

    def build(self, cmd, res, conn, chain_pos, related):
        """Return (request, parser) for one model command."""
        tag = jtag(cmd)
        v = jval(cmd)

        if tag == "CCreate":
            if jint(v["dir"]) != ROOT_INO:
                raise RuntimeError(
                    "harness limit: CCreate targets dir ino %d, but this "
                    "harness only models the flat share root. Teach it a "
                    "path map before generating nested corpora."
                    % jint(v["dir"]))
            opts = (W.FILE_DIRECTORY_FILE if v["isDir"]
                    else W.FILE_NON_DIRECTORY_FILE)
            if v["delOnClose"]:
                opts |= W.FILE_DELETE_ON_CLOSE
            level, lease = oplock_wire(v["oplock"])
            if jtag(v["durable"]) != "DurNone":
                raise RuntimeError(
                    "harness limit: durable create contexts are not "
                    "implemented; they occur only in the smb2Durable / "
                    "smb2Replay instances, which are not registered")
            return W.req_create(v["name"], DISP_WIRE[jtag(v["disp"])],
                                access_wire(v["access"]),
                                share_wire(v["share"]), opts,
                                oplock_level=level, lease=lease)

        if tag == "CClose":
            return W.req_close(self.fid_wire(v, chain_pos, related))

        if tag == "CRead":
            fid = self.fid_wire(v["fid"], chain_pos, related)
            return W.req_read(fid, jint(v["off"]) * BS, jint(v["len"]) * BS)

        if tag == "CWrite":
            fid = self.fid_wire(v["fid"], chain_pos, related)
            data = block_bytes(jint(v["pat"]), jint(v["len"]))
            return W.req_write(fid, jint(v["off"]) * BS, data)

        if tag == "CFlush":
            return W.req_flush(self.fid_wire(v, chain_pos, related))

        if tag == "CLock":
            # Lock ranges are scaled by BS exactly like read and write offsets.
            # The model compares a lock's [lo,hi) against an I/O's [off,off+len)
            # directly (smb2_state.qnt rangeIoConflict), so the two live in one
            # coordinate space -- and if the harness scaled only the I/O side,
            # a lock the model places clear of a write would land on top of it
            # on the wire and the server would refuse a write the model allows.
            fid = self.fid_wire(v["fid"], chain_pos, related)
            lo, hi = jint(v["lo"]) * BS, jint(v["hi"]) * BS
            return W.req_lock(fid, lo, hi - lo, v["wr"], v["unlock"],
                              v["failImmediately"])

        if tag == "CSetEof":
            fid = self.fid_wire(v["fid"], chain_pos, related)
            return W.req_set_eof(fid, jint(v["sizeBlocks"]) * BS)

        if tag == "CSetDisposition":
            fid = self.fid_wire(v["fid"], chain_pos, related)
            return W.req_set_disposition(fid, v["del"])

        if tag == "CSetRename":
            if jint(v["newdir"]) != ROOT_INO:
                raise RuntimeError(
                    "harness limit: CSetRename targets dir ino %d; this "
                    "harness only models the flat share root"
                    % jint(v["newdir"]))
            fid = self.fid_wire(v["fid"], chain_pos, related)
            return W.req_set_rename(fid, v["newname"])

        if tag == "CQueryBasic":
            return W.req_query_standard(self.fid_wire(v, chain_pos, related))

        raise RuntimeError(
            "harness limit: model command %s is not implemented. It does not "
            "occur in the registered smb2Base corpus (it belongs to the "
            "caching/durable instances); implement it before registering "
            "those batches." % tag)

    # -- reply checking ----------------------------------------------------

    @staticmethod
    def describe(cmd):
        """A one-line rendering of the request, so a divergence names the exact
        shape that produced it rather than just the command class."""
        tag = jtag(cmd)
        v = jval(cmd)
        if tag == "CCreate":
            acc = "".join(k for k in "rwd" if v["access"].get(k)) or "-"
            shr = "".join(k for k in "rwd" if v["share"].get(k)) or "-"
            return ("CREATE '%s' %s acc=%s shr=%s%s%s"
                    % (v["name"], jtag(v["disp"]), acc, shr,
                       " dir" if v["isDir"] else "",
                       " doc" if v["delOnClose"] else ""))
        if tag == "CLock":
            return ("LOCK [%d,%d) %s%s%s"
                    % (jint(v["lo"]), jint(v["hi"]),
                       "w" if v["wr"] else "r",
                       " unlock" if v["unlock"] else "",
                       " nowait" if v["failImmediately"] else ""))
        if tag == "CRead":
            return "READ off=%d len=%d" % (jint(v["off"]), jint(v["len"]))
        if tag == "CWrite":
            return ("WRITE off=%d len=%d pat=%d"
                    % (jint(v["off"]), jint(v["len"]), jint(v["pat"])))
        if tag == "CSetEof":
            return "SET_EOF %d blocks" % jint(v["sizeBlocks"])
        if tag == "CSetDisposition":
            return "SET_DISPOSITION del=%s" % v["del"]
        if tag == "CSetRename":
            return "SET_RENAME -> '%s'" % v["newname"]
        return tag

    def check(self, cmd, res, status, parsed, conn):
        rtag = jtag(res)
        rv = jval(res)
        cv = jval(cmd)
        exp = jint(rv["st"]) & 0xFFFFFFFF
        what = self.describe(cmd)
        ctx = self.cmd_ctx(cmd)
        ctx["wire_status"] = status

        if not self.check_status(rtag, exp, status, cv, rv, what, ctx):
            return
        if status != W.ST_SUCCESS:
            if rtag == "RCreate":
                self.check_silent_truncate(cv, rv, status, conn, what)
            return

        if rtag == "RCreate":
            self.check_create(cv, rv, parsed, conn, what)
        elif rtag == "RRead":
            self.check_read(cv, rv, parsed, what)
        elif rtag == "RWrite":
            got = parsed['count'].get_value()
            self.check_field(rtag, "count", jint(rv["count"]) * BS, got,
                             cv, rv, what)
        elif rtag == "RQueryBasic":
            self.check_query(cv, rv, parsed, what)
        elif rtag == "RClose":
            self.forget_fid(cmd)

    def forget_related(self):
        """Unbind the handle a related chain's CREATE produced and its CLOSE
        then consumed.

        The CLOSE names it as `FidRelated`, so the command itself does not say
        which model fid went away.  Without this the binding survives a handle
        the server has genuinely closed, and the next reference to it would
        fail with STATUS_FILE_CLOSED -- a confusing failure a long way from its
        cause.
        """
        if self.chain_fid is None:
            return
        self.fids.pop(self.chain_fid, None)
        self.fid_access.pop(self.chain_fid, None)
        self.fid_act.pop(self.chain_fid, None)
        self.chain_fid = None

    def check_create(self, cv, rv, parsed, conn, what):
        got_action = parsed['create_action'].get_value()
        self.check_field("RCreate", "act", jint(rv["act"]), got_action,
                         cv, rv, what)

        # The model's instance has caching off, so the wire must grant none.
        oplock = parsed['oplock_level'].get_value()
        caching = jtag(rv["caching"])
        if caching == "CNone" and oplock != 0:
            self.check_field("RCreate", "caching", "none",
                             "oplock level %d" % oplock, cv, rv, what)

        wire_fid = parsed['file_id'].get_value()
        model_fid = jint(rv["fid"])
        if model_fid >= 0:
            self.fids[model_fid] = (conn, wire_fid)
            self.fid_access[model_fid] = cv["access"]
            # The CreateAction, which is what decides whether the server had to
            # open the backing object for write (CREATED / OVERWRITTEN /
            # SUPERSEDED) or merely opened it (OPENED).
            self.fid_act[model_fid] = jint(rv["act"])
            self.chain_fid = model_fid

        if self.args.check_identity:
            self.check_identity(cv, rv, parsed, what)

    def model_size_blocks(self, name):
        """The size the MODEL believes `name` has, from the post-state.

        Read straight out of the trace's own `sdb` rather than inferred: the
        whole point of this oracle is to catch a divergence both sides report
        identically, so it has to compare actual state, not a proxy for it.
        Returns None when the name does not exist in the model.
        """
        if self.post_sdb is None:
            return None
        fs = self.post_sdb.get("fs")
        if not fs:
            return None
        inodes = jmap(fs.get("inodes"))
        root = inodes.get(ROOT_INO)
        if root is None:
            return None
        ino = jmap(root.get("ents")).get(name)
        if ino is None:
            return None
        node = inodes.get(jint(ino))
        return None if node is None else jint(node.get("sizeBlocks"))

    def check_silent_truncate(self, cv, rv, status, conn, what):
        """Catch a divergence both sides report identically.

        The model advances the filesystem with a truncating disposition BEFORE
        it arbitrates share access, so a CREATE it refuses with a sharing
        violation has still emptied the file.  A real server refuses without
        touching anything.  Both answer STATUS_SHARING_VIOLATION, so the status
        comparison sees nothing -- and the damage surfaces dozens of steps
        later as a read that should have returned data, or a size that is one
        block short.

        Detected here, at the step that causes it, and only when it is
        actually observable: if the file is already empty, truncating it again
        changed nothing and there is no divergence to report.
        """
        if status != DEV.ST_SHARING_VIOLATION:
            return
        if jtag(cv["disp"]) not in ("DispSupersede", "DispOverwrite",
                                    "DispOverwriteIf"):
            return
        want = self.model_size_blocks(cv["name"])
        if want is None:
            return
        got = self.peek_size(cv["name"], conn)
        if got is None or got % BS:
            return
        got //= BS
        if want == got:
            return
        d = DEV.find("RCreate", status, status, "truncate-on-refused-open",
                     None, None, cv, rv, {})
        if d is None:
            self.mism("%s: the open was refused by both, but the file is %d "
                      "block(s) in the model and %d on the server -- a refused "
                      "CREATE modified something", what, want, got)
            return
        self.deviation(d, "%s: refused open left %d block(s) in the model and "
                          "%d on the server (%s)", what, want, got, d.summary)
        if not d.is_reconcilable(cv, rv, {}):
            self.abort_cause = d
            raise Abort()

    def peek_size(self, name, conn):
        """The server's current EndOfFile for `name`, or 0 / None.

        Opened attribute-only, which takes no part in share arbitration in
        either direction -- measured against this server: an attribute-only,
        non-truncating open succeeds against a peer that denies everything, and
        imposes no deny of its own.  So this observation cannot itself change
        what the next modeled command sees.
        """
        tid = next(iter(conn.trees), None)
        if tid is None:
            return None
        req, parse = W.req_create(name, W.FILE_OPEN, W.FILE_READ_ATTRIBUTES,
                                  W.FILE_SHARE_READ | W.FILE_SHARE_WRITE
                                  | W.FILE_SHARE_DELETE,
                                  W.FILE_NON_DIRECTORY_FILE,
                                  want_disk_id=False)
        st, resp = conn._send1(req, tid, parse)
        if st != W.ST_SUCCESS:
            return None
        fid = resp['file_id'].get_value()
        try:
            q, qp = W.req_query_standard(fid)
            st2, qr = conn._send1(q, tid, qp)
            return W.parse_standard_info(qr)["eof"] if st2 == 0 else None
        finally:
            rq, _ = W.req_close(fid)
            conn._send1(rq, tid, None)

    def check_identity(self, cv, rv, parsed, what):
        """The model's Ino against the server's on-disk file id.

        Not an equality check -- the model's inode numbers are symbolic and the
        server's are whatever the backing filesystem hands out.  What must hold
        is that the mapping is a BIJECTION: two opens the model calls the same
        object must land on the same on-disk id, and two it calls different
        must not.  That is what catches a disposition arm that silently reuses
        an object's identity, or silently replaces it.

        The id arrives in the CREATE reply itself (the QFid context), so this
        costs no extra request and cannot race the CLOSE that so often follows
        a CREATE in the same compound chain.
        """
        model_ino = jint(rv["ino"])
        if model_ino < 0:
            return
        idx = W.parse_disk_id(parsed)
        if idx is None:
            # The server declined to answer QFid.  Not a divergence -- the
            # context is optional -- but the oracle is then unavailable, so say
            # so once rather than silently checking nothing.
            if not self.warned_no_qfid:
                self.warned_no_qfid = True
                print("# note: server does not answer the QFid create "
                      "context; the ino bijection oracle is inactive")
            return
        known = self.ino_of.get(model_ino)
        if known is None:
            owner = self.model_of_ino.get(idx)
            if owner is not None and owner != model_ino:
                self.mism("%s identity: model ino %d is a NEW object but the "
                          "server reused on-disk id %d, already bound to model "
                          "ino %d", what, model_ino, idx, owner)
                return
            self.ino_of[model_ino] = idx
            self.model_of_ino[idx] = model_ino
        elif known != idx:
            self.mism("%s identity: model ino %d was on-disk id %d but is now "
                      "%d -- the server changed the object's identity where "
                      "the model kept it", what, model_ino, known, idx)

    def check_read(self, cv, rv, parsed, what):
        data = parsed['buffer'].get_value()
        exp_blocks = [jint(b) for b in rv["blocks"]]
        exp_count = jint(rv["count"]) * BS
        if not self.check_field("RRead", "count", exp_count, len(data),
                                cv, rv, what):
            return
        for i, sym in enumerate(exp_blocks):
            got = data[i * BS:(i + 1) * BS]
            want = block_bytes(sym, 1)
            if got != want:
                self.check_field("RRead", "block%d" % i, sym,
                                 got[0] if got else None, cv, rv, what)
                return

    def check_query(self, cv, rv, parsed, what):
        info = W.parse_standard_info(parsed)
        a = rv["attrs"]
        want_dir = jtag(a["ftype"]) == "FDir"
        self.check_field("RQueryBasic", "directory", want_dir,
                         info["directory"], cv, rv, what)
        self.check_field("RQueryBasic", "nlink", jint(a["nlink"]),
                         info["nlink"], cv, rv, what)
        self.check_field("RQueryBasic", "deletePending",
                         a["deletePending"], info["delete_pending"],
                         cv, rv, what)
        # `change` is deliberately not asserted: it is the model's own change
        # counter, and no wire field carries a comparable value (ChangeTime is
        # a timestamp, not a monotonic count).  chimera's C replayer omits it
        # for the same reason.
        eof = info["eof"]
        if eof % BS:
            self.mism("QUERY EndOfFile %d is not a whole number of %d-byte "
                      "model blocks", eof, BS)
            return
        self.check_field("RQueryBasic", "sizeBlocks", jint(a["sizeBlocks"]),
                         eof // BS, cv, rv, what)

    def forget_fid(self, cmd):
        sel = jval(cmd)
        if jtag(sel) == "FidRelated":
            self.forget_related()
            return
        fid = jint(jval(sel))
        self.fids.pop(fid, None)
        self.fid_access.pop(fid, None)
        self.fid_act.pop(fid, None)

    # -- message dispatch --------------------------------------------------

    def do_message(self, v):
        msg = v["msg"]
        cmds = msg["cmds"]
        results = v["results"]
        related = bool(msg["related"])
        msess = jint(msg["sess"])
        mtree = jint(msg["tree"])

        # A related compound stops at the first error, and the model truncates
        # its result list there.  Replay exactly what the model ran.
        n = min(len(cmds), len(results))
        if n == 0:
            return

        # Session/tree-lifecycle commands are their own singleton shapes and
        # never appear inside a compound in the generated corpus.
        tag0 = jtag(cmds[0])
        if tag0 in ("CSessionSetup", "CLogoff", "CTreeConnect",
                    "CTreeDisconnect"):
            if n != 1:
                raise RuntimeError("harness limit: %s inside a compound" % tag0)
            return self.do_lifecycle(tag0, cmds[0], results[0], msess, mtree)

        conn = self.sessions.get(msess)
        if conn is None or conn.dead:
            raise Abort()
        tent = self.trees.get(mtree)
        if tent is None:
            raise Abort()
        tid = tent[1]

        reqs, parsers = [], []
        for i in range(n):
            r, p = self.build(cmds[i], results[i], conn, i, related)
            reqs.append(r)
            parsers.append(p)

        self.chain_fid = None
        outs = conn.send_chain(reqs, tid, related, parsers)
        for i in range(n):
            status, parsed = outs[i]
            self.check(cmds[i], results[i], status, parsed, conn)

    def do_lifecycle(self, tag, cmd, res, msess, mtree):
        rv = jval(res)
        exp = jint(rv["st"]) & 0xFFFFFFFF

        if tag == "CSessionSetup":
            csym = jint(jval(cmd)["clientSym"])
            try:
                conn = W.Conn(self.args.server, self.args.port,
                              self.args.share, self.args.user,
                              self.args.password,
                              W.new_client_guid(csym))
            except Exception as e:
                if exp == W.ST_SUCCESS:
                    self.mism("SESSION_SETUP failed: %s", e)
                raise Abort()
            if not self.check_status("RSessionSetup", exp, W.ST_SUCCESS,
                                     jval(cmd), rv, "SESSION_SETUP"):
                conn.close()
                return
            sess_id = jint(rv["sess"])
            self.sessions[sess_id] = conn
            self.sess_client[sess_id] = csym
            return

        conn = self.sessions.get(msess)
        if conn is None or conn.dead:
            raise Abort()

        if tag == "CLogoff":
            st = conn.logoff()
            self.check_status("RLogoff", exp, st, jval(cmd), rv, "LOGOFF")
            self.forget_session(msess)
            conn.close()
            return

        if tag == "CTreeConnect":
            try:
                st, wire_tid = conn.tree_connect()
            except W.SMBResponseException as e:
                st, wire_tid = W._status_of(e), None
            if not self.check_status("RTreeConnect", exp, st, jval(cmd), rv,
                                     "TREE_CONNECT"):
                return
            self.trees[jint(rv["tree"])] = (conn, wire_tid)
            return

        if tag == "CTreeDisconnect":
            tent = self.trees.get(mtree)
            if tent is None:
                raise Abort()
            st = conn.tree_disconnect(tent[1])
            self.check_status("RTreeDisconnect", exp, st, jval(cmd), rv,
                              "TREE_DISCONNECT")
            self.trees.pop(mtree, None)
            return

        raise RuntimeError("unhandled lifecycle command %s" % tag)

    def forget_session(self, msess):
        conn = self.sessions.pop(msess, None)
        self.sess_client.pop(msess, None)
        for k, (c, _t) in list(self.trees.items()):
            if c is conn:
                self.trees.pop(k, None)
        for k, (c, _f) in list(self.fids.items()):
            if c is conn:
                self.fids.pop(k, None)
                self.fid_access.pop(k, None)
                self.fid_act.pop(k, None)

    # -- trace driver ------------------------------------------------------

    def reset_share(self):
        """Empty the share between traces.

        The model starts every trace on a fresh, empty namespace (chimera's
        replayer gets that with a per-trace mkfs).  Samba serves a real
        directory, so the harness clears it directly -- it runs on the same
        host, inside the same namespace, and owns the path.
        """
        p = self.args.share_path
        for ent in os.listdir(p):
            full = os.path.join(p, ent)
            if os.path.isdir(full) and not os.path.islink(full):
                shutil.rmtree(full, ignore_errors=True)
            else:
                try:
                    os.unlink(full)
                except OSError:
                    pass

    def run_trace(self, path):
        self.trace = os.path.basename(path)
        with open(path) as f:
            doc = json.load(f)
        states = doc["states"]
        key = last_op_key(states[0])
        skey = sdb_key(states[0])

        init = states[0][key]
        if jtag(init) != "LInit":
            raise RuntimeError("trace does not start with LInit")
        # What this harness can drive.  The corpus is generated unconditionally
        # -- every instance and flavor the model defines -- so a harness that
        # implements only part of the surface has to say so here, per trace,
        # rather than have the missing part quietly left ungenerated.  The
        # oplock/lease break-and-acknowledge lifecycle and the durable
        # reconnect are not implemented, so any trace whose profile turns them
        # on is skipped and counted, not failed.
        caps = jval(init)["caps"]
        for c in ("oplocks", "leases", "dirLeases", "durable"):
            if caps.get(c):
                self.nskipped += 1
                self.skip_reasons[c] = self.skip_reasons.get(c, 0) + 1
                return

        before = self.nmismatch
        self.abort_cause = None
        self.abort_unrecorded = False
        self.drop_connections()
        self.reset_share()
        try:
            for n, st in enumerate(states[1:], start=1):
                lo = st.get(key)
                if not lo or jtag(lo) != "LMsg":
                    continue
                self.step = n
                # The model's state AFTER this message, for the oracles that
                # compare state rather than replies.
                self.post_sdb = st.get(skey) if skey else None
                self.do_message(jval(lo))
            self.ncomplete += 1
        except Abort:
            self.nabandoned += 1
            if self.abort_cause is not None:
                print("ABANDONED [%s]: %s is not reconcilable -- the model and "
                      "the server now hold different state, so the rest of "
                      "this trace would report noise"
                      % (self.where(), self.abort_cause.id))
            elif self.abort_unrecorded:
                pass          # the MISMATCH above already said everything
            else:
                print("ABANDONED [%s]: model and server state diverged with no "
                      "recorded deviation to explain it" % self.where())
                if self.nmismatch == before:
                    self.nmismatch += 1
        finally:
            self.drop_connections()
        return


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--server", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=445)
    ap.add_argument("--share", default="share")
    ap.add_argument("--share-path", required=True,
                    help="local path backing the share, reset between traces")
    ap.add_argument("--user", required=True)
    ap.add_argument("--password", required=True)
    ap.add_argument("--trace", action="append", default=[])
    ap.add_argument("--trace-dir", action="append", default=[])
    ap.add_argument("--limit", type=int, default=0,
                    help="replay at most N traces (0 = all)")
    ap.add_argument("--keep-going", action="store_true",
                    help="do not stop a trace at its first unrecorded "
                         "divergence; for surveying every distinct shape at "
                         "once, at the cost of cascade noise")
    ap.add_argument("--no-check-identity", dest="check_identity",
                    action="store_false", default=True,
                    help="skip the ino<->IndexNumber bijection oracle")
    args = ap.parse_args()

    traces = list(args.trace)
    for d in args.trace_dir:
        traces.extend(glob.glob(os.path.join(d, "*.itf.json")))
    traces.sort()
    if args.limit:
        traces = traces[:args.limit]
    if not traces:
        print("no traces found", file=sys.stderr)
        return 77

    r = Replayer(args)
    for t in traces:
        try:
            r.run_trace(t)
        except Exception:
            print("HARNESS ERROR replaying %s" % t, file=sys.stderr)
            traceback.print_exc()
            r.drop_connections()
            return 2

    if r.nskipped:
        print("# %d of %d trace(s) skipped -- this harness does not implement "
              "the capabilities their profile turns on: %s"
              % (r.nskipped, len(traces),
                 ", ".join("%s x%d" % (k, v)
                           for k, v in sorted(r.skip_reasons.items()))))
    if r.nskipped == len(traces):
        # Nothing was driven at all.  That is a ctest SKIP, not a pass: a
        # batch this harness cannot replay must not read as evidence about the
        # server.
        print("# nothing in this batch is replayable by this harness")
        return 77
    print("# %d trace(s): %d replayed to completion, %d abandoned at a "
          "non-reconcilable deviation"
          % (len(traces) - r.nskipped, r.ncomplete, r.nabandoned))
    if r.ndeviation:
        print("# %d recorded divergence(s):" % r.ndeviation)
        for k in sorted(r.deviations_seen):
            print("#   %-6s %-6s x%d"
                  % (k, r.deviation_verdict.get(k, "?"), r.deviations_seen[k]))
        print("#   verdict 'model' = the model is wrong and samba is right; "
              "'samba' = the reverse; 'both' = each is wrong differently.")
    if r.nmismatch:
        print("%d unrecorded divergence(s) across %d trace(s)"
              % (r.nmismatch, len(traces)))
        return 1
    print("ok: %d trace(s) replayed against samba; every divergence is a "
          "recorded, analyzed one" % (len(traces) - r.nskipped))
    return 0


if __name__ == "__main__":
    sys.exit(main())
