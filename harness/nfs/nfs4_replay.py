#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 The Quint Specs Authors
#
# SPDX-License-Identifier: MIT

"""Replay the generated NFSv4 corpus (quint/nfs, the nfs4 instances) against
a live NFSv4 server and compare every reply to what the model baked into
the trace.

Each state's `lastOp` is either the initial `LInit {minor, caps}` or one
`LCompound {tag, tagName, ops, status, results}` (see nfs4.qnt).  The
harness encodes every model op on the wire through nfs4_client.py, sends
the compound at the trace's minorversion, and compares the server's per-op
results and compound status against the model's expectations.

Identity indirection maintained here (model values are abstract):
  - ino        -> nfs_fh4, learned from GETFH replies (the model's SGetfh
                  result names the ino, so the binding is exact)
  - clientid   -> wire clientid, from SETCLIENTID/EXCHANGE_ID replies
  - sessionid  -> wire sessionid, from CREATE_SESSION replies
  - stateid    -> wire `other`, from OPEN/LOCK/delegation/LAYOUTGET
                  replies; stateid seqids are predicted by the model and
                  compared exactly
  - change     -> never predicted; per-ino consistency (equal abstract
                  values must observe equal wire values, distinct abstract
                  values distinct wire values).  change_info4 lives in the
                  same domain (RFC 7530 2.2.6: its values ARE the change
                  attribute).
  - block s    -> BLOCK_SIZE bytes, symbol 0 = zeroes, s > 0 = 0x40+s
  - lock byte  -> wire byte offset; a range ending at the top of the lock
                  space (LOCK_BYTES) is sent as a to-EOF lock
  - names      -> the model's component names are strings; a handful are
                  sentinels the harness materializes into bytes a JSON
                  trace cannot carry (embedded NUL, invalid UTF-8, a
                  256-byte name); see expand_name

Capability reconciliation is lazy: the first divergence that matches a
capability-assumption pattern (NOTSUPP vs supported for the 4.2 op
families and pNFS, delegation granted-vs-not, DELAY-vs-block on recall
conflicts, CLOSE frees-locks-vs-LOCKS_HELD, EXCHANGE_ID pNFS flag) marks
the trace not applicable to this server and it is reported as a SKIP,
never a failure: a third-party server owes the model nothing about which
optional features it implements.

Every other divergence is a Finding, looked up in the server's deviation
registry (--server-kind picks ganesha_deviations / knfsd_deviations): a
recorded, reconcilable deviation is tallied and replay continues; a
recorded non-reconcilable one abandons the trace after the first hit; an
unrecorded one is a MISMATCH and fails the run.
"""

import argparse
import importlib
import os
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nfs4_client as c4  # noqa: E402
from itf import load_states, Divergence, TraceFormatError, diff_bytes  # noqa: E402
from deviations import Finding  # noqa: E402
import deviations as dv  # noqa: E402

BLOCK_SIZE = 8192
LOCK_BYTES = 8
TO_EOF = 0xffffffffffffffff

NFS4_OK = 0
E_DELAY = dv.NFS4ERR_DELAY
E_GRACE = dv.NFS4ERR_GRACE
E_DENIED = dv.NFS4ERR_DENIED
E_NOTSUPP = dv.NFS4ERR_NOTSUPP
E_LOCKS_HELD = dv.NFS4ERR_LOCKS_HELD
E_LAYOUTUNAVAILABLE = dv.NFS4ERR_LAYOUTUNAVAILABLE
E_RESOURCE = dv.NFS4ERR_RESOURCE
E_SERVERFAULT = dv.NFS4ERR_SERVERFAULT

EXCHGID4_FLAG_CONFIRMED_R = 0x40000000

FTYPE_WIRE = {"FReg": c4.NF4REG, "FDir": c4.NF4DIR, "FLnk": c4.NF4LNK,
              "FFifo": c4.NF4FIFO, "FSock": c4.NF4SOCK,
              "FBlk": c4.NF4BLK, "FChr": c4.NF4CHR}

XSETHOW_WIRE = {"XsEither": 0, "XsCreate": 1, "XsReplace": 2}

# Model result tag -> capability the op's support hinges on (lazy
# reconciliation classes).
SPARSE_TAGS = {"SAllocate", "SDeallocate", "SSeek"}
COPY_TAGS = {"SCopy"}
XATTR_TAGS = {"SGetxattr", "SSetxattr", "SListxattrs", "SRemovexattr"}
PNFS_TAGS = {"SLayoutget", "SLayoutreturn", "SLayoutcommit",
             "SGetdeviceinfo"}
CAP_OF_TAG = {"SReadPlus": "readPlus", "SIoAdvise": "ioAdvise",
              "SWriteSame": "writeSame", "SClone": "clone"}

# Component-name sentinels (see BAD_NAMES / UTF8_NAMES in nfs4.qnt).  The
# model names them; the harness puts these bytes on the wire.  Everything
# not listed is sent as the UTF-8 encoding of the name itself.
NAME_SENTINELS = {
    # rejected by name validation
    "NEMPTY": b"",
    "NDOT": b".",
    "NDOTDOT": b"..",
    "NSLASH": b"a/b",
    "NNUL": b"a\0b",
    # rejected by UTF-8 validation, one per reject branch
    "NUTF8": b"\x80",                              # stray continuation
    "NUTF8B": b"\xC0\x80",                         # overlong 2-byte
    "NUTF8C": b"\xE0\x80\x80",                     # overlong 3-byte
    "NUSUR": b"\xED\xA0\x80",                      # surrogate U+D800
    "NUNCH": b"\xEF\xBF\xBF",                      # non-char U+FFFF
    "NU4OV": b"\xF0\x8F\xBF\xBF",                  # overlong 4-byte
    "NU4HI": b"\xF4\x90\x80\x80",                  # above U+10FFFF
    "NUF5": b"\xF5\x80\x80\x80",                   # lead byte > 0xF4
    "NUTRUNC": b"\xE6\x97",                        # truncated 3-byte
    "NUBADC": b"\xC3A",                            # bad continuation
    # multi-character: valid prefix, malformed tail
    "NUMIXB": b"a\xC3\xA9\x80",
    "NUMIXT": b"a\xE6\x97",
    "NUMIXS": b"\xC3\xA9\xED\xA0\x80",
    # accepted: the multi-byte success paths
    "NUMIX": b"a\xC3\xA9\xE6\x97\xA5\xF0\x9D\x84\x9E",   # 1+2+3+4 widths
    "NUREP": b"\xC3\xA9\xC3\xA9\xC3\xA9",
    "NU2": b"\xC3\xA9",                            # U+00E9
    "NU3": b"\xE6\x97\xA5",                        # U+65E5
    "NU4": b"\xF0\x9D\x84\x9E",                    # U+1D11E
    "NU3E": b"\xE0\xA0\x80",                       # U+0800, 3-byte minimum
    "NU3S": b"\xED\x9F\xBF",                       # U+D7FF, below surrogates
    "NU4M": b"\xF4\x8F\xBF\xBF",                   # U+10FFFF
}


def expand_name(name):
    if name == "NLONG":
        return b"x" * 256
    b = NAME_SENTINELS.get(name)
    if b is not None:
        return b
    return name.encode()


class CapsSkip(Exception):
    """Trace assumes a capability profile the live server does not have."""

    def __init__(self, feature, detail):
        self.feature = feature
        self.detail = detail
        super().__init__(f"capability mismatch [{feature}]: {detail}")


class Abandon(Exception):
    """A recorded, non-reconcilable deviation: stop comparing this trace."""

    def __init__(self, step, dev, finding):
        self.step = step
        self.dev = dev
        self.finding = finding
        super().__init__(f"step {step}: {dev.id}: {finding}")


def load_trace_v4(path):
    states = load_states(path)
    steps = [st["lastOp"] for st in states]
    if steps[0]["tag"] != "LInit":
        raise TraceFormatError(f"{path}: first state is not LInit")
    return steps


def block_bytes(sym):
    if sym == 0:
        return b"\0" * BLOCK_SIZE
    return bytes([0x40 + sym]) * BLOCK_SIZE


def expand(syms):
    return b"".join(block_bytes(s) for s in syms)


def lock_range(lo, hi):
    """Model lock units -> wire offset/length (top of space = to-EOF)."""
    if hi >= LOCK_BYTES:
        return lo, TO_EOF
    return lo, hi - lo


def owner_bytes(kind, n):
    return f"{kind}{n}".encode()


def xattr_value(sym):
    return b"xattr-value-%d" % sym


class Replayer:
    RETRY_DELAY_MAX = 40          # x 0.1s
    RETRY_GRACE_MAX = 60          # x 0.5s

    def __init__(self, client, root_fh, minor, caps, registry, epoch,
                 wide_attrs, keep_going=False, verbose=False):
        self.c = client
        self.minor = minor
        self.caps = caps
        self.registry = registry
        self.epoch = epoch
        self.wide_attrs = wide_attrs
        self.keep_going = keep_going
        self.verbose = verbose
        self.fh = {0: root_fh}
        self.clientid = {}            # model ClientId -> wire clientid
        self.confirm = {}             # tok -> (wire clientid, confirm verf)
        self.sess = {}                # model SessId -> wire sessionid 16B
        self.cs_base = {}             # model ClientId -> wire csa_seq - model
        self.sid_other = {}           # model Sid -> wire `other`
        self.sid_owner = {}           # model Sid -> (client, owner)
        self.sid_client = {}          # model Sid -> wire clientid
        self.sid_seq = {}             # model Sid -> wire stateid seqid
        self.chg = {}                 # ino -> {abstract change -> wire}
        self.replay_cache = {}        # (model sess, slot) -> raw reply
        self.deviceid = None
        self.write_verf = None
        self.deviations_hit = {}      # id -> count
        self.unmatched = []           # (step, findings) in --keep-going mode
        self.history = []
        self.recall_log = []
        self.compounds = 0
        self.cur_open_client = None
        self.dry = False              # encode only, no server (--dry-run)

    # -- bookkeeping --------------------------------------------------------

    def hit(self, dev):
        self.deviations_hit[dev.id] = self.deviations_hit.get(dev.id, 0) + 1

    def fnd(self, mism, op, kind, expected, actual, detail=""):
        mism.append(Finding(op, kind, expected, actual, detail))

    def real_fh(self, ino):
        fh = self.fh.get(ino)
        if fh is None:
            if self.dry:
                return b"\x7f" * 16
            raise TraceFormatError(f"model ino {ino} has no learned "
                                   f"filehandle (earlier divergence?)")
        return fh

    def learn_fh(self, ino, fh, mism):
        known = self.fh.get(ino)
        if known is None:
            for oino, ofh in self.fh.items():
                if ofh == fh:
                    self.fnd(mism, "SGetfh", "fh_identity", f"ino {ino}",
                             f"ino {oino}",
                             f"filehandle {fh.hex()} already names model "
                             f"ino {oino}")
            self.fh[ino] = fh
        elif known != fh:
            self.fnd(mism, "SGetfh", "fh_identity", known.hex(), fh.hex(),
                     f"ino {ino}: filehandle changed")

    def resolve_sel(self, sel):
        if sel["tag"] == "SelAnon":
            return c4.ANON_STATEID
        if sel["tag"] == "SelBypass":
            return c4.BYPASS_STATEID
        r = sel["value"]
        # A SelRef names a real (open/lock) stateid.  The model's argSeq 0
        # means "the current seqid", but (0, real_other) is NOT the all-zeros
        # wildcard -- a strict server reads it as literal seqid 0, which is
        # OLD once OPEN_CONFIRM/LOCK have advanced the stateid.  Send the seqid
        # the server last handed us for this Sid, as a conforming client does.
        return (self.sid_seq.get(r["sid"], r["argSeq"]), self.sid_of(r["sid"]))

    def sid_of(self, sid):
        other = self.sid_other.get(sid)
        if other is None:
            # A stateid the model minted on a path the server refused (or
            # that an earlier deviation swallowed).  Send a stateid that
            # names nothing so the server answers BAD_STATEID rather than
            # the harness giving up: the model may well predict exactly
            # that.
            return b"\x7f" * 11 + bytes([sid & 0xff])
        return other

    def learn_sid(self, sid, wire, mism, expect_seq=None, what="stateid"):
        seq, other = wire
        # OPEN_CONFIRM must echo the OPEN stateid unchanged, seqid
        # included (RFC 7530 9.1.4.2 -- the first stateid has seqid 1).
        # Remember it so ROpenConfirm sends the real seqid rather than a
        # forced 0, which a strict server (knfsd) rejects as OLD_STATEID.
        self.sid_seq[sid] = seq
        known = self.sid_other.get(sid)
        if known is None:
            for osid, oother in self.sid_other.items():
                if oother == other:
                    self.fnd(mism, what, "stateid_identity", f"sid {sid}",
                             f"sid {osid}",
                             f"other {other.hex()} already bound to model "
                             f"sid {osid}")
            self.sid_other[sid] = other
        elif known != other:
            self.fnd(mism, what, "stateid_identity", known.hex(),
                     other.hex(), f"model sid {sid}: other changed")
        if expect_seq is not None and seq != expect_seq:
            self.fnd(mism, what, "seqid", expect_seq, seq)

    def check_seq_only(self, op, wire_sid, expect_seq, mism):
        if wire_sid[0] != expect_seq:
            self.fnd(mism, op, "seqid", expect_seq, wire_sid[0])

    def wire_seq(self, sid, arg_seq):
        """Seqid to put in a request stateid for a *sequenced* op.

        The model predicts it exactly (arg_seq), but its absolute seqid
        numbering can drift from the server's once OPEN_CONFIRM / DOWNGRADE
        / LOCKU have bumped the live stateid, so send the seqid the server
        last handed us for this Sid.  arg_seq 0 on a real stateid is the
        model's "current seqid", not the all-zeros wildcard, so it too maps to
        the tracked seqid (a strict server rejects a literal 0 as OLD).  Falls
        back to arg_seq for a Sid we have not learned a wire seqid for.
        """
        return self.sid_seq.get(sid, arg_seq)

    def relearn_seq(self, req, wire):
        """Track the seqid the server bumped a stateid to.  Called from the
        OPEN_CONFIRM / OPEN_DOWNGRADE / LOCKU reply handlers, which run only
        on matched success, so wire['stateid'] is the fresh confirmed value.
        """
        if req is not None and "sid" in req.get("value", {}):
            self.sid_seq[req["value"]["sid"]] = wire["stateid"][0]

    def check_change(self, op, ino, abstract, wire, mism, what):
        """Per-ino change-attribute consistency (never predict values)."""
        if ino is None:
            return
        m = self.chg.setdefault(ino, {})
        known = m.get(abstract)
        if known is None:
            for oabs, owire in m.items():
                if owire == wire:
                    self.fnd(mism, op, what, f"!= {wire:#x}", f"{wire:#x}",
                             f"ino {ino}: unchanged on the wire but the "
                             f"model mutated the object (abstract {oabs} "
                             f"vs {abstract})")
                    return
            m[abstract] = wire
        elif known != wire:
            self.fnd(mism, op, what, f"{known:#x}", f"{wire:#x}",
                     f"ino {ino}: abstract change {abstract} reported "
                     f"two wire values")

    def check_cinfo(self, op, ino, exp, wire, mism, what):
        # RFC 7530 2.2.6 / 16.16.5: change_info4 carries values OF the
        # change attribute, so before/after live in the GETATTR domain.
        # `before` is only meaningful when the server asserts atomicity.
        if wire["atomic"]:
            self.check_change(op, ino, exp["before"], wire["before"], mism,
                              what + ".before")
        self.check_change(op, ino, exp["after"], wire["after"], mism,
                          what + ".after")

    def caps_mismatch(self, feature, detail):
        raise CapsSkip(feature, detail)

    def client_owner(self, sym):
        return b"specs-%s-%d" % (self.epoch.encode(), sym)

    # -- op encoding ----------------------------------------------------------

    def encode_op(self, req):
        tag = req["tag"]
        v = req.get("value")
        if tag == "RPutrootfh":
            # The model's ROOT is the export root.  Where the server puts a
            # pseudo-fs above it, PUTROOTFH would land elsewhere, so the
            # harness substitutes the export root handle it resolved at
            # start.  (LOOKUPP at the root is then the one place the two
            # namespaces differ; the model expects NOENT.)
            return c4.enc_putfh(self.fh[0])
        if tag == "RPutfh":
            return c4.enc_putfh(self.real_fh(v))
        if tag == "RGetfh":
            return c4.enc_getfh()
        if tag == "RSavefh":
            return c4.enc_savefh()
        if tag == "RRestorefh":
            return c4.enc_restorefh()
        if tag == "RLookup":
            return c4.enc_lookup(expand_name(v))
        if tag == "RLookupp":
            return c4.enc_lookupp()
        if tag == "RGetattr":
            return c4.enc_getattr([c4.FATTR4_TYPE, c4.FATTR4_CHANGE,
                                   c4.FATTR4_SIZE, c4.FATTR4_MODE,
                                   c4.FATTR4_NUMLINKS])
        if tag == "RGetattrWide":
            return c4.enc_getattr(self.wide_attrs)
        if tag == "RSecinfo":
            return c4.enc_secinfo(expand_name(v))
        if tag == "RSetattrWide":
            return c4.enc_setattr_wide(c4.ANON_STATEID, v)
        if tag in ("RVerifyWide", "RNverifyWide"):
            return c4.enc_verify_wide(self.wide_attrs,
                                      nverify=(tag == "RNverifyWide"))
        if tag == "RBindConnToSession":
            return c4.enc_bind_conn_to_session(
                self.sess.get(v["sess"], b"\0" * 16), v["dir"])
        if tag == "RReadlink":
            return c4.enc_readlink()
        if tag == "RAccess":
            return c4.enc_access(v)
        if tag == "RReaddir":
            return c4.enc_readdir()
        if tag == "RCreate":
            ft = v["ctype"]["tag"]
            return c4.enc_create(FTYPE_WIRE[ft], expand_name(v["name"]),
                                 mode=v["mode"],
                                 linkdata=v["target"] if ft == "FLnk"
                                 else None)
        if tag == "RRemove":
            return c4.enc_remove(expand_name(v))
        if tag == "RRename":
            return c4.enc_rename(expand_name(v["oldname"]),
                                 expand_name(v["newname"]))
        if tag == "RLink":
            return c4.enc_link(expand_name(v))
        if tag == "RSetattr":
            return c4.enc_setattr(
                self.resolve_sel(v["sel"]),
                mode=None if v["mode"] < 0 else v["mode"],
                size=None if v["sizeBlocks"] < 0
                     else v["sizeBlocks"] * BLOCK_SIZE)
        if tag == "RVerifySize":
            return c4.enc_verify_size(v * BLOCK_SIZE)
        if tag == "RNverifySize":
            return c4.enc_verify_size(v * BLOCK_SIZE, nverify=True)
        if tag == "RSetclientid":
            return c4.enc_setclientid(struct.pack(">Q", v["verfSym"]),
                                      self.client_owner(v["ownerSym"]))
        if tag == "RSetclientidConfirm":
            pair = self.confirm.get(v["tok"])
            if pair is None:
                # A confirm for a token the server never issued (the model
                # generates stale confirms deliberately): send a clientid
                # nobody owns.
                pair = (0x7f7f7f7f7f7f7f7f, b"\x7f" * 8)
            return c4.enc_setclientid_confirm(pair[0], pair[1])
        if tag == "RRenew":
            return c4.enc_renew(self.clientid.get(v, 0x7f7f7f7f7f7f7f7f))
        if tag == "RReleaseLockowner":
            return c4.enc_release_lockowner(
                self.clientid.get(v["client"], 0x7f7f7f7f7f7f7f7f),
                owner_bytes("lo", v["lockOwner"]))
        if tag == "RExchangeId":
            return c4.enc_exchange_id(struct.pack(">Q", v["verfSym"]),
                                      self.client_owner(v["ownerSym"]))
        if tag == "RCreateSession":
            # The model counts CREATE_SESSION sequence ids from 1; the wire
            # counts from whatever eir_sequenceid the server chose (RFC 8881
            # 18.35.3 leaves the initial value to the server).  Rebase.
            return c4.enc_create_session(
                self.clientid.get(v["client"], 0x7f7f7f7f7f7f7f7f),
                v["csaSeq"] + self.cs_base.get(v["client"], 0),
                v["backChan"])
        if tag == "RSequence":
            return c4.enc_sequence(self.sess.get(v["sess"], b"\0" * 16),
                                   v["slot"], v["seq"], v["cacheThis"])
        if tag == "RDestroySession":
            return c4.enc_destroy_session(self.sess.get(v, b"\0" * 16))
        if tag == "RDestroyClientid":
            return c4.enc_destroy_clientid(
                self.clientid.get(v, 0x7f7f7f7f7f7f7f7f))
        if tag == "RReclaimComplete":
            return c4.enc_reclaim_complete()
        if tag == "RFreeStateid":
            return c4.enc_free_stateid((v["argSeq"], self.sid_of(v["sid"])))
        if tag == "ROpen":
            how = v["how"]
            openhow = None
            if how["tag"] == "HUnchecked":
                openhow = ("UNCHECKED", how["value"]["mode"],
                           how["value"]["truncate"])
            elif how["tag"] == "HGuarded":
                openhow = ("GUARDED", how["value"]["mode"])
            elif how["tag"] == "HExclusive":
                openhow = ("EXCLUSIVE",
                           struct.pack(">Q", how["value"]["verf"]))
            claim = v["claim"]
            wclaim = (("NULL", expand_name(claim["value"]))
                      if claim["tag"] == "OCNull" else ("FH",))
            return c4.enc_open(v["oseq"], v["access"], v["deny"],
                               self.clientid.get(v["client"],
                                                 0x7f7f7f7f7f7f7f7f),
                               owner_bytes("oo", v["owner"]),
                               openhow, wclaim)
        if tag == "ROpenConfirm":
            return c4.enc_open_confirm(
                (self.sid_seq.get(v["sid"], 0), self.sid_of(v["sid"])),
                v["oseq"])
        if tag == "ROpenDowngrade":
            return c4.enc_open_downgrade(
                (self.wire_seq(v["sid"], v["argSeq"]), self.sid_of(v["sid"])),
                v["oseq"],
                v["access"], v["deny"])
        if tag == "RClose":
            return c4.enc_close(
                v["oseq"],
                (self.wire_seq(v["sid"], v["argSeq"]), self.sid_of(v["sid"])))
        if tag == "RRead":
            return c4.enc_read(self.resolve_sel(v["sel"]),
                               v["off"] * BLOCK_SIZE, v["len"] * BLOCK_SIZE)
        if tag == "RWrite":
            return c4.enc_write(self.resolve_sel(v["sel"]),
                                v["off"] * BLOCK_SIZE, v["stable"],
                                block_bytes(v["pat"]) * v["len"])
        if tag == "RCommit":
            return c4.enc_commit()
        if tag == "RLock":
            off, length = lock_range(v["lo"], v["hi"])
            if v["newOwner"]:
                return c4.enc_lock(
                    v["wr"], False, off, length, True,
                    open_seqid=v["oseq"],
                    open_sid=(0, self.sid_of(v["openSid"])),
                    lock_seqid=v["lseq"],
                    clientid=self.clientid_of_sid(v),
                    owner=owner_bytes("lo", v["lockOwner"]))
            return c4.enc_lock(
                v["wr"], False, off, length, False,
                lock_seqid=v["lseq"],
                lock_sid=(0, self.sid_of(v["lockSid"])))
        if tag == "RLockt":
            off, length = lock_range(v["lo"], v["hi"])
            return c4.enc_lockt(v["wr"], off, length,
                                self.clientid.get(v["client"],
                                                  0x7f7f7f7f7f7f7f7f),
                                owner_bytes("lo", v["lockOwner"]))
        if tag == "RLocku":
            off, length = lock_range(v["lo"], v["hi"])
            return c4.enc_locku(v["lseq"],
                                (self.wire_seq(v["sid"], v["argSeq"]),
                                 self.sid_of(v["sid"])),
                                off, length)
        if tag == "RDelegreturn":
            return c4.enc_delegreturn((v["argSeq"], self.sid_of(v["sid"])))
        if tag == "RLayoutget":
            return c4.enc_layoutget(v["rw"], v["lo"] * BLOCK_SIZE,
                                    (v["hi"] - v["lo"]) * BLOCK_SIZE,
                                    self.resolve_sel(v["sel"]))
        if tag == "RLayoutreturn":
            return c4.enc_layoutreturn(
                (v["argSeq"], self.sid_of(v["sid"])),
                v["lo"] * BLOCK_SIZE, (v["hi"] - v["lo"]) * BLOCK_SIZE)
        if tag == "RLayoutcommit":
            return c4.enc_layoutcommit(
                (0, self.sid_of(v["sid"])), v["lo"] * BLOCK_SIZE,
                (v["hi"] - v["lo"]) * BLOCK_SIZE,
                v["hi"] * BLOCK_SIZE - 1)
        if tag == "RGetdeviceinfo":
            return c4.enc_getdeviceinfo(self.deviceid or b"\0" * 16)
        if tag == "RAllocate":
            return c4.enc_allocate(self.resolve_sel(v["sel"]),
                                   v["off"] * BLOCK_SIZE,
                                   v["len"] * BLOCK_SIZE)
        if tag == "RDeallocate":
            return c4.enc_allocate(self.resolve_sel(v["sel"]),
                                   v["off"] * BLOCK_SIZE,
                                   v["len"] * BLOCK_SIZE, deallocate=True)
        if tag == "RSeek":
            return c4.enc_seek(self.resolve_sel(v["sel"]),
                               v["off"] * BLOCK_SIZE, v["whatData"])
        if tag == "RCopy":
            return c4.enc_copy(self.resolve_sel(v["srcSel"]),
                               self.resolve_sel(v["dstSel"]),
                               v["srcOff"] * BLOCK_SIZE,
                               v["dstOff"] * BLOCK_SIZE,
                               v["cnt"] * BLOCK_SIZE)
        if tag == "RReadPlus":
            return c4.enc_read_plus(self.resolve_sel(v["sel"]),
                                    v["off"] * BLOCK_SIZE,
                                    v["len"] * BLOCK_SIZE)
        if tag == "RIoAdvise":
            return c4.enc_io_advise(self.resolve_sel(v["sel"]),
                                    v["off"] * BLOCK_SIZE,
                                    v["len"] * BLOCK_SIZE, [v["hint"]])
        if tag == "RWriteSame":
            return c4.enc_write_same(self.resolve_sel(v["sel"]),
                                     v["off"] * BLOCK_SIZE, BLOCK_SIZE,
                                     v["blocks"], block_bytes(v["pat"]),
                                     blocknum=v["blocknum"])
        if tag == "RClone":
            return c4.enc_clone(self.resolve_sel(v["srcSel"]),
                                self.resolve_sel(v["dstSel"]),
                                v["srcOff"] * BLOCK_SIZE,
                                v["dstOff"] * BLOCK_SIZE,
                                v["cnt"] * BLOCK_SIZE)
        if tag == "RGetxattr":
            return c4.enc_getxattr(v)
        if tag == "RSetxattr":
            return c4.enc_setxattr(XSETHOW_WIRE[v["how"]["tag"]],
                                   v["name"], xattr_value(v["sym"]))
        if tag == "RListxattrs":
            return c4.enc_listxattrs()
        if tag == "RRemovexattr":
            return c4.enc_removexattr(v)
        raise TraceFormatError(f"no encoder for {tag}")

    def clientid_of_sid(self, lockv):
        # open_to_lock_owner's clientid: the lock owner belongs to the
        # open's client; the model supplies no client field here, so learn
        # it from the open stateid's creator.
        sid = lockv["openSid"]
        cid = self.sid_client.get(sid)
        if cid is not None:
            return cid
        if len(self.clientid) == 1:
            return next(iter(self.clientid.values()))
        return 0x7f7f7f7f7f7f7f7f

    # -- result checking ------------------------------------------------------

    def check_result(self, exp, wire, ctx, mism, req):
        """Compare one expected OpRes against the wire result.  ctx carries
        the cur/saved ino tracking maintained from the model's own ops."""
        tag = exp["tag"]
        v = exp["value"]
        est = v["st"]
        ast = wire["status"]

        if est != ast:
            self.classify_status_mismatch(tag, v, est, ast, wire, mism, req)
            return

        if ast != NFS4_OK:
            # Error statuses matched; DENIED bodies still carry payload.
            if tag in ("SLock", "SLockt") and ast == E_DENIED \
                    and "denied" in wire:
                want = owner_bytes("lo", v["deniedOwner"])
                got = wire["denied"]["owner"]
                if got != want:
                    # acceptance: which of several conflicting locks a
                    # server reports is discretionary (RFC 7530 16.10.5),
                    # so this is a finding a registry may waive rather
                    # than an assertion of the model's pick.
                    self.fnd(mism, tag, "denied_owner", want, got)
            return

        if tag == "SGetfh":
            self.learn_fh(v["ino"], wire["fh"], mism)
            ctx["cur"] = v["ino"]
        elif tag == "SLookup":
            ctx["cur"] = v["child"]
        elif tag == "SLookupp":
            ctx["cur"] = v["parent"]
        elif tag == "SSecinfo":
            ctx["cur"] = None         # SECINFO consumes the current fh
        elif tag == "SGetattr":
            self.check_attrs(v["attrs"], wire["attrs"], ctx["cur"], mism)
        elif tag == "SReadlink":
            if wire["target"] != v["target"]:
                self.fnd(mism, tag, "target", v["target"], wire["target"])
        elif tag == "SAccess":
            if wire["supported"] != v["supported"]:
                self.fnd(mism, tag, "supported", v["supported"],
                         wire["supported"])
            if wire["access"] != v["access"]:
                self.fnd(mism, tag, "access", v["access"], wire["access"])
        elif tag == "SReaddir":
            names = [e["name"] for e in wire["entries"]]
            want = sorted(expand_name(n) for n in v["names"])
            if len(names) != len(set(names)):
                self.fnd(mism, tag, "names", want, sorted(names),
                         "duplicate entries")
            elif sorted(names) != want:
                self.fnd(mism, tag, "names", want, sorted(names))
            if not wire["eof"]:
                self.fnd(mism, tag, "eof", True, False,
                         "eof unset on a full listing")
        elif tag == "SCreate":
            self.check_cinfo(tag, ctx["cur"], v["cinfo"], wire["cinfo"],
                             mism, "cinfo")
            ctx["cur"] = v["ino"]
        elif tag == "SRemove":
            self.check_cinfo(tag, ctx["cur"], v["cinfo"], wire["cinfo"],
                             mism, "cinfo")
        elif tag == "SRename":
            self.check_cinfo(tag, ctx["saved"], v["cinfoS"],
                             wire["source_cinfo"], mism, "cinfoS")
            self.check_cinfo(tag, ctx["cur"], v["cinfoT"],
                             wire["target_cinfo"], mism, "cinfoT")
        elif tag == "SLink":
            self.check_cinfo(tag, ctx["cur"], v["cinfo"], wire["cinfo"],
                             mism, "cinfo")
        elif tag == "SSetclientid":
            self.confirm[v["tok"]] = (wire["clientid"], wire["confirm"])
            self.clientid[v["client"]] = wire["clientid"]
        elif tag == "SExchangeId":
            known = self.clientid.get(v["client"])
            if known is not None and known != wire["clientid"]:
                self.fnd(mism, tag, "clientid", f"{known:#x}",
                         f"{wire['clientid']:#x}",
                         f"model client {v['client']}: wire clientid "
                         f"changed on a repeat EXCHANGE_ID")
                if not v["confirmedR"]:
                    self.clientid[v["client"]] = wire["clientid"]
            else:
                self.clientid[v["client"]] = wire["clientid"]
            # RFC 8881 18.35.3: eir_sequenceid is meaningful only for a
            # newly registered (unconfirmed) client ID, and its initial
            # value is the server's to choose -- so the model's csSeq is
            # symbolic.  The first answer for a client anchors the mapping;
            # a later one must agree with it.
            if not v["confirmedR"]:
                base = self.cs_base.get(v["client"])
                if base is None:
                    self.cs_base[v["client"]] = wire["sequenceid"] - v["csSeq"]
                elif wire["sequenceid"] != v["csSeq"] + base:
                    self.fnd(mism, tag, "sequenceid", v["csSeq"] + base,
                             wire["sequenceid"])
            wire_conf = bool(wire["flags"] & EXCHGID4_FLAG_CONFIRMED_R)
            if wire_conf != v["confirmedR"]:
                self.fnd(mism, tag, "confirmed_r", v["confirmedR"],
                         wire_conf)
            wire_pnfs = bool(wire["flags"] & c4.EXCHGID4_FLAG_USE_PNFS_MDS)
            if wire_pnfs != v["pnfsMds"]:
                self.caps_mismatch(
                    "pnfs", f"trace assumes pnfsMds={v['pnfsMds']}, "
                            f"server advertises {wire_pnfs}")
        elif tag == "SCreateSession":
            self.sess[v["sess"]] = wire["sessionid"]
            # Let a CB_NULL backchannel probe through before the next op:
            # a server that verifies the backchannel before granting
            # delegations does it right here.
            self.c.drain_backchannel(0.05)
        elif tag == "SSequence":
            pass                      # cache bookkeeping in run_compound
        elif tag == "SOpen":
            self.learn_sid(v["sid"], wire["stateid"], mism,
                           expect_seq=v["seq"], what=tag)
            self.sid_client[v["sid"]] = self.cur_open_client
            if req is not None and req["tag"] == "ROpen":
                self.sid_owner[v["sid"]] = (req["value"]["client"],
                                            req["value"]["owner"])
            need = bool(wire["rflags"] & c4.OPEN4_RESULT_CONFIRM)
            if need != v["needConfirm"]:
                self.fnd(mism, tag, "rflags_confirm", v["needConfirm"],
                         need)
            self.check_cinfo(tag, ctx["cur"], v["cinfo"], wire["cinfo"],
                             mism, "cinfo")
            self.check_deleg(v["deleg"], wire, mism)
        elif tag == "SOpenConfirm":
            self.check_seq_only(tag, wire["stateid"], v["seq"], mism)
            self.relearn_seq(req, wire)
        elif tag == "SOpenDowngrade":
            self.check_seq_only(tag, wire["stateid"], v["seq"], mism)
            self.relearn_seq(req, wire)
        elif tag == "SRead":
            data = expand(v["blocks"])
            if wire["eof"] != v["eof"]:
                self.fnd(mism, tag, "eof", v["eof"], wire["eof"])
            if len(wire["data"]) != v["count"] * BLOCK_SIZE:
                self.fnd(mism, tag, "count", v["count"] * BLOCK_SIZE,
                         len(wire["data"]))
            elif wire["data"] != data:
                self.fnd(mism, tag, "data", "<model blocks>", "<wire>",
                         diff_bytes(data, wire["data"], BLOCK_SIZE))
        elif tag == "SWrite":
            if wire["count"] != v["count"] * BLOCK_SIZE:
                self.fnd(mism, tag, "count", v["count"] * BLOCK_SIZE,
                         wire["count"])
            if self.write_verf is None:
                self.write_verf = wire["verf"]
            elif wire["verf"] != self.write_verf:
                self.fnd(mism, tag, "verf", self.write_verf.hex(),
                         wire["verf"].hex(), "write verifier changed")
        elif tag == "SCommit":
            if self.write_verf is not None \
                    and wire["verf"] != self.write_verf:
                self.fnd(mism, tag, "verf", self.write_verf.hex(),
                         wire["verf"].hex(),
                         "commit verifier differs from write verifier")
        elif tag == "SLock":
            self.learn_sid(v["sid"], wire["stateid"], mism,
                           expect_seq=v["seq"], what=tag)
        elif tag == "SLocku":
            self.check_seq_only(tag, wire["stateid"], v["seq"], mism)
            self.relearn_seq(req, wire)
        elif tag == "SLayoutget":
            self.learn_sid(v["sid"], wire["stateid"], mism,
                           expect_seq=v["seq"], what=tag)
            self.check_layout_segments(v, wire, mism)
        elif tag == "SLayoutreturn":
            if wire["present"] != v["present"]:
                self.fnd(mism, tag, "present", v["present"],
                         wire["present"])
            elif v["present"] and wire["stateid"][0] != v["seq"]:
                self.fnd(mism, tag, "seqid", v["seq"], wire["stateid"][0])
        elif tag == "SLayoutcommit":
            if wire["newsize"] is not None and \
                    wire["newsize"] != v["newSizeBlocks"] * BLOCK_SIZE:
                self.fnd(mism, tag, "newsize",
                         v["newSizeBlocks"] * BLOCK_SIZE, wire["newsize"])
        elif tag == "SSeek":
            if wire["eof"] != v["eof"]:
                self.fnd(mism, tag, "eof", v["eof"], wire["eof"])
            if wire["offset"] != v["offset"] * BLOCK_SIZE:
                self.fnd(mism, tag, "offset", v["offset"] * BLOCK_SIZE,
                         wire["offset"])
        elif tag == "SCopy":
            if wire["count"] != v["copied"] * BLOCK_SIZE:
                self.fnd(mism, tag, "count", v["copied"] * BLOCK_SIZE,
                         wire["count"])
        elif tag == "SReadPlus":
            self.check_read_plus(v, wire, req, mism)
        elif tag == "SIoAdvise":
            asked = req["value"]["hint"] if req else None
            extra = [h for h in wire["hints"] if h != asked]
            if extra:
                self.fnd(mism, tag, "hints", [asked], wire["hints"],
                         "honored a hint the client did not ask for")
        elif tag == "SWriteSame":
            if wire["count"] != v["count"] * BLOCK_SIZE:
                self.fnd(mism, tag, "count", v["count"] * BLOCK_SIZE,
                         wire["count"])
        elif tag == "SGetxattr":
            if wire["value"] != xattr_value(v["sym"]):
                self.fnd(mism, tag, "value", xattr_value(v["sym"]),
                         wire["value"])
        elif tag == "SSetxattr":
            self.check_cinfo(tag, ctx["cur"], v["cinfo"], wire["cinfo"],
                             mism, "cinfo")
        elif tag == "SListxattrs":
            if set(wire["names"]) != set(v["names"]):
                self.fnd(mism, tag, "names", sorted(v["names"]),
                         sorted(wire["names"]))
        elif tag == "SRemovexattr":
            self.check_cinfo(tag, ctx["cur"], v["cinfo"], wire["cinfo"],
                             mism, "cinfo")
        # All remaining tags are status-only.

    def check_attrs(self, exp, wire, ino, mism):
        ft = exp["ftype"]["tag"]
        if wire.get(c4.FATTR4_TYPE) != FTYPE_WIRE[ft]:
            self.fnd(mism, "SGetattr", "type", FTYPE_WIRE[ft],
                     wire.get(c4.FATTR4_TYPE), ft)
        # The standard leaves a symlink's permission bits unspecified
        # (POSIX: never consulted; Linux forces 0777), so mode is not
        # asserted for one.
        if ft != "FLnk" and wire.get(c4.FATTR4_MODE) != exp["mode"]:
            self.fnd(mism, "SGetattr", "mode", f"{exp['mode']:#o}",
                     f"{wire.get(c4.FATTR4_MODE, -1):#o}")
        if wire.get(c4.FATTR4_NUMLINKS) != exp["nlink"]:
            self.fnd(mism, "SGetattr", "nlink", exp["nlink"],
                     wire.get(c4.FATTR4_NUMLINKS))
        if ft == "FReg":
            want = exp["sizeBlocks"] * BLOCK_SIZE
            if wire.get(c4.FATTR4_SIZE) != want:
                self.fnd(mism, "SGetattr", "size", want,
                         wire.get(c4.FATTR4_SIZE))
        if c4.FATTR4_CHANGE in wire:
            self.check_change("SGetattr", ino, exp["change"],
                              wire[c4.FATTR4_CHANGE], mism, "change")

    def check_deleg(self, exp, wire, mism):
        dt = wire["deleg_type"]
        etag = exp["tag"]
        if etag == "DNone":
            if dt != 0:
                kind = "readDeleg" if dt == 1 else "writeDeleg"
                self.caps_mismatch(
                    kind, f"trace assumes no delegation, server granted "
                          f"type {dt}")
            return
        want = 1 if etag == "DRead" else 2
        if dt == 0:
            kind = "readDeleg" if want == 1 else "writeDeleg"
            self.caps_mismatch(
                kind, "trace assumes a delegation grant, server granted "
                      "none")
            return
        if dt != want:
            self.fnd(mism, "SOpen", "delegation_type", want, dt)
            return
        self.learn_sid(exp["value"]["sid"], wire["deleg_stateid"], mism,
                       expect_seq=1, what="SOpen.delegation")

    def check_layout_segments(self, v, wire, mism):
        if not wire["segments"]:
            self.fnd(mism, "SLayoutget", "segments", ">= 1", 0,
                     "empty segment list")
            return
        lo = min(s["offset"] for s in wire["segments"])
        hi = max(s["offset"] + min(s["length"], TO_EOF - s["offset"])
                 for s in wire["segments"])
        if lo > v["lo"] * BLOCK_SIZE or hi < v["hi"] * BLOCK_SIZE:
            self.fnd(mism, "SLayoutget", "coverage",
                     f"[{v['lo'] * BLOCK_SIZE}, {v['hi'] * BLOCK_SIZE})",
                     f"[{lo}, {hi})")
        seg = wire["segments"][0]
        if "deviceid" in seg:
            self.deviceid = seg["deviceid"]

    def check_read_plus(self, v, wire, req, mism):
        """The model predicts the DATA/HOLE classification and contents of
        the whole requested range.  A server may legally return a shorter
        prefix (rpr_contents is an array and the client re-issues from the
        last byte returned), so the segments are validated as a
        contiguous, block-aligned prefix from the requested offset and only
        the blocks actually returned are compared."""
        tag = "SReadPlus"
        req_off = req["value"]["off"] * BLOCK_SIZE if req else 0
        want = req_off
        nmodel = len(v["blocks"])
        got = 0
        for i, seg in enumerate(wire["segments"]):
            if seg["offset"] != want:
                self.fnd(mism, tag, "segment_offset", want, seg["offset"],
                         f"segment {i} does not tile the range")
                return
            if seg["length"] == 0 or seg["length"] % BLOCK_SIZE:
                self.fnd(mism, tag, "segment_length",
                         f"multiple of {BLOCK_SIZE}", seg["length"],
                         f"segment {i}")
                return
            for b in range(seg["length"] // BLOCK_SIZE):
                if got >= nmodel:
                    self.fnd(mism, tag, "blocks", nmodel, got + 1,
                             "returned more blocks than the model predicts")
                    return
                is_data = v["isData"][got]
                if seg["is_data"] != is_data:
                    self.fnd(mism, tag, f"block{got}",
                             "DATA" if is_data else "HOLE",
                             "DATA" if seg["is_data"] else "HOLE")
                elif seg["is_data"]:
                    chunk = seg["data"][b * BLOCK_SIZE:(b + 1) * BLOCK_SIZE]
                    if chunk != block_bytes(v["blocks"][got]):
                        self.fnd(mism, tag, f"block{got}",
                                 f"byte {0x40 + v['blocks'][got]:#x}",
                                 f"byte {chunk[0]:#x}" if chunk else "",
                                 "data mismatch")
                got += 1
            want += seg["length"]
        if got == 0 and nmodel > 0 and not wire["eof"]:
            self.fnd(mism, tag, "progress", ">= 1 block", 0,
                     f"no segment for {nmodel} predicted blocks and eof "
                     f"unset")
        if got < nmodel and wire["eof"]:
            self.fnd(mism, tag, "eof", False, True,
                     f"eof after {got} of {nmodel} predicted blocks")
        if got == nmodel and wire["eof"] != v["eof"]:
            self.fnd(mism, tag, "eof", v["eof"], wire["eof"])

    def classify_status_mismatch(self, tag, v, est, ast, wire, mism, req):
        """Divergence in status: capability reconciliation or a finding."""
        pair = {est, ast}
        if tag in SPARSE_TAGS and E_NOTSUPP in pair:
            self.caps_mismatch("sparse", f"{tag}: expected {est}, got {ast}")
        if tag in COPY_TAGS and E_NOTSUPP in pair:
            self.caps_mismatch("copy", f"{tag}: expected {est}, got {ast}")
        if tag in XATTR_TAGS and E_NOTSUPP in pair:
            self.caps_mismatch("xattr", f"{tag}: expected {est}, got {ast}")
        if tag in CAP_OF_TAG and E_NOTSUPP in pair:
            self.caps_mismatch(CAP_OF_TAG[tag],
                               f"{tag}: expected {est}, got {ast}")
        if tag in PNFS_TAGS and pair & {E_NOTSUPP, E_LAYOUTUNAVAILABLE}:
            self.caps_mismatch("pnfs", f"{tag}: expected {est}, got {ast}")
        if tag == "SClose" and pair == {NFS4_OK, E_LOCKS_HELD}:
            self.caps_mismatch("closeFreesLocks",
                               f"expected {est}, got {ast}")
        if tag == "SOpen" and est == E_DELAY and ast == NFS4_OK:
            self.caps_mismatch(
                "conflictDelays",
                "model expected NFS4ERR_DELAY during recall, server "
                "completed the op")
        self.fnd(mism, tag, "status", est, ast)

    # -- compound driver ------------------------------------------------------

    def run_compound(self, idx, lab):
        ops = lab["ops"]
        exp_results = lab["results"]
        exp_status = lab["status"]
        mism = []

        self.cur_open_client = None
        for op in ops:
            if op["tag"] == "ROpen":
                self.cur_open_client = \
                    self.clientid.get(op["value"]["client"])

        encoded = [self.encode_op(op) for op in ops]
        if lab.get("tagName"):
            tag_bytes = expand_name(lab["tagName"])
        else:
            tag_bytes = b"t%d" % lab["tag"]

        # Send; retry when the server reports a transient condition the
        # model did not predict (DELAY, and GRACE on a server whose grace
        # period has not run out yet).
        expected_st = {i: r["value"]["st"] for i, r in enumerate(exp_results)}
        delays = 0
        graces = 0
        while True:
            try:
                rep = self.c.compound(self.minor, encoded, tag=tag_bytes)
            except (c4.RpcError, c4.XdrError):
                # A 256-byte compound tag (tagName "NLONG"): both reference
                # servers cap the tag well below 256 bytes.  knfsd rejects the
                # message at the RPC layer (GARBAGE_ARGS -> RpcError); ganesha
                # decodes it and returns NFS4ERR_INVAL, reconciled as GD-34.
                # RFC 8881 2.2 sets no maximum tag length, so the model accepts
                # it.  Record the server's limit and skip this one compound.
                if lab.get("tagName") == "NLONG":
                    self.deviations_hit["GD-34-long-compound-tag"] = \
                        self.deviations_hit.get(
                            "GD-34-long-compound-tag", 0) + 1
                    return None
                raise
            self.compounds += 1
            transient = None
            for i, r in enumerate(rep["results"]):
                if r["status"] == E_DELAY and expected_st.get(i) != E_DELAY:
                    transient = "delay"
                elif r["status"] == E_GRACE and \
                        expected_st.get(i) != E_GRACE:
                    transient = "grace"
            if transient == "delay" and delays < self.RETRY_DELAY_MAX:
                delays += 1
                time.sleep(0.1)
                continue
            if transient == "grace" and graces < self.RETRY_GRACE_MAX:
                graces += 1
                time.sleep(0.5)
                continue
            break
        if delays >= self.RETRY_DELAY_MAX:
            self.fnd(mism, "compound", "status", "!= DELAY", E_DELAY,
                     f"still NFS4ERR_DELAY after {delays} retries")
        # Callbacks raised by this compound (a recall against another
        # client's delegation) arrive on the same connection; answer them
        # now rather than on the next call.
        self.c.drain_backchannel(0)

        # 4.1 SEQUENCE replay contract: bit-for-bit against our own record
        # of the original reply.
        seq_req = ops[0]["value"] if ops and ops[0]["tag"] == "RSequence" \
            else None
        seq_exp = exp_results[0]["value"] \
            if exp_results and exp_results[0]["tag"] == "SSequence" else None
        if seq_req and seq_exp and seq_exp["replay"] \
                and seq_exp["st"] == NFS4_OK:
            key = (seq_req["sess"], seq_req["slot"])
            cached = self.replay_cache.get(key)
            if cached is None:
                self.fnd(mism, "SSequence", "replay", "<cached reply>",
                         "<none>", "replay step but no cached original")
            elif rep["raw"] != cached:
                self.fnd(mism, "SSequence", "replay", "<original reply>",
                         "<different reply>",
                         "reply cache violation on a slot replay")
            self.reconcile(idx, lab, ops, mism)
            return rep

        ctx = {"cur": None, "saved": None}
        n = min(len(exp_results), len(rep["results"]))
        for i in range(n):
            eop = ops[i]["tag"] if i < len(ops) else "?"
            if eop == "RPutfh":
                ctx["cur"] = ops[i]["value"]
            elif eop == "RPutrootfh":
                ctx["cur"] = 0
            elif eop == "RSavefh":
                ctx["saved"] = ctx["cur"]
            elif eop == "RRestorefh":
                ctx["cur"] = ctx["saved"]
            self.check_result(exp_results[i], rep["results"][i], ctx,
                              mism, ops[i] if i < len(ops) else None)

        if len(rep["results"]) != len(exp_results):
            self.fnd(mism, "compound", "results", len(exp_results),
                     len(rep["results"]),
                     f"statuses {[r['status'] for r in rep['results']]}")
        if rep["status"] != exp_status:
            self.fnd(mism, "compound", "status", exp_status,
                     rep["status"])

        # Record the reply for future SEQUENCE replays of this slot.
        if seq_req is not None and rep["results"] \
                and rep["results"][0]["status"] == NFS4_OK:
            self.replay_cache[(seq_req["sess"], seq_req["slot"])] = \
                rep["raw"]

        # Recall observations promised by this compound.
        for r in exp_results:
            if r["tag"] == "SOpen" and r["value"].get("recalls"):
                self.await_recalls(r["value"]["recalls"], mism)

        self.reconcile(idx, lab, ops, mism)
        return rep

    def reconcile(self, idx, lab, ops, findings):
        """Run every finding through the deviation registry.  A status
        finding on the compound as a whole is dropped when a per-op finding
        already explains it (the compound status is the failing op's)."""
        if not findings:
            return
        op_status = [f for f in findings
                     if f.kind == "status" and f.op != "compound"]
        if op_status:
            findings = [f for f in findings
                        if not (f.op == "compound" and
                                f.kind in ("status", "results"))]
        ctx = {"minor": self.minor, "caps": self.caps, "ops": ops,
               "lab": lab, "step": idx, "replayer": self}
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
                self.unmatched.append((idx, lab, unmatched))
                for f in unmatched:
                    print(f"  [{idx:4d}] MISMATCH {f}")
            else:
                raise Divergence(idx, ("LCompound", lab), unmatched)
        if abandon is not None:
            raise Abandon(idx, abandon[0], abandon[1])

    def await_recalls(self, sids, mism):
        want = {self.sid_other[s] for s in sids if s in self.sid_other}
        deadline = time.time() + 3.0
        while want and time.time() < deadline:
            self.c.drain_backchannel(0.05)
            got = {sid[1] for kind, sid in self.c.recalls
                   if sid is not None}
            self.recall_log.extend(o for o in got if o in want)
            want -= got
        if want:
            self.fnd(mism, "SOpen", "recalls", [o.hex() for o in want], [],
                     "CB_RECALL not observed for delegation stateids")

    def replay(self, steps):
        for idx, lab in enumerate(steps[1:], start=1):
            if lab["tag"] != "LCompound":
                raise TraceFormatError(f"step {idx}: unexpected "
                                       f"{lab['tag']}")
            lab = lab["value"]
            rep = self.run_compound(idx, lab)
            self.history.append((idx, lab, rep))
            if self.verbose:
                stats = [r["status"] for r in rep["results"]]
                opl = ",".join(o["tag"][1:] for o in lab["ops"])
                print(f"  [{idx:4d}] {opl} -> {rep['status']} {stats}")

    def cleanup(self):
        """Best-effort teardown of the state this trace registered, so a
        server that outlives the trace is not left holding it."""
        try:
            if self.minor >= 1:
                for sid in list(self.sess.values()):
                    self.c.compound(self.minor,
                                    [c4.enc_destroy_session(sid)])
                for cid in list(self.clientid.values()):
                    self.c.compound(self.minor,
                                    [c4.enc_destroy_clientid(cid)])
        except Exception:
            pass


def report_divergence(trace_path, div, replayer):
    print(f"\n=== DIVERGENCE in {trace_path} ===", file=sys.stderr)
    lab = div.op[1] if isinstance(div.op[1], dict) else {}
    ops = lab.get("ops")
    print(f"step {div.step}:", file=sys.stderr)
    if ops:
        for i, o in enumerate(ops):
            print(f"    op[{i}] {o['tag']}: {o.get('value')}",
                  file=sys.stderr)
        print(f"  expected status {lab['status']}; expected results:",
              file=sys.stderr)
        for i, r in enumerate(lab["results"]):
            print(f"    res[{i}] {r['tag']}: {r.get('value')}",
                  file=sys.stderr)
    for f in div.findings:
        print(f"  MISMATCH: {f}", file=sys.stderr)
    print("\nlast compounds before failure:", file=sys.stderr)
    for idx, lab, rep in replayer.history[-6:]:
        opl = ",".join(o["tag"][1:] for o in lab["ops"])
        stats = [r["status"] for r in rep["results"]]
        print(f"  [{idx:4d}] {opl} -> {rep['status']} {stats}",
              file=sys.stderr)


def resolve_export(client, export):
    """Walk the export path from PUTROOTFH with a minorversion-0 compound
    (4.1 forbids non-session compounds beyond a tiny op set) and read the
    server's supported attribute set off the export root."""
    comps = [c for c in export.split("/") if c]
    ops = [c4.enc_putrootfh()] + [c4.enc_lookup(c) for c in comps] + \
          [c4.enc_getfh(),
           c4.enc_getattr([c4.FATTR4_SUPPORTED_ATTRS])]
    rep = client.compound(0, ops, tag=b"specs-root")
    if rep["status"] != NFS4_OK:
        raise RuntimeError(f"cannot resolve export {export!r}: "
                           f"status {rep['status']} "
                           f"({[r['status'] for r in rep['results']]})")
    fh = rep["results"][len(comps) + 1]["fh"]
    supported = rep["results"][len(comps) + 2]["attrs"] \
        .get(c4.FATTR4_SUPPORTED_ATTRS, [])
    return fh, supported


class TraceOutcome:
    def __init__(self, path):
        self.path = path
        self.status = "ok"        # ok | skip | abandoned | mismatch | error
        self.detail = ""
        self.deviations = {}
        self.compounds = 0
        self.steps = 0


def run_trace(trace_path, args, registry, epoch):
    out = TraceOutcome(trace_path)
    steps = load_trace_v4(trace_path)
    out.steps = len(steps) - 1
    init = steps[0]["value"]
    minor = init["minor"]
    caps = init["caps"]

    if args.dry_run:
        # No server: still run every op through its encoder, so a trace
        # carrying an op this harness cannot put on the wire is a loud
        # failure here rather than a surprise mid-replay.
        r = Replayer(None, b"\x7f" * 16, minor, caps, registry, epoch,
                     c4.WIDE_ATTRS)
        r.dry = True
        nops = 0
        for lab in steps[1:]:
            for op in lab["value"]["ops"]:
                r.encode_op(op)
                nops += 1
        print(f"{trace_path}: {len(steps) - 1} compounds / {nops} ops, "
              f"minor {minor}, encode OK")
        return out

    client = c4.Nfs4Client(args.server, port=args.port,
                           timeout=args.rpc_timeout)
    replayer = None
    try:
        client.null()
        root_fh, supported = resolve_export(client, args.export)
        wide = sorted(set(supported) & set(c4.WIDE_ATTRS))
        replayer = Replayer(client, root_fh, minor, caps, registry, epoch,
                            wide, keep_going=args.keep_going,
                            verbose=args.verbose)
        try:
            replayer.replay(steps)
        except CapsSkip as skip:
            out.status = "skip"
            out.detail = str(skip)
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
        out.deviations = dict(replayer.deviations_hit)
        out.compounds = replayer.compounds
        replayer.cleanup()
    except (OSError, c4.RpcError, c4.XdrError, RuntimeError) as e:
        out.status = "error"
        out.detail = f"{type(e).__name__}: {e}"
        if replayer is not None:
            out.deviations = dict(replayer.deviations_hit)
            out.compounds = replayer.compounds
            print(f"\n=== {trace_path}: {out.detail} ===", file=sys.stderr)
            for idx, lab, rep in replayer.history[-6:]:
                opl = ",".join(o["tag"][1:] for o in lab["ops"])
                stats = [r["status"] for r in rep["results"]]
                print(f"  [{idx:4d}] {opl} -> {rep['status']} {stats}",
                      file=sys.stderr)
    finally:
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
        print(f"{name}: OK ({out.steps} compounds, minor {minor}{devs})")
    elif out.status == "skip":
        print(f"{name}: SKIP (not applicable): {out.detail}{devs}")
    elif out.status == "abandoned":
        print(f"{name}: ABANDONED after {out.compounds}/{out.steps} "
              f"compounds: {out.detail}{devs}")
    elif out.status == "mismatch":
        print(f"{name}: MISMATCH ({out.detail}){devs}")
    else:
        print(f"{name}: ERROR {out.detail}{devs}")
    return out


def load_registry(kind, suite="NFS4"):
    if kind in (None, "", "none"):
        return None
    mod = importlib.import_module(f"{kind}_deviations")
    return getattr(mod, suite)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--trace", action="append", required=True)
    ap.add_argument("--server", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=2049)
    ap.add_argument("--export", default="/",
                    help="path of the export below PUTROOTFH (the model's "
                         "root); '/' when the export is the pseudo root")
    ap.add_argument("--server-kind", default="none",
                    help="deviation registry to consult: ganesha, knfsd, "
                         "or none")
    ap.add_argument("--owner-epoch", default=None,
                    help="salt for client owner strings; default: pid+time")
    ap.add_argument("--keep-going", action="store_true",
                    help="report every divergence in a trace instead of "
                         "stopping at the first unrecorded one")
    ap.add_argument("--rpc-timeout", type=float, default=30.0)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    registry = load_registry(args.server_kind)
    epoch = args.owner_epoch or f"{os.getpid()}-{int(time.time())}"

    outcomes = []
    for i, trace in enumerate(args.trace):
        outcomes.append(run_trace(trace, args, registry, f"{epoch}-{i}"))

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
    if by.get("skip", 0) == n:
        return 77
    return 0


if __name__ == "__main__":
    sys.exit(main())
