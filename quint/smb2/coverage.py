# SPDX-FileCopyrightText: 2026 The Quint Specs Authors
#
# SPDX-License-Identifier: MIT

"""SMB2 MBT corpus coverage gate.

Scans the generated ITF traces and asserts the corpus actually exercises the
behavior buckets the model is meant to cover.  Uniform random stepping can
silently starve a matrix corner; this gate turns that starvation red instead
of letting a never-exercised path masquerade as covered (the SMB analogue of
the NFS `coverage` ctest).

Three properties this gate deliberately has:

  * It discovers instances and flavors from the trace file names rather than
    hard-coding one, so a second instance's traces cannot be invisible to it.
    CMake passes the exact set of traces the current configuration generates,
    so a stale trace left in the build directory by an earlier configuration
    can neither satisfy a bucket nor be replayed as coverage.
  * It requires coverage **per (instance, flavor) group**, not as one global
    union, so a new flavor cannot ride on an old flavor's buckets.
  * It requires the CREATE *request* axes (DesiredAccess and ShareAccess
    profiles), not only the reply statuses.  Without that, a generator that
    stopped varying access and share entirely would still pass every
    status-and-action bucket.

Trace file names are `<inst>_<flavor>_<steps>_<seed>_<seq>.itf.json` (see
smb2_mbt_add_batch in CMakeLists.txt); the group key is `<inst>/<flavor>`.
"""

import collections
import glob
import json
import os
import re
import sys

# NTSTATUS values the corpus must exercise.
ST_SUCCESS = 0x00000000
ST_END_OF_FILE = 0xC0000011
ST_OBJECT_NAME_NOT_FOUND = 0xC0000034
ST_OBJECT_NAME_COLLISION = 0xC0000035
ST_SHARING_VIOLATION = 0xC0000043
ST_INVALID_DEVICE_REQUEST = 0xC0000010
ST_FILE_IS_A_DIRECTORY = 0xC00000BA
ST_NOT_A_DIRECTORY = 0xC0000103

DISPOSITIONS = ["DispOpen", "DispCreate", "DispOpenIf", "DispOverwrite",
                "DispOverwriteIf", "DispSupersede"]
# The dispositions that take WRITE at open time whatever DesiredAccess says
# (MS-FSA 2.1.5.1.2; smb_proc_create.c "A truncating disposition must obtain
# write access at open time").
TRUNCATING = ("DispSupersede", "DispOverwrite", "DispOverwriteIf")
# CreateAction: SUPERSEDED=0, OPENED=1, CREATED=2, OVERWRITTEN=3
ACTIONS = [0, 1, 2, 3]

# DesiredAccess / ShareAccess profiles, spelled as the sorted subset of the
# axes the request sets.  "-" is the empty profile: for ShareAccess that is
# SHARE_NONE (deny everything), for DesiredAccess it is the ATTRIBUTE-ONLY
# open, which takes no part in share arbitration in either direction.  `h`
# (READ_ATTRIBUTES) is not listed for access because every modeled access
# profile sets it, so it would be a constant bucket.
#
# "d" (DELETE alone) and the "w" / "d" / "rd" share profiles are what make the
# three arbitration axes INDEPENDENT: while the domain held only r/rw/rwd,
# "shares write" implied "shares read" and no trace could distinguish a
# read-axis conflict from a write-axis one.
ACCESS_PROFILES = ["-", "d", "r", "rw", "rwd", "w"]
SHARE_PROFILES = ["-", "d", "r", "rd", "rw", "rwd", "w"]

# Flavors whose whole point is the oplock/lease caching lifecycle.  Their
# groups carry extra required buckets so a caching corpus that stops granting,
# breaking or acknowledging anything turns the gate red instead of coasting on
# the filesystem-core buckets it shares with `stepCore`.
CACHING_FLAVORS = ("stepLease",)

# Flavors that never build a compound message, so the compound buckets do not
# apply to them.
NON_COMPOUND_FLAVORS = ("stepReplay",)

# Flavors whose whole point is the file/directory TYPE matrix and the
# directory-handle I/O guard.  Without extra buckets a `stepDir` corpus that
# stopped producing directories at all would still satisfy every generic
# bucket by riding on its file CREATEs.
DIR_FLAVORS = ("stepDir",)

# Flavors whose whole point is the oplock/lease REQUEST matrix on a server
# with caching off: every CreateContext-carrying CREATE encoding, the
# bare-RqLs reply (OplockLevel=LEASE, state NONE, epoch echoed) and the
# lease-key-per-file binding.  Without these a `stepReq` corpus that stopped
# asking for oplocks would be indistinguishable from `stepCore`.
REQ_FLAVORS = ("stepReq",)

# Flavors whose whole point is the DURABLE-handle lifecycle: request, grant,
# park on a transport drop, reconnect, reclaim, and the reclaim DENIAL matrix.
# Without extra buckets a `stepDurable` corpus that stopped asking for durable
# handles -- or that asked and never dropped a connection, so nothing ever
# parked and no reclaim was ever adjudicated -- would satisfy every generic
# bucket by riding on its ordinary CREATEs.
DUR_FLAVORS = ("stepDurable",)

# Metadata + byte-range-lock flavors: QUERY_INFO, FLUSH, SET_INFO/EndOfFile and
# the SMB2 LOCK command, none of which any earlier corpus could put on the wire.
INFO_FLAVORS = ("stepInfo",)

# Namespace mutation + session/tree teardown: SET_INFO/Rename, LOGOFF,
# TREE_DISCONNECT.
NS_FLAVORS = ("stepNs",)

# The CHANGE_NOTIFY lifecycle: arm a directory watch, buffer changes against
# its two filters, deliver or overflow them, and end the parked request every
# way it can end.
#
# This flavor deliberately SHARES EVERYTHING and issues no READ, and both are
# load-bearing rather than oversights, so several generic buckets are dropped
# for it in required_buckets() -- see the justification there.
NOTIFY_FLAVORS = ("stepNotify", "stepNotifyNs")

# The namespace half of it, which is the subset an independent server agrees
# on record-for-record.  Narrower by construction -- one name filter per
# handle, buffers that always fit, one waiter at a time -- so the buckets that
# belong to the axes it drops are not required of it.
NOTIFY_NS_FLAVORS = ("stepNotifyNs",)

ST_NOTIFY_CLEANUP = 0x0000010B
ST_NOTIFY_ENUM_DIR = 0x0000010C
ST_CANCELLED = 0xC0000120
ST_ACCESS_DENIED = 0xC0000022

# FILE_ACTION_* (MS-FSCC 2.7.1).  All five must be delivered to a watcher: the
# rename pair is what proves a two-record event survives serialization, and
# ADDED / REMOVED / MODIFIED are what prove the three mutation classes are
# distinguished rather than collapsed.
FILE_ACTIONS = [1, 2, 3, 4, 5]

ST_LOCK_NOT_GRANTED = 0xC0000055
ST_RANGE_NOT_LOCKED = 0xC000007E
ST_FILE_LOCK_CONFLICT = 0xC0000054

ST_INVALID_PARAMETER = 0xC000000D
ST_DUPLICATE_OBJECTID = 0xC000022A

# Connection.MaxTransactSize, as the model pins it (smb2ops.MAX_TRANSACT).
MAX_TRANSACT = 1048576

# Acknowledgment outcomes (MS-SMB2 3.3.5.22.1/.2): success, the two
# not-Breaking rejections, and the keep-too-much rejection.
ACK_STATUSES = [0x00000000, 0xC0000001, 0xC0000184, 0xC00000D0]

# `<inst>_<flavor>_<steps>_<seed>_<seq>.itf.json`
NAME_RE = re.compile(r"^(?P<inst>[^_]+)_(?P<flavor>[^_]+)_")


def as_int(o):
    if isinstance(o, dict) and "#bigint" in o:
        return int(o["#bigint"])
    return o


def last_op_key(state):
    for k in state:
        if k.endswith("::lastOp"):
            return k
    return None


def profile(rec, axes):
    s = "".join(a for a in axes if rec.get(a))
    return s if s else "-"


def as_set(o):
    """An ITF set is {"#set": [...]}; anything else is taken as a list."""
    if isinstance(o, dict) and "#set" in o:
        return o["#set"]
    return o or []


def caching_bucket(caching):
    """Bucket name for a granted caching grant, by SHAPE not just kind."""
    tag = caching.get("tag")
    if tag == "CNone":
        return "grant:none"
    if tag == "COplock":
        return "grant:oplock:" + caching["value"]["tag"]
    st = caching["value"]["st"]
    return "grant:lease:" + profile(st, "rwh")


def scan(path, buckets):
    with open(path) as f:
        doc = json.load(f)
    states = doc["states"]
    key = last_op_key(states[0])
    # The capability profile the corpus was generated under.  Some rules are
    # conditional on a capability actually being advertised, and a bucket that
    # can only be reached under a capability the instance turned off is not a
    # coverage hole -- it is a requirement that does not apply.
    init = states[0].get(key)
    if init and init.get("tag") == "LInit":
        for cap, on in init["value"]["caps"].items():
            if on:
                buckets["caps:" + cap] = True
    for st in states[1:]:
        lo = st.get(key)
        if not lo or lo.get("tag") != "LMsg":
            continue
        v = lo["value"]
        cmds = v["msg"]["cmds"]
        res = v["results"]
        # A related compound whose first error stops the chain comes back with
        # fewer results than commands.  That truncation is the model's
        # first-error-stop rule; if the corpus never produces one, the abort
        # branch is untested.
        if len(res) < len(cmds):
            buckets["compound:abort"] = True
        elif len(cmds) > 1:
            buckets["compound:full"] = True
        for i in range(min(len(cmds), len(res))):
            c = cmds[i]
            r = res[i]
            ctag = c.get("tag")
            cv = c.get("value", {})
            rv = r.get("value", {})
            status = as_int(rv.get("st", 0)) & 0xFFFFFFFF
            if ctag == "CCreate":
                acc = profile(cv["access"], "rwd")
                disp = cv["disp"]["tag"]
                buckets["disp:" + disp] = True
                buckets["acc:" + acc] = True
                buckets["shr:" + profile(cv["share"], "rwd")] = True
                buckets["cr_status:0x%08x" % status] = True
                # The M-1 shape, bucketed by OUTCOME.  A truncating
                # disposition needs WRITE at open time even when DesiredAccess
                # never asked for it, so it must be arbitrated against a peer's
                # deny-W.  Requiring BOTH arms means the corpus has to contain
                # a no-write truncating open that was admitted and one that was
                # refused -- the exact pair the pre-M-1 model got wrong.  A
                # generator that stopped drawing truncating dispositions, or a
                # walk too shallow to put one behind a write-denying peer,
                # turns the gate red instead of passing on the `disp:` bucket
                # alone.
                if disp in TRUNCATING and "w" not in acc:
                    buckets["truncnw:0x%08x" % status] = True
                # The attribute-only open: no R/W/D at all, so it is exempt
                # from share arbitration in both directions (M-5).
                if acc == "-":
                    buckets["attronly:0x%08x" % status] = True
                buckets["oplreq:" + cv["oplock"]["tag"]] = True
                # --- durable-handle contexts (MS-SMB2 2.2.13.2.3/.5/.11/.12)
                dur = cv.get("durable", {})
                dtag = dur.get("tag", "DurNone")
                dv = dur.get("value", {})
                buckets["durreq:" + dtag] = True
                if dtag == "DurQ":
                    buckets["durq:v2" if dv.get("v2") else "durq:v1"] = True
                elif dtag == "DurC":
                    # A RECONNECT: its version, its status (the whole denial
                    # matrix of C-17 is distinguished by status), and the
                    # malformed arms, which are what probe D4 pins.
                    buckets["durc:v2" if dv.get("v2") else "durc:v1"] = True
                    buckets["durc:0x%08x" % status] = True
                    if dv.get("alsoQ"):
                        buckets["durc:alsoq"] = True
                    if dv.get("withName"):
                        buckets["durc:withname"] = True
                    if dv.get("persistent"):
                        buckets["durc:persist"] = True
                if cv["oplock"]["tag"] == "OrLease":
                    buckets["lease:v2" if cv["oplock"]["value"]["v2"]
                            else "lease:v1"] = True
                if status == ST_SUCCESS:
                    buckets["action:%d" % as_int(rv.get("act", -1))] = True
                    buckets[caching_bucket(rv["caching"])] = True
                    # Whether the reply carried a DHnQ / DH2Q response context,
                    # which IS the durable grant signal on the wire (C-13).
                    # Both arms are required for a durable flavor: a corpus
                    # that only ever asked with a BATCH oplock would never see
                    # the refusal, and vice versa.
                    if dtag != "DurNone":
                        buckets["durgrant:%d"
                                % (1 if rv.get("durable") else 0)] = True
                    # An async interim (STATUS_PENDING) had to go out first.
                    buckets["park:%d" % (1 if rv.get("parked") else 0)] = True
            elif ctag == "CBreakAck":
                buckets["ack:0x%08x" % status] = True
            elif ctag == "CRead":
                buckets["read:0x%08x" % status] = True
            elif ctag == "CWrite":
                buckets["write:0x%08x" % status] = True
            elif ctag == "CClose":
                buckets["close:0x%08x" % status] = True
            elif ctag == "CSessionSetup":
                buckets["session:0x%08x" % status] = True
            elif ctag == "CTreeConnect":
                buckets["tree:0x%08x" % status] = True
            elif ctag == "CQueryBasic":
                buckets["query:0x%08x" % status] = True
                if status == ST_SUCCESS:
                    a = rv["attrs"]
                    # The query oracle is only as good as the range of states
                    # it is asked about.  A corpus whose every QUERY_INFO sees
                    # the same empty, link-1, not-pending file would pass while
                    # checking one constant, so the SHAPE of what was observed
                    # is bucketed: an empty file and a non-empty one (the
                    # EndOfFile field actually moving), and both delete-pending
                    # verdicts.
                    buckets["qsize:%s" % ("0" if as_int(a["sizeBlocks"]) == 0
                                          else "nz")] = True
                    buckets["qtype:%s" % ("dir" if a["ftype"]["tag"] == "FDir"
                                          else "file")] = True
                    buckets["qdel:%d" % (1 if a["deletePending"] else 0)] = True
            elif ctag == "CFlush":
                buckets["flush:0x%08x" % status] = True
            elif ctag == "CLock":
                if cv["unlock"]:
                    buckets["unlock:0x%08x" % status] = True
                else:
                    buckets["lock:%s:0x%08x"
                            % ("excl" if cv["wr"] else "shared", status)] = True
            elif ctag == "CSetEof":
                buckets["seteof:0x%08x" % status] = True
            elif ctag == "CSetDisposition":
                buckets["setdisp:%d:0x%08x"
                        % (1 if cv["del"] else 0, status)] = True
            elif ctag == "CSetRename":
                buckets["rename:0x%08x" % status] = True
            elif ctag == "CLogoff":
                buckets["logoff:0x%08x" % status] = True
            elif ctag == "CNotify":
                buckets["notify:0x%08x" % status] = True
                buckets["notify:wt:%d" % (1 if cv["watchTree"] else 0)] = True
                # The two filters are only distinguishable if the corpus draws
                # more than one, so every CompletionFilter bit the model can
                # ask for is a bucket of its own.
                for bit in as_set(cv["cf"]):
                    buckets["notify:cf:" + bit] = True
                # OutputBufferLength, by what it MEANS rather than by value: a
                # zero-length poll, a buffer that can hold records, and one
                # past Connection.MaxTransactSize (refused, not clamped).
                obl = as_int(cv["obl"])
                if obl == 0:
                    buckets["notify:obl:poll"] = True
                elif obl > MAX_TRANSACT:
                    buckets["notify:obl:overmax"] = True
                else:
                    buckets["notify:obl:fit"] = True
                # Did it park (an async interim went out) or answer inline?
                # Both are required: a corpus where every request parked would
                # never exercise the synchronous drain, and one where none did
                # would never exercise the async completion path at all.
                buckets["notify:park:%d"
                        % (1 if rv.get("parked") else 0)] = True
                for rec in rv.get("recs", []):
                    buckets["notifyrec:act:%d" % as_int(rec["act"])] = True
                if status == ST_SUCCESS:
                    buckets["notify:recs:%s"
                            % ("0" if not rv.get("recs") else "nz")] = True
            elif ctag == "CCancel":
                buckets["cancel:found:%d"
                        % (1 if rv.get("found") else 0)] = True
            elif ctag == "CTreeDisconnect":
                buckets["treedisc:0x%08x" % status] = True
            elif ctag == "CDisconnect":
                buckets["disconnect"] = True
            elif ctag == "CReconnect":
                buckets["reconnect"] = True
            else:
                buckets["cmd:" + str(ctag) + ":0x%08x" % status] = True
            # Break notifications the model says the server must push.  Their
            # SHAPE is the coverage that matters: lease vs legacy, whether an
            # acknowledgment is required, and each rung of the RWH -> RH -> R
            # -> NONE cascade.
            for b in as_set(rv.get("breaks")):
                buckets["break:" + ("lease" if b["isLease"] else "oplock")] = True
                buckets["break:ack:%d" % (1 if b["ackReq"] else 0)] = True
                buckets["break:new:0x%02x" % as_int(b["newState"])] = True
                if as_int(b["epoch"]) > 1:
                    buckets["break:epoch_bump"] = True
        # CHANGE_NOTIFY completions this message caused, on whatever handles
        # had a request parked.  They hang off the MESSAGE rather than any
        # command's reply, because the watcher is usually not the client whose
        # command woke it -- which is the whole shape this flavor exists to
        # exercise.
        for n in as_set(v.get("notes")):
            buckets["note:0x%08x" % (as_int(n["st"]) & 0xFFFFFFFF)] = True
            buckets["note:recs:%s" % ("0" if not n["recs"] else "nz")] = True
            for rec in n["recs"]:
                buckets["notifyrec:act:%d" % as_int(rec["act"])] = True


def required_buckets(flavor, observed=None):
    """Buckets this (instance, flavor) group must exercise.

    `observed` is the group's own bucket set, used only for requirements that
    are conditional on the capability profile the corpus was generated under.
    """
    observed = observed or {}
    req = []
    req += ["disp:" + d for d in DISPOSITIONS]
    req += ["acc:" + a for a in ACCESS_PROFILES]
    req += ["shr:" + s for s in SHARE_PROFILES]
    req += ["action:%d" % a for a in ACTIONS]
    req += ["cr_status:0x%08x" % s for s in
            (ST_SUCCESS, ST_SHARING_VIOLATION, ST_OBJECT_NAME_COLLISION,
             ST_OBJECT_NAME_NOT_FOUND)]
    req += ["read:0x%08x" % ST_SUCCESS, "read:0x%08x" % ST_END_OF_FILE]
    req += ["write:0x%08x" % ST_SUCCESS]
    req += ["close:0x%08x" % ST_SUCCESS]
    req += ["session:0x%08x" % ST_SUCCESS, "tree:0x%08x" % ST_SUCCESS]
    # Compounds, but only for the flavors that build them.  stepReplay's whole
    # purpose is stamping ChannelSequence and the REPLAY flag on ORDINARY
    # singleton requests, so it draws no compound at all -- demanding one there
    # would be demanding the flavor stop being itself.
    if flavor not in NON_COMPOUND_FLAVORS:
        req += ["compound:full", "compound:abort"]
    # Both arms of the truncating-open share check, and the attribute-only
    # bypass.  See the scan() comment: these are shapes, not statuses, and
    # they are what the M-1 / M-5 model defects got wrong.
    req += ["truncnw:0x%08x" % s for s in (ST_SUCCESS, ST_SHARING_VIOLATION)]
    req += ["attronly:0x%08x" % ST_SUCCESS]
    if flavor in REQ_FLAVORS:
        # Every oplock/lease REQUEST encoding, both lease context versions,
        # the bare-RqLs reply shape (a lease reported with NO caching state --
        # the M-4/M-6 path), and the lease-key-per-file binding of MS-SMB2
        # 3.3.5.9.8 (STATUS_INVALID_PARAMETER, C-10).
        req += ["oplreq:" + o for o in ("OrNone", "OrLevelII", "OrExclusive",
                                        "OrBatch", "OrLease")]
        req += ["lease:v1", "lease:v2", "grant:lease:-"]
        # The lease-key-per-file binding (MS-SMB2 3.3.5.9.8) answers
        # STATUS_INVALID_PARAMETER -- but only on a server that ADVERTISES
        # leasing.  With leasing off the RqLs context is not processed at all,
        # so the rule never fires and demanding the status here would require
        # the model to invent it (which it used to, and which Samba caught as
        # SD-6).  On a leases-off instance the rule is pinned by the
        # smb2TestNoLease self-test instead, where it belongs.
        if observed.get("caps:leases"):
            req += ["cr_status:0x%08x" % ST_INVALID_PARAMETER]
    if flavor in DUR_FLAVORS:
        # The durable REQUEST, both versions, and both verdicts (granted /
        # refused -- probe D1's matrix boils down to that pair).
        req += ["durreq:DurNone", "durreq:DurQ", "durreq:DurC"]
        req += ["durq:v1", "durq:v2", "durgrant:0", "durgrant:1"]
        # The lifecycle itself: a transport drop and a reconnect must actually
        # happen, or nothing below is reachable.
        req += ["disconnect", "reconnect"]
        # The reclaim and its denial matrix, distinguished by status (C-17):
        # a successful reclaim, an OBJECT_NAME_NOT_FOUND refusal (wrong guid /
        # wrong lease key / wrong client / unknown handle) and an
        # INVALID_PARAMETER one (DH2C+DH2Q, a named leased reconnect, a
        # persistent reconnect of a non-persistent handle).
        req += ["durc:0x%08x" % s for s in
                (ST_SUCCESS, ST_OBJECT_NAME_NOT_FOUND, ST_INVALID_PARAMETER)]
        req += ["durc:v1", "durc:v2"]
        # The malformed arms the denial matrix is made of.  Requiring them by
        # SHAPE as well as by status is what stops the three status buckets
        # above from all being satisfied by one arm.
        req += ["durc:alsoq", "durc:withname", "durc:persist"]
        # A CreateGuid names ONE durable open per client: the collision the
        # FIRST generated durable trace found (M-7).
        req += ["cr_status:0x%08x" % ST_DUPLICATE_OBJECTID]
    if flavor in INFO_FLAVORS:
        # QUERY_INFO with a MOVING oracle: the corpus must show the query
        # agreeing about an empty file and about a non-empty one, and about
        # both delete-pending verdicts, or the attribute comparison is only
        # ever checking a constant.
        req += ["query:0x%08x" % ST_SUCCESS, "qsize:0", "qsize:nz",
                "qtype:file", "qdel:0"]
        req += ["flush:0x%08x" % ST_SUCCESS]
        req += ["seteof:0x%08x" % ST_SUCCESS]
        # Both lock kinds granted, an exclusive one REFUSED
        # (STATUS_LOCK_NOT_GRANTED -- either a peer's conflicting lock or the
        # same-handle overlap rule of M-18), an unlock that matched and one
        # that did not (STATUS_RANGE_NOT_LOCKED, the exact-range rule of M-17).
        req += ["lock:excl:0x%08x" % ST_SUCCESS,
                "lock:shared:0x%08x" % ST_SUCCESS,
                "lock:excl:0x%08x" % ST_LOCK_NOT_GRANTED,
                "unlock:0x%08x" % ST_SUCCESS,
                "unlock:0x%08x" % ST_RANGE_NOT_LOCKED]
        # And the point of locks: they are MANDATORY, so a peer's I/O over a
        # locked range is refused.  Without this the corpus could take every
        # lock in the world and never prove one was enforced.
        req += ["write:0x%08x" % ST_FILE_LOCK_CONFLICT]
    if flavor in NS_FLAVORS:
        # A rename that moved a name and one refused because the target was
        # occupied (MS-FSA 2.1.5.14.11, ReplaceIfExists = FALSE).
        req += ["rename:0x%08x" % ST_SUCCESS,
                "rename:0x%08x" % ST_OBJECT_NAME_COLLISION]
        # Teardown actually happening, both scopes.
        req += ["logoff:0x%08x" % ST_SUCCESS,
                "treedisc:0x%08x" % ST_SUCCESS]
        # A query is drawn here too, and it is what proves a renamed handle
        # still resolves to the object it named before the move.
        req += ["query:0x%08x" % ST_SUCCESS]
        # The FileDispositionInformation class, unmark arm (see smb2.qnt's
        # smbSetDispositionOff for why only that arm is generated).
        req += ["setdisp:0:0x%08x" % ST_SUCCESS]
    if flavor in NOTIFY_NS_FLAVORS:
        # This flavor is not about the CREATE matrix at all -- it is the
        # notify machinery watched through the name filters, and it draws a
        # deliberately narrow set of opens (read-capable directory handles and
        # RWD file handles) so that no request is ever refused for access and
        # no delivery is ever cut short.  Requiring the generic
        # disposition/access/share matrix of it would be requiring it to stop
        # being itself; stepCore and stepShare own that matrix.
        keep = ("action:", "close:", "session:", "tree:", "compound:full")
        req = [b for b in req
               if b.startswith(keep) or b == "cr_status:0x00000000"]
    if flavor in NOTIFY_FLAVORS:
        # Drop the generic buckets this flavor cannot reach BY CONSTRUCTION,
        # each for a stated reason rather than because it happened to starve:
        #
        #  * every open shares R/W/D, so share arbitration never refuses one.
        #    That is deliberate: a refused TRUNCATING create is CD-3, a
        #    non-reconcilable deviation that abandons the trace and takes the
        #    remaining hundreds of steps of notify coverage with it.  Share
        #    arbitration is stepCore's and stepShare's subject.
        #  * no action issues a READ.  Reading a file raises no change and
        #    tells a watcher nothing; the flavor spends its budget on mutations
        #    instead.
        #  * the one compound it builds (open-for-delete + close) always
        #    succeeds, so no chain is ever cut short by a first error.
        req = [b for b in req
               if not b.startswith("read:") and
               not (b.startswith("shr:") and b != "shr:rwd")]
        req = [b for b in req
               if b not in ("compound:abort",
                            "cr_status:0x%08x" % ST_SHARING_VIOLATION,
                            "truncnw:0x%08x" % ST_SHARING_VIOLATION)]
        # Every outcome an arriving CHANGE_NOTIFY can have that this flavor
        # can produce: answered from the buffer, parked, and the handle going
        # away.  The refusals and the overflow arms belong to the full flavor.
        req += ["notify:0x%08x" % s for s in (ST_SUCCESS, 0x00000103)]
        req += ["notify:park:0", "notify:park:1", "notify:obl:fit"]
        # A CHANGE_NOTIFY answered from the buffer with records in it -- the
        # synchronous drain.  Without this the corpus could park every request
        # and never serialize a record on the reply path at all.
        req += ["notify:recs:nz"]
        # Every way a PARKED request can end that this flavor reaches.
        req += ["note:0x%08x" % s for s in
                (ST_SUCCESS, ST_NOTIFY_CLEANUP, ST_CANCELLED)]
        req += ["note:recs:nz", "cancel:found:1"]
        # The four namespace FILE_ACTIONs actually delivered to a client.
        # MODIFIED (3) belongs to the data half, which this flavor omits.
        req += ["notifyrec:act:%d" % a for a in (1, 2, 4, 5)]
        # Both name filters actually used, and the discrimination between
        # them: this is the axis the flavor exists for, and a corpus that
        # asked for both at once on every handle would not test it.
        req += ["notify:cf:fileName", "notify:cf:dirName"]
    if flavor in NOTIFY_FLAVORS and flavor not in NOTIFY_NS_FLAVORS:
        # Every outcome an arriving CHANGE_NOTIFY can have: answered from the
        # buffer, parked, told to rescan, and the three refusals (wrong handle
        # type / no FILE_LIST_DIRECTORY / a buffer past MaxTransactSize).
        req += ["notify:0x%08x" % s for s in
                (ST_SUCCESS, 0x00000103, ST_NOTIFY_ENUM_DIR,
                 ST_INVALID_PARAMETER, ST_ACCESS_DENIED)]
        # Both halves of the park/answer split, both recursion settings, and
        # all three OutputBufferLength meanings.
        req += ["notify:park:0", "notify:park:1",
                "notify:wt:0", "notify:wt:1",
                "notify:obl:poll", "notify:obl:fit", "notify:obl:overmax"]
        req += ["notify:recs:nz"]
        # Every way a PARKED request can end: an event, an overflow, an
        # explicit CANCEL, and the handle going away.
        req += ["note:0x%08x" % s for s in
                (ST_SUCCESS, ST_NOTIFY_ENUM_DIR, ST_NOTIFY_CLEANUP,
                 ST_CANCELLED)]
        req += ["note:recs:nz", "cancel:found:1"]
        # All five FILE_ACTIONs actually delivered to a client.
        req += ["notifyrec:act:%d" % a for a in FILE_ACTIONS]
    if flavor in DIR_FLAVORS:
        # Both diagonals of the type matrix (a file open of a directory and a
        # directory open of a file), and a READ through a directory handle --
        # STATUS_INVALID_DEVICE_REQUEST, the guard MS-FSA 2.1.5.2 mandates.
        # (A directory WRITE is deliberately not generated: DEVIATIONS-SMB.md
        # S-2.  Add "write:0x%08x" % ST_INVALID_DEVICE_REQUEST here when it
        # closes.)
        req += ["cr_status:0x%08x" % s for s in
                (ST_FILE_IS_A_DIRECTORY, ST_NOT_A_DIRECTORY)]
        req += ["read:0x%08x" % ST_INVALID_DEVICE_REQUEST]
    if flavor not in CACHING_FLAVORS:
        return req
    # --- caching lifecycle (oplocks + leases) ---------------------------
    # Every oplock/lease REQUEST form, including OrLevelII, which no action
    # used to draw at all.
    req += ["oplreq:" + o for o in ("OrNone", "OrLevelII", "OrExclusive",
                                    "OrBatch", "OrLease")]
    req += ["lease:v1", "lease:v2"]
    # Grant shapes: the legacy levels and the lease states that matter.
    req += ["grant:none", "grant:oplock:OpLevelII"]
    # A share carrying SMB2_SHAREFLAG_FORCE_LEVELII_OPLOCK caps every grant to
    # a READ cache (MS-SMB2 2.2.10), so on such an instance an exclusive or
    # batch oplock, a W- or H-carrying lease, and everything that follows from
    # one -- an ack-required break, the parked open waiting behind it, the
    # acknowledgment matrix -- are unreachable BY CONSTRUCTION, not starved.
    # Requiring them there would demand the share flag stop working.  The
    # capped instance is still gated on the read-cache lifecycle below.
    if not observed.get("caps:forceLevel2"):
        req += ["grant:oplock:OpExclusive", "grant:oplock:OpBatch",
                "grant:lease:rwh", "grant:lease:rh"]
        # A CREATE that had to park behind an ack-required break, and one that
        # did not: without both, the async-interim path is untested in one
        # direction.
        req += ["park:0", "park:1"]
        req += ["break:ack:1", "break:new:0x01", "break:new:0x03"]
        # Acknowledgment outcomes, including the three rejections.  A break
        # that needs no ack is never acknowledged, so with caching capped there
        # is nothing here to exercise.
        req += ["ack:0x%08x" % s for s in ACK_STATUSES]
    else:
        req += ["park:0"]
    # Break notifications: both wire shapes, the no-ack requirement, and the
    # NONE rung -- all reachable however the grant is capped.
    req += ["break:oplock", "break:lease", "break:ack:0", "break:new:0x00"]
    req += ["break:epoch_bump"]
    return req


def main():
    args = sys.argv[1:]
    if not args:
        sys.stderr.write("usage: coverage.py <trace.itf.json>... | "
                         "<trace-dir>\n")
        return 2
    if len(args) == 1 and os.path.isdir(args[0]):
        traces = sorted(glob.glob(os.path.join(args[0], "*.itf.json")))
    else:
        traces = sorted(args)
    if not traces:
        sys.stderr.write("no traces found in %s\n" % " ".join(args))
        return 2
    for t in traces:
        if not os.path.isfile(t):
            sys.stderr.write("missing trace %s\n" % t)
            return 2

    groups = collections.OrderedDict()
    for t in traces:
        m = NAME_RE.match(os.path.basename(t))
        if not m:
            sys.stderr.write("trace name not <inst>_<flavor>_...: %s\n" % t)
            return 2
        groups.setdefault("%s/%s" % (m.group("inst"), m.group("flavor")),
                          []).append(t)

    rc = 0
    for gname, gtraces in groups.items():
        buckets = {}
        for t in gtraces:
            scan(t, buckets)
        required = required_buckets(gname.split("/", 1)[1], buckets)
        missing = [b for b in required if b not in buckets]
        print("SMB2 MBT coverage for %s over %d trace(s):"
              % (gname, len(gtraces)))
        for b in required:
            print("  %-28s %s" % (b, "HIT" if b in buckets else "MISSING"))
        extra = sorted(b for b in buckets if b not in required)
        if extra:
            print("  (also observed: %s)" % ", ".join(extra))
        if missing:
            sys.stderr.write("coverage gate: %s: %d bucket(s) never "
                             "exercised: %s\n"
                             % (gname, len(missing), ", ".join(missing)))
            rc = 1
        else:
            print("  all %d coverage buckets exercised" % len(required))
    return rc


if __name__ == "__main__":
    sys.exit(main())
