# SPDX-FileCopyrightText: 2026 The Quint Specs Authors
#
# SPDX-License-Identifier: MIT

"""The deviation registry contract for the NFS conformance harness.

The models in quint/nfs encode RFC 1813 / 7530 / 8881 / 7862 / 8276, not any
one server.  When the corpus is replayed against a server, a disagreement is
one of three things:

  1. a MODEL bug -- the standard says what the server does, and the model is
     wrong.  Fix the model; nothing belongs in a registry.
  2. a SERVER deviation -- the server knowingly or unknowingly does something
     the standard does not describe.  Record it, with a citation, so the
     suite keeps running and the divergence stays enumerable.
  3. an unanalyzed difference -- neither of the above yet.  It must fail.

A per-server registry module (ganesha_deviations.py, knfsd_deviations.py)
is what separates (2) from (3): a Finding that matches one of its entries
is reported as a DEVIATION and does not fail the run; anything else is a
MISMATCH and does.  This is the same contract the Samba harness uses
(harness/samba/samba_deviations.py) and the consuming project's own
registries use: never used to hide an unanalyzed failure, always carrying a
citation and a root cause.

Reconcilability
---------------
Only status-and-observable deviations are reconcilable: the server's state
after the diverging reply still matches the model's, so replay continues in
sync.  A deviation that leaves the server holding different filesystem or
protocol state than the model believes would desync every later step; those
carry reconcilable=False, which reports the first occurrence and then
abandons the trace rather than emitting a cascade of follow-on noise.
"""

import dataclasses
from dataclasses import dataclass
from typing import Callable, Optional


# Who is wrong.  Analyzed and non-fatal either way, but the remedies are
# opposite, so the suite never conflates them.
SERVER = "server"  # the server diverges from the standard; the model is right
MODEL = "model"    # the model diverges from the standard; the server is right
                   # (recorded rather than silently patched: the corpus has
                   # other consumers, and a model change regenerates it)
BOTH = "both"      # both are wrong, differently, in the same reply


@dataclass(frozen=True)
class Finding:
    """One disagreement observed at replay time."""
    op: str                       # model result tag ("SOpen", "SLookup"...)
    kind: str                     # "status" or a field name ("nlink"...)
    expected: object
    actual: object
    detail: str = ""              # human-readable description

    def __str__(self):
        if self.kind == "status":
            return (f"{self.op}: status: expected {self.expected}, "
                    f"got {self.actual}" +
                    (f" ({self.detail})" if self.detail else ""))
        return (f"{self.op}.{self.kind}: expected {self.expected!r}, "
                f"got {self.actual!r}" +
                (f" ({self.detail})" if self.detail else ""))


@dataclass(frozen=True)
class Deviation:
    id: str
    verdict: str                  # SERVER / MODEL / BOTH
    spec: str                     # RFC citation
    summary: str
    root_cause: str               # server source location or behavior note
    candidate_fix: str
    # What it applies to: model result tags ("SOpen", "SLock", ...); empty
    # matches any op.
    ops: tuple = ()
    # Status divergence: None on either side means "any value".
    expected_status: Optional[object] = None
    actual_status: Optional[object] = None
    # Non-status divergence: the Finding.kind it applies to.  None means the
    # entry is about a status only.
    field: Optional[str] = None
    expected_value: object = None
    actual_value: object = None
    # Extra guard on (finding, ctx) -> bool.  `ctx` carries harness-side
    # facts the trace does not spell out (the request that produced the
    # result, the minor version, the current filehandle's model ino...).
    context: Callable = dataclasses.field(default=lambda f, ctx: True)
    # Whether replay can continue afterwards: a bool, or a callable
    # (finding, ctx) -> bool for a divergence that desyncs only sometimes.
    reconcilable: object = True

    def is_reconcilable(self, finding, ctx):
        if callable(self.reconcilable):
            try:
                return bool(self.reconcilable(finding, ctx))
            except Exception:
                return False
        return bool(self.reconcilable)

    def matches(self, finding, ctx):
        if self.ops and finding.op not in self.ops:
            return False
        if self.field is None:
            if finding.kind != "status":
                return False
            if self.expected_status is not None and \
                    not _match(self.expected_status, finding.expected):
                return False
            if self.actual_status is not None and \
                    not _match(self.actual_status, finding.actual):
                return False
        else:
            if not _match(self.field, finding.kind):
                return False
            if self.expected_value is not None and \
                    not _match(self.expected_value, finding.expected):
                return False
            if self.actual_value is not None and \
                    not _match(self.actual_value, finding.actual):
                return False
        try:
            return bool(self.context(finding, ctx))
        except Exception:
            return False


def _match(pattern, value):
    """A registry value may be a single value or a set/tuple of them."""
    if isinstance(pattern, (set, frozenset, tuple, list)):
        return value in pattern
    return pattern == value


class Registry:
    def __init__(self, name, entries):
        self.name = name
        self.entries = list(entries)
        ids = [e.id for e in self.entries]
        dup = {i for i in ids if ids.count(i) > 1}
        if dup:
            raise ValueError(f"{name}: duplicate deviation ids {sorted(dup)}")

    def lookup(self, finding, ctx):
        for e in self.entries:
            if e.matches(finding, ctx):
                return e
        return None

    def by_id(self, dev_id):
        for e in self.entries:
            if e.id == dev_id:
                return e
        return None


# NFSv4 status values referenced by registries (RFC 7530 / 8881 / 7862).
NFS4_OK = 0
NFS4ERR_PERM = 1
NFS4ERR_NOENT = 2
NFS4ERR_IO = 5
NFS4ERR_NXIO = 6
NFS4ERR_ACCESS = 13
NFS4ERR_EXIST = 17
NFS4ERR_XDEV = 18
NFS4ERR_NOTDIR = 20
NFS4ERR_ISDIR = 21
NFS4ERR_INVAL = 22
NFS4ERR_FBIG = 27
NFS4ERR_NOSPC = 28
NFS4ERR_ROFS = 30
NFS4ERR_MLINK = 31
NFS4ERR_NAMETOOLONG = 63
NFS4ERR_NOTEMPTY = 66
NFS4ERR_DQUOT = 69
NFS4ERR_STALE = 70
NFS4ERR_BADHANDLE = 10001
NFS4ERR_BAD_COOKIE = 10003
NFS4ERR_NOTSUPP = 10004
NFS4ERR_TOOSMALL = 10005
NFS4ERR_SERVERFAULT = 10006
NFS4ERR_BADTYPE = 10007
NFS4ERR_DELAY = 10008
NFS4ERR_SAME = 10009
NFS4ERR_DENIED = 10010
NFS4ERR_EXPIRED = 10011
NFS4ERR_LOCKED = 10012
NFS4ERR_GRACE = 10013
NFS4ERR_FHEXPIRED = 10014
NFS4ERR_SHARE_DENIED = 10015
NFS4ERR_WRONGSEC = 10016
NFS4ERR_CLID_INUSE = 10017
NFS4ERR_RESOURCE = 10018
NFS4ERR_MOVED = 10019
NFS4ERR_NOFILEHANDLE = 10020
NFS4ERR_MINOR_VERS_MISMATCH = 10021
NFS4ERR_STALE_CLIENTID = 10022
NFS4ERR_STALE_STATEID = 10023
NFS4ERR_OLD_STATEID = 10024
NFS4ERR_BAD_STATEID = 10025
NFS4ERR_BAD_SEQID = 10026
NFS4ERR_NOT_SAME = 10027
NFS4ERR_LOCK_RANGE = 10028
NFS4ERR_SYMLINK = 10029
NFS4ERR_RESTOREFH = 10030
NFS4ERR_LEASE_MOVED = 10031
NFS4ERR_ATTRNOTSUPP = 10032
NFS4ERR_NO_GRACE = 10033
NFS4ERR_RECLAIM_BAD = 10034
NFS4ERR_RECLAIM_CONFLICT = 10035
NFS4ERR_BADXDR = 10036
NFS4ERR_LOCKS_HELD = 10037
NFS4ERR_OPENMODE = 10038
NFS4ERR_BADOWNER = 10039
NFS4ERR_BADCHAR = 10040
NFS4ERR_BADNAME = 10041
NFS4ERR_BAD_RANGE = 10042
NFS4ERR_LOCK_NOTSUPP = 10043
NFS4ERR_OP_ILLEGAL = 10044
NFS4ERR_DEADLOCK = 10045
NFS4ERR_FILE_OPEN = 10046
NFS4ERR_ADMIN_REVOKED = 10047
NFS4ERR_CB_PATH_DOWN = 10048
NFS4ERR_BADIOMODE = 10049
NFS4ERR_BADLAYOUT = 10050
NFS4ERR_BAD_SESSION_DIGEST = 10051
NFS4ERR_BADSESSION = 10052
NFS4ERR_BADSLOT = 10053
NFS4ERR_COMPLETE_ALREADY = 10054
NFS4ERR_CONN_NOT_BOUND_TO_SESSION = 10055
NFS4ERR_DELEG_ALREADY_WANTED = 10056
NFS4ERR_BACK_CHAN_BUSY = 10057
NFS4ERR_LAYOUTTRYLATER = 10058
NFS4ERR_LAYOUTUNAVAILABLE = 10059
NFS4ERR_NOMATCHING_LAYOUT = 10060
NFS4ERR_RECALLCONFLICT = 10061
NFS4ERR_UNKNOWN_LAYOUTTYPE = 10062
NFS4ERR_SEQ_MISORDERED = 10063
NFS4ERR_SEQUENCE_POS = 10064
NFS4ERR_REQ_TOO_BIG = 10065
NFS4ERR_REP_TOO_BIG = 10066
NFS4ERR_REP_TOO_BIG_TO_CACHE = 10067
NFS4ERR_RETRY_UNCACHED_REP = 10068
NFS4ERR_UNSAFE_COMPOUND = 10069
NFS4ERR_TOO_MANY_OPS = 10070
NFS4ERR_OP_NOT_IN_SESSION = 10071
NFS4ERR_HASH_ALG_UNSUPP = 10072
NFS4ERR_CLIENTID_BUSY = 10074
NFS4ERR_PNFS_IO_HOLE = 10075
NFS4ERR_SEQ_FALSE_RETRY = 10076
NFS4ERR_BAD_HIGH_SLOT = 10077
NFS4ERR_DEADSESSION = 10078
NFS4ERR_ENCR_ALG_UNSUPP = 10079
NFS4ERR_PNFS_NO_LAYOUT = 10080
NFS4ERR_NOT_ONLY_OP = 10081
NFS4ERR_WRONG_CRED = 10082
NFS4ERR_WRONG_TYPE = 10083
NFS4ERR_DIRDELEG_UNAVAIL = 10084
NFS4ERR_REJECT_DELEG = 10085
NFS4ERR_RETURNCONFLICT = 10086
NFS4ERR_DELEG_REVOKED = 10087
NFS4ERR_PARTNER_NOTSUPP = 10088
NFS4ERR_PARTNER_NO_AUTH = 10089
NFS4ERR_UNION_NOTSUPP = 10090
NFS4ERR_OFFLOAD_DENIED = 10091
NFS4ERR_WRONG_LFS = 10092
NFS4ERR_BADLABEL = 10093
NFS4ERR_OFFLOAD_NO_REQS = 10094
NFS4ERR_NOXATTR = 10095
NFS4ERR_XATTR2BIG = 10096

# nfsstat3 (RFC 1813 2.6) -- the same numbers where they overlap.
NFS3_OK = 0
NFS3ERR_PERM = 1
NFS3ERR_NOENT = 2
NFS3ERR_IO = 5
NFS3ERR_NXIO = 6
NFS3ERR_ACCES = 13
NFS3ERR_EXIST = 17
NFS3ERR_XDEV = 18
NFS3ERR_NODEV = 19
NFS3ERR_NOTDIR = 20
NFS3ERR_ISDIR = 21
NFS3ERR_INVAL = 22
NFS3ERR_FBIG = 27
NFS3ERR_NOSPC = 28
NFS3ERR_ROFS = 30
NFS3ERR_MLINK = 31
NFS3ERR_NAMETOOLONG = 63
NFS3ERR_NOTEMPTY = 66
NFS3ERR_DQUOT = 69
NFS3ERR_STALE = 70
NFS3ERR_REMOTE = 71
NFS3ERR_BADHANDLE = 10001
NFS3ERR_NOT_SYNC = 10002
NFS3ERR_BAD_COOKIE = 10003
NFS3ERR_NOTSUPP = 10004
NFS3ERR_TOOSMALL = 10005
NFS3ERR_SERVERFAULT = 10006
NFS3ERR_BADTYPE = 10007
NFS3ERR_JUKEBOX = 10008
