# SPDX-FileCopyrightText: 2026 The Quint Specs Authors
#
# SPDX-License-Identifier: MIT

"""The deviation registry contract for the POSIX conformance harness.

`quint/posix` encodes POSIX.1-2024 plus the profile knobs the standard
explicitly leaves to the implementation -- not any one filesystem.  When the
corpus is replayed against a real one, a disagreement is one of three
things:

  1. a MODEL bug -- POSIX says what the filesystem does, and the model is
     wrong.  Fix the model; nothing belongs in a registry.
  2. a FILESYSTEM deviation -- the implementation does something POSIX does
     not describe.  Record it, with a citation, so the suite keeps running
     and the divergence stays enumerable.
  3. an unanalyzed difference -- neither of the above yet.  It must fail.

A per-target registry module (ext4_deviations.py) is what separates (2) from
(3): a Finding that matches one of its entries is reported as a DEVIATION and
does not fail the run; anything else is a MISMATCH and does.  Same contract
as harness/nfs and harness/samba: never used to hide an unanalyzed failure,
always carrying a citation and a root cause.

Reconcilability
---------------
Only status-and-observable deviations are reconcilable: the filesystem's
state after the diverging call still matches the model's, so replay
continues in sync.  A deviation that leaves the filesystem holding different
state than the model believes would desync every later step; those carry
reconcilable=False, which reports the first occurrence and then abandons the
trace rather than emitting a cascade of follow-on noise.
"""

import dataclasses
from dataclasses import dataclass
from typing import Callable, Optional


# Who is wrong.  Analyzed and non-fatal either way, but the remedies are
# opposite, so the suite never conflates them.
SERVER = "server"  # the filesystem diverges from POSIX; the model is right
MODEL = "model"    # the model diverges from POSIX; the filesystem is right
                   # (recorded rather than silently patched: the corpus has
                   # other consumers, and a model change regenerates it)
BOTH = "both"      # both are wrong, differently, in the same result


@dataclass(frozen=True)
class Finding:
    """One disagreement observed at replay time."""
    op: str                       # model request tag ("ROpen", "RRename"...)
    kind: str                     # "status" or a field name ("nlink"...)
    expected: object
    actual: object
    detail: str = ""

    def __str__(self):
        if self.kind == "status":
            return (f"{self.op}: errno: expected {self.expected}, "
                    f"got {self.actual}" +
                    (f" ({self.detail})" if self.detail else ""))
        return (f"{self.op}.{self.kind}: expected {self.expected!r}, "
                f"got {self.actual!r}" +
                (f" ({self.detail})" if self.detail else ""))


@dataclass(frozen=True)
class Deviation:
    id: str
    verdict: str                  # SERVER / MODEL / BOTH
    spec: str                     # POSIX / man-page citation
    summary: str
    root_cause: str
    candidate_fix: str
    # Model request tags it applies to; empty matches any op.
    ops: tuple = ()
    # Status divergence: None on either side means "any value".
    expected_status: Optional[object] = None
    actual_status: Optional[object] = None
    # Non-status divergence: the Finding.kind it applies to.  None means the
    # entry is about an errno only.
    field: Optional[str] = None
    expected_value: object = None
    actual_value: object = None
    # Extra guard on (finding, ctx) -> bool.  `ctx` carries harness-side
    # facts the trace does not spell out (the request that produced the
    # result, the drawn profile, the model's pre-state...).
    context: Callable = dataclasses.field(default=lambda f, ctx: True)
    # Whether replay can continue afterwards: a bool, or a callable
    # (finding, ctx) -> bool for a divergence that desyncs only sometimes.
    reconcilable: object = True

    def is_reconcilable(self, finding, ctx):
        if callable(self.reconcilable):
            try:
                return bool(self.reconcilable(finding, ctx))
            except Exception:                        # noqa: BLE001
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
        except Exception:                            # noqa: BLE001
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


# Errno values the registries cite (Linux numbering, as the model uses).
OK = 0
EPERM = 1
ENOENT = 2
EIO = 5
ENXIO = 6
EBADF = 9
EAGAIN = 11
EACCES = 13
EBUSY = 16
EEXIST = 17
EXDEV = 18
ENODEV = 19
ENOTDIR = 20
EISDIR = 21
EINVAL = 22
EMFILE = 24
EFBIG = 27
ENOSPC = 28
ESPIPE = 29
EROFS = 30
EMLINK = 31
EDEADLK = 35
ENAMETOOLONG = 36
ENOSYS = 38
ENOTEMPTY = 39
ELOOP = 40
EOPNOTSUPP = 95
