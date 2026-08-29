# SPDX-FileCopyrightText: 2026 The Quint Specs Authors
#
# SPDX-License-Identifier: MIT

"""Registry of known Samba divergences from the SMB2 model.

The model in quint/smb2 encodes MS-SMB2 / MS-FSA, not any one server.  When
it is replayed against Samba, a disagreement is one of three things:

  1. a MODEL bug -- the spec says what Samba does, and the model is wrong.
     Fix the model; nothing belongs here.
  2. a Samba DEVIATION -- Samba knowingly or unknowingly does something the
     standard does not describe.  Record it here, with a citation, so the
     suite keeps running and the divergence stays enumerable.
  3. an unanalyzed difference -- neither of the above yet.  It must fail.

This file is what separates (2) from (3).  A divergence that matches an
entry here is reported as a DEVIATION and does not fail the run; anything
else is a MISMATCH and does.  That is deliberately the same contract the
POSIX suite uses (chimera's src/posix/tests/quint/posix_deviations.py), and
the same one the SMB ground-truth probes use with their DEVIATION() macro:
never used to hide an unanalyzed failure, always carrying a citation and a
root cause.

Reconcilability
---------------
Only *status-and-observable* deviations are reconcilable: ones where the
server's state after the diverging reply still matches the model's, so
replay can continue in sync.  A deviation that leaves Samba holding
different filesystem or handle state than the model believes would desync
every later command in the trace; those are recorded with
reconcilable=False, which reports the first occurrence and then abandons
the trace rather than emitting a cascade of meaningless follow-on failures.

Samba version
-------------
Deviations are recorded against the Samba in this repo's devcontainer
(.devcontainer/Dockerfile pins the Ubuntu release, which pins Samba).  The
harness prints the version it measured; if it moves, re-verify the entries.
"""

import dataclasses
from dataclasses import dataclass
from typing import Callable, Optional


# NTSTATUS values referenced below (MS-ERREF 2.3.1).
ST_SUCCESS = 0x00000000
ST_UNSUCCESSFUL = 0xC0000001
ST_NOT_IMPLEMENTED = 0xC0000002
ST_INVALID_PARAMETER = 0xC000000D
ST_INVALID_DEVICE_REQUEST = 0xC0000010
ST_END_OF_FILE = 0xC0000011
ST_ACCESS_DENIED = 0xC0000022
ST_OBJECT_NAME_NOT_FOUND = 0xC0000034
ST_OBJECT_NAME_COLLISION = 0xC0000035
ST_SHARING_VIOLATION = 0xC0000043
ST_FILE_LOCK_CONFLICT = 0xC0000054
ST_LOCK_NOT_GRANTED = 0xC0000055
ST_RANGE_NOT_LOCKED = 0xC000007E
ST_DELETE_PENDING = 0xC0000056
ST_DIRECTORY_NOT_EMPTY = 0xC0000101
ST_NOT_A_DIRECTORY = 0xC0000103
ST_FILE_IS_A_DIRECTORY = 0xC00000BA
ST_CANNOT_DELETE = 0xC0000121
ST_NOT_SUPPORTED = 0xC00000BB


# Who is wrong.  Both kinds are analyzed and non-fatal, but they mean opposite
# things and have opposite remedies, so the suite never conflates them.
SAMBA = "samba"    # Samba diverges from the standard; the model is right.
MODEL = "model"    # The model diverges from the standard; Samba is right.
                   # Recorded rather than silently patched: these models are a
                   # published corpus with other consumers, and changing one
                   # changes every trace generated from it.
BOTH = "both"      # Both are wrong, in different ways, in the same reply.


@dataclass(frozen=True)
class Deviation:
    id: str
    verdict: str              # SAMBA / MODEL / BOTH
    spec: str                 # MS-SMB2 / MS-FSA citation
    summary: str
    root_cause: str           # Samba source location or behavior note
    candidate_fix: str
    # What it applies to.  `ops` are model result tags ("RCreate", "RLock", ...).
    ops: tuple = ()
    # Status divergence: None on either side means "any value".
    expected_status: Optional[int] = None
    actual_status: Optional[int] = None
    # Non-status (observable) divergence, e.g. field="act" for CreateAction or
    # field="nlink".  None means this entry is about a status only.
    field: Optional[str] = None
    expected_value: object = None
    actual_value: object = None
    # Whether replay can continue afterwards.  A bool, or a callable
    # (cmd, res, ctx) -> bool for a divergence that desyncs only sometimes --
    # typically one where the server sometimes fails alongside the model (both
    # end up with no handle, still in step) and sometimes succeeds (the server
    # holds a handle the model does not know about).
    # Extra guard on (cmd_value, res_value, ctx) -> bool; default always-true.
    # `ctx` carries harness-side facts the trace does not spell out -- notably
    # `access`, the model DesiredAccess profile of the handle the command
    # targets, which is what most of these entries actually turn on.
    context: Callable = dataclasses.field(
        default=lambda cmd, res, ctx: True)
    reconcilable: object = True

    def is_reconcilable(self, cmd, res, ctx):
        if callable(self.reconcilable):
            try:
                return bool(self.reconcilable(cmd, res, ctx))
            except Exception:
                return False
        return bool(self.reconcilable)

    def matches(self, op, exp_status, act_status, fieldname,
                exp_value, act_value, cmd, res, ctx):
        if self.ops and op not in self.ops:
            return False
        if self.field != fieldname:
            return False
        if self.field is None:
            if self.expected_status is not None and \
                    self.expected_status != exp_status:
                return False
            if self.actual_status is not None and \
                    self.actual_status != act_status:
                return False
        else:
            if self.expected_value is not None and \
                    self.expected_value != exp_value:
                return False
            if self.actual_value is not None and \
                    self.actual_value != act_value:
                return False
        try:
            return bool(self.context(cmd, res, ctx))
        except Exception:
            return False


# ---------------------------------------------------------------------------
# The registry.
#
# Every entry is one enumerable line item: what the standard mandates, what
# Samba does instead, where it comes from, and what would retire the entry.
# An entry whose behavior Samba later fixes simply stops matching -- the model
# already encodes the standard, so the suite goes green with no edit here.
# ---------------------------------------------------------------------------

KNOWN_DEVIATIONS = [

    Deviation(
        id="SD-2",
        verdict=SAMBA,
        spec="MS-SMB2 3.3.5.14 (Receiving an SMB2 LOCK Request)",
        summary="a LOCK on a handle holding neither FILE_READ_DATA nor "
                "FILE_WRITE_DATA is refused with STATUS_INVALID_HANDLE rather "
                "than STATUS_ACCESS_DENIED",
        root_cause="measured directly: a DELETE-only and an attribute-only "
                   "handle both answer 0xC0000008, while read-only and "
                   "write-only handles lock successfully.  So Samba does make "
                   "the access check the spec calls for -- it just reports the "
                   "wrong status for it.  (This entry began as a `both`: the "
                   "model performed no access check at all and granted the "
                   "lock.  That half is fixed, leaving only Samba's status.)",
        candidate_fix="samba: return STATUS_ACCESS_DENIED from the LOCK "
                      "GrantedAccess check",
        ops=("RLock",),
        expected_status=ST_ACCESS_DENIED,
        actual_status=0xC0000008,
        # Both sides refuse and neither takes a lock, so replay stays in sync.
        reconcilable=True,
    ),

    Deviation(
        id="SD-4",
        verdict=SAMBA,
        spec="MS-FSA 2.1.5.14.11 (Set FileRenameInformation)",
        summary="Samba checks the destination for a collision before it "
                "checks that the handle holds DELETE access, so a rename that "
                "fails both ways reports the collision instead of the access "
                "failure",
        root_cause="measured directly: with a handle opened without DELETE, a "
                   "rename onto a FREE name answers STATUS_ACCESS_DENIED, "
                   "while a rename onto an EXISTING name answers "
                   "STATUS_OBJECT_NAME_COLLISION -- so the target lookup runs "
                   "first. The spec's algorithm makes the DELETE-access check "
                   "an early precondition, which is the order the model "
                   "encodes.",
        candidate_fix="samba: hoist the GrantedAccess DELETE check above the "
                      "destination lookup in the rename path",
        ops=("RSetRename",),
        expected_status=ST_ACCESS_DENIED,
        actual_status=ST_OBJECT_NAME_COLLISION,
        # Neither side renames anything, so the namespace stays in step.
        reconcilable=True,
    ),

    Deviation(
        id="SD-5",
        verdict=SAMBA,
        spec="MS-FSA 2.1.5.1.2 (Open of Existing File), disposition ordering",
        summary="FILE_CREATE onto an existing DIRECTORY opened with "
                "FILE_NON_DIRECTORY_FILE reports STATUS_FILE_IS_A_DIRECTORY "
                "instead of STATUS_OBJECT_NAME_COLLISION",
        root_cause="Samba runs the create-options TYPE check ahead of the "
                   "FILE_CREATE collision check, but only in one direction. "
                   "Measured on all four corners: existing directory + "
                   "NON_DIRECTORY_FILE answers 0xC00000BA, while existing "
                   "FILE + DIRECTORY_FILE answers 0xC0000035 (collision), not "
                   "STATUS_NOT_A_DIRECTORY -- so the ordering is asymmetric. "
                   "The spec makes the FILE_CREATE collision the first thing "
                   "the existing-target path decides, before the type is "
                   "consulted at all, which is the order the model encodes.",
        candidate_fix="samba: decide the FILE_CREATE collision before the "
                      "create-options type check, so both directions agree",
        ops=("RCreate",),
        expected_status=ST_OBJECT_NAME_COLLISION,
        actual_status=ST_FILE_IS_A_DIRECTORY,
        context=lambda cmd, res, ctx: (cmd["disp"]["tag"] == "DispCreate"
                                       and not cmd["isDir"]),
        # Both sides refuse and neither creates anything, so the namespace
        # stays in step.
        reconcilable=True,
    ),

    Deviation(
        id="SD-8",
        verdict=SAMBA,
        spec="MS-SMB2 3.3.5.14 (Receiving an SMB2 LOCK Request); MS-FSA "
             "2.1.5.1.2 on the transience of a truncate's write",
        summary="a handle whose CREATE actually created or overwrote the file "
                "may take byte-range locks even when its DesiredAccess "
                "carried no data access -- the write the server took to do "
                "that is treated as if the handle kept it",
        root_cause="the CreateAction decides it exactly.  Holding "
                   "DesiredAccess fixed at DELETE-only and varying only "
                   "whether the file already existed: act=OPENED refuses LOCK "
                   "with 0xC0000008, while act=CREATED (FILE_CREATE, or "
                   "FILE_OPEN_IF on a missing name) and act=OVERWRITTEN both "
                   "GRANT it.  Samba opens the backing descriptor for write "
                   "when it has to create or truncate, and its lock path "
                   "consults that descriptor rather than the SMB "
                   "GrantedAccess.  Samba itself does not treat the write as "
                   "retained for SHARE purposes -- the same handle denies a "
                   "later writer nothing -- so its two checks disagree with "
                   "each other, which is what makes this a bug rather than an "
                   "interpretation.",
        candidate_fix="samba: check the SMB GrantedAccess in the LOCK path, "
                      "not the descriptor's open mode",
        ops=("RLock",),
        expected_status=ST_ACCESS_DENIED,
        # CreateAction: SUPERSEDED=0, OPENED=1, CREATED=2, OVERWRITTEN=3.
        # Everything except OPENED means the server wrote to the object to
        # bring it into that state.
        context=lambda cmd, res, ctx: (ctx.get("access") is not None
                                       and not ctx["access"].get("r")
                                       and not ctx["access"].get("w")
                                       and ctx.get("create_action") is not None
                                       and ctx["create_action"] != 1),
        # Reconcilable only when the server ALSO declined to change anything.
        # A granted lock the model does not know about desyncs every later
        # read and write over that range; a RANGE_NOT_LOCKED on an unlock
        # changes nothing on either side.
        reconcilable=lambda cmd, res, ctx: ctx.get("wire_status") != 0,
    ),

    Deviation(
        id="SD-9",
        verdict=SAMBA,
        spec="MS-SMB2 3.3.5.14 (Receiving an SMB2 LOCK Request)",
        summary="the GrantedAccess check is applied to a lock request but not "
                "to an unlock request, so an unlock on a handle with no data "
                "access is processed and answers STATUS_RANGE_NOT_LOCKED",
        root_cause="measured on one handle: DELETE-only and attribute-only "
                   "handles, act=OPENED, refuse LOCK with 0xC0000008 and then "
                   "accept the matching UNLOCK, answering 0xC000007E.  The "
                   "spec conditions the whole request on the access check, not "
                   "just its locking half.  Distinct from SD-2 (which is about "
                   "the STATUS the check reports) and SD-8 (which is about "
                   "WHAT it consults): here the check does not run at all.",
        candidate_fix="samba: apply the LOCK GrantedAccess check before "
                      "dispatching either half of the request",
        ops=("RLock",),
        expected_status=ST_ACCESS_DENIED,
        actual_status=ST_RANGE_NOT_LOCKED,
        context=lambda cmd, res, ctx: (bool(cmd.get("unlock"))
                                       and ctx.get("access") is not None
                                       and not ctx["access"].get("r")
                                       and not ctx["access"].get("w")),
        # Neither side unlocks anything, so replay stays in step.
        reconcilable=True,
    ),
]

# Retired -- the model was wrong and has been fixed, so these no longer occur.
# Kept as a record of what the exercise found, and of what would resurface if
# a fix were reverted:
#
#   SD-1 (model)  FLUSH succeeded on a handle with no write access.
#                 Fixed: quint/smb2/smb2_ops.qnt doCmdFlush now performs the
#                 MS-SMB2 3.3.5.13 GrantedAccess check.
#   SD-3 (model)  an attribute-only CREATE with a truncating disposition
#                 skipped share arbitration, discarding the write wantOf() had
#                 just added.  Fixed: the sharing check is now guarded on a
#                 true STAT open (attribute-only AND non-truncating), and the
#                 open asserts its ShareAccess at open time while retaining
#                 none of it afterwards (denyCheck vs deny).
#   SD-6 (model)  the lease-key-to-file binding was enforced on a profile whose
#                 server advertises no leasing.  Fixed: gated on caps.leases.
#   SD-7 (model)  a truncating CREATE refused with a sharing violation still
#                 truncated the file.  Fixed: the disposition's filesystem
#                 effect is committed on the success path only.  The oracle
#                 that found it (check_silent_truncate in smb2_replay.py) is
#                 still armed -- with no entry to excuse it, a recurrence is
#                 now a hard failure.


def find(op, exp_status, act_status, fieldname=None,
         exp_value=None, act_value=None, cmd=None, res=None, ctx=None):
    """Return the Deviation covering this divergence, or None."""
    for d in KNOWN_DEVIATIONS:
        if d.matches(op, exp_status, act_status, fieldname,
                     exp_value, act_value, cmd, res, ctx or {}):
            return d
    return None
