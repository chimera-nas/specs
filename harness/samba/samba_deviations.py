# SPDX-FileCopyrightText: 2026 The Quint Specs Authors
#
# SPDX-License-Identifier: MIT

"""What is left of the Samba divergence registry: CHANGE_NOTIFY, only.

A divergence between the model and a real smbd is one of three things:

  1. a MODEL bug -- the spec says what Samba does, and the model is wrong.
     Fix the model; nothing belongs here.
  2. a Samba DEVIATION -- Samba knowingly or unknowingly does something the
     standard does not describe.
  3. an unanalyzed difference -- neither of the above yet.  It must fail.

Case 2 no longer belongs here EITHER.  A deviation is now written into the
model as a branch guarded on the cell's config (quint/smb2/smb2_ops.qnt, and
`deviations` in configs/*.json), so the trace's expectation is already what
Samba does and replay is an exact match.  SD-2, SD-4, SD-5, SD-8 and SD-9
moved there; see quint/smb2/corpus.schema.json for each one's measurement and
citation, and tools/devliveness.py for the gate that stops one outliving its
fix.

Three entries could not follow them, and they are all CHANGE_NOTIFY:

  SD-10  Samba raises a different SET of change classes than MS-FSA.
  SD-11  the CompletionFilter of the FIRST request on a handle is binding.
  SD-12  an intra-directory rename also reports the old name as REMOVED.

What blocks all three is the same thing, and it is structural rather than a
matter of effort: Samba delivers ONE model-level mutation as SEVERAL
completions.  The model buffers events during a message and drains each watch
once at the end of it (smb2_state.qnt stFireNotifies), and a completion is
identified by (handle, queue position) -- so "the create woke the first waiter
with ADDED and the second with MODIFIED" has no representation, and neither
does SD-12's spurious REMOVED arriving as its own delivery.  SD-10's write and
create faces additionally turn on DOS-attribute state (the ARCHIVE bit Samba
stamps, which is what raises the notification at all) that the model does not
carry, so even the classes are not a function of anything the model knows.
Modelling them on a guess would make every stepNotify trace wrong; leaving
them here keeps them enumerable and keeps the flavour running as far as the
first of them.  That is why the stepNotifyNs flavour still exists.

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


FILE_ACTION_REMOVED = 0x00000002


def _extra_removes_consumed(model_recs, wire_recs):
    """How many of `model_recs` `wire_recs` accounts for, or None if it is not
    "the model's records with extra REMOVEDs mixed in" at all.

    Walks both in order: every wire record either matches the next model one
    or is a FILE_ACTION_REMOVED the model did not predict.  Anything else --
    a reordering, or an extra record of some other action -- returns None and
    the divergence fails as unanalyzed.  A record the model expected and the
    wire has not sent YET is not a failure here: Samba's spurious REMOVED can
    arrive as its own delivery, which splits the model's one delivery across
    two, and that case is separated out by reconcilability rather than by
    pretending it did not happen.
    """
    if model_recs is None or wire_recs is None:
        return None
    i = 0
    for got in wire_recs:
        if i < len(model_recs) and tuple(model_recs[i]) == tuple(got):
            i += 1
        elif got[0] == FILE_ACTION_REMOVED:
            continue
        else:
            return None
    return i


def _extra_removes_match(cmd, res, ctx):
    return _extra_removes_consumed(ctx.get("model_recs"),
                                   ctx.get("wire_recs")) is not None


def _extra_removes_in_step(cmd, res, ctx):
    """Reconcilable only when the whole predicted delivery arrived together.

    When it did, the extra REMOVED is pure addition: both sides drained the
    same changes in the same request and replay stays in step.  When Samba
    delivered the spurious record ALONE, the request the model answered here
    is answered there by the NEXT one -- the two sides are a delivery apart
    from then on, and everything after it would be reporting that.
    """
    model_recs = ctx.get("model_recs")
    got = _extra_removes_consumed(model_recs, ctx.get("wire_recs"))
    return got is not None and model_recs is not None and got == len(model_recs)


# The one NTSTATUS still referenced from here: smb2_replay.py's
# silent-truncate oracle asks whether a refused CREATE was refused for
# sharing (MS-ERREF 2.3.1).
ST_SHARING_VIOLATION = 0xC0000043


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
    # `ctx` carries harness-side facts the trace does not spell out.  The one
    # entry that still uses it is SD-12, which is handed the model's and the
    # wire's FILE_NOTIFY_INFORMATION record lists.
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

    # -- CHANGE_NOTIFY: the event vocabulary ------------------------------

    Deviation(
        id="SD-10",
        verdict=SAMBA,
        spec="MS-FSA 2.1.5.1.2 / 2.1.5.3 / 2.1.5.4 (change notification)",
        summary="Samba raises a different SET of change classes than MS-FSA "
                "for writes, closes and creates, so the two sides end up "
                "holding different buffered events",
        root_cause="one finding wearing three faces, each measured directly "
                   "against this Samba with a FRESH connection and watch per "
                   "case so no leftover buffer can contaminate it:\n"
                   "  * a WRITE reaches a watcher filtered on `attributes` "
                   "and reaches NEITHER `size` nor `lastWrite` -- MS-FSA "
                   "2.1.5.3 makes a write a last-write and size change, which "
                   "are the two filters a client would actually use for it;\n"
                   "  * CLOSING a handle that wrote raises nothing at all, "
                   "where MS-FSA 2.1.5.4 reports the settled size and write "
                   "time -- so a watcher never learns the write finished;\n"
                   "  * CREATING a file raises FILE_ACTION_MODIFIED as well "
                   "as ADDED (measured with two waiters queued on one handle: "
                   "the first is answered ADDED, the second MODIFIED, from a "
                   "single FILE_CREATE).\n"
                   "The consequence, not the reply, is what makes this "
                   "non-reconcilable: from the first write or create onwards "
                   "the model and Samba hold different sets of buffered "
                   "events, so every later request on that handle diverges "
                   "for reasons that have nothing to do with the notify logic "
                   "under test.  The comparable subset -- namespace mutations "
                   "watched through the name filters, where the two agree "
                   "exactly -- is generated as its own flavor (stepNotifyNs) "
                   "and IS driven to completion here.",
        candidate_fix="samba: raise LAST_WRITE|SIZE from the write path and "
                      "at the cleanup of a modified handle, and suppress the "
                      "metadata-settle notification that follows a create it "
                      "has already reported as ADDED",
        ops=("RNotify", "RNotifyAsync"),
        reconcilable=False,
    ),

    Deviation(
        id="SD-12",
        verdict=SAMBA,
        spec="MS-FSCC 2.7.1 (FILE_NOTIFY_INFORMATION), FILE_ACTION_RENAMED_*",
        summary="a rename within a directory also reports the old name as "
                "FILE_ACTION_REMOVED, on top of the RENAMED_OLD_NAME / "
                "RENAMED_NEW_NAME pair",
        root_cause="measured: a run of renames delivers, for each one, an "
                   "extra FILE_ACTION_REMOVED naming the name the object was "
                   "renamed AWAY from, in addition to the pair.  The pair "
                   "already says the name went away and where it went; the "
                   "extra record says it was deleted, which is a different "
                   "and untrue statement -- a client that acts on REMOVED "
                   "drops the file it should have followed.",
        candidate_fix="samba: emit only the RENAMED_OLD_NAME/_NEW_NAME pair "
                      "for an intra-directory rename",
        ops=("RNotify", "RNotifyAsync"),
        field="recs",
        # Precise, not a blanket record excuse: the model's records must be a
        # SUBSEQUENCE of the wire's, and every extra wire record must be a
        # FILE_ACTION_REMOVED.  A missing record, a reordered one, or an extra
        # record of any other action still fails.
        context=_extra_removes_match,
        reconcilable=_extra_removes_in_step,
    ),

    Deviation(
        id="SD-11",
        verdict=SAMBA,
        spec="MS-SMB2 2.2.35 (SMB2 CHANGE_NOTIFY Request), CompletionFilter",
        summary="the CompletionFilter of the FIRST CHANGE_NOTIFY on a handle "
                "is binding: a later request on that handle cannot widen or "
                "change it",
        root_cause="measured four ways on one handle.  arm(dirName), cancel, "
                   "arm(fileName), create a file -> nothing is ever "
                   "delivered; the same handle armed with fileName FROM THE "
                   "START gets the record, and arm(fileName)/cancel/"
                   "arm(fileName) also gets it -- so it is the CHANGE of "
                   "filter that is ignored, not the re-arm.  Queueing a "
                   "second request with a different filter behind the first "
                   "does not help either: neither waiter sees the create.  "
                   "CompletionFilter is a per-REQUEST field (2.2.35) and "
                   "MS-FSA 2.1.5.9 records it per pending request; nothing "
                   "makes the first one binding for the life of the handle.  "
                   "A client that narrows its watch and later widens it again "
                   "is therefore watching nothing, with no error to say so.",
        candidate_fix="samba: re-register the fsp's notify filter from the "
                      "current request rather than keeping the one the first "
                      "request installed",
        ops=("RNotify", "RNotifyAsync"),
        reconcilable=False,
    ),
]

# MIGRATED -- these are Samba divergences that the MODEL now predicts, gated on
# the cell's config.  They are gone from here because they are enumerated
# somewhere better: quint/smb2/corpus.schema.json carries each one's
# measurement and citation, configs/*.json say which cells claim it, and
# tools/devliveness.py fails a cell that claims one its corpus never reaches.
#
#   SD-2 (samba)  LOCK on a handle with no data access answers
#                 STATUS_INVALID_HANDLE, not STATUS_ACCESS_DENIED.
#   SD-4 (samba)  rename checks the destination before the handle's DELETE
#                 access, so a rename that fails both ways reports the
#                 collision.
#   SD-5 (samba)  FILE_CREATE onto an existing DIRECTORY opened
#                 FILE_NON_DIRECTORY_FILE answers STATUS_FILE_IS_A_DIRECTORY.
#   SD-8 (samba)  a handle whose CreateAction is not OPENED may lock without
#                 data access -- and the lock it takes is now a lock the model
#                 takes too, so the rest of the trace keeps testing instead of
#                 being abandoned.
#   SD-9 (samba)  the access check is not applied to an UNLOCK at all.
#
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
