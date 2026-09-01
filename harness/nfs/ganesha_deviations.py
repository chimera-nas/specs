# SPDX-FileCopyrightText: 2026 The Quint Specs Authors
#
# SPDX-License-Identifier: MIT

"""Registry of known NFS-Ganesha divergences from the NFS models.

Retired (the model was corrected to the standard, so ganesha no longer
diverges): the ACCESS type-masking (was GD-2/GN-1) and READLINK-on-a-directory
returning INVAL (was GD-3) -- the models now predict exactly what ganesha,
the Linux server and the RFCs all produce.

See deviations.py for the contract.  Entries are recorded against the
Ganesha in this repo's devcontainer (.devcontainer/Dockerfile pins the
Ubuntu release, which pins Ganesha); the harness prints the version it
measured, and if it moves the entries should be re-verified.

Each entry has three parts a reader needs: the verdict (who is wrong), the
citation (which clause decides it), and what would retire the entry.
"""

from deviations import (Deviation, Registry, SERVER, MODEL, BOTH,  # noqa: F401
                        NFS4_OK, NFS3_OK)
from deviations import *  # noqa: F401,F403  -- the status constants


# GD-1: the change attribute is the object's ctime.  FSAL_VFS derives
# `change` (and therefore change_info4's before/after) from st_ctime in
# nanoseconds.  ctime moves at the kernel's coarse clock tick (a few
# milliseconds on a kernel without multigrain timestamps), so two mutations
# of one directory inside a tick report the same value, and the model's
# consistency check -- distinct abstract change values must observe distinct
# wire values -- fires.  RFC 7530 5.8.1.4 / RFC 8881 5.8.1.4 require the
# value to change on every modification.  Timing-dependent, so it is
# recorded for whenever it fires; state stays in sync (the mutation itself
# happened), so replay continues.
GD_1_CHANGE_GRANULARITY = Deviation(
    id="GD-1-change-is-coarse-ctime",
    verdict=SERVER,
    spec="RFC 7530 5.8.1.4 / RFC 8881 5.8.1.4 (change): must differ after "
         "any modification",
    summary="two mutations within one clock tick report the same change "
            "value (FSAL_VFS change = ctime in ns)",
    root_cause="FSAL_VFS attrs: change = timespec_to_nsecs(ctime); ctime "
               "granularity is the kernel's coarse clock",
    candidate_fix="a per-object modification counter, or multigrain "
                  "timestamps (Linux >= 6.13 with an FS_MGTIME filesystem)",
    ops=("SCreate", "SRemove", "SRename", "SLink", "SOpen", "SSetxattr",
         "SRemovexattr", "SGetattr"),
    field=("cinfo.after", "cinfo.before", "cinfoS.after", "cinfoS.before",
           "cinfoT.after", "cinfoT.before", "change"),
    context=lambda f, ctx: "unchanged on the wire" in f.detail,
)



# GD-4: the wide VERIFY / NVERIFY assert an implementation-specific status.
# opVerifyWide sends the server's whole supported-attribute bitmap with an
# EMPTY value blob to drive the attribute marshaller without predicting a
# single value, and then relies on the reference implementation's length
# guard (out_len == attr_vals.len is false) to decide the comparison "not
# equal" -- so it predicts NFS4ERR_NOT_SAME for VERIFY and NFS4_OK for
# NVERIFY.  Ganesha reads the empty value blob as "no attributes to compare",
# which trivially matches, so it answers the opposite: NFS4_OK for VERIFY and
# NFS4ERR_SAME for NVERIFY.  Both are defensible readings of a deliberately
# under-specified request (RFC 7530 16.15 / RFC 8881 18.31 do not say what an
# attrmask with fewer values than bits means), so the model is the one to
# change -- send a well-formed value blob, or stop asserting the status of
# the wide variant and only exercise the marshaller.  Recorded as MODEL,
# reconcilable (VERIFY/NVERIFY change no state), pending that coordinated fix.
GD_4_VERIFY_WIDE_EMPTY = Deviation(
    id="GD-4-verify-wide-empty-blob",
    verdict=MODEL,
    spec="RFC 7530 16.15 / RFC 8881 18.31 (VERIFY/NVERIFY; an attrmask with "
         "fewer values than bits is unspecified)",
    summary="the wide VERIFY/NVERIFY predict NOT_SAME/OK from an empty value "
            "blob; ganesha reads the empty blob as a trivial match (OK/SAME)",
    root_cause="opVerifyWide encodes the reference server's length-guard "
               "behaviour for an empty value blob",
    candidate_fix="model: send a well-formed value blob for the wide "
                  "VERIFY/NVERIFY, or drop the status assertion and keep only "
                  "the marshaller exercise",
    ops=("SVerify", "SNverify"),
)

# GD-5: OPEN of an existing non-regular, non-symlink target (a FIFO, socket
# or device node) answers NFS4ERR_SYMLINK instead of NFS4ERR_WRONG_TYPE.
# RFC 8881 18.16.4 gives NFS4ERR_SYMLINK its specific meaning -- the target is
# a symbolic link -- and NFS4ERR_WRONG_TYPE for any other type mismatch, which
# is what the model predicts on 4.1+.  Ganesha returns the older RFC 7530
# generic NFS4ERR_SYMLINK for every non-directory special file, a FIFO
# included.  Status-only, so replay continues.
GD_5_OPEN_SPECIAL_SYMLINK = Deviation(
    id="GD-5-open-special-as-symlink",
    verdict=SERVER,
    spec="RFC 8881 18.16.4 (a non-symlink type mismatch is NFS4ERR_WRONG_TYPE; "
         "NFS4ERR_SYMLINK is specifically for a symbolic link)",
    summary="OPEN of a FIFO/socket/device target returns NFS4ERR_SYMLINK "
            "instead of NFS4ERR_WRONG_TYPE",
    root_cause="ganesha uses the RFC 7530 generic SYMLINK for every "
               "non-directory special open target",
    candidate_fix="none required (RFC 8881's WRONG_TYPE is a SHOULD)",
    ops=("SOpen",),
    expected_status=NFS4ERR_WRONG_TYPE,
    actual_status=NFS4ERR_SYMLINK,
)

# GD-6: component-name handling.  RFC 7530 12.7 / RFC 8881 12.6 make UTF-8
# validation a server SHOULD, not a MUST, and 12.8 lets a server pick among
# NFS4ERR_INVAL / NFS4ERR_BADCHAR / NFS4ERR_BADNAME for a name it does reject.
# The model follows the SHOULD and rejects malformed-UTF-8 components
# (overlong encodings, lead bytes > 0xF4, a valid prefix followed by a
# surrogate or a truncated sequence); ganesha does not reject all of them
# even with Enforce_UTF8_Validation, so a name the model calls INVAL/BADCHAR/
# BADNAME either resolves as an ordinary component (NOENT, or OK/EXIST when it
# names something) or is rejected under a different one of the three codes.
# Recorded across the name-bearing operations.  Reconcilable: a rejected name
# changes nothing, and a leniently-accepted one is only ever referenced again
# by the same name, which this entry also covers.
GD_6_NAME_HANDLING = Deviation(
    id="GD-6-name-handling",
    verdict=SERVER,
    spec="RFC 7530 12.7 / RFC 8881 12.6 (UTF-8 validation is a SHOULD) and "
         "12.8 (INVAL/BADCHAR/BADNAME are the server's choice)",
    summary="a malformed-UTF-8 component the model rejects is resolved as an "
            "ordinary name, or rejected under a different name-error code",
    root_cause="ganesha does not enforce the model's strict UTF-8 component "
               "validation and picks its own name-error code",
    candidate_fix="none required (both are conformant); the model could relax "
                  "to accept a status set for these names",
    ops=("SLookup", "SOpen", "SCreate", "SRemove", "SRename", "SLink",
         "SSecinfo"),
    expected_status=(NFS4ERR_INVAL, NFS4ERR_BADCHAR, NFS4ERR_BADNAME),
    actual_status=(NFS4ERR_INVAL, NFS4ERR_BADCHAR, NFS4ERR_BADNAME,
                   NFS4ERR_NOENT, NFS4_OK, NFS4ERR_EXIST),
)

# GD-7: a SETATTR that changes size through the anonymous stateid, on a file
# another owner holds open with a deny-write share reservation, answers
# NFS4ERR_SHARE_DENIED instead of NFS4ERR_LOCKED.  RFC 8881 9.1.4.3 makes the
# anonymous/special stateid usable for I/O and size changes only when no
# conflicting OPEN exists; a conflict is reported as NFS4ERR_LOCKED (RFC 8881
# 18.30, SETATTR).  NFS4ERR_SHARE_DENIED is defined for a conflicting OPEN,
# not for a special-stateid size change, so the model's LOCKED is the RFC's
# answer.  Ganesha reuses the share-reservation error.  Both leave the object
# unchanged, so replay continues.
GD_7_SETATTR_SHARE_DENIED = Deviation(
    id="GD-7-setattr-share-denied",
    verdict=SERVER,
    spec="RFC 8881 9.1.4.3 (special stateid vs a conflicting OPEN) / 18.30 "
         "(SETATTR): the conflict is NFS4ERR_LOCKED",
    summary="a size SETATTR / ALLOCATE / DEALLOCATE through the anonymous "
            "stateid against a deny-write share reservation returns "
            "SHARE_DENIED instead of LOCKED",
    root_cause="ganesha reports the share-reservation conflict with "
               "NFS4ERR_SHARE_DENIED rather than the size op's NFS4ERR_LOCKED",
    candidate_fix="ganesha: return NFS4ERR_LOCKED for a special-stateid size "
                  "change that hits a share reservation",
    ops=("SSetattr", "SAllocate", "SDeallocate"),
    expected_status=NFS4ERR_LOCKED,
    actual_status=NFS4ERR_SHARE_DENIED,
)


# GD-9: LINK whose saved (source) filehandle is a directory answers
# NFS4ERR_NOTDIR, not the NFS4ERR_ISDIR the model predicts.  Hard-linking a
# directory is refused by every server; RFC 7530 16.9.4 lists NFS4ERR_ISDIR
# for LINK and the model (and its self-test) pick it, but both real servers
# report NOTDIR -- a not-a-directory framing of the same refusal.  Recorded
# against the model's pick; a candidate for switching the model to NOTDIR
# since knfsd and ganesha agree.  Nothing is linked, so replay continues.
GD_9_LINK_DIR_NOTDIR = Deviation(
    id="GD-9-link-dir-notdir",
    verdict=SERVER,
    spec="RFC 7530 16.9.4 (LINK; ISDIR is listed, but the directory-source "
         "status is effectively unspecified and servers differ)",
    summary="LINK of a directory source: the name-vs-source-type precedence "
            "and the source-type code (ISDIR/NOTDIR) both differ from the model",
    root_cause="ganesha's LINK precedence is inconsistent across cases -- it "
               "answers the name error or the source NOTDIR in an order the "
               "model, which validates the name then reports ISDIR, cannot match",
    candidate_fix="switch the model (and nfs4Test) to NOTDIR -- both servers "
                  "agree on it -- or keep ISDIR and this record",
    ops=("SLink",),
    expected_status=(NFS4ERR_ISDIR, NFS4ERR_INVAL, NFS4ERR_BADNAME,
                     NFS4ERR_BADCHAR),
    actual_status=(NFS4ERR_NOTDIR, NFS4ERR_ISDIR, NFS4ERR_INVAL,
                   NFS4ERR_BADNAME, NFS4ERR_BADCHAR),
)

# GD-10: RENEW of a lease that has lapsed answers NFS4ERR_EXPIRED where the
# model predicts NFS4ERR_STALE_CLIENTID.  The model drops a client id the
# moment a superseding SETCLIENTID retires its incarnation, so RENEW of the
# retired id is STALE_CLIENTID; ganesha keeps the id past the lease and
# reports the lease itself as EXPIRED (RFC 7530 16.30.4 lists both, and
# 9.6.3 leaves how long an expired-lease client id survives to the server).
# Timing-adjacent, like GD-1: recorded whenever it fires; the client
# re-establishes state either way, so replay continues.
GD_10_RENEW_EXPIRED = Deviation(
    id="GD-10-renew-expired",
    verdict=SERVER,
    spec="RFC 7530 16.30.4 / 9.6.3 (RENEW; EXPIRED vs STALE_CLIENTID for a "
         "lapsed lease is the server's to time)",
    summary="RENEW of a lapsed lease returns NFS4ERR_EXPIRED where the model "
            "predicts NFS4ERR_STALE_CLIENTID",
    root_cause="ganesha retains the client id past the lease and reports "
               "EXPIRED; the model retires it and reports STALE_CLIENTID",
    candidate_fix="none required (defensible); the model could retain a "
                  "lapsed client id briefly to match",
    ops=("SRenew",),
    expected_status=NFS4ERR_STALE_CLIENTID,
    actual_status=NFS4ERR_EXPIRED,
)

# GD-11: a wrong-type operation on 4.1+ answers the POSIX-aligned status
# (NFS4ERR_ISDIR / NFS4ERR_INVAL / NFS4ERR_SYMLINK) where the model predicts
# NFS4ERR_WRONG_TYPE.  RFC 8881 makes WRONG_TYPE a SHOULD for a type mismatch
# (e.g. 18.32.3 for the size attribute), and the model takes it on 4.1+ (4.0
# has no such code); neither real server implements it, so a size SETATTR or a
# WRITE on a non-regular object, an OPEN of a special file, and the like come
# back as the file's natural error instead.  GD-5 recorded the OPEN case
# specifically; this is the general form.  Status-only, so replay continues.
GD_11_WRONG_TYPE = Deviation(
    id="GD-11-wrong-type-posix-status",
    verdict=SERVER,
    spec="RFC 8881 (NFS4ERR_WRONG_TYPE is a SHOULD for a type mismatch; the "
         "POSIX-aligned ISDIR/INVAL/SYMLINK are equally conformant)",
    summary="a wrong-type op returns ISDIR/INVAL/SYMLINK where the model, "
            "following the 4.1+ SHOULD, predicts NFS4ERR_WRONG_TYPE",
    root_cause="ganesha reports the object's natural POSIX-aligned status, "
               "never NFS4ERR_WRONG_TYPE",
    candidate_fix="none required (both conformant); the model could drop "
                  "WRONG_TYPE for the POSIX-aligned codes on all minors",
    ops=("SSetattr", "SWrite", "SRead", "SOpen", "SLayoutget"),
    expected_status=NFS4ERR_WRONG_TYPE,
    actual_status=(NFS4ERR_ISDIR, NFS4ERR_INVAL, NFS4ERR_SYMLINK),
)

# GD-12: a repeat EXCHANGE_ID of an already-confirmed client (same co_ownerid
# and verifier) returns the client id with EXGID4_FLAG_CONFIRMED_R clear.
# RFC 8881 18.35.4 sets that flag when the server already holds a confirmed
# record for the owner+verifier, which the model predicts; ganesha returns the
# same client id (no client-id divergence) but leaves the flag false.  The
# client stays confirmed either way, so replay continues.
GD_12_CONFIRMED_R = Deviation(
    id="GD-12-exchange-id-confirmed-r",
    verdict=SERVER,
    spec="RFC 8881 18.35.4 (EXGID4_FLAG_CONFIRMED_R is set for a repeat "
         "EXCHANGE_ID of a confirmed owner+verifier)",
    summary="a repeat EXCHANGE_ID of a confirmed client leaves confirmed_r "
            "false where the model predicts true",
    root_cause="ganesha does not report CONFIRMED_R on a second EXCHANGE_ID "
               "for an already-confirmed client id",
    candidate_fix="none required from the model's side; a ganesha behaviour",
    ops=("SExchangeId",),
    field="confirmed_r",
    expected_value=True,
    actual_value=False,
)

# GD-13: OPEN with GUARDED4 or EXCLUSIVE4 over an existing non-regular target,
# or over a share-reservation conflict, reports the target's type error
# (NFS4ERR_ISDIR / NFS4ERR_SYMLINK) or NFS4ERR_SHARE_DENIED where the model
# reports NFS4ERR_EXIST.  The model keeps the fail-if-exists dispositions on
# the RFC-literal / POSIX O_EXCL reading -- an existing name is EXIST whatever
# its type -- and checks the share reservation only after resolve; ganesha
# reports the type or the share conflict first.  RFC 7530 16.16.4 / RFC 8881
# 18.16.4 list all of these without ordering them.  The OPEN fails either way,
# so replay continues.
GD_13_OPEN_EXIST_PRECEDENCE = Deviation(
    id="GD-13-open-exist-precedence",
    verdict=SERVER,
    spec="RFC 7530 16.16.4 / RFC 8881 18.16.4 (OPEN; EXIST vs the target "
         "type vs a share conflict are listed without a pinned order)",
    summary="a GUARDED/EXCLUSIVE OPEN over an existing dir/symlink or a share "
            "conflict returns ISDIR/SYMLINK/SHARE_DENIED, not the model's EXIST",
    root_cause="ganesha checks the target type and the share reservation "
               "before the create-exclusivity existence check",
    candidate_fix="none required (defensible); the model keeps the RFC-literal "
                  "EXIST for a fail-if-exists disposition",
    ops=("SOpen",),
    expected_status=NFS4ERR_EXIST,
    actual_status=(NFS4ERR_ISDIR, NFS4ERR_SYMLINK, NFS4ERR_SHARE_DENIED),
)


# GD-14: extend GD-1's change-attribute reconciliation to its other facet.
# check_change also fires "abstract change X reported two wire values" when the
# wire change advances for an object the model did not mutate in that step
# (coarse ctime crossing a tick boundary between two reads).  Same root cause
# and RFC clause as GD-1; recorded here for the OPEN/GETATTR path.
GD_14_CHANGE_ADVANCED = Deviation(
    id="GD-14-change-advanced-untracked",
    verdict=SERVER,
    spec="RFC 7530 5.8.1.4 / RFC 8881 5.8.1.4 (change): coarse ctime makes the "
         "value non-injective against the model's abstract change",
    summary="the wire change advances where the model recorded no mutation "
            "(the ctime-granularity dual of GD-1)",
    root_cause="FSAL_VFS change = ctime in ns; a tick boundary moves it "
               "between two reads the model treats as unchanged",
    candidate_fix="a per-object modification counter (as GD-1)",
    ops=("SOpen", "SGetattr", "SCreate", "SRemove", "SRename", "SLink"),
    field=("cinfo.after", "cinfo.before", "cinfoS.before", "cinfoS.after",
           "cinfoT.before", "cinfoT.after", "change"),
    context=lambda f, ctx: "reported two wire values" in f.detail,
)

# GD-15: open-mode vs lock/IO enforcement.  RFC 8881 9.1.2 requires the stateid's
# open to allow the access a READ/WRITE/LOCK needs (NFS4ERR_OPENMODE otherwise),
# but leaves how strictly a lock's type is matched to the open's share access
# under-specified.  The model and ganesha draw the line differently in both
# directions: a READ_LT lock on a write-only open is OPENMODE to ganesha but
# allowed by the model, and a READ through a stateid the model thinks lacks
# READ is OPENMODE to the model but allowed by ganesha.  Status-only.
GD_15_OPENMODE = Deviation(
    id="GD-15-openmode-lock-vs-io",
    verdict=BOTH,
    spec="RFC 8881 9.1.2 (NFS4ERR_OPENMODE; the exact open-access/lock-type "
         "match is under-specified)",
    summary="READ/LOCK vs the stateid's open access: model and ganesha enforce "
            "NFS4ERR_OPENMODE in opposite directions",
    root_cause="the model and ganesha calibrate the open-access-vs-lock/IO "
               "check differently",
    candidate_fix="pin the model's opLock/opRead openmode rule to ganesha's",
    ops=("SLock", "SRead", "SWrite"),
    expected_status=(NFS4_OK, NFS4ERR_OPENMODE, NFS4ERR_LOCKED),
    actual_status=(NFS4ERR_OPENMODE, NFS4_OK),
)

# GD-16: EXCLUSIVE open verifier lifecycle and share-vs-create precedence.  The
# model stores the exclusive verifier in time_modify and predicts idempotent
# EXIST/OK on a same/different-verifier retry; ganesha's own verifier bookkeeping
# and its share-reservation check land on the opposite EXIST<->OK, or on
# SHARE_DENIED where the model has not yet noticed the reservation.  RFC 7530
# 16.16 leaves the verifier's storage and the create-vs-share order to the
# server.  reconcilable=False: an open that one side created and the other did
# not parts the state, so the trace stops here rather than cascading.
GD_16_EXCL_VERIFIER = Deviation(
    id="GD-16-exclusive-verifier-lifecycle",
    verdict=SERVER,
    spec="RFC 7530 16.16 / RFC 8881 18.16 (EXCLUSIVE verifier storage and the "
         "create-vs-share-reservation order are the server's)",
    summary="EXCLUSIVE-open retry lands on the opposite EXIST/OK, or on "
            "SHARE_DENIED, from the model's verifier/share prediction",
    root_cause="ganesha's exclusive-verifier bookkeeping and share check differ "
               "from the model's time_modify-based prediction",
    candidate_fix="align the model's exclusive-verifier storage with ganesha",
    ops=("SOpen",),
    expected_status=(NFS4ERR_EXIST, NFS4_OK),
    actual_status=(NFS4_OK, NFS4ERR_EXIST, NFS4ERR_SHARE_DENIED),
    reconcilable=False,
)

# GD-17: OPEN's OPEN4_RESULT_CONFIRM flag.  On 4.1+ there is no OPEN_CONFIRM, so
# the model predicts needConfirm=false; ganesha sets the flag in a case the
# model does not (or vice versa).  The confirm handshake is 4.0-only, so the
# flag on 4.1+ changes nothing observable -- field-only, reconcilable.
GD_17_RFLAGS_CONFIRM = Deviation(
    id="GD-17-open-rflags-confirm",
    verdict=SERVER,
    spec="RFC 8881 18.16 (OPEN4_RESULT_CONFIRM is meaningful only for the "
         "4.0 OPEN_CONFIRM handshake)",
    summary="OPEN's confirm flag differs from the model's needConfirm "
            "prediction where it has no observable effect",
    root_cause="ganesha's OPEN4_RESULT_CONFIRM bookkeeping differs from the "
               "model's needConfirm",
    candidate_fix="none required (no observable effect off 4.0)",
    ops=("SOpen",),
    field="rflags_confirm",
)

# GD-18: the wide GETATTR (every supported attribute at once) answers
# NFS4ERR_INVAL.  ganesha rejects the whole-bitmap request that the model, which
# asks only for the attributes it can predict, treats as OK.  RFC 8881 18.7
# lets a server reject an attribute request it cannot satisfy; status-only.
GD_18_GETATTR_WIDE_INVAL = Deviation(
    id="GD-18-getattr-wide-inval",
    verdict=SERVER,
    spec="RFC 8881 18.7.3 (GETATTR may reject an unsupported attribute "
         "combination)",
    summary="the whole-bitmap wide GETATTR returns NFS4ERR_INVAL where the "
            "model predicts OK",
    root_cause="ganesha rejects the full supported-attribute bitmap request",
    candidate_fix="model: narrow the wide GETATTR to attributes ganesha "
                  "marshals without INVAL",
    ops=("SGetattrWide",),
    expected_status=NFS4_OK,
    actual_status=NFS4ERR_INVAL,
)

# GD-19: the model deliberately drives NFS4ERR_BAD_SEQID by sending an OPEN
# owner-seqid two past the last (nfs4_ops.qnt oseq: seqid + 2), but ganesha does
# not fail the gap -- it processes the OPEN and answers on the name/existence
# (NOENT, or the object status).  RFC 7530 9.1.7 makes strict +1 sequencing a
# server enforcement point that this ganesha build does not police.
# reconcilable=False: the owner seqid then parts, so the trace stops here.
GD_19_OWNER_SEQID_GAP = Deviation(
    id="GD-19-owner-seqid-gap-unpoliced",
    verdict=SERVER,
    spec="RFC 7530 9.1.7 (the open-owner seqid must be exactly one greater; "
         "enforcement is the server's)",
    summary="an OPEN owner-seqid gap the model predicts NFS4ERR_BAD_SEQID for "
            "is processed by ganesha (NOENT / the object status)",
    root_cause="this ganesha build does not police the +1 open-owner seqid gap",
    candidate_fix="none from the model; drop the BAD_SEQID negative probe or "
                  "record",
    ops=("SOpen", "SClose", "SOpenDowngrade", "SLock"),
    expected_status=(NFS4ERR_BAD_SEQID, NFS4_OK, NFS4ERR_INVAL),
    actual_status=(NFS4ERR_NOENT, NFS4_OK, NFS4ERR_NOTDIR, NFS4ERR_EXIST,
                   NFS4ERR_ISDIR, NFS4ERR_BAD_SEQID),
    reconcilable=False,
)


# GD-20: object/stateid lifecycle -- the model references a stateid or
# filehandle the server has already reaped or invalidated, or vice versa.  A
# SETATTR through an open stateid the model has freed is BAD_STATEID to the
# model but OK to ganesha; a PUTFH of a handle the model still holds is STALE
# to ganesha; a LINK/SEEK against such an object diverges likewise.  These
# follow from the deviations already recorded upstream (name handling, owner
# seqid, verifier) parting the two sides' state.  reconcilable=False.
GD_20_LIFECYCLE = Deviation(
    id="GD-20-object-stateid-lifecycle",
    verdict=SERVER,
    spec="RFC 8881 9.1.4 / 8.2 (stateid and filehandle validity track the "
         "server's object lifecycle)",
    summary="a stateid/filehandle the model and ganesha disagree on the "
            "validity of (BAD_STATEID/STALE/LOCKED vs OK), after upstream "
            "state parted",
    root_cause="an upstream recorded deviation left the model and ganesha with "
               "different live stateids/objects",
    candidate_fix="none (downstream of the recorded upstream deviation)",
    ops=("SSetattr", "SPutfh", "SSeek", "SLink"),
    expected_status=(NFS4ERR_BAD_STATEID, NFS4_OK, NFS4ERR_LOCKED),
    actual_status=(NFS4_OK, NFS4ERR_STALE, NFS4ERR_NOENT),
    reconcilable=False,
)

# GD-21: leftover status/field divergences that fall out of the recorded
# clusters -- a name-vs-share OPEN precedence (BADCHAR vs SHARE_DENIED), a
# DESTROY_CLIENTID that finds the id still busy (NOT_ONLY_OP vs CLIENTID_BUSY),
# a LOCKU/ACCESS whose seqid/mask the model and ganesha compute differently.
# All conformant and status/field-only.
GD_21_RESIDUAL = Deviation(
    id="GD-21-residual-precedence",
    verdict=BOTH,
    spec="RFC 7530 16.16 / RFC 8881 18.50 (a name-vs-share OPEN order and "
         "DESTROY_CLIENTID's still-in-use status are the server's)",
    summary="a name-vs-share OPEN (BADCHAR vs SHARE_DENIED) and a "
            "DESTROY_CLIENTID of an id still in use (NOT_ONLY_OP vs "
            "CLIENTID_BUSY) differ from the model",
    root_cause="ganesha orders the OPEN name/share checks and reports an "
               "in-use client id differently from the model",
    candidate_fix="triage per edge if any recurs at volume",
    ops=("SOpen", "SDestroyClientid"),
    expected_status=(NFS4ERR_BADCHAR, NFS4ERR_NOT_ONLY_OP),
    actual_status=(NFS4ERR_SHARE_DENIED, NFS4ERR_CLIENTID_BUSY),
)

# GD-22: LOCKU/ACCESS field divergences -- the LOCKU reply seqid the model and
# ganesha compute differently once an upstream seqid deviation has shifted the
# lock stateid, and the ACCESS mask ganesha grants that the model's type-masking
# does not.  Field-only, no state change.
GD_22_FIELD = Deviation(
    id="GD-22-locku-access-field",
    verdict=BOTH,
    spec="RFC 8881 18.12 (LOCKU seqid) / 18.1 (ACCESS mask is the server's to "
         "grant within the supported set)",
    summary="LOCKU reply seqid and ACCESS granted-mask differ from the model",
    root_cause="ganesha's LOCKU seqid and ACCESS accounting differ from the "
               "model's",
    candidate_fix="triage if either recurs at volume",
    ops=("SLocku", "SAccess"),
    field=("seqid", "access"),
)


# GD-23: compound-level structural divergences.  The model over-validates the
# compound tag (a malformed-UTF-8 tag makes the whole compound NFS4ERR_INVAL
# with no results), and predicts a result for a sole-op rule (BIND_CONN_TO_
# SESSION NOT_ONLY_OP) that ganesha rejects at the connection level with zero
# results.  RFC 8881 2.2 leaves compound-tag validation to the server, and the
# reply's result count follows the server's processing.  Compound-level only.
GD_23_COMPOUND = Deviation(
    id="GD-23-compound-tag-and-shape",
    verdict=SERVER,
    spec="RFC 8881 2.2 (the compound tag is opaque UTF-8 the server need not "
         "police; the result count follows server processing)",
    summary="a compound's result count or status differs (tag validation / "
            "BIND_CONN sole-op) with no per-op finding",
    root_cause="ganesha does not reject a malformed tag and shapes the reply "
               "differently on the BIND_CONN edge",
    candidate_fix="model: relax compound-tag validation to match the servers",
    ops=("compound",),
    field="results",
    expected_value=(0, 1),
    actual_value=(0, 1),
)

# GD-24: the compound status the model predicts INVAL (malformed tag) that
# ganesha answers OK, paired with GD-23's result-count row.
GD_24_COMPOUND_STATUS = Deviation(
    id="GD-24-compound-tag-status",
    verdict=SERVER,
    spec="RFC 8881 2.2 (compound-tag validation is the server's)",
    summary="a malformed-tag compound the model calls NFS4ERR_INVAL is OK to "
            "ganesha",
    root_cause="ganesha does not reject a malformed compound tag",
    candidate_fix="model: relax compound-tag validation",
    ops=("compound",),
    expected_status=NFS4ERR_INVAL,
    actual_status=NFS4_OK,
)


# GD-25: residual field/status edges -- READDIR lists a leniently-accepted
# malformed name the model rejected (like KN-18), BIND_CONN_TO_SESSION accepts a
# channel direction the model calls INVAL, and a LINK/name error lands on a
# different code.  All downstream of the recorded name/dir latitude.
GD_25_RESIDUAL2 = Deviation(
    id="GD-25-readdir-bindconn-residual",
    verdict=SERVER,
    spec="RFC 8881 18.34 (BIND_CONN direction) / 12.7 (malformed-name "
         "acceptance feeds READDIR and LINK)",
    summary="READDIR name set, BIND_CONN direction (INVAL->OK), and a residual "
            "LINK name-error code differ from the model",
    root_cause="ganesha accepts a malformed name/direction the model rejects",
    candidate_fix="none (downstream of the recorded name/dir latitude)",
    ops=("SReaddir", "SBindConnToSession", "SLink"),
    field=("names",),
    expected_value=None,
    actual_value=None,
    context=lambda f, ctx: f.kind == "names",
)

# GD-26: the status companions of GD-25 (BIND_CONN INVAL->OK, LINK name code).
GD_26_RESIDUAL2_STATUS = Deviation(
    id="GD-26-bindconn-link-status",
    verdict=SERVER,
    spec="RFC 8881 18.34 (BIND_CONN direction validation is the server's) / "
         "RFC 7530 16.9.4 (LINK name error)",
    summary="BIND_CONN accepts a direction (INVAL->OK) and a LINK name error "
            "lands on a different code",
    root_cause="ganesha validates the BIND_CONN direction and the LINK name "
               "differently from the model",
    candidate_fix="none required (defensible)",
    ops=("SBindConnToSession", "SLink"),
    expected_status=(NFS4ERR_INVAL, 63),
    actual_status=(NFS4_OK, NFS4ERR_ISDIR),
)


# GD-27: filehandle-identity and a compound status edge downstream of the
# recorded object-lifecycle deviations.  When an upstream deviation left the
# model and ganesha with different live objects, a GETFH sees a different
# filehandle for the abstract object, and a compound the model predicts
# NFS4ERR_MINOR_VERS_MISMATCH ganesha answers NFS4ERR_INVAL.  Field/status-only,
# downstream of the recorded upstream deviation.
GD_27_FH_IDENTITY = Deviation(
    id="GD-27-fh-identity-and-compound",
    verdict=SERVER,
    spec="RFC 8881 4.2.1 (a filehandle's persistence tracks the object) / 2.2 "
         "(minorversion vs INVAL is the server's)",
    summary="GETFH filehandle identity, and a compound MINOR_VERS_MISMATCH vs "
            "INVAL, differ from the model after upstream state parted",
    root_cause="an upstream recorded deviation left ganesha with a different "
               "object/minorversion handling than the model",
    candidate_fix="none (downstream of the recorded upstream deviation)",
    ops=("SGetfh", "compound"),
    field=("fh_identity",),
    context=lambda f, ctx: f.kind == "fh_identity",
)

# GD-28: the compound-status companion of GD-27.
GD_28_COMPOUND_MVM = Deviation(
    id="GD-28-compound-minorversion",
    verdict=SERVER,
    spec="RFC 8881 2.2 (a bad minorversion vs a malformed compound is the "
         "server's to distinguish)",
    summary="a compound the model calls NFS4ERR_OP_NOT_IN_SESSION is "
            "NFS4ERR_INVAL to ganesha",
    root_cause="ganesha reports INVAL where the model predicts "
               "OP_NOT_IN_SESSION for an op used outside a session",
    candidate_fix="none required (defensible)",
    ops=("compound",),
    expected_status=NFS4ERR_OP_NOT_IN_SESSION,
    actual_status=NFS4ERR_INVAL,
)


# GD-29: GETATTR nlink/mode on a directory whose subdirectory count the
# backing ext4 export folds into nlink where the model keeps a flat 2 (the
# ganesha analog of KN-16).  RFC 7530 5.8.1 leaves nlink to the filesystem.
GD_29_DIR_NLINK = Deviation(
    id="GD-29-dir-nlink-accounting",
    verdict=SERVER,
    spec="RFC 7530 5.8.1 (numlinks follows the backing filesystem)",
    summary="GETATTR nlink/mode on a directory differs from the model's flat "
            "accounting",
    root_cause="ganesha's ext4 export counts subdirectories in a directory's "
               "nlink",
    candidate_fix="model: count subdirectories in a directory's nlink",
    ops=("SGetattr",),
    field=("nlink", "mode"),
)

# GD-30: a READ returns stale non-zero data for a block the model (and chimera's
# memfs, which passes the same trace) reads as a hole.  Root-caused on
# nfs4Memfs41_stepData: a name is written (symbol 3 into a block), the name is
# unlinked and re-created (an exclusive OPEN of the same name later in the
# trace), and a READ of the new, empty file returns the *old* file's bytes.
# ganesha's FSAL_VFS over ext4 recycles the unlinked inode and serves its
# residual data for the recreated name, where the model reads the fresh file as
# holes.  Matched only when the model expected a hole (byte 0x0), so a genuine
# data corruption -- where the model expects real bytes -- still fails.
GD_30_READ_STALE_HOLE = Deviation(
    id="GD-30-read-stale-after-recreate",
    verdict=SERVER,
    spec="RFC 7530 5.8 / POSIX: a freshly created file reads as zero-fill "
         "(holes)",
    summary="READ returns a recycled inode's stale bytes for a block the "
            "model reads as a hole",
    root_cause="ganesha's FSAL_VFS over ext4 recycles an unlinked file's inode "
               "and serves its residual data for the recreated name",
    candidate_fix="invalidate the FSAL data cache on unlink/create of a "
                  "recycled inode",
    ops=("SRead", "SReadPlus"),
    field=("data",),
    context=lambda f, ctx: "expected byte 0x0" in f.detail,
)

# GD-31: DESTROY_CLIENTID against a client that still owns sessions or state.
# RFC 8881 18.50.3 makes NFS4ERR_CLIENTID_BUSY the required answer then; the
# model destroys the clientid unconditionally.  ganesha enforces the RFC
# precondition, so its CLIENTID_BUSY is the more-correct answer.
GD_31_DESTROY_CLIENTID_BUSY = Deviation(
    id="GD-31-destroy-clientid-busy",
    verdict=SERVER,
    spec="RFC 8881 18.50.3: DESTROY_CLIENTID is NFS4ERR_CLIENTID_BUSY while the "
         "client owns sessions or state",
    summary="DESTROY_CLIENTID answers CLIENTID_BUSY where the model expects OK",
    root_cause="ganesha enforces the RFC precondition that no sessions/state "
               "remain; the model destroys the clientid unconditionally",
    candidate_fix="model: gate DESTROY_CLIENTID on the client being quiescent",
    ops=("SDestroyClientid",),
    expected_status=0,
    actual_status=NFS4ERR_CLIENTID_BUSY,
)

# GD-32: OPEN(no-create) that both names a symlink and carries a stale owner
# seqid.  RFC 7530 16.16 orders neither the owner-seqid check nor component
# resolution, so either error is conformant: the model reports the seqid first
# (NFS4ERR_BAD_SEQID), ganesha the resolution (NFS4ERR_SYMLINK).  Nothing opens
# either way.
GD_32_OPEN_SEQID_VS_SYMLINK = Deviation(
    id="GD-32-open-seqid-vs-symlink",
    verdict=SERVER,
    spec="RFC 7530 16.16.5 / 8.1.5: BAD_SEQID and SYMLINK both apply to this "
         "OPEN and their precedence is unspecified",
    summary="OPEN of a symlink with a stale owner seqid: model BAD_SEQID vs "
            "ganesha SYMLINK",
    root_cause="unordered error precedence between the owner-seqid check and "
               "component resolution",
    candidate_fix=None,
    ops=("SOpen",),
    expected_status=NFS4ERR_BAD_SEQID,
    actual_status=NFS4ERR_SYMLINK,
)


NFS4 = Registry("ganesha/nfs4", [
    GD_1_CHANGE_GRANULARITY,
    GD_4_VERIFY_WIDE_EMPTY,
    GD_5_OPEN_SPECIAL_SYMLINK,
    GD_6_NAME_HANDLING,
    GD_7_SETATTR_SHARE_DENIED,
    GD_9_LINK_DIR_NOTDIR,
    GD_10_RENEW_EXPIRED,
    GD_11_WRONG_TYPE,
    GD_12_CONFIRMED_R,
    GD_13_OPEN_EXIST_PRECEDENCE,
    GD_14_CHANGE_ADVANCED,
    GD_15_OPENMODE,
    GD_16_EXCL_VERIFIER,
    GD_17_RFLAGS_CONFIRM,
    GD_18_GETATTR_WIDE_INVAL,
    GD_19_OWNER_SEQID_GAP,
    GD_20_LIFECYCLE,
    GD_21_RESIDUAL,
    GD_22_FIELD,
    GD_23_COMPOUND,
    GD_24_COMPOUND_STATUS,
    GD_25_RESIDUAL2,
    GD_26_RESIDUAL2_STATUS,
    GD_27_FH_IDENTITY,
    GD_28_COMPOUND_MVM,
    GD_29_DIR_NLINK,
    GD_30_READ_STALE_HOLE,
    GD_31_DESTROY_CLIENTID_BUSY,
    GD_32_OPEN_SEQID_VS_SYMLINK,
])


# GN-2: LINK of a directory answers NFS3ERR_BADTYPE, not NFS3ERR_ISDIR.
# Hard-linking a directory is refused by every server, but the status is not
# pinned: RFC 1813 3.3.15 lists neither ISDIR nor a POSIX EPERM among LINK's
# errors, so servers differ -- the reference implementation (and this model)
# answer ISDIR, ganesha answers BADTYPE, and the Linux server answers yet
# another.  Recorded as a ganesha divergence from the model's pick; once the
# knfsd harness lands it becomes the tiebreaker for whether the model should
# assert a *set* of acceptable statuses here rather than one.  Note the v4
# LINK path is unaffected -- ganesha's NFSv4 LINK of a directory does return
# NFS4ERR_ISDIR, matching the model.  Status-only, so replay continues.
GN_2_LINK_DIR_BADTYPE = Deviation(
    id="GN-2-link-dir-badtype",
    verdict=SERVER,
    spec="RFC 1813 3.3.15 (LINK; the directory-source status is unspecified)",
    summary="LINK of a directory returns NFS3ERR_BADTYPE instead of "
            "NFS3ERR_ISDIR",
    root_cause="ganesha refuses a directory hard link with BADTYPE",
    candidate_fix="none required (defensible); revisit whether the model "
                  "should accept a status set once knfsd is the tiebreaker",
    ops=("OLink",),
    expected_status=NFS3ERR_ISDIR,
    actual_status=NFS3ERR_BADTYPE,
)

# GN-3: CREATE disposition and precedence.  RFC 1813 3.3.8 leaves the order of
# the existence, type and permission checks (and which of GUARDED's collisions
# is EXIST vs the object's own status) to the server.  ganesha reports the
# object type (BADTYPE), a permission failure (ACCES), or EXIST where the model
# predicts EXIST or OK.  A create that one side made and the other did not parts
# the state, so reconcilable=False.
GN_3_CREATE = Deviation(
    id="GN-3-create-disposition",
    verdict=SERVER,
    spec="RFC 1813 3.3.8 (CREATE; the existence/type/permission check order is "
         "the server's)",
    summary="CREATE disposition/precedence lands on BADTYPE/ACCES/EXIST/OK "
            "differently from the model",
    root_cause="ganesha orders the CREATE existence/type/permission checks "
               "differently from the model",
    candidate_fix="align the model's CREATE precedence with ganesha",
    ops=("OCreate",),
    expected_status=(NFS3ERR_EXIST, NFS3_OK, NFS3ERR_ACCES, NFS3ERR_ISDIR),
    actual_status=(NFS3ERR_BADTYPE, NFS3ERR_ACCES, NFS3ERR_EXIST, NFS3_OK,
                   NFS3ERR_NXIO),
    reconcilable=False,
)

# GN-4: RENAME of a non-empty directory target reports NFS3ERR_NOTEMPTY where
# the model predicts NFS3ERR_ISDIR (both are conformant, RFC 1813 3.3.14 lists
# neither order).  Nothing is renamed, so replay continues.
GN_4_RENAME = Deviation(
    id="GN-4-rename-notempty",
    verdict=SERVER,
    spec="RFC 1813 3.3.14 (RENAME; ISDIR vs NOTEMPTY for a directory target is "
         "unordered)",
    summary="RENAME onto a directory reports NFS3ERR_NOTEMPTY where the model "
            "predicts NFS3ERR_ISDIR",
    root_cause="ganesha reports the non-empty target before its type",
    candidate_fix="none required (defensible)",
    ops=("ORename",),
    expected_status=(NFS3ERR_ISDIR, NFS3ERR_NOTEMPTY, NFS3ERR_INVAL, NFS3_OK),
    actual_status=(NFS3ERR_NOTEMPTY, NFS3ERR_EXIST, NFS3_OK, NFS3ERR_IO),
    reconcilable=False,
)

# GN-5: object attribute fields the FSAL reports differently -- a symlink's
# size is its target length in the model but 0 from ganesha's FSAL_VFS, and a
# directory's nlink/mode follow the ext4 export (as GD-29).  Field-only.
GN_5_ATTR_FIELDS = Deviation(
    id="GN-5-attr-fields",
    verdict=SERVER,
    spec="RFC 1813 2.5 (size/numlinks follow the backing filesystem)",
    summary="symlink size (target length vs 0) and directory nlink/mode differ "
            "from the model",
    root_cause="ganesha's FSAL_VFS reports a symlink size 0 and counts ext4 "
               "subdirectory links",
    candidate_fix="model: use 0 for symlink size and count subdir nlink",
    ops=("OSymlink", "OCreate", "OGetattr", "OReaddir", "OLookup", "OMkdir",
         "OReadlink", "OLink", "OAccess"),
    field=("obj_attrs.size", "obj_attrs.nlink", "attrs.nlink", "attrs.size",
           "wcc.after.nlink", "file_attributes.size", "readdirplus[b].size"),
)

NFS3 = Registry("ganesha/nfs3", [
    GN_2_LINK_DIR_BADTYPE,
    GN_3_CREATE,
    GN_4_RENAME,
    GN_5_ATTR_FIELDS,
])
