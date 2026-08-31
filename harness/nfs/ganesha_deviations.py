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

# GD-8: CREATE whose parent (current filehandle) is a symbolic link answers
# NFS4ERR_SYMLINK.  The model, knfsd and chimera all treat a symlink current
# filehandle as a non-directory and answer NFS4ERR_NOTDIR (RFC 7530 16.4.4
# does not list NFS4ERR_SYMLINK for CREATE); ganesha singles the symlink out.
# Nothing is created, so replay continues.
GD_8_CREATE_SYMLINK_PARENT = Deviation(
    id="GD-8-create-symlink-parent",
    verdict=SERVER,
    spec="RFC 7530 16.4.4 / RFC 8881 18.4 (CREATE; NFS4ERR_SYMLINK is not "
         "listed, and a symlink current filehandle is a non-directory)",
    summary="CREATE into a symlink parent reports NFS4ERR_SYMLINK where the "
            "model (and knfsd and chimera) report NFS4ERR_NOTDIR",
    root_cause="ganesha singles out a symlink current filehandle instead of "
               "reporting the generic not-a-directory status",
    candidate_fix="none required (defensible)",
    ops=("SCreate",),
    expected_status=NFS4ERR_NOTDIR,
    actual_status=NFS4ERR_SYMLINK,
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


NFS4 = Registry("ganesha/nfs4", [
    GD_1_CHANGE_GRANULARITY,
    GD_4_VERIFY_WIDE_EMPTY,
    GD_5_OPEN_SPECIAL_SYMLINK,
    GD_6_NAME_HANDLING,
    GD_7_SETATTR_SHARE_DENIED,
    GD_8_CREATE_SYMLINK_PARENT,
    GD_9_LINK_DIR_NOTDIR,
    GD_10_RENEW_EXPIRED,
    GD_11_WRONG_TYPE,
    GD_12_CONFIRMED_R,
    GD_13_OPEN_EXIST_PRECEDENCE,
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

NFS3 = Registry("ganesha/nfs3", [
    GN_2_LINK_DIR_BADTYPE,
])
