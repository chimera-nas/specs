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
    summary="a size SETATTR through the anonymous stateid against a deny-write "
            "share reservation returns SHARE_DENIED instead of LOCKED",
    root_cause="ganesha reports the share-reservation conflict with "
               "NFS4ERR_SHARE_DENIED rather than the size op's NFS4ERR_LOCKED",
    candidate_fix="ganesha: return NFS4ERR_LOCKED for a special-stateid size "
                  "change that hits a share reservation",
    ops=("SSetattr",),
    expected_status=NFS4ERR_LOCKED,
    actual_status=NFS4ERR_SHARE_DENIED,
)

# GD-8: CREATE of a regular file (an illegal object type for CREATE, which is
# for non-regular objects only) into a non-directory parent.  The request is
# doubly invalid -- bad object type AND bad parent -- and RFC 7530 16.4 /
# RFC 8881 18.4 do not order the two checks.  The model reports the object
# type first (NFS4ERR_BADTYPE); ganesha reports the parent first
# (NFS4ERR_SYMLINK for a symlink parent, NFS4ERR_NOTDIR for any other
# non-directory).  Nothing is created either way, so replay continues.
GD_8_CREATE_PARENT_FIRST = Deviation(
    id="GD-8-create-parent-before-type",
    verdict=SERVER,
    spec="RFC 7530 16.4 / RFC 8881 18.4 (CREATE; the type vs parent check "
         "order is unspecified)",
    summary="CREATE of a regular file into a non-directory parent reports the "
            "parent (SYMLINK/NOTDIR) where the model reports the type (BADTYPE)",
    root_cause="ganesha validates the current filehandle's type before the "
               "requested object type",
    candidate_fix="none required (defensible); the model could check the "
                  "parent type first to match",
    ops=("SCreate",),
    expected_status=NFS4ERR_BADTYPE,
    actual_status=(NFS4ERR_SYMLINK, NFS4ERR_NOTDIR),
)

NFS4 = Registry("ganesha/nfs4", [
    GD_1_CHANGE_GRANULARITY,
    GD_4_VERIFY_WIDE_EMPTY,
    GD_5_OPEN_SPECIAL_SYMLINK,
    GD_6_NAME_HANDLING,
    GD_7_SETATTR_SHARE_DENIED,
    GD_8_CREATE_PARENT_FIRST,
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
