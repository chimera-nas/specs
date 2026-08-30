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

NFS4 = Registry("ganesha/nfs4", [
    GD_1_CHANGE_GRANULARITY,
    GD_4_VERIFY_WIDE_EMPTY,
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
