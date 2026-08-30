# SPDX-FileCopyrightText: 2026 The Quint Specs Authors
#
# SPDX-License-Identifier: MIT

"""Registry of known NFS-Ganesha divergences from the NFS models.

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

# GD-2: ACCESS reports only the bits meaningful for the object's type.
# RFC 7530 16.1.4 / RFC 8881 18.1.4 define `supported` as "the access rights
# for which the server can verify reliably", and ACCESS4_EXECUTE has "no
# meaning for a directory" while ACCESS4_LOOKUP has "no meaning for a
# non-directory".  Ganesha therefore drops EXECUTE from a directory's reply
# and LOOKUP from a file's, and additionally reports DELETE as 0 for a
# non-directory (the RFC's own worked example permits a 0 DELETE bit).  The
# model asserts supported == access == the requested mask, which is stricter
# than the RFC requires -- so the MODEL is the one to change here (mask the
# reply by object type), and the reference implementation makes the same
# reduction, so a coordinated model fix + pin bump is what retires this.
# Recorded rather than patched unilaterally: changing the shared model
# regenerates every consumer's corpus (see the paired-rebase discipline).
GD_2_ACCESS_TYPE_MASK = Deviation(
    id="GD-2-access-type-mask",
    verdict=MODEL,
    spec="RFC 7530 16.1.4 / RFC 8881 18.1.4 (EXECUTE 'no meaning for a "
         "directory'; LOOKUP 'no meaning for a non-directory'; DELETE MAY "
         "be 0)",
    summary="ACCESS supported/access drop the type-irrelevant bits; the "
            "model predicts the full requested mask",
    root_cause="model opAccess returns supported=access=mask; ganesha and "
               "the reference implementation both mask by object type",
    candidate_fix="model: mask the ACCESS reply by ftype (drop EXECUTE for "
                  "directories, LOOKUP for non-directories); leave DELETE "
                  "on non-directories as tolerated discretion",
    ops=("SAccess",),
    field=("supported", "access"),
)

# GD-3: READLINK on a directory answers NFS4ERR_INVAL, not NFS4ERR_ISDIR.
# RFC 7530 16.25.4 says a READLINK whose object is a directory "should"
# return NFS4ERR_ISDIR (and NFS4ERR_INVAL for any other non-symlink); ganesha
# collapses both to NFS4ERR_INVAL.  A "should", so INVAL is not forbidden --
# recorded as a Ganesha divergence from the more specific status the RFC
# recommends and the model predicts.  Status-only, so replay continues.
GD_3_READLINK_DIR_INVAL = Deviation(
    id="GD-3-readlink-dir-inval",
    verdict=SERVER,
    spec="RFC 7530 16.25.4 (READLINK on a directory SHOULD be NFS4ERR_ISDIR)",
    summary="READLINK on a directory returns NFS4ERR_INVAL instead of "
            "NFS4ERR_ISDIR",
    root_cause="ganesha READLINK returns INVAL for every non-symlink type",
    candidate_fix="ganesha: distinguish a directory target as ISDIR",
    ops=("SReadlink",),
    expected_status=NFS4ERR_ISDIR,
    actual_status=NFS4ERR_INVAL,
)

NFS4 = Registry("ganesha/nfs4", [
    GD_1_CHANGE_GRANULARITY,
    GD_2_ACCESS_TYPE_MASK,
    GD_3_READLINK_DIR_INVAL,
])

# GN-1: the v3 ACCESS reply masks the type-irrelevant bits, exactly as
# GD-2 describes for v4 -- ACCESS3_EXECUTE "no meaning for a directory",
# ACCESS3_LOOKUP "no meaning for non-directory objects" (RFC 1813 3.3.4), and
# DELETE reported 0 for a non-directory.  The v3 model asserts access ==
# mask.  Same verdict and remedy as GD-2: a model fix (mask by type), pending
# a coordinated regenerate.
GN_1_ACCESS_TYPE_MASK = Deviation(
    id="GN-1-access-type-mask",
    verdict=SERVER,
    spec="RFC 1813 3.3.4 (EXECUTE 'no meaning for a directory'; LOOKUP 'no "
         "meaning for non-directory objects')",
    summary="ACCESS access mask drops the type-irrelevant bits; the model "
            "predicts the full requested mask",
    root_cause="model applyAccess returns access=mask; ganesha masks by type",
    candidate_fix="model: mask the ACCESS reply by ftype",
    ops=("OAccess",),
    field="access",
)

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
    GN_1_ACCESS_TYPE_MASK,
    GN_2_LINK_DIR_BADTYPE,
])
