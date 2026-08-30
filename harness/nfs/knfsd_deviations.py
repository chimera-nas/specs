# SPDX-FileCopyrightText: 2026 The Quint Specs Authors
#
# SPDX-License-Identifier: MIT

"""Registry of known Linux kernel NFS server (knfsd) divergences from the
NFS models.  See deviations.py for the contract and ganesha_deviations.py
for the shape of an entry.  Recorded against the kernel of the
kvm-test-base guest the harness boots (harness/nfs/run_nfs_mbt.sh).
"""

from deviations import (Deviation, Registry, SERVER, MODEL, BOTH,  # noqa: F401
                        NFS4_OK, NFS3_OK)
from deviations import *  # noqa: F401,F403  -- the status constants


# knfsd confirms two findings the Ganesha suite already records, which is the
# value of a second, unrelated reference: a divergence seen on both servers is
# far more likely a model issue than a quirk of one implementation.

# KK-1: ACCESS reports only the bits meaningful for the object type -- exactly
# GD-2.  RFC 8881 18.1.4: EXECUTE has "no meaning for a directory", LOOKUP none
# for a non-directory, and DELETE MAY be 0.  knfsd masks the same way Ganesha
# and the reference server do, so the model (which asserts the full requested
# mask) is the one to change.  Recorded as MODEL, reconcilable.
KK_1_ACCESS_TYPE_MASK = Deviation(
    id="KK-1-access-type-mask",
    verdict=MODEL,
    spec="RFC 8881 18.1.4 (EXECUTE/LOOKUP have no meaning for the wrong type; "
         "DELETE MAY be 0)",
    summary="ACCESS supported/access drop the type-irrelevant bits; the model "
            "predicts the full requested mask (also seen on ganesha, GD-2)",
    root_cause="knfsd masks the ACCESS reply by object type, as ganesha and "
               "the reference implementation do",
    candidate_fix="model: mask the ACCESS reply by ftype (see GD-2)",
    ops=("SAccess",),
    field=("supported", "access"),
)

# KK-2: READLINK on a directory answers NFS4ERR_INVAL, not NFS4ERR_ISDIR --
# exactly GD-3.  RFC 7530 16.25.4 only "should" return ISDIR for a directory,
# so INVAL is permitted; recorded as a knfsd divergence from the more specific
# status the model predicts (and ganesha shares).
KK_2_READLINK_DIR_INVAL = Deviation(
    id="KK-2-readlink-dir-inval",
    verdict=SERVER,
    spec="RFC 7530 16.25.4 (READLINK on a directory SHOULD be NFS4ERR_ISDIR)",
    summary="READLINK on a directory returns NFS4ERR_INVAL instead of "
            "NFS4ERR_ISDIR (also seen on ganesha, GD-3)",
    root_cause="knfsd returns INVAL for a non-symlink READLINK target",
    candidate_fix="none required (defensible)",
    ops=("SReadlink",),
    expected_status=NFS4ERR_ISDIR,
    actual_status=NFS4ERR_INVAL,
)

NFS4 = Registry("knfsd/nfs4", [
    KK_1_ACCESS_TYPE_MASK,
    KK_2_READLINK_DIR_INVAL,
])

# KN-1: the v3 ACCESS reply masks the type-irrelevant bits (RFC 1813 3.3.4),
# the v3 counterpart of KK-1/GN-1.  The v3 model asserts access == the mask;
# knfsd, like ganesha and the reference server, masks by type.  v3 ACCESS is
# advisory, so this is server discretion.
KN_1_ACCESS_TYPE_MASK = Deviation(
    id="KN-1-access-type-mask",
    verdict=SERVER,
    spec="RFC 1813 3.3.4 (EXECUTE/LOOKUP have no meaning for the wrong type)",
    summary="ACCESS access mask drops the type-irrelevant bits; the model "
            "predicts the full requested mask (also seen on ganesha, GN-1)",
    root_cause="knfsd masks the v3 ACCESS reply by object type",
    candidate_fix="model: mask the ACCESS reply by ftype",
    ops=("OAccess",),
    field="access",
)

NFS3 = Registry("knfsd/nfs3", [
    KN_1_ACCESS_TYPE_MASK,
])
