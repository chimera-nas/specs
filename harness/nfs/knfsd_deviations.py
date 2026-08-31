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


# knfsd's ACCESS-masking and READLINK-on-a-directory findings drove the model
# to the standard (they matched ganesha and the RFCs); the model was corrected,
# so nothing is recorded here yet.  New knfsd-specific divergences go here.



# KN-1: component-name handling -- the same latitude recorded for ganesha in
# GD-6.  RFC 7530 12.7 / RFC 8881 12.6 make UTF-8 validation a server SHOULD
# and 12.8 lets the server pick the rejection code; knfsd does not enforce the
# model's strict validation, so a malformed-UTF-8 component the model rejects
# (INVAL/BADCHAR/BADNAME) resolves as an ordinary name (NOENT, or OK/EXIST) or
# is rejected under a different one of the three codes (observed:
# BADCHAR -> BADNAME).  Reconcilable for the same reason as GD-6.
KN_1_NAME_HANDLING = Deviation(
    id="KN-1-name-handling",
    verdict=SERVER,
    spec="RFC 7530 12.7 / RFC 8881 12.6 (UTF-8 validation is a SHOULD) and "
         "12.8 (INVAL/BADCHAR/BADNAME are the server's choice)",
    summary="a malformed-UTF-8 component the model rejects is resolved as an "
            "ordinary name, or rejected under a different name-error code",
    root_cause="knfsd does not enforce the model's strict UTF-8 component "
               "validation and picks its own name-error code",
    candidate_fix="none required (both are conformant); the model could relax "
                  "to accept a status set for these names",
    ops=("SLookup", "SOpen", "SCreate", "SRemove", "SRename", "SLink",
         "SSecinfo"),
    expected_status=(NFS4ERR_INVAL, NFS4ERR_BADCHAR, NFS4ERR_BADNAME),
    actual_status=(NFS4ERR_INVAL, NFS4ERR_BADCHAR, NFS4ERR_BADNAME,
                   NFS4ERR_NOENT, NFS4_OK, NFS4ERR_EXIST),
)

# KN-2: CREATE of a regular file into a non-directory parent -- the doubly
# invalid request of GD-8.  RFC 7530 16.4 / RFC 8881 18.4 do not order the
# object-type and parent checks; the model reports the type (NFS4ERR_BADTYPE)
# and knfsd reports the parent (NFS4ERR_NOTDIR -- knfsd does not single out a
# symlink parent the way ganesha does).  Nothing is created, so replay
# continues.
KN_2_CREATE_PARENT_FIRST = Deviation(
    id="KN-2-create-parent-before-type",
    verdict=SERVER,
    spec="RFC 7530 16.4 / RFC 8881 18.4 (CREATE; the type vs parent check "
         "order is unspecified)",
    summary="CREATE of a regular file into a non-directory parent reports "
            "NFS4ERR_NOTDIR where the model reports NFS4ERR_BADTYPE",
    root_cause="knfsd validates the current filehandle's type before the "
               "requested object type",
    candidate_fix="none required (defensible); the model could check the "
                  "parent type first to match",
    ops=("SCreate",),
    expected_status=NFS4ERR_BADTYPE,
    actual_status=NFS4ERR_NOTDIR,
)


NFS4 = Registry("knfsd/nfs4", [
    KN_1_NAME_HANDLING,
    KN_2_CREATE_PARENT_FIRST,
])


NFS3 = Registry("knfsd/nfs3", [
])
