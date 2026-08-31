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



# KN-3: LINK of a directory source -> NFS4ERR_NOTDIR, the knfsd side of GD-9
# (both real servers agree on NOTDIR where the model and RFC 7530 16.9.4 pick
# NFS4ERR_ISDIR).  Nothing is linked, so replay continues.
KN_3_LINK_DIR_NOTDIR = Deviation(
    id="KN-3-link-dir-notdir",
    verdict=SERVER,
    spec="RFC 7530 16.9.4 (LINK; the directory-source status is effectively "
         "unspecified and servers differ)",
    summary="LINK of a directory source returns NFS4ERR_NOTDIR instead of "
            "the model's NFS4ERR_ISDIR",
    root_cause="knfsd refuses a directory hard link with NOTDIR",
    candidate_fix="switch the model (and nfs4Test) to NOTDIR -- both servers "
                  "agree on it -- or keep ISDIR and this record",
    ops=("SLink",),
    expected_status=(NFS4ERR_ISDIR, NFS4ERR_INVAL, NFS4ERR_BADNAME,
                     NFS4ERR_BADCHAR),
    actual_status=(NFS4ERR_NOTDIR, NFS4ERR_ISDIR, NFS4ERR_INVAL,
                   NFS4ERR_BADNAME, NFS4ERR_BADCHAR),
)

# KN-4: RENEW of a lapsed lease -> NFS4ERR_EXPIRED, the knfsd side of GD-10.
# RFC 7530 16.30.4 / 9.6.3 leave EXPIRED vs STALE_CLIENTID to the server; the
# client re-establishes state either way, so replay continues.
KN_4_RENEW_EXPIRED = Deviation(
    id="KN-4-renew-expired",
    verdict=SERVER,
    spec="RFC 7530 16.30.4 / 9.6.3 (RENEW; EXPIRED vs STALE_CLIENTID for a "
         "lapsed lease is the server's to time)",
    summary="RENEW of a lapsed lease returns NFS4ERR_EXPIRED where the model "
            "predicts NFS4ERR_STALE_CLIENTID",
    root_cause="knfsd retains the client id past the lease and reports "
               "EXPIRED; the model retires it and reports STALE_CLIENTID",
    candidate_fix="none required (defensible); the model could retain a "
                  "lapsed client id briefly to match",
    ops=("SRenew",),
    expected_status=NFS4ERR_STALE_CLIENTID,
    actual_status=NFS4ERR_EXPIRED,
)

# KN-5: RENAME across a symlink directory -> NFS4ERR_NOTDIR.  When the source
# or target directory handle names a symlink, the model reports NFS4ERR_SYMLINK
# (matching ganesha), but knfsd reports NFS4ERR_NOTDIR -- a symlink is not a
# directory (RFC 7530 16.27.4 lists NOTDIR; the symlink-vs-notdir framing is
# the server's).  Nothing is renamed, so replay continues.
KN_5_RENAME_SYMLINK_NOTDIR = Deviation(
    id="KN-5-rename-symlink-notdir",
    verdict=SERVER,
    spec="RFC 7530 16.27.4 (RENAME; NOTDIR is listed, and symlink-vs-notdir "
         "for a symlink directory handle is the server's framing)",
    summary="RENAME with a symlink source/target directory returns "
            "NFS4ERR_NOTDIR instead of the model's NFS4ERR_SYMLINK",
    root_cause="knfsd frames a symlink used as a directory as NOTDIR",
    candidate_fix="none required (defensible)",
    ops=("SRename",),
    expected_status=NFS4ERR_SYMLINK,
    actual_status=NFS4ERR_NOTDIR,
)

# KN-6: the knfsd side of GD-11 -- a wrong-type operation on 4.1+ comes back
# as the POSIX-aligned ISDIR/INVAL/SYMLINK, never the model's 4.1+
# NFS4ERR_WRONG_TYPE (RFC 8881's SHOULD).  Status-only, so replay continues.
KN_6_WRONG_TYPE = Deviation(
    id="KN-6-wrong-type-posix-status",
    verdict=SERVER,
    spec="RFC 8881 (NFS4ERR_WRONG_TYPE is a SHOULD; the POSIX-aligned "
         "ISDIR/INVAL/SYMLINK are equally conformant)",
    summary="a wrong-type op returns ISDIR/INVAL/SYMLINK where the model, "
            "following the 4.1+ SHOULD, predicts NFS4ERR_WRONG_TYPE",
    root_cause="knfsd reports the object's natural POSIX-aligned status, "
               "never NFS4ERR_WRONG_TYPE",
    candidate_fix="none required (both conformant)",
    ops=("SSetattr", "SWrite", "SRead", "SOpen", "SLayoutget"),
    expected_status=NFS4ERR_WRONG_TYPE,
    actual_status=(NFS4ERR_ISDIR, NFS4ERR_INVAL, NFS4ERR_SYMLINK),
)


# KN-7: an OPEN whose stateid still awaits OPEN_CONFIRM does not survive an
# intervening SETCLIENTID on knfsd -- the later OPEN_CONFIRM (and any I/O or
# CLOSE on that stateid) comes back NFS4ERR_OLD_STATEID / NFS4ERR_BAD_STATEID.
# The model keeps the unconfirmed open valid: RFC 7530 16.33.5 / 16.34 purge a
# rebooted client's state at SETCLIENTID_CONFIRM, not at SETCLIENTID, so it
# still expects the confirm to succeed.  This is reconcilable=False: the
# server and model states have genuinely parted (the stateid is gone on one
# side), so the trace is abandoned at the confirm rather than cascading
# NFS4ERR_*_STATEID through every following op.  Candidate for a dedicated
# v4.0 client-lifecycle model-fidelity pass.
KN_7_UNCONFIRMED_OPEN_LOST = Deviation(
    id="KN-7-unconfirmed-open-across-setclientid",
    verdict=SERVER,
    spec="RFC 7530 16.33.5 / 16.34 (a rebooted client's state is purged at "
         "SETCLIENTID_CONFIRM, not at SETCLIENTID)",
    summary="an OPEN_CONFIRM (and later I/O/CLOSE) on a stateid from an "
            "unconfirmed OPEN that an intervening SETCLIENTID preceded returns "
            "OLD_STATEID/BAD_STATEID where the model expects success",
    root_cause="knfsd drops an unconfirmed open's stateid when the client "
               "issues a new SETCLIENTID before confirming it",
    candidate_fix="a dedicated v4.0 client-lifecycle pass: decide whether the "
                  "model should drop an unconfirmed open across SETCLIENTID",
    ops=("SOpenConfirm",),
    expected_status=NFS4_OK,
    actual_status=(NFS4ERR_OLD_STATEID, NFS4ERR_BAD_STATEID),
    reconcilable=False,
)




NFS4 = Registry("knfsd/nfs4", [
    KN_1_NAME_HANDLING,
    KN_3_LINK_DIR_NOTDIR,
    KN_4_RENEW_EXPIRED,
    KN_5_RENAME_SYMLINK_NOTDIR,
    KN_6_WRONG_TYPE,
    KN_7_UNCONFIRMED_OPEN_LOST,
])


NFS3 = Registry("knfsd/nfs3", [
])
