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




# KN-9: open-owner seqid enforcement, both directions.  The model drives a
# deliberate +2 gap expecting NFS4ERR_BAD_SEQID (nfs4_ops.qnt oseq: seqid + 2);
# knfsd processes the OPEN instead (NOENT / the object status).  Conversely,
# where the model expects a name/other status knfsd sometimes answers BAD_SEQID
# from its own owner bookkeeping.  RFC 7530 9.1.7 makes exactly-+1 sequencing a
# server enforcement point the two sides police differently.  reconcilable=False:
# the owner seqid parts, so the trace stops here.
KN_9_OWNER_SEQID = Deviation(
    id="KN-9-owner-seqid-enforcement",
    verdict=SERVER,
    spec="RFC 7530 9.1.7 (open-owner seqid must be exactly one greater; "
         "enforcement is the server's)",
    summary="open-owner seqid: knfsd processes a gap the model calls BAD_SEQID, "
            "or answers BAD_SEQID where the model expects another status",
    root_cause="knfsd's open-owner seqid bookkeeping diverges from the model's "
               "strict +1 gate",
    candidate_fix="none from the model; drop the BAD_SEQID probe or record",
    ops=("SOpen", "SClose", "SOpenDowngrade"),
    expected_status=(NFS4ERR_BAD_SEQID, NFS4ERR_INVAL, NFS4_OK,
                     NFS4ERR_EXIST),
    actual_status=(NFS4ERR_NOENT, NFS4_OK, NFS4ERR_BAD_SEQID, NFS4ERR_INVAL,
                   NFS4ERR_NOTDIR, NFS4ERR_BAD_STATEID, NFS4ERR_EXPIRED),
    reconcilable=False,
)

# KN-10: share reservation / open-attempt enforcement.  A second OPEN that the
# model predicts SHARE_DENIED against a deny reservation, or predicts OK, knfsd
# instead allows (OK) or rejects (NFS4ERR_INVAL) per its own share bookkeeping.
# RFC 8881 9.7 makes share-reservation conflict detection the server's; an OPEN
# knfsd accepts that the model did not creates divergent state, so
# reconcilable=False.
KN_10_SHARE = Deviation(
    id="KN-10-share-reservation-enforcement",
    verdict=SERVER,
    spec="RFC 8881 9.7 (share-reservation conflict detection is the server's)",
    summary="a second OPEN's share outcome (SHARE_DENIED/OK/INVAL) differs from "
            "the model's prediction",
    root_cause="knfsd's share-reservation bookkeeping differs from the model's",
    candidate_fix="align the model's share-conflict rule with knfsd",
    ops=("SOpen",),
    expected_status=(NFS4ERR_SHARE_DENIED, NFS4_OK),
    actual_status=(NFS4_OK, NFS4ERR_INVAL, NFS4ERR_SHARE_DENIED),
    reconcilable=False,
)

# KN-11: open-mode vs lock/IO enforcement -- the knfsd side of GD-15.  A READ or
# WRITE through a stateid whose open the model thinks lacks the matching access
# is OPENMODE/LOCKED to the model but allowed by knfsd, or the reverse.  RFC 8881
# 9.1.2 leaves the exact match under-specified.  Status-only.
KN_11_OPENMODE = Deviation(
    id="KN-11-openmode-lock-vs-io",
    verdict=BOTH,
    spec="RFC 8881 9.1.2 (NFS4ERR_OPENMODE; the open-access/lock-type match is "
         "under-specified)",
    summary="READ/WRITE vs the stateid's open access: model and knfsd enforce "
            "OPENMODE/LOCKED in opposite directions",
    root_cause="the model and knfsd calibrate the open-access-vs-IO check "
               "differently",
    candidate_fix="pin the model's opRead/opWrite openmode rule to knfsd's",
    ops=("SRead", "SWrite", "SLock"),
    expected_status=(NFS4_OK, NFS4ERR_OPENMODE, NFS4ERR_LOCKED),
    actual_status=(NFS4ERR_OPENMODE, NFS4_OK, NFS4ERR_BAD_STATEID,
                   NFS4ERR_OLD_STATEID),
)

# KN-12: RENEW of a lapsed lease succeeds (NFS4_OK) where the model, having
# retired the client id, predicts STALE_CLIENTID -- the OK-valued companion of
# KN-4.  RFC 7530 16.30.4 / 9.6.3: how long a lapsed client id survives, and
# whether a late RENEW still refreshes it, is the server's to time.
KN_12_RENEW_OK = Deviation(
    id="KN-12-renew-ok",
    verdict=SERVER,
    spec="RFC 7530 16.30.4 / 9.6.3 (a lapsed client id's survival is the "
         "server's to time)",
    summary="RENEW of a lapsed lease succeeds where the model predicts "
            "STALE_CLIENTID",
    root_cause="knfsd still holds the client id and refreshes it",
    candidate_fix="none required (defensible)",
    ops=("SRenew",),
    expected_status=NFS4ERR_STALE_CLIENTID,
    actual_status=NFS4_OK,
)

# KN-13: LOOKUP of a malformed-UTF-8 component answers NFS4ERR_ACCESS -- the
# knfsd side of KN-1's name-handling latitude, landing on ACCESS rather than a
# name-error code or NOENT.  RFC 7530 12.7 / 12.8 leave malformed-name handling
# to the server.
KN_13_NAME_ACCESS = Deviation(
    id="KN-13-name-access",
    verdict=SERVER,
    spec="RFC 7530 12.7 / 12.8 (malformed-UTF-8 component handling is the "
         "server's)",
    summary="LOOKUP of a malformed component returns NFS4ERR_ACCESS where the "
            "model predicts NFS4ERR_BADCHAR",
    root_cause="knfsd maps the component to an access failure",
    candidate_fix="none required (both conformant)",
    ops=("SLookup", "SRename", "SRemove"),
    expected_status=NFS4ERR_BADCHAR,
    actual_status=NFS4ERR_ACCESS,
)

# KN-14: a byte-range LOCKT during the grace period answers NFS4ERR_GRACE where
# the model, which does not model the reclaim grace window for LOCKT, predicts
# the ordinary result (OK or the conflicting-lock ISDIR/DENIED).  RFC 7530
# 9.6.2 / RFC 8881 8.4.2 make LOCKT reject with GRACE until reclaim completes.
KN_14_LOCKT_GRACE = Deviation(
    id="KN-14-lockt-grace",
    verdict=SERVER,
    spec="RFC 7530 9.6.2 / RFC 8881 8.4.2 (operations reject with NFS4ERR_GRACE "
         "until the reclaim grace period ends)",
    summary="LOCKT during the grace window returns NFS4ERR_GRACE where the "
            "model predicts the ordinary result",
    root_cause="the model does not gate LOCKT behind the reclaim grace window",
    candidate_fix="model: gate LOCKT on grace as OPEN already is",
    ops=("SLockt",),
    expected_status=(NFS4_OK, NFS4ERR_ISDIR),
    actual_status=NFS4ERR_GRACE,
)

# KN-15: change-attribute consistency -- the knfsd side of GD-1/GD-14.  knfsd's
# change attribute is the object's coarse ctime, so two mutations within a tick
# report the same value, or the value advances between two reads the model
# treats as unchanged.  RFC 7530 5.8.1.4 requires it differ on every change.
KN_15_CHANGE = Deviation(
    id="KN-15-change-coarse-ctime",
    verdict=SERVER,
    spec="RFC 7530 5.8.1.4 / RFC 8881 5.8.1.4 (change must differ after any "
         "modification)",
    summary="knfsd's change attribute (coarse ctime) is non-injective against "
            "the model's abstract change",
    root_cause="knfsd change = ctime; a tick boundary makes it collide or "
               "advance untracked",
    candidate_fix="a per-object modification counter (as GD-1)",
    ops=("SCreate", "SLink", "SRemove", "SRename", "SGetattr", "SOpen"),
    field=("cinfo.before", "cinfo.after", "cinfoS.before", "cinfoT.before",
           "change"),
    context=lambda f, ctx: ("unchanged on the wire" in f.detail or
                            "reported two wire values" in f.detail),
)

# KN-16: GETATTR mode/nlink on a directory whose link count or mode knfsd tracks
# differently from the model (a subdirectory bumps a POSIX directory's nlink to
# 3; the model keeps 2).  RFC 7530 5.8 leaves nlink's exact accounting to the
# filesystem.  Field-only, reconcilable.
KN_16_ATTR = Deviation(
    id="KN-16-dir-attr-accounting",
    verdict=SERVER,
    spec="RFC 7530 5.8.1 (numlinks/mode follow the backing filesystem's "
         "accounting)",
    summary="GETATTR nlink/mode on a directory differs from the model's "
            "abstract accounting",
    root_cause="knfsd's ext4 export counts a directory's subdirectories in "
               "nlink where the model keeps a flat 2",
    candidate_fix="model: count subdirectories in a directory's nlink",
    ops=("SGetattr",),
    field=("nlink", "mode"),
)


# KN-17: client-id and object lifecycle cascades.  A SETCLIENTID_CONFIRM whose
# id the model still holds but knfsd has retired answers STALE_CLIENTID; a LINK
# whose source the model created leniently (KN-1) but knfsd never did answers
# NOENT.  Both follow from an upstream recorded deviation parting the state.
# reconcilable=False.
KN_17_LIFECYCLE = Deviation(
    id="KN-17-clientid-object-lifecycle",
    verdict=SERVER,
    spec="RFC 7530 16.34 / 8.2 (client-id and filehandle validity track the "
         "server's lifecycle)",
    summary="SETCLIENTID_CONFIRM STALE_CLIENTID / LINK NOENT where the model "
            "expects OK, after upstream state parted",
    root_cause="an upstream recorded deviation left knfsd without a client id "
               "or object the model still holds",
    candidate_fix="none (downstream of the recorded upstream deviation)",
    ops=("SSetclientidConfirm", "SLink"),
    expected_status=NFS4_OK,
    actual_status=(NFS4ERR_STALE_CLIENTID, NFS4ERR_NOENT),
    reconcilable=False,
)

# KN-18: READDIR returns a different set of names than the model expects, once
# a leniently-accepted malformed name (KN-1) is present in the directory on
# knfsd but not in the model (or vice versa).  Field-only.
KN_18_READDIR_NAMES = Deviation(
    id="KN-18-readdir-names",
    verdict=SERVER,
    spec="RFC 7530 12.7 (malformed-name acceptance, KN-1) feeds through to the "
         "directory listing",
    summary="READDIR lists a different name set than the model, from a "
            "leniently-accepted malformed name",
    root_cause="knfsd holds a malformed name the model rejected (KN-1)",
    candidate_fix="none (downstream of KN-1)",
    ops=("SReaddir",),
    field="names",
)


# KN-19: residual v4 CREATE/SETATTR edges.  A CREATE whose EXIST collision the
# model predicts is accepted by knfsd (OK); a size SETATTR on a symlink the
# model calls INVAL is NFS4ERR_SYMLINK to knfsd (the POSIX-aligned type error,
# as KN-6).  Both conformant; the create parts state, so reconcilable=False.
KN_19_CREATE_SETATTR = Deviation(
    id="KN-19-create-setattr-edges",
    verdict=SERVER,
    spec="RFC 8881 18.4 / 18.30 (CREATE disposition and SETATTR-on-non-regular "
         "status are the server's)",
    summary="CREATE EXIST->OK and SETATTR INVAL->SYMLINK edges differ from the "
            "model",
    root_cause="knfsd accepts the colliding create and types the symlink "
               "setattr as SYMLINK",
    candidate_fix="align the model's create/setattr edges with knfsd",
    ops=("SCreate", "SSetattr"),
    expected_status=(NFS4ERR_EXIST, NFS4ERR_INVAL),
    actual_status=(NFS4_OK, NFS4ERR_SYMLINK),
    reconcilable=False,
)


# KN-20/21: compound-level structural divergences -- the knfsd side of
# GD-23/24.  knfsd does not reject a malformed compound tag, so a compound the
# model predicts NFS4ERR_INVAL with no results is processed (OK, one result).
# RFC 8881 2.2 leaves tag validation to the server.  Compound-level only.
KN_20_COMPOUND_STATUS = Deviation(
    id="KN-20-compound-tag-status",
    verdict=SERVER,
    spec="RFC 8881 2.2 (compound-tag validation is the server's)",
    summary="a malformed-tag compound the model calls NFS4ERR_INVAL is OK to "
            "knfsd",
    root_cause="knfsd does not reject a malformed compound tag",
    candidate_fix="model: relax compound-tag validation",
    ops=("compound",),
    expected_status=NFS4ERR_INVAL,
    actual_status=NFS4_OK,
)

KN_21_COMPOUND_RESULTS = Deviation(
    id="KN-21-compound-tag-results",
    verdict=SERVER,
    spec="RFC 8881 2.2 (the result count follows server processing of a tag "
         "the model would have rejected)",
    summary="a compound's result count differs (knfsd processed a tag the "
            "model rejected)",
    root_cause="knfsd returns a result for a compound the model dropped whole",
    candidate_fix="model: relax compound-tag validation",
    ops=("compound",),
    field="results",
    expected_value=(0, 1),
    actual_value=(0, 1),
)


NFS4 = Registry("knfsd/nfs4", [
    KN_1_NAME_HANDLING,
    KN_3_LINK_DIR_NOTDIR,
    KN_4_RENEW_EXPIRED,
    KN_5_RENAME_SYMLINK_NOTDIR,
    KN_6_WRONG_TYPE,
    KN_7_UNCONFIRMED_OPEN_LOST,
    KN_9_OWNER_SEQID,
    KN_10_SHARE,
    KN_11_OPENMODE,
    KN_12_RENEW_OK,
    KN_13_NAME_ACCESS,
    KN_14_LOCKT_GRACE,
    KN_15_CHANGE,
    KN_16_ATTR,
    KN_17_LIFECYCLE,
    KN_18_READDIR_NAMES,
    KN_19_CREATE_SETATTR,
    KN_20_COMPOUND_STATUS,
    KN_21_COMPOUND_RESULTS,
])


# KN3-1: CREATE disposition -- knfsd accepts a GUARDED/EXCLUSIVE create the
# model predicts EXIST or ISDIR for (returning OK), or reports EXIST where the
# model expects OK.  RFC 1813 3.3.8 leaves the disposition/precedence to the
# server.  reconcilable=False: a create one side made parts the state.
KN3_1_CREATE = Deviation(
    id="KN3-1-create-disposition",
    verdict=SERVER,
    spec="RFC 1813 3.3.8 (CREATE disposition/precedence is the server's)",
    summary="CREATE disposition lands on OK/EXIST differently from the model",
    root_cause="knfsd's CREATE existence/type checks differ from the model",
    candidate_fix="align the model's CREATE precedence with knfsd",
    ops=("OCreate",),
    expected_status=(NFS3ERR_EXIST, NFS3ERR_ISDIR, NFS3_OK),
    actual_status=(NFS3_OK, NFS3ERR_EXIST),
    reconcilable=False,
)

# KN3-2: an EXCLUSIVE-created file materialises mode 0 on knfsd (the client is
# expected to SETATTR its permissions), where the model -- like ganesha and
# chimera -- uses 0600.  RFC 1813 3.3.8 leaves the mode undefined until that
# SETATTR.  Field-only (the WCC mode), no state divergence.
KN3_2_EXCL_MODE = Deviation(
    id="KN3-2-exclusive-mode-zero",
    verdict=SERVER,
    spec="RFC 1813 3.3.8 (the mode of an EXCLUSIVE-created file is undefined "
         "until the client's SETATTR)",
    summary="an EXCLUSIVE-created file is mode 0 on knfsd where the model "
            "predicts 0600",
    root_cause="knfsd creates the exclusive file with no permission bits until "
               "the follow-up SETATTR",
    candidate_fix="none required (RFC-undefined); a knfsd-specific choice",
    ops=("OWrite", "OSetattr", "OCreate", "OGetattr", "ORead"),
    field=("wcc.after.mode", "attrs.mode", "mode", "file_attributes.mode"),
)

# KN3-3: RENAME onto a directory reports NFS3ERR_NOTEMPTY (the knfsd side of
# GN-4).  RFC 1813 3.3.14 leaves ISDIR vs NOTEMPTY unordered.
KN3_3_RENAME = Deviation(
    id="KN3-3-rename-notempty",
    verdict=SERVER,
    spec="RFC 1813 3.3.14 (RENAME; ISDIR vs NOTEMPTY is unordered)",
    summary="RENAME onto a directory reports NFS3ERR_NOTEMPTY where the model "
            "predicts NFS3ERR_ISDIR",
    root_cause="knfsd reports the non-empty target before its type",
    candidate_fix="none required (defensible)",
    ops=("ORename",),
    expected_status=NFS3ERR_ISDIR,
    actual_status=NFS3ERR_NOTEMPTY,
)

NFS3 = Registry("knfsd/nfs3", [
    KN3_1_CREATE,
    KN3_2_EXCL_MODE,
    KN3_3_RENAME,
])
