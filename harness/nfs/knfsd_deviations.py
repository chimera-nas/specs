# SPDX-FileCopyrightText: 2026 The Quint Specs Authors
#
# SPDX-License-Identifier: MIT

"""What is LEFT of the Linux kernel NFS server (knfsd) divergence registry.

Most of what this file used to hold now lives in the MODEL, switched on per
cell by harness/nfs/configs/knfsd_*.json and declared with its citation in
quint/nfs3/corpus.schema.json and quint/nfs4/corpus.schema.json.  Moved, with
the id that replaced them -- note how many are S4-*, meaning the SAME id
NFS-Ganesha enables, which is what makes them evidence of an ambiguous clause
rather than of one server's bug:

  KN-3          -> T_LINK_REFUSAL tolerance      (shared with ganesha)
  KN-4, KN-12   -> T_RENEW_LAPSED tolerance      (shared with ganesha)
  KN-5          -> K4-rename-symlink-notdir      (narrower twin of chimera's
                   own D4-19-dirop-symlink-notdir)
  KN-6          -> S4-no-wrong-type              (shared with ganesha)
  KN-9          -> S4-owner-seqid-gap-unpoliced  (shared with ganesha)
  KN-15         -> S4-change-is-coarse-ctime     (shared with ganesha)
  KN-20, KN-21  -> S4-compound-tag-unvalidated   (shared with ganesha)
  KN3-2         -> K3-exclusive-mode-zero, and its NFSv4 twin
                   K4-exclusive-create-mode-zero
  KN3-3         -> the existing T_ERROR_PRECEDENCE tolerance (shared with
                   ganesha AND with chimera, which already had it)

KN-16 (a directory's nlink) was retired here during the migration and has
been restored: the model does count subdirectories, and that is exactly why
the count still differs -- knfsd holds a child created under a name the model
rejected (KN-1), so the parent carries one link the model has no object for.

See deviations.py for the contract and ganesha_deviations.py for the shape of
an entry.  Recorded against the kernel of the kvm-test-base guest the harness
boots (harness/nfs/run_nfs_mbt.sh).
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
                   NFS4ERR_NOENT, NFS4_OK, NFS4ERR_EXIST, NFS4ERR_NOTDIR),
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
    ops=("SLookup", "SRename", "SRemove", "SSecinfo", "SCreate", "SOpen"),
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
    summary="SETCLIENTID_CONFIRM STALE_CLIENTID / LINK|RENAME|LOOKUP NOENT "
            "where the model expects OK, after upstream state parted",
    root_cause="an upstream recorded deviation left knfsd without a client id "
               "or object the model still holds",
    candidate_fix="none (downstream of the recorded upstream deviation)",
    ops=("SSetclientidConfirm", "SLink", "SRename", "SLookup"),
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




# KN-16: a directory's link count after knfsd leniently accepted a malformed
# name the model rejected (KN-1).  The name became a real subdirectory on the
# server and never existed in the model, so the parent's nlink is one higher
# on the wire -- ext4 counts the child's "..", and so does the model, for the
# children it has.  Field-only and downstream of KN-1, exactly as KN-18 is for
# READDIR's name set.  (Retired once during the config migration on the
# reading that the model had learnt to count subdirectories -- it had, which
# is precisely why the count now differs by the child knfsd holds and the
# model does not.)
KN_16_ATTR_AFTER_LENIENT_NAME = Deviation(
    id="KN-16-nlink-after-lenient-name",
    verdict=SERVER,
    spec="RFC 7530 12.7 (malformed-name acceptance, KN-1) feeds through to "
         "the parent's numlinks",
    summary="a directory's nlink is one per leniently-accepted subdirectory "
            "higher than the model's",
    root_cause="knfsd holds a subdirectory created under a name the model "
               "rejected (KN-1)",
    candidate_fix="none (downstream of KN-1)",
    ops=("SGetattr",),
    field=("nlink",),
)


# KN-22: the ACCESS granted-mask differs from the model's type-masking, as
# GD-22 records for ganesha.  Field-only.
KN_22_ACCESS = Deviation(
    id="KN-22-access-mask",
    verdict=BOTH,
    spec="RFC 8881 18.1 (ACCESS grants within the server's supported set)",
    summary="ACCESS granted-mask differs from the model",
    root_cause="knfsd's ACCESS accounting differs from the model's type-masking",
    candidate_fix="triage if it recurs at volume",
    ops=("SAccess",),
    field="access",
)


NFS4 = Registry("knfsd/nfs4", [
    KN_1_NAME_HANDLING,
    KN_7_UNCONFIRMED_OPEN_LOST,
    KN_10_SHARE,
    KN_11_OPENMODE,
    KN_13_NAME_ACCESS,
    KN_14_LOCKT_GRACE,
    KN_17_LIFECYCLE,
    KN_16_ATTR_AFTER_LENIENT_NAME,
    KN_18_READDIR_NAMES,
    KN_19_CREATE_SETATTR,
    KN_22_ACCESS,
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



NFS3 = Registry("knfsd/nfs3", [
    KN3_1_CREATE,
])
