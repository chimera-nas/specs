# SPDX-FileCopyrightText: 2026 The Quint Specs Authors
#
# SPDX-License-Identifier: MIT

"""What is LEFT of the NFS-Ganesha divergence registry.

Most of what this file used to hold now lives in the MODEL, switched on per
cell by harness/nfs/configs/ganesha_*.json and declared with its citation in
quint/nfs3/corpus.schema.json and quint/nfs4/corpus.schema.json.  A model that
DESCRIBES what the server does produces a trace whose expectation already is
the truth, so replay is an exact match and nothing here has to forgive
anything.  Moved, with the id that replaced them:

  GD-1, GD-14   -> S4-change-is-coarse-ctime   (shared with knfsd)
  GD-4          -> G4-verify-wide-trivial-match
  GD-5, GD-11   -> S4-no-wrong-type            (shared with knfsd)
  GD-7          -> G4-setattr-share-denied
  GD-9          -> T_LINK_REFUSAL tolerance    (shared with knfsd)
  GD-10         -> T_RENEW_LAPSED tolerance    (shared with knfsd)
  GD-12         -> G4-exchange-id-no-confirmed-r
  GD-13 (type)  -> G4-open-type-before-exist
  GD-17         -> T_RFLAGS_CONFIRM tolerance
  GD-18         -> T_WIDE_ATTR_REFUSAL tolerance
  GD-19, GD-32  -> nothing, and GD-19 came BACK: this ganesha polices the
                   open-owner seqid gap only sometimes, in both directions,
                   so neither a deviation nor a tolerance can state it.  (The
                   knfsd cell still enables S4-owner-seqid-gap-unpoliced; the
                   Linux server does not police it.)
  GD-23, GD-24  -> S4-compound-tag-unvalidated  (shared with knfsd)
  GD-33         -> G4-seek-at-eof-not-nxio
  GD-34         -> G4-compound-tag-length-limit
  GD-35         -> the existing T_HOLE_TRACKING tolerance
  GD-25/26 (BIND_CONN) -> G4-bindconn-direction-accepted
  GD-28         -> G4-op-outside-session-inval
  GD-21 (DESTROY_CLIENTID) -> G4-destroy-clientid-busy-first
  GN-2          -> G3-link-dir-badtype
  GN-4          -> the existing T_ERROR_PRECEDENCE tolerance (shared with
                   knfsd AND with chimera, which already had it)

Retired without a replacement because the model was already corrected to the
standard and ganesha no longer diverges: the ACCESS type-masking (was
GD-2/GN-1), READLINK-on-a-directory returning INVAL (was GD-3), the
directory nlink accounting (was GD-29 -- nfs4_fs.qnt's fsInv has counted
subdirectories for some time), and DESTROY_CLIENTID against a busy client
(was GD-31 -- opDestroyClientid already gates on clientBusy).  Both of the
last two were live entries forgiving a divergence that no longer existed.

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
    # NARROWED: the DESTROY_CLIENTID arm moved into the model as
    # G4-destroy-clientid-busy-first.  What is left is the OPEN
    # name-vs-share ordering, which is downstream of GD-6's name latitude.
    ops=("SOpen",),
    expected_status=(NFS4ERR_BADCHAR,),
    actual_status=(NFS4ERR_SHARE_DENIED,),
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
    # NARROWED: the BIND_CONN direction arm moved into the model as
    # G4-bindconn-direction-accepted.  What is left is the READDIR name set,
    # which is downstream of GD-6's malformed-name latitude.
    ops=("SReaddir",),
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
    # NARROWED: the BIND_CONN direction arm moved into the model as
    # G4-bindconn-direction-accepted; the LINK name-error code is left,
    # downstream of GD-6.
    ops=("SLink",),
    expected_status=(63,),
    actual_status=(NFS4ERR_ISDIR,),
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






# GD-19: the open-owner sequence gap, and why it is here rather than in the
# model.  The walk deliberately sends an OPEN whose owner seqid is two past
# the last (nfs4_ops.qnt oseq: seqid + 2), which RFC 7530 9.1.7 makes
# NFS4ERR_BAD_SEQID.  ganesha polices it SOMETIMES: measured across the 4.0
# corpus, three OPENs answered on the name or the object (NOENT, or the
# object's status) where the model with the deviation off predicts BAD_SEQID,
# and in the run before this one -- with the model predicting the ordinary
# answer instead -- three others came back BAD_SEQID.  Both directions occur,
# which is why neither a deviation nor a tolerance fits: the two branches
# leave DIFFERENT state (one OPEN creates an object and a stateid, the other
# does not), so an accept set would keep replaying against a server the model
# has already parted from.  reconcilable=False: the owner seqid parts here and
# the trace stops.
GD_19_OWNER_SEQID_GAP = Deviation(
    id="GD-19-owner-seqid-gap",
    verdict=SERVER,
    spec="RFC 7530 9.1.7 (the open-owner seqid must be exactly one greater; "
         "enforcement is the server's)",
    summary="an OPEN with a two-past owner seqid is policed as BAD_SEQID only "
            "sometimes; the other times it is answered on its merits",
    root_cause="ganesha's open-owner sequence check does not fire uniformly",
    candidate_fix="ganesha: police the gap on every OPEN, or on none",
    ops=("SOpen",),
    expected_status=(NFS4ERR_BAD_SEQID, NFS4_OK, NFS4ERR_NOENT,
                     NFS4ERR_EXIST, NFS4ERR_SHARE_DENIED, NFS4ERR_NOTDIR),
    actual_status=(NFS4ERR_BAD_SEQID, NFS4_OK, NFS4ERR_NOENT, NFS4ERR_EXIST,
                   NFS4ERR_SHARE_DENIED, NFS4ERR_NOTDIR),
    context=lambda f, ctx: ctx.get("minor") == 0 and
                           (f.expected == NFS4ERR_BAD_SEQID or
                            f.actual == NFS4ERR_BAD_SEQID),
    reconcilable=False,
)


NFS4 = Registry("ganesha/nfs4", [
    GD_19_OWNER_SEQID_GAP,
    GD_6_NAME_HANDLING,
    GD_15_OPENMODE,
    GD_16_EXCL_VERIFIER,
    GD_20_LIFECYCLE,
    GD_21_RESIDUAL,
    GD_22_FIELD,
    GD_25_RESIDUAL2,
    GD_26_RESIDUAL2_STATUS,
    GD_27_FH_IDENTITY,
    GD_30_READ_STALE_HOLE,
])



# GN-3: CREATE disposition and precedence.  RFC 1813 3.3.8 leaves the order of
# the existence, type and permission checks (and which of GUARDED's collisions
# is EXIST vs the object's own status) to the server.  ganesha reports the
# object type (BADTYPE), a permission failure (ACCES), or EXIST where the model
# predicts EXIST or OK.  A create that one side made and the other did not parts
# the state, so reconcilable=False.
#
# NOTDIR belongs to the same entry for a specific reason: the model treats a
# name held by a symbolic link as taken (EXIST) and does not follow it, while
# ganesha's FSAL_VFS creates with openat(O_CREAT), which follows a trailing
# symlink as POSIX requires -- so the status it reports is whatever resolving
# the link's TARGET lands on (NOTDIR for a target under a non-directory,
# measured on d -> "a/b/target" with a as a FIFO).  Predicting that needs
# multi-component path resolution the model does not have, which is why this
# stays a recorded residual rather than moving into the model.
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
                   NFS3ERR_NXIO, NFS3ERR_NOTDIR),
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

# GN-6: an ACCESS on a socket or a FIFO answers NFS3ERR_INVAL instead of the
# granted subset of the requested mask.  RFC 1813 3.3.4 lists no INVAL for
# ACCESS at all, so ganesha is wrong -- but it is wrong only SOMETIMES, and
# that is why this is recorded rather than modelled.  Measured across the
# ganesha_nfs3 corpus: seven ACCESS calls on sockets and FIFOs, six answered
# with the ordinary granted mask and one (a socket, full 0x3F mask) answered
# INVAL, with no property of the call -- type, mask, mode -- separating them.
# A model branch was tried and had to be reverted: it predicted INVAL for all
# seven and failed six traces that had passed before.  Nothing is mutated, so
# replay continues.
GN_6_ACCESS_SPECIAL = Deviation(
    id="GN-6-access-special-inval",
    verdict=SERVER,
    spec="RFC 1813 3.3.4 (ACCESS returns the granted subset of the mask; no "
         "NFS3ERR_INVAL is listed for the procedure)",
    summary="ACCESS on a socket or FIFO intermittently returns NFS3ERR_INVAL "
            "where the model reports the type-applicable bits",
    root_cause="ganesha's FSAL_VFS refuses the access check on a special file "
               "under a condition this corpus has not isolated",
    candidate_fix="ganesha: answer on the granted bits for a special file as "
                  "for any other object",
    ops=("OAccess",),
    expected_status=NFS3_OK,
    actual_status=NFS3ERR_INVAL,
)


NFS3 = Registry("ganesha/nfs3", [
    GN_6_ACCESS_SPECIAL,
    GN_3_CREATE,
    GN_5_ATTR_FIELDS,
])
