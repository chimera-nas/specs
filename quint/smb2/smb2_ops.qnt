// SPDX-FileCopyrightText: 2026 The Quint Specs Authors
//
// SPDX-License-Identifier: MIT

// SMB2/3 command evaluator.
//
// `Cmd` describes one command of an SMB2 message (which may be a singleton
// or a NextCommand-chained compound); `Res` the reply the server must
// produce for it.  `evalMsg` interprets a command list with real SMB2
// compound semantics: related (SMB2_FLAGS_RELATED_OPERATIONS) commands
// inherit the FileId produced by the preceding CREATE and a failure aborts
// the remainder of the chain; unrelated commands are independent
// (MS-SMB2 3.3.5.2.7).  This is the direct analogue of nfs4_ops.evalCompound
// threading current/saved filehandle.
//
// The module is pure: the generator (smb2.qnt) owns the state variables and
// calls evalMsg from its actions; smb2Test.qnt drives it directly with
// hand-built messages.
//
// Conventions:
//  - FileIds, session ids and tree ids are model handles; the harness
//    learns the wire values (the opaque (persistent,volatile) FileId,
//    SessionId, TreeId) from replies (CREATE, SESSION_SETUP, TREE_CONNECT).
//  - Where MS-SMB2/MS-FSA leave a server choice (oplock/lease grant policy,
//    the OPEN-time lease-break asymmetry) the choice is pinned by the
//    capability/policy profile (`Caps`) and annotated `// discretion:`.
//  - Only the coherency-relevant NTSTATUS codes are modeled exactly
//    (SHARING_VIOLATION, OBJECT_NAME_COLLISION, DELETE_PENDING, ...);
//    info-class/name-validation fidelity is deviation material (DESIGN §5).

module smb2ops {

    import nfs4fs.* from "../nfs/nfs4_fs"
    import smb2notify.* from "./smb2_notify"
    import smb2state.* from "./smb2_state"

    // ------------------------------------------------------------------
    // NTSTATUS (MS-ERREF 2.3.1; numerically the wire values)
    // ------------------------------------------------------------------

    pure val ST_SUCCESS = 0x00000000
    pure val ST_PENDING = 0x00000103
    pure val ST_UNSUCCESSFUL = 0xC0000001
    pure val ST_INVALID_PARAMETER = 0xC000000D
    // A data operation issued against a handle whose stream is a DirectoryStream
    // (MS-FSA 2.1.5.2 READ / 2.1.5.3 WRITE).
    pure val ST_INVALID_DEVICE_REQUEST = 0xC0000010
    pure val ST_END_OF_FILE = 0xC0000011
    pure val ST_ACCESS_DENIED = 0xC0000022
    pure val ST_OBJECT_NAME_NOT_FOUND = 0xC0000034
    pure val ST_OBJECT_NAME_COLLISION = 0xC0000035
    pure val ST_OBJECT_PATH_NOT_FOUND = 0xC000003A
    pure val ST_SHARING_VIOLATION = 0xC0000043
    pure val ST_FILE_LOCK_CONFLICT = 0xC0000054
    pure val ST_LOCK_NOT_GRANTED = 0xC0000055
    pure val ST_DELETE_PENDING = 0xC0000056
    pure val ST_RANGE_NOT_LOCKED = 0xC000007E
    pure val ST_FILE_IS_A_DIRECTORY = 0xC00000BA
    pure val ST_NOT_SUPPORTED = 0xC00000BB
    pure val ST_NETWORK_NAME_DELETED = 0xC00000CB
    pure val ST_DIRECTORY_NOT_EMPTY = 0xC0000101
    pure val ST_NOT_A_DIRECTORY = 0xC0000103
    pure val ST_FILE_CLOSED = 0xC0000128
    pure val ST_USER_SESSION_DELETED = 0xC0000203
    // A CREATE whose DH2Q CreateGuid collides with a durable open this client
    // already holds (MS-SMB2 3.3.5.9.10).
    pure val ST_DUPLICATE_OBJECTID = 0xC000022A
    // MS-SMB2 3.3.5.2.10: the reply to a MUTATING request that arrives with a
    // superseded ChannelSequence.  The exactly-once guarantee for a mutation is
    // this refusal and nothing else -- there is no reply cache on that path
    // (probe R6/4).
    pure val ST_FILE_NOT_AVAILABLE = 0xC0000467
    // Oplock/lease acknowledgment rejection arms (MS-SMB2 3.3.5.22.1/.2).
    pure val ST_INVALID_OPLOCK_PROTOCOL = 0xC00000E3
    pure val ST_REQUEST_NOT_ACCEPTED = 0xC00000D0
    pure val ST_INVALID_DEVICE_STATE = 0xC0000184
    // CHANGE_NOTIFY arms (MS-SMB2 3.3.5.19).  ST_NOTIFY_CLEANUP and
    // ST_NOTIFY_ENUM_DIR are defined with the watch layer in smb2_notify.qnt,
    // beside the rules that produce them.
    pure val ST_NOT_IMPLEMENTED = 0xC0000002
    pure val ST_CANCELLED = 0xC0000120
    pure val ST_INSUFFICIENT_RESOURCES = 0xC000009A
    pure val ST_INTERNAL_ERROR = 0xC00000E5

    // CreateAction (MS-SMB2 2.2.14).
    pure val ACT_SUPERSEDED = 0
    pure val ACT_OPENED = 1
    pure val ACT_CREATED = 2
    pure val ACT_OVERWRITTEN = 3

    // ------------------------------------------------------------------
    // Feature configuration and capability / policy profile
    // ------------------------------------------------------------------

    // Same operator-facing mode as the NFS model:
    //  - FeatOff: never exercised; traces contain no dependent steps.
    //  - FeatIfAdvertised: init nondeterministically assumes support; the
    //    corpus covers both, replay skips on mismatch.
    //  - FeatMandatory: fixed true; a server that fails to advertise fails
    //    the suite rather than passing vacuously.
    type FeatureMode = FeatOff | FeatIfAdvertised | FeatMandatory

    pure def capChoices(m: FeatureMode): Set[bool] =
        match m {
            | FeatOff => Set(false)
            | FeatIfAdvertised => Set(false, true)
            | FeatMandatory => Set(true)
        }

    type Caps = {
        // legacy oplocks advertised (set_smb_oplocks).
        oplocks: bool,
        // SMB2 leases (RqLs v1/v2) advertised (LEASING cap; set_smb_leases).
        leases: bool,
        // directory leases (set_smb_directory_leases).
        dirLeases: bool,
        // durable handles v1/v2 observed grantable.
        durable: bool,
        // SMB2_SHAREFLAG_FORCE_LEVELII_OPLOCK on the share (MS-SMB2 2.2.10):
        // every caching grant is capped to a read (LEVEL_II / R) cache, so an
        // exclusive/batch oplock or a W/H lease is stripped down to R.  This is
        // a share property, not a negotiated capability, so it is pinned per
        // instance rather than drawn at init.  (WPTS ShareForceLevel2 is the
        // single largest oplock family: 112 of its 156 green cases.)
        forceLevel2: bool,
        // discretion: does a conflicting CREATE break a peer's lease at OPEN
        // time (MS-FSA-correct = true), or does an SMB2 RqLs lease survive a
        // conflicting open and break only on the later I/O / namespace op
        // (the reference implementation's Seam-A asymmetry)?  The pure model
        // pins the MS-correct value; the coherency probe (Increment 4)
        // records the reference implementation's real answer, and a mismatch
        // is a deviation.
        leaseOpenBreak: bool
    }

    // ------------------------------------------------------------------
    // Request / reply shapes
    // ------------------------------------------------------------------

    type Disposition =
        | DispSupersede
        | DispOpen
        | DispCreate
        | DispOpenIf
        | DispOverwrite
        | DispOverwriteIf

    // DesiredAccess reduced to the R/W/H(=handle/attr)/D(=delete) axes the
    // model reasons about.
    type DesiredAccess = { r: bool, w: bool, h: bool, d: bool }

    // ShareAccess as the three shared axes (R/W/D); the denied set is the
    // complement, computed at CREATE time.
    type ShareAccess = { r: bool, w: bool, d: bool }

    // Oplock/lease request in a CREATE.  An OrLease carries the RqLs context's
    // version: a v2 context is epoch-versioned (the grant lands at the
    // requested epoch + 1) and is the only form that can carry a directory
    // lease; a v1 context is not versioned at all (epoch 0).
    type OplockReq =
        | OrNone
        | OrLevelII
        | OrExclusive
        | OrBatch
        | OrLease({ key: LeaseKey, r: bool, w: bool, h: bool,
                    v2: bool, epoch: int })

    // The lease key a CREATE identifies itself by, or -1 for a legacy oplock /
    // no oplock.  A holder under the SAME key is the requester's own grant and
    // is coalesced onto, never broken (smb_proc_create.c break_for_open).
    pure def reqLeaseKey(o: OplockReq): LeaseKey =
        match o { | OrLease(x) => x.key | _ => -1 }

    // Does this request ask for a WRITE cache?  MS-FSA routes exactly these
    // through 2.1.5.18.1 "Algorithm to Request an Exclusive Oplock" (the one
    // with the sole-Open condition); LEVEL_II and an R / RH lease are SHARED
    // requests (2.1.5.18.2) and carry no sole-Open condition at all.
    pure def reqWantsWrite(o: OplockReq): bool =
        match o {
            | OrExclusive => true
            | OrBatch => true
            | OrLease(x) => x.w
            | _ => false
        }

    // Is this an RqLs lease request (as opposed to a legacy oplock)?
    pure def reqIsLease(o: OplockReq): bool =
        match o { | OrLease(_) => true | _ => false }

    // The durable-handle context (if any) a CREATE carries (MS-SMB2 2.2.13.2.3
    // DHnQ, 2.2.13.2.5 DHnC, 2.2.13.2.11 DH2Q, 2.2.13.2.12 DH2C).
    //
    //  DurNone         no durable context at all.
    //  DurQ(x)         a durable REQUEST.  `v2` picks DH2Q (identified by a
    //                  CreateGuid) over DHnQ (no guid at all).  `persistent`
    //                  sets SMB2_DHANDLE_FLAG_PERSISTENT, which is only ever
    //                  honored on a continuously-available share -- no modeled
    //                  instance has one, so it is carried but never grants.
    //  DurC(x)         a durable RECONNECT naming a parked handle by the FileId
    //                  it kept.  `alsoQ` additionally puts the matching REQUEST
    //                  context on the same CREATE, which is the one place the
    //                  two versions differ: DH2C + DH2Q is INVALID_PARAMETER,
    //                  while DHnC + DHnQ is legal and the request is ignored
    //                  (probe D4e; MS-SMB2 3.3.5.9.7 vs 3.3.5.9.12).
    //  `withName`      the reconnect names the file instead of sending the
    //                  usual empty Name -- which a LEASED handle rejects with
    //                  INVALID_PARAMETER when the name is not its own (D4d).
    type DurableReq =
        | DurNone
        | DurQ({ v2: bool, guid: int, persistent: bool })
        | DurC({ v2: bool, fid: FileId, guid: int, persistent: bool,
                 alsoQ: bool, withName: bool })

    pure def durIsReq(d: DurableReq): bool =
        match d { | DurQ(_) => true | _ => false }

    pure def durIsReconnect(d: DurableReq): bool =
        match d { | DurC(_) => true | _ => false }

    pure def durReqV2(d: DurableReq): bool =
        match d { | DurQ(x) => x.v2 | DurC(x) => x.v2 | DurNone => false }

    pure def durReqGuid(d: DurableReq): int =
        match d { | DurQ(x) => x.guid | DurC(x) => x.guid | DurNone => -1 }

    // Which FileId a command targets: the related-compound current fid, or
    // an explicit learned fid.
    type FidSel = FidRelated | FidRef(FileId)

    type Cmd =
        | CSessionSetup({ clientSym: int })
        | CLogoff
        | CTreeConnect({ share: int })
        | CTreeDisconnect
        | CCreate({ dir: Ino, name: Name, disp: Disposition,
                    access: DesiredAccess, share: ShareAccess,
                    isDir: bool, delOnClose: bool, oplock: OplockReq,
                    durable: DurableReq })
        // The transport dropped (MS-SMB2 3.3.7.1).  Not an SMB2 command -- it
        // is the connection going away -- but the model needs it as a
        // transition, and the replayer drives it with an actual
        // client-initiated disconnect.  It targets the message's session, whose
        // trees die with it; durable opens PARK and everything else closes.
        | CDisconnect
        // A fresh connection + session presenting the SAME ClientGuid as
        // `prev`, i.e. the reconnect half of a durable handle's lifecycle.  Not
        // a session BIND (MS-SMB2 3.2.4.1.8 channel binding is out of scope):
        // a new session, a new session id, the same client identity -- which is
        // what a leased reclaim's ClientGuid check compares (3.3.5.9.7).
        | CReconnect({ prev: SessionId })
        | CClose(FidSel)
        | CRead({ fid: FidSel, off: int, len: int })
        | CWrite({ fid: FidSel, off: int, len: int, pat: int })
        | CFlush(FidSel)
        | CLock({ fid: FidSel, lo: int, hi: int, wr: bool, unlock: bool,
                  failImmediately: bool })
        | CSetEof({ fid: FidSel, sizeBlocks: int })
        | CSetDisposition({ fid: FidSel, del: bool })
        | CSetRename({ fid: FidSel, newdir: Ino, newname: Name })
        | CQueryBasic(FidSel)
        // OPLOCK_BREAK / LEASE_BREAK acknowledgment.  `asLease` picks the wire
        // shape (StructureSize 36 lease ack vs 24 oplock ack -- the server
        // discriminates on exactly that); `ackLevel` / `ackState` are what the
        // holder chooses to KEEP, which the server validates against the
        // retained mask the break asked for.
        | CBreakAck({ fid: FidSel, asLease: bool, ackLevel: OplockLevel,
                      ackState: LeaseState })
        // CHANGE_NOTIFY (MS-SMB2 2.2.35).  `cf` is the CompletionFilter as a
        // set of named bits, `obl` the OutputBufferLength in BYTES -- the
        // model computes record sizes exactly (smb2notify.recSize), so a
        // buffer that is one record short is a modeled outcome and not a
        // guess.
        | CNotify({ fid: FidSel, cf: Set[str], watchTree: bool, obl: int })
        // CANCEL (MS-SMB2 2.2.30) of the CHANGE_NOTIFY parked on `fid`.
        // CANCEL itself is never answered (3.3.5.17); what it produces is the
        // STATUS_CANCELLED completion of the request it targets, which the
        // model reports in the message's notify notes like any other async
        // completion.
        | CCancel(FidSel)

    type AttrSnap = { ftype: Ftype, nlink: int, sizeBlocks: int,
                      change: int, deletePending: bool }

    type Res =
        | RSessionSetup({ st: int, sess: SessionId })
        | RLogoff({ st: int })
        | RTreeConnect({ st: int, tree: TreeId })
        | RTreeDisconnect({ st: int })
        // `parked` records that the server emitted an async interim
        // (STATUS_PENDING) before this reply -- i.e. the open was granted but
        // held until a peer's ack-required break settled.  It is a first-class
        // wire observable (smb_async_interim.c), not an alternative status: the
        // CREATE still carries its final status here.
        // `durable` records that the reply carried a DHnQ / DH2Q response
        // context, which IS the durable grant signal on the wire: chimera emits
        // one only when it granted (build_dhnq_response / build_dh2q_response).
        // A RECONNECT grants nothing new, so it answers false (probe D3).
        | RCreate({ st: int, fid: FileId, act: int, ino: Ino,
                    caching: Caching, breaks: Set[BreakNote], parked: bool,
                    durable: bool })
        | RDisconnect({ st: int })
        | RReconnect({ st: int, sess: SessionId })
        | RClose({ st: int, gone: Ino })
        | RRead({ st: int, count: int, eof: bool, blocks: List[int] })
        | RWrite({ st: int, count: int, breaks: Set[BreakNote] })
        | RFlush({ st: int })
        | RLock({ st: int })
        | RSetEof({ st: int })
        | RSetDisposition({ st: int })
        | RSetRename({ st: int, breaks: Set[BreakNote] })
        | RQueryBasic({ st: int, attrs: AttrSnap })
        | RBreakAck({ st: int })
        // A CHANGE_NOTIFY answers in one of two shapes and the difference is
        // the whole point of the command: either it completes NOW (there were
        // buffered events, or the watch is in a terminal state) carrying
        // `recs`, or it PARKS -- an async interim STATUS_PENDING and no reply
        // until something happens.  `parked` names which, and is checked
        // against the interim the connection actually saw.
        | RNotify({ st: int, parked: bool, recs: List[NotifyRec] })
        // CANCEL produces no reply at all.  `found` records whether it hit a
        // parked request, which is what decides whether a CANCELLED completion
        // appears in the message's notes.
        | RCancel({ found: bool })

    // ------------------------------------------------------------------
    // FsStatus -> NTSTATUS (MS-FSA 2.1.5.1 status mapping)
    // ------------------------------------------------------------------

    pure def fsStatusToNt(s: FsStatus): int =
        match s {
            | FsOk => ST_SUCCESS
            | FsNoent => ST_OBJECT_NAME_NOT_FOUND
            | FsExist => ST_OBJECT_NAME_COLLISION
            | FsNotdir => ST_NOT_A_DIRECTORY
            | FsIsdir => ST_FILE_IS_A_DIRECTORY
            | FsNotempty => ST_DIRECTORY_NOT_EMPTY
            | FsInval => ST_INVALID_PARAMETER
            | FsNoxattr => ST_NOT_SUPPORTED
        }

    // ------------------------------------------------------------------
    // Access / share helpers
    // ------------------------------------------------------------------

    // A truncating disposition replaces the file's data, so it invalidates
    // every cached holder all the way to NONE rather than leaving a read cache.
    pure def truncating(d: Disposition): bool =
        d == DispSupersede or d == DispOverwrite or d == DispOverwriteIf

    // The access a CREATE asserts for SHARE ARBITRATION.  A truncating
    // disposition (SUPERSEDE / OVERWRITE / OVERWRITE_IF) must obtain WRITE at
    // open time to overwrite the data, even when DesiredAccess never asked for
    // it -- so it conflicts with a peer that denies write (MS-FSA 2.1.5.1.2
    // runs the sharing check against the access the open actually needs;
    // smb_proc_create.c:993-998 "A truncating disposition must obtain write
    // access at open time to overwrite the data").
    //
    // chimera holds that bit only TRANSIENTLY: `held_granted` is snapshotted
    // before the bit is added and the retained grant is downgraded back to it
    // once the share lease is inserted, so the HANDLE does not keep write
    // access.  The model splits the two the same way -- `wantOf` is the
    // conflict-time access and carries the transient W, while doInsertOpen
    // below stores x.access unchanged, so a later WRITE through such a handle
    // is still ACCESS_DENIED when DesiredAccess carried no write bit.
    //
    // An attribute-only open is exempt in both: chimera zeroes granted/denied/
    // held_granted after adding the truncate W when DesiredAccess carries no
    // share-mode access bit at all, and doCmdCreate's `attrOnly` gate skips the
    // share check for exactly that case.
    pure def wantOf(a: DesiredAccess, disp: Disposition): Access =
        { r: a.r, w: a.w or truncating(disp), d: a.d }

    // Denied set = complement of ShareAccess over R/W/D (MS-FSA: a bit not
    // in ShareAccess means concurrent access along that axis is denied).
    pure def denyOf(s: ShareAccess): Access =
        { r: not(s.r), w: not(s.w), d: not(s.d) }

    // A CREATE that only asks for attribute/handle access (no R/W/D) never
    // takes part in share arbitration (SMB2_SHAREMODE bypass).
    pure def attrOnly(a: DesiredAccess): bool =
        not(a.r) and not(a.w) and not(a.d)

    // ------------------------------------------------------------------
    // CREATE disposition / existence decision (MS-FSA 2.1.5.1)
    // ------------------------------------------------------------------

    // Resolve the disposition against existing state, producing the
    // filesystem effect and the CreateAction.  Returns st != SUCCESS on a
    // disposition/type error; otherwise ino names the target and the fs is
    // advanced (created / truncated / superseded) as required.
    //
    // SUPERSEDE is modeled as truncate-or-create keeping the CreateAction
    // FILE_SUPERSEDED (exact delete-recreate identity churn is deferred;
    // the coherency-relevant effect is the zero-length + action code).
    //
    // CHECK ORDER (MS-FSA 2.1.5.1.2, "Open of Existing File").  The spec runs,
    // in this order:
    //   1. `If CreateDisposition is FILE_CREATE -> STATUS_OBJECT_NAME_COLLISION`
    //      -- the very first thing the existing-file path does, before the
    //      target's TYPE is consulted at all;
    //   2. the type mismatch: in the DirectoryFile branch,
    //      CreateOptions.FILE_NON_DIRECTORY_FILE -> STATUS_FILE_IS_A_DIRECTORY;
    //      in the DataFile branch, FILE_DIRECTORY_FILE -> STATUS_NOT_A_DIRECTORY;
    //   3. only THEN, still inside the DirectoryFile branch, a truncating
    //      disposition (SUPERSEDE / OVERWRITE / OVERWRITE_IF) on a directory
    //      -> STATUS_INVALID_PARAMETER (decideByDisp's truncOver/truncSuper).
    // The model used to run 2 before 1, so a FILE_CREATE over an existing
    // directory reported FILE_IS_A_DIRECTORY (and a directory FILE_CREATE over
    // an existing file NOT_A_DIRECTORY) where the spec -- and chimera, which
    // maps the disposition onto an exclusive VFS create and answers the
    // backend's EEXIST -- says OBJECT_NAME_COLLISION.  Note 1 is hoisted alone:
    // running the whole disposition decision first would move 3 ahead of 2 and
    // answer INVALID_PARAMETER where the spec says FILE_IS_A_DIRECTORY.
    pure def decideCreate(fs: Fs, dir: Ino, name: Name, disp: Disposition,
                          isDir: bool):
            { fs2: Fs, st: int, ino: Ino, act: int } = {
        val dnode = fs.inodes.get(dir)
        if (dnode.ftype != FDir)
            { fs2: fs, st: ST_NOT_A_DIRECTORY, ino: -1, act: 0 }
        // An EMPTY relative path names `dir` itself -- the share root when
        // `dir` is ROOT.  This is how an SMB client gets a handle on a
        // DIRECTORY at all: there is no path-based directory command, so
        // enumerating a share, or watching it for changes, starts with a
        // CREATE of "".  It is always an open of something that exists, so
        // there is nothing to create and nothing to truncate; a disposition
        // that insists on creating is a parameter error.  (The generator draws
        // only FILE_OPEN, so the error arm is pinned by smb2Test rather than
        // by the corpus.)
        else if (name == "")
            if (disp == DispOpen or disp == DispOpenIf)
                { fs2: fs, st: ST_SUCCESS, ino: dir, act: ACT_OPENED }
            else { fs2: fs, st: ST_INVALID_PARAMETER, ino: -1, act: 0 }
        else {
            val ex = fsHasEnt(fs, dir, name)
            val ino = if (ex) fsChild(fs, dir, name) else -1
            val isdir = ex and fs.inodes.get(ino).ftype == FDir
            // type mismatch: a directory-create over a file (or vice versa),
            // or opening an existing object as the wrong type.
            val typeBad =
                ex and (if (isDir) not(isdir) else isdir)
            if (not(ex))
                decideByDisp(fs, dir, name, disp, isDir, ex, ino, isdir)
            // step 1: the disposition's existence verdict, ahead of the type.
            else if (disp == DispCreate)
                { fs2: fs, st: ST_OBJECT_NAME_COLLISION, ino: -1, act: 0 }
            // step 2: the type mismatch.
            else if (typeBad)
                { fs2: fs, st: if (isDir) ST_NOT_A_DIRECTORY
                               else ST_FILE_IS_A_DIRECTORY,
                  ino: -1, act: 0 }
            // step 3 lives in decideByDisp (truncate-a-directory).
            else
                decideByDisp(fs, dir, name, disp, isDir, ex, ino, isdir)
        }
    }

    pure def mkNode(isDir: bool, mode: int, chgv: int): Inode =
        if (isDir) mkDir(mode, 0, chgv) else mkFile(mode, chgv)

    pure def decideByDisp(fs: Fs, dir: Ino, name: Name, disp: Disposition,
                          isDir: bool, ex: bool, ino: Ino, isdir: bool):
            { fs2: Fs, st: int, ino: Ino, act: int } = {
        // create a fresh object under (dir,name).
        val create = {
            val r = fsMknode(fs, dir, name, mkNode(isDir, 420, fs.chg))
            { fs2: r.fs2, st: fsStatusToNt(r.st), ino: r.ino,
              act: ACT_CREATED }
        }
        // open the existing object (no content change).
        val open = { fs2: fs, st: ST_SUCCESS, ino: ino, act: ACT_OPENED }
        // truncate the existing object to zero length; a directory cannot
        // be overwritten (MS-FSA: OVERWRITE/SUPERSEDE require a data stream).
        // Two flavors differing only in the CreateAction they report.
        val truncOver =
            if (isdir) { fs2: fs, st: ST_INVALID_PARAMETER, ino: -1, act: 0 }
            else { fs2: fsResize(fs, ino, 0), st: ST_SUCCESS, ino: ino,
                   act: ACT_OVERWRITTEN }
        val truncSuper =
            if (isdir) { fs2: fs, st: ST_INVALID_PARAMETER, ino: -1, act: 0 }
            else { fs2: fsResize(fs, ino, 0), st: ST_SUCCESS, ino: ino,
                   act: ACT_SUPERSEDED }
        match disp {
            | DispOpen =>
                if (ex) open
                else { fs2: fs, st: ST_OBJECT_NAME_NOT_FOUND, ino: -1,
                       act: 0 }
            // The `ex` arm is adjudicated by decideCreate ahead of the type
            // check (MS-FSA 2.1.5.1.2 step 1) and so never reaches here; kept
            // so decideByDisp stays total over the whole matrix.
            | DispCreate =>
                if (ex) { fs2: fs, st: ST_OBJECT_NAME_COLLISION, ino: -1,
                              act: 0 }
                else create
            | DispOpenIf =>
                if (ex) open else create
            | DispOverwrite =>
                if (ex) truncOver
                else { fs2: fs, st: ST_OBJECT_NAME_NOT_FOUND, ino: -1,
                       act: 0 }
            | DispOverwriteIf =>
                if (ex) truncOver else create
            | DispSupersede =>
                if (ex) truncSuper else create
        }
    }

    // ------------------------------------------------------------------
    // Oplock / lease grant policy (discretion, pinned by Caps)
    // ------------------------------------------------------------------

    // A force-level-2 share caps a grant to a read cache: the W and H caching
    // bits are cleared before arbitration (smb_proc_create.c
    // `req_smb &= SMB2_LEASE_READ_CACHING`), so a batch oplock lands at
    // LEVEL_II and an RWH lease at R.  Pinned by probe O10.
    pure def capForceLevel2(caps: Caps, b: LeaseState): LeaseState =
        if (caps.forceLevel2) bitsAnd(b, BITS_R) else b

    // An existing grant on f held under lease key `k` (any open), or CNone.
    //
    // A member must actually HOLD caching bits.  An RqLs open that was granted
    // NONE -- leasing not advertised (the bare-RqLs path), or the invalid
    // W/H-without-R request of MS-SMB2 3.3.5.9.8 -- records a lease key and a
    // lease-shaped reply but establishes no grant to coalesce onto: chimera
    // takes no VFS caching grant for it at all (`smb_proc_create.c`, the
    // `grant == NULL` reporting branch, which reaches
    // `chimera_vfs_state_put(file_state)` rather than sharing a grant).
    //
    // Coalescing onto such an empty record made the model report the FIRST
    // request's lease version and epoch on a later open under the same key --
    // so a v1 RqLs joining an earlier v2 bare-RqLs answered v2/epoch 1 where
    // the wire answers 0, because a v1 response context (MS-SMB2 2.2.13.2.8 /
    // 2.2.14.2.10) has no Epoch field at all and the reply follows the
    // REQUEST's version when there is no grant to inherit one from.
    pure def grantUnderKey(sdb: StateDB, f: Ino, self: FileId,
                           k: LeaseKey, sess: SessionId): Caching = {
        // A lease binds its key for as long as the lease EXISTS, which is not
        // the same as holding caching right now.  This used to require the
        // member to be above level NONE, so a lease that was granted and then
        // broken to NONE stopped binding -- and the next open under that key
        // minted a brand new lease, at a new version, under a key already bound
        // to the old one.  (Found replaying against chimera: a v1 lease on 'a'
        // under key 1, broken to NONE but still open, was re-opened v2 under
        // the same key; the model answered a fresh v2 lease at epoch 2 where
        // the server correctly reported the existing v1 lease at epoch 0.)
        //
        // MS-SMB2 3.3.5.9.8 identifies a lease by (client, lease key); a
        // LeaseState of NONE does not destroy it while an open still references
        // it.  It is the `grant` flag, not the current state, that says whether
        // there is a lease here at all -- a bare RqLs reply binds nothing.
        val members = opensOfFile(sdb, f).exclude(Set(self)).filter(fid =>
            isLeaseGrantEstablished(sdb.opens.get(fid).caching) and
            leaseKeyOf(sdb.opens.get(fid).caching) == k and
            sdb.opens.get(fid).session == sess)
        if (members.size() == 0) CNone
        else sdb.opens.get(members.fold(-1, (acc, x) =>
                 if (acc < 0 or x < acc) x else acc)).caching
    }

    // Compute the caching grant for a freshly inserted handle `self` on file f.
    //
    //  - A second open under an EXISTING lease key COALESCES onto that grant:
    //    it reports the grant's current state and epoch and never reduces it
    //    (MS-SMB2 3.3.5.9.8; probe O7).  This is checked first, so a re-open
    //    asking for less does not downgrade the lease.
    //  - W/H caching is meaningful only alongside R: a requested lease state
    //    with W or H but no R is invalid and grants NONE (3.3.5.9.8).
    //  - A WRITE cache (legacy EXCLUSIVE / BATCH, or a lease carrying W) needs
    //    sole access: MS-FSA 2.1.5.18.1 ("Algorithm to Request an Exclusive
    //    Oplock", numbered 2.1.5.17.2 in the revision this suite's older
    //    citations use) fails the request when "Open.File.OpenList contains
    //    more than one Open whose Stream is the same as Open.Stream, and
    //    NO_OPLOCK is present in Open.Stream.Oplock.State".  That clause has NO
    //    OplockKey and NO client-identity exemption -- the key exemptions in
    //    2.1.5.18.1 apply only to UPGRADING a stream that already holds an
    //    R / RH oplock, and a same-lease-key re-open never reaches the FSA
    //    layer at all (MS-SMB2 3.3.5.9.8 coalesces it -- the `joined` arm
    //    below).  So the model caps W against EVERY peer open; chimera exempts
    //    two peer shapes and that is recorded as DEVIATIONS-SMB.md S-3, not
    //    copied into the model.
    //  - HANDLE caching on a lease is capped instead against a peer open that
    //    is not itself lease-backed (probe O12): two RqLs leases coexist at
    //    R+H, but a plain open owns the handle exclusively.  Granting less than
    //    was asked for is server discretion (MS-SMB2 3.3.5.9), so this is a
    //    policy pinned by measurement, not a mandate.
    //  - A LEGACY oplock request by a client that already holds an H
    //    (handle-caching) lease on the file is granted NOTHING, at every level
    //    including LEVEL_II (probe O12[32]/O12[33]): handle caching already
    //    owns the handle and the oplock must never recall the requester's own
    //    lease (smb_proc_create.c chimera_vfs_client_holds_handle_lease).
    //  - A v2 lease is granted at the client's epoch + 1; a v1 lease is not
    //    versioned and is granted (and broken) at epoch 0 (probe O9).
    // Gated by caps.oplocks / caps.leases and capped by caps.forceLevel2.
    pure def grantCaching(sdb: StateDB, f: Ino, self: FileId,
                          oplock: OplockReq, caps: Caps,
                          sess: SessionId): Caching = {
        val others = opensOfFile(sdb, f).exclude(Set(self))
        // Parked handles that SURVIVED this open's purge (doPurgeParked) still
        // count for the sole-Open condition of MS-FSA 2.1.5.18.1: probe D7d
        // measured a fully compatible RWH-lease request behind a parked RH
        // lease being granted RH, i.e. the write cache withheld on account of a
        // holder that is not even connected.  Found by a generated trace, which
        // predicted RWH where the wire said RH.
        val survivors = parkedOnFile(sdb, f)
        val sole = others.size() == 0 and survivors.size() == 0
        // A peer open that caps the HANDLE bit of a fresh lease: it must be
        // visible to the arbitration (not attribute-only) and must not itself
        // be lease-backed (probe O12[23]-O12[31]).
        val capsHandle = others.exists(g => {
            val o = sdb.opens.get(g)
            openVisibleToGrant(o) and not(isLeaseGrant(o.caching))
        }) or survivors.exists(k => {
            // A surviving parked holder is always lease-backed in practice (a
            // parked OPLOCK holder is a batch oplock, i.e. a write cache, and
            // is therefore always purged), so this arm is defensive rather than
            // measured -- kept structurally identical to the live-open test
            // above so the two cannot drift apart.
            val o = sdb.parked.get(k).open
            openVisibleToGrant(o) and not(isLeaseGrant(o.caching))
        })
        // Does the REQUESTING client already hold an H lease on this file?
        //
        // A PARKED handle of the same client counts, and that is measured, not
        // assumed: a generated durable trace (smb2Durable/stepDurable 160x8
        // @0x61, trace 0, smallest failing prefix 96 states) requested a
        // LEVEL_II oplock on a file whose only holder was this client's own
        // PARKED R+H lease.  The model granted LEVEL_II; the wire granted
        // NOTHING -- the same answer G-4 pins for a LIVE H-lease holder
        // (O12[32], O12[33]), which is coherent with C-28: a surviving parked
        // holder is still a holder.  DEVIATIONS-SMB.md M-14.
        //
        // The parked arm compares CLIENT TAGS, because a parked handle records
        // its owner as one (there is no session left to compare).  The live arm
        // deliberately still compares SESSIONS: whether the model's lease-owner
        // identity should drop the session term is the open question Q-6, and
        // it is not settled by this trace, so it is not quietly changed here.
        val myTag = sdb.sessions.get(sess).clientTag
        val ownHandleLease = others.exists(g => {
            val o = sdb.opens.get(g)
            o.session == sess and isLeaseGrant(o.caching) and cachBits(o.caching).h
        }) or survivors.exists(k => {
            val p = sdb.parked.get(k)
            p.owner == myTag and isLeaseGrant(p.open.caching) and
                cachBits(p.open.caching).h
        })
        match oplock {
            | OrNone => CNone
            | OrLevelII =>
                if (caps.oplocks and not(ownHandleLease))
                    COplock(oplockOfBits(capForceLevel2(caps, BITS_R)))
                else CNone
            | OrExclusive =>
                if (not(caps.oplocks) or ownHandleLease) CNone
                else if (sole) COplock(oplockOfBits(capForceLevel2(caps, BITS_RW)))
                else COplock(oplockOfBits(capForceLevel2(caps, BITS_R)))
            | OrBatch =>
                if (not(caps.oplocks) or ownHandleLease) CNone
                else if (sole) COplock(oplockOfBits(capForceLevel2(caps, BITS_RWH)))
                else COplock(oplockOfBits(capForceLevel2(caps, BITS_R)))
            | OrLease(x) => {
                val joined = grantUnderKey(sdb, f, self, x.key, sess)
                // What this open would be granted on its own.  Computed for
                // both arms: the fresh grant takes it as-is, and the join uses
                // it as the ceiling for an upgrade.
                //
                // An RqLs open with leasing disabled still reports a lease --
                // with state NONE (the bare-RqLs path), so nothing is cached
                // and no break can ever stall a peer.
                val req = if (not(caps.leases) or not(x.r)) BITS_NONE
                          else capForceLevel2(caps, { r: x.r, w: x.w,
                                                      h: x.h })
                // W caching only to a sole opener (MS-FSA 2.1.5.18.1, the
                // mandate above); H caching only when no non-lease peer
                // open owns the handle (probe O12, discretion).
                val st = { r: req.r, w: req.w and sole,
                           h: req.h and not(capsHandle) }
                if (not(isLeaseGrant(joined))) {
                    CLease({ key: x.key,
                             st: st,
                             // A v2 lease is granted at the client's epoch + 1
                             // -- but ONLY when caching was actually
                             // established.  A DENIED grant (leasing not
                             // advertised, or a W/H-without-R request, which is
                             // invalid and grants NONE per 3.3.5.9.8) sets up no
                             // caching state, so its epoch does NOT advance: it
                             // is echoed back unchanged.  MS-SMB2 3.3.5.9.11 --
                             // the epoch versions the lease STATE, so with no
                             // state there is nothing to version; chimera says
                             // the same in the bare-RqLs branch of
                             // smb_proc_create.c ("No caching state was
                             // established (granted NONE), so the v2 epoch does
                             // NOT advance -- it is echoed unchanged").
                             epoch: if (not(x.v2)) 0
                                    else if (bitsEmpty(st)) x.epoch
                                    else x.epoch + 1,
                             v2: x.v2,
                             // A real grant exactly when caching was actually
                             // established -- chimera's `req_vfs != 0`.  A
                             // bare RqLs reply is not a lease and binds no key.
                             grant: not(bitsEmpty(st)) })
                } else
                    // Joining an existing lease under this key.  A join never
                    // REDUCES the lease (MS-SMB2 3.3.5.9.8; probe O7), and it
                    // may RAISE it: an open asking for caching the lease does
                    // not hold yet upgrades it, which is what chimera's claim
                    // core does (vfs_claim.c R31 -- upgrade to a strict
                    // superset, only when grantable without breaking another
                    // owner) and what the epoch exists to version
                    // (3.3.5.9.11: the epoch tracks changes to the lease
                    // STATE).  The union with `st` gives both halves at once:
                    // it can only add bits, and only ones this open would have
                    // been granted anyway.
                    //
                    // The upgrade matters most exactly where the join does: a
                    // lease broken to NONE that is still bound to its key.
                    // Re-opening under that key returns the lease to the
                    // caching it can now hold rather than leaving it dead.
                    match joined {
                        | CLease(j) => {
                            val up = { r: j.st.r or st.r,
                                       w: j.st.w or st.w,
                                       h: j.st.h or st.h }
                            if (bitsEq(up, j.st)) joined
                            else CLease({ key: j.key, st: up,
                                          // The lease keeps the version it was
                                          // established with -- the response
                                          // follows the LEASE, not this
                                          // request -- so a v1 lease stays
                                          // unversioned at epoch 0.
                                          epoch: if (j.v2) j.epoch + 1 else 0,
                                          v2: j.v2, grant: true })
                        }
                        | _ => joined
                    }
            }
        }
    }

    // ------------------------------------------------------------------
    // Command dispatch
    // ------------------------------------------------------------------

    type Acc = {
        sdb: StateDB,
        caps: Caps,
        related: bool,
        sess: SessionId,
        tree: TreeId,
        cfid: FileId,        // current related fid (last CREATE), -1 if none
        // The two SMB2 header fields that carry the exactly-once semantics
        // (MS-SMB2 2.2.1.2).  `cs` is the request's ChannelSequence -- the
        // low 16 bits of the field a REPLY calls Status -- and `replay` is
        // SMB2_FLAGS_REPLAY_OPERATION (0x20000000).  Both belong to the
        // message rather than the command: the model applies one header to a
        // whole compound, and the replayer stamps every element of it.
        cs: int,
        replay: bool,
        done: bool,
        results: List[Res],
        // CHANGE_NOTIFY completions this message owes.  They are gathered here
        // rather than emitted into `results` because they belong to no command
        // slot: an async completion is an unsolicited message on the WATCHER's
        // connection, which is usually not the connection that ran the
        // command.  Teardown commands (CLOSE, TREE_DISCONNECT, LOGOFF) add
        // theirs as they run; the event-driven ones are added by evalMsg once
        // every command has raised its events.
        notes: Set[NotifyNote],
        // Position of the command being dispatched within the compound, and
        // how many there are.  Needed by exactly one rule: a CHANGE_NOTIFY
        // that would go async anywhere but the LAST slot of a multi-command
        // compound is failed outright (MS-SMB2 <159>/<162>).
        ci: int,
        nc: int
    }

    // ------------------------------------------------------------------
    // Raising change notifications (MS-FSA "Object Store Report Change")
    // ------------------------------------------------------------------

    // Raise a change on directory `d`.  Buffering is the state layer's job;
    // this only names the classes, which is where the fidelity lives.
    pure def accEmitEv(acc: Acc, d: Ino, cls: Set[str], name: Name,
                       oldName: Name): Acc =
        acc.with("sdb", stEmitEv(acc.sdb, d, cls, name, oldName))

    // What an OPEN reports to watchers of the directory it opened in
    // (MS-FSA 2.1.5.1).  Three outcomes and only three, keyed on the
    // CreateAction the open actually took rather than on the disposition it
    // asked for:
    //
    //   CREATED      the entry appeared -- FILE_ADDED, plus STREAM_NAME for a
    //                regular file, whose default $DATA stream appears with it
    //   OVERWRITTEN  the entry was already there and its data was replaced,
    //   SUPERSEDED   which is a MODIFIED, not an ADDED
    //   OPENED       nothing.  Opening a file does not change the directory
    //                that holds it, and a watcher must not be woken for it.
    pure def createNotifyCls(act: int, isDir: bool): Set[str] =
        if (act == ACT_CREATED)
            if (isDir) Set(EV_DIR_ADDED)
            else Set(EV_FILE_ADDED, EV_STREAM_NAME)
        else if (act == ACT_OVERWRITTEN or act == ACT_SUPERSEDED)
            Set(EV_FILE_MODIFIED, EV_SIZE, EV_ATTRS, EV_STREAM_SIZE)
        else Set()

    // Complete and drop the watches of handles that are going away with their
    // session, tree or handle.  MS-SMB2 3.3.4.4: STATUS_NOTIFY_CLEANUP, which
    // carries whatever records were buffered -- the client is told what it
    // missed on the way out, not merely that it is over.
    pure def accCleanupWatches(acc: Acc, fids: Set[FileId]): Acc =
        fids.fold(acc, (a, f) => {
            val r = stCleanupWatch(a.sdb, f)
            a.with("sdb", r.sdb2).with("notes", a.notes.union(r.notes))
        })

    // The transport went away instead.  The watches die with it and NOTHING is
    // sent: there is no connection left to carry a completion, and a server
    // that tried would be writing into a closed bind.
    pure def accDropWatches(acc: Acc, fids: Set[FileId]): Acc =
        acc.with("sdb", fids.fold(acc.sdb, (d, f) => stDropWatch(d, f)))

    pure def opensOfSess(sdb: StateDB, se: SessionId): Set[FileId] =
        sdb.opens.keys().filter(f => sdb.opens.get(f).session == se)

    pure def opensOfTree(sdb: StateDB, t: TreeId): Set[FileId] =
        sdb.opens.keys().filter(f => sdb.opens.get(f).tree == t)

    pure def resolveFid(acc: Acc, sel: FidSel): FileId =
        match sel {
            | FidRelated => acc.cfid
            | FidRef(f) => f
        }

    pure def sessOk(acc: Acc): bool = acc.sdb.sessions.keys().contains(acc.sess)
    pure def treeOk(acc: Acc): bool = acc.sdb.trees.keys().contains(acc.tree)

    // Append a result and, for a related compound, stop on error (SMB2
    // first-error-stops; PENDING and SUCCESS continue).
    pure def emit(acc: Acc, r: Res, st: int): Acc =
        acc.with("results", acc.results.append(r))
           .with("done", acc.related and st != ST_SUCCESS and st != ST_PENDING)

    pure def stOf(r: Res): int =
        match r {
            | RSessionSetup(x) => x.st
            | RLogoff(x) => x.st
            | RTreeConnect(x) => x.st
            | RTreeDisconnect(x) => x.st
            | RCreate(x) => x.st
            | RClose(x) => x.st
            | RRead(x) => x.st
            | RWrite(x) => x.st
            | RFlush(x) => x.st
            | RLock(x) => x.st
            | RSetEof(x) => x.st
            | RSetDisposition(x) => x.st
            | RSetRename(x) => x.st
            | RQueryBasic(x) => x.st
            | RBreakAck(x) => x.st
            | RDisconnect(x) => x.st
            | RReconnect(x) => x.st
            | RNotify(x) => x.st
            // CANCEL has no status: it has no reply.  SUCCESS keeps a related
            // compound running, which is what the wire does -- the slot simply
            // produces nothing.
            | RCancel(_) => ST_SUCCESS
        }

    // Which FileId a command RESOLVES, or -1 when it resolves none.
    //
    // The set matters for one reason: chimera clears IsReplayEligible inside
    // chimera_smb_open_file_resolve, so every command listed here closes the
    // replay window, whatever its own status turns out to be.  Measured, not
    // inferred: probe R13/1 shows a plain READ closing it and R13/2 shows an
    // OPLOCK-form break acknowledgment closing it too (it resolves by FileId,
    // while the LEASE-form ack goes through open_file_resolve_by_lease_key and
    // does not).  CLOSE is absent because it uses a different resolver -- and
    // is moot anyway, the handle stops existing.
    pure def cmdResolvesFid(acc: Acc, c: Cmd): FileId =
        match c {
            | CRead(x) => resolveFid(acc, x.fid)
            | CWrite(x) => resolveFid(acc, x.fid)
            | CFlush(sel) => resolveFid(acc, sel)
            | CLock(x) => resolveFid(acc, x.fid)
            | CSetEof(x) => resolveFid(acc, x.fid)
            | CSetDisposition(x) => resolveFid(acc, x.fid)
            | CSetRename(x) => resolveFid(acc, x.fid)
            | CQueryBasic(sel) => resolveFid(acc, sel)
            | CBreakAck(x) => if (x.asLease) -1 else resolveFid(acc, x.fid)
            | CNotify(x) => resolveFid(acc, x.fid)
            | _ => -1
        }

    pure def dispatch(acc0: Acc, c: Cmd): Acc = {
        val rf = cmdResolvesFid(acc0, c)
        val acc =
            if (acc0.replay or rf < 0 or
                not(acc0.sdb.opens.keys().contains(rf))) acc0
            else acc0.with("sdb", doClearReplayable(acc0.sdb, rf))
        match c {
            | CSessionSetup(x) => doCmdSessionSetup(acc, x.clientSym)
            | CLogoff => doCmdLogoff(acc)
            | CTreeConnect(x) => doCmdTreeConnect(acc, x.share)
            | CTreeDisconnect => doCmdTreeDisconnect(acc)
            | CCreate(x) => doCmdCreate(acc, x)
            | CClose(sel) => doCmdClose(acc, sel)
            | CRead(x) => doCmdRead(acc, x)
            | CWrite(x) => doCmdWrite(acc, x)
            | CFlush(sel) => doCmdFlush(acc, sel)
            | CLock(x) => doCmdLock(acc, x)
            | CSetEof(x) => doCmdSetEof(acc, x)
            | CSetDisposition(x) => doCmdSetDisposition(acc, x)
            | CSetRename(x) => doCmdSetRename(acc, x)
            | CQueryBasic(sel) => doCmdQueryBasic(acc, sel)
            | CBreakAck(x) => doCmdBreakAck(acc, x)
            | CDisconnect => doCmdDisconnect(acc)
            | CReconnect(x) => doCmdReconnectSession(acc, x.prev)
            | CNotify(x) => doCmdNotify(acc, x)
            | CCancel(sel) => doCmdCancel(acc, sel)
        }
    }

    // ------------------------------------------------------------------
    // The ChannelSequence gate (MS-SMB2 3.3.5.2.10)
    // ------------------------------------------------------------------
    //
    // WHERE this sits is as load-bearing as the rule itself.  Probe R12
    // measures the order: FILE_CLOSED (no resolved Open) outranks it, and
    // ACCESS_DENIED outranks it too -- chimera resolves, rejects on access,
    // and only then consults the sequence.  So every caller below applies the
    // gate AFTER its own closed/access checks and BEFORE it touches state.
    //
    // A MUTATING op from a superseded channel is refused and changes nothing;
    // an accepted one advances the mark.  A READ is never refused, but a
    // FORWARD read still advances the mark (probe R7), which is why the
    // non-mutating form exists at all instead of simply skipping the gate.

    pure def csRefuse(acc: Acc, fid: FileId): bool =
        csStale(acc.sdb, fid, acc.cs)

    // Accept path: record the new high-water mark.
    pure def csAccept(acc: Acc, fid: FileId): Acc =
        acc.with("sdb", doAdvanceCs(acc.sdb, fid, acc.cs))

    // Non-mutating (READ): never refuses; advances only when not stale.
    pure def csObserve(acc: Acc, fid: FileId): Acc =
        if (csStale(acc.sdb, fid, acc.cs)) acc else csAccept(acc, fid)

    // --- session / tree ----------------------------------------------

    pure def doCmdSessionSetup(acc: Acc, clientSym: int): Acc = {
        val r = doSessionSetup(acc.sdb, clientSym)
        // a new session becomes the message's active session for the rest
        // of a related chain.
        emit(acc.with("sdb", r.sdb2).with("sess", r.sess),
             RSessionSetup({ st: ST_SUCCESS, sess: r.sess }), ST_SUCCESS)
    }

    // The transport drop (MS-SMB2 3.3.7.1).  Durable opens of this session
    // PARK and everything else closes; the session and its trees die with the
    // connection.  There is no reply on the wire -- the connection is gone --
    // so the status here exists only so the transition has a result to record;
    // the replayer asserts the disconnect was DELIVERED instead.
    pure def doCmdDisconnect(acc: Acc): Acc =
        if (not(sessOk(acc)))
            emit(acc, RDisconnect({ st: ST_USER_SESSION_DELETED }),
                 ST_USER_SESSION_DELETED)
        else {
            val a1 = accDropWatches(acc, opensOfSess(acc.sdb, acc.sess))
            emit(a1.with("sdb", doDisconnect(a1.sdb, a1.sess)),
                 RDisconnect({ st: ST_SUCCESS }), ST_SUCCESS)
        }

    // A fresh connection + session presenting `prev`'s ClientGuid.  `prev` need
    // not still exist -- the usual case is that it does not, because the
    // disconnect that made the reconnect necessary destroyed it -- so the tag
    // is taken from the parked handles it left behind when the session itself
    // is gone.  A reconnect naming a client nothing is known about is still a
    // perfectly good new session; it simply reclaims nothing.
    pure def doCmdReconnectSession(acc: Acc, prev: SessionId): Acc = {
        val sdb = acc.sdb
        val tag =
            if (sdb.sessions.keys().contains(prev))
                sdb.sessions.get(prev).clientTag
            else {
                val orphans = sdb.parked.keys().filter(k =>
                    sdb.parked.get(k).open.session == prev)
                if (orphans.size() == 0) prev
                else sdb.parked.get(orphans.fold(-1, (a, x) =>
                         if (a < 0 or x < a) x else a)).owner
            }
        val r = doSessionSetupAs(sdb, prev, tag)
        emit(acc.with("sdb", r.sdb2).with("sess", r.sess),
             RReconnect({ st: ST_SUCCESS, sess: r.sess }), ST_SUCCESS)
    }

    pure def doCmdLogoff(acc: Acc): Acc =
        if (not(sessOk(acc)))
            emit(acc, RLogoff({ st: ST_USER_SESSION_DELETED }),
                 ST_USER_SESSION_DELETED)
        else {
            val a1 = accCleanupWatches(acc, opensOfSess(acc.sdb, acc.sess))
            emit(a1.with("sdb", doLogoff(a1.sdb, a1.sess)),
                 RLogoff({ st: ST_SUCCESS }), ST_SUCCESS)
        }

    pure def doCmdTreeConnect(acc: Acc, share: int): Acc =
        if (not(sessOk(acc)))
            emit(acc, RTreeConnect({ st: ST_USER_SESSION_DELETED, tree: -1 }),
                 ST_USER_SESSION_DELETED)
        else {
            val r = doTreeConnect(acc.sdb, acc.sess, share)
            emit(acc.with("sdb", r.sdb2).with("tree", r.tree),
                 RTreeConnect({ st: ST_SUCCESS, tree: r.tree }), ST_SUCCESS)
        }

    pure def doCmdTreeDisconnect(acc: Acc): Acc =
        if (not(treeOk(acc)))
            emit(acc, RTreeDisconnect({ st: ST_NETWORK_NAME_DELETED }),
                 ST_NETWORK_NAME_DELETED)
        else {
            val a1 = accCleanupWatches(acc, opensOfTree(acc.sdb, acc.tree))
            emit(a1.with("sdb", doTreeDisconnect(a1.sdb, a1.tree)),
                 RTreeDisconnect({ st: ST_SUCCESS }), ST_SUCCESS)
        }

    // --- CREATE -------------------------------------------------------

    // ------------------------------------------------------------------
    // The CREATE reply cache (MS-SMB2 3.3.5.9.10)
    // ------------------------------------------------------------------
    //
    // The mechanism has NOTHING in common with the ChannelSequence rule above,
    // and conflating them is the single easiest way to get this wrong.  A
    // replayed CREATE is *answered from the original open* -- a genuine reply
    // cache, keyed by the DH2Q CreateGuid -- so its effect is NOT re-applied.
    // A replayed mutation has no cache at all; it is simply rejected when it
    // comes from a superseded channel.
    //
    // Ground truth: smb2_replay_probe.c R2-R5 and R13.  R3 is the one that
    // matters most: it asserts the exactly-once property on the EFFECT (the
    // reply's CreateAction, which a re-applied FILE_CREATE could not produce,
    // and the open COUNT, proved by handing the file to a share-conflicting
    // opener after a single close) rather than on the status code, because a
    // create applied once and one applied twice both report SUCCESS.

    // The handle-type check both replay paths share.  A replay that asks for a
    // different handle KIND than the open it matched, or for a lease under a
    // different key, is STATUS_ACCESS_DENIED.
    //
    // Note the contrast the model MUST keep: the DH2C reconnect path answers
    // OBJECT_NAME_NOT_FOUND for the very same mistake (probe R4's note, and
    // durable probe D4b/D4c).  Two mandates, 3.3.5.9.10 and 3.3.5.9.12, and one
    // rule for "the reclaim did not match" would be wrong for one of them.
    pure def replayTypeOk(reqKey: LeaseKey, openIsLease: bool,
                          openKey: LeaseKey): bool =
        (reqKey >= 0) == openIsLease and
        (not(openIsLease) or reqKey == openKey)

    // WHAT a replayed CREATE reports when it asks for something other than
    // what the open it matched was granted (probe R16, DEVIATIONS-SMB.md M-15).
    //
    // Two different rules, and a model with one is wrong for the other:
    //
    //  * a LEGACY-oplock handle reports the level the REPLAY REQUESTED, not the
    //    one the open holds -- chimera's replay reply path "echoes ... (for an
    //    oplock handle) the requested oplock level" -- and its durable response
    //    context is emitted only when that requested level is BATCH, i.e. only
    //    when the request could itself have earned durability
    //    (build_dh2q_response, citing WPTS replay-dhv2-oplock2, which expects
    //    durable_open_v2=false for a lesser replay);
    //  * a LEASE handle reports the grant's CURRENT state instead, because a
    //    coalesced lease may have been upgraded by a sibling open since this
    //    handle was granted (chimera re-reads grant->lease.mode.granted), and
    //    it keeps its durable response.
    //
    // Both are about the REPLY only: nothing about the open changes.
    pure def replayReqLevel(o: OplockReq): OplockLevel =
        match o {
            | OrLevelII => OpLevelII
            | OrExclusive => OpExclusive
            | OrBatch => OpBatch
            | _ => OpNone
        }

    pure def replayReportedCaching(c: Caching, req: OplockReq): Caching =
        if (isLeaseGrant(c)) c
        else if (replayReqLevel(req) == OpNone) CNone
        else COplock(replayReqLevel(req))

    pure def replayReportedDurable(durOn: bool, c: Caching,
                                   req: OplockReq): bool =
        durOn and (isLeaseGrant(c) or replayReqLevel(req) == OpBatch)

    pure def createErr(acc: Acc, st: int): Acc =
        emit(acc, RCreate({ st: st, fid: -1, act: 0, ino: -1,
                            caching: CNone, breaks: Set(),
                            parked: false, durable: false }), st)

    // An "oplock-transparent" stat open: attribute-only access, no
    // delete-on-close, non-truncating.  It breaks nobody (MS-FSA;
    // smb_proc_create.c break_for_open's break_trigger is exactly its inverse).
    pure def statOpen(x: DesiredAccess, d: Disposition): bool =
        attrOnly(x) and not(truncating(d))

    // ------------------------------------------------------------------
    // Durable RECONNECT (MS-SMB2 3.3.5.9.7 / 3.3.5.9.12)
    //
    // A CREATE carrying DH2C / DHnC does not resolve a name at all: it names a
    // handle that outlived its connection, by the persistent id the handle
    // kept.  chimera dispatches it (chimera_smb_durable_reconnect) BEFORE the
    // ordinary create path, so none of the disposition / share / caching logic
    // runs.  The checks below are in chimera_smb_durable_claim's order, and
    // every arm is measured by probe D4.
    // ------------------------------------------------------------------

    // The lease key the reconnect presents, or -1 when it carries no RqLs
    // context at all.
    pure def reconnectLeaseKey(opl: OplockReq): LeaseKey = reqLeaseKey(opl)

    pure def doCmdReconnect(acc, x, d) = {
        val sdb = acc.sdb
        // Malformed context combinations, checked before the registry is even
        // consulted.  DH2C must stand alone; DHnC may carry a v1 REQUEST
        // (DHnQ), which is simply ignored (probe D4e vs D5).
        if (d.alsoQ and d.v2)
            createErr(acc, ST_INVALID_PARAMETER)
        else if (not(isParked(sdb, d.fid)))
            // No parked handle with this id.  This is also where a SECOND
            // reclaim of an already-reclaimed handle lands: the first reclaim
            // re-homed it, so it is live, not parked, and a live handle is
            // never stolen.
            //
            // The two ways of not being parked are distinguishable ON THE WIRE,
            // and the model has to say which: an id that names a LIVE durable
            // open cannot be told apart, at the moment it is looked up, from
            // one whose disconnect has not been processed yet, so chimera
            // announces an async interim and retries on a timer until its
            // budget lapses (chimera_smb_durable_reconnect_retry_cb); an id
            // that names nothing at all is refused immediately with no interim.
            // Both end at OBJECT_NAME_NOT_FOUND.  Found by a generated trace
            // whose reclaim of a live durable handle drew an interim the model
            // had not predicted.
            emit(acc, RCreate({ st: ST_OBJECT_NAME_NOT_FOUND, fid: -1, act: 0,
                                ino: -1, caching: CNone, breaks: Set(),
                                parked: liveDurable(sdb, d.fid),
                                durable: false }),
                 ST_OBJECT_NAME_NOT_FOUND)
        else {
            val p = sdb.parked.get(d.fid)
            val hasLeaseCtx = reqIsLease(x.oplock)
            val myTag = sdb.sessions.get(acc.sess).clientTag
            if (d.v2 and p.guid != d.guid)
                createErr(acc, ST_OBJECT_NAME_NOT_FOUND)
            else if (d.v2 and d.persistent and not(p.persistent))
                // 3.3.5.9.12: the reconnect asked for a persistent handle but
                // the surviving open is not persistent (probe D4g).  Only DH2C
                // can ask: DHnC (2.2.13.2.5) has no Flags field at all, so a v1
                // reconnect can never carry FLAG_PERSISTENT and this arm must
                // not fire for it -- a MODEL bug found by a generated trace
                // (model INVALID_PARAMETER, wire OBJECT_NAME_NOT_FOUND).
                createErr(acc, ST_INVALID_PARAMETER)
            else if (p.hadLease and p.owner != myTag)
                // 3.3.5.9.7 binds the ClientGuid check to LEASED opens: a
                // leased handle is not visible to another client (probe D4i).
                createErr(acc, ST_OBJECT_NAME_NOT_FOUND)
            else if (p.hadLease and not(hasLeaseCtx))
                // 3.3.5.9.7: a leased handle reconnected with no RqLs context
                // at all.  Kept because the spec and chimera both name it as a
                // separate check, but note it is SUBSUMED by the lease-key
                // check below for every input this model can produce: with no
                // lease context reconnectLeaseKey() is -1, which never matches
                // a real key, so the next arm answers the same status.
                // Deleting this branch leaves every self-test passing, and
                // that was verified rather than assumed -- it is the one
                // mutation in the durable set the suite does not catch.
                createErr(acc, ST_OBJECT_NAME_NOT_FOUND)
            else if (p.hadLease and reconnectLeaseKey(x.oplock) != p.leaseKey)
                createErr(acc, ST_OBJECT_NAME_NOT_FOUND)
            else if (p.hadLease and d.withName and x.name != p.name)
                // A leased reconnect that names a different, non-empty file is
                // malformed.  An EMPTY name -- the usual reconnect form -- and
                // a non-leased reconnect both ignore the name entirely.
                createErr(acc, ST_INVALID_PARAMETER)
            else {
                // Warm reclaim: the surviving open is re-homed onto this
                // session and tree, keeping its FileId, its caching grant at
                // the same state AND epoch, and its durability -- so a second
                // drop parks it again (probe D3, D3b).  The reply reports
                // CreateAction = OPENED and carries NO durable response
                // context: a reconnect grants nothing new.
                val sdb2 = doReclaim(sdb, d.fid, acc.sess, acc.tree, acc.cs)
                emit(acc.with("sdb", sdb2).with("cfid", d.fid),
                     RCreate({ st: ST_SUCCESS, fid: d.fid, act: ACT_OPENED,
                               ino: p.open.file, caching: p.open.caching,
                               breaks: Set(), parked: false,
                               // A lone reconnect grants nothing new and its
                               // reply carries no durable context (probe D3).
                               // A v1 reconnect MAY carry a DHnQ REQUEST
                               // alongside (3.3.5.9.7), and then the reply does
                               // carry a DHnQ response context -- measured by
                               // probe D5c, and found by a generated trace that
                               // saw the context the model had not predicted.
                               durable: d.alsoQ }), ST_SUCCESS)
            }
        }
    }

    // The CREATE path, in the order MS-FSA 2.1.5.1 (and chimera's
    // smb_proc_create.c) runs it:
    //
    //   phase 1  break a conflicting HANDLE-caching holder BEFORE the share
    //            check -- it may close its deferred handle and dissolve the
    //            conflict, so the break fires even when the open is ultimately
    //            refused (smb2.oplock.batch5).  RqLs leases are SPARED here (a
    //            lease keeps H across a compatible open) and dealt with at
    //            phase 2; retained = R, or nothing for a truncating open.
    //   share    the share-reservation check.  A refused open STILL recalls
    //            handle caching (retained R|W) so the holder may relinquish and
    //            a later retry succeed (smb2.lease.break_twice).
    //   phase 2  once the open is granted, a conflicting exclusive (W) holder
    //            breaks down to R|H; a truncating open instead invalidates
    //            every holder to NONE.
    //
    // The share check therefore sits BETWEEN the two break phases rather than
    // after a single all-or-nothing break, and no result is ST_PENDING: the
    // reply carries the real status, with `parked` recording whether the server
    // had to emit an async interim first.
    pure def doCmdCreate(acc, x) =
        if (not(sessOk(acc))) createErr(acc, ST_USER_SESSION_DELETED)
        else if (not(treeOk(acc))) createErr(acc, ST_NETWORK_NAME_DELETED)
        // A durable RECONNECT bypasses the whole create path (see above).
        else if (durIsReconnect(x.durable))
            match x.durable {
                | DurC(d) => doCmdReconnect(acc, x, d)
                | _ => createErr(acc, ST_INVALID_PARAMETER)
            }
        // --- the reply cache: a REPLAYED create is answered, not executed ---
        // chimera scans this TREE's live opens first (a still-eligible open
        // carrying the guid), then the durable registry of this CLIENT (a
        // parked open).  The two scopes really do differ and the model keeps
        // them apart (chimera_smb_create_guid_replay ->
        // chimera_smb_durable_claim_by_guid).
        else if (acc.replay and durIsReq(x.durable) and durReqV2(x.durable) and
                 acc.caps.durable and
                 replayLiveMatch(acc.sdb, acc.tree,
                                 durReqGuid(x.durable)).size() > 0) {
            val fid = replayLiveMatch(acc.sdb, acc.tree,
                                      durReqGuid(x.durable)).fold(-1,
                          (a, f) => if (a < 0) f else a)
            val o = acc.sdb.opens.get(fid)
            if (not(replayTypeOk(reqLeaseKey(x.oplock),
                                 isLeaseGrant(o.caching),
                                 leaseKeyOf(o.caching))))
                createErr(acc, ST_ACCESS_DENIED)
            else
                // The ORIGINAL open, verbatim: the same FileId, the CreateAction
                // the original reported (probe R3c), the caching it holds now,
                // no breaks (nothing was arbitrated), and the durable grant
                // re-advertised exactly as the original reported it (probe R2
                // vs R3c -- present iff the original was granted).
                emit(acc.with("cfid", fid),
                     RCreate({ st: ST_SUCCESS, fid: fid, act: o.replayAct,
                               ino: o.file,
                               caching: replayReportedCaching(o.caching,
                                                              x.oplock),
                               breaks: Set(), parked: false,
                               durable: replayReportedDurable(o.durable.on,
                                                              o.caching,
                                                              x.oplock) }),
                     ST_SUCCESS)
        }
        else if (acc.replay and durIsReq(x.durable) and durReqV2(x.durable) and
                 acc.caps.durable and
                 replayParkedMatch(acc.sdb,
                     acc.sdb.sessions.get(acc.sess).clientTag,
                     durReqGuid(x.durable)).size() > 0) {
            val pk = replayParkedMatch(acc.sdb,
                         acc.sdb.sessions.get(acc.sess).clientTag,
                         durReqGuid(x.durable)).fold(-1,
                         (a, f) => if (a < 0) f else a)
            val p = acc.sdb.parked.get(pk)
            if (not(replayTypeOk(reqLeaseKey(x.oplock), p.hadLease,
                                 p.leaseKey)))
                createErr(acc, ST_ACCESS_DENIED)
            else {
                // RECLAIM: re-home the parked handle onto this session/tree,
                // exactly as a DH2C reconnect would -- but the REPLY differs.
                // A DH2C reclaim carries no DH2Q response context; a
                // replay-driven reclaim does, because the replayed request IS a
                // DH2Q create and chimera's emitters key on the request's
                // context mask (probe R4 against durable probe D3).
                val sdb1 = doReclaim(acc.sdb, pk, acc.sess, acc.tree, acc.cs)
                emit(acc.with("sdb", sdb1).with("cfid", pk),
                     RCreate({ st: ST_SUCCESS, fid: pk,
                               act: p.open.replayAct, ino: p.open.file,
                               caching: replayReportedCaching(p.open.caching,
                                                              x.oplock),
                               breaks: Set(), parked: false,
                               durable: replayReportedDurable(true,
                                                              p.open.caching,
                                                              x.oplock) }),
                     ST_SUCCESS)
            }
        }
        // MS-SMB2 3.3.5.9.10: a CreateGuid identifies ONE durable open per
        // client.  A non-replay CREATE carrying a DH2Q whose CreateGuid already
        // names a durable open of this ClientGuid -- live on any connection, or
        // parked -- collides with it and is refused STATUS_DUPLICATE_OBJECTID.
        // chimera checks this before it resolves the name, so it outranks every
        // disposition and share outcome (chimera_smb_create_guid_replay ->
        // chimera_smb_durable_claim_by_guid).
        //
        // Found by the FIRST generated durable trace, which drew two creates
        // with one CreateGuid symbol: the model said SUCCESS, the wire said
        // DUPLICATE_OBJECTID, and the wire was right.
        else if (durIsReq(x.durable) and durReqV2(x.durable) and
                 acc.caps.durable and
                 durGuidCollisionEx(acc.sdb, durReqGuid(x.durable),
                                    acc.sdb.sessions.get(acc.sess).clientTag,
                                    acc.sess, acc.replay))
            createErr(acc, ST_DUPLICATE_OBJECTID)
        // FILE_DELETE_ON_CLOSE requires DELETE access in DesiredAccess
        // (MS-FSA 2.1.5.1: an open that sets delete-on-close without DELETE
        // access is failed with STATUS_ACCESS_DENIED, checked before name
        // resolution).
        else if (x.delOnClose and not(x.access.d))
            createErr(acc, ST_ACCESS_DENIED)
        else {
            val dec = decideCreate(acc.sdb.fs, x.dir, x.name, x.disp, x.isDir)
            if (dec.st != ST_SUCCESS) createErr(acc, dec.st)
            // delete pending on the target -> DELETE_PENDING (only for an
            // existing object being opened; a fresh create has a new ino).
            else if (acc.sdb.deletePending.contains(dec.ino) and
                     dec.act == ACT_OPENED)
                createErr(acc, ST_DELETE_PENDING)
            else {
                val want = wantOf(x.access, x.disp)
                // An attribute-only open (no R/W/D in DesiredAccess) neither
                // takes part in share arbitration nor IMPOSES a deny on later
                // openers: chimera registers it as an inert (granted=0,
                // denied=0) SHARE entry -- "Attribute-only opens hold no
                // share-mode rights and impose no deny", smb_proc_create.c:1002
                // -1010, which zeroes granted/denied/held_granted whenever
                // DesiredAccess carries no SMB2_SHAREMODE_ACCESS_MASK bit.  The
                // entry still exists so the layer can answer "is there another
                // opener?", which is why it is inserted rather than skipped.
                // Storing denyOf(share) here instead would let a stat-open with
                // ShareAccess=NONE lock every later opener out.
                val trunc = truncating(x.disp)
                val stat = statOpen(x.access, x.disp) and not(x.delOnClose)
                // TWO deny values, because the open asserts one thing while it
                // is being arbitrated and retains another once it is open.
                //
                // denyCheck is what this open asserts AGAINST existing holders.
                // A truncating open is a full participant in both directions --
                // it asserts WRITE (see wantOf) and it asserts its ShareAccess
                // -- because it is going to modify the file.  Only a true STAT
                // open (attribute-only AND non-truncating) is exempt.
                //
                // deny is what the open LEAVES BEHIND on the share entry, and
                // there the attribute-only bypass is unconditional: the write
                // was transient, so an attribute-only handle denies nothing to
                // later openers however it was created.  Measured against
                // Samba, which refuses a peer's read at open time and then
                // admits the identical open once the truncating handle is
                // established (samba conformance suite, SD-3).
                val denyCheck = if (stat) ACC_NONE else denyOf(x.share)
                val deny = if (attrOnly(x.access)) ACC_NONE
                           else denyOf(x.share)
                val selfKey = reqLeaseKey(x.oplock)
                // A PARKED durable holder of this file is purged by any open
                // that would have had to break it -- which is every open except
                // an attribute-only, non-truncating one, because the parked
                // holder is by construction a BATCH / HANDLE-caching holder and
                // has nobody left to acknowledge the break (MS-SMB2 3.3.4.6).
                // Both halves are measured: probe D7 (a conflicting open takes
                // the file and the reclaim then fails) and probe D7b (an
                // attribute-only open leaves the parked handle reclaimable).
                // Purged BEFORE the share check, as chimera does -- the parked
                // handle must not contribute a sharing violation it is about to
                // stop existing for.
                val sdb1 = if (stat) acc.sdb
                           else doPurgeParked(acc.sdb, dec.ino, want, denyCheck)
                // NOTE the filesystem effect of the disposition (dec.fs2) is
                // deliberately NOT committed here.  A CREATE that goes on to
                // be REFUSED must leave the file exactly as it found it, and a
                // truncating disposition committed at this point survived into
                // the failure arms below -- so a refused OVERWRITE still
                // emptied the file (MS-FSA 2.1.5.1.2 runs the sharing check
                // before it modifies anything).  Both sides answered
                // STATUS_SHARING_VIOLATION, so nothing caught it until the
                // reads that came after did.  dec.fs2 is now applied on the
                // success path only, where the open is actually inserted.
                // Found by the samba conformance suite as SD-7.
                //
                // Nothing between here and there needs the new filesystem:
                // the purge, the break phases and the share check all read
                // `opens` and `parked`, never `fs`.
                //
                // A lease key binds to exactly ONE file per client
                // (MS-SMB2 3.3.5.9.8): reusing it on a different file is
                // STATUS_INVALID_PARAMETER, not a second grant.  Gated on the
                // server actually ADVERTISING leases: the spec conditions RqLs
                // processing on lease support, so a server with leasing off
                // ignores the context outright and with it this rule -- which
                // is what Samba does with `leases = no`, and what the model
                // used to get wrong by keying off the mere presence of the
                // context (samba conformance suite, SD-6).
                if (acc.caps.leases and selfKey >= 0 and
                    sdb1.opens.keys().exists(g => {
                        val o = sdb1.opens.get(g)
                        o.session == acc.sess and
                        leaseKeyOf(o.caching) == selfKey and
                        o.file != dec.ino
                    }))
                    emit(acc.with("sdb", sdb1),
                         RCreate({ st: ST_INVALID_PARAMETER, fid: -1, act: 0,
                                   ino: -1, caching: CNone, breaks: Set(),
                                   parked: false, durable: false }),
                         ST_INVALID_PARAMETER)
                else {
                // --- phase 1: handle-caching holders, leases spared --------
                // Phase 1 recalls only HANDLE caching and always SPARES RqLs
                // leases (a lease keeps H across a compatible open and is dealt
                // with at phase 2); a truncating open retains nothing, so a
                // batch oplock goes straight to NONE here.
                val r1 = if (trunc) BITS_NONE else BITS_R
                val h1 = if (stat) Set()
                         else breakHolders(sdb1, dec.ino, -1, BITS_H, r1, true,
                                           selfKey, acc.sess)
                // A truncating open then ALSO runs break_on_write, so a legacy
                // oplock broken here is broken a second time -- and settles
                // without an ack (see breakNotesEx).
                val n1 = breakNotesEx(sdb1, dec.ino, h1, r1, trunc)
                val sdb2a = h1.fold(sdb1, (a, fid) => doBreakOne(a, fid, r1))
                val sdb2 = if (not(trunc)) sdb2a
                           else h1.fold(sdb2a, (a, fid) =>
                               if (isLeaseGrant(a.opens.get(fid).caching)) a
                               else doAckBreak(a, fid, BITS_NONE))
                // --- share reservation check (MS-FSA SharingViolation) -----
                // Skipped only for a true STAT open -- attribute-only AND
                // non-truncating.  It used to be skipped for any
                // attribute-only open, which threw away the whole point of
                // `want`: wantOf() adds WRITE for a truncating disposition
                // precisely so it can conflict with a peer that denies write,
                // and the one case where the truncate is the ONLY source of
                // that write was exactly the case that never arbitrated.  The
                // model's own statOpen() already draws the line in the right
                // place (samba conformance suite, SD-3).
                if (not(stat) and
                    shareConflict(sdb2, dec.ino, want, denyCheck)) {
                    val h2 = breakHolders(sdb2, dec.ino, -1, BITS_H, BITS_RW,
                                          false, selfKey, acc.sess)
                    val n2 = breakNotes(sdb2, dec.ino, h2, BITS_RW)
                    val sdb3 = h2.fold(sdb2, (a, fid) =>
                                   doBreakOne(a, fid, BITS_RW))
                    emit(acc.with("sdb", sdb3),
                         RCreate({ st: ST_SHARING_VIOLATION, fid: -1, act: 0,
                                   ino: -1, caching: CNone,
                                   breaks: n1.union(n2), parked: false,
                                   durable: false }),
                         ST_SHARING_VIOLATION)
                } else {
                    // --- insert the open ------------------------------------
                    // The disposition's create/truncate lands HERE, on the
                    // success path, and nowhere else (see SD-7 above).
                    val ins = doInsertOpen(sdb2.with("fs", dec.fs2),
                        acc.sess, acc.tree, dec.ino,
                        x.dir, x.name,
                        { r: x.access.r, w: x.access.w, h: x.access.h,
                          d: x.access.d },
                        // The CREATE's own ChannelSequence seeds the handle's
                        // high-water mark (probe R11): an Open does NOT start
                        // at zero.
                        deny, x.delOnClose, acc.cs)
                    // --- phase 2: exclusive (W) holders ---------------------
                    val r2 = if (trunc) BITS_NONE else BITS_RH
                    // A truncating open replaces the data, so it invalidates
                    // every cached holder (break_on_write); a plain
                    // conflicting open only recalls the exclusive WRITE cache.
                    val t2 = if (trunc) BITS_RWH else BITS_W
                    val h2 = if (stat or not(acc.caps.leaseOpenBreak)) Set()
                             else breakHolders(ins.sdb2, dec.ino, ins.fid, t2,
                                               r2, false, selfKey, acc.sess)
                    val n2 = breakNotes(ins.sdb2, dec.ino, h2, r2)
                    val sdb3 = h2.fold(ins.sdb2, (a, fid) =>
                                   doBreakOne(a, fid, r2))
                    // --- grant this open's own caching ----------------------
                    val gr = grantCaching(sdb3, dec.ino, ins.fid, x.oplock,
                                          acc.caps, acc.sess)
                    val sdb4 = doSetCaching(sdb3, ins.fid, gr)
                    val sdb4b = if (x.delOnClose)
                                   sdb4.with("deletePending",
                                             sdb4.deletePending.union(Set(dec.ino)))
                               else sdb4
                    // --- grant this open's DURABILITY -----------------------
                    // MS-SMB2 3.3.5.9.6 / 3.3.5.9.10, measured by probe D1:
                    // the durable request is honored only when the caching
                    // grant that was actually made is a BATCH oplock or a
                    // HANDLE-caching lease -- and only when the server
                    // advertises durable handles at all (caps.durable, i.e.
                    // config persistent_handles; chimera returns immediately
                    // from chimera_smb_create_grant_durable otherwise).
                    val durOk = acc.caps.durable and durIsReq(x.durable) and
                                durableEligible(gr)
                    val durSt: DurState =
                        if (not(durOk)) DUR_NONE
                        else { on: true, v2: durReqV2(x.durable),
                               guid: if (durReqV2(x.durable))
                                         durReqGuid(x.durable) else -1,
                               // Persistence needs a continuously-available
                               // share, which no modeled instance has (probe
                               // D11 covers it deterministically instead).
                               persistent: false }
                    val sdb5 = doSetDurable(sdb4b, ins.fid, durSt)
                    // --- replay ELIGIBILITY ---------------------------------
                    // Set by the DH2Q CONTEXT, not by the durable GRANT: probe
                    // R2 replays a create that was refused durability for want
                    // of a caching oplock and still gets the original handle
                    // back.  Still gated on caps.durable, because
                    // chimera_smb_create_grant_durable -- which is where the
                    // create_guid is recorded at all -- returns immediately
                    // when persistent_handles is off.
                    val sdb6 = if (acc.caps.durable and durIsReq(x.durable) and
                                   durReqV2(x.durable))
                                   doSetReplayable(sdb5, ins.fid,
                                                   durReqGuid(x.durable),
                                                   dec.act)
                               else sdb5
                    // The directory this open changed, if it changed it.
                    val sdb7 = stEmitEv(sdb6, x.dir,
                                        createNotifyCls(dec.act, x.isDir),
                                        x.name, "")
                    emit(acc.with("sdb", sdb7).with("cfid", ins.fid),
                         RCreate({ st: ST_SUCCESS, fid: ins.fid,
                                   act: dec.act, ino: dec.ino,
                                   caching: gr, breaks: n1.union(n2),
                                   // the open was granted but is held until a
                                   // peer's ack-required break settles: the
                                   // server emits an async interim first
                                   // (chimera_vfs_state_caching_breaking).
                                   parked: breakInProgress(sdb6, dec.ino,
                                                           ins.fid),
                                   durable: durOk }),
                         ST_SUCCESS)
                }
                }
            }
        }

    // --- fid-targeted ops --------------------------------------------

    pure def fidBad(acc: Acc): bool =
        not(sessOk(acc)) or not(treeOk(acc))

    // Does this handle name a DIRECTORY?  A READ or a WRITE issued through a
    // directory handle is STATUS_INVALID_DEVICE_REQUEST (MS-FSA 2.1.5.2 /
    // 2.1.5.3: "If Open.Stream.StreamType is DirectoryStream, the operation
    // MUST be failed with STATUS_INVALID_DEVICE_REQUEST") -- adjudicated on the
    // stream type BEFORE the access mask, the offset and any lock, so it never
    // degenerates into END_OF_FILE or ACCESS_DENIED.
    pure def isDirOpen(acc: Acc, fid: FileId): bool =
        fsGet(acc.sdb.fs, acc.sdb.opens.get(fid).file).ftype == FDir

    pure def doCmdClose(acc: Acc, sel: FidSel): Acc = {
        val fid = resolveFid(acc, sel)
        if (not(acc.sdb.opens.keys().contains(fid)))
            emit(acc, RClose({ st: ST_FILE_CLOSED, gone: -1 }), ST_FILE_CLOSED)
        else {
            val o = acc.sdb.opens.get(fid)
            val wasDir = fsGet(acc.sdb.fs, o.file).ftype == FDir
            // Does this close UNLINK?  Only the last close of a delete-pending
            // handle whose name still resolves to its own inode does; doClose
            // also reports `gone` when it reaps a rename-orphaned inode, and
            // that removed no directory entry -- the entry went at rename time
            // and was reported then, so reporting it again here would invent a
            // REMOVED record no directory ever saw.
            val unlinks = opensOfFile(acc.sdb, o.file).exclude(Set(fid))
                              .size() == 0 and
                acc.sdb.deletePending.contains(o.file) and
                fsHasEnt(acc.sdb.fs, o.dir, o.name) and
                fsChild(acc.sdb.fs, o.dir, o.name) == o.file
            // The handle's own watch dies FIRST: chimera tears the notify
            // state down at the top of the close handler, before the close
            // path raises anything, so a watch on the directory being closed
            // never sees the events its own close produces.
            val a1 = accCleanupWatches(acc, Set(fid))
            val r = doClose(a1.sdb, fid)
            // MS-FSA 2.1.5.4: a handle that WROTE reports the file's settled
            // size and write time to the parent on the way out -- the write
            // changed the file, the close is what makes that change visible in
            // the directory.
            //
            // ONE class, not three.  FILE_MODIFIED is reachable from both
            // FILE_NOTIFY_CHANGE_SIZE and FILE_NOTIFY_CHANGE_LAST_WRITE
            // (cfToMask), so a watcher of either is woken by it without the
            // event having to name their classes.  What it deliberately does
            // NOT raise is ATTRS: closing a file settles its length and write
            // time, it does not change the file's attributes, and a client
            // watching FILE_NOTIFY_CHANGE_ATTRIBUTES alone must not be woken.
            val sdbM = if (o.modified)
                stEmitEv(r.sdb2, o.dir, Set(EV_FILE_MODIFIED), o.name, "")
                else r.sdb2
            val sdbR = if (not(unlinks)) sdbM
                else stEmitDelete(
                         stEmitEv(sdbM, o.dir,
                                  Set(if (wasDir) EV_DIR_REMOVED
                                      else EV_FILE_REMOVED),
                                  o.name, ""),
                         o.file)
            emit(a1.with("sdb", sdbR),
                 RClose({ st: ST_SUCCESS, gone: r.gone }), ST_SUCCESS)
        }
    }

    pure def doCmdRead(acc, x) = {
        val fid = resolveFid(acc, x.fid)
        if (not(acc.sdb.opens.keys().contains(fid)))
            emit(acc, RRead({ st: ST_FILE_CLOSED, count: -1, eof: false,
                              blocks: [] }), ST_FILE_CLOSED)
        else if (isDirOpen(acc, fid))
            // MS-FSA 2.1.5.2: a READ on a DirectoryStream handle is refused on
            // the stream type, ahead of the access/offset checks -- so it is
            // never END_OF_FILE, which is what a directory's zero data length
            // would otherwise produce.
            emit(acc, RRead({ st: ST_INVALID_DEVICE_REQUEST, count: -1,
                              eof: false, blocks: [] }),
                 ST_INVALID_DEVICE_REQUEST)
        else {
            val o = acc.sdb.opens.get(fid)
            if (not(o.granted.r))
                emit(acc, RRead({ st: ST_ACCESS_DENIED, count: -1,
                                  eof: false, blocks: [] }), ST_ACCESS_DENIED)
            else {
                // MS-SMB2 3.3.5.2.10: a READ is never REFUSED for a stale
                // ChannelSequence, but a FORWARD one still ADVANCES the Open's
                // high-water mark (probe R7) -- which is why this is a distinct
                // operation rather than "skip the gate".  It sits after the
                // access check and before the lock check, exactly where
                // smb_proc_read.c:271 sits (probe R12 pins that ACCESS_DENIED
                // outranks the sequence on the I/O path).
                val a1 = csObserve(acc, fid)
                // mandatory byte-range lock enforcement (MS-FSA 2.1.4.2).
                if (rangeIoConflict(a1.sdb, o.file, fid, x.off, x.len, false))
                    emit(a1, RRead({ st: ST_FILE_LOCK_CONFLICT, count: -1,
                                     eof: false, blocks: [] }),
                         ST_FILE_LOCK_CONFLICT)
                else {
                    val nd = a1.sdb.fs.inodes.get(o.file)
                    val rd = fsReadData(nd, x.off, x.len)
                    // a read wholly at/after EOF returns STATUS_END_OF_FILE.
                    if (x.off >= nd.sizeBlocks and x.len > 0)
                        emit(a1, RRead({ st: ST_END_OF_FILE, count: 0,
                                         eof: true, blocks: [] }),
                             ST_END_OF_FILE)
                    else
                        emit(a1, RRead({ st: ST_SUCCESS, count: rd.count,
                                         eof: rd.eof, blocks: rd.syms }),
                             ST_SUCCESS)
                }
            }
        }
    }

    pure def doCmdWrite(acc0, x) = {
        val fid = resolveFid(acc0, x.fid)
        if (not(acc0.sdb.opens.keys().contains(fid)))
            emit(acc0, RWrite({ st: ST_FILE_CLOSED, count: -1, breaks: Set() }),
                 ST_FILE_CLOSED)
        else if (isDirOpen(acc0, fid))
            // MS-FSA 2.1.5.3, the WRITE twin of the READ guard above.  Without
            // it the model let a directory handle accumulate data blocks, which
            // then made a later directory READ report SUCCESS.
            emit(acc0, RWrite({ st: ST_INVALID_DEVICE_REQUEST, count: -1,
                               breaks: Set() }), ST_INVALID_DEVICE_REQUEST)
        else {
            val o = acc0.sdb.opens.get(fid)
            if (not(o.granted.w))
                emit(acc0, RWrite({ st: ST_ACCESS_DENIED, count: -1,
                                   breaks: Set() }), ST_ACCESS_DENIED)
            // MS-SMB2 3.3.5.2.10: a WRITE from a SUPERSEDED channel is refused
            // so a delayed retry cannot clobber newer data -- and it must
            // change NOTHING, which is the property probe R6/2 asserts on the
            // file's content rather than on this status.  The gate sits AFTER
            // the access check (probe R12: a write that is both unauthorized
            // and stale answers ACCESS_DENIED) and before the lock check,
            // matching smb_proc_write.c:294.
            else if (csRefuse(acc0, fid))
                emit(acc0, RWrite({ st: ST_FILE_NOT_AVAILABLE, count: -1,
                                   breaks: Set() }), ST_FILE_NOT_AVAILABLE)
            else {
            // The mark advances the MOMENT the gate is passed, not when the
            // write finally lands: chimera advances inside
            // chimera_smb_channel_sequence_stale (smb_proc_write.c:294), which
            // runs BEFORE the byte-range-lock check (:356).  So a write that
            // clears the gate and is then refused for a lock conflict has
            // still moved the mark, and a following request at the earlier
            // sequence is stale.  Modeling the advance on the success path
            // only would have been wrong for exactly that interleaving.
            val acc = csAccept(acc0, fid)
            if (rangeIoConflict(acc.sdb, o.file, fid, x.off, x.len, true))
                emit(acc, RWrite({ st: ST_FILE_LOCK_CONFLICT, count: -1,
                                   breaks: Set() }), ST_FILE_LOCK_CONFLICT)
            else {
                // break_reads_for_write: this write recalls every OTHER
                // handle's read cache to NONE (protocol-agnostic, Seam 4a).
                // The write itself completes -- the D4-12 ordering hazard
                // (write lands before the recall drains) applies here too.
                // A holder under the writer's OWN lease key is exempt
                // (chimera_vfs_lease_smb2_same_key).
                val selfKey = leaseKeyOf(o.caching)
                val holders = breakHolders(acc.sdb, o.file, fid, BITS_RWH,
                                           BITS_NONE, false, selfKey,
                                           o.session)
                val notes = breakNotes(acc.sdb, o.file, holders, BITS_NONE)
                val sdb1 = holders.fold(acc.sdb, (a, h) =>
                               doBreakOne(a, h, BITS_NONE))
                // A LEVEL_II oplock confers no write coherence, so a write
                // through the very handle that holds one must break the
                // writer's OWN read cache to NONE (vfs_state.c: "a write by
                // one LEVEL_II holder breaks BOTH LEVEL_II oplocks").  A
                // grant carrying W (exclusive/batch, or a W lease) is the
                // writer's own coherent cache and survives.
                val selfII = match o.caching {
                    | COplock(l) => l == OpLevelII
                    | _ => false
                }
                val selfNotes = if (selfII)
                                    breakNotes(sdb1, o.file, Set(fid), BITS_NONE)
                                else Set()
                val sdb2 = if (selfII) doBreakOne(sdb1, fid, BITS_NONE) else sdb1
                val wr = fsWrite(sdb2.fs, o.file, x.off, x.len, x.pat)
                // MS-FSA 2.1.5.3: a write changes the file's data and length.
                // Beyond the generic MODIFIED class it touches the data
                // STREAM's contents and size, so a watcher that asked only for
                // FILE_NOTIFY_CHANGE_STREAM_WRITE or _STREAM_SIZE must still
                // be told -- the stream classes widen who hears about the
                // write, they do not change what it is called
                // (FILE_ACTION_MODIFIED either way).
                val sdb3 = stEmitEv(doMarkModified(sdb2, fid).with("fs", wr.fs2),
                                    o.dir,
                                    Set(EV_FILE_MODIFIED, EV_STREAM_WRITE,
                                        EV_STREAM_SIZE),
                                    o.name, "")
                emit(acc.with("sdb", sdb3),
                     RWrite({ st: ST_SUCCESS, count: x.len,
                              breaks: notes.union(selfNotes) }),
                     ST_SUCCESS)
            }
            }
        }
    }

    pure def doCmdFlush(acc: Acc, sel: FidSel): Acc = {
        val fid = resolveFid(acc, sel)
        if (not(acc.sdb.opens.keys().contains(fid)))
            emit(acc, RFlush({ st: ST_FILE_CLOSED }), ST_FILE_CLOSED)
        // MS-SMB2 3.3.5.13: FLUSH is a WRITE-side operation and the handle
        // must carry write access for it.  The model used to answer SUCCESS on
        // any open handle, which made a flush through a read-only or
        // attribute-only handle succeed; Samba refuses it, and so does Windows
        // (FlushFileBuffers on a read-only handle fails ERROR_ACCESS_DENIED).
        // Found by the samba conformance suite as SD-1.
        else if (not(acc.sdb.opens.get(fid).granted.w))
            emit(acc, RFlush({ st: ST_ACCESS_DENIED }), ST_ACCESS_DENIED)
        else
            emit(acc, RFlush({ st: ST_SUCCESS }), ST_SUCCESS)
    }

    pure def doCmdLock(acc, x) = {
        val fid = resolveFid(acc, x.fid)
        if (not(acc.sdb.opens.keys().contains(fid)))
            emit(acc, RLock({ st: ST_FILE_CLOSED }), ST_FILE_CLOSED)
        // MS-SMB2 3.3.5.14: a byte-range lock needs FILE_READ_DATA or
        // FILE_WRITE_DATA on the handle.  The model used to perform no access
        // check at all, so it granted locks on DELETE-only and attribute-only
        // handles.  Samba refuses those -- though it answers
        // STATUS_INVALID_HANDLE where the spec calls for STATUS_ACCESS_DENIED,
        // which remains a recorded Samba deviation (SD-2).
        else if (not(acc.sdb.opens.get(fid).granted.r) and
                 not(acc.sdb.opens.get(fid).granted.w))
            emit(acc, RLock({ st: ST_ACCESS_DENIED }), ST_ACCESS_DENIED)
        else {
            val o = acc.sdb.opens.get(fid)
            if (x.unlock)
                if (not(rangeLockedBy(acc.sdb, o.file, fid, x.lo, x.hi)))
                    emit(acc, RLock({ st: ST_RANGE_NOT_LOCKED }),
                         ST_RANGE_NOT_LOCKED)
                else
                    emit(acc.with("sdb", doUnlock(acc.sdb, o.file, fid,
                                                  x.lo, x.hi)),
                         RLock({ st: ST_SUCCESS }), ST_SUCCESS)
            else if (lockConflict(acc.sdb, o.file, fid, x.lo, x.hi, x.wr))
                // FAIL_IMMEDIATELY -> LOCK_NOT_GRANTED; a blocking lock that
                // cannot be granted synchronously is modeled the same way
                // (async blocking-grant observability is deferred, DESIGN
                // "deliberately deferred").
                emit(acc, RLock({ st: if (x.failImmediately) ST_LOCK_NOT_GRANTED
                                       else ST_LOCK_NOT_GRANTED }),
                     ST_LOCK_NOT_GRANTED)
            else
                emit(acc.with("sdb", doLock(acc.sdb, o.file, fid,
                                            x.lo, x.hi, x.wr)),
                     RLock({ st: ST_SUCCESS }), ST_SUCCESS)
        }
    }

    // SET_INFO's ChannelSequence gate sits in the OPPOSITE place to WRITE's,
    // and the asymmetry is measured, not assumed: chimera consults the sequence
    // in chimera_smb_set_info immediately after resolving the handle and BEFORE
    // the per-info-class switch (smb_proc_set_info.c:509), so on SET_INFO a
    // stale sequence outranks the very ACCESS_DENIED that outranks it on WRITE.
    // Probe R12 drives exactly that pair: the same read-only handle, the same
    // stale sequence, ACCESS_DENIED from WRITE and FILE_NOT_AVAILABLE from
    // SET_INFO.
    pure def doCmdSetEof(acc, x) = {
        val fid = resolveFid(acc, x.fid)
        if (not(acc.sdb.opens.keys().contains(fid)))
            emit(acc, RSetEof({ st: ST_FILE_CLOSED }), ST_FILE_CLOSED)
        else if (csRefuse(acc, fid))
            emit(acc, RSetEof({ st: ST_FILE_NOT_AVAILABLE }),
                 ST_FILE_NOT_AVAILABLE)
        else {
            val a1 = csAccept(acc, fid)
            val o = a1.sdb.opens.get(fid)
            if (not(o.granted.w))
                emit(a1, RSetEof({ st: ST_ACCESS_DENIED }), ST_ACCESS_DENIED)
            else
                // MS-FSA 2.1.5.14.5 (SetFileEndOfFileInformation): a length
                // change is a SIZE change and, because it changes the file's
                // data extent, a LAST_WRITE one -- which is why the model
                // raises FILE_MODIFIED alongside SIZE rather than treating the
                // two filters as alternatives.
                emit(a1.with("sdb",
                         stEmitEv(a1.sdb.with("fs",
                                      fsResize(a1.sdb.fs, o.file,
                                               x.sizeBlocks)),
                                  o.dir,
                                  Set(EV_SIZE, EV_FILE_MODIFIED,
                                      EV_STREAM_SIZE),
                                  o.name, "")),
                     RSetEof({ st: ST_SUCCESS }), ST_SUCCESS)
        }
    }

    pure def doCmdSetDisposition(acc0, x) = {
        val fid = resolveFid(acc0, x.fid)
        if (not(acc0.sdb.opens.keys().contains(fid)))
            emit(acc0, RSetDisposition({ st: ST_FILE_CLOSED }), ST_FILE_CLOSED)
        else if (csRefuse(acc0, fid))
            emit(acc0, RSetDisposition({ st: ST_FILE_NOT_AVAILABLE }),
                 ST_FILE_NOT_AVAILABLE)
        else {
            val acc = csAccept(acc0, fid)
            val o = acc.sdb.opens.get(fid)
            // MS-FSA 2.1.5.14.3 (FileDispositionInformation): the set
            // requires DELETE access on the handle -- marking or UNmarking a
            // file for deletion is a delete-authorization decision -- and
            // without it the operation MUST fail ACCESS_DENIED.  chimera does
            // not check (smb_proc_set_info.c has no access check of any kind,
            // DEVIATIONS-SMB.md S-4), so the model stays spec-first here and
            // the generator draws only DELETE-capable handles.
            if (not(o.granted.d))
                emit(acc, RSetDisposition({ st: ST_ACCESS_DENIED }),
                     ST_ACCESS_DENIED)
            else
            // a directory must be empty to set delete-on-close.
            if (x.del and fsGet(acc.sdb.fs, o.file).ftype == FDir and
                fsGet(acc.sdb.fs, o.file).ents.keys().size() > 0)
                emit(acc, RSetDisposition({ st: ST_DIRECTORY_NOT_EMPTY }),
                     ST_DIRECTORY_NOT_EMPTY)
            else
                emit(acc.with("sdb", doSetDisposition(acc.sdb, fid, x.del)),
                     RSetDisposition({ st: ST_SUCCESS }), ST_SUCCESS)
        }
    }

    pure def doCmdSetRename(acc0, x) = {
        val fid = resolveFid(acc0, x.fid)
        if (not(acc0.sdb.opens.keys().contains(fid)))
            emit(acc0, RSetRename({ st: ST_FILE_CLOSED, breaks: Set() }),
                 ST_FILE_CLOSED)
        else if (csRefuse(acc0, fid))
            // A RENAME is the sharpest case for the exactly-once rule: it is
            // the one mutating op that genuinely cannot be applied twice.  A
            // stale one must leave the namespace exactly as it was.
            emit(acc0, RSetRename({ st: ST_FILE_NOT_AVAILABLE, breaks: Set() }),
                 ST_FILE_NOT_AVAILABLE)
        else {
            val acc = csAccept(acc0, fid)
            val o = acc.sdb.opens.get(fid)
            // MS-FSA 2.1.5.14.11.1: a rename removes the old name from its
            // parent and adds a new one, so the SOURCE handle must hold
            // DELETE; without it the operation MUST fail ACCESS_DENIED.  The
            // gate runs BEFORE the destination-existence probe, so a target
            // collision on an unauthorized handle still reports the
            // authorization error rather than masking it (chimera gates in the
            // same place and cites the same clause; DEVIATIONS-SMB.md M-20 --
            // the model used to have no access check here at all and answered
            // SUCCESS for every read-only handle).
            if (not(o.granted.d))
                emit(acc, RSetRename({ st: ST_ACCESS_DENIED, breaks: Set() }),
                     ST_ACCESS_DENIED)
            else
            // SetFileRenameInformation with ReplaceIfExists = false
            // (MS-FSA 2.1.5.14.11): a rename onto an existing different name
            // fails with OBJECT_NAME_COLLISION.  Modeling the no-replace case
            // keeps the target's identity/handles intact -- replacing a
            // still-open directory target is exactly what the fs core cannot
            // represent, and MS rename does not replace directories anyway.
            if (fsHasEnt(acc.sdb.fs, x.newdir, x.newname) and
                fsChild(acc.sdb.fs, x.newdir, x.newname) != o.file)
                emit(acc, RSetRename({ st: ST_OBJECT_NAME_COLLISION,
                                       breaks: Set() }),
                     ST_OBJECT_NAME_COLLISION)
            else {
            // namespace mutation recalls every caching holder (Seam 4b).
            val selfKey = leaseKeyOf(o.caching)
            val holders = breakHolders(acc.sdb, o.file, fid, BITS_RWH,
                                       BITS_NONE, false, selfKey, o.session)
            val notes = breakNotes(acc.sdb, o.file, holders, BITS_NONE)
            val sdb1 = holders.fold(acc.sdb, (a, h) =>
                           doBreakOne(a, h, BITS_NONE))
            // target is absent or the same file, so fsRename never replaces.
            val rn = fsRename(sdb1.fs, o.dir, o.name, x.newdir, x.newname,
                              pinnedFiles(sdb1))
            if (rn.st != FsOk)
                emit(acc, RSetRename({ st: fsStatusToNt(rn.st),
                                       breaks: Set() }), fsStatusToNt(rn.st))
            else {
                // Rename is by handle (FileId), not by path: EVERY open of
                // this inode now names (newdir,newname).  Syncing all handles
                // keeps o.dir/o.name current so a later rename or
                // delete-on-close through any handle targets the right name
                // (a stale name would otherwise operate on whatever object
                // currently sits at the old path).
                val sdb2 = sdb1.with("fs", rn.fs2)
                    .with("opens", sdb1.opens.keys().mapBy(k => {
                        val oo = sdb1.opens.get(k)
                        if (oo.file == o.file)
                            oo.with("dir", x.newdir).with("name", x.newname)
                        else oo
                    }))
                // MS-FSA 2.1.5.14.11.1.  An intra-directory rename is ONE
                // event on that directory carrying both names, which the
                // serializer expands into the RENAMED_OLD_NAME /
                // RENAMED_NEW_NAME record pair.  A cross-directory move is two
                // one-sided events: the source parent only ever learns the old
                // name left, the destination only that the new name arrived --
                // neither directory saw the whole move, and neither is told
                // about the other.
                // Which NAME filter sees it is decided by the renamed
                // object's type, not by the fact that it was a rename.
                val rcls = if (fsGet(sdb2.fs, o.file).ftype == FDir)
                               Set(EV_RENAMED_DIR) else Set(EV_RENAMED_FILE)
                val sdb3 = if (o.dir == x.newdir)
                    stEmitEv(sdb2, o.dir, rcls, x.newname, o.name)
                    else stEmitEv(
                        stEmitEv(sdb2, o.dir, rcls, "", o.name),
                        x.newdir, rcls, x.newname, "")
                emit(acc.with("sdb", sdb3),
                     RSetRename({ st: ST_SUCCESS, breaks: notes }),
                     ST_SUCCESS)
            }
            }
        }
    }

    pure def doCmdQueryBasic(acc: Acc, sel: FidSel): Acc = {
        val fid = resolveFid(acc, sel)
        if (not(acc.sdb.opens.keys().contains(fid)))
            emit(acc, RQueryBasic({ st: ST_FILE_CLOSED,
                                    attrs: { ftype: FReg, nlink: 0,
                                             sizeBlocks: 0, change: 0,
                                             deletePending: false } }),
                 ST_FILE_CLOSED)
        else {
            val o = acc.sdb.opens.get(fid)
            val nd = fsGet(acc.sdb.fs, o.file)
            emit(acc, RQueryBasic({ st: ST_SUCCESS,
                                    attrs: { ftype: nd.ftype, nlink: nd.nlink,
                                             sizeBlocks: nd.sizeBlocks,
                                             change: nd.change,
                                             deletePending:
                                                 acc.sdb.deletePending
                                                    .contains(o.file) } }),
                 ST_SUCCESS)
        }
    }

    // --- oplock / lease break ack ------------------------------------

    // The status an OPLOCK_BREAK ack (StructureSize 24) gets when the open is
    // NOT in the Breaking state (MS-SMB2 3.3.5.22.1): the exact code depends on
    // the level held and the level acknowledged.  chimera used to collapse all
    // of these to INVALID_OPLOCK_PROTOCOL; the WPTS
    // OplockOnShareWithForceLevel2 not-Breaking acks distinguish them.
    pure def oplockAckNotBreaking(cur: OplockLevel, ack: OplockLevel): int =
        if ((cur == OpExclusive or cur == OpBatch) and
            ack != OpLevelII and ack != OpNone)
            ST_INVALID_OPLOCK_PROTOCOL
        else if (cur == OpLevelII and ack != OpNone)
            ST_INVALID_OPLOCK_PROTOCOL
        else if (ack == OpLevelII or ack == OpNone)
            ST_INVALID_DEVICE_STATE
        else ST_INVALID_OPLOCK_PROTOCOL

    // OPLOCK_BREAK / LEASE_BREAK acknowledgment (MS-SMB2 3.3.5.22.1/.2).
    //
    // Four distinct rejection arms, all reachable:
    //   * an ack whose FileId names no open -> FILE_CLOSED (oplock ack only; a
    //     lease ack whose key resolves to nothing is benign SUCCESS, because
    //     another handle may still carry the lease);
    //   * an ack while no break is outstanding -> UNSUCCESSFUL for a lease,
    //     and the INVALID_DEVICE_STATE / INVALID_OPLOCK_PROTOCOL matrix above
    //     for a legacy oplock;
    //   * an ack that tries to KEEP a caching bit the break asked the holder to
    //     give up -> REQUEST_NOT_ACCEPTED, with the grant left BREAKING;
    //   * otherwise the grant settles at exactly what the holder kept -- which
    //     may be LESS than it was allowed to keep.
    pure def doCmdBreakAck(acc, x) = {
        val fid = resolveFid(acc, x.fid)
        if (not(acc.sdb.opens.keys().contains(fid)))
            if (x.asLease)
                emit(acc, RBreakAck({ st: ST_SUCCESS }), ST_SUCCESS)
            else
                emit(acc, RBreakAck({ st: ST_FILE_CLOSED }), ST_FILE_CLOSED)
        else {
            val o = acc.sdb.opens.get(fid)
            // What the holder chooses to keep: a lease ack names the state
            // directly, a legacy ack keeps a read cache only at LEVEL_II.
            val kept = if (x.asLease) x.ackState
                       else if (x.ackLevel == OpLevelII) BITS_R
                       else BITS_NONE
            if (not(o.breaking))
                if (x.asLease)
                    emit(acc, RBreakAck({ st: ST_UNSUCCESSFUL }),
                         ST_UNSUCCESSFUL)
                else {
                    val st = oplockAckNotBreaking(oplockOfBits(cachBits(o.caching)),
                                                  x.ackLevel)
                    emit(acc, RBreakAck({ st: st }), st)
                }
            else if (not(bitsSubset(kept, cachBits(o.breakTo))))
                emit(acc, RBreakAck({ st: ST_REQUEST_NOT_ACCEPTED }),
                     ST_REQUEST_NOT_ACCEPTED)
            else
                emit(acc.with("sdb", doAckBreak(acc.sdb, fid, kept)),
                     RBreakAck({ st: ST_SUCCESS }), ST_SUCCESS)
        }
    }

    // ------------------------------------------------------------------
    // CHANGE_NOTIFY (MS-SMB2 3.3.5.19) and its CANCEL
    // ------------------------------------------------------------------

    // Connection.MaxTransactSize.  A CHANGE_NOTIFY asking for a buffer larger
    // than the connection can carry is refused rather than clamped: the server
    // would otherwise arm a watch it could never satisfy.
    pure val MAX_TRANSACT = 1048576

    pure def putWatch(acc: Acc, fid: FileId, w: Watch): Acc =
        acc.with("sdb", acc.sdb.with("watches", acc.sdb.watches.put(fid, w)))

    pure def notifyErr(acc: Acc, st: int): Acc =
        emit(acc, RNotify({ st: st, parked: false, recs: [] }), st)

    pure def doCmdNotify(acc, x) = {
        val fid = resolveFid(acc, x.fid)
        if (not(acc.sdb.opens.keys().contains(fid)))
            notifyErr(acc, ST_FILE_CLOSED)
        // MS-SMB2 3.3.5.19: the watch is on a DIRECTORY.  A file handle is a
        // parameter error, not an unsupported operation -- there is nothing
        // about the request the server could have honoured.
        else if (not(isDirOpen(acc, fid)))
            notifyErr(acc, ST_INVALID_PARAMETER)
        // ... and the handle must hold FILE_LIST_DIRECTORY, which on a
        // directory is spelled FILE_READ_DATA.  Watching a directory is
        // reading it, one change at a time.
        else if (not(acc.sdb.opens.get(fid).granted.r))
            notifyErr(acc, ST_ACCESS_DENIED)
        else if (x.obl > MAX_TRANSACT)
            notifyErr(acc, ST_INVALID_PARAMETER)
        else {
            val o = acc.sdb.opens.get(fid)
            val known = acc.sdb.watches.keys().contains(fid)
            // The watch is created (or RE-AIMED) before anything else can
            // reject the request, and the order is observable: a duplicate
            // CHANGE_NOTIFY is refused BUT still leaves the watch pointing at
            // its filter, so the events the FIRST request eventually collects
            // are the ones the SECOND asked for.  chimera does this in
            // chimera_smb_change_notify (watch_create / watch_update run ahead
            // of the state->pending check) and it is not obviously right --
            // but it is what a client observes, so the model says it.
            val w0 =
                if (known) watchReaim(acc.sdb.watches.get(fid),
                                      cfToMask(x.cf), x.watchTree)
                else watchNew(o.file, cfToMask(x.cf), x.watchTree)
                         // Armed on a handle to a directory that is ALREADY
                         // gone: the delete fired before this watch existed
                         // (the deleting client need not wait for our interim),
                         // and the tombstone is what keeps the request from
                         // parking on a directory that can never change again.
                         .with("deleted", acc.sdb.tombstones.contains(o.file))
            val accW = acc.with("sdb",
                acc.sdb.with("watches", acc.sdb.watches.put(fid, w0)))
            {
                // A request already outstanding on this handle owns the ring
                // until it is answered, so a second one parks behind it rather
                // than draining ahead of it (MS-FSA 2.1.5.9: the requests are a
                // LIST and they are served in order).
                val d = if (w0.queue.length() > 0)
                            { fired: false, st: 0, recs: [], w: w0 }
                        else watchDrain(w0, x.cf, x.obl, false)
                if (d.fired)
                    // Something to say already: answer NOW.  No interim, no
                    // park -- a CHANGE_NOTIFY is only asynchronous when the
                    // directory happens to be quiet.
                    emit(putWatch(accW, fid, d.w),
                         RNotify({ st: d.st, parked: false, recs: d.recs }),
                         d.st)
                // MS-SMB2 <159>/<162>: a CHANGE_NOTIFY that would go
                // ASYNCHRONOUS anywhere but the last slot of a compound is
                // failed outright, because the server cannot split a
                // mid-compound request off into its own async message and
                // still deliver the slots after it.  One that completes
                // synchronously is fine in any position, which is why this
                // sits AFTER the drain and not before it.
                else if (acc.nc > 1 and acc.ci != acc.nc - 1)
                    emit(putWatch(accW, fid, d.w),
                         RNotify({ st: ST_INTERNAL_ERROR, parked: false,
                                   recs: [] }), ST_INTERNAL_ERROR)
                else
                    // Park: an interim STATUS_PENDING now, the real answer
                    // whenever the directory changes.  Appended, so the
                    // requests are answered in the order they were made.
                    emit(putWatch(accW, fid, d.w.with("queue",
                             d.w.queue.append({ cf: x.cf, obl: x.obl }))),
                         RNotify({ st: ST_PENDING, parked: true, recs: [] }),
                         ST_PENDING)
            }
        }
    }

    // CANCEL (MS-SMB2 3.3.5.17 / 3.3.4.4).  The CANCEL itself is never
    // answered; what it produces is STATUS_CANCELLED on the request it hit.
    //
    // It does NOT drain the ring.  A cancelled watcher keeps whatever was
    // buffered, so a client that cancels and re-arms sees the events it was
    // waiting for -- which is exactly the point of cancelling rather than
    // closing the handle.
    pure def doCmdCancel(acc: Acc, sel: FidSel): Acc = {
        val fid = resolveFid(acc, sel)
        val r = stCancelNotify(acc.sdb, fid)
        if (r.notes.size() == 0)
            emit(acc, RCancel({ found: false }), ST_SUCCESS)
        else
            emit(acc.with("sdb", r.sdb2)
                    .with("notes", acc.notes.union(r.notes)),
                 RCancel({ found: true }), ST_SUCCESS)
    }

    // ------------------------------------------------------------------
    // Message (compound) evaluator
    // ------------------------------------------------------------------

    type Msg = { sess: SessionId, tree: TreeId, related: bool,
                 cs: int, replay: bool, cmds: List[Cmd] }

    // `notes` are the CHANGE_NOTIFY completions this message caused, on
    // whatever connections were watching -- see Acc.notes.
    type MsgOutcome = { sdb2: StateDB, results: List[Res],
                        notes: Set[NotifyNote] }

    pure def evalMsg(sdb: StateDB, caps: Caps, msg: Msg): MsgOutcome = {
        val a0: Acc = {
            sdb: sdb, caps: caps, related: msg.related,
            sess: msg.sess, tree: msg.tree, cfid: -1,
            cs: msg.cs, replay: msg.replay,
            done: false, results: [],
            notes: Set(), ci: 0, nc: msg.cmds.length()
        }
        val aN = msg.cmds.foldl(a0, (acc, c) =>
            (if (acc.done) acc else dispatch(acc, c)).with("ci", acc.ci + 1))
        // Wake the parked watchers LAST, once every command in the message has
        // raised its events.  A compound is one message on the wire and the
        // server drains a woken watch once, so a compound that adds a file and
        // then renames it delivers BOTH records in a single completion rather
        // than firing twice -- the granularity is the message, not the command.
        val fired = stFireNotifies(aN.sdb)
        { sdb2: fired.sdb2, results: aN.results,
          notes: aN.notes.union(fired.notes) }
    }
}
