// SPDX-FileCopyrightText: 2026 The Quint Specs Authors
//
// SPDX-License-Identifier: MIT

// SMB2/3 stateful generator: config constants, the capability profile
// chosen at init, generator actions (session/tree bootstrap, the CREATE
// family, I/O, byte-range locks, oplock/lease grant+break+ack, set/query
// info, compound chains, deliberate negatives), step distributions and
// invariants.
//
// This is the SMB sibling of nfs4.qnt.  Only this module holds var state
// and constants; smb2state and smb2ops are pure and importable without
// instantiation, so smb2Test.qnt unit-tests the CREATE matrix and the
// conflict/break rules standalone.
//
// One transition = one SMB2 message (a singleton or a NextCommand-chained
// compound), recorded in `lastOp` as an ITF label the replay harness reads.

module smb2 {

    import nfs4fs.* from "../nfs/nfs4_fs"
    import smb2notify.* from "./smb2_notify"
    import smb2state.* from "./smb2_state"
    import smb2ops.* from "./smb2_ops"

    // ------------------------------------------------------------------
    // Feature configuration (see smb2ops.FeatureMode)
    // ------------------------------------------------------------------

    // Negotiated dialect the trace pins (2.0.2=0x0202 ... 3.1.1=0x0311);
    // recorded in LInit for the harness, not otherwise branched on here.
    const DIALECT: int

    const F_OPLOCKS: FeatureMode      // legacy oplocks (set_smb_oplocks)
    const F_LEASES: FeatureMode       // SMB2 leases (set_smb_leases)
    const F_DIRLEASE: FeatureMode     // directory leases
    const F_DURABLE: FeatureMode      // durable handles

    // Policy: does a conflicting CREATE break a peer's lease at OPEN time
    // (MS-FSA-correct = true), or does an SMB2 lease survive the open and
    // break only on later I/O / namespace (the reference implementation's
    // Seam-A asymmetry)?
    const P_LEASE_OPEN_BREAK: bool

    // Share property, not a negotiated capability: the share carries
    // SMB2_SHAREFLAG_FORCE_LEVELII_OPLOCK, so every caching grant is capped to
    // a read cache (MS-SMB2 2.2.10).  The harness sets it on the share when the
    // trace's LInit says so.
    const P_FORCE_LEVEL2: bool

    // ------------------------------------------------------------------
    // Config constants (bound the state space; the harness maps symbols to
    // wire values)
    // ------------------------------------------------------------------

    pure val SHARES = Set(1)
    pure val CLIENTS = Set(1, 2)              // two client symbols
    pure val NAMES = Set("a", "b", "c")
    pure val LEASE_KEYS = Set(1, 2)
    pure val MAX_OBJECTS = 10
    pure val MAX_SESSIONS = 2
    pure val MAX_TREES = 3
    pure val MAX_OPENS = 6
    pure val MAX_BLOCKS = 4
    pure val BLOCK_SYMS = Set(1, 2, 3)
    pure val LOCK_BYTES = 6

    // DesiredAccess profiles the generator draws from (R/W/H/D).
    //
    // Every profile sets `h` (FILE_READ_ATTRIBUTES).  That is not a modeling
    // shortcut: the replayer's access_wire (smb2_mbt_replay.c) sets
    // FILE_READ_ATTRIBUTES unconditionally, so a profile with `h: false` would
    // put a mask on the wire the model did not ask for.  Keeping `h` true in
    // every profile makes the model and the wire agree by construction; the
    // interesting axis is which of R/W/D accompany it, and that is fully
    // varied below.
    //
    // ACCESS_H is the attribute-ONLY open: no R/W/D at all, so it takes no
    // part in share arbitration (smb2ops.attrOnly, and chimera's matching
    // bypass in smb_proc_create.c) and succeeds against a peer that denies
    // everything.  ACCESS_D asks for DELETE alone, so it conflicts on the D
    // axis and ONLY the D axis -- the only way to exercise share-delete
    // arbitration without dragging R or W into the conflict.
    pure val ACCESS_H  = { r: false, w: false, h: true,  d: false }
    pure val ACCESS_R  = { r: true,  w: false, h: true,  d: false }
    pure val ACCESS_W  = { r: false, w: true,  h: true,  d: false }
    pure val ACCESS_D  = { r: false, w: false, h: true,  d: true }
    pure val ACCESS_RW = { r: true,  w: true,  h: true,  d: false }
    pure val ACCESS_RWD = { r: true, w: true,  h: true,  d: true }
    pure val ACCESS_SET = Set(ACCESS_H, ACCESS_R, ACCESS_W, ACCESS_D,
                              ACCESS_RW, ACCESS_RWD)

    // ShareAccess profiles (which axes peers may share).  All eight subsets of
    // {R,W,D} minus the two that add nothing over a sibling here: the set is
    // complete except for RD-without-W being spelled SHARE_RD and WD being
    // omitted (SHARE_D and SHARE_RW between them already deny/allow each axis
    // in both polarities against every access profile).
    //
    // SHARE_W and SHARE_D are the profiles that make the arbitration axes
    // INDEPENDENT: with only SHARE_R and SHARE_RW/SHARE_RWD in the domain,
    // "shares write" implied "shares read", so no trace could distinguish a
    // read-axis conflict from a write-axis one.
    pure val SHARE_NONE = { r: false, w: false, d: false }
    pure val SHARE_R    = { r: true,  w: false, d: false }
    pure val SHARE_W    = { r: false, w: true,  d: false }
    pure val SHARE_D    = { r: false, w: false, d: true }
    pure val SHARE_RD   = { r: true,  w: false, d: true }
    pure val SHARE_RW   = { r: true,  w: true,  d: false }
    pure val SHARE_RWD  = { r: true,  w: true,  d: true }
    pure val SHARE_SET = Set(SHARE_NONE, SHARE_R, SHARE_W, SHARE_D,
                             SHARE_RD, SHARE_RW, SHARE_RWD)

    // Every CreateDisposition the model decides (smb2ops.decideByDisp) and
    // the replayer maps to the wire.  DispOverwrite (FILE_OVERWRITE:
    // truncate-if-present, OBJECT_NAME_NOT_FOUND otherwise) is the one arm
    // that used to be reachable only from smb2Test.createMatrixTest, so five
    // parallel `switch (create_disposition)` blocks in smb_proc_create.c
    // never saw it from a generated trace.
    pure val DISP_SET = Set(DispOpen, DispCreate, DispOpenIf,
                            DispOverwrite, DispOverwriteIf, DispSupersede)

    // ------------------------------------------------------------------
    // State
    // ------------------------------------------------------------------

    type Label =
        | LInit({ dialect: int, caps: Caps })
        // `notes` are the CHANGE_NOTIFY completions this message caused, on
        // whatever connections had a request parked.  They sit beside
        // `results` rather than inside one, because an async completion
        // belongs to no command slot: it is an unsolicited message on the
        // WATCHER's connection, and the watcher is usually not the client
        // whose command triggered it.
        | LMsg({ tag: int, msg: Msg, results: List[Res],
                 notes: Set[NotifyNote] })

    var sdb: StateDB
    var caps: Caps
    var tag: int
    var lastOp: Label

    action init = {
        nondet cOp = oneOf(capChoices(F_OPLOCKS))
        nondet cLe = oneOf(capChoices(F_LEASES))
        nondet cDl = oneOf(capChoices(F_DIRLEASE))
        nondet cDu = oneOf(capChoices(F_DURABLE))
        val c: Caps = {
            oplocks: cOp,
            leases: cLe,
            dirLeases: cDl and cLe,
            durable: cDu,
            forceLevel2: P_FORCE_LEVEL2,
            leaseOpenBreak: P_LEASE_OPEN_BREAK
        }
        all {
            // ref: in-memory share roots are 0777; the root mode is not
            // asserted by the harness (backend-specific).
            sdb' = stInit(511),
            caps' = c,
            tag' = 1,
            lastOp' = LInit({ dialect: DIALECT, caps: c }),
        }
    }

    // The one transition shape: evaluate a message, record the label.
    action runM(msg: Msg): bool = {
        val out = evalMsg(sdb, caps, msg)
        all {
            sdb' = out.sdb2,
            caps' = caps,
            tag' = tag + 1,
            lastOp' = LMsg({ tag: tag, msg: msg, results: out.results,
                             notes: out.notes }),
        }
    }

    // A singleton (non-compound) message on session/tree.
    def one(sess: SessionId, tree: TreeId, c: Cmd): Msg =
        { sess: sess, tree: tree, related: false, cs: 0,
          replay: false, cmds: [ c ] }

    // ------------------------------------------------------------------
    // Convenience projections
    // ------------------------------------------------------------------

    def fsv: Fs = sdb.fs
    def dirs: Set[Ino] = fsDirs(sdb.fs)
    def files: Set[Ino] = fsFiles(sdb.fs)
    def liveInos: Set[Ino] = sdb.fs.inodes.keys()
    def sessions: Set[SessionId] = sdb.sessions.keys()
    def trees: Set[TreeId] = sdb.trees.keys()
    def opens: Set[FileId] = sdb.opens.keys()

    def treeSess(t: TreeId): SessionId = sdb.trees.get(t).session

    // Opens with read / write access, for I/O generation.
    def readOpens: Set[FileId] =
        opens.filter(f => sdb.opens.get(f).granted.r)
    def writeOpens: Set[FileId] =
        opens.filter(f => sdb.opens.get(f).granted.w)
    // Opens holding DELETE, the access a rename or a disposition change
    // requires (MS-FSA 2.1.5.14.3 / 2.1.5.14.11.1).
    def deleteOpens: Set[FileId] =
        opens.filter(f => sdb.opens.get(f).granted.d)

    // Opens on a DIRECTORY, and the subset of them a CHANGE_NOTIFY can
    // actually be armed on: MS-SMB2 3.3.5.19 wants FILE_LIST_DIRECTORY, which
    // on a directory handle is spelled FILE_READ_DATA.
    def dirOpens: Set[FileId] =
        opens.filter(f => fsGet(sdb.fs, sdb.opens.get(f).file).ftype == FDir)
    def watchOpens: Set[FileId] =
        dirOpens.filter(f => sdb.opens.get(f).granted.r)
    // Names not currently in use under ROOT.  With three names in the pool and
    // a walk that keeps creating, a rename drawn blindly nearly always
    // collides -- so the one action whose whole purpose is to produce a
    // RENAMED event draws its target from here instead.
    def freeNames: Set[Name] =
        NAMES.exclude(sdb.fs.inodes.get(ROOT).ents.keys())
    // Names under ROOT naming a FILE that nothing currently has open.  The
    // delete idiom (open-for-delete, close) removes such a name on its own
    // close, so the model and chimera agree on WHEN the entry goes -- which
    // they do not when a second handle is open, the unresolved Q-1 question
    // (MS-FSA 2.1.5.4 keeps the entry until the last handle drops; chimera
    // unlinks at the delete-on-close handle's close).
    def quietNames: Set[Name] =
        NAMES.filter(n =>
            fsHasEnt(sdb.fs, ROOT, n) and
            fsGet(sdb.fs, fsChild(sdb.fs, ROOT, n)).ftype != FDir and
            opensOfFile(sdb, fsChild(sdb.fs, ROOT, n)).size() == 0)
    def fileOpens: Set[FileId] =
        opens.filter(f => fsGet(sdb.fs, sdb.opens.get(f).file).ftype != FDir)
    // Handles with a CHANGE_NOTIFY currently parked -- what a CANCEL can hit,
    // and what an event can complete.
    def notifyParked: Set[FileId] =
        sdb.watches.keys().filter(f => sdb.watches.get(f).queue.length() > 0)

    // Opens whose caching grant is mid-break (a break ack is due).
    def breakingOpens: Set[FileId] =
        opens.filter(f => sdb.opens.get(f).breaking)

    // Opens holding a settled (not mid-break) caching grant: acking one of
    // these is the not-Breaking rejection path (MS-SMB2 3.3.5.22.1/.2).
    def settledCachingOpens: Set[FileId] =
        opens.filter(f => not(sdb.opens.get(f).breaking) and
                     not(cachingLevelNone(sdb.opens.get(f).caching)))

    // The inode a CREATE of `n` under ROOT resolves to, or -1 when the name is
    // absent (so the open would be the sole opener of a fresh object).
    def targetIno(n: Name): Ino =
        if (fsHasEnt(sdb.fs, ROOT, n)) fsChild(sdb.fs, ROOT, n) else -1

    // May this CREATE ask for a WRITE cache behind the peer opens that exist?
    //
    // This guard is NARROW and it names a MEASURED chimera deviation, S-3
    // (DEVIATIONS-SMB.md), not a suspicion.  MS-FSA 2.1.5.18.1 refuses an
    // exclusive oplock -- legacy EXCLUSIVE / BATCH, or a lease carrying W --
    // whenever "Open.File.OpenList contains more than one Open whose Stream is
    // the same as Open.Stream", with no OplockKey and no client-identity
    // exemption.  Probe O12 measures chimera exempting two peer shapes anyway:
    //
    //   * an ATTRIBUTE-ONLY peer open, whose share reservation is inert, caps
    //     nothing -- a full BATCH oplock and a full RWH lease are handed out
    //     behind one (O12[20], O12[21], O12[23], O12[25]);
    //   * a peer open by the SAME client caps no LEGACY oplock (O12[6],
    //     O12[7], O12[11], O12[12]) -- though it does cap a lease (O12[9]).
    //
    // Those two shapes, and only those, are kept out of the generated corpus,
    // exactly as delete-on-close is kept out pending Q-1: the model stays
    // spec-first and is never weakened to match.  Everything else is now
    // GENERATED -- most importantly a caching request behind a peer open by a
    // different client, which is the WPTS Oplocks/Leases surface and which the
    // predecessor of this guard (keyed on "any peer open at all", justified by
    // the since-retired S-1) suppressed wholesale.
    //
    // A request that asks for no WRITE cache -- OrNone, OrLevelII, an R / RH
    // lease -- is a SHARED oplock request (MS-FSA 2.1.5.18.2), has no
    // sole-Open condition, and is never guarded.
    def grantAgreed(n: Name, opl: OplockReq, sess: SessionId): bool = {
        val ino = targetIno(n)
        if (not(reqWantsWrite(opl)) or ino < 0) true
        else {
            val peers = opensOfFile(sdb, ino)
            // Sole opener: model and wire both grant the full request.
            peers.size() == 0 or
            // Otherwise at least one peer must be one that chimera's cap
            // actually sees, so that both sides withhold the write cache.
            peers.exists(f => {
                val o = sdb.opens.get(f)
                openVisibleToGrant(o) and
                (reqIsLease(opl) or o.session != sess)
            })
        }
    }

    // ------------------------------------------------------------------
    // Bootstrap: session + tree
    // ------------------------------------------------------------------

    action smbSessionSetup = all {
        sessions.size() < MAX_SESSIONS,
        {
            nondet cs = oneOf(CLIENTS)
            runM({ sess: -1, tree: -1, related: false, cs: 0, replay: false,
                   cmds: [ CSessionSetup({ clientSym: cs }) ] })
        },
    }

    action smbTreeConnect = all {
        sessions.size() > 0,
        trees.size() < MAX_TREES,
        {
            nondet s = oneOf(sessions)
            nondet sh = oneOf(SHARES)
            runM({ sess: s, tree: -1, related: false, cs: 0, replay: false,
                   cmds: [ CTreeConnect({ share: sh }) ] })
        },
    }

    // Session teardown (MS-SMB2 3.3.5.6).  A LOGOFF destroys the session and
    // everything under it -- its trees and every open on them -- which is why
    // it is the cheapest way to make the walk RECYCLE its session and tree
    // budget instead of saturating MAX_SESSIONS / MAX_TREES and then only ever
    // reusing the same two sessions for the rest of a 500-step trace.
    //
    // The replayer keeps the CONNECTION (a reconnect may still want its
    // ClientGuid) and unbinds only the session id, so a later command naming
    // the dead session is a reported harness bug rather than a silent send.
    action smbLogoff = all {
        sessions.size() > 0,
        {
            nondet s = oneOf(sessions)
            runM({ sess: s, tree: -1, related: false, cs: 0, replay: false,
                   cmds: [ CLogoff ] })
        },
    }

    // Tree teardown (MS-SMB2 3.3.5.8): closes every open on the tree and
    // leaves the session alive.  The narrower half of the pair, and the one
    // that separates "the tree went away" from "the session went away" in the
    // status a later command gets (NETWORK_NAME_DELETED vs
    // USER_SESSION_DELETED).
    action smbTreeDisconnect = all {
        trees.size() > 0,
        {
            nondet t = oneOf(trees)
            runM(one(treeSess(t), t, CTreeDisconnect))
        },
    }

    // ------------------------------------------------------------------
    // CREATE family
    // ------------------------------------------------------------------

    action smbCreate = all {
        trees.size() > 0,
        liveInos.size() < MAX_OBJECTS,
        opens.size() < MAX_OPENS,
        {
            nondet t = oneOf(trees)
            nondet n = oneOf(NAMES)
            nondet disp = oneOf(DISP_SET)
            nondet acc = oneOf(ACCESS_SET)
            nondet sh = oneOf(SHARE_SET)
            nondet doc = oneOf(Set(false, true))
            nondet lk = oneOf(LEASE_KEYS)
            nondet v2 = oneOf(Set(false, true))
            // OrLevelII was previously drawn by no action at all, so the
            // LEVEL_II request arm of five parallel switch blocks in
            // smb_proc_create.c was unreachable from a generated trace.
            nondet oplWant = oneOf(Set(
                OrNone,
                OrLevelII,
                OrBatch,
                OrExclusive,
                OrLease({ key: lk, r: true, w: true, h: true, v2: v2,
                          epoch: 1 }),
                OrLease({ key: lk, r: true, w: false, h: true, v2: v2,
                          epoch: 1 })))
            val opl = if (grantAgreed(n, oplWant, treeSess(t))) oplWant
                      else OrNone
            runM(one(treeSess(t), t,
                CCreate({ dir: ROOT, name: n, disp: disp, access: acc,
                          share: sh, isDir: false, delOnClose: doc,
                          oplock: opl, durable: DurNone })))
        },
    }

    // Create a directory (no oplock, share-all) to exercise the type matrix.
    action smbMkdir = all {
        trees.size() > 0,
        liveInos.size() < MAX_OBJECTS,
        opens.size() < MAX_OPENS,
        {
            nondet t = oneOf(trees)
            nondet n = oneOf(NAMES)
            runM(one(treeSess(t), t,
                CCreate({ dir: ROOT, name: n, disp: DispOpenIf,
                          access: ACCESS_R, share: SHARE_RWD, isDir: true,
                          delOnClose: false, oplock: OrNone, durable: DurNone })))
        },
    }

    // A directory CREATE that asks for DATA access (FILE_READ_DATA /
    // FILE_WRITE_DATA on a directory handle are FILE_LIST_DIRECTORY /
    // FILE_ADD_FILE, both legal), so the directory-handle I/O guards are
    // reachable: MS-FSA 2.1.5.2 / 2.1.5.3 fail a READ or a WRITE issued
    // through a DirectoryStream handle with STATUS_INVALID_DEVICE_REQUEST.
    // smbMkdir asks for read only, so a directory WRITE was unreachable.
    action smbMkdirRW = all {
        trees.size() > 0,
        liveInos.size() < MAX_OBJECTS,
        opens.size() < MAX_OPENS,
        {
            nondet t = oneOf(trees)
            nondet n = oneOf(NAMES)
            runM(one(treeSess(t), t,
                CCreate({ dir: ROOT, name: n, disp: DispOpenIf,
                          access: ACCESS_RW, share: SHARE_RWD, isDir: true,
                          delOnClose: false, oplock: OrNone, durable: DurNone })))
        },
    }

    // FILE_CREATE of a directory: the other diagonal of the type matrix -- a
    // directory create over a name that is already a FILE.  MS-FSA 2.1.5.1.2
    // adjudicates the DISPOSITION first, so this is OBJECT_NAME_COLLISION, not
    // STATUS_NOT_A_DIRECTORY.
    action smbMkdirExcl = all {
        trees.size() > 0,
        liveInos.size() < MAX_OBJECTS,
        opens.size() < MAX_OPENS,
        {
            nondet t = oneOf(trees)
            nondet n = oneOf(NAMES)
            runM(one(treeSess(t), t,
                CCreate({ dir: ROOT, name: n, disp: DispCreate,
                          access: ACCESS_R, share: SHARE_RWD, isDir: true,
                          delOnClose: false, oplock: OrNone, durable: DurNone })))
        },
    }

    action smbClose = all {
        opens.size() > 0,
        {
            nondet f = oneOf(opens)
            val o = sdb.opens.get(f)
            runM(one(o.session, o.tree, CClose(FidRef(f))))
        },
    }

    // Open-for-delete + close in one related compound: the SMB idiom for
    // unlinking a path (there is no path-based REMOVE).  Frees an object
    // slot in a single transition, so the random walk cannot exhaust
    // MAX_OBJECTS and deadlock.  A no-op if the name is absent (the CREATE
    // fails and first-error-stops skips the CLOSE).
    action smbDeleteExisting = all {
        trees.size() > 0,
        opens.size() < MAX_OPENS,
        {
            nondet t = oneOf(trees)
            nondet n = oneOf(NAMES)
            runM({ sess: treeSess(t), tree: t, related: true, cs: 0, replay: false,
                   cmds: [
                       CCreate({ dir: ROOT, name: n, disp: DispOpen,
                                 access: ACCESS_RWD, share: SHARE_RWD,
                                 isDir: false, delOnClose: true,
                                 oplock: OrNone, durable: DurNone }),
                       CClose(FidRelated) ] })
        },
    }

    // ------------------------------------------------------------------
    // I/O
    // ------------------------------------------------------------------

    action smbRead = all {
        readOpens.size() > 0,
        {
            nondet f = oneOf(readOpens)
            val o = sdb.opens.get(f)
            nondet off = oneOf(0.to(MAX_BLOCKS))
            nondet len = oneOf(1.to(MAX_BLOCKS))
            runM(one(o.session, o.tree,
                CRead({ fid: FidRef(f), off: off, len: len })))
        },
    }

    action smbWrite = all {
        writeOpens.size() > 0,
        {
            nondet f = oneOf(writeOpens)
            val o = sdb.opens.get(f)
            nondet off = oneOf(0.to(MAX_BLOCKS - 1))
            nondet len = oneOf(1.to(MAX_BLOCKS))
            nondet pat = oneOf(BLOCK_SYMS)
            runM(one(o.session, o.tree,
                CWrite({ fid: FidRef(f), off: off, len: len, pat: pat })))
        },
    }

    action smbFlush = all {
        opens.size() > 0,
        {
            nondet f = oneOf(opens)
            val o = sdb.opens.get(f)
            runM(one(o.session, o.tree, CFlush(FidRef(f))))
        },
    }

    // ------------------------------------------------------------------
    // Byte-range locks
    // ------------------------------------------------------------------

    action smbLock = all {
        opens.size() > 0,
        {
            nondet f = oneOf(opens)
            val o = sdb.opens.get(f)
            nondet lo = oneOf(0.to(LOCK_BYTES - 1))
            nondet span = oneOf(1.to(2))
            nondet wr = oneOf(Set(false, true))
            runM(one(o.session, o.tree,
                CLock({ fid: FidRef(f), lo: lo, hi: lo + span, wr: wr,
                        unlock: false, failImmediately: true })))
        },
    }

    action smbUnlock = all {
        opens.size() > 0,
        {
            nondet f = oneOf(opens)
            val o = sdb.opens.get(f)
            nondet lo = oneOf(0.to(LOCK_BYTES - 1))
            nondet span = oneOf(1.to(2))
            runM(one(o.session, o.tree,
                CLock({ fid: FidRef(f), lo: lo, hi: lo + span, wr: false,
                        unlock: true, failImmediately: true })))
        },
    }

    // ------------------------------------------------------------------
    // SET_INFO / QUERY_INFO
    // ------------------------------------------------------------------

    action smbSetEof = all {
        writeOpens.size() > 0,
        {
            nondet f = oneOf(writeOpens)
            val o = sdb.opens.get(f)
            nondet sz = oneOf(0.to(MAX_BLOCKS))
            runM(one(o.session, o.tree,
                CSetEof({ fid: FidRef(f), sizeBlocks: sz })))
        },
    }

    action smbSetDisposition = all {
        opens.size() > 0,
        {
            nondet f = oneOf(opens)
            val o = sdb.opens.get(f)
            nondet del = oneOf(Set(false, true))
            runM(one(o.session, o.tree,
                CSetDisposition({ fid: FidRef(f), del: del })))
        },
    }

    // The generated disposition change: DELETE-capable handle, and only the
    // UNMARK arm.
    //
    // Two narrowings, each for a recorded reason.  The handle must hold DELETE
    // because chimera does not access-check SET_INFO at all (S-4) while the
    // model does; and `del` is fixed FALSE because arming delete-on-close
    // through SET_INFO lands in the same unresolved Q-1 family as arming it on
    // the CREATE -- the model adjudicates DELETE_PENDING before the sharing
    // check and the wire the other way round.  What survives is real: the
    // FileDispositionInformation parse, the class dispatch and the
    // delete-pending clear, none of which any generated trace could reach
    // before.  Widen to `oneOf(Set(false, true))` when Q-1 closes.
    action smbSetDispositionOff = all {
        deleteOpens.size() > 0,
        {
            nondet f = oneOf(deleteOpens)
            val o = sdb.opens.get(f)
            runM(one(o.session, o.tree,
                CSetDisposition({ fid: FidRef(f), del: false })))
        },
    }

    action smbSetRename = all {
        opens.size() > 0,
        {
            nondet f = oneOf(opens)
            val o = sdb.opens.get(f)
            nondet nn = oneOf(NAMES)
            runM(one(o.session, o.tree,
                CSetRename({ fid: FidRef(f), newdir: ROOT, newname: nn })))
        },
    }

    // The generated rename: the target name is drawn from NAMES MINUS the
    // handle's own current name.
    //
    // A rename onto the handle's OWN name is the unresolved Q-14 case -- the
    // model treats it as a no-op SUCCESS (MS-FSA 2.1.5.14.11.1 guards the
    // collision branch on the target link being a DIFFERENT link, which is
    // what makes a case-only rename possible at all), chimera answers
    // OBJECT_NAME_COLLISION because its destination probe never asks whether
    // the destination IS the source.  Until a probe ratifies one of the two,
    // the corpus stays free of it, exactly as it does for S-2 and Q-1; the
    // model's own rule is pinned by smb2Test.renameToSelfTest.
    action smbSetRenameNew = all {
        opens.size() > 0,
        {
            nondet f = oneOf(opens)
            val o = sdb.opens.get(f)
            nondet nn = oneOf(NAMES.exclude(Set(o.name)))
            runM(one(o.session, o.tree,
                CSetRename({ fid: FidRef(f), newdir: ROOT, newname: nn })))
        },
    }

    action smbQuery = all {
        opens.size() > 0,
        {
            nondet f = oneOf(opens)
            val o = sdb.opens.get(f)
            runM(one(o.session, o.tree, CQueryBasic(FidRef(f))))
        },
    }

    // ------------------------------------------------------------------
    // Oplock / lease break ack (drains a break so a stalled op can retry)
    // ------------------------------------------------------------------

    // A conformant acknowledgment: keep exactly what the break allows.
    action smbBreakAck = all {
        breakingOpens.size() > 0,
        {
            nondet f = oneOf(breakingOpens)
            val o = sdb.opens.get(f)
            val keep = cachBits(o.breakTo)
            runM(one(o.session, o.tree,
                CBreakAck({ fid: FidRef(f), asLease: isLeaseGrant(o.caching),
                            ackLevel: oplockOfBits(keep), ackState: keep })))
        },
    }

    // A holder may drop FURTHER than the break asked (MS-SMB2 3.3.5.22.1/.2:
    // "it may drop further than we asked -- e.g. straight to NONE").
    action smbBreakAckNone = all {
        breakingOpens.size() > 0,
        {
            nondet f = oneOf(breakingOpens)
            val o = sdb.opens.get(f)
            runM(one(o.session, o.tree,
                CBreakAck({ fid: FidRef(f), asLease: isLeaseGrant(o.caching),
                            ackLevel: OpNone, ackState: BITS_NONE })))
        },
    }

    // An acknowledgment that insists on keeping a READ cache.  Legal when the
    // break left one; STATUS_REQUEST_NOT_ACCEPTED when it did not (a break
    // driven by a write / truncate invalidation leaves nothing, and re-arming
    // a stale read cache over data a writer is mutating must be refused).
    action smbBreakAckKeepRead = all {
        breakingOpens.size() > 0,
        {
            nondet f = oneOf(breakingOpens)
            val o = sdb.opens.get(f)
            runM(one(o.session, o.tree,
                CBreakAck({ fid: FidRef(f), asLease: isLeaseGrant(o.caching),
                            ackLevel: OpLevelII, ackState: BITS_R })))
        },
    }

    // An acknowledgment for a grant with NO break outstanding: the
    // not-Breaking rejection matrix (UNSUCCESSFUL for a lease;
    // INVALID_DEVICE_STATE / INVALID_OPLOCK_PROTOCOL for a legacy oplock).
    action smbBreakAckStale = all {
        settledCachingOpens.size() > 0,
        {
            nondet f = oneOf(settledCachingOpens)
            val o = sdb.opens.get(f)
            runM(one(o.session, o.tree,
                CBreakAck({ fid: FidRef(f), asLease: isLeaseGrant(o.caching),
                            ackLevel: OpNone, ackState: BITS_NONE })))
        },
    }

    // ------------------------------------------------------------------
    // Durable handles (MS-SMB2 3.3.5.9.6/.10 request, 3.3.7.1 park,
    // 3.3.5.9.7/.12 reconnect).  Every rule these actions exercise is pinned
    // by smb2_durable_probe.c (sections D1-D8) and recorded in
    // DEVIATIONS-SMB.md as C-13 ... C-22.
    //
    // Gated on caps.durable, which is drawn from F_DURABLE and, before this
    // increment, was written at init and read by nothing.
    // ------------------------------------------------------------------

    // CreateGuid symbols.  Two are enough to make a guid MISMATCH reachable
    // while keeping the domain small; the harness maps each to a distinct
    // 16-byte guid.
    pure val DUR_GUIDS = Set(1, 2)

    // Handles parked by a transport drop, waiting to be reclaimed.
    def parkedFids: Set[FileId] = sdb.parked.keys()

    // Sessions that left parked handles behind: the meaningful `prev` for a
    // reconnect, because the new connection must present THAT client's guid.
    def parkedSessions: Set[SessionId] =
        parkedFids.map(f => sdb.parked.get(f).open.session)

    // The RqLs request that re-presents a parked handle's own lease: the
    // reconnect of a LEASED handle must carry the lease context and the same
    // lease key (MS-SMB2 3.3.5.9.7, probe D4b/D4c).
    def parkedLeaseReq(p: Parked): OplockReq =
        match p.open.caching {
            | CLease(x) => OrLease({ key: x.key, r: x.st.r, w: x.st.w,
                                     h: x.st.h, v2: x.v2, epoch: x.epoch })
            | _ => OrNone
        }

    // May this flavor open `n` at all?
    //
    // A CREATE that lands behind a LIVE caching holder whose break needs an
    // acknowledgment is deferred by the server until the holder acks (C-11),
    // and the acknowledgment is a separate step the DURABLE flavor does not
    // draw -- servicing the caching break lifecycle is stepLease's job, and
    // stepLease is blocked on Q-4/Q-5/Q-6.  Generating that shape here would
    // wedge the replayer on a CREATE with no reply (measured: the first
    // stepDurable corpus wedged for exactly this reason), which is a harness
    // dead end, not a finding.
    //
    // A PARKED holder is a different matter and is deliberately NOT excluded:
    // it has nobody to acknowledge a break, so the server purges it and admits
    // the opener outright (probe D7) -- which is the durable-specific behavior
    // this flavor exists to exercise.
    def cachingQuiet(n: Name): bool = {
        val ino = targetIno(n)
        ino < 0 or opensOfFile(sdb, ino).forall(f =>
            cachingLevelNone(sdb.opens.get(f).caching))
    }

    // The plain (non-durable) opens that drive the parked-holder purge: the
    // conflicting ones purge (D7), the attribute-only ones must not (D7b).
    // The full disposition set is drawn, truncating dispositions included: a
    // truncating open is not a stat open, so it purges, and it is also the only
    // way this flavor reaches SUPERSEDED / OVERWRITTEN CreateActions and the
    // truncating-open share check that the coverage gate requires.
    action smbCreateQuiet = all {
        trees.size() > 0,
        liveInos.size() < MAX_OBJECTS,
        opens.size() < MAX_OPENS,
        {
            nondet t = oneOf(trees)
            nondet n = oneOf(NAMES)
            nondet disp = oneOf(DISP_SET)
            nondet acc = oneOf(ACCESS_SET)
            nondet sh = oneOf(SHARE_SET)
            all {
                cachingQuiet(n),
                runM(one(treeSess(t), t,
                    CCreate({ dir: ROOT, name: n, disp: disp, access: acc,
                              share: sh, isDir: false, delOnClose: false,
                              oplock: OrNone, durable: DurNone }))),
            }
        },
    }

    // A CREATE that asks for a durable handle.  The oplock draw deliberately
    // spans both sides of the precondition: OrBatch and an H-carrying lease
    // GRANT durability, OrLevelII and an R-only lease do not (probe D1), so the
    // corpus contains both the grant and the refusal on every walk.
    action smbCreateDurable = all {
        caps.durable,
        trees.size() > 0,
        liveInos.size() < MAX_OBJECTS,
        opens.size() < MAX_OPENS,
        {
            nondet t = oneOf(trees)
            nondet n = oneOf(NAMES)
            nondet disp = oneOf(Set(DispOpenIf, DispOpen, DispCreate))
            nondet acc = oneOf(Set(ACCESS_R, ACCESS_RW, ACCESS_RWD))
            nondet sh = oneOf(SHARE_SET)
            nondet lk = oneOf(LEASE_KEYS)
            nondet g = oneOf(DUR_GUIDS)
            nondet v2 = oneOf(Set(false, true))
            nondet oplWant = oneOf(Set(
                OrBatch,
                OrLevelII,
                OrLease({ key: lk, r: true, w: true, h: true, v2: true,
                          epoch: 1 }),
                OrLease({ key: lk, r: true, w: false, h: true, v2: true,
                          epoch: 1 }),
                OrLease({ key: lk, r: true, w: false, h: false, v2: true,
                          epoch: 1 })))
            val opl = if (grantAgreed(n, oplWant, treeSess(t))) oplWant
                      else OrNone
            all {
                cachingQuiet(n),
                runM(one(treeSess(t), t,
                    CCreate({ dir: ROOT, name: n, disp: disp, access: acc,
                              share: sh, isDir: false, delOnClose: false,
                              oplock: opl,
                              durable: DurQ({ v2: v2, guid: g,
                                              persistent: false }) }))),
            }
        },
    }

    // The compound (CREATE + WRITE + CLOSE) with the same caching guard: the
    // durable flavor needs the NextCommand threading and the first-error-stop
    // path in its corpus, but must not park behind a live caching holder any
    // more than its singleton creates may.
    action smbCompoundQuiet = all {
        trees.size() > 0,
        liveInos.size() < MAX_OBJECTS,
        opens.size() < MAX_OPENS,
        {
            nondet t = oneOf(trees)
            nondet n = oneOf(NAMES)
            nondet pat = oneOf(BLOCK_SYMS)
            all {
                cachingQuiet(n),
                runM({ sess: treeSess(t), tree: t, related: true, cs: 0, replay: false,
                       cmds: [
                           CCreate({ dir: ROOT, name: n, disp: DispOpenIf,
                                     access: ACCESS_RW, share: SHARE_RW,
                                     isDir: false, delOnClose: false,
                                     oplock: OrNone, durable: DurNone }),
                           CWrite({ fid: FidRelated, off: 0, len: 1,
                                    pat: pat }),
                           CClose(FidRelated) ] }),
            }
        },
    }

    // May this session be dropped by the GENERATED corpus?
    //
    // The model handles any drop -- durable opens park, everything else closes
    // (probe D6) -- but the REPLAYER can only order against the half of that
    // the server lets it observe.  A client-initiated disconnect returns when
    // the DISCONNECTED notification reaches the client bind; the server's
    // teardown runs afterwards on the dropped connection's own thread, and
    // there is no echo path to that thread once its connection is gone.  For
    // a DURABLE open there is a barrier -- a wrong-CreateGuid DH2C blocks in
    // chimera's reconnect retry until the handle parks (park_barrier_flush in
    // smb2_mbt_replay.c) -- and chimera additionally resolves the window
    // itself, retrying a conflicting CREATE while the holder is on its way out
    // (chimera_smb_durable_conn_disconnecting: the four "confirmed disconnect"
    // signals).  A NON-durable open has neither: a conflicting CREATE simply
    // gets STATUS_SHARING_VIOLATION until the teardown happens to run.
    //
    // Measured, not assumed: a corpus without this guard replayed 7 of 8, and
    // the failure was exactly that -- a CREATE two steps after a drop, model
    // SUCCESS and wire SHARING_VIOLATION, on a file whose only opener was a
    // NON-durable handle of the dropped connection.
    //
    // So the generated drop is restricted to sessions whose opens are all
    // durable (typically: none at all, or exactly the parked-handle shapes this
    // flavor exists for).  The excluded shape is not untested -- probe D6 pins
    // it deterministically, with the probe's own ordering.
    def sessionParkable(s: SessionId): bool =
        opens.filter(f => sdb.opens.get(f).session == s)
             .forall(f => sdb.opens.get(f).durable.on)

    // The transport drop.  Durable opens of this session park; everything else
    // closes (probe D6), and the session and its trees go with the connection.
    action smbDisconnect = all {
        sessions.size() > 0,
        {
            nondet s = oneOf(sessions)
            all {
                sessionParkable(s),
                runM(one(s, -1, CDisconnect)),
            }
        },
    }

    // The reconnect half: a fresh connection presenting a previous session's
    // ClientGuid.  Drawn from the sessions that left parked handles whenever
    // there are any, so the corpus reaches the reclaim rather than merely
    // making sessions; otherwise from the live ones, which exercises the
    // cross-client denial (a reclaim by the WRONG client, probe D4i).
    action smbReconnect = all {
        sessions.size() < MAX_SESSIONS,
        parkedSessions.size() + sessions.size() > 0,
        {
            nondet p = oneOf(if (parkedSessions.size() > 0) parkedSessions
                             else sessions)
            runM({ sess: -1, tree: -1, related: false, cs: 0, replay: false,
                   cmds: [ CReconnect({ prev: p }) ] })
        },
    }

    // A well-formed reclaim: the right CreateGuid, the right lease context, an
    // empty Name (MS-SMB2 3.3.5.9.12).  Succeeds when it comes from the owning
    // client and fails OBJECT_NAME_NOT_FOUND when it does not -- the model
    // decides which, and the corpus contains both because `smbReconnect` also
    // draws non-owning sessions.
    action smbReclaim = all {
        trees.size() > 0,
        parkedFids.size() > 0,
        opens.size() < MAX_OPENS,
        {
            nondet t = oneOf(trees)
            nondet f = oneOf(parkedFids)
            val p = sdb.parked.get(f)
            runM(one(treeSess(t), t,
                CCreate({ dir: p.dir, name: "", disp: DispOpen,
                          access: ACCESS_RW, share: SHARE_RWD, isDir: false,
                          delOnClose: false,
                          oplock: parkedLeaseReq(p),
                          durable: DurC({ v2: p.v2, fid: f, guid: p.guid,
                                          persistent: false, alsoQ: false,
                                          withName: false }) })))
        },
    }

    // The reclaim DENIAL matrix (probe D4), one malformed reconnect per draw.
    // A refused reconnect must consume nothing, so these are safe to interleave
    // with the good ones -- and that they leave the handle reclaimable is
    // exactly what the corpus checks.
    action smbReclaimBad = all {
        trees.size() > 0,
        parkedFids.size() > 0,
        opens.size() < MAX_OPENS,
        {
            nondet t = oneOf(trees)
            nondet f = oneOf(parkedFids)
            nondet bad = oneOf(Set("guid", "nolease", "leasekey", "name",
                                   "alsoq", "persist"))
            val p = sdb.parked.get(f)
            val good = parkedLeaseReq(p)
            val badKey =
                match good {
                    | OrLease(x) => OrLease(x.with("key", 3 - x.key))
                    | _ => OrNone
                }
            runM(one(treeSess(t), t,
                CCreate({ dir: p.dir,
                          name: if (bad == "name") "a" else "",
                          disp: DispOpen,
                          access: ACCESS_RW, share: SHARE_RWD, isDir: false,
                          delOnClose: false,
                          oplock: if (bad == "nolease") OrNone
                                  else if (bad == "leasekey") badKey
                                  else good,
                          durable: DurC({
                              v2: p.v2,
                              fid: f,
                              guid: if (bad == "guid") 3 - p.guid else p.guid,
                              persistent: bad == "persist",
                              alsoQ: bad == "alsoq",
                              withName: bad == "name" }) })))
        },
    }

    // Handles a reconnect can name that resolve to nothing at all: not parked,
    // and not a LIVE durable open either.  The live-durable case is excluded on
    // purpose and pinned by probe D4k instead: chimera cannot tell it apart
    // from a reclaim racing its own disconnect, so it announces an async
    // interim and retries for ~3 s before refusing -- correct, and far too
    // expensive to put in every trace.
    def unknownFids: Set[FileId] =
        Set(0, 1, 2, 3).filter(f =>
            not(isParked(sdb, f)) and not(liveDurable(sdb, f)))

    // A reconnect naming a handle that is NOT parked -- a closed handle's
    // FileId, a non-durable open's, or one that never existed.
    // OBJECT_NAME_NOT_FOUND, with no interim (probe D4h).
    action smbReclaimUnknown = all {
        trees.size() > 0,
        unknownFids.size() > 0,
        {
            nondet t = oneOf(trees)
            nondet f = oneOf(unknownFids)
            runM(one(treeSess(t), t,
                CCreate({ dir: ROOT, name: "", disp: DispOpen,
                          access: ACCESS_RW, share: SHARE_RWD, isDir: false,
                          delOnClose: false, oplock: OrNone,
                          durable: DurC({ v2: true, fid: f, guid: 1,
                                          persistent: false, alsoQ: false,
                                          withName: false }) })))
        },
    }

    // ------------------------------------------------------------------
    // Compound (NextCommand chain): CREATE + WRITE + CLOSE, related so the
    // WRITE/CLOSE inherit the CREATE's FileId.  Exercises the related-op
    // FileId threading and first-error-stops.
    // ------------------------------------------------------------------

    action smbCompoundCreateWriteClose = all {
        trees.size() > 0,
        liveInos.size() < MAX_OBJECTS,
        opens.size() < MAX_OPENS,
        {
            nondet t = oneOf(trees)
            nondet n = oneOf(NAMES)
            nondet pat = oneOf(BLOCK_SYMS)
            runM({ sess: treeSess(t), tree: t, related: true, cs: 0, replay: false,
                   cmds: [
                       CCreate({ dir: ROOT, name: n, disp: DispOpenIf,
                                 access: ACCESS_RW, share: SHARE_RW,
                                 isDir: false, delOnClose: false,
                                 oplock: OrNone, durable: DurNone }),
                       CWrite({ fid: FidRelated, off: 0, len: 1, pat: pat }),
                       CClose(FidRelated) ] })
        },
    }

    // ==================================================================
    // CHANGE_NOTIFY (MS-SMB2 3.3.5.19; the watch layer is smb2_notify.qnt)
    // ==================================================================

    // The CompletionFilter profiles the corpus draws from.  Small and chosen
    // so the two filters are DISTINGUISHABLE rather than merely varied: each
    // profile admits a different slice of what the other actions raise, so a
    // server that ignored the filter (or applied only one of the two) would
    // deliver records some profile must not see.
    //
    //   CF_NAMES    entries appearing and disappearing, and renames
    //   CF_MODIFY   size and last-write: what a WRITE or a SET_EOF changes
    //   CF_ATTRS    metadata only -- reachable from a rename's target, not
    //               from a write, so it is the profile that must stay QUIET
    //               through the I/O actions
    //   CF_STREAMS  the named-stream classes, which a write and a create
    //               raise ALONGSIDE their generic class: this profile is the
    //               only way to check that the stream bits widen the audience
    //               without changing the FILE_ACTION
    //   CF_ALL      everything, so events are never lost to the filter and a
    //               missing record is a delivery bug rather than a filter one
    pure val CF_NAMES = Set(CF_FILE_NAME, CF_DIR_NAME)
    pure val CF_MODIFY = Set(CF_SIZE, CF_LAST_WRITE)
    pure val CF_ATTRS = Set(CF_ATTRIBUTES)
    pure val CF_STREAMS = Set(CF_STREAM_NAME, CF_STREAM_SIZE, CF_STREAM_WRITE)
    pure val CF_SET = Set(CF_NAMES, CF_MODIFY, CF_ATTRS, CF_STREAMS, CF_ALL)

    // OutputBufferLength draws, in BYTES.  Every generated name is one
    // character, so a FILE_NOTIFY_INFORMATION record is exactly 16 bytes
    // (smb2notify.recSize) and these are "no room at all", "one record",
    // "two records" and "as much as anyone needs".
    //
    // 0 is not a degenerate case, it is a documented one: MS-SMB2 2.2.36 makes
    // a zero-length buffer a POLL -- the client asks whether anything happened
    // without asking what -- and it must NOT set the sticky overflow that a
    // too-small non-zero buffer does, because nothing was lost that the client
    // had asked to receive.  16 and 32 are where the atomic per-event fit
    // check bites: a rename needs 32 all by itself, so it does not fit in 16
    // however few events precede it.
    pure val OBL_SET = Set(0, 16, 32, 4096)

    // A handle on the SHARE ROOT.  The generated namespace is flat -- every
    // name lives directly under ROOT -- so the root handle is the only place a
    // watcher can stand and see anything at all.
    action smbOpenDir = all {
        trees.size() > 0,
        opens.size() < MAX_OPENS,
        {
            nondet t = oneOf(trees)
            runM(one(treeSess(t), t,
                CCreate({ dir: ROOT, name: "", disp: DispOpen,
                          access: ACCESS_R, share: SHARE_RWD, isDir: true,
                          delOnClose: false, oplock: OrNone,
                          durable: DurNone })))
        },
    }

    // The same handle without FILE_LIST_DIRECTORY.  A perfectly good directory
    // handle -- it can be queried, renamed through, closed -- that simply may
    // not WATCH, and the only way to reach the ACCESS_DENIED arm of arming a
    // watch.  Kept as its own action rather than a draw inside smbOpenDir so
    // the flavor can weight it: a corpus where half the root handles cannot
    // watch spends half its CHANGE_NOTIFY draws on one error arm.
    action smbOpenDirNoRead = all {
        trees.size() > 0,
        opens.size() < MAX_OPENS,
        {
            nondet t = oneOf(trees)
            runM(one(treeSess(t), t,
                CCreate({ dir: ROOT, name: "", disp: DispOpen,
                          access: ACCESS_H, share: SHARE_RWD, isDir: true,
                          delOnClose: false, oplock: OrNone,
                          durable: DurNone })))
        },
    }

    // Arm a watch on a handle that has no request outstanding.  Draws over the
    // whole (filter x buffer x watch-tree) space, so the same handle is
    // re-armed with different filters as a trace runs -- which is what makes
    // the ENQUEUE filter and the DELIVERY filter distinguishable: events
    // buffered under a wide mask are drained by a narrow request.
    action smbNotify = all {
        watchOpens.exclude(notifyParked).size() > 0,
        {
            nondet f = oneOf(watchOpens.exclude(notifyParked))
            val o = sdb.opens.get(f)
            nondet cf = oneOf(CF_SET)
            nondet obl = oneOf(OBL_SET)
            nondet wt = oneOf(Set(false, true))
            runM(one(o.session, o.tree,
                CNotify({ fid: FidRef(f), cf: cf, watchTree: wt, obl: obl })))
        },
    }

    // A SECOND CHANGE_NOTIFY while one is still outstanding.  It is QUEUED,
    // not refused (MS-FSA 2.1.5.9 keeps the requests on a list), and the two
    // are answered oldest-first, one delivery cycle each -- which is how an
    // overlapped client keeps a directory continuously watched.  Drawn with a
    // filter that differs from the parked request's, so the corpus contains
    // handles whose queued requests want different things.
    action smbNotifyDup = all {
        notifyParked.size() > 0,
        {
            nondet f = oneOf(notifyParked)
            val o = sdb.opens.get(f)
            nondet cf = oneOf(CF_SET)
            runM(one(o.session, o.tree,
                CNotify({ fid: FidRef(f), cf: cf, watchTree: false,
                          obl: 4096 })))
        },
    }

    // Delete a file nothing else has open: the SMB unlink idiom (there is no
    // path-based REMOVE), narrowed so its removal timing is not the Q-1 case.
    // This is what raises FILE_REMOVED for the name-filter profiles, and the
    // tombstone that a CHANGE_NOTIFY armed afterwards on a handle to the same
    // object must report.
    action smbDeleteQuiet = all {
        trees.size() > 0,
        opens.size() < MAX_OPENS,
        quietNames.size() > 0,
        {
            nondet t = oneOf(trees)
            nondet n = oneOf(quietNames)
            runM({ sess: treeSess(t), tree: t, related: true, cs: 0,
                   replay: false,
                   cmds: [
                       CCreate({ dir: ROOT, name: n, disp: DispOpen,
                                 access: ACCESS_RWD, share: SHARE_RWD,
                                 isDir: false, delOnClose: true,
                                 oplock: OrNone, durable: DurNone }),
                       CClose(FidRelated) ] })
        },
    }

    // A rename that actually renames.  smbSetRenameNew draws its handle from
    // every open and its target from every name, so in a walk that keeps the
    // small name pool full it is nearly always ACCESS_DENIED (the handle lacks
    // DELETE) or OBJECT_NAME_COLLISION -- neither of which raises an event.
    // This one draws a DELETE-capable handle and a FREE name, so it produces
    // the RENAMED record pair the name-filter profiles exist to observe.
    action smbRenameFresh = all {
        deleteOpens.size() > 0,
        freeNames.size() > 0,
        {
            nondet f = oneOf(deleteOpens)
            val o = sdb.opens.get(f)
            nondet nn = oneOf(freeNames)
            runM(one(o.session, o.tree,
                CSetRename({ fid: FidRef(f), newdir: ROOT, newname: nn })))
        },
    }

    // A create that varies its access and disposition but SHARES everything.
    //
    // The share-all part is what keeps this flavor about notifications.  A
    // restrictive ShareAccess makes some later create fail arbitration, and a
    // truncating create that is refused is DEVIATIONS-SMB.md CD-3 -- a
    // non-reconcilable deviation that abandons the trace, taking the remaining
    // hundreds of steps of notify coverage with it.  Share arbitration is
    // stepCore's and stepShare's subject; here it is only a way to lose the
    // trace.
    action smbCreateShared = all {
        trees.size() > 0,
        liveInos.size() < MAX_OBJECTS,
        opens.size() < MAX_OPENS,
        {
            nondet t = oneOf(trees)
            nondet n = oneOf(NAMES)
            nondet disp = oneOf(DISP_SET)
            nondet acc = oneOf(ACCESS_SET)
            runM(one(treeSess(t), t,
                CCreate({ dir: ROOT, name: n, disp: disp, access: acc,
                          share: SHARE_RWD, isDir: false, delOnClose: false,
                          oplock: OrNone, durable: DurNone })))
        },
    }

    // A file handle that can actually WRITE.  smbCreateShared draws its access
    // at random, so a walk that spends its handle budget on read-only and
    // attribute-only opens has nothing to write through -- and a CHANGE_NOTIFY
    // corpus with no writes exercises the namespace classes only.
    action smbCreateRW = all {
        trees.size() > 0,
        liveInos.size() < MAX_OBJECTS,
        opens.size() < MAX_OPENS,
        {
            nondet t = oneOf(trees)
            nondet n = oneOf(NAMES)
            nondet disp = oneOf(Set(DispOpenIf, DispOverwriteIf, DispSupersede))
            runM(one(treeSess(t), t,
                CCreate({ dir: ROOT, name: n, disp: disp, access: ACCESS_RWD,
                          share: SHARE_RWD, isDir: false, delOnClose: false,
                          oplock: OrNone, durable: DurNone })))
        },
    }

    // The NAME filter a given handle uses, derived from the handle so it is
    // the SAME for every request on it.  Three profiles across the handles, so
    // the discrimination is still exercised -- a file create must not wake a
    // dirName watcher, and a file rename must not either -- while no single
    // handle ever changes its filter.
    //
    // That last part is a concession to Samba, not a modeling choice: a
    // handle's CompletionFilter is binding there after its first request
    // (samba_deviations.py SD-11), so a corpus that re-aims one is comparing
    // against a server that stopped watching.  The full stepNotify flavor does
    // re-aim, and is where that axis is covered.
    def nameFilterFor(f: FileId): Set[str] =
        if (f % 3 == 0) CF_NAMES
        else if (f % 3 == 1) Set(CF_FILE_NAME)
        else Set(CF_DIR_NAME)

    action smbNotifyNames = all {
        watchOpens.exclude(notifyParked).size() > 0,
        {
            nondet f = oneOf(watchOpens.exclude(notifyParked))
            val o = sdb.opens.get(f)
            // Buffers that always FIT.  The overflow arithmetic is the full
            // stepNotify flavor's subject; here it would only mean that a
            // record Samba adds and the model does not (SD-12) tips one side
            // into STATUS_NOTIFY_ENUM_DIR and not the other, which says
            // nothing new and costs the rest of the trace.
            nondet obl = oneOf(Set(4096, 65536))
            runM(one(o.session, o.tree,
                CNotify({ fid: FidRef(f), cf: nameFilterFor(f),
                          watchTree: false, obl: obl })))
        },
    }

    action smbNotifyDupNames = all {
        notifyParked.size() > 0,
        {
            nondet f = oneOf(notifyParked)
            val o = sdb.opens.get(f)
            runM(one(o.session, o.tree,
                CNotify({ fid: FidRef(f), cf: nameFilterFor(f),
                          watchTree: false, obl: 4096 })))
        },
    }

    // A CHANGE_NOTIFY through a directory handle that lacks
    // FILE_LIST_DIRECTORY.  Its own action so the flavor can weight it: drawn
    // from the same pool as the productive arm it would soak up most of the
    // CHANGE_NOTIFY budget, since an attribute-only root handle is as
    // long-lived as a readable one.
    action smbNotifyNoRead = all {
        dirOpens.exclude(watchOpens).size() > 0,
        {
            nondet f = oneOf(dirOpens.exclude(watchOpens))
            val o = sdb.opens.get(f)
            runM(one(o.session, o.tree,
                CNotify({ fid: FidRef(f), cf: CF_ALL, watchTree: false,
                          obl: 4096 })))
        },
    }

    // A CHANGE_NOTIFY on a FILE handle.  There is no such thing as watching a
    // file for directory changes, so this is STATUS_INVALID_PARAMETER -- and
    // it must not arm anything, which the rest of the trace checks by
    // continuing to mutate that file.
    action smbNotifyFile = all {
        fileOpens.size() > 0,
        {
            nondet f = oneOf(fileOpens)
            val o = sdb.opens.get(f)
            runM(one(o.session, o.tree,
                CNotify({ fid: FidRef(f), cf: CF_ALL, watchTree: false,
                          obl: 4096 })))
        },
    }

    // An OutputBufferLength past Connection.MaxTransactSize.  Refused rather
    // than clamped: a watch the server could never answer must not be armed.
    //
    // Drawn from the READ-CAPABLE handles only.  A handle that fails BOTH this
    // check and the FILE_LIST_DIRECTORY one would report whichever the server
    // makes first, and that order is not settled: the model checks access
    // first, Samba checks the buffer first, and MS-SMB2 3.3.5.19 does not say.
    // Keeping the two failures apart means each arm reports its own rule.
    action smbNotifyHuge = all {
        watchOpens.size() > 0,
        {
            nondet f = oneOf(watchOpens)
            val o = sdb.opens.get(f)
            runM(one(o.session, o.tree,
                CNotify({ fid: FidRef(f), cf: CF_ALL, watchTree: false,
                          obl: MAX_TRANSACT + 1 })))
        },
    }

    // CANCEL the parked request (MS-SMB2 3.3.5.17).  The cancel is never
    // answered; the request it hits completes STATUS_CANCELLED, and the
    // BUFFERED events survive -- so a later CHANGE_NOTIFY on the same handle
    // still collects them, which is what separates cancelling from closing.
    action smbCancelNotify = all {
        notifyParked.size() > 0,
        {
            nondet f = oneOf(notifyParked)
            val o = sdb.opens.get(f)
            runM(one(o.session, o.tree, CCancel(FidRef(f))))
        },
    }

    // A CHANGE_NOTIFY that would go async in a NON-final compound slot
    // (MS-SMB2 <159>/<162>): failed outright, while the rest of the compound
    // is served.  The compound is deliberately UNRELATED, because that is the
    // shape where the following slots really do still run -- a related chain
    // would stop at the first error and the rule would be untestable.
    //
    // Deliberately NOT in stepNotify, and for a harness reason rather than a
    // model one: the chimera replayer expands a modeled compound into one SMB2
    // message per command (it threads the FileId itself rather than building a
    // NextCommand chain), so a "mid-compound" CHANGE_NOTIFY reaches that server
    // as an ordinary standalone request and parks, which is correct for what
    // was actually sent and a false failure against this rule.  The rule is
    // pinned deterministically by smb2Test.notifyMidCompoundTest instead;
    // register this action once a replayer builds real chains.
    action smbNotifyMidCompound = all {
        dirOpens.size() > 0,
        {
            nondet f = oneOf(dirOpens)
            val o = sdb.opens.get(f)
            runM({ sess: o.session, tree: o.tree, related: false, cs: 0,
                   replay: false,
                   cmds: [
                       CNotify({ fid: FidRef(f), cf: CF_ALL,
                                 watchTree: false, obl: 4096 }),
                       CQueryBasic(FidRef(f)) ] })
        },
    }

    // ------------------------------------------------------------------
    // Step distributions
    // ------------------------------------------------------------------

    action step = any {
        smbSessionSetup,
        smbTreeConnect,
        smbCreate,
        smbMkdir,
        smbClose,
        smbRead,
        smbWrite,
        smbFlush,
        smbLock,
        smbUnlock,
        smbSetEof,
        smbSetDisposition,
        smbSetRename,
        smbQuery,
        smbBreakAck, smbBreakAckStale,
        smbDeleteExisting,
        smbCompoundCreateWriteClose,
        smbMkdirRW, smbMkdirExcl,
    }

    // Share/create-matrix heavy: CREATE arbitration, close, query.
    action stepShare = any {
        smbSessionSetup, smbTreeConnect,
        smbCreate, smbCreate, smbCreate, smbMkdir,
        smbClose, smbClose, smbQuery,
        smbSetDisposition, smbSetRename,
        smbDeleteExisting, smbDeleteExisting,
    }

    // The caching CREATE: the full oplock/lease request draw, but never
    // delete-on-close.  Delete-on-close removal timing against a second open
    // handle is the unresolved Q-1 question, and it interacts with the CREATE
    // ordering (the model adjudicates DELETE_PENDING before the share check,
    // the server the other way round), so it is excluded here exactly as it is
    // from `stepCore` -- the caching lifecycle is what this flavor is for.
    action smbCreateCache = all {
        trees.size() > 0,
        liveInos.size() < MAX_OBJECTS,
        opens.size() < MAX_OPENS,
        {
            nondet t = oneOf(trees)
            nondet n = oneOf(NAMES)
            nondet disp = oneOf(DISP_SET)
            nondet acc = oneOf(ACCESS_SET)
            nondet sh = oneOf(SHARE_SET)
            nondet lk = oneOf(LEASE_KEYS)
            nondet v2 = oneOf(Set(false, true))
            nondet oplWant = oneOf(Set(
                OrNone,
                OrLevelII,
                OrBatch,
                OrExclusive,
                OrLease({ key: lk, r: true, w: true, h: true, v2: v2,
                          epoch: 1 }),
                OrLease({ key: lk, r: true, w: false, h: true, v2: v2,
                          epoch: 1 })))
            val opl = if (grantAgreed(n, oplWant, treeSess(t))) oplWant
                      else OrNone
            runM(one(treeSess(t), t,
                CCreate({ dir: ROOT, name: n, disp: disp, access: acc,
                          share: sh, isDir: false, delOnClose: false,
                          oplock: opl, durable: DurNone })))
        },
    }

    // Oplock/lease lifecycle: grants, cross-handle break, every acknowledgment
    // arm, and the I/O that drives break-on-write.  Every command here is one
    // the in-process replayer builds on the wire, so this flavor is
    // generatable as well as self-testable.
    action stepLease = any {
        smbSessionSetup, smbTreeConnect,
        smbCreateCache, smbCreateCache, smbCreateCache, smbCreateCache,
        smbClose, smbClose,
        smbRead, smbWrite, smbWrite,
        smbBreakAck, smbBreakAck, smbBreakAckNone,
        smbBreakAckKeepRead, smbBreakAckStale,
        smbCompoundCreateWriteClose,
    }

    // Data / lock heavy.
    action stepData = any {
        smbSessionSetup, smbTreeConnect,
        smbCreate, smbClose,
        smbRead, smbRead, smbWrite, smbWrite, smbFlush,
        smbLock, smbLock, smbUnlock, smbSetEof,
        smbQuery,
    }

    // Replayable core (file CREATE matrix + share arbitration + I/O +
    // delete-on-close + compounds): exactly the commands the in-process C
    // replayer builds on the wire today (CREATE/CLOSE/READ/WRITE), with no
    // directories, locks, set/query-info or oplock/lease breaks -- those
    // extend the replayer in a later pass.  smbCreate here is file-only.
    action stepIo = any {
        smbSessionSetup, smbTreeConnect,
        smbCreate, smbCreate, smbCreate,
        smbClose, smbClose,
        smbRead, smbWrite, smbWrite,
        smbDeleteExisting,
        smbCompoundCreateWriteClose,
    }

    // stepIo without delete-on-close.
    //
    // `stepIo` itself is NOT generatable: it draws smbCreate (which draws
    // delOnClose) and smbDeleteExisting, and delete-on-close is the unresolved
    // Q-1 question.  Measured, not assumed: `smb2Base/stepIo 60x8 seed 0x11`
    // replays 2 of 8 clean, and every mismatch in the other six is the Q-1
    // family -- the model says STATUS_DELETE_PENDING (MS-FSA 2.1.5.1
    // adjudicates delete-pending before the sharing check) where the wire says
    // STATUS_SHARING_VIOLATION or, once the model and the server disagree about
    // whether the name still exists, STATUS_SUCCESS.  Registering it would land
    // a red suite on an unratified expectation.
    //
    // What stepIo reaches that stepCore does not, and this flavor keeps, is the
    // oplock/lease REQUEST matrix on a server with caching OFF: smbCreateCache
    // draws OrNone / OrLevelII / OrExclusive / OrBatch / OrLease(v1,v2) and
    // never delOnClose, so the corpus exercises every CreateContext-carrying
    // CREATE encoding (five parallel `switch` blocks in smb_proc_create.c), the
    // bare-RqLs reply shape -- OplockLevel=LEASE, state NONE, epoch ECHOED, the
    // M-4 shape -- and the lease-key-per-file binding of MS-SMB2 3.3.5.9.8
    // (C-10, STATUS_INVALID_PARAMETER), none of which stepCore can reach
    // because smbCreateCore always asks OrNone.
    action stepReq = any {
        smbSessionSetup, smbTreeConnect,
        smbCreateCache, smbCreateCache, smbCreateCache,
        smbClose, smbClose,
        smbRead, smbWrite, smbWrite,
        smbCompoundCreateWriteClose,
    }

    // A CREATE that never requests delete-on-close (nor an oplock): the
    // deterministic CREATE disposition/type matrix + share arbitration alone.
    action smbCreateCore = all {
        trees.size() > 0,
        liveInos.size() < MAX_OBJECTS,
        opens.size() < MAX_OPENS,
        {
            nondet t = oneOf(trees)
            nondet n = oneOf(NAMES)
            nondet disp = oneOf(DISP_SET)
            nondet acc = oneOf(ACCESS_SET)
            nondet sh = oneOf(SHARE_SET)
            runM(one(treeSess(t), t,
                CCreate({ dir: ROOT, name: n, disp: disp, access: acc,
                          share: sh, isDir: false, delOnClose: false,
                          oplock: OrNone, durable: DurNone })))
        },
    }

    // The CREATE-matrix + share + I/O + compound core with NO delete-on-close.
    // Delete-on-close semantics (deferral vs. immediate removal when another
    // handle is open) are a coherency subtlety that a dedicated ground-truth
    // probe must pin before generated traces bake an expectation -- the same
    // pin-ground-truth-first discipline the oplock probe follows -- so they
    // are excluded here.
    action stepCore = any {
        smbSessionSetup, smbTreeConnect,
        smbCreateCore, smbCreateCore, smbCreateCore,
        smbClose, smbClose,
        smbRead, smbWrite, smbWrite,
        smbCompoundCreateWriteClose,
    }

    // Metadata + byte-range locks on the deterministic core.
    //
    // This is the flavor that makes QUERY_INFO, FLUSH, SET_INFO/EndOfFile and
    // the SMB2 LOCK command reachable from a generated trace at all: before
    // it, the replayer could not build any of those PDUs, so
    // smb_proc_query_info.c and smb_proc_flush.c sat at 0% and
    // smb_proc_lock.c was reached only through the mandatory-lock consultation
    // that READ and WRITE do -- i.e. the lock TABLE was exercised and the LOCK
    // COMMAND never was.
    //
    // The two halves are drawn together on purpose.  A lock is only
    // interesting if something later runs into it, so LOCK/UNLOCK sit
    // alongside READ and WRITE, which is what turns a granted lock into the
    // mandatory-lock refusal MS-FSA 2.1.4.2/2.1.4.3 requires
    // (STATUS_FILE_LOCK_CONFLICT); and SET_EOF changes the size that the
    // QUERY_INFO oracle then has to agree about, so the query is checking a
    // moving value rather than a constant.
    //
    // smbSetEof draws `writeOpens`, not `opens`: a SET_INFO through a handle
    // without FILE_WRITE_DATA is DEVIATIONS-SMB.md S-4 (chimera does not
    // access-check SET_INFO at all), and the corpus stays free of the
    // unratified arm exactly as it does for S-2 and Q-1.
    action stepInfo = any {
        smbSessionSetup, smbTreeConnect,
        smbCreateCore, smbCreateCore,
        smbClose, smbClose,
        smbRead, smbRead, smbWrite, smbWrite,
        smbQuery, smbQuery,
        smbFlush,
        smbLock, smbLock, smbLock, smbUnlock, smbUnlock,
        smbSetEof, smbSetEof,
        smbCompoundCreateWriteClose,
    }

    // Namespace mutation + session/tree teardown on the deterministic core:
    // SET_INFO/Rename (smb_proc_set_info_rename.c, 553 lines that no generated
    // trace could reach), LOGOFF and TREE_DISCONNECT.
    //
    // What makes this a real test rather than three more status checks is that
    // all three are OBSERVED THROUGH LATER COMMANDS: a rename moves a name, so
    // every subsequent CREATE of the old and the new name adjudicates against
    // the moved namespace, and QUERY_INFO through the renamed handle must still
    // resolve; a LOGOFF or a TREE_DISCONNECT destroys every open underneath it,
    // so the objects those opens pinned become removable and the handles
    // themselves must be gone.
    //
    // smbSetDisposition is deliberately NOT drawn: setting delete-on-close
    // through SET_INFO lands in the same unresolved Q-1 family as setting it
    // on the CREATE (the model adjudicates DELETE_PENDING before the sharing
    // check, the wire the other way round), and generating it would bake an
    // unratified expectation.  The command is still built by the replayer and
    // pinned deterministically by smb2Test; add it here when Q-1 closes.
    action stepNs = any {
        smbSessionSetup, smbSessionSetup, smbTreeConnect, smbTreeConnect,
        smbCreateCore, smbCreateCore, smbCreateCore,
        smbClose, smbClose,
        smbRead, smbWrite,
        smbQuery,
        smbSetRenameNew, smbSetRenameNew,
        smbSetDispositionOff,
        smbLogoff, smbTreeDisconnect,
        smbCompoundCreateWriteClose,
    }

    // Directory-aware core: the file/directory TYPE matrix (a file CREATE over
    // an existing directory name and the reverse) and READs issued through a
    // directory handle.  Both surfaces were unreachable from a generated trace
    // -- no flavor drew smbMkdir alongside a file CREATE of the same name --
    // and both are exactly where MS-FSA 2.1.5.1.2's check ORDER and 2.1.5.2's
    // device-request guard live.  Every command here is one the in-process
    // replayer builds on the wire, so the flavor is generatable as well as
    // self-testable.
    //
    // smbMkdirRW is deliberately NOT drawn here: it is the only way to reach a
    // WRITE through a directory handle, and that is an OPEN deviation --
    // chimera answers STATUS_INTERNAL_ERROR where MS-FSA 2.1.5.3 mandates
    // STATUS_INVALID_DEVICE_REQUEST (DEVIATIONS-SMB.md S-2).  The model stays
    // spec-first and the guard is pinned deterministically by
    // smb2Test.directoryIoGuardTest; the generated corpus stays free of the
    // unresolved case, exactly as it does for delete-on-close (Q-1).  Add
    // smbMkdirRW here when S-2 closes.
    action stepDir = any {
        smbSessionSetup, smbTreeConnect,
        smbMkdir, smbMkdirExcl,
        smbCreateCore, smbCreateCore,
        smbClose, smbClose,
        smbRead, smbRead, smbWrite,
        smbCompoundCreateWriteClose,
    }

    // stepDir plus a directory open that asks for WRITE access -- the only way
    // to reach a WRITE issued through a directory handle.  Deliberately NOT
    // registered as a generated batch: it is the standing reproduction for
    // DEVIATIONS-SMB.md S-2 (chimera answers such a WRITE
    // STATUS_INTERNAL_ERROR where MS-FSA 2.1.5.3 mandates
    // STATUS_INVALID_DEVICE_REQUEST).  Register it when S-2 closes.
    action stepDirRW = any {
        smbSessionSetup, smbTreeConnect,
        smbMkdirRW, smbMkdirExcl,
        smbCreateCore,
        smbClose, smbClose,
        smbRead, smbWrite, smbWrite,
    }

    // The durable-handle lifecycle: request, grant, park on a transport drop,
    // reconnect, reclaim (well-formed and every malformed arm), and the
    // conflicting open that PURGES a parked holder.
    //
    // Deliberately narrow, for the same reason stepReq is: delete-on-close (Q-1)
    // and directories are excluded, so a failure here is a durable-handle
    // failure and not an unrelated known gap.  smbCreateCore supplies the
    // smbCreateQuiet supplies the conflicting opens that drive the purge (probe
    // D7) and, being attribute-capable, also the stat opens that must NOT purge
    // (D7b).
    //
    // Session/connection budget: EVERY smbSessionSetup and smbReconnect makes a
    // new connection in the replayer, and connections are never recycled (a
    // retired one must outlive evpl_destroy).  SMB2C_MAX_CONNS bounds that, so
    // this flavor's generated depth is bounded too -- see the batch comment in
    // CMakeLists.txt.
    // ==================================================================
    // The exactly-once layer (ROADMAP-SMB.md B4)
    //
    // Ground truth: smb2_replay_probe.c R1-R13.  Two mechanisms with two
    // different oracles, so two families of action:
    //   - a REPLAYED CREATE is answered from the original open (a reply cache
    //     keyed by the DH2Q CreateGuid) and is NOT re-applied;
    //   - a mutating op is not cached at all; one from a superseded
    //     ChannelSequence is REFUSED so it cannot clobber newer data.
    // ==================================================================

    // The ChannelSequence values the corpus draws from.  Small on purpose, and
    // chosen so both verdicts are REACHABLE from any mark the walk can be in:
    // 0/1/3 give small forward steps and the backward steps between them, and
    // 0x7FFF / 0x8000 sit exactly on the accept/reject boundary (probe R6/5,
    // R6/6).  A wider set would mostly draw pairs whose verdict is never in
    // doubt.
    pure val CS_VALUES = Set(0, 1, 3, 0x7FFF, 0x8000)

    // A WRITE carrying an explicit ChannelSequence.  Whether it is accepted or
    // refused depends on the mark the target handle happens to hold, which is
    // exactly the state the corpus should be exploring.
    action smbWriteCs = all {
        writeOpens.size() > 0,
        {
            nondet f = oneOf(writeOpens)
            val o = sdb.opens.get(f)
            nondet off = oneOf(0.to(MAX_BLOCKS - 1))
            nondet len = oneOf(1.to(MAX_BLOCKS))
            nondet pat = oneOf(BLOCK_SYMS)
            nondet cs = oneOf(CS_VALUES)
            nondet rp = oneOf(Set(false, true))
            // `rp` varies SMB2_FLAGS_REPLAY_OPERATION deliberately: the flag
            // must make NO difference to the sequence rule, in either
            // direction (probe R9).  Drawing it here is what would catch a
            // model -- or a server -- that let it matter.
            runM({ sess: o.session, tree: o.tree, related: false, cs: cs,
                   replay: rp,
                   cmds: [ CWrite({ fid: FidRef(f), off: off, len: len,
                                    pat: pat }) ] })
        },
    }

    // A READ carrying an explicit ChannelSequence.  Never refused -- but a
    // FORWARD one still moves the handle's mark (probe R7), which is the
    // interaction that makes a later write stale.
    action smbReadCs = all {
        readOpens.size() > 0,
        {
            nondet f = oneOf(readOpens)
            val o = sdb.opens.get(f)
            nondet off = oneOf(0.to(MAX_BLOCKS))
            nondet len = oneOf(1.to(MAX_BLOCKS))
            nondet cs = oneOf(CS_VALUES)
            runM({ sess: o.session, tree: o.tree, related: false, cs: cs,
                   replay: false,
                   cmds: [ CRead({ fid: FidRef(f), off: off, len: len }) ] })
        },
    }

    // A SET_INFO carrying an explicit ChannelSequence.  Its gate sits in the
    // OPPOSITE place to WRITE's -- before the class check rather than after
    // the access check (probe R12) -- so the corpus needs both.
    //
    // Drawn from `writeOpens`, not from every open, and the restriction is a
    // KNOWN DEVIATION being kept out of the corpus, not a modeling choice:
    // chimera does not access-check a SET_INFO at all, so a SET_EOF through a
    // handle with no FILE_WRITE_DATA succeeds and resizes the file where
    // MS-FSA 2.1.5.14 mandates STATUS_ACCESS_DENIED (DEVIATIONS-SMB.md S-4,
    // measured by probe R15).  The model stays spec-first -- doCmdSetEof still
    // answers ACCESS_DENIED and is pinned by smb2Test.setEofNeedsWriteTest --
    // and the generator simply does not draw the unratified shape, exactly as
    // stepDir declines to draw a directory WRITE for S-2.  What this flavor is
    // FOR is unaffected: the sequence gate's placement is measured on writable
    // handles, both the accepted and the FILE_NOT_AVAILABLE arm.
    // When S-4 closes: draw from `opens` again.
    action smbSetEofCs = all {
        writeOpens.size() > 0,
        {
            nondet f = oneOf(writeOpens)
            val o = sdb.opens.get(f)
            nondet sz = oneOf(0.to(MAX_BLOCKS))
            nondet cs = oneOf(CS_VALUES)
            runM({ sess: o.session, tree: o.tree, related: false, cs: cs,
                   replay: false,
                   cmds: [ CSetEof({ fid: FidRef(f), sizeBlocks: sz }) ] })
        },
    }

    // A CREATE re-sent with SMB2_FLAGS_REPLAY_OPERATION.  The CreateGuid is
    // drawn from the same small pool the durable creates use, so the draw
    // lands on all four classifications: a live still-eligible open (answered
    // from the cache), a parked one (reclaimed), a collision, and a guid that
    // matches nothing (an ordinary create).
    action smbReplayCreate = all {
        trees.size() > 0,
        liveInos.size() < MAX_OBJECTS,
        opens.size() < MAX_OPENS,
        {
            nondet t = oneOf(trees)
            nondet n = oneOf(NAMES)
            nondet disp = oneOf(Set(DispOpenIf, DispCreate))
            nondet g = oneOf(DUR_GUIDS)
            nondet lk = oneOf(LEASE_KEYS)
            nondet oplWant = oneOf(Set(
                OrNone,
                OrBatch,
                OrLease({ key: lk, r: true, w: true, h: true, v2: true,
                          epoch: 1 })))
            val opl = if (grantAgreed(n, oplWant, treeSess(t))) oplWant
                      else OrNone
            all {
                cachingQuiet(n),
                runM({ sess: treeSess(t), tree: t, related: false, cs: 0,
                       replay: true,
                       cmds: [ CCreate({ dir: ROOT, name: n, disp: disp,
                                         access: ACCESS_RW, share: SHARE_RWD,
                                         isDir: false, delOnClose: false,
                                         oplock: opl,
                                         durable: DurQ({ v2: true, guid: g,
                                                    persistent: false }) }) ] }),
            }
        },
    }

    // A replay carrying NO CreateGuid: there is no idempotence key, so the
    // create must be EXECUTED (probe R5).  Separate from smbReplayCreate
    // because it is the negative half that gives the cache its meaning.
    action smbReplayCreateNoKey = all {
        trees.size() > 0,
        liveInos.size() < MAX_OBJECTS,
        opens.size() < MAX_OPENS,
        {
            nondet t = oneOf(trees)
            nondet n = oneOf(NAMES)
            nondet disp = oneOf(Set(DispOpenIf, DispCreate))
            all {
                cachingQuiet(n),
                runM({ sess: treeSess(t), tree: t, related: false, cs: 0,
                       replay: true,
                       cmds: [ CCreate({ dir: ROOT, name: n, disp: disp,
                                         access: ACCESS_RW, share: SHARE_RWD,
                                         isDir: false, delOnClose: false,
                                         oplock: OrNone,
                                         durable: DurNone }) ] }),
            }
        },
    }

    // A CREATE whose own header carries a non-zero ChannelSequence, which
    // SEEDS the handle's mark (probe R11).  Without this every handle in the
    // corpus would start at 0 and the seeding rule would never be exercised.
    action smbCreateSeeded = all {
        trees.size() > 0,
        liveInos.size() < MAX_OBJECTS,
        opens.size() < MAX_OPENS,
        {
            nondet t = oneOf(trees)
            nondet n = oneOf(NAMES)
            nondet cs = oneOf(CS_VALUES)
            nondet g = oneOf(DUR_GUIDS)
            all {
                cachingQuiet(n),
                runM({ sess: treeSess(t), tree: t, related: false, cs: cs,
                       replay: false,
                       cmds: [ CCreate({ dir: ROOT, name: n, disp: DispOpenIf,
                                         access: ACCESS_RW, share: SHARE_RWD,
                                         isDir: false, delOnClose: false,
                                         oplock: OrNone,
                                         durable: DurQ({ v2: true, guid: g,
                                                    persistent: false }) }) ] }),
            }
        },
    }

    action stepDurable = any {
        smbSessionSetup, smbTreeConnect,
        smbCreateDurable, smbCreateDurable, smbCreateDurable,
        smbCreateQuiet, smbCreateQuiet,
        smbClose, smbClose,
        smbRead, smbWrite,
        smbDisconnect, smbDisconnect,
        smbReconnect, smbReconnect,
        smbReclaim, smbReclaim,
        // Weighted heavily on purpose: smbReclaimBad is enabled only while a
        // handle is actually parked, which is a minority of states, and it has
        // to cover a six-way denial draw.  Measured at the old weight it fired
        // 3 times in 136 reconnects across 8 traces of depth 200 and three of
        // its six arms never appeared -- the coverage gate turns exactly that
        // starvation red.
        smbReclaimBad, smbReclaimBad, smbReclaimBad, smbReclaimBad,
        smbReclaimUnknown,
        smbCompoundQuiet,
    }

    // The exactly-once flavor.  It keeps the durable lifecycle -- park,
    // reconnect, reclaim -- because the CREATE reply cache's PARKED arm needs
    // it, and adds the two replay families on top.
    action stepReplay = any {
        smbSessionSetup, smbTreeConnect,
        smbCreateDurable, smbCreateDurable,
        smbCreateSeeded, smbCreateSeeded,
        smbCreateQuiet,
        smbClose,
        smbWriteCs, smbWriteCs, smbWriteCs,
        smbReadCs, smbReadCs,
        smbSetEofCs, smbSetEofCs,
        smbReplayCreate, smbReplayCreate, smbReplayCreate,
        smbReplayCreateNoKey,
        smbDisconnect,
        smbReconnect,
        smbReclaim,
    }

    // The CHANGE_NOTIFY lifecycle: arm, buffer, deliver, overflow, cancel,
    // clean up.  Deliberately caching-free (no oplocks, no leases, no
    // delete-on-close): a divergence here should be a NOTIFY divergence, not a
    // break-lifecycle one that happens to have a watcher attached.
    //
    // The mix is chosen so watchers and mutators COMPETE.  Two sessions each
    // hold a root handle, so a mutation by one completes a request parked by
    // the other -- the cross-connection delivery that is the whole point of
    // the command, and the one shape a single-connection probe cannot reach.
    // Mutations outnumber arms roughly two to one so that the ring genuinely
    // fills between requests rather than being drained after every change.
    // smbSetRenameNew is deliberately absent: its target is any name but the
    // handle's own, so it mostly COLLIDES, and a collision raises no event --
    // it would spend the flavor's rename budget on an arm stepNs already
    // covers.  smbRenameFresh is here instead because it always succeeds and
    // therefore always produces the RENAMED record pair.
    action stepNotify = any {
        smbSessionSetup, smbTreeConnect,
        smbOpenDir, smbOpenDir, smbOpenDirNoRead,
        smbNotify, smbNotify, smbNotify, smbNotify,
        smbNotifyDup, smbNotifyNoRead, smbNotifyFile, smbNotifyHuge,
        smbCancelNotify,
        smbCreateRW, smbCreateRW, smbCreateRW, smbCreateShared, smbMkdir,
        smbWrite, smbWrite, smbWrite, smbSetEof, smbSetEof,
        smbRenameFresh, smbRenameFresh, smbRenameFresh,
        smbDeleteQuiet, smbDeleteQuiet,
        smbClose, smbClose,
        smbTreeDisconnect,
    }

    // The NAMESPACE half of the CHANGE_NOTIFY surface: entries appearing,
    // being renamed and disappearing, watched through the two NAME filters and
    // nothing else.
    //
    // It exists because it is the subset two independent servers agree on.
    // The classes a mutation raises are where implementations differ in
    // practice -- Samba reports a write as an attribute change, reports
    // nothing at all when a modified handle closes, and reports a create as
    // both ADDED and MODIFIED (samba_deviations.py SD-10) -- and once the two
    // sides hold different buffered events, every later request on that handle
    // diverges for reasons that have nothing to do with the notify logic.
    //
    // Restricted to the name filters, those differences become invisible: a
    // spurious MODIFIED does not match FILE_NAME, and a missing write
    // notification is not one this flavor asks for.  What remains -- the park,
    // the FIFO queue, the delivery, the cancel, the cleanup, the record pair a
    // rename expands to -- is exactly the machinery, and it is checked
    // record-for-record against a real server rather than only against the
    // implementation the model was written beside.
    //
    // One waiter per handle at a time, deliberately.  Samba reports a rename
    // as the OLD/NEW pair PLUS a spurious REMOVED (SD-12), and an extra record
    // shifts where one delivery ends and the next begins -- so with a queue,
    // two servers that agree about every event can still disagree about which
    // request each record arrived on.  The FIFO queue is covered by the full
    // stepNotify flavor and, against Samba, by the ground-truth probes that
    // established it.
    action stepNotifyNs = any {
        smbSessionSetup, smbTreeConnect,
        smbOpenDir, smbOpenDir,
        smbNotifyNames, smbNotifyNames, smbNotifyNames, smbNotifyNames,
        smbCancelNotify,
        smbCreateRW, smbCreateRW, smbMkdir,
        smbRenameFresh, smbRenameFresh, smbRenameFresh,
        smbDeleteQuiet, smbDeleteQuiet,
        smbClose, smbClose,
        smbTreeDisconnect,
    }

    // ------------------------------------------------------------------
    // Invariants
    // ------------------------------------------------------------------

    // Structural fs + protocol-state invariants.
    val invFs = fsInv(sdb.fs)
    val invSt = stInv(sdb)

    // Every caching grant that exists is one the capability profile allows --
    // per grant KIND, structurally, and with no "either feature on disarms the
    // whole check" escape.  See smb2state.stCapsRespected for what the old
    // cachingLevelNone() form could not see.
    val capsRespected = stCapsRespected(sdb, caps.oplocks, caps.leases)

    // A directory-lease-only cap (dirLeases without leases) never arises.
    val capsWellFormed = not(caps.dirLeases) or caps.leases

    // No durable grant exists unless the server advertises durable handles.
    // This is what makes caps.durable load-bearing: before this increment it
    // was drawn at init and read by nothing, so an instance with F_DURABLE off
    // could not have detected a durable grant if the model had produced one.
    val durableRespected =
        caps.durable or
        (opens.forall(f => not(sdb.opens.get(f).durable.on)) and
         sdb.parked.keys().size() == 0)

    val inv = invFs and invSt and capsRespected and capsWellFormed and
              durableRespected
}
