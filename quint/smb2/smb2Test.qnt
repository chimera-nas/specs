// SPDX-FileCopyrightText: 2026 The Quint Specs Authors
//
// SPDX-License-Identifier: MIT

// Deterministic self-checks for the SMB2 model, executed with
//   quint test smb2Test.qnt --main=smb2Test
// They validate the model's own transition logic without a server, so a
// model regression is caught before it can invalidate generated traces --
// the SMB sibling of nfs4Test.qnt.  The instance pins every optional
// feature to FeatMandatory so the capability profile is deterministic.

module smb2Test {
    import nfs4fs.* from "../nfs/nfs4_fs"
    import smb2state.* from "./smb2_state"
    import smb2ops.* from "./smb2_ops"
    import smb2(
        DIALECT = 0x0311,
        F_OPLOCKS = FeatMandatory,
        F_LEASES = FeatMandatory,
        F_DIRLEASE = FeatMandatory,
        F_DURABLE = FeatMandatory,
        P_LEASE_OPEN_BREAK = true,
        P_FORCE_LEVEL2 = false
    ).* from "./smb2"

    // ------------------------------------------------------------------
    // Result accessors
    // ------------------------------------------------------------------

    def lastResults: List[Res] =
        match lastOp {
            | LMsg(l) => l.results
            | LInit(_) => []
        }

    def resAt(i: int): Res = lastResults[i]
    def stAt(i: int): int = stOf(resAt(i))

    val noCreate: { st: int, fid: FileId, act: int, ino: Ino,
                    caching: Caching, breaks: Set[BreakNote],
                    parked: bool, durable: bool } =
        { st: -1, fid: -1, act: -1, ino: -1, caching: CNone,
          breaks: Set(), parked: false, durable: false }
    def asCreate(r) =
        match r { | RCreate(x) => x | _ => noCreate }

    val noRead = { st: -1, count: -1, eof: false, blocks: [] }
    def asRead(r) =
        match r { | RRead(x) => x | _ => noRead }

    val noWrite: { st: int, count: int, breaks: Set[BreakNote] } =
        { st: -1, count: -1, breaks: Set() }
    def asWrite(r) =
        match r { | RWrite(x) => x | _ => noWrite }

    val noQuery = { st: -1, attrs: { ftype: FReg, nlink: 0, sizeBlocks: 0,
                                     change: 0, deletePending: false } }
    def asQuery(r) =
        match r { | RQueryBasic(x) => x | _ => noQuery }

    // Common CREATE argument shorthand (non-directory).
    def create(dir: Ino, name: Name, disp: Disposition, acc: DesiredAccess,
               sh: ShareAccess, doc: bool, opl: OplockReq): Cmd =
        CCreate({ dir: dir, name: name, disp: disp, access: acc, share: sh,
                  isDir: false, delOnClose: doc, oplock: opl, durable: DurNone })

    // A one-command message with an explicit SMB2 header ChannelSequence
    // and/or SMB2_FLAGS_REPLAY_OPERATION -- the two fields the exactly-once
    // layer turns on (smb2_replay_probe.c R1-R13).
    def oneCs(sess: SessionId, tree: TreeId, c: Cmd, cs: int): Msg =
        { sess: sess, tree: tree, related: false, cs: cs, replay: false,
          cmds: [ c ] }

    def oneRp(sess: SessionId, tree: TreeId, c: Cmd): Msg =
        { sess: sess, tree: tree, related: false, cs: 0, replay: true,
          cmds: [ c ] }

    def oneCsRp(sess: SessionId, tree: TreeId, c: Cmd, cs: int): Msg =
        { sess: sess, tree: tree, related: false, cs: cs, replay: true,
          cmds: [ c ] }

    // ------------------------------------------------------------------
    // Bootstrap: one session (client 1) + one tree.
    // ------------------------------------------------------------------

    run bootRun =
        init
            .then(runM({ sess: -1, tree: -1, related: false, cs: 0, replay: false,
                         cmds: [ CSessionSetup({ clientSym: 1 }) ] }))
            .expect(stAt(0) == ST_SUCCESS and sdb.sessions.keys().contains(0))
            .then(runM(one(0, -1, CTreeConnect({ share: 1 }))))
            .expect(stAt(0) == ST_SUCCESS and sdb.trees.keys().contains(0))

    // Bootstrap plus a second session (client 2) + tree for cross-session
    // conflict tests: session 1, tree 1.
    run boot2Run =
        bootRun
            .then(runM({ sess: -1, tree: -1, related: false, cs: 0, replay: false,
                         cmds: [ CSessionSetup({ clientSym: 2 }) ] }))
            .expect(stAt(0) == ST_SUCCESS and sdb.sessions.keys().contains(1))
            .then(runM(one(1, -1, CTreeConnect({ share: 1 }))))
            .expect(stAt(0) == ST_SUCCESS and sdb.trees.keys().contains(1))

    // ------------------------------------------------------------------
    // CREATE disposition / type matrix (MS-FSA 2.1.5.1)
    // ------------------------------------------------------------------

    run createMatrixTest =
        bootRun
            // OPEN of a missing name -> OBJECT_NAME_NOT_FOUND.
            .then(runM(one(0, 0, create(ROOT, "a", DispOpen, ACCESS_R,
                                        SHARE_RWD, false, OrNone))))
            .expect(stAt(0) == ST_OBJECT_NAME_NOT_FOUND)
            // CREATE of a fresh file -> CREATED, fid 0.
            .then(runM(one(0, 0, create(ROOT, "a", DispCreate, ACCESS_RW,
                                        SHARE_RWD, false, OrNone))))
            .expect(stAt(0) == ST_SUCCESS and asCreate(resAt(0)).act == ACT_CREATED)
            .expect(asCreate(resAt(0)).fid == 0)
            // CREATE over the existing file -> OBJECT_NAME_COLLISION.
            .then(runM(one(0, 0, create(ROOT, "a", DispCreate, ACCESS_RW,
                                        SHARE_RWD, false, OrNone))))
            .expect(stAt(0) == ST_OBJECT_NAME_COLLISION)
            // OPEN_IF of the existing file -> OPENED.
            .then(runM(one(0, 0, create(ROOT, "a", DispOpenIf, ACCESS_R,
                                        SHARE_RWD, false, OrNone))))
            .expect(stAt(0) == ST_SUCCESS and asCreate(resAt(0)).act == ACT_OPENED)
            // OVERWRITE of a missing name -> OBJECT_NAME_NOT_FOUND.
            .then(runM(one(0, 0, create(ROOT, "z", DispOverwrite, ACCESS_RW,
                                        SHARE_RWD, false, OrNone))))
            .expect(stAt(0) == ST_OBJECT_NAME_NOT_FOUND)
            // SUPERSEDE of the existing file -> FILE_SUPERSEDED, size 0.
            .then(runM(one(0, 0, create(ROOT, "a", DispSupersede, ACCESS_RW,
                                        SHARE_RWD, false, OrNone))))
            .expect(stAt(0) == ST_SUCCESS and
                    asCreate(resAt(0)).act == ACT_SUPERSEDED)

    // A directory-create then a non-directory OPEN of the same name is a
    // type mismatch -> FILE_IS_A_DIRECTORY.
    run createTypeMismatchTest =
        bootRun
            .then(runM(one(0, 0, CCreate({ dir: ROOT, name: "d",
                                           disp: DispCreate, access: ACCESS_R,
                                           share: SHARE_RWD, isDir: true,
                                           delOnClose: false,
                                           oplock: OrNone, durable: DurNone }))))
            .expect(stAt(0) == ST_SUCCESS and asCreate(resAt(0)).act == ACT_CREATED)
            .then(runM(one(0, 0, create(ROOT, "d", DispOpen, ACCESS_R,
                                        SHARE_RWD, false, OrNone))))
            .expect(stAt(0) == ST_FILE_IS_A_DIRECTORY)

    // MS-FSA 2.1.5.1.2 runs the existing-file checks in a fixed order, and the
    // order is observable: FILE_CREATE's OBJECT_NAME_COLLISION comes BEFORE the
    // type mismatch, which in turn comes before the truncate-a-directory
    // INVALID_PARAMETER.  Every rung of that order is pinned here.
    run createCheckOrderTest =
        bootRun
            .then(runM(one(0, 0, CCreate({ dir: ROOT, name: "d",
                                           disp: DispCreate, access: ACCESS_R,
                                           share: SHARE_RWD, isDir: true,
                                           delOnClose: false,
                                           oplock: OrNone, durable: DurNone }))))
            .expect(stAt(0) == ST_SUCCESS and asCreate(resAt(0)).fid == 0)
            // Rung 1: FILE_CREATE over an EXISTING directory is a collision.
            // The target's type is not consulted at all, so this is NOT
            // STATUS_FILE_IS_A_DIRECTORY.
            .then(runM(one(0, 0, create(ROOT, "d", DispCreate, ACCESS_R,
                                        SHARE_RWD, false, OrNone))))
            .expect(stAt(0) == ST_OBJECT_NAME_COLLISION)
            // Rung 2: a non-FILE_CREATE disposition DOES reach the type check.
            .then(runM(one(0, 0, create(ROOT, "d", DispOpen, ACCESS_R,
                                        SHARE_RWD, false, OrNone))))
            .expect(stAt(0) == ST_FILE_IS_A_DIRECTORY)
            // Rung 2 before rung 3: a TRUNCATING disposition on a directory
            // opened with FILE_NON_DIRECTORY_FILE reports the type mismatch,
            // not the truncate-a-directory INVALID_PARAMETER.
            .then(runM(one(0, 0, create(ROOT, "d", DispOverwriteIf, ACCESS_RW,
                                        SHARE_RWD, false, OrNone))))
            .expect(stAt(0) == ST_FILE_IS_A_DIRECTORY)
            // Rung 3: with FILE_DIRECTORY_FILE the type matches, so the
            // truncate-a-directory arm is what fires.
            .then(runM(one(0, 0, CCreate({ dir: ROOT, name: "d",
                                           disp: DispOverwriteIf,
                                           access: ACCESS_RW,
                                           share: SHARE_RWD, isDir: true,
                                           delOnClose: false,
                                           oplock: OrNone, durable: DurNone }))))
            .expect(stAt(0) == ST_INVALID_PARAMETER)
            // The other diagonal: a DIRECTORY FILE_CREATE over an existing
            // FILE is a collision too, not STATUS_NOT_A_DIRECTORY...
            .then(runM(one(0, 0, create(ROOT, "f", DispCreate, ACCESS_RW,
                                        SHARE_RWD, false, OrNone))))
            .expect(stAt(0) == ST_SUCCESS and asCreate(resAt(0)).fid == 1)
            .then(runM(one(0, 0, CCreate({ dir: ROOT, name: "f",
                                           disp: DispCreate, access: ACCESS_R,
                                           share: SHARE_RWD, isDir: true,
                                           delOnClose: false,
                                           oplock: OrNone, durable: DurNone }))))
            .expect(stAt(0) == ST_OBJECT_NAME_COLLISION)
            // ... while a directory OPEN of that file still reports the type.
            .then(runM(one(0, 0, CCreate({ dir: ROOT, name: "f",
                                           disp: DispOpen, access: ACCESS_R,
                                           share: SHARE_RWD, isDir: true,
                                           delOnClose: false,
                                           oplock: OrNone, durable: DurNone }))))
            .expect(stAt(0) == ST_NOT_A_DIRECTORY)

    // A READ or a WRITE through a DIRECTORY handle is refused on the stream
    // type -- STATUS_INVALID_DEVICE_REQUEST (MS-FSA 2.1.5.2 / 2.1.5.3) -- and
    // never degenerates into the END_OF_FILE a zero-length data stream would
    // otherwise produce, nor into a write that gives a directory data blocks.
    run directoryIoGuardTest =
        bootRun
            .then(runM(one(0, 0, CCreate({ dir: ROOT, name: "d",
                                           disp: DispCreate, access: ACCESS_RW,
                                           share: SHARE_RWD, isDir: true,
                                           delOnClose: false,
                                           oplock: OrNone, durable: DurNone }))))
            .expect(stAt(0) == ST_SUCCESS and asCreate(resAt(0)).fid == 0)
            .then(runM(one(0, 0, CRead({ fid: FidRef(0), off: 0, len: 1 }))))
            .expect(stAt(0) == ST_INVALID_DEVICE_REQUEST)
            // The guard precedes the access check: a directory handle WITHOUT
            // write access is still INVALID_DEVICE_REQUEST, not ACCESS_DENIED.
            .then(runM(one(0, 0, CCreate({ dir: ROOT, name: "d",
                                           disp: DispOpen, access: ACCESS_R,
                                           share: SHARE_RWD, isDir: true,
                                           delOnClose: false,
                                           oplock: OrNone, durable: DurNone }))))
            .expect(stAt(0) == ST_SUCCESS and asCreate(resAt(0)).fid == 1)
            .then(runM(one(0, 0, CWrite({ fid: FidRef(1), off: 0, len: 1,
                                          pat: 1 }))))
            .expect(stAt(0) == ST_INVALID_DEVICE_REQUEST)
            .then(runM(one(0, 0, CWrite({ fid: FidRef(0), off: 0, len: 1,
                                          pat: 1 }))))
            .expect(stAt(0) == ST_INVALID_DEVICE_REQUEST)
            // The directory is untouched: no data blocks, no size, still FDir.
            .expect(fsGet(sdb.fs, 1).ftype == FDir and
                    fsGet(sdb.fs, 1).sizeBlocks == 0)
            // A FILE handle is unaffected -- a read at EOF is still
            // END_OF_FILE, so the guard did not swallow the data path.
            .then(runM(one(0, 0, create(ROOT, "f", DispCreate, ACCESS_RW,
                                        SHARE_RWD, false, OrNone))))
            .expect(stAt(0) == ST_SUCCESS and asCreate(resAt(0)).fid == 2)
            .then(runM(one(0, 0, CRead({ fid: FidRef(2), off: 0, len: 1 }))))
            .expect(stAt(0) == ST_END_OF_FILE)
            .then(runM(one(0, 0, CWrite({ fid: FidRef(2), off: 0, len: 1,
                                          pat: 1 }))))
            .expect(stAt(0) == ST_SUCCESS)

    // ------------------------------------------------------------------
    // Share reservations (MS-FSA SharingViolation)
    // ------------------------------------------------------------------

    run shareConflictTest =
        boot2Run
            // Client 1 opens "a" for read+write, sharing READ only (deny
            // WRITE + DELETE).
            .then(runM(one(0, 0, create(ROOT, "a", DispCreate, ACCESS_RW,
                                        SHARE_R, false, OrNone))))
            .expect(stAt(0) == ST_SUCCESS)
            // Client 2 opens "a" for WRITE -> intersects client 1's deny-W
            // -> SHARING_VIOLATION.
            .then(runM(one(1, 1, create(ROOT, "a", DispOpen, ACCESS_W,
                                        SHARE_RWD, false, OrNone))))
            .expect(stAt(0) == ST_SHARING_VIOLATION)
            // Client 2 opens "a" for READ, sharing R+W+D so it denies
            // nothing of client 1's held R+W -> OK (client 1 shares READ,
            // so client 2's read access is permitted too).
            .then(runM(one(1, 1, create(ROOT, "a", DispOpen, ACCESS_R,
                                        SHARE_RWD, false, OrNone))))
            .expect(stAt(0) == ST_SUCCESS)
            // An attribute-only open bypasses share arbitration entirely.
            .then(runM(one(1, 1, create(ROOT, "a", DispOpen,
                                        { r: false, w: false, h: true,
                                          d: false }, SHARE_NONE, false,
                                        OrNone))))
            .expect(stAt(0) == ST_SUCCESS)

    // A truncating disposition (SUPERSEDE / OVERWRITE / OVERWRITE_IF) must
    // obtain WRITE access at open time to replace the data, so it takes part in
    // share arbitration as a WRITER even when DesiredAccess asked for none --
    // and it does NOT retain that write access for the handle's lifetime
    // (MS-FSA 2.1.5.1.2; smb_proc_create.c's held_granted snapshot).
    run truncatingTakesWriteTest =
        boot2Run
            // Seed "a" with one block, so a truncate is OBSERVABLE.  Without
            // data every truncate is a no-op and the SD-7 assertion below --
            // that a REFUSED truncating open did not truncate -- would hold
            // vacuously.
            .then(runM(one(0, 0, create(ROOT, "a", DispCreate, ACCESS_RW,
                                        SHARE_RWD, false, OrNone))))
            .expect(stAt(0) == ST_SUCCESS and asCreate(resAt(0)).fid == 0)
            .then(runM(one(0, 0, CWrite({ fid: FidRef(0), off: 0, len: 1,
                                          pat: 1 }))))
            .expect(stAt(0) == ST_SUCCESS)
            .then(runM(one(0, 0, CClose(FidRef(0)))))
            .expect(stAt(0) == ST_SUCCESS)
            // Client 0 now holds "a" read-only and shares READ only, so it
            // denies WRITE and DELETE to everyone else.
            .then(runM(one(0, 0, create(ROOT, "a", DispOpen, ACCESS_R,
                                        SHARE_R, false, OrNone))))
            .expect(stAt(0) == ST_SUCCESS and asCreate(resAt(0)).fid == 1)
            // A read-only OPEN asserts no write, so it coexists.
            .then(runM(one(1, 1, create(ROOT, "a", DispOpen, ACCESS_R,
                                        SHARE_R, false, OrNone))))
            .expect(stAt(0) == ST_SUCCESS and asCreate(resAt(0)).fid == 2)
            .then(runM(one(1, 1, CClose(FidRef(2)))))
            .expect(stAt(0) == ST_SUCCESS)
            // The SAME DesiredAccess with a truncating disposition asserts
            // WRITE and therefore collides with client 1's deny-W.  All three
            // truncating dispositions behave alike.
            .then(runM(one(1, 1, create(ROOT, "a", DispOverwriteIf, ACCESS_R,
                                        SHARE_R, false, OrNone))))
            .expect(stAt(0) == ST_SHARING_VIOLATION)
            .then(runM(one(1, 1, create(ROOT, "a", DispOverwrite, ACCESS_R,
                                        SHARE_R, false, OrNone))))
            .expect(stAt(0) == ST_SHARING_VIOLATION)
            .then(runM(one(1, 1, create(ROOT, "a", DispSupersede, ACCESS_R,
                                        SHARE_R, false, OrNone))))
            .expect(stAt(0) == ST_SHARING_VIOLATION)
            // An ATTRIBUTE-ONLY open with a TRUNCATING disposition is NOT a
            // stat open: the truncate is the only thing asserting write, and
            // it asserts it just as much as an explicit FILE_WRITE_DATA would.
            // So it collides with the deny-W peer exactly like the arms above.
            // (This used to expect SUCCESS -- the share check was skipped for
            // any attribute-only open, which discarded the very write bit
            // wantOf() had just added.  Samba refuses it; SD-3.)
            .then(runM(one(1, 1, create(ROOT, "a", DispOverwriteIf,
                                        { r: false, w: false, h: true,
                                          d: false }, SHARE_NONE, false,
                                        OrNone))))
            .expect(stAt(0) == ST_SHARING_VIOLATION)
            // ...and a REFUSED truncating open must not have truncated:
            // "a" still holds the block client 0 wrote.  A failed open has no
            // side effects (MS-FSA 2.1.5.1.2 arbitrates before it modifies).
            // The model used to commit the disposition before the share check,
            // so the refusal above silently emptied the file (SD-7).
            .expect(sdb.fs.inodes.get(1).sizeBlocks == 1)
            // With the write-denying peer gone the truncating open succeeds --
            // and the write access it took for the CONFLICT CHECK is not
            // RETAINED: the handle still carries no write, so a WRITE through
            // it is ACCESS_DENIED.
            .then(runM(one(0, 0, CClose(FidRef(1)))))
            .expect(stAt(0) == ST_SUCCESS)
            .then(runM(one(1, 1, create(ROOT, "a", DispOverwriteIf, ACCESS_R,
                                        SHARE_R, false, OrNone))))
            .expect(stAt(0) == ST_SUCCESS and asCreate(resAt(0)).fid == 3)
            .expect(sdb.opens.get(3).granted.r and
                    not(sdb.opens.get(3).granted.w))
            // NOW it truncated -- the open succeeded, so the disposition landed.
            .expect(sdb.fs.inodes.get(1).sizeBlocks == 0)
            .then(runM(one(1, 1, CWrite({ fid: FidRef(3), off: 0, len: 1,
                                          pat: 1 }))))
            .expect(stAt(0) == ST_ACCESS_DENIED)

    // The other half of a truncating open's participation: it asserts its
    // ShareAccess against existing holders at OPEN time, but leaves no deny
    // behind afterwards.  The two are genuinely different values -- the write
    // it takes is transient, so once the handle exists it is an ordinary
    // attribute-only handle and denies nobody.
    run truncatingDenyIsOpenTimeOnlyTest =
        boot2Run
            .then(runM(one(0, 0, create(ROOT, "a", DispCreate, ACCESS_RW,
                                        SHARE_RWD, false, OrNone))))
            .expect(stAt(0) == ST_SUCCESS and asCreate(resAt(0)).fid == 0)
            // A peer holding READ and sharing everything.
            .then(runM(one(0, 0, create(ROOT, "a", DispOpen, ACCESS_R,
                                        SHARE_RWD, false, OrNone))))
            .expect(stAt(0) == ST_SUCCESS and asCreate(resAt(0)).fid == 1)
            // An attribute-only TRUNCATING open that shares nothing collides
            // with that peer's READ -- its ShareAccess is arbitrated.
            .then(runM(one(1, 1, create(ROOT, "a", DispOverwriteIf, ACCESS_H,
                                        SHARE_NONE, false, OrNone))))
            .expect(stAt(0) == ST_SHARING_VIOLATION)
            // The same open is fine while nothing else holds the file...
            .then(runM(one(0, 0, CClose(FidRef(1)))))
            .expect(stAt(0) == ST_SUCCESS)
            .then(runM(one(0, 0, CClose(FidRef(0)))))
            .expect(stAt(0) == ST_SUCCESS)
            .then(runM(one(1, 1, create(ROOT, "a", DispOverwriteIf, ACCESS_H,
                                        SHARE_NONE, false, OrNone))))
            .expect(stAt(0) == ST_SUCCESS and asCreate(resAt(0)).fid == 2)
            // ...and having taken it, it denies NOTHING: a reader gets in even
            // though the truncating handle shared nothing.
            .expect(sdb.opens.get(2).denied == { r: false, w: false, d: false })
            .then(runM(one(0, 0, create(ROOT, "a", DispOpen, ACCESS_R,
                                        SHARE_RWD, false, OrNone))))
            .expect(stAt(0) == ST_SUCCESS)

    // A byte-range lock is a data operation and needs data access on the
    // handle: neither a DELETE-only nor an attribute-only handle may take one
    // (MS-SMB2 3.3.5.14).  The model used to perform no access check at all
    // and granted both (samba conformance suite, SD-2).
    run lockNeedsDataAccessTest =
        bootRun
            .then(runM(one(0, 0, create(ROOT, "a", DispCreate, ACCESS_RW,
                                        SHARE_RWD, false, OrNone))))
            .expect(stAt(0) == ST_SUCCESS)
            .then(runM(one(0, 0, CLock({ fid: FidRef(0), lo: 0, hi: 2,
                                         wr: true, unlock: false,
                                         failImmediately: true }))))
            .expect(stAt(0) == ST_SUCCESS)
            // read-only is enough
            .then(runM(one(0, 0, create(ROOT, "a", DispOpen, ACCESS_R,
                                        SHARE_RWD, false, OrNone))))
            .then(runM(one(0, 0, CLock({ fid: FidRef(1), lo: 4, hi: 5,
                                         wr: false, unlock: false,
                                         failImmediately: true }))))
            .expect(stAt(0) == ST_SUCCESS)
            // DELETE-only is not
            .then(runM(one(0, 0, create(ROOT, "a", DispOpen, ACCESS_D,
                                        SHARE_RWD, false, OrNone))))
            .then(runM(one(0, 0, CLock({ fid: FidRef(2), lo: 5, hi: 6,
                                         wr: true, unlock: false,
                                         failImmediately: true }))))
            .expect(stAt(0) == ST_ACCESS_DENIED)
            // nor is attribute-only
            .then(runM(one(0, 0, create(ROOT, "a", DispOpen, ACCESS_H,
                                        SHARE_RWD, false, OrNone))))
            .then(runM(one(0, 0, CLock({ fid: FidRef(3), lo: 5, hi: 6,
                                         wr: true, unlock: false,
                                         failImmediately: true }))))
            .expect(stAt(0) == ST_ACCESS_DENIED)
            // and the refusals took no lock: the range is still free
            .then(runM(one(0, 0, CLock({ fid: FidRef(0), lo: 5, hi: 6,
                                         wr: true, unlock: false,
                                         failImmediately: true }))))
            .expect(stAt(0) == ST_SUCCESS)

    // ------------------------------------------------------------------
    // Oplock/lease break lifecycle
    // ------------------------------------------------------------------

    // Acknowledgment shorthands.
    def ackKeep(f: FileId, isL: bool, b: LeaseState): Cmd =
        CBreakAck({ fid: FidRef(f), asLease: isL, ackLevel: oplockOfBits(b),
                    ackState: b })

    // A sole opener gets a batch oplock.  A conflicting open breaks it to
    // LEVEL_II and, because that break is ACK-REQUIRED, the opener's own
    // CREATE is held behind an async interim (parked) -- but it still carries
    // its real status, not STATUS_PENDING.  The holder then acks.
    run oplockBreakOnOpenTest =
        boot2Run
            .then(runM(one(0, 0, create(ROOT, "a", DispCreate, ACCESS_RW,
                                        SHARE_RW, false, OrBatch))))
            .expect(stAt(0) == ST_SUCCESS)
            .expect(asCreate(resAt(0)).caching == COplock(OpBatch))
            // Client 2's conflicting open: the batch holder breaks to LEVEL_II
            // (phase 1, retained R) and the open completes, parked.
            .then(runM(one(1, 1, create(ROOT, "a", DispOpen, ACCESS_R,
                                        SHARE_RW, false, OrNone))))
            .expect(stAt(0) == ST_SUCCESS)
            .expect(asCreate(resAt(0)).parked)
            .expect(asCreate(resAt(0)).breaks.size() == 1)
            .expect(asCreate(resAt(0)).breaks.forall(b =>
                    b.fid == 0 and not(b.isLease) and b.ackReq and
                    b.newLevel == 0x01))
            .expect(sdb.opens.get(0).breaking and
                    sdb.opens.get(0).breakTo == COplock(OpLevelII))
            // Holder acks, keeping the read cache -> settles at level II.
            .then(runM(one(0, 0, ackKeep(0, false, BITS_R))))
            .expect(stAt(0) == ST_SUCCESS)
            .expect(sdb.opens.get(0).caching == COplock(OpLevelII) and
                    not(sdb.opens.get(0).breaking))
            // Idempotency: a second ack on the settled grant is rejected.  For
            // a legacy oplock the code depends on the level held and the level
            // acknowledged: LEVEL_II held, NONE acknowledged ->
            // STATUS_INVALID_DEVICE_STATE (MS-SMB2 3.3.5.22.1).
            .then(runM(one(0, 0, ackKeep(0, false, BITS_NONE))))
            .expect(stAt(0) == ST_INVALID_DEVICE_STATE)
            // A further open no longer parks: no ack-required break is left.
            .then(runM(one(1, 1, create(ROOT, "a", DispOpen, ACCESS_R,
                                        SHARE_RW, false, OrNone))))
            .expect(stAt(0) == ST_SUCCESS and asCreate(resAt(0)).fid == 2)
            .expect(not(asCreate(resAt(0)).parked))

    // break_reads_for_write (Seam 4a): a writer coexisting with a level-II
    // read cache breaks that cache to NONE when it writes.  The writer
    // opened first (no cache), so the reader's later level-II grant is not
    // broken at open; the WRITE op is what recalls it.  A LEVEL_II break needs
    // NO acknowledgment, so the grant settles the instant it is sent.
    run oplockBreakOnWriteTest =
        boot2Run
            // Writer opens first, no oplock -> no cache.
            .then(runM(one(0, 0, create(ROOT, "b", DispCreate, ACCESS_RW,
                                        SHARE_RW, false, OrNone))))
            .expect(stAt(0) == ST_SUCCESS and asCreate(resAt(0)).fid == 0)
            // Reader opens, level II granted (writer holds no cache to break).
            .then(runM(one(1, 1, create(ROOT, "b", DispOpen, ACCESS_R,
                                        SHARE_RW, false, OrLevelII))))
            .expect(stAt(0) == ST_SUCCESS)
            .expect(asCreate(resAt(0)).caching == COplock(OpLevelII) and
                    asCreate(resAt(0)).fid == 1)
            // Writer writes -> reader's level-II cache is recalled to NONE,
            // unsolicited and final (ackReq false), so it settles at once.
            .then(runM(one(0, 0, CWrite({ fid: FidRef(0), off: 0, len: 1,
                                          pat: 1 }))))
            .expect(stAt(0) == ST_SUCCESS)
            .expect(asWrite(resAt(0)).breaks.size() == 1)
            .expect(asWrite(resAt(0)).breaks.forall(b =>
                    b.fid == 1 and not(b.isLease) and not(b.ackReq) and
                    b.newLevel == 0x00))
            .expect(not(sdb.opens.get(1).breaking) and
                    sdb.opens.get(1).caching == COplock(OpNone))
            // Acking a break that required no ack is a protocol error, not a
            // benign no-op (probe O8).
            .then(runM(one(1, 1, ackKeep(1, false, BITS_NONE))))
            .expect(stAt(0) == ST_INVALID_DEVICE_STATE)

    // A lease that has been broken to NONE is still a LEASE: it stays bound to
    // its key until its last open closes, and a later open under that key joins
    // it rather than minting a new one.  Regression test -- the model used to
    // drop the binding the moment the state hit NONE, so the re-open below
    // produced a brand new v2 lease at a fresh epoch under a key already bound
    // to a v1 lease.  Caught by replaying the corpus against chimera, which
    // reported the existing lease (v1, epoch 0) exactly as MS-SMB2 3.3.5.9.8
    // requires.
    //
    // The join also UPGRADES: the re-open asks for caching the lease no longer
    // holds, and gets it back, at the lease's own version.
    run leaseSurvivesBreakToNoneTest =
        boot2Run
            // Session 0 takes a v1 lease under key 5 on "s", caching R.
            .then(runM(one(0, 0, create(ROOT, "s", DispCreate, ACCESS_RW,
                                        SHARE_RW, false,
                                        OrLease({ key: 5, r: true, w: false,
                                                  h: false, v2: false,
                                                  epoch: 0 })))))
            .expect(stAt(0) == ST_SUCCESS and asCreate(resAt(0)).fid == 0)
            .expect(match asCreate(resAt(0)).caching {
                | CLease(x) => x.st.r and x.key == 5 and not(x.v2)
                | _ => false })
            // A peer write recalls it to NONE.  The open stays open.
            .then(runM(one(1, 1, create(ROOT, "s", DispOpen, ACCESS_RW,
                                        SHARE_RW, false, OrNone))))
            .expect(stAt(0) == ST_SUCCESS)
            .then(runM(one(1, 1, CWrite({ fid: FidRef(1), off: 0, len: 1,
                                          pat: 7 }))))
            .expect(stAt(0) == ST_SUCCESS)
            .expect(cachingLevelNone(sdb.opens.get(0).caching))
            // ... and it is still a lease bound to key 5, not a dead entry.
            .expect(match sdb.opens.get(0).caching {
                | CLease(x) => x.key == 5 and not(x.v2)
                | _ => false })
            // Re-open under the SAME key, now asking v2.  This must JOIN the
            // existing v1 lease -- reporting its version, so epoch 0 -- and not
            // mint a v2 lease at epoch 2.
            .then(runM(one(0, 0, create(ROOT, "s", DispOpen, ACCESS_R,
                                        SHARE_RW, false,
                                        OrLease({ key: 5, r: true, w: false,
                                                  h: false, v2: true,
                                                  epoch: 1 })))))
            .expect(stAt(0) == ST_SUCCESS)
            .expect(match asCreate(resAt(0)).caching {
                | CLease(x) => x.key == 5 and not(x.v2) and x.epoch == 0 and
                               // upgraded back to R by the join
                               x.st.r and not(x.st.w) and not(x.st.h)
                | _ => false })

    // A lease grants RWH to a sole opener; write caching (W) is only handed
    // to a sole opener (discretion).  A v2 lease is granted at the client's
    // epoch + 1 (MS-SMB2 3.3.5.9.11; probe O7 observed epoch 2 for a request
    // of epoch 1), a v1 lease is not versioned at all (epoch 0; probe O9).
    run leaseGrantTest =
        bootRun
            .then(runM(one(0, 0, create(ROOT, "a", DispCreate, ACCESS_RW,
                                        SHARE_RW, false,
                                        OrLease({ key: 7, r: true, w: true,
                                                  h: true, v2: true,
                                                  epoch: 1 })))))
            .expect(stAt(0) == ST_SUCCESS)
            .expect(match asCreate(resAt(0)).caching {
                | CLease(x) => x.st.r and x.st.w and x.st.h and
                               x.key == 7 and x.epoch == 2 and x.v2
                | _ => false })
            .then(runM(one(0, 0, create(ROOT, "z", DispCreate, ACCESS_RW,
                                        SHARE_RW, false,
                                        OrLease({ key: 8, r: true, w: true,
                                                  h: true, v2: false,
                                                  epoch: 4 })))))
            .expect(stAt(0) == ST_SUCCESS)
            .expect(match asCreate(resAt(0)).caching {
                | CLease(x) => x.epoch == 0 and not(x.v2)
                | _ => false })
            // A lease state asking for W or H without R is invalid and grants
            // NONE (MS-SMB2 3.3.5.9.8).
            .then(runM(one(0, 0, create(ROOT, "y", DispCreate, ACCESS_RW,
                                        SHARE_RW, false,
                                        OrLease({ key: 9, r: false, w: true,
                                                  h: true, v2: true,
                                                  epoch: 1 })))))
            .expect(stAt(0) == ST_SUCCESS)
            .expect(cachingLevelNone(asCreate(resAt(0)).caching))

    // The v2 epoch versions the lease STATE, so a grant that establishes NO
    // caching state does not advance it: the requested epoch is echoed back
    // unchanged (MS-SMB2 3.3.5.9.11; chimera's bare-RqLs branch says the same).
    run deniedLeaseEpochTest =
        bootRun
            // W/H without R is an invalid lease state and grants NONE
            // (3.3.5.9.8) -- a DENIED grant, so epoch 4 in, epoch 4 out.
            .then(runM(one(0, 0, create(ROOT, "y", DispCreate, ACCESS_RW,
                                        SHARE_RW, false,
                                        OrLease({ key: 9, r: false, w: true,
                                                  h: true, v2: true,
                                                  epoch: 4 })))))
            .expect(stAt(0) == ST_SUCCESS)
            .expect(match asCreate(resAt(0)).caching {
                | CLease(x) => bitsEmpty(x.st) and x.epoch == 4 and x.v2
                | _ => false })
            // A grant that DOES establish caching lands at epoch + 1.
            .then(runM(one(0, 0, create(ROOT, "z", DispCreate, ACCESS_RW,
                                        SHARE_RW, false,
                                        OrLease({ key: 10, r: true, w: true,
                                                  h: true, v2: true,
                                                  epoch: 4 })))))
            .expect(stAt(0) == ST_SUCCESS)
            .expect(match asCreate(resAt(0)).caching {
                | CLease(x) => x.st.r and x.st.w and x.st.h and x.epoch == 5
                | _ => false })
            // A v1 lease is not epoch-versioned at all, granted or denied.
            .then(runM(one(0, 0, create(ROOT, "w", DispCreate, ACCESS_RW,
                                        SHARE_RW, false,
                                        OrLease({ key: 11, r: false, w: true,
                                                  h: true, v2: false,
                                                  epoch: 4 })))))
            .expect(stAt(0) == ST_SUCCESS)
            .expect(match asCreate(resAt(0)).caching {
                | CLease(x) => bitsEmpty(x.st) and x.epoch == 0
                | _ => false })

    // The capability invariant is STRUCTURAL and per grant KIND.  The form it
    // replaced -- `(caps.oplocks or caps.leases) or opens.forall(
    // cachingLevelNone)` -- was satisfied by any grant that merely happened to
    // be empty, and disarmed completely as soon as either feature was on.
    run capsRespectedStructuralTest =
        bootRun
            .then(runM(one(0, 0, create(ROOT, "a", DispCreate, ACCESS_RW,
                                        SHARE_RW, false, OrNone))))
            .expect(stAt(0) == ST_SUCCESS and asCreate(resAt(0)).fid == 0)
            // No grant at all is legal under every profile.
            .expect(stCapsRespected(sdb, false, false) and
                    stCapsRespected(sdb, true, true))
            // An INERT legacy grant is still a legacy grant: legal only where
            // oplocks are advertised.  cachingLevelNone() accepted COplock(
            // OpNone) unconditionally, which is the hole this closes.
            .expect({
                val inert = sdb.with("opens", sdb.opens.setBy(0, o =>
                                o.with("caching", COplock(OpNone))))
                cachingLevelNone(COplock(OpNone)) and
                stCapsRespected(inert, true, false) and
                not(stCapsRespected(inert, false, false)) and
                not(stCapsRespected(inert, false, true))
            })
            // A level-II oplock handed out with oplocks OFF but leases ON: the
            // old form's `caps.oplocks or caps.leases` guard let this through.
            .expect({
                val ii = sdb.with("opens", sdb.opens.setBy(0, o =>
                             o.with("caching", COplock(OpLevelII))))
                not(stCapsRespected(ii, false, true)) and
                stCapsRespected(ii, true, false)
            })
            // With leasing off, the bare-RqLs echo -- a lease that caches
            // nothing, which is exactly what the wire reports -- survives; a
            // lease that CACHES does not.
            .expect({
                val bare = sdb.with("opens", sdb.opens.setBy(0, o =>
                               o.with("caching", CLease({ key: 1, st: BITS_NONE,
                                                          epoch: 3,
                                                          v2: true,
                                                          grant: false }))))
                val cached = sdb.with("opens", sdb.opens.setBy(0, o =>
                                 o.with("caching", CLease({ key: 1, st: BITS_R,
                                                            epoch: 3,
                                                            v2: true,
                                                            grant: true }))))
                stCapsRespected(bare, false, false) and
                not(stCapsRespected(cached, false, false)) and
                not(stCapsRespected(cached, true, false)) and
                stCapsRespected(cached, false, true)
            })

    // Two opens under ONE lease key coalesce onto a single grant: the second
    // reports the first's state and epoch, never reduces it, and the pair
    // breaks ONCE (MS-SMB2 3.3.5.9.8/.11; probe O7).
    run leaseCoalesceTest =
        boot2Run
            .then(runM(one(0, 0, create(ROOT, "a", DispCreate, ACCESS_RW,
                                        SHARE_RWD, false,
                                        OrLease({ key: 5, r: true, w: true,
                                                  h: true, v2: true,
                                                  epoch: 1 })))))
            .expect(stAt(0) == ST_SUCCESS)
            // Second open, same key, asking for LESS.
            .then(runM(one(0, 0, create(ROOT, "a", DispOpen, ACCESS_R,
                                        SHARE_RWD, false,
                                        OrLease({ key: 5, r: true, w: false,
                                                  h: false, v2: true,
                                                  epoch: 1 })))))
            .expect(stAt(0) == ST_SUCCESS)
            .expect(match asCreate(resAt(0)).caching {
                | CLease(x) => x.st.r and x.st.w and x.st.h and x.epoch == 2
                | _ => false })
            // The same-key opens never break each other.
            .expect(asCreate(resAt(0)).breaks.size() == 0)
            // A third open under a DIFFERENT key breaks the coalesced grant
            // exactly once (RWH -> RH: W stripped, ack required, epoch bumped).
            .then(runM(one(1, 1, create(ROOT, "a", DispOpen, ACCESS_R,
                                        SHARE_RWD, false,
                                        OrLease({ key: 6, r: true, w: false,
                                                  h: true, v2: true,
                                                  epoch: 1 })))))
            .expect(stAt(0) == ST_SUCCESS)
            .expect(asCreate(resAt(0)).breaks.size() == 1)
            .expect(asCreate(resAt(0)).breaks.forall(b =>
                    b.isLease and b.key == 5 and b.ackReq and
                    b.curState == 7 and b.newState == 3 and b.epoch == 3))
            .expect(sdb.opens.get(0).breaking and sdb.opens.get(1).breaking)
            // One ack settles every member of the coalesced grant.
            .then(runM(one(0, 0, ackKeep(0, true, BITS_RH))))
            .expect(stAt(0) == ST_SUCCESS)
            .expect(not(sdb.opens.get(0).breaking) and
                    not(sdb.opens.get(1).breaking))
            .expect(match sdb.opens.get(1).caching {
                | CLease(x) => x.st.r and x.st.h and not(x.st.w)
                | _ => false })

    // An acknowledgment may drop FURTHER than asked, but may never KEEP a bit
    // the break took away (STATUS_REQUEST_NOT_ACCEPTED, grant left breaking).
    run leaseAckRejectTest =
        boot2Run
            .then(runM(one(0, 0, create(ROOT, "a", DispCreate, ACCESS_RW,
                                        SHARE_RWD, false,
                                        OrLease({ key: 5, r: true, w: true,
                                                  h: true, v2: true,
                                                  epoch: 1 })))))
            .expect(stAt(0) == ST_SUCCESS)
            // A conflicting WRITE-capable open truncates nothing, so the break
            // is RWH -> RH.  Acking RWH tries to keep W: refused.
            .then(runM(one(1, 1, create(ROOT, "a", DispOpen, ACCESS_R,
                                        SHARE_RWD, false, OrNone))))
            .expect(stAt(0) == ST_SUCCESS and sdb.opens.get(0).breaking)
            .then(runM(one(0, 0, ackKeep(0, true, BITS_RWH))))
            .expect(stAt(0) == ST_REQUEST_NOT_ACCEPTED)
            .expect(sdb.opens.get(0).breaking)
            // Dropping further than asked is fine.
            .then(runM(one(0, 0, ackKeep(0, true, BITS_NONE))))
            .expect(stAt(0) == ST_SUCCESS)
            .expect(cachingLevelNone(sdb.opens.get(0).caching))
            // An ack for a settled lease -> STATUS_UNSUCCESSFUL.
            .then(runM(one(0, 0, ackKeep(0, true, BITS_NONE))))
            .expect(stAt(0) == ST_UNSUCCESSFUL)

    // A share-CONFLICTING open behind a handle-caching holder is refused, but
    // the holder is STILL told to relinquish its handle cache so a later retry
    // can succeed (smb2.lease.break_twice).  The refusal is immediate: no
    // interim, no park (probe O6b).
    run shareConflictBreaksHandleTest =
        boot2Run
            .then(runM(one(0, 0, create(ROOT, "a", DispCreate, ACCESS_RW,
                                        SHARE_NONE, false,
                                        OrLease({ key: 5, r: true, w: true,
                                                  h: true, v2: true,
                                                  epoch: 1 })))))
            .expect(stAt(0) == ST_SUCCESS)
            .then(runM(one(1, 1, create(ROOT, "a", DispOpen, ACCESS_R,
                                        SHARE_RWD, false, OrNone))))
            .expect(stAt(0) == ST_SHARING_VIOLATION)
            .expect(not(asCreate(resAt(0)).parked))
            // RWH -> RW: handle caching recalled even though the open failed.
            .expect(asCreate(resAt(0)).breaks.size() == 1)
            .expect(asCreate(resAt(0)).breaks.forall(b =>
                    b.isLease and b.curState == 7 and b.newState == 5 and
                    b.ackReq))

    // A force-level-2 share caps every grant to a read cache (probe O10).
    run forceLevel2Test =
        bootRun
            .then(runM(one(0, 0, create(ROOT, "a", DispCreate, ACCESS_RW,
                                        SHARE_RW, false, OrBatch))))
            .expect(stAt(0) == ST_SUCCESS)
            .expect(asCreate(resAt(0)).caching ==
                    (if (caps.forceLevel2) COplock(OpLevelII)
                     else COplock(OpBatch)))

    // ------------------------------------------------------------------
    // Byte-range locks (mandatory)
    // ------------------------------------------------------------------

    run lockConflictTest =
        boot2Run
            .then(runM(one(0, 0, create(ROOT, "a", DispCreate, ACCESS_RW,
                                        SHARE_RW, false, OrNone))))
            .then(runM(one(1, 1, create(ROOT, "a", DispOpen, ACCESS_RW,
                                        SHARE_RW, false, OrNone))))
            .expect(stAt(0) == ST_SUCCESS and asCreate(resAt(0)).fid == 1)
            // Handle 0 write-locks [0,2).
            .then(runM(one(0, 0, CLock({ fid: FidRef(0), lo: 0, hi: 2,
                                         wr: true, unlock: false,
                                         failImmediately: true }))))
            .expect(stAt(0) == ST_SUCCESS)
            // Handle 1's overlapping write lock -> LOCK_NOT_GRANTED.
            .then(runM(one(1, 1, CLock({ fid: FidRef(1), lo: 1, hi: 2,
                                         wr: true, unlock: false,
                                         failImmediately: true }))))
            .expect(stAt(0) == ST_LOCK_NOT_GRANTED)
            // Mandatory enforcement: handle 1's WRITE over a locked byte
            // -> FILE_LOCK_CONFLICT (PROPERTY-3c).
            .then(runM(one(1, 1, CWrite({ fid: FidRef(1), off: 0, len: 1,
                                          pat: 1 }))))
            .expect(stAt(0) == ST_FILE_LOCK_CONFLICT)
            // Handle 0 unlocks the exact range; handle 1's unlock of an
            // unheld range -> RANGE_NOT_LOCKED.
            .then(runM(one(0, 0, CLock({ fid: FidRef(0), lo: 0, hi: 2,
                                         wr: false, unlock: true,
                                         failImmediately: true }))))
            .expect(stAt(0) == ST_SUCCESS)
            .then(runM(one(1, 1, CLock({ fid: FidRef(1), lo: 0, hi: 1,
                                         wr: false, unlock: true,
                                         failImmediately: true }))))
            .expect(stAt(0) == ST_RANGE_NOT_LOCKED)

    // The SAME-HANDLE conflict rule (DEVIATIONS-SMB.md M-18).  Windows does
    // not merge a handle's own byte-range locks: a new EXCLUSIVE lock is
    // refused where it overlaps one the handle already holds -- including an
    // identical re-lock -- while a new SHARED lock never conflicts with the
    // handle's own locks and simply stacks on them.  The pre-list model
    // exempted the requesting handle from the conflict check entirely and
    // granted every one of these.
    run lockSameHandleTest =
        bootRun
            .then(runM(one(0, 0, create(ROOT, "a", DispCreate, ACCESS_RW,
                                        SHARE_RW, false, OrNone))))
            .expect(stAt(0) == ST_SUCCESS)
            .then(runM(one(0, 0, CLock({ fid: FidRef(0), lo: 0, hi: 2,
                                         wr: true, unlock: false,
                                         failImmediately: true }))))
            .expect(stAt(0) == ST_SUCCESS)
            // An overlapping exclusive re-lock by the SAME handle is refused.
            .then(runM(one(0, 0, CLock({ fid: FidRef(0), lo: 1, hi: 3,
                                         wr: true, unlock: false,
                                         failImmediately: true }))))
            .expect(stAt(0) == ST_LOCK_NOT_GRANTED)
            // So is an IDENTICAL exclusive re-lock.
            .then(runM(one(0, 0, CLock({ fid: FidRef(0), lo: 0, hi: 2,
                                         wr: true, unlock: false,
                                         failImmediately: true }))))
            .expect(stAt(0) == ST_LOCK_NOT_GRANTED)
            // A SHARED lock over the handle's own exclusive range is granted.
            .then(runM(one(0, 0, CLock({ fid: FidRef(0), lo: 0, hi: 2,
                                         wr: false, unlock: false,
                                         failImmediately: true }))))
            .expect(stAt(0) == ST_SUCCESS)
            // A disjoint exclusive lock is granted (the rule is about
            // OVERLAP, not about holding any lock at all).
            .then(runM(one(0, 0, CLock({ fid: FidRef(0), lo: 3, hi: 4,
                                         wr: true, unlock: false,
                                         failImmediately: true }))))
            .expect(stAt(0) == ST_SUCCESS)

    // The EXACT-RANGE unlock rule and lock STACKING (DEVIATIONS-SMB.md M-17).
    // MS-FSA 2.1.5.8 matches an unlock against a held lock's (LockOffset,
    // LockLength) and nothing else, so neither a sub-range nor a super-range
    // of a held lock can be released; and two identical shared locks are two
    // entries, so releasing the range once leaves one behind -- which the
    // mandatory-lock rule then still enforces against another handle.  The
    // pre-list model merged per byte and got both of these wrong.
    run lockExactRangeTest =
        boot2Run
            .then(runM(one(0, 0, create(ROOT, "a", DispCreate, ACCESS_RW,
                                        SHARE_RW, false, OrNone))))
            .then(runM(one(1, 1, create(ROOT, "a", DispOpen, ACCESS_RW,
                                        SHARE_RW, false, OrNone))))
            .expect(stAt(0) == ST_SUCCESS and asCreate(resAt(0)).fid == 1)
            .then(runM(one(0, 0, CLock({ fid: FidRef(0), lo: 0, hi: 2,
                                         wr: false, unlock: false,
                                         failImmediately: true }))))
            .expect(stAt(0) == ST_SUCCESS)
            // A SUB-range of the held lock cannot be unlocked.
            .then(runM(one(0, 0, CLock({ fid: FidRef(0), lo: 0, hi: 1,
                                         wr: false, unlock: true,
                                         failImmediately: true }))))
            .expect(stAt(0) == ST_RANGE_NOT_LOCKED)
            // Neither can a SUPER-range.
            .then(runM(one(0, 0, CLock({ fid: FidRef(0), lo: 0, hi: 3,
                                         wr: false, unlock: true,
                                         failImmediately: true }))))
            .expect(stAt(0) == ST_RANGE_NOT_LOCKED)
            // A second identical shared lock STACKS: two entries now.
            .then(runM(one(0, 0, CLock({ fid: FidRef(0), lo: 0, hi: 2,
                                         wr: false, unlock: false,
                                         failImmediately: true }))))
            .expect(stAt(0) == ST_SUCCESS)
            .then(runM(one(0, 0, CLock({ fid: FidRef(0), lo: 0, hi: 2,
                                         wr: false, unlock: true,
                                         failImmediately: true }))))
            .expect(stAt(0) == ST_SUCCESS)
            // One entry survives, so handle 1's WRITE is still refused.
            .then(runM(one(1, 1, CWrite({ fid: FidRef(1), off: 0, len: 1,
                                          pat: 1 }))))
            .expect(stAt(0) == ST_FILE_LOCK_CONFLICT)
            // The second unlock releases the last entry, and the write lands.
            .then(runM(one(0, 0, CLock({ fid: FidRef(0), lo: 0, hi: 2,
                                         wr: false, unlock: true,
                                         failImmediately: true }))))
            .expect(stAt(0) == ST_SUCCESS)
            .then(runM(one(1, 1, CWrite({ fid: FidRef(1), off: 0, len: 1,
                                          pat: 1 }))))
            .expect(stAt(0) == ST_SUCCESS)

    // Mandatory enforcement is ASYMMETRIC between the two lock kinds
    // (DEVIATIONS-SMB.md M-19).  A SHARED lock is a promise the range will not
    // change, so it refuses a WRITE issued through the very handle that took
    // it; an EXCLUSIVE lock is the owner's private right to the range, so the
    // owner may write through it freely and only OTHER handles are refused.
    // Neither lock kind blocks the owner's READ.  The pre-fix model exempted
    // the requesting handle from both.
    run lockSelfIoTest =
        boot2Run
            .then(runM(one(0, 0, create(ROOT, "a", DispCreate, ACCESS_RW,
                                        SHARE_RW, false, OrNone))))
            .then(runM(one(1, 1, create(ROOT, "a", DispOpen, ACCESS_RW,
                                        SHARE_RW, false, OrNone))))
            .expect(stAt(0) == ST_SUCCESS and asCreate(resAt(0)).fid == 1)
            // Give the file three blocks so every read below is in range.
            .then(runM(one(0, 0, CWrite({ fid: FidRef(0), off: 0, len: 3,
                                          pat: 1 }))))
            .expect(stAt(0) == ST_SUCCESS)
            // Handle 0 takes a SHARED lock over [0,1).
            .then(runM(one(0, 0, CLock({ fid: FidRef(0), lo: 0, hi: 1,
                                         wr: false, unlock: false,
                                         failImmediately: true }))))
            .expect(stAt(0) == ST_SUCCESS)
            // Its OWN write over that range is refused ...
            .then(runM(one(0, 0, CWrite({ fid: FidRef(0), off: 0, len: 1,
                                          pat: 2 }))))
            .expect(stAt(0) == ST_FILE_LOCK_CONFLICT)
            // ... and so is the peer's ...
            .then(runM(one(1, 1, CWrite({ fid: FidRef(1), off: 0, len: 1,
                                          pat: 2 }))))
            .expect(stAt(0) == ST_FILE_LOCK_CONFLICT)
            // ... while BOTH may still read it.
            .then(runM(one(0, 0, CRead({ fid: FidRef(0), off: 0, len: 1 }))))
            .expect(stAt(0) == ST_SUCCESS)
            .then(runM(one(1, 1, CRead({ fid: FidRef(1), off: 0, len: 1 }))))
            .expect(stAt(0) == ST_SUCCESS)
            // An EXCLUSIVE lock over [2,3) by handle 0: its own write lands,
            // the peer's write and the peer's READ are both refused.
            .then(runM(one(0, 0, CLock({ fid: FidRef(0), lo: 2, hi: 3,
                                         wr: true, unlock: false,
                                         failImmediately: true }))))
            .expect(stAt(0) == ST_SUCCESS)
            .then(runM(one(0, 0, CWrite({ fid: FidRef(0), off: 2, len: 1,
                                          pat: 3 }))))
            .expect(stAt(0) == ST_SUCCESS)
            .then(runM(one(1, 1, CWrite({ fid: FidRef(1), off: 2, len: 1,
                                          pat: 3 }))))
            .expect(stAt(0) == ST_FILE_LOCK_CONFLICT)
            .then(runM(one(1, 1, CRead({ fid: FidRef(1), off: 2, len: 1 }))))
            .expect(stAt(0) == ST_FILE_LOCK_CONFLICT)

    // ------------------------------------------------------------------
    // FLUSH, LOGOFF, TREE_DISCONNECT
    // ------------------------------------------------------------------

    // FLUSH (MS-SMB2 3.3.5.13) has no observable effect in this model beyond
    // its status, which is exactly why the status must be pinned: a live
    // WRITABLE handle succeeds, a FileId that names no open is
    // STATUS_FILE_CLOSED, and a handle without write access is
    // STATUS_ACCESS_DENIED -- FLUSH is a write-side operation and needs the
    // access to match, exactly as SET_INFO/EndOfFile does above.  The model
    // used to answer SUCCESS on any live handle whatever its access (SD-1).
    run flushTest =
        bootRun
            .then(runM(one(0, 0, create(ROOT, "a", DispCreate, ACCESS_RW,
                                        SHARE_RW, false, OrNone))))
            .expect(stAt(0) == ST_SUCCESS)
            .then(runM(one(0, 0, CFlush(FidRef(0)))))
            .expect(stAt(0) == ST_SUCCESS)
            // a read-only handle on the same file may not flush it
            .then(runM(one(0, 0, create(ROOT, "a", DispOpen, ACCESS_R,
                                        SHARE_RWD, false, OrNone))))
            .expect(stAt(0) == ST_SUCCESS)
            .then(runM(one(0, 0, CFlush(FidRef(1)))))
            .expect(stAt(0) == ST_ACCESS_DENIED)
            // nor may an attribute-only one
            .then(runM(one(0, 0, create(ROOT, "a", DispOpen, ACCESS_H,
                                        SHARE_RWD, false, OrNone))))
            .expect(stAt(0) == ST_SUCCESS)
            .then(runM(one(0, 0, CFlush(FidRef(2)))))
            .expect(stAt(0) == ST_ACCESS_DENIED)
            .then(runM(one(0, 0, CClose(FidRef(0)))))
            .expect(stAt(0) == ST_SUCCESS)
            .then(runM(one(0, 0, CFlush(FidRef(0)))))
            .expect(stAt(0) == ST_FILE_CLOSED)

    // LOGOFF (MS-SMB2 3.3.5.6) and TREE_DISCONNECT (3.3.5.8) differ in SCOPE,
    // and the difference is the whole content of the pair: a tree disconnect
    // closes the opens on that tree and leaves the session (and its other
    // trees) alive; a logoff destroys the session, every tree under it and
    // every open on it.  Both also release the byte-range locks those opens
    // held, which is what lets a peer's write through afterwards.
    run teardownScopeTest =
        bootRun
            // A second tree on the SAME session, so the scopes are separable.
            .then(runM(one(0, -1, CTreeConnect({ share: 1 }))))
            .expect(stAt(0) == ST_SUCCESS and sdb.trees.keys().contains(1))
            .then(runM(one(0, 0, create(ROOT, "a", DispCreate, ACCESS_RW,
                                        SHARE_RW, false, OrNone))))
            .expect(stAt(0) == ST_SUCCESS and asCreate(resAt(0)).fid == 0)
            .then(runM(one(0, 1, create(ROOT, "a", DispOpen, ACCESS_RW,
                                        SHARE_RW, false, OrNone))))
            .expect(stAt(0) == ST_SUCCESS and asCreate(resAt(0)).fid == 1)
            // Handle 0 (tree 0) write-locks [0,1).
            .then(runM(one(0, 0, CLock({ fid: FidRef(0), lo: 0, hi: 1,
                                         wr: true, unlock: false,
                                         failImmediately: true }))))
            .expect(stAt(0) == ST_SUCCESS)
            .then(runM(one(0, 1, CWrite({ fid: FidRef(1), off: 0, len: 1,
                                          pat: 1 }))))
            .expect(stAt(0) == ST_FILE_LOCK_CONFLICT)
            // Disconnecting tree 0 takes handle 0 and its lock with it, and
            // leaves the session, tree 1 and handle 1 untouched.
            .then(runM(one(0, 0, CTreeDisconnect)))
            .expect(stAt(0) == ST_SUCCESS and
                    not(sdb.trees.keys().contains(0)) and
                    sdb.trees.keys().contains(1) and
                    sdb.sessions.keys().contains(0) and
                    not(sdb.opens.keys().contains(0)) and
                    sdb.opens.keys().contains(1))
            .then(runM(one(0, 1, CWrite({ fid: FidRef(1), off: 0, len: 1,
                                          pat: 1 }))))
            .expect(stAt(0) == ST_SUCCESS)
            // A second disconnect of the same tree finds nothing.
            .then(runM(one(0, 0, CTreeDisconnect)))
            .expect(stAt(0) == ST_NETWORK_NAME_DELETED)
            // LOGOFF takes the session, the remaining tree and handle 1.
            .then(runM({ sess: 0, tree: -1, related: false, cs: 0,
                         replay: false, cmds: [ CLogoff ] }))
            .expect(stAt(0) == ST_SUCCESS and
                    not(sdb.sessions.keys().contains(0)) and
                    sdb.trees.keys().size() == 0 and
                    sdb.opens.keys().size() == 0)
            // And a logoff of a session that is already gone.
            .then(runM({ sess: 0, tree: -1, related: false, cs: 0,
                         replay: false, cmds: [ CLogoff ] }))
            .expect(stAt(0) == ST_USER_SESSION_DELETED)

    // ------------------------------------------------------------------
    // SET_INFO: rename and disposition
    // ------------------------------------------------------------------

    // MS-FSA 2.1.5.14.11.1 / 2.1.5.14.3: both a rename and a disposition
    // change are DELETE-authorization decisions, so a handle without DELETE
    // gets ACCESS_DENIED -- and the rename's gate runs BEFORE the
    // destination-existence probe, so an unauthorized rename onto an OCCUPIED
    // name still reports ACCESS_DENIED rather than OBJECT_NAME_COLLISION.
    // (DEVIATIONS-SMB.md M-20: the model had no access check on either.)
    run setInfoNeedsDeleteTest =
        bootRun
            .then(runM(one(0, 0, create(ROOT, "a", DispCreate, ACCESS_RW,
                                        SHARE_RWD, false, OrNone))))
            .expect(stAt(0) == ST_SUCCESS)
            .then(runM(one(0, 0, create(ROOT, "b", DispCreate, ACCESS_RWD,
                                        SHARE_RWD, false, OrNone))))
            .expect(stAt(0) == ST_SUCCESS and asCreate(resAt(0)).fid == 1)
            // fid 0 holds R+W but not DELETE: neither set is allowed.
            .then(runM(one(0, 0, CSetRename({ fid: FidRef(0), newdir: ROOT,
                                              newname: "c" }))))
            .expect(stAt(0) == ST_ACCESS_DENIED)
            .then(runM(one(0, 0, CSetDisposition({ fid: FidRef(0),
                                                   del: true }))))
            .expect(stAt(0) == ST_ACCESS_DENIED)
            // The access gate OUTRANKS the collision: renaming onto the
            // occupied name "b" still answers ACCESS_DENIED.
            .then(runM(one(0, 0, CSetRename({ fid: FidRef(0), newdir: ROOT,
                                              newname: "b" }))))
            .expect(stAt(0) == ST_ACCESS_DENIED)
            // fid 1 holds DELETE, so its collision is a real collision ...
            .then(runM(one(0, 0, CSetRename({ fid: FidRef(1), newdir: ROOT,
                                              newname: "a" }))))
            .expect(stAt(0) == ST_OBJECT_NAME_COLLISION)
            // ... and its rename onto a free name lands.
            .then(runM(one(0, 0, CSetRename({ fid: FidRef(1), newdir: ROOT,
                                              newname: "c" }))))
            .expect(stAt(0) == ST_SUCCESS and
                    fsHasEnt(sdb.fs, ROOT, "c") and
                    not(fsHasEnt(sdb.fs, ROOT, "b")))

    // A rename onto the handle's OWN current name is a no-op SUCCESS, not a
    // collision: MS-FSA 2.1.5.14.11.1 guards the OBJECT_NAME_COLLISION branch
    // on the target link being a DIFFERENT link (which is what makes a
    // case-only rename expressible at all).  chimera answers
    // OBJECT_NAME_COLLISION here -- DEVIATIONS-SMB.md Q-14, unresolved, which
    // is why the generated corpus never draws this shape.  Pinned so the model
    // rule cannot drift while the question is open.
    run renameToSelfTest =
        bootRun
            .then(runM(one(0, 0, create(ROOT, "a", DispCreate, ACCESS_RWD,
                                        SHARE_RWD, false, OrNone))))
            .expect(stAt(0) == ST_SUCCESS)
            .then(runM(one(0, 0, CSetRename({ fid: FidRef(0), newdir: ROOT,
                                              newname: "a" }))))
            .expect(stAt(0) == ST_SUCCESS and fsHasEnt(sdb.fs, ROOT, "a"))

    // A rename is by HANDLE, so it re-points EVERY open of the inode: a
    // second handle that was opened under the old name must, after the move,
    // act on the new one.  Measured through the delete-on-close path, which is
    // the only op that names a handle's (dir,name) again after the fact.
    run renameRepointsPeerHandleTest =
        boot2Run
            .then(runM(one(0, 0, create(ROOT, "a", DispCreate, ACCESS_RWD,
                                        SHARE_RWD, false, OrNone))))
            .then(runM(one(1, 1, create(ROOT, "a", DispOpen, ACCESS_RWD,
                                        SHARE_RWD, false, OrNone))))
            .expect(stAt(0) == ST_SUCCESS and asCreate(resAt(0)).fid == 1)
            .then(runM(one(0, 0, CSetRename({ fid: FidRef(0), newdir: ROOT,
                                              newname: "b" }))))
            .expect(stAt(0) == ST_SUCCESS and
                    fsHasEnt(sdb.fs, ROOT, "b") and
                    not(fsHasEnt(sdb.fs, ROOT, "a")))
            // The PEER handle sets delete-on-close and closes: what
            // disappears is "b", the name the rename moved the object to.
            .then(runM(one(1, 1, CSetDisposition({ fid: FidRef(1),
                                                   del: true }))))
            .expect(stAt(0) == ST_SUCCESS)
            .then(runM(one(0, 0, CClose(FidRef(0)))))
            .then(runM(one(1, 1, CClose(FidRef(1)))))
            .expect(stAt(0) == ST_SUCCESS and not(fsHasEnt(sdb.fs, ROOT, "b")))

    // ------------------------------------------------------------------
    // Delete-on-close / delete-pending / unlink-while-open
    // ------------------------------------------------------------------

    run deleteOnCloseTest =
        boot2Run
            // Client 1 opens "a" with FILE_DELETE_ON_CLOSE.
            .then(runM(one(0, 0, create(ROOT, "a", DispCreate, ACCESS_RWD,
                                        SHARE_RWD, true, OrNone))))
            .expect(stAt(0) == ST_SUCCESS and
                    sdb.deletePending.contains(asCreate(resAt(0)).ino))
            // A concurrent OPEN observes the pending delete -> DELETE_PENDING.
            .then(runM(one(1, 1, create(ROOT, "a", DispOpen, ACCESS_R,
                                        SHARE_RWD, false, OrNone))))
            .expect(stAt(0) == ST_DELETE_PENDING)
            // Closing the delete-on-close handle unlinks the file.
            .then(runM(one(0, 0, CClose(FidRef(0)))))
            .expect(stAt(0) == ST_SUCCESS)
            .expect(not(fsLive(sdb.fs, 1)) and sdb.fs.removed.contains(1))

    // Delete-deferred-to-last-close (MS-FSA 2.1.5.4): with delete-disposition
    // armed and a second handle still open, the directory entry persists
    // (nlink 1, delete-pending) until the final handle closes.
    run unlinkWhileOpenTest =
        bootRun
            .then(runM(one(0, 0, create(ROOT, "b", DispCreate, ACCESS_RWD,
                                        SHARE_RWD, false, OrNone))))
            .expect(stAt(0) == ST_SUCCESS and asCreate(resAt(0)).fid == 0)
            .then(runM(one(0, 0, create(ROOT, "b", DispOpen, ACCESS_R,
                                        SHARE_RWD, false, OrNone))))
            .expect(stAt(0) == ST_SUCCESS and asCreate(resAt(0)).fid == 1)
            // Arm delete-disposition on handle 0 and close it: the file
            // remains (handle 1 still open), now delete-pending.
            .then(runM(one(0, 0, CSetDisposition({ fid: FidRef(0),
                                                   del: true }))))
            .expect(stAt(0) == ST_SUCCESS)
            .then(runM(one(0, 0, CClose(FidRef(0)))))
            .expect(stAt(0) == ST_SUCCESS)
            .expect(fsLive(sdb.fs, 1) and fsGet(sdb.fs, 1).nlink == 1 and
                    sdb.deletePending.contains(1))
            // Closing the last handle performs the deferred unlink.
            .then(runM(one(0, 0, CClose(FidRef(1)))))
            .expect(stAt(0) == ST_SUCCESS and not(fsLive(sdb.fs, 1)))

    // ------------------------------------------------------------------
    // Compound (NextCommand) threading
    // ------------------------------------------------------------------

    run compoundThreadingTest =
        bootRun
            // Related CREATE+WRITE+CLOSE: WRITE and CLOSE inherit the
            // CREATE's FileId; all three execute and succeed.
            .then(runM({ sess: 0, tree: 0, related: true, cs: 0, replay: false,
                         cmds: [
                             create(ROOT, "a", DispOpenIf, ACCESS_RW,
                                    SHARE_RW, false, OrNone),
                             CWrite({ fid: FidRelated, off: 0, len: 1,
                                      pat: 2 }),
                             CClose(FidRelated) ] }))
            .expect(lastResults.length() == 3)
            .expect(stAt(0) == ST_SUCCESS and stAt(1) == ST_SUCCESS and
                    stAt(2) == ST_SUCCESS)
            .expect(asCreate(resAt(0)).act == ACT_CREATED)
            .expect(sdb.opens.keys().size() == 0 and
                    fsGet(sdb.fs, 1).sizeBlocks == 1)
            // Related first-error-stops: a failing CREATE aborts the chain,
            // so only its result is present.
            .then(runM({ sess: 0, tree: 0, related: true, cs: 0, replay: false,
                         cmds: [
                             create(ROOT, "zz", DispOpen, ACCESS_R,
                                    SHARE_RWD, false, OrNone),
                             CWrite({ fid: FidRelated, off: 0, len: 1,
                                      pat: 1 }),
                             CClose(FidRelated) ] }))
            .expect(stAt(0) == ST_OBJECT_NAME_NOT_FOUND and
                    lastResults.length() == 1)
            // Unrelated compound: both commands execute independently.
            .then(runM({ sess: 0, tree: 0, related: false, cs: 0, replay: false,
                         cmds: [ CClose(FidRef(99)), CClose(FidRef(98)) ] }))
            .expect(lastResults.length() == 2 and
                    stAt(0) == ST_FILE_CLOSED and stAt(1) == ST_FILE_CLOSED)

    // ------------------------------------------------------------------
    // Change attribute consistency across a mutation
    // ------------------------------------------------------------------

    run changeAttrTest =
        bootRun
            .then(runM(one(0, 0, create(ROOT, "a", DispCreate, ACCESS_RW,
                                        SHARE_RW, false, OrNone))))
            .then(runM(one(0, 0, CQueryBasic(FidRef(0)))))
            .expect(stAt(0) == ST_SUCCESS)
            .then(runM(one(0, 0, CWrite({ fid: FidRef(0), off: 0, len: 2,
                                          pat: 3 }))))
            .expect(stAt(0) == ST_SUCCESS)
            .then(runM(one(0, 0, CQueryBasic(FidRef(0)))))
            .expect(stAt(0) == ST_SUCCESS and
                    asQuery(resAt(0)).attrs.sizeBlocks == 2)

    // ------------------------------------------------------------------
    // An RqLs open granted NONE is not a grant to coalesce onto
    // ------------------------------------------------------------------

    // MS-SMB2 2.2.13.2.8 / 2.2.14.2.10: a v1 RqLs request context and its
    // response context carry NO Epoch field; only v2 does.  So a reply's
    // version -- and therefore whether it reports an epoch at all -- follows
    // the version of the LEASE the open joined when it joined one, and the
    // version of the REQUEST when there is nothing to join.
    //
    // A request granted NONE (here: the invalid W/H-without-R state of
    // 3.3.5.9.8) establishes no caching state and takes no grant, so it is
    // nothing to join.  The model used to treat any lease-key-bearing open as
    // a joinable member, so a later v1 request under the same key inherited
    // the first request's v2 flag and epoch and answered epoch 4 where chimera
    // -- which has no grant object at all on this path and falls into the
    // `grant == NULL` reporting branch of smb_proc_create.c -- answers 0.
    // Found by replaying smb2Base/stepReq at depth 2000 (DEVIATIONS-SMB.md
    // M-6); this pins it.
    run emptyLeaseNoCoalesceTest =
        bootRun
            // v2, key 9, W/H without R -> granted NONE, epoch echoed.
            .then(runM(one(0, 0, create(ROOT, "y", DispCreate, ACCESS_RW,
                                        SHARE_RWD, false,
                                        OrLease({ key: 9, r: false, w: true,
                                                  h: true, v2: true,
                                                  epoch: 4 })))))
            .expect(stAt(0) == ST_SUCCESS)
            .expect(match asCreate(resAt(0)).caching {
                | CLease(x) => bitsEmpty(x.st) and x.epoch == 4 and x.v2
                | _ => false })
            // A SECOND open of the same file under the SAME key, this time v1.
            // There is no grant to join, so the reply follows the request's
            // version: v1, and therefore no epoch (0), NOT the v2/epoch 4 of
            // the empty record above.
            .then(runM(one(0, 0, create(ROOT, "y", DispOpen, ACCESS_R,
                                        SHARE_RWD, false,
                                        OrLease({ key: 9, r: false, w: true,
                                                  h: true, v2: false,
                                                  epoch: 4 })))))
            .expect(stAt(0) == ST_SUCCESS)
            .expect(match asCreate(resAt(0)).caching {
                | CLease(x) => bitsEmpty(x.st) and x.epoch == 0 and not(x.v2)
                | _ => false })
            // Positive control: a grant that DOES hold caching is still
            // joinable, and the joiner inherits ITS version and epoch even
            // when the joining request is v1 -- "the response follows the
            // lease's version, set at first grant" (smb_proc_create.c).  The
            // fix must not have disabled coalescing altogether.
            .then(runM(one(0, 0, create(ROOT, "z", DispCreate, ACCESS_RW,
                                        SHARE_RWD, false,
                                        OrLease({ key: 12, r: true, w: true,
                                                  h: true, v2: true,
                                                  epoch: 4 })))))
            .expect(stAt(0) == ST_SUCCESS)
            .expect(match asCreate(resAt(0)).caching {
                | CLease(x) => x.st.r and x.st.w and x.st.h and x.epoch == 5
                | _ => false })
            .then(runM(one(0, 0, create(ROOT, "z", DispOpen, ACCESS_R,
                                        SHARE_RWD, false,
                                        OrLease({ key: 12, r: true, w: false,
                                                  h: false, v2: false,
                                                  epoch: 1 })))))
            .expect(stAt(0) == ST_SUCCESS)
            .expect(match asCreate(resAt(0)).caching {
                | CLease(x) => x.st.r and x.st.w and x.st.h and x.epoch == 5
                             and x.v2
                | _ => false })

    // ------------------------------------------------------------------
    // An attribute-only open imposes no deny
    // ------------------------------------------------------------------

    // An open whose DesiredAccess carries no R/W/D bit takes no part in share
    // arbitration in EITHER direction: it neither conflicts with an existing
    // opener's deny nor imposes its own ShareAccess on later openers.  chimera
    // registers it as an inert (granted=0, denied=0) SHARE entry --
    // smb_proc_create.c "Attribute-only opens hold no share-mode rights and
    // impose no deny", which zeroes granted/denied/held_granted whenever
    // DesiredAccess has no SMB2_SHAREMODE_ACCESS_MASK bit.
    //
    // The model checked only the first half (doCmdCreate's attrOnly gate) and
    // still stored denyOf(ShareAccess) on the open, so a stat-open with
    // ShareAccess=NONE locked every later opener out.  With ACCESS_H in the
    // generator's domain that fired immediately as a stSharesConsistent
    // violation (DEVIATIONS-SMB.md M-5); this pins both halves.
    run attrOnlyImposesNoDenyTest =
        boot2Run
            // A stat-open sharing NOTHING.
            .then(runM(one(0, 0, create(ROOT, "a", DispCreate, ACCESS_H,
                                        SHARE_NONE, false, OrNone))))
            .expect(stAt(0) == ST_SUCCESS and asCreate(resAt(0)).fid == 0)
            .expect(not(sdb.opens.get(0).denied.r) and
                    not(sdb.opens.get(0).denied.w) and
                    not(sdb.opens.get(0).denied.d))
            // A full-access opener from another session is unaffected by it.
            .then(runM(one(1, 1, create(ROOT, "a", DispOpen, ACCESS_RWD,
                                        SHARE_NONE, false, OrNone))))
            .expect(stAt(0) == ST_SUCCESS and asCreate(resAt(0)).fid == 1)
            // And the converse: a stat-open is admitted THROUGH a peer that
            // denies everything.
            .then(runM(one(0, 0, create(ROOT, "a", DispOpen, ACCESS_H,
                                        SHARE_NONE, false, OrNone))))
            .expect(stAt(0) == ST_SUCCESS and asCreate(resAt(0)).fid == 2)
            // A real access request is NOT admitted through that same peer --
            // the bypass is scoped to attribute-only opens, not a hole.
            .then(runM(one(0, 0, create(ROOT, "a", DispOpen, ACCESS_R,
                                        SHARE_RWD, false, OrNone))))
            .expect(stAt(0) == ST_SHARING_VIOLATION)
            // ACCESS_D asks for DELETE alone: it conflicts on the D axis and
            // only the D axis.  fid 1 denies delete, so this collides ...
            .then(runM(one(0, 0, create(ROOT, "a", DispOpen, ACCESS_D,
                                        SHARE_RWD, false, OrNone))))
            .expect(stAt(0) == ST_SHARING_VIOLATION)
            // ... and once it is gone, the same request succeeds.
            .then(runM(one(1, 1, CClose(FidRef(1)))))
            .expect(stAt(0) == ST_SUCCESS)
            .then(runM(one(0, 0, create(ROOT, "a", DispOpen, ACCESS_D,
                                        SHARE_RWD, false, OrNone))))
            .expect(stAt(0) == ST_SUCCESS)

    // Which PEER OPEN caps a fresh caching grant, and by how much.
    //
    // MANDATE (MS-FSA 2.1.5.18.1, "Algorithm to Request an Exclusive Oplock",
    // numbered 2.1.5.17.2 in the revision the older citations here use): a
    // request carrying WRITE caching -- legacy EXCLUSIVE / BATCH, or a lease
    // with W -- is refused when "Open.File.OpenList contains more than one Open
    // whose Stream is the same as Open.Stream, and NO_OPLOCK is present in
    // Open.Stream.Oplock.State".  No OplockKey and no client-identity exemption
    // appears in that clause, so the model caps W against EVERY peer open, and
    // chimera's two exemptions stay in DEVIATIONS-SMB.md (S-3) rather than in
    // the model.
    //
    // DISCRETION (MS-SMB2 3.3.5.9 -- granting LESS is always allowed), pinned
    // to what probe O12 measured on the wire:
    //   * a capped request lands at a shared read cache (LEVEL_II / R), not at
    //     NONE;
    //   * the HANDLE bit of a lease is capped by a peer open that is NOT itself
    //     lease-backed, and survives one that is (two RqLs leases coexist at
    //     R+H -- O12[26]-O12[31]);
    //   * a LEGACY oplock request by a client that already holds an H lease on
    //     the file is granted NOTHING at any level, II included
    //     (O12[32]/O12[33]).
    run peerOpenGrantCapTest =
        boot2Run
            // Sole opener: the full BATCH is granted.
            .then(runM(one(0, 0, create(ROOT, "a", DispCreate, ACCESS_R,
                                        SHARE_RWD, false, OrBatch))))
            .expect(stAt(0) == ST_SUCCESS)
            .expect(asCreate(resAt(0)).caching == COplock(OpBatch))
            // A peer open by the other session ...
            .then(runM(one(1, 1, create(ROOT, "b", DispCreate, ACCESS_R,
                                        SHARE_RWD, false, OrNone))))
            .expect(stAt(0) == ST_SUCCESS)
            // ... caps a BATCH request to a shared read cache.
            .then(runM(one(0, 0, create(ROOT, "b", DispOpen, ACCESS_R,
                                        SHARE_RWD, false, OrBatch))))
            .expect(stAt(0) == ST_SUCCESS)
            .expect(asCreate(resAt(0)).caching == COplock(OpLevelII))
            // An RWH lease in the same position keeps R alone: W by the
            // mandate, H because the peer open is not lease-backed.
            .then(runM(one(0, 0, create(ROOT, "b", DispOpen, ACCESS_R,
                                        SHARE_RWD, false,
                                        OrLease({ key: 3, r: true, w: true,
                                                  h: true, v2: true,
                                                  epoch: 1 })))))
            .expect(stAt(0) == ST_SUCCESS)
            .expect(match asCreate(resAt(0)).caching {
                | CLease(x) => x.st.r and not(x.st.w) and not(x.st.h)
                | _ => false })
            // A LEASE-backed peer open does not own the handle: an RH lease
            // behind another client's RH lease keeps H.
            .then(runM(one(1, 1, create(ROOT, "c", DispCreate, ACCESS_R,
                                        SHARE_RWD, false,
                                        OrLease({ key: 4, r: true, w: false,
                                                  h: true, v2: true,
                                                  epoch: 1 })))))
            .expect(stAt(0) == ST_SUCCESS)
            .then(runM(one(0, 0, create(ROOT, "c", DispOpen, ACCESS_R,
                                        SHARE_RWD, false,
                                        OrLease({ key: 5, r: true, w: false,
                                                  h: true, v2: true,
                                                  epoch: 1 })))))
            .expect(stAt(0) == ST_SUCCESS)
            .expect(match asCreate(resAt(0)).caching {
                | CLease(x) => x.st.r and x.st.h and not(x.st.w)
                | _ => false })
            // Session 0 now holds an H lease on "c", so a legacy oplock
            // request of ITS OWN is granted nothing -- at BATCH ...
            .then(runM(one(0, 0, create(ROOT, "c", DispOpen, ACCESS_R,
                                        SHARE_RWD, false, OrBatch))))
            .expect(stAt(0) == ST_SUCCESS)
            .expect(asCreate(resAt(0)).caching == CNone)
            // ... and at LEVEL_II, which is not a cap but a refusal.
            .then(runM(one(0, 0, create(ROOT, "c", DispOpen, ACCESS_R,
                                        SHARE_RWD, false, OrLevelII))))
            .expect(stAt(0) == ST_SUCCESS)
            .expect(asCreate(resAt(0)).caching == CNone)
            // An ATTRIBUTE-ONLY peer holds no share-mode rights, so it does not
            // own the handle either: an RH lease behind one keeps H.
            .then(runM(one(1, 1, create(ROOT, "d", DispCreate, ACCESS_H,
                                        SHARE_RWD, false, OrNone))))
            .expect(stAt(0) == ST_SUCCESS)
            .then(runM(one(0, 0, create(ROOT, "d", DispOpen, ACCESS_R,
                                        SHARE_RWD, false,
                                        OrLease({ key: 6, r: true, w: false,
                                                  h: true, v2: true,
                                                  epoch: 1 })))))
            .expect(stAt(0) == ST_SUCCESS)
            .expect(match asCreate(resAt(0)).caching {
                | CLease(x) => x.st.r and x.st.h
                | _ => false })
            // But it is still an Open on the stream, so the W bit is refused:
            // the model does NOT copy chimera's inert-peer exemption (S-3).
            .then(runM(one(0, 0, create(ROOT, "d", DispOpen, ACCESS_R,
                                        SHARE_RWD, false,
                                        OrLease({ key: 7, r: true, w: true,
                                                  h: true, v2: true,
                                                  epoch: 1 })))))
            .expect(stAt(0) == ST_SUCCESS)
            .expect(match asCreate(resAt(0)).caching {
                | CLease(x) => not(x.st.w)
                | _ => false })

    // The generator guard that keeps the S-3 shapes out of the corpus, pinned
    // in both directions so it can neither rot open nor quietly widen to the
    // "any peer open at all" refusal it replaced.
    run grantAgreedScopeTest =
        boot2Run
            // Nothing open: every request shape is generatable.
            .expect(grantAgreed("a", OrBatch, 0))
            .expect(grantAgreed("a", OrLease({ key: 1, r: true, w: true,
                                               h: true, v2: true, epoch: 1 }), 0))
            // A peer open by ANOTHER session is the agreed shape: chimera and
            // the model both withhold the write cache, so it is generatable.
            .then(runM(one(1, 1, create(ROOT, "b", DispCreate, ACCESS_R,
                                        SHARE_RWD, false, OrNone))))
            .expect(stAt(0) == ST_SUCCESS)
            .expect(grantAgreed("b", OrBatch, 0))
            .expect(grantAgreed("b", OrExclusive, 0))
            .expect(grantAgreed("b", OrLease({ key: 1, r: true, w: true,
                                               h: true, v2: true, epoch: 1 }), 0))
            // A peer open by the SAME session is S-3 for a LEGACY oplock
            // (chimera grants the full BATCH there) but not for a lease
            // (chimera caps it to R), so only the legacy request is suppressed.
            .then(runM(one(0, 0, create(ROOT, "e", DispCreate, ACCESS_R,
                                        SHARE_RWD, false, OrNone))))
            .expect(stAt(0) == ST_SUCCESS)
            .expect(not(grantAgreed("e", OrBatch, 0)))
            .expect(not(grantAgreed("e", OrExclusive, 0)))
            .expect(grantAgreed("e", OrLease({ key: 1, r: true, w: true,
                                               h: true, v2: true, epoch: 1 }), 0))
            // An ATTRIBUTE-ONLY peer is invisible to chimera's cap, so a
            // write-caching request behind one is suppressed for both kinds.
            .then(runM(one(1, 1, create(ROOT, "f", DispCreate, ACCESS_H,
                                        SHARE_RWD, false, OrNone))))
            .expect(stAt(0) == ST_SUCCESS)
            .expect(not(grantAgreed("f", OrBatch, 0)))
            .expect(not(grantAgreed("f", OrLease({ key: 1, r: true, w: true,
                                                   h: true, v2: true,
                                                   epoch: 1 }), 0)))
            // A request that asks for no write cache is never suppressed: a
            // shared oplock (MS-FSA 2.1.5.18.2) has no sole-Open condition.
            .expect(grantAgreed("f", OrLevelII, 0))
            .expect(grantAgreed("f", OrNone, 0))
            .expect(grantAgreed("f", OrLease({ key: 1, r: true, w: false,
                                               h: true, v2: true, epoch: 1 }), 0))
            .expect(grantAgreed("e", OrLevelII, 0))
            // Once a peer that DOES cap joins the attribute-only one, the
            // shape is agreed again and generation resumes.
            .then(runM(one(1, 1, create(ROOT, "f", DispOpen, ACCESS_R,
                                        SHARE_RWD, false, OrNone))))
            .expect(stAt(0) == ST_SUCCESS)
            .expect(grantAgreed("f", OrBatch, 0))

    // ------------------------------------------------------------------
    // Durable handles (MS-SMB2 3.3.5.9.6/.10 request, 3.3.7.1 park,
    // 3.3.5.9.7/.12 reconnect)
    //
    // Every expectation below is ground truth measured by
    // smb2_durable_probe.c, cited by section (D1 ... D8) and recorded in
    // DEVIATIONS-SMB.md as C-13 ... C-22.  None of it is derived from the
    // spec alone, because the spec leaves most of it to the server.
    // ------------------------------------------------------------------

    // A CREATE carrying a durable REQUEST.
    def createDurQ(name: Name, disp: Disposition, acc: DesiredAccess,
                   sh: ShareAccess, opl: OplockReq, v2: bool,
                   guid: int): Cmd =
        CCreate({ dir: ROOT, name: name, disp: disp, access: acc, share: sh,
                  isDir: false, delOnClose: false, oplock: opl,
                  durable: DurQ({ v2: v2, guid: guid, persistent: false }) })

    // A CREATE carrying a durable RECONNECT.
    def createDurC(name: Name, opl: OplockReq, v2: bool, fid: FileId,
                   guid: int, persistent: bool, alsoQ: bool,
                   withName: bool): Cmd =
        CCreate({ dir: ROOT, name: name, disp: DispOpen, access: ACCESS_RW,
                  share: SHARE_RWD, isDir: false, delOnClose: false,
                  oplock: opl,
                  durable: DurC({ v2: v2, fid: fid, guid: guid,
                                  persistent: persistent, alsoQ: alsoQ,
                                  withName: withName }) })

    // D1: the durable precondition is on the caching grant that was actually
    // MADE -- a BATCH oplock or a lease carrying HANDLE caching.  LEVEL_II and
    // an R-only lease are refused; a BATCH oplock and an RH lease are granted.
    run durableGrantMatrixTest =
        bootRun
            .then(runM(one(0, 0, createDurQ("a", DispCreate, ACCESS_RW,
                                            SHARE_RWD, OrBatch, true, 1))))
            .expect(stAt(0) == ST_SUCCESS and asCreate(resAt(0)).durable)
            .then(runM(one(0, 0, createDurQ("b", DispCreate, ACCESS_RW,
                                            SHARE_RWD, OrLevelII, true, 2))))
            .expect(stAt(0) == ST_SUCCESS and not(asCreate(resAt(0)).durable))
            .then(runM(one(0, 0, createDurQ("c", DispCreate, ACCESS_RW,
                                            SHARE_RWD,
                                            OrLease({ key: 1, r: true,
                                                      w: false, h: true,
                                                      v2: true, epoch: 1 }),
                                            true, 1))))
            // Same guid as "a" is fine only because "a" is a DIFFERENT durable
            // open of the same client -- it is not: this must COLLIDE.
            .expect(stAt(0) == ST_DUPLICATE_OBJECTID)
            .then(runM(one(0, 0, createDurQ("c", DispCreate, ACCESS_RW,
                                            SHARE_RWD,
                                            OrLease({ key: 1, r: true,
                                                      w: false, h: true,
                                                      v2: true, epoch: 1 }),
                                            true, 3))))
            .expect(stAt(0) == ST_SUCCESS and asCreate(resAt(0)).durable)
            // An R-only lease carries no HANDLE caching: refused.
            .then(runM(one(0, 0, createDurQ("d", DispCreate, ACCESS_RW,
                                            SHARE_RWD,
                                            OrLease({ key: 2, r: true,
                                                      w: false, h: false,
                                                      v2: true, epoch: 1 }),
                                            true, 4))))
            .expect(stAt(0) == ST_SUCCESS and not(asCreate(resAt(0)).durable))

    // D3 / D3b: a transport drop PARKS a durable open; the reclaim re-homes
    // the same handle with the same FileId and the same caching grant, and a
    // SECOND drop parks it again.  D6: a non-durable open does not survive.
    run durableParkReclaimTest =
        bootRun
            .then(runM(one(0, 0, createDurQ("a", DispCreate, ACCESS_RW,
                                            SHARE_RWD, OrBatch, true, 1))))
            .expect(stAt(0) == ST_SUCCESS and asCreate(resAt(0)).durable)
            .expect(asCreate(resAt(0)).fid == 0)
            // A second, NON-durable open of another file on the same session.
            .then(runM(one(0, 0, create(ROOT, "b", DispCreate, ACCESS_RW,
                                        SHARE_RWD, false, OrNone))))
            .expect(stAt(0) == ST_SUCCESS and asCreate(resAt(0)).fid == 1)
            .then(runM(one(0, -1, CDisconnect)))
            .expect(stAt(0) == ST_SUCCESS)
            // fid 0 parked, fid 1 gone, session and tree gone.
            .expect(sdb.parked.keys() == Set(0))
            .expect(sdb.opens.keys() == Set())
            .expect(not(sdb.sessions.keys().contains(0)))
            // Reconnect as the same client and reclaim.
            .then(runM({ sess: -1, tree: -1, related: false, cs: 0, replay: false,
                         cmds: [ CReconnect({ prev: 0 }) ] }))
            .expect(stAt(0) == ST_SUCCESS)
            .then(runM(one(1, -1, CTreeConnect({ share: 1 }))))
            .expect(stAt(0) == ST_SUCCESS)
            .then(runM(one(1, 1, createDurC("", OrNone, true, 0, 1, false,
                                            false, false))))
            .expect(stAt(0) == ST_SUCCESS)
            .expect(asCreate(resAt(0)).fid == 0)
            .expect(asCreate(resAt(0)).act == ACT_OPENED)
            // A reconnect grants nothing new: no durable response context.
            .expect(not(asCreate(resAt(0)).durable))
            // The caching grant survived the drop untouched.
            .expect(asCreate(resAt(0)).caching == COplock(OpBatch))
            .expect(sdb.parked.keys() == Set())
            // A SECOND drop parks it again (D3b), and a second reclaim works.
            .then(runM(one(1, -1, CDisconnect)))
            .expect(sdb.parked.keys() == Set(0))

    // D4: the reclaim denial matrix.  Each arm is a DIFFERENT status, and a
    // refused reconnect consumes nothing -- the final, well-formed reclaim
    // still succeeds.
    run durableReclaimDenialTest =
        bootRun
            .then(runM(one(0, 0, createDurQ("a", DispCreate, ACCESS_RW,
                                            SHARE_RWD,
                                            OrLease({ key: 1, r: true,
                                                      w: false, h: true,
                                                      v2: true, epoch: 1 }),
                                            true, 1))))
            .expect(stAt(0) == ST_SUCCESS and asCreate(resAt(0)).durable)
            .then(runM(one(0, -1, CDisconnect)))
            .then(runM({ sess: -1, tree: -1, related: false, cs: 0, replay: false,
                         cmds: [ CReconnect({ prev: 0 }) ] }))
            .then(runM(one(1, -1, CTreeConnect({ share: 1 }))))
            .expect(stAt(0) == ST_SUCCESS)
            // The lease the parked handle actually holds, for the good arms.
            .then(runM(one(1, 1, createDurC("", OrLease({ key: 1, r: true,
                                                          w: false, h: true,
                                                          v2: true,
                                                          epoch: 2 }),
                                            true, 0, 9, false, false, false))))
            // wrong CreateGuid
            .expect(stAt(0) == ST_OBJECT_NAME_NOT_FOUND)
            .then(runM(one(1, 1, createDurC("", OrNone, true, 0, 1, false,
                                            false, false))))
            // leased handle, reconnect with no lease context
            .expect(stAt(0) == ST_OBJECT_NAME_NOT_FOUND)
            .then(runM(one(1, 1, createDurC("", OrLease({ key: 2, r: true,
                                                          w: false, h: true,
                                                          v2: true,
                                                          epoch: 2 }),
                                            true, 0, 1, false, false, false))))
            // wrong lease key
            .expect(stAt(0) == ST_OBJECT_NAME_NOT_FOUND)
            .then(runM(one(1, 1, createDurC("b", OrLease({ key: 1, r: true,
                                                           w: false, h: true,
                                                           v2: true,
                                                           epoch: 2 }),
                                            true, 0, 1, false, false, true))))
            // a leased reconnect naming another file
            .expect(stAt(0) == ST_INVALID_PARAMETER)
            .then(runM(one(1, 1, createDurC("", OrLease({ key: 1, r: true,
                                                          w: false, h: true,
                                                          v2: true,
                                                          epoch: 2 }),
                                            true, 0, 1, false, true, false))))
            // DH2C + DH2Q
            .expect(stAt(0) == ST_INVALID_PARAMETER)
            .then(runM(one(1, 1, createDurC("", OrLease({ key: 1, r: true,
                                                          w: false, h: true,
                                                          v2: true,
                                                          epoch: 2 }),
                                            true, 0, 1, true, false, false))))
            // FLAG_PERSISTENT against a durable-only handle
            .expect(stAt(0) == ST_INVALID_PARAMETER)
            .then(runM(one(1, 1, createDurC("", OrLease({ key: 1, r: true,
                                                          w: false, h: true,
                                                          v2: true,
                                                          epoch: 2 }),
                                            true, 7, 1, false, false, false))))
            // an id that names nothing
            .expect(stAt(0) == ST_OBJECT_NAME_NOT_FOUND)
            // ... and after all of that the handle is still there.
            .then(runM(one(1, 1, createDurC("", OrLease({ key: 1, r: true,
                                                          w: false, h: true,
                                                          v2: true,
                                                          epoch: 2 }),
                                            true, 0, 1, false, false, false))))
            .expect(stAt(0) == ST_SUCCESS and asCreate(resAt(0)).fid == 0)
            // A SECOND reclaim of the now-live handle: never stolen, and the
            // refusal is announced with an async interim first, because the
            // server cannot tell it from a reclaim racing its own disconnect.
            .then(runM(one(1, 1, createDurC("", OrLease({ key: 1, r: true,
                                                          w: false, h: true,
                                                          v2: true,
                                                          epoch: 2 }),
                                            true, 0, 1, false, false, false))))
            .expect(stAt(0) == ST_OBJECT_NAME_NOT_FOUND)
            .expect(asCreate(resAt(0)).parked)

    // D7 / D7d / D7e / D7f: which incoming opens DISSOLVE a parked holder.
    //
    // A parked holder owning a WRITE cache is purged by any non-stat open,
    // even a fully compatible one; one without a write cache survives a
    // compatible open -- and then CAPS it, because the sole-Open condition of
    // MS-FSA 2.1.5.18.1 counts a holder that is not even connected.
    run durablePurgeTest =
        bootRun
            // (1) a parked BATCH holder (write cache) meets a compatible open.
            .then(runM(one(0, 0, createDurQ("a", DispCreate, ACCESS_RW,
                                            SHARE_RWD, OrBatch, true, 1))))
            .expect(stAt(0) == ST_SUCCESS and asCreate(resAt(0)).durable)
            .then(runM(one(0, -1, CDisconnect)))
            .expect(sdb.parked.keys() == Set(0))
            .then(runM({ sess: -1, tree: -1, related: false, cs: 0, replay: false,
                         cmds: [ CSessionSetup({ clientSym: 2 }) ] }))
            .then(runM(one(1, -1, CTreeConnect({ share: 1 }))))
            .then(runM(one(1, 1, create(ROOT, "a", DispOpen, ACCESS_RW,
                                        SHARE_RWD, false,
                                        OrLease({ key: 2, r: true, w: true,
                                                  h: true, v2: true,
                                                  epoch: 1 })))))
            .expect(stAt(0) == ST_SUCCESS)
            // purged, and the opener got the full write cache
            .expect(sdb.parked.keys() == Set())
            .expect(cachBits(asCreate(resAt(0)).caching) == BITS_RWH)

    run durableParkedCapTest =
        bootRun
            // (2) a parked RH-lease holder (NO write cache) meets the same
            // compatible open: it SURVIVES, and the opener is capped to RH.
            .then(runM(one(0, 0, createDurQ("a", DispCreate, ACCESS_RW,
                                            SHARE_RWD,
                                            OrLease({ key: 1, r: true,
                                                      w: false, h: true,
                                                      v2: true, epoch: 1 }),
                                            true, 1))))
            .expect(stAt(0) == ST_SUCCESS and asCreate(resAt(0)).durable)
            .then(runM(one(0, -1, CDisconnect)))
            .expect(sdb.parked.keys() == Set(0))
            .then(runM({ sess: -1, tree: -1, related: false, cs: 0, replay: false,
                         cmds: [ CSessionSetup({ clientSym: 2 }) ] }))
            .then(runM(one(1, -1, CTreeConnect({ share: 1 }))))
            .then(runM(one(1, 1, create(ROOT, "a", DispOpen, ACCESS_RW,
                                        SHARE_RWD, false,
                                        OrLease({ key: 2, r: true, w: true,
                                                  h: true, v2: true,
                                                  epoch: 1 })))))
            .expect(stAt(0) == ST_SUCCESS)
            .expect(sdb.parked.keys() == Set(0))
            .expect(cachBits(asCreate(resAt(0)).caching) == BITS_RH)
            // A SHARE-conflicting open dissolves even that one (D7f).
            .then(runM(one(1, 1, create(ROOT, "a", DispOpen, ACCESS_RW,
                                        SHARE_NONE, false, OrNone))))
            .expect(sdb.parked.keys() == Set())

    // An attribute-only, non-truncating open breaks nobody, so it purges
    // nothing (D7b) -- the converse of durablePurgeTest, and the reason the
    // purge is gated on statOpen rather than applied to every CREATE.
    run durableStatOpenNoPurgeTest =
        bootRun
            .then(runM(one(0, 0, createDurQ("a", DispCreate, ACCESS_RW,
                                            SHARE_RWD, OrBatch, true, 1))))
            .expect(stAt(0) == ST_SUCCESS and asCreate(resAt(0)).durable)
            .then(runM(one(0, -1, CDisconnect)))
            .expect(sdb.parked.keys() == Set(0))
            .then(runM({ sess: -1, tree: -1, related: false, cs: 0, replay: false,
                         cmds: [ CSessionSetup({ clientSym: 2 }) ] }))
            .then(runM(one(1, -1, CTreeConnect({ share: 1 }))))
            .then(runM(one(1, 1, create(ROOT, "a", DispOpen, ACCESS_H,
                                        SHARE_RWD, false, OrNone))))
            .expect(stAt(0) == ST_SUCCESS)
            .expect(sdb.parked.keys() == Set(0))

    // MS-SMB2 3.3.5.9.10: a CreateGuid names ONE durable open per client.  A
    // second DH2Q carrying it -- against a LIVE open or a PARKED one -- is
    // STATUS_DUPLICATE_OBJECTID, and it outranks the disposition, so it fires
    // even where the create would otherwise have been a name collision.
    // Another CLIENT may use the same guid freely.
    run durableDuplicateGuidTest =
        boot2Run
            .then(runM(one(0, 0, createDurQ("a", DispCreate, ACCESS_RW,
                                            SHARE_RWD, OrBatch, true, 5))))
            .expect(stAt(0) == ST_SUCCESS and asCreate(resAt(0)).durable)
            // same client, same guid, different file -> collision
            .then(runM(one(0, 0, createDurQ("b", DispCreate, ACCESS_RW,
                                            SHARE_RWD, OrBatch, true, 5))))
            .expect(stAt(0) == ST_DUPLICATE_OBJECTID)
            // a DIFFERENT client may use it
            .then(runM(one(1, 1, createDurQ("c", DispCreate, ACCESS_RW,
                                            SHARE_RWD, OrBatch, true, 5))))
            .expect(stAt(0) == ST_SUCCESS)
            // the collision survives the holder being PARKED
            .then(runM(one(0, -1, CDisconnect)))
            .expect(sdb.parked.keys() == Set(0))
            .then(runM({ sess: -1, tree: -1, related: false, cs: 0, replay: false,
                         cmds: [ CReconnect({ prev: 0 }) ] }))
            .then(runM(one(2, -1, CTreeConnect({ share: 1 }))))
            .then(runM(one(2, 2, createDurQ("b", DispOpenIf, ACCESS_RW,
                                            SHARE_RWD, OrBatch, true, 5))))
            .expect(stAt(0) == ST_DUPLICATE_OBJECTID)
            // a DHnQ (v1) request carries no CreateGuid at all, so it cannot
            // collide however many durable handles this client holds.
            .then(runM(one(2, 2, createDurQ("b", DispOpenIf, ACCESS_RW,
                                            SHARE_RWD, OrBatch, false, 5))))
            .expect(stAt(0) == ST_SUCCESS and asCreate(resAt(0)).durable)

    // A durable grant needs the server to advertise durable handles at all
    // (config persistent_handles).  This is what makes caps.durable
    // load-bearing: with it off no grant is made and nothing can ever park,
    // which is the `durableRespected` invariant.
    run durableCapGateTest =
        bootRun
            .then(runM(one(0, 0, createDurQ("a", DispCreate, ACCESS_RW,
                                            SHARE_RWD, OrBatch, true, 1))))
            .expect(caps.durable == asCreate(resAt(0)).durable)
            .expect(durableRespected)

    // The durable flavor is generated, so it needs its own invariant walk.
    run randomDurableWalkTest =
        init.then(80.reps(_ => all { inv, stepDurable }))

    // ------------------------------------------------------------------
    // Random-walk invariant preservation
    // ------------------------------------------------------------------

    run randomWalkTest =
        init.then(80.reps(_ => all { inv, step }))

    run randomShareWalkTest =
        init.then(60.reps(_ => all { inv, stepShare }))

    run randomLeaseWalkTest =
        init.then(60.reps(_ => all { inv, stepLease }))

    run randomDataWalkTest =
        init.then(60.reps(_ => all { inv, stepData }))

    // Every flavor the corpus is generated from must itself preserve the
    // invariant.  stepIo is NOT generated (delete-on-close, Q-1) but is walked
    // anyway: it is the superset stepReq was carved out of, so a rule gap that
    // only delete-on-close reaches still shows up here.
    run randomCoreWalkTest =
        init.then(60.reps(_ => all { inv, stepCore }))

    run randomIoWalkTest =
        init.then(60.reps(_ => all { inv, stepIo }))

    // stepDir is generated too, so it needs its own walk.
    run randomDirWalkTest =
        init.then(60.reps(_ => all { inv, stepDir }))

    // stepReq is generated too (the oplock/lease REQUEST matrix).
    run randomReqWalkTest =
        init.then(60.reps(_ => all { inv, stepReq }))
    // ==================================================================
    // The exactly-once layer (MS-SMB2 3.3.5.2.10 / 3.3.5.9.10)
    //
    // Ground truth for every expectation below is smb2_replay_probe.c; the
    // section it mirrors is named on each test.  Two mechanisms, deliberately
    // tested apart: the CREATE reply cache (keyed by DH2Q CreateGuid, answers
    // without re-applying) and the ChannelSequence window (no cache at all,
    // refuses a request from a superseded channel).
    // ==================================================================

    // R6: the window itself, and the fact that a REJECTED request changes
    // nothing while an ACCEPTED one at the same sequence is re-executed.  The
    // content assertions are the point -- the statuses alone cannot separate
    // "applied once" from "applied twice".
    run csWindowTest =
        bootRun
            .then(runM(one(0, 0, create(ROOT, "a", DispCreate, ACCESS_RW,
                                        SHARE_RWD, false, OrNone))))
            .expect(stAt(0) == ST_SUCCESS)
            // forward from the seeded 0 -> accepted
            .then(runM(oneCs(0, 0, CWrite({ fid: FidRef(0), off: 0, len: 1,
                                            pat: 7 }), 5)))
            .expect(stAt(0) == ST_SUCCESS)
            .expect(sdb.opens.get(0).cs == 5)
            .then(runM(oneCs(0, 0, CRead({ fid: FidRef(0), off: 0, len: 1 }), 5)))
            .expect(asRead(resAt(0)).blocks == [ 7 ])
            // behind -> refused ...
            .then(runM(oneCs(0, 0, CWrite({ fid: FidRef(0), off: 0, len: 1,
                                            pat: 9 }), 0)))
            .expect(stAt(0) == ST_FILE_NOT_AVAILABLE)
            // ... and THE EFFECT: the file is untouched.  This is the
            // assertion that separates "rejected" from "applied anyway"; the
            // status alone could not.
            .then(runM(oneCs(0, 0, CRead({ fid: FidRef(0), off: 0, len: 1 }), 5)))
            .expect(asRead(resAt(0)).blocks == [ 7 ])
            // a rejected request does NOT move the mark
            .expect(sdb.opens.get(0).cs == 5)
            // the SAME sequence is accepted and RE-EXECUTED: there is no reply
            // cache on the mutation path (probe R6/4)
            .then(runM(oneCs(0, 0, CWrite({ fid: FidRef(0), off: 0, len: 1,
                                            pat: 9 }), 5)))
            .expect(stAt(0) == ST_SUCCESS)
            .then(runM(oneCs(0, 0, CRead({ fid: FidRef(0), off: 0, len: 1 }), 5)))
            .expect(asRead(resAt(0)).blocks == [ 9 ])

    // R6/5, R6/6, R10a: the comparison is modular, so the accept/reject
    // boundary is a distance and a forward jump is BOUNDED.
    run csModularTest =
        bootRun
            .then(runM(one(0, 0, create(ROOT, "a", DispCreate, ACCESS_RW,
                                        SHARE_RWD, false, OrNone))))
            // delta 0x7FFF: still forward
            .then(runM(oneCs(0, 0, CWrite({ fid: FidRef(0), off: 0, len: 1,
                                            pat: 1 }), 0x7FFF)))
            .expect(stAt(0) == ST_SUCCESS and sdb.opens.get(0).cs == 0x7FFF)
            // delta 0x8000 exactly: stale
            .then(runM(oneCs(0, 0, CWrite({ fid: FidRef(0), off: 0, len: 1,
                                            pat: 2 }), 0xFFFF)))
            .expect(stAt(0) == ST_FILE_NOT_AVAILABLE)
            // a single jump of more than +0x7FFF is refused, not forward
            .then(runM(oneCs(0, 0, CWrite({ fid: FidRef(0), off: 0, len: 1,
                                            pat: 3 }), 0x0FFE)))
            .expect(stAt(0) == ST_FILE_NOT_AVAILABLE)
            // ... but the wrap itself is forward: from 0x7FFF, 0xFFFE is +0x7FFF
            .then(runM(oneCs(0, 0, CWrite({ fid: FidRef(0), off: 0, len: 1,
                                            pat: 4 }), 0xFFFE)))
            .expect(stAt(0) == ST_SUCCESS and sdb.opens.get(0).cs == 0xFFFE)
            // and from 0xFFFE, ChannelSequence 1 is FORWARD by 3
            .then(runM(oneCs(0, 0, CWrite({ fid: FidRef(0), off: 0, len: 1,
                                            pat: 5 }), 1)))
            .expect(stAt(0) == ST_SUCCESS and sdb.opens.get(0).cs == 1)

    // R11 + R8: the mark is seeded by the CREATE and is per-OPEN.
    run csSeedAndScopeTest =
        bootRun
            // an Open created at 0x0100 does not start at 0
            .then(runM(oneCs(0, 0, create(ROOT, "a", DispCreate, ACCESS_RW,
                                          SHARE_RWD, false, OrNone), 0x0100)))
            .expect(stAt(0) == ST_SUCCESS and sdb.opens.get(0).cs == 0x0100)
            .then(runM(oneCs(0, 0, CWrite({ fid: FidRef(0), off: 0, len: 1,
                                            pat: 1 }), 0)))
            .expect(stAt(0) == ST_FILE_NOT_AVAILABLE)
            // a SECOND open of the same file keeps its own mark
            .then(runM(one(0, 0, create(ROOT, "a", DispOpen, ACCESS_RW,
                                        SHARE_RWD, false, OrNone))))
            .expect(stAt(0) == ST_SUCCESS and sdb.opens.get(1).cs == 0)
            .then(runM(oneCs(0, 0, CWrite({ fid: FidRef(1), off: 0, len: 1,
                                            pat: 1 }), 1)))
            .expect(stAt(0) == ST_SUCCESS)
            // ... and driving handle 1 forward leaves handle 0 where it was
            .expect(sdb.opens.get(0).cs == 0x0100)

    // R7: which operations consult the sequence.  A READ is never refused, a
    // STALE read does not move the mark, and a FORWARD read DOES -- so a later
    // write at the earlier sequence becomes stale.
    run csReadAdvancesTest =
        bootRun
            .then(runM(one(0, 0, create(ROOT, "a", DispCreate, ACCESS_RW,
                                        SHARE_RWD, false, OrNone))))
            .then(runM(oneCs(0, 0, CWrite({ fid: FidRef(0), off: 0, len: 1,
                                            pat: 1 }), 10)))
            .expect(stAt(0) == ST_SUCCESS and sdb.opens.get(0).cs == 10)
            // a stale READ is served, and does not move the mark backwards
            .then(runM(oneCs(0, 0, CRead({ fid: FidRef(0), off: 0, len: 1 }), 1)))
            .expect(stAt(0) == ST_SUCCESS and sdb.opens.get(0).cs == 10)
            .then(runM(oneCs(0, 0, CWrite({ fid: FidRef(0), off: 0, len: 1,
                                            pat: 2 }), 10)))
            .expect(stAt(0) == ST_SUCCESS)
            // a FORWARD read advances it
            .then(runM(oneCs(0, 0, CRead({ fid: FidRef(0), off: 0, len: 1 }),
                             200)))
            .expect(stAt(0) == ST_SUCCESS and sdb.opens.get(0).cs == 200)
            .then(runM(oneCs(0, 0, CWrite({ fid: FidRef(0), off: 0, len: 1,
                                            pat: 3 }), 10)))
            .expect(stAt(0) == ST_FILE_NOT_AVAILABLE)

    // R14: WHEN the mark advances -- at the gate, or on success?  Invisible
    // until an op clears the gate and is then refused for a LATER reason.  A
    // write into another handle's exclusive byte-range lock is exactly that
    // shape: chimera advances inside the sequence check (smb_proc_write.c:294)
    // and enforces the lock afterwards (:356), so the refused write has still
    // moved the mark.  Measured by probe R14 before it was modeled.
    run csAdvanceAtGateTest =
        bootRun
            .then(runM(one(0, 0, create(ROOT, "a", DispCreate, ACCESS_RW,
                                        SHARE_RWD, false, OrNone))))
            .expect(stAt(0) == ST_SUCCESS)
            .then(runM(one(0, 0, create(ROOT, "a", DispOpen, ACCESS_RW,
                                        SHARE_RWD, false, OrNone))))
            .expect(stAt(0) == ST_SUCCESS)
            // handle 0 locks [0,2) exclusively
            .then(runM(one(0, 0, CLock({ fid: FidRef(0), lo: 0, hi: 2,
                                         wr: true, unlock: false,
                                         failImmediately: true }))))
            .expect(stAt(0) == ST_SUCCESS)
            // handle 1 writes INTO the lock at a forward sequence: the gate
            // passes, the lock refuses
            .then(runM(oneCs(0, 0, CWrite({ fid: FidRef(1), off: 0, len: 1,
                                            pat: 1 }), 100)))
            .expect(stAt(0) == ST_FILE_LOCK_CONFLICT)
            // ... and the mark moved anyway
            .expect(sdb.opens.get(1).cs == 100)
            .then(runM(oneCs(0, 0, CWrite({ fid: FidRef(1), off: 3, len: 1,
                                            pat: 1 }), 1)))
            .expect(stAt(0) == ST_FILE_NOT_AVAILABLE)
            .then(runM(oneCs(0, 0, CWrite({ fid: FidRef(1), off: 3, len: 1,
                                            pat: 1 }), 100)))
            .expect(stAt(0) == ST_SUCCESS)

    // R12: WHERE the gate sits, and that the two placements really differ.
    // On WRITE, ACCESS_DENIED outranks a stale sequence; on SET_INFO the stale
    // sequence outranks the class check.  A test that only owned the rule and
    // not its position would pass with either placement.
    run csGateOrderTest =
        bootRun
            .then(runM(one(0, 0, create(ROOT, "a", DispCreate, ACCESS_RW,
                                        SHARE_RWD, false, OrNone))))
            // a read-only second handle, seeded at 0
            .then(runM(one(0, 0, create(ROOT, "a", DispOpen, ACCESS_R,
                                        SHARE_RWD, false, OrNone))))
            .expect(stAt(0) == ST_SUCCESS)
            // control: on the WRITABLE handle that sequence really is stale
            .then(runM(oneCs(0, 0, CWrite({ fid: FidRef(0), off: 0, len: 1,
                                            pat: 1 }), 0x9000)))
            .expect(stAt(0) == ST_FILE_NOT_AVAILABLE)
            // WRITE: the access fault wins
            .then(runM(oneCs(0, 0, CWrite({ fid: FidRef(1), off: 0, len: 1,
                                            pat: 1 }), 0x9000)))
            .expect(stAt(0) == ST_ACCESS_DENIED)
            // SET_INFO: the stale sequence wins
            .then(runM(oneCs(0, 0, CSetEof({ fid: FidRef(1), sizeBlocks: 0 }),
                             0x9000)))
            .expect(stAt(0) == ST_FILE_NOT_AVAILABLE)
            // a closed handle outranks both
            .then(runM(one(0, 0, CClose(FidRef(1)))))
            .then(runM(oneCs(0, 0, CWrite({ fid: FidRef(1), off: 0, len: 1,
                                            pat: 1 }), 0x9000)))
            .expect(stAt(0) == ST_FILE_CLOSED)

    // MS-FSA 2.1.5.14: setting file information is gated on the access the
    // class requires, and FileEndOfFileInformation requires FILE_WRITE_DATA --
    // so a SET_EOF through a read-only or attribute-only handle is
    // ACCESS_DENIED even at a perfectly fresh ChannelSequence.
    //
    // This pins the arm the generated corpus deliberately does NOT draw:
    // chimera answers SUCCESS and resizes the file (DEVIATIONS-SMB.md S-4,
    // probe R15), so `smbSetEofCs` draws only writable handles.  Without this
    // test the rule would be unowned the moment the generator stopped
    // reaching it.  The two positive arms keep it honest: a writable handle
    // succeeds, and the refusal changes nothing (a later read still sees the
    // original size).
    run setEofNeedsWriteTest =
        bootRun
            .then(runM(one(0, 0, create(ROOT, "a", DispCreate, ACCESS_RW,
                                        SHARE_RWD, false, OrNone))))
            .then(runM(one(0, 0, CWrite({ fid: FidRef(0), off: 0, len: 2,
                                          pat: 1 }))))
            .expect(stAt(0) == ST_SUCCESS)
            // a read-only handle on the same file
            .then(runM(one(0, 0, create(ROOT, "a", DispOpen, ACCESS_R,
                                        SHARE_RWD, false, OrNone))))
            .expect(stAt(0) == ST_SUCCESS)
            .then(runM(one(0, 0, CSetEof({ fid: FidRef(1), sizeBlocks: 0 }))))
            .expect(stAt(0) == ST_ACCESS_DENIED)
            // an attribute-only handle has strictly less access still
            .then(runM(one(0, 0, create(ROOT, "a", DispOpen, ACCESS_H,
                                        SHARE_RWD, false, OrNone))))
            .expect(stAt(0) == ST_SUCCESS)
            .then(runM(one(0, 0, CSetEof({ fid: FidRef(2), sizeBlocks: 0 }))))
            .expect(stAt(0) == ST_ACCESS_DENIED)
            // and the refusals changed nothing: the file is still 2 blocks
            .then(runM(one(0, 0, CRead({ fid: FidRef(1), off: 0, len: 2 }))))
            .expect(stAt(0) == ST_SUCCESS)
            // the writable handle may do it
            .then(runM(one(0, 0, CSetEof({ fid: FidRef(0), sizeBlocks: 0 }))))
            .expect(stAt(0) == ST_SUCCESS)

    // R9: SMB2_FLAGS_REPLAY_OPERATION plays NO part in the ChannelSequence
    // rule, in EITHER direction.  Both halves are needed: a model that
    // exempted a replay from the rule would pass a test that only checked the
    // forward case, and one that refused to advance on a replay would pass a
    // test that only checked the stale case.
    //
    // Worth its own test because it is a live question in the tree: chimera's
    // own note on chimera_smb_channel_sequence_stale records that the Windows
    // reference behavior treats a replayed and a fresh forward jump
    // identically, contradicting the premise of issue #1290.
    run csReplayFlagIrrelevantTest =
        bootRun
            .then(runM(one(0, 0, create(ROOT, "a", DispCreate, ACCESS_RW,
                                        SHARE_RWD, false, OrNone))))
            .then(runM(oneCs(0, 0, CWrite({ fid: FidRef(0), off: 0, len: 1,
                                            pat: 1 }), 50)))
            .expect(stAt(0) == ST_SUCCESS and sdb.opens.get(0).cs == 50)
            // stale + the replay flag is still stale, and still changes nothing
            .then(runM(oneCsRp(0, 0, CWrite({ fid: FidRef(0), off: 0, len: 1,
                                              pat: 2 }), 1)))
            .expect(stAt(0) == ST_FILE_NOT_AVAILABLE)
            .then(runM(oneCs(0, 0, CRead({ fid: FidRef(0), off: 0, len: 1 }),
                             50)))
            .expect(asRead(resAt(0)).blocks == [ 1 ])
            // forward + the replay flag still ADVANCES the mark
            .then(runM(oneCsRp(0, 0, CWrite({ fid: FidRef(0), off: 0, len: 1,
                                              pat: 3 }), 60)))
            .expect(stAt(0) == ST_SUCCESS and sdb.opens.get(0).cs == 60)
            .then(runM(oneCs(0, 0, CWrite({ fid: FidRef(0), off: 0, len: 1,
                                            pat: 4 }), 50)))
            .expect(stAt(0) == ST_FILE_NOT_AVAILABLE)

    // R3: the CREATE reply cache, asserted on the EFFECT.  The replay answers
    // with the ORIGINAL FileId and the ORIGINAL CreateAction -- which a
    // re-applied FILE_CREATE could not produce, as the control shows -- and it
    // creates NO second open.
    run replayCreateExactlyOnceTest =
        bootRun
            // control: FILE_CREATE is not idempotent
            .then(runM(one(0, 0, create(ROOT, "c", DispCreate, ACCESS_RW,
                                        SHARE_RWD, false, OrNone))))
            .expect(stAt(0) == ST_SUCCESS)
            .then(runM(one(0, 0, create(ROOT, "c", DispCreate, ACCESS_RW,
                                        SHARE_RWD, false, OrNone))))
            .expect(stAt(0) == ST_OBJECT_NAME_COLLISION)
            // the original: durable, batch-oplocked, carrying a CreateGuid
            .then(runM(one(0, 0, createDurQ("a", DispCreate, ACCESS_RW,
                                            SHARE_RWD, OrBatch, true, 1))))
            .expect(stAt(0) == ST_SUCCESS)
            .expect(asCreate(resAt(0)).act == ACT_CREATED)
            .expect(asCreate(resAt(0)).durable)
            .expect(sdb.opens.get(1).replayOk)
            // the replay: answered from the original open
            .then(runM(oneRp(0, 0, createDurQ("a", DispCreate, ACCESS_RW,
                                              SHARE_RWD, OrBatch, true, 1))))
            .expect(stAt(0) == ST_SUCCESS)
            .expect(asCreate(resAt(0)).fid == 1)
            .expect(asCreate(resAt(0)).act == ACT_CREATED)
            // it re-advertises the grant the original reported (R3c)
            .expect(asCreate(resAt(0)).durable)
            // THE EFFECT: no second open exists
            .expect(sdb.opens.keys() == Set(0, 1))
            // ... and the replay did NOT close its own eligibility window
            .expect(sdb.opens.get(1).replayOk)

    // M-16 / probe R17: a reclaim RESEEDS the handle's ChannelSequence mark
    // from the reclaiming CREATE, rather than keeping the pre-drop one.  The
    // marks are chosen so "kept" and "reseeded" disagree about BOTH following
    // writes, which is what makes this test able to fail.
    run reclaimReseedsChannelSequenceTest =
        bootRun
            .then(runM(one(0, 0, createDurQ("a", DispCreate, ACCESS_RW,
                                            SHARE_RWD, OrBatch, true, 1))))
            .expect(stAt(0) == ST_SUCCESS and asCreate(resAt(0)).durable)
            .then(runM(oneCs(0, 0, CWrite({ fid: FidRef(0), off: 0, len: 1,
                                            pat: 1 }), 100)))
            .expect(stAt(0) == ST_SUCCESS and sdb.opens.get(0).cs == 100)
            .then(runM(one(0, -1, CDisconnect)))
            .expect(sdb.parked.keys() == Set(0))
            .then(runM({ sess: -1, tree: -1, related: false, cs: 0,
                         replay: false, cmds: [ CReconnect({ prev: 0 }) ] }))
            .then(runM(one(1, -1, CTreeConnect({ share: 1 }))))
            .expect(stAt(0) == ST_SUCCESS)
            // the reclaim arrives on a new channel, at sequence 5
            .then(runM(oneCs(1, 1, createDurC("", OrBatch, true, 0, 1, false,
                                              false, false), 5)))
            .expect(stAt(0) == ST_SUCCESS and asCreate(resAt(0)).fid == 0)
            .expect(sdb.opens.get(0).cs == 5)
            // a write at 5 is accepted -- it would be STALE against a kept 100
            .then(runM(oneCs(1, 1, CWrite({ fid: FidRef(0), off: 0, len: 1,
                                            pat: 2 }), 5)))
            .expect(stAt(0) == ST_SUCCESS)
            // and 4 is stale against the reseeded mark -- it would have been
            // stale against 100 too, which is why the pair is needed
            .then(runM(oneCs(1, 1, CWrite({ fid: FidRef(0), off: 0, len: 1,
                                            pat: 3 }), 4)))
            .expect(stAt(0) == ST_FILE_NOT_AVAILABLE)

    // M-15 / probe R16: WHAT a replay reports when it asks for less than the
    // open it matched holds.  A LEGACY-oplock handle echoes the REQUESTED
    // level and emits a durable response only when that request was BATCH; a
    // LEASE handle reports the grant's current state and keeps its durable
    // response.  Both arms are here, because a model with one rule for both is
    // wrong for one of them.
    run replayReportsRequestedOplockTest =
        bootRun
            .then(runM(one(0, 0, createDurQ("a", DispCreate, ACCESS_RW,
                                            SHARE_RWD, OrBatch, true, 1))))
            .expect(stAt(0) == ST_SUCCESS)
            .expect(asCreate(resAt(0)).caching == COplock(OpBatch))
            .expect(asCreate(resAt(0)).durable)
            // a replay asking for NO oplock: the reply reports none, and no
            // durable grant -- while the OPEN still holds its batch oplock
            .then(runM(oneRp(0, 0, createDurQ("a", DispCreate, ACCESS_RW,
                                              SHARE_RWD, OrNone, true, 1))))
            .expect(stAt(0) == ST_SUCCESS and asCreate(resAt(0)).fid == 0)
            .expect(asCreate(resAt(0)).caching == CNone)
            .expect(not(asCreate(resAt(0)).durable))
            .expect(sdb.opens.get(0).caching == COplock(OpBatch))
            .expect(sdb.opens.get(0).durable.on)
            // a replay asking for LEVEL_II: echoed, still no durable response
            .then(runM(oneRp(0, 0, createDurQ("a", DispCreate, ACCESS_RW,
                                              SHARE_RWD, OrLevelII, true, 1))))
            .expect(asCreate(resAt(0)).caching == COplock(OpLevelII))
            .expect(not(asCreate(resAt(0)).durable))
            // asking for BATCH again brings both back
            .then(runM(oneRp(0, 0, createDurQ("a", DispCreate, ACCESS_RW,
                                              SHARE_RWD, OrBatch, true, 1))))
            .expect(asCreate(resAt(0)).caching == COplock(OpBatch))
            .expect(asCreate(resAt(0)).durable)
            // the LEASE arm: the reply follows the GRANT, not the request
            .then(runM(one(0, 0, createDurQ("b", DispCreate, ACCESS_RW,
                                            SHARE_RWD,
                                            OrLease({ key: 2, r: true,
                                                      w: true, h: true,
                                                      v2: true, epoch: 1 }),
                                            true, 2))))
            .expect(stAt(0) == ST_SUCCESS and asCreate(resAt(0)).durable)
            .then(runM(oneRp(0, 0, createDurQ("b", DispCreate, ACCESS_RW,
                                              SHARE_RWD,
                                              OrLease({ key: 2, r: true,
                                                        w: false, h: false,
                                                        v2: true, epoch: 1 }),
                                              true, 2))))
            .expect(stAt(0) == ST_SUCCESS and asCreate(resAt(0)).fid == 1)
            .expect(asCreate(resAt(0)).caching == sdb.opens.get(1).caching)
            .expect(asCreate(resAt(0)).durable)

    // R3e + R5: what the replay flag is worth.  Without it the same create is
    // a CreateGuid collision; with it but without a CreateGuid there is no key
    // to answer from and the create is EXECUTED.
    run replayNeedsFlagAndKeyTest =
        bootRun
            .then(runM(one(0, 0, createDurQ("a", DispCreate, ACCESS_RW,
                                            SHARE_RWD, OrBatch, true, 1))))
            .expect(stAt(0) == ST_SUCCESS)
            // no flag: a CreateGuid collision
            .then(runM(one(0, 0, createDurQ("a", DispCreate, ACCESS_RW,
                                            SHARE_RWD, OrBatch, true, 1))))
            .expect(stAt(0) == ST_DUPLICATE_OBJECTID)
            // flag, no CreateGuid: executed, and FILE_CREATE collides
            .then(runM(oneRp(0, 0, create(ROOT, "a", DispCreate, ACCESS_RW,
                                          SHARE_RWD, false, OrNone))))
            .expect(stAt(0) == ST_OBJECT_NAME_COLLISION)
            // flag, a CreateGuid that matches nothing: an ordinary create
            .then(runM(oneRp(0, 0, createDurQ("b", DispCreate, ACCESS_RW,
                                              SHARE_RWD, OrBatch, true, 2))))
            .expect(stAt(0) == ST_SUCCESS)
            .expect(asCreate(resAt(0)).act == ACT_CREATED)
            .expect(asCreate(resAt(0)).fid == 1)

    // R2: eligibility comes from the DH2Q CONTEXT, not from the durable GRANT.
    // A create with no caching oplock is refused durability and is replayable
    // anyway -- and its replay advertises no grant, because none was made.
    run replayWithoutDurableGrantTest =
        bootRun
            .then(runM(one(0, 0, createDurQ("a", DispCreate, ACCESS_RW,
                                            SHARE_RWD, OrNone, true, 1))))
            .expect(stAt(0) == ST_SUCCESS)
            .expect(not(asCreate(resAt(0)).durable))
            .expect(sdb.opens.get(0).replayOk)
            .then(runM(oneRp(0, 0, createDurQ("a", DispCreate, ACCESS_RW,
                                              SHARE_RWD, OrNone, true, 1))))
            .expect(stAt(0) == ST_SUCCESS)
            .expect(asCreate(resAt(0)).fid == 0)
            .expect(asCreate(resAt(0)).act == ACT_CREATED)
            .expect(not(asCreate(resAt(0)).durable))

    // R13: the eligibility window is ONE OPERATION wide, and it is closed by
    // any request that resolves the handle -- including a purely non-mutating
    // READ.  Afterwards the replay falls through to an ordinary create.
    run replayWindowClosesTest =
        bootRun
            .then(runM(one(0, 0, createDurQ("a", DispCreate, ACCESS_RW,
                                            SHARE_RWD, OrBatch, true, 1))))
            .expect(stAt(0) == ST_SUCCESS and sdb.opens.get(0).replayOk)
            // a plain READ closes it
            .then(runM(one(0, 0, CRead({ fid: FidRef(0), off: 0, len: 1 }))))
            .expect(not(sdb.opens.get(0).replayOk))
            // the replay is now an ordinary FILE_CREATE, which collides
            .then(runM(oneRp(0, 0, createDurQ("a", DispCreate, ACCESS_RW,
                                              SHARE_RWD, OrBatch, true, 1))))
            .expect(stAt(0) == ST_OBJECT_NAME_COLLISION)
            // a REPLAY-flagged request does NOT close the window
            .then(runM(one(0, 0, createDurQ("b", DispCreate, ACCESS_RW,
                                            SHARE_RWD, OrBatch, true, 2))))
            .expect(stAt(0) == ST_SUCCESS and sdb.opens.get(1).replayOk)
            .then(runM(oneRp(0, 0, CRead({ fid: FidRef(1), off: 0, len: 1 }))))
            .expect(sdb.opens.get(1).replayOk)

    // R4: the four outcomes of the create_guid classification against a
    // PARKED open.  DUPLICATE and DENIED must consume nothing, so the RECLAIM
    // that follows them still works.
    // M-14: a PARKED H-lease holder of the requesting client refuses a legacy
    // oplock exactly as a LIVE one does.
    //
    // G-4 (probe O12[32]/O12[33]) measured the live case: a client that already
    // holds an H lease on the file is granted NOTHING for a legacy oplock
    // request, LEVEL_II included -- handle caching already owns the handle and
    // the oplock must not recall the requester's own lease.  The model applied
    // that rule over live opens only, so a request behind the same client's
    // PARKED lease was granted LEVEL_II where the wire granted none
    // (smb2Durable/stepDurable 160x8 @0x61 trace 0, smallest failing prefix 96
    // states).  Coherent with C-28: a surviving parked holder is still a holder.
    //
    // The control is what makes this a scoped rule rather than "a parked lease
    // refuses everyone": a DIFFERENT client asking for the same LEVEL_II behind
    // the same parked lease still gets its read cache.
    run parkedHandleLeaseRefusesOplockTest =
        bootRun
            // an R+H lease, durable, so the drop parks it rather than closing it
            .then(runM(one(0, 0, createDurQ("a", DispCreate, ACCESS_RW,
                                            SHARE_RWD,
                                            OrLease({ key: 1, r: true,
                                                      w: false, h: true,
                                                      v2: true, epoch: 1 }),
                                            true, 1))))
            .expect(stAt(0) == ST_SUCCESS and asCreate(resAt(0)).durable)
            .then(runM(one(0, -1, CDisconnect)))
            .expect(sdb.parked.keys() == Set(0))
            // the same CLIENT comes back on a new connection ...
            .then(runM({ sess: -1, tree: -1, related: false, cs: 0,
                         replay: false, cmds: [ CReconnect({ prev: 0 }) ] }))
            .then(runM(one(1, -1, CTreeConnect({ share: 1 }))))
            .expect(stAt(0) == ST_SUCCESS)
            // ... and asks for a legacy read cache on the parked file: NOTHING.
            .then(runM(one(1, 1, create(ROOT, "a", DispOpen, ACCESS_RW,
                                        SHARE_RWD, false, OrLevelII))))
            .expect(stAt(0) == ST_SUCCESS)
            .expect(asCreate(resAt(0)).caching == CNone)
            // the parked holder survived the compatible open (C-27/D7d)
            .expect(sdb.parked.keys() == Set(0))
            // control: another CLIENT in the same position still gets LEVEL_II
            .then(runM({ sess: -1, tree: -1, related: false, cs: 0,
                         replay: false,
                         cmds: [ CSessionSetup({ clientSym: 2 }) ] }))
            .then(runM(one(2, -1, CTreeConnect({ share: 1 }))))
            .expect(stAt(0) == ST_SUCCESS)
            .then(runM(one(2, 2, create(ROOT, "a", DispOpen, ACCESS_RW,
                                        SHARE_RWD, false, OrLevelII))))
            .expect(stAt(0) == ST_SUCCESS)
            .expect(asCreate(resAt(0)).caching == COplock(OpLevelII))

    run replayClassifyParkedTest =
        bootRun
            .then(runM(one(0, 0, createDurQ("a", DispCreate, ACCESS_RW,
                                            SHARE_RWD,
                                            OrLease({ key: 1, r: true,
                                                      w: true, h: true,
                                                      v2: true, epoch: 1 }),
                                            true, 1))))
            .expect(stAt(0) == ST_SUCCESS and asCreate(resAt(0)).durable)
            .then(runM(one(0, -1, CDisconnect)))
            .expect(sdb.parked.keys() == Set(0))
            .then(runM({ sess: -1, tree: -1, related: false, cs: 0,
                         replay: false, cmds: [ CReconnect({ prev: 0 }) ] }))
            .then(runM(one(1, -1, CTreeConnect({ share: 1 }))))
            .expect(stAt(0) == ST_SUCCESS)
            // DUPLICATE: a NON-replay create colliding with the parked open
            .then(runM(one(1, 1, createDurQ("a", DispOpenIf, ACCESS_RW,
                                            SHARE_RWD,
                                            OrLease({ key: 1, r: true,
                                                      w: true, h: true,
                                                      v2: true, epoch: 1 }),
                                            true, 1))))
            .expect(stAt(0) == ST_DUPLICATE_OBJECTID)
            .expect(sdb.parked.keys() == Set(0))
            // DENIED: a replay of a LEASED parked open with no lease context
            .then(runM(oneRp(1, 1, createDurQ("a", DispOpenIf, ACCESS_RW,
                                              SHARE_RWD, OrNone, true, 1))))
            .expect(stAt(0) == ST_ACCESS_DENIED)
            .expect(sdb.parked.keys() == Set(0))
            // DENIED: the right kind, the WRONG lease key
            .then(runM(oneRp(1, 1, createDurQ("a", DispOpenIf, ACCESS_RW,
                                              SHARE_RWD,
                                              OrLease({ key: 2, r: true,
                                                        w: true, h: true,
                                                        v2: true, epoch: 1 }),
                                              true, 1))))
            .expect(stAt(0) == ST_ACCESS_DENIED)
            .expect(sdb.parked.keys() == Set(0))
            // RECLAIM: the matching replay takes it, with the ORIGINAL FileId
            .then(runM(oneRp(1, 1, createDurQ("a", DispOpenIf, ACCESS_RW,
                                              SHARE_RWD,
                                              OrLease({ key: 1, r: true,
                                                        w: true, h: true,
                                                        v2: true, epoch: 1 }),
                                              true, 1))))
            .expect(stAt(0) == ST_SUCCESS)
            .expect(asCreate(resAt(0)).fid == 0)
            // unlike a DH2C reclaim, a REPLAY-driven one DOES carry a durable
            // response context (R4 against durable probe D3)
            .expect(asCreate(resAt(0)).durable)
            .expect(sdb.parked.keys() == Set())

}

// A SECOND instance of the same model with durable handles NOT advertised.
//
// It exists because `caps.durable` cannot be shown to be load-bearing from
// inside smb2Test: that instance pins F_DURABLE = FeatMandatory, so the
// capability is always true there and a model that stopped reading it would
// behave identically.  Measured: deleting `acc.caps.durable` from the grant
// condition leaves all 41 smb2Test checks passing and fails only here.
//
// Run as its own `quint test --main=smb2TestNoDurable` (see CMakeLists.txt).
module smb2TestNoDurable {
    import nfs4fs.* from "../nfs/nfs4_fs"
    import smb2state.* from "./smb2_state"
    import smb2ops.* from "./smb2_ops"
    import smb2(
        DIALECT = 0x0311,
        F_OPLOCKS = FeatMandatory,
        F_LEASES = FeatMandatory,
        F_DIRLEASE = FeatMandatory,
        F_DURABLE = FeatOff,
        P_LEASE_OPEN_BREAK = true,
        P_FORCE_LEVEL2 = false
    ).* from "./smb2"

    def lastResults: List[Res] =
        match lastOp {
            | LMsg(l) => l.results
            | LInit(_) => []
        }

    def resAt(i: int): Res = lastResults[i]
    def stAt(i: int): int = stOf(resAt(i))

    val noCreate: { st: int, fid: FileId, act: int, ino: Ino,
                    caching: Caching, breaks: Set[BreakNote],
                    parked: bool, durable: bool } =
        { st: -1, fid: -1, act: -1, ino: -1, caching: CNone,
          breaks: Set(), parked: false, durable: false }
    def asCreate(r) =
        match r { | RCreate(x) => x | _ => noCreate }

    // With durable handles not advertised, the request that WOULD have been
    // granted under smb2Test (a DH2Q behind a BATCH oplock -- probe D1) takes
    // no durable handle, nothing can park, and a reconnect finds nothing.
    run noDurableGrantTest =
        init
            .then(runM({ sess: -1, tree: -1, related: false, cs: 0, replay: false,
                         cmds: [ CSessionSetup({ clientSym: 1 }) ] }))
            .then(runM(one(0, -1, CTreeConnect({ share: 1 }))))
            .then(runM(one(0, 0,
                CCreate({ dir: ROOT, name: "a", disp: DispCreate,
                          access: ACCESS_RW, share: SHARE_RWD, isDir: false,
                          delOnClose: false, oplock: OrBatch,
                          durable: DurQ({ v2: true, guid: 1,
                                          persistent: false }) }))))
            .expect(stAt(0) == ST_SUCCESS)
            .expect(not(asCreate(resAt(0)).durable))
            .expect(asCreate(resAt(0)).caching == COplock(OpBatch))
            // The drop closes it: nothing survives.
            .then(runM(one(0, -1, CDisconnect)))
            .expect(sdb.parked.keys() == Set())
            .expect(durableRespected)

    // The whole durable step distribution, with the capability off: no grant
    // may appear anywhere along the walk.
    run noDurableWalkTest =
        init.then(60.reps(_ => all { inv, durableRespected, stepDurable }))
}

// A THIRD instance, with LEASES not advertised.
//
// It exists for the same reason smb2TestNoDurable does: `caps.leases` cannot
// be shown to be load-bearing from inside smb2Test, which pins
// F_LEASES = FeatMandatory.  The rule under test is the lease-key-to-file
// binding (MS-SMB2 3.3.5.9.8).  The model used to enforce it whenever a
// request merely CARRIED an RqLs context, which made a server that does no
// leasing at all answer STATUS_INVALID_PARAMETER for a rebound key -- while a
// real one (Samba with `leases = no`) ignores the context outright, as the
// spec allows.  Deleting `acc.caps.leases` from that condition leaves every
// smb2Test check passing and fails only here (samba conformance suite, SD-6).
//
// Run as its own `quint test --main=smb2TestNoLease` (see CMakeLists.txt).
module smb2TestNoLease {
    import nfs4fs.* from "../nfs/nfs4_fs"
    import smb2state.* from "./smb2_state"
    import smb2ops.* from "./smb2_ops"
    import smb2(
        DIALECT = 0x0311,
        F_OPLOCKS = FeatOff,
        F_LEASES = FeatOff,
        F_DIRLEASE = FeatOff,
        F_DURABLE = FeatOff,
        P_LEASE_OPEN_BREAK = true,
        P_FORCE_LEVEL2 = false
    ).* from "./smb2"

    def lastResults: List[Res] =
        match lastOp {
            | LMsg(l) => l.results
            | LInit(_) => []
        }

    def resAt(i: int): Res = lastResults[i]
    def stAt(i: int): int = stOf(resAt(i))

    val noCreate: { st: int, fid: FileId, act: int, ino: Ino,
                    caching: Caching, breaks: Set[BreakNote],
                    parked: bool, durable: bool } =
        { st: -1, fid: -1, act: -1, ino: -1, caching: CNone,
          breaks: Set(), parked: false, durable: false }
    def asCreate(r) =
        match r { | RCreate(x) => x | _ => noCreate }

    def leaseReq(k: int): OplockReq =
        OrLease({ key: k, r: true, w: false, h: true, v2: false, epoch: 0 })

    def createL(n: Name, d: Disposition, o: OplockReq): Cmd =
        CCreate({ dir: ROOT, name: n, disp: d, access: ACCESS_RW,
                  share: SHARE_RWD, isDir: false, delOnClose: false,
                  oplock: o, durable: DurNone })

    // The bare-RqLs reply: leasing is off, so the request is answered with a
    // lease that caches NOTHING rather than with a grant.
    def bareRqLs(c: Caching, k: int): bool =
        match c {
            | CLease(l) => l.key == k and l.st == BITS_NONE
            | _ => false
        }

    // One lease key, two different files, one session.  With leasing
    // advertised this is STATUS_INVALID_PARAMETER (MS-SMB2 3.3.5.9.8); with
    // leasing off the binding rule does not apply at all, so both opens
    // succeed and each is answered with the bare, cacheless RqLs reply.
    run noLeaseKeyBindingTest =
        init
            .then(runM({ sess: -1, tree: -1, related: false, cs: 0,
                         replay: false,
                         cmds: [ CSessionSetup({ clientSym: 1 }) ] }))
            .then(runM(one(0, -1, CTreeConnect({ share: 1 }))))
            .then(runM(one(0, 0, createL("a", DispCreate, leaseReq(1)))))
            .expect(stAt(0) == ST_SUCCESS)
            .expect(bareRqLs(asCreate(resAt(0)).caching, 1))
            // the SAME key on a DIFFERENT file
            .then(runM(one(0, 0, createL("b", DispCreate, leaseReq(1)))))
            .expect(stAt(0) == ST_SUCCESS)
            .expect(bareRqLs(asCreate(resAt(0)).caching, 1))

    // The whole request-matrix walk with caching off: no grant may appear.
    run noLeaseWalkTest =
        init.then(60.reps(_ => all { inv, stepReq }))
}
