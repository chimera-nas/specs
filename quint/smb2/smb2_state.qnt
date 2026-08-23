// SPDX-FileCopyrightText: 2026 The Quint Specs Authors
//
// SPDX-License-Identifier: MIT

// SMB2/3 protocol state model: sessions, tree connects, opens (handles),
// share reservations, the unified oplock/lease caching grant, byte-range
// locks and delete-on-close.
//
// Like nfs4_state.qnt this module is pure: every function maps a StateDB
// (plus arguments) to a new StateDB and an abstract outcome; the compound
// evaluator in smb2_ops.qnt maps outcomes to NTSTATUS codes and wire
// shapes.  Keeping it pure lets smb2Test.qnt unit-test the share-conflict
// and oplock/lease-break rules without a model in the loop.
//
// The filesystem core is the SAME module the NFSv4 model uses
// (nfs4_fs.qnt): SMB share modes, oplocks/leases and byte-range locks are
// `protocol = SMB2` entries in the very state object NFSv4 OPEN share/deny,
// delegations and NLM locks drive (survey Seam 1/2).  That shared substrate
// is the whole reason the SMB model lives beside the NFS one.
//
// Conventions:
//  - Model handles (SessionId, TreeId, FileId, LeaseKey) are small ints;
//    the harness learns the wire values (SessionId, TreeId, the opaque
//    (persistent,volatile) FileId, the 16-byte lease key) from replies.
//  - Share access is stored as the DENIED set (the complement of SMB2
//    ShareAccess), so `shareConflict` is symmetric with the NFSv4 deny
//    check: a proposed access intersecting an existing open's deny, or a
//    proposed deny intersecting an existing open's access, is a violation.
//  - Byte-range locks use a per-byte map over a small lock space, exactly
//    as nfs4state.LockState.bytes, so overlap/exact-unlock are exact by
//    construction.  SMB locks are mandatory (enforced against READ/WRITE);
//    the `mandatory` flag records that, the PROPERTY-3c adjudication point.

module smb2state {

    import nfs4fs.* from "../nfs/nfs4_fs"

    type SessionId = int
    type TreeId = int
    type FileId = int
    type LeaseKey = int

    // ------------------------------------------------------------------
    // Caching grants (oplocks + leases, unified)
    // ------------------------------------------------------------------

    // Legacy oplock levels (MS-SMB2 2.2.14 SMB2_OPLOCK_LEVEL_*).
    type OplockLevel = OpNone | OpLevelII | OpExclusive | OpBatch

    // RWH lease caching bits (MS-SMB2 2.2.13 lease state):
    //   r = SMB2_LEASE_READ_CACHING, w = WRITE_CACHING, h = HANDLE_CACHING.
    type LeaseState = { r: bool, w: bool, h: bool }

    // One caching grant.  Legacy oplocks and RqLs leases are ONE list in
    // the VFS (caching_leases); the model unifies them as a caching grant
    // with a level, exactly as nfs4state models a delegation.  A keyless
    // COplock carries a level; a keyed CLease carries RWH bits + epoch.
    //
    // `v2` distinguishes an RqLs v2 (52-byte, epoch-versioned) lease from a v1
    // (32-byte) one: only a v2 lease versions its state, so a v1 lease is
    // granted and broken with epoch 0 (smb_proc_create.c `grant->is_v2`,
    // smb_proc_oplock_break.c "a v1 lease breaks with epoch 0"; pinned by the
    // ground-truth probe section O9).
    type Caching =
        | CNone
        | COplock(OplockLevel)
        | CLease({ key: LeaseKey, st: LeaseState, epoch: int, v2: bool })

    // ------------------------------------------------------------------
    // Caching-bit algebra
    // ------------------------------------------------------------------

    pure val BITS_NONE: LeaseState = { r: false, w: false, h: false }
    pure val BITS_R: LeaseState    = { r: true,  w: false, h: false }
    pure val BITS_W: LeaseState    = { r: false, w: true,  h: false }
    pure val BITS_H: LeaseState    = { r: false, w: false, h: true }
    pure val BITS_RH: LeaseState   = { r: true,  w: false, h: true }
    pure val BITS_RW: LeaseState   = { r: true,  w: true,  h: false }
    pure val BITS_RWH: LeaseState  = { r: true,  w: true,  h: true }

    pure def bitsAnd(a: LeaseState, b: LeaseState): LeaseState =
        { r: a.r and b.r, w: a.w and b.w, h: a.h and b.h }

    pure def bitsEmpty(a: LeaseState): bool =
        not(a.r) and not(a.w) and not(a.h)

    pure def bitsEq(a: LeaseState, b: LeaseState): bool =
        a.r == b.r and a.w == b.w and a.h == b.h

    // b is a subset of a (every bit set in b is set in a).
    pure def bitsSubset(b: LeaseState, a: LeaseState): bool =
        (a.r or not(b.r)) and (a.w or not(b.w)) and (a.h or not(b.h))

    // The caching bits a grant currently confers.  A legacy oplock maps onto
    // the same R/W/H axes the VFS uses for leases (smb_internal.h:139:
    // RWH -> BATCH, RW -> EXCLUSIVE, R -> LEVEL_II, none -> NONE), which is why
    // one break rule serves both.
    pure def cachBits(c: Caching): LeaseState =
        match c {
            | CNone => BITS_NONE
            | COplock(l) =>
                match l {
                    | OpNone => BITS_NONE
                    | OpLevelII => BITS_R
                    | OpExclusive => BITS_RW
                    | OpBatch => BITS_RWH
                }
            | CLease(x) => x.st
        }

    pure def oplockOfBits(b: LeaseState): OplockLevel =
        if (b.w and b.h) OpBatch
        else if (b.w) OpExclusive
        else if (b.r) OpLevelII
        else OpNone

    // Wire OplockLevel byte (MS-SMB2 2.2.14) for a level, so a break
    // notification's predicted level can be compared byte-for-byte.
    pure def oplockWire(l: OplockLevel): int =
        match l {
            | OpNone => 0x00
            | OpLevelII => 0x01
            | OpExclusive => 0x08
            | OpBatch => 0x09
        }

    // Wire lease-state bits (smb2.h:867: R=0x01, H=0x02, W=0x04).
    pure def leaseWire(b: LeaseState): int =
        (if (b.r) 1 else 0) + (if (b.h) 2 else 0) + (if (b.w) 4 else 0)

    // Replace a grant's caching bits, keeping its kind, key and epoch.
    pure def withBits(c: Caching, b: LeaseState): Caching =
        match c {
            | CNone => CNone
            | COplock(_) => COplock(oplockOfBits(b))
            | CLease(x) => CLease({ key: x.key, st: b, epoch: x.epoch,
                                    v2: x.v2 })
        }

    // Advance the epoch of a v2 lease (once per break EVENT).  A v1 lease and
    // a legacy oplock are not versioned.
    pure def bumpEpoch(c: Caching): Caching =
        match c {
            | CLease(x) =>
                if (x.v2) CLease({ key: x.key, st: x.st, epoch: x.epoch + 1,
                                   v2: true })
                else c
            | _ => c
        }

    pure def isLeaseGrant(c: Caching): bool =
        match c { | CLease(_) => true | _ => false }

    pure def leaseKeyOf(c: Caching): LeaseKey =
        match c { | CLease(x) => x.key | _ => -1 }

    // ------------------------------------------------------------------
    // Sessions, trees, opens
    // ------------------------------------------------------------------

    // ~ nfs4state Client.  Auth is a null/guest path (crypto out of scope);
    // the model exercises session lifecycle that matters for handle
    // ownership: new / logoff.
    // `clientTag` is the identity that goes on the WIRE as the ClientGuid, and
    // it is NOT the same thing as `client`.  The replayer opens one connection
    // per SESSION_SETUP and seeds each connection's ClientGuid from its own
    // index, so two sessions drawn with the same `client` symbol are still two
    // distinct clients to the server.  A durable RECONNECT is the one place
    // where that distinction becomes load-bearing (a leased reclaim compares
    // ClientGuids -- MS-SMB2 3.3.5.9.7), so the model tracks the wire identity
    // explicitly: a fresh session gets its own tag, and a session established
    // by a reconnect INHERITS its predecessor's.
    type Session = { client: int, clientTag: int, valid: bool }

    type Tree = { session: SessionId, share: int }

    // R/W/D access triple used for share arbitration.  H (handle caching)
    // and the full DesiredAccess mask are not conflict-bearing, so the
    // conflict axes are exactly read/write/delete.
    type Access = { r: bool, w: bool, d: bool }

    // One open handle.  The SMB analogue of nfs4state.OpenState, keyed by an
    // opaque FileId rather than an (owner,file) stateid, and carrying the
    // SMB-only bits (H caching, delete share, delete-on-close, the caching
    // grant this handle holds and its break progress).
    type Open = {
        session: SessionId,
        tree: TreeId,
        file: Ino,
        // the (dir,name) this handle was opened under, so delete-on-close
        // can unlink the exact name (the harness's Ino->path binding).
        dir: Ino,
        name: Name,
        // granted DesiredAccess as R/W/H/D bits; denied as the complement
        // of ShareAccess over R/W/D.  Both land in one VFS SHARE entry.
        granted: { r: bool, w: bool, h: bool, d: bool },
        denied: Access,
        caching: Caching,
        // An ACK-REQUIRED break notification was sent for this grant and is not
        // yet acknowledged.  A break that strips only READ caching (or that
        // hits a LEVEL_II oplock) needs no ack and settles the instant it is
        // sent, so it never sets this flag -- acking such a break is a protocol
        // error, not a no-op (smb_proc_oplock_break.c, probe O8).
        // breakTo is the grant the break asked the holder to retain: the
        // `break_needed_mode` an acknowledgment may not exceed.
        breaking: bool,
        breakTo: Caching,
        deleteOnClose: bool,
        // The durable-handle grant this open holds, if any (MS-SMB2
        // 3.3.5.9.6 / 3.3.5.9.10).  `on` is the grant; `v2` distinguishes the
        // DH2Q form (identified by a CreateGuid) from the DHnQ form (no guid,
        // reconnected by persistent id alone); `guid` is the DH2Q CreateGuid,
        // -1 for v1.  `persistent` is reserved for a continuously-available
        // share and is never set by the modeled surface -- see the note on
        // Parked.
        durable: DurState,
        // ---- the exactly-once layer (MS-SMB2 3.3.5.2.10 / 3.3.5.9.10) ----
        // `cs` is the highest ChannelSequence this Open has accepted.  It is
        // SEEDED BY ITS OWN CREATE, not started at zero -- an Open created at
        // ChannelSequence 0x0100 already treats 0 as stale (probe R11) -- and
        // it is advanced by every ACCEPTED request, reads included (probe R7).
        cs: int,
        // A create carrying a DH2Q context is REPLAY-ELIGIBLE: a replay of it
        // is answered from this handle rather than re-executed.  Eligibility
        // comes from the CONTEXT, not from the durable GRANT (probe R2: a
        // create refused durability for want of a caching oplock is still
        // replayable), and it is ONE OPERATION WIDE -- the first non-replay
        // request that resolves the handle clears it, whatever that request's
        // own status turns out to be (chimera_smb_open_file_resolve).
        // `replayGuid` is the CreateGuid to match on; `replayAct` is the
        // CreateAction the ORIGINAL create reported, which the replay echoes
        // (probe R3c -- the evidence the create was not re-evaluated).
        replayOk: bool,
        replayGuid: int,
        replayAct: int
    }

    // A durable grant as it sits on an open handle.
    type DurState = { on: bool, v2: bool, guid: int, persistent: bool }

    pure val DUR_NONE: DurState =
        { on: false, v2: false, guid: -1, persistent: false }

    // A durable open that OUTLIVED its connection (MS-SMB2 3.3.7.1): the
    // transport dropped, the handle was not closed, and it waits to be
    // reclaimed by a DH2C / DHnC reconnect.  It is deliberately NOT in
    // sdb.opens: a parked handle takes no part in share arbitration, holds no
    // lease anyone can break, and is purged outright by any open that would
    // have had to break it (probe D7 / D7b) -- so leaving it in the live map
    // would make it conflict with openers the server lets through.
    //
    // `owner` is the ClientGuid tag (Session.clientTag) of the client that owns
    // it; `hadLease` and `leaseKey` record whether the surviving handle held an
    // RqLs lease, because the ClientGuid / lease-key / file-name reconnect
    // checks of 3.3.5.9.7 apply ONLY to a leased handle.
    //
    // Persistent (continuously-available) handles are NOT modeled: their parked
    // holder BLOCKS a conflicting opener with STATUS_FILE_NOT_AVAILABLE instead
    // of yielding (probe D11), and continuous availability is a share property
    // no generated instance turns on.  `persistent` is carried so the
    // INVALID_PARAMETER arm of a persistent reconnect against a non-persistent
    // handle stays reachable (probe D4g).
    type Parked = {
        open: Open,
        v2: bool,
        guid: int,
        persistent: bool,
        owner: int,
        hadLease: bool,
        leaseKey: LeaseKey,
        dir: Ino,
        name: Name
    }

    // One break notification as it appears on the wire, so the replayer can
    // assert the notification the server actually pushed rather than merely
    // that "a break happened".  Levels/states are the wire encodings.
    type BreakNote = {
        fid: FileId,          // the model handle the notification names
        isLease: bool,        // LEASE_BREAK (SS=44) vs OPLOCK_BREAK (SS=24)
        key: LeaseKey,
        curState: int,        // CurrentLeaseState (wire bits)
        newState: int,        // NewLeaseState (wire bits)
        newLevel: int,        // legacy break: the level to break down to
        ackReq: bool,
        epoch: int
    }

    // One byte-range lock, exactly as SMB keeps it: an ENTRY on the owning
    // handle's list with its own (offset,length).  It is deliberately NOT a
    // per-byte map any more.  SMB byte-range locks do not coalesce and do not
    // split: MS-FSA 2.1.5.8 unlocks by matching an EXACT (LockOffset,
    // LockLength) pair, and a handle may STACK several shared locks over the
    // same range, each of which needs its own unlock.  A per-byte map cannot
    // express either fact -- it accepted an unlock of any sub- or super-range
    // whose bytes the handle happened to own, and it collapsed a stack of
    // shared locks into one byte.  (DEVIATIONS-SMB.md M-17.)
    type RangeLock = { file: Ino, lo: int, hi: int, wr: bool, owner: FileId }

    type StateDB = {
        fs: Fs,
        sessions: SessionId -> Session,
        trees: TreeId -> Tree,
        opens: FileId -> Open,
        nextSess: int,
        nextTree: int,
        nextFile: int,
        // Byte-range locks, in grant order.  A LIST rather than a byte map
        // because the unlock rule and the stacking rule are both about
        // ENTRIES, not about bytes -- see RangeLock above.
        rangeLocks: List[RangeLock],
        // inodes with a delete pending (a delete-on-close handle exists or
        // SetDisposition(delete) was issued): a new CREATE observing this
        // returns STATUS_DELETE_PENDING (MS-FSA 2.1.5.1.1).
        deletePending: Set[Ino],
        // durable opens that survived their connection, keyed by the FileId
        // they keep across the reclaim (MS-SMB2 3.3.7.1).  Disjoint from
        // `opens` by construction: a handle is live or parked, never both.
        parked: FileId -> Parked
    }

    pure def stInit(rootMode: int): StateDB = {
        fs: fsInit(rootMode),
        sessions: Map(),
        trees: Map(),
        opens: Map(),
        nextSess: 0,
        nextTree: 0,
        nextFile: 0,
        rangeLocks: List(),
        deletePending: Set(),
        parked: Map()
    }

    pure def smapDrop(m, k) = m.keys().exclude(Set(k)).mapBy(x => m.get(x))

    // ------------------------------------------------------------------
    // Session / tree lifecycle
    // ------------------------------------------------------------------

    // SESSION_SETUP: establish a session for a client symbol (MS-SMB2
    // 3.3.5.5; the null/guest auth path).  Returns the new session id.
    //
    // `clientTag` defaults to the new session id -- one connection, one client
    // -- which is exactly what the replayer puts on the wire.  A reconnect
    // passes the predecessor's tag instead (doReconnect).
    pure def doSessionSetupAs(sdb: StateDB, clientSym: int, tag: int):
            { sdb2: StateDB, sess: SessionId } = {
        val s = sdb.nextSess
        val t = if (tag < 0) s else tag
        { sdb2: sdb
              .with("sessions", sdb.sessions.put(s, { client: clientSym,
                                                      clientTag: t,
                                                      valid: true }))
              .with("nextSess", s + 1),
          sess: s }
    }

    pure def doSessionSetup(sdb: StateDB, clientSym: int):
            { sdb2: StateDB, sess: SessionId } =
        doSessionSetupAs(sdb, clientSym, -1)

    // LOGOFF (MS-SMB2 3.3.5.6): the session's trees and opens go away; the
    // handles' caching grants and locks are released with them.
    pure def doLogoff(sdb: StateDB, sess: SessionId): StateDB = {
        val deadTrees = sdb.trees.keys().filter(t =>
            sdb.trees.get(t).session == sess)
        val deadOpens = sdb.opens.keys().filter(f =>
            sdb.opens.get(f).session == sess)
        deadOpens.fold(sdb, (acc, f) => doCloseRaw(acc, f))
           .with("trees", sdb.trees.keys().exclude(deadTrees)
                 .mapBy(t => sdb.trees.get(t)))
           .with("sessions", smapDrop(sdb.sessions, sess))
    }

    // TREE_CONNECT (MS-SMB2 3.3.5.7): bind a share to a session.
    pure def doTreeConnect(sdb: StateDB, sess: SessionId, share: int):
            { sdb2: StateDB, tree: TreeId } = {
        val t = sdb.nextTree
        { sdb2: sdb
              .with("trees", sdb.trees.put(t, { session: sess, share: share }))
              .with("nextTree", t + 1),
          tree: t }
    }

    pure def doTreeDisconnect(sdb: StateDB, tree: TreeId): StateDB = {
        val deadOpens = sdb.opens.keys().filter(f =>
            sdb.opens.get(f).tree == tree)
        deadOpens.fold(sdb, (acc, f) => doCloseRaw(acc, f))
           .with("trees", smapDrop(sdb.trees, tree))
    }

    // ------------------------------------------------------------------
    // Share reservations (MS-FSA 2.1.4.1 SharingViolation)
    // ------------------------------------------------------------------

    pure def accItsc(a: Access, b: Access): bool =
        (a.r and b.r) or (a.w and b.w) or (a.d and b.d)

    // The empty access/deny set: the share-mode footprint of an
    // attribute-only open (chimera's inert granted=0, denied=0 SHARE entry).
    pure val ACC_NONE: Access = { r: false, w: false, d: false }

    // Granted DesiredAccess projected onto the conflict axes.
    pure def grantedAcc(o: Open): Access =
        { r: o.granted.r, w: o.granted.w, d: o.granted.d }

    // A proposed open (desired access `want`, denied set `deny`) conflicts
    // with an existing open iff its access intersects that open's deny, or
    // its deny intersects that open's access (MS-FSA 2.1.4.1; the symmetric
    // share-reservation check, identical in shape to NFSv4 shareConflict).
    // Attribute-only opens (no r/w/d) never conflict.
    pure def shareConflict(sdb: StateDB, f: Ino, want: Access,
                           deny: Access): bool =
        sdb.opens.keys().exists(fid => {
            val o = sdb.opens.get(fid)
            o.file == f and
            (accItsc(want, o.denied) or accItsc(deny, grantedAcc(o)))
        })

    // The set of opens of file f (any session).
    pure def opensOfFile(sdb: StateDB, f: Ino): Set[FileId] =
        sdb.opens.keys().filter(fid => sdb.opens.get(fid).file == f)

    // Every inode currently pinned by an open handle.  A namespace op that
    // would unlink such an inode orphans it instead (unlink-while-open),
    // exactly as NFSv4 pins open files against REMOVE/RENAME.
    // A PARKED durable handle still holds its file open on the server, so it
    // pins the inode exactly as a live handle does.
    pure def pinnedFiles(sdb: StateDB): Set[Ino] =
        sdb.opens.keys().map(fid => sdb.opens.get(fid).file)
            .union(sdb.parked.keys().map(fid => sdb.parked.get(fid).open.file))

    // ------------------------------------------------------------------
    // Opens
    // ------------------------------------------------------------------

    // Install a new open handle over file f (the share check has already
    // passed).  Returns the fresh FileId.  Caching is set separately by the
    // grant step so the CREATE handler controls oplock/lease policy.
    pure def doInsertOpen(sdb: StateDB, sess: SessionId, tree: TreeId,
                          f: Ino, dir: Ino, name: Name,
                          granted: { r: bool, w: bool, h: bool, d: bool },
                          deny: Access, delOnClose: bool, cs: int):
            { sdb2: StateDB, fid: FileId } = {
        val fid = sdb.nextFile
        { sdb2: sdb
              .with("opens", sdb.opens.put(fid, {
                  session: sess, tree: tree, file: f, dir: dir, name: name,
                  granted: granted, denied: deny, caching: CNone,
                  breaking: false, breakTo: CNone,
                  deleteOnClose: delOnClose, durable: DUR_NONE,
                  // The CREATE's own ChannelSequence seeds the handle
                  // (probe R11).  Replay eligibility is set by the CREATE
                  // handler afterwards, only when a DH2Q context was present.
                  cs: cs, replayOk: false, replayGuid: -1, replayAct: -1 }))
              .with("nextFile", fid + 1),
          fid: fid }
    }

    // ------------------------------------------------------------------
    // Exactly-once: the ChannelSequence window (MS-SMB2 3.3.5.2.10)
    // ------------------------------------------------------------------
    //
    // Ground truth for every rule here is smb2_replay_probe.c sections R6-R11.
    // The comparison is MODULAR over 16 bits, and that is not a detail: probe
    // R10 shows both of its counter-intuitive consequences -- a single forward
    // jump of more than +0x7FFF is refused as if it went backwards, and
    // ChannelSequence 0 is a FORWARD jump from any mark in the upper half, so
    // an ordinary request that never sets the field RESETS the mark.

    pure val CS_MOD: int = 65536
    pure val CS_HALF: int = 32768

    // How far `reqCs` is AHEAD of `openCs`, modulo 2^16.
    pure def csDelta(reqCs: int, openCs: int): int =
        (reqCs - openCs + CS_MOD) % CS_MOD

    // Is this request from a SUPERSEDED channel?  delta in [0x8000, 0xFFFF].
    pure def csStale(sdb: StateDB, fid: FileId, reqCs: int): bool =
        csDelta(reqCs, sdb.opens.get(fid).cs) >= CS_HALF

    // Record a new high-water mark.  Called ONLY on the accept path: a
    // rejected request leaves the mark exactly where it was (probe R6/3).
    pure def doAdvanceCs(sdb: StateDB, fid: FileId, reqCs: int): StateDB =
        sdb.with("opens", sdb.opens.setBy(fid, o => o.with("cs", reqCs)))

    // ------------------------------------------------------------------
    // Exactly-once: the CREATE reply cache (MS-SMB2 3.3.5.9.10)
    // ------------------------------------------------------------------

    // Mark a freshly created handle replay-eligible under `guid`, remembering
    // the CreateAction the reply reported.
    pure def doSetReplayable(sdb: StateDB, fid: FileId, guid: int,
                             act: int): StateDB =
        sdb.with("opens", sdb.opens.setBy(fid, o =>
            o.with("replayOk", true).with("replayGuid", guid)
             .with("replayAct", act)))

    // A non-replay request resolved this handle: the window closes.
    pure def doClearReplayable(sdb: StateDB, fid: FileId): StateDB =
        if (not(sdb.opens.keys().contains(fid))) sdb
        else sdb.with("opens", sdb.opens.setBy(fid, o =>
                 o.with("replayOk", false)))

    // The LIVE, still-eligible open of this TREE carrying `guid`, if any.
    // Scoped to the tree because chimera scans tree->open_files
    // (chimera_smb_create_guid_replay); the parked registry below is scoped to
    // the CLIENT instead, and the two scopes really do differ.
    pure def replayLiveMatch(sdb: StateDB, tree: TreeId, guid: int):
            Set[FileId] =
        sdb.opens.keys().filter(f => {
            val o = sdb.opens.get(f)
            o.tree == tree and o.replayOk and o.replayGuid == guid
        })

    // The PARKED handle of this client carrying `guid`, if any.
    pure def replayParkedMatch(sdb: StateDB, tag: int, guid: int):
            Set[FileId] =
        sdb.parked.keys().filter(k => {
            val p = sdb.parked.get(k)
            p.v2 and p.guid == guid and p.owner == tag
        })

    // Drop an open and everything pinned to it: its byte-range locks and,
    // if it was the last opener, a delete-pending reap.  Does NOT run the
    // delete-on-close unlink -- doClose does that first, then calls this.
    pure def doCloseRaw(sdb: StateDB, fid: FileId): StateDB = {
        val keptLocks = sdb.rangeLocks.select(e => e.owner != fid)
        sdb.with("opens", smapDrop(sdb.opens, fid))
           .with("rangeLocks", keptLocks)
    }

    // CLOSE (MS-SMB2 3.3.5.10 + MS-FSA 2.1.5.4): release the handle.  SMB
    // delete-on-close deletes at the LAST close when the file is
    // delete-pending (MS-FSA 2.1.5.4: the directory entry persists until the
    // final handle drops), so no pinned-orphan intermediate arises -- unlike
    // NFSv4 REMOVE-of-open which orphans immediately.  The one orphan source
    // is a RENAME that replaced a still-open target (fsRename orphans it);
    // that nlink-0 inode is reaped when its own last handle closes.
    pure def doClose(sdb: StateDB, fid: FileId):
            { sdb2: StateDB, gone: Ino } = {
        val o = sdb.opens.get(fid)
        val isLast = opensOfFile(sdb, o.file).exclude(Set(fid)).size() == 0
        if (isLast and sdb.deletePending.contains(o.file) and
            fsHasEnt(sdb.fs, o.dir, o.name) and
            fsChild(sdb.fs, o.dir, o.name) == o.file) {
            // last close of a delete-pending file: unlink now (no pins left).
            val rm = fsRemove(sdb.fs, o.dir, o.name, Set())
            val sdb1 = sdb.with("fs", rm.fs2)
                          .with("deletePending",
                                sdb.deletePending.exclude(Set(o.file)))
            { sdb2: doCloseRaw(sdb1, fid), gone: rm.gone }
        } else if (isLast and fsLive(sdb.fs, o.file) and
                   fsGet(sdb.fs, o.file).nlink == 0) {
            // reap a rename-orphaned inode once its last handle drops.
            val sdb1 = sdb.with("fs", fsReap(sdb.fs, o.file))
                          .with("deletePending",
                                sdb.deletePending.exclude(Set(o.file)))
            { sdb2: doCloseRaw(sdb1, fid), gone: o.file }
        } else {
            { sdb2: doCloseRaw(sdb, fid), gone: -1 }
        }
    }

    // SetDisposition (MS-FSA 2.1.5.14.2 SetFileDispositionInformation):
    // arm or disarm delete-on-close on a handle and mark/unmark the inode
    // delete-pending.
    pure def doSetDisposition(sdb: StateDB, fid: FileId, del: bool): StateDB = {
        val o = sdb.opens.get(fid)
        sdb.with("opens", sdb.opens.setBy(fid, x =>
                x.with("deleteOnClose", del)))
           .with("deletePending",
                 if (del) sdb.deletePending.union(Set(o.file))
                 else sdb.deletePending.exclude(Set(o.file)))
    }

    // ------------------------------------------------------------------
    // Oplock / lease caching grants and the break lifecycle
    // ------------------------------------------------------------------

    // Set (or replace) the caching grant on a handle.
    pure def doSetCaching(sdb: StateDB, fid: FileId, c: Caching): StateDB =
        sdb.with("opens", sdb.opens.setBy(fid, o => o.with("caching", c)))

    pure def cachingLevelNone(c: Caching): bool = bitsEmpty(cachBits(c))

    // The level a grant CONFERS right now.  A grant with an ack-required break
    // outstanding is treated by the conflict matrix as already sitting at its
    // retained level ("the conflict matrix treats a BREAKING SMB lease as
    // already at its retained (break_needed_mode) level, so a coexisting
    // acquirer proceeds immediately without waiting for the ack" --
    // smb_proc_oplock_break.c), so a second conflicting op neither re-breaks it
    // nor waits on it.
    pure def effCaching(o: Open): Caching =
        if (o.breaking) o.breakTo else o.caching

    // Does a break that leaves `nb` require the holder to acknowledge?
    //   - legacy oplock: only an EXCLUSIVE/BATCH holder acks; a LEVEL_II break
    //     is unsolicited-and-final, and a client ack for it is a protocol
    //     error (MS-SMB2 3.3.5.22.1).
    //   - RqLs lease: only a break that strips WRITE or HANDLE caching; losing
    //     read caching alone settles immediately.
    // (smb_proc_oplock_break.c chimera_smb_lease_break_cb; probe O8.)
    pure def breakNeedsAck(c: Caching, nb: LeaseState): bool =
        match c {
            | CNone => false
            | COplock(l) => l == OpExclusive or l == OpBatch
            | CLease(x) => (x.st.w and not(nb.w)) or (x.st.h and not(nb.h))
        }

    // Two opens share ONE caching grant when they are RqLs leases under the
    // same lease key (MS-SMB2 3.3.5.9.8; probe O7): they coalesce, so they
    // break once and settle together.  A legacy oplock is keyed by file id and
    // is therefore always a sole member.
    // The grant is owned by (client, lease key): chimera derives the client
    // half from the connection's ClientGuid (chimera_smb_lease_client_key), so
    // two DIFFERENT clients using the same lease key own two grants and
    // arbitrate normally.  The model's session stands in for the client, and
    // the harness gives each connection its own ClientGuid to match.
    // Is this open VISIBLE to the fresh-grant arbitration?
    //
    // An attribute-only open (DesiredAccess with no R/W/D) holds no share-mode
    // rights and registers an INERT share reservation -- granted = 0 and
    // denied = 0 (M-5, smb_proc_create.c "Attribute-only opens hold no
    // share-mode rights and impose no deny") -- and vfs_state's sole-open cap
    // skips inert entries outright ("Pure attribute-only opens take no share
    // reservation, so they do not preclude an oplock").  So such a peer caps
    // nothing on the wire: probe O12[20]-O12[25] measure a full BATCH oplock
    // and a full RWH lease handed out behind one.
    //
    // MS-FSA 2.1.5.18.1 counts Opens on the stream, not share reservations, so
    // that exemption is a chimera deviation (DEVIATIONS-SMB.md S-3) and this
    // predicate is deliberately NOT used to decide whether a WRITE cache may be
    // granted -- the model stays spec-first there and caps against every peer
    // open.  It is used only for the HANDLE-cap rule, which is a discretionary
    // (grant-LESS) choice, and by the generator's guard.
    pure def openVisibleToGrant(o: Open): bool =
        o.granted.r or o.granted.w or o.granted.d

    pure def sameGrant(a: Open, b: Open): bool =
        isLeaseGrant(a.caching) and isLeaseGrant(b.caching) and
        leaseKeyOf(a.caching) == leaseKeyOf(b.caching) and
        a.session == b.session

    // The lowest-numbered member of a coalesced grant: the one open whose
    // notification represents the whole grant, so a break of a two-open
    // coalesced lease emits ONE notification, not one per member.
    pure def isGrantRep(sdb: StateDB, f: Ino, fid: FileId): bool = {
        val o = sdb.opens.get(fid)
        not(opensOfFile(sdb, f).exists(g =>
            g < fid and sameGrant(sdb.opens.get(g), o)))
    }

    // Handles other than `self` whose grant a conflicting access must break.
    //   trigger    -- the caching bit whose presence makes a holder a target of
    //                 THIS break.  chimera passes it as break_trigger_mode:
    //                 H before the share check (only a HANDLE-caching holder
    //                 may close and dissolve the conflict), W after it (an
    //                 exclusive write cache must yield to a coexisting open),
    //                 and R|W|H for a write / truncate / namespace
    //                 invalidation.  A holder without the trigger bit is left
    //                 alone even when `retain` would strip something.
    //   retain     -- the caching bits the holder may KEEP (break_needed_mode):
    //                 R for a plain conflicting open at phase 1, R|H at phase 2,
    //                 R|W on a refused (SHARING_VIOLATION) open, 0 for a write /
    //                 truncate / namespace invalidation.
    //   spareLeases-- phase 1 breaks only NON-lease handle-caching holders (a
    //                 batch oplock); an RqLs lease keeps H across a compatible
    //                 open and is dealt with at phase 2
    //                 (smb_proc_create.c chimera_smb_create_break_for_open).
    //   selfKey    -- the opener's lease key (-1 for none): a holder under the
    //                 SAME key is the opener's own grant and is never broken.
    // A holder already mid-break is skipped (begin_break is a no-op on a lease
    // still BREAKING), as is one that would lose nothing.
    pure def breakHolders(sdb: StateDB, f: Ino, self: FileId,
                          trigger: LeaseState, retain: LeaseState,
                          spareLeases: bool,
                          selfKey: LeaseKey, selfSess: SessionId): Set[FileId] =
        opensOfFile(sdb, f).exclude(Set(self)).filter(fid => {
            val o = sdb.opens.get(fid)
            val cur = cachBits(o.caching)
            not(o.breaking) and
            not(bitsEmpty(bitsAnd(cur, trigger))) and
            not(bitsEq(bitsAnd(cur, retain), cur)) and
            not(spareLeases and isLeaseGrant(o.caching)) and
            not(selfKey >= 0 and leaseKeyOf(o.caching) == selfKey and
                o.session == selfSess)
        })

    // The notification set a break over `holders` puts on the wire (one per
    // GRANT, so coalesced same-key opens produce a single note).
    // `oplockNoAck` forces the legacy-oplock notes to report "no ack needed".
    // A TWO-STEP break of one op (a truncating open: the pre-share handle
    // recall, then break_on_write) settles a legacy oplock outright: the server
    // stamps the post-break level onto the open at the first step
    // (`open_file->oplock_level = new_level`), so the second step recomputes
    // ack_required against the ALREADY-LOWERED level and gets false, which
    // clears grant->break_ack_required and settles the lease.  An RqLs lease
    // recomputes from the grant's granted mode, which the ack has not yet
    // lowered, so it still waits.
    pure def breakNotesEx(sdb: StateDB, f: Ino, holders: Set[FileId],
                          retain: LeaseState,
                          oplockNoAck: bool): Set[BreakNote] =
        holders.filter(fid => isGrantRep(sdb, f, fid)).map(fid => {
            val o = sdb.opens.get(fid)
            val cur = cachBits(o.caching)
            val nb = bitsAnd(cur, retain)
            val bumped = bumpEpoch(o.caching)
            { fid: fid,
              isLease: isLeaseGrant(o.caching),
              key: leaseKeyOf(o.caching),
              curState: leaseWire(cur),
              newState: leaseWire(nb),
              newLevel: oplockWire(oplockOfBits(nb)),
              ackReq: breakNeedsAck(o.caching, nb) and
                      not(oplockNoAck and not(isLeaseGrant(o.caching))),
              epoch: match bumped { | CLease(x) => x.epoch | _ => 0 } }
        })

    pure def breakNotes(sdb: StateDB, f: Ino, holders: Set[FileId],
                        retain: LeaseState): Set[BreakNote] =
        breakNotesEx(sdb, f, holders, retain, false)

    // Apply a break to one holder: an ack-required break marks the grant
    // breaking and records the retained level; a no-ack break settles at once.
    pure def doBreakOne(sdb: StateDB, fid: FileId,
                        retain: LeaseState): StateDB = {
        val o = sdb.opens.get(fid)
        val cur = cachBits(o.caching)
        val nb = bitsAnd(cur, retain)
        val bumped = bumpEpoch(o.caching)
        val newc = withBits(bumped, nb)
        if (breakNeedsAck(o.caching, nb))
            sdb.with("opens", sdb.opens.setBy(fid, x => x
                  .with("caching", bumped)
                  .with("breaking", true)
                  .with("breakTo", newc)))
        else
            sdb.with("opens", sdb.opens.setBy(fid, x => x
                  .with("caching", newc)
                  .with("breaking", false)
                  .with("breakTo", CNone)))
    }

    // Emit breaks to every holder a conflicting access must recall.
    pure def doBreakAll(sdb: StateDB, f: Ino, self: FileId,
                        trigger: LeaseState, retain: LeaseState,
                        spareLeases: bool,
                        selfKey: LeaseKey, selfSess: SessionId): StateDB =
        breakHolders(sdb, f, self, trigger, retain, spareLeases, selfKey,
                     selfSess)
            .fold(sdb, (acc, fid) => doBreakOne(acc, fid, retain))

    // Is any handle other than `self` sitting on an UNACKNOWLEDGED break of
    // file f?  A CREATE whose own open has been granted parks (async interim
    // STATUS_PENDING, deferred completion) exactly while this holds --
    // chimera_vfs_state_caching_breaking, the `will_park` predicate in
    // smb_proc_create.c.
    pure def breakInProgress(sdb: StateDB, f: Ino, self: FileId): bool =
        opensOfFile(sdb, f).exclude(Set(self)).exists(fid =>
            sdb.opens.get(fid).breaking)

    // Acknowledge a break (OPLOCK_BREAK / LEASE_BREAK ack) with the caching
    // bits the holder chose to KEEP.  Every member of the (possibly coalesced)
    // grant settles together.  The caller adjudicates the error arms
    // (not-breaking, kept-not-a-subset) before calling this.
    pure def doAckBreak(sdb: StateDB, fid: FileId,
                        kept: LeaseState): StateDB = {
        val o = sdb.opens.get(fid)
        sdb.with("opens", sdb.opens.keys().mapBy(k => {
            val x = sdb.opens.get(k)
            if (k == fid or (x.file == o.file and sameGrant(x, o)))
                x.with("caching", withBits(x.caching, kept))
                 .with("breaking", false)
                 .with("breakTo", CNone)
            else x
        }))
    }

    // ------------------------------------------------------------------
    // Durable handles: grant, park, purge, reclaim
    //
    // Ground truth for every rule here is smb2_durable_probe.c, sections
    // D1-D8 (see DEVIATIONS-SMB.md C-13 ... C-22).  Nothing below is inferred
    // from the spec alone.
    // ------------------------------------------------------------------

    // Record the durable grant on a handle.
    pure def doSetDurable(sdb: StateDB, fid: FileId, d: DurState): StateDB =
        sdb.with("opens", sdb.opens.setBy(fid, o => o.with("durable", d)))

    // Does this handle's CACHING grant satisfy the durable precondition?
    //
    // MS-SMB2 3.3.5.9.6 / 3.3.5.9.10: a durable open needs a BATCH oplock or a
    // lease carrying HANDLE caching -- and the test is on what was GRANTED, not
    // on what was asked for, so a BATCH request capped to LEVEL_II behind a
    // peer open takes no durable handle.  Probe D1 measures all thirteen rows:
    // NONE, LEVEL_II and EXCLUSIVE all refuse (v1 and v2 alike); BATCH grants;
    // an R-only lease refuses; RH and RWH grant.
    pure def durableEligible(c: Caching): bool =
        match c {
            | CNone => false
            | COplock(l) => l == OpBatch
            | CLease(x) => x.st.h
        }

    // Park every open of a dropped connection's session, and close the rest
    // (MS-SMB2 3.3.7.1).  The session and its trees go away either way -- this
    // is a transport drop, not a LOGOFF, but the session state dies with the
    // connection because the model gives every session its own connection.
    //
    // A handle with no durable grant does NOT survive (probe D6): it is closed
    // exactly as doClose would close it, delete-on-close and orphan reaping
    // included.
    pure def doDisconnect(sdb: StateDB, sess: SessionId): StateDB = {
        val mine = sdb.opens.keys().filter(f => sdb.opens.get(f).session == sess)
        val dur = mine.filter(f => sdb.opens.get(f).durable.on)
        val tag = sdb.sessions.get(sess).clientTag
        // Park the durable ones first (they leave `opens` without any of
        // doClose's unlink/reap side effects -- the file stays open).
        val sdb1 = dur.fold(sdb, (a, f) => {
            val o = a.opens.get(f)
            a.with("parked", a.parked.put(f, {
                    open: o,
                    v2: o.durable.v2,
                    guid: o.durable.guid,
                    persistent: o.durable.persistent,
                    owner: tag,
                    hadLease: isLeaseGrant(o.caching),
                    leaseKey: leaseKeyOf(o.caching),
                    dir: o.dir,
                    name: o.name }))
             .with("opens", smapDrop(a.opens, f))
             .with("rangeLocks", a.rangeLocks.select(e => e.owner != f))
        })
        // Then close the rest, with full CLOSE semantics.
        val sdb2 = mine.exclude(dur).fold(sdb1, (a, f) => doClose(a, f).sdb2)
        val deadTrees = sdb2.trees.keys().filter(t =>
            sdb2.trees.get(t).session == sess)
        sdb2.with("trees", sdb2.trees.keys().exclude(deadTrees)
                  .mapBy(t => sdb2.trees.get(t)))
            .with("sessions", smapDrop(sdb2.sessions, sess))
    }

    // The parked handles on file `f`.
    pure def parkedOnFile(sdb: StateDB, f: Ino): Set[FileId] =
        sdb.parked.keys().filter(k => sdb.parked.get(k).open.file == f)

    // Does a parked handle's share reservation conflict with an incoming open?
    // Same pairwise test as shareConflict, applied to the parked handle.
    pure def parkedShareConflict(p: Parked, want: Access, deny: Access): bool =
        accItsc(grantedAcc(p.open), deny) or accItsc(want, p.open.denied)
 
    // Purge the parked handles on `f` that an incoming open DISSOLVES.
    //
    // A parked holder has nobody to acknowledge a break, so where the server
    // would have had to break it, it closes it instead and admits the opener
    // (MS-SMB2 3.3.4.6); the handle is then GONE, not merely busy, and its
    // owner's later reclaim answers OBJECT_NAME_NOT_FOUND.  Measured, and NOT
    // all-or-nothing -- probe D7/D7b/D7c/D7d/D7e/D7f separate the three
    // variables:
    //
    //   * an attribute-only, non-truncating open breaks nobody, so it purges
    //     nothing (D7b) -- the caller applies that test and does not call here;
    //   * a parked holder that owns a WRITE cache (a BATCH oplock, or a lease
    //     carrying W) is purged by ANY such open, even a fully compatible one:
    //     the caching-acquire path has to revoke the write cache and there is
    //     no one to revoke it with (D7c, D7e);
    //   * a parked holder with no write cache (an R / RH lease) is purged only
    //     when the open actually conflicts on the SHARE axes (D7f); a
    //     compatible open leaves it standing (D7d) -- and it then caps that
    //     open's grant, which is what grantCaching accounts for.
    pure def doPurgeParked(sdb: StateDB, f: Ino, want: Access,
                           deny: Access): StateDB = {
        val doomed = parkedOnFile(sdb, f).filter(k => {
            val p = sdb.parked.get(k)
            cachBits(p.open.caching).w or parkedShareConflict(p, want, deny)
        })
        sdb.with("parked", sdb.parked.keys().exclude(doomed)
                 .mapBy(k => sdb.parked.get(k)))
    }

    // Does a durable open of client `tag` already carry CreateGuid `g`?
    //
    // The registry holds every open that took a durable GRANT, live or parked
    // (a DH2Q that was refused durability is never registered and so never
    // collides), and the scan is scoped to one ClientGuid: two different
    // clients may use the same CreateGuid without colliding.  MS-SMB2
    // 3.3.5.9.10 / chimera_smb_durable_claim_by_guid.
    pure def durGuidCollision(sdb: StateDB, g: int, tag: int): bool =
        durGuidCollisionEx(sdb, g, tag, -1, false)

    // The same test, but aware of WHO is asking and whether this is a replay.
    //
    // chimera_smb_durable_claim_by_guid does not answer DUPLICATE_OBJECTID
    // unconditionally: a REPLAY that collides with a live durable open on the
    // SAME connection is "ignored" and falls through to a fresh open, because
    // that is the ineligible-replay case -- the eligibility window has closed
    // and the replay is now an ordinary create (measured: probe R13, where the
    // fall-through create then collides on the NAME with
    // STATUS_OBJECT_NAME_COLLISION, not on the guid).  A replay colliding with
    // a live open on a DIFFERENT connection of the same client, or any
    // NON-replay collision, is still DUPLICATE_OBJECTID (probe R3e, R4).
    //
    // A PARKED entry has no connection, so only the replay flag decides -- and
    // a matching replay never reaches here anyway: it was answered as a
    // RECLAIM or refused ACCESS_DENIED by the reply-cache branch above.
    pure def durGuidCollisionEx(sdb: StateDB, g: int, tag: int,
                                sess: SessionId, isReplay: bool): bool =
        sdb.opens.keys().exists(f => {
            val o = sdb.opens.get(f)
            o.durable.on and o.durable.v2 and o.durable.guid == g and
            sdb.sessions.get(o.session).clientTag == tag and
            (not(isReplay) or o.session != sess)
        }) or
        sdb.parked.keys().exists(k => {
            val p = sdb.parked.get(k)
            p.open.durable.on and p.v2 and p.guid == g and p.owner == tag and
            not(isReplay)
        })

    // Does `fid` name a LIVE handle that holds a durable grant, i.e. one that
    // still has an entry in the durable registry?  A reconnect naming such an
    // id is the "do not steal a live handle" case: it is retried behind an
    // async interim and then refused.
    pure def liveDurable(sdb: StateDB, fid: FileId): bool =
        sdb.opens.keys().contains(fid) and sdb.opens.get(fid).durable.on

    // Is `fid` a parked handle?
    pure def isParked(sdb: StateDB, fid: FileId): bool =
        sdb.parked.keys().contains(fid)

    // Re-home a parked handle onto (sess, tree): it keeps its FileId, its
    // caching grant and its durable grant, so a second drop parks it again
    // (probe D3b).
    // `cs` is the reclaiming CREATE's own ChannelSequence, and it RESEEDS the
    // handle's high-water mark rather than leaving the pre-drop one in place:
    // chimera_smb_durable_rehome says so in as many words ("Reseed the
    // channel-sequence baseline from the reconnecting CREATE"), which is the
    // only coherent choice -- the mark tracks a CHANNEL, and the reclaim is
    // arriving on a new one.  Found by a generated exactly-once trace whose
    // pre-drop mark of 3 made the model refuse a WRITE at 0 that the wire
    // accepted (DEVIATIONS-SMB.md M-16).
    pure def doReclaim(sdb: StateDB, fid: FileId, sess: SessionId,
                       tree: TreeId, cs: int): StateDB = {
        val p = sdb.parked.get(fid)
        sdb.with("opens", sdb.opens.put(fid, p.open.with("session", sess)
                                             .with("tree", tree)
                                             .with("cs", cs)))
           .with("parked", smapDrop(sdb.parked, fid))
    }

    // ------------------------------------------------------------------
    // Byte-range locks (MS-FSA 2.1.4.10 / MS-SMB2 3.3.5.14)
    // ------------------------------------------------------------------

    // Do two ranges over the same file overlap?  Half-open [lo,hi), so a
    // lock ending exactly where another begins does NOT overlap.
    pure def lkOverlap(e: RangeLock, f: Ino, lo: int, hi: int): bool =
        e.file == f and e.lo < hi and lo < e.hi

    // Does a lock of type `wr` over [lo,hi) requested by handle `self`
    // conflict with a lock already held?
    //
    // Two rules, and the SECOND one is the one the pre-list model got wrong
    // (M-18).  Against ANOTHER handle: WRITE conflicts with everything, READ
    // only with a WRITE.  Against the REQUESTING handle's own locks: a new
    // EXCLUSIVE lock conflicts with any of them it overlaps -- re-locking a
    // range you already hold is STATUS_LOCK_NOT_GRANTED, not a merge -- while
    // a new SHARED lock never conflicts with your own and simply stacks.
    // (Windows behavior; chimera implements exactly this in
    // smb_proc_lock.c's "SMB same-handle conflict rule", citing smbtorture
    // smb2.lock.errorcode / smb2.lock.unlock.)
    pure def lockConflict(sdb: StateDB, f: Ino, self: FileId,
                          lo: int, hi: int, wr: bool): bool =
        sdb.rangeLocks.foldl(false, (acc, e) =>
            acc or (lkOverlap(e, f, lo, hi) and
                    (if (e.owner == self) wr else (wr or e.wr))))

    // Install a lock over [lo,hi) owned by handle `self`.  It is APPENDED:
    // an identical shared lock taken twice is two entries, and each needs its
    // own unlock.
    pure def doLock(sdb: StateDB, f: Ino, self: FileId,
                    lo: int, hi: int, wr: bool): StateDB =
        sdb.with("rangeLocks", sdb.rangeLocks.append(
            { file: f, lo: lo, hi: hi, wr: wr, owner: self }))

    // Does handle `self` hold a lock whose range is EXACTLY [lo,hi)?
    // MS-FSA 2.1.5.8 matches on (LockOffset, LockLength) and nothing else, so
    // a sub-range, a super-range and an overlapping range are all
    // STATUS_RANGE_NOT_LOCKED even when every byte named is locked by `self`.
    pure def rangeLockedBy(sdb: StateDB, f: Ino, self: FileId,
                           lo: int, hi: int): bool =
        sdb.rangeLocks.foldl(false, (acc, e) =>
            acc or (e.file == f and e.owner == self and
                    e.lo == lo and e.hi == hi))

    // Release exactly ONE matching entry (the first granted), which is what
    // makes a stack of identical shared locks need one unlock each.
    pure def doUnlock(sdb: StateDB, f: Ino, self: FileId,
                      lo: int, hi: int): StateDB = {
        val r = sdb.rangeLocks.foldl({ out: List(), done: false }, (a, e) =>
            if (not(a.done) and e.file == f and e.owner == self and
                e.lo == lo and e.hi == hi)
                { out: a.out, done: true }
            else
                { out: a.out.append(e), done: a.done })
        sdb.with("rangeLocks", r.out)
    }

    // A READ/WRITE over [off,off+len) against the mandatory byte-range locks
    // (MS-FSA 2.1.4.2/2.1.4.3 via the conflict algorithm of 2.1.4.10).  This
    // is the coherency point PROPERTY-3c: SMB locks are mandatory, so I/O
    // consults them.
    //
    // The two lock kinds are NOT symmetric, and the asymmetry is the part the
    // pre-list model got wrong (M-19).  An EXCLUSIVE lock is the owner's
    // private right to the range: it blocks another handle's reads and writes
    // and exempts its own.  A SHARED lock is a promise that the range will
    // not CHANGE, so it blocks every write -- including a write issued through
    // the very handle that took the lock -- while blocking no reads at all.
    // (chimera states the same rule at smb_proc_write.c: "a shared lock denies
    // writes from everyone, an exclusive lock denies writes from other
    // opens".)
    pure def rangeIoConflict(sdb: StateDB, f: Ino, self: FileId,
                             off: int, len: int, isWrite: bool): bool =
        sdb.rangeLocks.foldl(false, (acc, e) =>
            acc or (lkOverlap(e, f, off, off + len) and
                    (if (e.wr) e.owner != self else isWrite)))

    // ------------------------------------------------------------------
    // Structural invariants (model self-checks)
    // ------------------------------------------------------------------

    // Every open belongs to a live session and tree and names a live inode.
    pure def stOpensLive(sdb: StateDB): bool =
        sdb.opens.keys().forall(fid => {
            val o = sdb.opens.get(fid)
            sdb.sessions.keys().contains(o.session) and
            sdb.trees.keys().contains(o.tree) and
            fsLive(sdb.fs, o.file)
        })

    // Every tree belongs to a live session.
    pure def stTreesLive(sdb: StateDB): bool =
        sdb.trees.keys().forall(t =>
            sdb.sessions.keys().contains(sdb.trees.get(t).session))

    // No two opens' share reservations conflict pairwise (the grant-time
    // check keeps this: shareConflict includes existing opens).
    pure def stSharesConsistent(sdb: StateDB): bool =
        sdb.opens.keys().forall(f1 =>
            sdb.opens.keys().forall(f2 => {
                val a = sdb.opens.get(f1)
                val b = sdb.opens.get(f2)
                f1 == f2 or a.file != b.file or
                (not(accItsc(grantedAcc(a), b.denied)) and
                 not(accItsc(grantedAcc(b), a.denied)))
            }))

    // Conflicting byte-range locks never coexist ACROSS handles: two
    // overlapping locks on one file owned by different handles are both
    // shared.  (Same-handle overlap is legal and reachable -- a shared lock
    // stacks on the handle's own exclusive one -- so the check is scoped to
    // distinct owners rather than asserting global disjointness.)
    pure def stLocksDisjoint(sdb: StateDB): bool =
        sdb.rangeLocks.foldl(true, (acc, a) =>
            acc and sdb.rangeLocks.foldl(true, (acc2, b) =>
                acc2 and (a.owner == b.owner or a.file != b.file or
                          not(a.lo < b.hi and b.lo < a.hi) or
                          (not(a.wr) and not(b.wr)))))

    // Every lock entry is owned by a live open OF THAT FILE.
    pure def stLocksAnchored(sdb: StateDB): bool =
        sdb.rangeLocks.foldl(true, (acc, e) =>
            acc and sdb.opens.keys().contains(e.owner) and
            sdb.opens.get(e.owner).file == e.file)

    // Every caching grant that EXISTS is one the capability profile allows,
    // checked per grant KIND and structurally.
    //
    // The predicate this replaces -- `opens.forall(cachingLevelNone)`, guarded
    // by `caps.oplocks or caps.leases` -- had two holes.  It disarmed entirely
    // as soon as EITHER feature was on, so a legacy oplock handed out with
    // oplocks off but leases on went unnoticed; and `cachingLevelNone` is
    // satisfied by COplock(OpNone) and by an all-false CLease alike, so "no
    // caching state exists" was true of any grant that merely happened to be
    // empty, however it arose.  It could therefore not tell "the server took no
    // grant" from "the server took a grant of a disabled kind that is inert
    // right now".  The two arms are now separate and structural:
    //
    //  * oplocks off -> NO legacy grant may exist at all.  chimera leaves
    //    req_smb 0 and takes no grant whatsoever (smb_proc_create.c, "Legacy
    //    SMB oplocks are opt-in (smb_oplocks); when disabled no oplock is
    //    granted"), so COplock(OpNone) -- which the old form accepted -- is a
    //    model bug here, not a pass.
    //  * leases off -> a lease grant may exist but must CACHE NOTHING.  chimera
    //    keeps via_rqls set with leasing disabled and answers the bare-RqLs
    //    echo (OplockLevel=LEASE, state NONE, epoch echoed unchanged), so that
    //    inert shape is the ONE lease-shaped state permitted; any caching bit
    //    on it is a violation.  (An all-false CLease is therefore NOT claimed
    //    to be "no caching state" -- it is a lease record that caches nothing,
    //    which is exactly what the wire reports and what the invariant now
    //    says.)
    pure def stCapsRespected(sdb: StateDB, oplocks: bool,
                             leases: bool): bool =
        sdb.opens.keys().forall(fid =>
            match sdb.opens.get(fid).caching {
                | CNone => true
                | COplock(_) => oplocks
                | CLease(x) => leases or bitsEmpty(x.st)
            })

    // A grant that is mid-break has a target no stronger than its current
    // level (a break only ever downgrades).
    pure def stBreaksDowngrade(sdb: StateDB): bool =
        sdb.opens.keys().forall(fid => {
            val o = sdb.opens.get(fid)
            not(o.breaking) or cachingRank(o.breakTo) <= cachingRank(o.caching)
        })

    // A coarse ordering on caching strength for the break-downgrade check.
    pure def cachingRank(c: Caching): int =
        match c {
            | CNone => 0
            | COplock(l) =>
                match l {
                    | OpNone => 0
                    | OpLevelII => 1
                    | OpExclusive => 3
                    | OpBatch => 4
                }
            | CLease(x) =>
                (if (x.st.r) 1 else 0) + (if (x.st.h) 1 else 0) +
                (if (x.st.w) 2 else 0)
        }

    // A parked handle is a handle that survived its connection, so:
    //  * it is NOT also live -- the two maps are disjoint;
    //  * it still names a live inode (a parked handle pins its file);
    //  * it held a durable grant when it parked (nothing else survives a drop
    //    -- probe D6), and that grant's caching satisfied the durable
    //    precondition (probe D1);
    //  * its recorded lease key agrees with the caching grant it carries, which
    //    is what the reconnect's lease-key check compares against.
    pure def stParkedWellFormed(sdb: StateDB): bool =
        sdb.parked.keys().forall(fid => {
            val p = sdb.parked.get(fid)
            not(sdb.opens.keys().contains(fid)) and
            fsLive(sdb.fs, p.open.file) and
            p.open.durable.on and
            // NOTE: the caching grant is deliberately NOT required to still
            // satisfy durableEligible().  The precondition is checked when the
            // durable handle is GRANTED (MS-SMB2 3.3.5.9.6/.10); a later break
            // may strip the oplock down without revoking the durability --
            // chimera never clears durable_flags on a break -- so a parked
            // handle can legitimately carry a weaker grant than it was granted
            // durability for.
            p.hadLease == isLeaseGrant(p.open.caching) and
            p.leaseKey == leaseKeyOf(p.open.caching)
        })

    // Every live open's durable grant is well formed: a v1 grant carries no
    // CreateGuid (there is no such field on the wire -- MS-SMB2 2.2.13.2.3),
    // and a handle that holds no durable grant carries no guid either.
    pure def stDurableWellFormed(sdb: StateDB): bool =
        sdb.opens.keys().forall(fid => {
            // NOTE the shape: `val d = <...>.durable` must NOT be followed by a
            // line starting with `(`, or quint reads the pair as the UFCS call
            // `durable(<...>, ...)` and reports the field name as an unknown
            // operator.
            val d = sdb.opens.get(fid).durable
            val guidOk = d.v2 or d.guid == -1
            val emptyOk = d.on or
                (d.guid == -1 and not(d.v2) and not(d.persistent))
            guidOk and emptyOk
        })

    pure def stInv(sdb: StateDB): bool =
        stOpensLive(sdb) and stTreesLive(sdb) and stSharesConsistent(sdb) and
        stLocksDisjoint(sdb) and stLocksAnchored(sdb) and
        stBreaksDowngrade(sdb) and stParkedWellFormed(sdb) and
        stDurableWellFormed(sdb)
}
