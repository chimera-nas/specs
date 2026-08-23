// SPDX-FileCopyrightText: 2026 The Quint Specs Authors
//
// SPDX-License-Identifier: MIT

// Quint model of an NFSv4 server (RFC 7530 / RFC 8881 / RFC 7862 /
// RFC 8276), used for model-based testing -- the NFSv4 sibling of nfs3.qnt.
//
// Every step is one COMPOUND: the transition label `lastOp` records the
// request ops, the expected per-op results and the expected compound
// status; the replay harness sends the compound to a live server and
// compares.  See DESIGN-NFS4.md for the architecture, the identity
// indirections the harness maintains (Ino -> filehandle, model stateid ->
// wire stateid, abstract change values -> consistency checks), and the
// feature-gating contract.
//
// The module is parameterized by the minor version under test and a
// FeatureMode per optional feature (see nfs4_ops.qnt); nfs4_run.qnt holds
// the concrete instances that `quint run` executes.

module nfs4 {

    import nfs4fs.* from "./nfs4_fs"
    import nfs4state.* from "./nfs4_state"
    import nfs4ops.* from "./nfs4_ops"

    // ------------------------------------------------------------------
    // Configuration
    // ------------------------------------------------------------------

    // Minor version under test: 0, 1 or 2.
    const MINOR: int

    // Optional-feature modes.  pNFS requires MINOR >= 1; xattrs and the
    // 4.2 ops require MINOR >= 2 -- an instance combining FeatMandatory
    // with a minor version that cannot carry the feature is a
    // configuration error (init downgrades the capability to false).
    const F_PNFS: FeatureMode
    const F_READ_DELEG: FeatureMode
    const F_WRITE_DELEG: FeatureMode
    const F_XATTR: FeatureMode
    const F_SPARSE: FeatureMode
    const F_COPY: FeatureMode
    const F_READ_PLUS: FeatureMode
    const F_IO_ADVISE: FeatureMode
    const F_WRITE_SAME: FeatureMode
    const F_CLONE: FeatureMode

    // Server-policy profile knobs (both choices are RFC-conformant; the
    // trace pins the assumption and the harness verifies it holds):
    //  - P_CONFLICT_DELAYS: a delegation-conflicting op returns
    //    NFS4ERR_DELAY while the recall is outstanding (vs blocking).
    //  - P_CLOSE_FREES_LOCKS: CLOSE with live byte-range locks frees them
    //    (vs NFS4ERR_LOCKS_HELD).
    const P_CONFLICT_DELAYS: bool
    const P_CLOSE_FREES_LOCKS: bool

    // ------------------------------------------------------------------
    // Bounded universes
    // ------------------------------------------------------------------

    pure val NAMES = Set("a", "b", "c", "d")
    // Hostile component names: abstract sentinels the harness materializes
    // into bytes a JSON trace cannot carry (embedded NUL, invalid UTF-8, 256
    // chars) -- see v4_expand_name in nfs4_mbt_replay.c and nameStatus in
    // nfs4_ops.qnt.  Every op that names a component runs chimera's
    // validator, and the corpus had never driven it off its success path.
    pure val BAD_NAMES = Set("NEMPTY", "NLONG", "NDOT", "NDOTDOT",
                             "NSLASH", "NNUL",
                             // one per reject branch of the UTF-8 validator
                             "NUTF8", "NUTF8B", "NUTF8C", "NUSUR", "NUNCH",
                             "NU4OV", "NU4HI", "NUF5", "NUTRUNC", "NUBADC",
                             // multi-character: valid prefix, malformed tail
                             "NUMIXB", "NUMIXT", "NUMIXS")
    // Valid multi-byte UTF-8 component names.  These are legal and behave
    // like any other name -- the point is the validator's ACCEPT paths for
    // 2-, 3- and 4-byte sequences (and the U+0800 / U+D7FF / U+10FFFF
    // boundaries), which every name the model generated before this was pure
    // ASCII and therefore skipped.  Kept out of NAMES so the ordinary
    // namespace stays small and collisions stay frequent; they enter the
    // namespace only through nsUtf8Name.
    pure val UTF8_NAMES = Set("NU2", "NU3", "NU4", "NU3E", "NU3S", "NU4M",
                              // multi-character: mixed widths in one name,
                              // and a repeated 2-byte character, so the
                              // validator's loop actually iterates
                              "NUMIX", "NUREP")
    // 0644, 0755, 0600, 0700, 0777.  Plain permission bits only: the
    // set-user-ID / set-group-ID / sticky bits are deliberately excluded
    // because the model does not pin whether a backend preserves them, and a
    // mismatch there would be a backend question rather than a protocol one.
    pure val MODES = Set(420, 493, 384, 448, 511)
    // Every NFSv4 object type the model can name.  CREATE draws from this set
    // directly: NF4REG is not creatable through CREATE and must draw
    // NFS4ERR_BADTYPE (RFC 7530 16.4.4), which is a modeled answer, not a
    // malformed request.
    pure val FTYPES = Set(FReg, FDir, FLnk, FFifo, FSock, FBlk, FChr)
    pure val MAX_OBJECTS = 12
    pure val MAX_BLOCKS = 6
    // Symbol 0 is reserved for holes/zeroes; see nfs4_fs.qnt.
    pure val BLOCK_SYMS = 1.to(3)

    // io_advise_type4 bit numbers (RFC 7862 15.5): NORMAL, SEQUENTIAL,
    // RANDOM, WILLNEED, DONTNEED.  Advisory, so the value only has to be a
    // legal hint -- the server may honor none of them.
    pure val IO_ADVISE_HINTS = Set(1, 2, 3, 4, 5)
    pure val STABLE_LEVELS = Set(0, 1, 2)   // UNSTABLE4/DATA_SYNC4/FILE_SYNC4
    pure val ACCESS_MASKS = Set(1, 32, 63)
    // Byte-range lock space [0, LOCK_BYTES); a lock reaching LOCK_BYTES is
    // sent as a to-EOF lock by the harness.
    pure val LOCK_BYTES = 8
    // Client-owner symbols (two model clients -- conflicts between clients
    // are where most NFSv4 semantics live), per-client open-owner and
    // lock-owner symbols, boot/exclusive-create verifiers.
    pure val CLIENT_OWNERS = Set(1, 2)
    pure val OPEN_OWNERS = Set(1, 2)
    pure val LOCK_OWNERS = Set(6, 7)
    pure val VERFS = Set(1, 2)
    pure val XATTR_NAMES = Set("xa", "xb")
    pure val XATTR_SYMS = 1.to(3)

    // ------------------------------------------------------------------
    // State
    // ------------------------------------------------------------------

    type Label =
        | LInit({ minor: int, caps: Caps })
        // `tag` is the compound's identity (an int the harness formats as
        // "t<N>").  `tagName` overrides the wire tag with a sentinel the
        // harness materializes -- "" means use the default.
        | LCompound({ tag: int, tagName: str, ops: List[OpReq], status: int,
                      results: List[OpRes] })

    var fs: Fs
    var sdb: StateDB
    var caps: Caps
    var tag: int
    var lastOp: Label

    action init = {
        nondet cPnfs = oneOf(capChoices(F_PNFS))
        nondet cRd = oneOf(capChoices(F_READ_DELEG))
        nondet cWd = oneOf(capChoices(F_WRITE_DELEG))
        nondet cXa = oneOf(capChoices(F_XATTR))
        nondet cSp = oneOf(capChoices(F_SPARSE))
        nondet cCp = oneOf(capChoices(F_COPY))
        // Resolved deterministically rather than drawn.  A nondet draw here
        // would consume from the same random stream the step actions use, so
        // adding one regenerates EVERY existing trace in the corpus for every
        // instance and flavor -- a corpus-wide churn that buries whatever the
        // new operations actually change.  The instances that feed the ctest
        // corpus pin these FeatMandatory or FeatOff, so there is no profile
        // to explore; FeatIfAdvertised resolves to "unsupported", which the
        // harness reconciles against the live advertisement as usual.
        val cRp = F_READ_PLUS == FeatMandatory
        val cIa = F_IO_ADVISE == FeatMandatory
        val cWs = F_WRITE_SAME == FeatMandatory
        val cCl = F_CLONE == FeatMandatory
        val c: Caps = {
            pnfs: cPnfs and MINOR >= 1,
            readDeleg: cRd,
            writeDeleg: cWd,
            xattr: cXa and MINOR >= 2,
            sparse: cSp and MINOR >= 2,
            copy: cCp and MINOR >= 2,
            readPlus: cRp and MINOR >= 2,
            ioAdvise: cIa and MINOR >= 2,
            writeSame: cWs and MINOR >= 2,
            clone: cCl and MINOR >= 2,
            conflictDelays: P_CONFLICT_DELAYS,
            closeFreesLocks: P_CLOSE_FREES_LOCKS
        }
        all {
            // ref: in-memory share roots are 0777; the root mode is not
            // asserted by the harness (backend-specific).
            fs' = fsInit(511),
            sdb' = sdbInit,
            caps' = c,
            tag' = 1,
            // The harness reads the assumed capability profile from this
            // label and reconciles it against the live advertisement
            // before replaying step 1 (skip on mismatch unless the
            // feature is FeatMandatory -- then mismatch is a failure).
            lastOp' = LInit({ minor: MINOR, caps: c }),
        }
    }

    // ------------------------------------------------------------------
    // Generator plumbing
    // ------------------------------------------------------------------

    // The one transition shape: evaluate a compound, record the label.
    action runC(ops: List[OpReq]): bool = {
        val out = evalCompound(fs, sdb, MINOR, caps, tag, ops)
        all {
            fs' = out.fs2,
            sdb' = out.sdb2,
            caps' = caps,
            tag' = tag + 1,
            lastOp' = LCompound({ tag: tag, tagName: "", ops: ops,
                                  status: out.status,
                                  results: out.results }),
        }
    }


    // The COMPOUND tag (RFC 7530 16.2.3 / RFC 8881 16.2.3) is a utf8str_cs
    // that chimera validates *before any operation runs*: a malformed tag is
    // NFS4ERR_INVAL with an EMPTY result array (nfs4_proc_compound.c), a
    // compound shape the model had no way to express.  Nothing executes, so
    // no filesystem or state changes -- and, importantly, no SEQUENCE slot
    // advances, which is why these compounds carry no SEQUENCE at all.
    //
    // The tag is checked against the UTF-8 rules only, not the component-name
    // rules: "." or a 256-byte tag is a perfectly legal tag, and a zero-length
    // tag skips validation entirely (chimera guards on `args->tag.len &&`).
    // A well-formed tag -- including multi-byte -- is accepted and the
    // compound runs normally, which is what reaches the validator's accept
    // paths.
    pure def tagStatus(t: str): int =
        if (t == "NUTF8" or t == "NUTF8B" or t == "NUTF8C" or t == "NUSUR" or
            t == "NUNCH" or t == "NU4OV" or t == "NU4HI" or t == "NUF5" or
            t == "NUTRUNC" or t == "NUBADC" or t == "NUMIXB" or
            t == "NUMIXT" or t == "NUMIXS") E_INVAL
        else OK

    action runTagged(t: str, ops: List[OpReq]): bool =
        if (tagStatus(t) != OK)
            all {
                fs' = fs,
                sdb' = sdb,
                caps' = caps,
                tag' = tag + 1,
                lastOp' = LCompound({ tag: tag, tagName: t, ops: ops,
                                      status: E_INVAL, results: [] }),
            }
        else {
            val out = evalCompound(fs, sdb, MINOR, caps, tag, ops)
            all {
                fs' = out.fs2,
                sdb' = out.sdb2,
                caps' = caps,
                tag' = tag + 1,
                lastOp' = LCompound({ tag: tag, tagName: t, ops: ops,
                                      status: out.status,
                                      results: out.results }),
            }
        }

    // Newest session of a client; -1 if none.
    def sessOf(c: ClientId): SessId =
        sdb.sessions.keys().filter(s => sdb.sessions.get(s).client == c)
            .fold(-1, (acc, s) => imax(acc, s))

    // Clients whose state machinery is usable: 4.0 needs a confirmed
    // clientid, 4.1+ additionally a session.
    def readyClients: Set[ClientId] =
        sdb.clients.keys().filter(c =>
            sdb.clients.get(c).confirmed and (MINOR == 0 or sessOf(c) != -1))

    // SEQUENCE prefix for a 4.1+ compound: slot 0, next slot seqid.
    // (List(..) rather than a [..] literal: a bracket after a val binding
    // would parse as list indexing.)
    def withSess(c: ClientId, body: List[OpReq]): List[OpReq] =
        if (MINOR == 0) body
        else List(RSequence({ sess: sessOf(c), slot: 0,
                              seq: sdb.sessions.get(sessOf(c)).slots[0].seq + 1,
                              cacheThis: true })).concat(body)

    // 4.0 owner-seqid arguments (ignored by the evaluator for 4.1+).
    def oseqFor(c: ClientId, owner: int): int =
        if (sdb.oo40.keys().contains((c, owner)))
            sdb.oo40.get((c, owner)).seqid + 1
        else 1

    def lseqFor(c: ClientId, owner: int): int =
        if (sdb.lo40.keys().contains((c, owner)))
            sdb.lo40.get((c, owner)).seqid + 1
        else 1

    def dirs = fsDirs(fs)
    def files = fsFiles(fs)
    def symlinks = fsSymlinks(fs)
    def liveInos = fs.inodes.keys()

    // Live objects of type `t`, or the whole namespace when the type is
    // currently unrepresented (so a draw is never made from an empty set).
    def ofTypeOr(t: Ftype): Set[Ino] = {
        val s = liveInos.filter(i => fs.inodes.get(i).ftype == t)
        if (s.size() > 0) s else liveInos
    }

    // Target draw for a type-gated op.  Three draws in four hand the op the
    // object type it likes, so the deep behavior behind the gate -- block
    // maps, share state, lock ranges, cinfo -- is not starved; the fourth
    // hands it an object of the separately drawn TYPE, so the evaluator's
    // type gates (dataTypeGate, opSetattr's non-regular size gate,
    // opReadlink's non-symlink arms, the parent-must-be-a-directory gates in
    // fsRemove/fsRename/fsLink/openResolve) are reached by the walk instead
    // of being unreachable code.  Drawing the TYPE first and the object
    // second is deliberate: a uniform draw over liveInos would hit the
    // specials only at population frequency (one block device among eight
    // regular files), which is exactly the starvation this closes.
    def wide(typed: Set[Ino], m: int, t: Ftype): Set[Ino] =
        if (m == 0 or typed.size() == 0) ofTypeOr(t) else typed

    // Files delegated to a client other than `cid`.  Mutating such a file
    // through SETATTR/WRITE/LINK/xattr/sparse ops is EXCLUDED from
    // generation: the reference implementation recalls but COMPLETES those
    // ops (empirically probed), a state-mutating divergence from the
    // RFC's recall-then-DELAY discipline (DEVIATIONS-NFS4.md D4-12), so
    // the model neither predicts nor randomly exercises it.  OPEN and
    // REMOVE/RENAME conflicts follow the DELAY discipline and stay in
    // generation -- they are the delegation-break workload.
    def delegOther(f: Ino, cid: ClientId): bool =
        sdb.delegs.keys().exists(s => {
            val d = sdb.delegs.get(s)
            d.file == f and d.client != cid
        })

    // Files delegated to `cid` itself.  A client's own REMOVE/RENAME of
    // a file it holds a delegation on triggers a recall of its OWN
    // delegation and an unresolvable NFS4ERR_DELAY in the reference
    // implementation (the
    // namespace-op lease-conflict path does not recognize the requester
    // as the holder, unlike the OPEN path -- DEVIATIONS-NFS4.md D4-13),
    // so generation diverts those; the OPEN-path self-exemption is
    // empirically pinned.
    def delegSelf(f: Ino, cid: ClientId): bool =
        sdb.delegs.keys().exists(s => {
            val d = sdb.delegs.get(s)
            d.file == f and d.client == cid
        })

    // Same, write delegations only (reads conflict only with those).
    def delegOtherWrite(f: Ino, cid: ClientId): bool =
        sdb.delegs.keys().exists(s => {
            val d = sdb.delegs.get(s)
            d.file == f and d.client != cid and d.isWrite
        })

    // (dir, name) pairs currently naming inode f (for OPEN upgrades and
    // open-over-existing coverage).
    def namePairsOf(f: Ino): Set[{ d: Ino, n: Name }] =
        dirs.fold(Set(), (acc, d) =>
            acc.union(fs.inodes.get(d).ents.keys()
                .filter(n => fs.inodes.get(d).ents.get(n) == f)
                .map(n => { d: d, n: n })))

    // A client the generator can still drive: 4.1+ needs a live session
    // (DESTROY_SESSION may strand state until a new session is created --
    // legal server state, but such state can't be exercised meanwhile).
    def clientUsable(c: ClientId): bool =
        MINOR == 0 or sessOf(c) != -1

    // CLONE pairs: a source open and a destination open held by ONE client
    // on DISTINCT files, the source readable and the destination writable.
    // CLONE resolves both stateids as concrete open state, so having such a
    // pair is a precondition of generating the operation at all -- drawing
    // two opens at random almost never satisfies it.
    def clonePairs: Set[{ src: Sid, dst: Sid }] =
        usableOpens.fold(Set(), (acc, sp) => {
            val so = sdb.opens.get(sp)
            if (not(bitsOverlap(so.access, 1))) acc
            else acc.union(usableOpens.fold(Set(), (a2, dp) => {
                val dofs = sdb.opens.get(dp)
                if (bitsOverlap(dofs.access, 2) and
                    dofs.client == so.client and
                    dofs.file != so.file)
                    a2.union(Set({ src: sp, dst: dp }))
                else a2
            }))
        })

    // Opens usable for I/O: 4.0 unconfirmed opens and stranded-client
    // opens are excluded from generation.
    def usableOpens: Set[Sid] =
        sdb.opens.keys().filter(s =>
            not(sdb.opens.get(s).needConfirm) and
            clientUsable(sdb.opens.get(s).client))

    def usableLocks: Set[Sid] =
        sdb.locks.keys().filter(s => clientUsable(sdb.locks.get(s).client))

    def usableDelegs: Set[Sid] =
        sdb.delegs.keys().filter(s => clientUsable(sdb.delegs.get(s).client))

    def usableLayouts: Set[Sid] =
        sdb.layouts.keys().filter(s => clientUsable(sdb.layouts.get(s).client))

    def openSel(s: Sid): SidSel =
        SelRef({ sid: s, kind: KOpen, argSeq: 0 })

    // Files a usable client currently holds a delegation on, plus who
    // holds each, and the ready clients that could break it (any ready
    // client other than the holder).  These drive the deleg-break
    // actions below, which deterministically construct the
    // A-holds / B-breaks conflict the random walk almost never hits on
    // its own (both clients must target the exact same file while a
    // delegation is live).
    def delegatedFiles: Set[Ino] =
        usableDelegs.map(s => sdb.delegs.get(s).file)

    def holderOf(f: Ino): ClientId =
        usableDelegs.fold(-1, (acc, s) =>
            if (sdb.delegs.get(s).file == f) sdb.delegs.get(s).client
            else acc)

    def breakersOf(f: Ino): Set[ClientId] =
        readyClients.filter(c => c != holderOf(f))

    def breakableDelegs: Set[Ino] =
        delegatedFiles.filter(f => breakersOf(f).size() > 0)

    // ------------------------------------------------------------------
    // Client bootstrap
    // ------------------------------------------------------------------

    action setupSetclientid = all {
        MINOR == 0,
        {
            nondet ow = oneOf(CLIENT_OWNERS)
            nondet vf = oneOf(VERFS)
            // The confirm token must be fresh per request; the step tag is.
            runC([ RSetclientid({ ownerSym: ow, verfSym: vf, tok: tag }) ])
        },
    }

    action setupSetclientidConfirm = all {
        MINOR == 0,
        sdb.clients.keys().exists(c => not(sdb.clients.get(c).confirmed)),
        {
            nondet c = oneOf(sdb.clients.keys().filter(c =>
                not(sdb.clients.get(c).confirmed)))
            runC([ RSetclientidConfirm({ client: c,
                                         tok: sdb.clients.get(c).confirmTok }) ])
        },
    }

    action setupExchangeId = all {
        MINOR >= 1,
        {
            nondet ow = oneOf(CLIENT_OWNERS)
            nondet vf = oneOf(VERFS)
            runC([ RExchangeId({ ownerSym: ow, verfSym: vf }) ])
        },
    }

    action setupCreateSession = all {
        MINOR >= 1,
        sdb.clients.keys().size() > 0,
        {
            nondet c = oneOf(sdb.clients.keys())
            runC([ RCreateSession({ client: c,
                                    csaSeq: sdb.clients.get(c).csSeq,
                                    backChan: true }) ])
        },
    }

    action reclaimComplete = all {
        MINOR >= 1,
        readyClients.exists(c => not(sdb.clients.get(c).reclaimDone)),
        {
            nondet c = oneOf(readyClients.filter(c =>
                not(sdb.clients.get(c).reclaimDone)))
            runC(withSess(c, [ RReclaimComplete ]))
        },
    }

    // 4.1+: until a client sends its global RECLAIM_COMPLETE, every
    // lock-obtaining op is NFS4ERR_GRACE (RFC 8881 18.51.3 -- the gate at
    // the top of opOpen).  A flavor that never generates one therefore
    // emits a trace of nothing but GRACE, and every OPEN/LOCK/CLOSE and
    // stateid-I/O behavior it was written to cover is vacuous.  So the
    // flavors are reclaim-first: while a ready client still owes its
    // reclaim, that is nearly the only thing generated.  MINOR == 0 has no
    // grace window, so this is false there and the wrapper is inert.
    def reclaimPending: bool =
        MINOR >= 1 and
        readyClients.exists(c => not(sdb.clients.get(c).reclaimDone))

    // Negative (4.1+): a non-reclaim OPEN before the client's global
    // RECLAIM_COMPLETE -> NFS4ERR_GRACE, no state touched (RFC 8881
    // 18.51.3).  Reachable only from inside the reclaim window, which the
    // reclaim-first wrapper otherwise closes immediately.
    action openBeforeReclaim = all {
        MINOR >= 1,
        readyClients.exists(c => not(sdb.clients.get(c).reclaimDone)),
        {
            nondet c = oneOf(readyClients.filter(c =>
                not(sdb.clients.get(c).reclaimDone)))
            nondet ow = oneOf(OPEN_OWNERS)
            nondet d = oneOf(dirs)
            nondet n = oneOf(NAMES)
            runC(withSess(c,
                [ RPutfh(d),
                  ROpen({ client: c, owner: ow, oseq: oseqFor(c, ow),
                          claim: OCNull(n), how: HNoCreate,
                          access: 1, deny: 0 }) ]))
        },
    }

    // Negative (4.1+): a second RECLAIM_COMPLETE from a client that has
    // already reclaimed -> NFS4ERR_COMPLETE_ALREADY (RFC 8881 18.51.3).
    // reclaimComplete filters those clients out, so opReclaimComplete's
    // COMPLETE_ALREADY arm is unreachable in generation without this.
    action reclaimAgain = all {
        MINOR >= 1,
        readyClients.exists(c => sdb.clients.get(c).reclaimDone),
        {
            nondet c = oneOf(readyClients.filter(c =>
                sdb.clients.get(c).reclaimDone))
            runC(withSess(c, [ RReclaimComplete ]))
        },
    }

    // Inside the grace window the generator sends the RECLAIM_COMPLETE,
    // but takes the chance to probe the gate itself first: an OPEN inside
    // the window MUST be NFS4ERR_GRACE.  The 3:1 weighting keeps the
    // window ~1.3 extra steps wide per client rather than the ~27 steps a
    // flat draw over the whole flavor would cost.
    action reclaimFirst = any {
        reclaimComplete, reclaimComplete, reclaimComplete,
        openBeforeReclaim,
    }

    // Negative: SEQUENCE with a skipped slot seqid -> NFS4ERR_SEQ_MISORDERED
    // (state must be untouched, RFC 8881 2.10.6.1).
    action seqMisordered = all {
        MINOR >= 1,
        readyClients.size() > 0,
        {
            nondet c = oneOf(readyClients)
            val s = sessOf(c)
            val slot = sdb.sessions.get(s).slots[0]
            runC([ RSequence({ sess: s, slot: 0, seq: slot.seq + 2,
                               cacheThis: true }),
                   RPutrootfh ])
        },
    }

    action destroySession = all {
        MINOR >= 1,
        sdb.sessions.keys().size() > 0,
        {
            nondet s = oneOf(sdb.sessions.keys())
            runC([ RDestroySession(s) ])
        },
    }

    // DESTROY_CLIENTID: CLIENTID_BUSY while sessions/state exist, OK on a
    // bare client record.
    action destroyClientid = all {
        MINOR >= 1,
        sdb.clients.keys().size() > 0,
        {
            nondet c = oneOf(sdb.clients.keys())
            runC([ RDestroyClientid(c) ])
        },
    }

    // ------------------------------------------------------------------
    // Namespace / attribute compounds (need a ready client only for the
    // 4.1 SEQUENCE prefix)
    // ------------------------------------------------------------------

    def genReady: bool = MINOR == 0 or readyClients.size() > 0

    def anyReady: ClientId =
        if (MINOR == 0) -1
        else readyClients.fold(-1, (acc, c) => imax(acc, c))

    action nsLookup = all {
        genReady,
        {
            nondet d = oneOf(liveInos)
            nondet n = oneOf(NAMES)
            runC(withSess(anyReady, [ RPutfh(d), RLookup(n), RGetfh ]))
        },
    }

    action nsLookupp = all {
        genReady,
        {
            nondet d = oneOf(liveInos)
            runC(withSess(anyReady, [ RPutfh(d), RLookupp, RGetfh ]))
        },
    }

    action nsGetattr = all {
        genReady,
        {
            nondet o = oneOf(liveInos)
            runC(withSess(anyReady, [ RPutfh(o), RGetattr ]))
        },
    }

    action nsAccess = all {
        genReady,
        {
            nondet o = oneOf(liveInos)
            nondet m = oneOf(ACCESS_MASKS)
            runC(withSess(anyReady, [ RPutfh(o), RAccess(m) ]))
        },
    }

    action nsReaddir = all {
        genReady,
        {
            nondet o = oneOf(liveInos)
            runC(withSess(anyReady, [ RPutfh(o), RReaddir ]))
        },
    }

    // READLINK against any object type: symlink -> OK, directory -> ISDIR,
    // any other type -> INVAL (RFC 7530 16.25.4/.5, R-CORE-86).  The
    // symlinks-must-exist guard is gone: the non-symlink arms are the point.
    action nsReadlink = all {
        genReady,
        {
            nondet m = oneOf(0.to(3))
            nondet wt = oneOf(FTYPES)
            nondet l = oneOf(wide(symlinks, m, wt))
            runC(withSess(anyReady, [ RPutfh(l), RReadlink ]))
        },
    }

    // RENEW (RFC 7530 16.30): explicit 4.0 lease renewal; 4.1+ renews
    // implicitly through SEQUENCE, so the op answers NFS4ERR_NOTSUPP there.
    // Both arms were modeled and neither was ever generated, which is why
    // chimera's whole renew path sat unexercised.  Drawing the *argument*
    // clientid from every record (not just the confirmed ones) also reaches
    // the NFS4ERR_STALE_CLIENTID arm, while the SEQUENCE prefix -- when there
    // is one -- rides on a ready client as usual.
    // 4.0 only: RENEW (op 30) was *removed* in NFSv4.1, so a 4.1+ server
    // answers with a resop of OP_ILLEGAL rather than a RENEW result -- a wire
    // shape the harness has no decoder for.  Generating it there aborts the
    // replay instead of testing anything, so the minor gate lives here; the
    // evaluator's own minor arm stays as the specification of the answer.
    // Drives chimera's full attribute marshaller (see opGetattrWide): the
    // harness asks for every attribute the server advertises as supported,
    // and the oracle checks only the status.  Aimed at every object type,
    // since several attributes (RAWDEV, SPACE_*, TIME_*) are type-dependent.
    // SECINFO, plus the NFS4ERR_NOFILEHANDLE it strands behind it.  Half the
    // draws trail a GETFH: SECINFO consumes the current filehandle, so that
    // GETFH must fail NOFILEHANDLE -- currently the model's only route to
    // chimera's cfh-less path, and one of the error codes the corpus never
    // produced.  The parent is a `wide` draw so the NOTDIR arm is reached too.
    // BIND_CONN_TO_SESSION.  Two shapes: as the lone op in a compound (the
    // normal form, which reaches the bind path and the INVAL direction arm),
    // and paired with a second op and no SEQUENCE, which must answer
    // NFS4ERR_NOT_ONLY_OP.  Direction 5 is not a channel_dir_from_client4
    // value (the valid ones are 1/2/3/7), so it drives the INVAL arm.
    // Compound-position rules for the session-management ops (RFC 8881
    // 18.35.3 / 18.36.3 / 18.37.3 / 18.50.3).  EXCHANGE_ID and CREATE_SESSION
    // become ordinary operations once a SEQUENCE is present; DESTROY_SESSION
    // and DESTROY_CLIENTID must additionally be the *last* op.  None of these
    // shapes was ever generated, which is why the model could carry the wrong
    // gate on all four ops without a single trace noticing.
    //
    // The two destroy ops are generated only in the *illegal* position: they
    // answer NFS4ERR_NOT_ONLY_OP and so tear nothing down, which keeps this
    // action free of side effects on the rest of the walk.
    action nsSessionPosition = all {
        MINOR >= 1,
        readyClients.size() > 0,
        {
            nondet c = oneOf(readyClients)
            nondet ow = oneOf(CLIENT_OWNERS)
            nondet vf = oneOf(VERFS)
            nondet which = oneOf(0.to(3))
            if (which == 0)
                runC(withSess(c, [ RExchangeId({ ownerSym: ow, verfSym: vf }),
                                   RPutrootfh ]))
            else if (which == 1)
                runC(withSess(c, [ RCreateSession({ client: c,
                                                    csaSeq: sdb.clients.get(c).csSeq,
                                                    backChan: true }),
                                   RPutrootfh ]))
            else if (which == 2)
                runC(withSess(c, [ RDestroySession(sessOf(c)), RPutrootfh ]))
            else
                runC(withSess(c, [ RDestroyClientid(c), RPutrootfh ]))
        },
    }

    action nsBindConnToSession = all {
        MINOR >= 1,
        sdb.sessions.keys().size() > 0,
        {
            nondet s = oneOf(sdb.sessions.keys())
            nondet d = oneOf(Set(1, 2, 3, 7, 5))
            nondet lone = oneOf(Set(false, false, true))
            if (lone)
                runC([ RBindConnToSession({ sess: s, dir: d }), RPutrootfh ])
            else
                runC([ RBindConnToSession({ sess: s, dir: d }) ])
        },
    }

    // Wide VERIFY/NVERIFY -- see opVerifyWide.  Aimed at every object type,
    // since a good part of the attribute marshaller is type-dependent
    // (RAWDEV for device nodes, the SPACE_* and TIME_* families).
    // Aim a hostile name at each op that names a component.  This is the only
    // generator of NFS4ERR_BADNAME, NFS4ERR_BADCHAR and NFS4ERR_NAMETOOLONG,
    // all three of which had zero occurrences across the whole corpus, and it
    // drives chimera_nfs4_validate_name / chimera_nfs4_utf8_valid off the
    // success path they had always taken.
    // Compound tags: malformed ones (rejected whole, zero results) and valid
    // multi-byte ones (accepted, compound runs).  Deliberately SEQUENCE-free:
    // a rejected compound advances no slot, and keeping the session out of it
    // means the two cases differ only in the tag.
    action nsCompoundTag = all {
        MINOR == 0 or readyClients.size() > 0,
        {
            nondet t = oneOf(BAD_NAMES.union(UTF8_NAMES))
            runTagged(t, [ RPutrootfh ])
        },
    }

    action nsBadName = all {
        genReady,
        {
            nondet bn = oneOf(BAD_NAMES)
            nondet gn = oneOf(NAMES)
            nondet d = oneOf(dirs)
            nondet o = oneOf(liveInos)
            nondet which = oneOf(0.to(6))
            if (which == 0)
                runC(withSess(anyReady, [ RPutfh(d), RLookup(bn) ]))
            else if (which == 1)
                runC(withSess(anyReady, [ RPutfh(d), RRemove(bn) ]))
            else if (which == 2)
                runC(withSess(anyReady,
                    [ RPutfh(d), RCreate({ ctype: FDir, name: bn,
                                           mode: 493, target: "t" }) ]))
            else if (which == 3)
                runC(withSess(anyReady,
                    [ RPutfh(o), RSavefh, RPutfh(d), RLink(bn) ]))
            else if (which == 4)
                // hostile source name
                runC(withSess(anyReady,
                    [ RPutfh(d), RSavefh, RPutfh(d),
                      RRename({ oldname: bn, newname: gn }) ]))
            else if (which == 5)
                // hostile target name -- reached only after the source name
                // validates, so it pins the two-step order chimera uses
                runC(withSess(anyReady,
                    [ RPutfh(d), RSavefh, RPutfh(d),
                      RRename({ oldname: gn, newname: bn }) ]))
            else
                runC(withSess(anyReady, [ RPutfh(d), RSecinfo(bn) ]))
        },
    }

    // Legal multi-byte names through the full namespace lifecycle: created,
    // looked up, linked, renamed and enumerated.  This is what drives
    // chimera_nfs4_utf8_valid's accept paths, and it also pushes multi-byte
    // bytes through READDIR's per-entry name encoding.
    action nsUtf8Name = all {
        genReady,
        liveInos.size() < MAX_OBJECTS,
        {
            nondet un = oneOf(UTF8_NAMES)
            nondet gn = oneOf(NAMES)
            nondet d = oneOf(dirs)
            nondet which = oneOf(0.to(4))
            if (which == 0)
                // RGetfh matters: without it the harness never learns the new
                // object's filehandle and a later PUTFH on it cannot be sent.
                runC(withSess(anyReady,
                    [ RPutfh(d), RCreate({ ctype: FDir, name: un,
                                           mode: 493, target: "t" }),
                      RGetfh, RGetattr ]))
            else if (which == 1)
                runC(withSess(anyReady, [ RPutfh(d), RLookup(un), RGetfh ]))
            else if (which == 2)
                runC(withSess(anyReady, [ RPutfh(d), RRemove(un) ]))
            else if (which == 3)
                runC(withSess(anyReady,
                    [ RPutfh(d), RSavefh, RPutfh(d),
                      RRename({ oldname: gn, newname: un }) ]))
            else
                runC(withSess(anyReady, [ RPutfh(d), RReaddir ]))
        },
    }

    // SETATTR carrying every writable attribute chimera accepts except SIZE
    // and ACL.  The model treats it as exactly a mode-only SETATTR (identical
    // oracle, so the change attribute bumps the same way); the extra
    // attributes exist to drive SETATTR's own copy of
    // chimera_nfs4_unmarshall_attrs, which a mode/size-only model leaves at a
    // fraction of its regions.  The delegation guard mirrors nsSetattrMode:
    // mutating another client's delegated file is excluded from generation
    // (D4-12).
    action nsSetattrWide = all {
        genReady,
        {
            nondet o = oneOf(liveInos)
            nondet m = oneOf(MODES)
            if (delegOther(o, anyReady))
                runC(withSess(anyReady, [ RPutfh(o), RGetattr ]))
            else
                runC(withSess(anyReady, [ RPutfh(o), RSetattrWide(m), RGetattr ]))
        },
    }

    action nsVerifyWide = all {
        genReady,
        {
            nondet o = oneOf(liveInos)
            nondet neg = oneOf(Set(false, true))
            runC(withSess(anyReady,
                [ RPutfh(o), if (neg) RNverifyWide else RVerifyWide ]))
        },
    }

    action nsSecinfo = all {
        genReady,
        {
            nondet wm = oneOf(0.to(3))
            nondet wt = oneOf(FTYPES)
            nondet d = oneOf(wide(dirs, wm, wt))
            nondet n = oneOf(NAMES)
            nondet trail = oneOf(Set(false, true))
            if (trail)
                runC(withSess(anyReady, [ RPutfh(d), RSecinfo(n), RGetfh ]))
            else
                runC(withSess(anyReady, [ RPutfh(d), RSecinfo(n) ]))
        },
    }

    action nsGetattrWide = all {
        genReady,
        {
            nondet o = oneOf(liveInos)
            runC(withSess(anyReady, [ RPutfh(o), RGetattrWide ]))
        },
    }

    action nsRenew = all {
        MINOR == 0,
        genReady,
        sdb.clients.keys().size() > 0,
        {
            nondet c = oneOf(sdb.clients.keys())
            runC([ RRenew(c) ])
        },
    }

    // RESTOREFH (RFC 7530 16.31 / RFC 8881 18.30): with a SAVEFH earlier in
    // the compound the saved handle comes back and GETFH observes it; with no
    // saved handle the op must answer NFS4ERR_RESTOREFH.  SAVEFH was already
    // generated (inside RENAME and LINK) but RESTOREFH never was, so neither
    // arm -- nor the compound-scoped save register itself -- was under test.
    action nsRestorefh = all {
        genReady,
        {
            nondet o1 = oneOf(liveInos)
            nondet o2 = oneOf(liveInos)
            nondet saved = oneOf(Set(false, true))
            if (saved)
                runC(withSess(anyReady,
                    [ RPutfh(o1), RSavefh, RPutfh(o2), RRestorefh, RGetfh ]))
            else
                runC(withSess(anyReady, [ RPutfh(o1), RRestorefh ]))
        },
    }

    action nsCreate = all {
        genReady,
        liveInos.size() < MAX_OBJECTS,
        {
            nondet wm = oneOf(0.to(3))
            nondet wt = oneOf(FTYPES)
            nondet d = oneOf(wide(dirs, wm, wt))
            nondet n = oneOf(NAMES)
            nondet m = oneOf(MODES)
            // FReg draws NFS4ERR_BADTYPE (CREATE cannot make regular files,
            // RFC 7530 16.4.4); FBlk/FChr are device nodes the harness and
            // chimera already encode.
            nondet ct = oneOf(FTYPES)
            runC(withSess(anyReady,
                [ RPutfh(d),
                  RCreate({ ctype: ct, name: n, mode: m, target: "t" }),
                  RGetfh, RGetattr ]))
        },
    }

    action nsRemove = all {
        genReady,
        {
            nondet wm = oneOf(0.to(3))
            nondet wt = oneOf(FTYPES)
            nondet d = oneOf(wide(dirs, wm, wt))
            nondet n = oneOf(NAMES)
            val victim = if (fsHasEnt(fs, d, n)) fsChild(fs, d, n) else -1
            if (victim != -1 and delegSelf(victim, anyReady))
                runC(withSess(anyReady, [ RPutfh(d), RGetattr ]))
            else
                runC(withSess(anyReady, [ RPutfh(d), RRemove(n) ]))
        },
    }

    action nsRename = all {
        genReady,
        {
            // Two independent (mode, type) pairs, so a mistyped *source*
            // parent and a mistyped *target* parent both arise.
            nondet wm = oneOf(0.to(3))
            nondet wt = oneOf(FTYPES)
            nondet wm2 = oneOf(0.to(3))
            nondet wt2 = oneOf(FTYPES)
            nondet sd = oneOf(wide(dirs, wm, wt))
            nondet sn = oneOf(NAMES)
            nondet td = oneOf(wide(dirs, wm2, wt2))
            nondet tn = oneOf(NAMES)
            val srcObj = if (fsHasEnt(fs, sd, sn)) fsChild(fs, sd, sn) else -1
            val tgtObj = if (fsHasEnt(fs, td, tn)) fsChild(fs, td, tn) else -1
            if ((srcObj != -1 and delegSelf(srcObj, anyReady)) or
                (tgtObj != -1 and delegSelf(tgtObj, anyReady)))
                runC(withSess(anyReady, [ RPutfh(sd), RGetattr ]))
            else
                runC(withSess(anyReady,
                    [ RPutfh(sd), RSavefh, RPutfh(td),
                      RRename({ oldname: sn, newname: tn }) ]))
        },
    }

    action nsLink = all {
        genReady,
        {
            nondet wm = oneOf(0.to(3))
            nondet wt = oneOf(FTYPES)
            nondet o = oneOf(liveInos)
            nondet d = oneOf(wide(dirs, wm, wt))
            nondet n = oneOf(NAMES)
            if (delegOther(o, anyReady))
                runC(withSess(anyReady, [ RPutfh(o), RGetattr ]))
            else
                runC(withSess(anyReady,
                    [ RPutfh(o), RSavefh, RPutfh(d), RLink(n) ]))
        },
    }

    action nsSetattrMode = all {
        genReady,
        {
            // A mode set is valid on every object type, so no `wide` draw is
            // needed here -- the whole namespace is already the right domain.
            nondet o = oneOf(liveInos)
            nondet m = oneOf(MODES)
            if (delegOther(o, anyReady))
                runC(withSess(anyReady, [ RPutfh(o), RGetattr ]))
            else
                runC(withSess(anyReady,
                    [ RPutfh(o),
                      RSetattr({ mode: m, sizeBlocks: -1, sel: SelAnon }) ]))
        },
    }

    // VERIFY/NVERIFY of the size attribute, followed by GETATTR so the
    // continue-on-match path is observable.
    action nsVerify = all {
        genReady,
        files.size() > 0,
        {
            nondet f = oneOf(files)
            nondet sz = oneOf(0.to(MAX_BLOCKS))
            nondet neg = oneOf(Set(false, true))
            runC(withSess(anyReady,
                [ RPutfh(f),
                  if (neg) RNverifySize(sz) else RVerifySize(sz),
                  RGetattr ]))
        },
    }

    // ------------------------------------------------------------------
    // OPEN family
    // ------------------------------------------------------------------

    action openNew = all {
        readyClients.size() > 0,
        liveInos.size() < MAX_OBJECTS,
        {
            nondet c = oneOf(readyClients)
            nondet ow = oneOf(OPEN_OWNERS)
            nondet wm = oneOf(0.to(3))
            nondet wt = oneOf(FTYPES)
            nondet d = oneOf(wide(dirs, wm, wt))
            nondet n = oneOf(NAMES)
            nondet acc = oneOf(Set(1, 2, 3))
            nondet dny = oneOf(Set(0, 1, 2, 3))
            nondet m = oneOf(MODES)
            nondet vf = oneOf(VERFS)
            nondet how = oneOf(Set(
                HNoCreate,
                HUnchecked({ mode: m, truncate: false }),
                HUnchecked({ mode: m, truncate: true }),
                HGuarded({ mode: m }),
                HExclusive({ verf: vf })))
            runC(withSess(c,
                [ RPutfh(d),
                  ROpen({ client: c, owner: ow, oseq: oseqFor(c, ow),
                          claim: OCNull(n), how: how,
                          access: acc, deny: dny }),
                  RGetfh ]))
        },
    }

    // Deny-free open used by the delegation flavor: grants a read/write
    // delegation without the deny-mode share state whose cross-client
    // accounting is exercised (and diverges, pending analysis) elsewhere.
    action delegOpenNew = all {
        readyClients.size() > 0,
        liveInos.size() < MAX_OBJECTS,
        {
            nondet c = oneOf(readyClients)
            nondet ow = oneOf(OPEN_OWNERS)
            nondet d = oneOf(dirs)
            nondet n = oneOf(NAMES)
            nondet acc = oneOf(Set(1, 2))
            nondet m = oneOf(MODES)
            runC(withSess(c,
                [ RPutfh(d),
                  ROpen({ client: c, owner: ow, oseq: oseqFor(c, ow),
                          claim: OCNull(n),
                          how: HUnchecked({ mode: m, truncate: false }),
                          access: acc, deny: 0 }),
                  RGetfh ]))
        },
    }

    // CLAIM_FH re-open of an already-open file (4.1+).
    action openFh = all {
        MINOR >= 1,
        readyClients.size() > 0,
        usableOpens.size() > 0,
        {
            nondet s = oneOf(usableOpens)
            val o = sdb.opens.get(s)
            nondet acc = oneOf(Set(1, 2, 3))
            runC(withSess(o.client,
                [ RPutfh(o.file),
                  ROpen({ client: o.client, owner: o.owner, oseq: 0,
                          claim: OCFh, how: HNoCreate,
                          access: acc, deny: 0 }),
                  RGetfh ]))
        },
    }

    // 4.0: confirm a fresh open-owner's first open.
    action openConfirm = all {
        MINOR == 0,
        sdb.opens.keys().exists(s => sdb.opens.get(s).needConfirm),
        {
            nondet s = oneOf(sdb.opens.keys().filter(s =>
                sdb.opens.get(s).needConfirm))
            val o = sdb.opens.get(s)
            runC([ RPutfh(o.file),
                   ROpenConfirm({ sid: s, oseq: oseqFor(o.client, o.owner) }) ])
        },
    }

    action openDowngrade = all {
        genReady,
        usableOpens.size() > 0,
        {
            nondet s = oneOf(usableOpens)
            val o = sdb.opens.get(s)
            nondet acc = oneOf(Set(1, 2, 3))
            nondet dny = oneOf(Set(0, 1, 2, 3))
            runC(withSess(o.client,
                [ RPutfh(o.file),
                  ROpenDowngrade({ sid: s, argSeq: 0, access: acc, deny: dny,
                                   oseq: oseqFor(o.client, o.owner) }) ]))
        },
    }

    action closeOpen = all {
        genReady,
        usableOpens.size() > 0,
        {
            nondet s = oneOf(usableOpens)
            val o = sdb.opens.get(s)
            nondet exact = oneOf(Set(false, true))
            runC(withSess(o.client,
                [ RPutfh(o.file),
                  RClose({ sid: s, argSeq: if (exact) o.seq else 0,
                           oseq: oseqFor(o.client, o.owner) }) ]))
        },
    }

    // Negative (4.0): OPEN with a skipped owner seqid -> NFS4ERR_BAD_SEQID,
    // no seqid consumed.
    // OPEN whose CLAIM_NULL name is malformed, or a valid multi-byte name.
    // OPEN was the one name-taking op the hostile-name work skipped, because
    // its error path also has to settle the 4.0 open-owner seqid: INVAL,
    // BADNAME, BADCHAR and NAMETOOLONG all consume it (RFC 7530 9.1.7), so
    // this exercises the name validator and that settling path together.
    // Drawing valid multi-byte names too covers the accept side, where the
    // OPEN then proceeds to an ordinary NOENT.
    action openOddName = all {
        readyClients.size() > 0,
        {
            nondet c = oneOf(readyClients)
            nondet ow = oneOf(OPEN_OWNERS)
            nondet d = oneOf(dirs)
            nondet n = oneOf(BAD_NAMES.union(UTF8_NAMES))
            runC(withSess(c,
                [ RPutfh(d),
                  ROpen({ client: c, owner: ow, oseq: oseqFor(c, ow),
                          claim: OCNull(n), how: HNoCreate,
                          access: 1, deny: 0 }) ]))
        },
    }

    action openBadSeqid = all {
        MINOR == 0,
        readyClients.size() > 0,
        sdb.oo40.keys().size() > 0,
        {
            nondet k = oneOf(sdb.oo40.keys())
            nondet wm = oneOf(0.to(3))
            nondet wt = oneOf(FTYPES)
            nondet d = oneOf(wide(dirs, wm, wt))
            nondet n = oneOf(NAMES)
            runC([ RPutfh(d),
                   ROpen({ client: k._1, owner: k._2,
                           oseq: sdb.oo40.get(k).seqid + 2,
                           claim: OCNull(n), how: HNoCreate,
                           access: 1, deny: 0 }) ])
        },
    }

    // ------------------------------------------------------------------
    // Data I/O
    // ------------------------------------------------------------------

    action ioRead = all {
        genReady,
        files.size() > 0,
        {
            nondet wm = oneOf(0.to(3))
            nondet wt = oneOf(FTYPES)
            nondet f = oneOf(wide(files, wm, wt))
            nondet off = oneOf(0.to(MAX_BLOCKS))
            nondet len = oneOf(1.to(2))
            val opensOfF = usableOpens.filter(s => sdb.opens.get(s).file == f)
            nondet useOpen = oneOf(Set(false, true))
            val sel = if (useOpen and opensOfF.size() > 0)
                          openSel(opensOfF.fold(-1, (a2, s) => imax(a2, s)))
                      else SelAnon
            val cid = if (useOpen and opensOfF.size() > 0)
                          sdb.opens.get(opensOfF.fold(-1, (a2, s) =>
                              imax(a2, s))).client
                      else anyReady
            val rcid = if (MINOR == 0) -1 else
                       (if (cid == -1) anyReady else cid)
            if (delegOtherWrite(f, if (rcid == -1) anyReady else rcid))
                runC(withSess(rcid, [ RPutfh(f), RGetattr ]))
            else
                runC(withSess(rcid,
                    [ RPutfh(f), RRead({ sel: sel, off: off, len: len }) ]))
        },
    }

    action ioWrite = all {
        genReady,
        files.size() > 0,
        {
            nondet wm = oneOf(0.to(3))
            nondet wt = oneOf(FTYPES)
            nondet f = oneOf(wide(files, wm, wt))
            nondet off = oneOf(0.to(MAX_BLOCKS - 1))
            nondet len = oneOf(1.to(2))
            nondet pat = oneOf(BLOCK_SYMS)
            nondet stable = oneOf(STABLE_LEVELS)
            val opensOfF = usableOpens.filter(s => sdb.opens.get(s).file == f)
            nondet useOpen = oneOf(Set(false, true))
            val sid = opensOfF.fold(-1, (a2, s) => imax(a2, s))
            val sel = if (useOpen and sid != -1) openSel(sid) else SelAnon
            val cid = if (useOpen and sid != -1) sdb.opens.get(sid).client
                      else anyReady
            val wcid = if (MINOR == 0) -1 else
                       (if (cid == -1) anyReady else cid)
            if (delegOther(f, if (wcid == -1) anyReady else wcid))
                runC(withSess(wcid, [ RPutfh(f), RGetattr ]))
            else
                runC(withSess(wcid,
                    [ RPutfh(f),
                      RWrite({ sel: sel, off: off,
                               len: imin(len, MAX_BLOCKS - off), pat: pat,
                               stable: stable }) ]))
        },
    }

    action ioCommit = all {
        genReady,
        files.size() > 0,
        {
            nondet wm = oneOf(0.to(3))
            nondet wt = oneOf(FTYPES)
            nondet f = oneOf(wide(files, wm, wt))
            runC(withSess(anyReady, [ RPutfh(f), RCommit ]))
        },
    }

    action ioSetattrSize = all {
        genReady,
        files.size() > 0,
        {
            nondet wm = oneOf(0.to(3))
            nondet wt = oneOf(FTYPES)
            nondet f = oneOf(wide(files, wm, wt))
            nondet sz = oneOf(0.to(MAX_BLOCKS))
            val opensOfF = usableOpens.filter(s => sdb.opens.get(s).file == f)
            nondet useOpen = oneOf(Set(false, true))
            val sid = opensOfF.fold(-1, (a2, s) => imax(a2, s))
            val sel = if (useOpen and sid != -1) openSel(sid) else SelAnon
            if (delegOther(f, anyReady))
                runC(withSess(anyReady, [ RPutfh(f), RGetattr ]))
            else
                runC(withSess(anyReady,
                    [ RPutfh(f),
                      RSetattr({ mode: -1, sizeBlocks: sz, sel: sel }) ]))
        },
    }

    // ------------------------------------------------------------------
    // Byte-range locks
    // ------------------------------------------------------------------

    def lockRange: { lo: int, hi: int } = { lo: 0, hi: LOCK_BYTES }

    action lockNew = all {
        genReady,
        usableOpens.size() > 0,
        {
            nondet s = oneOf(usableOpens)
            val o = sdb.opens.get(s)
            nondet lown = oneOf(LOCK_OWNERS)
            nondet lo = oneOf(0.to(LOCK_BYTES - 2))
            nondet len = oneOf(1.to(3))
            // WRITE_LT only under a write-capable open: whether a WRITE_LT
            // under a read-only open draws NFS4ERR_OPENMODE is
            // server-dependent (RFC 8881 9.1.2 discretion) -- not generated.
            nondet wr = oneOf(if (o.access >= 2) Set(false, true)
                              else Set(false))
            runC(withSess(o.client,
                [ RPutfh(o.file),
                  RLock({ wr: wr, lo: lo, hi: imin(lo + len, LOCK_BYTES),
                          newOwner: true, openSid: s, lockSid: -1,
                          lockOwner: lown,
                          oseq: oseqFor(o.client, o.owner),
                          lseq: lseqFor(o.client, lown) }) ]))
        },
    }

    action lockExist = all {
        genReady,
        usableLocks.size() > 0,
        {
            nondet s = oneOf(usableLocks)
            val l = sdb.locks.get(s)
            val o = sdb.opens.get(l.openSid)
            nondet lo = oneOf(0.to(LOCK_BYTES - 2))
            nondet len = oneOf(1.to(3))
            nondet wr = oneOf(if (o.access >= 2) Set(false, true)
                              else Set(false))
            runC(withSess(l.client,
                [ RPutfh(l.file),
                  RLock({ wr: wr, lo: lo, hi: imin(lo + len, LOCK_BYTES),
                          newOwner: false, openSid: -1, lockSid: s,
                          lockOwner: l.owner, oseq: 0,
                          lseq: lseqFor(l.client, l.owner) }) ]))
        },
    }

    action lockCheck = all {
        genReady,
        readyClients.size() > 0,
        files.size() > 0,
        {
            nondet c = oneOf(readyClients)
            nondet lown = oneOf(LOCK_OWNERS)
            nondet wm = oneOf(0.to(3))
            nondet wt = oneOf(FTYPES)
            nondet f = oneOf(wide(files, wm, wt))
            nondet lo = oneOf(0.to(LOCK_BYTES - 2))
            nondet len = oneOf(1.to(3))
            nondet wr = oneOf(Set(false, true))
            runC(withSess(c,
                [ RPutfh(f),
                  RLockt({ client: c, lockOwner: lown, wr: wr,
                           lo: lo, hi: imin(lo + len, LOCK_BYTES) }) ]))
        },
    }

    action lockUnlock = all {
        genReady,
        usableLocks.size() > 0,
        {
            nondet s = oneOf(usableLocks)
            val l = sdb.locks.get(s)
            nondet lo = oneOf(0.to(LOCK_BYTES - 2))
            nondet len = oneOf(1.to(4))
            runC(withSess(l.client,
                [ RPutfh(l.file),
                  RLocku({ sid: s, argSeq: 0, lseq: lseqFor(l.client, l.owner),
                           lo: lo, hi: imin(lo + len, LOCK_BYTES) }) ]))
        },
    }

    action lockFree = all {
        MINOR >= 1,
        usableLocks.size() > 0,
        {
            nondet s = oneOf(usableLocks)
            val l = sdb.locks.get(s)
            runC(withSess(l.client,
                [ RFreeStateid({ sid: s, kind: KLock, argSeq: 0 }) ]))
        },
    }

    // FREE_STATEID against an *open* stateid.  Only lock stateids were ever
    // fed to the op, so the model's open/delegation arms -- and chimera's
    // NFS4_SLOT_TYPE_OPEN branch -- were both unreachable.  A live open still
    // has state, so the answer is NFS4ERR_LOCKS_HELD, not BAD_STATEID.
    action freeStateidOpen = all {
        MINOR >= 1,
        usableOpens.size() > 0,
        {
            nondet s = oneOf(usableOpens)
            val o = sdb.opens.get(s)
            runC(withSess(o.client,
                [ RFreeStateid({ sid: s, kind: KOpen, argSeq: 0 }) ]))
        },
    }

    action lockReleaseOwner = all {
        MINOR == 0,
        sdb.locks.keys().size() > 0,
        {
            nondet s = oneOf(sdb.locks.keys())
            val l = sdb.locks.get(s)
            runC([ RReleaseLockowner({ client: l.client,
                                       lockOwner: l.owner }) ])
        },
    }

    // ------------------------------------------------------------------
    // Delegations
    // ------------------------------------------------------------------

    // Voluntary or post-recall DELEGRETURN.  Recalls themselves are
    // triggered inside conflicting OPENs (see opOpen), which return
    // NFS4ERR_DELAY and mark the delegation recalled; the harness observes
    // the CB_RECALL and this action generates the client's return.
    action delegReturn = all {
        genReady,
        usableDelegs.size() > 0,
        {
            nondet s = oneOf(usableDelegs)
            val d = sdb.delegs.get(s)
            runC(withSess(d.client,
                [ RPutfh(d.file),
                  RDelegreturn({ sid: s, kind: KDeleg, argSeq: 0 }) ]))
        },
    }

    // A different ready client opens (CLAIM_FH) a file the holder has a
    // delegation on: forces a recall + NFS4ERR_DELAY (the break half of
    // the delegation lifecycle; RFC 8881 10.4.3).
    action delegBreakOpen = all {
        MINOR >= 1,
        breakableDelegs.size() > 0,
        {
            nondet f = oneOf(breakableDelegs)
            nondet c = oneOf(breakersOf(f))
            nondet ow = oneOf(OPEN_OWNERS)
            nondet acc = oneOf(Set(1, 2, 3))
            runC(withSess(c,
                [ RPutfh(f),
                  ROpen({ client: c, owner: ow, oseq: oseqFor(c, ow),
                          claim: OCFh, how: HNoCreate,
                          access: acc, deny: 0 }),
                  RGetfh ]))
        },
    }

    // A different ready client removes the holder's delegated file:
    // forces a recall + NFS4ERR_DELAY on REMOVE (modeled in opRemove).
    action delegBreakRemove = all {
        breakableDelegs.size() > 0,
        {
            nondet f = oneOf(breakableDelegs)
            val d = fsGet(fs, f).parent
            nondet n = oneOf(fsGet(fs, d).ents.keys()
                             .filter(nm => fsGet(fs, d).ents.get(nm) == f))
            nondet c = oneOf(breakersOf(f))
            runC(withSess(c, [ RPutfh(d), RRemove(n) ]))
        },
    }

    // ------------------------------------------------------------------
    // pNFS
    // ------------------------------------------------------------------

    action pnfsLayoutget = all {
        MINOR >= 1,
        caps.pnfs,
        usableOpens.size() > 0,
        {
            nondet s = oneOf(usableOpens)
            val o = sdb.opens.get(s)
            nondet rw = oneOf(Set(false, true))
            nondet lo = oneOf(0.to(MAX_BLOCKS - 1))
            nondet len = oneOf(1.to(3))
            // First LAYOUTGET presents an open stateid; afterwards the
            // layout stateid (RFC 8881 12.5.3).
            val lay = layoutByClient(sdb, o.client, o.file)
            val sel = if (lay != -1)
                          SelRef({ sid: lay, kind: KLayout, argSeq: 0 })
                      else openSel(s)
            runC(withSess(o.client,
                [ RPutfh(o.file),
                  RLayoutget({ rw: rw, lo: lo,
                               hi: imin(lo + len, MAX_BLOCKS), sel: sel }) ]))
        },
    }

    action pnfsLayoutreturn = all {
        MINOR >= 1,
        usableLayouts.size() > 0,
        {
            nondet s = oneOf(usableLayouts)
            val l = sdb.layouts.get(s)
            nondet lo = oneOf(0.to(MAX_BLOCKS - 1))
            nondet len = oneOf(1.to(MAX_BLOCKS))
            runC(withSess(l.client,
                [ RPutfh(l.file),
                  RLayoutreturn({ sid: s, argSeq: 0, lo: lo,
                                  hi: imin(lo + len, MAX_BLOCKS) }) ]))
        },
    }

    action pnfsLayoutcommit = all {
        MINOR >= 1,
        usableLayouts.size() > 0,
        {
            nondet s = oneOf(usableLayouts)
            val l = sdb.layouts.get(s)
            nondet lo = oneOf(0.to(MAX_BLOCKS - 1))
            nondet len = oneOf(1.to(2))
            runC(withSess(l.client,
                [ RPutfh(l.file),
                  RLayoutcommit({ sid: s, lo: lo,
                                  hi: imin(lo + len, MAX_BLOCKS) }) ]))
        },
    }

    action pnfsDeviceinfo = all {
        MINOR >= 1,
        readyClients.size() > 0,
        {
            nondet c = oneOf(readyClients)
            runC(withSess(c, [ RGetdeviceinfo ]))
        },
    }

    // A pNFS op against a non-pNFS profile: NFS4ERR_NOTSUPP expected.
    action pnfsNotsupp = all {
        MINOR >= 1,
        not(caps.pnfs),
        readyClients.size() > 0,
        files.size() > 0,
        {
            nondet c = oneOf(readyClients)
            nondet f = oneOf(files)
            runC(withSess(c,
                [ RPutfh(f),
                  RLayoutget({ rw: false, lo: 0, hi: 1, sel: SelAnon }) ]))
        },
    }

    // ------------------------------------------------------------------
    // NFSv4.2 + xattrs
    // ------------------------------------------------------------------

    action sparseAllocate = all {
        MINOR >= 2,
        files.size() > 0,
        genReady,
        {
            nondet wm = oneOf(0.to(3))
            nondet wt = oneOf(FTYPES)
            nondet f = oneOf(wide(files, wm, wt))
            nondet off = oneOf(0.to(MAX_BLOCKS - 1))
            nondet len = oneOf(1.to(2))
            if (delegOther(f, anyReady))
                runC(withSess(anyReady, [ RPutfh(f), RGetattr ]))
            else
                runC(withSess(anyReady,
                    [ RPutfh(f),
                      RAllocate({ sel: SelAnon, off: off,
                                  len: imin(len, MAX_BLOCKS - off) }) ]))
        },
    }

    action sparseDeallocate = all {
        MINOR >= 2,
        files.size() > 0,
        genReady,
        {
            nondet wm = oneOf(0.to(3))
            nondet wt = oneOf(FTYPES)
            nondet f = oneOf(wide(files, wm, wt))
            nondet off = oneOf(0.to(MAX_BLOCKS - 1))
            nondet len = oneOf(1.to(2))
            if (delegOther(f, anyReady))
                runC(withSess(anyReady, [ RPutfh(f), RGetattr ]))
            else
                runC(withSess(anyReady,
                    [ RPutfh(f),
                      RDeallocate({ sel: SelAnon, off: off, len: len }) ]))
        },
    }

    action sparseSeek = all {
        MINOR >= 2,
        files.size() > 0,
        genReady,
        {
            nondet wm = oneOf(0.to(3))
            nondet wt = oneOf(FTYPES)
            nondet f = oneOf(wide(files, wm, wt))
            nondet off = oneOf(0.to(MAX_BLOCKS))
            nondet whatData = oneOf(Set(false, true))
            if (delegOtherWrite(f, anyReady))
                runC(withSess(anyReady, [ RPutfh(f), RGetattr ]))
            else
                runC(withSess(anyReady,
                    [ RPutfh(f),
                      RSeek({ sel: SelAnon, off: off, whatData: whatData }) ]))
        },
    }

    // COPY draws from the same pair set as CLONE so it runs against real
    // files with real open state.  It deliberately does NOT generate the
    // anonymous stateid: the model accepts it there but the reference server
    // rejects it (see opCopy), and that divergence is not this corpus's to
    // assert.
    action copyRange = all {
        MINOR >= 2,
        genReady,
        clonePairs.size() > 0,
        {
            nondet p = oneOf(clonePairs)
            val so = sdb.opens.get(p.src)
            val dofs = sdb.opens.get(p.dst)
            nondet srcOff = oneOf(0.to(MAX_BLOCKS - 1))
            nondet dstOff = oneOf(0.to(MAX_BLOCKS - 1))
            nondet cnt = oneOf(1.to(2))
            // Keep the source range inside the source file.  The out-of-range
            // shapes are a second open divergence: RFC 7862 15.2.3 makes a
            // source offset past the source size NFS4ERR_INVAL, and the
            // reference server answers NFS4_OK.  Asserting that is not this
            // corpus's job.
            if (delegOther(dofs.file, dofs.client) or
                delegOtherWrite(so.file, so.client) or
                srcOff + cnt > fsGet(fs, so.file).sizeBlocks)
                runC(withSess(dofs.client, [ RPutfh(dofs.file), RGetattr ]))
            else
                runC(withSess(dofs.client,
                    [ RPutfh(so.file), RSavefh, RPutfh(dofs.file),
                      RCopy({ srcSel: openSel(p.src), dstSel: openSel(p.dst),
                              srcOff: srcOff, dstOff: dstOff,
                              cnt: cnt }) ]))
        },
    }

    // READ_PLUS over a range that straddles written blocks, holes and EOF:
    // the interesting classifications all live near a sparse file's edges.
    action sparseReadPlus = all {
        MINOR >= 2,
        files.size() > 0,
        genReady,
        {
            nondet f = oneOf(files)
            nondet off = oneOf(0.to(MAX_BLOCKS))
            nondet len = oneOf(1.to(3))
            // Only opens carrying the read bit: READ (and so READ_PLUS)
            // through a write-only open is a MAY the model resolves as
            // NFS4ERR_OPENMODE, and the generator avoids that discretion
            // rather than assert either answer (see opRead).
            val opensOfF = usableOpens.filter(s =>
                sdb.opens.get(s).file == f and
                bitsOverlap(sdb.opens.get(s).access, 1))
            nondet useOpen = oneOf(Set(false, true))
            val sid = opensOfF.fold(-1, (a2, s) => imax(a2, s))
            val sel = if (useOpen and sid != -1) openSel(sid) else SelAnon
            val cid = if (useOpen and sid != -1) sdb.opens.get(sid).client
                      else anyReady
            val rcid = if (MINOR == 0) -1 else
                       (if (cid == -1) anyReady else cid)
            if (delegOtherWrite(f, if (rcid == -1) anyReady else rcid))
                runC(withSess(rcid, [ RPutfh(f), RGetattr ]))
            else
                runC(withSess(rcid,
                    [ RPutfh(f),
                      RReadPlus({ sel: sel, off: off, len: len }) ]))
        },
    }

    // IO_ADVISE is advisory and never mutates state, so it is generated
    // freely: it validates only a filehandle and a stateid.
    action ioAdvise = all {
        MINOR >= 2,
        files.size() > 0,
        genReady,
        {
            nondet f = oneOf(files)
            nondet off = oneOf(0.to(MAX_BLOCKS))
            nondet len = oneOf(1.to(2))
            nondet hint = oneOf(IO_ADVISE_HINTS)
            val opensOfF = usableOpens.filter(s => sdb.opens.get(s).file == f)
            nondet useOpen = oneOf(Set(false, true))
            val sid = opensOfF.fold(-1, (a2, s) => imax(a2, s))
            val sel = if (useOpen and sid != -1) openSel(sid) else SelAnon
            val cid = if (useOpen and sid != -1) sdb.opens.get(sid).client
                      else anyReady
            val acid = if (MINOR == 0) -1 else
                       (if (cid == -1) anyReady else cid)
            runC(withSess(acid,
                [ RPutfh(f),
                  RIoAdvise({ sel: sel, off: off, len: len, hint: hint }) ]))
        },
    }

    // WRITE_SAME, including the per-block-number arm the server rejects with
    // NFS4ERR_UNION_NOTSUPP before it looks at anything else.
    action writeSame = all {
        MINOR >= 2,
        files.size() > 0,
        genReady,
        {
            nondet f = oneOf(files)
            nondet off = oneOf(0.to(MAX_BLOCKS - 1))
            nondet blocks = oneOf(1.to(2))
            nondet pat = oneOf(BLOCK_SYMS)
            // Set literals deduplicate, so weight with an int draw: one in
            // four WRITE_SAMEs takes the per-block-number arm.
            nondet bnDraw = oneOf(0.to(3))
            val blocknum = (bnDraw == 0)
            val opensOfF = usableOpens.filter(s =>
                sdb.opens.get(s).file == f and
                bitsOverlap(sdb.opens.get(s).access, 2))
            nondet useOpen = oneOf(Set(false, true))
            val sid = opensOfF.fold(-1, (a2, s) => imax(a2, s))
            val sel = if (useOpen and sid != -1) openSel(sid) else SelAnon
            val cid = if (useOpen and sid != -1) sdb.opens.get(sid).client
                      else anyReady
            val wcid = if (MINOR == 0) -1 else
                       (if (cid == -1) anyReady else cid)
            if (delegOther(f, if (wcid == -1) anyReady else wcid))
                runC(withSess(wcid, [ RPutfh(f), RGetattr ]))
            else
                runC(withSess(wcid,
                    [ RPutfh(f),
                      RWriteSame({ sel: sel, off: off,
                                   blocks: imin(blocks, MAX_BLOCKS - off),
                                   pat: pat, blocknum: blocknum }) ]))
        },
    }

    // CLONE needs ONE client holding opens on TWO different files.  openNew
    // draws its client uniformly from readyClients, so two concurrent opens
    // almost never share a client and the pair never forms by chance.  This
    // action grows an existing client's open set instead, opening for BOTH
    // read and write so the new open can serve as either clone end.
    action cloneOpenPair = all {
        MINOR >= 2,
        usableOpens.size() > 0,
        liveInos.size() < MAX_OBJECTS,
        {
            nondet sp = oneOf(usableOpens)
            val o = sdb.opens.get(sp)
            nondet ow = oneOf(OPEN_OWNERS)
            nondet d = oneOf(dirs)
            nondet n = oneOf(NAMES)
            nondet m = oneOf(MODES)
            runC(withSess(o.client,
                [ RPutfh(d),
                  ROpen({ client: o.client, owner: ow,
                          oseq: oseqFor(o.client, ow),
                          claim: OCNull(n),
                          how: HUnchecked({ mode: m, truncate: false }),
                          access: 3, deny: 0 }),
                  RGetfh ]))
        },
    }

    // CLONE reflinks a source range into another file.  A minority of draws
    // use the anonymous stateid, which CLONE must reject with
    // NFS4ERR_BAD_STATEID -- it resolves both stateids as concrete state and
    // takes no special-stateid shortcut.
    action cloneRange = all {
        MINOR >= 2,
        genReady,
        clonePairs.size() > 0,
        {
            nondet p = oneOf(clonePairs)
            val so = sdb.opens.get(p.src)
            val dofs = sdb.opens.get(p.dst)
            nondet srcOff = oneOf(0.to(MAX_BLOCKS - 1))
            nondet dstOff = oneOf(0.to(MAX_BLOCKS - 1))
            nondet cnt = oneOf(0.to(2))
            // As above: one clone in four uses the anonymous stateid so the
            // BAD_STATEID rejection is covered without starving the success
            // path.
            nondet anonDraw = oneOf(0.to(3))
            val anon = (anonDraw == 0)
            val srcSel = if (anon) SelAnon else openSel(p.src)
            if (delegOther(dofs.file, dofs.client) or
                delegOtherWrite(so.file, so.client))
                runC(withSess(dofs.client, [ RPutfh(dofs.file), RGetattr ]))
            else
                runC(withSess(dofs.client,
                    [ RPutfh(so.file), RSavefh, RPutfh(dofs.file),
                      RClone({ srcSel: srcSel, dstSel: openSel(p.dst),
                               srcOff: srcOff, dstOff: dstOff,
                               cnt: cnt }) ]))
        },
    }

    action xattrSet = all {
        MINOR >= 2,
        genReady,
        files.size() > 0,
        {
            nondet o = oneOf(files)
            nondet n = oneOf(XATTR_NAMES)
            nondet v = oneOf(XATTR_SYMS)
            nondet how = oneOf(Set(XsCreate, XsReplace, XsEither))
            if (delegOther(o, anyReady))
                runC(withSess(anyReady, [ RPutfh(o), RGetattr ]))
            else
                runC(withSess(anyReady,
                    [ RPutfh(o), RSetxattr({ name: n, sym: v, how: how }) ]))
        },
    }

    action xattrGet = all {
        MINOR >= 2,
        genReady,
        files.size() > 0,
        {
            nondet o = oneOf(files)
            nondet n = oneOf(XATTR_NAMES)
            runC(withSess(anyReady, [ RPutfh(o), RGetxattr(n) ]))
        },
    }

    action xattrList = all {
        MINOR >= 2,
        genReady,
        files.size() > 0,
        {
            nondet o = oneOf(files)
            runC(withSess(anyReady, [ RPutfh(o), RListxattrs ]))
        },
    }

    action xattrRemove = all {
        MINOR >= 2,
        genReady,
        files.size() > 0,
        {
            nondet o = oneOf(files)
            nondet n = oneOf(XATTR_NAMES)
            if (delegOther(o, anyReady))
                runC(withSess(anyReady, [ RPutfh(o), RGetattr ]))
            else
                runC(withSess(anyReady, [ RPutfh(o), RRemovexattr(n) ]))
        },
    }

    // ------------------------------------------------------------------
    // Step distributions
    // ------------------------------------------------------------------

    action stepBody = any {
        setupSetclientid,
        setupSetclientidConfirm,
        setupExchangeId,
        setupCreateSession,
        reclaimAgain,
        seqMisordered,
        destroySession,
        destroyClientid,
        nsLookup,
        nsLookupp,
        nsGetattr,
        nsAccess,
        nsReaddir,
        nsReadlink,
        nsCreate,
        nsRemove,
        nsRename,
        nsLink,
        nsSetattrMode,
        nsVerify,
        nsRenew,
        nsRestorefh,
        nsGetattrWide,
        nsSecinfo,
        nsVerifyWide,
        nsSetattrWide,
        nsBadName, nsBadName,
        nsCompoundTag, nsCompoundTag,
        nsUtf8Name, nsUtf8Name,
        nsBindConnToSession,
        nsSessionPosition,
        openNew,
        openFh,
        openConfirm,
        openDowngrade,
        closeOpen,
        openBadSeqid,
        openOddName,
        ioRead,
        ioWrite,
        ioCommit,
        ioSetattrSize,
        lockNew,
        lockExist,
        lockCheck,
        lockUnlock,
        lockFree,
        freeStateidOpen,
        lockReleaseOwner,
        delegReturn,
        pnfsLayoutget,
        pnfsLayoutreturn,
        pnfsLayoutcommit,
        pnfsDeviceinfo,
        pnfsNotsupp,
        sparseAllocate,
        sparseDeallocate,
        sparseSeek,
        copyRange,
        xattrSet,
        xattrGet,
        xattrList,
        xattrRemove,
    }

    // Open/close/lock-heavy: exercises share matrices, upgrades,
    // downgades, seqid discipline and lock splitting.
    action stepStateBody = any {
        setupSetclientid, setupSetclientidConfirm,
        setupExchangeId, setupCreateSession,
        reclaimAgain,
        openNew, openNew, openNew, openFh, openConfirm, openConfirm,
        openDowngrade, openDowngrade, closeOpen, closeOpen, openBadSeqid,
        openOddName, openOddName,
        lockNew, lockNew, lockExist, lockCheck, lockUnlock, lockUnlock,
        lockFree, freeStateidOpen, lockReleaseOwner, delegReturn,
        ioRead, ioWrite,
        nsGetattr,
    }

    // Namespace churn (the v3-style workload plus OPEN-created files).
    action stepNamespaceBody = any {
        setupSetclientid, setupSetclientidConfirm,
        setupExchangeId, setupCreateSession,
        nsCreate, nsCreate, nsRemove, nsRemove, nsRename, nsRename,
        nsLink, nsLink, openNew, closeOpen,
        nsLookup, nsLookupp, nsGetattr, nsReaddir,
        nsRestorefh, nsRenew, nsGetattrWide, nsSecinfo, nsVerifyWide,
        nsBadName, nsBadName,
        nsUtf8Name, nsUtf8Name,
        nsBindConnToSession,
    }

    // Delegation lifecycle: grants, cross-client conflicts (recall +
    // NFS4ERR_DELAY), returns and retried opens.  Both clients collide on
    // the small NAMES set, so A-holds/B-breaks sequences arise routinely;
    // delegReturn is weighted up so DELAYed victims get unblocked and the
    // retried OPEN's grant path is reached.
    // Delegation lifecycle only: grants, cross-client open/remove breaks
    // (recall + NFS4ERR_DELAY), returns and retried opens.  Data-path I/O
    // through delegated files (how cached writes and recall flushes
    // reconcile with the model's block map) is a deeper coherency layer
    // left to a follow-on; nsGetattr is the one read here, and it only
    // observes the change attribute the lifecycle already tracks.
    action stepDelegBody = any {
        setupSetclientid, setupSetclientidConfirm,
        setupExchangeId, setupCreateSession,
        delegOpenNew, delegOpenNew, delegOpenNew,
        delegBreakOpen, delegBreakOpen, delegBreakOpen,
        delegBreakRemove, delegBreakRemove,
        delegReturn, delegReturn, delegReturn, delegReturn,
        closeOpen, closeOpen,
        nsGetattr, nsGetattr,
    }

    // Data-path heavy: I/O, sparse ops, copies, layouts.
    // Deny-free OPEN for the RFC 7862 data flavor.  Share-conflict semantics
    // are stepState's subject; here a deny-mode open only drives the server
    // into a persistent NFS4ERR_DELAY on a later OPEN -- which reproduces
    // with none of the 7862 operations present, so it is pre-existing and not
    // this flavor's to chase.
    action openNoDeny = all {
        readyClients.size() > 0,
        liveInos.size() < MAX_OBJECTS,
        {
            nondet c = oneOf(readyClients)
            nondet ow = oneOf(OPEN_OWNERS)
            nondet d = oneOf(dirs)
            nondet n = oneOf(NAMES)
            nondet acc = oneOf(Set(1, 2, 3))
            nondet m = oneOf(MODES)
            runC(withSess(c,
                [ RPutfh(d),
                  ROpen({ client: c, owner: ow, oseq: oseqFor(c, ow),
                          claim: OCNull(n),
                          how: HUnchecked({ mode: m, truncate: false }),
                          access: acc, deny: 0 }),
                  RGetfh ]))
        },
    }

    // RFC 7862 data operations (READ_PLUS, IO_ADVISE, WRITE_SAME, CLONE).
    //
    // A dedicated flavor rather than an addition to stepData, for two
    // reasons.  First, stepData carries neither reclaimComplete nor nsCreate,
    // so every OPEN in it returns NFS4ERR_GRACE and `files` stays empty --
    // every data action's guard fails and the flavor generates nothing but
    // setup churn.  Second, once those are supplied the walk reaches
    // pre-existing model/server divergences in SETATTR-size and COPY that are
    // unrelated to these operations; keeping this flavor separate exercises
    // the 7862 ops without asserting on them.
    //
    // The mix deliberately builds the state these ops need: files (nsCreate),
    // opens on two files for one client (cloneOpenPair), written blocks
    // (ioWrite) and holes/unwritten extents (sparseAllocate, sparseDeallocate)
    // so READ_PLUS has both DATA and HOLE runs to classify.
    action stepData42 = any {
        setupExchangeId, setupCreateSession,
        reclaimComplete, reclaimComplete,
        nsCreate, nsCreate,
        openNoDeny, openNoDeny, cloneOpenPair, cloneOpenPair, closeOpen,
        ioWrite, ioWrite, ioRead,
        sparseReadPlus, sparseReadPlus, sparseReadPlus,
        ioAdvise, ioAdvise,
        writeSame, writeSame, writeSame,
        cloneRange, cloneRange, cloneRange,
        nsGetattr,
    }

    action stepDataBody = any {
        setupSetclientid, setupSetclientidConfirm,
        setupExchangeId, setupCreateSession,
        openNew, closeOpen,
        ioRead, ioRead, ioWrite, ioWrite, ioCommit, ioSetattrSize,
        sparseAllocate, sparseDeallocate, sparseSeek, sparseSeek,
        copyRange, copyRange,
        pnfsLayoutget, pnfsLayoutget, pnfsLayoutreturn, pnfsLayoutcommit,
        xattrSet, xattrGet, xattrList, xattrRemove,
        nsGetattr,
    }

    // Object-type matrix.  Every other flavor reaches a mistyped target only
    // at the wide() rate; here that is the whole point, so each type-gated op
    // is weighted up and the create mix (which is what makes all seven types
    // exist at once) is weighted highest.  nsRemove stays at weight 1:
    // MAX_OBJECTS is 12 and the matrix needs the types alive together.
    action stepTypesBody = any {
        setupSetclientid, setupSetclientidConfirm,
        setupExchangeId, setupCreateSession,
        nsCreate, nsCreate, nsCreate, nsCreate, nsCreate,
        nsReadlink, nsReadlink, nsReadlink,
        nsVerifyWide, nsVerifyWide,
        nsBadName,
        ioRead, ioRead, ioWrite, ioWrite, ioCommit, ioCommit,
        ioSetattrSize, ioSetattrSize, nsSetattrMode,
        lockCheck, lockCheck, lockCheck,
        nsRemove, nsRename, nsLink, openNew, closeOpen,
        nsGetattr, nsGetattrWide, nsGetattrWide,
        nsAccess, nsReaddir, nsLookup, nsLookupp,
    }

    // The public flavor names -- CMake passes these to `--step=`, so they
    // must not change.  Each is its body behind the reclaim-first wrapper:
    // under 4.1+ a ready client that still owes its RECLAIM_COMPLETE sends
    // it (or probes the grace gate with an OPEN that must fail GRACE)
    // before the flavor's real workload starts, so that workload runs
    // against a server that has left grace.  Under 4.0 there is no grace
    // window, reclaimPending is always false, and each of these is exactly
    // its body.
    action step          = if (reclaimPending) reclaimFirst else stepBody
    action stepState     = if (reclaimPending) reclaimFirst else stepStateBody
    action stepNamespace = if (reclaimPending) reclaimFirst else stepNamespaceBody
    action stepDeleg     = if (reclaimPending) reclaimFirst else stepDelegBody
    action stepData      = if (reclaimPending) reclaimFirst else stepDataBody
    action stepTypes     = if (reclaimPending) reclaimFirst else stepTypesBody

    // ------------------------------------------------------------------
    // Invariants
    // ------------------------------------------------------------------

    // Protocol state only ever references live inodes (unlinked-but-open
    // files stay alive as orphans until their last pin drops).
    val statePinsLive = pinnedInos(sdb).forall(f => fsLive(fs, f))

    // An orphan (nlink 0) is always pinned by some state.
    val orphansPinned =
        fsNonDirs(fs).forall(f =>
            fs.inodes.get(f).nlink > 0 or pinnedInos(sdb).contains(f))

    // 4.1+ configurations never create 4.0 owner-seqid state and
    // vice-versa sessions never exist under 4.0.
    val minorSeparation =
        (MINOR >= 1 or sdb.sessions.keys().size() == 0) and
        (MINOR == 0 or sdb.oo40.keys().size() == 0)

    // Capability gating: no pNFS/xattr/4.2 state or results can exist when
    // the capability is off.
    val capsRespected =
        (caps.pnfs or sdb.layouts.keys().size() == 0)

    // Named aliases so `quint run --invariant=...` can bisect a violation
    // from the instance modules (imports are not re-exported).
    val invFs = fsInv(fs)
    val invSdb = sdbInv(sdb)

    val inv = invFs and invSdb and statePinsLive and
              orphansPinned and minorSeparation and capsRespected
}
