// SPDX-FileCopyrightText: 2026 The Quint Specs Authors
//
// SPDX-License-Identifier: MIT

// Deterministic self-checks for the nfsaux model, executed with
//   quint test nfsauxTest.qnt --main=nfsauxTestRef
//   quint test nfsauxTest.qnt --main=nfsauxTestFull
//
// They pin the model's own transition logic without a server, so a model
// regression is caught before it can invalidate generated traces.  The two
// instances differ only in configuration, which is the point: the same
// procedure is expected to answer PROC_UNAVAIL under one profile and to
// implement its RFC semantics under the other.

// =====================================================================
// The reference profile: a minimal embedded portmapper, full MOUNT / NLM
// / NSM, no lock state across a restart.
// =====================================================================
module nfsauxTestRef {
    import portmapProto.* from "./aux_portmap"
    import mountProto.* from "./aux_mount"
    import nlmProto.* from "./aux_nlm"
    import nsmProto.* from "./aux_nsm"
    import nfsauxProfiles.* from "./nfsaux_run"

    import nfsaux(
        IMPLEMENTED = PORTMAP_MINIMAL
            .union(MOUNT_PROCS)
            .union(NLM_PROCS)
            .union(NSM_PROCS),
        SERVICES = NFS_SERVICES,
        UADDR_HOST = "127.0.0.1",
        PM_SET_MUTATES = false,
        EXPORTS = TWO_EXPORTS,
        PATHS = NFS_PATHS,
        MOUNT_HOST = "inproc",
        NSM_MON_FROM_LOCKS = true,
        NSM_ADDRS_DISTINCT = false,
        NSM_INITIAL_STATE = 1,
        NLM_UPGRADE_IS_NOOP = true,
        NLM_SHARE_ENFORCED = false,
        NLM_IN_GRACE = false,
        NLM_BLOCKING = true,
        NLM_GRANT_CALLBACK_OBSERVABLE = false,
        NLM_CANCEL_MSG_CANCELS = true
    ).* from "./nfsaux"

    // ---- shorthand for the lock shapes the tests use -----------------
    def ownerA: Owner = { caller: "c1", oh: 1, svid: 1 }
    def ownerA2: Owner = { caller: "c1", oh: 1, svid: 2 }
    def ownerB: Owner = { caller: "c2", oh: 1, svid: 1 }

    def lk(o: Owner, off: int, len: int, x: bool): Lock =
        { file: 0, owner: o, offset: off, wireLen: len, excl: x }

    def lkOn(f: int, o: Owner, off: int, len: int, x: bool): Lock =
        { file: f, owner: o, offset: off, wireLen: len, excl: x }

    // ------------------------------------------------------------------
    // portmap: what the minimal profile answers, and what it refuses
    // ------------------------------------------------------------------

    /// GETPORT matches the exact (prog, vers, prot) triple or returns 0.
    /// The last clause is the property that distinguishes RFC 1833 from
    /// classic BSD portmap, which would fall back to a sibling version.
    run getportExactTest =
        init
            .then(pmGetport(100003, 3, PROT_TCP))
            .expect(lastOp == OPmGetport({ prog: 100003, vers: 3,
                                           prot: PROT_TCP,
                                           reply: RPort(2049) }))
            .then(pmGetport(100021, 4, PROT_TCP))
            .expect(lastOp == OPmGetport({ prog: 100021, vers: 4,
                                           prot: PROT_TCP,
                                           reply: RPort(32803) }))
            .then(pmGetport(100003, 3, PROT_UDP))
            .expect(lastOp == OPmGetport({ prog: 100003, vers: 3,
                                           prot: PROT_UDP,
                                           reply: RPort(0) }))
            .then(pmGetport(100003, 2, PROT_TCP))
            .expect(lastOp == OPmGetport({ prog: 100003, vers: 2,
                                           prot: PROT_TCP,
                                           reply: RPort(0) }))

    /// GETADDR is GETPORT with the transport named by a netid; an
    /// unrecognised netid is unserved, not an error.
    run getaddrTest =
        init
            .then(rbGetaddr(3, 100005, 3, NetTcp))
            .expect(lastOp == ORbGetaddr({ rbvers: 3, prog: 100005, vers: 3,
                                           netid: NetTcp,
                                           reply: RUaddr({ host: "127.0.0.1",
                                                           port: 20048 }) }))
            .then(rbGetaddr(4, 100003, 3, NetTcp6))
            .expect(lastOp == ORbGetaddr({ rbvers: 4, prog: 100003, vers: 3,
                                           netid: NetTcp6,
                                           reply: RUaddr({ host: "",
                                                           port: 0 }) }))

    /// DUMP returns the table verbatim, order included.
    run dumpTest =
        init
            .then(pmDump)
            .expect(lastOp == OPmDump({ reply: RMaps(NFS_SERVICES) }))
            .then(rbDump(4))
            .expect(lastOp == ORbDump({ rbvers: 4,
                                        reply: RMaps(NFS_SERVICES) }))

    /// The registration and utility procedures this profile does not
    /// register are still called; the expected answer is the refusal, and
    /// the table is untouched.
    run portmapUnimplementedTest =
        init
            .then(pmSet(false, { prog: 300000, vers: 1, prot: PROT_TCP,
                                 port: 4242 }))
            .expect(lastOp == OPmSet({ unset: false,
                                       map: { prog: 300000, vers: 1,
                                              prot: PROT_TCP, port: 4242 },
                                       reply: RUnavail }))
            .expect(services == NFS_SERVICES)
            .then(pmGetport(300000, 1, PROT_TCP))
            .expect(lastOp == OPmGetport({ prog: 300000, vers: 1,
                                           prot: PROT_TCP,
                                           reply: RPort(0) }))
            .then(rbGettime(4))
            .expect(lastOp == ORbGettime({ rbvers: 4, reply: RUnavail }))
            .then(pmCallit(100003, 3, 0))
            .expect(lastOp == OPmCallit({ prog: 100003, vers: 3, cproc: 0,
                                          reply: RUnavail }))

    // ------------------------------------------------------------------
    // MOUNT
    // ------------------------------------------------------------------

    /// Export resolution: exact name, name without the leading slash, a
    /// longer name that must not be shadowed by a shorter one, a name that
    /// matches only as a string prefix, and no match at all.
    run mntResolutionTest =
        init
            .then(mnt("/share"))
            .expect(lastOp == OMnt({ path: "/share",
                                     reply: RMntOk(DEFAULT_FLAVORS) }))
            .then(mnt("share"))
            .expect(lastOp == OMnt({ path: "share",
                                     reply: RMntOk(DEFAULT_FLAVORS) }))
            .then(mnt("/share2"))
            .expect(lastOp == OMnt({ path: "/share2",
                                     reply: RMntOk(DEFAULT_FLAVORS) }))
            .then(mnt("/shareXX"))
            .expect(lastOp == OMnt({ path: "/shareXX",
                                     reply: RMntErr(MNT3ERR_NOENT) }))
            .then(mnt("/nope"))
            .expect(lastOp == OMnt({ path: "/nope",
                                     reply: RMntErr(MNT3ERR_NOENT) }))
            /* The walk reached f0 and could not descend into it. */
            .then(mnt("/share/f0/x"))
            .expect(lastOp == OMnt({ path: "/share/f0/x",
                                     reply: RMntErr(MNT3ERR_NOTDIR) }))
            /* ...but f0 itself mounts: MNT does not type-check the object. */
            .then(mnt("/share/f0"))
            .expect(lastOp == OMnt({ path: "/share/f0",
                                     reply: RMntOk(DEFAULT_FLAVORS) }))

    /// A MNT that fails because the path under the export does not exist
    /// STILL records a mount-table row; one that matches no export does
    /// not.  DUMP reports the table most-recent-first.
    run mntRecordsOnFailureTest =
        init
            .then(mnt("/share"))
            .then(mnt("/nope"))
            .then(mnt("/share/nope"))
            .expect(lastOp == OMnt({ path: "/share/nope",
                                     reply: RMntErr(MNT3ERR_NOENT) }))
            .then(mntDump)
            .expect(lastOp == OMntDump({
                reply: RMountTab(List({ host: "inproc", dir: "/share/nope" },
                                      { host: "inproc", dir: "/share" }))
            }))

    /// A repeat mount neither duplicates the row nor moves it.
    run mntIdempotentTest =
        init
            .then(mnt("/share"))
            .then(mnt("/share2"))
            .then(mnt("/share"))
            .then(mntDump)
            .expect(lastOp == OMntDump({
                reply: RMountTab(List({ host: "inproc", dir: "/share2" },
                                      { host: "inproc", dir: "/share" }))
            }))

    /// UMNT drops one row, UMNTALL the lot.
    run umntTest =
        init
            .then(mnt("/share"))
            .then(mnt("/share2"))
            .then(mntUmnt("/share2"))
            .then(mntDump)
            .expect(lastOp == OMntDump({
                reply: RMountTab(List({ host: "inproc", dir: "/share" }))
            }))
            .then(mntUmntAll)
            .then(mntDump)
            .expect(lastOp == OMntDump({ reply: RMountTab(List()) }))

    run exportListTest =
        init
            .then(mntExport)
            .expect(lastOp == OMntExport({
                reply: RExports(List("/share2", "/share"))
            }))

    // ------------------------------------------------------------------
    // NLM: byte-range locking
    // ------------------------------------------------------------------

    /// The basic conflict matrix: shared/shared coexists, anything with an
    /// exclusive side conflicts, and disjoint ranges never do.
    run lockConflictTest =
        init
            .then(nlmLock(2, lk(ownerA, 0, 16, true), false, false))
            .expect(lastOp == ONlmLock({ nproc: 2,
                                         lock: lk(ownerA, 0, 16, true),
                                         block: false, reclaim: false,
                                         asyncs: List(),
                                         reply: RNlm(NLM4_GRANTED) }))
            .then(nlmLock(2, lk(ownerB, 8, 16, true), false, false))
            .expect(lastOp == ONlmLock({ nproc: 2,
                                         lock: lk(ownerB, 8, 16, true),
                                         block: false, reclaim: false,
                                         asyncs: List(),
                                         reply: RNlm(NLM4_DENIED) }))
            .then(nlmLock(2, lk(ownerB, 16, 8, true), false, false))
            .expect(lastOp == ONlmLock({ nproc: 2,
                                         lock: lk(ownerB, 16, 8, true),
                                         block: false, reclaim: false,
                                         asyncs: List(),
                                         reply: RNlm(NLM4_GRANTED) }))

    run sharedLocksCoexistTest =
        init
            .then(nlmLock(2, lk(ownerA, 0, 16, false), false, false))
            .then(nlmLock(2, lk(ownerB, 0, 16, false), false, false))
            .expect(lastOp == ONlmLock({ nproc: 2,
                                         lock: lk(ownerB, 0, 16, false),
                                         block: false, reclaim: false,
                                         asyncs: List(),
                                         reply: RNlm(NLM4_GRANTED) }))
            .then(nlmLock(2, lkOn(0, { caller: "c2", oh: 2, svid: 2 },
                                  0, 16, true), false, false))
            .expect(lastOp == ONlmLock({
                nproc: 2,
                lock: lkOn(0, { caller: "c2", oh: 2, svid: 2 }, 0, 16, true),
                block: false, reclaim: false,
                asyncs: List(),
                reply: RNlm(NLM4_DENIED) }))

    /// The svid is part of the owner identity: two processes on one client
    /// with one owner handle are still two owners.
    run svidIsPartOfOwnerTest =
        init
            .then(nlmLock(2, lk(ownerA, 0, 16, true), false, false))
            .then(nlmLock(2, lk(ownerA2, 0, 16, true), false, false))
            .expect(lastOp == ONlmLock({ nproc: 2,
                                         lock: lk(ownerA2, 0, 16, true),
                                         block: false, reclaim: false,
                                         asyncs: List(),
                                         reply: RNlm(NLM4_DENIED) }))

    /// Under this profile a re-LOCK of a range the owner already holds is
    /// an idempotent retry, mode included: an upgrade request is answered
    /// GRANTED and changes nothing, so the shared lock still stands and a
    /// third party's exclusive request is still denied rather than
    /// blocked behind an exclusive.
    run upgradeIsNoopTest =
        init
            .then(nlmLock(2, lk(ownerA, 0, 16, false), false, false))
            .then(nlmLock(2, lk(ownerA, 0, 16, true), false, false))
            .expect(lastOp == ONlmLock({ nproc: 2,
                                         lock: lk(ownerA, 0, 16, true),
                                         block: false, reclaim: false,
                                         asyncs: List(),
                                         reply: RNlm(NLM4_GRANTED) }))
            .expect(held.length() == 1)
            .expect(held[0].excl == false)

    /// Both wire spellings of to-EOF mean the same range, so a lock taken
    /// with one is released by the other.
    run eofLengthEquivalenceTest =
        init
            .then(nlmLock(2, lk(ownerA, 0, 0, true), false, false))
            .expect(held.length() == 1)
            .then(nlmLock(2, lk(ownerB, 16, 8, true), false, false))
            .expect(lastOp == ONlmLock({ nproc: 2,
                                         lock: lk(ownerB, 16, 8, true),
                                         block: false, reclaim: false,
                                         asyncs: List(),
                                         reply: RNlm(NLM4_DENIED) }))
            .then(nlmUnlock(false, lk(ownerA, 0, EOF_LEN, true)))
            .expect(held.length() == 0)

    /// UNLOCK answers GRANTED whether or not it found anything.
    run unlockAlwaysGrantedTest =
        init
            .then(nlmUnlock(false, lk(ownerA, 0, 16, true)))
            .expect(lastOp == ONlmUnlock({ msg: false,
                                           lock: lk(ownerA, 0, 16, true),
                                           granted: List(), asyncs: List(),
                                           reply: RNlm(NLM4_GRANTED) }))

    /// A handle the server cannot decode is STALE_FH, and nothing is
    /// recorded for it.
    run staleHandleTest =
        init
            .then(nlmLock(2, lkOn(STALE_FILE, ownerA, 0, 16, true), false,
                          false))
            .expect(lastOp == ONlmLock({
                nproc: 2, lock: lkOn(STALE_FILE, ownerA, 0, 16, true),
                block: false, reclaim: false,
                asyncs: List(),
                reply: RNlm(NLM4_STALE_FH) }))
            .expect(held.length() == 0)
            .then(nlmTestOp(false, lkOn(STALE_FILE, ownerA, 0, 16, true)))
            .expect(lastOp == ONlmTestOp({
                msg: false, lock: lkOn(STALE_FILE, ownerA, 0, 16, true),
                asyncs: List(),
                reply: RNlmTestRes({ stat: NLM4_STALE_FH,
                                  holders: List() }) }))

    /// TEST reports the conflicting holder; with one conflict the
    /// candidate set has exactly one member.
    run testReportsHolderTest =
        init
            .then(nlmLock(2, lk(ownerA, 0, 16, true), false, false))
            .then(nlmTestOp(false, lk(ownerB, 8, 8, true)))
            .expect(lastOp == ONlmTestOp({
                msg: false, lock: lk(ownerB, 8, 8, true),
                asyncs: List(),
                reply: RNlmTestRes({ stat: NLM4_DENIED,
                                  holders: List(lk(ownerA, 0, 16,
                                                   true)) }) }))

    /// A blocking LOCK over a held range is queued and answered with the
    /// interim BLOCKED; releasing the blocker promotes it.
    run blockingLockTest =
        init
            .then(nlmLock(2, lk(ownerA, 0, 16, true), false, false))
            .then(nlmLock(2, lk(ownerB, 0, 16, true), true, false))
            .expect(lastOp == ONlmLock({ nproc: 2,
                                         lock: lk(ownerB, 0, 16, true),
                                         block: true, reclaim: false,
                                         asyncs: List(),
                                         reply: RNlm(NLM4_BLOCKED) }))
            .expect(queue.length() == 1)
            .then(nlmUnlock(false, lk(ownerA, 0, 16, true)))
            .expect(queue.length() == 0)
            .expect(held == List(lk(ownerB, 0, 16, true)))
            .then(nlmTestOp(false, lk(ownerA, 0, 16, true)))
            .expect(lastOp == ONlmTestOp({
                msg: false, lock: lk(ownerA, 0, 16, true),
                asyncs: List(),
                reply: RNlmTestRes({ stat: NLM4_DENIED,
                                  holders: List(lk(ownerB, 0, 16,
                                                   true)) }) }))

    /// CANCEL withdraws a queued request, so releasing the blocker no
    /// longer grants it.
    run cancelBlockedTest =
        init
            .then(nlmLock(2, lk(ownerA, 0, 16, true), false, false))
            .then(nlmLock(2, lk(ownerB, 0, 16, true), true, false))
            .expect(queue.length() == 1)
            .then(nlmCancel(false, lk(ownerB, 0, 16, true)))
            .expect(lastOp == ONlmCancel({ msg: false,
                                           lock: lk(ownerB, 0, 16, true),
                                           asyncs: List(),
                                           reply: RNlm(NLM4_GRANTED) }))
            .expect(queue.length() == 0)
            .then(nlmUnlock(false, lk(ownerA, 0, 16, true)))
            .expect(held.length() == 0)

    /// The asynchronous half: a *_MSG is acknowledged with a void reply and
    /// the result comes back as the matching *_RES.
    run asyncMsgTest =
        init
            .then(nlmLock(7, lk(ownerA, 0, 16, true), false, false))
            .expect(lastOp == ONlmLock({ nproc: 7,
                                         lock: lk(ownerA, 0, 16, true),
                                         block: false, reclaim: false,
                                         asyncs: List({ proc: 12,
                                                        stat: NLM4_GRANTED }),
                                         reply: RVoid }))
            .expect(held.length() == 1)
            .then(nlmTestOp(true, lk(ownerB, 0, 16, true)))
            .expect(lastOp == ONlmTestOp({
                msg: true, lock: lk(ownerB, 0, 16, true),
                asyncs: List({ proc: 11, stat: NLM4_DENIED }),
                reply: RVoid }))
            .then(nlmGranted(true, lk(ownerA, 0, 16, true)))
            .expect(lastOp == ONlmGranted({
                msg: true, lock: lk(ownerA, 0, 16, true),
                asyncs: List(), reply: RVoid }))

    /// Cancelling a queued asynchronous LOCK produces TWO messages: the
    /// CANCEL_RES that answers the cancel, and a final LOCK_RES telling the
    /// client its blocked request is gone.  A queued SYNCHRONOUS LOCK gets
    /// only the first: its RPC completed when the interim BLOCKED went out,
    /// so there is nothing left to answer on.
    run cancelOfAsyncLockTest =
        init
            .then(nlmLock(2, lk(ownerA, 0, 16, true), false, false))
            .then(nlmLock(7, lk(ownerB, 0, 16, true), true, false))
            .expect(queue.length() == 1)
            .then(nlmCancel(true, lk(ownerB, 0, 16, true)))
            .expect(lastOp == ONlmCancel({
                msg: true, lock: lk(ownerB, 0, 16, true),
                asyncs: List({ proc: 13, stat: NLM4_GRANTED },
                             { proc: 12, stat: NLM4_DENIED }),
                reply: RVoid }))
            .expect(queue.length() == 0)

    /// NM_LOCK takes the lock without putting its holder on the monitor
    /// list; a plain LOCK does both.
    run nmLockIsUnmonitoredTest =
        init
            .then(nlmLock(22, lk(ownerA, 0, 16, true), false, false))
            .expect(held.length() == 1)
            .expect(monitors == Set())
            .then(nlmLock(2, lkOn(1, ownerB, 0, 16, true), false, false))
            .expect(monitors == Set("c2"))

    /// FREE_ALL drops one client's locks, shares and monitor entry, and
    /// lets anything queued behind them through.
    run freeAllTest =
        init
            .then(nlmLock(2, lk(ownerA, 0, 16, true), false, false))
            .then(nlmLock(2, lkOn(1, ownerA, 0, 16, true), false, false))
            .then(nlmLock(2, lk(ownerB, 0, 16, true), true, false))
            .expect(queue.length() == 1)
            .then(nlmFreeAll("c1"))
            .expect(held == List(lk(ownerB, 0, 16, true)))
            .expect(queue.length() == 0)
            /* c2's lock was queued, not granted, when it was requested, so
             * c2 joined the monitor list only when the queue promoted it. */
            .expect(monitors == Set("c2"))

    /// SHARE is accepted without enforcement under this profile: a
    /// deny-all reservation does not stop the next one.
    run shareNotEnforcedTest =
        init
            .then(nlmShare(false, { file: 0, caller: "c1", oh: 1,
                                    mode: FSM_DRW, access: FSA_RW }))
            .expect(lastOp == ONlmShare({
                unshare: false,
                share: { file: 0, caller: "c1", oh: 1, mode: FSM_DRW,
                         access: FSA_RW },
                reply: RNlmShare({ stat: NLM4_GRANTED, sequence: 0 }) }))
            .then(nlmShare(false, { file: 0, caller: "c2", oh: 1,
                                    mode: FSM_DN, access: FSA_RW }))
            .expect(lastOp == ONlmShare({
                unshare: false,
                share: { file: 0, caller: "c2", oh: 1, mode: FSM_DN,
                         access: FSA_RW },
                reply: RNlmShare({ stat: NLM4_GRANTED, sequence: 0 }) }))

    // ------------------------------------------------------------------
    // NSM
    // ------------------------------------------------------------------

    /// Every reply carries the state number, and SIMU_CRASH advances it to
    /// the next odd value.
    run nsmStateTest =
        init
            .then(smStat("c1"))
            .expect(lastOp == OSmStat({ host: "c1",
                                        reply: RSmStatRes({ res: STAT_SUCC,
                                                            state: 1 }) }))
            .then(smSimuCrash)
            .expect(nsmState == 3)
            .then(smSimuCrash)
            .expect(nsmState == 5)
            .then(smStat("c1"))
            .expect(lastOp == OSmStat({ host: "c1",
                                        reply: RSmStatRes({ res: STAT_SUCC,
                                                            state: 5 }) }))

    /// Under this profile the monitor list is fed by lock grants, so
    /// SM_MON changes nothing.
    run monFromLocksTest =
        init
            .then(smMon("c1"))
            .expect(monitors == Set())
            .then(nlmLock(2, lk(ownerA, 0, 16, true), false, false))
            .expect(monitors == Set("c1"))
            .then(smUnmon("c1"))
            .expect(monitors == Set())

    /// SM_NOTIFY naming a host NLM knows drops exactly that host's locks.
    run notifyExactMatchTest =
        init
            .then(nlmLock(2, lk(ownerA, 0, 16, true), false, false))
            .then(nlmLock(2, lkOn(1, ownerB, 0, 16, true), false, false))
            .then(smNotify("c1", 7))
            .expect(held == List(lkOn(1, ownerB, 0, 16, true)))
            .expect(monitors == Set("c2"))

    /// A name NLM has never seen falls back to matching by source address.
    /// With one address for every peer -- a single-transport harness, or
    /// clients behind one NAT -- that match is indiscriminate: one
    /// stranger's notify drops every monitored host's locks.
    run notifyAddressFallbackTest =
        init
            .then(nlmLock(2, lk(ownerA, 0, 16, true), false, false))
            .then(nlmLock(2, lkOn(1, ownerB, 0, 16, true), false, false))
            .expect(monitors == Set("c1", "c2"))
            .then(smNotify(STRANGER, 9))
            .expect(held == List())
            .expect(monitors == Set())

    /// A client whose locks are all gone is still a client, so a notify
    /// for its name takes the exact-match path and leaves everyone else
    /// alone.
    run knownClientOutlivesItsLocksTest =
        init
            .then(nlmLock(2, lk(ownerA, 0, 16, true), false, false))
            .then(nlmUnlock(false, lk(ownerA, 0, 16, true)))
            .then(nlmLock(2, lkOn(1, ownerB, 0, 16, true), false, false))
            .then(smNotify("c1", 7))
            .expect(held == List(lkOn(1, ownerB, 0, 16, true)))
}

// =====================================================================
// The everything-implemented profile: the RFC semantics of the
// procedures the reference profile refuses.
// =====================================================================
module nfsauxTestFull {
    import portmapProto.* from "./aux_portmap"
    import mountProto.* from "./aux_mount"
    import nlmProto.* from "./aux_nlm"
    import nsmProto.* from "./aux_nsm"
    import nfsauxProfiles.* from "./nfsaux_run"

    import nfsaux(
        IMPLEMENTED = PORTMAP_PROCS
            .union(MOUNT_PROCS)
            .union(NLM_PROCS)
            .union(NSM_PROCS),
        SERVICES = NFS_SERVICES,
        UADDR_HOST = "127.0.0.1",
        PM_SET_MUTATES = true,
        EXPORTS = TWO_EXPORTS,
        PATHS = NFS_PATHS,
        MOUNT_HOST = "client",
        NSM_MON_FROM_LOCKS = false,
        NSM_ADDRS_DISTINCT = true,
        NSM_INITIAL_STATE = 1,
        NLM_UPGRADE_IS_NOOP = false,
        NLM_SHARE_ENFORCED = true,
        NLM_IN_GRACE = false,
        NLM_BLOCKING = true,
        NLM_GRANT_CALLBACK_OBSERVABLE = true,
        NLM_CANCEL_MSG_CANCELS = true
    ).* from "./nfsaux"

    def ownerA: Owner = { caller: "c1", oh: 1, svid: 1 }
    def ownerB: Owner = { caller: "c2", oh: 1, svid: 1 }

    def lk(o: Owner, off: int, len: int, x: bool): Lock =
        { file: 0, owner: o, offset: off, wireLen: len, excl: x }

    /// SET registers a new triple and returns TRUE; a second SET of the
    /// same triple changes nothing and returns FALSE; registering port 0
    /// is refused.
    run registrySetTest =
        init
            .then(pmSet(false, { prog: 300000, vers: 1, prot: PROT_TCP,
                                 port: 4242 }))
            .expect(lastOp == OPmSet({ unset: false,
                                       map: { prog: 300000, vers: 1,
                                              prot: PROT_TCP, port: 4242 },
                                       reply: RBool(true) }))
            .then(pmGetport(300000, 1, PROT_TCP))
            .expect(lastOp == OPmGetport({ prog: 300000, vers: 1,
                                           prot: PROT_TCP,
                                           reply: RPort(4242) }))
            .then(pmSet(false, { prog: 300000, vers: 1, prot: PROT_TCP,
                                 port: 4243 }))
            .expect(lastOp == OPmSet({ unset: false,
                                       map: { prog: 300000, vers: 1,
                                              prot: PROT_TCP, port: 4243 },
                                       reply: RBool(false) }))
            .then(pmGetport(300000, 1, PROT_TCP))
            .expect(lastOp == OPmGetport({ prog: 300000, vers: 1,
                                           prot: PROT_TCP,
                                           reply: RPort(4242) }))

    /// UNSET removes every transport of a (prog, vers) and reports whether
    /// anything went.
    run registryUnsetTest =
        init
            .then(pmSet(true, { prog: 100003, vers: 3, prot: PROT_TCP,
                                port: 0 }))
            .expect(lastOp == OPmSet({ unset: true,
                                       map: { prog: 100003, vers: 3,
                                              prot: PROT_TCP, port: 0 },
                                       reply: RBool(true) }))
            .then(pmGetport(100003, 3, PROT_TCP))
            .expect(lastOp == OPmGetport({ prog: 100003, vers: 3,
                                           prot: PROT_TCP,
                                           reply: RPort(0) }))
            .then(pmSet(true, { prog: 100003, vers: 3, prot: PROT_TCP,
                                port: 0 }))
            .expect(lastOp == OPmSet({ unset: true,
                                       map: { prog: 100003, vers: 3,
                                              prot: PROT_TCP, port: 0 },
                                       reply: RBool(false) }))

    /// The utility procedures answer rather than refusing here.
    run utilityProcsImplementedTest =
        init
            .then(rbGettime(3))
            .expect(lastOp == ORbGettime({ rbvers: 3, reply: RPort(0) }))
            .then(rbGetversaddr(100005, 3, NetTcp))
            .expect(lastOp == ORbGetversaddr({
                prog: 100005, vers: 3, netid: NetTcp,
                reply: RUaddr({ host: "127.0.0.1", port: 20048 }) }))

    /// With upgrades re-evaluated rather than short-circuited, a
    /// shared-to-exclusive upgrade over another owner's shared lock is a
    /// genuine conflict.
    run upgradeIsEvaluatedTest =
        init
            .then(nlmLock(2, lk(ownerA, 0, 16, false), false, false))
            .then(nlmLock(2, lk(ownerB, 0, 16, false), false, false))
            .then(nlmLock(2, lk(ownerA, 0, 16, true), false, false))
            .expect(lastOp == ONlmLock({ nproc: 2,
                                         lock: lk(ownerA, 0, 16, true),
                                         block: false, reclaim: false,
                                         asyncs: List(),
                                         reply: RNlm(NLM4_DENIED) }))

    /// Enforced share reservations: a deny-write holder blocks a writer,
    /// and UNSHARE lets it through.
    run shareEnforcedTest =
        init
            .then(nlmShare(false, { file: 0, caller: "c1", oh: 1,
                                    mode: FSM_DW, access: FSA_R }))
            .expect(lastOp == ONlmShare({
                unshare: false,
                share: { file: 0, caller: "c1", oh: 1, mode: FSM_DW,
                         access: FSA_R },
                reply: RNlmShare({ stat: NLM4_GRANTED, sequence: 0 }) }))
            .then(nlmShare(false, { file: 0, caller: "c2", oh: 1,
                                    mode: FSM_DN, access: FSA_W }))
            .expect(lastOp == ONlmShare({
                unshare: false,
                share: { file: 0, caller: "c2", oh: 1, mode: FSM_DN,
                         access: FSA_W },
                reply: RNlmShare({ stat: NLM4_DENIED, sequence: 0 }) }))
            .then(nlmShare(true, { file: 0, caller: "c1", oh: 1,
                                   mode: FSM_DW, access: FSA_R }))
            .then(nlmShare(false, { file: 0, caller: "c2", oh: 1,
                                    mode: FSM_DN, access: FSA_W }))
            .expect(lastOp == ONlmShare({
                unshare: false,
                share: { file: 0, caller: "c2", oh: 1, mode: FSM_DN,
                         access: FSA_W },
                reply: RNlmShare({ stat: NLM4_GRANTED, sequence: 0 }) }))

    /// SM_MON builds the monitor list here, and SM_UNMON_ALL clears the
    /// caller's own entry.
    run monFromSmMonTest =
        init
            .then(smMon("c1"))
            .expect(monitors == Set("c1"))
            .then(smMon("c2"))
            .expect(monitors == Set("c1", "c2"))
            .then(smUnmonAll("c1"))
            .expect(monitors == Set("c2"))

    /// With peers distinguishable by address, a notify for a name nobody
    /// holds locks under matches nothing.
    run notifyNoFallbackTest =
        init
            .then(smMon("c1"))
            .then(nlmLock(2, lk(ownerA, 0, 16, true), false, false))
            .then(smNotify(STRANGER, 9))
            .expect(held == List(lk(ownerA, 0, 16, true)))
            .expect(monitors == Set("c1"))
}

// =====================================================================
// The grace-window profile.
// =====================================================================
module nfsauxTestGrace {
    import portmapProto.* from "./aux_portmap"
    import mountProto.* from "./aux_mount"
    import nlmProto.* from "./aux_nlm"
    import nsmProto.* from "./aux_nsm"
    import nfsauxProfiles.* from "./nfsaux_run"

    import nfsaux(
        IMPLEMENTED = PORTMAP_MINIMAL
            .union(MOUNT_PROCS)
            .union(NLM_PROCS)
            .union(NSM_PROCS),
        SERVICES = NFS_SERVICES,
        UADDR_HOST = "127.0.0.1",
        PM_SET_MUTATES = false,
        EXPORTS = TWO_EXPORTS,
        PATHS = NFS_PATHS,
        MOUNT_HOST = "inproc",
        NSM_MON_FROM_LOCKS = true,
        NSM_ADDRS_DISTINCT = false,
        NSM_INITIAL_STATE = 1,
        NLM_UPGRADE_IS_NOOP = true,
        NLM_SHARE_ENFORCED = false,
        NLM_IN_GRACE = true,
        NLM_BLOCKING = false,
        NLM_GRANT_CALLBACK_OBSERVABLE = false,
        NLM_CANCEL_MSG_CANCELS = true
    ).* from "./nfsaux"

    def ownerA: Owner = { caller: "c1", oh: 1, svid: 1 }

    def lk(o: Owner, off: int, len: int, x: bool): Lock =
        { file: 0, owner: o, offset: off, wireLen: len, excl: x }

    /// During the grace window only reclaim requests are admitted; a fresh
    /// lock is refused with DENIED_GRACE_PERIOD, which is distinct from an
    /// ordinary conflict so the client knows to retry rather than give up.
    run graceRefusesFreshLocksTest =
        init
            .then(nlmLock(2, lk(ownerA, 0, 16, true), false, false))
            .expect(lastOp == ONlmLock({
                nproc: 2, lock: lk(ownerA, 0, 16, true), block: false,
                reclaim: false,
                asyncs: List(),
                reply: RNlm(NLM4_DENIED_GRACE_PERIOD) }))
            .expect(held.length() == 0)
            .then(nlmLock(2, lk(ownerA, 0, 16, true), false, true))
            .expect(lastOp == ONlmLock({
                nproc: 2, lock: lk(ownerA, 0, 16, true), block: false,
                reclaim: true, asyncs: List(),
                reply: RNlm(NLM4_GRANTED) }))
            .expect(held.length() == 1)
}
