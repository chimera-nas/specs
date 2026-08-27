// SPDX-FileCopyrightText: 2026 The Quint Specs Authors
//
// SPDX-License-Identifier: MIT

/**
 * nfsaux.qnt -- the four protocols that surround NFSv3, composed into one
 * model: portmap/rpcbind (100000 v2/v3/v4), MOUNT (100005 v3), NLM
 * (100021 v4) and NSM (100024 v1).
 *
 * They are modeled together rather than separately because they are not
 * independent.  A granted NLM lock puts its holder on the NSM monitor list;
 * an SM_NOTIFY drops that holder's locks; NLMPROC4_FREE_ALL does both at
 * once; and the portmapper is how a client finds the lock manager in the
 * first place.  A trace that can move between them exercises those seams,
 * which is where the interesting behaviour lives.
 *
 * Each protocol's semantics live in its own module (aux_portmap.qnt,
 * aux_mount.qnt, aux_nlm.qnt, aux_nsm.qnt), each complete with respect to
 * its RFC.  This module holds the state, the transition relation, and the
 * CONFIGURATION that narrows the full protocols down to one server:
 *
 *   - IMPLEMENTED names the procedures the server under test registers.  A
 *     procedure outside it is still called by the traces -- the expected
 *     reply simply becomes the RPC layer's PROC_UNAVAIL instead of the
 *     protocol's own result.  Nothing is dropped from the corpus for being
 *     unimplemented; the refusal is itself under test.
 *   - the rest are behavioural choices where more than one answer is
 *     legitimate (see each const).  A trace is generated against one
 *     profile and must only be replayed against a server matching it.
 *
 * Every step is one RPC.  `lastOp` records the call and the reply the
 * server must produce; the replay harness compares them field by field.
 */
module nfsaux {

    import portmapProto.* from "./aux_portmap"
    import mountProto.* from "./aux_mount"
    import nlmProto.* from "./aux_nlm"
    import nsmProto.* from "./aux_nsm"

    // ==================================================================
    // Configuration
    // ==================================================================

    /// The procedures the server registers.  Anything else answers
    /// PROC_UNAVAIL (RFC 5531 accept_stat 3).
    const IMPLEMENTED: Set[str]

    /// The portmap service table the server publishes at startup.
    const SERVICES: List[Mapping]

    /// The host half of the universal addresses rpcbind reports.
    const UADDR_HOST: str

    /// Whether PMAPPROC_SET/UNSET mutate the registry.  A server that
    /// publishes a fixed table does not register them at all (they fall
    /// outside IMPLEMENTED); one that does register them may still refuse
    /// to mutate.  Only meaningful when they are implemented.
    const PM_SET_MUTATES: bool

    /// The export list, in the order the server reports it.
    const EXPORTS: List[Export]

    /// Every path the traces may present to MOUNTPROC3_MNT, mapped to how
    /// it resolves.  The universe is closed because Quint cannot do string
    /// surgery; the resolution rules it encodes (component-boundary match,
    /// optional leading slash, "/" as a catch-all) are what the scenario
    /// tests and the live replay check.
    const PATHS: str -> Resolution

    /// The hostname the server records in the mount table for the replay
    /// client.  Derived from the connection's peer address, so it is a
    /// property of the harness's transport, not of the protocol.
    const MOUNT_HOST: str

    /// Whether the NSM monitor list is fed by SM_MON (the classic statd) or
    /// by NLM lock grants (a server that monitors its own lock holders --
    /// real NFS clients SM_MON their own local statd, not the server's).
    const NSM_MON_FROM_LOCKS: bool

    /// Whether monitored peers are distinguishable by source address.  When
    /// they are not, SM_NOTIFY's fallback match is indiscriminate; see
    /// notifyMatches in aux_nsm.qnt.
    const NSM_ADDRS_DISTINCT: bool

    /// The state number a freshly started server reports.
    const NSM_INITIAL_STATE: int

    /// Whether a LOCK naming a range its own owner already holds is
    /// answered as an idempotent retry without re-evaluating the mode (so a
    /// shared-to-exclusive upgrade is a silent no-op).  See findExact.
    const NLM_UPGRADE_IS_NOOP: bool

    /// Whether NLM DOS share reservations are enforced or merely accepted.
    const NLM_SHARE_ENFORCED: bool

    /// Whether the server is in its post-restart grace window for the whole
    /// trace.  A server whose lock state cannot survive a restart has
    /// nothing to reclaim and opens for business immediately.
    const NLM_IN_GRACE: bool

    /// Whether traces may issue blocking LOCK requests.
    const NLM_BLOCKING: bool

    /// Whether the out-of-band NLMPROC4_GRANTED callback that delivers a
    /// deferred blocking lock is observable by the replay client.  It is
    /// addressed to the client's own lock manager, which a harness that is
    /// not a real lockd may not be able to receive; the lock is granted
    /// server-side either way, so the model tracks it regardless and only
    /// the callback itself is gated.
    const NLM_GRANT_CALLBACK_OBSERVABLE: bool

    /// Whether NLMPROC4_CANCEL_MSG withdraws a queued blocking request the
    /// way NLMPROC4_CANCEL does.  RFC 1813 gives the two the same meaning;
    /// a server may nonetheless acknowledge the asynchronous form without
    /// acting on it.
    const NLM_CANCEL_MSG_CANCELS: bool

    // ==================================================================
    // Bounded universes
    // ==================================================================

    /// Two model files, both pre-created by the harness, plus the handle
    /// that does not decode.
    pure val FILES = Set(0, 1)
    pure val ALL_FILES = FILES.union(Set(STALE_FILE))

    /// Two calling hosts and, per host, two owner handles and two process
    /// ids: enough for same-owner, same-host-other-owner and other-host
    /// conflicts, which is every distinction the identity triple makes.
    pure val CALLERS = Set("c1", "c2")
    pure val OHS = Set(1, 2)
    pure val SVIDS = Set(1, 2)

    /// A name that never holds a lock, so SM_NOTIFY's fallback path is
    /// reachable.
    pure val STRANGER = "c3"
    pure val NOTIFY_NAMES = CALLERS.union(Set(STRANGER))

    /// Byte ranges.  0 and EOF_LEN are the two wire spellings of to-EOF and
    /// must behave identically.
    pure val OFFSETS = Set(0, 8, 16)
    pure val LENGTHS = Set(8, 16, 0, EOF_LEN)

    /// Programs and versions the portmap queries range over: every
    /// registered program, one that is not, and versions past the served
    /// range.
    pure val PROGS = Set(100000, 100003, 100005, 100021, 100024, 300000)
    pure val VERSIONS = 1.to(5)
    pure val WIRE_PROTS = Set(PROT_TCP, PROT_UDP)
    pure val NETIDS = Set(NetTcp, NetUdp, NetTcp6, NetUdp6, NetLocal)

    pure val SHARE_MODES = Set(FSM_DN, FSM_DR, FSM_DW, FSM_DRW)
    pure val SHARE_ACCESS = Set(FSA_NONE, FSA_R, FSA_W, FSA_RW)

    /// The nlm4_stats a client may report in an NLMPROC4_*_RES.
    pure val RES_STATS = Set(NLM4_GRANTED, NLM4_DENIED, NLM4_BLOCKED)

    // ==================================================================
    // Replies
    // ==================================================================

    /*
     * The reply a procedure produces.
     *
     *   RUnavail    the RPC layer refused the call outright: MSG_ACCEPTED
     *               with accept_stat PROC_UNAVAIL, because the server
     *               registers no handler for that procedure.
     *   RVoid       a void procedure, or an acknowledged one-way message.
     *               An NLM *_MSG replies void as well; what it produces
     *               afterwards is carried by the op's `asyncs` list, not by
     *               the reply.
     */
    type Reply =
        | RUnavail
        | RVoid
        | RPort(int)
        | RBool(bool)
        | RMaps(List[Mapping])
        | RUaddr(Uaddr)
        | RMntOk(List[int])
        | RMntErr(int)
        | RMountTab(List[MountEnt])
        | RExports(List[str])
        | RNlm(int)
        | RNlmTestRes({ stat: int, holders: List[Lock] })
        | RNlmShare({ stat: int, sequence: int })
        | RSmStatRes({ res: int, state: int })
        | RSmStat(int)

    /// The locks a promotion granted, and the holders it put on the
    /// monitor list.
    pure def grantedLocks(g: List[Queued]): List[Lock] =
        g.foldl(List(), (acc, q) => acc.append(q.lock))

    pure def promotedMonitors(g: List[Queued]): Set[str] =
        g.foldl(Set(), (acc, q) =>
            if (q.monitor) acc.union(Set(q.lock.owner.caller)) else acc)

    /// Fold the IMPLEMENTED gate over a protocol-level reply.
    pure def gated(name: str, r: Reply): Reply =
        if (IMPLEMENTED.contains(name)) r else RUnavail

    pure def isRun(name: str): bool = IMPLEMENTED.contains(name)

    /**
     * A message the SERVER sends after answering: an NLMPROC4_*_RES
     * reporting the outcome of an asynchronous request.  An op's `asyncs`
     * is everything it provokes, and is usually empty or a single entry --
     * but not always.  Cancelling a queued NLMPROC4_LOCK_MSG produces two:
     * the CANCEL_RES that answers the cancel, and the LOCK_RES that tells
     * the client its blocked LOCK is gone.  They are not ordered with
     * respect to each other.
     */
    type AsyncMsg = { proc: int, stat: int }

    // ==================================================================
    // State
    // ==================================================================

    type Op =
        | OInit
        // ---- portmap / rpcbind ----
        | OPmNull({ reply: Reply })
        | OPmGetport({ prog: int, vers: int, prot: int, reply: Reply })
        | OPmSet({ unset: bool, map: Mapping, reply: Reply })
        | OPmDump({ reply: Reply })
        | OPmCallit({ prog: int, vers: int, cproc: int, reply: Reply })
        | ORbGetaddr({ rbvers: int, prog: int, vers: int, netid: Netid,
                       reply: Reply })
        | ORbDump({ rbvers: int, reply: Reply })
        | ORbGettime({ rbvers: int, reply: Reply })
        | ORbGetversaddr({ prog: int, vers: int, netid: Netid, reply: Reply })
        // ---- MOUNT ----
        | OMntNull({ reply: Reply })
        | OMnt({ path: str, reply: Reply })
        | OMntDump({ reply: Reply })
        | OMntUmnt({ path: str, reply: Reply })
        | OMntUmntAll({ reply: Reply })
        | OMntExport({ reply: Reply })
        // ---- NLM ----
        | ONlmNull({ reply: Reply })
        | ONlmTestOp({ msg: bool, lock: Lock, asyncs: List[AsyncMsg],
                       reply: Reply })
        | ONlmLock({ nproc: int, lock: Lock, block: bool, reclaim: bool,
                     asyncs: List[AsyncMsg], reply: Reply })
        | ONlmCancel({ msg: bool, lock: Lock, asyncs: List[AsyncMsg],
                       reply: Reply })
        | ONlmUnlock({ msg: bool, lock: Lock, granted: List[Lock],
                       asyncs: List[AsyncMsg], reply: Reply })
        | ONlmGranted({ msg: bool, lock: Lock, asyncs: List[AsyncMsg],
                          reply: Reply })
        | ONlmRes({ nproc: int, stat: int, reply: Reply })
        | ONlmReserved({ nproc: int, reply: Reply })
        | ONlmShare({ unshare: bool, share: ShareEnt, reply: Reply })
        | ONlmFreeAll({ name: str, granted: List[Lock], reply: Reply })
        // ---- NSM ----
        | OSmNull({ reply: Reply })
        | OSmStat({ host: str, reply: Reply })
        | OSmMon({ host: str, reply: Reply })
        | OSmUnmon({ host: str, reply: Reply })
        | OSmUnmonAll({ name: str, reply: Reply })
        | OSmSimuCrash({ reply: Reply })
        | OSmNotify({ host: str, state: int, granted: List[Lock],
                      reply: Reply })

    var services: List[Mapping]      // portmap registry
    var rmtab: List[MountEnt]        // MOUNT table, most recent first
    var held: List[Lock]             // granted NLM byte-range locks
    var queue: List[Queued]            // blocking LOCKs awaiting their range
    var shares: List[ShareEnt]       // NLM DOS share reservations
    var nlmClients: Set[str]         // caller_names NLM has ever seen
    var monitors: Set[str]           // NSM monitor list
    var nsmState: int                // NSM state number (odd == up)
    var lastOp: Op

    action init = all {
        services' = SERVICES,
        rmtab' = List(),
        held' = List(),
        queue' = List(),
        shares' = List(),
        nlmClients' = Set(),
        monitors' = Set(),
        nsmState' = NSM_INITIAL_STATE,
        lastOp' = OInit,
    }

    /// Frame condition: everything except lastOp is unchanged.  Every
    /// read-only procedure uses it, which is most of them.
    action readOnly(op: Op): bool = all {
        services' = services,
        rmtab' = rmtab,
        held' = held,
        queue' = queue,
        shares' = shares,
        nlmClients' = nlmClients,
        monitors' = monitors,
        nsmState' = nsmState,
        lastOp' = op,
    }

    // ==================================================================
    // portmap / rpcbind
    // ==================================================================

    action pmNull = readOnly(OPmNull({
        reply: gated("PMAPPROC_NULL", RVoid)
    }))

    action pmGetport(prog: int, vers: int, prot: int): bool =
        readOnly(OPmGetport({
            prog: prog, vers: vers, prot: prot,
            reply: gated("PMAPPROC_GETPORT",
                         RPort(lookupPort(services, prog, vers, prot)))
        }))

    action pmDump = readOnly(OPmDump({
        reply: gated("PMAPPROC_DUMP", RMaps(services))
    }))

    /// SET and UNSET are the only portmap procedures that can change state,
    /// so they do not use readOnly.
    action pmSet(unset: bool, m: Mapping): bool = {
        val name = if (unset) "PMAPPROC_UNSET" else "PMAPPROC_SET"
        val runs = isRun(name) and PM_SET_MUTATES
        val accepted =
            if (unset) unsetAccepted(services, m) else setAccepted(services, m)
        all {
            services' =
                if (not(runs)) services
                else if (unset) registryUnset(services, m)
                else registrySet(services, m),
            rmtab' = rmtab,
            held' = held,
            queue' = queue,
            shares' = shares,
            nlmClients' = nlmClients,
            monitors' = monitors,
            nsmState' = nsmState,
            lastOp' = OPmSet({
                unset: unset, map: m,
                reply: if (not(isRun(name))) RUnavail
                       else if (PM_SET_MUTATES) RBool(accepted)
                       else RBool(false)
            }),
        }
    }

    action pmCallit(prog: int, vers: int, cproc: int): bool =
        readOnly(OPmCallit({
            prog: prog, vers: vers, cproc: cproc,
            /* CALLIT proxies a call to another local service and returns
             * that service's port and result.  A server that registers it
             * would answer for the services it knows; one that does not
             * refuses.  Only the refusal is modeled concretely, because a
             * proxied result is the proxied protocol's business, not
             * portmap's. */
            reply: gated("PMAPPROC_CALLIT",
                         RPort(lookupPort(services, prog, vers, PROT_TCP)))
        }))

    action rbGetaddr(rbvers: int, prog: int, vers: int, netid: Netid): bool = {
        val name = if (rbvers == 3) "rpcbproc_getaddr" else "RPCBPROC_GETADDR"
        readOnly(ORbGetaddr({
            rbvers: rbvers, prog: prog, vers: vers, netid: netid,
            reply: gated(name,
                         RUaddr(getaddr(services, UADDR_HOST, prog, vers,
                                        netid)))
        }))
    }

    action rbDump(rbvers: int): bool = {
        val name = if (rbvers == 3) "rpcbproc_dump" else "RPCBPROC_DUMP"
        readOnly(ORbDump({
            rbvers: rbvers,
            reply: gated(name, RMaps(services))
        }))
    }

    action rbGettime(rbvers: int): bool = {
        val name = if (rbvers == 3) "rpcbproc_gettime" else "RPCBPROC_GETTIME"
        readOnly(ORbGettime({
            rbvers: rbvers,
            /* The reply is the server's wall clock, which no oracle can
             * predict; only the refusal is checkable, so a server that
             * registers GETTIME must have its trace checked for the
             * accept_stat alone.  RPort(0) is a placeholder the harness
             * ignores when the procedure ran. */
            reply: gated(name, RPort(0))
        }))
    }

    action rbGetversaddr(prog: int, vers: int, netid: Netid): bool =
        readOnly(ORbGetversaddr({
            prog: prog, vers: vers, netid: netid,
            /* GETVERSADDR is GETADDR restricted to the exact version asked
             * for -- which, for a server that already matches the exact
             * triple, is the same answer. */
            reply: gated("RPCBPROC_GETVERSADDR",
                         RUaddr(getaddr(services, UADDR_HOST, prog, vers,
                                        netid)))
        }))

    // ==================================================================
    // MOUNT
    // ==================================================================

    action mntNull = readOnly(OMntNull({
        reply: gated("MOUNTPROC3_NULL", RVoid)
    }))

    action mnt(path: str): bool = {
        val res = PATHS.get(path)
        val status = mntStatus(res)
        val runs = isRun("MOUNTPROC3_MNT")
        all {
            services' = services,
            /* The row is recorded as soon as an export matches, before the
             * resolved object is looked up: a MNT that ends in NOENT
             * because the subdirectory is missing still leaves one behind. */
            rmtab' = if (runs and mntRecords(res))
                         mountRecord(rmtab, MOUNT_HOST, path)
                     else rmtab,
            held' = held,
            queue' = queue,
            shares' = shares,
            nlmClients' = nlmClients,
            monitors' = monitors,
            nsmState' = nsmState,
            lastOp' = OMnt({
                path: path,
                reply: gated("MOUNTPROC3_MNT",
                             if (status == MNT3_OK)
                                 RMntOk(mntFlavors(EXPORTS, res))
                             else RMntErr(status))
            }),
        }
    }

    action mntDump = readOnly(OMntDump({
        reply: gated("MOUNTPROC3_DUMP", RMountTab(rmtab))
    }))

    action mntUmnt(path: str): bool = {
        val runs = isRun("MOUNTPROC3_UMNT")
        all {
            services' = services,
            rmtab' = if (runs) mountRemove(rmtab, MOUNT_HOST, path) else rmtab,
            held' = held,
            queue' = queue,
            shares' = shares,
            nlmClients' = nlmClients,
            monitors' = monitors,
            nsmState' = nsmState,
            lastOp' = OMntUmnt({
                path: path, reply: gated("MOUNTPROC3_UMNT", RVoid)
            }),
        }
    }

    action mntUmntAll = {
        val runs = isRun("MOUNTPROC3_UMNTALL")
        all {
            services' = services,
            rmtab' = if (runs) mountRemoveHost(rmtab, MOUNT_HOST) else rmtab,
            held' = held,
            queue' = queue,
            shares' = shares,
            nlmClients' = nlmClients,
            monitors' = monitors,
            nsmState' = nsmState,
            lastOp' = OMntUmntAll({
                reply: gated("MOUNTPROC3_UMNTALL", RVoid)
            }),
        }
    }

    action mntExport = readOnly(OMntExport({
        reply: gated("MOUNTPROC3_EXPORT", RExports(exportNames(EXPORTS)))
    }))

    // ==================================================================
    // NLM
    // ==================================================================

    action nlmNull = readOnly(ONlmNull({
        reply: gated("NLMPROC4_NULL", RVoid)
    }))

    action nlmTestOp(msg: bool, l: Lock): bool = {
        val name = if (msg) "NLMPROC4_TEST_MSG" else "NLMPROC4_TEST"
        val stat = testStatus(held, l)
        readOnly(ONlmTestOp({
            msg: msg, lock: l,
            asyncs: if (msg and isRun(name)) List({ proc: 11, stat: stat })
                    else List(),
            reply: gated(name,
                         if (msg) RVoid
                         else RNlmTestRes({ stat: stat,
                                            holders: conflictsWith(held, l) }))
        }))
    }

    /**
     * LOCK (proc 2), LOCK_MSG (7) and NM_LOCK (22) share one implementation:
     * the same admission decision, differing only in how the answer is
     * delivered and -- for NM_LOCK, the "non-monitored" form -- whether the
     * holder joins the NSM monitor list.
     */
    action nlmLock(nproc: int, l: Lock, block: bool, reclaim: bool): bool = {
        val name = if (nproc == 7) "NLMPROC4_LOCK_MSG"
                   else if (nproc == 22) "NLMPROC4_NM_LOCK"
                   else "NLMPROC4_LOCK"
        val runs = isRun(name)
        val stat = lockStatus(held, l, block, reclaim, NLM_IN_GRACE,
                              NLM_UPGRADE_IS_NOOP)
        /* NM_LOCK is the non-monitored form; every other LOCK puts its
         * holder on the monitor list once -- and only once -- the lock is
         * actually held, which for a blocking request is when the queue
         * promotes it rather than when it was accepted. */
        val monitorable = NSM_MON_FROM_LOCKS and nproc != 22
        val monitored = monitorable and stat == NLM4_GRANTED
        all {
            services' = services,
            rmtab' = rmtab,
            held' = if (runs) heldAfterLock(held, l, stat) else held,
            queue' = if (runs and stat == NLM4_BLOCKED)
                         queue.append({ lock: l, monitor: monitorable,
                                        msg: nproc == 7 })
                     else queue,
            shares' = shares,
            /* A client entry is created by the attempt, not by the grant,
             * and a server keeps it after the client's last lock is gone --
             * which is what makes an SM_NOTIFY for that name take the exact
             * match rather than the address fallback. */
            nlmClients' = if (runs and l.file != STALE_FILE)
                              nlmClients.union(Set(l.owner.caller))
                          else nlmClients,
            monitors' = if (runs and monitored)
                            monitors.union(Set(l.owner.caller))
                        else monitors,
            nsmState' = nsmState,
            lastOp' = ONlmLock({
                nproc: nproc, lock: l, block: block, reclaim: reclaim,
                asyncs: if (nproc == 7 and runs)
                            List({ proc: 12, stat: stat })
                        else List(),
                reply: gated(name, if (nproc == 7) RVoid else RNlm(stat))
            }),
        }
    }

    action nlmCancel(msg: bool, l: Lock): bool = {
        val name = if (msg) "NLMPROC4_CANCEL_MSG" else "NLMPROC4_CANCEL"
        val runs = isRun(name)
        val cancels = runs and (not(msg) or NLM_CANCEL_MSG_CANCELS)
        /* Each withdrawn request that arrived asynchronously is owed a
         * final LOCK_RES saying its blocked LOCK is gone.  The synchronous
         * form has nothing left to answer on. */
        val taken = if (cancels) cancelTaken(queue, l) else List()
        val lockRes = taken.foldl(List(), (acc, q) =>
            if (q.msg) acc.append({ proc: 12, stat: NLM4_DENIED }) else acc)
        all {
            services' = services,
            rmtab' = rmtab,
            held' = held,
            queue' = if (cancels) cancelQueued(queue, l) else queue,
            shares' = shares,
            nlmClients' = nlmClients,
            monitors' = monitors,
            nsmState' = nsmState,
            /* CANCEL answers GRANTED whether or not it found anything: the
             * client is being told the request is no longer outstanding. */
            lastOp' = ONlmCancel({
                msg: msg, lock: l,
                asyncs: if (not(runs)) List()
                        else if (msg)
                            List({ proc: 13, stat: NLM4_GRANTED })
                                .concat(lockRes)
                        else lockRes,
                reply: gated(name, if (msg) RVoid else RNlm(NLM4_GRANTED))
            }),
        }
    }

    /**
     * UNLOCK releases the named range and lets the blocking queue run.
     * RFC 1813 A.6.4: the answer is GRANTED even when nothing matched -- an
     * unlock of a lock that is not held is not an error.
     */
    action nlmUnlock(msg: bool, l: Lock): bool = {
        val name = if (msg) "NLMPROC4_UNLOCK_MSG" else "NLMPROC4_UNLOCK"
        val runs = isRun(name)
        val after = if (runs) dropExact(held, l) else held
        val pumped = promoteBlocked(after, queue)
        all {
            services' = services,
            rmtab' = rmtab,
            held' = if (runs) pumped.held else held,
            queue' = if (runs) pumped.queue else queue,
            shares' = shares,
            nlmClients' = nlmClients,
            monitors' = if (runs) monitors.union(promotedMonitors(pumped.granted))
                        else monitors,
            nsmState' = nsmState,
            lastOp' = ONlmUnlock({
                msg: msg, lock: l,
                granted: if (runs) grantedLocks(pumped.granted) else List(),
                asyncs: if (msg and runs)
                            List({ proc: 14, stat: NLM4_GRANTED })
                        else List(),
                reply: gated(name, if (msg) RVoid else RNlm(NLM4_GRANTED))
            }),
        }
    }

    /// GRANTED / GRANTED_MSG travel client-ward in normal operation; a
    /// server still has to answer them, and answering GRANTED is the only
    /// sensible reply to "your lock is available".  GRANTED_MSG is one-way:
    /// its *_RES would come from the client, so nothing follows.
    action nlmGranted(msg: bool, l: Lock): bool = {
        val name = if (msg) "NLMPROC4_GRANTED_MSG" else "NLMPROC4_GRANTED"
        readOnly(ONlmGranted({
            msg: msg, lock: l,
            /* GRANTED_MSG is one-way in the client-ward direction: its
             * *_RES would come FROM the client, so a server that receives
             * one sends nothing back beyond the acknowledgement. */
            asyncs: List(),
            reply: gated(name, if (msg) RVoid else RNlm(NLM4_GRANTED))
        }))
    }

    /// The *_RES procedures (11-15): a client reporting an asynchronous
    /// result.  A server records or ignores it and acknowledges.
    action nlmRes(nproc: int, stat: int): bool = {
        val name = if (nproc == 11) "NLMPROC4_TEST_RES"
                   else if (nproc == 12) "NLMPROC4_LOCK_RES"
                   else if (nproc == 13) "NLMPROC4_CANCEL_RES"
                   else if (nproc == 14) "NLMPROC4_UNLOCK_RES"
                   else "NLMPROC4_GRANTED_RES"
        readOnly(ONlmRes({
            nproc: nproc, stat: stat, reply: gated(name, RVoid)
        }))
    }

    /// Slots 16-19 are reserved by the protocol and carry no arguments.  A
    /// server may register them as no-ops or leave them unregistered; the
    /// difference is visible as an acknowledgement versus PROC_UNAVAIL.
    action nlmReserved(nproc: int): bool = {
        val name = if (nproc == 16) "NLMPROC4_RESERVED_16"
                   else if (nproc == 17) "NLMPROC4_RESERVED_17"
                   else if (nproc == 18) "NLMPROC4_RESERVED_18"
                   else "NLMPROC4_RESERVED_19"
        readOnly(ONlmReserved({ nproc: nproc, reply: gated(name, RVoid) }))
    }

    action nlmShare(unshare: bool, sh: ShareEnt): bool = {
        val name = if (unshare) "NLMPROC4_UNSHARE" else "NLMPROC4_SHARE"
        val runs = isRun(name)
        val stat = if (unshare) NLM4_GRANTED
                   else shareStatus(shares, sh, NLM_SHARE_ENFORCED)
        all {
            services' = services,
            rmtab' = rmtab,
            held' = held,
            queue' = queue,
            shares' = if (not(runs)) shares
                      else if (unshare) sharesAfterUnshare(shares, sh)
                      else sharesAfterShare(shares, sh, stat),
            nlmClients' = nlmClients,
            monitors' = monitors,
            nsmState' = nsmState,
            /* nlm4_shareres carries a sequence number the RFC leaves to the
             * server; a server that does not sequence reservations reports
             * 0 for every reply. */
            lastOp' = ONlmShare({
                unshare: unshare, share: sh,
                reply: gated(name, RNlmShare({ stat: stat, sequence: 0 }))
            }),
        }
    }

    /**
     * FREE_ALL drops everything one client holds: its byte-range locks, its
     * queued blocking requests, its share reservations, and its place on
     * the monitor list.  It is a void procedure -- the client is announcing,
     * not asking.
     */
    action nlmFreeAll(name: str): bool = {
        val runs = isRun("NLMPROC4_FREE_ALL")
        /* The client's queued requests are withdrawn first (a server
         * cancels every outstanding ticket before it starts releasing),
         * then its held locks go one at a time with a pump after each. */
        val q = if (runs) queue.select(e => e.lock.owner.caller != name)
                else queue
        val pumped = if (runs) releaseClient(held, q, name)
                     else { held: held, queue: q, granted: List() }
        all {
            services' = services,
            rmtab' = rmtab,
            held' = if (runs) pumped.held else held,
            queue' = if (runs) pumped.queue else queue,
            shares' = if (runs) shares.select(s => s.caller != name)
                      else shares,
            /* The client's table entry outlives its locks; only the monitor
             * relationship ends here. */
            nlmClients' = nlmClients,
            monitors' = if (runs)
                            monitors.exclude(Set(name))
                                .union(promotedMonitors(pumped.granted))
                        else monitors,
            nsmState' = nsmState,
            lastOp' = ONlmFreeAll({
                name: name,
                granted: if (runs) grantedLocks(pumped.granted) else List(),
                reply: gated("NLMPROC4_FREE_ALL", RVoid)
            }),
        }
    }

    // ==================================================================
    // NSM
    // ==================================================================

    action smNull = readOnly(OSmNull({
        reply: gated("SM_NULL", RVoid)
    }))

    /// STAT asks whether a host can be monitored.  A server that does not
    /// probe peers reports success for any name.
    action smStat(host: str): bool = readOnly(OSmStat({
        host: host,
        reply: gated("SM_STAT", RSmStatRes({ res: STAT_SUCC,
                                             state: nsmState }))
    }))

    action smMon(host: str): bool = {
        val runs = isRun("SM_MON")
        all {
            services' = services,
            rmtab' = rmtab,
            held' = held,
            queue' = queue,
            shares' = shares,
            nlmClients' = nlmClients,
            monitors' = if (runs and not(NSM_MON_FROM_LOCKS))
                            monitors.union(Set(host))
                        else monitors,
            nsmState' = nsmState,
            lastOp' = OSmMon({
                host: host,
                reply: gated("SM_MON", RSmStatRes({ res: STAT_SUCC,
                                                    state: nsmState }))
            }),
        }
    }

    action smUnmon(host: str): bool = {
        val runs = isRun("SM_UNMON")
        all {
            services' = services,
            rmtab' = rmtab,
            held' = held,
            queue' = queue,
            shares' = shares,
            nlmClients' = nlmClients,
            monitors' = if (runs) monitors.exclude(Set(host)) else monitors,
            nsmState' = nsmState,
            lastOp' = OSmUnmon({
                host: host,
                reply: gated("SM_UNMON", RSmStat(nsmState))
            }),
        }
    }

    action smUnmonAll(name: str): bool = {
        val runs = isRun("SM_UNMON_ALL")
        all {
            services' = services,
            rmtab' = rmtab,
            held' = held,
            queue' = queue,
            shares' = shares,
            nlmClients' = nlmClients,
            monitors' = if (runs) unmonAll(monitors, name) else monitors,
            nsmState' = nsmState,
            lastOp' = OSmUnmonAll({
                name: name,
                reply: gated("SM_UNMON_ALL", RSmStat(nsmState))
            }),
        }
    }

    /**
     * SIMU_CRASH makes the server behave as though it had restarted: the
     * state number advances to the next odd value and every monitored peer
     * is told.  Sending those notifications is asynchronous work against
     * hosts outside the model, so traces only issue it with an empty
     * monitor list, where there is nothing to send and the observable
     * effect is exactly the state bump.
     */
    action smSimuCrash = {
        val runs = isRun("SM_SIMU_CRASH")
        all {
            services' = services,
            rmtab' = rmtab,
            held' = held,
            queue' = queue,
            shares' = shares,
            nlmClients' = nlmClients,
            monitors' = monitors,
            nsmState' = if (runs) nextState(nsmState) else nsmState,
            lastOp' = OSmSimuCrash({
                reply: gated("SM_SIMU_CRASH", RVoid)
            }),
        }
    }

    /**
     * NOTIFY: "peer <host> restarted".  Every lock the peer held is stale
     * and is dropped, which can let queued blocking requests through.
     */
    action smNotify(host: str, state: int): bool = {
        val runs = isRun("SM_NOTIFY")
        val victims = if (runs)
                          notifyMatches(monitors, nlmClients, host,
                                        NSM_ADDRS_DISTINCT)
                      else Set()
        /* Each matched host is released in turn, exactly as FREE_ALL
         * releases one: queued requests withdrawn, then held locks one at a
         * time with a pump after each. */
        val q0 = queue.select(e => not(victims.contains(e.lock.owner.caller)))
        val pumped = victims.fold({ held: held, queue: q0, granted: List() },
                                  (acc, v) => {
            val r = releaseClient(acc.held, acc.queue, v)
            { held: r.held, queue: r.queue,
              granted: acc.granted.concat(r.granted) }
        })
        all {
            services' = services,
            rmtab' = rmtab,
            held' = pumped.held,
            queue' = pumped.queue,
            shares' = shares.select(s => not(victims.contains(s.caller))),
            nlmClients' = nlmClients,
            monitors' = monitors.exclude(victims)
                .union(promotedMonitors(pumped.granted)),
            nsmState' = nsmState,
            lastOp' = OSmNotify({
                host: host, state: state,
                granted: grantedLocks(pumped.granted),
                reply: gated("SM_NOTIFY", RVoid)
            }),
        }
    }

    // ==================================================================
    // Transition relation
    // ==================================================================

    action anyPmGetport = {
        nondet prog = PROGS.oneOf()
        nondet vers = VERSIONS.oneOf()
        nondet prot = WIRE_PROTS.oneOf()
        pmGetport(prog, vers, prot)
    }

    action anyPmSet = {
        nondet unset = Set(false, true).oneOf()
        nondet prog = PROGS.oneOf()
        nondet vers = VERSIONS.oneOf()
        nondet prot = WIRE_PROTS.oneOf()
        nondet port = Set(0, 4242).oneOf()
        pmSet(unset, { prog: prog, vers: vers, prot: prot, port: port })
    }

    action anyPmCallit = {
        nondet prog = PROGS.oneOf()
        nondet vers = VERSIONS.oneOf()
        pmCallit(prog, vers, 0)
    }

    action anyRbGetaddr = {
        nondet rbvers = Set(3, 4).oneOf()
        nondet prog = PROGS.oneOf()
        nondet vers = VERSIONS.oneOf()
        nondet netid = NETIDS.oneOf()
        rbGetaddr(rbvers, prog, vers, netid)
    }

    action anyRbDump = {
        nondet rbvers = Set(3, 4).oneOf()
        rbDump(rbvers)
    }

    action anyRbGettime = {
        nondet rbvers = Set(3, 4).oneOf()
        rbGettime(rbvers)
    }

    action anyRbGetversaddr = {
        nondet prog = PROGS.oneOf()
        nondet vers = VERSIONS.oneOf()
        nondet netid = NETIDS.oneOf()
        rbGetversaddr(prog, vers, netid)
    }

    action anyMnt = {
        nondet path = PATHS.keys().oneOf()
        mnt(path)
    }

    action anyUmnt = {
        nondet path = PATHS.keys().oneOf()
        mntUmnt(path)
    }

    /*
     * Every NLM request carries the same shape -- an owner triple, a file
     * and a byte range -- so each generator draws the same six nondets.
     * They are spelled out per action rather than factored through a
     * higher-order helper because an action is not a value in Quint.
     */
    action anyNlmTestOp = {
        nondet msg = Set(false, true).oneOf()
        nondet caller = CALLERS.oneOf()
        nondet oh = OHS.oneOf()
        nondet svid = SVIDS.oneOf()
        nondet file = ALL_FILES.oneOf()
        nondet offset = OFFSETS.oneOf()
        nondet wireLen = LENGTHS.oneOf()
        nondet excl = Set(false, true).oneOf()
        nlmTestOp(msg, { file: file,
                       owner: { caller: caller, oh: oh, svid: svid },
                       offset: offset, wireLen: wireLen, excl: excl })
    }

    action anyNlmLock = {
        nondet nproc = Set(2, 7, 22).oneOf()
        nondet blockPick = Set(false, true).oneOf()
        nondet reclaim = Set(false, true).oneOf()
        nondet caller = CALLERS.oneOf()
        nondet oh = OHS.oneOf()
        nondet svid = SVIDS.oneOf()
        nondet file = ALL_FILES.oneOf()
        nondet offset = OFFSETS.oneOf()
        nondet wireLen = LENGTHS.oneOf()
        nondet excl = Set(false, true).oneOf()
        nlmLock(nproc, { file: file,
                         owner: { caller: caller, oh: oh, svid: svid },
                         offset: offset, wireLen: wireLen, excl: excl },
                blockPick and NLM_BLOCKING, reclaim)
    }

    /// A non-blocking, non-reclaim LOCK: the shape most traces want.
    action anyNlmPlainLock = {
        nondet caller = CALLERS.oneOf()
        nondet oh = OHS.oneOf()
        nondet svid = SVIDS.oneOf()
        nondet file = ALL_FILES.oneOf()
        nondet offset = OFFSETS.oneOf()
        nondet wireLen = LENGTHS.oneOf()
        nondet excl = Set(false, true).oneOf()
        nlmLock(2, { file: file,
                     owner: { caller: caller, oh: oh, svid: svid },
                     offset: offset, wireLen: wireLen, excl: excl },
                false, false)
    }

    action anyNlmCancel = {
        nondet msg = Set(false, true).oneOf()
        nondet caller = CALLERS.oneOf()
        nondet oh = OHS.oneOf()
        nondet svid = SVIDS.oneOf()
        nondet file = ALL_FILES.oneOf()
        nondet offset = OFFSETS.oneOf()
        nondet wireLen = LENGTHS.oneOf()
        nondet excl = Set(false, true).oneOf()
        nlmCancel(msg, { file: file,
                         owner: { caller: caller, oh: oh, svid: svid },
                         offset: offset, wireLen: wireLen, excl: excl })
    }

    action anyNlmUnlock = {
        nondet msg = Set(false, true).oneOf()
        nondet caller = CALLERS.oneOf()
        nondet oh = OHS.oneOf()
        nondet svid = SVIDS.oneOf()
        nondet file = ALL_FILES.oneOf()
        nondet offset = OFFSETS.oneOf()
        nondet wireLen = LENGTHS.oneOf()
        nondet excl = Set(false, true).oneOf()
        nlmUnlock(msg, { file: file,
                         owner: { caller: caller, oh: oh, svid: svid },
                         offset: offset, wireLen: wireLen, excl: excl })
    }

    action anyNlmGranted = {
        nondet msg = Set(false, true).oneOf()
        nondet caller = CALLERS.oneOf()
        nondet oh = OHS.oneOf()
        nondet svid = SVIDS.oneOf()
        nondet file = FILES.oneOf()
        nondet offset = OFFSETS.oneOf()
        nondet wireLen = LENGTHS.oneOf()
        nondet excl = Set(false, true).oneOf()
        nlmGranted(msg, { file: file,
                          owner: { caller: caller, oh: oh, svid: svid },
                          offset: offset, wireLen: wireLen, excl: excl })
    }

    action anyNlmRes = {
        nondet nproc = Set(11, 12, 13, 14, 15).oneOf()
        nondet stat = RES_STATS.oneOf()
        nlmRes(nproc, stat)
    }

    action anyNlmReserved = {
        nondet nproc = Set(16, 17, 18, 19).oneOf()
        nlmReserved(nproc)
    }

    action anyNlmShare = {
        nondet unshare = Set(false, true).oneOf()
        nondet caller = CALLERS.oneOf()
        nondet oh = OHS.oneOf()
        nondet file = FILES.oneOf()
        nondet mode = SHARE_MODES.oneOf()
        nondet access = SHARE_ACCESS.oneOf()
        nlmShare(unshare, { file: file, caller: caller, oh: oh, mode: mode,
                            access: access })
    }

    action anyNlmFreeAll = {
        nondet name = NOTIFY_NAMES.oneOf()
        nlmFreeAll(name)
    }

    action anySmStat = {
        nondet host = NOTIFY_NAMES.oneOf()
        smStat(host)
    }

    action anySmMon = {
        nondet host = NOTIFY_NAMES.oneOf()
        smMon(host)
    }

    action anySmUnmon = {
        nondet host = NOTIFY_NAMES.oneOf()
        smUnmon(host)
    }

    action anySmUnmonAll = {
        nondet name = NOTIFY_NAMES.oneOf()
        smUnmonAll(name)
    }

    /*
     * SM_NOTIFY for a name NLM knows names exactly one victim, and its
     * locks are released in a defined order.  The ADDRESS FALLBACK can match
     * several monitored hosts at once, and the order a server visits them in
     * is a property of its hash table, not of the protocol -- which matters
     * only when there is a wait queue for those releases to feed, because
     * then the order decides which waiter wins.  Restrict the fallback to a
     * quiet queue, where every visiting order produces the same result.
     */
    action anySmNotify = {
        nondet host = NOTIFY_NAMES.oneOf()
        nondet state = Set(1, 7).oneOf()
        all {
            nlmClients.contains(host) or queue.length() == 0,
            smNotify(host, state),
        }
    }

    /// SIMU_CRASH only when there is nobody to notify; see smSimuCrash.
    action anySmSimuCrash = all {
        monitors.size() == 0,
        smSimuCrash,
    }

    action step = any {
        pmNull, anyPmGetport, pmDump, anyPmSet, anyPmCallit,
        anyRbGetaddr, anyRbDump, anyRbGettime, anyRbGetversaddr,
        mntNull, anyMnt, mntDump, anyUmnt, mntUmntAll, mntExport,
        nlmNull, anyNlmTestOp, anyNlmLock, anyNlmCancel, anyNlmUnlock,
        anyNlmGranted, anyNlmRes, anyNlmReserved, anyNlmShare, anyNlmFreeAll,
        smNull, anySmStat, anySmMon, anySmUnmon, anySmUnmonAll,
        anySmNotify, anySmSimuCrash,
    }

    // ------------------------------------------------------------------
    // Biased step distributions (quint run --step=<name>).  `any` weights
    // by duplicate branches, so listing an action N times gives it ~N times
    // the odds among the enabled branches.
    // ------------------------------------------------------------------

    /// Registry-only: every portmap and rpcbind procedure, nothing else.
    action stepPortmap = any {
        pmNull, anyPmGetport, anyPmGetport, pmDump, anyPmSet, anyPmCallit,
        anyRbGetaddr, anyRbGetaddr, anyRbDump, anyRbGettime,
        anyRbGetversaddr,
    }

    /// The mount table: heavy MNT/UMNT churn with DUMP to observe it.
    action stepMount = any {
        mntNull, anyMnt, anyMnt, anyMnt, mntDump, mntDump, anyUmnt, anyUmnt,
        mntUmntAll, mntExport,
    }

    /// Byte-range locking proper: no portmap or mount noise.
    action stepLocks = any {
        nlmNull, anyNlmTestOp, anyNlmTestOp, anyNlmPlainLock, anyNlmPlainLock,
        anyNlmPlainLock, anyNlmUnlock, anyNlmUnlock, anyNlmCancel,
        anyNlmFreeAll,
    }

    /// The asynchronous half: _MSG requests, _RES reports, GRANTED, and the
    /// reserved slots.
    action stepAsync = any {
        anyNlmTestOp, anyNlmLock, anyNlmCancel, anyNlmUnlock, anyNlmGranted,
        anyNlmGranted, anyNlmRes, anyNlmRes, anyNlmReserved,
    }

    /// Blocking locks: enough queue pressure that requests are queued,
    /// promoted when the blocker releases, and cancelled while waiting.
    action anyNlmBlockingLock = {
        nondet nproc = Set(2, 7).oneOf()
        nondet caller = CALLERS.oneOf()
        nondet oh = OHS.oneOf()
        nondet svid = SVIDS.oneOf()
        nondet file = FILES.oneOf()
        nondet offset = OFFSETS.oneOf()
        nondet wireLen = LENGTHS.oneOf()
        nlmLock(nproc, { file: file,
                         owner: { caller: caller, oh: oh, svid: svid },
                         offset: offset, wireLen: wireLen, excl: true },
                NLM_BLOCKING, false)
    }

    action stepBlocking = any {
        anyNlmBlockingLock, anyNlmBlockingLock, anyNlmBlockingLock,
        anyNlmUnlock, anyNlmUnlock, anyNlmUnlock,
        anyNlmCancel, anyNlmTestOp, anyNlmFreeAll,
    }

    /// The lock-manager / status-monitor seam: grants put holders on the
    /// monitor list, notifies and FREE_ALL take them off with their locks.
    action stepRecovery = any {
        anyNlmPlainLock, anyNlmPlainLock, anyNlmPlainLock, anyNlmTestOp,
        anyNlmFreeAll, anySmNotify, anySmNotify, anySmMon, anySmUnmon,
        anySmUnmonAll, anySmStat, anySmSimuCrash,
    }

    /// DOS share reservations.
    action stepShare = any {
        anyNlmShare, anyNlmShare, anyNlmShare, anyNlmPlainLock, anyNlmTestOp,
        anyNlmFreeAll,
    }

    // ==================================================================
    // Structural invariants over the model itself
    // ==================================================================

    /// No two granted locks conflict with each other.  This is the whole
    /// point of a lock manager, restated independently of the admission
    /// rule that maintains it.
    val locksCompatible = held.indices().forall(i =>
        held.indices().forall(j =>
            i == j or not(
                locksOverlap(held[i], held[j]) and
                not(sameOwner(held[i].owner, held[j].owner)) and
                (held[i].excl or held[j].excl))))

    /// A queued request is queued because it conflicts; once it does not,
    /// it must have been promoted.
    val queueJustified = queue.indices().forall(i =>
        hasConflict(held, queue[i].lock))

    /// Nothing is granted for a handle that does not decode.
    val noStaleLocks = held.indices().forall(i =>
        held[i].file != STALE_FILE)

    /// The mount table holds no duplicates.
    val rmtabDistinct = rmtab.indices().forall(i =>
        rmtab.indices().forall(j =>
            i == j or not(rmtab[i].host == rmtab[j].host and
                          rmtab[i].dir == rmtab[j].dir)))

    /// The NSM state number is odd while the server is up.
    val stateOdd = nsmState % 2 == 1

    /// Only hosts NLM knows about are monitored.
    val monitorsAreClients = NSM_MON_FROM_LOCKS
        implies monitors.forall(h => nlmClients.contains(h))

    val inv = and {
        locksCompatible,
        queueJustified,
        noStaleLocks,
        rmtabDistinct,
        stateOdd,
        monitorsAreClients,
    }
}
