// SPDX-FileCopyrightText: 2026 The Quint Specs Authors
//
// SPDX-License-Identifier: MIT

/**
 * aux_nsm.qnt -- the Network Status Monitor ("sm_inter", program 100024
 * version 1), the reboot-monitor service that drives NLM lock recovery.
 *
 * All seven procedures are covered: NULL, STAT, MON, UNMON, UNMON_ALL,
 * SIMU_CRASH, NOTIFY.
 *
 * Two pieces of state:
 *
 *   - the STATE NUMBER.  A monotonically increasing integer that is ODD
 *     while the host is up; a peer detects that we restarted by seeing it
 *     change.  Every reply that carries a state carries this one.
 *   - the MONITOR LIST, the set of peers to be told when we restart.  Who
 *     puts entries in it is a server policy, not an RFC rule: the classic
 *     statd records what peers SM_MON, while a server that embeds its own
 *     monitor derives the list from the NLM locks it has granted (a real
 *     NFS client SM_MONs its OWN local statd, not the server's).  Both are
 *     expressible; `monFromMon` selects.
 *
 * The interesting semantics are in SM_NOTIFY, which is the only procedure
 * that reaches across into NLM: "peer X restarted" means every lock X held
 * is stale and must be dropped.  Matching X to a lock holder is where
 * implementations differ, and the difference is observable -- see
 * `notifyMatches`.
 */
module nsmProto {

    /// res (sm_inter.x)
    pure val STAT_SUCC = 0
    pure val STAT_FAIL = 1

    pure val NSM_PROCS = Set(
        "SM_NULL", "SM_STAT", "SM_MON", "SM_UNMON", "SM_UNMON_ALL",
        "SM_SIMU_CRASH", "SM_NOTIFY"
    )

    /// The next state number after a (re)boot: the smallest odd value
    /// strictly greater than the current one.  Odd == "the host is up" is
    /// the classic statd convention a peer uses to detect a restart.
    pure def nextState(prev: int): int =
        if (prev % 2 == 1) prev + 2 else prev + 1

    /**
     * Which monitored hosts an SM_NOTIFY releases locks for.
     *
     * The notify carries a mon_name.  The primary match is exact: the
     * name is the caller_name the peer used for its NLM locks, so a lock
     * holder of that name is the peer that restarted.
     *
     * When no NLM client of that name is known, a server may fall back to
     * matching monitored hosts by the SOURCE ADDRESS of the notify, because
     * a peer's statd is allowed to present a different name than its lockd
     * used.  That fallback is only as selective as the addresses are
     * distinct: where every peer reaches the server from the same address --
     * a single-address test harness, or several clients behind one NAT --
     * it matches every monitored host at once, and one peer's reboot drops
     * everyone's locks.  `addrsDistinct` says which world we are in, so a
     * trace generated for one is never replayed against the other.
     *
     * `knownClients` is the set of caller_names NLM has ever seen; a server
     * keeps that entry after the client's last lock goes away, so a name
     * that once held a lock still takes the exact-match path.
     */
    pure def notifyMatches(monitors: Set[str], knownClients: Set[str],
                           monName: str, addrsDistinct: bool): Set[str] =
        if (knownClients.contains(monName))
            Set(monName)
        else if (addrsDistinct)
            Set()
        else
            monitors

    /// SM_UNMON drops the single named host.  SM_UNMON_ALL drops every
    /// monitor the CALLING host established; where the monitor table is
    /// keyed by the monitored host's name, that is the caller's own entry.
    pure def unmonAll(monitors: Set[str], caller: str): Set[str] =
        monitors.exclude(Set(caller))
}
