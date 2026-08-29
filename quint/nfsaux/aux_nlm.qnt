// SPDX-FileCopyrightText: 2026 The Quint Specs Authors
//
// SPDX-License-Identifier: MIT

/**
 * aux_nlm.qnt -- the Network Lock Manager version 4 (RFC 1813 Appendix II /
 * the X/Open NFS specification), modeled as pure transitions over the set of
 * byte-range locks a server holds.
 *
 * All twenty-four procedure slots are covered: the synchronous quartet
 * (TEST/LOCK/CANCEL/UNLOCK) and GRANTED, their asynchronous _MSG twins and
 * the _RES messages that answer them, the four reserved slots, the DOS
 * share-reservation pair (SHARE/UNSHARE), the non-monitored NM_LOCK, and
 * FREE_ALL.
 *
 * ------------------------------------------------------------------------
 * Lock identity
 * ------------------------------------------------------------------------
 * A lock's owner is the triple (caller_name, oh, svid): the host, the
 * client's opaque owner handle, and the client-side process id.  Two
 * requests with the same triple are the same owner and never conflict with
 * each other; anything else is a different owner.  svid being part of the
 * identity is what keeps two processes on one client from sharing a lock.
 *
 * ------------------------------------------------------------------------
 * Ranges
 * ------------------------------------------------------------------------
 * Lengths are kept in the POSIX convention -- 0 means "to end of file" --
 * because that is what a server stores and what UNLOCK matching compares.
 * On the wire, RFC 1813 gives to-EOF two spellings, l_len = 0 and
 * l_len = 0xffffffffffffffff, and both normalize to the same stored length,
 * so a lock taken with one is released by the other.  The model carries the
 * WIRE length and normalizes with `posixLen`, so that equivalence is under
 * test rather than assumed away.
 */
module nlmProto {

    // ------------------------------------------------------------------
    // nlm4_stats (RFC 1813 Appendix II), numerically as on the wire
    // ------------------------------------------------------------------
    pure val NLM4_GRANTED             = 0
    pure val NLM4_DENIED              = 1
    pure val NLM4_DENIED_NOLOCKS      = 2
    pure val NLM4_BLOCKED             = 3
    pure val NLM4_DENIED_GRACE_PERIOD = 4
    pure val NLM4_DEADLCK             = 5
    pure val NLM4_ROFS                = 6
    pure val NLM4_STALE_FH            = 7
    pure val NLM4_FBIG                = 8
    pure val NLM4_FAILED              = 9

    /// fsh4_mode / fsh4_access (the DOS share half)
    pure val FSM_DN  = 0
    pure val FSM_DR  = 1
    pure val FSM_DW  = 2
    pure val FSM_DRW = 3
    pure val FSA_NONE = 0
    pure val FSA_R    = 1
    pure val FSA_W    = 2
    pure val FSA_RW   = 3

    pure val NLM_PROCS = Set(
        "NLMPROC4_NULL", "NLMPROC4_TEST", "NLMPROC4_LOCK", "NLMPROC4_CANCEL",
        "NLMPROC4_UNLOCK", "NLMPROC4_GRANTED",
        "NLMPROC4_TEST_MSG", "NLMPROC4_LOCK_MSG", "NLMPROC4_CANCEL_MSG",
        "NLMPROC4_UNLOCK_MSG", "NLMPROC4_GRANTED_MSG",
        "NLMPROC4_TEST_RES", "NLMPROC4_LOCK_RES", "NLMPROC4_CANCEL_RES",
        "NLMPROC4_UNLOCK_RES", "NLMPROC4_GRANTED_RES",
        "NLMPROC4_RESERVED_16", "NLMPROC4_RESERVED_17",
        "NLMPROC4_RESERVED_18", "NLMPROC4_RESERVED_19",
        "NLMPROC4_SHARE", "NLMPROC4_UNSHARE", "NLMPROC4_NM_LOCK",
        "NLMPROC4_FREE_ALL"
    )

    // ------------------------------------------------------------------
    // Domain
    // ------------------------------------------------------------------

    /// Files are named by a small integer.  STALE_FILE stands for a handle
    /// the server cannot decode; the harness sends deliberate garbage for it.
    pure val STALE_FILE = -1

    type Owner = { caller: str, oh: int, svid: int }

    /// A held or requested lock.  `wireLen` is as sent (0 and EOF_LEN both
    /// mean to-EOF); `excl` distinguishes a write lock from a read lock.
    type Lock = {
        file: int,
        owner: Owner,
        offset: int,
        wireLen: int,
        excl: bool
    }

    /// The wire spelling of "to end of file" that is not 0.  The harness
    /// sends 0xffffffffffffffff for it.
    pure val EOF_LEN = -1

    /// Stored (POSIX) length: 0 means to-EOF.
    pure def posixLen(wireLen: int): int =
        if (wireLen <= 0) 0 else wireLen

    /// Half-open overlap with 0 meaning to-EOF on either side.
    pure def rangesOverlap(aOff: int, aLen: int, bOff: int,
                           bLen: int): bool =
        if (aLen == 0 and bLen == 0) true
        else if (aLen == 0) bOff + bLen > aOff
        else if (bLen == 0) aOff + aLen > bOff
        else bOff + bLen > aOff and aOff + aLen > bOff

    pure def locksOverlap(a: Lock, b: Lock): bool =
        a.file == b.file and
        rangesOverlap(a.offset, posixLen(a.wireLen),
                      b.offset, posixLen(b.wireLen))

    pure def sameOwner(a: Owner, b: Owner): bool =
        a.caller == b.caller and a.oh == b.oh and a.svid == b.svid

    // ------------------------------------------------------------------
    // Conflict
    // ------------------------------------------------------------------

    /**
     * The locks already held that stand in the way of `probe`.
     *
     * The POSIX rule: a different owner's overlapping lock conflicts unless
     * both sides are shared.  A lock never conflicts with its own owner --
     * that is what makes a re-lock or a range merge possible rather than a
     * deadlock against oneself.
     */
    pure def conflictsWith(held: List[Lock], probe: Lock): List[Lock] =
        held.select(l =>
            locksOverlap(l, probe) and
            not(sameOwner(l.owner, probe.owner)) and
            (l.excl or probe.excl))

    pure def hasConflict(held: List[Lock], probe: Lock): bool =
        conflictsWith(held, probe).length() > 0

    /**
     * The exact lock a request names: owner + file + exact offset and
     * length.  A repeat LOCK uses this to recognize an idempotent retry: a
     * client holding two non-overlapping ranges on one file with one owner
     * needs the range to pick the right one.
     *
     * The mode is NOT part of the match -- a repeat LOCK carries no
     * meaningful one for this purpose -- which has a consequence worth
     * naming: a LOCK that names a range this owner already holds is
     * answered GRANTED as an idempotent retry even when it asks for a
     * DIFFERENT mode, so an upgrade from shared to exclusive is a silent
     * no-op rather than a conflict test.  `upgradeIsNoop` says whether the
     * server under test behaves that way; a server that instead re-evaluates
     * the request can conflict and deny.
     */
    pure def findExact(held: List[Lock], probe: Lock): List[Lock] =
        held.select(l =>
            l.file == probe.file and
            sameOwner(l.owner, probe.owner) and
            l.offset == probe.offset and
            posixLen(l.wireLen) == posixLen(probe.wireLen))

    pure def holdsExact(held: List[Lock], probe: Lock): bool =
        findExact(held, probe).length() > 0

    /// Containment, with 0 meaning to-EOF on either side: is
    /// [aOff, aOff+aLen) inside [bOff, bOff+bLen)?
    pure def rangeWithin(aOff: int, aLen: int, bOff: int,
                         bLen: int): bool =
        aOff >= bOff and
        (bLen == 0 or (aLen != 0 and aOff + aLen <= bOff + bLen))

    /**
     * UNLOCK's reach: the owner's locks on the file that lie WITHIN the
     * named range are released, not only an exactly-equal one -- every real
     * client unlocks [0, to-EOF) at close(2) to drop whatever it still
     * holds on the file, and an exact-match unlock would leave those locks
     * (and the open handles pinning their files) held forever.
     * Containment only: a lock straddling the range boundary would need a
     * split, which the server under test does not implement and no known
     * client emits.
     */
    pure def dropWithin(held: List[Lock], probe: Lock): List[Lock] =
        held.select(l => not(
            l.file == probe.file and
            sameOwner(l.owner, probe.owner) and
            rangeWithin(l.offset, posixLen(l.wireLen),
                        probe.offset, posixLen(probe.wireLen))))

    // ------------------------------------------------------------------
    // LOCK
    // ------------------------------------------------------------------

    /**
     * The status a LOCK request produces.
     *
     *   inGrace         the server is in its post-restart grace window and
     *                   only reclaim requests are admitted
     *   upgradeIsNoop   see findExact
     *
     * Order matters and mirrors what a server does: the file handle is
     * validated first, then grace, then the idempotent retry, and only then
     * is the conflict test reached.
     */
    pure def lockStatus(held: List[Lock], probe: Lock, block: bool,
                        reclaim: bool, inGrace: bool,
                        upgradeIsNoop: bool): int =
        if (probe.file == STALE_FILE) NLM4_STALE_FH
        else if (inGrace and not(reclaim)) NLM4_DENIED_GRACE_PERIOD
        else if (upgradeIsNoop and holdsExact(held, probe)) NLM4_GRANTED
        else if (not(hasConflict(held, probe))) NLM4_GRANTED
        else if (block) NLM4_BLOCKED
        else NLM4_DENIED

    /// The lock set after a LOCK.  Only an outright grant of a range this
    /// owner does not already hold inserts anything; a BLOCKED request is
    /// queued instead (see `blockedAfterLock`), and an idempotent retry
    /// leaves the existing entry exactly as it was, mode included.
    pure def heldAfterLock(held: List[Lock], probe: Lock,
                           status: int): List[Lock] =
        if (status != NLM4_GRANTED) held
        else if (holdsExact(held, probe)) held
        else held.append(probe)

    // ------------------------------------------------------------------
    // The blocking queue
    // ------------------------------------------------------------------

    /**
     * A queued blocking request.  It carries two things besides the lock,
     * both because they decide what happens when the wait ends:
     *
     *   monitor  a deferred grant monitors its holder exactly as an
     *            immediate one does -- and NM_LOCK, the non-monitored form,
     *            does not.
     *   msg      whether the request arrived asynchronously.  A queued
     *            NLMPROC4_LOCK_MSG that is later CANCELled is told so with
     *            a final NLMPROC4_LOCK_RES carrying NLM4_DENIED; the
     *            synchronous form has nothing left to answer on, because
     *            its RPC completed when the interim NLM4_BLOCKED went out.
     */
    type Queued = { lock: Lock, monitor: bool, msg: bool }

    /**
     * A blocking LOCK that could not be granted is queued and answered with
     * the interim NLM4_BLOCKED.  When the range frees up the request is
     * granted, and because its RPC is long since finished the grant is
     * delivered out of band, as an NLMPROC4_GRANTED call back to the client.
     *
     * The queue is drained in arrival order, and a queued request is
     * promoted only when nothing conflicts with it any more -- promoting one
     * can leave a later one still blocked, so this is a fold, not a filter.
     */
    pure def promoteBlocked(held: List[Lock],
                            queue: List[Queued]): { held: List[Lock],
                                                    queue: List[Queued],
                                                    granted: List[Queued] } =
        queue.foldl({ held: held, queue: List(), granted: List() },
                    (acc, q) =>
                        if (hasConflict(acc.held, q.lock))
                            { held: acc.held,
                              queue: acc.queue.append(q),
                              granted: acc.granted }
                        else
                            { held: acc.held.append(q.lock),
                              queue: acc.queue,
                              granted: acc.granted.append(q) })

    /**
     * Release one client's locks the way a server does, and let the wait
     * queue run.
     *
     * The releases happen ONE AT A TIME, each followed by a pump.  That is
     * not an implementation detail: dropping a client's locks is not atomic
     * with respect to the queue, so a waiter whose range is satisfied by a
     * PARTIAL release is granted before a wider waiter that is still blocked
     * by whatever has not been released yet -- and the wider waiter then
     * finds the narrow one in its way and stays queued.  Releasing
     * everything first and pumping once would hand the range to the wider
     * waiter instead, which is a different, observable outcome.
     *
     * The locks go in the order the client acquired them, which is the order
     * a per-client list holds them in.
     */
    pure def releaseClient(held: List[Lock], queue: List[Queued],
                           caller: str): { held: List[Lock],
                                           queue: List[Queued],
                                           granted: List[Queued] } =
        held.select(l => l.owner.caller == caller)
            .foldl({ held: held, queue: queue, granted: List() }, (acc, d) => {
                val remaining = acc.held.select(l => not(l == d))
                val pumped = promoteBlocked(remaining, acc.queue)
                { held: pumped.held,
                  queue: pumped.queue,
                  granted: acc.granted.concat(pumped.granted) }
            })

    /// CANCEL withdraws a queued blocking request.  RFC 1813 keys it by the
    /// mode as well as the owner and range, because a client may have two
    /// outstanding requests for one range.  The reply is GRANTED whether or
    /// not anything was found.
    pure def cancelMatches(q: Queued, probe: Lock): bool =
        q.lock.file == probe.file and
        sameOwner(q.lock.owner, probe.owner) and
        q.lock.offset == probe.offset and
        posixLen(q.lock.wireLen) == posixLen(probe.wireLen) and
        q.lock.excl == probe.excl

    pure def cancelQueued(queue: List[Queued], probe: Lock): List[Queued] =
        queue.select(q => not(cancelMatches(q, probe)))

    /// The requests a CANCEL withdrew, which are the ones owed a final
    /// NLMPROC4_LOCK_RES if they arrived asynchronously.
    pure def cancelTaken(queue: List[Queued], probe: Lock): List[Queued] =
        queue.select(q => cancelMatches(q, probe))

    // ------------------------------------------------------------------
    // TEST
    // ------------------------------------------------------------------

    /**
     * TEST reports whether the range is available, and when it is not,
     * describes ONE conflicting holder.  Which one is not determined by the
     * protocol when several conflict, so the model reports the whole
     * candidate set and the oracle checks the server named a member of it.
     *
     * The holder's svid and oh are informational; a server whose lock
     * arbitration does not retain the requester's identity reports zeroes
     * for both, which is legal and is what `holderIdentified` distinguishes.
     */
    pure def testStatus(held: List[Lock], probe: Lock): int =
        if (probe.file == STALE_FILE) NLM4_STALE_FH
        else if (hasConflict(held, probe)) NLM4_DENIED
        else NLM4_GRANTED

    // ------------------------------------------------------------------
    // SHARE / UNSHARE (the DOS share-reservation half)
    // ------------------------------------------------------------------

    type ShareEnt = {
        file: int,
        caller: str,
        oh: int,
        mode: int,       /* fsh4_mode:   what others are denied */
        access: int      /* fsh4_access: what this holder wants */
    }

    /// Bit tests over the two-bit access/deny words.
    pure def wantsRead(access: int): bool = access == FSA_R or access == FSA_RW
    pure def wantsWrite(access: int): bool = access == FSA_W or access == FSA_RW
    pure def deniesRead(mode: int): bool = mode == FSM_DR or mode == FSM_DRW
    pure def deniesWrite(mode: int): bool = mode == FSM_DW or mode == FSM_DRW

    /// A new reservation is refused when it wants something an existing
    /// holder denies, or denies something an existing holder is using.  A
    /// holder never conflicts with itself.
    pure def shareConflicts(shares: List[ShareEnt],
                            probe: ShareEnt): bool =
        shares.indices().exists(i =>
            shares[i].file == probe.file and
            not(shares[i].caller == probe.caller and shares[i].oh == probe.oh) and
            ((wantsRead(probe.access) and deniesRead(shares[i].mode)) or
             (wantsWrite(probe.access) and deniesWrite(shares[i].mode)) or
             (deniesRead(probe.mode) and wantsRead(shares[i].access)) or
             (deniesWrite(probe.mode) and wantsWrite(shares[i].access))))

    /**
     * The status a SHARE produces.  `enforced` selects between the two
     * legitimate server postures: honour the reservations, or accept them
     * without enforcement.  DOS share modes are advisory and essentially
     * unused by modern clients, so accepting everything is common -- but it
     * is a choice, and a trace generated for one posture must not be
     * replayed against the other.
     */
    pure def shareStatus(shares: List[ShareEnt], probe: ShareEnt,
                         enforced: bool): int =
        if (probe.file == STALE_FILE) NLM4_STALE_FH
        else if (enforced and shareConflicts(shares, probe)) NLM4_DENIED
        else NLM4_GRANTED

    pure def sharesAfterShare(shares: List[ShareEnt], probe: ShareEnt,
                              status: int): List[ShareEnt] =
        if (status != NLM4_GRANTED) shares
        else if (shares.indices().exists(i =>
                     shares[i].file == probe.file and
                     shares[i].caller == probe.caller and
                     shares[i].oh == probe.oh)) shares
        else shares.append(probe)

    pure def sharesAfterUnshare(shares: List[ShareEnt],
                                probe: ShareEnt): List[ShareEnt] =
        shares.select(s => not(
            s.file == probe.file and
            s.caller == probe.caller and
            s.oh == probe.oh))
}
