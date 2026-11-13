// SPDX-FileCopyrightText: 2026 The Quint Specs Authors
//
// SPDX-License-Identifier: MIT

/**
 * nfsdrc.qnt -- the duplicate-request caches of NFSv3 and NFSv4.0.
 *
 * Both exist for the same reason and are told apart by one decision: what a
 * cache entry belongs to.
 *
 *   NFSv3 has no client identity on the wire, so an entry belongs to a source
 *   ADDRESS.  Nothing announces that a client has gone, so entries have no
 *   natural lifetime, and everything behind one address -- a NAT, a container
 *   host, several users on one machine -- shares a cache.  The upside is that
 *   the cache follows the client across a reconnect, which is exactly when a
 *   retransmit happens.
 *
 *   NFSv4.0 runs over a connection-oriented transport and a connection belongs
 *   to one client, so an entry belongs to a CONNECTION.  That is strictly
 *   narrower -- no amount of address sharing can cross it -- and it gives
 *   entries a lifetime: they die with the connection.  The cost is that a
 *   retransmit arriving on a new connection is not covered, which for v4.0 is
 *   acceptable because a reconnecting client must re-establish through
 *   SETCLIENTID anyway and its seqid-sequenced state operations have their own
 *   per-owner replay cache (RFC 7530 Section 9.1.7).
 *
 * The two are modeled together because the interesting traces move between
 * them: the same reconnect that makes an address-scoped entry answer makes a
 * connection-scoped one disappear, and a suite that could only do one of those
 * would be asserting half of each rule.
 *
 * Almost every step is one RPC (or one reconnect).  `lastOp` records the call
 * and the reply the server must produce; the state records the directory,
 * which the harness re-reads after every step -- a cache that answers with the
 * right status from the wrong entry is invisible in the reply and obvious in
 * the directory.
 *
 * The exception is the one case an atomic RPC cannot express: a retransmit
 * that arrives while its original is still executing.  That is the ordinary
 * case after a client loses its connection -- it reconnects and resends long
 * before a slow original finishes -- and a cache that only learns of a request
 * once its reply exists has nothing to answer it with, so it executes it a
 * second time.  An NFSv3 original can therefore be PARKED: it has arrived and
 * claimed its identity in the cache, but not yet executed.  Until it COMPLETES,
 * a retransmit of it is never executed; it is held for the original's reply or
 * dropped for the client to send again.  See `v3Park`.
 */
module nfsdrc {

    import drcCache.* from "./drc_cache"
    import drcOps.* from "./drc_ops"

    // ==================================================================
    // Configuration
    // ==================================================================

    /**
     * Whether the server keeps an NFSv3 duplicate-request cache at all.
     *
     * It is a choice, not a requirement: RFC 1813 does not mention one, and a
     * server without one is not violating anything -- it simply re-executes
     * retransmits, which is what NFSv3 servers did for years.  Both answers
     * are under test because both are shipped: chimera's is off by default.
     */
    const V3_DRC: bool

    /**
     * Which source address the server sees each connection as coming from.
     *
     * This is a property of the transport, not of the protocol, and it is the
     * whole of the NFSv3 cache's notion of a client.  Two connections mapped
     * to one address are one client as far as the v3 cache is concerned; the
     * NFSv4.0 cache is unaffected either way.
     */
    const ADDR_OF: int -> str

    /**
     * Whether the caches separate requests made under different credentials.
     *
     * They should.  Two users behind one address can send byte-identical
     * requests, and answering one from the other's entry silently drops a
     * mutation -- the same failure a cache exists to prevent, aimed at a
     * different victim.  RFC 8881 Section 2.10.6.1.3.1 makes this a MUST for
     * the NFSv4.1 reply cache; nothing says otherwise for v3 or v4.0, where
     * the hazard is identical and the RFCs simply do not discuss a cache.
     *
     * The false setting describes a server that checksums only the procedure
     * arguments -- which begin after the RPC header, and so exclude the
     * credential.  It is kept under test rather than deleted because it is
     * what an unfixed server does, and because a trace generated against it
     * is the shortest demonstration of the difference.
     */
    const KEY_CRED: bool

    /**
     * How many replies one NFSv4.0 connection's cache holds before the oldest
     * is evicted.  Bounded because a connection could otherwise accumulate
     * entries without limit; the bound is a resource choice, and the only
     * requirement is that it exceed the number of non-idempotent requests a
     * client keeps in flight.
     */
    const V40_SLOTS: int

    /// The directory these traces work in, as it appears in a digest.
    const DIR: str

    /// The object identity of that directory.  It is created before the trace
    /// starts, so it is outside the id sequence the trace itself mints.
    pure val DIR_FH: int = 0

    /// The names available.  Closed because a digest compares concrete
    /// arguments; every name a trace can use must be one of these.
    const NAMES: Set[str]

    /// The connections the client may use.
    const CONNS: Set[int]

    /// The credentials the client may present.
    const CREDS: Set[int]

    /**
     * The transaction ids the traces draw on.  A small set on purpose: an
     * XID is 32 bits and a real client reuses one within a few seconds of
     * traffic, so reuse is the normal case and not an edge case.  Everything
     * this suite is about happens when two requests share one.
     */
    const XIDS: Set[int]

    // ==================================================================
    // Replies and steps
    // ==================================================================

    /**
     * How a reply was produced.  The harness cannot see this directly -- that
     * is the point of a cache -- so it checks the two things that follow from
     * it: the reply must be the one `tag` names (byte for byte, not merely the
     * same status), and the directory must show one execution, not two.
     */
    type Served =
        | SExecuted
        | SReplayed

    /**
     * What becomes of a retransmit that finds its original still in progress.
     * It is never executed -- that is the whole rule -- so the only question is
     * whether the server holds it for the original's reply or drops it for the
     * client to send again.
     *
     *   WHeld          held, and answered with the original's reply when the
     *                  original completes.
     *   WDropOrigin    it came in on the original's own connection, which the
     *                  original's reply will reach anyway.
     *   WDropWaiting   its connection already has one held; one reply under the
     *                  XID on the connection the client listens on answers it.
     */
    type Wait =
        | WHeld
        | WDropOrigin
        | WDropWaiting

    type Op =
        | ONull({ conn: int })
        | OV3Park({ conn: int, xid: int, cred: int, proc: int, act: Act })
        | OV3Wait({ conn: int, xid: int, cred: int, proc: int, act: Act,
                    fate: Wait })
        | OV3Done({ conn: int, xid: int, cred: int, proc: int, act: Act,
                    live: bool, answered: Set[int], st: int, tag: int })
        | OV3({ conn: int, xid: int, cred: int, proc: int, act: Act,
                served: Served, st: int, tag: int })
        | OV4({ conn: int, xid: int, cred: int, act: Act,
                served: Served, st: int, tag: int })
        | OReconnect({ conn: int })

    // ==================================================================
    // State
    // ==================================================================

    /// A request as it was sent, so it can be sent again.  A retransmit is
    /// not a fresh request that happens to look similar; it is the same bytes
    /// under the same identity, and the only way to produce one is to keep
    /// what was sent.
    type Sent = { v4Proto: bool, conn: int, xid: int, cred: int, act: Act }

    var dir: Dir              // the test directory's contents
    var nextId: int           // identity to give the next object created
    var cache3: Cache         // the NFSv3 cache, address-scoped
    var cache40: Cache        // the NFSv4.0 cache, connection-scoped
    var gen: int -> int       // per connection: which incarnation of it is open
    var tag: int              // executions so far; names each reply
    var recent: List[Sent]    // what can still be retransmitted, oldest first
    var lastOp: Op

    /**
     * An NFSv3 original in progress: the request, its key, the incarnation of
     * the connection it arrived on, and the connections a retransmit of it is
     * held on.  At most one -- one is all it takes to put a retransmit inside
     * the window, and a second would only multiply the interleavings.
     */
    type Pend = { sent: Sent, key: ReqId, gen: int, waiters: Set[ConnId] }
    var pend: List[Pend]

    /// How far back a trace may reach for something to retransmit.  A real
    /// client retransmits what is still outstanding, which is a short list.
    pure val RECENT_MAX = 8

    pure def remember(r: List[Sent], s: Sent): List[Sent] = {
        val g = r.append(s)
        if (g.length() > RECENT_MAX) g.slice(1, g.length()) else g
    }

    /// A deterministic representative of a set, for seeding.
    pure def firstStr(s: Set[str]): str = s.fold("", (a, x) => if (a == "") x else a)
    pure def firstInt(s: Set[int]): int = s.fold(0, (a, x) => if (a == 0) x else a)

    action init = all {
        dir' = Map(),
        nextId' = 1,
        cache3' = [],
        cache40' = [],
        gen' = CONNS.mapBy(_ => 1),
        tag' = 0,
        // Seeded with a request that changes nothing, so the retransmit step
        // always has something to choose and needs no emptiness guard.
        recent' = [ { v4Proto: false, conn: firstInt(CONNS),
                      xid: firstInt(XIDS), cred: firstInt(CREDS),
                      act: ALookup({ name: firstStr(NAMES) }) } ],
        lastOp' = ONull({ conn: firstInt(CONNS) }),
        pend' = [],
    }

    /// The connection as the caches see it: which one, and which incarnation.
    pure def connId(c: int, g: int -> int): ConnId = { id: c, gen: g.get(c) }

    /// The credential the key carries.  A server that does not separate
    /// requests by principal keys them all the same, which is what makes two
    /// users' identical requests collide.
    pure def keyCred(cred: int): int = if (KEY_CRED) cred else 0

    // ==================================================================
    // NFSv3
    // ==================================================================

    /**
     * One NFSv3 request.
     *
     * The order is the server's: decide whether the procedure is one this
     * cache covers, and if it is not, hand the request straight to the real
     * dispatcher without so much as a lookup.  That early return is why a
     * LOOKUP, whose arguments are byte-identical to a REMOVE's, can never be
     * answered from a REMOVE's entry even though their digests agree.
     */
    action v3(conn: int, xid: int, cred: int, act: Act): bool = {
        val proc      = act3Proc(act)
        val cacheable = V3_DRC and proc3Cacheable(proc)
        val key       = { scope: ByAddress(ADDR_OF.get(conn)),
                          call: { rpcProc: proc, body: act3Digest(DIR, act) },
                          xid: xid, cred: keyCred(cred) }
        val hit       = if (cacheable) drcLookup(cache3, key) else Miss
        val sent      = { v4Proto: false, conn: conn, xid: xid, cred: cred,
                          act: act }
        if (cacheable and pend.length() > 0 and pend[0].key == key)
            v3InProgress(conn, xid, cred, act, proc, sent)
        else match hit {
            | Hit(r) => all {
                dir' = dir, nextId' = nextId, cache3' = cache3, cache40' = cache40,
                gen' = gen, tag' = tag, recent' = remember(recent, sent),
                pend' = pend,
                lastOp' = OV3({ conn: conn, xid: xid, cred: cred, proc: proc,
                                act: act, served: SReplayed, st: r.st,
                                tag: r.tag }),
            }
            | Miss => {
                val e = runAct(dir, nextId, act, false)
                val t = tag + 1
                all {
                    dir' = e.d, nextId' = e.nextId, cache40' = cache40, gen' = gen,
                    tag' = t, recent' = remember(recent, sent), pend' = pend,
                    cache3' = if (cacheable)
                                  drcInsert(cache3, key, { tag: t, st: e.st }, 0)
                              else cache3,
                    lastOp' = OV3({ conn: conn, xid: xid, cred: cred,
                                    proc: proc, act: act, served: SExecuted,
                                    st: e.st, tag: t }),
                }
            }
        }
    }

    // ==================================================================
    // NFSv3: an original in progress
    // ==================================================================

    /**
     * The operations an original may be parked with: the ones that name their
     * object by directory and name.  An original executes when it completes,
     * possibly many steps after it was parked, and a handle-based one could by
     * then name an object that is gone -- the timing-dependent STALE answer
     * the rest of this model is careful never to ask for (see stepV3Only).
     */
    pure def parkable(a: Act): bool = match a {
        | ACreate(_) => true
        | ARemove(_) => true
        | ARename(_) => true
        | _ => false
    }

    /**
     * An NFSv3 request arrives and claims its identity in the cache, but does
     * not execute yet.
     *
     * This is what a server must do for the window between a request's arrival
     * and its reply to be covered at all: the cache learns of a request when it
     * arrives, not when its reply exists.  Nothing visible changes -- the
     * directory is as it was and there is no reply -- until `v3Complete`.
     *
     * Only a request the cache would otherwise execute can be parked: one it
     * covers, that is not already answered from it.
     */
    action v3Park(conn: int, xid: int, cred: int, act: Act): bool = {
        val proc = act3Proc(act)
        val key  = { scope: ByAddress(ADDR_OF.get(conn)),
                     call: { rpcProc: proc, body: act3Digest(DIR, act) },
                     xid: xid, cred: keyCred(cred) }
        val sent = { v4Proto: false, conn: conn, xid: xid, cred: cred,
                     act: act }
        all {
            V3_DRC,
            proc3Cacheable(proc),
            parkable(act),
            pend.length() == 0,
            not(drcHit(cache3, key)),
            dir' = dir, nextId' = nextId, cache3' = cache3, cache40' = cache40,
            gen' = gen, tag' = tag, recent' = remember(recent, sent),
            pend' = [{ sent: sent, key: key, gen: gen.get(conn),
                       waiters: Set() }],
            lastOp' = OV3Park({ conn: conn, xid: xid, cred: cred, proc: proc,
                                act: act }),
        }
    }

    /**
     * A retransmit of the original in progress.  It is not executed and not
     * answered now; whether it is held for the original's reply depends only
     * on the connection it came in on.  A connection is named with its
     * incarnation: the original's connection reopened is a new connection, and
     * a retransmit on it is held like one on any other.
     */
    action v3InProgress(conn: int, xid: int, cred: int, act: Act, proc: int,
                        sent: Sent): bool = {
        val p    = pend[0]
        val cid  = connId(conn, gen)
        val fate = if (cid == { id: p.sent.conn, gen: p.gen }) WDropOrigin
                   else if (p.waiters.contains(cid)) WDropWaiting
                   else WHeld
        all {
            dir' = dir, nextId' = nextId, cache3' = cache3, cache40' = cache40,
            gen' = gen, tag' = tag, recent' = remember(recent, sent),
            pend' = if (fate == WHeld)
                        [{ ...p, waiters: p.waiters.union(Set(cid)) }]
                    else pend,
            lastOp' = OV3Wait({ conn: conn, xid: xid, cred: cred, proc: proc,
                                act: act, fate: fate }),
        }
    }

    /**
     * The original executes, once, and its reply is cached.  Every retransmit
     * held on a connection that is still open is answered with that reply; so
     * is the original itself, if its own connection is.
     */
    action v3Complete: bool = all {
        pend.length() == 1,
        {
            val p = pend[0]
            val e = runAct(dir, nextId, p.sent.act, false)
            val t = tag + 1
            all {
                dir' = e.d, nextId' = e.nextId, cache40' = cache40, gen' = gen,
                tag' = t, recent' = recent, pend' = [],
                cache3' = drcInsert(cache3, p.key, { tag: t, st: e.st }, 0),
                lastOp' = OV3Done({
                    conn: p.sent.conn, xid: p.sent.xid, cred: p.sent.cred,
                    proc: act3Proc(p.sent.act), act: p.sent.act,
                    live: gen.get(p.sent.conn) == p.gen,
                    answered: p.waiters.filter(w => gen.get(w.id) == w.gen)
                                       .map(w => w.id),
                    st: e.st, tag: t }),
            }
        },
    }

    // ==================================================================
    // NFSv4.0
    // ==================================================================

    /**
     * One NFSv4.0 COMPOUND.
     *
     * Unlike the v3 path, the lookup runs for every COMPOUND, read-only ones
     * included: the operations are not known until the body is decoded, and
     * the cache sits in front of that.  It is safe because only a COMPOUND
     * carrying a non-idempotent operation is ever inserted, and the key covers
     * a digest of the whole body -- so a read-only COMPOUND's bytes cannot
     * equal a cached mutating one's, and it always misses and executes.
     */
    action v4(conn: int, xid: int, cred: int, act: Act): bool = {
        val body      = act4Digest(DIR, DIR_FH, act)
        val cacheable = compoundCacheable(body.ops)
        val key       = { scope: ByConn(connId(conn, gen)),
                          call: { rpcProc: PROC4_COMPOUND, body: body },
                          xid: xid, cred: keyCred(cred) }
        val sent      = { v4Proto: true, conn: conn, xid: xid, cred: cred,
                          act: act }
        match drcLookup(cache40, key) {
            | Hit(r) => all {
                dir' = dir, nextId' = nextId, cache3' = cache3, cache40' = cache40,
                gen' = gen, tag' = tag, recent' = remember(recent, sent),
                pend' = pend,
                lastOp' = OV4({ conn: conn, xid: xid, cred: cred, act: act,
                                served: SReplayed, st: r.st, tag: r.tag }),
            }
            | Miss => {
                val e = runAct(dir, nextId, act, true)
                val t = tag + 1
                all {
                    dir' = e.d, nextId' = e.nextId, cache3' = cache3, gen' = gen,
                    tag' = t, recent' = remember(recent, sent), pend' = pend,
                    cache40' = if (cacheable)
                                   drcInsert(cache40, key,
                                             { tag: t, st: nfs4Status(e.st) },
                                             V40_SLOTS)
                               else cache40,
                    lastOp' = OV4({ conn: conn, xid: xid, cred: cred, act: act,
                                    served: SExecuted, st: nfs4Status(e.st),
                                    tag: t }),
                }
            }
        }
    }

    // ==================================================================
    // Transport
    // ==================================================================

    /**
     * Drop a connection and open another in its place.
     *
     * The two caches must answer this differently, and the difference is the
     * whole of what separates them.  Address-scoped entries survive -- a
     * reconnect is the ordinary reason a retransmit exists, so a cache that
     * lost them at exactly that moment would be useless.  Connection-scoped
     * entries go, and MUST go: a server that kept them keyed on a handle it
     * then recycles would answer the next connection from the previous one's
     * cache, which is the address-sharing failure it chose connection scoping
     * to avoid.
     */
    action reconnect(conn: int): bool = all {
        dir' = dir, nextId' = nextId, cache3' = cache3, tag' = tag,
        recent' = recent,
        cache40' = drcDropConn(cache40, connId(conn, gen)),
        gen' = gen.setBy(conn, g => g + 1),
        // An original in progress keeps running: it is already inside the
        // server, and the client going away does not stop it.  Its reply is
        // lost with the connection, but it is still cached, so the client's
        // retransmit on the next connection is answered with it.  A held
        // retransmit on this connection is released, and is not answered.
        pend' = pend,
        lastOp' = OReconnect({ conn: conn }),
    }

    /// A round trip that touches nothing.  Present so a trace can separate two
    /// steps in time without changing any state the caches read.
    action nullCall(conn: int): bool = all {
        dir' = dir, nextId' = nextId, cache3' = cache3, cache40' = cache40,
        gen' = gen, tag' = tag, recent' = recent, pend' = pend,
        lastOp' = ONull({ conn: conn }),
    }

    // ==================================================================
    // Steps
    // ==================================================================

    /**
     * One request, of either protocol, over the whole operation alphabet.
     *
     * Connection, transaction id and credential are chosen independently of
     * the operation, which is what makes reuse happen: a walk over three names
     * and three XIDs revisits (xid, operation, arguments) triples often, and
     * every one of those revisits is a retransmit as far as a cache can tell.
     */
    action call(v4Proto: bool, c: int, x: int, u: int, a: Act): bool =
        if (v4Proto) v4(c, x, u, a) else v3(c, x, u, a)

    /**
     * The operations both protocols carry.  Names are the trace's to choose
     * freely: the interesting states -- a name that exists, one that does not,
     * one whose handle has gone stale -- are reached by the walk rather than
     * by restricting the alphabet.
     */
    action stepShared(v4Proto: bool, c: int, x: int, u: int, n: str,
                      m: str): bool = any {
        // One branch per object type rather than a type chosen inside one
        // create branch: nesting the choice makes each individual type a third
        // as likely as any other operation, and a corpus then has to be three
        // times as long before a replay lands on, say, a MKDIR.  Creates are
        // also the operations whose replay is most visible, so weighting them
        // up is the right way round.
        //
        // NFSv4 CREATE makes non-regular objects only -- a regular file is
        // OPEN's job (RFC 7530 Section 16.4) -- so the regular-file branch is
        // NFSv3's alone.
        call(v4Proto, c, x, u, ACreate({ name: n, ftype: T_DIR })),
        call(v4Proto, c, x, u, ACreate({ name: n, ftype: T_LNK })),
        all { not(v4Proto),
              call(false, c, x, u, ACreate({ name: n, ftype: T_REG })) },

        // RMDIR and REMOVE both, for NFSv3: identical arguments, different
        // procedure numbers, and only the key's procedure field between them.
        // A COMPOUND has one REMOVE for both, so asDir is immaterial there and
        // is left false to keep every v4 request distinct.
        call(v4Proto, c, x, u, ARemove({ name: n, asDir: false })),
        all { not(v4Proto), call(false, c, x, u,
                                 ARemove({ name: n, asDir: true })) },

        call(v4Proto, c, x, u, ARename({ from: n, to: m })),
        call(v4Proto, c, x, u, ALookup({ name: n })),
    }

    /**
     * The operations only the NFSv3 traces carry.
     *
     * All three name their object by a handle rather than by a directory and
     * a name, which is why they are here: a COMPOUND would have to set that
     * handle with a PUTFH, and the NFSv4 traces stay on the directory handle
     * alone -- the cache questions they answer (which operations are cached,
     * which connection an entry belongs to, when it is evicted) do not turn on
     * which object an operation names.
     *
     * The guard is on the handle existing at all, not on it still being live:
     * a handle to a removed name is exactly the interesting case, because a
     * retransmit carrying one must be answered from the cache rather than
     * re-resolved.
     */
    /**
     * The operations only the NFSv3 traces carry.
     *
     * All three name their object by a handle rather than by a directory and a
     * name, which is why they are here: a COMPOUND would have to set that
     * handle with a PUTFH, and the NFSv4 traces stay on the directory handle
     * alone -- the cache questions they answer (which operations are cached,
     * which connection an entry belongs to, when one is evicted, what a
     * reconnect does) do not turn on which object an operation names.
     *
     * The handle is drawn from the objects that currently exist.  A FRESH
     * request on a handle whose object is gone is deliberately not generated
     * here even though the model answers it (NFS3ERR_STALE): what chimera
     * answers depends on whether the handle is still in its own handle cache,
     * which is a timing question, and a corpus that walked into it would be
     * flaky for a reason that has nothing to do with a cache.  The property
     * that matters -- a RETRANSMIT carrying a handle whose object is gone
     * replays rather than re-resolving -- is asserted in the ground-truth
     * probe, where it is deterministic.
     */
    action stepV3Only(c: int, x: int, u: int, m: str): bool = all {
        dir.keys().size() > 0,
        nondet h = liveFhs(dir).oneOf()
        any {
            call(false, c, x, u, ALink({ src: h, to: m })),
            nondet z = Set(0, 4096).oneOf()
                call(false, c, x, u, ASetsize({ fh: h, size: z })),
            call(false, c, x, u, AGetattr({ fh: h })),
        },
    }

    action stepCall(v4Proto: bool): bool = {
        nondet c = CONNS.oneOf()
        nondet x = XIDS.oneOf()
        nondet u = CREDS.oneOf()
        nondet n = NAMES.oneOf()
        nondet m = NAMES.oneOf()
        any {
            stepShared(v4Proto, c, x, u, n, m),
            all { not(v4Proto), stepV3Only(c, x, u, m) },
        }
    }

    action stepV3 = stepCall(false)
    action stepV4 = stepCall(true)

    action stepTransport = {
        nondet c = CONNS.oneOf()
        any {
            reconnect(c),
            nullCall(c),
        }
    }

    /// The whole relation.  Transport events are one branch of three rather
    /// than one of many, so a walk of a few dozen steps reconnects several
    /// times -- which is when an address-scoped entry proves it survived and a
    /// connection-scoped one proves it did not.
    /**
     * Send an earlier request again.
     *
     * Three shapes, and the difference between them is the whole subject:
     *
     *   exact      the same request, under the same identity, on the same
     *              connection.  The one case a cache exists to answer.
     *   elsewhere  the same request on the other connection.  Whether this is
     *              a retransmit depends entirely on the scope: to an
     *              address-keyed cache it is one (both connections come from
     *              the same client as far as it can tell), to a
     *              connection-keyed one it is a new request.
     *   asOther    the same bytes under a different credential.  Never a
     *              retransmit -- a different principal is a different
     *              requester -- and answering it from the cache is how one
     *              user's mutation gets silently dropped.
     *   otherProc  the same bytes, under the same identity, as the OTHER
     *              removal procedure.  REMOVE and RMDIR take an identical
     *              diropargs3, so this is the one case where two genuinely
     *              different requests are byte-identical and only the RPC
     *              procedure number in the key separates them.
     */
    action stepRetransmit = {
        nondet back = 0.to(RECENT_MAX - 1).oneOf()
        val s = recent[if (back < recent.length()) recent.length() - 1 - back
                       else 0]
        all {
            // Same reason as stepV3Only: a retransmit that MISSES executes for
            // real, and executing on a handle whose object is gone is the one
            // outcome a live server answers unpredictably.
            actFhLive(dir, s.act),
            any {
                call(s.v4Proto, s.conn, s.xid, s.cred, s.act),
                nondet c = CONNS.oneOf()
                    call(s.v4Proto, c, s.xid, s.cred, s.act),
                nondet u = CREDS.oneOf()
                    call(s.v4Proto, s.conn, s.xid, u, s.act),
                all { not(s.v4Proto), isRemove(s.act),
                      call(false, s.conn, s.xid, s.cred,
                           flipRemove(s.act)) },
            },
        }
    }

    /// Park an original.  Same choice of operation as stepShared, less the
    /// LOOKUP the cache does not cover.
    action stepPark = {
        nondet c = CONNS.oneOf()
        nondet x = XIDS.oneOf()
        nondet u = CREDS.oneOf()
        nondet n = NAMES.oneOf()
        nondet m = NAMES.oneOf()
        any {
            v3Park(c, x, u, ACreate({ name: n, ftype: T_DIR })),
            v3Park(c, x, u, ACreate({ name: n, ftype: T_LNK })),
            v3Park(c, x, u, ACreate({ name: n, ftype: T_REG })),
            v3Park(c, x, u, ARemove({ name: n, asDir: false })),
            v3Park(c, x, u, ARemove({ name: n, asDir: true })),
            v3Park(c, x, u, ARename({ from: n, to: m })),
        }
    }

    /// Send the original in progress again, on either connection: on its own
    /// it is the client that never lost the connection, on the other the one
    /// that did.  stepRetransmit reaches it too, but only as one of the last
    /// RECENT_MAX requests; this is what makes the window busy.
    action stepRetransmitPending = all {
        pend.length() > 0,
        {
            val s = pend[0].sent
            nondet c = CONNS.oneOf()
                call(false, c, s.xid, s.cred, s.act)
        },
    }

    action step = any {
        stepV3,
        stepV4,
        stepRetransmit,
        stepRetransmit,
        stepTransport,
        stepPark,
        stepRetransmitPending,
        v3Complete,
    }

    // ==================================================================
    // Invariants
    // ==================================================================

    /**
     * The properties that make a cache correct, checked at every state.
     *
     *   - a connection-scoped entry never outlives its connection.  This is
     *     the one that a recycled connection handle breaks.
     *   - no entry names a reply that was never produced.  A tag greater than
     *     the number of executions would mean the cache invented one.
     *   - the v4.0 cache stays within its bound, per connection.  A cache that
     *     grew without limit would be a way to spend a server's memory from
     *     the wire.
     *   - nothing is cached when the v3 cache is switched off.
     */
    val inv: bool = and {
        cache40.select(e =>
            match e.key.scope {
                | ByConn(c) => not(gen.keys().contains(c.id)) or
                               gen.get(c.id) != c.gen
                | ByAddress(_) => true
            }).length() == 0,

        cache3.select(e => e.reply.tag > tag).length() == 0,
        cache40.select(e => e.reply.tag > tag).length() == 0,

        CONNS.forall(c =>
            cache40.select(e => e.key.scope == ByConn({ id: c,
                                                        gen: gen.get(c) }))
                   .length() <= V40_SLOTS),

        V3_DRC or cache3.length() == 0,

        // At most one original in progress, never one the cache has already
        // answered, and none at all without a cache to claim an identity in.
        pend.length() <= 1,
        pend.select(p => drcHit(cache3, p.key)).length() == 0,
        V3_DRC or pend.length() == 0,
    }
}
