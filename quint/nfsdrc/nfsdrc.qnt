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
 * Every step is one RPC (or one reconnect).  `lastOp` records the call and the
 * reply the server must produce; the state records the directory, which the
 * harness re-reads after every step -- a cache that answers with the right
 * status from the wrong entry is invisible in the reply and obvious in the
 * directory.
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

    type Op =
        | ONull({ conn: int })
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
        match hit {
            | Hit(r) => all {
                dir' = dir, nextId' = nextId, cache3' = cache3, cache40' = cache40,
                gen' = gen, tag' = tag, recent' = remember(recent, sent),
                lastOp' = OV3({ conn: conn, xid: xid, cred: cred, proc: proc,
                                act: act, served: SReplayed, st: r.st,
                                tag: r.tag }),
            }
            | Miss => {
                val e = runAct(dir, nextId, act, false)
                val t = tag + 1
                all {
                    dir' = e.d, nextId' = e.nextId, cache40' = cache40, gen' = gen,
                    tag' = t, recent' = remember(recent, sent),
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
                lastOp' = OV4({ conn: conn, xid: xid, cred: cred, act: act,
                                served: SReplayed, st: r.st, tag: r.tag }),
            }
            | Miss => {
                val e = runAct(dir, nextId, act, true)
                val t = tag + 1
                all {
                    dir' = e.d, nextId' = e.nextId, cache3' = cache3, gen' = gen,
                    tag' = t, recent' = remember(recent, sent),
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
        lastOp' = OReconnect({ conn: conn }),
    }

    /// A round trip that touches nothing.  Present so a trace can separate two
    /// steps in time without changing any state the caches read.
    action nullCall(conn: int): bool = all {
        dir' = dir, nextId' = nextId, cache3' = cache3, cache40' = cache40,
        gen' = gen, tag' = tag, recent' = recent,
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
        // NFSv4 CREATE makes non-regular objects only -- a regular file is
        // OPEN's job (RFC 7530 Section 16.4) -- so the NFSv4 traces choose from
        // the two types their CREATE can actually ask for.
        nondet t = (if (v4Proto) Set(T_DIR, T_LNK)
                    else Set(T_REG, T_DIR, T_LNK)).oneOf()
            call(v4Proto, c, x, u, ACreate({ name: n, ftype: t })),
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
        any {
            all { linkableFhs(dir).size() > 0,
                  nondet h = linkableFhs(dir).oneOf()
                      call(false, c, x, u, ALink({ src: h, to: m })) },
            nondet h = liveFhs(dir).oneOf()
                any {
                    nondet z = Set(0, 4096).oneOf()
                        call(false, c, x, u, ASetsize({ fh: h, size: z })),
                    call(false, c, x, u, AGetattr({ fh: h })),
                },
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

    action step = any {
        stepV3,
        stepV4,
        stepRetransmit,
        stepRetransmit,
        stepTransport,
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
    }
}
