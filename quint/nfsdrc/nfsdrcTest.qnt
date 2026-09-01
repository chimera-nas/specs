// SPDX-FileCopyrightText: 2026 The Quint Specs Authors
//
// SPDX-License-Identifier: MIT

// Deterministic self-checks for the nfsdrc model, executed with
//   quint test nfsdrcTest.qnt --main=nfsdrcTestRef
//   quint test nfsdrcTest.qnt --main=nfsdrcTestNoV3
//   quint test nfsdrcTest.qnt --main=nfsdrcTestTwoAddr
//   quint test nfsdrcTest.qnt --main=nfsdrcTestCredBlind
//
// They pin the model's transition logic without a server, so a model
// regression is caught before it can invalidate a generated trace.  The four
// instances differ only in configuration, and that is the point: the same two
// requests are a retransmit under one profile and two separate requests under
// another, and each test says which and why.

// =====================================================================
// The reference profile.
// =====================================================================
module nfsdrcTestRef {
    import drcCache.* from "./drc_cache"
    import drcOps.* from "./drc_ops"
    import nfsdrcProfiles.* from "./nfsdrc_run"

    import nfsdrc(
        V3_DRC = true,
        ADDR_OF = ONE_ADDR,
        KEY_CRED = true,
        V40_SLOTS = SLOTS_16,
        DIR = TEST_DIR,
        NAMES = THREE_NAMES,
        CONNS = TWO_CONNS,
        CREDS = TWO_CREDS,
        XIDS = THREE_XIDS
    ).* from "./nfsdrc"

    // ---- shorthand ---------------------------------------------------
    pure val U1 = 1000
    pure val U2 = 1001
    pure def mkdir(n: str): Act = ACreate({ name: n, ftype: T_DIR })
    pure def rm(n: str): Act = ARemove({ name: n, asDir: false })
    pure def rmdir(n: str): Act = ARemove({ name: n, asDir: true })

    /// The status the last operation reported, whichever protocol carried it.
    val st: int = match lastOp {
        | OV3(o) => o.st
        | OV4(o) => o.st
        | ONull(_) => -1
        | OReconnect(_) => -1
    }

    /// Whether it was answered from a cache.
    val replayed: bool = match lastOp {
        | OV3(o) => o.served == SReplayed
        | OV4(o) => o.served == SReplayed
        | ONull(_) => false
        | OReconnect(_) => false
    }

    /// Which execution's reply it carried.  A replay must name an EARLIER
    /// execution: that is what makes it a replay rather than a fresh answer
    /// that happens to look the same.
    val replyTag: int = match lastOp {
        | OV3(o) => o.tag
        | OV4(o) => o.tag
        | ONull(_) => 0
        | OReconnect(_) => 0
    }

    // ==================================================================
    // NFSv3: the premise
    // ==================================================================

    /// The whole point.  A MKDIR that succeeded, sent again under the same
    /// identity, answers with the reply it produced the first time -- and the
    /// client, which cannot tell a lost reply from a lost request, is told
    /// its directory was created rather than that it already exists.
    run v3ReplayTest =
        init
            .then(v3(1, 1, U1, mkdir("a")))
            .expect(st == NFS3_OK and not(replayed) and replyTag == 1)
            .then(v3(1, 1, U1, mkdir("a")))
            .expect(st == NFS3_OK and replayed and replyTag == 1)
            .expect(dir.keys() == Set("a"))

    /// Without the cache the same pair is a create and a failure, which is
    /// the damage the cache exists to prevent.
    run v3NoCacheContrastTest =
        init
            .then(v3(1, 1, U1, mkdir("a")))
            .then(v3(1, 2, U1, mkdir("a")))
            .expect(st == NFS3ERR_EXIST and not(replayed))

    /// An XID is the only thing separating those two requests, so a cache
    /// that ignored it would answer every MKDIR of "a" from one entry.
    run v3XidInKeyTest =
        init
            .then(v3(1, 1, U1, mkdir("a")))
            .then(v3(1, 3, U1, mkdir("a")))
            .expect(st == NFS3ERR_EXIST)

    /**
     * REMOVE and RMDIR carry byte-identical arguments -- a bare diropargs3 --
     * so their digests agree and only the procedure number tells them apart.
     * A cache that keyed on the digest alone would answer the RMDIR from the
     * REMOVE's entry and leave the directory in place.
     */
    run v3ProcInKeyTest =
        init
            .then(v3(1, 1, U1, mkdir("a")))
            .then(v3(1, 2, U1, rm("a")))
            .expect(st == NFS3ERR_ISDIR)
            // The RMDIR carries the same bytes at the same XID and is a
            // different request only because its procedure number differs.
            .then(v3(1, 2, U1, rmdir("a")))
            .expect(not(replayed) and st == NFS3_OK)
            .expect(dir.keys() == Set())

    /**
     * A LOOKUP's arguments are byte-identical to a REMOVE's too, but a
     * cacheable procedure's entry can never answer it: the server returns
     * before it looks, because the procedure is idempotent and needs no cache.
     */
    run v3IdempotentNotCachedTest =
        init
            .then(v3(1, 1, U1, mkdir("a")))
            .then(v3(1, 2, U1, rm("a")))
            .expect(st == NFS3ERR_ISDIR)
            .then(v3(1, 2, U1, ALookup({ name: "a" })))
            .expect(not(replayed) and st == NFS3_OK)

    /**
     * A second user's byte-identical request is a NEW request.  Answering it
     * from the first user's entry would tell the second its MKDIR succeeded
     * when nothing of the sort happened -- the same silent loss the cache is
     * there to prevent, aimed at a different client.
     */
    run v3CredInKeyTest =
        init
            .then(v3(1, 1, U1, mkdir("a")))
            .then(v3(1, 1, U2, mkdir("a")))
            .expect(not(replayed) and st == NFS3ERR_EXIST)

    /**
     * An address-scoped entry crosses connections, because an address is all
     * the identity NFSv3 has.  This is the cost of that scope and not a
     * defect: with no client identity on the wire there is nothing finer to
     * key on, and the same property is what makes the entry survive the
     * reconnect below.
     */
    run v3CrossesConnectionsTest =
        init
            .then(v3(1, 1, U1, mkdir("a")))
            .then(v3(2, 1, U1, mkdir("a")))
            .expect(replayed and st == NFS3_OK)

    /// And survives a reconnect, which is the ordinary reason a retransmit
    /// exists in the first place.
    run v3SurvivesReconnectTest =
        init
            .then(v3(1, 1, U1, mkdir("a")))
            .then(reconnect(1))
            .then(v3(1, 1, U1, mkdir("a")))
            .expect(replayed and st == NFS3_OK)

    /**
     * An error is a reply like any other, and must be replayed like one.  The
     * client that sent the original was told NOENT; a retransmit that
     * re-executed after the name appeared would remove a file its sender never
     * asked to remove.
     */
    run v3ErrorRepliesCachedTest =
        init
            .then(v3(1, 1, U1, ARemove({ name: "a", asDir: false })))
            .expect(st == NFS3ERR_NOENT)
            .then(v3(1, 2, U1, ACreate({ name: "a", ftype: T_REG })))
            .then(v3(1, 1, U1, ARemove({ name: "a", asDir: false })))
            .expect(replayed and st == NFS3ERR_NOENT)
            .expect(dir.keys() == Set("a"))

    /**
     * A handle outlives its object, and a retransmit carries the handle it was
     * built with.  The SETATTR below is answered from the cache even though
     * the object it names is gone -- re-resolving it would answer STALE for a
     * request that succeeded.
     */
    run v3StaleHandleReplayTest =
        init
            .then(v3(1, 1, U1, ACreate({ name: "a", ftype: T_REG })))
            .then(v3(1, 2, U1, ASetsize({ fh: 1, size: 4096 })))
            .expect(st == NFS3_OK)
            .then(v3(1, 3, U1, rm("a")))
            .then(v3(1, 2, U1, ASetsize({ fh: 1, size: 4096 })))
            .expect(replayed and st == NFS3_OK)

    /// A fresh request on the new incarnation is not that request: different
    /// handle bytes, different digest, no match.
    /// A handle to the object created the second time is different bytes, so
    /// the same SETATTR arguments at the same XID are a different request.
    run v3NewObjectMissesTest =
        init
            .then(v3(1, 1, U1, ACreate({ name: "a", ftype: T_REG })))
            .then(v3(1, 2, U1, ASetsize({ fh: 1, size: 4096 })))
            .then(v3(1, 3, U1, rm("a")))
            .then(v3(1, 4, U1, ACreate({ name: "a", ftype: T_REG })))
            .then(v3(1, 2, U1, ASetsize({ fh: 2, size: 4096 })))
            .expect(not(replayed) and st == NFS3_OK)

    /// A hard link shares its object's handle, so a SETATTR through either name
    /// is literally the same request.
    run v3HardLinkSharesHandleTest =
        init
            .then(v3(1, 1, U1, ACreate({ name: "a", ftype: T_REG })))
            .then(v3(1, 2, U1, ALink({ src: 1, to: "b" })))
            .expect(st == NFS3_OK)
            .then(v3(1, 3, U1, ASetsize({ fh: 1, size: 4096 })))
            .expect(dir.get("a").size == 4096 and dir.get("b").size == 4096)
            // Removing one name leaves the object, and its handle, alive.
            .then(v3(1, 4, U1, rm("a")))
            .then(v3(1, 5, U1, AGetattr({ fh: 1 })))
            .expect(st == NFS3_OK)

    // ==================================================================
    // NFSv4.0
    // ==================================================================

    /// The same premise, one protocol up.
    run v4ReplayTest =
        init
            .then(v4(1, 1, U1, mkdir("a")))
            .expect(st == NFS4_OK and not(replayed))
            .then(v4(1, 1, U1, mkdir("a")))
            .expect(st == NFS4_OK and replayed)

    /**
     * A connection-scoped entry does not cross connections.  This is the
     * difference from NFSv3 and the reason NFSv4.0 chooses this scope: a
     * connection belongs to one client, so no amount of address sharing can
     * let one client be answered from another's entry.
     */
    run v4DoesNotCrossConnectionsTest =
        init
            .then(v4(1, 1, U1, mkdir("a")))
            .then(v4(2, 1, U1, mkdir("a")))
            .expect(not(replayed) and st == NFS4ERR_EXIST)

    /**
     * And it dies with the connection.  A server that kept entries keyed on a
     * connection handle it then recycles would answer the replacement from the
     * old connection's cache -- exactly the confusion connection scoping was
     * chosen to rule out.
     */
    run v4DroppedOnReconnectTest =
        init
            .then(v4(1, 1, U1, mkdir("a")))
            .then(reconnect(1))
            .then(v4(1, 1, U1, mkdir("a")))
            .expect(not(replayed) and st == NFS4ERR_EXIST)

    /// A reconnect leaves the other connection's cache alone.
    run v4ReconnectIsPerConnectionTest =
        init
            .then(v4(1, 1, U1, mkdir("a")))
            .then(v4(2, 2, U1, mkdir("b")))
            .then(reconnect(1))
            .then(v4(2, 2, U1, mkdir("b")))
            .expect(replayed and st == NFS4_OK)

    /**
     * A read-only COMPOUND is looked up like every other -- the operations are
     * not known until the body is decoded -- but never cached, and its bytes
     * cannot equal a cached mutating COMPOUND's, so it always executes.
     */
    run v4IdempotentNotCachedTest =
        init
            .then(v4(1, 1, U1, mkdir("a")))
            .then(v4(1, 2, U1, ALookup({ name: "a" })))
            .expect(not(replayed) and st == NFS4_OK)
            .then(v4(1, 2, U1, mkdir("b")))
            .expect(not(replayed) and st == NFS4_OK)

    /// A second user's identical COMPOUND, same as NFSv3.
    run v4CredInKeyTest =
        init
            .then(v4(1, 1, U1, mkdir("a")))
            .then(v4(1, 1, U2, mkdir("a")))
            .expect(not(replayed) and st == NFS4ERR_EXIST)

    // ==================================================================
    // Bounds
    // ==================================================================

    /**
     * The per-connection cache is bounded and evicts oldest-first.  Sixteen
     * distinct entries fit; the seventeenth pushes the first out, so its
     * retransmit re-executes -- correct behaviour, and the reason a bound has
     * to exceed what a client keeps in flight rather than being arbitrary.
     *
     * Three names is not sixteen, so the entries are made distinct by XID
     * instead, which is what a real client varies anyway.
     */
    run v4EvictsOldestTest =
        init
            .then(v4(1, 1, U1, mkdir("a")))
            .then(v4(1, 2, U1, mkdir("a")))
            .then(v4(1, 3, U1, mkdir("a")))
            .then(v4(1, 4, U1, mkdir("a")))
            .then(v4(1, 5, U1, mkdir("a")))
            .then(v4(1, 6, U1, mkdir("a")))
            .then(v4(1, 7, U1, mkdir("a")))
            .then(v4(1, 8, U1, mkdir("a")))
            .then(v4(1, 9, U1, mkdir("a")))
            .then(v4(1, 10, U1, mkdir("a")))
            .then(v4(1, 11, U1, mkdir("a")))
            .then(v4(1, 12, U1, mkdir("a")))
            .then(v4(1, 13, U1, mkdir("a")))
            .then(v4(1, 14, U1, mkdir("a")))
            .then(v4(1, 15, U1, mkdir("a")))
            .then(v4(1, 16, U1, mkdir("a")))
            .then(v4(1, 17, U1, mkdir("a")))
            // Seventeen distinct entries have been offered to a sixteen-slot
            // cache, so the first is gone and its retransmit re-executes.
            .then(v4(1, 1, U1, mkdir("a")))
            .expect(not(replayed) and st == NFS4ERR_EXIST)
            // The seventeenth is the newest and is still there.
            .then(v4(1, 17, U1, mkdir("a")))
            .expect(replayed and st == NFS4ERR_EXIST)

    // ==================================================================
    // The invariant, on a trace built to stress it
    // ==================================================================

    run invHoldsTest =
        init
            .then(v4(1, 1, U1, mkdir("a")))
            .then(v3(1, 1, U1, mkdir("b")))
            .then(reconnect(1))
            .then(v4(1, 1, U1, mkdir("a")))
            .then(v3(1, 1, U1, mkdir("b")))
            .expect(inv)
}

// =====================================================================
// The NFSv3 cache switched off -- the shipped default.
// =====================================================================
module nfsdrcTestNoV3 {
    import drcCache.* from "./drc_cache"
    import drcOps.* from "./drc_ops"
    import nfsdrcProfiles.* from "./nfsdrc_run"

    import nfsdrc(
        V3_DRC = false,
        ADDR_OF = ONE_ADDR,
        KEY_CRED = true,
        V40_SLOTS = SLOTS_16,
        DIR = TEST_DIR,
        NAMES = THREE_NAMES,
        CONNS = TWO_CONNS,
        CREDS = TWO_CREDS,
        XIDS = THREE_XIDS
    ).* from "./nfsdrc"

    pure val U1 = 1000
    pure def mkdir(n: str): Act = ACreate({ name: n, ftype: T_DIR })

    val st: int = match lastOp {
        | OV3(o) => o.st
        | OV4(o) => o.st
        | ONull(_) => -1
        | OReconnect(_) => -1
    }
    val replayed: bool = match lastOp {
        | OV3(o) => o.served == SReplayed
        | OV4(o) => o.served == SReplayed
        | ONull(_) => false
        | OReconnect(_) => false
    }

    /// Every NFSv3 retransmit re-executes, which is what an NFSv3 server
    /// without a cache has always done.  The client is told its directory
    /// already exists; whether that is acceptable is a deployment choice, and
    /// the flag is how it is made.
    run v3NoCacheTest =
        init
            .then(v3(1, 1, U1, mkdir("a")))
            .then(v3(1, 1, U1, mkdir("a")))
            .expect(not(replayed) and st == NFS3ERR_EXIST)

    /// Nothing is retained, so the invariant's "empty when off" clause holds.
    run v3NothingCachedTest =
        init
            .then(v3(1, 1, U1, mkdir("a")))
            .expect(cache3.length() == 0 and inv)

    /// The NFSv4.0 cache is a separate mechanism and is unaffected: it has no
    /// switch, because it is bounded by the connections that are open.
    run v4UnaffectedTest =
        init
            .then(v4(1, 1, U1, mkdir("a")))
            .then(v4(1, 1, U1, mkdir("a")))
            .expect(replayed and st == NFS4_OK)
}

// =====================================================================
// Two connections from two addresses.
// =====================================================================
module nfsdrcTestTwoAddr {
    import drcCache.* from "./drc_cache"
    import drcOps.* from "./drc_ops"
    import nfsdrcProfiles.* from "./nfsdrc_run"

    import nfsdrc(
        V3_DRC = true,
        ADDR_OF = TWO_ADDRS,
        KEY_CRED = true,
        V40_SLOTS = SLOTS_16,
        DIR = TEST_DIR,
        NAMES = THREE_NAMES,
        CONNS = TWO_CONNS,
        CREDS = TWO_CREDS,
        XIDS = THREE_XIDS
    ).* from "./nfsdrc"

    pure val U1 = 1000
    pure def mkdir(n: str): Act = ACreate({ name: n, ftype: T_DIR })

    val st: int = match lastOp {
        | OV3(o) => o.st
        | OV4(o) => o.st
        | ONull(_) => -1
        | OReconnect(_) => -1
    }
    val replayed: bool = match lastOp {
        | OV3(o) => o.served == SReplayed
        | OV4(o) => o.served == SReplayed
        | ONull(_) => false
        | OReconnect(_) => false
    }

    /**
     * Two addresses are two clients, so the entry does not cross.  This is
     * what an address-scoped cache is supposed to give, and it is exactly what
     * a shared address takes away -- the same request, the same key, two
     * different clients.  A transport where every peer reports one address
     * (a loopback, an in-process one) cannot demonstrate either half.
     */
    run v3AddressSeparatesClientsTest =
        init
            .then(v3(1, 1, U1, mkdir("a")))
            .then(v3(2, 1, U1, mkdir("a")))
            .expect(not(replayed) and st == NFS3ERR_EXIST)

    /// The client's own retransmit still replays.
    run v3OwnRetransmitStillReplaysTest =
        init
            .then(v3(1, 1, U1, mkdir("a")))
            .then(v3(1, 1, U1, mkdir("a")))
            .expect(replayed and st == NFS3_OK)
}

// =====================================================================
// A server that cannot tell two users' identical requests apart.
// =====================================================================
module nfsdrcTestCredBlind {
    import drcCache.* from "./drc_cache"
    import drcOps.* from "./drc_ops"
    import nfsdrcProfiles.* from "./nfsdrc_run"

    import nfsdrc(
        V3_DRC = true,
        ADDR_OF = ONE_ADDR,
        KEY_CRED = false,
        V40_SLOTS = SLOTS_16,
        DIR = TEST_DIR,
        NAMES = THREE_NAMES,
        CONNS = TWO_CONNS,
        CREDS = TWO_CREDS,
        XIDS = THREE_XIDS
    ).* from "./nfsdrc"

    pure val U1 = 1000
    pure val U2 = 1001
    pure def mkdir(n: str): Act = ACreate({ name: n, ftype: T_DIR })

    val st: int = match lastOp {
        | OV3(o) => o.st
        | OV4(o) => o.st
        | ONull(_) => -1
        | OReconnect(_) => -1
    }
    val replayed: bool = match lastOp {
        | OV3(o) => o.served == SReplayed
        | OV4(o) => o.served == SReplayed
        | ONull(_) => false
        | OReconnect(_) => false
    }

    /**
     * What a credential-blind key costs, in three steps.
     *
     * The second user asks for a directory it does not have, is told NFS3_OK,
     * and now believes it created one.  It did not: the directory belongs to
     * the first user's request, and no operation of the second user's ever
     * ran.  Nothing in the reply says so, and the next thing the second user
     * does with what it thinks it created will fail somewhere else entirely.
     *
     * The RFCs are silent for NFSv3 and NFSv4.0 -- neither discusses a reply
     * cache at all -- but RFC 8881 Section 2.10.6.1.3.1 spells out the same
     * situation for the NFSv4.1 reply cache and calls a retry under a
     * different principal a false retry that the replier MUST NOT answer from
     * the cache.  The hazard does not change because the protocol did.
     */
    run v3CredBlindReplaysAcrossUsersTest =
        init
            .then(v3(1, 1, U1, mkdir("a")))
            .then(v3(1, 1, U2, mkdir("a")))
            .expect(replayed and st == NFS3_OK)

    /// The same on NFSv4.0, where a connection scope narrows who can collide
    /// but does not separate two users sharing one connection -- a container
    /// host, or any client multiplexing its users over one mount.
    run v4CredBlindReplaysAcrossUsersTest =
        init
            .then(v4(1, 1, U1, mkdir("a")))
            .then(v4(1, 1, U2, mkdir("a")))
            .expect(replayed and st == NFS4_OK)
}
