// SPDX-FileCopyrightText: 2026 The Quint Specs Authors
//
// SPDX-License-Identifier: MIT

// Concrete instances of the nfsdrc model -- the units `quint run` executes:
//
//   quint run nfsdrc_run.qnt --main=nfsdrcRef --step=step --invariant=inv
//
// Four ship.  Two describe servers a harness can actually stand up and are
// where the trace corpus comes from; two exist so that behaviour no available
// transport can produce stays under test by `quint test`.
//
//   nfsdrcRef        the reference profile: an NFSv3 duplicate-request cache
//                    switched on, the NFSv4.0 one always present, every
//                    connection arriving from one address, and both caches
//                    separating requests by credential.  The corpus.
//
//   nfsdrcNoV3       the same server with the NFSv3 cache switched off, which
//                    is the shipped default.  Small, and its whole job is to
//                    show that the switch is real: every NFSv3 retransmit
//                    re-executes, and the NFSv4.0 cache is unaffected.
//
//   nfsdrcTwoAddr    two connections from two addresses.  An address-scoped
//                    entry must not cross between them.  Unreachable over a
//                    loopback or in-process transport, where every peer has
//                    the same address, so `quint test` only.
//
//   nfsdrcCredBlind  a server that checksums only the procedure arguments and
//                    so cannot tell two users' identical requests apart.  Kept
//                    under test because it is what an unfixed server does and
//                    because the traces it generates are the shortest
//                    statement of what that costs.

module nfsdrcProfiles {

    /// The names the traces work with.  Three is enough for every shape that
    /// matters -- a source, a target, and a third to rename or link into --
    /// and small enough that a random walk revisits them often, which is what
    /// puts two requests on the same name and the same transaction id.
    pure val THREE_NAMES: Set[str] = Set("a", "b", "c")

    /// Two connections, so connection scoping has something to separate.
    pure val TWO_CONNS: Set[int] = Set(1, 2)

    /// Two unprivileged users.  Unprivileged so that neither is the one an
    /// export might map the other onto, and so the two are genuinely different
    /// principals rather than two spellings of root.
    pure val TWO_CREDS: Set[int] = Set(1000, 1001)

    /// One address for every connection: what an in-process or loopback
    /// transport reports, and what a NAT or container host produces in
    /// practice.
    pure val ONE_ADDR: int -> str = Map(1 -> "peer", 2 -> "peer")

    /// One address per connection: two clients the v3 cache can tell apart.
    pure val TWO_ADDRS: int -> str = Map(1 -> "peerA", 2 -> "peerB")

    /**
     * Three transaction ids.  A client's XID counter is 32 bits and monotonic,
     * so in real traffic a repeat means a retransmit; here the counter is the
     * trace's to choose, and three values reused across a walk of a few dozen
     * steps put many pairs of requests on the same one.  That is the point --
     * every question this suite asks is about two requests sharing an XID.
     */
    pure val THREE_XIDS: Set[int] = Set(1, 2, 3)

    /// The directory the traces work in, as a digest names it.
    pure val TEST_DIR: str = "d"

    /// The NFSv4.0 per-connection cache size.  Sixteen covers any plausible
    /// number of non-idempotent requests one client keeps in flight.
    pure val SLOTS_16: int = 16
}

module nfsdrcRef {
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
}

module nfsdrcNoV3 {
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
}

module nfsdrcTwoAddr {
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
}

module nfsdrcCredBlind {
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
}
