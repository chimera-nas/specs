// SPDX-FileCopyrightText: 2026 The Quint Specs Authors
//
// SPDX-License-Identifier: MIT

/**
 * drc_cache.qnt -- what a duplicate-request cache is, independently of the
 * protocol whose requests it holds.
 *
 * A server that executes a non-idempotent request twice has corrupted the
 * client's view of the filesystem: the second CREATE of a name the first one
 * made answers EXIST, the second REMOVE answers NOENT, and the client -- which
 * has no way to tell a lost reply from a lost request -- concludes its
 * operation failed when it succeeded.  Neither NFSv3 nor NFSv4.0 has any
 * in-protocol sequencing to prevent that (NFSv4.1 does: see the session slot
 * table in the nfs4 model), so both rely on the server remembering its recent
 * replies and re-sending one rather than re-executing.  That memory is the
 * duplicate-request cache.
 *
 * A correct cache is defined entirely by what it treats as "the same request":
 *
 *   1. A retransmit -- the same requester, re-presenting the same call under
 *      the same identity -- MUST be answered with the reply the original
 *      produced, and MUST NOT execute.
 *   2. Anything else MUST NOT be answered from the cache.  A different
 *      requester, a different call, or the same call under a different
 *      principal is a new request, and answering it from the cache silently
 *      drops a mutation the client believes it made.
 *
 * Rule 2 is the whole difficulty, because the cache has to decide identity
 * from what the wire carries.  The three parts of an entry's key below are
 * exactly those three clauses of rule 2, and each one is a place a real server
 * has got it wrong:
 *
 *   scope   who the requester is.  NFSv3 has no client identity of its own,
 *           so the source address is all there is; NFSv4.0 has a connection,
 *           which belongs to exactly one client.  Getting this too coarse
 *           lets one client be answered from another's entry.
 *   call    which call it is: the RPC procedure and a digest of the request
 *           body.  The transaction id alone is not enough -- it is only 32
 *           bits and a client is free to reuse one.
 *   cred    on whose behalf.  Two users sharing an address (a container host,
 *           a NAT, a multi-user machine) can present byte-identical calls;
 *           without the credential in the key they are indistinguishable, and
 *           one user's reply answers the other's request.  RFC 8881
 *           Section 2.10.6.1.3.1 makes this explicit for the NFSv4.1 reply
 *           cache -- a retry "that uses a different principal in the RPC
 *           request's credential field that translates to a different user"
 *           is a false retry, and the replier MUST NOT treat it as a replay.
 *           The hazard is identical for v3 and v4.0, which have no such
 *           wording only because neither RFC discusses a reply cache at all.
 */
module drcCache {

    // ==================================================================
    // Identity
    // ==================================================================

    /**
     * Who the requester is, as far as the cache can tell.
     *
     * Address scoping is inherent to NFSv3, which carries no client identity
     * -- the price is that everything behind one address shares a cache.
     * Connection scoping is available to NFSv4.0 and is strictly narrower: a
     * connection belongs to one client, and it also gives entries a lifetime
     * (they die with it) that an address-keyed cache has to invent.
     */
    type Scope =
        | ByAddress(str)
        | ByConn(ConnId)

    /**
     * A connection, as an identity rather than a resource.  `gen` distinguishes
     * a reconnect from the connection it replaced: a server that keys on a
     * reused connection handle without clearing what the previous connection
     * cached would answer a new connection from the old one's entries, so the
     * two must not compare equal.
     */
    type ConnId = { id: int, gen: int }

    /**
     * The call: the RPC procedure number and a digest of the request body.
     *
     * They are separate because the digest does not cover the procedure --
     * a server checksums the argument bytes it was handed, which begin after
     * the RPC header.  Two different procedures can have byte-identical
     * arguments (NFSv3 REMOVE and RMDIR both take a bare diropargs3), so a
     * cache that dropped the procedure from its key would answer an RMDIR
     * from a REMOVE's entry.
     */
    type Call = { rpcProc: int, body: Digest }

    /**
     * The arguments of one operation, at the granularity the digest can tell
     * apart.  Concrete rather than a hash: two operations collide exactly
     * when they are equal, which is what a 64-bit checksum gives with
     * overwhelming probability and what the model needs to reason about.  A
     * real cache is free to use a cheaper digest as long as a mismatch always
     * means a miss.
     *
     * A handle appears as the identity of the object it names, because that is
     * what distinguishes handle bytes: a name removed and created again is a
     * different object with a different handle, while two names hard linked to
     * one object share one.  This is what makes a retransmit still match its
     * own entry after its object has gone -- it carries the handle it was
     * built with, which is the bytes that were checksummed -- while a fresh
     * request naming the same string does not.
     */
    type OpDigest =
        | DPutfh({ fh: int })
        | DDirop({ dir: str, name: str })
        | DLookup({ dir: str, name: str })
        | DCreate({ dir: str, name: str, ftype: int })
        | DSymlink({ dir: str, name: str, target: str })
        | DRename({ dir: str, from: str, to: str })
        | DLink({ fh: int, dir: str, to: str })
        | DSetattr({ fh: int, size: int })
        | DGetattr({ fh: int })

    /**
     * A digest of the whole request body.  One operation for NFSv3, whose
     * procedures each carry a single operation's arguments; the operation
     * array for an NFSv4 COMPOUND, whose RPC procedure is always COMPOUND and
     * whose entire content is therefore in the body.
     */
    type Digest = { ops: List[OpDigest] }

    /// The full key.  Two requests are the same request exactly when these
    /// three agree.
    type ReqId = { scope: Scope, call: Call, xid: int, cred: int }

    // ==================================================================
    // Entries
    // ==================================================================

    /**
     * A cached reply.  `tag` identifies the execution that produced it, so a
     * replay can be checked to be *that* reply and not merely one with the
     * same status: a cache that returned the right status from the wrong entry
     * would pass a status comparison and still hand the client another
     * request's filehandle.  `st` is carried alongside because it is what most
     * checks read.
     */
    type Reply = { tag: int, st: int }

    type Entry = { key: ReqId, reply: Reply }

    /// Cache contents, oldest first.  Order is part of the specification: a
    /// bounded cache evicts in this order.
    type Cache = List[Entry]

    /// What a lookup found.  A hit carries the reply the original produced,
    /// which is the only thing the requester may be sent.
    type Lookup =
        | Miss
        | Hit(Reply)

    pure def drcLookup(c: Cache, k: ReqId): Lookup =
        c.foldl(Miss, (acc, e) => if (e.key == k) Hit(e.reply) else acc)

    pure def drcHit(c: Cache, k: ReqId): bool =
        c.select(e => e.key == k).length() > 0

    /**
     * Record a reply.
     *
     * A key already present is refreshed in place, keeping its position: it is
     * the same request, so it is not worth a second entry, and it has not
     * become any newer in eviction terms than when it was first admitted.
     *
     * A new key is appended, and if that puts the cache over `cap` the oldest
     * entry goes.  `cap` of 0 means unbounded (an NFSv3 cache is bounded by a
     * byte budget large enough that the traces here never reach it).
     */
    pure def drcInsert(c: Cache, k: ReqId, r: Reply, cap: int): Cache = {
        val e = { key: k, reply: r }
        if (c.select(x => x.key == k).length() > 0)
            c.foldl([], (acc, x) => acc.append(if (x.key == k) e else x))
        else {
            val grown = c.append(e)
            if (cap > 0 and grown.length() > cap)
                grown.slice(grown.length() - cap, grown.length())
            else grown
        }
    }

    /// Everything a connection cached goes when the connection does.  An
    /// address-scoped cache has no equivalent: nothing announces that a client
    /// has stopped being able to retransmit.
    pure def drcDropConn(c: Cache, cn: ConnId): Cache =
        c.select(e => e.key.scope != ByConn(cn))
}
