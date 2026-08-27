// SPDX-FileCopyrightText: 2026 The Quint Specs Authors
//
// SPDX-License-Identifier: MIT

/**
 * aux_portmap.qnt -- the portmap / rpcbind protocol (RFC 1833), modeled as
 * pure request -> reply functions over a service table.
 *
 * All three versions are covered: PMAP v2 (program 100000 version 2) and
 * rpcbind v3 and v4.  The model is complete with respect to the RFC's
 * procedure set; which procedures a given server actually registers is a
 * separate question, answered by the IMPLEMENTED gate the composing module
 * carries (see nfsaux.qnt).  A procedure that is not registered is not
 * dropped from the model -- it is still called, and the expected reply
 * becomes the RPC layer's PROC_UNAVAIL rather than the RFC's result.  That
 * keeps the unregistered half of the protocol under test instead of
 * untested.
 *
 * The registry is a parameter rather than state.  A server that supports
 * PMAPPROC_SET/UNSET mutates it; one that publishes a fixed table (the
 * common case for an NFS server that embeds a minimal portmapper) does not,
 * and there the table is a constant of the configuration.  Both are
 * expressible: `setSupported` decides whether SET/UNSET are modeled as
 * mutations or as refusals.
 *
 * Universal addresses are modeled as (host, port) pairs rather than the
 * "h.o.s.t.hi.lo" string, because Quint has no integer-to-string
 * conversion.  The replay harness formats and parses; the model predicts
 * the host and the port, which is where all the semantics live.
 */
module portmapProto {

    // ------------------------------------------------------------------
    // Domain
    // ------------------------------------------------------------------

    /// Transport protocol numbers as they appear in a `mapping`.
    pure val PROT_TCP = 6
    pure val PROT_UDP = 17

    /// One row of the service table (struct mapping, RFC 1833 sec 3.1).
    type Mapping = { prog: int, vers: int, prot: int, port: int }

    /// rpcbind network identifiers.  A server maps the two it serves to
    /// protocol numbers and treats every other netid as unserved.
    type Netid =
        | NetTcp
        | NetUdp
        | NetTcp6
        | NetUdp6
        | NetLocal

    pure def netidProt(n: Netid): int = match n {
        | NetTcp   => PROT_TCP
        | NetUdp   => PROT_UDP
        | NetTcp6  => 0
        | NetUdp6  => 0
        | NetLocal => 0
    }

    /// Every procedure the three versions define, named as the .x file names
    /// them so a gate reads like the registration code it mirrors.
    pure val PMAP_PROCS = Set(
        "PMAPPROC_NULL", "PMAPPROC_SET", "PMAPPROC_UNSET",
        "PMAPPROC_GETPORT", "PMAPPROC_DUMP", "PMAPPROC_CALLIT"
    )

    pure val RPCB3_PROCS = Set(
        "rpcbproc_set", "rpcbproc_unset", "rpcbproc_getaddr",
        "rpcbproc_dump", "rpcbproc_callit", "rpcbproc_gettime",
        "rpcbproc_uaddr2taddr", "rpcbproc_taddr2uaddr"
    )

    pure val RPCB4_PROCS = Set(
        "RPCBPROC_SET", "RPCBPROC_UNSET", "RPCBPROC_GETADDR",
        "RPCBPROC_DUMP", "RPCBPROC_BCAST", "RPCBPROC_GETTIME",
        "RPCBPROC_UADDR2TADDR", "RPCBPROC_TADDR2UADDR",
        "RPCBPROC_GETVERSADDR", "RPCBPROC_INDIRECT",
        "RPCBPROC_GETADDRLIST", "RPCBPROC_GETSTAT"
    )

    pure val PORTMAP_PROCS = PMAP_PROCS.union(RPCB3_PROCS).union(RPCB4_PROCS)

    // ------------------------------------------------------------------
    // Lookup
    // ------------------------------------------------------------------

    /**
     * First-match scan of the service table, 0 when the exact
     * (prog, vers, prot) triple is not served.
     *
     * RFC 1833 sec 2.2 defines GETPORT as returning the port of the
     * requested triple, and 0 when it is not registered.  Classic BSD
     * portmap additionally falls back to the port of *some* other
     * registered version of the same program on a version mismatch; that
     * behaviour is not in the RFC and is not modeled.  A server that wants
     * it would need a second lookup function here and a profile flag; the
     * strict reading is what `soundPort` below asserts.
     *
     * Port 0 doubles as "not found": a registered port is never 0.
     */
    pure def lookupPort(services: List[Mapping], prog: int, vers: int,
                        prot: int): int =
        services.foldl(0, (acc, m) =>
            if (acc != 0) acc
            else if (m.prog == prog and m.vers == vers and m.prot == prot)
                m.port
            else acc)

    /// Quantified restatement of lookupPort, independent of the scan that
    /// implements it: 0 iff the triple is absent (even when sibling versions
    /// of the program are served -- the no-BSD-fallback property), and a
    /// nonzero port names a row carrying exactly that triple.
    pure def soundPort(services: List[Mapping], prog: int, vers: int,
                       prot: int, p: int): bool =
        if (p == 0)
            services.indices().forall(i => not(
                services[i].prog == prog and
                services[i].vers == vers and
                services[i].prot == prot))
        else
            services.indices().exists(i =>
                services[i].prog == prog and
                services[i].vers == vers and
                services[i].prot == prot and
                services[i].port == p)

    // ------------------------------------------------------------------
    // Registry mutation (PMAPPROC_SET / UNSET, rpcbproc_set / unset)
    // ------------------------------------------------------------------

    /// RFC 1833 sec 2.2: SET registers (prog, vers, prot, port) and returns
    /// TRUE, unless the triple is already registered, in which case it
    /// changes nothing and returns FALSE.  Registering port 0 is refused.
    pure def setAccepted(services: List[Mapping], m: Mapping): bool =
        m.port != 0 and lookupPort(services, m.prog, m.vers, m.prot) == 0

    pure def registrySet(services: List[Mapping], m: Mapping): List[Mapping] =
        if (setAccepted(services, m)) services.append(m) else services

    /// UNSET removes every row for (prog, vers) regardless of transport, and
    /// returns TRUE iff something was removed.  Per the RFC the port field
    /// of the argument is ignored.
    pure def unsetAccepted(services: List[Mapping], m: Mapping): bool =
        services.indices().exists(i =>
            services[i].prog == m.prog and services[i].vers == m.vers)

    pure def registryUnset(services: List[Mapping],
                           m: Mapping): List[Mapping] =
        services.select(r => not(r.prog == m.prog and r.vers == m.vers))

    // ------------------------------------------------------------------
    // Replies
    // ------------------------------------------------------------------

    /// A universal address: the host half plus the port the last two
    /// components encode.  port == 0 is the empty string on the wire, which
    /// is how rpcbind reports "not registered".
    type Uaddr = { host: str, port: int }

    pure def uaddrOf(host: str, port: int): Uaddr =
        { host: if (port == 0) "" else host, port: port }

    /// GETADDR: the exact-triple lookup, with the transport taken from the
    /// netid.  An unrecognised netid yields protocol 0, which no row
    /// carries, so the answer is the empty universal address.
    pure def getaddr(services: List[Mapping], host: str, prog: int, vers: int,
                     netid: Netid): Uaddr =
        uaddrOf(host, lookupPort(services, prog, vers, netidProt(netid)))

    /**
     * The rpcbind DUMP projection of the service table.
     *
     * Each row becomes an rpcb entry.  The netid a row is advertised under
     * is a property of the row's transport; a server that only serves TCP
     * reports "tcp" for every row, which is what `rowNetid` yields for
     * PROT_TCP.  r_owner is unspecified by the RFC and is modeled as the
     * empty string, matching a server that does not track ownership.
     */
    pure def rowNetid(prot: int): Netid =
        if (prot == PROT_UDP) NetUdp else NetTcp
}
