// SPDX-FileCopyrightText: 2026 The Quint Specs Authors
//
// SPDX-License-Identifier: MIT

// Concrete instances of the nfsaux model -- the units `quint run` executes:
//
//   quint run nfsaux_run.qnt --main=nfsauxRef --step=step --invariant=inv
//
// Operators add configurations here.  Two ship:
//
//   nfsauxRef   the reference profile: an NFS server that embeds a minimal
//               portmapper (no registration procedures), serves MOUNT, NLM
//               and NSM in full, and keeps no lock state across a restart.
//               This is the profile the trace corpus is generated from.
//
//   nfsauxFull  every procedure in all four RFCs registered, share
//               reservations enforced, peers distinguishable by address.
//               No server implements this today; it exists so the RFC
//               semantics of the procedures the reference profile refuses
//               stay under test by `quint test`, and so a server that grows
//               them has a profile waiting.

// ----------------------------------------------------------------------
// Shared vocabulary: the service table and path universe both instances
// draw on.  A module of `pure val`s rather than a base instance, because
// consts cannot be defined in terms of other consts.
// ----------------------------------------------------------------------
module nfsauxProfiles {

    import portmapProto.* from "./aux_portmap"
    import mountProto.* from "./aux_mount"

    /**
     * The service table an NFS server publishes: the portmapper itself at
     * every version it answers, NFS, MOUNT, then the lock manager and the
     * status monitor, which are appended once their ports are known.  TCP
     * only -- no UDP transport is served.  DUMP returns this list verbatim,
     * so the ORDER is part of the contract, not just the content.
     */
    pure val NFS_SERVICES: List[Mapping] = List(
        { prog: 100000, vers: 2, prot: 6, port: 111 },
        { prog: 100000, vers: 3, prot: 6, port: 111 },
        { prog: 100000, vers: 4, prot: 6, port: 111 },
        { prog: 100003, vers: 3, prot: 6, port: 2049 },
        { prog: 100003, vers: 4, prot: 6, port: 2049 },
        { prog: 100005, vers: 3, prot: 6, port: 20048 },
        { prog: 100021, vers: 4, prot: 6, port: 32803 },
        { prog: 100024, vers: 1, prot: 6, port: 32765 }
    )

    /// An export with no security policy advertises the historical pair.
    pure val DEFAULT_FLAVORS: List[int] = List(AUTH_NONE, AUTH_SYS)

    /**
     * Two exports over one directory, so MNT has something to disambiguate
     * and EXPORT has more than one row to order.  The list is in the order
     * the server reports them, which for a server that prepends each new
     * export is the reverse of creation order: the harness creates /share
     * first, /share2 second.
     */
    pure val TWO_EXPORTS: List[Export] = List(
        { name: "/share2", path: "/share", flavors: DEFAULT_FLAVORS },
        { name: "/share", path: "/share", flavors: DEFAULT_FLAVORS }
    )

    /**
     * The paths MNT and UMNT may name, and how each resolves.
     *
     * Together they cover every branch of export resolution:
     *   - an exact export name, with and without the leading slash
     *   - a second, longer export name that must not be shadowed by the
     *     first (/share2 vs /share)
     *   - a path below an export that exists, both a directory and a file
     *     (MNT does not type-check the object, so both succeed)
     *   - a path below an export that does not exist
     *   - a path whose parent component is a regular file, which is NOTDIR
     *     rather than NOENT: the walk got as far as f0 and could not
     *     descend
     *   - a name that matches an export only as a string prefix, not at a
     *     component boundary (/shareXX vs /share)
     *   - a path no export matches at all
     */
    pure val NFS_PATHS: str -> Resolution = Map(
        "/share"      -> Resolved({ exp: "/share", status: MNT3_OK }),
        "share"       -> Resolved({ exp: "/share", status: MNT3_OK }),
        "/share2"     -> Resolved({ exp: "/share2", status: MNT3_OK }),
        "/share/d"    -> Resolved({ exp: "/share", status: MNT3_OK }),
        "/share/f0"   -> Resolved({ exp: "/share", status: MNT3_OK }),
        "/share/nope" -> Resolved({ exp: "/share", status: MNT3ERR_NOENT }),
        "/share/f0/x" -> Resolved({ exp: "/share", status: MNT3ERR_NOTDIR }),
        "/shareXX"    -> NoExport,
        "/nope"       -> NoExport
    )

    /// The procedures a minimal embedded portmapper registers: enough for a
    /// client to find the services, and nothing that would let a client
    /// change the table.
    pure val PORTMAP_MINIMAL = Set(
        "PMAPPROC_NULL", "PMAPPROC_GETPORT", "PMAPPROC_DUMP",
        "rpcbproc_getaddr", "rpcbproc_dump",
        "RPCBPROC_GETADDR", "RPCBPROC_DUMP"
    )
}

// ----------------------------------------------------------------------
// The reference profile -- what the corpus is generated from.
// ----------------------------------------------------------------------
module nfsauxRef {
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
        // Every connection reaches the server over one in-process
        // transport, so the mount table records a single host name.
        MOUNT_HOST = "inproc",
        // The monitor list is built from NLM lock grants, not from SM_MON.
        NSM_MON_FROM_LOCKS = true,
        // ...and with one transport there is one peer address, so
        // SM_NOTIFY's fallback cannot tell monitored hosts apart.
        NSM_ADDRS_DISTINCT = false,
        NSM_INITIAL_STATE = 1,
        // A re-LOCK of a range this owner holds is an idempotent retry,
        // mode included, so an upgrade is a silent no-op.
        NLM_UPGRADE_IS_NOOP = true,
        // DOS share reservations are accepted, not enforced.
        NLM_SHARE_ENFORCED = false,
        // Lock state does not survive a restart, so there is nothing to
        // reclaim and no grace window to sit out.
        NLM_IN_GRACE = false,
        NLM_BLOCKING = true,
        // The deferred grant goes to the client's own lock manager, which
        // the replay harness is not; the grant still happens and is visible
        // through TEST, but the callback itself is not observed.
        NLM_GRANT_CALLBACK_OBSERVABLE = false,
        NLM_CANCEL_MSG_CANCELS = true
    ).* from "./nfsaux"
}

// ----------------------------------------------------------------------
// The everything-implemented profile -- model self-tests only.
// ----------------------------------------------------------------------
module nfsauxFull {
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
}

// ----------------------------------------------------------------------
// The reference profile inside its post-restart grace window.
// ----------------------------------------------------------------------
module nfsauxGrace {
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
        // Only reclaim requests are admitted until the window closes.
        NLM_IN_GRACE = true,
        NLM_BLOCKING = false,
        NLM_GRANT_CALLBACK_OBSERVABLE = false,
        NLM_CANCEL_MSG_CANCELS = true
    ).* from "./nfsaux"
}
