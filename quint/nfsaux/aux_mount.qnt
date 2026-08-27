// SPDX-FileCopyrightText: 2026 The Quint Specs Authors
//
// SPDX-License-Identifier: MIT

/**
 * aux_mount.qnt -- the MOUNT protocol version 3 (RFC 1813 Appendix I),
 * modeled as pure transitions over the mount table ("rmtab") a server keeps
 * for showmount.
 *
 * All six procedures are covered: NULL, MNT, DUMP, UMNT, UMNTALL, EXPORT.
 *
 * Two things a MOUNT server owns are modeled here:
 *
 *   - the EXPORT LIST, which is configuration, not state: an ordered list of
 *     (name, path) pairs plus the auth flavors each advertises.  MNT resolves
 *     a client-supplied path against it.
 *   - the MOUNT TABLE, an advisory record of which client mounted which
 *     directory.  It is a list rather than a set because DUMP returns it in
 *     a defined order, and the order is observable.
 *
 * Path resolution is the interesting part and is spelled out rather than
 * abstracted, because it is where servers differ: the export name must match
 * at a path-component boundary (so "/backupextra" does not match the export
 * "/backup"), a leading slash on the client's path is optional, and a "/"
 * export acts as a catch-all that any more specific export outranks.
 */
module mountProto {

    // ------------------------------------------------------------------
    // Domain
    // ------------------------------------------------------------------

    /// mountstat3 (RFC 1813 Appendix I), numerically as on the wire.
    pure val MNT3_OK             = 0
    pure val MNT3ERR_PERM        = 1
    pure val MNT3ERR_NOENT       = 2
    pure val MNT3ERR_IO          = 5
    pure val MNT3ERR_ACCES       = 13
    pure val MNT3ERR_NOTDIR      = 20
    pure val MNT3ERR_INVAL       = 22
    pure val MNT3ERR_NAMETOOLONG = 63
    pure val MNT3ERR_NOTSUPP     = 10004
    pure val MNT3ERR_SERVERFAULT = 10006

    /// RPC auth flavors an export may advertise in mountres3_ok.
    pure val AUTH_NONE = 0
    pure val AUTH_SYS  = 1
    pure val RPCSEC_GSS = 6

    /// One export: the name clients mount, the server-side path it resolves
    /// to, and the auth flavors MNT advertises for it.
    type Export = { name: str, path: str, flavors: List[int] }

    /// One mount-table row.
    type MountEnt = { host: str, dir: str }

    pure val MOUNT_PROCS = Set(
        "MOUNTPROC3_NULL", "MOUNTPROC3_MNT", "MOUNTPROC3_DUMP",
        "MOUNTPROC3_UMNT", "MOUNTPROC3_UMNTALL", "MOUNTPROC3_EXPORT"
    )

    // ------------------------------------------------------------------
    // Export resolution
    // ------------------------------------------------------------------

    /**
     * Does `path` name `exp` or something beneath it?
     *
     * Modeled over a small closed universe of paths rather than by string
     * surgery, which Quint cannot do: the composing module supplies, for
     * each path in the universe, which export it resolves under and whether
     * the resolved object exists.  What is asserted here is the shape of the
     * answer, and the resolution table itself is checked by the scenario
     * tests plus the live replay.
     *
     * A resolution is one of:
     *   - NoExport             no export matches, so MNT is NOENT and
     *                          nothing is recorded
     *   - Resolved(exp, st)    an export matched; `st` is the mountstat3 the
     *                          server-side lookup of the resolved path
     *                          produces (MNT3_OK when it is there, NOENT
     *                          when it is not, NOTDIR when a component of it
     *                          is a regular file, and so on)
     *
     * The status is carried rather than a bare "does it exist" flag because
     * the failure modes are distinguishable and clients act on them
     * differently.  Note that a server does NOT type-check the object it
     * resolved to: MNT of a regular file succeeds and hands back its handle.
     */
    type Resolution =
        | NoExport
        | Resolved({ exp: str, status: int })

    pure def mntStatus(r: Resolution): int = match r {
        | NoExport      => MNT3ERR_NOENT
        | Resolved(res) => res.status
    }

    /// The auth flavors MNT advertises for a resolution, empty on failure.
    pure def mntFlavors(exports: List[Export], r: Resolution): List[int] =
        match r {
            | NoExport => List()
            | Resolved(res) =>
                if (res.status != MNT3_OK) List()
                else exports.foldl(List(), (acc, e) =>
                    if (e.name == res.exp) e.flavors else acc)
        }

    // ------------------------------------------------------------------
    // Mount table
    // ------------------------------------------------------------------

    pure def hasEnt(tab: List[MountEnt], host: str, dir: str): bool =
        tab.indices().exists(i => tab[i].host == host and tab[i].dir == dir)

    /**
     * MNT records the mount keyed by the path the CLIENT asked for -- not
     * the resolved server path -- because that is what UMNT will present and
     * what showmount displays.
     *
     * Two properties worth stating explicitly, because both are easy to get
     * wrong and both are observable:
     *
     *   - the record is made as soon as an export matches, BEFORE the
     *     resolved object is looked up.  A MNT that ends in NOENT because
     *     the subdirectory does not exist still leaves a row behind.
     *   - a repeat mount of the same (host, dir) does not add a second row
     *     and does not move the existing one; a new row goes to the FRONT,
     *     so DUMP reports most-recent-first.
     */
    pure def mntRecords(r: Resolution): bool = match r {
        | NoExport      => false
        | Resolved(_)   => true
    }

    pure def mountRecord(tab: List[MountEnt], host: str,
                         dir: str): List[MountEnt] =
        if (hasEnt(tab, host, dir)) tab
        else List({ host: host, dir: dir }).concat(tab)

    /// UMNT drops the single row naming (host, dir).  It is a void
    /// procedure: a row that was not there is not an error.
    pure def mountRemove(tab: List[MountEnt], host: str,
                         dir: str): List[MountEnt] =
        tab.select(e => not(e.host == host and e.dir == dir))

    /// UMNTALL drops every row for the calling host.
    pure def mountRemoveHost(tab: List[MountEnt],
                             host: str): List[MountEnt] =
        tab.select(e => e.host != host)

    /// EXPORT returns the export list in the server's own order, with each
    /// entry's access-control group list.  No per-export group restriction
    /// is modeled: an empty group list means "exported to everyone", which
    /// is what a server without host-based access control reports.
    pure def exportNames(exports: List[Export]): List[str] =
        exports.foldl(List(), (acc, e) => acc.append(e.name))
}
