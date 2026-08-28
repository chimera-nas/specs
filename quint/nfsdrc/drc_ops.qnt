// SPDX-FileCopyrightText: 2026 The Quint Specs Authors
//
// SPDX-License-Identifier: MIT

/**
 * drc_ops.qnt -- the requests the duplicate-request caches hold replies to,
 * and what executing one does.
 *
 * The filesystem here is deliberately the smallest one that can tell a replay
 * from a re-execution.  That is the only question this suite asks, and it
 * needs exactly two things of a filesystem:
 *
 *   - every cacheable operation must have a state in which running it twice
 *     produces a DIFFERENT answer the second time.  Otherwise the cache is
 *     invisible: a re-executed idempotent request and a replayed one are the
 *     same reply, and no trace can distinguish a working cache from an absent
 *     one.  Each operation below is used in exactly that state.
 *   - the directory's contents after every step must be predictable, because
 *     comparing them is what catches a cache that returned the right status
 *     from the wrong entry.
 *
 * Everything else about NFS -- attributes, permissions, cookies, the whole
 * namespace -- is the nfs3 and nfs4 models' business, and is absent here.
 */
module drcOps {

    import drcCache.* from "./drc_cache"

    // ==================================================================
    // Objects
    // ==================================================================

    /// ftype3 / nfs_ftype4, for the three types these traces create.
    pure val T_REG = 1
    pure val T_DIR = 2
    pure val T_LNK = 5

    /// NFSv3 status codes (RFC 1813 Section 2.6).  NFSv4 uses different
    /// numbers for the same conditions; nfsStatus/nfs4Status below map one
    /// outcome onto whichever the protocol in hand uses.
    pure val NFS3_OK        = 0
    pure val NFS3ERR_NOENT  = 2
    pure val NFS3ERR_EXIST  = 17
    pure val NFS3ERR_NOTDIR = 20
    pure val NFS3ERR_INVAL  = 22
    pure val NFS3ERR_ISDIR  = 21
    pure val NFS3ERR_STALE  = 70

    /// NFSv4 status codes (RFC 7530 Section 13.1.1).
    pure val NFS4_OK        = 0
    pure val NFS4ERR_NOENT  = 2
    pure val NFS4ERR_EXIST  = 17
    pure val NFS4ERR_NOTDIR = 20
    pure val NFS4ERR_INVAL  = 22
    pure val NFS4ERR_ISDIR  = 21
    pure val NFS4ERR_STALE  = 70

    /**
     * One name in the test directory, and the object it names.
     *
     * `id` identifies the OBJECT, not the name, and that distinction is the
     * whole reason it is here.  A filehandle names an object: two names hard
     * linked to one object share a handle, a rename carries the handle with the
     * object, and a name removed and created again is a different object with
     * different handle bytes.  A request carries handle bytes, so a model that
     * identified objects by name would call two different requests the same
     * one, and a cache would appear to replay something it had never seen.
     */
    type Obj = { ftype: int, size: int, id: int }

    /// The directory: the names that exist, and what each one is.  Absent names
    /// are simply not keys.
    type Dir = str -> Obj

    /// A filehandle, as the wire carries it: the identity of one object.
    type Fh = int

    /// Drop one name.
    pure def dirDrop(d: Dir, k: str): Dir =
        d.keys().exclude(Set(k)).mapBy(x => d.get(x))

    /// The handle a name currently resolves to.  Only meaningful for a name
    /// that exists; the traces take handles from objects they created.
    pure def fhOf(d: Dir, name: str): Fh = d.get(name).id

    /**
     * Is this handle still usable -- does the object it names still exist?
     *
     * An object exists while any name refers to it, which is what makes a hard
     * link's handle survive the removal of the name it was taken from.  These
     * traces link only within the one directory, so the names here are all of
     * them.
     */
    pure def fhLive(d: Dir, fh: Fh): bool =
        d.keys().exists(n => d.get(n).id == fh)

    /// Every name currently referring to one object.
    pure def namesOf(d: Dir, fh: Fh): Set[str] =
        d.keys().filter(n => d.get(n).id == fh)

    /// Every object that currently exists.
    pure def liveFhs(d: Dir): Set[Fh] =
        d.keys().map(n => d.get(n).id)

    /**
     * Every object a hard link may be made to.
     *
     * Directories are excluded, and not because linking one is legal.  It is
     * refused everywhere -- but by different errors: RFC 1813 Section 3.3.15
     * lists neither NFS3ERR_ISDIR (which chimera answers) nor NFS3ERR_PERM
     * (which Linux answers) among LINK's errors, and offers NFS3ERR_INVAL and
     * NFS3ERR_NOTSUPP without saying which applies.  A trace that asked would
     * be a test of that disagreement rather than of a reply cache.
     */
    pure def linkableFhs(d: Dir): Set[Fh] =
        d.keys().filter(n => d.get(n).ftype != T_DIR).map(n => d.get(n).id)

    // ==================================================================
    // The operations
    // ==================================================================

    /**
     * What a request asks for, at the level the filesystem cares about.
     * The same set serves NFSv3 procedures and NFSv4 COMPOUNDs; the protocols
     * differ in how they package these, not in what they do.
     */
    type Act =
        | ACreate({ name: str, ftype: int })   // CREATE / MKDIR / SYMLINK
        | ARemove({ name: str, asDir: bool })  // RMDIR when asDir, else REMOVE
        | ARename({ from: str, to: str })
        | ALink({ src: Fh, to: str })
        | ASetsize({ fh: Fh, size: int })
        | ALookup({ name: str })               // idempotent: never cached
        | AGetattr({ fh: Fh })                 // idempotent: never cached

    /// The state left behind, and the status reported.  `nextId` is the object
    /// counter, advanced by whatever this operation created.
    type Effect = { d: Dir, nextId: int, st: int }

    /**
     * Execute one operation.  Statuses are the NFSv3 ones; nfs4Status maps
     * them for a COMPOUND.
     *
     * A CREATE over an existing name is EXIST rather than a silent success
     * because every creating request here is exclusive in the NFSv3 sense
     * (CREATE is GUARDED, MKDIR and SYMLINK are inherently so).  An UNCHECKED
     * CREATE would succeed twice and could not tell a replay from a
     * re-execution, which is precisely why it is not used.
     */
    pure def runAct(d: Dir, nextId: int, a: Act, v4Proto: bool): Effect =
        match a {
            | ACreate(c) =>
                if (d.keys().contains(c.name))
                    { d: d, nextId: nextId, st: NFS3ERR_EXIST }
                else
                    { d: d.put(c.name, { ftype: c.ftype, size: 0,
                                         id: nextId }),
                      nextId: nextId + 1,
                      st: NFS3_OK }

            /*
             * NFSv3 splits removal in two and each half asserts the type it
             * expects: REMOVE over a directory is ISDIR, RMDIR over anything
             * else is NOTDIR (RFC 1813 Sections 3.3.12 and 3.3.13).  NFSv4 has
             * one REMOVE for both and so has no assertion to make (RFC 7530
             * Section 16.25).
             *
             * The two NFSv3 procedures carry identical arguments, which is why
             * this suite uses them: their digests agree and only the procedure
             * number in the cache key tells them apart.
             */
            | ARemove(r) =>
                if (not(d.keys().contains(r.name)))
                    { d: d, nextId: nextId, st: NFS3ERR_NOENT }
                else if (v4Proto)
                    { d: dirDrop(d, r.name), nextId: nextId, st: NFS3_OK }
                else if (r.asDir)
                    if (d.get(r.name).ftype != T_DIR)
                        { d: d, nextId: nextId, st: NFS3ERR_NOTDIR }
                    else
                        { d: dirDrop(d, r.name), nextId: nextId, st: NFS3_OK }
                else if (d.get(r.name).ftype == T_DIR)
                    { d: d, nextId: nextId, st: NFS3ERR_ISDIR }
                else
                    { d: dirDrop(d, r.name), nextId: nextId, st: NFS3_OK }

            /*
             * The object moves; its handle does not change with it.
             *
             * An occupied target is not an error by default -- RENAME replaces
             * it (RFC 1813 Section 3.3.14, which defers to POSIX rename(2)).
             * The two ways it can fail are type mismatches, and renaming a name
             * onto another name for the SAME object succeeds having done
             * nothing at all, which is POSIX's rule and not an obvious one.
             */
            | ARename(r) =>
                if (not(d.keys().contains(r.from)))
                    { d: d, nextId: nextId, st: NFS3ERR_NOENT }
                else if (r.from == r.to)
                    { d: d, nextId: nextId, st: NFS3_OK }
                else if (d.keys().contains(r.to))
                    if (d.get(r.to).id == d.get(r.from).id)
                        // Two names for one object: succeed, change nothing.
                        { d: d, nextId: nextId, st: NFS3_OK }
                    else if (d.get(r.from).ftype == T_DIR and
                             d.get(r.to).ftype != T_DIR)
                        { d: d, nextId: nextId, st: NFS3ERR_NOTDIR }
                    else if (d.get(r.from).ftype != T_DIR and
                             d.get(r.to).ftype == T_DIR)
                        { d: d, nextId: nextId, st: NFS3ERR_ISDIR }
                    else
                        // Compatible types: the target is replaced.  Every
                        // directory in these traces is empty, so the
                        // directory-onto-directory case never has to report
                        // NFS3ERR_NOTEMPTY.
                        { d: dirDrop(d, r.from).put(r.to, d.get(r.from)),
                          nextId: nextId, st: NFS3_OK }
                else
                    { d: dirDrop(d, r.from).put(r.to, d.get(r.from)),
                      nextId: nextId, st: NFS3_OK }

            // A second name for the same object, sharing its handle.
            | ALink(l) =>
                if (not(fhLive(d, l.src)))
                    { d: d, nextId: nextId, st: NFS3ERR_STALE }
                else if (namesOf(d, l.src).exists(n =>
                                                  d.get(n).ftype == T_DIR))
                    // Not generated: see linkableFhs for why a directory is
                    // left out.  NFS3ERR_INVAL is the answer RFC 1813
                    // Section 3.3.15 does list for a link it will not make.
                    { d: d, nextId: nextId, st: NFS3ERR_INVAL }
                else if (d.keys().contains(l.to))
                    { d: d, nextId: nextId, st: NFS3ERR_EXIST }
                else {
                    val src = namesOf(d, l.src).fold("", (acc, n) =>
                                                     if (acc == "") n else acc)
                    { d: d.put(l.to, d.get(src)), nextId: nextId,
                      st: NFS3_OK }
                }

            /*
             * A size belongs to a regular file.  Setting one on a directory is
             * NFS3ERR_ISDIR and on anything else NFS3ERR_INVAL -- both are in
             * SETATTR's error list (RFC 1813 Section 3.3.2), and a symlink is
             * the case that reaches the second: the size of a symlink is the
             * length of its target, not something to assign.
             *
             * Size is a property of the object, so every name for it changes.
             */
            | ASetsize(s) =>
                if (not(fhLive(d, s.fh)))
                    { d: d, nextId: nextId, st: NFS3ERR_STALE }
                else if (namesOf(d, s.fh).exists(n => d.get(n).ftype == T_DIR))
                    { d: d, nextId: nextId, st: NFS3ERR_ISDIR }
                else if (namesOf(d, s.fh).exists(n => d.get(n).ftype != T_REG))
                    { d: d, nextId: nextId, st: NFS3ERR_INVAL }
                else
                    { d: d.keys().mapBy(n =>
                          if (d.get(n).id == s.fh)
                              { ...d.get(n), size: s.size }
                          else d.get(n)),
                      nextId: nextId, st: NFS3_OK }

            | ALookup(l) =>
                { d: d, nextId: nextId,
                  st: if (d.keys().contains(l.name)) NFS3_OK
                      else NFS3ERR_NOENT }

            | AGetattr(g) =>
                { d: d, nextId: nextId,
                  st: if (fhLive(d, g.fh)) NFS3_OK else NFS3ERR_STALE }
        }

    /**
     * Does this operation name an object that still exists?
     *
     * An operation that does not is a well-formed question with a definite
     * answer -- NFS3ERR_STALE -- and the model gives it one.  It is asked of a
     * live server only through a retransmit, where the reply comes from the
     * cache and no handle is resolved at all; see the README on why a fresh
     * request on a dead handle is left to the ground-truth probe instead.
     */
    pure def actFhLive(d: Dir, a: Act): bool =
        match a {
            | ALink(l)    => fhLive(d, l.src)
            | ASetsize(s) => fhLive(d, s.fh)
            | AGetattr(g) => fhLive(d, g.fh)
            | ACreate(_)  => true
            | ARemove(_)  => true
            | ARename(_)  => true
            | ALookup(_)  => true
        }

    /**
     * The same arguments as the other removal procedure.
     *
     * NFSv3 REMOVE and RMDIR take an identical diropargs3, so these two
     * requests are byte-identical and are separated only by the RPC procedure
     * number -- the one place in either protocol where the procedure has to be
     * part of a cache key in its own right.
     */
    pure def isRemove(a: Act): bool =
        match a { | ARemove(_) => true | _ => false }

    pure def flipRemove(a: Act): Act =
        match a {
            | ARemove(r) => ARemove({ name: r.name, asDir: not(r.asDir) })
            | _ => a
        }

    /// The NFSv4 spelling of a status runAct reported.  The four the traces
    /// produce happen to share their numeric values across the two protocols,
    /// but they are distinct constants and the mapping is written out so a
    /// divergence would be a change here rather than a coincidence.
    pure def nfs4Status(st: int): int =
        if (st == NFS3_OK) NFS4_OK
        else if (st == NFS3ERR_NOENT) NFS4ERR_NOENT
        else if (st == NFS3ERR_EXIST) NFS4ERR_EXIST
        else if (st == NFS3ERR_ISDIR) NFS4ERR_ISDIR
        else if (st == NFS3ERR_NOTDIR) NFS4ERR_NOTDIR
        else if (st == NFS3ERR_INVAL) NFS4ERR_INVAL
        else NFS4ERR_STALE

    // ==================================================================
    // NFSv3: procedures
    // ==================================================================

    pure val PROC3_GETATTR = 1
    pure val PROC3_SETATTR = 2
    pure val PROC3_LOOKUP  = 3
    pure val PROC3_CREATE  = 8
    pure val PROC3_MKDIR   = 9
    pure val PROC3_SYMLINK = 10
    pure val PROC3_REMOVE  = 12
    pure val PROC3_RMDIR   = 13
    pure val PROC3_RENAME  = 14
    pure val PROC3_LINK    = 15

    /**
     * The NFSv3 procedures whose replies must be cached: the ones that are not
     * idempotent.  Re-running a READ, a GETATTR or a LOOKUP costs a little
     * work and produces the same answer, so a retransmit of one needs no cache
     * -- and caching them would spend the cache on the overwhelming majority
     * of the traffic.  Re-running any of these changes the answer.
     *
     * SETATTR is here because it is not idempotent in general: a SETATTR
     * carrying a ctime guard succeeds once and fails NFS3ERR_NOT_SYNC
     * afterwards, and a size change re-applied after a later write silently
     * truncates data the client has since sent.
     */
    pure def proc3Cacheable(p: int): bool =
        Set(PROC3_SETATTR, PROC3_CREATE, PROC3_MKDIR, PROC3_SYMLINK,
            PROC3_REMOVE, PROC3_RMDIR, PROC3_RENAME, PROC3_LINK).contains(p)

    /// The RPC procedure that carries an action, and the argument digest that
    /// goes on the wire with it.  DIR is the one directory these traces use.
    pure def act3Proc(a: Act): int =
        match a {
            | ACreate(c)  => if (c.ftype == T_DIR) PROC3_MKDIR
                             else if (c.ftype == T_LNK) PROC3_SYMLINK
                             else PROC3_CREATE
            | ARemove(r)  => if (r.asDir) PROC3_RMDIR else PROC3_REMOVE
            | ARename(_)  => PROC3_RENAME
            | ALink(_)    => PROC3_LINK
            | ASetsize(_) => PROC3_SETATTR
            | ALookup(_)  => PROC3_LOOKUP
            | AGetattr(_) => PROC3_GETATTR
        }

    /**
     * The argument digest of an NFSv3 procedure.
     *
     * REMOVE and RMDIR share DDirop deliberately: their arguments are the same
     * diropargs3 structure, so their request bodies are byte-identical and
     * their digests must be too.  What separates them in a cache key is the
     * procedure number, and a cache that omitted it would answer one from the
     * other's entry.  The same holds for a directory name that could be
     * removed either way.
     */
    pure def act3Digest(dir: str, a: Act): Digest =
        match a {
            | ACreate(c)  => { ops: [ DCreate({ dir: dir, name: c.name,
                                                ftype: c.ftype }) ] }
            | ARemove(r)  => { ops: [ DDirop({ dir: dir, name: r.name }) ] }
            | ARename(r)  => { ops: [ DRename({ dir: dir, from: r.from,
                                                to: r.to }) ] }
            | ALink(l)    => { ops: [ DLink({ fh: l.src, dir: dir,
                                              to: l.to }) ] }
            | ASetsize(s) => { ops: [ DSetattr({ fh: s.fh, size: s.size }) ] }
            // Byte-identical to a REMOVE of the same name, and correctly so:
            // both are a bare diropargs3.  It never collides with one in a
            // cache because a v3 cache does not look up a request whose
            // procedure it does not cache -- it returns before it would.
            | ALookup(l)  => { ops: [ DDirop({ dir: dir, name: l.name }) ] }
            | AGetattr(g) => { ops: [ DGetattr({ fh: g.fh }) ] }
        }

    // ==================================================================
    // NFSv4.0: COMPOUNDs
    // ==================================================================

    /// The RPC procedure of every NFSv4 request.  All of a COMPOUND's content
    /// is in its body, so the procedure number contributes nothing to a key
    /// and a v4 cache keys on the body digest alone.
    pure val PROC4_COMPOUND = 1

    /**
     * Whether a COMPOUND carries an operation that must not run twice.
     *
     * The question a v3 cache answers per procedure has to be answered per
     * COMPOUND, because a COMPOUND is a sequence: one non-idempotent operation
     * anywhere in it makes the whole request non-idempotent, since a replay
     * cannot re-run part of a COMPOUND.
     *
     * The list of operations is the v3 list plus the state operations, which a
     * v4.0 server must also protect: OPEN, CLOSE, LOCK, LOCKU, OPEN_CONFIRM,
     * OPEN_DOWNGRADE and DELEGRETURN all change state that a second execution
     * would get wrong, and SETCLIENTID/SETCLIENTID_CONFIRM must be cached
     * outright -- RFC 7530 Section 16.33.5 says so in as many words, because
     * each SETCLIENTID mints a fresh confirm verifier and re-executing one
     * invalidates the verifier the client was sent.  These traces exercise the
     * namespace subset; the state operations belong to the nfs4 model.
     */
    pure def compoundCacheable(ops: List[OpDigest]): bool =
        ops.select(o =>
            match o {
                | DCreate(_)  => true
                | DSymlink(_) => true
                | DDirop(_)   => true    // REMOVE; LOOKUP is DLookup
                | DRename(_)  => true
                | DLink(_)    => true
                | DSetattr(_) => true
                | DLookup(_)  => false
                | DGetattr(_) => false
                | DPutfh(_)   => false
            }).length() > 0

    /**
     * The operation array an action becomes, which for NFSv4 is the whole of
     * the request body.
     *
     * Two differences from act3Digest, both of them consequences of a COMPOUND
     * carrying its own operation codes:
     *
     *   - LOOKUP gets its own shape.  In NFSv3 a LOOKUP, a REMOVE and an RMDIR
     *     have byte-identical bodies and are told apart by the RPC procedure
     *     number outside them; in NFSv4 the operation code is in the body, so
     *     they differ there instead.  This matters: a v4 cache looks up every
     *     COMPOUND, read-only ones included, because it cannot know what a
     *     COMPOUND contains until the body is decoded.  It is only safe to do
     *     that because a read-only COMPOUND's bytes cannot equal a cached
     *     mutating one's.
     *   - the handle-setting operations are part of the digest.  A COMPOUND
     *     that operates on a different directory differs in its PUTFH, not in
     *     the operation that follows.
     */
    pure def act4Digest(dir: str, dirFh: int, a: Act): Digest = {
        val pdir = DPutfh({ fh: dirFh })
        match a {
            | ACreate(c)  => { ops: [ pdir,
                                      DCreate({ dir: dir, name: c.name,
                                                ftype: c.ftype }) ] }
            | ARemove(r)  => { ops: [ pdir,
                                      DDirop({ dir: dir, name: r.name }) ] }
            | ARename(r)  => { ops: [ pdir, pdir,
                                      DRename({ dir: dir, from: r.from,
                                                to: r.to }) ] }
            | ALink(l)    => { ops: [ DPutfh({ fh: l.src }), pdir,
                                      DLink({ fh: l.src, dir: dir, to: l.to }) ] }
            | ASetsize(s) => { ops: [ DPutfh({ fh: s.fh }),
                                      DSetattr({ fh: s.fh,
                                                 size: s.size }) ] }
            | ALookup(l)  => { ops: [ pdir,
                                      DLookup({ dir: dir, name: l.name }) ] }
            | AGetattr(g) => { ops: [ DPutfh({ fh: g.fh }),
                                      DGetattr({ fh: g.fh }) ] }
        }
    }
}
