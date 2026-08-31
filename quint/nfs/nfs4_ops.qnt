// SPDX-FileCopyrightText: 2026 The Quint Specs Authors
//
// SPDX-License-Identifier: MIT

// NFSv4 COMPOUND evaluator.
//
// `OpReq` describes one operation of a COMPOUND request; `OpRes` the reply
// the server must produce for it.  `evalCompound` interprets a request list
// with the real COMPOUND semantics: current/saved filehandle threading,
// first-error-stops, per-op status, compound status = last executed op's
// status (RFC 7530 14.2/15.2.4; RFC 8881 16.2), 4.1 session gating
// (SEQUENCE-first, session-exempt singleton ops), and the 4.0 open-owner
// seqid discipline.
//
// The module is pure: the top-level model (nfs4.qnt) owns the state
// variables and calls evalCompound from its actions; nfs4Test.qnt drives
// it directly with hand-built compounds.
//
// Conventions:
//  - Inos, client ids, session ids and stateid indices are model handles;
//    the harness learns the wire values (filehandles, clientid4,
//    sessionid4, stateid4.other) from replies (GETFH, SETCLIENTID,
//    EXCHANGE_ID, CREATE_SESSION, OPEN, LOCK, LAYOUTGET...).
//  - Stateid *seqids* are predicted exactly; `argSeq` 0 in a request means
//    the wildcard "current seqid" (RFC 7530 9.1.4.4 / RFC 8881 8.2.2).
//  - Where the RFCs leave a server choice, the choice is pinned by the
//    capability/policy profile (`Caps`) and annotated `// discretion:`;
//    where two statuses are both conformant the modeled one is annotated
//    `// acceptance:` with the alternative, for the harness's registry.

module nfs4ops {

    import nfs4fs.* from "./nfs4_fs"
    import nfs4state.* from "./nfs4_state"

    // ------------------------------------------------------------------
    // nfsstat4 (RFC 7530 13.1 / RFC 8881 15.1; numerically the wire values)
    // ------------------------------------------------------------------

    pure val OK = 0
    pure val E_PERM = 1
    pure val E_NOENT = 2
    pure val E_IO = 5
    pure val E_NXIO = 6
    pure val E_ACCESS = 13
    pure val E_EXIST = 17
    pure val E_XDEV = 18
    pure val E_NOTDIR = 20
    pure val E_ISDIR = 21
    pure val E_INVAL = 22
    pure val E_FBIG = 27
    pure val E_NOSPC = 28
    pure val E_ROFS = 30
    pure val E_MLINK = 31
    pure val E_NAMETOOLONG = 63
    pure val E_NOTEMPTY = 66
    pure val E_DQUOT = 69
    pure val E_STALE = 70
    pure val E_BADHANDLE = 10001
    pure val E_BAD_COOKIE = 10003
    pure val E_NOTSUPP = 10004
    pure val E_TOOSMALL = 10005
    pure val E_SERVERFAULT = 10006
    pure val E_BADTYPE = 10007
    pure val E_DELAY = 10008
    pure val E_SAME = 10009
    pure val E_DENIED = 10010
    pure val E_EXPIRED = 10011
    pure val E_LOCKED = 10012
    pure val E_GRACE = 10013
    pure val E_FHEXPIRED = 10014
    pure val E_SHARE_DENIED = 10015
    pure val E_WRONGSEC = 10016
    pure val E_CLID_INUSE = 10017
    pure val E_RESOURCE = 10018
    pure val E_MOVED = 10019
    pure val E_NOFILEHANDLE = 10020
    pure val E_MINOR_VERS_MISMATCH = 10021
    pure val E_STALE_CLIENTID = 10022
    pure val E_STALE_STATEID = 10023
    pure val E_OLD_STATEID = 10024
    pure val E_BAD_STATEID = 10025
    pure val E_BAD_SEQID = 10026
    pure val E_NOT_SAME = 10027
    pure val E_LOCK_RANGE = 10028
    pure val E_SYMLINK = 10029
    pure val E_RESTOREFH = 10030
    pure val E_LEASE_MOVED = 10031
    pure val E_ATTRNOTSUPP = 10032
    pure val E_NO_GRACE = 10033
    pure val E_RECLAIM_BAD = 10034
    pure val E_RECLAIM_CONFLICT = 10035
    pure val E_BADXDR = 10036
    pure val E_LOCKS_HELD = 10037
    pure val E_OPENMODE = 10038
    pure val E_BADOWNER = 10039
    pure val E_BADCHAR = 10040
    pure val E_BADNAME = 10041
    pure val E_BAD_RANGE = 10042
    pure val E_LOCK_NOTSUPP = 10043
    pure val E_OP_ILLEGAL = 10044
    pure val E_DEADLOCK = 10045
    pure val E_FILE_OPEN = 10046
    pure val E_ADMIN_REVOKED = 10047
    pure val E_CB_PATH_DOWN = 10048
    // NFSv4.1 (RFC 8881 15.1)
    pure val E_BADIOMODE = 10049
    pure val E_BADLAYOUT = 10050
    pure val E_BADSESSION = 10052
    pure val E_BADSLOT = 10053
    pure val E_COMPLETE_ALREADY = 10054
    pure val E_CONN_NOT_BOUND = 10055
    pure val E_DELEG_ALREADY_WANTED = 10056
    pure val E_BACK_CHAN_BUSY = 10057
    pure val E_LAYOUTTRYLATER = 10058
    pure val E_LAYOUTUNAVAILABLE = 10059
    pure val E_NOMATCHING_LAYOUT = 10060
    pure val E_RECALLCONFLICT = 10061
    pure val E_UNKNOWN_LAYOUTTYPE = 10062
    pure val E_SEQ_MISORDERED = 10063
    pure val E_SEQUENCE_POS = 10064
    pure val E_REQ_TOO_BIG = 10065
    pure val E_REP_TOO_BIG = 10066
    pure val E_REP_TOO_BIG_TO_CACHE = 10067
    pure val E_RETRY_UNCACHED_REP = 10068
    pure val E_UNSAFE_COMPOUND = 10069
    pure val E_TOO_MANY_OPS = 10070
    pure val E_OP_NOT_IN_SESSION = 10071
    pure val E_HASH_ALG_UNSUPP = 10072
    pure val E_CLIENTID_BUSY = 10074
    pure val E_PNFS_IO_HOLE = 10075
    pure val E_SEQ_FALSE_RETRY = 10076
    pure val E_BAD_HIGH_SLOT = 10077
    pure val E_DEADSESSION = 10078
    pure val E_ENCR_ALG_UNSUPP = 10079
    pure val E_PNFS_NO_LAYOUT = 10080
    pure val E_NOT_ONLY_OP = 10081
    pure val E_WRONG_CRED = 10082
    pure val E_WRONG_TYPE = 10083
    pure val E_DIRDELEG_UNAVAIL = 10084
    pure val E_REJECT_DELEG = 10085
    pure val E_RETURNCONFLICT = 10086
    pure val E_DELEG_REVOKED = 10087
    // NFSv4.2 (RFC 7862 11.2) and xattrs (RFC 8276 8.2)
    pure val E_PARTNER_NOTSUPP = 10088
    pure val E_PARTNER_NO_AUTH = 10089
    pure val E_UNION_NOTSUPP = 10090
    pure val E_OFFLOAD_DENIED = 10091
    pure val E_WRONG_LFS = 10092
    pure val E_BADLABEL = 10093
    pure val E_OFFLOAD_NO_REQS = 10094
    pure val E_NOXATTR = 10095
    pure val E_XATTR2BIG = 10096

    // ------------------------------------------------------------------
    // Feature configuration and capability / policy profile
    // ------------------------------------------------------------------

    // Operator-facing mode for every optional NFSv4 feature:
    //  - FeatOff: never exercised; traces contain no dependent steps.
    //  - FeatIfAdvertised (default): init nondeterministically assumes the
    //    server does or does not support the feature; the corpus covers
    //    both, and the harness skips traces whose assumption mismatches
    //    the live server's advertisement (reported not-applicable).
    //  - FeatMandatory: the capability is fixed true; at replay time a
    //    server that fails to advertise it FAILS the suite instead of
    //    vacuously passing.
    type FeatureMode = FeatOff | FeatIfAdvertised | FeatMandatory

    pure def capChoices(m: FeatureMode): Set[bool] =
        match m {
            | FeatOff => Set(false)
            | FeatIfAdvertised => Set(false, true)
            | FeatMandatory => Set(true)
        }

    // Assumed at init (per the FeatureMode configuration, see nfs4.qnt) and
    // embedded in the trace.  The harness reconciles it against the live
    // server's advertisement/observed policy at replay time.
    type Caps = {
        // pNFS MDS advertised (EXCHGID4_FLAG_USE_PNFS_MDS + fs_layout_types);
        // false: every pNFS op is NFS4ERR_NOTSUPP (RFC 8881 13.1).
        pnfs: bool,
        // Delegation grant policy under the canonical conditions (grants
        // are always discretionary: RFC 7530 10.4 / RFC 8881 10.4).
        readDeleg: bool,
        writeDeleg: bool,
        // RFC 8276 xattr ops supported (xattr_support attribute).
        xattr: bool,
        // RFC 7862 ALLOCATE/DEALLOCATE/SEEK supported (per-op NOTSUPP).
        sparse: bool,
        // RFC 7862 intra-server synchronous COPY supported.
        copy: bool,
        // RFC 7862 15.10 READ_PLUS (sparse-aware READ) supported.
        readPlus: bool,
        // RFC 7862 15.5 IO_ADVISE supported.  Advisory: a server that
        // supports the operation may still honor no hints at all.
        ioAdvise: bool,
        // RFC 7862 15.13 WRITE_SAME (Application Data Block expansion)
        // supported.
        writeSame: bool,
        // RFC 7862 15.4 CLONE (reflink a byte range) supported.
        clone: bool,
        // discretion: the granularity a server keeps layouts at.  true: one
        // whole-file layout per (client, file) -- LAYOUTGET always grants
        // [0, EOF) whatever range was asked for, and a LAYOUTRETURN4_FILE of
        // any sub-range retires the whole thing (nothing is left to hold a
        // stateid for, so lrs_present is false).  false: the server accounts
        // for the returned range and keeps the remainder.  Both satisfy
        // RFC 8881 12.5.3 / 18.44.3; whole-file is the simpler contract and
        // the one a server that never stripes has any reason to implement.
        layoutWholeFile: bool,
        // discretion: a conflicting op during delegation recall returns
        // NFS4ERR_DELAY (true) or blocks until the recall completes
        // (false).  Both are conformant (RFC 8881 10.4.4); only the DELAY
        // profile generates linear traces.
        conflictDelays: bool,
        // discretion: CLOSE with byte-range locks still held under the
        // open either frees them (true) or fails NFS4ERR_LOCKS_HELD
        // (false) -- (free) XOR (LOCKS_HELD) per RFC 7530 9.10 /
        // RFC 8881 9.8.
        closeFreesLocks: bool
    }

    // ------------------------------------------------------------------
    // Request / reply shapes
    // ------------------------------------------------------------------

    // Reference to a stateid the harness has learned: model index + class
    // + the seqid to put on the wire (0 = wildcard current).
    type SidRef = { sid: Sid, kind: SidKind, argSeq: int }

    // Stateid selector for I/O-class ops (READ/WRITE/SETATTR/SEEK/...).
    type SidSel =
        | SelAnon                  // all-zero anonymous stateid
        | SelBypass                // all-ones READ-bypass stateid
        | SelRef(SidRef)

    type OpenClaim =
        | OCNull(Name)             // CLAIM_NULL: cfh = dir, named child
        | OCFh                     // CLAIM_FH (4.1+): cfh = the file

    type OpenHow =
        | HNoCreate
        | HUnchecked({ mode: int, truncate: bool })
        | HGuarded({ mode: int })
        | HExclusive({ verf: int })

    type XattrSetHow = XsCreate | XsReplace | XsEither

    type OpReq =
        | RPutrootfh
        | RPutfh(Ino)
        | RGetfh
        | RSavefh
        | RRestorefh
        | RLookup(Name)
        | RLookupp
        | RGetattr
        | RGetattrWide
        | RSecinfo(Name)
        | RSetattrWide(int)
        | RVerifyWide
        | RNverifyWide
        | RBindConnToSession({ sess: SessId, dir: int })
        | RReadlink
        | RAccess(int)
        | RReaddir
        | RCreate({ ctype: Ftype, name: Name, mode: int, target: str })
        | RRemove(Name)
        | RRename({ oldname: Name, newname: Name })
        | RLink(Name)
        | RSetattr({ mode: int, sizeBlocks: int, sel: SidSel })
        | RVerifySize(int)
        | RNverifySize(int)
        | RSetclientid({ ownerSym: int, verfSym: int, tok: int })
        | RSetclientidConfirm({ client: ClientId, tok: int })
        | RRenew(ClientId)
        | RReleaseLockowner({ client: ClientId, lockOwner: int })
        | RExchangeId({ ownerSym: int, verfSym: int })
        | RCreateSession({ client: ClientId, csaSeq: int, backChan: bool })
        | RSequence({ sess: SessId, slot: int, seq: int, cacheThis: bool })
        | RDestroySession(SessId)
        | RDestroyClientid(ClientId)
        | RReclaimComplete
        | RFreeStateid(SidRef)
        | ROpen({ client: ClientId, owner: int, oseq: int, claim: OpenClaim,
                  how: OpenHow, access: int, deny: int })
        | ROpenConfirm({ sid: Sid, oseq: int })
        | ROpenDowngrade({ sid: Sid, argSeq: int, access: int, deny: int,
                           oseq: int })
        | RClose({ sid: Sid, argSeq: int, oseq: int })
        | RRead({ sel: SidSel, off: int, len: int })
        | RWrite({ sel: SidSel, off: int, len: int, pat: int, stable: int })
        | RCommit
        | RLock({ wr: bool, lo: int, hi: int, newOwner: bool,
                  openSid: Sid, lockSid: Sid, lockOwner: int,
                  oseq: int, lseq: int })
        | RLockt({ client: ClientId, lockOwner: int, wr: bool, lo: int, hi: int })
        | RLocku({ sid: Sid, argSeq: int, lseq: int, lo: int, hi: int })
        | RDelegreturn(SidRef)
        | RLayoutget({ rw: bool, lo: int, hi: int, sel: SidSel })
        | RLayoutreturn({ sid: Sid, argSeq: int, lo: int, hi: int })
        | RLayoutcommit({ sid: Sid, lo: int, hi: int })
        | RGetdeviceinfo
        | RAllocate({ sel: SidSel, off: int, len: int })
        | RDeallocate({ sel: SidSel, off: int, len: int })
        | RSeek({ sel: SidSel, off: int, whatData: bool })
        | RCopy({ srcSel: SidSel, dstSel: SidSel,
                  srcOff: int, dstOff: int, cnt: int })
        | RReadPlus({ sel: SidSel, off: int, len: int })
        | RIoAdvise({ sel: SidSel, off: int, len: int, hint: int })
        | RWriteSame({ sel: SidSel, off: int, blocks: int, pat: int,
                       blocknum: bool })
        | RClone({ srcSel: SidSel, dstSel: SidSel,
                   srcOff: int, dstOff: int, cnt: int })
        | RGetxattr(Name)
        | RSetxattr({ name: Name, sym: int, how: XattrSetHow })
        | RListxattrs
        | RRemovexattr(Name)

    // Delegation granted in an OPEN reply.
    type DelegRes =
        | DNone
        | DRead({ sid: Sid })
        | DWrite({ sid: Sid })

    // Attribute snapshot for GETATTR-class checks.  change is the abstract
    // change value (harness checks consistency, not raw equality).
    type AttrSnap = { ftype: Ftype, mode: int, nlink: int,
                      sizeBlocks: int, change: int }

    type OpRes =
        | SPutrootfh({ st: int })
        | SPutfh({ st: int })
        | SGetfh({ st: int, ino: Ino })
        | SSavefh({ st: int })
        | SGetattrWide({ st: int })
        | SSecinfo({ st: int })
        | SBindConnToSession({ st: int })
        | SRestorefh({ st: int })
        | SLookup({ st: int, child: Ino })
        | SLookupp({ st: int, parent: Ino })
        | SGetattr({ st: int, attrs: AttrSnap })
        | SReadlink({ st: int, target: str })
        | SAccess({ st: int, supported: int, access: int })
        | SReaddir({ st: int, names: Set[Name] })
        | SCreate({ st: int, ino: Ino, cinfo: CInfo })
        | SRemove({ st: int, cinfo: CInfo })
        | SRename({ st: int, cinfoS: CInfo, cinfoT: CInfo })
        | SLink({ st: int, cinfo: CInfo })
        | SSetattr({ st: int })
        | SVerify({ st: int })
        | SNverify({ st: int })
        | SSetclientid({ st: int, client: ClientId, tok: int })
        | SSetclientidConfirm({ st: int })
        | SRenew({ st: int })
        | SReleaseLockowner({ st: int })
        | SExchangeId({ st: int, client: ClientId, csSeq: int,
                        confirmedR: bool, pnfsMds: bool })
        | SCreateSession({ st: int, sess: SessId })
        | SSequence({ st: int, replay: bool })
        | SDestroySession({ st: int })
        | SDestroyClientid({ st: int })
        | SReclaimComplete({ st: int })
        | SFreeStateid({ st: int })
        // recalls: delegation sids for which the harness must observe a
        // CB_RECALL before this op can eventually succeed (the op itself
        // returns NFS4ERR_DELAY under the conflictDelays profile).
        | SOpen({ st: int, sid: Sid, seq: int, needConfirm: bool,
                  cinfo: CInfo, deleg: DelegRes, recalls: Set[Sid] })
        | SOpenConfirm({ st: int, seq: int })
        | SOpenDowngrade({ st: int, seq: int })
        | SClose({ st: int })
        | SRead({ st: int, count: int, eof: bool, blocks: List[int] })
        | SWrite({ st: int, count: int, newSizeBlocks: int })
        | SCommit({ st: int })
        // denied: the owner symbol of one conflicting lock (-1 if OK).
        // acceptance: which conflicting lock a server reports when several
        // exist is discretionary; the harness checks the reported conflict
        // is real rather than comparing owners exactly.
        | SLock({ st: int, sid: Sid, seq: int, deniedOwner: int })
        | SLockt({ st: int, deniedOwner: int })
        | SLocku({ st: int, seq: int })
        | SDelegreturn({ st: int })
        | SLayoutget({ st: int, sid: Sid, seq: int, lo: int, hi: int })
        | SLayoutreturn({ st: int, present: bool, seq: int })
        | SLayoutcommit({ st: int, newSizeBlocks: int })
        | SGetdeviceinfo({ st: int })
        | SAllocate({ st: int })
        | SDeallocate({ st: int })
        | SSeek({ st: int, eof: bool, offset: int })
        | SCopy({ st: int, copied: int })
        // blocks/isData describe the requested range block by block; a
        // server may legally return a shorter prefix (see opReadPlus).
        | SReadPlus({ st: int, eof: bool, count: int,
                      blocks: List[int], isData: List[bool] })
        | SIoAdvise({ st: int })
        | SWriteSame({ st: int, count: int })
        | SClone({ st: int })
        | SGetxattr({ st: int, sym: int })
        | SSetxattr({ st: int })
        | SListxattrs({ st: int, names: Set[Name] })
        | SRemovexattr({ st: int })

    // ------------------------------------------------------------------
    // Evaluation accumulator
    // ------------------------------------------------------------------

    type Acc = {
        fs: Fs,
        sdb: StateDB,
        minor: int,
        caps: Caps,
        nOps: int,          // total ops in the compound (for NOT_ONLY_OP)
        reqTag: int,        // identity of this compound (SEQUENCE replay)
        idx: int,           // index of the op being evaluated
        cfh: Ino,           // -1 = unset
        sfh: Ino,           // -1 = unset
        seqDone: bool,      // a SEQUENCE op has been executed
        seqClient: ClientId,// client of the SEQUENCE's session (4.1)
        done: bool,         // stop: an op returned non-OK (or replay)
        status: int,        // status of the last executed op
        results: List[OpRes]
    }

    pure def statusOf(r: OpRes): int =
        match r {
            | SPutrootfh(x) => x.st
            | SPutfh(x) => x.st
            | SGetfh(x) => x.st
            | SSavefh(x) => x.st
            | SGetattrWide(x) => x.st
            | SSecinfo(x) => x.st
            | SBindConnToSession(x) => x.st
            | SRestorefh(x) => x.st
            | SLookup(x) => x.st
            | SLookupp(x) => x.st
            | SGetattr(x) => x.st
            | SReadlink(x) => x.st
            | SAccess(x) => x.st
            | SReaddir(x) => x.st
            | SCreate(x) => x.st
            | SRemove(x) => x.st
            | SRename(x) => x.st
            | SLink(x) => x.st
            | SSetattr(x) => x.st
            | SVerify(x) => x.st
            | SNverify(x) => x.st
            | SSetclientid(x) => x.st
            | SSetclientidConfirm(x) => x.st
            | SRenew(x) => x.st
            | SReleaseLockowner(x) => x.st
            | SExchangeId(x) => x.st
            | SCreateSession(x) => x.st
            | SSequence(x) => x.st
            | SDestroySession(x) => x.st
            | SDestroyClientid(x) => x.st
            | SReclaimComplete(x) => x.st
            | SFreeStateid(x) => x.st
            | SOpen(x) => x.st
            | SOpenConfirm(x) => x.st
            | SOpenDowngrade(x) => x.st
            | SClose(x) => x.st
            | SRead(x) => x.st
            | SWrite(x) => x.st
            | SCommit(x) => x.st
            | SLock(x) => x.st
            | SLockt(x) => x.st
            | SLocku(x) => x.st
            | SDelegreturn(x) => x.st
            | SLayoutget(x) => x.st
            | SLayoutreturn(x) => x.st
            | SLayoutcommit(x) => x.st
            | SGetdeviceinfo(x) => x.st
            | SAllocate(x) => x.st
            | SDeallocate(x) => x.st
            | SSeek(x) => x.st
            | SCopy(x) => x.st
            | SReadPlus(x) => x.st
            | SIoAdvise(x) => x.st
            | SWriteSame(x) => x.st
            | SClone(x) => x.st
            | SGetxattr(x) => x.st
            | SSetxattr(x) => x.st
            | SListxattrs(x) => x.st
            | SRemovexattr(x) => x.st
        }

    // Append a result; halt the compound when it is an error
    // (first-error-stops, RFC 7530 14.2 / RFC 8881 16.2.4 -- this applies
    // even to "non-error" statuses like NFS4ERR_SAME).
    pure def emit(a: Acc, r: OpRes): Acc = {
        val st = statusOf(r)
        a.with("results", a.results.append(r))
         .with("status", st)
         .with("done", st != OK)
    }

    pure def cfhLive(a: Acc): bool = a.cfh != -1 and fsLive(a.fs, a.cfh)
    pure def cfhNode(a: Acc): Inode = fsGet(a.fs, a.cfh)

    // Component-name validation, mirroring chimera_nfs4_validate_name()
    // (nfs4_procs.h) exactly, including its order: empty before too-long
    // before dot/dotdot before path-separator/NUL before malformed UTF-8.
    // The hostile names are abstract sentinels the harness materializes into
    // real bytes (v4_expand_name in nfs4_mbt_replay.c) -- a JSON trace cannot
    // carry an embedded NUL or a lone 0x80.  Every op that names a component
    // runs this immediately after its filehandle gate, which is where chimera
    // runs it too.
    pure def nameStatus(n: Name): int =
        if (n == "NEMPTY") E_INVAL
        else if (n == "NLONG") E_NAMETOOLONG
        else if (n == "NDOT" or n == "NDOTDOT") E_BADNAME
        else if (n == "NSLASH" or n == "NNUL") E_BADCHAR
        // Malformed UTF-8, one sentinel per reject branch of
        // chimera_nfs4_utf8_valid: stray continuation, overlong 2/3/4-byte,
        // surrogate, non-character, above U+10FFFF, c > 0xF4, truncated
        // sequence, bad continuation byte.
        else if (n == "NUTF8" or n == "NUTF8B" or n == "NUTF8C" or
                 n == "NUSUR" or n == "NUNCH" or n == "NU4OV" or
                 n == "NU4HI" or n == "NUF5" or n == "NUTRUNC" or
                 n == "NUBADC" or
                 // valid prefix, malformed tail: these reach the loop's
                 // second and later iterations, which a single-character
                 // sentinel cannot
                 n == "NUMIXB" or n == "NUMIXT" or n == "NUMIXS") E_INVAL
        // Everything else -- including the valid multi-byte names NU2/NU3/
        // NU4/NU3E/NU3S/NU4M -- is a legal component and travels as an
        // ordinary name.  Those exist to drive the validator's ACCEPT paths
        // for 2-, 3- and 4-byte sequences, which pure-ASCII names skip.
        else OK

    // The name a claim carries, if any.  CLAIM_FH names no component, so it
    // has nothing to validate.
    pure def claimNameStatus(c: OpenClaim): int =
        match c {
            | OCNull(n) => nameStatus(n)
            | OCFh => OK
        }

    // Shared filehandle gate: NOFILEHANDLE when unset (RFC 7530 13.1.2.5),
    // STALE when the object has been removed (RFC 7530 13.1.2.7; checked
    // at the op that uses the handle -- PUTFH may defer, R-CORE-102).
    // Returns OK when the cfh is usable.
    pure def fhGate(a: Acc): int =
        if (a.cfh == -1) E_NOFILEHANDLE
        else if (not(fsLive(a.fs, a.cfh))) E_STALE
        else OK

    // Map an abstract filesystem status onto nfsstat4.
    pure def fsStatus(st: FsStatus): int =
        match st {
            | FsOk => OK
            | FsNoent => E_NOENT
            | FsExist => E_EXIST
            | FsNotdir => E_NOTDIR
            | FsIsdir => E_ISDIR
            | FsNotempty => E_NOTEMPTY
            | FsInval => E_INVAL
            | FsNoxattr => E_NOXATTR
        }

    pure def snapOf(nd: Inode): AttrSnap =
        { ftype: nd.ftype, mode: nd.mode, nlink: nd.nlink,
          sizeBlocks: nd.sizeBlocks, change: nd.change }

    // Inodes that must survive losing their last name: a file with opens or
    // delegations stays reachable through its filehandle until that state
    // goes away (RFC 7530 16.26.5 / RFC 8881 18.25.4).
    //
    // A LAYOUT is deliberately NOT a pin.  It grants a client direct access to
    // where the data lives, not a reference to the file: RFC 8881 has no rule
    // keeping a removed file alive for one, and a client holding a layout must
    // also hold an open to have obtained it.  A server that reaped the file at
    // its last open would then answer PUTFH on the layout's filehandle with
    // NFS4ERR_STALE, which is exactly what the layout stateid becoming stale
    // means.  (Pinning here instead was a model-only assumption; it made the
    // model expect a file to outlive its last open whenever a layout survived.)
    pure def pinnedInos(sdb: StateDB): Set[Ino] =
        sdb.opens.keys().map(s => sdb.opens.get(s).file)
            .union(sdb.delegs.keys().map(s => sdb.delegs.get(s).file))

    // Reap an orphan once its last pin is gone (called after CLOSE /
    // DELEGRETURN).
    pure def maybeReap(fs: Fs, sdb: StateDB, f: Ino): Fs =
        if (fsLive(fs, f) and fsGet(fs, f).nlink == 0 and
            not(pinnedInos(sdb).contains(f)))
            fsReap(fs, f)
        else fs

    // Sweep every unpinned orphan: needed after bulk state removal (a
    // client reboot purging its old incarnation's opens releases every
    // pin that incarnation held).
    pure def reapOrphans(fs: Fs, sdb: StateDB): Fs = {
        val dead = fs.inodes.keys().filter(i =>
            fsGet(fs, i).ftype != FDir and fsGet(fs, i).nlink == 0 and
            not(pinnedInos(sdb).contains(i)))
        fs.with("inodes", fs.inodes.keys().exclude(dead)
              .mapBy(i => fs.inodes.get(i)))
          .with("removed", fs.removed.union(dead))
    }

    // ------------------------------------------------------------------
    // 4.0 owner-seqid discipline (RFC 7530 9.1.7)
    // ------------------------------------------------------------------

    // Errors that do NOT consume an owner seqid (RFC 7530 9.1.7).
    pure def consumesSeqid(st: int): bool =
        not(Set(E_STALE_CLIENTID, E_STALE_STATEID, E_BAD_STATEID,
                E_BAD_SEQID, E_BADXDR, E_RESOURCE, E_NOFILEHANDLE,
                E_MOVED).contains(st))

    // Gate an open-owner-sequenced op (OPEN/OPEN_CONFIRM/OPEN_DOWNGRADE/
    // CLOSE).  A brand-new owner is accepted with any seqid (SHOULD be 1);
    // an existing owner must present last+1.  Replays (r == last) are not
    // generated by this model (deferred with the DRC work) and are treated
    // as BAD_SEQID here.
    pure def ooGateOk(sdb: StateDB, cid: ClientId, owner: int, oseq: int): bool = {
        val k = (cid, owner)
        if (not(sdb.oo40.keys().contains(k))) true
        else oseq == sdb.oo40.get(k).seqid + 1
    }

    // Record the outcome of a sequenced op: advance the owner seqid iff the
    // status consumes it; create the owner record on first use.
    pure def ooSettle(sdb: StateDB, cid: ClientId, owner: int, oseq: int,
                      st: int, nowConfirmed: bool): StateDB = {
        val k = (cid, owner)
        if (not(consumesSeqid(st))) sdb
        else if (sdb.oo40.keys().contains(k))
            sdb.with("oo40", sdb.oo40.setBy(k, x =>
                { seqid: oseq, confirmed: x.confirmed or nowConfirmed }))
        else
            sdb.with("oo40", sdb.oo40.put(k,
                { seqid: oseq, confirmed: nowConfirmed }))
    }

    pure def ooConfirmed(sdb: StateDB, cid: ClientId, owner: int): bool = {
        val k = (cid, owner)
        sdb.oo40.keys().contains(k) and sdb.oo40.get(k).confirmed
    }

    // Lock-owner seqid gate (4.0), same shape.
    pure def loGateOk(sdb: StateDB, cid: ClientId, owner: int, lseq: int): bool = {
        val k = (cid, owner)
        if (not(sdb.lo40.keys().contains(k))) true
        else lseq == sdb.lo40.get(k).seqid + 1
    }

    pure def loSettle(sdb: StateDB, cid: ClientId, owner: int, lseq: int,
                      st: int): StateDB = {
        val k = (cid, owner)
        if (not(consumesSeqid(st))) sdb
        else if (sdb.lo40.keys().contains(k))
            sdb.with("lo40", sdb.lo40.setBy(k, x => { seqid: lseq }))
        else
            sdb.with("lo40", sdb.lo40.put(k, { seqid: lseq }))
    }

    // ------------------------------------------------------------------
    // Stateid selector resolution for I/O ops
    // ------------------------------------------------------------------

    type IoSid =
        | IoAnon
        | IoBypass
        | IoState({ sid: Sid, kind: SidKind })
        | IoError(int)

    // Resolve an I/O stateid selector against the tables.  Checks:
    // liveness + seqid window (BAD/OLD_STATEID), the state's file must be
    // the current filehandle (RFC 7530 9.1.4.4 / RFC 8881 8.2.4), and 4.0
    // unconfirmed opens are unusable (RFC 7530 16.18.5).
    pure def resolveSel(a: Acc, sel: SidSel): IoSid =
        match sel {
            | SelAnon => IoAnon
            | SelBypass => IoBypass
            | SelRef(r) =>
                match checkSid(a.sdb, r.sid, r.kind, r.argSeq) {
                    | SidBad => IoError(E_BAD_STATEID)
                    | SidOld => IoError(E_OLD_STATEID)
                    | SidOk => {
                        val fOf = match r.kind {
                            | KOpen => a.sdb.opens.get(r.sid).file
                            | KLock => a.sdb.locks.get(r.sid).file
                            | KDeleg => a.sdb.delegs.get(r.sid).file
                            | KLayout => a.sdb.layouts.get(r.sid).file
                        }
                        // The client the stateid was issued to.  A stateid
                        // belongs to the client that created it, so it
                        // designates no state for anyone else and using it
                        // from another client is NFS4ERR_BAD_STATEID (RFC
                        // 8881 15.1.5.2: "a stateid does not properly
                        // designate any valid state").
                        //
                        // Only 4.1+ can detect this: a 4.0 COMPOUND carries
                        // no client identity of its own, so the stateid is
                        // the only binding there and there is nothing to
                        // compare it against.
                        val ownedBy = match r.kind {
                            | KOpen => a.sdb.opens.get(r.sid).client
                            | KLock => a.sdb.locks.get(r.sid).client
                            | KDeleg => a.sdb.delegs.get(r.sid).client
                            | KLayout => a.sdb.layouts.get(r.sid).client
                        }
                        if (fOf != a.cfh) IoError(E_BAD_STATEID)
                        else if (a.minor >= 1 and a.seqClient != -1 and
                                 ownedBy != a.seqClient)
                            IoError(E_BAD_STATEID)
                        else if (r.kind == KOpen and
                                 a.sdb.opens.get(r.sid).needConfirm)
                            IoError(E_BAD_STATEID)
                        else IoState({ sid: r.sid, kind: r.kind })
                    }
                }
        }

    // Access mode the stateid carries for I/O checks: 1 read, 2 write,
    // 3 both.  Delegations: read deleg = 1, write deleg = 3; lock stateids
    // inherit their open's mode.
    pure def ioMode(a: Acc, io: IoSid): int =
        match io {
            | IoState(s) =>
                match s.kind {
                    | KOpen => a.sdb.opens.get(s.sid).access
                    | KLock => a.sdb.opens.get(a.sdb.locks.get(s.sid).openSid).access
                    | KDeleg => if (a.sdb.delegs.get(s.sid).isWrite) 3 else 1
                    | KLayout => 0
                }
            | IoAnon => 3
            | IoBypass => 3
            | IoError(e) => 0
        }

    // Does any current open of file f deny the given I/O kind (1 = read,
    // 2 = write)?  Anonymous-stateid I/O against a deny mode fails
    // NFS4ERR_LOCKED (RFC 7530 9.1.4.3 / RFC 8881 8.2.3).
    // A stateid selection that carries no open of its own, and so gets no
    // share grant with it.
    pure def namesNoOpen(sel: SidSel): bool =
        match sel {
            | SelAnon => true
            | SelBypass => true
            | SelRef(_) => false
        }

    pure def anyDeny(sdb: StateDB, f: Ino, kindBit: int): bool =
        sdb.opens.keys().exists(s => {
            val o = sdb.opens.get(s)
            o.file == f and bitsOverlap(o.deny, kindBit)
        })

    // ------------------------------------------------------------------
    // Per-op handlers
    // ------------------------------------------------------------------

    pure def opPutrootfh(a: Acc): Acc =
        emit(a.with("cfh", ROOT), SPutrootfh({ st: OK }))

    // The generator only presents live inos; a removed ino would surface
    // STALE here or at first use (R-CORE-102 leaves the position open).
    pure def opPutfh(a: Acc, i: Ino): Acc =
        emit(a.with("cfh", i), SPutfh({ st: OK }))

    pure def opGetfh(a: Acc): Acc = {
        val g = fhGate(a)
        if (g != OK) emit(a, SGetfh({ st: g, ino: -1 }))
        else emit(a, SGetfh({ st: OK, ino: a.cfh }))
    }

    pure def opSavefh(a: Acc): Acc = {
        val g = fhGate(a)
        if (g != OK) emit(a, SSavefh({ st: g }))
        else emit(a.with("sfh", a.cfh), SSavefh({ st: OK }))
    }

    // RESTOREFH: sfh copied to cfh, sfh survives (RFC 7530 16.29.4).
    pure def opRestorefh(a: Acc): Acc =
        if (a.sfh == -1) emit(a, SRestorefh({ st: E_RESTOREFH }))
        else emit(a.with("cfh", a.sfh), SRestorefh({ st: OK }))

    // LOOKUP (RFC 7530 16.13 / RFC 8881 18.13): single component; cfh a
    // symlink -> NFS4ERR_SYMLINK, other non-directory -> NFS4ERR_NOTDIR.
    pure def opLookup(a: Acc, n: Name): Acc = {
        val g = fhGate(a)
        val ns = nameStatus(n)
        if (g != OK) emit(a, SLookup({ st: g, child: -1 }))
        else if (ns != OK) emit(a, SLookup({ st: ns, child: -1 }))
        else {
            val nd = cfhNode(a)
            if (nd.ftype == FLnk)
                emit(a, SLookup({ st: E_SYMLINK, child: -1 }))
            else if (nd.ftype != FDir)
                emit(a, SLookup({ st: E_NOTDIR, child: -1 }))
            else if (not(fsHasEnt(a.fs, a.cfh, n)))
                emit(a, SLookup({ st: E_NOENT, child: -1 }))
            else {
                val c = fsChild(a.fs, a.cfh, n)
                emit(a.with("cfh", c), SLookup({ st: OK, child: c }))
            }
        }
    }

    // LOOKUPP (RFC 7530 16.14 / RFC 8881 18.14): parent of cfh; NOENT at
    // the namespace root.  acceptance: for a symlink cfh either NOTDIR
    // (op text) or SYMLINK (error table) is conformant; NOTDIR modeled.
    pure def opLookupp(a: Acc): Acc = {
        val g = fhGate(a)
        if (g != OK) emit(a, SLookupp({ st: g, parent: -1 }))
        else {
            val nd = cfhNode(a)
            if (nd.ftype == FLnk)
                emit(a, SLookupp({ st: E_SYMLINK, parent: -1 }))
            else if (nd.ftype != FDir)
                emit(a, SLookupp({ st: E_NOTDIR, parent: -1 }))
            else if (a.cfh == ROOT)
                emit(a, SLookupp({ st: E_NOENT, parent: -1 }))
            else
                emit(a.with("cfh", nd.parent),
                     SLookupp({ st: OK, parent: nd.parent }))
        }
    }

    pure def opGetattr(a: Acc): Acc = {
        val g = fhGate(a)
        if (g != OK)
            emit(a, SGetattr({ st: g, attrs: { ftype: FReg, mode: 0, nlink: 0,
                                               sizeBlocks: 0, change: 0 } }))
        else emit(a, SGetattr({ st: OK, attrs: snapOf(cfhNode(a)) }))
    }

    // GETATTR over the server's whole supported-attribute set.  The model
    // predicts only that the call succeeds, not the values: the point is to
    // drive chimera's attribute marshaller, which encodes ~50 attributes of
    // which the five the model tracks are a small corner.  Deliberately a
    // separate op rather than a wider mask on RGetattr -- the harness decodes
    // the attribute blob positionally in FATTR4 bit order and knows only
    // those five, so widening the existing request would shift every offset
    // and compare garbage.  There is no SGetattrWide comparator arm, so only
    // the status is checked.
    pure def opGetattrWide(a: Acc): Acc = {
        val g = fhGate(a)
        if (g != OK) emit(a, SGetattrWide({ st: g }))
        else emit(a, SGetattrWide({ st: OK }))
    }

    // BIND_CONN_TO_SESSION (RFC 8881 18.34): associates the connection the
    // request arrived on with an existing session; 4.1+ only.
    //
    // The NOT_ONLY_OP rule is the subtle one and the reason this op is worth
    // modeling carefully: it applies only when the compound carries NO
    // SEQUENCE (chimera gates on `!req->seen_sequence && num_argarray != 1`),
    // not unconditionally on nOps > 1.  Getting that backwards is exactly the
    // mispredict the pynfs audit found sitting in opExchangeId /
    // opCreateSession / opDestroyClientid.
    //
    // Valid directions are the four channel_dir_from_client4 values (FORE=1,
    // BACK=2, FORE_OR_BOTH=3, BACK_OR_BOTH=7 -- note 4 is NOT one of them);
    // anything else is NFS4ERR_INVAL, after the session lookup.  The model
    // predicts the status only: the reply's direction and rdma flag are a
    // deterministic function of the argument, and comparing them needs a
    // comparator arm this cluster leaves to a follow-on.
    pure def opBindConnToSession(a: Acc, ar: { sess: SessId, dir: int }): Acc =
        if (a.minor == 0) emit(a, SBindConnToSession({ st: E_OP_ILLEGAL }))
        else if (not(a.seqDone) and a.nOps > 1)
            emit(a, SBindConnToSession({ st: E_NOT_ONLY_OP }))
        else if (not(a.sdb.sessions.keys().contains(ar.sess)))
            emit(a, SBindConnToSession({ st: E_BADSESSION }))
        else if (not(Set(1, 2, 3, 7).contains(ar.dir)))
            emit(a, SBindConnToSession({ st: E_INVAL }))
        else emit(a, SBindConnToSession({ st: OK }))

    // SECINFO (RFC 7530 16.31 / RFC 8881 18.29): reports which security
    // flavors may be used for `name` in the current directory.  The model
    // predicts the status only -- the flavor list is export policy, not
    // filesystem state, so there is no SSecinfo comparator arm.
    //
    // The interesting part is the side effect on the current filehandle, and
    // it is minor-version-specific: RFC 8881 18.29.3 says SECINFO **consumes**
    // the current filehandle (a following op that needs one gets
    // NFS4ERR_NOFILEHANDLE), but RFC 7530 16.31.3 says it is **retained** ("On
    // success, the current filehandle retains its value").  Both NFS-Ganesha
    // and the Linux kernel server retain it on 4.0, so the model consumes only
    // on 4.1+.  (The reference implementation zeroes req->fhlen for every
    // minor, which now shows as a chimera divergence on 4.0.)  This is the
    // model's only generator of a cfh-less op.
    pure def opSecinfo(a: Acc, n: Name): Acc = {
        val g = fhGate(a)
        val ns = nameStatus(n)
        if (g != OK) emit(a, SSecinfo({ st: g }))
        else if (ns != OK) emit(a, SSecinfo({ st: ns }))
        else {
            val nd = cfhNode(a)
            if (nd.ftype == FLnk) emit(a, SSecinfo({ st: E_SYMLINK }))
            else if (nd.ftype != FDir) emit(a, SSecinfo({ st: E_NOTDIR }))
            else if (not(fsHasEnt(a.fs, a.cfh, n)))
                emit(a, SSecinfo({ st: E_NOENT }))
            else emit(if (a.minor >= 1) a.with("cfh", -1) else a,
                      SSecinfo({ st: OK }))
        }
    }

    // READLINK (RFC 7530 16.25 / RFC 8881 18.24): directory -> ISDIR,
    // other non-symlink -> INVAL ("should" wording).
    // READLINK on a non-symlink is NFS4ERR_INVAL.  RFC 7530 16.25.4 names it
    // outright ("should return NFS4ERR_INVAL if the object is not a symbolic
    // link" -- a directory is not a symbolic link); RFC 8881 18.24.4 later
    // recommends NFS4ERR_WRONG_TYPE, but only as a SHOULD, and every server
    // this corpus is replayed against (NFS-Ganesha and the Linux kernel
    // server) kept the original INVAL for all minor versions -- so the model
    // predicts INVAL rather than recording the same permitted divergence on
    // every server.  No special NFS4ERR_ISDIR case: one status covers every
    // non-symlink target.
    pure def opReadlink(a: Acc): Acc = {
        val g = fhGate(a)
        if (g != OK) emit(a, SReadlink({ st: g, target: "" }))
        else {
            val nd = cfhNode(a)
            if (nd.ftype != FLnk)
                emit(a, SReadlink({ st: E_INVAL, target: "" }))
            else emit(a, SReadlink({ st: OK, target: nd.target }))
        }
    }

    // ACCESS (RFC 7530 16.1 / RFC 8881 18.1): supported must be a subset
    // of the request; access a subset of supported.  discretion: the
    // harness runs as root over AUTH_SYS, and the model predicts
    // access == supported == requested (the reference implementation grants
    // root everything; within RFC discretion, as in the v3 model).
    // The ACCESS4_* bit for each request class, and the bitwise AND the reply
    // masking needs (Quint has no native bitwise operator).
    pure val ACCESS4_READ    = 1
    pure val ACCESS4_LOOKUP  = 2
    pure val ACCESS4_MODIFY  = 4
    pure val ACCESS4_EXTEND  = 8
    pure val ACCESS4_DELETE  = 16
    pure val ACCESS4_EXECUTE = 32
    pure def iand(x: int, y: int): int =
        List(1, 2, 4, 8, 16, 32).foldl(0, (acc, b) =>
            if ((x / b) % 2 == 1 and (y / b) % 2 == 1) acc + b else acc)
    // Any execute bit set in a mode (owner/group/other x).
    pure def anyExec(m: int): bool =
        (m % 2 == 1) or ((m / 8) % 2 == 1) or ((m / 64) % 2 == 1)

    // ACCESS (RFC 7530 16.1 / RFC 8881 18.1).  `supported` is the requested
    // bits the server can evaluate for the object's TYPE: ACCESS4_LOOKUP has
    // no meaning for a non-directory and ACCESS4_EXECUTE none for a directory
    // (RFC 8881 18.1.4), so each is dropped for the wrong type.  `access` is
    // the granted subset -- the harness runs as root over AUTH_SYS, and root
    // is granted every evaluated class EXCEPT ACCESS4_EXECUTE on a file with
    // no execute bit anywhere in its mode (RFC 8881 18.1.4: the server MUST
    // NOT set ACCESS4_EXECUTE unless at least one execute bit is set).  This
    // is what the reference implementation, NFS-Ganesha and the Linux kernel
    // server all do; the model formerly returned the full requested mask.
    // The bits meaningful for the object type (matches the reference
    // implementation's chimera_nfs4_access_meaningful, RFC 8881 18.1.4):
    // a directory drops EXECUTE and keeps LOOKUP+DELETE; a non-directory
    // keeps EXECUTE and drops LOOKUP (no meaning off a directory) AND DELETE
    // (deletability is a property of the parent, which an ACCESS on the
    // object itself cannot check, so the server reports it 0 -- RFC 8881
    // 18.1.4 permits DELETE = 0).
    pure def accessMeaningful(ft: Ftype): int =
        if (ft == FDir) ACCESS4_READ + ACCESS4_LOOKUP + ACCESS4_MODIFY +
                        ACCESS4_EXTEND + ACCESS4_DELETE
        else ACCESS4_READ + ACCESS4_MODIFY + ACCESS4_EXTEND + ACCESS4_EXECUTE

    pure def opAccess(a: Acc, mask: int): Acc = {
        val g = fhGate(a)
        if (g != OK) emit(a, SAccess({ st: g, supported: 0, access: 0 }))
        else {
            val nd = cfhNode(a)
            val supported = iand(mask, accessMeaningful(nd.ftype))
            val access =
                if (iand(supported, ACCESS4_EXECUTE) == ACCESS4_EXECUTE and
                    not(anyExec(nd.mode)))
                    supported - ACCESS4_EXECUTE
                else supported
            emit(a, SAccess({ st: OK, supported: supported, access: access }))
        }
    }

    // READDIR (RFC 7530 16.24 / RFC 8881 18.23): single-shot with a large
    // maxcount, as in the v3 model; cookie continuation is deferred.
    // "." and ".." are never returned (R-CORE-85).
    pure def opReaddir(a: Acc): Acc = {
        val g = fhGate(a)
        if (g != OK) emit(a, SReaddir({ st: g, names: Set() }))
        else {
            val nd = cfhNode(a)
            if (nd.ftype == FLnk) emit(a, SReaddir({ st: E_SYMLINK, names: Set() }))
            else if (nd.ftype != FDir) emit(a, SReaddir({ st: E_NOTDIR, names: Set() }))
            else emit(a, SReaddir({ st: OK, names: nd.ents.keys() }))
        }
    }

    // CREATE (RFC 7530 16.4 / RFC 8881 18.4): non-regular types only;
    // NF4REG -> NFS4ERR_BADTYPE.  On success cfh moves to the new object.
    pure def opCreate(a: Acc, ar: { ctype: Ftype, name: Name, mode: int,
                                    target: str }): Acc = {
        val g = fhGate(a)
        val bad = { st: g, ino: -1, cinfo: { before: 0, after: 0 } }
        if (g != OK) emit(a, SCreate(bad))
        else if (nameStatus(ar.name) != OK)
            emit(a, SCreate(bad.with("st", nameStatus(ar.name))))
        else if (ar.ctype == FReg)
            emit(a, SCreate(bad.with("st", E_BADTYPE)))
        else {
            val node =
                if (ar.ctype == FDir) mkDir(ar.mode, a.cfh, 0)
                else if (ar.ctype == FLnk) mkSymlink(ar.target, ar.mode, 0)
                else mkSpecial(ar.ctype, ar.mode, 0)
            val o = fsMknode(a.fs, a.cfh, ar.name, node)
            if (o.st != FsOk)
                emit(a, SCreate(bad.with("st", fsStatus(o.st))))
            else
                emit(a.with("fs", o.fs2).with("cfh", o.ino),
                     SCreate({ st: OK, ino: o.ino, cinfo: o.cinfo }))
        }
    }

    // REMOVE (RFC 7530 16.26 / RFC 8881 18.25): untyped; non-empty
    // directory -> NFS4ERR_NOTEMPTY.  Removal of an open file is
    // permitted (NFS4ERR_FILE_OPEN is a server MAY, R-CORE-71); the
    // object is orphaned while opens/delegations/layouts pin it and
    // reaped at the last CLOSE.
    pure def opRemove(a: Acc, n: Name): Acc = {
        val g = fhGate(a)
        val ns = nameStatus(n)
        if (g != OK) emit(a, SRemove({ st: g, cinfo: { before: 0, after: 0 } }))
        else if (ns != OK)
            emit(a, SRemove({ st: ns, cinfo: { before: 0, after: 0 } }))
        else if (cfhNode(a).ftype == FLnk)
            emit(a, SRemove({ st: E_SYMLINK, cinfo: { before: 0, after: 0 } }))
        else {
            // Delegations held by other clients on the victim force a
            // recall; REMOVE observes NFS4ERR_DELAY until they return
            // (probed: nfs4_deleg_probe.c C3, same discipline as OPEN).
            val victim = if (fsHasEnt(a.fs, a.cfh, n))
                             fsChild(a.fs, a.cfh, n) else -1
            val recalls = if (victim == -1) Set() else
                delegsOnFile(a.sdb, victim).filter(s =>
                    a.sdb.delegs.get(s).client != a.seqClient)
            if (recalls.size() > 0) {
                emit(a.with("sdb", recalls.fold(a.sdb, (acc, s) =>
                                                doRecallDeleg(acc, s))),
                     SRemove({ st: E_DELAY, cinfo: { before: 0, after: 0 } }))
            } else {
                val o = fsRemove(a.fs, a.cfh, n, pinnedInos(a.sdb))
                emit(a.with("fs", o.fs2),
                     SRemove({ st: fsStatus(o.st), cinfo: o.cinfo }))
            }
        }
    }

    // RENAME (RFC 7530 16.27 / RFC 8881 18.26): sfh = source dir, cfh =
    // target dir.  acceptance: for a non-empty-directory target the model
    // predicts NOTEMPTY (Table 7 + POSIX servers); the op text's EXIST is
    // also conformant (R-CORE-73).
    pure def opRename(a: Acc, ar: { oldname: Name, newname: Name }): Acc = {
        val zero = { before: 0, after: 0 }
        if (a.sfh == -1 or a.cfh == -1)
            emit(a, SRename({ st: E_NOFILEHANDLE, cinfoS: zero, cinfoT: zero }))
        else if (not(fsLive(a.fs, a.sfh)) or not(fsLive(a.fs, a.cfh)))
            emit(a, SRename({ st: E_STALE, cinfoS: zero, cinfoT: zero }))
        else if (nameStatus(ar.oldname) != OK)
            emit(a, SRename({ st: nameStatus(ar.oldname),
                              cinfoS: zero, cinfoT: zero }))
        else if (nameStatus(ar.newname) != OK)
            emit(a, SRename({ st: nameStatus(ar.newname),
                              cinfoS: zero, cinfoT: zero }))
        else if (fsGet(a.fs, a.sfh).ftype == FLnk or
                 fsGet(a.fs, a.cfh).ftype == FLnk)
            emit(a, SRename({ st: E_SYMLINK, cinfoS: zero, cinfoT: zero }))
        else {
            // Rename-over unlinks the target: other-client delegations on
            // it force a recall + NFS4ERR_DELAY, mirroring REMOVE.  (The
            // source object merely changes name; no conflict.)
            val victim = if (fsHasEnt(a.fs, a.cfh, ar.newname))
                             fsChild(a.fs, a.cfh, ar.newname) else -1
            val recalls = if (victim == -1) Set() else
                delegsOnFile(a.sdb, victim).filter(s =>
                    a.sdb.delegs.get(s).client != a.seqClient)
            if (recalls.size() > 0) {
                emit(a.with("sdb", recalls.fold(a.sdb, (acc, s) =>
                                                doRecallDeleg(acc, s))),
                     SRename({ st: E_DELAY, cinfoS: zero, cinfoT: zero }))
            } else {
                val o = fsRename(a.fs, a.sfh, ar.oldname, a.cfh, ar.newname,
                                 pinnedInos(a.sdb))
                emit(a.with("fs", o.fs2),
                     SRename({ st: fsStatus(o.st), cinfoS: o.cinfoS,
                               cinfoT: o.cinfoT }))
            }
        }
    }

    // LINK (RFC 7530 16.9 / RFC 8881 18.9): sfh = object, cfh = target
    // dir.  acceptance: LINK of a directory is ISDIR (modeled; NOTSUPP
    // also in the valid list, R-CORE-78).
    pure def opLink(a: Acc, n: Name): Acc = {
        val zero = { before: 0, after: 0 }
        if (a.sfh == -1 or a.cfh == -1)
            emit(a, SLink({ st: E_NOFILEHANDLE, cinfo: zero }))
        else if (not(fsLive(a.fs, a.sfh)) or not(fsLive(a.fs, a.cfh)))
            emit(a, SLink({ st: E_STALE, cinfo: zero }))
        else if (fsGet(a.fs, a.cfh).ftype == FLnk)
            emit(a, SLink({ st: E_SYMLINK, cinfo: zero }))
        // The type of the source (saved) filehandle is checked before the
        // name: hard-linking a directory is NFS4ERR_ISDIR, which both the
        // Linux server and NFS-Ganesha report ahead of a malformed newname
        // (RFC 7530 16.9 leaves the ordering open; the servers agree).
        else if (fsGet(a.fs, a.sfh).ftype == FDir)
            emit(a, SLink({ st: E_ISDIR, cinfo: zero }))
        else if (nameStatus(n) != OK)
            emit(a, SLink({ st: nameStatus(n), cinfo: zero }))
        else {
            val o = fsLink(a.fs, a.sfh, a.cfh, n)
            emit(a.with("fs", o.fs2), SLink({ st: fsStatus(o.st), cinfo: o.cinfo }))
        }
    }

    // SETATTR (RFC 7530 16.32 / RFC 8881 18.30): mode and/or size.  The
    // stateid argument matters only when size is set (R-ATTR); a size set
    // on a directory is ISDIR in 4.0 and WRONG_TYPE in 4.1+ (per the
    // valid-error tables; the RFCs state no explicit rule).  Size changes
    // via a stateid lacking WRITE access -> NFS4ERR_OPENMODE (MUST,
    // RFC 8881 9.1.2).
    pure def opSetattr(a: Acc, ar: { mode: int, sizeBlocks: int,
                                     sel: SidSel }): Acc = {
        val g = fhGate(a)
        if (g != OK) emit(a, SSetattr({ st: g }))
        else {
            val nd = cfhNode(a)
            if (ar.sizeBlocks >= 0 and nd.ftype != FReg)
                emit(a, SSetattr({ st: if (nd.ftype == FDir and a.minor == 0)
                                           E_ISDIR
                                       else if (a.minor == 0) E_INVAL
                                       else E_WRONG_TYPE }))
            else if (ar.sizeBlocks >= 0) {
                val io = resolveSel(a, ar.sel)
                match io {
                    | IoError(e) => emit(a, SSetattr({ st: e }))
                    | IoAnon =>
                        if (anyDeny(a.sdb, a.cfh, 2))
                            emit(a, SSetattr({ st: E_LOCKED }))
                        else {
                            val fs1 = fsResize(a.fs, a.cfh, ar.sizeBlocks)
                            val fs2 = if (ar.mode >= 0) fsChmod(fs1, a.cfh, ar.mode)
                                      else fs1
                            // A size change recalls every layout on the file
                            // (see revokeLayoutsOn).  A layout is a pin, so
                            // losing the last one can be what finally reaps an
                            // unlinked-but-pinned file.
                            val sdbR = revokeLayoutsOn(a.sdb, a.cfh)
                            emit(a.with("fs", maybeReap(fs2, sdbR, a.cfh))
                                  .with("sdb", sdbR),
                                 SSetattr({ st: OK }))
                        }
                    | IoBypass =>
                        // READ-bypass acts as anonymous outside READ
                        // (RFC 8881 8.2.3); deny check still applies.
                        if (anyDeny(a.sdb, a.cfh, 2))
                            emit(a, SSetattr({ st: E_LOCKED }))
                        else {
                            val fs1 = fsResize(a.fs, a.cfh, ar.sizeBlocks)
                            val fs2 = if (ar.mode >= 0) fsChmod(fs1, a.cfh, ar.mode)
                                      else fs1
                            // A size change recalls every layout on the file
                            // (see revokeLayoutsOn).  A layout is a pin, so
                            // losing the last one can be what finally reaps an
                            // unlinked-but-pinned file.
                            val sdbR = revokeLayoutsOn(a.sdb, a.cfh)
                            emit(a.with("fs", maybeReap(fs2, sdbR, a.cfh))
                                  .with("sdb", sdbR),
                                 SSetattr({ st: OK }))
                        }
                    | IoState(s) =>
                        if (not(bitsOverlap(ioMode(a, io), 2)))
                            emit(a, SSetattr({ st: E_OPENMODE }))
                        else {
                            val fs1 = fsResize(a.fs, a.cfh, ar.sizeBlocks)
                            val fs2 = if (ar.mode >= 0) fsChmod(fs1, a.cfh, ar.mode)
                                      else fs1
                            // A size change recalls every layout on the file
                            // (see revokeLayoutsOn).  A layout is a pin, so
                            // losing the last one can be what finally reaps an
                            // unlinked-but-pinned file.
                            val sdbR = revokeLayoutsOn(a.sdb, a.cfh)
                            emit(a.with("fs", maybeReap(fs2, sdbR, a.cfh))
                                  .with("sdb", sdbR),
                                 SSetattr({ st: OK }))
                        }
                }
            } else if (ar.mode >= 0)
                emit(a.with("fs", fsChmod(a.fs, a.cfh, ar.mode)),
                     SSetattr({ st: OK }))
            else emit(a, SSetattr({ st: OK }))
        }
    }

    // VERIFY/NVERIFY on the size attribute (RFC 7530 16.35/16.15;
    // RFC 8881 18.31/18.15): same -> continue / NFS4ERR_SAME, differ ->
    // NFS4ERR_NOT_SAME / continue.
    pure def opVerifySize(a: Acc, sz: int): Acc = {
        val g = fhGate(a)
        if (g != OK) emit(a, SVerify({ st: g }))
        else if (cfhNode(a).sizeBlocks == sz) emit(a, SVerify({ st: OK }))
        else emit(a, SVerify({ st: E_NOT_SAME }))
    }

    // VERIFY / NVERIFY over the server's whole supported-attribute set.
    //
    // chimera marshals every requested attribute and only then compares --
    // one memcmp over the finished buffer, guarded by a length check
    // (nfs4_proc_verify.c) -- so a wide mask drives its private copy of
    // chimera_nfs4_marshall_attrs no matter what the comparison decides.
    // The decision is still deterministic without the model predicting a
    // single attribute value: the harness sends the wide mask with an EMPTY
    // value blob, so `out_len == args->attr_vals.len` is false and the
    // attributes always compare as different.  VERIFY therefore answers
    // NFS4ERR_NOT_SAME and NVERIFY answers NFS4_OK.
    pure def opVerifyWide(a: Acc): Acc = {
        val g = fhGate(a)
        if (g != OK) emit(a, SVerify({ st: g }))
        else emit(a, SVerify({ st: E_NOT_SAME }))
    }

    pure def opNverifyWide(a: Acc): Acc = {
        val g = fhGate(a)
        if (g != OK) emit(a, SNverify({ st: g }))
        else emit(a, SNverify({ st: OK }))
    }

    pure def opNverifySize(a: Acc, sz: int): Acc = {
        val g = fhGate(a)
        if (g != OK) emit(a, SNverify({ st: g }))
        else if (cfhNode(a).sizeBlocks == sz) emit(a, SNverify({ st: E_SAME }))
        else emit(a, SNverify({ st: OK }))
    }

    // ------------------------------------------------------------------
    // Client management: 4.0
    // ------------------------------------------------------------------

    pure def opSetclientid(a: Acc, ar: { ownerSym: int, verfSym: int,
                                         tok: int }): Acc =
        if (a.minor != 0)
            // 4.0-only op in a 4.1+ compound: MNI, NFS4ERR_NOTSUPP
            // (RFC 8881 17).
            emit(a, SSetclientid({ st: E_NOTSUPP, client: -1, tok: -1 }))
        else {
            val r = applySetclientid(a.sdb, ar.ownerSym, ar.verfSym, ar.tok)
            emit(a.with("sdb", r.sdb2),
                 SSetclientid({ st: OK, client: r.clientid, tok: r.confirmTok }))
        }

    pure def opSetclientidConfirm(a: Acc, ar: { client: ClientId,
                                                tok: int }): Acc =
        if (a.minor != 0)
            emit(a, SSetclientidConfirm({ st: E_NOTSUPP }))
        else {
            // discretion: cbUp = true -- the harness always registers a
            // live callback service, so the callback probe succeeds.
            val r = applySetclientidConfirm(a.sdb, ar.client, ar.tok, true)
            match r.st {
                | ConfOk =>
                    // Confirming a rebooted client purges the old
                    // incarnation's state; orphans it pinned are reaped.
                    emit(a.with("sdb", r.sdb2)
                          .with("fs", reapOrphans(a.fs, r.sdb2)),
                         SSetclientidConfirm({ st: OK }))
                | ConfStale => emit(a, SSetclientidConfirm({ st: E_STALE_CLIENTID }))
            }
        }

    // RENEW is 4.0-only: RFC 8881 removed it (4.1+ renews the lease
    // implicitly through SEQUENCE), so a 4.1+ server treats op 30 as unknown
    // and answers OP_ILLEGAL -- not NOTSUPP, which is the answer for a
    // *recognized* but unsupported op.  Matches opReclaimComplete's use of
    // E_OP_ILLEGAL for the mirror-image case.  Not generated under 4.1+ (see
    // nsRenew), because the wire form is a resop the harness cannot decode.
    pure def opRenew(a: Acc, cid: ClientId): Acc =
        if (a.minor != 0) emit(a, SRenew({ st: E_OP_ILLEGAL }))
        else if (not(a.sdb.clients.keys().contains(cid)) or
                 not(a.sdb.clients.get(cid).confirmed))
            emit(a, SRenew({ st: E_STALE_CLIENTID }))
        else emit(a, SRenew({ st: OK }))

    // RELEASE_LOCKOWNER (RFC 7530 16.37): frees the lock-owner's stateids;
    // NFS4ERR_LOCKS_HELD while any byte remains locked.
    pure def opReleaseLockowner(a: Acc, ar: { client: ClientId,
                                              lockOwner: int }): Acc =
        if (a.minor != 0) emit(a, SReleaseLockowner({ st: E_NOTSUPP }))
        else {
            val held = a.sdb.locks.keys().filter(s => {
                val l = a.sdb.locks.get(s)
                l.client == ar.client and l.owner == ar.lockOwner
            })
            if (held.exists(s => a.sdb.locks.get(s).bytes.keys().size() > 0))
                emit(a, SReleaseLockowner({ st: E_LOCKS_HELD }))
            else {
                val sdb2 = a.sdb
                    .with("locks", a.sdb.locks.keys().exclude(held)
                          .mapBy(s => a.sdb.locks.get(s)))
                    .with("freedSids", a.sdb.freedSids.union(held))
                emit(a.with("sdb", sdb2), SReleaseLockowner({ st: OK }))
            }
        }

    // ------------------------------------------------------------------
    // Client management and sessions: 4.1+
    // ------------------------------------------------------------------

    pure def opExchangeId(a: Acc, ar: { ownerSym: int, verfSym: int }): Acc =
        if (a.minor == 0)
            emit(a, SExchangeId({ st: E_OP_ILLEGAL, client: -1, csSeq: 0,
                                  confirmedR: false, pnfsMds: false }))
        else if (not(a.seqDone) and a.nOps > 1)
            // *Outside a session* EXCHANGE_ID must be the only op
            // (RFC 8881 18.35.3).  Inside one -- i.e. when the compound
            // carries a SEQUENCE -- it may appear as an ordinary operation
            // anywhere, which is exactly what chimera implements
            // (`!req->seen_sequence && num_argarray != 1`).  Gating on
            // nOps > 1 alone was an over-approximation.
            emit(a, SExchangeId({ st: E_NOT_ONLY_OP, client: -1, csSeq: 0,
                                  confirmedR: false, pnfsMds: false }))
        else {
            val r = applyExchangeId(a.sdb, ar.ownerSym, ar.verfSym)
            emit(a.with("sdb", r.sdb2),
                 SExchangeId({ st: OK, client: r.clientid, csSeq: r.csSeq,
                               confirmedR: r.confirmedR,
                               // EXCHGID4_FLAG_USE_PNFS_MDS vs USE_NON_PNFS
                               // per the capability profile.
                               pnfsMds: a.caps.pnfs }))
        }

    pure def opCreateSession(a: Acc, ar: { client: ClientId, csaSeq: int,
                                           backChan: bool }): Acc =
        if (a.minor == 0)
            emit(a, SCreateSession({ st: E_OP_ILLEGAL, sess: -1 }))
        else if (not(a.seqDone) and a.nOps > 1)
            // Same rule as EXCHANGE_ID above (RFC 8881 18.36.3): sole op
            // only when the compound carries no SEQUENCE.
            emit(a, SCreateSession({ st: E_NOT_ONLY_OP, sess: -1 }))
        else {
            val r = applyCreateSession(a.sdb, ar.client, ar.csaSeq,
                                       NSLOTS, ar.backChan)
            match r.st {
                | CsOk =>
                    // The confirming CREATE_SESSION of a rebooted client
                    // purges the old incarnation's state (RFC 8881
                    // 18.35.4 case 5); reap orphans it pinned.
                    emit(a.with("sdb", r.sdb2)
                          .with("fs", reapOrphans(a.fs, r.sdb2)),
                         SCreateSession({ st: OK, sess: r.sess }))
                | CsReplay => emit(a, SCreateSession({ st: OK, sess: r.sess }))
                | CsMisordered =>
                    emit(a, SCreateSession({ st: E_SEQ_MISORDERED, sess: -1 }))
                | CsStale =>
                    emit(a, SCreateSession({ st: E_STALE_CLIENTID, sess: -1 }))
            }
        }

    // Fore-channel slot count the model's sessions use (the harness
    // negotiates at least this many via ca_maxrequests).
    pure val NSLOTS = 4

    pure def opSequence(a: Acc, ar: { sess: SessId, slot: int, seq: int,
                                      cacheThis: bool }): Acc =
        if (a.minor == 0)
            emit(a, SSequence({ st: E_OP_ILLEGAL, replay: false }))
        else if (a.idx != 0)
            // SEQUENCE anywhere but first -> NFS4ERR_SEQUENCE_POS
            // (RFC 8881 18.46.3).
            emit(a, SSequence({ st: E_SEQUENCE_POS, replay: false }))
        else {
            val r = applySequence(a.sdb, ar.sess, ar.slot, ar.seq,
                                  a.reqTag, ar.cacheThis)
            match r.st {
                | SeqNew => {
                    val cl = a.sdb.sessions.get(ar.sess).client
                    emit(a.with("sdb", r.sdb2).with("seqDone", true)
                          .with("seqClient", cl),
                         SSequence({ st: OK, replay: false }))
                }
                | SeqReplay =>
                    // The whole compound is a replay: the server answers
                    // from the slot's reply cache.  The harness compares
                    // against the reply it recorded for this slot/seq; the
                    // model stops predicting here (results after SEQUENCE
                    // are the cached ones).
                    emit(a, SSequence({ st: OK, replay: true }))
                      .with("done", true)
                | SeqFalseRetry =>
                    emit(a, SSequence({ st: E_SEQ_FALSE_RETRY, replay: false }))
                | SeqMisordered =>
                    emit(a, SSequence({ st: E_SEQ_MISORDERED, replay: false }))
                | SeqBadSession =>
                    emit(a, SSequence({ st: E_BADSESSION, replay: false }))
                | SeqBadSlot =>
                    emit(a, SSequence({ st: E_BADSLOT, replay: false }))
            }
        }

    pure def opDestroySession(a: Acc, sess: SessId): Acc =
        if (a.minor == 0) emit(a, SDestroySession({ st: E_OP_ILLEGAL }))
        else if (if (a.seqDone) a.idx != a.nOps - 1 else a.nOps > 1)
            // RFC 8881 18.37.3, the same shape as DESTROY_CLIENTID: last op
            // when a SEQUENCE precedes it, sole op when none does.  The model
            // had no position guard at all here.
            emit(a, SDestroySession({ st: E_NOT_ONLY_OP }))
        else {
        val r = applyDestroySession(a.sdb, sess)
        if (r.ok) emit(a.with("sdb", r.sdb2), SDestroySession({ st: OK }))
        else emit(a, SDestroySession({ st: E_BADSESSION }))
        }

    pure def opDestroyClientid(a: Acc, cid: ClientId): Acc =
        if (a.minor == 0) emit(a, SDestroyClientid({ st: E_OP_ILLEGAL }))
        else if (if (a.seqDone) a.idx != a.nOps - 1 else a.nOps > 1)
            // RFC 8881 18.50.3: preceded by a SEQUENCE, DESTROY_CLIENTID
            // must be the *final* operation of the compound; with no
            // SEQUENCE it must be the only one.  chimera implements both
            // arms (nfs4_proc_destroy_clientid.c).
            emit(a, SDestroyClientid({ st: E_NOT_ONLY_OP }))
        else if (not(a.sdb.clients.keys().contains(cid)))
            emit(a, SDestroyClientid({ st: E_STALE_CLIENTID }))
        else if (clientBusy(a.sdb, cid))
            emit(a, SDestroyClientid({ st: E_CLIENTID_BUSY }))
        else
            emit(a.with("sdb", purgeClient(a.sdb, cid)),
                 SDestroyClientid({ st: OK }))

    // RECLAIM_COMPLETE (RFC 8881 18.51, rca_one_fs = false): once per
    // client; a repeat is NFS4ERR_COMPLETE_ALREADY.
    pure def opReclaimComplete(a: Acc): Acc =
        if (a.minor == 0) emit(a, SReclaimComplete({ st: E_OP_ILLEGAL }))
        else {
        val cid = a.seqClient
        if (cid == -1) emit(a, SReclaimComplete({ st: E_OP_NOT_IN_SESSION }))
        else if (a.sdb.clients.get(cid).reclaimDone)
            emit(a, SReclaimComplete({ st: E_COMPLETE_ALREADY }))
        else
            emit(a.with("sdb", a.sdb.with("clients",
                     a.sdb.clients.setBy(cid, c => c.with("reclaimDone", true)))),
                 SReclaimComplete({ st: OK }))
    }

    // FREE_STATEID (RFC 8881 18.38): the model generates it for lock
    // stateids whose ranges are all unlocked; NFS4ERR_LOCKS_HELD while any
    // byte remains locked.  (Freeing revoked delegations/layouts is part
    // of the deferred restart scenarios.)
    pure def opFreeStateid(a: Acc, r: SidRef): Acc =
        if (a.minor == 0) emit(a, SFreeStateid({ st: E_OP_ILLEGAL }))
        // A *live* open or delegation stateid is not a bad stateid -- it names
        // state that FREE_STATEID is simply not the way to release (CLOSE and
        // DELEGRETURN are).  RFC 8881 18.38.3 defines the op as freeing a
        // stateid with no associated locks, "including opens, byte-range
        // locks, delegations and layouts", so a live one is NFS4ERR_LOCKS_HELD
        // -- which is what chimera answers (nfs4_proc_free_stateid.c handles
        // NFS4_SLOT_TYPE_OPEN and NFS4_SLOT_TYPE_DELEG that way).
        else if (r.kind == KOpen and sidLive(a.sdb, r.sid, KOpen))
            emit(a, SFreeStateid({ st: E_LOCKS_HELD }))
        else if (r.kind == KDeleg and sidLive(a.sdb, r.sid, KDeleg))
            emit(a, SFreeStateid({ st: E_LOCKS_HELD }))
        else if (r.kind != KLock or not(sidLive(a.sdb, r.sid, KLock)))
            emit(a, SFreeStateid({ st: E_BAD_STATEID }))
        else if (a.sdb.locks.get(r.sid).bytes.keys().size() > 0)
            emit(a, SFreeStateid({ st: E_LOCKS_HELD }))
        else {
            val sdb2 = a.sdb
                .with("locks", smapDrop(a.sdb.locks, r.sid))
                .with("freedSids", a.sdb.freedSids.union(Set(r.sid)))
            emit(a.with("sdb", sdb2), SFreeStateid({ st: OK }))
        }

    // ------------------------------------------------------------------
    // OPEN family
    // ------------------------------------------------------------------

    // Read-delegation recall triggers for an OPEN (RFC 8881 10.4.3 /
    // 18.16.4): access includes WRITE, deny includes READ, or a truncating
    // create.  Write delegations conflict with any other-client open.
    pure def openRecallSet(sdb: StateDB, cid: ClientId, f: Ino,
                           access: int, deny: int, truncates: bool): Set[Sid] =
        delegsOnFile(sdb, f).filter(s => {
            val d = sdb.delegs.get(s)
            d.client != cid and
            (d.isWrite or access >= 2 or deny % 2 == 1 or truncates)
        })

    // The delegation-grant profile, pinned against the reference
    // implementation by empirical probing (grants are always a server MAY --
    // RFC 8881
    // 10.4 -- so the model asserts the reference implementation's observed,
    // deterministic
    // in-process policy):
    //  - grants are active from the client's FIRST open once the
    //    backchannel is up (a 4.1 session created with the backchannel
    //    flag; no CB_NULL kick round-trip is observable in-process);
    //  - WRITE/BOTH open -> write delegation when no other client has
    //    the file open or delegated;
    //  - READ open -> read delegation when no other client has a
    //    write-mode open or a write delegation (read delegations and
    //    read opens coexist across clients);
    //  - no second grant to a client already holding a delegation on
    //    the file (and no self-recall);
    //  - never on a 4.0 open that demands OPEN_CONFIRM (RFC 7530
    //    9.1.11).
    pure def delegGrant(a: Acc, cid: ClientId, f: Ino, access: int, deny: int,
                        needConfirm: bool): int = {
        val othersOpenAny = a.sdb.opens.keys().exists(s => {
            val o = a.sdb.opens.get(s)
            o.file == f and o.client != cid
        })
        val othersOpenWrite = a.sdb.opens.keys().exists(s => {
            val o = a.sdb.opens.get(s)
            o.file == f and o.client != cid and o.access >= 2
        })
        val selfDeleg = delegsOnFile(a.sdb, f).exists(s =>
            a.sdb.delegs.get(s).client == cid)
        val otherDeleg = delegsOnFile(a.sdb, f).exists(s =>
            a.sdb.delegs.get(s).client != cid)
        val otherWriteDeleg = delegsOnFile(a.sdb, f).exists(s => {
            val d = a.sdb.delegs.get(s)
            d.client != cid and d.isWrite
        })
        val cbUp = a.sdb.clients.keys().contains(cid) and
                   a.sdb.clients.get(cid).cbUp
        if (needConfirm or selfDeleg or not(cbUp)) 0
        else if (access >= 2 and a.caps.writeDeleg and
                 not(othersOpenAny) and not(otherDeleg)) 2
        else if (access == 1 and a.caps.readDeleg and
                 not(othersOpenWrite) and not(otherWriteDeleg)) 1
        else 0
    }

    // Resolve an OPEN claim to a target file, creating it if asked.
    // Returns the typing/creation status plus the file and directory
    // change info.
    pure def openResolve(a: Acc, claim: OpenClaim, how: OpenHow):
            { st: int, fs2: Fs, file: Ino, cinfo: CInfo, truncated: bool } = {
        val zero = { before: 0, after: 0 }
        val base = { st: OK, fs2: a.fs, file: -1, cinfo: zero, truncated: false }
        match claim {
            | OCFh =>
                // CLAIM_FH (4.1+): cfh is the file itself; no create
                // (OPEN4_CREATE with CLAIM_FH is INVAL, RFC 8881 18.16.3).
                if (how != HNoCreate) base.with("st", E_INVAL)
                else {
                    val nd = cfhNode(a)
                    if (nd.ftype == FDir) base.with("st", E_ISDIR)
                    else if (nd.ftype == FLnk) base.with("st", E_SYMLINK)
                    else if (nd.ftype != FReg) base.with("st", E_WRONG_TYPE)
                    else base.with("file", a.cfh)
                }
            | OCNull(n) => {
                val dnd = cfhNode(a)
                if (dnd.ftype == FLnk) base.with("st", E_SYMLINK)
                else if (dnd.ftype != FDir) base.with("st", E_NOTDIR)
                else {
                    val present = fsHasEnt(a.fs, a.cfh, n)
                    val child = if (present) fsChild(a.fs, a.cfh, n) else -1
                    val childT = if (present) fsGet(a.fs, child).ftype else FReg
                    // Typing of an existing non-regular target: 4.0 uses
                    // SYMLINK for every non-directory special file; 4.1
                    // splits ISDIR/SYMLINK/WRONG_TYPE (RFC 7530 16.16.6 /
                    // RFC 8881 18.16.4).
                    val typeErr =
                        if (childT == FDir) E_ISDIR
                        else if (childT == FLnk) E_SYMLINK
                        else if (childT != FReg)
                            (if (a.minor == 0) E_SYMLINK else E_WRONG_TYPE)
                        else OK
                    match how {
                        | HNoCreate =>
                            if (not(present)) base.with("st", E_NOENT)
                            else if (typeErr != OK) base.with("st", typeErr)
                            else base.with("file", child)
                                     .with("cinfo", { before: dnd.change,
                                                      after: dnd.change })
                        | HUnchecked(u) =>
                            if (present and typeErr != OK)
                                // acceptance: EXIST is also seen from
                                // servers that order the existence check
                                // first (R-OPEN-803, UNSPECIFIED order).
                                base.with("st", typeErr)
                            else if (present) {
                                val fs2 = if (u.truncate)
                                              fsResize(a.fs, child, 0)
                                          else a.fs
                                base.with("file", child).with("fs2", fs2)
                                    .with("truncated", u.truncate)
                                    .with("cinfo", { before: dnd.change,
                                                     after: dnd.change })
                            } else {
                                val o = fsMknode(a.fs, a.cfh, n,
                                                 mkFile(u.mode, 0))
                                base.with("file", o.ino).with("fs2", o.fs2)
                                    .with("cinfo", o.cinfo)
                            }
                        | HGuarded(gm) =>
                            if (present) base.with("st", E_EXIST)
                            else {
                                val o = fsMknode(a.fs, a.cfh, n,
                                                 mkFile(gm.mode, 0))
                                base.with("file", o.ino).with("fs2", o.fs2)
                                    .with("cinfo", o.cinfo)
                            }
                        | HExclusive(x) =>
                            // EXCLUSIVE4: verifier match on an existing
                            // regular file is idempotent success; any
                            // other existing object is EXIST
                            // (RFC 7530 16.16.5 / RFC 8881 18.16.3).
                            // The mode of an exclusive-created file is
                            // undefined until the client's follow-up SETATTR
                            // (RFC 7530 16.16.5); a POSIX-filesystem backend
                            // creates it owner-only (0600).  chimera's memfs
                            // uses 0644, now a chimera divergence.
                            if (present and childT == FReg and
                                fsGet(a.fs, child).xverf == x.verf and
                                x.verf != 0)
                                base.with("file", child)
                                    .with("cinfo", { before: dnd.change,
                                                     after: dnd.change })
                            else if (present) base.with("st", E_EXIST)
                            else {
                                val o = fsMknode(a.fs, a.cfh, n,
                                                 mkExclFile(384, x.verf, 0))
                                base.with("file", o.ino).with("fs2", o.fs2)
                                    .with("cinfo", o.cinfo)
                            }
                    }
                }
            }
        }
    }

    pure def opOpen(a: Acc, ar: { client: ClientId, owner: int, oseq: int,
                                  claim: OpenClaim, how: OpenHow,
                                  access: int, deny: int }): Acc = {
        val zero = { before: 0, after: 0 }
        val nores = { st: OK, sid: -1, seq: 0, needConfirm: false,
                      cinfo: zero, deleg: DNone, recalls: Set() }
        val g = fhGate(a)
        // 4.0: the owner-seqid gate runs first and BAD_SEQID does not
        // consume a seqid (RFC 7530 9.1.7/9.1.9).
        if (a.minor == 0 and
            (not(a.sdb.clients.keys().contains(ar.client)) or
             not(a.sdb.clients.get(ar.client).confirmed)))
            emit(a, SOpen(nores.with("st", E_STALE_CLIENTID)))
        else if (a.minor == 0 and
                 not(ooGateOk(a.sdb, ar.client, ar.owner, ar.oseq)))
            emit(a, SOpen(nores.with("st", E_BAD_SEQID)))
        else if (g != OK) {
            val a1 = emit(a, SOpen(nores.with("st", g)))
            if (a.minor == 0)
                a1.with("sdb", ooSettle(a1.sdb, ar.client, ar.owner, ar.oseq,
                                        g, false))
            else a1
        }
        else if (ar.access < 1 or ar.access > 3 or ar.deny < 0 or ar.deny > 3) {
            val a1 = emit(a, SOpen(nores.with("st", E_INVAL)))
            if (a.minor == 0)
                a1.with("sdb", ooSettle(a1.sdb, ar.client, ar.owner, ar.oseq,
                                        E_INVAL, false))
            else a1
        }
        else if (a.minor >= 1 and a.seqClient != -1 and
                 a.sdb.clients.keys().contains(a.seqClient) and
                 not(a.sdb.clients.get(a.seqClient).reclaimDone))
            // RFC 8881 18.51.3: a non-reclaim lock-obtaining operation
            // before the client's global RECLAIM_COMPLETE fails
            // NFS4ERR_GRACE.  (The gate precedes name resolution, so an
            // OPEN of a missing name is GRACE, not NOENT.)  LOCK needs no
            // twin gate: lock state requires an open stateid, which this
            // gate already forces behind RECLAIM_COMPLETE.
            emit(a, SOpen(nores.with("st", E_GRACE)))
        // CLAIM_NULL names a component, so it runs the same validator every
        // other name-taking op does.  It sits *after* the grace gate on
        // purpose: chimera checks grace in chimera_nfs4_open() (the entry
        // point) and validates the name later, in
        // chimera_nfs4_open_parent_complete() -- so inside the grace window
        // the answer is GRACE even for a malformed name.
        //
        // The status consumes the 4.0 open-owner seqid: NFS4ERR_INVAL,
        // BADNAME, BADCHAR and NAMETOOLONG are none of them in RFC 7530
        // §9.1.7's no-consume list (see consumesSeqid), and chimera reaches
        // this through chimera_nfs4_open_complete(), which advances the
        // owner seqid via nfs4_seqid_should_advance().  So settle the owner
        // exactly as the other consuming error arms above do.
        else if (claimNameStatus(ar.claim) != OK) {
            val st = claimNameStatus(ar.claim)
            val a1 = emit(a, SOpen(nores.with("st", st)))
            if (a.minor == 0)
                a1.with("sdb", ooSettle(a1.sdb, ar.client, ar.owner, ar.oseq,
                                        st, false))
            else a1
        }
        else {
            val res = openResolve(a, ar.claim, ar.how)
            if (res.st != OK) {
                val a1 = emit(a, SOpen(nores.with("st", res.st)))
                if (a.minor == 0)
                    a1.with("sdb", ooSettle(a1.sdb, ar.client, ar.owner,
                                            ar.oseq, res.st, false))
                else a1
            } else {
                // Delegations held by other clients force a recall before
                // the OPEN can proceed; the conflicting OPEN observes
                // NFS4ERR_DELAY (discretion: conflictDelays profile).
                val recalls = openRecallSet(a.sdb, ar.client, res.file,
                                            ar.access, ar.deny,
                                            res.truncated)
                if (recalls.size() > 0) {
                    val sdb1 = recalls.fold(a.sdb, (acc, s) =>
                        doRecallDeleg(acc, s))
                    val sdb2 = if (a.minor == 0)
                                   ooSettle(sdb1, ar.client, ar.owner,
                                            ar.oseq, E_DELAY, false)
                               else sdb1
                    emit(a.with("sdb", sdb2),
                         SOpen(nores.with("st", E_DELAY)
                                    .with("recalls", recalls)))
                }
                else if (shareConflict(a.sdb, ar.client, ar.owner, res.file,
                                       ar.access, ar.deny)) {
                    val sdb2 = if (a.minor == 0)
                                   ooSettle(a.sdb, ar.client, ar.owner,
                                            ar.oseq, E_SHARE_DENIED, false)
                               else a.sdb
                    // Note: the resolve step may have created/truncated
                    // the file before the share check; the RFCs do not
                    // order creation vs share conflict.  The model checks
                    // shares first against the pre-existing state and
                    // discards the create on conflict, matching the
                    // no-side-effects reading.
                    emit(a.with("sdb", sdb2),
                         SOpen(nores.with("st", E_SHARE_DENIED)))
                }
                else {
                    val needConf = a.minor == 0 and
                        not(ooConfirmed(a.sdb, ar.client, ar.owner))
                    val o = doOpen(a.sdb, ar.client, ar.owner, res.file,
                                   ar.access, ar.deny, needConf)
                    val dg = delegGrant(a.with("sdb", o.sdb2), ar.client,
                                        res.file, ar.access, ar.deny,
                                        needConf)
                    val withDeleg =
                        if (dg == 0)
                            { sdb2: o.sdb2, deleg: DNone }
                        else {
                            val d = doGrantDeleg(o.sdb2, ar.client, res.file,
                                                 dg == 2)
                            { sdb2: d.sdb2,
                              deleg: if (dg == 2) DWrite({ sid: d.sid })
                                     else DRead({ sid: d.sid }) }
                        }
                    val sdbF = if (a.minor == 0)
                                   ooSettle(withDeleg.sdb2, ar.client,
                                            ar.owner, ar.oseq, OK, false)
                               else withDeleg.sdb2
                    emit(a.with("fs", res.fs2).with("sdb", sdbF)
                          .with("cfh", res.file),
                         SOpen({ st: OK, sid: o.sid, seq: o.seq,
                                 needConfirm: o.needConfirm,
                                 cinfo: res.cinfo,
                                 deleg: withDeleg.deleg,
                                 recalls: Set() }))
                }
            }
        }
    }

    // OPEN_CONFIRM (RFC 7530 16.18, 4.0 only): owner seqid must be the
    // OPEN's seqid + 1; on success the owner is confirmed and the stateid
    // seqid advances (acceptance: a server returning seqid 1 here is also
    // conformant -- UNSPECIFIED, R-OPEN-502).
    pure def opOpenConfirm(a: Acc, ar: { sid: Sid, oseq: int }): Acc =
        if (a.minor != 0) emit(a, SOpenConfirm({ st: E_NOTSUPP, seq: 0 }))
        else {
            val g = fhGate(a)
            if (g != OK) emit(a, SOpenConfirm({ st: g, seq: 0 }))
            else if (not(sidLive(a.sdb, ar.sid, KOpen)))
                emit(a, SOpenConfirm({ st: E_BAD_STATEID, seq: 0 }))
            else {
                val o = a.sdb.opens.get(ar.sid)
                if (o.file != a.cfh)
                    emit(a, SOpenConfirm({ st: E_BAD_STATEID, seq: 0 }))
                else if (not(o.needConfirm))
                    emit(a, SOpenConfirm({ st: E_BAD_STATEID, seq: 0 }))
                else if (not(ooGateOk(a.sdb, o.client, o.owner, ar.oseq)))
                    // Wrong seqid on OPEN_CONFIRM: the server releases the
                    // state of the original OPEN (RFC 7530 16.18.5).
                    emit(a.with("sdb", doClose(a.sdb, ar.sid)),
                         SOpenConfirm({ st: E_BAD_SEQID, seq: 0 }))
                else {
                    val r = doOpenConfirm(a.sdb, ar.sid)
                    val sdb2 = ooSettle(r.sdb2, o.client, o.owner, ar.oseq,
                                        OK, true)
                    emit(a.with("sdb", sdb2),
                         SOpenConfirm({ st: OK, seq: r.seq }))
                }
            }
        }

    pure def opOpenDowngrade(a: Acc, ar: { sid: Sid, argSeq: int, access: int,
                                           deny: int, oseq: int }): Acc = {
        val g = fhGate(a)
        if (g != OK) emit(a, SOpenDowngrade({ st: g, seq: 0 }))
        else if (not(sidLive(a.sdb, ar.sid, KOpen)))
            emit(a, SOpenDowngrade({ st: E_BAD_STATEID, seq: 0 }))
        else {
            val o = a.sdb.opens.get(ar.sid)
            if (a.minor == 0 and not(ooGateOk(a.sdb, o.client, o.owner, ar.oseq)))
                emit(a, SOpenDowngrade({ st: E_BAD_SEQID, seq: 0 }))
            else if (o.needConfirm)
                emit(a, SOpenDowngrade({ st: E_BAD_STATEID, seq: 0 }))
            else if (o.file != a.cfh)
                emit(a, SOpenDowngrade({ st: E_BAD_STATEID, seq: 0 }))
            else {
                val chk = checkSid(a.sdb, ar.sid, KOpen, ar.argSeq)
                val st0 = match chk {
                    | SidOk => OK
                    | SidOld => E_OLD_STATEID
                    | SidBad => E_BAD_STATEID
                }
                if (st0 != OK) {
                    val a1 = emit(a, SOpenDowngrade({ st: st0, seq: 0 }))
                    if (a.minor == 0)
                        a1.with("sdb", ooSettle(a1.sdb, o.client, o.owner,
                                                ar.oseq, st0, false))
                    else a1
                } else {
                    val r = doOpenDowngrade(a.sdb, ar.sid, ar.access, ar.deny)
                    val st = if (r.ok) OK else E_INVAL
                    val sdb2 = if (a.minor == 0)
                                   ooSettle(r.sdb2, o.client, o.owner,
                                            ar.oseq, st, false)
                               else r.sdb2
                    emit(a.with("sdb", sdb2),
                         SOpenDowngrade({ st: st, seq: if (r.ok) r.seq else 0 }))
                }
            }
        }
    }

    pure def opClose(a: Acc, ar: { sid: Sid, argSeq: int, oseq: int }): Acc = {
        val g = fhGate(a)
        if (g != OK) emit(a, SClose({ st: g }))
        else if (not(sidLive(a.sdb, ar.sid, KOpen)))
            emit(a, SClose({ st: E_BAD_STATEID }))
        else {
            val o = a.sdb.opens.get(ar.sid)
            if (a.minor == 0 and not(ooGateOk(a.sdb, o.client, o.owner, ar.oseq)))
                emit(a, SClose({ st: E_BAD_SEQID }))
            else if (o.needConfirm)
                // CLOSE of an unconfirmed open (RFC 7530 16.18.5).
                emit(a, SClose({ st: E_BAD_STATEID }))
            else if (o.file != a.cfh)
                emit(a, SClose({ st: E_BAD_STATEID }))
            else {
                val chk = checkSid(a.sdb, ar.sid, KOpen, ar.argSeq)
                val st0 = match chk {
                    | SidOk => OK
                    | SidOld => E_OLD_STATEID
                    | SidBad => E_BAD_STATEID
                }
                if (st0 != OK) {
                    val a1 = emit(a, SClose({ st: st0 }))
                    if (a.minor == 0)
                        a1.with("sdb", ooSettle(a1.sdb, o.client, o.owner,
                                                ar.oseq, st0, false))
                    else a1
                } else {
                    val lockSids = locksUnderOpen(a.sdb, ar.sid)
                    val locked = lockSids.exists(s =>
                        a.sdb.locks.get(s).bytes.keys().size() > 0)
                    if (locked and not(a.caps.closeFreesLocks)) {
                        val a1 = emit(a, SClose({ st: E_LOCKS_HELD }))
                        if (a.minor == 0)
                            a1.with("sdb", ooSettle(a1.sdb, o.client, o.owner,
                                                    ar.oseq, E_LOCKS_HELD,
                                                    false))
                        else a1
                    } else {
                        val sdb1 = doClose(a.sdb, ar.sid)
                        val sdb2 = if (a.minor == 0)
                                       ooSettle(sdb1, o.client, o.owner,
                                                ar.oseq, OK, false)
                                   else sdb1
                        // Last CLOSE of an unlinked-while-open file reaps
                        // the orphaned inode.
                        emit(a.with("sdb", sdb2)
                              .with("fs", maybeReap(a.fs, sdb2, o.file)),
                             SClose({ st: OK }))
                    }
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // Data ops
    // ------------------------------------------------------------------

    // Type gate shared by READ/WRITE-class ops: directory -> ISDIR;
    // symlink -> SYMLINK (acceptance: INVAL also conformant in 4.0, the
    // op text vs Table 7 disagree, R-CORE-91); other non-regular ->
    // 4.0 INVAL / 4.1+ WRONG_TYPE.
    pure def dataTypeGate(a: Acc): int = {
        val t = cfhNode(a).ftype
        if (t == FReg) OK
        else if (t == FDir) E_ISDIR
        else if (t == FLnk) E_SYMLINK
        else if (a.minor == 0) E_INVAL
        else E_WRONG_TYPE
    }

    pure def opRead(a: Acc, ar: { sel: SidSel, off: int, len: int }): Acc = {
        val nores = { st: OK, count: 0, eof: false, blocks: [] }
        val g = fhGate(a)
        if (g != OK) emit(a, SRead(nores.with("st", g)))
        else {
            val tg = dataTypeGate(a)
            if (tg != OK) emit(a, SRead(nores.with("st", tg)))
            else {
                val io = resolveSel(a, ar.sel)
                match io {
                    | IoError(e) => emit(a, SRead(nores.with("st", e)))
                    | IoAnon =>
                        // Anonymous I/O against an existing deny-read open
                        // fails NFS4ERR_LOCKED (RFC 7530 9.1.4.3).
                        if (anyDeny(a.sdb, a.cfh, 1))
                            emit(a, SRead(nores.with("st", E_LOCKED)))
                        else {
                            val r = fsReadData(cfhNode(a), ar.off, ar.len)
                            emit(a, SRead({ st: OK, count: r.count,
                                            eof: r.eof, blocks: r.syms }))
                        }
                    | IoBypass =>
                        // READ-bypass: the server MAY bypass share checks
                        // (RFC 8881 8.2.3).  discretion: modeled as NOT
                        // bypassing -- the reference implementation's unified
                        // VFS share
                        // enforcement applies to every accessor, so the
                        // bypass stateid behaves like the anonymous one.
                        if (anyDeny(a.sdb, a.cfh, 1))
                            emit(a, SRead(nores.with("st", E_LOCKED)))
                        else {
                            val r = fsReadData(cfhNode(a), ar.off, ar.len)
                            emit(a, SRead({ st: OK, count: r.count,
                                            eof: r.eof, blocks: r.syms }))
                        }
                    | IoState(s) =>
                        // discretion: READ via a write-only open is a MAY
                        // (RFC 8881 9.1.2); the model predicts OPENMODE
                        // and the generator avoids the case.
                        if (not(bitsOverlap(ioMode(a, io), 1)))
                            emit(a, SRead(nores.with("st", E_OPENMODE)))
                        else {
                            val r = fsReadData(cfhNode(a), ar.off, ar.len)
                            emit(a, SRead({ st: OK, count: r.count,
                                            eof: r.eof, blocks: r.syms }))
                        }
                }
            }
        }
    }

    pure def opWrite(a: Acc, ar: { sel: SidSel, off: int, len: int,
                                   pat: int, stable: int }): Acc = {
        val nores = { st: OK, count: 0, newSizeBlocks: 0 }
        val g = fhGate(a)
        if (g != OK) emit(a, SWrite(nores.with("st", g)))
        else {
            val tg = dataTypeGate(a)
            if (tg != OK) emit(a, SWrite(nores.with("st", tg)))
            else {
                val io = resolveSel(a, ar.sel)
                match io {
                    | IoError(e) => emit(a, SWrite(nores.with("st", e)))
                    | IoAnon =>
                        if (anyDeny(a.sdb, a.cfh, 2))
                            emit(a, SWrite(nores.with("st", E_LOCKED)))
                        else {
                            val w = fsWrite(a.fs, a.cfh, ar.off, ar.len, ar.pat)
                            emit(a.with("fs", w.fs2),
                                 SWrite({ st: OK, count: ar.len,
                                          newSizeBlocks: w.newSizeBlocks }))
                        }
                    | IoBypass =>
                        // All-ones stateid in WRITE is treated as
                        // anonymous (RFC 8881 8.2.3).
                        if (anyDeny(a.sdb, a.cfh, 2))
                            emit(a, SWrite(nores.with("st", E_LOCKED)))
                        else {
                            val w = fsWrite(a.fs, a.cfh, ar.off, ar.len, ar.pat)
                            emit(a.with("fs", w.fs2),
                                 SWrite({ st: OK, count: ar.len,
                                          newSizeBlocks: w.newSizeBlocks }))
                        }
                    | IoState(s) =>
                        // WRITE through a stateid lacking WRITE access is
                        // NFS4ERR_OPENMODE (MUST, RFC 8881 9.1.2).
                        if (not(bitsOverlap(ioMode(a, io), 2)))
                            emit(a, SWrite(nores.with("st", E_OPENMODE)))
                        else {
                            val w = fsWrite(a.fs, a.cfh, ar.off, ar.len, ar.pat)
                            emit(a.with("fs", w.fs2),
                                 SWrite({ st: OK, count: ar.len,
                                          newSizeBlocks: w.newSizeBlocks }))
                        }
                }
            }
        }
    }

    // COMMIT (RFC 7530 16.3 / RFC 8881 18.3): takes no stateid; flushing
    // nothing is not an error.  The harness checks the write verifier is
    // stable across the run (R-CORE-95).
    pure def opCommit(a: Acc): Acc = {
        val g = fhGate(a)
        if (g != OK) emit(a, SCommit({ st: g }))
        else {
            val tg = dataTypeGate(a)
            if (tg != OK) emit(a, SCommit({ st: tg }))
            else emit(a, SCommit({ st: OK }))
        }
    }

    // ------------------------------------------------------------------
    // Byte-range locks
    // ------------------------------------------------------------------

    pure def opLock(a: Acc, ar: { wr: bool, lo: int, hi: int, newOwner: bool,
                                  openSid: Sid, lockSid: Sid, lockOwner: int,
                                  oseq: int, lseq: int }): Acc = {
        val nores = { st: OK, sid: -1, seq: 0, deniedOwner: -1 }
        val g = fhGate(a)
        if (g != OK) emit(a, SLock(nores.with("st", g)))
        else if (ar.lo >= ar.hi)
            // Zero-length lock -> NFS4ERR_INVAL (RFC 7530 16.10.4 /
            // RFC 8881 18.10.3).
            emit(a, SLock(nores.with("st", E_INVAL)))
        else if (ar.newOwner) {
            // open_to_lock_owner4 arm: the open stateid anchors the new
            // lock state.
            if (not(sidLive(a.sdb, ar.openSid, KOpen)))
                emit(a, SLock(nores.with("st", E_BAD_STATEID)))
            else {
                val o = a.sdb.opens.get(ar.openSid)
                if (o.file != a.cfh or o.needConfirm)
                    emit(a, SLock(nores.with("st", E_BAD_STATEID)))
                else if (a.minor == 0 and
                         not(ooGateOk(a.sdb, o.client, o.owner, ar.oseq)))
                    emit(a, SLock(nores.with("st", E_BAD_SEQID)))
                else if (a.minor == 0 and
                         lockHeldByOwner(a.sdb, o.client, ar.lockOwner, o.file))
                    // 4.0: new_lock_owner=TRUE while this lock-owner still
                    // *holds* byte-range locks on the file is BAD_SEQID (RFC
                    // 7530 16.10.5); a fully-LOCKU'd stateid may be
                    // re-established, and 4.1 reuses the state (falls through
                    // to the merge in doLock).
                    emit(a, SLock(nores.with("st", E_BAD_SEQID)))
                else if (lockConflict(a.sdb, o.client, ar.lockOwner, o.file,
                                      ar.lo, ar.hi, ar.wr)) {
                    val who = lockConflictOwner(a.sdb, o.client, ar.lockOwner,
                                                o.file, ar.lo, ar.hi, ar.wr)
                    val a1 = emit(a, SLock(nores.with("st", E_DENIED)
                                                .with("deniedOwner", who)))
                    if (a.minor == 0)
                        a1.with("sdb", ooSettle(a1.sdb, o.client, o.owner,
                                                ar.oseq, E_DENIED, false))
                    else a1
                } else {
                    val r = doLock(a.sdb, o.client, ar.lockOwner, o.file,
                                   ar.openSid, ar.lo, ar.hi, ar.wr)
                    val sdb2 = if (a.minor == 0)
                                   loSettle(ooSettle(r.sdb2, o.client, o.owner,
                                                     ar.oseq, OK, false),
                                            o.client, ar.lockOwner, ar.lseq, OK)
                               else r.sdb2
                    emit(a.with("sdb", sdb2),
                         SLock(nores.with("sid", r.sid).with("seq", r.seq)))
                }
            }
        } else {
            // exist_lock_owner4 arm: the lock stateid itself.
            if (not(sidLive(a.sdb, ar.lockSid, KLock)))
                emit(a, SLock(nores.with("st", E_BAD_STATEID)))
            else {
                val l = a.sdb.locks.get(ar.lockSid)
                if (l.file != a.cfh)
                    emit(a, SLock(nores.with("st", E_BAD_STATEID)))
                else if (a.minor == 0 and
                         not(loGateOk(a.sdb, l.client, l.owner, ar.lseq)))
                    emit(a, SLock(nores.with("st", E_BAD_SEQID)))
                else if (lockConflict(a.sdb, l.client, l.owner, l.file,
                                      ar.lo, ar.hi, ar.wr)) {
                    val who = lockConflictOwner(a.sdb, l.client, l.owner,
                                                l.file, ar.lo, ar.hi, ar.wr)
                    val a1 = emit(a, SLock(nores.with("st", E_DENIED)
                                                .with("deniedOwner", who)))
                    if (a.minor == 0)
                        a1.with("sdb", loSettle(a1.sdb, l.client, l.owner,
                                                ar.lseq, E_DENIED))
                    else a1
                } else {
                    val r = doLock(a.sdb, l.client, l.owner, l.file,
                                   l.openSid, ar.lo, ar.hi, ar.wr)
                    val sdb2 = if (a.minor == 0)
                                   loSettle(r.sdb2, l.client, l.owner,
                                            ar.lseq, OK)
                               else r.sdb2
                    emit(a.with("sdb", sdb2),
                         SLock(nores.with("sid", r.sid).with("seq", r.seq)))
                }
            }
        }
    }

    // LOCKT (RFC 7530 16.11 / RFC 8881 18.11): stateless test by
    // lock-owner; the requester's own locks do not conflict (SHOULD).
    pure def opLockt(a: Acc, ar: { client: ClientId, lockOwner: int,
                                   wr: bool, lo: int, hi: int }): Acc = {
        val g = fhGate(a)
        if (g != OK) emit(a, SLockt({ st: g, deniedOwner: -1 }))
        else if (ar.lo >= ar.hi)
            emit(a, SLockt({ st: E_INVAL, deniedOwner: -1 }))
        else {
            // Byte-range locking is defined for regular files only, so the
            // same type gate READ/WRITE/COMMIT use applies (RFC 7530 16.11 /
            // RFC 8881 18.11).  The zero-length check precedes it, matching
            // chimera (nfs4_proc_lockt.c puts the length check in the open
            // callback and the type check in the getattr probe); the RFCs do
            // not order the two.  opLock needs no twin gate: its target is
            // reached only through an open stateid, and openResolve admits
            // regular files only.
            val tg = dataTypeGate(a)
            if (tg != OK) emit(a, SLockt({ st: tg, deniedOwner: -1 }))
            else if (lockConflict(a.sdb, ar.client, ar.lockOwner, a.cfh,
                                  ar.lo, ar.hi, ar.wr)) {
                val who = lockConflictOwner(a.sdb, ar.client, ar.lockOwner,
                                            a.cfh, ar.lo, ar.hi, ar.wr)
                emit(a, SLockt({ st: E_DENIED, deniedOwner: who }))
            }
            else emit(a, SLockt({ st: OK, deniedOwner: -1 }))
        }
    }

    // LOCKU (RFC 7530 16.12 / RFC 8881 18.12): unlocking a never-locked
    // range succeeds; partial unlocks split (per-byte model).  The seqid
    // bump on a no-op unlock is a MAY; the model always bumps.
    //
    // LOCKU is a lock-owner-sequenced op (RFC 7530 9.1.7): 4.0 requires the
    // request `lseq` to be the lock-owner's last + 1 (a stateid seqid of 0 is
    // the wildcard for the *stateid*, `argSeq`, not for the owner sequence).
    // The gate precedes the stateid-seqid check (matching the reference
    // implementation's order);
    // only a successful unlock advances the owner seqid.
    pure def opLocku(a: Acc, ar: { sid: Sid, argSeq: int, lseq: int,
                                   lo: int, hi: int }): Acc = {
        val g = fhGate(a)
        if (g != OK) emit(a, SLocku({ st: g, seq: 0 }))
        else if (ar.lo >= ar.hi)
            emit(a, SLocku({ st: E_INVAL, seq: 0 }))
        else if (not(sidLive(a.sdb, ar.sid, KLock)))
            emit(a, SLocku({ st: E_BAD_STATEID, seq: 0 }))
        else {
            val l = a.sdb.locks.get(ar.sid)
            if (l.file != a.cfh)
                emit(a, SLocku({ st: E_BAD_STATEID, seq: 0 }))
            else if (a.minor == 0 and
                     not(loGateOk(a.sdb, l.client, l.owner, ar.lseq)))
                emit(a, SLocku({ st: E_BAD_SEQID, seq: 0 }))
            else {
                val chk = checkSid(a.sdb, ar.sid, KLock, ar.argSeq)
                match chk {
                    | SidOld => emit(a, SLocku({ st: E_OLD_STATEID, seq: 0 }))
                    | SidBad => emit(a, SLocku({ st: E_BAD_STATEID, seq: 0 }))
                    | SidOk => {
                        val r = doLocku(a.sdb, ar.sid, ar.lo, ar.hi)
                        val sdb2 = if (a.minor == 0)
                                       loSettle(r.sdb2, l.client, l.owner,
                                                ar.lseq, OK)
                                   else r.sdb2
                        emit(a.with("sdb", sdb2),
                             SLocku({ st: OK, seq: r.seq }))
                    }
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // Delegations
    // ------------------------------------------------------------------

    pure def opDelegreturn(a: Acc, r: SidRef): Acc = {
        val g = fhGate(a)
        if (g != OK) emit(a, SDelegreturn({ st: g }))
        else if (r.kind != KDeleg or not(sidLive(a.sdb, r.sid, KDeleg)))
            emit(a, SDelegreturn({ st: E_BAD_STATEID }))
        else if (a.sdb.delegs.get(r.sid).file != a.cfh)
            emit(a, SDelegreturn({ st: E_BAD_STATEID }))
        else {
            val f = a.sdb.delegs.get(r.sid).file
            val sdb2 = doDelegReturn(a.sdb, r.sid)
            emit(a.with("sdb", sdb2).with("fs", maybeReap(a.fs, sdb2, f)),
                 SDelegreturn({ st: OK }))
        }
    }

    // ------------------------------------------------------------------
    // pNFS (all ops NFS4ERR_NOTSUPP when the MDS role is not advertised,
    // RFC 8881 13.1)
    // ------------------------------------------------------------------

    pure def opLayoutget(a: Acc, ar: { rw: bool, lo: int, hi: int,
                                       sel: SidSel }): Acc = {
        val nores = { st: OK, sid: -1, seq: 0, lo: 0, hi: 0 }
        if (a.minor < 1) emit(a, SLayoutget(nores.with("st", E_OP_ILLEGAL)))
        else if (not(a.caps.pnfs)) emit(a, SLayoutget(nores.with("st", E_NOTSUPP)))
        else {
            val g = fhGate(a)
            if (g != OK) emit(a, SLayoutget(nores.with("st", g)))
            else if (cfhNode(a).ftype != FReg)
                emit(a, SLayoutget(nores.with("st", E_WRONG_TYPE)))
            else {
                val io = resolveSel(a, ar.sel)
                match io {
                    | IoError(e) => emit(a, SLayoutget(nores.with("st", e)))
                    | IoAnon => emit(a, SLayoutget(nores.with("st", E_BAD_STATEID)))
                    | IoBypass => emit(a, SLayoutget(nores.with("st", E_BAD_STATEID)))
                    | IoState(s) => {
                        val cid = match s.kind {
                            | KOpen => a.sdb.opens.get(s.sid).client
                            | KLock => a.sdb.locks.get(s.sid).client
                            | KDeleg => a.sdb.delegs.get(s.sid).client
                            | KLayout => a.sdb.layouts.get(s.sid).client
                        }
                        // The model grants exactly the requested range
                        // (a server MUST cover the requested range and MAY
                        // widen, RFC 8881 18.43.3 Table 22; the harness
                        // checks coverage, not equality).
                        val r = doLayoutGet(a.sdb, cid, a.cfh, ar.lo, ar.hi,
                                            ar.rw)
                        emit(a.with("sdb", r.sdb2),
                             SLayoutget({ st: OK, sid: r.sid, seq: r.seq,
                                          lo: ar.lo, hi: ar.hi }))
                    }
                }
            }
        }
    }

    pure def opLayoutreturn(a: Acc, ar: { sid: Sid, argSeq: int, lo: int,
                                          hi: int }): Acc = {
        val nores = { st: OK, present: false, seq: 0 }
        if (a.minor < 1) emit(a, SLayoutreturn(nores.with("st", E_OP_ILLEGAL)))
        else if (not(a.caps.pnfs)) emit(a, SLayoutreturn(nores.with("st", E_NOTSUPP)))
        else {
            val g = fhGate(a)
            if (g != OK) emit(a, SLayoutreturn(nores.with("st", g)))
            else if (ar.argSeq == 0)
                // RFC 8881 18.44.3: a LAYOUTRETURN4_FILE stateid's seqid
                // MUST NOT be zero.  This is the one place a zero seqid is
                // NOT the "current stateid" wildcard checkSid otherwise
                // models, so the check has to come before it.
                emit(a, SLayoutreturn(nores.with("st", E_BAD_STATEID)))
            else if (not(sidLive(a.sdb, ar.sid, KLayout)))
                emit(a, SLayoutreturn(nores.with("st", E_BAD_STATEID)))
            else {
                val chk = checkSid(a.sdb, ar.sid, KLayout, ar.argSeq)
                match chk {
                    | SidOld => emit(a, SLayoutreturn(nores.with("st", E_OLD_STATEID)))
                    | SidBad => emit(a, SLayoutreturn(nores.with("st", E_BAD_STATEID)))
                    | SidOk => {
                        // Returning an unheld range is success, not an
                        // error (RFC 8881 18.44.3).
                        val f = a.sdb.layouts.get(ar.sid).file
                        val r = doLayoutReturn(a.sdb, ar.sid, ar.lo, ar.hi,
                                               a.caps.layoutWholeFile)
                        emit(a.with("sdb", r.sdb2)
                              .with("fs", maybeReap(a.fs, r.sdb2, f)),
                             SLayoutreturn({ st: OK, present: r.remains,
                                             seq: r.seq }))
                    }
                }
            }
        }
    }

    // LAYOUTCOMMIT (RFC 8881 18.42): requires a held RW layout overlapping
    // the committed range (else NFS4ERR_BADLAYOUT); makes DS writes and
    // the new size visible at the MDS.  The model treats WRITEs as
    // MDS-visible already (single-node server), so only the size result
    // is interesting.
    pure def opLayoutcommit(a: Acc, ar: { sid: Sid, lo: int, hi: int }): Acc = {
        val nores = { st: OK, newSizeBlocks: 0 }
        if (a.minor < 1) emit(a, SLayoutcommit(nores.with("st", E_OP_ILLEGAL)))
        else if (not(a.caps.pnfs)) emit(a, SLayoutcommit(nores.with("st", E_NOTSUPP)))
        else {
            val g = fhGate(a)
            if (g != OK) emit(a, SLayoutcommit(nores.with("st", g)))
            else if (not(sidLive(a.sdb, ar.sid, KLayout)))
                emit(a, SLayoutcommit(nores.with("st", E_BAD_STATEID)))
            else {
                val l = a.sdb.layouts.get(ar.sid)
                // A server holding one whole-file layout has no per-range
                // accounting to consult (caps.layoutWholeFile): the layout
                // either covers writes or it does not, and lo/hi say nothing.
                val overlapRw = if (a.caps.layoutWholeFile)
                                    l.blocks.keys().exists(b => l.blocks.get(b))
                                else
                                    range(ar.lo, ar.hi).foldl(false, (acc, b) =>
                                        acc or (l.blocks.keys().contains(b)
                                                and l.blocks.get(b)))
                // loca_last_write_offset is how far the client wrote through
                // the layout, not a truncate: it extends the file and never
                // shrinks it (RFC 8881 18.42.3).  The harness reports the last
                // byte of [lo, hi), so the commit's high-water mark is hi.
                val newSize = imax(fsGet(a.fs, l.file).sizeBlocks, ar.hi)
                if (l.file != a.cfh)
                    emit(a, SLayoutcommit(nores.with("st", E_BAD_STATEID)))
                else if (not(overlapRw))
                    emit(a, SLayoutcommit(nores.with("st", E_BADLAYOUT)))
                else
                    emit(a.with("fs", fsResize(a.fs, l.file, newSize)),
                         SLayoutcommit({ st: OK, newSizeBlocks: newSize }))
            }
        }
    }

    pure def opGetdeviceinfo(a: Acc): Acc =
        if (a.minor < 1) emit(a, SGetdeviceinfo({ st: E_OP_ILLEGAL }))
        else if (not(a.caps.pnfs)) emit(a, SGetdeviceinfo({ st: E_NOTSUPP }))
        else emit(a, SGetdeviceinfo({ st: OK }))

    // ------------------------------------------------------------------
    // NFSv4.2 ops (each individually optional; NFS4ERR_NOTSUPP when the
    // capability profile says unsupported, RFC 7862 13)
    // ------------------------------------------------------------------

    // Common stateid+type gate for the 4.2 I/O-class ops; needWrite
    // selects the access-mode check.
    pure def io42Gate(a: Acc, sel: SidSel, needWrite: bool): int = {
        val g = fhGate(a)
        if (g != OK) g
        else {
            val tg = dataTypeGate(a)
            if (tg != OK) tg
            else {
                val io = resolveSel(a, sel)
                match io {
                    | IoError(e) => e
                    | IoAnon =>
                        if (anyDeny(a.sdb, a.cfh, if (needWrite) 2 else 1))
                            E_LOCKED
                        else OK
                    | IoBypass => OK
                    | IoState(s) =>
                        if (not(bitsOverlap(ioMode(a, io),
                                            if (needWrite) 2 else 1)))
                            E_OPENMODE
                        else OK
                }
            }
        }
    }

    // CLONE resolves both stateids through the state table, which does not
    // accept the special stateids (they name no concrete state).  Unlike the
    // single-filehandle I/O ops, the two stateids are validated against
    // DIFFERENT filehandles -- the source against the saved FH and the
    // destination against the current one -- so this cannot reuse resolveSel,
    // which always checks against the current FH.
    pure def cloneSidGate(a: Acc, sel: SidSel, fh: Ino): int =
        match sel {
            | SelAnon => E_BAD_STATEID
            | SelBypass => E_BAD_STATEID
            | SelRef(r) =>
                match checkSid(a.sdb, r.sid, r.kind, r.argSeq) {
                    | SidBad => E_BAD_STATEID
                    | SidOld => E_OLD_STATEID
                    | SidOk => {
                        val fOf = match r.kind {
                            | KOpen => a.sdb.opens.get(r.sid).file
                            | KLock => a.sdb.locks.get(r.sid).file
                            | KDeleg => a.sdb.delegs.get(r.sid).file
                            | KLayout => a.sdb.layouts.get(r.sid).file
                        }
                        if (fOf != fh) E_BAD_STATEID
                        else if (r.kind == KOpen and
                                 a.sdb.opens.get(r.sid).needConfirm)
                            E_BAD_STATEID
                        else OK
                    }
                }
        }

    pure def opAllocate(a: Acc, ar: { sel: SidSel, off: int, len: int }): Acc =
        if (a.minor < 2) emit(a, SAllocate({ st: E_OP_ILLEGAL }))
        else if (not(a.caps.sparse)) emit(a, SAllocate({ st: E_NOTSUPP }))
        else {
            val g = io42Gate(a, ar.sel, true)
            if (g != OK) emit(a, SAllocate({ st: g }))
            else if (ar.len <= 0) emit(a, SAllocate({ st: E_INVAL }))
            else emit(a.with("fs", fsAllocate(a.fs, a.cfh, ar.off, ar.len)),
                      SAllocate({ st: OK }))
        }

    pure def opDeallocate(a: Acc, ar: { sel: SidSel, off: int, len: int }): Acc =
        if (a.minor < 2) emit(a, SDeallocate({ st: E_OP_ILLEGAL }))
        else if (not(a.caps.sparse)) emit(a, SDeallocate({ st: E_NOTSUPP }))
        else {
            val g = io42Gate(a, ar.sel, true)
            if (g != OK) emit(a, SDeallocate({ st: g }))
            else if (ar.len <= 0) emit(a, SDeallocate({ st: E_INVAL }))
            else emit(a.with("fs", fsDeallocate(a.fs, a.cfh, ar.off, ar.len)),
                      SDeallocate({ st: OK }))
        }

    // SEEK (RFC 7862 15.11): offset at/after EOF -> NFS4ERR_NXIO, and so is a
    // data search that finds no data before EOF.
    //
    // 15.11.3 reads as though the second case were NFS4_OK with sr_eof set
    // ("if the server cannot find a corresponding sa_what, then the status
    // will still be NFS4_OK, but sr_eof would be TRUE"), and the model used to
    // say that.  Every deployed implementation disagrees: Linux's nfsd maps
    // the vfs_llseek ENXIO straight to NFS4ERR_NXIO, and nfstest_sparse
    // asserts it outright -- "SEEK should fail with NFS4ERR_NXIO using
    // SEEK_DATA when offset is in the middle of last hole".  A model that
    // contradicts the suite the servers are tested against is the wrong
    // oracle, so follow the ecosystem.
    //
    // SEEK_HOLE is unaffected: every file has a virtual hole at EOF, so a hole
    // search always finds one.  Allocated-but-unwritten blocks count as data.
    pure def opSeek(a: Acc, ar: { sel: SidSel, off: int, whatData: bool }): Acc = {
        val nores = { st: OK, eof: false, offset: 0 }
        if (a.minor < 2) emit(a, SSeek(nores.with("st", E_OP_ILLEGAL)))
        else if (not(a.caps.sparse)) emit(a, SSeek(nores.with("st", E_NOTSUPP)))
        else {
            val g = io42Gate(a, ar.sel, false)
            if (g != OK) emit(a, SSeek(nores.with("st", g)))
            else {
                val nd = cfhNode(a)
                if (ar.off >= nd.sizeBlocks)
                    emit(a, SSeek(nores.with("st", E_NXIO)))
                else {
                    val r = fsSeek(nd, ar.off, ar.whatData)
                    if (ar.whatData and not(r.found))
                        // No data between the offset and EOF.
                        emit(a, SSeek(nores.with("st", E_NXIO)))
                    else
                        emit(a, SSeek({ st: OK,
                                        eof: r.offset >= nd.sizeBlocks,
                                        offset: r.offset }))
                }
            }
        }
    }

    // Intra-server synchronous COPY (RFC 7862 15.2): sfh = source, cfh =
    // destination; same file -> NFS4ERR_INVAL (any ranges); source range
    // beyond the source size -> NFS4ERR_INVAL; cnt = 0 copies through the
    // source EOF.  The special stateids are accepted (copyTest pins this):
    // nothing in RFC 7862 15.2 excludes them, and the server derives its
    // access check from the filehandles.  NOTE: the reference implementation
    // resolves both stateids through the state table and so answers
    // NFS4ERR_BAD_STATEID for an anonymous COPY -- an open divergence, which
    // is why copyRange generates concrete open stateids only.
    pure def opCopy(a: Acc, ar: { srcSel: SidSel, dstSel: SidSel,
                                  srcOff: int, dstOff: int, cnt: int }): Acc = {
        val nores = { st: OK, copied: 0 }
        if (a.minor < 2) emit(a, SCopy(nores.with("st", E_OP_ILLEGAL)))
        else if (not(a.caps.copy)) emit(a, SCopy(nores.with("st", E_NOTSUPP)))
        else if (a.sfh == -1 or a.cfh == -1)
            emit(a, SCopy(nores.with("st", E_NOFILEHANDLE)))
        else if (not(fsLive(a.fs, a.sfh)) or not(fsLive(a.fs, a.cfh)))
            emit(a, SCopy(nores.with("st", E_STALE)))
        else if (a.sfh == a.cfh)
            emit(a, SCopy(nores.with("st", E_INVAL)))
        else {
            val src = fsGet(a.fs, a.sfh)
            val dst = fsGet(a.fs, a.cfh)
            if (src.ftype != FReg or dst.ftype != FReg)
                emit(a, SCopy(nores.with("st",
                    if (src.ftype == FDir or dst.ftype == FDir) E_ISDIR
                    else E_WRONG_TYPE)))
            else {
                val cnt = if (ar.cnt == 0) imax(0, src.sizeBlocks - ar.srcOff)
                          else ar.cnt
                if (ar.srcOff + cnt > src.sizeBlocks or
                    (ar.cnt == 0 and ar.srcOff > src.sizeBlocks))
                    emit(a, SCopy(nores.with("st", E_INVAL)))
                // COPY reads the source and writes the destination, so the
                // share reservations that gate READ and WRITE gate it too
                // (RFC 8881 9.7).  A stateid that names an open carries its
                // own grant; an anonymous or READ-bypass one does not, so a
                // deny held by any owner of any client makes it
                // NFS4ERR_LOCKED -- otherwise the anonymous stateid would be
                // a way around the reservation.  Checked after the range so
                // an out-of-range COPY still reports the argument error.
                else if (namesNoOpen(ar.srcSel) and anyDeny(a.sdb, a.sfh, 1))
                    emit(a, SCopy(nores.with("st", E_LOCKED)))
                else if (namesNoOpen(ar.dstSel) and anyDeny(a.sdb, a.cfh, 2))
                    emit(a, SCopy(nores.with("st", E_LOCKED)))
                else {
                    val data = fsReadData(src, ar.srcOff, cnt)
                    val w = range(0, cnt).foldl(a.fs, (acc, i) =>
                        fsWrite(acc, a.cfh, ar.dstOff + i, 1,
                                data.syms[i]).fs2)
                    emit(a.with("fs", w), SCopy({ st: OK, copied: cnt }))
                }
            }
        }
    }

    // IO_ADVISE validates only the filehandle and the stateid.  The
    // operation is advisory, so no file-type and no open-mode check applies
    // (RFC 7862 15.5 requires neither).
    pure def ioAdviseGate(a: Acc, sel: SidSel): int = {
        val g = fhGate(a)
        if (g != OK) g
        else match resolveSel(a, sel) {
            | IoError(e) => e
            | IoAnon => OK
            | IoBypass => OK
            | IoState(s) => OK
        }
    }

    // READ_PLUS (RFC 7862 15.10): a sparse-aware READ that reports the range
    // as DATA and HOLE segments.  Allocated-but-unwritten blocks classify as
    // DATA, the same rule SEEK uses.  The model predicts the classification
    // and contents of the WHOLE requested range; a server may legally return
    // a shorter prefix of it (rpr_contents is an array and the client
    // re-issues from the last byte returned), so the harness matches the
    // returned segments against this as a prefix rather than for equality.
    pure def opReadPlus(a: Acc, ar: { sel: SidSel, off: int, len: int }): Acc = {
        val nores = { st: OK, eof: false, count: 0, blocks: [], isData: [] }
        if (a.minor < 2) emit(a, SReadPlus(nores.with("st", E_OP_ILLEGAL)))
        else if (not(a.caps.readPlus))
            emit(a, SReadPlus(nores.with("st", E_NOTSUPP)))
        else {
            val g = io42Gate(a, ar.sel, false)
            if (g != OK) emit(a, SReadPlus(nores.with("st", g)))
            else {
                val nd = cfhNode(a)
                val r = fsReadData(nd, ar.off, ar.len)
                emit(a, SReadPlus({
                    st: OK, eof: r.eof, count: r.count, blocks: r.syms,
                    isData: range(ar.off, ar.off + r.count).foldl([],
                        (acc, i) => acc.append(match blockAt(nd, i) {
                            | BHole => false
                            | BZero => true
                            | BData(s) => true
                        })) }))
            }
        }
    }

    // IO_ADVISE (RFC 7862 15.5): purely advisory I/O hints.  A server is
    // permitted to honor none of them, so the model predicts the status only
    // and the harness checks the honored set is a subset of the requested
    // hints (the one constraint the RFC does impose).
    pure def opIoAdvise(a: Acc, ar: { sel: SidSel, off: int, len: int,
                                      hint: int }): Acc =
        if (a.minor < 2) emit(a, SIoAdvise({ st: E_OP_ILLEGAL }))
        else if (not(a.caps.ioAdvise)) emit(a, SIoAdvise({ st: E_NOTSUPP }))
        else emit(a, SIoAdvise({ st: ioAdviseGate(a, ar.sel) }))

    // WRITE_SAME (RFC 7862 15.13) expands an Application Data Block -- a
    // pattern replicated across a run of fixed-size blocks -- so the pattern
    // crosses the wire once.  Per-block-number stamping (adb_reloff_blocknum
    // != NFS4_UINT64_MAX) is the unsupported arm of the union and is rejected
    // by argument validation, ahead of every filehandle, stateid and
    // capability check.  The model pins one ADB block to one model block, so
    // `blocks` is adb_block_count and the byte count follows from it.
    pure def opWriteSame(a: Acc, ar: { sel: SidSel, off: int, blocks: int,
                                       pat: int, blocknum: bool }): Acc = {
        val nores = { st: OK, count: 0 }
        if (a.minor < 2) emit(a, SWriteSame(nores.with("st", E_OP_ILLEGAL)))
        else if (ar.blocknum)
            emit(a, SWriteSame(nores.with("st", E_UNION_NOTSUPP)))
        else if (not(a.caps.writeSame))
            emit(a, SWriteSame(nores.with("st", E_NOTSUPP)))
        else {
            val g = io42Gate(a, ar.sel, true)
            if (g != OK) emit(a, SWriteSame(nores.with("st", g)))
            else if (ar.blocks <= 0) emit(a, SWriteSame({ st: OK, count: 0 }))
            else emit(a.with("fs", fsWrite(a.fs, a.cfh, ar.off, ar.blocks,
                                           ar.pat).fs2),
                      SWriteSame({ st: OK, count: ar.blocks }))
        }
    }

    // CLONE (RFC 7862 15.4) reflinks a source range (sfh) into the
    // destination (cfh); the ranges then share storage copy-on-write, which
    // is invisible at the protocol level -- the observable effect is a COPY.
    // cl_count == 0 clones through the source EOF, and a source offset at or
    // past EOF is a no-op success.  Unlike COPY, CLONE resolves both stateids
    // as concrete open/lock state: it takes no special-stateid shortcut, so
    // an anonymous or read-bypass selector is NFS4ERR_BAD_STATEID.  Cloning
    // overlapping ranges of one file is NFS4ERR_INVAL.
    pure def opClone(a: Acc, ar: { srcSel: SidSel, dstSel: SidSel,
                                   srcOff: int, dstOff: int, cnt: int }): Acc = {
        if (a.minor < 2) emit(a, SClone({ st: E_OP_ILLEGAL }))
        else if (a.sfh == -1 or a.cfh == -1)
            emit(a, SClone({ st: E_NOFILEHANDLE }))
        else if (not(fsLive(a.fs, a.sfh)) or not(fsLive(a.fs, a.cfh)))
            emit(a, SClone({ st: E_STALE }))
        else {
            // Both stateids are resolved before the operation is judged
            // unsupported, so a bad stateid outranks NFS4ERR_NOTSUPP.
            val sg = cloneSidGate(a, ar.srcSel, a.sfh)
            val dg = cloneSidGate(a, ar.dstSel, a.cfh)
            if (sg != OK) emit(a, SClone({ st: sg }))
            else if (dg != OK) emit(a, SClone({ st: dg }))
            else if (not(a.caps.clone)) emit(a, SClone({ st: E_NOTSUPP }))
            else {
                val src = fsGet(a.fs, a.sfh)
                val dst = fsGet(a.fs, a.cfh)
                if (src.ftype != FReg or dst.ftype != FReg)
                    emit(a, SClone({ st:
                        if (src.ftype == FDir or dst.ftype == FDir) E_ISDIR
                        else E_WRONG_TYPE }))
                else {
                    val cnt = if (ar.cnt == 0)
                                  imax(0, src.sizeBlocks - ar.srcOff)
                              else ar.cnt
                    if (a.sfh == a.cfh and
                        ar.srcOff < ar.dstOff + cnt and
                        ar.dstOff < ar.srcOff + cnt)
                        emit(a, SClone({ st: E_INVAL }))
                    else if (cnt == 0)
                        // Nothing to clone (count 0 with the source offset at
                        // or past EOF): success, no state change.
                        emit(a, SClone({ st: OK }))
                    else if (ar.srcOff + cnt > src.sizeBlocks)
                        emit(a, SClone({ st: E_INVAL }))
                    else
                        // Reflink: the destination takes the source's block
                        // CONTENT, so a hole in the source stays a hole.
                        emit(a.with("fs",
                                    fsCopyBlocks(a.fs, a.sfh, ar.srcOff,
                                                 a.cfh, ar.dstOff, cnt)),
                             SClone({ st: OK }))
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // Extended attributes (RFC 8276; one per-fs gate: xattr_support)
    // ------------------------------------------------------------------

    pure def opGetxattr(a: Acc, n: Name): Acc =
        if (a.minor < 2) emit(a, SGetxattr({ st: E_OP_ILLEGAL, sym: 0 }))
        else if (not(a.caps.xattr)) emit(a, SGetxattr({ st: E_NOTSUPP, sym: 0 }))
        else {
            val g = fhGate(a)
            if (g != OK) emit(a, SGetxattr({ st: g, sym: 0 }))
            else {
                val nd = cfhNode(a)
                if (not(nd.xattrs.keys().contains(n)))
                    emit(a, SGetxattr({ st: E_NOXATTR, sym: 0 }))
                else emit(a, SGetxattr({ st: OK, sym: nd.xattrs.get(n) }))
            }
        }

    pure def opSetxattr(a: Acc, ar: { name: Name, sym: int,
                                      how: XattrSetHow }): Acc =
        if (a.minor < 2) emit(a, SSetxattr({ st: E_OP_ILLEGAL }))
        else if (not(a.caps.xattr)) emit(a, SSetxattr({ st: E_NOTSUPP }))
        else {
            val g = fhGate(a)
            if (g != OK) emit(a, SSetxattr({ st: g }))
            else {
                val how = match ar.how {
                    | XsCreate => XCreate
                    | XsReplace => XReplace
                    | XsEither => XEither
                }
                val r = fsSetXattr(a.fs, a.cfh, ar.name, ar.sym, how)
                emit(a.with("fs", r.fs2), SSetxattr({ st: fsStatus(r.st) }))
            }
        }

    pure def opListxattrs(a: Acc): Acc =
        if (a.minor < 2) emit(a, SListxattrs({ st: E_OP_ILLEGAL, names: Set() }))
        else if (not(a.caps.xattr))
            emit(a, SListxattrs({ st: E_NOTSUPP, names: Set() }))
        else {
            val g = fhGate(a)
            if (g != OK) emit(a, SListxattrs({ st: g, names: Set() }))
            else emit(a, SListxattrs({ st: OK,
                                       names: cfhNode(a).xattrs.keys() }))
        }

    pure def opRemovexattr(a: Acc, n: Name): Acc =
        if (a.minor < 2) emit(a, SRemovexattr({ st: E_OP_ILLEGAL }))
        else if (not(a.caps.xattr)) emit(a, SRemovexattr({ st: E_NOTSUPP }))
        else {
            val g = fhGate(a)
            if (g != OK) emit(a, SRemovexattr({ st: g }))
            else {
                val r = fsRemoveXattr(a.fs, a.cfh, n)
                emit(a.with("fs", r.fs2), SRemovexattr({ st: fsStatus(r.st) }))
            }
        }

    // ------------------------------------------------------------------
    // The compound evaluator
    // ------------------------------------------------------------------

    // Ops that may legally appear outside a session in 4.1+ (RFC 8881
    // 18.46.3 plus DESTROY_CLIENTID per 18.50.3 -- the RFC's two lists
    // disagree; the 18.50.3 reading is modeled).
    pure def sessionExempt(r: OpReq): bool =
        match r {
            | RExchangeId(x) => true
            | RCreateSession(x) => true
            | RDestroySession(x) => true
            | RDestroyClientid(x) => true
            | RSequence(x) => true
            // BIND_CONN_TO_SESSION is exempt by construction: its whole job is
            // to associate a connection with a session, which a client must be
            // able to do before it can issue SEQUENCE over that connection
            // (RFC 8881 18.34.3, and 18.46.3's list).  chimera agrees -- it
            // has an explicit `!req->seen_sequence` path.
            | RBindConnToSession(x) => true
            | _ => false
        }

    pure def dispatch(a: Acc, r: OpReq): Acc =
        match r {
            | RPutrootfh => opPutrootfh(a)
            | RPutfh(i) => opPutfh(a, i)
            | RGetfh => opGetfh(a)
            | RSavefh => opSavefh(a)
            | RRestorefh => opRestorefh(a)
            | RLookup(n) => opLookup(a, n)
            | RLookupp => opLookupp(a)
            | RGetattr => opGetattr(a)
            | RGetattrWide => opGetattrWide(a)
            | RSecinfo(n) => opSecinfo(a, n)
            // Same oracle as a mode-only SETATTR on purpose: the extra
            // attributes the harness sends (owner, owner_group, both settable
            // times) are ones the model does not track, so the observable
            // outcome -- status, mode, and the change-attribute bump -- is
            // identical.  Only chimera's attribute parser sees the difference.
            | RSetattrWide(m) =>
                opSetattr(a, { mode: m, sizeBlocks: -1, sel: SelAnon })
            | RVerifyWide => opVerifyWide(a)
            | RNverifyWide => opNverifyWide(a)
            | RBindConnToSession(r) => opBindConnToSession(a, r)
            | RReadlink => opReadlink(a)
            | RAccess(m) => opAccess(a, m)
            | RReaddir => opReaddir(a)
            | RCreate(ar) => opCreate(a, ar)
            | RRemove(n) => opRemove(a, n)
            | RRename(ar) => opRename(a, ar)
            | RLink(n) => opLink(a, n)
            | RSetattr(ar) => opSetattr(a, ar)
            | RVerifySize(sz) => opVerifySize(a, sz)
            | RNverifySize(sz) => opNverifySize(a, sz)
            | RSetclientid(ar) => opSetclientid(a, ar)
            | RSetclientidConfirm(ar) => opSetclientidConfirm(a, ar)
            | RRenew(c) => opRenew(a, c)
            | RReleaseLockowner(ar) => opReleaseLockowner(a, ar)
            | RExchangeId(ar) => opExchangeId(a, ar)
            | RCreateSession(ar) => opCreateSession(a, ar)
            | RSequence(ar) => opSequence(a, ar)
            | RDestroySession(s) => opDestroySession(a, s)
            | RDestroyClientid(c) => opDestroyClientid(a, c)
            | RReclaimComplete => opReclaimComplete(a)
            | RFreeStateid(sr) => opFreeStateid(a, sr)
            | ROpen(ar) => opOpen(a, ar)
            | ROpenConfirm(ar) => opOpenConfirm(a, ar)
            | ROpenDowngrade(ar) => opOpenDowngrade(a, ar)
            | RClose(ar) => opClose(a, ar)
            | RRead(ar) => opRead(a, ar)
            | RWrite(ar) => opWrite(a, ar)
            | RCommit => opCommit(a)
            | RLock(ar) => opLock(a, ar)
            | RLockt(ar) => opLockt(a, ar)
            | RLocku(ar) => opLocku(a, ar)
            | RDelegreturn(sr) => opDelegreturn(a, sr)
            | RLayoutget(ar) => opLayoutget(a, ar)
            | RLayoutreturn(ar) => opLayoutreturn(a, ar)
            | RLayoutcommit(ar) => opLayoutcommit(a, ar)
            | RGetdeviceinfo => opGetdeviceinfo(a)
            | RAllocate(ar) => opAllocate(a, ar)
            | RDeallocate(ar) => opDeallocate(a, ar)
            | RSeek(ar) => opSeek(a, ar)
            | RCopy(ar) => opCopy(a, ar)
            | RReadPlus(ar) => opReadPlus(a, ar)
            | RIoAdvise(ar) => opIoAdvise(a, ar)
            | RWriteSame(ar) => opWriteSame(a, ar)
            | RClone(ar) => opClone(a, ar)
            | RGetxattr(n) => opGetxattr(a, n)
            | RSetxattr(ar) => opSetxattr(a, ar)
            | RListxattrs => opListxattrs(a)
            | RRemovexattr(n) => opRemovexattr(a, n)
        }

    type CompoundOutcome = {
        fs2: Fs,
        sdb2: StateDB,
        status: int,
        results: List[OpRes]
    }

    pure def mkCaps(pnfs: bool, readDeleg: bool, writeDeleg: bool,
                    xattr: bool, sparse: bool, copyOk: bool): Caps =
        { pnfs: pnfs, readDeleg: readDeleg, writeDeleg: writeDeleg,
          xattr: xattr, sparse: sparse, copy: copyOk,
          readPlus: copyOk, ioAdvise: copyOk, writeSame: copyOk,
          clone: copyOk,
          conflictDelays: true, closeFreesLocks: true,
          layoutWholeFile: true }

    // Evaluate a whole COMPOUND.  reqTag identifies the request for the
    // 4.1 SEQUENCE replay/false-retry classification.
    pure def evalCompound(fs: Fs, sdb: StateDB, minor: int, caps: Caps,
                          reqTag: int, ops: List[OpReq]): CompoundOutcome = {
        val a0: Acc = {
            fs: fs, sdb: sdb, minor: minor, caps: caps,
            nOps: ops.length(), reqTag: reqTag, idx: 0,
            cfh: -1, sfh: -1, seqDone: false, seqClient: -1,
            done: false, status: OK, results: []
        }
        val aN = ops.foldl(a0, (acc, r) => {
            val acc2 =
                if (acc.done) acc
                else if (acc.minor >= 1 and acc.idx == 0 and
                         not(sessionExempt(r))) {
                    // First op of a 4.1+ compound must be SEQUENCE or a
                    // session-exempt op.
                    val res = SSequence({ st: E_OP_NOT_IN_SESSION,
                                          replay: false })
                    acc.with("results", acc.results.append(res))
                       .with("status", E_OP_NOT_IN_SESSION)
                       .with("done", true)
                }
                else dispatch(acc, r)
            acc2.with("idx", acc.idx + 1)
        })
        { fs2: aN.fs, sdb2: aN.sdb, status: aN.status, results: aN.results }
    }
}
