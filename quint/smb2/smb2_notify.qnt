// SPDX-FileCopyrightText: 2026 The Quint Specs Authors
//
// SPDX-License-Identifier: MIT

// SMB2 CHANGE_NOTIFY: the directory-watch layer (MS-SMB2 2.2.35 / 2.2.36 /
// 3.3.5.19, MS-FSA 2.1.5.9 "Server Requests a Directory Change Notification").
//
// This module is PURE and holds no protocol state of its own: it owns the
// WATCH -- what a CHANGE_NOTIFY arms on a directory handle -- and the two
// filters, the buffer arithmetic and the record shape that decide what a
// watcher is eventually told.  smb2_state.qnt keeps the watches in the
// StateDB (one per open handle, exactly as chimera hangs one notify_state off
// each chimera_smb_open_file) and smb2_ops.qnt drives them from the commands.
//
// The layer has two filters, not one, and the difference is observable:
//
//   * the ENQUEUE filter is the watch's, set by the most recent CHANGE_NOTIFY
//     on the handle.  An event whose class the watch does not carry is never
//     buffered at all, so it is not merely invisible to the current request --
//     it is gone.
//   * the DELIVERY filter is the parked (or arriving) REQUEST's
//     CompletionFilter, applied again when the ring is drained.  It matters
//     because a request may be narrower than the watch was when the events
//     were buffered: arm wide, let events accumulate, arm narrow, and the
//     wide-only events are dropped on the way out.
//
// Both are modeled because chimera implements both (smb_proc_change_notify.c
// re-filters after chimera_vfs_notify_drain, as does the async
// smb_notify.c:do_send_response) and a model with only one of them cannot
// distinguish "never buffered" from "buffered and discarded" -- which is the
// difference between a later request seeing the event and not.
//
// Classes vs filters vs actions.  Three vocabularies meet here and the
// mapping between them is lossy in both directions, which is why each is
// named separately rather than folded into one bitmask:
//
//   CompletionFilter (wire, 12 bits)  --cfToMask-->  event class (VFS)
//   event class                       --evAction-->  FILE_ACTION (wire, 5)
//
// A model that carried only FILE_ACTION could not express that a WRITE is
// delivered to a watcher asking for STREAM_WRITE but not to one asking for
// DIR_NAME, though both would see FILE_ACTION_MODIFIED.

module smb2notify {

    import nfs4fs.* from "../nfs/nfs4_fs"

    // ------------------------------------------------------------------
    // NTSTATUS values this layer owns (MS-ERREF 2.3.1)
    // ------------------------------------------------------------------

    // Warning-level, not errors: both carry the ordinary CHANGE_NOTIFY
    // response body (StructureSize 9), which is why they are statuses and not
    // a separate reply shape.
    pure val ST_NOTIFY_CLEANUP = 0x0000010B
    pure val ST_NOTIFY_ENUM_DIR = 0x0000010C

    // ------------------------------------------------------------------
    // The three vocabularies
    // ------------------------------------------------------------------

    // CompletionFilter bits (MS-SMB2 2.2.35), by name.  The harness maps each
    // name to its FILE_NOTIFY_CHANGE_* wire bit; the model never needs the
    // numeric value, and a set is what the two filter operations below
    // actually want.
    pure val CF_FILE_NAME = "fileName"
    pure val CF_DIR_NAME = "dirName"
    pure val CF_ATTRIBUTES = "attributes"
    pure val CF_SIZE = "size"
    pure val CF_LAST_WRITE = "lastWrite"
    pure val CF_LAST_ACCESS = "lastAccess"
    pure val CF_CREATION = "creation"
    pure val CF_EA = "ea"
    pure val CF_SECURITY = "security"
    pure val CF_STREAM_NAME = "streamName"
    pure val CF_STREAM_SIZE = "streamSize"
    pure val CF_STREAM_WRITE = "streamWrite"

    pure val CF_ALL = Set(CF_FILE_NAME, CF_DIR_NAME, CF_ATTRIBUTES, CF_SIZE,
                          CF_LAST_WRITE, CF_LAST_ACCESS, CF_CREATION, CF_EA,
                          CF_SECURITY, CF_STREAM_NAME, CF_STREAM_SIZE,
                          CF_STREAM_WRITE)

    // Event classes, the vocabulary the filesystem raises changes in
    // (chimera's CHIMERA_VFS_NOTIFY_* in vfs_notify.h).  One namespace
    // mutation raises a SET of these -- a create touches both the directory
    // entry and the file's default data stream -- which is what lets a single
    // event satisfy watchers holding disjoint filters.
    pure val EV_FILE_ADDED = "fileAdded"
    pure val EV_FILE_REMOVED = "fileRemoved"
    pure val EV_FILE_MODIFIED = "fileModified"
    pure val EV_DIR_ADDED = "dirAdded"
    pure val EV_DIR_REMOVED = "dirRemoved"
    // A rename is split by the TYPE of the object renamed, because the two
    // name filters are: MS-FSCC makes FILE_NOTIFY_CHANGE_FILE_NAME "any file
    // name change ... including renaming" and _DIR_NAME the same for
    // directories.  A single `renamed` class cannot say which filter should
    // see it, and admitting both -- which the model used to do -- wakes a
    // client watching directory names because a FILE was renamed.
    pure val EV_RENAMED_FILE = "renamedFile"
    pure val EV_RENAMED_DIR = "renamedDir"
    pure val EV_ATTRS = "attrs"
    pure val EV_SIZE = "size"
    pure val EV_STREAM_NAME = "streamName"
    pure val EV_STREAM_SIZE = "streamSize"
    pure val EV_STREAM_WRITE = "streamWrite"

    // FILE_ACTION_* (MS-FSCC 2.7.1), the only classification that reaches the
    // client: eleven classes collapse onto five actions, and the collapse is
    // many-to-one, so two events that differ in class can share a record.
    pure val FA_ADDED = 1
    pure val FA_REMOVED = 2
    pure val FA_MODIFIED = 3
    pure val FA_RENAMED_OLD = 4
    pure val FA_RENAMED_NEW = 5

    // ------------------------------------------------------------------
    // CompletionFilter -> event classes
    // ------------------------------------------------------------------

    // MS-FSA 2.1.5.9 gives the filter its meaning per class; this is the
    // mapping chimera implements in chimera_smb_map_completion_filter.
    //
    // Two properties of it are load-bearing and neither is obvious:
    //
    //   * a rename is admitted by the name filter matching the renamed
    //     object's TYPE, not by both.  MS-FSCC scopes
    //     FILE_NOTIFY_CHANGE_FILE_NAME to file name changes "including
    //     renaming" and _DIR_NAME to directory ones, so a client watching
    //     directory names is not woken because a file was renamed.  (The
    //     model used to admit both, which Samba caught: it delivers a file
    //     rename to a FILE_NAME watcher and nothing to a DIR_NAME one.)
    //   * SIZE admits FILE_MODIFIED and LAST_WRITE admits ATTRS.  The classes
    //     are not a partition of the filters: a plain WRITE (which raises
    //     FILE_MODIFIED) reaches a SIZE watcher, and a metadata change (ATTRS)
    //     reaches a LAST_WRITE watcher.
    pure def cfToMask(cf: Set[str]): Set[str] = {
        val nameBits =
            if (cf.contains(CF_FILE_NAME))
                Set(EV_FILE_ADDED, EV_FILE_REMOVED, EV_RENAMED_FILE)
            else Set()
        val dirBits =
            if (cf.contains(CF_DIR_NAME))
                Set(EV_DIR_ADDED, EV_DIR_REMOVED, EV_RENAMED_DIR)
            else Set()
        val sizeBits =
            if (cf.contains(CF_SIZE)) Set(EV_SIZE, EV_FILE_MODIFIED)
            else Set()
        val writeBits =
            if (cf.contains(CF_LAST_WRITE)) Set(EV_FILE_MODIFIED, EV_ATTRS)
            else Set()
        // ATTRIBUTES, LAST_ACCESS, CREATION, EA and SECURITY are all the same
        // class to the filesystem: something about the object other than its
        // name or its data changed.
        val attrBits =
            if (cf.contains(CF_ATTRIBUTES) or cf.contains(CF_LAST_ACCESS) or
                cf.contains(CF_CREATION) or cf.contains(CF_EA) or
                cf.contains(CF_SECURITY)) Set(EV_ATTRS)
            else Set()
        val strNameBits =
            if (cf.contains(CF_STREAM_NAME)) Set(EV_STREAM_NAME) else Set()
        val strSizeBits =
            if (cf.contains(CF_STREAM_SIZE)) Set(EV_STREAM_SIZE) else Set()
        val strWriteBits =
            if (cf.contains(CF_STREAM_WRITE)) Set(EV_STREAM_WRITE) else Set()
        nameBits.union(dirBits).union(sizeBits).union(writeBits)
                .union(attrBits).union(strNameBits).union(strSizeBits)
                .union(strWriteBits)
    }

    // ------------------------------------------------------------------
    // Events and records
    // ------------------------------------------------------------------

    // One buffered change.  `oldName` is "" except on a rename, which carries
    // both halves in ONE event and expands to TWO records at serialization
    // time -- the only event shape that is not one-for-one with a record.
    type NotifyEv = { cls: Set[str], name: Name, oldName: Name }

    // One FILE_NOTIFY_INFORMATION record, as the client reads it.
    type NotifyRec = { act: int, name: Name }

    pure def evMatches(e: NotifyEv, mask: Set[str]): bool =
        e.cls.intersect(mask).size() > 0

    // The FILE_ACTION a non-rename event serializes to.  ADDED outranks
    // REMOVED outranks MODIFIED, because one mutation may raise several
    // classes (a create raises FILE_ADDED and STREAM_NAME) and the record can
    // only say one thing.  Mirrors chimera_smb_notify_file_action.
    pure def evAction(cls: Set[str]): int =
        if (cls.contains(EV_FILE_ADDED) or cls.contains(EV_DIR_ADDED)) FA_ADDED
        else if (cls.contains(EV_FILE_REMOVED) or cls.contains(EV_DIR_REMOVED))
            FA_REMOVED
        else FA_MODIFIED

    // Records for one event.  A rename with both names produces the OLD_NAME
    // record first, then NEW_NAME (MS-FSCC 2.7.1); a one-sided rename (which
    // a cross-directory move produces on each parent) produces only its half.
    /// Is this event a rename?  Either type of one -- the record SHAPE (the
    /// OLD/NEW pair) is the same; only which filter sees it differs.
    pure def isRename(cls: Set[str]): bool =
        cls.contains(EV_RENAMED_FILE) or cls.contains(EV_RENAMED_DIR)

    pure def evRecs(e: NotifyEv): List[NotifyRec] =
        if (isRename(e.cls)) {
            val oldRec = if (e.oldName != "")
                [ { act: FA_RENAMED_OLD, name: e.oldName } ] else []
            val newRec = if (e.name != "")
                [ { act: FA_RENAMED_NEW, name: e.name } ] else []
            oldRec.concat(newRec)
        } else if (e.name != "") [ { act: evAction(e.cls), name: e.name } ]
        else []

    // ------------------------------------------------------------------
    // Coalescing
    // ------------------------------------------------------------------

    // Adjacent events that would serialize to the SAME record collapse into
    // one (chimera_smb_notify_coalesce_events).  This is not an optimization:
    // one client-visible operation drives several filesystem events -- a
    // create stamps the entry and then the stream -- and Windows reports one
    // record per (action, name) transition, so a model that did not coalesce
    // would predict duplicate records the server never sends.
    //
    // ADJACENT, not global: two ADDED("a") records separated by an ADDED("b")
    // stay two records, because the client must be able to see that "a"
    // changed again after "b" did.  Renames never merge -- their record pair
    // is a unit.
    pure def coalesceStep(acc: List[NotifyEv], e: NotifyEv): List[NotifyEv] = {
        val n = acc.length()
        if (n == 0) [ e ]
        else {
            val prev = acc[n - 1]
            if (not(isRename(e.cls)) and
                not(isRename(prev.cls)) and
                evAction(e.cls) == evAction(prev.cls) and
                e.name == prev.name)
                // Fold the class bits in, exactly as chimera does: matching
                // already happened, so the union only affects nothing, but
                // keeping it makes the two implementations comparable.
                acc.slice(0, n - 1)
                   .append(prev.with("cls", prev.cls.union(e.cls)))
            else acc.append(e)
        }
    }

    pure def coalesce(evs: List[NotifyEv]): List[NotifyEv] =
        evs.foldl([], (acc, e) => coalesceStep(acc, e))

    pure def filterEvs(evs: List[NotifyEv], mask: Set[str]): List[NotifyEv] =
        evs.foldl([], (acc, e) => if (evMatches(e, mask)) acc.append(e) else acc)

    // ------------------------------------------------------------------
    // Buffer arithmetic
    // ------------------------------------------------------------------

    // A FILE_NOTIFY_INFORMATION record is a 12-byte header plus the name in
    // UTF-16, padded to a 4-byte boundary (MS-FSCC 2.7.1;
    // chimera_smb_notify_write_record).  Every name the generator draws is one
    // character, so every record is 12 + 2 = 14 -> 16 bytes.  Keeping the
    // formula here rather than the constant is what makes the OutputBufferLength
    // draws in smb2.qnt readable as "room for N records".
    pure def align4(n: int): int = (n + 3) / 4 * 4
    pure def recSize(n: Name): int = align4(12 + 2 * 1)

    pure def evSize(e: NotifyEv): int =
        evRecs(e).foldl(0, (a, r) => a + recSize(r.name))

    // How many of `evs` fit in `obl` bytes.  An event is atomic: if its
    // records do not ALL fit, none of them are written and the count stops
    // there (the rollback in chimera_smb_notify_serialize_events).  That
    // atomicity is the whole reason the server can report a consumed count the
    // caller can compare against nevents; a serializer that truncated
    // mid-rename could not.
    pure def fitCount(evs: List[NotifyEv], obl: int): int =
        evs.foldl({ used: 0, n: 0, stop: false }, (a, e) =>
            if (a.stop) a
            else if (a.used + evSize(e) > obl) a.with("stop", true)
            else { used: a.used + evSize(e), n: a.n + 1, stop: false }).n

    pure def recsOf(evs: List[NotifyEv]): List[NotifyRec] =
        evs.foldl([], (acc, e) => acc.concat(evRecs(e)))

    // ------------------------------------------------------------------
    // The watch
    // ------------------------------------------------------------------

    // What a CHANGE_NOTIFY arms on a directory handle, and what survives
    // between requests.  Created by the FIRST CHANGE_NOTIFY on the handle and
    // destroyed with the handle -- never by the completion of a request, which
    // is why the ring can hold events across the gap between one request
    // completing and the next arriving.
    //
    // `queue` is what makes this a WATCH and not a request.  MS-FSA 2.1.5.9
    // keeps the outstanding requests on an open as a LIST
    // (Open.PendingNotifyChanges) and appends to it, so a handle may carry
    // several at once -- which is not an exotic case but the ordinary one: an
    // overlapped Windows client keeps two or three ReadDirectoryChangesW calls
    // posted on a directory precisely so it never has a window with none.
    //
    // They are answered FIFO, one delivery cycle each: when a change arrives
    // the OLDEST outstanding request drains the ring and completes, and the
    // rest stay parked for the next one.  Measured against Samba, which hands
    // two waiters two different slices of one create's events.
    type Watch = {
        dir: Ino,               // the watched directory (the handle's object)
        mask: Set[str],         // ENQUEUE filter: the last request's, mapped
        watchTree: bool,        // SMB2_WATCH_TREE: also watch below `dir`
        ring: List[NotifyEv],   // buffered, oldest first
        overflow: bool,         // the ring dropped events, or a request could
                                // not be served: report ENUM_DIR until drained
        // The watched directory itself is gone.  MS-SMB2 3.3.4.4 terminates
        // the parked request with STATUS_DELETE_PENDING and no records: the
        // records would describe a directory that is no longer there.
        //
        // NOT REACHABLE from the generated corpus, and not from a
        // deterministic run either, for one structural reason: a watcher holds
        // a HANDLE on the directory, and MS-FSA 2.1.5.4 keeps a delete-pending
        // object's entry until the LAST handle drops -- so as long as there is
        // a watcher to tell, there is a handle keeping the directory alive,
        // and the close that finally removes it is the close that tears the
        // watch down (STATUS_NOTIFY_CLEANUP).  The arm becomes reachable the
        // moment the Q-1 removal-timing question is settled the other way,
        // which is what chimera already does (it unlinks at the
        // delete-on-close handle's close regardless of other handles) and what
        // smbtorture's smb2.notify.rmdir3/4 exercise.  The rule is modeled now
        // so that resolving Q-1 does not also have to invent it.
        deleted: bool,
        queue: List[NotifyReq]  // outstanding requests, oldest first
    }

    // One outstanding CHANGE_NOTIFY, with the terms IT was asked on: the
    // CompletionFilter and OutputBufferLength travel with the request, not
    // with the watch, so two waiters on one handle can want different things.
    type NotifyReq = { cf: Set[str], obl: int }

    // The ring is bounded (CHIMERA_VFS_NOTIFY_RING_SIZE).  Overrunning it is
    // not an error -- it is the condition STATUS_NOTIFY_ENUM_DIR exists to
    // report, telling the client to rescan because the server can no longer
    // enumerate what changed.
    pure val RING_SIZE = 32

    pure def watchNew(dir: Ino, mask: Set[str], wt: bool): Watch = {
        dir: dir, mask: mask, watchTree: wt, ring: [], overflow: false,
        deleted: false, queue: []
    }

    pure def watchPush(w: Watch, e: NotifyEv): Watch =
        if (not(evMatches(e, w.mask))) w
        else if (w.ring.length() >= RING_SIZE) w.with("overflow", true)
        else w.with("ring", w.ring.append(e))

    // Re-aim an existing watch at a new request's filter and recursion flag.
    //
    // Both are free.  The filter only decides what is buffered from here on,
    // and what is already in the ring is filtered again on the way out; the
    // recursion flag likewise only widens or narrows what arrives next.
    // Nothing already buffered is discarded, and no overflow is raised.
    //
    // That last part is worth stating because it is easy to argue otherwise: a
    // subtree event names its object by a path relative to the watched
    // directory while an exact event names it by a bare filename, so a ring
    // filled under WATCH_TREE could in principle hand a path to a client that
    // has since narrowed to the directory itself.  The model USED to purge on
    // that reasoning -- and it was wrong to, because it was reasoning about one
    // implementation rather than about the standard.  MS-SMB2 mandates no
    // purge, and Samba delivers the buffered events across the flip.  A server
    // that cannot tell its subtree events from its exact ones has an
    // implementation problem, not a licence to discard a client's changes.
    pure def watchReaim(w: Watch, mask: Set[str], wt: bool): Watch =
        w.with("mask", mask).with("watchTree", wt)

    // Does an event raised on directory `d` reach this watch?  Exactly `dir`
    // for a plain watch; `dir` or anything beneath it for a WATCH_TREE one.
    pure def watchCovers(w: Watch, fs: Fs, d: Ino): bool =
        if (w.dir == d) true
        else if (not(w.watchTree)) false
        else {
            // The generator builds at most ROOT/dir/subdir, so three levels of
            // parent are the whole namespace; Quint has no recursion and an
            // unrolled walk is exact for a bounded tree.
            val p1 = if (fsLive(fs, d)) fsGet(fs, d).parent else -1
            val p2 = if (p1 >= 0 and fsLive(fs, p1)) fsGet(fs, p1).parent else -1
            val p3 = if (p2 >= 0 and fsLive(fs, p2)) fsGet(fs, p2).parent else -1
            p1 == w.dir or p2 == w.dir or p3 == w.dir
        }

    // ------------------------------------------------------------------
    // Draining a watch into a reply
    // ------------------------------------------------------------------

    // The outcome of draining, before the caller decides which status the
    // three cases map to.  `fired` is false when the drain found nothing this
    // request cares about, which for a PARKED request means "stay parked" --
    // the wakeup was spurious and the client is told nothing at all.
    type Drain = {
        fired: bool,
        st: int,
        recs: List[NotifyRec],
        w: Watch            // the watch after the drain
    }

    // `cleanup` forces a completion even when the drain is empty: the handle
    // is going away, so there will never be another event and the request
    // cannot be left parked (MS-SMB2 3.3.4.4).
    //
    // The status precedence is DELETE_PENDING > NOTIFY_ENUM_DIR > cleanup >
    // SUCCESS, and it is a precedence rather than a set of independent tests:
    // a watch whose directory was deleted reports that even if it also has
    // records to deliver, because the records describe a directory that no
    // longer exists.
    pure def watchDrain(w: Watch, cf: Set[str], obl: int,
                        cleanup: bool): Drain = {
        val kept = coalesce(filterEvs(w.ring, cfToMask(cf)))
        val drained = w.with("ring", []).with("overflow", false)
                       .with("deleted", false)
        if (not(w.deleted) and not(w.overflow) and kept.length() == 0 and
            not(cleanup))
            // Nothing this request wants.  Leave the ring DRAINED (the server
            // drained it too -- the events it discarded are gone) but keep the
            // request parked.
            { fired: false, st: 0, recs: [], w: drained.with("ring", []) }
        else if (w.deleted)
            { fired: true, st: ST_DELETE_PENDING_N, recs: [], w: drained }
        else if (w.overflow)
            { fired: true, st: ST_NOTIFY_ENUM_DIR, recs: [], w: drained }
        else {
            val fits = fitCount(kept, obl)
            if (fits < kept.length())
                // The client's buffer could not hold what it asked for, so it
                // is told to rescan instead of being handed a truncated
                // prefix.  A NON-ZERO buffer that still could not be served
                // makes the overflow STICKY: the events are gone, so the next
                // request must not report a clean SUCCESS as though nothing
                // had been lost.  A zero-length buffer is a deliberate poll
                // and loses nothing it did not intend to.
                { fired: true, st: ST_NOTIFY_ENUM_DIR, recs: [],
                  w: drained.with("overflow", obl > 0) }
            else if (cleanup)
                { fired: true, st: ST_NOTIFY_CLEANUP, recs: recsOf(kept),
                  w: drained }
            else
                { fired: true, st: 0, recs: recsOf(kept), w: drained }
        }
    }

    // STATUS_DELETE_PENDING, spelled here so this module does not have to
    // import the status table from smb2_ops (which imports this one).
    pure val ST_DELETE_PENDING_N = 0xC0000056
}
