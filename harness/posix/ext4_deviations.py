# SPDX-FileCopyrightText: 2026 The Quint Specs Authors
#
# SPDX-License-Identifier: MIT

"""Known divergences between the POSIX model and Linux/ext4.

The contract lives in deviations.py: an entry here means the disagreement
has been analyzed and attributed, so the suite keeps running; anything not
listed fails.  Every entry carries a citation, a root cause, and something
that would retire it.

`verdict` says who is wrong, because the remedies are opposite:

  MODEL  -- POSIX (or, for the Linux-only interfaces, their man pages) says
            what ext4 does, and the model is wrong or over-asserts.  These
            are the findings this suite exists to produce.  Recorded rather
            than silently patched: the corpus has other consumers and a
            model change regenerates all of it, so each entry names the
            change it is waiting for.
  SERVER -- ext4, or the Linux VFS above it, does something POSIX does not
            describe.  The model is right and stays as it is.
  BOTH   -- each is wrong, differently, in the same result.

Two model bugs this suite found are NOT here, because they were fixed at the
source instead: lockf(F_TEST) and lockf(F_ULOCK) do not need a writable
descriptor (XSH lockf's EBADF names F_LOCK and F_TLOCK only), and an
existing final component on the create path is EEXIST whatever the trailing
slash says (`mkdir("f/")`, `mkdir("dangling/")`, `symlink(t, "f/")` are all
EEXIST on Linux).  Both were plain misreadings with no defensible other
side; everything below has one.
"""

from deviations import MODEL, SERVER, Deviation, Registry
from deviations import (EACCES, EAGAIN, EEXIST, EINVAL, EISDIR, ENOTDIR,
                        ENOTEMPTY, ENXIO, EPERM, OK)

SETID = 0o6000


def _setid_dropped(f, ctx):
    """The only difference is a set-user-ID / set-group-ID bit ext4 refused
    to take from mkdir."""
    try:
        want = int(str(f.expected), 8)
        got = int(str(f.actual), 8)
    except (TypeError, ValueError):
        return False
    return want != got and (want & ~SETID) == got and (want & SETID) != 0


def _only_suid_dropped(f, ctx):
    """S_ISUID on a directory changes nothing else about it, so replay stays
    in sync.  S_ISGID does not: a subdirectory of a set-group-ID directory
    inherits both the bit and the group (posix_ops.qnt newDirMode/newGid),
    so from there the model and the filesystem create different objects and
    the trace is abandoned instead."""
    try:
        want = int(str(f.expected), 8)
        got = int(str(f.actual), 8)
    except (TypeError, ValueError):
        return False
    return (want & ~got) == 0o4000


DEVIATIONS = [
    # ------------------------------------------------------------ pwrite
    Deviation(
        id="EXT4-14",
        verdict=SERVER,
        spec="POSIX.1-2024 XSH pwrite; Linux pwrite(2) BUGS",
        summary="pwrite through an O_APPEND descriptor appends instead of "
                "writing at the offset it was given.",
        root_cause="Linux's write path honours O_APPEND for pwrite as well "
                   "as write, so the offset argument is ignored whenever the "
                   "descriptor carries O_APPEND.  pwrite(2) documents it "
                   "under BUGS: 'POSIX requires that opening a file with the "
                   "O_APPEND flag should have no effect on the location at "
                   "which pwrite() writes data.  However, on Linux, ... "
                   "pwrite() appends data to the end of the file, regardless "
                   "of the value of offset.'",
        candidate_fix="XSH pwrite is prescriptive -- it writes at the given "
                      "offset 'regardless of whether O_APPEND is set' -- so "
                      "the model asserts that and this is Linux's departure, "
                      "not a choice the standard offers.  It was a model knob "
                      "(P_PWRITE_APPENDS) until the widening, which meant the "
                      "corpus assumed the divergence and could never report "
                      "it.  Retired only by Linux changing, which it will not.",
        ops=("RPwrite", "RPwritev"),
        field="size",
        # Same post-state shape, different landing offset: the harness's
        # shadow follows the model, so everything downstream disagrees.
        reconcilable=False,
    ),
    # ----------------------------------------------------------------- mkdir
    Deviation(
        id="EXT4-1",
        verdict=MODEL,
        spec="POSIX.1-2024 XSH mkdir; Linux fs/namei.c vfs_mkdir()",
        summary="mkdir does not take the set-user-ID or set-group-ID bits "
                "from its mode argument; the model keeps whatever was asked "
                "for.",
        root_cause="vfs_mkdir() runs the requested mode through "
                   "vfs_prepare_mode() with the mask S_IRWXUGO|S_ISVTX, so "
                   "S_ISUID and S_ISGID are dropped before ext4 sees them "
                   "(S_ISVTX survives, and S_ISGID is re-added when the "
                   "parent has it).  Measured: mkdir(04755) and "
                   "mkdir(02755) both land as 0755, while mkdir(01777) "
                   "keeps its sticky bit and chmod(04755) on the same "
                   "directory takes it.",
        candidate_fix="XSH mkdir says only that 'the file permission bits "
                      "of the new directory shall be initialized from mode' "
                      "and that 'when bits in mode other than the file "
                      "permission bits are set, the meaning of these "
                      "additional bits is implementation-defined' -- so the "
                      "model is asserting a choice the standard hands to "
                      "the implementation.  Retire by making newDirMode "
                      "mask the set-id bits under a policy knob, the way "
                      "P_SGID_INHERIT already gates the inherited one.",
        ops=("RStat", "RFstat", "final-audit"),
        field=("mode", "audit"),
        context=_setid_dropped,
        reconcilable=_only_suid_dropped,
    ),

    # ------------------------------------------------------------ timestamps
    Deviation(
        id="EXT4-2",
        verdict=SERVER,
        spec="POSIX.1-2024 XBD 4.16 Pathname Resolution",
        summary="Traversing a symbolic link marks the link's last-access "
                "time; the model marks it only for readlink.",
        root_cause="Linux calls touch_atime() on the link inode in "
                   "step_into()/pick_link() as it resolves, so under "
                   "strictatime every path that runs through a symlink "
                   "moves that symlink's atime.  Visible here only because "
                   "the runner mounts strictatime; relatime hides it.",
        candidate_fix="XBD 4.16 says the last-access timestamp of a "
                      "symbolic link 'may be marked for update' when it is "
                      "traversed, so both sides are conforming.  Retire by "
                      "marking symlink atime on traversal in the model when "
                      "P_STRICT_ATIME is on -- or leave it: the model's "
                      "reading is the other permitted one.",
        ops=("RStat", "RFstat"),
        field="atime",
    ),
    Deviation(
        id="EXT4-3",
        verdict=SERVER,
        spec="POSIX.1-2024 XSH unlink",
        summary="unlink marks the file's last-status-change time even when "
                "the call drops the link count to zero.",
        root_cause="ext4_unlink() updates the inode's ctime unconditionally "
                   "before dropping the link, so an orphan still held open "
                   "by a descriptor shows a moved ctime.  XSH unlink "
                   "requires the update only 'if the file's link count is "
                   "not 0', and the model follows that literally.",
        candidate_fix="Harmless: nothing can observe the timestamp of an "
                      "object with no links except through a descriptor "
                      "that already existed.  Retire by marking ctime on "
                      "the unlinked inode unconditionally in fsUnlink.",
        ops=("RStat", "RFstat", "final-audit"),
        field="ctime",
        context=lambda f, ctx: (ctx.get("res") or {}).get("nlink") == 0,
    ),

    # ----------------------------------------------------------------- lseek
    Deviation(
        id="EXT4-4",
        verdict=MODEL,
        spec="POSIX.1-2024 XSH lseek; Linux fs/ext4/dir.c ext4_dir_llseek()",
        summary="A directory's size and seek domain are the "
                "implementation's, and the model abstracts them as an empty "
                "file.",
        root_cause="The model gives a directory size 0 and no data, so it "
                "predicts SEEK_END/SEEK_DATA/SEEK_HOLE relative to 0.  ext4 "
                "reports st_size 4096 for a small directory, answers "
                "SEEK_HOLE with the maximum file size, and rejects a "
                "SEEK_END past the htree end-of-file with EINVAL.",
        candidate_fix="POSIX leaves a directory's st_size unspecified and "
                      "says the offset of a directory descriptor is "
                      "meaningful only to readdir.  Retire by not asserting "
                      "size-relative seeks on directory descriptors -- "
                      "either in the model or by dropping them from the "
                      "generator, which is where they come from.",
        ops=("RLseek",),
        field=("status", "offset"),
        context=lambda f, ctx: bool(ctx.get("on_dir")),
    ),
    Deviation(
        id="EXT4-5",
        verdict=SERVER,
        spec="POSIX.1-2024 XSH lseek (SEEK_DATA/SEEK_HOLE); RFC 7862 "
             "§11.1 (ALLOCATE)",
        summary="An allocated-but-unwritten extent reads as a hole, not as "
                "data.",
        root_cause="ext4's fallocate leaves the range as unwritten extents, "
                "and ext4_seek_data()/ext4_seek_hole() report those as "
                "holes: after fallocate(fd, 0, 0, 4096), SEEK_DATA(0) is "
                "ENXIO and SEEK_HOLE(0) is 0.  The model materializes the "
                "blocks a fallocate reserves and calls them data, following "
                "RFC 7862's reading that allocated space is not a hole.",
        candidate_fix="lseek's SEEK_DATA/SEEK_HOLE let an implementation "
                      "report any allocated extent either way -- the "
                      "extreme conforming answer is 'all data' -- so "
                      "neither side is wrong.  Retire by making the "
                      "fallocate-reserves-data reading a policy knob, "
                      "which is what it is.",
        ops=("RLseek",),
        field=("status", "offset"),
        context=lambda f, ctx: (not ctx.get("on_dir")
                               and ctx.get("whence") in ("WData", "WHole")
                               and not ctx.get("written_after")),
    ),

    # ------------------------------------------------- order of checks

    # ------------------------------------------------------------- utimensat
    Deviation(
        id="EXT4-9",
        verdict=MODEL,
        spec="POSIX.1-2024 XSH futimens/utimensat; Linux fs/attr.c "
             "setattr_prepare()",
        summary="Any times array that is not two UTIME_NOWs takes the "
                "owner-or-privileged tier, so a mixed UTIME_NOW/UTIME_OMIT "
                "pair is EPERM rather than the write-permission tier's "
                "EACCES.",
        root_cause="vfs_utimes() sets ATTR_TIMES_SET whenever times is not "
                   "null and not both UTIME_NOW, and setattr_prepare() "
                   "answers EPERM for that unless the caller owns the file. "
                   "Only the null / both-UTIME_NOW form takes ATTR_TOUCH, "
                   "which is the one that accepts write permission instead.",
        candidate_fix="XSH utimensat specifies exactly two tiers -- EACCES "
                      "when 'the times argument is a null pointer, or both "
                      "tv_nsec values are UTIME_NOW', EPERM when 'neither "
                      "tv_nsec field is UTIME_NOW, neither ... is "
                      "UTIME_OMIT' -- and says nothing about the mixed "
                      "pairs in between, which is where every one of these "
                      "lands.  Retire by defining the model's `explicit` "
                      "predicate as 'not both UTIME_NOW', matching the "
                      "clause structure.",
        ops=("RUtimens", "RFutimens"),
        expected_status=(OK, EACCES),
        actual_status=EPERM,
    ),

    # ---------------------------------------------------- descriptor table
    Deviation(
        id="EXT4-10",
        verdict=MODEL,
        spec="POSIX.1-2024 XSH open (EMFILE)",
        summary="The model's descriptor table holds 16 entries; a real "
                "process gets RLIMIT_NOFILE of them, so the open the model "
                "refuses with EMFILE succeeds.",
        root_cause="posix_ops.qnt pins MAX_FDS at 16 to bound its "
                   "lowest-free-descriptor search.  EMFILE is a limit, not "
                   "a behavior: POSIX requires only that one exist.  The "
                   "harness closes the extra descriptor, and unlinks the "
                   "file an O_CREAT minted that the model does not have, so "
                   "replay stays in sync.",
        candidate_fix="Retire by keeping the generator's descriptor "
                      "universe below MAX_FDS (the model's own comment says "
                      "it is meant to be), or by having the driver set "
                      "RLIMIT_NOFILE so the real table is the modeled one.",
        ops=("ROpen", "RDup", "RDup2", "RFcntlDupfd"),
        expected_status=24,        # EMFILE
        actual_status=OK,
    ),

    # ------------------------------------------------------------ interfaces
    Deviation(
        id="EXT4-11",
        verdict=MODEL,
        spec="Linux open(2), fifo(7)",
        summary="The model answers ENXIO for every non-regular, "
                "non-directory object, before it has judged permissions -- "
                "so opening a FIFO O_RDWR (which succeeds) and opening a "
                "device node the caller may not write (EACCES) both "
                "disagree.",
        root_cause="posix_ops.qnt's open handler folds FIFOs, sockets and "
                   "device nodes into one ENXIO branch marked 'generators "
                   "never do it (defensive)' -- but the generator does, via "
                   "the mknod ops.  Linux's O_RDWR on a FIFO is the "
                   "documented non-blocking case: the caller is its own "
                   "peer, so it neither blocks nor fails.",
        candidate_fix="ENXIO is right for a socket and for a device node "
                      "with no driver behind it, and for O_WRONLY on a FIFO "
                      "with no reader only under O_NONBLOCK -- three "
                      "different rules the one branch cannot express.  "
                      "Retire by splitting it per type, or by keeping "
                      "special files out of the open universe.",
        ops=("ROpen",),
        expected_status=ENXIO,
    ),
    Deviation(
        id="EXT4-12",
        verdict=MODEL,
        spec="Linux copy_file_range(2)",
        summary="An empty copy returns 0 before the overlapping-range check "
                "can reject it.",
        root_cause="generic_copy_file_checks() shortens the count to the "
                   "source's end-of-file and returns 0 for 'nothing to "
                   "copy' before it tests whether the ranges overlap, so a "
                   "copy that starts past the end of the file succeeds "
                   "vacuously.  The model tests the overlap first.",
        candidate_fix="copy_file_range has no POSIX text; its man page is "
                      "the specification and it is silent on the order.  "
                      "Retire by moving opCopyRange's n == 0 short-circuit "
                      "above the overlap test.",
        ops=("RCopyRange",),
        expected_status=EINVAL,
        actual_status=OK,
    ),
    Deviation(
        id="EXT4-13",
        verdict=SERVER,
        spec="POSIX.1-2024 XSH lockf; glibc io/lockf.c",
        summary="lockf(F_TEST) probes with a read lock, so it does not see "
                "a conflicting read lock the model counts.",
        root_cause="lockf is a glibc wrapper: F_TEST becomes fcntl(F_GETLK) "
                   "with l_type F_RDLCK, which only a write lock conflicts "
                   "with, and a lock the caller holds itself is reported as "
                   "no conflict.  The model asks whether a *write* lock -- "
                   "the only kind lockf takes -- would be refused, which a "
                   "read lock also blocks.",
        candidate_fix="XSH lockf defines F_TEST as testing 'a section for "
                      "locks by other processes', which the model's reading "
                      "matches and glibc's narrows.  Retire by modeling "
                      "F_TEST's conflict domain as write locks only.",
        ops=("RLockf",),
        expected_status=(EAGAIN, EACCES),
        actual_status=OK,
        context=lambda f, ctx: (ctx.get("req") or {}).get(
            "cmd", {}).get("tag") == "LfTst",
    ),
]

REGISTRY = Registry("ext4", DEVIATIONS)
