# SPDX-FileCopyrightText: 2026 The Quint Specs Authors
#
# SPDX-License-Identifier: MIT

"""What is LEFT of the ext4 divergence registry.

Everything this file used to hold is now either a knob in
harness/posix/configs/ext4.json, which the model reads before it generates a
trace, or a deviation id declared with its citation in
quint/posix/corpus.schema.json.  The difference matters: a reconciliation here
excused a disagreement AFTER the fact, so the trace said one thing and the
filesystem did another and the harness forgave it.  A knob or a deviation id
makes the trace itself say what ext4 does, so replay is an exact match and a
NEW disagreement has nowhere to hide.

Carried over so far:

  EXT4-14  -> policies.pwriteAppends = supported.  pwrite(2) lists it under
              BUGS; the model now writes at EOF through an O_APPEND
              descriptor for this cell, so nothing is reconciled
  EXT4-5   -> features.cloneRange = unsupported settles the reflink half;
              the allocated-but-unwritten extent reading as a hole is ext4's
              own and still needs an id
  EXT4-1   -> the model was wrong and is fixed here: mkdir cannot set the
              set-user-ID bit (Linux vfs_mkdir masks the caller's mode to
              S_IRWXUGO|S_ISVTX, FreeBSD ufs_mkdir takes va_mode & 0777),
              measured as 04755 -> 02755 under a set-group-ID parent

The rest of the old registry -- the symlink-traversal atime mark, the ctime
mark on the link-count-zeroing unlink, the unwritten extent, lockf(F_TEST)
probing with a read lock, and the four the old file called the model's
(EXT4-4, -9, -11, -12) -- are NOT yet carried over.  Each needs re-measuring
against this corpus before it is written down again: the model has moved, and
a deviation copied forward without being re-measured is exactly the stale
entry this migration exists to remove.  The cell config enables no deviations
today, so the first run reports them all and each gets classified on the
evidence.

The registry stays because the contract does: a disagreement this file does
not name fails the run.

See deviations.py for the contract, and harness/nfs/knfsd_deviations.py for
the same migration done to the Linux NFS server's registry.
"""

from deviations import (Deviation, Registry, SERVER, MODEL, BOTH,  # noqa: F401
                        OK)

REGISTRY = Registry("ext4", [])
