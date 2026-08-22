// SPDX-FileCopyrightText: 2026 The Quint Specs Authors
//
// SPDX-License-Identifier: MIT

// Concrete SMB2 model instances for trace generation, pinned to what
// the reference implementation actually does so the generated corpus
// contains no
// not-applicable traces (the tactic that eliminated the NFS capability
// skips).  `quint run --main=<inst> --step=<flavor> --out-itf` emits ITF
// traces the replay harness drives against the server under test.
//
// smb2Base pins oplocks and leases OFF: it is the deterministic filesystem
// core -- the CREATE disposition/type matrix, share arbitration, byte-range
// locks, I/O, delete-on-close, rename and compound threading -- with no
// caching grants and therefore no oplock/lease break lifecycle.  That break
// lifecycle is asynchronous on the wire (an interim STATUS_PENDING then a
// deferred completion on the SAME request), which does not map onto the
// model's PENDING-then-retry abstraction; a caching instance (smb2Leases) is
// deferred until that impedance is reconciled in the replayer.

module smb2Base {
    import nfs4fs.* from "../nfs/nfs4_fs"
    import smb2state.* from "./smb2_state"
    import smb2ops.* from "./smb2_ops"
    import smb2(
        DIALECT = 0x0300,
        F_OPLOCKS = FeatOff,
        F_LEASES = FeatOff,
        F_DIRLEASE = FeatOff,
        F_DURABLE = FeatOff,
        P_LEASE_OPEN_BREAK = true
    ).* from "./smb2"
}
