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
// caching grants and therefore no oplock/lease break lifecycle.
//
// smb2Leases turns both on.  The asynchrony that used to block it is
// reconciled: the wire emits an interim STATUS_PENDING and then the real reply
// on the SAME request, so the model no longer answers a conflicting CREATE
// with a terminal ST_PENDING-then-retry.  It answers with the FINAL status and
// a `parked` flag naming the interim, which the replayer checks against the
// connection's interim counter (probe O6 pins both halves).  The break
// notifications themselves are modeled as wire records and asserted
// field-by-field, and every acknowledgment arm -- conformant, drop-further,
// keep-too-much, and ack-with-no-break-outstanding -- is generated.
//
// smb2LeasesAdv exercises FeatIfAdvertised, the capability mode no instance
// used before: init draws support on/off, so the corpus contains traces where
// the server must NOT advertise caching and traces where it must.

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
        P_LEASE_OPEN_BREAK = true,
        P_FORCE_LEVEL2 = false
    ).* from "./smb2"
}

// Caching instance: legacy oplocks AND SMB2 leases mandatory, so a server that
// fails to advertise them fails the suite instead of passing vacuously.
module smb2Leases {
    import nfs4fs.* from "../nfs/nfs4_fs"
    import smb2state.* from "./smb2_state"
    import smb2ops.* from "./smb2_ops"
    import smb2(
        DIALECT = 0x0300,
        F_OPLOCKS = FeatMandatory,
        F_LEASES = FeatMandatory,
        F_DIRLEASE = FeatOff,
        F_DURABLE = FeatOff,
        P_LEASE_OPEN_BREAK = true,
        P_FORCE_LEVEL2 = false
    ).* from "./smb2"
}

// The same caching model on a share carrying SMB2_SHAREFLAG_FORCE_LEVELII_
// OPLOCK: every grant caps to a read cache, so exclusive/batch and W/H leases
// are never handed out and the break lifecycle runs entirely at LEVEL_II / R.
// (WPTS ShareForceLevel2 is 112 of the 156 green oplock cases.)
module smb2ForceL2 {
    import nfs4fs.* from "../nfs/nfs4_fs"
    import smb2state.* from "./smb2_state"
    import smb2ops.* from "./smb2_ops"
    import smb2(
        DIALECT = 0x0300,
        F_OPLOCKS = FeatMandatory,
        F_LEASES = FeatMandatory,
        F_DIRLEASE = FeatOff,
        F_DURABLE = FeatOff,
        P_LEASE_OPEN_BREAK = true,
        P_FORCE_LEVEL2 = true
    ).* from "./smb2"
}

// The durable-handle instance: durable/persistent handles advertised
// (config persistent_handles), and oplocks AND leases mandatory because a
// durable grant is impossible without one of them -- MS-SMB2 3.3.5.9.6/.10
// require a BATCH oplock or a HANDLE-caching lease, so an instance with
// caching off could only ever generate REFUSALS (probe D1).
//
// The share is NOT continuously available, so nothing here is persistent:
// a parked persistent holder BLOCKS a conflicting opener where a durable-only
// one yields (probe D11), and that asymmetry is pinned deterministically by
// the probe rather than generated.
module smb2Durable {
    import nfs4fs.* from "../nfs/nfs4_fs"
    import smb2state.* from "./smb2_state"
    import smb2ops.* from "./smb2_ops"
    import smb2(
        DIALECT = 0x0300,
        F_OPLOCKS = FeatMandatory,
        F_LEASES = FeatMandatory,
        F_DIRLEASE = FeatOff,
        F_DURABLE = FeatMandatory,
        P_LEASE_OPEN_BREAK = true,
        P_FORCE_LEVEL2 = false
    ).* from "./smb2"
}

// The exactly-once instance (ROADMAP-SMB.md B4).  Identical capability
// settings to smb2Durable, and deliberately so: a replay is only answerable
// from a CreateGuid the server bothered to record, and chimera records one
// only when persistent_handles is on (chimera_smb_create_grant_durable returns
// immediately otherwise) -- so F_DURABLE must be mandatory even though most of
// what this instance generates is not about durability at all.  Caching is
// mandatory for the same reason smb2Durable needs it: the PARKED arm of the
// create reply cache cannot be reached without a handle that survives a drop.
//
// What distinguishes it is the FLAVOR (stepReplay), which stamps the two SMB2
// header fields the exactly-once layer turns on -- ChannelSequence and
// SMB2_FLAGS_REPLAY_OPERATION -- on ordinary requests.
module smb2Replay {
    import nfs4fs.* from "../nfs/nfs4_fs"
    import smb2state.* from "./smb2_state"
    import smb2ops.* from "./smb2_ops"
    import smb2(
        DIALECT = 0x0300,
        F_OPLOCKS = FeatMandatory,
        F_LEASES = FeatMandatory,
        F_DIRLEASE = FeatOff,
        F_DURABLE = FeatMandatory,
        P_LEASE_OPEN_BREAK = true,
        P_FORCE_LEVEL2 = false
    ).* from "./smb2"
}
