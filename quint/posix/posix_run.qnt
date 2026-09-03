// SPDX-FileCopyrightText: 2026 The Quint Specs Authors
//
// SPDX-License-Identifier: MIT

// Runnable instances of the POSIX model.
//
// There used to be one instance per backend -- posixMemfs, posixDisk,
// posixNfs3, posixNfs4, posixFuse, posixExt4 -- each pinning a profile of
// sixteen capability and policy knobs, and each generating its own corpus.
// That was the model picking one of several conforming answers and then
// recording every implementation that picked another as deviating; the
// corpus grew with the number of consumers, and a divergence in the shared
// behaviour had to be found six times.
//
// The knobs are gone (see posix_ops.qnt's Caps).  Where POSIX names more
// than one errno for a condition the model states the acceptance set and
// the harness honours it; where POSIX is silent the model encodes what the
// mature implementations agree on; where POSIX is prescriptive the model
// asserts it and a departure is recorded against whoever departs.  What is
// left is the optional interfaces, which are not a matter of opinion: a
// filesystem either has copy_file_range and reflink and SEEK_HOLE or it
// does not, and a call it answers EOPNOTSUPP changes what the rest of a
// trace means.  Those live in two flavors of their own (stepOffload,
// stepSparse) so that every other flavor is generated ONCE, for everybody.
//
//   posixFull     the generation instance: every optional interface
//                 present, so the capability flavors are exercised.  The
//                 general flavors never touch them, so their corpus is the
//                 same corpus for every implementation.
//   posixDefault  every knob explored, for hand simulation
//
// Simulate:  quint run posix_run.qnt --main=posixFull --invariant=inv

module posixFull {
    import posix(
        F_COPY_RANGE = FeatMandatory,
        F_CLONE_RANGE = FeatMandatory,
        F_SEEK_HOLE = FeatMandatory,
        F_ROOT = FeatIfAdvertised
    ).* from "./posix"
    import posixops.* from "./posix_ops"
}

// F_ROOT stays explorable everywhere: the harness chooses the credentials
// it runs the trace with, so both draws are real against any target.
module posixDefault {
    import posix(
        F_COPY_RANGE = FeatIfAdvertised,
        F_CLONE_RANGE = FeatIfAdvertised,
        F_SEEK_HOLE = FeatIfAdvertised,
        F_ROOT = FeatIfAdvertised
    ).* from "./posix"
    import posixops.* from "./posix_ops"
}
