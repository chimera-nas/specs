// SPDX-FileCopyrightText: 2026 The Quint Specs Authors
// SPDX-License-Identifier: MIT
//
// Umbrella entry point for the posix family: it names one module from the run
// file and one from the test file, which is enough for quint's resolver to pull
// BOTH files -- and the large shared base they each import -- into a single
// module tree.
//
// The point is one elaboration instead of two.  tools/gen.js loads this file
// once and then drives every generation batch (runSimulator) and every model
// self-test (runTests) against the same typechecked stage.  Elaborating the
// nfs4 family this way costs 16.4s against 17.3s for the run file alone: the
// shared base dominates, so the test file rides along for free, where running
// it separately paid the whole cost again.
//
// This module is never simulated or tested itself; --main always selects a
// module from one of the imported files.  Nothing may be added here.
module posixAll {
    import posixFull.* from "./posix_run"
    import posixTestStd.* from "./posixTest"
}
