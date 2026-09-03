#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 The Quint Specs Authors
// SPDX-License-Identifier: MIT
//
// Generate every trace batch for ONE quint model in a single process.
//
// WHY THIS EXISTS
//
// A batch is a (model, --main, --step) triple, and the CLI can only run one per
// invocation.  Elaborating a model -- load, parse, typecheck -- costs 13-21s for
// the larger specs here, while simulating a batch of eight 80-step traces costs
// about 0.45s.  Measured on nfs4_run.qnt: `quint typecheck` alone takes as long
// as a full `quint run`, so the CLI spends essentially all of its time
// re-elaborating a model it elaborated for the previous batch.  nfs4 has 18
// batches over one model, which is ~270s of work to produce ~8s of traces.
//
// The library does not have that limitation, only the CLI does.  cliCommands
// exposes the pipeline as stages -- load -> parse -> typecheck -> runSimulator
// -- and runSimulator reads main, step, nTraces, seed and outItf from
// stage.args at simulate time while the expensive artifact it needs is
// stage.resolver.table.  So one elaboration serves every batch: nfs4's 18 drop
// from ~270s to ~21s.
//
// The traces are the same ones.  Verified against the CLI byte-for-byte, with
// the two wall-clock fields in #meta (description, timestamp) excluded -- the
// CLI does not reproduce those against itself between two identical runs
// either.  vars and states match exactly.
//
// CAVEAT: cliCommands is NOT part of the package's public exports (index.js
// exports a much smaller set), so this reaches into dist/src directly.  That is
// safe only because .quint-version pins the release and CMake refuses to
// configure against any other one -- but it does mean a quint bump is a code
// change here, not just a version bump.  If a future quint grows a real batch
// mode, this file should be deleted in favour of it.
//
// The same elaboration also serves the family's model self-tests.  They run
// FIRST and abort the run on the first failure, so a model regression still
// stops the corpus at the source -- the property the stamp-file gate provided,
// now enforced inside one process instead of across build edges.  <family>_all.qnt
// is what makes this possible: it names a module from the run file and one from
// the test file, so quint's resolver pulls both into a single module tree.
//
// Usage: gen.js <spec.json>   where spec.json is written by CMake:
//   { "quintCli": "...", "model": "<family>_all.qnt",
//     "tests":   [ { "name": "...", "main": "-"|"name", "maxSamples": N } ],
//     "batches": [ { "outdir": "...", "main": "-"|"name", "step": "...",
//                    "maxSteps": N, "nTraces": N, "seed": "0x7",
//                    "naming": "x_{seq}" } ] }

const fs = require('fs')
const os = require('os')
const path = require('path')

function die(msg) {
  console.error(`gen.js: ${msg}`)
  process.exit(1)
}

const specPath = process.argv[2]
if (!specPath) die('usage: gen.js <spec.json>')
const spec = JSON.parse(fs.readFileSync(specPath, 'utf8'))

// Resolve the quint package from the CLI CMake found, rather than from
// NODE_PATH: the images install quint globally and a plain require() would not
// see it from this file's location.  realpath because the bin entry is a
// symlink into dist/src/cli.js.
let cliCommands
try {
  const cli = fs.realpathSync(spec.quintCli)
  cliCommands = require(path.join(path.dirname(cli), 'cliCommands'))
} catch (err) {
  die(`could not load quint's cliCommands from ${spec.quintCli}: ${err.message}\n` +
      `        this file depends on quint internals; see the caveat at the top`)
}
for (const fn of ['load', 'parse', 'typecheck', 'runSimulator', 'runTests']) {
  if (typeof cliCommands[fn] !== 'function') {
    die(`quint's cliCommands has no ${fn}(); the pinned quint is not the one this expects`)
  }
}

// The same defaults `quint run` applies, so a batch here is the batch the CLI
// would have run.  maxSamples tracks nTraces exactly as specs_gen passed both.
function argsFor(batch) {
  return {
    input: spec.model,
    main: batch.main === '-' ? undefined : batch.main,
    init: 'init',
    step: batch.step ?? 'step',
    invariant: 'inv',
    invariants: [],
    witnesses: [],
    hide: [],
    maxSamples: batch.maxSamples ?? batch.nTraces,
    maxSteps: batch.maxSteps ?? 20,
    nTraces: batch.nTraces ?? 1,
    nThreads: os.cpus().length,
    // Generation batches are seeded and so reproducible; self-tests are not,
    // exactly as `quint test` was invoked before -- it passed no --seed, so each
    // run walks a different sample.  Seeding them here would quietly turn a
    // randomised check into a fixed one.
    seed: batch.seed !== undefined ? BigInt(batch.seed) : undefined,
    backend: 'rust',
    mbt: false,
    verbosity: 0,
    quiet: true,
    out: undefined,
    outItf: batch.outdir ? path.join(batch.outdir, `${batch.naming}.itf.json`) : undefined,
  }
}

async function main() {
  const t0 = Date.now()
  const loaded = await cliCommands.load(argsFor(spec.batches[0]))
  if (loaded.isLeft()) die(`load ${spec.model}: ${JSON.stringify(loaded.value.errors)}`)
  const parsed = await cliCommands.parse(loaded.value)
  if (parsed.isLeft()) die(`parse ${spec.model}: ${JSON.stringify(parsed.value.errors)}`)
  const typechecked = await cliCommands.typecheck(parsed.value)
  if (typechecked.isLeft()) die(`typecheck ${spec.model}: ${JSON.stringify(typechecked.value.errors)}`)
  const stage = typechecked.value
  const elapsed = ((Date.now() - t0) / 1000).toFixed(1)
  const tests = spec.tests ?? []
  console.log(`  elaborated ${path.basename(spec.model)} in ${elapsed}s; ` +
              `${tests.length} self-test(s), ${spec.batches.length} batch(es)`)

  // Self-tests first, and fatal: generating a corpus from a model that fails
  // its own invariant checks is worse than not generating one.
  for (const tc of tests) {
    stage.args = argsFor(tc)
    const res = await cliCommands.runTests(stage)
    if (res.isLeft() || (res.value.status && res.value.status !== 'passed')) {
      die(`self-test ${tc.name} (${tc.main}) failed for ${spec.model}`)
    }
  }

  let failed = 0
  for (const batch of spec.batches) {
    fs.mkdirSync(batch.outdir, { recursive: true })
    // Per-batch configuration is just args; the typechecked table does not move.
    stage.args = argsFor(batch)
    const res = await cliCommands.runSimulator(stage)
    // A violated invariant comes back as a Left, exactly as it fails the CLI --
    // the gate has to keep gating.
    if (res.isLeft()) {
      failed++
      const label = `${batch.main}/${batch.step}`
      console.error(`  FAILED ${label}: ${JSON.stringify(res.value.errors ?? res.value.status)}`)
    }
  }
  if (failed > 0) die(`${failed} batch(es) failed for ${spec.model}`)
  console.log(`  ${path.basename(spec.model)}: ${tests.length} self-test(s) + ` +
              `${spec.batches.length} batch(es) in ${((Date.now() - t0) / 1000).toFixed(1)}s`)
}

main().catch(err => die(err.stack || String(err)))
