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
//   { "quintCli": "...", "model": "<family>_all.qnt", "backend": "typescript",
//     "tests":   [ { "name": "...", "main": "-"|"name", "maxSamples": N } ],
//     "batches": [ { "outdir": "...", "main": "-"|"name", "step": "...",
//                    "maxSteps": N, "nTraces": N, "seed": "0x7",
//                    "naming": "x_{seq}" } ] }
//
// THE TRACE CACHE
//
// When SPECS_CORPUS_CACHE_DIR is set, every cell's traces are also kept in a
// content-addressed store there, the way ccache keeps objects under CCACHE_DIR.
// A cell's key hashes everything its traces are a function of: the quint
// release and backend, every model and tool source under quint/ and tools/,
// the cell's rendered config module, and its batch list.  A cell whose key is
// present is copied out of the store instead of simulated, and when every cell
// of the family hits, the model is not even elaborated.  Unset, nothing
// changes.
//
// That is sound because generation is a pure function of those inputs: batches
// are seeded, the typescript simulator ignores nThreads (the key carries it for
// rust), and a cell's traces do not depend on which other cells share the
// elaboration -- one cell generated alone is byte-identical to the same cell
// generated with its whole family, #meta's wall-clock fields aside.  The whole
// model tree is hashed rather than the family's own dependency list, so a
// missed import can cost a regeneration but never serve a stale trace.
//
// Self-tests run only when something is generated.  A cell reaches the store
// only from a run whose self-tests passed on those same inputs.
//
// Each hit refreshes its entry's mtime, so a caller can trim the store to what
// a run used by deleting entries older than the run's start.

const crypto = require('crypto')
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
let quintPackage
try {
  const cli = fs.realpathSync(spec.quintCli)
  // npm's Windows launcher is a .cmd file alongside node_modules, rather
  // than a symlink into the package. Resolve that standard installation
  // layout without changing the pinned package or relying on NODE_PATH.
  const directory = path.dirname(cli)
  const candidates = [
    path.join(directory, 'cliCommands'),
    path.join(directory, 'node_modules', '@informalsystems', 'quint', 'dist', 'src', 'cliCommands'),
    path.join(directory, '..', '@informalsystems', 'quint', 'dist', 'src', 'cliCommands'),
  ]
  const commands = candidates.find(candidate => fs.existsSync(candidate + '.js'))
  if (!commands) throw new Error('cannot locate the Quint package beside its launcher')
  cliCommands = require(commands)
  quintPackage = path.join(path.dirname(commands), '..', '..', 'package.json')
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
    // The simulator backend.  DEFAULT IS TYPESCRIPT, and that is a portability
    // decision rather than a performance one.  quint publishes its Rust
    // evaluator only as *-unknown-linux-gnu built against glibc 2.39, newer
    // than ubuntu 22.04 and rocky 9 carry, with no musl build to mirror -- so
    // on those two CI images the rust backend loads and then dies
    // ("version `GLIBC_2.39' not found") the first time a generator runs.
    // While a prebuilt trace bundle existed that did not matter, because those
    // images replayed a corpus somebody else generated.  The corpus is now
    // generated on every build, so a backend that cannot run there costs those
    // cells their model-based tests entirely.  TypeScript is slower on the
    // large families and produces a DIFFERENT (equally valid) corpus for the
    // same seed; both were accepted deliberately in exchange for generating
    // everywhere.
    backend: spec.backend ?? 'typescript',
    // Generation batches are seeded and so reproducible; self-tests are not,
    // exactly as `quint test` was invoked before -- it passed no --seed, so each
    // run walks a different sample.  Seeding them here would quietly turn a
    // randomised check into a fixed one.
    seed: batch.seed !== undefined ? BigInt(batch.seed) : undefined,
    mbt: false,
    match: batch.run ? `^${batch.run}$` : undefined,
    verbosity: 0,
    quiet: true,
    out: undefined,
    outItf: batch.outdir ? path.join(batch.outdir, `${batch.naming}.itf.json`) : undefined,
  }
}

const CACHE_SCHEME = 'v1'
const cacheRoot = process.env.SPECS_CORPUS_CACHE_DIR || ''

// Line endings are normalised so a checkout with autocrlf keys the same as one
// without; quint reads both alike.
function hashFile(hash, file, name) {
  hash.update(`${name}\0`)
  hash.update(fs.readFileSync(file, 'utf8').replace(/\r\n/g, '\n'))
  hash.update('\0')
}

function listSources(root, rel, out) {
  for (const entry of fs.readdirSync(path.join(root, rel), { withFileTypes: true })) {
    const child = rel ? `${rel}/${entry.name}` : entry.name
    if (entry.isDirectory()) {
      listSources(root, child, out)
    } else if (/\.(qnt|json|js)$/.test(entry.name)) {
      out.push(child)
    }
  }
  return out
}

// Everything every cell's key shares.
function baseKey() {
  const hash = crypto.createHash('sha256')
  hash.update(`specs-corpus-cache ${CACHE_SCHEME}\0`)
  hashFile(hash, quintPackage, 'quint/package.json')
  hash.update(`backend ${spec.backend ?? 'typescript'}\0`)
  if (spec.backend === 'rust') hash.update(`threads ${os.cpus().length}\0`)
  const sources = [...listSources(spec.specsRoot, 'quint', []),
                   ...listSources(spec.specsRoot, 'tools', [])].sort()
  for (const rel of sources) hashFile(hash, path.join(spec.specsRoot, rel), rel)
  return hash.digest('hex')
}

function cellKey(base, dir, batches) {
  const hash = crypto.createHash('sha256')
  hash.update(`${base}\0cell ${dir.cell}\0`)
  hashFile(hash, dir.module, 'module')
  // Everything about a batch except where it is written.
  hash.update(JSON.stringify(batches.map(({ outdir, ...batch }) => batch)))
  return hash.digest('hex')
}

function cacheEntry(key) {
  return path.join(cacheRoot, CACHE_SCHEME, key)
}

function restoreCell(dir, key) {
  const entry = cacheEntry(key)
  if (!fs.existsSync(path.join(entry, '.complete')) ||
      !dir.traces.every(t => fs.existsSync(path.join(entry, t)))) {
    return false
  }
  fs.mkdirSync(dir.path, { recursive: true })
  // A copy, not a link: the output must be newer than its inputs for the build
  // system, and a later regeneration must not write through into the store.
  for (const t of dir.traces) {
    fs.copyFileSync(path.join(entry, t), path.join(dir.path, t))
  }
  const now = new Date()
  fs.utimesSync(entry, now, now)
  return true
}

// Written under a temporary name and renamed into place, so a concurrent
// reader or an interrupted run never sees a partial entry.
function storeCell(dir, key) {
  const entry = cacheEntry(key)
  if (fs.existsSync(path.join(entry, '.complete'))) return
  const tmp = `${entry}.tmp-${process.pid}-${crypto.randomBytes(4).toString('hex')}`
  fs.mkdirSync(tmp, { recursive: true })
  try {
    for (const t of dir.traces) {
      fs.copyFileSync(path.join(dir.path, t), path.join(tmp, t))
    }
    fs.writeFileSync(path.join(tmp, '.complete'), `${dir.cell}\n`)
    fs.renameSync(tmp, entry)
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true })
  }
}

// The store is an accelerator: any failure in it is a miss or a skipped
// store, never a failed build.
function tryCache(what, fn) {
  try {
    return fn()
  } catch (err) {
    console.error(`  trace cache: ${what} failed: ${err.message}`)
    return false
  }
}

// Replay and coverage both consume whole generated directories. Remove
// obsolete generated traces only after every declared output succeeded, so
// changing a batch/seed cannot leave an old trace satisfying a coverage gate.
function removeObsoleteTraces() {
  for (const { path: directory, traces } of spec.directories || []) {
    const expected = new Set(traces)
    for (const name of fs.readdirSync(directory)) {
      if (name.endsWith('.itf.json') && !expected.has(name)) {
        fs.unlinkSync(path.join(directory, name))
      }
    }
  }
}

async function main() {
  const t0 = Date.now()
  const dirs = spec.directories ?? []
  const keys = new Map()
  const cached = new Set()
  if (cacheRoot && spec.specsRoot && dirs.every(d => d.cell && d.module)) {
    const base = tryCache('keying', baseKey)
    for (const dir of base ? dirs : []) {
      const key = tryCache(`keying ${dir.cell}`, () =>
        cellKey(base, dir, spec.batches.filter(b => b.outdir === dir.path)))
      if (!key) continue
      keys.set(dir.path, key)
      if (tryCache(`restoring ${dir.cell}`, () => restoreCell(dir, key))) {
        cached.add(dir.path)
      }
    }
    console.log(`  ${path.basename(spec.model)}: trace cache hit ${cached.size} ` +
                `of ${dirs.length} cell(s)`)
  }
  const batches = spec.batches.filter(b => !cached.has(b.outdir))
  if (batches.length === 0) {
    removeObsoleteTraces()
    return
  }

  const loaded = await cliCommands.load(argsFor(batches[0]))
  if (loaded.isLeft()) die(`load ${spec.model}: ${JSON.stringify(loaded.value.errors)}`)
  const parsed = await cliCommands.parse(loaded.value)
  if (parsed.isLeft()) die(`parse ${spec.model}: ${JSON.stringify(parsed.value.errors)}`)
  const typechecked = await cliCommands.typecheck(parsed.value)
  if (typechecked.isLeft()) die(`typecheck ${spec.model}: ${JSON.stringify(typechecked.value.errors)}`)
  const stage = typechecked.value
  const elapsed = ((Date.now() - t0) / 1000).toFixed(1)
  const tests = spec.tests ?? []
  console.log(`  elaborated ${path.basename(spec.model)} in ${elapsed}s; ` +
              `${tests.length} self-test(s), ${batches.length} batch(es)`)

  // Self-tests first, and fatal: generating a corpus from a model that fails
  // its own invariant checks is worse than not generating one.
  for (const tc of tests) {
    stage.args = argsFor(tc)
    const res = await cliCommands.runTests(stage)
    if (res.isLeft() || (res.value.status && res.value.status !== 'passed')) {
      die(`self-test ${tc.name} (${tc.main}) failed for ${spec.model}: ` +
          JSON.stringify(res.value.failed ?? res.value.errors ?? res.value.status))
    }
  }

  let failed = 0
  for (const batch of batches) {
    fs.mkdirSync(batch.outdir, { recursive: true })
    for (let i = 0; i < batch.nTraces; i++) {
      fs.rmSync(path.join(batch.outdir,
        `${batch.naming.replace('{seq}', String(i))}.itf.json`), { force: true })
    }
    // Per-batch configuration is just args; the typechecked table does not move.
    stage.args = argsFor(batch)
    const res = batch.run ? await cliCommands.runTests(stage)
                          : await cliCommands.runSimulator(stage)
    // A violated invariant comes back as a Left, exactly as it fails the CLI --
    // the gate has to keep gating.
    if (res.isLeft() || (batch.run &&
        (res.value.passed.length !== 1 ||
         res.value.passed[0].split('::').pop() !== batch.run))) {
      failed++
      const label = `${batch.main}/${batch.run ?? batch.step}`
      console.error(`  FAILED ${label}: ${JSON.stringify(res.value.errors ?? res.value.status)}`)
    }
    // A misspelled run name can select zero tests successfully. Every declared
    // output must exist, including a named regression's single replay trace.
    for (let i = 0; i < batch.nTraces; i++) {
      const output = path.join(batch.outdir,
        `${batch.naming.replace('{seq}', String(i))}.itf.json`)
      if (!fs.existsSync(output)) die(`missing generated trace ${output}`)
    }
  }
  if (failed > 0) die(`${failed} batch(es) failed for ${spec.model}`)
  removeObsoleteTraces()
  for (const dir of dirs) {
    const key = keys.get(dir.path)
    if (key && !cached.has(dir.path)) {
      tryCache(`storing ${dir.cell}`, () => storeCell(dir, key))
    }
  }
  console.log(`  ${path.basename(spec.model)}: ${tests.length} self-test(s) + ` +
              `${batches.length} batch(es) in ${((Date.now() - t0) / 1000).toFixed(1)}s`)
}

main().catch(err => die(err.stack || String(err)))
