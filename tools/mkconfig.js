#!/usr/bin/env node
// SPDX-FileCopyrightText: 2026 The Quint Specs Authors
// SPDX-License-Identifier: MIT
//
// Turn a consumer's corpus CONFIGS into the quint that generates their traces.
//
// WHY THIS EXISTS
//
// A model family declares constants -- optional features, policy choices where
// the standard permits several behaviours, and (later) tolerances and known
// deviations.  Binding those constants used to mean hand-writing an instance
// module per profile inside this repo, which put the consumer's facts in the
// producer's tree: `posixNfs3`, `posixFuse` and `nfs4Memfs42Deleg` are
// statements about chimera that lived in a repo describing POSIX and NFS.
//
// Now a consumer writes a CONFIG -- JSON, validated against the family's
// corpus.schema.json -- and this script renders it into the instance module
// quint needs.  The config is the unit: it fixes every constant AND carries the
// batch list, so one config fully determines one corpus, and the cell that
// replays that corpus expects all of it to match.
//
// WHAT IT PRODUCES, all at CONFIGURE time
//
//   <stage>/quint/<family>/cfg_<cell>.qnt   one instance module per cell
//   <stage>/quint/<family>/<family>_cfg_all.qnt
//                                           the umbrella naming every cell
//                                           module and every self-test module,
//                                           so ONE elaboration serves them all
//   <stage>/<family>.gen.json               the spec tools/gen.js consumes
//   <stage>/<family>.cmake                  trace paths + deps, for CMake to
//                                           include() and turn into build edges
//
// THE STAGING TREE
//
// quint resolves `import ... from` RELATIVE TO THE IMPORTING FILE, and an
// absolute path does not parse at all (checked against 0.32.0).  A generated
// module in the build tree therefore cannot name the model directly.  So the
// stage mirrors quint/ with symlinks -- every family directory, every .qnt file
// -- and the generated modules are written INTO that mirror.  Then `./posix`
// and `../nfs/nfs4_fs` resolve exactly as they do in the source tree, and
// nothing depends on where the build directory sits.
//
// One more constraint from the same check: two instances of one module cannot
// share a file, so every cell gets its own file, and the umbrella imports each
// under an alias.  `--main` still selects an aliased module.
//
// Usage:
//   mkconfig.js <spec.json>
// where spec.json is written by SpecsCorpus.cmake:
//   { "family": "...", "schema": "...", "specsRoot": "...", "stage": "...",
//     "corpusRoot": "...", "quintCli": "...",
//     "cells": [ { "name": "nfs/drc_memfs", "config": "/abs/path.json" } ] }

const fs = require('fs')
const path = require('path')

function die(msg) {
  console.error(`mkconfig.js: ${msg}`)
  process.exit(1)
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

function readJson(p, what) {
  let text
  try {
    text = fs.readFileSync(p, 'utf8')
  } catch (err) {
    die(`cannot read ${what} ${p}: ${err.message}`)
  }
  // Strip //-comments so a config can explain itself.  Only at the start of a
  // line (after whitespace): a bare // inside a string stays untouched.
  text = text.replace(/^\s*\/\/.*$/gm, '')
  try {
    return JSON.parse(text)
  } catch (err) {
    die(`cannot parse ${what} ${p}: ${err.message}`)
  }
}

// Write only when the content changes.  Everything here runs at configure time
// and feeds build edges; rewriting an identical file would make ninja
// regenerate a corpus that has not changed.
function writeIfDifferent(p, content) {
  try {
    if (fs.readFileSync(p, 'utf8') === content) {
      return false
    }
  } catch (err) { /* absent or unreadable: write it */ }
  fs.mkdirSync(path.dirname(p), { recursive: true })
  fs.writeFileSync(p, content)
  return true
}

// The SPDX header the generated modules carry.  Assembled from a prefix rather
// than written out literally, because `reuse lint` scans file CONTENT for those
// tags: spelled in full inside a string literal, the licence tag would be read
// as THIS file's own licence, and the expression it saw would run on into the
// closing quote and fail to parse.
const SPDX_TAG = 'SPDX-'
const GENERATED_HEADER = [
  `// ${SPDX_TAG}FileCopyrightText: 2026 The Quint Specs Authors`,
  `// ${SPDX_TAG}License-Identifier: MIT`,
]

// A cell name is a path ("posix/nfs3_diskfs"); its module name has to be a
// quint identifier.
function moduleNameOf(cell) {
  return 'cfg_' + cell.replace(/[^A-Za-z0-9]+/g, '_')
}

// ---------------------------------------------------------------------------
// Config resolution: `extends` chains, then schema validation
// ---------------------------------------------------------------------------

const KINDS = ['features', 'policies', 'tolerances']

// Merge child over parent, one level into each kind bucket.  `batches` and
// scalar fields replace wholesale; a child that wants the parent's batches
// simply omits the key.
function mergeConfig(parent, child) {
  const out = Object.assign({}, parent, child)
  for (const kind of KINDS) {
    out[kind] = Object.assign({}, parent[kind] || {}, child[kind] || {})
  }
  // Deviations are a set: a child may add with "deviations" or subtract with
  // "deviationsOff", which is what lets a fixed-in-one-backend deviation be
  // retired for that cell alone.
  const base = new Set(parent.deviations || [])
  for (const d of child.deviations || []) base.add(d)
  for (const d of child.deviationsOff || []) base.delete(d)
  out.deviations = [...base].sort()
  delete out.deviationsOff
  return out
}

function resolveConfig(p, seen) {
  seen = seen || []
  const abs = path.resolve(p)
  if (seen.includes(abs)) {
    die(`extends cycle: ${seen.concat(abs).join(' -> ')}`)
  }
  const cfg = readJson(abs, 'config')
  const chain = [abs]
  if (!cfg.extends) {
    for (const kind of KINDS) cfg[kind] = cfg[kind] || {}
    cfg.deviations = cfg.deviations || []
    return { cfg, chain }
  }
  const parentPath = path.resolve(path.dirname(abs), cfg.extends)
  const parent = resolveConfig(parentPath, seen.concat(abs))
  delete cfg.extends
  return {
    cfg: mergeConfig(parent.cfg, cfg),
    chain: parent.chain.concat(chain),
  }
}

// Render one config value as a quint expression, per the schema's declared type.
function renderValue(constName, decl, value) {
  switch (decl.type) {
    case 'bool':
      if (typeof value !== 'boolean') {
        die(`${constName}: expected a boolean, got ${JSON.stringify(value)}`)
      }
      return value ? 'true' : 'false'
    case 'int':
      if (!Number.isInteger(value)) {
        die(`${constName}: expected an integer, got ${JSON.stringify(value)}`)
      }
      return String(value)
    case 'str':
      if (typeof value !== 'string') {
        die(`${constName}: expected a string, got ${JSON.stringify(value)}`)
      }
      return JSON.stringify(value)
    case 'enum': {
      if (!decl.values || !Object.prototype.hasOwnProperty.call(decl.values, value)) {
        die(`${constName}: ${JSON.stringify(value)} is not one of ` +
            `${Object.keys(decl.values || {}).join(', ')}`)
      }
      return decl.values[value]
    }
    case 'devset': {
      // The enabled-deviation set, rendered as a quint Set[str].  ONE const
      // per family rather than a const per deviation: a model that grows a
      // deviation then needs no schema signature change, and a config names
      // only what it enables.  The model asks `dev("PD3")`; see the family's
      // deviations block in corpus.schema.json for what each id means.
      if (!Array.isArray(value)) {
        die(`${constName}: deviations must be a list of ids`)
      }
      const known = decl.known || {}
      for (const id of value) {
        if (!Object.prototype.hasOwnProperty.call(known, id)) {
          die(`unknown deviation "${id}": the ${decl.family || 'family'} schema ` +
              `declares ${Object.keys(known).sort().join(', ') || '(none)'}. ` +
              `A deviation must be declared -- with a citation -- before a ` +
              `config may enable it.`)
        }
      }
      const ids = [...value].sort()
      return ids.length ? `Set(${ids.map(i => JSON.stringify(i)).join(', ')})`
                        : 'Set()'
    }
    case 'raw':
      // The config supplies a quint expression verbatim.  The escape hatch for
      // structured constants (Set[str], int -> str, List[Mapping]) that no
      // JSON-to-quint mapping would express more clearly than the quint itself.
      if (typeof value !== 'string') {
        die(`${constName}: a raw constant takes a quint expression as a string`)
      }
      return value
    default:
      die(`${constName}: unknown schema type ${decl.type}`)
  }
}

// Pull `features.copyRange` out of the resolved config.
function lookup(cfg, key) {
  const parts = key.split('.')
  let cur = cfg
  for (const part of parts) {
    if (cur === undefined || cur === null) return undefined
    cur = cur[part]
  }
  return cur
}

function bindConsts(schema, cfg, cellName) {
  const bindings = []
  for (const [constName, declared] of Object.entries(schema.consts || {})) {
    let decl = declared
    let value = lookup(cfg, decl.key)
    if (decl.type === 'devset') {
      // The strict twin: same config, every deviation off.  Its failures ARE
      // the conformance debt, re-measured on every run instead of remembered
      // in a registry -- which is what stops a deviation outliving its fix.
      value = cfg.__strict ? [] : (value || [])
      decl = Object.assign({ family: schema.family }, decl)
    }
    if (value === undefined) {
      if (!Object.prototype.hasOwnProperty.call(decl, 'default')) {
        // Deliberate: a model that grows a constant makes every consumer say
        // what it does with it, rather than silently inheriting someone's idea
        // of a default.
        die(`${cellName}: ${decl.key} is unset and ${constName} has no default`)
      }
      value = decl.default
    }
    bindings.push(`        ${constName} = ${renderValue(constName, decl, value)}`)
  }
  return bindings
}

// Flag config keys the schema does not know about.  A typo in a knob name
// would otherwise be silently ignored and the cell would generate the default
// corpus while claiming to test something else.
function checkUnknownKeys(schema, cfg, cellName) {
  const known = new Set()
  for (const decl of Object.values(schema.consts || {})) known.add(decl.key)
  for (const kind of KINDS) {
    for (const name of Object.keys(cfg[kind] || {})) {
      const key = `${kind}.${name}`
      if (!known.has(key)) {
        die(`${cellName}: ${key} is not a knob of the ${schema.family} model ` +
            `(known: ${[...known].sort().join(', ')})`)
      }
    }
  }
}

// ---------------------------------------------------------------------------
// The staging mirror
// ---------------------------------------------------------------------------

// Mirror quint/ into the stage with symlinks, so relative imports -- both
// "./posix" within a family and "../nfs/nfs4_fs" across families -- resolve
// unchanged from the generated modules written alongside them.
function stageSources(specsRoot, stage) {
  const src = path.join(specsRoot, 'quint')
  const dst = path.join(stage, 'quint')
  for (const family of fs.readdirSync(src)) {
    const famSrc = path.join(src, family)
    if (!fs.statSync(famSrc).isDirectory()) continue
    const famDst = path.join(dst, family)
    fs.mkdirSync(famDst, { recursive: true })
    for (const f of fs.readdirSync(famSrc)) {
      if (!f.endsWith('.qnt')) continue
      const link = path.join(famDst, f)
      const target = path.join(famSrc, f)
      let current = null
      try { current = fs.readlinkSync(link) } catch (err) { /* absent */ }
      if (current === target) continue
      try { fs.unlinkSync(link) } catch (err) { /* absent */ }
      fs.symlinkSync(target, link)
    }
  }
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

function renderCell(schema, cfg, cellName, modName) {
  const bindings = bindConsts(schema, cfg, cellName)
  // A strict twin binds DEVS = Set() whatever the config lists, so reporting the
  // config's list here would have the header contradict the code underneath it.
  const devs = cfg.__strict ? [] : (cfg.deviations || [])

  const head = [
    ...GENERATED_HEADER,
    '//',
    `// GENERATED by tools/mkconfig.js from the ${schema.family} config for cell`,
    `// ${cellName}.  Do not edit: edit the config, which is the thing that`,
    '// says what the implementation under test does.',
    '//',
  ]
  if (cfg.description) {
    head.push(`// ${cfg.description.replace(/\n/g, '\n// ')}`)
  }
  if (cfg.__strict) {
    head.push('//',
              '// STRICT TWIN: every deviation is off (DEVS = Set()) regardless of what',
              '// the config enables.  Replaying this corpus measures the conformance debt',
              '// directly -- each failure is a deviation that is still live.')
  } else if (devs.length) {
    head.push('//', `// Deviations enabled: ${devs.join(', ')}`)
  }

  const body = [`module ${modName} {`]
  for (const line of schema.prelude || []) {
    body.push(`    ${line}`)
  }
  if ((schema.prelude || []).length) {
    body.push('')
  }
  if (bindings.length === 0) {
    // A model that declares no constants takes no argument list at all --
    // `import m().*` is a syntax error, not an empty instantiation.  nfs3 and
    // s3 are in this shape today: they were generated with no --main because
    // there was nothing to parameterise.  They still get a cell module, because
    // that is what gives each cell its own corpus.
    body.push(`    import ${schema.modelModule}.* from "${schema.modelFile}"`)
  } else {
    body.push(`    import ${schema.modelModule}(`)
    body.push(bindings.join(',\n'))
    body.push(`    ).* from "${schema.modelFile}"`)
  }
  body.push('}', '')

  return head.concat(body).join('\n')
}

function renderUmbrella(schema, cells) {
  const lines = []
  for (const l of GENERATED_HEADER) lines.push(l)
  lines.push('//')
  lines.push(`// GENERATED umbrella for the ${schema.family} family.  It names every cell`)
  lines.push('// module and every self-test module, which is what lets tools/gen.js elaborate')
  lines.push('// the family ONCE and then drive every batch and every self-test against the')
  lines.push('// same typechecked stage.  Elaboration is 38-70% of a family\'s generation')
  lines.push('// cost and does not grow with cells; simulation does.')
  lines.push('//')
  lines.push('// Everything is imported under an alias: two instances of one module cannot')
  lines.push('// share a file, and `--main` selects an aliased module perfectly well.')
  lines.push(`module ${schema.family}CfgAll {`)
  let n = 0
  for (const c of cells) {
    lines.push(`    import ${c.modName} as _c${n++} from "./${c.modName}"`)
  }
  for (const t of schema.selfTests || []) {
    lines.push(`    import ${t.module} as _t${n++} from "${t.file}"`)
  }
  lines.push('}')
  lines.push('')
  return lines.join('\n')
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

const specPath = process.argv[2]
if (!specPath) die('usage: mkconfig.js <spec.json>')
const spec = readJson(specPath, 'spec')

const schemaPath = spec.schema
const schema = readJson(schemaPath, 'schema')
if (schema.family !== spec.family) {
  die(`schema ${schemaPath} is for family ${schema.family}, not ${spec.family}`)
}

stageSources(spec.specsRoot, spec.stage)

const famStage = path.join(spec.stage, 'quint', spec.family)
fs.mkdirSync(famStage, { recursive: true })

const cells = []
const cmakeLines = []
const genBatches = []
let allDeps = new Set([schemaPath, path.resolve(__filename)])

for (const cell of spec.cells) {
  const { cfg, chain } = resolveConfig(cell.config)
  if (cell.strict) {
    cfg.__strict = true
    if (cfg.description) {
      cfg.description = `STRICT TWIN (all deviations off) of: ${cfg.description}`
    }
  }
  for (const c of chain) allDeps.add(c)
  if (cfg.family && cfg.family !== spec.family) {
    die(`${cell.name}: config declares family ${cfg.family}, registered as ${spec.family}`)
  }
  checkUnknownKeys(schema, cfg, cell.name)

  const modName = moduleNameOf(cell.name)
  writeIfDifferent(path.join(famStage, `${modName}.qnt`),
                   renderCell(schema, cfg, cell.name, modName))
  cells.push({ name: cell.name, modName })

  const batches = cfg.batches || schema.defaultBatches
  if (!batches || !batches.length) {
    die(`${cell.name}: no batches (set "batches" in the config or ` +
        `"defaultBatches" in the schema)`)
  }
  // The trace stem keeps a name attributable and keeps the coverage gates
  // working: smb2's coverage.py groups buckets by parsing <stem>_<flavor>_ out
  // of the basename.  Defaults to the cell's leaf name.
  const stem = cfg.traceStem || cell.name.split('/').pop()
  const outdir = path.join(spec.corpusRoot, cell.name)
  const traces = []
  for (const b of batches) {
    if (b.flavor === undefined || b.steps === undefined ||
        b.traces === undefined || b.seed === undefined) {
      die(`${cell.name}: a batch needs flavor, steps, traces and seed`)
    }
    const naming = `${stem}_${b.flavor}_${b.steps}_${b.seed}_{seq}`
    for (let i = 0; i < b.traces; i++) {
      traces.push(path.join(outdir, naming.replace('{seq}', String(i)) + '.itf.json'))
    }
    genBatches.push({
      outdir,
      main: modName,
      step: b.flavor,
      maxSteps: b.steps,
      nTraces: b.traces,
      seed: b.seed,
      naming,
    })
  }
  const varName = cell.name.replace(/[^A-Za-z0-9]+/g, '_')
  cmakeLines.push(`set(SPECS_CELL_${varName}_DIR "${outdir}")`)
  cmakeLines.push(`set(SPECS_CELL_${varName}_TRACES "${traces.join(';')}")`)
}

const umbrella = path.join(famStage, `${spec.family}_cfg_all.qnt`)
writeIfDifferent(umbrella, renderUmbrella(schema, cells))

// The gen.js spec: self-tests first (they gate the corpus at the source), then
// every cell's batches, all against one elaboration.
const genSpec = {
  quintCli: spec.quintCli,
  // Which simulator backend gen.js drives.  See the note there: typescript is
  // the default because the rust evaluator will not run on every CI image.
  backend: spec.backend || 'typescript',
  model: umbrella,
  tests: (schema.selfTests || []).map(t => ({
    name: t.name,
    main: t.module,
    maxSamples: t.maxSamples || 200,
  })),
  batches: genBatches,
}
writeIfDifferent(path.join(spec.stage, `${spec.family}.gen.json`),
                 JSON.stringify(genSpec, null, 2) + '\n')

// Everything the family's build edge depends on: the model sources, the
// configs (whole extends chain), the schema, and this script.
for (const f of fs.readdirSync(path.join(spec.specsRoot, 'quint', spec.family))) {
  if (f.endsWith('.qnt')) {
    allDeps.add(path.join(spec.specsRoot, 'quint', spec.family, f))
  }
}
for (const extra of schema.extraSources || []) {
  allDeps.add(path.resolve(path.join(spec.specsRoot, 'quint', spec.family), extra))
}

const allTraces = []
for (const b of genBatches) {
  for (let i = 0; i < b.nTraces; i++) {
    allTraces.push(path.join(b.outdir, b.naming.replace('{seq}', String(i)) + '.itf.json'))
  }
}

cmakeLines.unshift(`set(SPECS_${spec.family}_GENSPEC "${path.join(spec.stage, `${spec.family}.gen.json`)}")`)
cmakeLines.unshift(`set(SPECS_${spec.family}_DEPS "${[...allDeps].join(';')}")`)
cmakeLines.unshift(`set(SPECS_${spec.family}_ALL_TRACES "${allTraces.join(';')}")`)
cmakeLines.unshift('# GENERATED by tools/mkconfig.js -- do not edit.')
writeIfDifferent(path.join(spec.stage, `${spec.family}.cmake`),
                 cmakeLines.join('\n') + '\n')

console.log(`mkconfig: ${spec.family}: ${cells.length} cell(s), ` +
            `${genBatches.length} batch(es), ${allTraces.length} trace(s)`)
