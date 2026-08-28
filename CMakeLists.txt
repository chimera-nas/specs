# SPDX-FileCopyrightText: 2026 The Quint Specs Authors
#
# SPDX-License-Identifier: MIT

# Model-based-test specifications.
#
# This repo owns the Quint models for the MBT suites (posix, nfs3, nfs4, smb2,
# nfsaux) and the logic that turns them into a corpus of ITF traces plus the
# model self-tests and coverage gates.  The replay harness that drives those
# traces against a server under test lives in the consuming project, which
# embeds this repo either as a prebuilt trace bundle (fetched by the submodule's
# git hash) or -- for spec development -- by building it locally.
#
# Building this project:
#   * `cmake --build` generates every trace (traces/<suite>/*.itf.json) and
#     runs the model self-tests as a build-time gate (a self-test failure stops
#     the corpus at the source).
#   * `ctest` runs the coverage gates over the generated corpus.
#   * `bundle.sh` tars traces/ into the artifact the consuming project fetches.
#
# Determinism: trace generation is reproducible only against a fixed quint
# version, recorded in .quint-version.  Both CI and a local build must use it
# (CI installs it; a developer should `npm i -g @informalsystems/quint@<ver>`).

cmake_minimum_required(VERSION 3.20)
project(specs NONE)
enable_testing()

find_program(QUINT_BIN quint REQUIRED)
find_package(Python3 COMPONENTS Interpreter REQUIRED)

file(READ ${CMAKE_CURRENT_SOURCE_DIR}/.quint-version PINNED_QUINT)
string(STRIP "${PINNED_QUINT}" PINNED_QUINT)

execute_process(COMMAND ${QUINT_BIN} --version
                OUTPUT_VARIABLE HAVE_QUINT OUTPUT_STRIP_TRAILING_WHITESPACE)
if(NOT HAVE_QUINT STREQUAL PINNED_QUINT)
    message(WARNING
        "quint ${HAVE_QUINT} does not match the pinned ${PINNED_QUINT}; "
        "generated traces may not be bit-identical to the published bundle.")
endif()
message(STATUS "specs: quint ${HAVE_QUINT} (pinned ${PINNED_QUINT})")

set(Q ${CMAKE_CURRENT_SOURCE_DIR}/quint)
set(T ${CMAKE_CURRENT_BINARY_DIR}/traces)

file(GLOB POSIX_QNT ${Q}/posix/*.qnt)
file(GLOB NFS_QNT   ${Q}/nfs/*.qnt)
file(GLOB SMB2_QNT  ${Q}/smb2/*.qnt)
file(GLOB NFSAUX_QNT ${Q}/nfsaux/*.qnt)
set(SMB2_DEPS ${SMB2_QNT} ${Q}/nfs/nfs4_fs.qnt)   # smb2 shares the nfs4 fs

set(ALL_TRACES)          # every generated trace, for the top-level target
set(SELFTEST_STAMPS)     # every self-test stamp, gating generation

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Model self-check (quint test): a bounded random walk with invariant checks.
# Produces a stamp so it reruns only when the model changes, and generation
# depends on it, so a model regression stops the corpus at the source.
function(specs_selftest name model mainarg samples deps_var)
    set(stamp ${CMAKE_CURRENT_BINARY_DIR}/${name}.stamp)
    if(mainarg STREQUAL "-")
        set(_main)
    else()
        set(_main --main=${mainarg})
    endif()
    add_custom_command(OUTPUT ${stamp}
        COMMAND ${QUINT_BIN} test --max-samples=${samples} ${_main} ${model} > /dev/null
        COMMAND ${CMAKE_COMMAND} -E touch ${stamp}
        DEPENDS ${${deps_var}}
        COMMENT "model self-test: ${name}"
        VERBATIM)
    set(SELFTEST_STAMPS ${SELFTEST_STAMPS} ${stamp} PARENT_SCOPE)
    set(SELFTEST_${name} ${stamp} PARENT_SCOPE)
endfunction()

# Generate `ntraces` traces from one (model, main, flavor, steps, seed) with a
# single quint invocation (--n-traces amortizes quint's node-startup cost over
# the batch).  `naming` is the output basename with a literal {seq} placeholder
# and no .itf.json suffix.  --invariant=inv gates every emitted trace.
function(specs_gen subdir model mainarg flavor steps ntraces seed naming gate_var deps_var)
    set(outdir ${T}/${subdir})
    if(mainarg STREQUAL "-")
        set(_main)
    else()
        set(_main --main=${mainarg})
    endif()
    set(traces)
    math(EXPR last "${ntraces} - 1")
    foreach(seq RANGE 0 ${last})
        string(REPLACE "{seq}" "${seq}" nm "${naming}")
        list(APPEND traces ${outdir}/${nm}.itf.json)
    endforeach()
    add_custom_command(OUTPUT ${traces}
        COMMAND ${CMAKE_COMMAND} -E make_directory ${outdir}
        COMMAND ${QUINT_BIN} run ${model} ${_main}
                --step=${flavor} --max-steps=${steps}
                --max-samples=${ntraces} --n-traces=${ntraces} --seed=${seed}
                --invariant=inv
                --out-itf=${outdir}/${naming}.itf.json > /dev/null
        DEPENDS ${${deps_var}} ${${gate_var}}
        COMMENT "generate ${ntraces} ${subdir} traces ${mainarg}/${flavor} steps=${steps}"
        VERBATIM)
    set(ALL_TRACES ${ALL_TRACES} ${traces} PARENT_SCOPE)
endfunction()

# ---------------------------------------------------------------------------
# POSIX  (models in quint/posix; instances select the backend profile)
# ---------------------------------------------------------------------------
specs_selftest(posixTestStd  ${Q}/posix/posixTest.qnt posixTestStd  100 POSIX_QNT)
specs_selftest(posixTestRoot ${Q}/posix/posixTest.qnt posixTestRoot 100 POSIX_QNT)
set(POSIX_GATE ${SELFTEST_posixTestStd} ${SELFTEST_posixTestRoot})

# instance | prefix (- = none) | flavor | steps | ntraces | seed
set(POSIX_BATCHES
  "posixMemfs|-|step|128|10|0x1"          "posixMemfs|-|step|128|6|0x2"
  "posixMemfs|-|step|256|3|0x100"         "posixMemfs|-|step|512|2|0x5"
  "posixMemfs|-|stepNamespace|128|4|0x1"  "posixMemfs|-|stepNamespace|256|2|0x9"
  "posixMemfs|-|stepDescriptors|128|4|0x1" "posixMemfs|-|stepMetadata|128|4|0x1"
  "posixMemfs|-|stepDirs|128|3|0x1"       "posixMemfs|-|stepData|128|4|0x1"
  "posixMemfs|-|stepLocks|128|2|0x1"      "posixMemfs|-|stepPerms|128|5|0x1"
  "posixMemfs|-|stepLinks|128|5|0x1"      "posixMemfs|-|stepFds|128|5|0x1"
  "posixMemfs|-|stepTooLong|128|4|0x1"    "posixMemfs|-|stepPrefix|128|5|0x1"
  "posixMemfs|-|stepFallocate|128|4|0x1"
  "posixNfs3|nfs3_|step|128|10|0x1"       "posixNfs3|nfs3_|step|128|6|0x2"
  "posixNfs3|nfs3_|step|256|3|0x100"      "posixNfs3|nfs3_|stepNamespace|128|4|0x1"
  "posixNfs3|nfs3_|stepDescriptors|128|4|0x1" "posixNfs3|nfs3_|stepMetadata|128|4|0x1"
  "posixNfs3|nfs3_|stepDirs|128|3|0x1"    "posixNfs3|nfs3_|stepData|128|4|0x1"
  "posixNfs3|nfs3_|stepPerms|128|5|0x1"   "posixNfs3|nfs3_|stepLinks|128|5|0x1"
  "posixNfs3|nfs3_|stepFds|128|5|0x1"
  "posixNfs4|nfs4_|step|128|10|0x1"       "posixNfs4|nfs4_|step|128|6|0x2"
  "posixNfs4|nfs4_|step|256|3|0x100"      "posixNfs4|nfs4_|stepNamespace|128|4|0x1"
  "posixNfs4|nfs4_|stepDescriptors|128|4|0x1" "posixNfs4|nfs4_|stepMetadata|128|4|0x1"
  "posixNfs4|nfs4_|stepDirs|128|3|0x1"    "posixNfs4|nfs4_|stepData|128|4|0x1"
  "posixNfs4|nfs4_|stepPerms|128|5|0x1"   "posixNfs4|nfs4_|stepLinks|128|5|0x1"
  "posixNfs4|nfs4_|stepFds|128|5|0x1"
  "posixDisk|disk_|step|128|10|0x1"       "posixDisk|disk_|step|128|6|0x2"
  "posixDisk|disk_|step|256|3|0x100"      "posixDisk|disk_|step|512|2|0x5"
  "posixDisk|disk_|stepNamespace|128|4|0x1" "posixDisk|disk_|stepNamespace|256|2|0x9"
  "posixDisk|disk_|stepDescriptors|128|4|0x1" "posixDisk|disk_|stepMetadata|128|4|0x1"
  "posixDisk|disk_|stepDirs|128|3|0x1"    "posixDisk|disk_|stepData|128|4|0x1"
  "posixDisk|disk_|stepLocks|128|2|0x1"   "posixDisk|disk_|stepPerms|128|5|0x1"
  "posixDisk|disk_|stepLinks|128|5|0x1"   "posixDisk|disk_|stepFds|128|5|0x1"
  "posixFuse|fuse_|step|128|10|0x1"       "posixFuse|fuse_|step|128|6|0x2"
  "posixFuse|fuse_|step|256|3|0x100"      "posixFuse|fuse_|step|512|2|0x5"
  "posixFuse|fuse_|stepNamespace|128|4|0x1" "posixFuse|fuse_|stepNamespace|256|2|0x9"
  "posixFuse|fuse_|stepDescriptors|128|4|0x1" "posixFuse|fuse_|stepMetadata|128|4|0x1"
  "posixFuse|fuse_|stepDirs|128|3|0x1"    "posixFuse|fuse_|stepData|128|4|0x1"
  "posixFuse|fuse_|stepLocks|128|2|0x1"   "posixFuse|fuse_|stepPerms|128|5|0x1"
  "posixFuse|fuse_|stepLinks|128|5|0x1"   "posixFuse|fuse_|stepFds|128|5|0x1"
  "posixFuse|fuse_|stepTooLong|128|4|0x1" "posixFuse|fuse_|stepPrefix|128|5|0x1"
  "posixFuse|fuse_|stepFallocate|128|4|0x1"
)
foreach(b ${POSIX_BATCHES})
    string(REPLACE "|" ";" parts "${b}")
    list(GET parts 0 inst)
    list(GET parts 1 pfx)
    list(GET parts 2 flavor)
    list(GET parts 3 steps)
    list(GET parts 4 nt)
    list(GET parts 5 seed)
    if(pfx STREQUAL "-")
        set(pfx "")
    endif()
    specs_gen(posix ${Q}/posix/posix_run.qnt ${inst} ${flavor} ${steps} ${nt}
              ${seed} "${pfx}${flavor}_${steps}_${seed}_{seq}"
              POSIX_GATE POSIX_QNT)
endforeach()

# ---------------------------------------------------------------------------
# NFS3  (nfs3.qnt is the run model directly; no --main)
# ---------------------------------------------------------------------------
specs_selftest(nfs3Test ${Q}/nfs/nfs3Test.qnt - 500 NFS_QNT)
set(NFS3_BATCHES
  "step|128|10|0x1"  "step|256|3|0x100"  "stepChurn|128|6|0x1"
  "stepChurn|256|2|0x200"  "stepDir|128|4|0x1"  "stepExcl|128|3|0x1")
foreach(b ${NFS3_BATCHES})
    string(REPLACE "|" ";" parts "${b}")
    list(GET parts 0 flavor)
    list(GET parts 1 steps)
    list(GET parts 2 nt)
    list(GET parts 3 seed)
    specs_gen(nfs3 ${Q}/nfs/nfs3.qnt - ${flavor} ${steps} ${nt} ${seed}
              "${flavor}_${steps}_{seq}" SELFTEST_nfs3Test NFS_QNT)
endforeach()

# ---------------------------------------------------------------------------
# NFS4  (nfs4_run.qnt with per-minorversion / delegation instances)
# ---------------------------------------------------------------------------
specs_selftest(nfs4Test42 ${Q}/nfs/nfs4Test.qnt nfs4Test42 200 NFS_QNT)
specs_selftest(nfs4Test40 ${Q}/nfs/nfs4Test.qnt nfs4Test40 200 NFS_QNT)
set(NFS4_GATE ${SELFTEST_nfs4Test42} ${SELFTEST_nfs4Test40})
# 8 traces per flavor rather than 6: the rare error branches the model now
# reaches (BADNAME/BADCHAR/NAMETOOLONG, the compound-tag rejections, the
# session-position rules) land only a handful of times per corpus, and a
# behaviour sampled 2-3 times is one generator tweak away from vanishing.
# stepTypes is the object-type matrix -- every type-gated op driven against
# directories, symlinks, FIFOs, sockets and device nodes as well as the type
# it expects.
foreach(inst nfs4Memfs42 nfs4Memfs41 nfs4Memfs40)
    foreach(fs step stepState stepNamespace stepData)
        specs_gen(nfs4 ${Q}/nfs/nfs4_run.qnt ${inst} ${fs} 80 8 0x7
                  "${inst}_${fs}_80_{seq}" NFS4_GATE NFS_QNT)
    endforeach()
    specs_gen(nfs4 ${Q}/nfs/nfs4_run.qnt ${inst} stepTypes 80 6 0x7
              "${inst}_stepTypes_80_{seq}" NFS4_GATE NFS_QNT)
endforeach()
# RFC 7862 data operations (READ_PLUS, IO_ADVISE, WRITE_SAME, CLONE).  4.2
# only: every action in the flavor guards on MINOR >= 2, so the 4.0/4.1
# instances would generate setup churn and nothing else.
specs_gen(nfs4 ${Q}/nfs/nfs4_run.qnt nfs4Memfs42 stepData42 80 8 0x7
          "nfs4Memfs42_stepData42_80_{seq}" NFS4_GATE NFS_QNT)

foreach(inst nfs4Memfs42Deleg nfs4Memfs41Deleg)
    specs_gen(nfs4 ${Q}/nfs/nfs4_run.qnt ${inst} stepDeleg 80 10 0x7
              "${inst}_stepDeleg_80_{seq}" NFS4_GATE NFS_QNT)
endforeach()

# ---------------------------------------------------------------------------
# SMB2  (smb2_run.qnt; depends on the shared nfs4_fs substrate too)
# ---------------------------------------------------------------------------
specs_selftest(smb2Test ${Q}/smb2/smb2Test.qnt smb2Test 200 SMB2_DEPS)
# Six registered batches.  Depth is capped per flavor by what replays green
# against the live server, not by taste: stepCore/stepReq/stepInfo/stepNs
# sustain 500 steps, stepDir 240, and stepDurable breaks at 180 on the Q-4
# caching-lifecycle family (see the chimera tree's DEVIATIONS-SMB.md).
# smb2Replay/stepReplay is deliberately absent -- Q-13 makes affected traces
# nondeterministic, so registering it would trade trust for coverage.
specs_gen(smb2 ${Q}/smb2/smb2_run.qnt smb2Base stepCore 500 8 0x7
          "smb2Base_stepCore_500_0x7_{seq}" SELFTEST_smb2Test SMB2_DEPS)
specs_gen(smb2 ${Q}/smb2/smb2_run.qnt smb2Base stepReq 500 8 0x11
          "smb2Base_stepReq_500_0x11_{seq}" SELFTEST_smb2Test SMB2_DEPS)
specs_gen(smb2 ${Q}/smb2/smb2_run.qnt smb2Base stepDir 240 8 0x5
          "smb2Base_stepDir_240_0x5_{seq}" SELFTEST_smb2Test SMB2_DEPS)
specs_gen(smb2 ${Q}/smb2/smb2_run.qnt smb2Base stepInfo 500 8 0x9
          "smb2Base_stepInfo_500_0x9_{seq}" SELFTEST_smb2Test SMB2_DEPS)
specs_gen(smb2 ${Q}/smb2/smb2_run.qnt smb2Base stepNs 500 8 0xd
          "smb2Base_stepNs_500_0xd_{seq}" SELFTEST_smb2Test SMB2_DEPS)
# smb2Durable/stepDurable is NOT generated, for the same reason
# smb2Replay/stepReplay is not: it does not replay green in this harness.  A
# durable handle is PARKED across a transport drop by design, so it outlives
# the connection -- and the batch replayer tears the share and filesystem down
# after every trace.  chimera_smb_remove_share() frees the share and destroys
# its sharemode table with no regard for opens still referencing it, giving a
# heap-use-after-free in chimera_smb_sharemode_release(); keeping the share
# instead just moves the problem to rmfs, which then spins on EBUSY until the
# parked handle's 60 s durable timeout.  The durable MODEL and its
# ground-truth probe (smb2_durable_probe) both ship and pass; only the
# generated batch is withheld until the share/handle lifetime is settled.
# specs_gen(smb2 ${Q}/smb2/smb2_run.qnt smb2Durable stepDurable 160 8 0x41
#           "smb2Durable_stepDurable_160_0x41_{seq}" SELFTEST_smb2Test SMB2_DEPS)

# ---------------------------------------------------------------------------
# NFSAUX -- the four protocols that surround NFSv3: portmap/rpcbind, MOUNT,
# NLM and NSM (nfsaux_run.qnt; nfsauxRef is the profile a real server matches).
#
# Three self-tests, not one: the reference profile, the everything-implemented
# profile that keeps the RFC semantics of the procedures a minimal server
# refuses under test, and the grace-window profile.  Only the reference
# profile generates traces -- it is the only one a server matches.
# ---------------------------------------------------------------------------
specs_selftest(nfsauxTestRef   ${Q}/nfsaux/nfsauxTest.qnt nfsauxTestRef   200 NFSAUX_QNT)
specs_selftest(nfsauxTestFull  ${Q}/nfsaux/nfsauxTest.qnt nfsauxTestFull  200 NFSAUX_QNT)
specs_selftest(nfsauxTestGrace ${Q}/nfsaux/nfsauxTest.qnt nfsauxTestGrace 200 NFSAUX_QNT)
set(NFSAUX_GATE ${SELFTEST_nfsauxTestRef} ${SELFTEST_nfsauxTestFull}
                ${SELFTEST_nfsauxTestGrace})

# flavor | steps | ntraces | seed.  The per-protocol flavors keep a divergence
# legible (a portmap trace fails on portmap); the mixed `step` flavor is what
# reaches the seams between them.
set(NFSAUX_BATCHES
  "stepPortmap|200|4|0x1"  "stepMount|200|4|0x2"
  "stepLocks|200|6|0x3"    "stepAsync|150|4|0x4"
  "stepRecovery|200|6|0x5" "stepShare|150|3|0x6"
  "stepBlocking|200|6|0x9"
  "step|200|6|0x7"         "step|300|3|0x8")
foreach(b ${NFSAUX_BATCHES})
    string(REPLACE "|" ";" parts "${b}")
    list(GET parts 0 flavor)
    list(GET parts 1 steps)
    list(GET parts 2 nt)
    list(GET parts 3 seed)
    specs_gen(nfsaux ${Q}/nfsaux/nfsaux_run.qnt nfsauxRef ${flavor} ${steps}
              ${nt} ${seed} "${flavor}_${steps}_${seed}_{seq}"
              NFSAUX_GATE NFSAUX_QNT)
endforeach()

# ---------------------------------------------------------------------------
# Aggregate + bundle
# ---------------------------------------------------------------------------
add_custom_target(specs_traces ALL DEPENDS ${ALL_TRACES})

add_custom_target(bundle
    COMMAND ${CMAKE_COMMAND} -E env QUINT_VERSION=${PINNED_QUINT}
            bash ${CMAKE_CURRENT_SOURCE_DIR}/bundle.sh ${T} ${CMAKE_CURRENT_BINARY_DIR}
    DEPENDS specs_traces
    COMMENT "bundling traces + manifest"
    VERBATIM)

# Coverage gates (ctest): classify the generated corpus into behavior buckets
# and fail if any is never exercised.
add_test(NAME coverage/nfs3
    COMMAND ${Python3_EXECUTABLE} ${Q}/nfs/coverage.py
            --fail-on-starved --glob "${T}/nfs3/*.itf.json")
add_test(NAME coverage/smb2
    COMMAND ${Python3_EXECUTABLE} ${Q}/smb2/coverage.py ${T}/smb2)
add_test(NAME coverage/nfsaux
    COMMAND ${Python3_EXECUTABLE} ${Q}/nfsaux/coverage.py ${T}/nfsaux)

# The NFSv4 gate is a *ratchet* rather than a fixed bucket list.  The v4
# generator keeps growing, and every branch added to a step flavor shifts the
# random walk's draw sequence, so a behaviour that used to be produced can
# quietly stop being produced.  The baseline records what a known-good corpus
# generates: anything in it that disappears fails, and anything new is
# reported so the baseline is raised deliberately (coverage.py --write-expect)
# rather than by drift.
add_test(NAME coverage/nfs4
    COMMAND ${Python3_EXECUTABLE} ${Q}/nfs/coverage.py --proto 4
            --expect ${Q}/nfs/nfs4_coverage_baseline.txt
            --glob "${T}/nfs4/*.itf.json")
