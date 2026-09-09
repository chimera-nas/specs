# SPDX-FileCopyrightText: 2026 The Quint Specs Authors
#
# SPDX-License-Identifier: MIT

# Model-based-test specifications.
#
# This repo owns the Quint models for the MBT suites (posix, nfs3, nfs4, smb2,
# nfsaux, s3) and the logic that turns them into a corpus of ITF traces plus the
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
#
# Determinism: trace generation is reproducible only against a fixed quint
# version, recorded in .quint-version.  Both CI and a local build must use it
# (CI installs it; a developer should `npm i -g @informalsystems/quint@<ver>`).

cmake_minimum_required(VERSION 3.20)
project(specs NONE)
enable_testing()

find_program(QUINT_BIN quint REQUIRED)
# tools/gen.js drives quint's staged API directly; see the specs_gen comment.
find_program(NODE_BIN NAMES node nodejs REQUIRED)
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

# The corpus API this repo exports: specs_corpus() / specs_corpus_finalize().
# A consuming project registers one cell per config and calls finalize once;
# see cmake/SpecsCorpus.cmake.  Included unconditionally so a consumer that
# add_subdirectory()s this repo gets the functions.
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/SpecsCorpus.cmake)

# The legacy whole-repo corpus -- one static trace set per model, carved at
# replay time by filename prefix -- is being replaced by config-driven per-cell
# corpora.  It still builds when specs is the top-level project, because this
# repo's own conformance suites (samba, ganesha, knfsd) and coverage gates read
# it and have not been converted yet.  A CONSUMER gets none of it: its cells
# come from its own configs, and generating a second corpus it will not replay
# is pure cost.
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    set(SPECS_LEGACY_CORPUS ON)
else()
    set(SPECS_LEGACY_CORPUS OFF)
endif()

set(Q ${CMAKE_CURRENT_SOURCE_DIR}/quint)
# Where the trace corpus lives.  Normally it is generated into the build tree;
# SPECS_TRACES_DIR points at a corpus produced elsewhere instead, which is how
# the conformance jobs replay the exact bytes the build job generated, gated and
# published rather than three independent regenerations of their own.
set(SPECS_TRACES_DIR "" CACHE PATH
    "Replay a prebuilt trace corpus at this path instead of generating one")
if(SPECS_TRACES_DIR)
    set(T ${SPECS_TRACES_DIR})
    message(STATUS "specs: replaying the prebuilt corpus at ${T} (generation disabled)")
else()
    set(T ${CMAKE_CURRENT_BINARY_DIR}/traces)
endif()

file(GLOB POSIX_QNT ${Q}/posix/*.qnt)
file(GLOB NFS_QNT   ${Q}/nfs/*.qnt)
file(GLOB SMB2_QNT  ${Q}/smb2/*.qnt)
file(GLOB NFSAUX_QNT ${Q}/nfsaux/*.qnt)
set(SMB2_DEPS ${SMB2_QNT} ${Q}/nfs/nfs4_fs.qnt)   # smb2 shares the nfs4 fs
file(GLOB S3_QNT    ${Q}/s3/*.qnt)

set(ALL_TRACES)          # every generated trace, for the top-level target
set(SELFTEST_STAMPS)     # every self-test stamp, gating generation

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Model self-check (quint test): a bounded random walk with invariant checks.
# Produces a stamp so it reruns only when the model changes, and generation
# depends on it, so a model regression stops the corpus at the source.
# Map any model file in a family to that family's umbrella entry point:
# <dir>/<stem>_all.qnt, where the stem drops a _run or Test suffix.  So
# posix_run.qnt and posixTest.qnt both resolve to posix/posix_all.qnt, and
# nfs3.qnt / nfs4_run.qnt resolve to different umbrellas despite sharing a
# directory.  The umbrella names one module from each file, which is enough for
# quint's resolver to pull both -- and their shared base -- into one module
# tree, so a family is elaborated once for its tests AND its generation.
function(specs_umbrella model out)
    get_filename_component(dir ${model} DIRECTORY)
    get_filename_component(nm ${model} NAME_WE)
    string(REGEX REPLACE "(_run|Test)$" "" stem "${nm}")
    set(${out} "${dir}/${stem}_all.qnt" PARENT_SCOPE)
endfunction()

function(specs_selftest name model mainarg samples deps_var)
    specs_umbrella("${model}" umbrella)
    string(MAKE_C_IDENTIFIER "${umbrella}" key)
    set_property(GLOBAL APPEND PROPERTY SPECS_GEN_KEYS "${key}")
    set_property(GLOBAL PROPERTY SPECS_GEN_${key}_UMBRELLA "${umbrella}")
    set_property(GLOBAL APPEND PROPERTY SPECS_GEN_${key}_DEPS ${${deps_var}} ${model})
    set_property(GLOBAL APPEND_STRING PROPERTY SPECS_GEN_${key}_TESTS
        "{\"name\":\"${name}\",\"main\":\"${mainarg}\",\"maxSamples\":${samples}},")

    # The gate is now internal: tools/gen.js runs a family's self-tests before
    # its generation batches and stops on the first failure, so a model
    # regression still stops the corpus at the source -- in one process instead
    # of behind a stamp file.  These stay defined and empty because the
    # specs_gen() call sites name them as their gate argument.
    set(SELFTEST_${name} "" PARENT_SCOPE)
endfunction()

# Generate `ntraces` traces from one (model, main, flavor, steps, seed) with a
# single quint invocation (--n-traces amortizes quint's node-startup cost over
# the batch).  `naming` is the output basename with a literal {seq} placeholder
# and no .itf.json suffix.  --invariant=inv gates every emitted trace.
# Batches are ACCUMULATED here and emitted, grouped by model, in
# specs_gen_finalize() below -- one build edge per model rather than per batch.
#
# The reason is cost.  A batch is a (model, --main, --step) triple, and
# `quint run` handles exactly one per process, so each batch re-elaborates the
# model from scratch.  Measured on nfs4_run.qnt: elaboration is 13-21s and
# `quint typecheck` alone costs as much as a full `quint run`, while simulating
# a batch costs ~0.45s.  nfs4 has 18 batches over one model -- ~270s of work for
# ~8s of traces.  tools/gen.js elaborates once and simulates every batch against
# the same typechecked model, which brings that to ~21s.
#
# The traces are unchanged; see tools/gen.js for how that was verified.
function(specs_gen subdir model mainarg flavor steps ntraces seed naming gate_var deps_var)
    set(outdir ${T}/${subdir})
    set(traces)
    math(EXPR last "${ntraces} - 1")
    foreach(seq RANGE 0 ${last})
        string(REPLACE "{seq}" "${seq}" nm "${naming}")
        list(APPEND traces ${outdir}/${nm}.itf.json)
    endforeach()

    # One bucket per model file.  Every call site for a given model passes the
    # same gate and deps (checked: posix/nfs3/nfs4/smb2/nfsaux/s3/nfsdrc each
    # have exactly one pair), so the bucket can carry them.
    specs_umbrella("${model}" umbrella)
    string(MAKE_C_IDENTIFIER "${umbrella}" key)
    set_property(GLOBAL APPEND PROPERTY SPECS_GEN_KEYS "${key}")
    set_property(GLOBAL PROPERTY SPECS_GEN_${key}_UMBRELLA "${umbrella}")
    set_property(GLOBAL APPEND PROPERTY SPECS_GEN_${key}_DEPS ${${deps_var}} ${model})
    set_property(GLOBAL APPEND PROPERTY SPECS_GEN_${key}_TRACES ${traces})
    set_property(GLOBAL APPEND_STRING PROPERTY SPECS_GEN_${key}_JSON
        "{\"outdir\":\"${outdir}\",\"main\":\"${mainarg}\",\"step\":\"${flavor}\",\"maxSteps\":${steps},\"nTraces\":${ntraces},\"seed\":\"${seed}\",\"naming\":\"${naming}\"},")

    set(ALL_TRACES ${ALL_TRACES} ${traces} PARENT_SCOPE)
endfunction()

# Emit the accumulated batches: one spec file and one build edge per model.
# Must be called after every specs_gen() and before the targets that consume
# ALL_TRACES.
function(specs_gen_finalize)
    get_property(keys GLOBAL PROPERTY SPECS_GEN_KEYS)
    list(REMOVE_DUPLICATES keys)
    foreach(key ${keys})
        get_property(umbrella GLOBAL PROPERTY SPECS_GEN_${key}_UMBRELLA)
        get_property(deps     GLOBAL PROPERTY SPECS_GEN_${key}_DEPS)
        get_property(traces   GLOBAL PROPERTY SPECS_GEN_${key}_TRACES)
        get_property(json     GLOBAL PROPERTY SPECS_GEN_${key}_JSON)
        get_property(tests    GLOBAL PROPERTY SPECS_GEN_${key}_TESTS)
        list(REMOVE_DUPLICATES deps)
        string(REGEX REPLACE ",$" "" json "${json}")
        string(REGEX REPLACE ",$" "" tests "${tests}")
        list(LENGTH traces ntraces)

        set(spec ${CMAKE_CURRENT_BINARY_DIR}/gen_${key}.json)
        file(GENERATE OUTPUT ${spec} CONTENT
             "{\"quintCli\":\"${QUINT_BIN}\",\"model\":\"${umbrella}\",\"tests\":[${tests}],\"batches\":[${json}]}\n")

        get_filename_component(fam ${umbrella} NAME_WE)
        add_custom_command(OUTPUT ${traces}
            COMMAND ${NODE_BIN} ${CMAKE_CURRENT_SOURCE_DIR}/tools/gen.js ${spec}
            DEPENDS ${deps} ${umbrella} ${CMAKE_CURRENT_SOURCE_DIR}/tools/gen.js ${spec}
            COMMENT "${fam}: self-test + generate ${ntraces} traces (one elaboration)"
            VERBATIM)
    endforeach()
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
  "posixMemfs|-|stepLocks|128|6|0x1"  "posixMemfs|-|stepLocks|256|3|0x7"      "posixMemfs|-|stepPerms|128|5|0x1"
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
  "posixDisk|disk_|stepLocks|128|6|0x1"   "posixDisk|disk_|stepPerms|128|5|0x1"
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
  # SMB loopback (posix client -> in-process SMB2 server -> backend).  Mirrors
  # the nfs3/nfs4 loopback batch set; no stepLocks (SMB record-lock support is
  # not wired through the loopback yet).
  "posixSmb|smb_|step|128|10|0x1"         "posixSmb|smb_|step|128|6|0x2"
  "posixSmb|smb_|step|256|3|0x100"        "posixSmb|smb_|stepNamespace|128|4|0x1"
  "posixSmb|smb_|stepDescriptors|128|4|0x1" "posixSmb|smb_|stepMetadata|128|4|0x1"
  "posixSmb|smb_|stepDirs|128|3|0x1"      "posixSmb|smb_|stepData|128|4|0x1"
  "posixSmb|smb_|stepPerms|128|5|0x1"     "posixSmb|smb_|stepLinks|128|5|0x1"
  "posixSmb|smb_|stepFds|128|5|0x1"
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

# pNFS traces are their own suite rather than more nfs4/ traces: a pNFS
# profile only replays against a server configured as a metadata server, and
# the plain nfs4 profiles only replay against one that is not, so a single
# directory would make each batch skip most of what it read.
foreach(inst nfs4Pnfs42 nfs4Pnfs41)
    foreach(fs stepPnfs stepData)
        specs_gen(nfs4pnfs ${Q}/nfs/nfs4_run.qnt ${inst} ${fs} 80 6 0x7
                  "${inst}_${fs}_80_{seq}" NFS4_GATE NFS_QNT)
    endforeach()
endforeach()

# ---------------------------------------------------------------------------
# SMB2  (smb2_run.qnt; depends on the shared nfs4_fs substrate too)
# ---------------------------------------------------------------------------
specs_selftest(smb2Test ${Q}/smb2/smb2Test.qnt smb2Test 200 SMB2_DEPS)
# Two capability-off instances of the same model.  They are what make
# `caps.durable` and `caps.leases` provably load-bearing: smb2Test pins both
# FeatMandatory, so a model that stopped reading either would behave
# identically there and only fail here.  (smb2TestNoDurable already said in
# its header that CMake ran it; it did not, so nothing was gating it.)
specs_selftest(smb2TestNoDurable ${Q}/smb2/smb2Test.qnt smb2TestNoDurable 200
               SMB2_DEPS)
specs_selftest(smb2TestNoLease ${Q}/smb2/smb2Test.qnt smb2TestNoLease 200
               SMB2_DEPS)
set(SMB2_GATE ${SELFTEST_smb2Test} ${SELFTEST_smb2TestNoDurable}
              ${SELFTEST_smb2TestNoLease})
# Every instance the model defines, with the flavors that instance exists to
# exercise.  Generation is UNCONDITIONAL: no batch is withheld, and no depth is
# clipped, on account of what some particular server does with it.  A corpus
# that quietly omits the cases an implementation fails is a corpus that cannot
# report them, and the omission then has to be remembered rather than measured.
# Where a server diverges, its own replay harness records the divergence
# against a registry that harness owns -- harness/samba/samba_deviations.py for
# Samba here, and the consuming project's own registry for its own server.
#
# Depth is per flavor and reflects how much state each one needs to reach its
# interesting behavior, nothing else.
specs_gen(smb2 ${Q}/smb2/smb2_run.qnt smb2Base stepCore 500 8 0x7
          "smb2Base_stepCore_500_0x7_{seq}" SMB2_GATE SMB2_DEPS)
specs_gen(smb2 ${Q}/smb2/smb2_run.qnt smb2Base stepReq 500 8 0x11
          "smb2Base_stepReq_500_0x11_{seq}" SMB2_GATE SMB2_DEPS)
specs_gen(smb2 ${Q}/smb2/smb2_run.qnt smb2Base stepDir 500 8 0x5
          "smb2Base_stepDir_500_0x5_{seq}" SMB2_GATE SMB2_DEPS)
specs_gen(smb2 ${Q}/smb2/smb2_run.qnt smb2Base stepInfo 500 8 0x9
          "smb2Base_stepInfo_500_0x9_{seq}" SMB2_GATE SMB2_DEPS)
specs_gen(smb2 ${Q}/smb2/smb2_run.qnt smb2Base stepNs 500 8 0xd
          "smb2Base_stepNs_500_0xd_{seq}" SMB2_GATE SMB2_DEPS)
# The caching instances: oplocks and leases mandatory, so the grant / break /
# acknowledge lifecycle is exercised rather than skipped.  smb2ForceL2 is the
# same model on a share carrying SMB2_SHAREFLAG_FORCE_LEVELII_OPLOCK, where
# every caching grant caps to a read cache.
specs_gen(smb2 ${Q}/smb2/smb2_run.qnt smb2Leases stepLease 300 8 0x21
          "smb2Leases_stepLease_300_0x21_{seq}" SMB2_GATE SMB2_DEPS)
specs_gen(smb2 ${Q}/smb2/smb2_run.qnt smb2ForceL2 stepLease 300 8 0x31
          "smb2ForceL2_stepLease_300_0x31_{seq}" SMB2_GATE SMB2_DEPS)
# The durable-handle lifecycle: request, grant, park across a transport drop,
# reconnect, reclaim, and the reclaim denial matrix.
specs_gen(smb2 ${Q}/smb2/smb2_run.qnt smb2Durable stepDurable 300 8 0x41
          "smb2Durable_stepDurable_300_0x41_{seq}" SMB2_GATE SMB2_DEPS)
# The exactly-once layer: ChannelSequence and SMB2_FLAGS_REPLAY_OPERATION
# stamped on ordinary requests.
specs_gen(smb2 ${Q}/smb2/smb2_run.qnt smb2Replay stepReplay 300 8 0x51
          "smb2Replay_stepReplay_300_0x51_{seq}" SMB2_GATE SMB2_DEPS)
# CHANGE_NOTIFY: arm a directory watch, buffer changes against its two filters,
# deliver or overflow them, and terminate the parked request every way it can
# end (an event, a cancel, the handle going away).  The one flavor whose
# interesting behavior is CROSS-CONNECTION -- one client's mutation completing
# another client's parked request -- so it needs both sessions live at once and
# runs deep enough for the ring to fill between requests.
specs_gen(smb2 ${Q}/smb2/smb2_run.qnt smb2Base stepNotify 400 8 0x61
          "smb2Base_stepNotify_400_0x61_{seq}" SMB2_GATE SMB2_DEPS)
# The NAMESPACE half of the same surface: entries appearing, being renamed and
# disappearing, watched through the two name filters and nothing else.  It is
# the subset two independent servers agree on -- which is what lets the samba
# harness drive it record-for-record to the end of a 400-message trace, where
# the full flavor above diverges on Samba's event vocabulary (SD-10) and its
# first-request-wins CompletionFilter (SD-11) within a few dozen steps.
specs_gen(smb2 ${Q}/smb2/smb2_run.qnt smb2Base stepNotifyNs 400 6 0x71
          "smb2Base_stepNotifyNs_400_0x71_{seq}" SMB2_GATE SMB2_DEPS)

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
# S3  (s3.qnt is the run model directly; no --main)
# ---------------------------------------------------------------------------
specs_selftest(s3Test ${Q}/s3/s3Test.qnt s3Test 200 S3_QNT)
# stepMultipart traces are replayed with a 5 MiB block size (the AWS
# minimum part size) and are therefore excluded from the normal-block-size
# batch by their filename prefix -- see the consuming project's quint
# CMakeLists.
set(S3_BATCHES
  "step|128|8|0x1"  "step|256|3|0x100"  "stepData|128|5|0x1"
  "stepList|128|5|0x1"  "stepBucket|64|4|0x1"  "stepTag|128|4|0x1"
  "stepMultipart|64|3|0x1"  "stepMultipart|64|2|0x11")
foreach(b ${S3_BATCHES})
    string(REPLACE "|" ";" parts "${b}")
    list(GET parts 0 flavor)
    list(GET parts 1 steps)
    list(GET parts 2 nt)
    list(GET parts 3 seed)
    specs_gen(s3 ${Q}/s3/s3.qnt - ${flavor} ${steps} ${nt} ${seed}
              "${flavor}_${steps}_${seed}_{seq}" SELFTEST_s3Test S3_QNT)
endforeach()

# ---------------------------------------------------------------------------
# NFSDRC -- the duplicate-request caches of NFSv3 and NFSv4.0 (nfsdrc_run.qnt).
#
# Four self-tests, two corpora.  nfsdrcRef is the server with the NFSv3 cache
# on; nfsdrcNoV3 is the same server with it off, which is the shipped default
# and is worth a corpus of its own because "the switch does nothing" and "the
# switch works" are indistinguishable without one.  The other two profiles
# describe servers no available transport can produce (two peer addresses) or
# that we do not want to be (a key that ignores the credential), and stay under
# `quint test`.
# ---------------------------------------------------------------------------
file(GLOB NFSDRC_QNT ${Q}/nfsdrc/*.qnt)
specs_selftest(nfsdrcTestRef       ${Q}/nfsdrc/nfsdrcTest.qnt nfsdrcTestRef       200 NFSDRC_QNT)
specs_selftest(nfsdrcTestNoV3      ${Q}/nfsdrc/nfsdrcTest.qnt nfsdrcTestNoV3      200 NFSDRC_QNT)
specs_selftest(nfsdrcTestTwoAddr   ${Q}/nfsdrc/nfsdrcTest.qnt nfsdrcTestTwoAddr   200 NFSDRC_QNT)
specs_selftest(nfsdrcTestCredBlind ${Q}/nfsdrc/nfsdrcTest.qnt nfsdrcTestCredBlind 200 NFSDRC_QNT)
set(NFSDRC_GATE ${SELFTEST_nfsdrcTestRef} ${SELFTEST_nfsdrcTestNoV3}
                ${SELFTEST_nfsdrcTestTwoAddr} ${SELFTEST_nfsdrcTestCredBlind})

# profile | steps | ntraces | seed.  Long runs on purpose: the NFSv4.0 cache
# holds sixteen entries per connection, and reaching its eviction bound takes
# more distinct requests on one connection than a short walk produces.
set(NFSDRC_BATCHES
  "nfsdrcRef|100|6|0x1"  "nfsdrcRef|160|4|0x2"
  "nfsdrcRef|100|4|0x3"  "nfsdrcNoV3|100|3|0x4")
foreach(b ${NFSDRC_BATCHES})
    string(REPLACE "|" ";" parts "${b}")
    list(GET parts 0 profile)
    list(GET parts 1 steps)
    list(GET parts 2 nt)
    list(GET parts 3 seed)
    specs_gen(nfsdrc ${Q}/nfsdrc/nfsdrc_run.qnt ${profile} step ${steps}
              ${nt} ${seed} "${profile}_${steps}_${seed}_{seq}"
              NFSDRC_GATE NFSDRC_QNT)
endforeach()

# ---------------------------------------------------------------------------
# Aggregate
# ---------------------------------------------------------------------------
if(NOT SPECS_LEGACY_CORPUS)
    # A consumer's corpora come from its own configs via specs_corpus().
    add_custom_target(specs_traces)
    return()
endif()

if(SPECS_TRACES_DIR)
    # Nothing to build: the traces are inputs, not outputs.  Emitting the
    # generation edges here would make ninja treat every trace file as something
    # it must produce, and the corpus would be regenerated on top of the one
    # supplied -- which is the whole thing this mode exists to avoid.
    add_custom_target(specs_traces)
else()
    specs_gen_finalize()
    add_custom_target(specs_traces ALL DEPENDS ${ALL_TRACES})
endif()

# Coverage gates (ctest): classify the generated corpus into behavior buckets
# and fail if any is never exercised.
add_test(NAME coverage/nfs3
    COMMAND ${Python3_EXECUTABLE} ${Q}/nfs/coverage.py
            --fail-on-starved --glob "${T}/nfs3/*.itf.json")
add_test(NAME coverage/smb2
    COMMAND ${Python3_EXECUTABLE} ${Q}/smb2/coverage.py ${T}/smb2)
add_test(NAME coverage/nfsaux
    COMMAND ${Python3_EXECUTABLE} ${Q}/nfsaux/coverage.py ${T}/nfsaux)
add_test(NAME coverage/nfsdrc
    COMMAND ${Python3_EXECUTABLE} ${Q}/nfsdrc/coverage.py ${T}/nfsdrc)

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

# ---------------------------------------------------------------------------
# Samba conformance (harness/samba)
#
# The smb2 model encodes MS-SMB2 / MS-FSA, not any one server.  These tests are
# what makes that claim falsifiable: they generate a corpus from configs that
# describe THIS smbd (harness/samba/configs/*.json), replay it against a real
# Samba, and compare every reply to the result the model baked into the trace.
# Where Samba is known to diverge, the config says so and the model predicts the
# divergence -- so the comparison is EXACT and a new disagreement turns the
# suite red.  The three CHANGE_NOTIFY divergences the model cannot express are
# the sole exception and are still recorded in harness/samba/samba_deviations.py,
# which explains why.
#
# One config is one cell is one ctest, so a divergence names the flavour that
# found it and the cells run concurrently.  Each test stands up its own smbd inside
# a private network namespace, which is what lets them: every instance binds
# 127.0.0.1:445 in its own namespace, so there is no port to broker.  Without
# CAP_NET_ADMIN there is no isolation, so the tests fall back to the shared
# host network serialized under one RESOURCE_LOCK -- the same graceful
# degradation chimera and libevpl use for their netns tests.
# ---------------------------------------------------------------------------

# Only when specs is the project being built, not when it is a subdirectory of
# a consumer.  A consuming project embeds this repo to get the CORPUS; its test
# suite is about ITS server, and silently adding third-party conformance tests
# to it would make a Samba or Ganesha divergence fail someone else's build --
# with a test they did not write, against a server they are not shipping.
# (Chimera's devcontainer carries samba for smbtorture, so this is not
# hypothetical: without the guard its `ctest` picks these up the moment it
# builds specs from source instead of fetching the bundle.)  The SPECS_*_TESTS
# options force the question either way.
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    set(_conformance_default ON)
else()
    set(_conformance_default OFF)
endif()
option(SPECS_SAMBA_TESTS
       "Register the Samba conformance suite (default: on only when specs is \
the top-level project)" ${_conformance_default})
option(SPECS_GANESHA_TESTS
       "Register the NFS-Ganesha conformance suite (default: on only when \
specs is the top-level project)" ${_conformance_default})
option(SPECS_KNFSD_TESTS
       "Register the Linux kernel NFS server (knfsd) conformance suite \
(default: on only when specs is the top-level project AND a KVM guest image \
is provided via KVM_IMAGE_DIR)" ${_conformance_default})
# Directory holding the kvm-test-base guest (vmlinuz + rootfs.qcow2) the knfsd
# suite boots.  CI fetches the image with oras and points this at it; without
# it the knfsd tests do not register.
set(KVM_IMAGE_DIR "" CACHE PATH
    "Directory with the KVM guest image (vmlinuz, rootfs.qcow2) for knfsd.")

set(SAMBA_HARNESS ${CMAKE_CURRENT_SOURCE_DIR}/harness/samba)

# The probes below only run when the suite is wanted: they are not free (one
# creates and deletes a real network namespace), and a consumer that is never
# going to register these tests should not pay for them -- nor have its
# configure step create namespaces as a side effect.
if(SPECS_SAMBA_TESTS OR SPECS_GANESHA_TESTS)
    # Can we create a network namespace?  If not the tests still run,
    # serialized on the host network.
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        execute_process(
            COMMAND bash -c "set -e; n=specs_netns_probe_$$; ip netns add \"$n\"; ip netns delete \"$n\""
            RESULT_VARIABLE NETNS_PROBE OUTPUT_QUIET ERROR_QUIET)
    else()
        set(NETNS_PROBE 1)
    endif()
    if(NETNS_PROBE EQUAL 0)
        set(CONFORMANCE_NETNS TRUE)
    else()
        set(CONFORMANCE_NETNS FALSE)
        if(REQUIRE_NETNS_TESTS)
            message(FATAL_ERROR
                "REQUIRE_NETNS_TESTS=ON but `ip netns add` failed (need "
                "CAP_NET_ADMIN / root).  Run privileged, or drop the flag.")
        endif()
    endif()
endif()

if(SPECS_SAMBA_TESTS)
    find_program(SMBD_BIN NAMES smbd
                 PATHS /usr/sbin /usr/local/sbin
                 DOC "Samba smbd, the server under test for the samba MBT suite")

    # The replay client is pure Python but needs `smbprotocol` (used at its raw
    # layer).  Probed rather than assumed: without it every samba test would
    # fail identically at import time, which reads as a broken suite rather
    # than a missing dependency.
    execute_process(COMMAND ${Python3_EXECUTABLE} -c "import smbprotocol"
                    RESULT_VARIABLE HAVE_SMBPROTOCOL
                    OUTPUT_QUIET ERROR_QUIET)
endif()

# A cell's CORPUS depends on its config and nothing else; whether this machine
# can run smbd gates only the ctests.  See the note on the knfsd block below for
# what conflating the two costs.
if(NOT SPECS_SAMBA_TESTS)
    message(STATUS
        "samba MBT tests: not registered (specs is a subdirectory of "
        "${CMAKE_PROJECT_NAME}; -DSPECS_SAMBA_TESTS=ON to register them)")
else()
    set(SAMBA_CAN_RUN TRUE)
    if(NOT SMBD_BIN)
        set(SAMBA_CAN_RUN FALSE)
        message(STATUS
            "samba MBT tests: corpus registered, tests disabled (smbd not found)")
    elseif(NOT HAVE_SMBPROTOCOL EQUAL 0)
        set(SAMBA_CAN_RUN FALSE)
        message(STATUS
            "samba MBT tests: corpus registered, tests disabled "
            "(python module 'smbprotocol' not installed)")
    endif()
    set(SAMBA_NETNS ${CONFORMANCE_NETNS})
    if(SAMBA_CAN_RUN AND SAMBA_NETNS)
        message(STATUS "samba MBT tests: enabled (${SMBD_BIN}, netns isolated)")
    elseif(SAMBA_CAN_RUN)
        message(STATUS "samba MBT tests: enabled (${SMBD_BIN}, no netns -- "
                "serialized on the host network)")
    endif()

    # tools/devliveness.py: the gate that stops a recorded deviation outliving
    # its fix.  See the devliveness cells below.
    set(SPECS_DEVLIVENESS ${CMAKE_CURRENT_SOURCE_DIR}/tools/devliveness.py)

    # One CONFIG is one CELL is one ctest.  A config binds every constant the
    # smb2 model declares -- which capabilities this smbd advertises, which of
    # ITS known divergences the model is told to predict -- and carries the one
    # batch that cell replays.  The cell then replays its whole directory: no
    # filename carving, no per-trace skipping, every reply an exact match
    # against what the model baked into the trace.
    #
    # One batch per cell rather than one profile per cell.  A family is
    # elaborated once however many cells it has (cmake/SpecsCorpus.cmake's cost
    # note), so splitting costs nothing to generate, and it keeps what the old
    # per-batch globs bought: a divergence names the flavour that found it, and
    # the cells run concurrently under `ctest -j` instead of serializing 54
    # traces through one smbd.
    #
    # ALL of them, including the four whose profile turns a caching capability
    # on: smb2_replay.py implements neither the oplock/lease break lifecycle
    # nor the durable reconnect, so those report a ctest SKIP (exit 77), which
    # keeps the gap visible and attributable to the harness instead of hiding
    # it by not generating the traces.  They enable no deviations and get no
    # strict twin: nothing replays them, so there is no claim to check and a
    # second byte-identical corpus would be pure cost.
    #
    # A cell gets a STRICT twin and a liveness gate only when its config
    # actually enables a deviation.  Three of the driveable flavours reach
    # none -- locks are drawn only by stepInfo and renames only by stepNs, so
    # stepCore, stepReq and stepNotifyNs cannot take any of the branches -- and
    # for those the cell already IS the strict corpus: it states the standard,
    # replay is an exact match, and it gates rather than reporting.  Generating
    # a byte-identical twin of it would buy nothing.
    #
    # cell name | config stem | driven by this harness? | enables a deviation?
    set(SAMBA_CELLS
        "stepCore|core|yes|no"
        "stepReq|req|yes|no"
        "stepDir|dir|yes|yes"
        "stepInfo|info|yes|yes"
        "stepNs|ns|yes|yes"
        "leases|leases|no|no"
        "forceL2|force_l2|no|no"
        "durable|durable|no|no"
        "replay|replay|no|no"
        "notify|notify|yes|yes"
        "notifyNs|notify_ns|yes|no")

    foreach(c ${SAMBA_CELLS})
        string(REPLACE "|" ";" parts "${c}")
        # Cells register regardless; only the smbd-driving tests below wait on
        # the environment.
        list(GET parts 0 bname)
        list(GET parts 1 cstem)
        list(GET parts 2 driven)
        list(GET parts 3 hasdev)
        set(scfg ${SAMBA_HARNESS}/configs/${cstem}.json)

        if("${hasdev}" STREQUAL "yes")
            specs_corpus(NAME    samba/smb2/${bname}
                         FAMILY  smb2
                         CONFIG  ${scfg}
                         OUT_DIR SAMBA_TRACES
                         STRICT_OUT_DIR SAMBA_STRICT)
        else()
            specs_corpus(NAME    samba/smb2/${bname}
                         FAMILY  smb2
                         CONFIG  ${scfg}
                         OUT_DIR SAMBA_TRACES)
            set(SAMBA_STRICT "")
        endif()

        # A cell this harness cannot drive is labelled as such, so
        # `ctest -LE unreplayable` runs only what actually reaches the server.
        set(clabels "samba;smb2;mbt")
        if(NOT "${driven}" STREQUAL "yes")
            set(clabels "${clabels};unreplayable")
        endif()

        set(tname samba/smb2/${bname})

        # The liveness gate, and it IS a gate: a cell that enables a deviation
        # no trace in its own corpus ever records having taken fails here.  It
        # needs no server -- it reads the config and the generated traces -- so
        # it runs everywhere the corpus is built, which is the point: the corpus
        # is generated on machines that cannot run smbd.
        add_test(NAME ${tname}/devliveness
                 COMMAND ${Python3_EXECUTABLE} ${SPECS_DEVLIVENESS}
                         ${scfg} ${SAMBA_TRACES})
        set_tests_properties(${tname}/devliveness PROPERTIES
            LABELS "samba;smb2;devliveness"
            TIMEOUT 120)

        if(NOT SAMBA_CAN_RUN)
            continue()   # no smbd to drive; the corpus above still exists
        endif()

        add_test(NAME ${tname}
                 COMMAND ${SAMBA_HARNESS}/run_samba_mbt.sh ${SAMBA_TRACES})
        # TIMEOUT: 8 traces at depth 240-500 against a real server, each
        # resetting the share and reconnecting per session -- minutes, not
        # seconds.  ENVIRONMENT hands the wrapper the smbd CMake resolved, so
        # the test does not depend on /usr/sbin being on the invoking shell's
        # PATH.  SKIP_RETURN_CODE lets the wrapper report "no samba here" as a
        # ctest SKIP rather than a failure.
        set_tests_properties(${tname} PROPERTIES
            LABELS "${clabels}"
            TIMEOUT 1800
            SKIP_RETURN_CODE 77
            ENVIRONMENT "SMBD=${SMBD_BIN}")

        if(SAMBA_STRICT)
            # The STRICT twin: the same server profile with every deviation
            # forced off, so the corpus states the standard and nothing else.
            # REPORTING, not gating -- its failures are exactly Samba's
            # conformance debt, re-measured on every run instead of remembered
            # in a registry, which is what keeps a deviation from outliving its
            # fix.  CONFIGURATIONS puts it in the extended tier: a plain
            # `ctest` does not run it, `ctest -C extended` does.
            add_test(NAME ${tname}-strict
                     CONFIGURATIONS extended
                     COMMAND ${SAMBA_HARNESS}/run_samba_mbt.sh ${SAMBA_STRICT})
            set_tests_properties(${tname}-strict PROPERTIES
                LABELS "samba;smb2;mbt;strict"
                TIMEOUT 1800
                SKIP_RETURN_CODE 77
                ENVIRONMENT "SMBD=${SMBD_BIN}")

        endif()

        if(NOT SAMBA_NETNS)
            # No namespace to keep the instances apart, so only one smbd may
            # own :445 at a time.
            # ENVIRONMENT is a list property and setting it again would
            # REPLACE the SMBD entry above, so append instead.
            set_tests_properties(${tname} PROPERTIES
                RESOURCE_LOCK samba_smb_port)
            set_property(TEST ${tname} APPEND PROPERTY
                ENVIRONMENT "SPECS_SAMBA_NO_NETNS=1")
            if(SAMBA_STRICT)
                set_tests_properties(${tname}-strict PROPERTIES
                    RESOURCE_LOCK samba_smb_port)
                set_property(TEST ${tname}-strict APPEND PROPERTY
                    ENVIRONMENT "SPECS_SAMBA_NO_NETNS=1")
            endif()
        endif()
    endforeach()
endif()

# ---------------------------------------------------------------------------
# NFS-Ganesha conformance (harness/nfs)
#
# The NFS counterpart of the Samba suite: replay an NFSv3 and NFSv4 corpus
# generated FOR THIS SERVER against a real NFS-Ganesha -- a userspace
# implementation nobody consulted while writing the NFS models -- and compare
# every reply to the result the model baked into the trace.  Disagreements are
# findings, and there is nothing left to forgive them: what ganesha does
# differently is stated in the MODEL, switched on by the cell's config and
# declared with its citation in quint/nfs{3,4}/corpus.schema.json, so the
# trace's expectation already IS what ganesha does.  A NEW divergence turns
# the suite red.  (harness/nfs/ganesha_deviations.py still holds the handful
# that could not be stated -- see its docstring for which and why.)
#
# One ctest per generated batch, as for Samba.  Each test runs its own
# rpcbind and a fresh ganesha PER TRACE inside a private network namespace
# (the export is an ext4 image the test loop-mounts), so the batches run
# concurrently.  Without CAP_NET_ADMIN they serialize under one RESOURCE_LOCK.
# ---------------------------------------------------------------------------
set(NFS_HARNESS ${CMAKE_CURRENT_SOURCE_DIR}/harness/nfs)

if(SPECS_GANESHA_TESTS)
    find_program(GANESHA_BIN NAMES ganesha.nfsd
                 PATHS /usr/bin /usr/sbin /usr/local/bin
                 DOC "NFS-Ganesha, the server under test for the NFS MBT suite")
    find_program(RPCBIND_BIN NAMES rpcbind
                 PATHS /sbin /usr/sbin
                 DOC "rpcbind, which ganesha registers its NFSv3 programs with")
endif()

# Same rule as samba and knfsd: the config determines the corpus, the machine
# determines only whether the tests run.
if(NOT SPECS_GANESHA_TESTS)
    message(STATUS
        "ganesha MBT tests: not registered (specs is a subdirectory of "
        "${CMAKE_PROJECT_NAME}; -DSPECS_GANESHA_TESTS=ON to register them)")
else()
    set(GANESHA_CAN_RUN TRUE)
    if(NOT GANESHA_BIN)
        set(GANESHA_CAN_RUN FALSE)
        message(STATUS
            "ganesha MBT tests: corpus registered, tests disabled "
            "(ganesha.nfsd not found)")
    elseif(NOT RPCBIND_BIN)
        set(GANESHA_CAN_RUN FALSE)
        message(STATUS
            "ganesha MBT tests: corpus registered, tests disabled "
            "(rpcbind not found)")
    endif()
    if(GANESHA_CAN_RUN AND CONFORMANCE_NETNS)
        message(STATUS "ganesha MBT tests: enabled (${GANESHA_BIN}, netns isolated)")
    elseif(GANESHA_CAN_RUN)
        message(STATUS "ganesha MBT tests: enabled (${GANESHA_BIN}, no netns -- "
                "serialized on the host network)")
    endif()

    # tools/devliveness.py: the gate that stops a recorded deviation outliving
    # its fix.  (Also set in the samba block above; both blocks are optional
    # and either may be the only one configured, so each names it for itself.)
    set(SPECS_DEVLIVENESS ${CMAKE_CURRENT_SOURCE_DIR}/tools/devliveness.py)

    # One CONFIG is one CELL: a config binds every constant the nfs3/nfs4
    # models declare -- which optional surface this ganesha serves, which minor
    # version, and which of ITS known divergences the model is told to predict
    # -- and carries the batch list that cell generates.  So the trace's
    # expectation is already what ganesha does, replay is an exact match, and
    # the harness needs no deviation registry for anything the model can state.
    #
    # One cell per PROFILE rather than per batch (the samba block above splits
    # per batch).  The reason is devliveness: it is evaluated per cell, and the
    # nfs4 profiles reach their divergences from different flavours -- the wide
    # GETATTR from `step`, the compound tag from `stepState`, LINK-of-a-
    # directory from `stepNamespace`.  Split per batch, every cell would have
    # to enable only what its own flavour reaches, which is a config per batch
    # and a maintenance trap.  The ctests still run one per batch, because a
    # divergence should name the flavour that found it and the batches should
    # run concurrently; each names its batch by the cell's own trace stem
    # inside the cell's own directory, which is not the cross-profile filename
    # carving this pass exists to delete.
    #
    # cell dir var | strict dir var | config | suite | test-name prefix |
    # batch names (each is <stem>_<flavor>_<steps>) | extra environment
    set(GANESHA_CELLS
        "nfs3|ganesha_nfs3|ganesha3|step_128,step_256,stepChurn_128,stepChurn_256,stepDir_128,stepExcl_128|"
        "nfs4|ganesha_nfs4_42|ganesha42|step_80,stepState_80,stepNamespace_80,stepData_80,stepTypes_80,stepData42_80|"
        "nfs4|ganesha_nfs4_41|ganesha41|step_80,stepState_80,stepNamespace_80,stepData_80,stepTypes_80|"
        "nfs4|ganesha_nfs4_40|ganesha40|step_80,stepState_80,stepNamespace_80,stepData_80,stepTypes_80|"
        "nfs4|ganesha_nfs4_42_deleg|ganesha42Deleg|stepDeleg_80|SPECS_NFS_DELEG=1"
        "nfs4|ganesha_nfs4_41_deleg|ganesha41Deleg|stepDeleg_80|SPECS_NFS_DELEG=1"
        "nfs4|ganesha_pnfs42|ganeshaPnfs42|stepPnfs_80,stepData_80|"
        "nfs4|ganesha_pnfs41|ganeshaPnfs41|stepPnfs_80,stepData_80|")

    foreach(c ${GANESHA_CELLS})
        string(REPLACE "|" ";" parts "${c}")
        # Cells register regardless; only the ganesha-driving tests below wait
        # on the environment.
        list(GET parts 0 fam)
        list(GET parts 1 cfgname)
        list(GET parts 2 stem)
        list(GET parts 3 bnames)
        # ',' rather than ';': a ';' inside a list ENTRY is flattened by CMake
        # when the outer foreach expands it, so the batch names have to travel
        # under a separator CMake does not treat as one.
        string(REPLACE "," ";" bnames "${bnames}")
        list(LENGTH parts nparts)
        set(extra_env)
        if(nparts GREATER 4)
            list(GET parts 4 extra_env)
        endif()
        set(gcfg ${NFS_HARNESS}/configs/${cfgname}.json)

        specs_corpus(NAME    ganesha/${cfgname}
                     FAMILY  ${fam}
                     CONFIG  ${gcfg}
                     OUT_DIR GANESHA_TRACES
                     STRICT_OUT_DIR GANESHA_STRICT)

        # The liveness gate: a cell that enables a deviation no trace in its own
        # corpus ever records having taken fails here.  It needs no server, so
        # it runs everywhere the corpus is built -- including the job that
        # generates it, which cannot run ganesha.
        add_test(NAME ganesha/${fam}/${cfgname}/devliveness
                 COMMAND ${Python3_EXECUTABLE} ${SPECS_DEVLIVENESS}
                         ${gcfg} ${GANESHA_TRACES})
        set_tests_properties(ganesha/${fam}/${cfgname}/devliveness PROPERTIES
            LABELS "ganesha;${fam};quint;devliveness"
            TIMEOUT 120)

        if(NOT GANESHA_CAN_RUN)
            continue()   # no ganesha to drive; the corpus above still exists
        endif()

        foreach(bname ${bnames})
            set(tname ganesha/${fam}/${cfgname}/${bname})
            add_test(NAME ${tname}
                     COMMAND ${NFS_HARNESS}/run_nfs_mbt.sh ganesha ${fam}
                             ${GANESHA_TRACES} ${stem}_${bname}_*.itf.json)
            # TIMEOUT: up to 10 traces, each on a fresh server, at 80-256 steps
            # against a real server -- minutes, not seconds.
            set_tests_properties(${tname} PROPERTIES
                LABELS "ganesha;${fam};mbt"
                TIMEOUT 1800
                SKIP_RETURN_CODE 77
                ENVIRONMENT "GANESHA=${GANESHA_BIN};RPCBIND=${RPCBIND_BIN}")
            if(extra_env)
                set_property(TEST ${tname} APPEND PROPERTY
                             ENVIRONMENT "${extra_env}")
            endif()
            if(NOT CONFORMANCE_NETNS)
                set_tests_properties(${tname} PROPERTIES
                    RESOURCE_LOCK nfs_server_ports)
                set_property(TEST ${tname} APPEND PROPERTY
                    ENVIRONMENT "SPECS_NFS_NO_NETNS=1")
            endif()

            # The STRICT twin of the same batch: the identical server profile
            # with every deviation forced off, so the corpus states the RFCs
            # and nothing else.  REPORTING, not gating -- its failures are
            # exactly ganesha's conformance debt, re-measured on every run
            # instead of remembered in a registry, which is what keeps a
            # deviation from outliving its fix.  CONFIGURATIONS puts it in the
            # extended tier: a plain `ctest` does not run it, `ctest -C
            # extended` does.
            add_test(NAME ${tname}-strict
                     CONFIGURATIONS extended
                     COMMAND ${NFS_HARNESS}/run_nfs_mbt.sh ganesha ${fam}
                             ${GANESHA_STRICT} ${stem}_${bname}_*.itf.json)
            set_tests_properties(${tname}-strict PROPERTIES
                LABELS "ganesha;${fam};mbt;strict"
                TIMEOUT 1800
                SKIP_RETURN_CODE 77
                ENVIRONMENT "GANESHA=${GANESHA_BIN};RPCBIND=${RPCBIND_BIN}")
            if(extra_env)
                set_property(TEST ${tname}-strict APPEND PROPERTY
                             ENVIRONMENT "${extra_env}")
            endif()
            if(NOT CONFORMANCE_NETNS)
                set_tests_properties(${tname}-strict PROPERTIES
                    RESOURCE_LOCK nfs_server_ports)
                set_property(TEST ${tname}-strict APPEND PROPERTY
                    ENVIRONMENT "SPECS_NFS_NO_NETNS=1")
            endif()
        endforeach()

        # The liveness gate, and it IS a gate: a cell that enables a deviation
        # no trace in its own corpus ever records having taken fails here.
    endforeach()
endif()

# ---------------------------------------------------------------------------
# knfsd conformance (harness/nfs, SERVER=knfsd)
#
# The same FLAVOURS, at the same depths and seeds, replayed against the Linux
# kernel NFS server booted in a KVM guest -- a third, unrelated reference
# beside Ganesha and the model.  Not the same corpus: a cell's traces encode
# the divergences of the server they are replayed against, and the Linux
# server's are not ganesha's.  What the two DO share is the vocabulary -- the
# S4-* ids both enable name one divergence with one citation, which is the
# evidence that a clause is ambiguous rather than that one server has a bug.
# The
# guest image (chimera-nas/kvm-test-base >= v1.10.0, which carries
# nfs-kernel-server) is fetched by CI and its directory passed in KVM_IMAGE_DIR;
# each batch boots one guest and drives it from the host side of a TAP link,
# resetting the export between traces over a 9p control channel.  Needs
# /dev/kvm at run time (the runner SKIPs without it) and qemu on the host.
# ---------------------------------------------------------------------------
# WHAT THE ENVIRONMENT MAY AND MAY NOT GATE.
#
# A cell's CORPUS is determined by its config and nothing else.  Whether this
# machine can run the server is a fact about the machine, so it gates the
# ctests -- never the registration.  Conflating the two breaks the CI shape
# outright: the `build` job generates the corpus once and the knfsd job replays
# those exact bytes, but only the knfsd job pulls the guest image.  With
# registration behind the image probe, `build` emitted a corpus with no knfsd
# cells in it and the knfsd job then had nothing to replay.  So the cells
# register on SPECS_KNFSD_TESTS alone, and only add_test() waits on qemu and a
# guest image.
#
# (The samba and ganesha blocks above have the same shape and are correct today
# only because smbd, ganesha and qemu all live in the image that generates the
# corpus.  Same principle applies if that ever stops being true.)
if(NOT SPECS_KNFSD_TESTS)
    message(STATUS
        "knfsd MBT tests: not registered (specs is a subdirectory of "
        "${CMAKE_PROJECT_NAME}; -DSPECS_KNFSD_TESTS=ON with -DKVM_IMAGE_DIR to "
        "register them)")
else()
    find_program(QEMU_BIN NAMES qemu-system-x86_64 qemu-system-aarch64
                 DOC "qemu, which boots the knfsd guest")
    set(KNFSD_CAN_RUN TRUE)
    if(NOT KVM_IMAGE_DIR OR NOT EXISTS "${KVM_IMAGE_DIR}/vmlinuz"
       OR NOT EXISTS "${KVM_IMAGE_DIR}/rootfs.qcow2")
        set(KNFSD_CAN_RUN FALSE)
        message(STATUS
            "knfsd MBT tests: corpus registered, tests disabled (no KVM guest "
            "image; set KVM_IMAGE_DIR to a directory with vmlinuz + "
            "rootfs.qcow2)")
    elseif(NOT QEMU_BIN)
        set(KNFSD_CAN_RUN FALSE)
        message(STATUS
            "knfsd MBT tests: corpus registered, tests disabled (qemu-system "
            "not found)")
    else()
        message(STATUS "knfsd MBT tests: enabled (guest ${KVM_IMAGE_DIR}, "
                "${QEMU_BIN})")
    endif()
    if(TRUE)
        set(SPECS_DEVLIVENESS ${CMAKE_CURRENT_SOURCE_DIR}/tools/devliveness.py)

        # The knfsd suite drives the same flavours the ganesha suite does, at
        # the same depths and seeds -- but NOT the same corpus.  It cannot: a
        # cell's corpus encodes the divergences of the server it is replayed
        # against, and the Linux server's are not ganesha's.  What the two do
        # share is the vocabulary: four of the five ids the knfsd nfs4 cells
        # enable are S4-*, divergences BOTH servers have, which is the evidence
        # that the clause is ambiguous rather than that one server is wrong.
        #
        # No delegation and no pNFS cells: the knfsd runner drives neither, as
        # before.
        #
        # cell dir var | config | trace stem | batch names
        set(KNFSD_CELLS
            "nfs3|knfsd_nfs3|knfsd3|step_128,step_256,stepChurn_128,stepChurn_256,stepDir_128,stepExcl_128"
            "nfs4|knfsd_nfs4_42|knfsd42|step_80,stepState_80,stepNamespace_80,stepData_80,stepTypes_80,stepData42_80"
            "nfs4|knfsd_nfs4_41|knfsd41|step_80,stepState_80,stepNamespace_80,stepData_80,stepTypes_80"
            "nfs4|knfsd_nfs4_40|knfsd40|step_80,stepState_80,stepNamespace_80,stepData_80,stepTypes_80")

        foreach(c ${KNFSD_CELLS})
            string(REPLACE "|" ";" parts "${c}")
            list(GET parts 0 fam)
            list(GET parts 1 cfgname)
            list(GET parts 2 stem)
            list(GET parts 3 bnames)
            string(REPLACE "," ";" bnames "${bnames}")
            set(kcfg ${NFS_HARNESS}/configs/${cfgname}.json)

            specs_corpus(NAME    knfsd/${cfgname}
                         FAMILY  ${fam}
                         CONFIG  ${kcfg}
                         OUT_DIR KNFSD_TRACES
                         STRICT_OUT_DIR KNFSD_STRICT)

            foreach(bname ${bnames})
                if(NOT KNFSD_CAN_RUN)
                    # No guest to drive.  The corpus is still generated above --
                    # this machine simply cannot replay it.
                    continue()
                endif()
                set(tname knfsd/${fam}/${cfgname}/${bname})
                add_test(NAME ${tname}
                         COMMAND ${NFS_HARNESS}/run_nfs_mbt.sh knfsd ${fam}
                                 ${KNFSD_TRACES} ${stem}_${bname}_*.itf.json)
                # A guest boot plus up to ~10 traces, each resetting the
                # export: minutes.  SKIP_RETURN_CODE 77 lets the runner report
                # "no /dev/kvm here" or "no guest image" as a ctest SKIP.
                set_tests_properties(${tname} PROPERTIES
                    LABELS "knfsd;${fam};mbt"
                    TIMEOUT 1800
                    SKIP_RETURN_CODE 77
                    ENVIRONMENT "KVM_VMLINUZ=${KVM_IMAGE_DIR}/vmlinuz;KVM_ROOTFS=${KVM_IMAGE_DIR}/rootfs.qcow2")
                # Every knfsd batch boots a guest that binds the same TAP
                # subnet and NFS ports; without a netns per test they would
                # collide, so if the netns is unavailable they serialize under
                # one lock.
                if(NOT CONFORMANCE_NETNS)
                    set_tests_properties(${tname} PROPERTIES
                        RESOURCE_LOCK nfs_server_ports)
                    set_property(TEST ${tname} APPEND PROPERTY
                        ENVIRONMENT "SPECS_NFS_NO_NETNS=1")
                endif()

                # The STRICT twin: the same profile with every deviation forced
                # off, so the corpus states the RFCs and nothing else.  Its
                # failures ARE the Linux server's conformance debt, re-measured
                # every run rather than remembered in a registry.  Extended
                # tier: reporting, not gating.
                add_test(NAME ${tname}-strict
                         CONFIGURATIONS extended
                         COMMAND ${NFS_HARNESS}/run_nfs_mbt.sh knfsd ${fam}
                                 ${KNFSD_STRICT} ${stem}_${bname}_*.itf.json)
                set_tests_properties(${tname}-strict PROPERTIES
                    LABELS "knfsd;${fam};mbt;strict"
                    TIMEOUT 1800
                    SKIP_RETURN_CODE 77
                    ENVIRONMENT "KVM_VMLINUZ=${KVM_IMAGE_DIR}/vmlinuz;KVM_ROOTFS=${KVM_IMAGE_DIR}/rootfs.qcow2")
                if(NOT CONFORMANCE_NETNS)
                    set_tests_properties(${tname}-strict PROPERTIES
                        RESOURCE_LOCK nfs_server_ports)
                    set_property(TEST ${tname}-strict APPEND PROPERTY
                        ENVIRONMENT "SPECS_NFS_NO_NETNS=1")
                endif()
            endforeach()

            # The liveness gate: a cell that enables a deviation no trace in
            # its own corpus ever records having taken fails here.  Needs no
            # guest, so it runs everywhere the corpus is built -- which matters
            # for knfsd, whose replay needs /dev/kvm and usually SKIPs.
            add_test(NAME knfsd/${fam}/${cfgname}/devliveness
                     COMMAND ${Python3_EXECUTABLE} ${SPECS_DEVLIVENESS}
                             ${kcfg} ${KNFSD_TRACES})
            set_tests_properties(knfsd/${fam}/${cfgname}/devliveness PROPERTIES
                LABELS "knfsd;${fam};quint;devliveness"
                TIMEOUT 120)
        endforeach()
    endif()
endif()

# ---------------------------------------------------------------------------
# Emit the build edges for every cell registered above (cmake/SpecsCorpus.cmake).
#
# A CONSUMER calls this itself, after its own specs_corpus() registrations; this
# call is for the standalone build, where the conformance suites above are the
# only consumer there is.  Guarded so that adding the same call elsewhere in
# this file cannot double-register: finalize creates targets, and creating them
# twice is a configure error.
# ---------------------------------------------------------------------------
if(NOT SPECS_CORPUS_FINALIZED)
    set(SPECS_CORPUS_FINALIZED TRUE)
    specs_corpus_finalize()
endif()
