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
#   * `bundle.sh` tars traces/ into the artifact the consuming project fetches.
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
  "posixExt4|ext4_|step|128|10|0x1"       "posixExt4|ext4_|step|128|6|0x2"
  "posixExt4|ext4_|step|256|3|0x100"      "posixExt4|ext4_|step|512|2|0x5"
  "posixExt4|ext4_|stepNamespace|128|4|0x1" "posixExt4|ext4_|stepNamespace|256|2|0x9"
  "posixExt4|ext4_|stepDescriptors|128|4|0x1" "posixExt4|ext4_|stepMetadata|128|4|0x1"
  "posixExt4|ext4_|stepDirs|128|3|0x1"    "posixExt4|ext4_|stepData|128|4|0x1"
  "posixExt4|ext4_|stepLocks|128|6|0x1"   "posixExt4|ext4_|stepPerms|128|5|0x1"
  "posixExt4|ext4_|stepLinks|128|5|0x1"   "posixExt4|ext4_|stepFds|128|5|0x1"
  "posixExt4|ext4_|stepTooLong|128|4|0x1" "posixExt4|ext4_|stepPrefix|128|5|0x1"
  "posixExt4|ext4_|stepFallocate|128|4|0x1"
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
# Aggregate + bundle
# ---------------------------------------------------------------------------
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
# The corpus above is generated from models that encode MS-SMB2 / MS-FSA, not
# any one server.  These tests are what makes that claim falsifiable: they
# replay the generated SMB2 traces against a real Samba smbd and compare every
# reply to the result the model baked into the trace.  Where the two disagree,
# one of them is wrong -- and harness/samba/samba_deviations.py records which,
# with a citation, so a known divergence stays enumerable and a NEW one turns
# the suite red.
#
# One ctest per generated batch, so a divergence names the flavor that found
# it and the batches run concurrently.  Each test stands up its own smbd inside
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
option(SPECS_EXT4_TESTS
       "Register the Linux ext4 conformance suite (default: on only when \
specs is the top-level project AND a KVM guest image is provided via \
KVM_IMAGE_DIR)" ${_conformance_default})
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

if(NOT SPECS_SAMBA_TESTS)
    message(STATUS
        "samba MBT tests: not registered (specs is a subdirectory of "
        "${CMAKE_PROJECT_NAME}; -DSPECS_SAMBA_TESTS=ON to register them)")
elseif(NOT SMBD_BIN)
    message(STATUS "samba MBT tests: disabled (smbd not found)")
elseif(NOT HAVE_SMBPROTOCOL EQUAL 0)
    message(STATUS "samba MBT tests: disabled "
            "(python module 'smbprotocol' not installed)")
else()
    set(SAMBA_NETNS ${CONFORMANCE_NETNS})
    if(SAMBA_NETNS)
        message(STATUS "samba MBT tests: enabled (${SMBD_BIN}, netns isolated)")
    else()
        message(STATUS "samba MBT tests: enabled (${SMBD_BIN}, no netns -- "
                "serialized on the host network)")
    endif()

    # batch name | trace glob.  One per specs_gen batch above -- ALL of them,
    # including the ones this harness cannot drive.  Those report a ctest SKIP
    # (the replayer exits 77 when every trace in a batch needs a capability it
    # does not implement), which keeps the gap visible and attributable to the
    # harness instead of hiding it by not generating the traces.
    set(SAMBA_BATCHES
        "stepCore|smb2Base_stepCore_500_0x7_*.itf.json"
        "stepReq|smb2Base_stepReq_500_0x11_*.itf.json"
        "stepDir|smb2Base_stepDir_500_0x5_*.itf.json"
        "stepInfo|smb2Base_stepInfo_500_0x9_*.itf.json"
        "stepNs|smb2Base_stepNs_500_0xd_*.itf.json"
        "leases|smb2Leases_stepLease_300_0x21_*.itf.json"
        "forceL2|smb2ForceL2_stepLease_300_0x31_*.itf.json"
        "durable|smb2Durable_stepDurable_300_0x41_*.itf.json"
        "replay|smb2Replay_stepReplay_300_0x51_*.itf.json"
        "notify|smb2Base_stepNotify_400_0x61_*.itf.json"
        "notifyNs|smb2Base_stepNotifyNs_400_0x71_*.itf.json")

    foreach(b ${SAMBA_BATCHES})
        string(REPLACE "|" ";" parts "${b}")
        list(GET parts 0 bname)
        list(GET parts 1 bglob)
        set(tname samba/smb2/${bname})
        add_test(NAME ${tname}
                 COMMAND ${SAMBA_HARNESS}/run_samba_mbt.sh ${T}/smb2 ${bglob})
        # TIMEOUT: 8 traces at depth 240-500 against a real server, each
        # resetting the share and reconnecting per session -- minutes, not
        # seconds.  ENVIRONMENT hands the wrapper the smbd CMake resolved, so
        # the test does not depend on /usr/sbin being on the invoking shell's
        # PATH.  SKIP_RETURN_CODE lets the wrapper report "no samba here" as a
        # ctest SKIP rather than a failure.
        set_tests_properties(${tname} PROPERTIES
            LABELS "samba;smb2;mbt"
            TIMEOUT 1800
            SKIP_RETURN_CODE 77
            ENVIRONMENT "SMBD=${SMBD_BIN}")
        if(NOT SAMBA_NETNS)
            # No namespace to keep the instances apart, so only one smbd may
            # own :445 at a time.
            # ENVIRONMENT is a list property and setting it again would
            # REPLACE the SMBD entry above, so append instead.
            set_tests_properties(${tname} PROPERTIES
                RESOURCE_LOCK samba_smb_port)
            set_property(TEST ${tname} APPEND PROPERTY
                ENVIRONMENT "SPECS_SAMBA_NO_NETNS=1")
        endif()
    endforeach()
endif()

# ---------------------------------------------------------------------------
# NFS-Ganesha conformance (harness/nfs)
#
# The NFS counterpart of the Samba suite: replay the generated NFSv3 and
# NFSv4 corpora against a real NFS-Ganesha server -- a userspace
# implementation nobody consulted while writing the NFS models -- and compare
# every reply to the result the model baked into the trace.  Disagreements are
# findings: a model bug, or a Ganesha divergence recorded with a citation in
# harness/nfs/ganesha_deviations.py.  A NEW one turns the suite red.
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

if(NOT SPECS_GANESHA_TESTS)
    message(STATUS
        "ganesha MBT tests: not registered (specs is a subdirectory of "
        "${CMAKE_PROJECT_NAME}; -DSPECS_GANESHA_TESTS=ON to register them)")
elseif(NOT GANESHA_BIN)
    message(STATUS "ganesha MBT tests: disabled (ganesha.nfsd not found)")
elseif(NOT RPCBIND_BIN)
    message(STATUS "ganesha MBT tests: disabled (rpcbind not found)")
else()
    if(CONFORMANCE_NETNS)
        message(STATUS "ganesha MBT tests: enabled (${GANESHA_BIN}, netns isolated)")
    else()
        message(STATUS "ganesha MBT tests: enabled (${GANESHA_BIN}, no netns -- "
                "serialized on the host network)")
    endif()

    # suite | batch name | trace glob | extra environment.  One per specs_gen
    # batch above -- ALL of them, including the ones this harness cannot drive
    # (a SKIP keeps the gap visible).  The Deleg batches need delegations
    # enabled on the server; the pNFS batches need a metadata server, which a
    # single-node ganesha over a local filesystem is not, so they SKIP.
    set(GANESHA_BATCHES
        "nfs3|step128|step_128_*.itf.json|"
        "nfs3|step256|step_256_*.itf.json|"
        "nfs3|churn128|stepChurn_128_*.itf.json|"
        "nfs3|churn256|stepChurn_256_*.itf.json|"
        "nfs3|dir|stepDir_128_*.itf.json|"
        "nfs3|excl|stepExcl_128_*.itf.json|")
    foreach(inst nfs4Memfs42 nfs4Memfs41 nfs4Memfs40)
        foreach(fs step stepState stepNamespace stepData stepTypes)
            list(APPEND GANESHA_BATCHES
                 "nfs4|${inst}_${fs}|${inst}_${fs}_80_*.itf.json|")
        endforeach()
    endforeach()
    list(APPEND GANESHA_BATCHES
         "nfs4|nfs4Memfs42_stepData42|nfs4Memfs42_stepData42_80_*.itf.json|"
         "nfs4|nfs4Memfs42Deleg_stepDeleg|nfs4Memfs42Deleg_stepDeleg_80_*.itf.json|SPECS_NFS_DELEG=1"
         "nfs4|nfs4Memfs41Deleg_stepDeleg|nfs4Memfs41Deleg_stepDeleg_80_*.itf.json|SPECS_NFS_DELEG=1"
         "nfs4pnfs|nfs4Pnfs42_stepPnfs|nfs4Pnfs42_stepPnfs_80_*.itf.json|"
         "nfs4pnfs|nfs4Pnfs41_stepPnfs|nfs4Pnfs41_stepPnfs_80_*.itf.json|")

    foreach(b ${GANESHA_BATCHES})
        string(REPLACE "|" ";" parts "${b}")
        list(GET parts 0 suite)
        list(GET parts 1 bname)
        list(GET parts 2 bglob)
        list(LENGTH parts nparts)
        set(extra_env)
        if(nparts GREATER 3)
            list(GET parts 3 extra_env)
        endif()
        if(suite STREQUAL "nfs4pnfs")
            set(replayer nfs4)
        else()
            set(replayer ${suite})
        endif()
        set(tname ganesha/${suite}/${bname})
        add_test(NAME ${tname}
                 COMMAND ${NFS_HARNESS}/run_nfs_mbt.sh ganesha ${replayer}
                         ${T}/${suite} ${bglob})
        # TIMEOUT: up to 10 traces, each on a fresh server, at 80-256 steps
        # against a real server -- minutes, not seconds.
        set_tests_properties(${tname} PROPERTIES
            LABELS "ganesha;${suite};mbt"
            TIMEOUT 1800
            SKIP_RETURN_CODE 77
            ENVIRONMENT "GANESHA=${GANESHA_BIN};RPCBIND=${RPCBIND_BIN}")
        if(extra_env)
            set_property(TEST ${tname} APPEND PROPERTY ENVIRONMENT "${extra_env}")
        endif()
        if(NOT CONFORMANCE_NETNS)
            set_tests_properties(${tname} PROPERTIES
                RESOURCE_LOCK nfs_server_ports)
            set_property(TEST ${tname} APPEND PROPERTY
                ENVIRONMENT "SPECS_NFS_NO_NETNS=1")
        endif()
    endforeach()
endif()

# ---------------------------------------------------------------------------
# knfsd conformance (harness/nfs, SERVER=knfsd)
#
# The same corpus, replayed against the Linux kernel NFS server booted in a
# KVM guest -- a third, unrelated reference beside Ganesha and the model.  The
# guest image (chimera-nas/kvm-test-base >= v1.10.0, which carries
# nfs-kernel-server) is fetched by CI and its directory passed in KVM_IMAGE_DIR;
# each batch boots one guest and drives it from the host side of a TAP link,
# resetting the export between traces over a 9p control channel.  Needs
# /dev/kvm at run time (the runner SKIPs without it) and qemu on the host.
# ---------------------------------------------------------------------------
if(NOT SPECS_KNFSD_TESTS)
    message(STATUS
        "knfsd MBT tests: not registered (specs is a subdirectory of "
        "${CMAKE_PROJECT_NAME}; -DSPECS_KNFSD_TESTS=ON with -DKVM_IMAGE_DIR to "
        "register them)")
elseif(NOT KVM_IMAGE_DIR OR NOT EXISTS "${KVM_IMAGE_DIR}/vmlinuz"
       OR NOT EXISTS "${KVM_IMAGE_DIR}/rootfs.qcow2")
    message(STATUS
        "knfsd MBT tests: disabled (no KVM guest image; set KVM_IMAGE_DIR to a "
        "directory with vmlinuz + rootfs.qcow2)")
else()
    find_program(QEMU_BIN NAMES qemu-system-x86_64 qemu-system-aarch64
                 DOC "qemu, which boots the knfsd guest")
    if(NOT QEMU_BIN)
        message(STATUS "knfsd MBT tests: disabled (qemu-system not found)")
    else()
        message(STATUS "knfsd MBT tests: enabled (guest ${KVM_IMAGE_DIR}, "
                "${QEMU_BIN})")
        # The same batches the ganesha suite drives (the corpus is shared); the
        # knfsd runner boots a guest per batch instead of a server per trace.
        set(KNFSD_BATCHES
            "nfs3|step128|step_128_*.itf.json"
            "nfs3|step256|step_256_*.itf.json"
            "nfs3|churn128|stepChurn_128_*.itf.json"
            "nfs3|churn256|stepChurn_256_*.itf.json"
            "nfs3|dir|stepDir_128_*.itf.json"
            "nfs3|excl|stepExcl_128_*.itf.json")
        foreach(inst nfs4Memfs42 nfs4Memfs41 nfs4Memfs40)
            foreach(fs step stepState stepNamespace stepData stepTypes)
                list(APPEND KNFSD_BATCHES
                     "nfs4|${inst}_${fs}|${inst}_${fs}_80_*.itf.json")
            endforeach()
        endforeach()
        list(APPEND KNFSD_BATCHES
             "nfs4|nfs4Memfs42_stepData42|nfs4Memfs42_stepData42_80_*.itf.json")

        foreach(b ${KNFSD_BATCHES})
            string(REPLACE "|" ";" parts "${b}")
            list(GET parts 0 suite)
            list(GET parts 1 bname)
            list(GET parts 2 bglob)
            set(tname knfsd/${suite}/${bname})
            add_test(NAME ${tname}
                     COMMAND ${NFS_HARNESS}/run_nfs_mbt.sh knfsd ${suite}
                             ${T}/${suite} ${bglob})
            # A guest boot plus up to ~10 traces, each resetting the export:
            # minutes.  SKIP_RETURN_CODE 77 lets the runner report "no /dev/kvm
            # here" or "no guest image" as a ctest SKIP.
            set_tests_properties(${tname} PROPERTIES
                LABELS "knfsd;${suite};mbt"
                TIMEOUT 1800
                SKIP_RETURN_CODE 77
                ENVIRONMENT "KVM_VMLINUZ=${KVM_IMAGE_DIR}/vmlinuz;KVM_ROOTFS=${KVM_IMAGE_DIR}/rootfs.qcow2")
            # Every knfsd batch boots a guest that binds the same TAP subnet and
            # NFS ports; without a netns per test they would collide, so if the
            # netns is unavailable they serialize under one lock.
            if(NOT CONFORMANCE_NETNS)
                set_tests_properties(${tname} PROPERTIES
                    RESOURCE_LOCK nfs_server_ports)
                set_property(TEST ${tname} APPEND PROPERTY
                    ENVIRONMENT "SPECS_NFS_NO_NETNS=1")
            endif()
        endforeach()
    endif()
endif()

# ---------------------------------------------------------------------------
# ext4 conformance (harness/posix)
#
# The POSIX counterpart of the Samba and NFS suites: replay the generated
# POSIX corpus against a real ext4 filesystem, in a KVM guest, and compare
# every syscall's outcome to the result the model baked into the trace.
# Disagreements are findings -- a model bug, or a Linux/ext4 divergence
# recorded with a citation in harness/posix/ext4_deviations.py.  A NEW one
# turns the suite red.
#
# A guest rather than a container, because the POSIX corpus is not a protocol:
# driving it needs a filesystem the harness may mount, a kernel it may set
# sysctls on, and root to fork the per-credential workers -- none of which
# the devcontainer the other suites run in can offer reproducibly.  The guest
# image is the same chimera-nas/kvm-test-base one the knfsd suite boots
# (KVM_IMAGE_DIR); there is no network at all, so unlike knfsd these tests
# need no network namespace and never collide with each other.
#
# One ctest per generation batch, derived from POSIX_BATCHES above so the two
# cannot drift: every posixExt4 batch generated is a batch replayed.
# ---------------------------------------------------------------------------
set(POSIX_HARNESS ${CMAKE_CURRENT_SOURCE_DIR}/harness/posix)

if(NOT SPECS_EXT4_TESTS)
    message(STATUS
        "ext4 MBT tests: not registered (specs is a subdirectory of "
        "${CMAKE_PROJECT_NAME}; -DSPECS_EXT4_TESTS=ON with -DKVM_IMAGE_DIR to "
        "register them)")
elseif(NOT KVM_IMAGE_DIR OR NOT EXISTS "${KVM_IMAGE_DIR}/vmlinuz"
       OR NOT EXISTS "${KVM_IMAGE_DIR}/rootfs.qcow2")
    message(STATUS
        "ext4 MBT tests: disabled (no KVM guest image; set KVM_IMAGE_DIR to a "
        "directory with vmlinuz + rootfs.qcow2)")
else()
    find_program(QEMU_BIN NAMES qemu-system-x86_64 qemu-system-aarch64
                 DOC "qemu, which boots the guest the ext4 suite measures")
    find_program(MKFS_EXT4_BIN NAMES mkfs.ext4 PATHS /sbin /usr/sbin
                 DOC "mke2fs, which builds the filesystem under test")
    if(NOT QEMU_BIN)
        message(STATUS "ext4 MBT tests: disabled (qemu-system not found)")
    elseif(NOT MKFS_EXT4_BIN)
        message(STATUS "ext4 MBT tests: disabled (mkfs.ext4 not found)")
    else()
        message(STATUS "ext4 MBT tests: enabled (guest ${KVM_IMAGE_DIR}, "
                "${QEMU_BIN})")

        set(EXT4_ENV
            "KVM_VMLINUZ=${KVM_IMAGE_DIR}/vmlinuz;KVM_ROOTFS=${KVM_IMAGE_DIR}/rootfs.qcow2")

        # The pinned capability/policy profile is a measurement (see
        # EXT4_PROFILE in posix_replay.py), and trace generation assumes it
        # -- posix_run.qnt's posixExt4 instance pins the same values.  If the
        # live filesystem drifts from it the corpus is not wrong, it is
        # answering a question about a filesystem that is no longer there,
        # and every trace would skip on the profile mismatch instead.  Check
        # it directly so the drift is reported once, as itself.
        add_test(NAME ext4/profile
                 COMMAND ${POSIX_HARNESS}/run_posix_mbt.sh ${T}/posix
                         "ext4_step_128_0x1_0.itf.json")
        set_tests_properties(ext4/profile PROPERTIES
            LABELS "ext4;posix;mbt"
            TIMEOUT 600
            SKIP_RETURN_CODE 77
            ENVIRONMENT "${EXT4_ENV};SPECS_POSIX_CHECK_PROFILE=1")

        foreach(b ${POSIX_BATCHES})
            string(REPLACE "|" ";" parts "${b}")
            list(GET parts 0 inst)
            if(NOT inst STREQUAL "posixExt4")
                continue()
            endif()
            list(GET parts 1 pfx)
            list(GET parts 2 flavor)
            list(GET parts 3 steps)
            list(GET parts 5 seed)
            set(tname ext4/posix/${flavor}_${steps}_${seed})
            add_test(NAME ${tname}
                     COMMAND ${POSIX_HARNESS}/run_posix_mbt.sh ${T}/posix
                             "${pfx}${flavor}_${steps}_${seed}_*.itf.json")
            # A guest boot plus up to 10 traces of 128-512 syscalls each,
            # every one of them a real syscall on a real filesystem:
            # minutes.  SKIP_RETURN_CODE 77 lets the runner report "no
            # /dev/kvm here" or "no guest image" as a ctest SKIP.
            set_tests_properties(${tname} PROPERTIES
                LABELS "ext4;posix;mbt"
                TIMEOUT 1800
                SKIP_RETURN_CODE 77
                ENVIRONMENT "${EXT4_ENV}")
        endforeach()
    endif()
endif()
