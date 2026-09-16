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



set(Q ${CMAKE_CURRENT_SOURCE_DIR}/quint)

# The legacy whole-repo corpus is gone.  It generated one static trace set per
# model, with every optional feature explored both ways, and every consumer then
# argued with it at replay time.  A corpus is now determined by a CONFIG --
# cmake/SpecsCorpus.cmake, specs_corpus() -- and the conformance suites below
# each own theirs, so nothing was left replaying the static one.
#
# It also could not survive the models growing a DEVS constant: nfs3 and s3 were
# generated with no --main, so there was no instance to bind it and every batch
# failed with an unbound constant.  The reference corpora the coverage gates
# read are now the STRICT TWINS of the conformance cells -- same models, every
# deviation off, which is precisely the spec-conformant corpus those gates
# always meant to measure.

# Coverage gates: NOT REGISTERED, deliberately, and this is a gap to close.
#
# They classified the LEGACY corpus into behaviour buckets and failed if one was
# never exercised.  That corpus is gone, and the gates cannot simply be repointed
# at a cell:
#
#   * coverage/nfsaux and coverage/nfsdrc have nothing to point AT here.  Those
#     families are configured only by consumers -- this repo owns no cell for
#     either -- so their gates belong with whoever owns the configs.
#   * coverage/nfs4 is a RATCHET against quint/nfs/nfs4_coverage_baseline.txt,
#     recorded over all 142 legacy nfs4 traces.  The conformance cells generate
#     a different set, so the baseline no longer describes them.  Rewriting it
#     (coverage.py --write-expect) is exactly the deliberate act the ratchet
#     exists to force, and doing it as a side effect of this refactor would
#     destroy the signal it was built to give.
#
# The per-cell equivalents that DO run: tools/devliveness.py gates every cell on
# its enabled deviations actually being exercised, and each cell's strict twin
# re-measures the conformance debt.  Neither replaces bucket coverage.
#
# Follow-up: give this repo reference configs (one per family, no deviations),
# point the gates at those cells, and re-baseline the nfs4 ratchet on purpose.

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
# ext4 conformance (harness/posix)
#
# The POSIX model encodes POSIX.1-2024 and the behaviour Linux actually ships
# where the standard leaves a choice.  This cell is what makes that claim
# falsifiable, and its value runs the opposite way to the other conformance
# suites here: ext4 IS the implementation the model was written against, so
# where THIS cell needs a deviation the suspicion falls on the model first.
#
# The traces are replayed by real syscalls, in a KVM guest, by a driver that
# forks one chrooted process per model pid and permanently drops credentials
# into it (harness/posix/posix_driver.py).  A guest is needed for three
# reasons the host cannot give: a scratch ext4 to mkfs per batch, root to
# become arbitrary uids, and Linux's fs.protected_* sysctls turned off -- they
# are a hardening policy layered over POSIX and would otherwise read as
# divergences.
#
# The same guest image the knfsd suite boots (KVM_IMAGE_DIR).
# ---------------------------------------------------------------------------
option(SPECS_EXT4_TESTS "Replay the POSIX corpus against a real ext4 filesystem"
       ${_conformance_default})

if(SPECS_EXT4_TESTS)
    set(POSIX_HARNESS ${CMAKE_CURRENT_SOURCE_DIR}/harness/posix)
    find_program(QEMU_BIN NAMES qemu-system-x86_64 qemu-system-aarch64
                 qemu-system-riscv64)
    set(EXT4_CAN_RUN TRUE)
    if(NOT KVM_IMAGE_DIR OR NOT EXISTS "${KVM_IMAGE_DIR}/vmlinuz"
       OR NOT EXISTS "${KVM_IMAGE_DIR}/rootfs.qcow2")
        set(EXT4_CAN_RUN FALSE)
        message(STATUS
            "ext4 MBT tests: corpus registered, tests disabled (no KVM guest "
            "image; set KVM_IMAGE_DIR to a directory with vmlinuz + "
            "rootfs.qcow2)")
    elseif(NOT QEMU_BIN)
        set(EXT4_CAN_RUN FALSE)
        message(STATUS
            "ext4 MBT tests: corpus registered, tests disabled (qemu-system "
            "not found)")
    else()
        message(STATUS "ext4 MBT tests: enabled (guest ${KVM_IMAGE_DIR}, "
                "${QEMU_BIN})")
    endif()

    # cell config | trace stem | batch names
    set(EXT4_CELLS
        "ext4|ext4|step_128,step_256,step_512,stepNamespace_128,stepNamespace_256,stepDescriptors_128,stepMetadata_128,stepDirs_128,stepData_128,stepLocks_128,stepLocks_256,stepPerms_128,stepLinks_128,stepFds_128,stepTooLong_128,stepPrefix_128,stepFallocate_128,stepVectored_128,stepLockOps_128,stepDevice_128")

    foreach(c ${EXT4_CELLS})
        string(REPLACE "|" ";" parts "${c}")
        list(GET parts 0 cfgname)
        list(GET parts 1 stem)
        list(GET parts 2 bnames)
        string(REPLACE "," ";" bnames "${bnames}")
        set(ecfg ${POSIX_HARNESS}/configs/${cfgname}.json)

        specs_corpus(NAME    ext4/${cfgname}
                     FAMILY  posix
                     CONFIG  ${ecfg}
                     OUT_DIR EXT4_TRACES
                     STRICT_OUT_DIR EXT4_STRICT)

        # The gate that stops a recorded deviation outliving its fix: a
        # deviation this cell enables that no trace in its own corpus ever
        # records having taken fails here.  It needs no guest -- it reads the
        # config and the generated traces -- so it runs everywhere the corpus
        # is built, which is the point, because that is most machines.
        set(SPECS_DEVLIVENESS ${CMAKE_CURRENT_SOURCE_DIR}/tools/devliveness.py)
        add_test(NAME ext4/posix/${cfgname}/devliveness
                 COMMAND ${Python3_EXECUTABLE} ${SPECS_DEVLIVENESS}
                         ${ecfg} ${EXT4_TRACES})
        set_tests_properties(ext4/posix/${cfgname}/devliveness PROPERTIES
            LABELS "ext4;posix;devliveness"
            TIMEOUT 120)

        foreach(bname ${bnames})
            if(NOT EXT4_CAN_RUN)
                continue()
            endif()
            set(tname ext4/posix/${cfgname}/${bname})
            add_test(NAME ${tname}
                     COMMAND ${POSIX_HARNESS}/run_posix_mbt.sh
                             ${EXT4_TRACES} ${stem}_${bname}_*.itf.json)
            # One guest boot plus a mkfs per batch: minutes.  SKIP_RETURN_CODE
            # 77 lets the runner report "no /dev/kvm here" as a ctest SKIP.
            set_tests_properties(${tname} PROPERTIES
                LABELS "ext4;posix;mbt"
                TIMEOUT 1800
                SKIP_RETURN_CODE 77
                ENVIRONMENT "KVM_VMLINUZ=${KVM_IMAGE_DIR}/vmlinuz;KVM_ROOTFS=${KVM_IMAGE_DIR}/rootfs.qcow2")

            # The STRICT twin: the same cell with every deviation forced off,
            # so the corpus states POSIX and nothing else.  Its failures ARE
            # ext4's conformance debt, re-measured every run rather than
            # remembered in a registry.  Extended tier: reporting, not gating.
            add_test(NAME ${tname}-strict
                     CONFIGURATIONS extended
                     COMMAND ${POSIX_HARNESS}/run_posix_mbt.sh
                             ${EXT4_STRICT} ${stem}_${bname}_*.itf.json)
            set_tests_properties(${tname}-strict PROPERTIES
                LABELS "ext4;posix;mbt;strict"
                TIMEOUT 1800
                SKIP_RETURN_CODE 77
                ENVIRONMENT "KVM_VMLINUZ=${KVM_IMAGE_DIR}/vmlinuz;KVM_ROOTFS=${KVM_IMAGE_DIR}/rootfs.qcow2")
        endforeach()
    endforeach()
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
