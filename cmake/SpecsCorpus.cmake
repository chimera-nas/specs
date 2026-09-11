# SPDX-FileCopyrightText: 2026 The Quint Specs Authors
#
# SPDX-License-Identifier: MIT
#
# The corpus API this repo exports to a consuming project.
#
# A CONFIG is the unit.  It fixes every constant the model family declares --
# which optional features the implementation has, which of several legal
# behaviours it chose, which known deviations it still carries -- and it carries
# the batch list.  So one config fully determines one corpus, and the cell that
# replays that corpus runs ALL of it and expects every reply to match.  No
# filename-prefix carving at replay time, no per-trace skipping.
#
# The consumer owns its configs.  chimera's live beside the harness that
# replays them; this repo's own conformance suites (samba, ganesha, knfsd) keep
# theirs under harness/<impl>/configs/.  Nothing in quint/ names an
# implementation any more.
#
# Usage from a consumer:
#
#   specs_corpus(NAME    posix/nfs3_diskfs
#                FAMILY  posix
#                CONFIG  ${CMAKE_CURRENT_SOURCE_DIR}/configs/nfs3_diskfs.json
#                OUT_DIR nfs3_diskfs_traces)   # set in the caller's scope
#   ...
#   specs_corpus_finalize()                    # once, after every registration
#
# OUT_DIR names a variable that receives the cell's trace directory, which is
# what the replay ctest points at.  The directory does not exist until the
# build runs; that is fine, the replayers take a directory rather than a list.
#
# Cost model.  Elaborating a family (load, parse, typecheck) is 16-185s and is
# 38-70% of that family's generation cost; simulating a batch is 2-20s.  So
# finalize emits ONE build edge per family covering every cell, and tools/gen.js
# elaborates once and simulates every batch against the same typechecked stage.
# Adding a cell costs simulation, not elaboration.

find_program(QUINT_BIN quint)
find_program(NODE_BIN NAMES node nodejs)

set(SPECS_CORPUS_ROOT "${CMAKE_BINARY_DIR}/specs-corpus" CACHE PATH
    "Root of the generated per-cell trace corpora")
set(SPECS_STAGE_DIR "${CMAKE_BINARY_DIR}/specs-gen" CACHE PATH
    "Staging tree: a symlink mirror of quint/ plus the generated config modules")

# Which simulator backend generation drives.  TypeScript by default because the
# Rust evaluator is published only against glibc 2.39 and will not run on the
# ubuntu 22.04 / rocky 9 CI images -- and with no prebuilt bundle any more, a
# backend that cannot run somewhere costs that platform its MBT suites outright.
# Rust is faster on the large families; switch to it where it runs and where a
# corpus regenerated under a different backend is acceptable (the two backends
# walk differently for the same seed, so the traces are not the same traces).
set(SPECS_QUINT_BACKEND "typescript" CACHE STRING
    "quint simulator backend for trace generation (typescript or rust)")
set_property(CACHE SPECS_QUINT_BACKEND PROPERTY STRINGS typescript rust)

# Replay a corpus generated elsewhere instead of generating one.  Cells are
# still registered and still validated -- mkconfig runs, so a broken config or
# an undeclared deviation is still a configure error -- but no build edge is
# emitted, so the traces are INPUTS rather than outputs and nothing regenerates
# on top of them.
#
# This is what lets one CI run generate the corpus once and replay the exact
# same bytes against several servers: three conformance jobs that each
# regenerated would be three chances to disagree about what they were testing,
# and would pay the generation cost three times.  Point SPECS_CORPUS_ROOT at the
# unpacked corpus and set this ON.
option(SPECS_CORPUS_PREBUILT
       "Replay the corpus already present at SPECS_CORPUS_ROOT; generate nothing"
       OFF)

# NOTE on scope: this file is include()d from ext/specs/CMakeLists.txt, i.e. in
# the ext/specs DIRECTORY scope, while specs_corpus_finalize() is called from
# the consumer's top-level CMakeLists.  A CMake function runs in its CALLER's
# variable scope, so a plain set() here would be invisible there and every path
# below would come out empty (the symptom is finalize reporting
# "family 'x' has no /quint/x/corpus.schema.json" -- note the leading slash).
# CMAKE_CURRENT_FUNCTION_LIST_DIR is the directory of the file that DEFINED the
# running function, so deriving the paths inside each function is correct from
# any caller and needs no cache entries.
#
# The stage mirrors quint/ with symlinks because quint resolves imports relative
# to the importing file and rejects an absolute path outright, so a generated
# module has to sit inside the same relative layout as the models it imports.
# See the header of tools/mkconfig.js.

define_property(GLOBAL PROPERTY SPECS_CORPUS_FAMILIES
    BRIEF_DOCS "families with at least one registered cell"
    FULL_DOCS  "families with at least one registered cell")

# Register one cell.  Accumulates; nothing is emitted until finalize.
# STRICT_OUT_DIR additionally registers a strict twin of the cell: the same
# config with every deviation forced off.  Its failures are the implementation's
# conformance debt, re-measured on every run rather than remembered in a
# registry -- which is what keeps a deviation from outliving its fix.  Replay it
# as a REPORTING test (extended tier), not a gate.
function(specs_corpus)
    cmake_parse_arguments(SC "" "NAME;FAMILY;CONFIG;OUT_DIR;STRICT_OUT_DIR" "" ${ARGN})
    if(NOT SC_NAME OR NOT SC_FAMILY OR NOT SC_CONFIG)
        message(FATAL_ERROR "specs_corpus: NAME, FAMILY and CONFIG are required")
    endif()
    if(NOT EXISTS ${SC_CONFIG})
        message(FATAL_ERROR "specs_corpus(${SC_NAME}): no config at ${SC_CONFIG}")
    endif()

    set_property(GLOBAL APPEND PROPERTY SPECS_CORPUS_FAMILIES ${SC_FAMILY})
    set_property(GLOBAL APPEND PROPERTY SPECS_FAM_${SC_FAMILY}_CELLS ${SC_NAME})
    set_property(GLOBAL APPEND PROPERTY SPECS_FAM_${SC_FAMILY}_CONFIGS ${SC_CONFIG})

    # The trace directory is derived, so the caller can have it now even though
    # the traces themselves are a build product.
    if(SC_OUT_DIR)
        set(${SC_OUT_DIR} "${SPECS_CORPUS_ROOT}/${SC_NAME}" PARENT_SCOPE)
    endif()

    if(SC_STRICT_OUT_DIR)
        set_property(GLOBAL APPEND PROPERTY SPECS_FAM_${SC_FAMILY}_CELLS
                     ${SC_NAME}-strict)
        set_property(GLOBAL APPEND PROPERTY SPECS_FAM_${SC_FAMILY}_CONFIGS
                     ${SC_CONFIG})
        set_property(GLOBAL APPEND PROPERTY SPECS_FAM_${SC_FAMILY}_STRICT
                     ${SC_NAME}-strict)
        set(${SC_STRICT_OUT_DIR} "${SPECS_CORPUS_ROOT}/${SC_NAME}-strict"
            PARENT_SCOPE)
    endif()

    # Reconfigure when a config changes: the batch list lives there, and the
    # build edge's outputs are computed from it at configure time.
    set_property(DIRECTORY ${CMAKE_SOURCE_DIR} APPEND
                 PROPERTY CMAKE_CONFIGURE_DEPENDS ${SC_CONFIG})
endfunction()

# Emit the build edges: one per family, covering every cell registered for it.
function(specs_corpus_finalize)
    get_property(families GLOBAL PROPERTY SPECS_CORPUS_FAMILIES)
    if(NOT families)
        return()
    endif()
    list(REMOVE_DUPLICATES families)

    # Resolved here rather than at file scope: see the scope note at the top.
    get_filename_component(specs_root "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/.."
                           ABSOLUTE)
    set(mkconfig ${specs_root}/tools/mkconfig.js)
    set_property(DIRECTORY ${CMAKE_SOURCE_DIR} APPEND
                 PROPERTY CMAKE_CONFIGURE_DEPENDS ${mkconfig})
    set(gen_js   ${specs_root}/tools/gen.js)

    if(NOT NODE_BIN OR (NOT QUINT_BIN AND NOT SPECS_CORPUS_PREBUILT))
        message(FATAL_ERROR
            "specs: quint and node are required to generate the trace corpus "
            "(npm i -g @informalsystems/quint@$(cat ${specs_root}/.quint-version)). "
            "Configure with -DCHIMERA_MBT_CORPUS=OFF to build without one.")
    endif()

    set(all_traces)
    foreach(fam ${families})
        get_property(cells   GLOBAL PROPERTY SPECS_FAM_${fam}_CELLS)
        get_property(configs GLOBAL PROPERTY SPECS_FAM_${fam}_CONFIGS)
        set(schema ${specs_root}/quint/${fam}/corpus.schema.json)
        if(NOT EXISTS ${schema})
            message(FATAL_ERROR
                "specs: family '${fam}' has no ${schema}; a family that a "
                "consumer configures must declare its knobs")
        endif()

        # Reconfigure when the SCHEMA changes, for the same reason a config
        # does: the schema is the list of constants mkconfig renders into each
        # cell module, so adding or retiring one leaves every cfg_*.qnt in an
        # existing build tree naming a set of constants the model no longer
        # declares.  Quint elaborates that fine and then fails every batch at
        # simulate time with an unhelpful bare "undefined", which is a long
        # way from "you edited a schema".  mkconfig.js itself is listed for
        # the same reason -- it decides how a knob is rendered.
        set_property(DIRECTORY ${CMAKE_SOURCE_DIR} APPEND
                     PROPERTY CMAKE_CONFIGURE_DEPENDS ${schema})

        # Build the mkconfig spec.  Cells and configs are parallel lists.
        set(celljson "")
        list(LENGTH cells ncells)
        math(EXPR last "${ncells} - 1")
        foreach(i RANGE 0 ${last})
            list(GET cells ${i} cname)
            list(GET configs ${i} cpath)
            get_property(strictcells GLOBAL PROPERTY SPECS_FAM_${fam}_STRICT)
            set(isstrict "false")
            if(strictcells AND "${cname}" IN_LIST strictcells)
                set(isstrict "true")
            endif()
            string(APPEND celljson
                   "    {\"name\": \"${cname}\", \"config\": \"${cpath}\", \"strict\": ${isstrict}}")
            if(i LESS last)
                string(APPEND celljson ",\n")
            endif()
        endforeach()

        set(mkspec ${SPECS_STAGE_DIR}/${fam}.mkconfig.json)
        file(WRITE ${mkspec}
"{
  \"family\": \"${fam}\",
  \"schema\": \"${schema}\",
  \"specsRoot\": \"${specs_root}\",
  \"stage\": \"${SPECS_STAGE_DIR}\",
  \"corpusRoot\": \"${SPECS_CORPUS_ROOT}\",
  \"quintCli\": \"${QUINT_BIN}\",
  \"backend\": \"${SPECS_QUINT_BACKEND}\",
  \"cells\": [
${celljson}
  ]
}
")

        # Render the config modules and compute the trace list, at CONFIGURE
        # time: CMake has to know the outputs to make a build edge out of them.
        execute_process(
            COMMAND ${NODE_BIN} ${mkconfig} ${mkspec}
            RESULT_VARIABLE rc
            OUTPUT_VARIABLE out
            ERROR_VARIABLE err)
        if(NOT rc EQUAL 0)
            message(FATAL_ERROR "specs: mkconfig failed for ${fam}:\n${out}${err}")
        endif()
        string(STRIP "${out}" out)
        message(STATUS "specs: ${out}")

        include(${SPECS_STAGE_DIR}/${fam}.cmake)

        if(SPECS_CORPUS_PREBUILT)
            # The traces are inputs.  Emitting the edge here would make ninja
            # treat every trace as something it must produce, and it would
            # regenerate the corpus on top of the one supplied -- which is the
            # whole thing this mode exists to avoid.
            continue()
        endif()

        add_custom_command(
            OUTPUT ${SPECS_${fam}_ALL_TRACES}
            COMMAND ${NODE_BIN} ${gen_js} ${SPECS_${fam}_GENSPEC}
            DEPENDS ${SPECS_${fam}_DEPS} ${gen_js} ${SPECS_${fam}_GENSPEC}
            COMMENT "${fam}: self-test + generate traces for ${ncells} cell(s) (one elaboration)"
            VERBATIM)
        list(APPEND all_traces ${SPECS_${fam}_ALL_TRACES})
    endforeach()

    add_custom_target(specs_corpus ALL DEPENDS ${all_traces})
endfunction()
