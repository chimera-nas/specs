# SPDX-FileCopyrightText: 2026 The Quint Specs Authors
# SPDX-License-Identifier: MIT
cmake_minimum_required(VERSION 3.22)
project(specs_native_consumer NONE)
get_filename_component(SPECS_SOURCE_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../.." ABSOLUTE)
add_subdirectory("${SPECS_SOURCE_ROOT}" specs)
specs_corpus(NAME smb2/native FAMILY smb2
    CONFIG "${SPECS_SOURCE_ROOT}/harness/samba/configs/core.json"
    OUT_DIR NATIVE_TRACES)
specs_corpus_finalize()
