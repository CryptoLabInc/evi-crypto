# ~~~
#  Copyright (C) 2025, CryptoLab, Inc.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
# ~~~
include(CPM)

# Guard: when built as a subdirectory of evi, CLI11 is already registered by
# evi/external/CMakeLists.txt. Standalone crypto/ builds register it here. See
# evi-monorepo-structure-v1.md §5.3.
if(NOT TARGET CLI11 AND NOT TARGET CLI11::CLI11)
  cpmaddpackage(NAME CLI11 GITHUB_REPOSITORY CLIUtils/CLI11 VERSION 2.4.0)
endif()

set(CLI11_TGT "")
if(TARGET CLI11::CLI11)
  set(CLI11_TGT CLI11::CLI11)
elseif(TARGET CLI11)
  set(CLI11_TGT CLI11)
endif()

if(USE_PROFILE AND NOT TARGET perfetto)
  cpmaddpackage(NAME perfetto GITHUB_REPOSITORY google/perfetto GIT_TAG v50.1)
  add_library(perfetto STATIC ${perfetto_SOURCE_DIR}/sdk/perfetto.cc)
  target_include_directories(perfetto PUBLIC ${perfetto_SOURCE_DIR}/sdk)
endif()

# On MSVC the C math library is part of the CRT; there is no separate 'm.lib'.
# alea's CMakeLists.txt does target_link_libraries(alea PRIVATE m), which causes
# LNK1181 on Windows.  Create a no-op 'm' interface target so CMake resolves the
# name without searching for a non-existent library file.
if(MSVC AND NOT TARGET m)
  add_library(m INTERFACE IMPORTED)
endif()

set(DEB_PARAMETER_JSON
    "${CMAKE_CURRENT_SOURCE_DIR}/deb-param.json"
    CACHE STRING "" FORCE)
set(DEB_MEMORY_ALIGN_SIZE
    "${ALIGNMENT_BYTE}"
    CACHE STRING "" FORCE)

# Guard: in a monorepo build, `deb` is brought in transitively by hem
# (registered from evi/external/). Standalone crypto/ builds register it here.
# See evi-monorepo-structure-v1.md §5.3.
if(NOT TARGET deb)
  cpmaddpackage(
    NAME
    deb
    GITHUB_REPOSITORY
    CryptoLabInc/deb
    GIT_TAG
    de429000b1ca577596ac11e18d46319ff3052d7f # deb main (includes u32 support)
    OPTIONS
    "DEB_BUILD_EXAMPLES OFF"
    "DEB_BUILD_TEST OFF"
    "DEB_BUILD_WITH_OMP OFF"
    "DEB_INSTALL_ALEA ON"
    "DEB_RUNTIME_RESOURCE_CHECK OFF"
    "DEB_SUPPORT_U32 ON")
endif()

# ---------------------------------------------------------
# nlohmann_json
# ---------------------------------------------------------
if(NOT TARGET nlohmann_json::nlohmann_json AND NOT TARGET nlohmann_json)
  cpmaddpackage(
    NAME
    nlohmann_json
    GITHUB_REPOSITORY
    nlohmann/json
    VERSION
    3.12.0
    EXCLUDE_FROM_ALL
    YES)
endif()

set(JSON_TGT "")
if(TARGET nlohmann_json::nlohmann_json)
  set(JSON_TGT nlohmann_json::nlohmann_json)
elseif(TARGET nlohmann_json)
  add_library(nlohmann_json::nlohmann_json ALIAS nlohmann_json)
  set(JSON_TGT nlohmann_json::nlohmann_json)
endif()

set(EXTERNAL_LIBS
    ${JSON_TGT}
    PARENT_SCOPE)

set(CLI11_TARGET
    ${CLI11_TGT}
    PARENT_SCOPE)

if(TARGET flatbuffers AND NOT TARGET flatbuffers::flatbuffers)
  add_library(flatbuffers::flatbuffers ALIAS flatbuffers)
endif()
