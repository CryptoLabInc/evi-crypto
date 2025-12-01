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

cpmaddpackage(NAME CLI11 GITHUB_REPOSITORY CLIUtils/CLI11 VERSION 2.4.0)

set(CLI11_TGT "")
if(TARGET CLI11::CLI11)
  set(CLI11_TGT CLI11::CLI11)
elseif(TARGET CLI11)
  set(CLI11_TGT CLI11)
endif()

if(USE_PROFILE)
  cpmaddpackage(NAME perfetto GITHUB_REPOSITORY google/perfetto GIT_TAG v50.1)
  add_library(perfetto STATIC ${perfetto_SOURCE_DIR}/sdk/perfetto.cc)
  target_include_directories(perfetto PUBLIC ${perfetto_SOURCE_DIR}/sdk)
endif()

set(DEB_PARAMETER_JSON
    "${CMAKE_CURRENT_SOURCE_DIR}/deb-param.json"
    CACHE STRING "" FORCE)
set(DEB_MEMORY_ALIGN_SIZE
    "${ALIGNMENT_BYTE}"
    CACHE STRING "" FORCE)

if(DEFINED ENV{GITHUB_TOKEN})
  cpmaddpackage(
    NAME
    deb
    GIT_REPOSITORY
    "https://$ENV{GITHUB_TOKEN}@github.com/CryptoLabInc/deb.git"
    GIT_TAG
    v0.2.1
    OPTIONS
    "DEB_BUILD_EXAMPLES OFF"
    "DEB_BUILD_TEST OFF"
    "DEB_BUILD_WITH_OMP OFF"
    "DEB_INSTALL_ALEA ON"
    "DEB_RUNTIME_RESOURCE_CHECK OFF")
else()
  cpmaddpackage(
    NAME
    deb
    GITHUB_REPOSITORY
    CryptoLabInc/deb
    GIT_TAG
    v0.2.1
    OPTIONS
    "DEB_BUILD_EXAMPLES OFF"
    "DEB_BUILD_TEST OFF"
    "DEB_BUILD_WITH_OMP OFF"
    "DEB_INSTALL_ALEA ON"
    "DEB_RUNTIME_RESOURCE_CHECK OFF")
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
