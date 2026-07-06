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

function(add_gtest_target_to_ctest target)
  add_test(NAME "${target}" COMMAND "${target}"
                                    --gtest_output=xml:${target}.xml)
endfunction()

cpmaddpackage(
  NAME
  googletest
  GITHUB_REPOSITORY
  google/googletest
  GIT_TAG
  v1.14.0
  OPTIONS
  "INSTALL_GTEST OFF"
  "BUILD_GMOCK OFF")

set(LINK_LIBRARIES ${PROJECT_LIB_NAME} gtest_main)

function(evi_add_test target)
  add_executable(${target} ${ARGN})
  target_link_libraries(${target} PRIVATE ${LINK_LIBRARIES})
  target_compile_definitions(${target}
                             PRIVATE EVI_PROJECT_ROOT=\"${PROJECT_SOURCE_DIR}\")
  add_gtest_target_to_ctest(${target})
endfunction()

evi_add_test(EnDecryptTest EnDecryptTest.cpp utils.cpp)

evi_add_test(ContextTest ContextTest.cpp utils.cpp)

evi_add_test(KeyValidationTest KeyValidationTest.cpp utils.cpp)

if(BUILD_KEY_MANAGEMENT)
  evi_add_test(KeyManagementTest KeyManagementTest.cpp utils.cpp)
  evi_add_test(AuditTest AuditTest.cpp)
endif()

evi_add_test(SerializationRoundTripTest SerializationRoundTripTest.cpp
             utils.cpp)

# EvisV1FixtureLoadTest reads ~35 MB of pre-refactor binary keys to verify
# wire-format compat. The fixtures live in
# gs://envector-qa/evi/fixtures/evis-v1/ (auth via GitHub OIDC -> WIF ->
# evi-fixture-reader@es2-msa SA). Register the test only if the bundle has been
# fetched: either crypto/test/fixtures/ evis-v1/v1/manifest.json exists (local
# `fetch.sh` or CI workspace download) or $EVIS_V1_FIXTURE_DIR is set so the
# test can find the bundle elsewhere.
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/fixtures/evis-v1/v1/manifest.json"
   OR DEFINED ENV{EVIS_V1_FIXTURE_DIR})
  evi_add_test(EvisV1FixtureLoadTest EvisV1FixtureLoadTest.cpp utils.cpp)
else()
  message(STATUS "EvisV1FixtureLoadTest skipped: fixtures not present "
                 "(run crypto/test/fixtures/evis-v1/fetch.sh to enable).")
endif()

evi_add_test(SecurityTest SecurityTest.cpp)

evi_add_test(EncodeTest EncodeTest.cpp)
evi_add_test(SyncKeyUAFTest SyncKeyUAFTest.cpp utils.cpp)
