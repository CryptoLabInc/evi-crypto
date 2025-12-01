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
  release-1.11.0
  OPTIONS
  "INSTALL_GTEST OFF"
  "BUILD_GMOCK OFF")

set(LINK_LIBRARIES ${PROJECT_LIB_NAME} gtest_main)

function(evi_add_test target)
  add_executable(${target} ${ARGN})
  target_link_libraries(${target} PRIVATE ${LINK_LIBRARIES})
  add_gtest_target_to_ctest(${target})
endfunction()

evi_add_test(EnDecryptTest EnDecryptTest.cpp utils.cpp)

evi_add_test(ContextTest ContextTest.cpp utils.cpp)

evi_add_test(KeyValidationTest KeyValidationTest.cpp utils.cpp)
