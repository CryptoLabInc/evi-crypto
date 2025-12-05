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

if(NOT CLI11_TARGET)
  set(CLI11_TARGET CLI11::CLI11)
endif()

set(LINK_LIBRARIES ${PROJECT_LIB_NAME} ${CLI11_TARGET})

function(evi_add_example target)
  add_executable(${target} ${ARGN})
  target_link_libraries(${target} PRIVATE ${LINK_LIBRARIES})
endfunction()

if(BUILD_WITH_VALGRIND)
  add_executable(sampler-constant-time sampler-constant-time.cpp)
  target_link_libraries(sampler-constant-time PRIVATE ${PROJECT_LIB_NAME})
  target_compile_options(sampler-constant-time PRIVATE -O0 -g -Wall)
endif()

evi_add_example(keygen keygen.cpp)
if(BUILD_KEY_MANAGEMENT)
  evi_add_example(km_kp km_kp.cpp)
endif()
