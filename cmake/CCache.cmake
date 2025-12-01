# ~~~
#  Copyright (C) 2021-2024, CryptoLab, Inc.
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

# Detect ccache and use it if possible. Modified from:
# https://crascit.com/2016/04/09/using-ccache-with-cmake/#h-improved-functionality-from-cmake-3-4
find_program(CCACHE_PROGRAM ccache)
if(CCACHE_PROGRAM)
  # Set up wrapper scripts
  set(CCACHE_LAUNCHER_DIR "${CMAKE_CURRENT_LIST_DIR}")
  set(CCACHE_LAUNCHER "${CCACHE_PROGRAM}")

  configure_file(${CCACHE_LAUNCHER_DIR}/launch-cxx.in
                 ${CCACHE_LAUNCHER_DIR}/launch-cxx)
  execute_process(COMMAND chmod a+rx "${CCACHE_LAUNCHER_DIR}/launch-cxx")

  if(CMAKE_GENERATOR STREQUAL "Xcode")
    # Set Xcode project attributes to route compilation and linking through our
    # scripts
    set(CMAKE_XCODE_ATTRIBUTE_CXX "${CCACHE_LAUNCHER_DIR}/launch-cxx")
    set(CMAKE_XCODE_ATTRIBUTE_CXX "${CCACHE_LAUNCHER_DIR}/launch-cxx")
    set(CMAKE_XCODE_ATTRIBUTE_LDPLUSPLUS "${CCACHE_LAUNCHER_DIR}/launch-cxx")
  else()
    # Support Unix Makefiles and Ninja
    set(CMAKE_CXX_COMPILER_LAUNCHER "${CCACHE_LAUNCHER_DIR}/launch-cxx")
  endif()

  if(CMAKE_CUDA_COMPILER)
    configure_file(${CCACHE_LAUNCHER_DIR}/launch-cuda.in
                   ${CCACHE_LAUNCHER_DIR}/launch-cuda)
    execute_process(COMMAND chmod a+rx "${CCACHE_LAUNCHER_DIR}/launch-cuda")
    if(NOT CMAKE_GENERATOR STREQUAL "Xcode")
      set(CMAKE_CUDA_COMPILER_LAUNCHER "${CCACHE_LAUNCHER_DIR}/launch-cuda")
    endif()
  endif()
endif()
