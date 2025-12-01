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
cmake_minimum_required(VERSION 3.19)
project(EVI_C_API LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(C_API_LIB_NAME evi_c_api)

set(C_API_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)
set(C_API_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)
set(EVI_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../include)

file(GLOB_RECURSE C_API_HEADERS ${C_API_INCLUDE_DIR}/*.h)
file(GLOB_RECURSE C_API_SOURCES ${C_API_SRC_DIR}/*.cpp)

add_library(${C_API_LIB_NAME} STATIC ${C_API_SOURCES} ${C_API_HEADERS})

target_link_libraries(${C_API_LIB_NAME} PUBLIC ${PROJECT_LIB_NAME})
target_include_directories(
  ${C_API_LIB_NAME}
  PUBLIC ${C_API_INCLUDE_DIR} $<BUILD_INTERFACE:${EVI_INCLUDE_DIR}>
         $<INSTALL_INTERFACE:include>)

target_compile_definitions(${C_API_LIB_NAME} PUBLIC BUILD_C_API)

include(GNUInstallDirs)
install(
  TARGETS ${C_API_LIB_NAME}
  EXPORT ${C_API_LIB_NAME}Targets
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  INCLUDES
  DESTINATION include)

install(DIRECTORY ${C_API_INCLUDE_DIR}/ DESTINATION include/evi_c)
# output libevi_c_api.a || libevi_c_api.so

# Test
if(BUILD_TEST)
  include(FetchContent)

  FetchContent_Declare(
    unity
    GIT_REPOSITORY https://github.com/ThrowTheSwitch/Unity.git
    GIT_TAG v2.5.2)

  FetchContent_GetProperties(unity)
  if(NOT unity_POPULATED)
    FetchContent_Populate(unity)
  endif()

  if(NOT TARGET UnityFramework)
    add_library(UnityFramework ${unity_SOURCE_DIR}/src/unity.c)
    target_include_directories(UnityFramework PUBLIC ${unity_SOURCE_DIR}/src)
  endif()

  add_executable(
    evi_c_api_test test/test_runner.c test/context_test.c test/encdec_test.c
                   test/keypack_test.c test/keygenerator_test.c)

  target_include_directories(
    evi_c_api_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include
                           ${unity_SOURCE_DIR}/src)

  target_link_libraries(evi_c_api_test PRIVATE evi_c_api UnityFramework)

  add_test(NAME EVI_C_API_Test COMMAND evi_c_api_test)
endif()
