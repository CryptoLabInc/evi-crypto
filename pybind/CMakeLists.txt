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

find_package(pybind11 REQUIRED)

set(_pybind_srcs
    bind_context.cpp
    bind_decryptor.cpp
    bind_encryptor.cpp
    bind_key_generator.cpp
    bind_keypack.cpp
    bind_utils.cpp
    bind_types.cpp
    module.cpp)

if(BUILD_KEY_MANAGEMENT)
  list(APPEND _pybind_srcs bind_key_manager.cpp)
endif()

pybind11_add_module(evi ${_pybind_srcs})

if(BUILD_KEY_MANAGEMENT)
  target_compile_definitions(evi PRIVATE EVI_KEY_MANAGEMENT)
endif()

set_target_properties(evi PROPERTIES PREFIX "")

add_dependencies(evi ${PROJECT_LIB_NAME})

target_link_libraries(evi PUBLIC ${PROJECT_LIB_NAME} ${PROJECT_DEPENDENCY})
target_compile_definitions(evi PUBLIC ${COMPILE_OPTION})

target_include_directories(
  evi PUBLIC $<INSTALL_INTERFACE:include>
             $<BUILD_INTERFACE:${CMAKE_HOME_DIRECTORY}/include>)

add_custom_command(
  TARGET evi
  POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy_directory
          ${PROJECT_SOURCE_DIR}/pybind/pymodule ${CMAKE_BINARY_DIR}/pymodule)

set(_pymodule_dir ${CMAKE_BINARY_DIR}/pymodule/evi)
set(_pymodule_lib_dir ${_pymodule_dir}/lib)
set(_pymodule_lib64_dir ${_pymodule_dir}/lib64)

if(APPLE)
  set(_shared_lib_ext ".dylib")
elseif(WIN32)
  set(_shared_lib_ext ".dll")
else()
  set(_shared_lib_ext ".so")
endif()

add_custom_command(
  TARGET evi
  POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E make_directory ${_pymodule_lib_dir}
  COMMAND ${CMAKE_COMMAND} -E make_directory ${_pymodule_lib64_dir}
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
          $<TARGET_FILE:${PROJECT_LIB_NAME}> ${_pymodule_lib_dir}/
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
          $<TARGET_FILE:${PROJECT_LIB_NAME}> ${_pymodule_lib64_dir}/)

# On Windows, bundle OpenSSL DLLs so the wheel is self-contained. FindOpenSSL
# creates UNKNOWN IMPORTED targets whose properties use per-configuration
# suffixes (IMPORTED_IMPLIB_RELEASE) under multi-config generators like Visual
# Studio.  Derive the DLL location from OPENSSL_INCLUDE_DIR (a plain variable
# always set by FindOpenSSL) instead.
if(WIN32 AND OPENSSL_INCLUDE_DIR)
  get_filename_component(_openssl_prefix "${OPENSSL_INCLUDE_DIR}" DIRECTORY)
  file(GLOB _openssl_dlls "${_openssl_prefix}/bin/libssl*.dll"
       "${_openssl_prefix}/bin/libcrypto*.dll")
  if(_openssl_dlls)
    message(STATUS "Bundling OpenSSL DLLs: ${_openssl_dlls}")
    add_custom_command(
      TARGET evi
      POST_BUILD
      COMMAND ${CMAKE_COMMAND} -E copy_if_different ${_openssl_dlls}
              ${_pymodule_lib_dir}/
      COMMAND ${CMAKE_COMMAND} -E copy_if_different ${_openssl_dlls}
              ${_pymodule_lib64_dir}/)
  else()
    message(WARNING "No OpenSSL DLLs found in ${_openssl_prefix}/bin/")
  endif()
endif()

if(BUILD_KEY_MANAGEMENT
   AND EVI_KM_PREFER_AWS_SDK
   AND DEFINED _evi_aws_external_prefix)
  # Bundle AWS SDK shared libraries into the Python package so runtime loading
  # works without host-level aws-sdk installation.
  file(
    GLOB
    _evi_aws_shared_libs
    "${_evi_aws_external_prefix}/lib/libaws*.so*"
    "${_evi_aws_external_prefix}/lib/libaws*.dylib*"
    "${_evi_aws_external_prefix}/lib/aws*.dll"
    "${_evi_aws_external_prefix}/lib64/libaws*.so*"
    "${_evi_aws_external_prefix}/lib64/libaws*.dylib*"
    "${_evi_aws_external_prefix}/lib64/aws*.dll")

  if(_evi_aws_shared_libs)
    add_custom_command(
      TARGET evi
      POST_BUILD
      COMMAND ${CMAKE_COMMAND} -E copy_if_different ${_evi_aws_shared_libs}
              ${_pymodule_lib_dir}/
      COMMAND ${CMAKE_COMMAND} -E copy_if_different ${_evi_aws_shared_libs}
              ${_pymodule_lib64_dir}/)
  endif()
endif()

# Windows has no RPATH; DLLs must be in the same directory or on PATH.
if(NOT WIN32)
  set(CMAKE_BUILD_WITH_INSTALL_RPATH TRUE)
  if(APPLE)
    set(_origin "@loader_path")
  else()
    set(_origin "$ORIGIN")
  endif()
  set_target_properties(
    evi PROPERTIES INSTALL_RPATH "${_origin};${_origin}/lib;${_origin}/lib64"
                   BUILD_RPATH "${_origin};${_origin}/lib;${_origin}/lib64")
endif()

install(
  TARGETS evi
  LIBRARY DESTINATION .
  RUNTIME DESTINATION .)
install(FILES ${CMAKE_BINARY_DIR}/pymodule/evi/__init__.py DESTINATION .)

install(
  DIRECTORY ${_pymodule_lib_dir}/
  DESTINATION lib
  FILES_MATCHING
  PATTERN "*.so"
  PATTERN "*.so.*"
  PATTERN "*.dylib"
  PATTERN "*.dylib.*"
  PATTERN "*.dll")

install(
  DIRECTORY ${_pymodule_lib64_dir}/
  DESTINATION lib64
  FILES_MATCHING
  PATTERN "*.so"
  PATTERN "*.so.*"
  PATTERN "*.dylib"
  PATTERN "*.dylib.*"
  PATTERN "*.dll")

if(BUILD_KEY_MANAGEMENT
   AND EVI_KM_PREFER_AWS_SDK
   AND DEFINED _evi_aws_external_prefix)
  # ExternalProject artifacts are produced after configure, so copy AWS SDK
  # libraries during install phase directly from the external install prefix.
  install(
    DIRECTORY "${_evi_aws_external_prefix}/lib/"
    DESTINATION lib
    OPTIONAL FILES_MATCHING
    PATTERN "libaws*.so"
    PATTERN "libaws*.so.*"
    PATTERN "libaws*.dylib"
    PATTERN "libaws*.dylib.*"
    PATTERN "aws*.dll"
    PATTERN "libs2n*.so"
    PATTERN "libs2n*.so.*"
    PATTERN "libs2n*.dylib"
    PATTERN "libs2n*.dylib.*"
    PATTERN "s2n*.dll")

  # Some builds place AWS SDK shared libs only under lib/. Mirror those into
  # lib64 as well so consumers that resolve from lib64 can still locate them.
  install(
    DIRECTORY "${_evi_aws_external_prefix}/lib/"
    DESTINATION lib64
    OPTIONAL FILES_MATCHING
    PATTERN "libaws*.so"
    PATTERN "libaws*.so.*"
    PATTERN "libaws*.dylib"
    PATTERN "libaws*.dylib.*"
    PATTERN "aws*.dll"
    PATTERN "libs2n*.so"
    PATTERN "libs2n*.so.*"
    PATTERN "libs2n*.dylib"
    PATTERN "libs2n*.dylib.*"
    PATTERN "s2n*.dll")

  install(
    DIRECTORY "${_evi_aws_external_prefix}/lib64/"
    DESTINATION lib64
    OPTIONAL FILES_MATCHING
    PATTERN "libaws*.so"
    PATTERN "libaws*.so.*"
    PATTERN "libaws*.dylib"
    PATTERN "libaws*.dylib.*"
    PATTERN "aws*.dll"
    PATTERN "libs2n*.so"
    PATTERN "libs2n*.so.*"
    PATTERN "libs2n*.dylib"
    PATTERN "libs2n*.dylib.*"
    PATTERN "s2n*.dll")
endif()

install(
  DIRECTORY ${CMAKE_BINARY_DIR}/pymodule/cli
  DESTINATION .
  FILES_MATCHING
  PATTERN "*.py")
