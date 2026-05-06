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

project(
  evi_crypto
  VERSION 1.0.0
  DESCRIPTION "Encrypted Vector Index library"
  LANGUAGES CXX)

# set(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)
set(CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake" ${CMAKE_MODULE_PATH})
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(PROJECT_LIB_NAME ${PROJECT_NAME})
set(PROJECT_INSTALL_INCLUDE_DIR "EVI")
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED YES)
set(CMAKE_CXX_EXTENSIONS NO)

include(BuildType OPTIONAL)
include(LTO OPTIONAL)
include(CTest)
include(CheckLanguage)
include(CCache OPTIONAL)

option(BUILD_TEST "Build tests" ON)
option(BUILD_EXAMPLE "Build Examples" ON)
option(BUILD_KEY_MANAGEMENT "Build key management components" ON)
option(BUILD_YUBIHSM "Use HSM for secret key encryption" OFF)
option(BUILD_WITH_VALGRIND
       "Build using Valgrind to check constant-time sampler" OFF)
option(BUILD_WITH_CUDA "Build with CUDA acceleration" OFF)
option(BUILD_AS_STATIC "Build library as static" ON)
option(USE_PROFILE "Activate Perfetto profiler" OFF)
option(BUILD_PYTHON "Build Python bindings" OFF)
option(BUILD_C_API "Build C language wrapper API" OFF)
option(EVI_ENABLE_INSTALL "Generate install/export targets" OFF)
option(HEM_BUILD_FOR_CLIENT
       "Propagate to HEM so it builds client-side components only" ON)
option(EVI_KM_PREFER_AWS_SDK "Prefer AWS SDK for S3 key storage" OFF)
option(EVI_KM_PREFER_GCP_SDK "Prefer google-cloud-cpp for GCS key storage" OFF)
set(EVI_KM_AWS_SDK_GIT_TAG
    "1.11.720"
    CACHE STRING "aws-sdk-cpp git tag used when EVI_KM_PREFER_AWS_SDK=ON")

if(BUILD_C_API)
  message(
    WARNING "BUILD_C_API=ON: AWS/GCP KeyManager SDK backends are disabled.")
  set(EVI_KM_PREFER_AWS_SDK
      OFF
      CACHE BOOL "Prefer AWS SDK for S3 key storage" FORCE)
  set(EVI_KM_PREFER_GCP_SDK
      OFF
      CACHE BOOL "Prefer google-cloud-cpp for GCS key storage" FORCE)
endif()

set(ALIGNMENT_BYTE
    "256"
    CACHE STRING "Memory alignment size in bytes")

if(BUILD_PYTHON)
  # Enforce packaging-friendly defaults whenever Python bindings are built.
  set(CMAKE_BUILD_TYPE
      "Release"
      CACHE STRING "Build type for Python packaging" FORCE)
  set(BUILD_TEST
      OFF
      CACHE BOOL "Disable tests when building Python artifacts" FORCE)
  set(BUILD_EXAMPLE
      OFF
      CACHE BOOL "Disable examples when building Python artifacts" FORCE)
  set(BUILD_AS_STATIC
      OFF
      CACHE BOOL "Build shared library for Python artifacts" FORCE)
  set(BUILD_WITH_VALGRIND
      OFF
      CACHE BOOL "Skip Valgrind when building Python artifacts" FORCE)
  set(CMAKE_POSITION_INDEPENDENT_CODE
      ON
      CACHE BOOL "Enable PIC for Python artifacts" FORCE)
  # -fPIC is GCC/Clang only; MSVC always produces position-independent code.
  if(NOT MSVC)
    string(APPEND CMAKE_C_FLAGS " -fPIC")
    string(APPEND CMAKE_CXX_FLAGS " -fPIC")
    set(CMAKE_C_FLAGS
        "${CMAKE_C_FLAGS}"
        CACHE STRING "C flags" FORCE)
    set(CMAKE_CXX_FLAGS
        "${CMAKE_CXX_FLAGS}"
        CACHE STRING "CXX flags" FORCE)
  endif()
  # Windows has no RPATH concept; DLLs are found via PATH or same-directory.
  if(NOT WIN32)
    if(APPLE)
      set(_origin "@loader_path")
    else()
      set(_origin "$ORIGIN")
    endif()
    set(CMAKE_INSTALL_RPATH "${_origin};${_origin}/lib;${_origin}/lib64")
    set(CMAKE_BUILD_RPATH "${CMAKE_INSTALL_RPATH}")
    set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)
  endif()
endif()

message(STATUS "BUILD_TEST=${BUILD_TEST}")
message(STATUS "BUILD_EXAMPLE=${BUILD_EXAMPLE}")
message(STATUS "BUILD_KEY_MANAGEMENT=${BUILD_KEY_MANAGEMENT}")
message(STATUS "BUILD_AS_STATIC=${BUILD_AS_STATIC}")
message(STATUS "USE_PROFILE=${USE_PROFILE}")
message(STATUS "BUILD_PYTHON=${BUILD_PYTHON}")
message(STATUS "BUILD_C_API=${BUILD_C_API}")
message(STATUS "BUILD_WITH_CUDA=${BUILD_WITH_CUDA}")
message(STATUS "HEM_BUILD_FOR_CLIENT=${HEM_BUILD_FOR_CLIENT}")
message(STATUS "EVI_KM_PREFER_AWS_SDK=${EVI_KM_PREFER_AWS_SDK}")
message(STATUS "EVI_KM_PREFER_GCP_SDK=${EVI_KM_PREFER_GCP_SDK}")

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  add_compile_definitions(BUILD_DEBUG)
endif()

set(PROJECT_DEPENDENCY "")
set(COMPILE_OPTION "")

set(CRYPT_SRCS src/crypto/fips202.cpp src/crypto/PRNG.cpp)

set(EVI_CORE_SOURCES
    src/ContextImpl.cpp
    src/Context.cpp
    src/Message.cpp
    src/Sampler.cpp
    src/Bitpack.cpp
    src/CKKSTypes.cpp
    src/Query.cpp
    src/SearchResult.cpp
    src/NTT.cpp
    src/KeyPackImpl.cpp
    src/SecretKeyImpl.cpp
    src/SecretKey.cpp
    src/KeyPack.cpp
    src/Utils.cpp
    src/DebUtils.cpp)
set(EVI_CORE_LIBS)

set(EVI_SRCS ${EVI_CORE_SOURCES})

add_subdirectory(external)

if(USE_PROFILE)
  list(APPEND EVI_SRCS src/Profiler.cpp)
  list(APPEND EXTERNAL_LIBS perfetto)
  list(APPEND COMPILE_OPTION USE_PROFILE)
endif()

# keygen
set(KEYGEN_SRCS
    src/KeyGeneratorImpl.cpp src/KeyGenerator.cpp src/DecryptorImpl.cpp
    src/Decryptor.cpp src/crypto/AES.cpp src/SealInfo.cpp)
list(APPEND KEYGEN_SRCS ${EVI_SRCS})

# enc/dec
set(ENC_DEC_SRCS
    src/EncryptorImpl.cpp
    src/Encryptor.cpp
    src/DecryptorImpl.cpp
    src/crypto/AES.cpp
    src/Decryptor.cpp
    src/crypto/TEEWrapper.cpp
    src/SealInfo.cpp)
list(APPEND ENC_DEC_SRCS ${EVI_SRCS})

# Aggregate sources for the main library.
set(PROJECT_MAIN_SRCS ${KEYGEN_SRCS} ${ENC_DEC_SRCS})

if(BUILD_KEY_MANAGEMENT)
  list(
    APPEND
    PROJECT_MAIN_SRCS
    src/km/KeyManager.cpp
    src/km/KeyManagerImpl.cpp
    src/km/KeyManagerCommon.cpp
    src/km/KeyEnvelope.cpp
    src/km/KeyManagerVault.cpp
    src/km/KeyManagerAws.cpp
    src/km/KeyManagerGcp.cpp
    src/km/HttpClient.cpp
    src/km/KeyProviderImpl.cpp
    src/km/KeyProviderCommon.cpp
    src/km/KeyStorageConfig.cpp
    src/km/audit/AuditStore.cpp)
endif()

# Security hardening (GAP-011): process hardening + secure memory primitives
list(APPEND PROJECT_MAIN_SRCS src/security/Security.cpp)

if(BUILD_AS_STATIC)
  add_library(${PROJECT_LIB_NAME} STATIC ${PROJECT_MAIN_SRCS})
else()
  add_library(${PROJECT_LIB_NAME} SHARED ${PROJECT_MAIN_SRCS})
endif()
set_property(TARGET ${PROJECT_LIB_NAME} PROPERTY POSITION_INDEPENDENT_CODE ON)

# Static builds: EVI_API becomes empty (no dllexport/dllimport).
if(BUILD_AS_STATIC)
  target_compile_definitions(${PROJECT_LIB_NAME} PUBLIC EVI_STATIC)
endif()

# On Windows, define EVI_BUILDING_LIB so that EVI_API resolves to
# __declspec(dllexport) when compiling library sources (see Export.hpp).
if(WIN32 AND NOT BUILD_AS_STATIC)
  target_compile_definitions(${PROJECT_LIB_NAME} PRIVATE EVI_BUILDING_LIB)
  # Export all symbols from the DLL so that internal helpers (getImpl etc.) used
  # across translation units are visible without individual dllexport.
  set_target_properties(${PROJECT_LIB_NAME}
                        PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS ON)
endif()

# HttpClient.cpp uses BSD sockets (Winsock2 on Windows).
if(WIN32 AND BUILD_KEY_MANAGEMENT)
  target_link_libraries(${PROJECT_LIB_NAME} PRIVATE ws2_32)
endif()

#
target_compile_definitions(${PROJECT_LIB_NAME}
                           PUBLIC alignment_byte=${ALIGNMENT_BYTE})

# Core dependencies
find_package(OpenSSL REQUIRED)
list(
  APPEND
  EXTERNAL_LIBS
  OpenSSL::SSL
  OpenSSL::Crypto
  deb
  alea
  flatbuffers)

if(EVI_CORE_LIBS)
  list(APPEND EXTERNAL_LIBS ${EVI_CORE_LIBS})
endif()

set(_PRIVATE_EXTERNAL_LIBS)
if(TARGET flatbuffers::flatbuffers)
  list(APPEND _PRIVATE_EXTERNAL_LIBS flatbuffers::flatbuffers)
elseif(TARGET flatbuffers)
  list(APPEND _PRIVATE_EXTERNAL_LIBS flatbuffers)
endif()

# Link dependencies directly to the main target (PUBLIC to propagate)
target_link_libraries(${PROJECT_LIB_NAME} PUBLIC ${EXTERNAL_LIBS}
                                                 ${PROJECT_DEPENDENCY})
if(_PRIVATE_EXTERNAL_LIBS)
  target_link_libraries(${PROJECT_LIB_NAME} PRIVATE ${_PRIVATE_EXTERNAL_LIBS})
endif()
target_compile_definitions(${PROJECT_LIB_NAME} PUBLIC ${COMPILE_OPTION})

# Key management remote providers: prefer official SDKs when available.
if(BUILD_KEY_MANAGEMENT AND EVI_KM_PREFER_AWS_SDK)
  set(_evi_aws_external_prefix "${CMAKE_BINARY_DIR}/_deps/aws-sdk-install")
  set(_evi_aws_lib_suffix "${CMAKE_SHARED_LIBRARY_SUFFIX}")
  set(_evi_aws_curl_cmake_args)
  if(DEFINED CURL_INCLUDE_DIR AND DEFINED CURL_LIBRARY)
    list(APPEND _evi_aws_curl_cmake_args
         "-DCURL_INCLUDE_DIR=${CURL_INCLUDE_DIR}"
         "-DCURL_LIBRARY=${CURL_LIBRARY}")
    message(
      STATUS
        "Forwarding curl to aws-sdk-cpp external build: include=${CURL_INCLUDE_DIR}, lib=${CURL_LIBRARY}"
    )
  endif()
  include(ExternalProject)

  message(
    STATUS
      "Building aws-sdk-cpp externally (${EVI_KM_AWS_SDK_GIT_TAG}) with BUILD_ONLY=s3;secretsmanager"
  )
  ExternalProject_Add(
    evi_aws_sdk_external
    GIT_REPOSITORY https://github.com/aws/aws-sdk-cpp.git
    GIT_TAG ${EVI_KM_AWS_SDK_GIT_TAG}
    GIT_SHALLOW TRUE
    UPDATE_DISCONNECTED TRUE
    PREFIX "${CMAKE_BINARY_DIR}/_deps/aws-sdk"
    INSTALL_DIR "${_evi_aws_external_prefix}"
    CMAKE_ARGS -DCMAKE_BUILD_TYPE=Release
               -DCMAKE_POSITION_INDEPENDENT_CODE=ON
               -DENABLE_TESTING=OFF
               -DBUILD_SHARED_LIBS=ON
               -DCMAKE_DISABLE_FIND_PACKAGE_s2n=ON
               -DCMAKE_INSTALL_LIBDIR=lib
               -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR>
               ${_evi_aws_curl_cmake_args}
    CMAKE_CACHE_ARGS "-DBUILD_ONLY:STRING=s3\\;secretsmanager"
    BUILD_BYPRODUCTS
      "${_evi_aws_external_prefix}/lib/libaws-cpp-sdk-s3${_evi_aws_lib_suffix}"
      "${_evi_aws_external_prefix}/lib/libaws-cpp-sdk-secretsmanager${_evi_aws_lib_suffix}"
      "${_evi_aws_external_prefix}/lib/libaws-cpp-sdk-core${_evi_aws_lib_suffix}"
  )

  # Always use the externally built SDK for both S3 and Secrets Manager.
  target_compile_definitions(${PROJECT_LIB_NAME} PRIVATE EVI_KM_USE_AWS_SDK=1)
  target_compile_definitions(${PROJECT_LIB_NAME}
                             PRIVATE EVI_KM_USE_AWS_SECRETSMANAGER_SDK=1)
  target_include_directories(${PROJECT_LIB_NAME}
                             PRIVATE "${_evi_aws_external_prefix}/include")
  # Distros can install shared libs to either lib or lib64.
  target_link_directories(
    ${PROJECT_LIB_NAME} PRIVATE "${_evi_aws_external_prefix}/lib"
    "${_evi_aws_external_prefix}/lib64")
  target_link_libraries(
    ${PROJECT_LIB_NAME}
    PRIVATE
      "${_evi_aws_external_prefix}/lib/libaws-cpp-sdk-s3${_evi_aws_lib_suffix}"
      "${_evi_aws_external_prefix}/lib/libaws-cpp-sdk-secretsmanager${_evi_aws_lib_suffix}"
      "${_evi_aws_external_prefix}/lib/libaws-cpp-sdk-core${_evi_aws_lib_suffix}"
  )
  add_dependencies(${PROJECT_LIB_NAME} evi_aws_sdk_external)
endif()

if(BUILD_KEY_MANAGEMENT AND EVI_KM_PREFER_GCP_SDK)
  # Try multiple package names / configs depending on installation method.
  find_package(google-cloud-cpp CONFIG QUIET)
  find_package(google_cloud_cpp_storage CONFIG QUIET)
  find_package(google_cloud_cpp_secretmanager CONFIG QUIET)

  set(_gcp_storage_target "")
  set(_gcp_secretmanager_target "")
  if(TARGET google-cloud-cpp::storage)
    set(_gcp_storage_target google-cloud-cpp::storage)
  elseif(TARGET google_cloud_cpp::storage)
    set(_gcp_storage_target google_cloud_cpp::storage)
  endif()
  if(TARGET google-cloud-cpp::secretmanager)
    set(_gcp_secretmanager_target google-cloud-cpp::secretmanager)
  elseif(TARGET google_cloud_cpp::secretmanager)
    set(_gcp_secretmanager_target google_cloud_cpp::secretmanager)
  endif()

  if(_gcp_storage_target AND _gcp_secretmanager_target)
    target_compile_definitions(${PROJECT_LIB_NAME} PRIVATE EVI_KM_USE_GCP_SDK=1)
    target_link_libraries(
      ${PROJECT_LIB_NAME} PRIVATE ${_gcp_storage_target}
                                  ${_gcp_secretmanager_target})
  else()
    message(
      WARNING
        "google-cloud-cpp storage+secretmanager not found; GCP provider will be disabled at runtime (requires EVI_KM_USE_GCP_SDK)"
    )
  endif()
endif()

# Include directories - Project's public headers
target_include_directories(
  ${PROJECT_LIB_NAME}
  PUBLIC $<INSTALL_INTERFACE:include>
         $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)

# * deb includes (limit to build tree to avoid leaking build-paths when
#   installing)
if(DEFINED deb_SOURCE_DIR)
  target_include_directories(
    ${PROJECT_LIB_NAME}
    PUBLIC $<BUILD_INTERFACE:${deb_SOURCE_DIR}/include>
           $<BUILD_INTERFACE:${deb_SOURCE_DIR}/include/deb>
           $<BUILD_INTERFACE:${deb_SOURCE_DIR}/include/generated>)
endif()

add_library(${PROJECT_LIB_NAME}::${PROJECT_LIB_NAME} ALIAS ${PROJECT_LIB_NAME})

if(NOT WIN32)
  target_compile_options(
    ${PROJECT_LIB_NAME} PRIVATE -fvisibility=hidden -fvisibility-inlines-hidden)
endif()

if(EVI_ENABLE_INSTALL)
  # Define exported target
  include(GNUInstallDirs)

  set(EVI_INSTALL_TARGETS ${PROJECT_LIB_NAME})

  # install( TARGETS ${EVI_INSTALL_TARGETS} EXPORT ${PROJECT_LIB_NAME}Targets
  # LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR} RUNTIME DESTINATION
  # ${CMAKE_INSTALL_BINDIR} ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR} INCLUDES
  # DESTINATION include PUBLIC_HEADER DESTINATION include)

  install(
    EXPORT ${PROJECT_LIB_NAME}Targets
    FILE ${PROJECT_LIB_NAME}Targets.cmake
    NAMESPACE ${PROJECT_LIB_NAME}::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_LIB_NAME})

  # Versioning
  configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/Version.hpp.in"
    "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_INSTALL_INCLUDE_DIR}/Version.hpp"
    @ONLY)

  install(
    FILES
      "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_INSTALL_INCLUDE_DIR}/Version.hpp"
    DESTINATION include/${PROJECT_INSTALL_INCLUDE_DIR})

  # Install include directory
  install(DIRECTORY include/${PROJECT_INSTALL_INCLUDE_DIR} DESTINATION include)

  # Make Config.cmake and ConfigVersion.cmake
  include(CMakePackageConfigHelpers)
  write_basic_package_version_file(
    ${PROJECT_LIB_NAME}ConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion)

  configure_package_config_file(
    ${CMAKE_CURRENT_LIST_DIR}/cmake/Config.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_LIB_NAME}Config.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_LIB_NAME})

  # Install them
  install(
    FILES ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_LIB_NAME}Config.cmake
          ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_LIB_NAME}ConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_LIB_NAME})
endif()

if(BUILD_TEST)
  enable_testing()
  add_subdirectory(test)
endif()

if(BUILD_EXAMPLE)
  add_subdirectory(examples)
endif()

if(BUILD_C_API)
  add_subdirectory(c_api)
endif()

if(BUILD_PYTHON)
  add_subdirectory(pybind)
endif()
