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

pybind11_add_module(
  evi
  bind_context.cpp
  bind_decryptor.cpp
  bind_encryptor.cpp
  bind_key_generator.cpp
  bind_keypack.cpp
  bind_utils.cpp
  bind_types.cpp
  module.cpp)

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

set(CMAKE_BUILD_WITH_INSTALL_RPATH TRUE)

if(APPLE)
  set(_origin "@loader_path")
else()
  set(_origin "$ORIGIN")
endif()
set_target_properties(
  evi PROPERTIES INSTALL_RPATH "${_origin};${_origin}/lib;${_origin}/lib64"
                 BUILD_RPATH "${_origin};${_origin}/lib;${_origin}/lib64")

install(TARGETS evi LIBRARY DESTINATION .)
install(FILES ${CMAKE_BINARY_DIR}/pymodule/evi/__init__.py DESTINATION .)

install(
  DIRECTORY ${_pymodule_lib_dir}/
  DESTINATION lib
  FILES_MATCHING
  PATTERN "*.so"
  PATTERN "*.dylib")

install(
  DIRECTORY ${_pymodule_lib64_dir}/
  DESTINATION lib64
  FILES_MATCHING
  PATTERN "*.so"
  PATTERN "*.dylib")

install(
  DIRECTORY ${CMAKE_BINARY_DIR}/pymodule/cli
  DESTINATION .
  FILES_MATCHING
  PATTERN "*.py")
