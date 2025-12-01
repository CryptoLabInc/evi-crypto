#!/usr/bin/env bash
#////////////////////////////////////////////////////////////////////////////////
#//                                                                            //
#//  Copyright (C) 2025, CryptoLab, Inc.                                       //
#//                                                                            //
#//  Licensed under the Apache License, Version 2.0 (the "License");           //
#//  you may not use this file except in compliance with the License.          //
#//  You may obtain a copy of the License at                                   //
#//                                                                            //
#//     http://www.apache.org/licenses/LICENSE-2.0                             //
#//                                                                            //
#//  Unless required by applicable law or agreed to in writing, software       //
#//  distributed under the License is distributed on an "AS IS" BASIS,         //
#//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  //
#//  See the License for the specific language governing permissions and       //
#//  limitations under the License.                                            //
#//                                                                            //
#////////////////////////////////////////////////////////////////////////////////

set -euo pipefail

BUILD_DIR=${BUILD_DIR:-build}
COMPILE_COMMANDS="${BUILD_DIR}/compile_commands.json"

if ! command -v clang-tidy >/dev/null 2>&1; then
  echo "error: clang-tidy is not available in PATH. Please install clang-tidy." >&2
  exit 1
fi

if [[ ! -f "${COMPILE_COMMANDS}" ]]; then
  echo "error: ${COMPILE_COMMANDS} not found. Please build first." >&2
  exit 1
fi

GCC_VERSION_RAW=$(g++ -dumpfullversion -dumpversion 2>/dev/null || true)
GCC_MAJOR=${GCC_VERSION_RAW%%.*}
MULTIARCH=$(gcc -print-multiarch 2>/dev/null || true)
STD_INCLUDE_ARGS=()
if [[ -n "${GCC_MAJOR}" ]]; then
  if [[ -d "/usr/include/c++/${GCC_MAJOR}" ]]; then
    STD_INCLUDE_ARGS+=(-extra-arg=-isystem/usr/include/c++/${GCC_MAJOR})
  fi
  if [[ -n "${MULTIARCH}" && -d "/usr/include/${MULTIARCH}/c++/${GCC_MAJOR}" ]]; then
    STD_INCLUDE_ARGS+=(-extra-arg=-isystem/usr/include/${MULTIARCH}/c++/${GCC_MAJOR})
  fi
  if [[ -d "/usr/include/c++/${GCC_MAJOR}/backward" ]]; then
    STD_INCLUDE_ARGS+=(-extra-arg=-isystem/usr/include/c++/${GCC_MAJOR}/backward)
  fi
fi

files=()
if [[ "$#" -gt 0 ]]; then
  candidates=("$@")
elif [[ "${RUN_ALL_FILES:-0}" == "1" ]]; then
  mapfile -t candidates < <(git ls-files)
else
  base_ref=${TARGET_SHA:-$(git merge-base HEAD origin/main 2>/dev/null || git hash-object -t tree /dev/null)}
  mapfile -t candidates < <(git diff --name-only "${base_ref}")
fi

for file in "${candidates[@]}"; do
  [[ -f "${file}" ]] || continue
  case "${file}" in
    c_api/*|pybind/*|build/_deps/*) continue ;;
    *.cc|*.cxx|*.cpp|*.cu) files+=("${file}") ;;
  esac
done

if [[ ${#files[@]} -eq 0 ]]; then
  echo "No source files to run clang-tidy on."
  exit 0
fi

status=0
for file in "${files[@]}"; do
  echo "[clang-tidy] ${file}"
  if ! clang-tidy --warnings-as-errors=* -p "${BUILD_DIR}" "${file}"; then
    status=1
  fi
done

exit ${status}
