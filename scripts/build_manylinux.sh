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

IMAGE="${MANYLINUX_IMAGE:-quay.io/pypa/manylinux_2_28_x86_64}"
PLATFORM_OPT="${PLATFORM_OPT:-}"
JOBS="${JOBS:-$(nproc)}"
GITHUB_TOKEN="${GITHUB_TOKEN:-}"

HOST_UID=$(id -u)
HOST_GID=$(id -g)

docker run --rm -t $PLATFORM_OPT \
  -v "$PWD":/io -w /io \
  -e GITHUB_TOKEN="$GITHUB_TOKEN" \
  -e HOST_UID=$HOST_UID \
  -e HOST_GID=$HOST_GID \
  "$IMAGE" bash -euxo pipefail -c '
    dnf -y install cmake gcc gcc-c++ make ninja-build \
                   openssl-devel zlib-devel >/dev/null 2>&1 || true

    cmake -S . -B build \
      -DCMAKE_BUILD_TYPE=Release \
      -DBUILD_TEST=OFF \
      -DBUILD_EXAMPLE=ON \
      -DBUILD_WITH_CUDA=OFF \
      -DBUILD_YUBIHSM=OFF \
      -DBUILD_WITH_VALGRIND=OFF \
      -DBUILD_AS_STATIC=OFF \
      -DENABLE_IVF=OFF \
      -DUSE_PROFILE=OFF \
      -DCMAKE_POSITION_INDEPENDENT_CODE=ON

    cmake --build build -j '"$JOBS"'

    chown -R $HOST_UID:$HOST_GID build
  '
