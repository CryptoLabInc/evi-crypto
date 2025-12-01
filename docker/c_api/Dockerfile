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

ARG UBUNTU_VERSION=22.04

FROM ubuntu:${UBUNTU_VERSION} AS base

ARG DEBIAN_FRONTEND=noninteractive
ARG TARGETARCH
RUN set -eux; \
    rm -f /etc/apt/sources.list.d/ubuntu.sources || true; \
    # Choose mirror set based on architecture (arm64 uses ubuntu-ports)
    if [ "${TARGETARCH:-amd64}" = "arm64" ]; then \
        MIRROR_CANDIDATES="mirror.kakao.com/ubuntu-ports ports.ubuntu.com/ubuntu-ports"; \
    else \
        MIRROR_CANDIDATES="mirror.kakao.com/ubuntu archive.ubuntu.com/ubuntu"; \
    fi; \
    . /etc/os-release; CODENAME=${VERSION_CODENAME}; \
    MIRROR_USED=""; \
    for MIRROR_HOST in ${MIRROR_CANDIDATES}; do \
      : > /etc/apt/sources.list; \
      echo "deb http://${MIRROR_HOST} ${CODENAME} main restricted universe multiverse"           >> /etc/apt/sources.list; \
      echo "deb http://${MIRROR_HOST} ${CODENAME}-updates main restricted universe multiverse"   >> /etc/apt/sources.list; \
      echo "deb http://${MIRROR_HOST} ${CODENAME}-backports main restricted universe multiverse" >> /etc/apt/sources.list; \
      echo "deb http://${MIRROR_HOST} ${CODENAME}-security main restricted universe multiverse"  >> /etc/apt/sources.list; \
      rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*; \
      for i in 1 2 3 4 5; do \
        if apt-get update; then \
          MIRROR_USED=${MIRROR_HOST}; \
          break 2; \
        fi; \
        echo "apt-get update attempt $i failed on mirror ${MIRROR_HOST}"; \
        rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*; \
        sleep 3; \
      done; \
    done; \
    if [ -z "${MIRROR_USED}" ]; then \
      echo "All configured mirrors failed"; \
      exit 1; \
    fi; \
    echo "Using apt mirror: ${MIRROR_USED}"; \
    for i in 1 2 3 4 5; do \
      DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        cmake \
        git \
        ninja-build \
        pkg-config \
        python3 \
        python3-pip \
        python3-venv \
        curl \
        wget \
        libssl-dev \
        zlib1g-dev \
      && break || { echo "apt-get install attempt $i failed"; rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*; sleep 3; }; \
    done; \
    rm -rf /var/lib/apt/lists/*

ARG CONDA_DIR=/opt/conda
ENV PATH=${CONDA_DIR}/bin:${PATH}
SHELL ["/bin/bash","-lc"]

RUN set -euo pipefail; \
    ARCH_TARGET="${TARGETARCH:-$(dpkg --print-architecture)}"; \
    case "${ARCH_TARGET}" in \
      amd64)  ARCH="x86_64"  ;; \
      arm64)  ARCH="aarch64" ;; \
      *) echo "Unsupported arch: ${ARCH_TARGET}"; exit 1 ;; \
    esac; \
    URL="https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-${ARCH}.sh"; \
    echo "Downloading $URL"; \
    wget -q "$URL" -O /tmp/miniconda.sh; \
    bash /tmp/miniconda.sh -b -p "${CONDA_DIR}"; \
    rm -f /tmp/miniconda.sh; \
    conda config --set always_yes yes --set changeps1 no; \
    conda config --set channel_priority flexible

RUN conda config --set always_yes yes --set changeps1 no && \
    conda tos accept --override-channels --channel https://repo.anaconda.com/pkgs/main && \
    conda tos accept --override-channels --channel https://repo.anaconda.com/pkgs/r

FROM base AS workspace
WORKDIR /workspace
COPY . .

FROM workspace AS cpu-builder
RUN conda env update -f conda/evi-crypto-dev.yml -n evi-crypto-dev
RUN conda run -n evi-crypto-dev cmake --preset envector-compute-cpu
RUN conda run -n evi-crypto-dev cmake --build --preset envector-compute-cpu


FROM workspace AS gpu-builder
RUN conda env update -f conda/evi-crypto-dev-cuda.yml -n evi-crypto-dev-cuda
RUN conda run -n evi-crypto-dev-cuda cmake --preset envector-compute-gpu
RUN conda run -n evi-crypto-dev-cuda cmake --build --preset envector-compute-gpu


# Dedicated builders for test artifacts so that evi_c_api_test is present
FROM workspace AS cpu-test-builder
RUN conda env update -f conda/evi-crypto-dev.yml -n evi-crypto-dev
RUN conda run -n evi-crypto-dev cmake --preset envector-compute-cpu-test
RUN conda run -n evi-crypto-dev cmake --build --preset envector-compute-cpu-test

FROM workspace AS gpu-test-builder
RUN conda env update -f conda/evi-crypto-dev-cuda.yml -n evi-crypto-dev-cuda
RUN conda run -n evi-crypto-dev-cuda cmake --preset envector-compute-gpu-test
RUN conda run -n evi-crypto-dev-cuda cmake --build --preset envector-compute-gpu-test

FROM ubuntu:${UBUNTU_VERSION} AS cpu-test
COPY --from=cpu-test-builder /workspace/build/c_api/ /workspace/cpu/
WORKDIR /workspace/cpu

FROM nvidia/cuda:11.8.0-runtime-ubuntu22.04 AS gpu-test
COPY --from=gpu-test-builder /workspace/build/c_api/ /workspace/gpu/
ENV LD_LIBRARY_PATH=/usr/local/cuda/lib64:${LD_LIBRARY_PATH}
WORKDIR /workspace/gpu

FROM nvidia/cuda:11.8.0-runtime-ubuntu22.04 AS test-all-cuda
COPY --from=gpu-test-builder /workspace/build/c_api/ /workspace/gpu/
COPY --from=cpu-test-builder /workspace/build/c_api/ /workspace/cpu/
ENV LD_LIBRARY_PATH=/usr/local/cuda/lib64:${LD_LIBRARY_PATH}
WORKDIR /workspace

FROM ubuntu:${UBUNTU_VERSION} AS test-all
COPY --from=gpu-test-builder /workspace/build/c_api/ /workspace/gpu/
COPY --from=cpu-test-builder /workspace/build/c_api/ /workspace/cpu/
WORKDIR /workspace

FROM ubuntu:${UBUNTU_VERSION} AS c-binary-cpu
COPY --from=cpu-test --chown=root:root --chmod=774 /workspace/cpu/libevi_c_api.a /workspace/cpu/
WORKDIR /workspace/cpu

FROM nvidia/cuda:11.8.0-runtime-ubuntu22.04 AS c-binary-gpu
COPY --from=gpu-test --chown=root:root --chmod=774 /workspace/gpu/libevi_c_api.a /workspace/gpu/
ENV LD_LIBRARY_PATH=/usr/local/cuda/lib64:${LD_LIBRARY_PATH}
WORKDIR /workspace/gpu

FROM nvidia/cuda:11.8.0-runtime-ubuntu22.04 AS c-binary-all-cuda
COPY --from=test-all --chown=root:root --chmod=774 /workspace/cpu/libevi_c_api.a /workspace/cpu/
COPY --from=test-all --chown=root:root --chmod=774 /workspace/gpu/libevi_c_api.a /workspace/gpu/
ENV LD_LIBRARY_PATH=/usr/local/cuda/lib64:${LD_LIBRARY_PATH}
WORKDIR /workspace

FROM ubuntu:${UBUNTU_VERSION} AS c-binary-all
COPY --from=test-all --chown=root:root --chmod=774 /workspace/cpu/libevi_c_api.a /workspace/cpu/
COPY --from=test-all --chown=root:root --chmod=774 /workspace/gpu/libevi_c_api.a /workspace/gpu/
WORKDIR /workspace
