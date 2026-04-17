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
RUN set -eux; \
    apt_ok=""; \
    for i in 1 2 3 4 5; do \
      rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*; \
      if apt-get update && \
         DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
           build-essential \
           ca-certificates \
           cmake \
           curl \
           git \
           libssl-dev \
           ninja-build \
           pkg-config \
           python3 \
           python3-pip \
           python3-venv \
           wget \
           zlib1g-dev; then \
        apt_ok=1; \
        break; \
      fi; \
      echo "apt bootstrap attempt ${i} failed"; \
      sleep 3; \
    done; \
    test -n "${apt_ok}"; \
    command -v wget; \
    rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*

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
