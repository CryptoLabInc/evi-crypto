////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2025, CryptoLab, Inc.                                       //
//                                                                            //
//  Licensed under the Apache License, Version 2.0 (the "License");           //
//  you may not use this file except in compliance with the License.          //
//  You may obtain a copy of the License at                                   //
//                                                                            //
//     http://www.apache.org/licenses/LICENSE-2.0                             //
//                                                                            //
//  Unless required by applicable law or agreed to in writing, software       //
//  distributed under the License is distributed on an "AS IS" BASIS,         //
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  //
//  See the License for the specific language governing permissions and       //
//  limitations under the License.                                            //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#include "utils.hpp"
#include "EVI/Enums.hpp"
#include "utils/span.hpp"
#include <array>
#include <iostream>
#include <random>
#include <type_traits>

static constexpr std::array<evi::ParameterPreset, 4> ALL_PRESETS = {
    evi::ParameterPreset::IP0, evi::ParameterPreset::IP1, evi::ParameterPreset::QF0, evi::ParameterPreset::QF1};
evi::ParameterPreset get_random_preset() {
    static std::mt19937 gen{std::random_device{}()};
    std::uniform_int_distribution<size_t> dist(0, ALL_PRESETS.size() - 1);
    return ALL_PRESETS[dist(gen)];
}

static constexpr std::array<evi::EvalMode, 2> ALL_EVAL_MODES = {evi::EvalMode::RMP, evi::EvalMode::FLAT};
evi::EvalMode get_random_eval_mode() {
    static std::mt19937 gen{std::random_device{}()};
    std::uniform_int_distribution<size_t> dist(0, ALL_EVAL_MODES.size() - 1);
    return ALL_EVAL_MODES[dist(gen)];
}

static constexpr std::array<evi::DeviceType, 1> ALL_DEVICE_TYPES = {evi::DeviceType::CPU};

evi::DeviceType get_random_device_type() {
    static std::mt19937 gen{std::random_device{}()};
    std::uniform_int_distribution<size_t> dist(0, ALL_DEVICE_TYPES.size() - 1);
    return ALL_DEVICE_TYPES[dist(gen)];
}

std::string getParamToString(evi::ParameterPreset preset) {
    std::string res;
    switch (preset) {
    case evi::ParameterPreset::IP0:
        res = "IP0";
        break;
    case evi::ParameterPreset::IP1:
        res = "IP1";
        break;
    case evi::ParameterPreset::QF1:
        res = "QF1";
        break;
    case evi::ParameterPreset::QF0:
        res = "QF0";
        break;
    }
    return res;
}

void normalizeFeature(float *src, const int dim) {
    float norm_sum = 0.0;
    for (u64 i = 0; i < dim; i++) {
        norm_sum += src[i] * src[i];
    }
    norm_sum = std::sqrt(norm_sum);
    for (u64 i = 0; i < dim; i++) {
        src[i] /= norm_sum;
    }
}

void randomFaces(std::array<float, 4096> &face, const float lo, const float hi, const int dim) {
    std::fill(face.begin(), face.end(), 0.f);
    std::uniform_real_distribution<float> dis(lo, hi);
    std::random_device rd;
    std::mt19937 gen(rd());

    for (int i = 0; i < dim; i++) {
        face[i] = dis(gen);
    }
    normalizeFeature(face.data(), dim);
}

void randomFaces(std::vector<float> &face, const float lo, const float hi, const int n, const int dim,
                 std::optional<unsigned> seed) {
    face.resize(n * dim);
    std::uniform_real_distribution<float> dis(lo, hi);
    if (!seed.has_value()) {
        std::random_device rd;
        std::mt19937 gen(rd());

        for (int i = 0; i < face.size(); i++) {
            face[i] = dis(gen);
        }
    } else {
        std::mt19937 gen(seed.value());

        for (int i = 0; i < face.size(); i++) {
            face[i] = dis(gen);
        }
    }
    for (int i = 0; i < face.size() / dim; i++) {
        normalizeFeature(face.data() + i * dim, dim);
    }
}

void randomFaces(float *face, const float lo, const float hi, const int n, const int dim) {
    std::uniform_real_distribution<float> dis(lo, hi);
    std::random_device rd;
    std::mt19937 gen(rd());

    for (int i = 0; i < n * dim; i++) {
        face[i] = dis(gen);
    }
    for (uint64_t fi = 0; fi < n; fi++) {
        float *ptr = face + fi * dim;
        normalizeFeature(ptr, dim);
    }
}

void randomSimilarFace(float *out, const float *face, const int rank, const float t, const bool over,
                       const float perturbation) {
    std::uniform_real_distribution<float> dis(-1, 1);
    std::random_device rd;
    std::mt19937 gen(rd());
    while (true) {
        for (int i = 0; i < rank; i++) {
            out[i] = dis(gen);
        }
        normalizeFeature(out, rank);
        for (int i = 0; i < rank; i++) {
            out[i] = face[i] * (1 - perturbation) + out[i] * perturbation;
        }

        float score = dot(face, out, rank);
        if (over && score > t) {
            return;
        }
        if (!over && score < t) {
            return;
        }
    }
}

float dot(const float *a, const float *b, const int dim) {
    float ret = 0.0;
    for (u64 i = 0; i < dim; i++) {
        ret += a[i] * b[i];
    }
    return ret;
}

float maxError(const evi::span<float> a, evi::span<float> b) {
    float max_error = 0;
    for (u64 i = 0; i < a.size(); i++) {
        max_error = std::max(max_error, std::abs(a[i] - b[i]));
    }
    return max_error;
}

float maxError(const float *a, const float *b, const u64 sz, const u64 dim, const bool is_score = true) {
    float max_error = 0;
    u64 len = is_score ? sz : sz * dim;
    for (u64 i = 0; i < len; i++) {
        max_error = std::max(max_error, std::abs(a[i] - b[i]));
        if (std::abs(a[i] - b[i]) > std::pow(2.0, -6)) {
            std::cout << "maxError at: " << (!is_score ? i / dim : i) << ", " << a[i] << ", " << b[i] << std::endl;
            break;
        }
    }
    return max_error;
}

void extract_feature(float *dest, float *src, const u64 dim, const u64 idx, bool zero_out) {
    for (int i = 0; i < dim; i++) {
        dest[i] = src[idx * dim + i];
        if (zero_out) {
            src[idx * dim + i] = 0;
        }
    }
}
