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

#pragma once

#include "EVI/Enums.hpp"
#include "EVI/impl/Type.hpp"
#include "utils/span.hpp"

#include <optional>
#include <random>
#include <stdlib.h>
#include <string>
#include <time.h>
#include <vector>

using namespace evi::detail;

evi::ParameterPreset get_random_preset();
evi::EvalMode get_random_eval_mode();
evi::DeviceType get_random_device_type();
std::string getParamToString(evi::ParameterPreset preset);

void normalizeFeature(float *src, const int dim);
void randomFaces(std::array<float, 4096> &face, const float lo, const float hi, const int dim);
void randomFaces(std::vector<float> &face, const float lo, const float hi, const int n, const int dim,
                 std::optional<unsigned> seed = std::nullopt);
void randomFaces(float *face, const float lo, const float hi, const int n, const int dim);
void randomSimilarFace(float *out, const float *face, const int rank, const float t, const bool over,
                       const float perturbation);
float dot(const float *a, const float *b, const int dim);
float maxError(const float *a, const float *b, const u64 sz, const u64 dim, const bool is_score);
void extract_feature(float *dest, float *src, const u64 dim, const u64 idx, bool zeroOut);

float maxError(const evi::span<float> a, evi::span<float> b);
