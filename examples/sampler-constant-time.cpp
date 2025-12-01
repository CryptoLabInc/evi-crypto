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

#include "EVI/EVI.hpp"
#include "EVI/Enums.hpp"
#include "EVI/impl/Const.hpp"
#include "EVI/impl/Parameter.hpp"
#include "EVI/impl/Type.hpp"
#include "poison.h"
#include "utils/Sampler.hpp"
#include <cstdlib>
#include <ctime>

/**
 * This file was created for Valgrind testing.
 * To run the test, simply execute the following command.
 * $ valgrind --track-origins=yes ./build/examples/constant-time-sampler
 */
using namespace evi::detail;

int main() {
    evi::ParameterPreset param = evi::ParameterPreset::IP0;
    evi::detail::Context ctx = evi::detail::makeContext(param, evi::DeviceType::CPU, 512, evi::EvalMode::FLAT);
    RandomSampler sampler(ctx, std::nullopt);
    i64 res[DEGREE] = {0};
    poison(res, sizeof(i64) * DEGREE);
    sampler.sampleHWT(res);

    u64 res_q[DEGREE] = {0};
    u64 res_p[DEGREE] = {0};
    poison(res_q, sizeof(u64) * DEGREE);
    poison(res_p, sizeof(u64) * DEGREE);
    sampler.sampleGaussian(res_q);
    sampler.sampleGaussian(res_q, res_p);
    sampler.sampleZO(res_q, res_p);

    u64 poly[DEGREE] = {0};
    poison(poly, sizeof(u64) * DEGREE);
    sampler.embedding(res, poly, IPBase::PRIME_P);

    // HEBase Test
    std::srand(std::time(0));
    u64 vec1[DEGREE] = {0};
    u64 vec2[DEGREE] = {0};
    for (u64 i = 0; i < DEGREE; ++i) {
        vec1[i] = static_cast<u64>(std::rand());
        vec2[i] = static_cast<u64>(std::rand());
    }
    u64 res_q_vec[DEGREE] = {0};
    u64 res_p_vec[DEGREE] = {0};
    poison(res_q_vec, sizeof(u64) * DEGREE);
    poison(res_p_vec, sizeof(u64) * DEGREE);

    ctx->addModQ(vec1, vec2, res_q_vec);
    ctx->addModP(vec1, vec2, res_p_vec);
}
