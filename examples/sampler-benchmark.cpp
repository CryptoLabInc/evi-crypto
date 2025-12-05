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
#include "EVI/impl/Const.hpp"
#include "EVI/impl/Type.hpp"
#include "poison.h"
#include "utils/Sampler.hpp"

#include <chrono>
#include <cstdlib>
#include <cstring>
#include <iostream>

using namespace evi::detail;

int main(int argc, char **argv) {
    std::vector<u8> seed[2] = {std::vector<u8>(evi::SEED_MIN_SIZE), std::vector<u8>(evi::SEED_MIN_SIZE)};
    for (u32 i = 0; i < evi::SEED_MIN_SIZE / 4; i++) {
        u32 val = rand();
        memcpy(seed[0].data() + i * 4, &val, sizeof(val));
        for (int j = 0; j < 4; j++) {
            seed[1][i * 4 + j] = (7 * i + 13 * j) % (1 << sizeof(u8) * 8); // Fixed seed for reproducibility
        }
    }

    evi::ParameterPreset param = evi::ParameterPreset::IP0;
    evi::detail::Context ctx = evi::detail::makeContext(param, evi::DeviceType::CPU, 512, evi::EvalMode::FLAT);
    int num_iterations = 1000;
    for (auto s : seed) {
        RandomSampler sample(ctx, s);
        i64 res[DEGREE] = {0};
        auto start = std::chrono::high_resolution_clock::now();
        for (int j = 0; j < num_iterations; ++j) {
            sample.getRandomBits(1);
        }
        auto duration =
            std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now() - start)
                .count();
        std::cout << num_iterations << " random 1Bit generation elapsed time: " << duration << " µs" << std::endl;
        start = std::chrono::high_resolution_clock::now();
        for (int j = 0; j < num_iterations; ++j) {
            sample.sampleHWT(evi::span<i64>(res, DEGREE));
        }
        duration =
            std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::high_resolution_clock::now() - start)
                .count();
        std::cout << num_iterations << " sampleHWT elapsed time: " << duration / 1000 << " ms" << std::endl;
    }

    return 0;
}
