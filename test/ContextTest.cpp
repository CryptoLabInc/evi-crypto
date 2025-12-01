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

#include "EVI/impl/ContextImpl.hpp"
#include <cmath>
#include <gtest/gtest.h>
#include <limits>
#include <random>
#include <span>
#include <vector>

template <typename T>
static evi::span<T> asSpan(std::vector<T> &v) {
    return evi::span<T>(v.data(), v.size());
}

using namespace evi::detail;

TEST(Context, MakeCPUNoneModeItemsPerCtxt) {

    const uint64_t rank = 192;
    auto ctx = makeContext(evi::ParameterPreset::QF0, evi::DeviceType::CPU, rank, evi::EvalMode::FLAT);
    const uint64_t pad_rank = isPowerOfTwo(rank) ? rank : nextPowerOfTwo(rank);
    const uint64_t expected_items = DEGREE / pad_rank;

    ASSERT_EQ(ctx->getItemsPerCtxt(), expected_items);
}

TEST(Context, NTTRoundTripQ) {
    using namespace evi;
    auto ctx = makeContext(ParameterPreset::QF0, DeviceType::CPU, 128, EvalMode::FLAT);

    std::vector<u64> poly(DEGREE, 0), original(DEGREE, 0);
    std::mt19937_64 rng(12345);
    u64 mod_q = ctx->getParam()->getPrimeQ();
    for (size_t i = 0; i < DEGREE; ++i) {
        poly[i] = rng() % mod_q;
        original[i] = poly[i];
    }
    ctx->nttModQ(asSpan(poly));
    ctx->inttModQ(asSpan(poly));

    EXPECT_EQ(poly, original);
}

TEST(Context, NTTRoundTripP) {
    using namespace evi;
    auto ctx = makeContext(ParameterPreset::QF0, DeviceType::CPU, 128, EvalMode::FLAT);

    std::vector<u64> poly(DEGREE, 0), original(DEGREE, 0);
    std::mt19937_64 rng(67890);
    u64 mod_p = ctx->getParam()->getPrimeP();
    for (size_t i = 0; i < DEGREE; ++i) {
        poly[i] = rng() % mod_p;
        original[i] = poly[i];
    }
    ctx->nttModP(asSpan(poly));
    ctx->inttModP(asSpan(poly));

    EXPECT_EQ(poly, original);
}

TEST(Context, ShiftIndexQOneHotShift) {
    using namespace evi;
    const u64 rank = 64;
    auto ctx = makeContext(ParameterPreset::QF0, DeviceType::CPU, rank, EvalMode::FLAT);

    const u64 pad_rank = rank;
    const u64 items_per_ctxt = DEGREE / pad_rank;

    std::vector<u64> t(DEGREE, 0), t_shifted(DEGREE, 0);
    t[0] = 1;
    std::vector<u64> ptxt_q = t;
    ctx->nttModQ(asSpan(ptxt_q));
    const u64 idx = 3;
    ASSERT_LT(idx, items_per_ctxt);

    std::vector<u64> out_q(DEGREE, 0);
    ctx->shiftIndexQ(idx, asSpan(ptxt_q), asSpan(out_q));
    std::vector<u64> out_t = out_q;
    ctx->inttModQ(asSpan(out_t));

    const u64 expected_pos = idx * pad_rank;
    for (u64 i = 0; i < DEGREE; ++i) {
        if (i == expected_pos) {
            EXPECT_EQ(out_t[i], 1u) << "i=" << i;
        } else {
            EXPECT_EQ(out_t[i], 0u) << "i=" << i;
        }
    }
}
