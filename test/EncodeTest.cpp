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

/// Encode32 utility tests for IP2 preset.
///
/// Validates:
/// 1. encodeToU32 round-trip precision
/// 2. encodeToU32 matches existing u64 encoding path
/// 3. narrowToU32 / widenToU64 consistency
/// 4. isU32Preset detection
/// 5. IP2 precision bounds

#include "EVI/impl/Encode.hpp"
#include "EVI/impl/Parameter.hpp"
#include "utils/ModArith.hpp"

#include <cmath>
#include <random>
#include <vector>

#include <gtest/gtest.h>

using namespace evi;
using namespace evi::detail;

class Encode32Test : public ::testing::Test {
protected:
    IP2Base param_;
    std::random_device rd_;
    std::mt19937 gen_{rd_()};
};

TEST_F(Encode32Test, IsU32Preset) {
    EXPECT_TRUE(isU32Preset(ParameterPreset::IP2));
    EXPECT_FALSE(isU32Preset(ParameterPreset::IP0));
    EXPECT_FALSE(isU32Preset(ParameterPreset::IP1));
    EXPECT_FALSE(isU32Preset(ParameterPreset::RUNTIME));
}

TEST_F(Encode32Test, EncodeDecodeRoundTrip) {
    const double scale = std::pow(2.0, param_.getScaleFactor());
    std::uniform_real_distribution<float> dist(-0.5f, 0.5f);

    std::vector<float> msg(DEGREE);
    for (auto &v : msg) {
        v = dist(gen_);
    }

    poly32 enc_q{};
    poly32 enc_p{};
    encodeToU32(msg.data(), enc_q.data(), enc_p.data(), DEGREE, scale, param_);

    // Verify all encoded values < prime
    for (u64 i = 0; i < DEGREE; ++i) {
        ASSERT_LT(enc_q[i], static_cast<u32>(param_.PRIME_Q)) << "q coefficient out of range at " << i;
        ASSERT_LT(enc_p[i], static_cast<u32>(param_.PRIME_P)) << "p coefficient out of range at " << i;
    }

    // Decode from q and check precision
    std::vector<float> decoded(DEGREE);
    decodeFromU32(enc_q.data(), decoded.data(), DEGREE, scale, param_.PRIME_Q);

    // IP2 scale ~30.4 bits, rounding error ~ 0.5/2^30.4
    // float (23-bit mantissa) → double → i128 truncation + signBias(±1.5)
    // Total: up to ~3 integer units of error → 3/scale
    const double tol = 4.0 / scale;
    for (u64 i = 0; i < DEGREE; ++i) {
        ASSERT_NEAR(decoded[i], msg[i], tol) << "Round-trip precision failure at index " << i;
    }
}

TEST_F(Encode32Test, EncodeMatchesU64Path) {
    // encodeCoeffs<u32> should produce the same values as encodeCoeffs<u64>
    const double scale = std::pow(2.0, param_.getScaleFactor());
    std::uniform_real_distribution<float> dist(-0.5f, 0.5f);

    for (int trial = 0; trial < 1000; ++trial) {
        float val = dist(gen_);

        u32 out32 = 0;
        encodeCoeffs<u32>(&val, &out32, static_cast<u32 *>(nullptr), 1, scale, param_);

        u64 out64 = 0;
        encodeCoeffs<u64>(&val, &out64, static_cast<u64 *>(nullptr), 1, scale, param_);

        ASSERT_EQ(static_cast<u64>(out32), out64) << "encodeCoeffs<u32> vs <u64> mismatch for val=" << val;
    }
}

TEST_F(Encode32Test, NarrowWidenRoundTrip) {
    std::uniform_int_distribution<u32> dist(0, static_cast<u32>(param_.PRIME_Q - 1));

    poly src{};
    for (u64 i = 0; i < DEGREE; ++i) {
        src[i] = dist(gen_);
    }

    poly32 narrow{};
    narrowToU32(src, narrow);

    poly wide{};
    widenToU64(narrow, wide);

    for (u64 i = 0; i < DEGREE; ++i) {
        ASSERT_EQ(wide[i], src[i]) << "narrow→widen round-trip mismatch at " << i;
    }
}

TEST_F(Encode32Test, PrecisionBounds) {
    const double scale = std::pow(2.0, param_.getScaleFactor());

    float test_values[] = {0.0f, 0.5f, -0.5f, 0.25f, -0.25f, 0.001f, -0.001f};

    for (float val : test_values) {
        u32 enc = 0;
        encodeToU32(&val, &enc, nullptr, 1, scale, param_);

        float dec = 0;
        decodeFromU32(&enc, &dec, 1, scale, param_.PRIME_Q);

        double abs_error = std::abs(static_cast<double>(dec) - val);
        double max_error = 4.0 / scale;

        ASSERT_LT(abs_error, max_error) << "Precision bound violated: val=" << val << " enc=" << enc << " dec=" << dec;
    }
}

TEST_F(Encode32Test, EncodeWithNullP) {
    const double scale = std::pow(2.0, param_.getScaleFactor());
    float val = 0.42f;
    u32 out_q = 0;

    // Should not crash when out_p is nullptr
    encodeToU32(&val, &out_q, nullptr, 1, scale, param_);
    ASSERT_LT(out_q, static_cast<u32>(param_.PRIME_Q));
}

// NTT<u32> cross-validation tests removed: deb::utils::NTT<u32> only supports
// primes < 2^30 (butterfly intermediate 4*prime must fit u32). IP2 prime Q is
// 32-bit. Production pipeline uses u64 NTT for all transforms; u32 is only
// used for CTMatrix storage and PCMM accumulation.

TEST_F(Encode32Test, ModArith32MatchesGroundTruth_IP2) {
    deb::utils::ModArith<1, deb::u32> ma32(static_cast<deb::Size>(DEGREE), param_.PRIME_Q);
    std::uniform_int_distribution<deb::u32> dist(0, static_cast<deb::u32>(param_.PRIME_Q - 1));

    for (int trial = 0; trial < 10000; ++trial) {
        deb::u32 a = dist(gen_);
        deb::u32 b = dist(gen_);
        deb::u32 result = ma32.mul<1>(a, b);
        deb::u64 expected = static_cast<deb::u64>((static_cast<deb::utils::u128>(a) * b) % param_.PRIME_Q);

        ASSERT_EQ(static_cast<deb::u64>(result), expected) << "ModArith<u32> mul wrong: " << a << " * " << b;
    }
}
