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
/// 1. encodeCoeffs<u32> round-trip precision
/// 2. encodeCoeffs<u32> matches encodeCoeffs<u64> output
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

    // Encode into the two PRIMES_Q limbs. The second buffer is named enc_q1
    // (not enc_p) to reflect post-refactor layout: IP2 has NumQ=2, NumP=1,
    // and the encoder fills the Q limbs only.
    poly32 enc_q0{};
    poly32 enc_q1{};
    u32 *limbs[2] = {enc_q0.data(), enc_q1.data()};
    encodeCoeffs<u32>(msg.data(), limbs, DEGREE, scale, param_);

    // Verify all encoded values < the respective prime
    for (u64 i = 0; i < DEGREE; ++i) {
        ASSERT_LT(enc_q0[i], static_cast<u32>(IP2Base::PRIMES_Q[0])) << "Q[0] coefficient out of range at " << i;
        ASSERT_LT(enc_q1[i], static_cast<u32>(IP2Base::PRIMES_Q[1])) << "Q[1] coefficient out of range at " << i;
    }

    // Decode from Q[0] and check precision
    std::vector<float> decoded(DEGREE);
    decodeCoeffs<u32>(enc_q0.data(), decoded.data(), DEGREE, scale, IP2Base::PRIMES_Q[0]);

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
        u32 *outs32[1] = {&out32};
        encodeCoeffs<u32>(&val, outs32, 1, scale, param_, 1u);

        u64 out64 = 0;
        u64 *outs64[1] = {&out64};
        encodeCoeffs<u64>(&val, outs64, 1, scale, param_, 1u);

        ASSERT_EQ(static_cast<u64>(out32), out64) << "encodeCoeffs<u32> vs <u64> mismatch for val=" << val;
    }
}

TEST_F(Encode32Test, NarrowWidenRoundTrip) {
    std::uniform_int_distribution<u32> dist(0, static_cast<u32>(IP2Base::PRIMES_Q[0] - 1));

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
        u32 *outs[1] = {&enc};
        encodeCoeffs<u32>(&val, outs, 1, scale, param_, 1u);

        float dec = 0;
        decodeCoeffs<u32>(&enc, &dec, 1, scale, IP2Base::PRIMES_Q[0]);

        double abs_error = std::abs(static_cast<double>(dec) - val);
        double max_error = 4.0 / scale;

        ASSERT_LT(abs_error, max_error) << "Precision bound violated: val=" << val << " enc=" << enc << " dec=" << dec;
    }
}

TEST_F(Encode32Test, EncodeWithNullSecondLimb) {
    const double scale = std::pow(2.0, param_.getScaleFactor());
    float val = 0.42f;
    u32 out_q = 0;
    u32 *limbs[2] = {&out_q, nullptr};

    // Should not crash when limb_outs[1] is nullptr (skip second limb).
    encodeCoeffs<u32>(&val, limbs, 1, scale, param_);
    ASSERT_LT(out_q, static_cast<u32>(IP2Base::PRIMES_Q[0]));
}

// NTT<u32> cross-validation tests removed: deb::utils::NTT<u32> only supports
// primes < 2^30 (butterfly intermediate 4*prime must fit u32). IP2 prime Q is
// 32-bit. Production pipeline uses u64 NTT for all transforms.
//
// NOTE (IP2->u64 demotion): IP2 is now a pure u64 preset (u32 storage <=>
// preset==IP3). This test is NOT an IP2-storage-path test — it exercises
// deb::utils::ModArith<1,u32>::mul correctness against a representative
// 32-bit prime (IP2Base::PRIMES_Q[0], still a valid constant since IP2Base
// is kept). Retained as-is: 32-bit-prime u32 ModArith coverage is still
// meaningful and independent of which preset uses u32 storage.
TEST_F(Encode32Test, ModArith32MatchesGroundTruth_IP2) {
    deb::utils::ModArith<1, deb::u32> ma32(static_cast<deb::Size>(DEGREE), IP2Base::PRIMES_Q[0]);
    std::uniform_int_distribution<deb::u32> dist(0, static_cast<deb::u32>(IP2Base::PRIMES_Q[0] - 1));

    for (int trial = 0; trial < 10000; ++trial) {
        deb::u32 a = dist(gen_);
        deb::u32 b = dist(gen_);
        deb::u32 result = ma32.mul<1>(a, b);
        deb::u64 expected = static_cast<deb::u64>((static_cast<deb::utils::u128>(a) * b) % IP2Base::PRIMES_Q[0]);

        ASSERT_EQ(static_cast<deb::u64>(result), expected) << "ModArith<u32> mul wrong: " << a << " * " << b;
    }
}
