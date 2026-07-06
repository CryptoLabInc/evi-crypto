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
#include "EVI/impl/Basic.cuh"
#include "EVI/impl/CKKSTypes.hpp"
#include "EVI/impl/Const.hpp"
#include "EVI/impl/Parameter.hpp"

#include <cassert>
#include <optional>

namespace evi {
namespace detail {

/// Returns true if the preset's primes fit in u32 storage (i.e., log2(prime) <= 32).
/// IP2 uses 32-bit primes; IP3 uses 30-bit primes — both fit u32 coefficient storage.
/// NOTE: this is a storage-width predicate, NOT a guarantee that the u32 NTT
/// (Barrett 4*p < 2^32) path is supported. The Barrett path additionally requires
/// p < 2^30, which IP2 does not satisfy.
inline bool isU32Preset(ParameterPreset preset) {
    return preset == ParameterPreset::IP2;
}

struct EncodedMagnitude {
    bool is_positive;
    u128 magnitude;
};

inline EncodedMagnitude encodeScaledMagnitude(double value) {
#if defined(_MSC_VER) && !defined(__clang__)
    // Keep the MSVC path aligned with EncryptorImpl's existing encoding logic.
    const auto rounded = static_cast<i64>(value + (value > 0 ? 0.5 : -0.5));
    const bool is_positive = rounded >= 0;
    const u64 magnitude = is_positive ? static_cast<u64>(rounded) : static_cast<u64>(-(rounded + 1)) + 1;
    return {is_positive, u128(magnitude)};
#else
    i128 temp = static_cast<i128>(value + (value > 0 ? 0.5 : -0.5));
    const bool is_positive = temp >= 0;
    temp = absI128(temp);
    return {is_positive, static_cast<u128>(temp)};
#endif
}

// =========================================================================
// Coefficient type conversion
// =========================================================================

template <typename From, typename To>
inline void convertCoeffs(const From *src, To *dst, u64 count) {
    for (u64 i = 0; i < count; ++i) {
        dst[i] = static_cast<To>(src[i]);
    }
}

/// Narrow u64 polynomial to u32.
inline void narrowToU32(const poly &src, poly32 &dst, u64 count = DEGREE) {
    convertCoeffs(src.data(), dst.data(), count);
}

/// Widen u32 polynomial to u64.
inline void widenToU64(const poly32 &src, poly &dst, u64 count = DEGREE) {
    convertCoeffs(src.data(), dst.data(), count);
}

/// Narrow u64 buffer to u32.
inline void narrowToU32(const u64 *src, u32 *dst, u64 count) {
    convertCoeffs(src, dst, count);
}

/// Widen u32 buffer to u64.
inline void widenToU64(const u32 *src, u64 *dst, u64 count) {
    convertCoeffs(src, dst, count);
}

// =========================================================================
// Templated encode / decode
// =========================================================================

/// Encode float values to polynomial coefficients over a variable-length prime chain.
///
/// CoeffT = u32 for IP2/IP3 (32-bit primes), u64 for IP0/IP1.
/// The encoding: float -> scale -> round -> abs -> Barrett reduce -> sign embed.
///
/// @tparam CoeffT     Output coefficient type (u32 or u64).
/// @param msg         Input float values.
/// @param limb_outs   Array of output buffers, one per limb. limb_outs[r]
///                    receives coefficients reduced mod param.getQ(r). Size must
///                    equal the resolved num_limbs. Any element may be nullptr
///                    to skip that limb.
/// @param msg_size    Number of message elements to encode (up to DEGREE).
/// @param scale       Scaling factor (2^scale_bits).
/// @param param       Parameter preset providing primes and Barrett constants.
/// @param num_limbs   Optional number of limbs to encode (default: param.getNumQ()
///                    = full chain). Must be <= param.getNumQ() (no aux P primes).
template <typename CoeffT = u64>
inline void encodeCoeffs(const float *msg, CoeffT **limb_outs, u64 msg_size, double scale, const ConstantPreset &param,
                         std::optional<uint32_t> num_limbs = std::nullopt) {
    const uint32_t actual_num_limbs = num_limbs.value_or(param.getNumQ());
    assert(actual_num_limbs <= param.getNumQ() && "encodeCoeffs: num_limbs exceeds preset NumQ");
    // limb_outs[] must have at least actual_num_limbs entries; raw-pointer API
    // cannot validate length at runtime — caller contract.
    for (u64 i = 0; i < msg_size; ++i) {
        const auto encoded = encodeScaledMagnitude(static_cast<double>(msg[i]) * scale);

        for (uint32_t r = 0; r < actual_num_limbs; ++r) {
            if (!limb_outs[r]) {
                continue;
            }
            const u64 mod_r = param.getQ(r);
            u64 value_r = reduceBarrett(mod_r, param.getTwoPrimeQ(r), param.getTwoTo64Q(r), param.getTwoTo64ShoupQ(r),
                                        param.getBarrRatioQ(r), encoded.magnitude);
            u64 final_r = selectIfCondU64(encoded.is_positive, value_r, mod_r - value_r);
            limb_outs[r][i] = static_cast<CoeffT>(final_r);
        }
    }
}

/// Decode polynomial coefficients to float.
///
/// Reverses the encoding: coefficient -> centered mod prime -> divide by scale.
///
/// @tparam CoeffT   Input coefficient type (u32 or u64).
/// @param coeff_q   Input coefficients mod prime_q.
/// @param out       Output float values.
/// @param msg_size  Number of message elements to decode.
/// @param scale     Scaling factor used during encoding.
/// @param prime_q   Prime modulus (for centering: if val > prime/2, val -= prime).
template <typename CoeffT = u64>
inline void decodeCoeffs(const CoeffT *coeff_q, float *out, u64 msg_size, double scale, u64 prime_q) {
    const u64 half_prime = prime_q >> 1;
    const double inv_scale = 1.0 / scale;
    for (u64 i = 0; i < msg_size; ++i) {
        u64 val = static_cast<u64>(coeff_q[i]);
        double centered =
            (val > half_prime) ? static_cast<double>(val) - static_cast<double>(prime_q) : static_cast<double>(val);
        out[i] = static_cast<float>(centered * inv_scale);
    }
}

} // namespace detail
} // namespace evi
