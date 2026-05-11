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

/// Encode float values to polynomial coefficients mod prime.
///
/// CoeffT = u32 for IP2 (32-bit primes), u64 for IP0/IP1.
/// The encoding: float -> scale -> round -> abs -> Barrett reduce -> sign embed.
///
/// @tparam CoeffT  Output coefficient type (u32 or u64).
/// @param msg      Input float values.
/// @param out_q    Output coefficients mod prime_q.
/// @param out_p    Output coefficients mod prime_p (nullptr to skip).
/// @param count    Number of elements to encode (up to DEGREE).
/// @param scale    Scaling factor (2^scale_bits).
/// @param param    Parameter preset providing primes and Barrett constants.
template <typename CoeffT = u64>
inline void encodeCoeffs(const float *msg, CoeffT *out_q, CoeffT *out_p, u64 count, double scale,
                         const ConstantPreset &param) {
    const u64 mod_q = param.getPrimeQ();
    const u64 mod_p = param.getPrimeP();

    for (u64 i = 0; i < count; ++i) {
        const auto encoded = encodeScaledMagnitude(msg[i] * scale);

        u64 value_q = reduceBarrett(mod_q, param.getTwoPrimeQ(), param.getTwoTo64Q(), param.getTwoTo64ShoupQ(),
                                    param.getBarrRatioQ(), encoded.magnitude);
        u64 final_q = selectIfCondU64(encoded.is_positive, value_q, mod_q - value_q);
        out_q[i] = static_cast<CoeffT>(final_q);

        if (out_p) {
            u64 value_p = reduceBarrett(mod_p, param.getTwoPrimeP(), param.getTwoTo64P(), param.getTwoTo64ShoupP(),
                                        param.getBarrRatioP(), encoded.magnitude);
            u64 final_p = selectIfCondU64(encoded.is_positive, value_p, mod_p - value_p);
            out_p[i] = static_cast<CoeffT>(final_p);
        }
    }
}

/// Decode polynomial coefficients to float.
///
/// Reverses the encoding: coefficient -> centered mod prime -> divide by scale.
///
/// @tparam CoeffT  Input coefficient type (u32 or u64).
/// @param coeff_q  Input coefficients mod prime_q.
/// @param out      Output float values.
/// @param count    Number of elements to decode.
/// @param scale    Scaling factor used during encoding.
/// @param prime_q  Prime modulus (for centering: if val > prime/2, val -= prime).
template <typename CoeffT = u64>
inline void decodeCoeffs(const CoeffT *coeff_q, float *out, u64 count, double scale, u64 prime_q) {
    const u64 half_prime = prime_q >> 1;
    const double inv_scale = 1.0 / scale;
    for (u64 i = 0; i < count; ++i) {
        u64 val = static_cast<u64>(coeff_q[i]);
        double centered =
            (val > half_prime) ? static_cast<double>(val) - static_cast<double>(prime_q) : static_cast<double>(val);
        out[i] = static_cast<float>(centered * inv_scale);
    }
}

// Backward-compat aliases
inline void encodeToU32(const float *msg, u32 *out_q, u32 *out_p, u64 count, double scale,
                        const ConstantPreset &param) {
    encodeCoeffs<u32>(msg, out_q, out_p, count, scale, param);
}

inline void decodeFromU32(const u32 *coeff_q, float *out, u64 count, double scale, u64 prime_q) {
    decodeCoeffs<u32>(coeff_q, out, count, scale, prime_q);
}

} // namespace detail
} // namespace evi
