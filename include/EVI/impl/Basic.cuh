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

#include "EVI/impl/Type.hpp"
#define CONSTEXPR_INLINE constexpr inline

namespace evi {

namespace detail {
CONSTEXPR_INLINE u64 u128Hi(const u128 value) {
    return static_cast<u64>(value >> 64);
};
CONSTEXPR_INLINE u64 u128Lo(const u128 value) {
    return static_cast<u64>(value);
};

CONSTEXPR_INLINE u128 mul64To128(const u64 op1, const u64 op2) {
    return static_cast<u128>(op1) * op2;
}

CONSTEXPR_INLINE u64 mul64To128Hi(const u64 op1, const u64 op2) {
    u128 mul = mul64To128(op1, op2);
    return u128Hi(mul);
}

CONSTEXPR_INLINE u64 divide128By64Lo(const u64 op1_hi, const u64 op1_lo, const u64 op2) {
    return static_cast<u64>(((static_cast<u128>(op1_hi) << 64) | static_cast<u128>(op1_lo)) / op2);
}

CONSTEXPR_INLINE u64 mulModSimple(const u64 op1, const u64 op2, const u64 mod) {
    return static_cast<u64>(mul64To128(op1, op2) % mod);
}

CONSTEXPR_INLINE u64 powModSimple(u64 base, u64 expo, const u64 mod) {
    u64 res = 1;
    while (expo > 0) {
        if ((expo & 1) == 1) // if odd
            res = mulModSimple(res, base, mod);
        base = mulModSimple(base, base, mod);
        expo >>= 1;
    }

    return res;
}

template <u32 InputModFactor = 4, u32 OutputModFactor = 1>
CONSTEXPR_INLINE void reduceModFactor(const u64 mod, const u64 two_mod, u64 &value) {
    if constexpr (InputModFactor > 2 && OutputModFactor <= 2)
        value = value >= two_mod ? value - two_mod : value;

    if constexpr (InputModFactor > 1 && OutputModFactor == 1)
        value = value >= mod ? value - mod : value;
}

template <u32 OutputModFactor = 1>
CONSTEXPR_INLINE u64 reduceBarrett(const u64 mod, const u64 two_mod, const u64 two_to_64, const u64 two_to_64_shoup,
                                   const u64 barrett_ratio_for_u64, const u128 value) {

    u64 high = u128Hi(value);
    u64 low = u128Lo(value);

    u64 quot = mul64To128Hi(high, two_to_64_shoup) + mul64To128Hi(low, barrett_ratio_for_u64);
    u64 res = high * two_to_64 + low;
    res -= quot * mod;

    reduceModFactor<4, OutputModFactor>(mod, two_mod, res);
    return res;
}

CONSTEXPR_INLINE u64 reduceBarrett(const u64 mod, const u64 barrett_ratio_for_u64, const u64 value) {
    u64 high = mul64To128Hi(value, barrett_ratio_for_u64);
    u64 out = value - high * mod;
    return out >= mod ? out - mod : out;
}

template <u32 OutputModFactor = 1>
CONSTEXPR_INLINE u64 mulMod(const u64 mod, const u64 two_mod, const u64 two_to_64, const u64 two_to_64_shoup,
                            const u64 barrett_ratio_for_u64, const u64 op1, const u64 op2) {
    return reduceBarrett<OutputModFactor>(mod, two_mod, two_to_64, two_to_64_shoup, barrett_ratio_for_u64,
                                          mul64To128(op1, op2));
}

CONSTEXPR_INLINE u64 mulModLazy(const u64 op1, const u64 op2, const u64 op2_barrett, const u64 mod) {
    return op1 * op2 - mul64To128Hi(op1, op2_barrett) * mod;
}

template <u32 OutputModFactor = 1>
CONSTEXPR_INLINE u64 powMod(const u64 mod, const u64 two_mod, const u64 two_to_64, const u64 two_to_64_shoup,
                            const u64 barrett_ratio_for_u64, u64 base, u64 expt) {

    u64 res = 1;
    while (expt > 0) {
        if ((expt & 1) == 1) // if odd
            res = mulMod<4>(mod, two_mod, two_to_64, two_to_64_shoup, barrett_ratio_for_u64, res, base);
        base = mulMod<4>(mod, two_mod, two_to_64, two_to_64_shoup, barrett_ratio_for_u64, base, base);
        expt >>= 1;
    }

    reduceModFactor<4, OutputModFactor>(mod, two_mod, res);

    return res;
}

CONSTEXPR_INLINE u64 inverse(const u64 mod, const u64 two_mod, const u64 two_to_64, const u64 two_to_64_shoup,
                             const u64 barrett_ratio_for_u64, const u64 value) {
    return powMod<1>(mod, two_mod, two_to_64, two_to_64_shoup, barrett_ratio_for_u64, value, mod - 2);
}

CONSTEXPR_INLINE u32 bitReverse32(u32 x) {
    x = (((x & 0xaaaaaaaa) >> 1) | ((x & 0x55555555) << 1));
    x = (((x & 0xcccccccc) >> 2) | ((x & 0x33333333) << 2));
    x = (((x & 0xf0f0f0f0) >> 4) | ((x & 0x0f0f0f0f) << 4));
    x = (((x & 0xff00ff00) >> 8) | ((x & 0x00ff00ff) << 8));
    return ((x >> 16) | (x << 16));
}

CONSTEXPR_INLINE u32 bitReverse(u32 x, u64 max_digits) {
    return bitReverse32(x) >> (32 - max_digits);
}

CONSTEXPR_INLINE u64 countLeftZeroes(u64 op) {
#ifndef __has_builtin
#define __has_builtin(arg) 0
#endif
#if __has_builtin(__builtin_clzll)
    return static_cast<u64>(__builtin_clzll(op));
#elif _MSC_VER
    return static_cast<u64>(__lzcnt64(op));
#else
    // Algorithm: see "Hacker's delight" 2nd ed., section 5.13, algorithm 5-12.
    u64 n = 64;
    u64 tmp = op >> 32;
    if (tmp != 0) {
        n = n - 32;
        op = tmp;
    }
    tmp = op >> 16;
    if (tmp != 0) {
        n = n - 16;
        op = tmp;
    }
    tmp = op >> 8;
    if (tmp != 0) {
        n = n - 8;
        op = tmp;
    }
    tmp = op >> 4;
    if (tmp != 0) {
        n = n - 4;
        op = tmp;
    }
    tmp = op >> 2;
    if (tmp != 0) {
        n = n - 2;
        op = tmp;
    }
    tmp = op >> 1;
    if (tmp != 0)
        return n - 2;
    return n - op;
#endif
}

CONSTEXPR_INLINE u64 bitWidth(const u64 op) {
    return op ? U64C(64) - countLeftZeroes(op) : U64C(0);
}

// Integral log2 with log2floor(0) := 0
CONSTEXPR_INLINE u64 log2floor(const u64 op) {
    return op ? bitWidth(op) - 1 : U64C(0);
}

CONSTEXPR_INLINE bool isPowerOfTwo(u64 op) {
    return op && (!(op & (op - 1)));
}

CONSTEXPR_INLINE u64 subIfGE(u64 a, u64 b) {
    return (a >= b ? a - b : a);
}

CONSTEXPR_INLINE u64 invModSimple(u64 a, u64 prime) {
    return powModSimple(a, prime - 2, prime);
}

CONSTEXPR_INLINE u64 nextPowerOfTwo(u64 op) {
    op--;

    op |= op >> 1;
    op |= op >> 2;
    op |= op >> 4;
    op |= op >> 8;
    op |= op >> 16;
    op |= op >> 32;

    return op + 1;
}

CONSTEXPR_INLINE float subIfGTModFloat(u64 val, u64 mod) {
    // val > mod ? val - mod : val
    return static_cast<float>(val - (static_cast<double>(val > (mod >> 1)) * mod));
}

CONSTEXPR_INLINE u64 selectIfCondU64(bool cond, u64 a, u64 b) {
    // cond ? a : b
    i64 tmp = static_cast<i64>(cond);
    return (a & -tmp) + (b & ~(-tmp));
}

CONSTEXPR_INLINE double signBiasDouble(i64 val) {
    // val > 0 ? 0.5 : -0.5;
    return 0.5 - (static_cast<double>((val <= 0) << 1));
}

CONSTEXPR_INLINE i64 subIfGEModI64(i64 val, i64 mod) {
    // val >= mod ? val - mod : val
    return val - (mod & -static_cast<i64>(val >= mod));
}

CONSTEXPR_INLINE i128 absI128(i128 val) {
    // val >= 0 ? val : -val
    i128 sign = val >> 127;
    return (val + sign) ^ sign;
}
} // namespace detail
} // namespace evi
