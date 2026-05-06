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

#include <array>
#include <cstdint>
#include <functional>

namespace evi {
namespace detail {
// NOLINTBEGIN(readability-identifier-naming)
using u64 = uint64_t;
using i64 = int64_t;
using u32 = uint32_t;
using i32 = int32_t;
using u8 = uint8_t;

#ifdef _MSC_VER
// MSVC lacks __int128 — provide struct-based 128-bit integer types.

struct i128; // forward declaration

struct u128 {
    u64 lo;
    u64 hi;

    constexpr u128() : lo(0), hi(0) {}
    constexpr u128(u64 val) : lo(val), hi(0) {} // NOLINT(implicit)
    constexpr u128(u64 hi_, u64 lo_) : lo(lo_), hi(hi_) {}

    constexpr explicit operator u64() const {
        return lo;
    }
    constexpr explicit operator bool() const {
        return lo || hi;
    }
    explicit operator double() const {
        constexpr double two64 = 18446744073709551616.0;
        return static_cast<double>(hi) * two64 + static_cast<double>(lo);
    }

    constexpr u128 operator>>(u64 n) const {
        if (n == 0)
            return *this;
        if (n >= 128)
            return u128();
        if (n >= 64)
            return u128(0, hi >> (n - 64));
        return u128(hi >> n, (lo >> n) | (hi << (64 - n)));
    }
    constexpr u128 operator<<(u64 n) const {
        if (n == 0)
            return *this;
        if (n >= 128)
            return u128();
        if (n >= 64)
            return u128(lo << (n - 64), 0);
        return u128((hi << n) | (lo >> (64 - n)), lo << n);
    }
    constexpr u128 operator|(const u128 &o) const {
        return u128(hi | o.hi, lo | o.lo);
    }
    constexpr u128 operator&(const u128 &o) const {
        return u128(hi & o.hi, lo & o.lo);
    }
    constexpr u128 operator+(const u128 &o) const {
        u64 r = lo + o.lo;
        return u128(hi + o.hi + (r < lo ? 1 : 0), r);
    }
    constexpr u128 operator-(const u128 &o) const {
        u64 r = lo - o.lo;
        return u128(hi - o.hi - (lo < o.lo ? 1 : 0), r);
    }
    constexpr u128 operator*(const u128 &o) const {
        u64 a0 = lo & 0xFFFFFFFF, a1 = lo >> 32;
        u64 b0 = o.lo & 0xFFFFFFFF, b1 = o.lo >> 32;
        u64 p00 = a0 * b0, p01 = a0 * b1, p10 = a1 * b0, p11 = a1 * b1;
        u64 mid = (p00 >> 32) + (p01 & 0xFFFFFFFF) + (p10 & 0xFFFFFFFF);
        u64 l = (p00 & 0xFFFFFFFF) | ((mid & 0xFFFFFFFF) << 32);
        u64 h = p11 + (p01 >> 32) + (p10 >> 32) + (mid >> 32);
        h += lo * o.hi + hi * o.lo;
        return u128(h, l);
    }
    constexpr u128 operator/(u64 d) const {
        if (hi == 0)
            return u128(0, lo / d);
        u64 qh = hi / d;
        u64 rem = hi % d;
        u64 ql = 0;
        for (int i = 63; i >= 0; i--) {
            bool overflow = (rem >> 63) != 0;
            rem = (rem << 1) | ((lo >> i) & 1);
            if (overflow || rem >= d) {
                rem -= d;
                ql |= (u64(1) << i);
            }
        }
        return u128(qh, ql);
    }
    constexpr u128 operator%(u64 d) const {
        if (hi == 0)
            return u128(0, lo % d);
        u64 rem = hi % d;
        for (int i = 63; i >= 0; i--) {
            bool overflow = (rem >> 63) != 0;
            rem = (rem << 1) | ((lo >> i) & 1);
            if (overflow || rem >= d) {
                rem -= d;
            }
        }
        return u128(0, rem);
    }

    constexpr u128 &operator|=(const u128 &o) {
        *this = *this | o;
        return *this;
    }
    constexpr u128 &operator&=(const u128 &o) {
        *this = *this & o;
        return *this;
    }
    constexpr u128 &operator>>=(u64 n) {
        *this = *this >> n;
        return *this;
    }
    constexpr u128 &operator<<=(u64 n) {
        *this = *this << n;
        return *this;
    }
    constexpr u128 &operator+=(const u128 &o) {
        *this = *this + o;
        return *this;
    }
    constexpr u128 &operator-=(const u128 &o) {
        *this = *this - o;
        return *this;
    }

    constexpr bool operator==(const u128 &o) const {
        return hi == o.hi && lo == o.lo;
    }
    constexpr bool operator!=(const u128 &o) const {
        return !(*this == o);
    }
    constexpr bool operator<(const u128 &o) const {
        return hi < o.hi || (hi == o.hi && lo < o.lo);
    }
    constexpr bool operator>(const u128 &o) const {
        return o < *this;
    }
    constexpr bool operator<=(const u128 &o) const {
        return !(o < *this);
    }
    constexpr bool operator>=(const u128 &o) const {
        return !(*this < o);
    }
};

struct i128 {
    u64 lo;
    i64 hi;

    constexpr i128() : lo(0), hi(0) {}
    constexpr i128(int val) // NOLINT(implicit)
        : lo(static_cast<u64>(static_cast<i64>(val))), hi(val < 0 ? i64(-1) : i64(0)) {}
    constexpr i128(i64 val) // NOLINT(implicit)
        : lo(static_cast<u64>(val)), hi(val < 0 ? i64(-1) : i64(0)) {}
    constexpr i128(u64 val) // NOLINT(implicit)
        : lo(val), hi(0) {}
    constexpr i128(i64 hi_, u64 lo_) : lo(lo_), hi(hi_) {}
    i128(double val) { // NOLINT(implicit)
        bool neg = val < 0;
        double abs_val = neg ? -val : val;
        constexpr double two64 = 18446744073709551616.0;
        u64 h = static_cast<u64>(abs_val / two64);
        u64 l = static_cast<u64>(abs_val - static_cast<double>(h) * two64);
        lo = l;
        hi = static_cast<i64>(h);
        if (neg) {
            *this = -(*this);
        }
    }

    constexpr explicit operator u64() const {
        return lo;
    }
    constexpr explicit operator u128() const {
        return u128(static_cast<u64>(hi), lo);
    }
    constexpr i128 operator>>(u64 n) const {
        if (n == 0)
            return *this;
        if (n >= 128)
            return i128(hi < 0 ? i64(-1) : i64(0));
        if (n >= 64) {
            i64 s = hi >> static_cast<int>(n - 64);
            return i128(hi < 0 ? i64(-1) : i64(0), static_cast<u64>(s));
        }
        return i128(hi >> static_cast<int>(n), (lo >> n) | (static_cast<u64>(hi) << (64 - n)));
    }
    constexpr i128 operator-() const {
        u64 nl = ~lo + 1;
        return i128(static_cast<i64>(~static_cast<u64>(hi) + (nl == 0 ? 1 : 0)), nl);
    }
    constexpr bool operator==(const i128 &o) const {
        return hi == o.hi && lo == o.lo;
    }
    constexpr bool operator!=(const i128 &o) const {
        return !(*this == o);
    }
    constexpr bool operator<(const i128 &o) const {
        return hi < o.hi || (hi == o.hi && lo < o.lo);
    }
    constexpr bool operator>(const i128 &o) const {
        return o < *this;
    }
    constexpr bool operator<=(const i128 &o) const {
        return !(o < *this);
    }
    constexpr bool operator>=(const i128 &o) const {
        return !(*this < o);
    }
};

#else
using u128 = unsigned __int128;
using i128 = __int128;
#endif
// NOLINTEND(readability-identifier-naming)

#define U64C(x) UINT64_C(x)
} // namespace detail
} // namespace evi
