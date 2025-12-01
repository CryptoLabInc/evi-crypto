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

#include "EVI/impl/NTT.hpp"
#include "EVI/impl/Basic.cuh"
#include <algorithm>
#include <array>
#include <chrono>
#include <iostream>

#define HEAAN_LOOP_UNROLL_2 _Pragma("clang loop unroll_count(2)")
#define HEAAN_LOOP_UNROLL_4 _Pragma("clang loop unroll_count(4)")
#define HEAAN_LOOP_UNROLL_8 _Pragma("clang loop unroll_count(8)")

namespace evi {
namespace detail {
class U64PosNeg {

public:
    U64PosNeg(u64 p, u64 n, u64 prime) : pos(p), neg(n), scale{prime} {}

    inline static void bufly(U64PosNeg left, U64PosNeg right) {
        u64 tmp = left.pos + right.pos;
        u64 tmp_neg = left.neg + right.neg;
        right.pos = left.pos + right.neg;
        right.neg = left.neg + right.pos;
        left.pos = tmp;
        left.neg = tmp_neg;
        left.scale = left.scale << 1;
        right.scale = right.scale << 1;
    }

    u64 pos;
    u64 neg;
    u64 scale;
};

namespace utils {

namespace {
// Decompose n to 2^expo * oddpart. Make sure n != 0.
void extractPowerOfTwo(u64 *expo, u64 *oddpart, u64 n) {
    u64 expoval = U64C(0);

    while ((n & U64C(1)) == U64C(0)) {
        expoval++;
        n >>= U64C(1);
    }

    *oddpart = n;
    *expo = expoval;
}
} // namespace

void findPrimeFactors(std::set<u64> &s, u64 n) {
    s.clear();

    while (n % 2 == 0) {
        s.insert(2);
        n /= 2;
    }

    for (u64 i = 3; i * i <= n; i += 2) {
        while (n % i == 0) {
            s.insert(i);
            n /= i;
        }
    }

    if (n > 2) {
        s.insert(n);
    }
}

u64 findPrimitiveRoot(u64 prime) {
    std::set<u64> s;
    u64 phi = prime - 1;
    findPrimeFactors(s, phi);
    for (u64 r = 2; r <= phi; r++) {
        bool passed = true;
        for (unsigned long it : s) {
            if (powModSimple(r, phi / it, prime) == 1) {
                passed = false;
                break;
            }
        }

        if (passed) {
            return r;
        }
    }

    return 0; // failed to find
}

// For small numbers we use try-division. Else we perform strong
// probable-primality test for Sinclair bases {2, 325, 9375, 28178, 450775,
// 9780504, 1795265022} to completely avoid pseudoprimes for 64b unsigned
// integers.
bool isPrime(const u64 n) {
    if (n == 2 || n == 3 || n == 5 || n == 7) {
        return true;
    }
    if (n % 2 == 0 || n % 3 == 0 || n % 5 == 0 || n % 7 == 0) {
        return false;
    }
    if (n < 121) {
        return (n > 1);
    }

    u64 expo, oddpart;
    extractPowerOfTwo(&expo, &oddpart, n - 1);

    static constexpr std::array<u64, 7> SINCLAIR_BASE{U64C(2),      U64C(325),     U64C(9375),      U64C(28178),
                                                      U64C(450775), U64C(9780504), U64C(1795265022)};

    auto is_strong_probable_prime_of_base = [=](u64 base) {
        u64 x = powModSimple(base, oddpart, n);
        if (x == U64C(1) || x == n - 1) {
            return true;
        }
        for (u64 i = 0; i < expo - 1; ++i) {
            x = mulModSimple(x, x, n);
            if (x == n - 1) {
                return true;
            }
        }
        return false;
    };

    return std::all_of(SINCLAIR_BASE.begin(), SINCLAIR_BASE.end(), is_strong_probable_prime_of_base);
}

// Find close-to-power-of-two primes as many as `number`, each of which meets p
// = 1 % `gap` and is near `center`. `gap` should be small enough compared to
// `center`. If `onlySmaller` is true, find the primes that are all smaller than
// `center`.
std::vector<u64> seekPrimes(const u64 center, const u64 gap, u64 number, const bool only_smaller) {
    std::vector<u64> res;
    res.reserve(number);

    u64 base = center + 1;
    if ((!only_smaller) && isPrime(base)) {
        res.push_back(base);
        number--;
    }

    u64 multiplier = 1;
    u64 p;

    while (true) {
        if (!only_smaller) {
            p = base + multiplier * gap;
            if (isPrime(p)) {
                res.push_back(p);
                number--;
            }

            if (number == 0) {
                break;
            }
        }

        p = base - multiplier * gap;
        if (isPrime(p)) {
            res.push_back(p);
            number--;
        }

        if (number == 0) {
            break;
        }

        multiplier++;
    }

    return res;
}

} // namespace utils
namespace {

inline void butterfly(u64 &x, u64 &y, const u64 w, const u64 ws, const u64 p1, const u64 p2) {
    u64 tx = subIfGE(x, p2);
    u64 ty = mulModLazy(y, w, ws, p1);
    x = tx + ty;
    y = tx + p2 - ty;
}

inline void butterflyInv(u64 &x, u64 &y, const u64 w, const u64 ws, const u64 p1, const u64 p2) {
    u64 tx = x + y;
    u64 ty = x + p2 - y;
    x = subIfGE(tx, p2);
    y = mulModLazy(ty, w, ws, p1);
}

inline void butterflyInvPrune(u64 &x, u64 &y, const u64 w, const u64 ws, const u64 p1, const u64 p2) {

    u64 ty = x + p2 - y;
    y = mulModLazy(ty, w, ws, p1);
}

} // anonymous namespace

NTT::NTT(u64 degree, u64 prime)
    : prime_(prime), two_prime_(prime_ << 1), degree_(degree), psi_rev_(degree_), psi_inv_rev_(degree_),
      psi_rev_shoup_(degree_), psi_inv_rev_shoup_(degree_) {
    // if (prime % (2 * degree_) != 1)
    //     throw RuntimeException("Not an NTT-friendly prime given.");

    // if (!isPowerOfTwo(degree_))
    //     throw RuntimeException("[NTT] degree must be a power of two.");

    // if (degree_ < 64)
    //     throw RuntimeException("[NTT] degree should be >= 64.");

    auto mult_with_barr = [](u64 x, u64 y, u64 y_barr, u64 prime) {
        u64 res = mulModLazy(x, y, y_barr, prime);
        return subIfGE(res, prime);
    };

    u64 psi = utils::findPrimitiveRoot(prime);
    psi = powModSimple(psi, (prime - 1) / (2 * degree_), prime);

    // Find the minimal 2N-th root of unity
    u64 psi_square = mulModSimple(psi, psi, prime);
    u64 psi_square_barr = divide128By64Lo(psi_square, 0, prime);
    u64 min_root = psi;
    u64 psi_tmp = psi;
    for (u64 i = 0; i < degree_; ++i) {
        psi_tmp = mult_with_barr(psi_tmp, psi_square, psi_square_barr, prime);
        if (psi_tmp < min_root) {
            min_root = psi_tmp;
        }
    }
    psi = min_root;

    u64 psi_inv = invModSimple(psi, prime);
    psi_rev_[0] = 1;
    psi_inv_rev_[0] = 1;

    u64 idx = 0;
    u64 previdx = 0;
    u64 max_digits = log2floor(degree_);
    u64 psi_barr = divide128By64Lo(psi, 0, prime);
    u64 psi_inv_barr = divide128By64Lo(psi_inv, 0, prime);
    for (u64 i = 1; i < degree_; i++) {
        idx = bitReverse(i, max_digits);
        psi_rev_[idx] = mult_with_barr(psi_rev_[previdx], psi, psi_barr, prime);
        psi_inv_rev_[idx] = mult_with_barr(psi_inv_rev_[previdx], psi_inv, psi_inv_barr, prime);
        previdx = idx;
    }

    polyvec tmp(degree_);
    tmp[0] = psi_inv_rev_[0];
    idx = 1;
    for (u64 m = (degree_ >> 1); m > 0; m >>= 1) {
        for (u64 i = 0; i < m; i++) {
            tmp[idx] = psi_inv_rev_[m + i];
            idx++;
        }
    }
    psi_inv_rev_ = std::move(tmp);

    for (u64 i = 0; i < degree_; i++) {
        psi_rev_shoup_[i] = divide128By64Lo(psi_rev_[i], 0, prime);
        psi_inv_rev_shoup_[i] = divide128By64Lo(psi_inv_rev_[i], 0, prime);
    }

    // variables for last step of backward NTT
    degree_inv_ = invModSimple(degree_, prime_);
    degree_inv_barrett_ = divide128By64Lo(degree_inv_, 0, prime_);
    degree_inv_w_ = mulModSimple(degree_inv_, psi_inv_rev_[degree_ - 1], prime_);
    degree_inv_w_barrett_ = divide128By64Lo(degree_inv_w_, 0, prime_);

    // Only up to one of them will be hit. This mandates the NTT object
    // can only be run on cores that has the same detected feature during
    // construction time.
}

NTT::NTT(u64 degree, u64 prime, u64 degree_mini)
    : prime_(prime), two_prime_(prime_ << 1), degree_(degree_mini), psi_rev_(degree_), psi_inv_rev_(degree_),
      psi_rev_shoup_(degree_), psi_inv_rev_shoup_(degree_) {
    // if (prime % (2 * degree_) != 1)
    //     throw RuntimeException("Not an NTT-friendly prime given.");

    // if (!isPowerOfTwo(degree_))
    //     throw RuntimeException("[NTT] degree must be a power of two.");

    // if (degree_ < 64)
    //     throw RuntimeException("[NTT] degree should be >= 64.");

    auto mult_with_barr = [](u64 x, u64 y, u64 y_barr, u64 prime) {
        u64 res = mulModLazy(x, y, y_barr, prime);
        return subIfGE(res, prime);
    };

    u64 psi = utils::findPrimitiveRoot(prime);
    psi = powModSimple(psi, (prime - 1) / (2 * degree), prime);

    // Find the minimal 2N-th root of unity
    u64 psi_square = mulModSimple(psi, psi, prime);
    u64 psi_square_barr = divide128By64Lo(psi_square, 0, prime);
    u64 min_root = psi;
    u64 psi_tmp = psi;
    for (u64 i = 0; i < degree; ++i) {
        psi_tmp = mult_with_barr(psi_tmp, psi_square, psi_square_barr, prime);
        if (psi_tmp < min_root) {
            min_root = psi_tmp;
        }
    }
    psi = min_root;

    psi = powModSimple(psi, degree / degree_, prime);

    u64 psi_inv = invModSimple(psi, prime);
    psi_rev_[0] = 1;
    psi_inv_rev_[0] = 1;

    u64 idx = 0;
    u64 previdx = 0;
    u64 max_digits = log2floor(degree_);
    u64 psi_barr = divide128By64Lo(psi, 0, prime);
    u64 psi_inv_barr = divide128By64Lo(psi_inv, 0, prime);
    for (u64 i = 1; i < degree_; i++) {
        idx = bitReverse(i, max_digits);
        psi_rev_[idx] = mult_with_barr(psi_rev_[previdx], psi, psi_barr, prime);
        psi_inv_rev_[idx] = mult_with_barr(psi_inv_rev_[previdx], psi_inv, psi_inv_barr, prime);
        previdx = idx;
    }

    polyvec tmp(degree_);
    tmp[0] = psi_inv_rev_[0];
    idx = 1;
    for (u64 m = (degree_ >> 1); m > 0; m >>= 1) {
        for (u64 i = 0; i < m; i++) {
            tmp[idx] = psi_inv_rev_[m + i];
            idx++;
        }
    }
    psi_inv_rev_ = std::move(tmp);

    for (u64 i = 0; i < degree_; i++) {
        psi_rev_shoup_[i] = divide128By64Lo(psi_rev_[i], 0, prime);
        psi_inv_rev_shoup_[i] = divide128By64Lo(psi_inv_rev_[i], 0, prime);
    }

    // variables for last step of backward NTT
    degree_inv_ = invModSimple(degree_, prime_);
    degree_inv_barrett_ = divide128By64Lo(degree_inv_, 0, prime_);
    degree_inv_w_ = mulModSimple(degree_inv_, psi_inv_rev_[degree_ - 1], prime_);
    degree_inv_w_barrett_ = divide128By64Lo(degree_inv_w_, 0, prime_);

    // Only up to one of them will be hit. This mandates the NTT object
    // can only be run on cores that has the same detected feature during
    // construction time.
}

void NTT::computeForwardNativeSingleStep(u64 *op, const u64 t) const {
    const u64 degree = this->degree_;
    const u64 prime = this->prime_;
    const u64 two_prime = this->two_prime_;

    const u64 m = (degree >> 1) / t;
    const u64 *w_ptr = psi_rev_.data() + m;
    const u64 *ws_ptr = psi_rev_shoup_.data() + m;

    switch (t) {
    case 1:
        HEAAN_LOOP_UNROLL_8
        for (u64 i = (degree >> 3); i > 0; --i, op += 8) {
            butterfly(op[0], op[1], *w_ptr++, *ws_ptr++, prime, two_prime);
            butterfly(op[2], op[3], *w_ptr++, *ws_ptr++, prime, two_prime);
            butterfly(op[4], op[5], *w_ptr++, *ws_ptr++, prime, two_prime);
            butterfly(op[6], op[7], *w_ptr++, *ws_ptr++, prime, two_prime);
        }
        break;
    case 2:
        HEAAN_LOOP_UNROLL_8
        for (u64 i = (degree >> 3); i > 0; --i, op += 8) {
            butterfly(op[0], op[2], *w_ptr, *ws_ptr, prime, two_prime);
            butterfly(op[1], op[3], *w_ptr++, *ws_ptr++, prime, two_prime);
            butterfly(op[4], op[6], *w_ptr, *ws_ptr, prime, two_prime);
            butterfly(op[5], op[7], *w_ptr++, *ws_ptr++, prime, two_prime);
        }
        break;
    case 4:
        HEAAN_LOOP_UNROLL_8
        for (u64 i = (degree >> 3); i > 0; --i, op += 8) {
            const u64 w = *w_ptr++;
            const u64 ws = *ws_ptr++;

            butterfly(op[0], op[4], w, ws, prime, two_prime);
            butterfly(op[1], op[5], w, ws, prime, two_prime);
            butterfly(op[2], op[6], w, ws, prime, two_prime);
            butterfly(op[3], op[7], w, ws, prime, two_prime);
        }
        break;
    case 8:
        HEAAN_LOOP_UNROLL_8
        for (u64 i = (degree >> 4); i > 0; --i, op += 16) {
            const u64 w = *w_ptr++;
            const u64 ws = *ws_ptr++;

            butterfly(op[0], op[8], w, ws, prime, two_prime);
            butterfly(op[1], op[9], w, ws, prime, two_prime);
            butterfly(op[2], op[10], w, ws, prime, two_prime);
            butterfly(op[3], op[11], w, ws, prime, two_prime);
            butterfly(op[4], op[12], w, ws, prime, two_prime);
            butterfly(op[5], op[13], w, ws, prime, two_prime);
            butterfly(op[6], op[14], w, ws, prime, two_prime);
            butterfly(op[7], op[15], w, ws, prime, two_prime);
        }
        break;
    default:
        u64 *x_ptr = op;
        u64 *y_ptr = op + t;

        for (u64 i = m; i > 0; --i) {
            const u64 w = *w_ptr++;
            const u64 ws = *ws_ptr++;

            HEAAN_LOOP_UNROLL_8
            for (u64 j = (t >> 3); j > 0; --j) {
                butterfly(*x_ptr++, *y_ptr++, w, ws, prime, two_prime);
                butterfly(*x_ptr++, *y_ptr++, w, ws, prime, two_prime);
                butterfly(*x_ptr++, *y_ptr++, w, ws, prime, two_prime);
                butterfly(*x_ptr++, *y_ptr++, w, ws, prime, two_prime);

                butterfly(*x_ptr++, *y_ptr++, w, ws, prime, two_prime);
                butterfly(*x_ptr++, *y_ptr++, w, ws, prime, two_prime);
                butterfly(*x_ptr++, *y_ptr++, w, ws, prime, two_prime);
                butterfly(*x_ptr++, *y_ptr++, w, ws, prime, two_prime);
            }
            x_ptr += t;
            y_ptr += t;
        }
    }
}

void NTT::computeForwardNativeSingleStep1(u64 *op, const u64 t, const u64 pad_rank) const {
    const u64 degree = pad_rank;
    const u64 prime = this->prime_;
    const u64 two_prime = this->two_prime_;

    const u64 m = (degree >> 1) / t;
    const u64 *w_ptr = psi_rev_.data() + m;
    const u64 *ws_ptr = psi_rev_shoup_.data() + m;

    switch (t) {
    case 1:
        HEAAN_LOOP_UNROLL_8
        for (u64 i = (degree >> 3); i > 0; --i, op += 8) {
            butterfly(op[0], op[1], *w_ptr++, *ws_ptr++, prime, two_prime);
            butterfly(op[2], op[3], *w_ptr++, *ws_ptr++, prime, two_prime);
            butterfly(op[4], op[5], *w_ptr++, *ws_ptr++, prime, two_prime);
            butterfly(op[6], op[7], *w_ptr++, *ws_ptr++, prime, two_prime);
        }
        break;
    case 2:
        HEAAN_LOOP_UNROLL_8
        for (u64 i = (degree >> 3); i > 0; --i, op += 8) {
            butterfly(op[0], op[2], *w_ptr, *ws_ptr, prime, two_prime);
            butterfly(op[1], op[3], *w_ptr++, *ws_ptr++, prime, two_prime);
            butterfly(op[4], op[6], *w_ptr, *ws_ptr, prime, two_prime);
            butterfly(op[5], op[7], *w_ptr++, *ws_ptr++, prime, two_prime);
        }
        break;
    case 4:
        HEAAN_LOOP_UNROLL_8
        for (u64 i = (degree >> 3); i > 0; --i, op += 8) {
            const u64 w = *w_ptr++;
            const u64 ws = *ws_ptr++;

            butterfly(op[0], op[4], w, ws, prime, two_prime);
            butterfly(op[1], op[5], w, ws, prime, two_prime);
            butterfly(op[2], op[6], w, ws, prime, two_prime);
            butterfly(op[3], op[7], w, ws, prime, two_prime);
        }
        break;
    case 8:
        HEAAN_LOOP_UNROLL_8
        for (u64 i = (degree >> 4); i > 0; --i, op += 16) {
            const u64 w = *w_ptr++;
            const u64 ws = *ws_ptr++;

            butterfly(op[0], op[8], w, ws, prime, two_prime);
            butterfly(op[1], op[9], w, ws, prime, two_prime);
            butterfly(op[2], op[10], w, ws, prime, two_prime);
            butterfly(op[3], op[11], w, ws, prime, two_prime);
            butterfly(op[4], op[12], w, ws, prime, two_prime);
            butterfly(op[5], op[13], w, ws, prime, two_prime);
            butterfly(op[6], op[14], w, ws, prime, two_prime);
            butterfly(op[7], op[15], w, ws, prime, two_prime);
        }
        break;
    default:
        u64 *x_ptr = op;
        u64 *y_ptr = op + t;

        for (u64 i = m; i > 0; --i) {
            const u64 w = *w_ptr++;
            const u64 ws = *ws_ptr++;

            HEAAN_LOOP_UNROLL_8
            for (u64 j = (t >> 3); j > 0; --j) {
                butterfly(*x_ptr++, *y_ptr++, w, ws, prime, two_prime);
                butterfly(*x_ptr++, *y_ptr++, w, ws, prime, two_prime);
                butterfly(*x_ptr++, *y_ptr++, w, ws, prime, two_prime);
                butterfly(*x_ptr++, *y_ptr++, w, ws, prime, two_prime);

                butterfly(*x_ptr++, *y_ptr++, w, ws, prime, two_prime);
                butterfly(*x_ptr++, *y_ptr++, w, ws, prime, two_prime);
                butterfly(*x_ptr++, *y_ptr++, w, ws, prime, two_prime);
                butterfly(*x_ptr++, *y_ptr++, w, ws, prime, two_prime);
            }
            x_ptr += t;
            y_ptr += t;
        }
    }
}

template <int OutputModFactor>
void NTT::computeForward(u64 *op) const {
    static_assert((OutputModFactor == 1) || (OutputModFactor == 2) || (OutputModFactor == 4),
                  "OutputModFactor must be 1, 2 or 4");
    // fallback
    const u64 degree = this->degree_;

    for (u64 t = (degree >> 1); t > 0; t >>= 1) {
        computeForwardNativeSingleStep(op, t);
    }

    if constexpr (OutputModFactor <= 2) {
        const u64 prime = this->prime_;
        const u64 two_prime = this->two_prime_;

        for (u64 i = 0; i < degree; i++) {
            op[i] = subIfGE(op[i], two_prime);
            if constexpr (OutputModFactor == 1) {
                op[i] = subIfGE(op[i], prime);
            }
        }

        (void)(prime);
    }
}

template <int OutputModFactor>
void NTT::computeForward(u64 *op, const u64 pad_rank) const {
    static_assert((OutputModFactor == 1) || (OutputModFactor == 2) || (OutputModFactor == 4),
                  "OutputModFactor must be 1, 2 or 4");
    // fallback
    const u64 degree = this->degree_;
    const u64 repeated = (degree / pad_rank);

    for (u64 i = 1; i < repeated; i++) {
        for (u64 j = 0; j < pad_rank; j++) {
            op[i * pad_rank + j] = op[j];
        }
    }

    for (u64 t = (pad_rank >> 1); t > 0; t >>= 1) {
        computeForwardNativeSingleStep(op, t);
    }
    if constexpr (OutputModFactor <= 2) {
        const u64 prime = this->prime_;
        const u64 two_prime = this->two_prime_;

        for (u64 i = 0; i < pad_rank; i++) {
            op[i] = subIfGE(op[i], two_prime);
            if constexpr (OutputModFactor == 1) {
                op[i] = subIfGE(op[i], prime);
            }
        }

        (void)(prime);
    }
}

template void NTT::computeForward<1>(u64 *op) const;
template void NTT::computeForward<2>(u64 *op) const;
template void NTT::computeForward<4>(u64 *op) const;

template void NTT::computeForward<1>(u64 *op, const u64 pad_rank) const;
template void NTT::computeForward<2>(u64 *op, const u64 pad_rank) const;
template void NTT::computeForward<4>(u64 *op, const u64 pad_rank) const;

void NTT::computeBackwardNativeSingleStep(u64 *op, const u64 t) const {
    const u64 degree = this->degree_;
    const u64 prime = this->prime_;
    const u64 two_prime = this->two_prime_;

    const u64 m = (degree >> 1) / t;
    const u64 root_idx = 1 + degree - (degree / t);
    const u64 *w_ptr = psi_inv_rev_.data() + root_idx;
    const u64 *ws_ptr = psi_inv_rev_shoup_.data() + root_idx;

    switch (t) {
    case 1:
        HEAAN_LOOP_UNROLL_8
        for (u64 i = (degree >> 3); i > 0; --i, op += 8) {
            butterflyInv(op[0], op[1], *w_ptr++, *ws_ptr++, prime, two_prime);
            butterflyInv(op[2], op[3], *w_ptr++, *ws_ptr++, prime, two_prime);
            butterflyInv(op[4], op[5], *w_ptr++, *ws_ptr++, prime, two_prime);
            butterflyInv(op[6], op[7], *w_ptr++, *ws_ptr++, prime, two_prime);
        }
        break;
    case 2:
        HEAAN_LOOP_UNROLL_8
        for (u64 i = (degree >> 3); i > 0; --i, op += 8) {
            butterflyInv(op[0], op[2], *w_ptr, *ws_ptr, prime, two_prime);
            butterflyInv(op[1], op[3], *w_ptr++, *ws_ptr++, prime, two_prime);
            butterflyInv(op[4], op[6], *w_ptr, *ws_ptr, prime, two_prime);
            butterflyInv(op[5], op[7], *w_ptr++, *ws_ptr++, prime, two_prime);
        }
        break;
    case 4:
        HEAAN_LOOP_UNROLL_8
        for (u64 i = (degree >> 3); i > 0; --i, op += 8) {
            const u64 w = *w_ptr++;
            const u64 ws = *ws_ptr++;

            butterflyInv(op[0], op[4], w, ws, prime, two_prime);
            butterflyInv(op[1], op[5], w, ws, prime, two_prime);
            butterflyInv(op[2], op[6], w, ws, prime, two_prime);
            butterflyInv(op[3], op[7], w, ws, prime, two_prime);
        }
        break;
    case 8:
        HEAAN_LOOP_UNROLL_8
        for (u64 i = (degree >> 4); i > 0; --i, op += 16) {
            const u64 w = *w_ptr++;
            const u64 ws = *ws_ptr++;

            butterflyInv(op[0], op[8], w, ws, prime, two_prime);
            butterflyInv(op[1], op[9], w, ws, prime, two_prime);
            butterflyInv(op[2], op[10], w, ws, prime, two_prime);
            butterflyInv(op[3], op[11], w, ws, prime, two_prime);
            butterflyInv(op[4], op[12], w, ws, prime, two_prime);
            butterflyInv(op[5], op[13], w, ws, prime, two_prime);
            butterflyInv(op[6], op[14], w, ws, prime, two_prime);
            butterflyInv(op[7], op[15], w, ws, prime, two_prime);
        }
        break;
    default:
        u64 *x_ptr = op;
        u64 *y_ptr = op + t;

        for (u64 i = m; i > 0; --i) {
            const u64 w = *w_ptr++;
            const u64 ws = *ws_ptr++;

            HEAAN_LOOP_UNROLL_8
            for (u64 j = (t >> 3); j > 0; --j) {
                butterflyInv(*x_ptr++, *y_ptr++, w, ws, prime, two_prime);
                butterflyInv(*x_ptr++, *y_ptr++, w, ws, prime, two_prime);
                butterflyInv(*x_ptr++, *y_ptr++, w, ws, prime, two_prime);
                butterflyInv(*x_ptr++, *y_ptr++, w, ws, prime, two_prime);

                butterflyInv(*x_ptr++, *y_ptr++, w, ws, prime, two_prime);
                butterflyInv(*x_ptr++, *y_ptr++, w, ws, prime, two_prime);
                butterflyInv(*x_ptr++, *y_ptr++, w, ws, prime, two_prime);
                butterflyInv(*x_ptr++, *y_ptr++, w, ws, prime, two_prime);
            }
            x_ptr += t;
            y_ptr += t;
        }
    }
}

void NTT::computeBackwardNativeSingleStep2(u64 *op, const u64 t, const u64 fullmod) const {
    const u64 degree = this->degree_;
    const u64 prime = this->prime_;
    const u64 two_prime = this->two_prime_;

    const u64 m = (degree >> 1) / t;
    const u64 root_idx = 1 + degree - (degree / t);
    const u64 *w_ptr = psi_inv_rev_.data() + root_idx;
    const u64 *ws_ptr = psi_inv_rev_shoup_.data() + root_idx;
    const u64 repeat = t / fullmod;

    switch (repeat) {
    default:
        u64 *x_ptr = op + fullmod - 1;
        u64 *y_ptr = op + fullmod - 1 + t;

        for (u64 i = m; i > 0; --i) {
            const u64 w = *w_ptr++;
            const u64 ws = *ws_ptr++;

            HEAAN_LOOP_UNROLL_8
            for (u64 j = repeat; j > 0; --j) {
                butterflyInv(*x_ptr, *y_ptr, w, ws, prime, two_prime);
                x_ptr += fullmod;
                y_ptr += fullmod;
            }
            x_ptr += t;
            y_ptr += t;
        }
    }
}

void NTT::computeBackwardNativeSingleStep1(u64 *op, const u64 t, const u64 fullmod) const {
    const u64 degree = this->degree_;
    const u64 prime = this->prime_;
    const u64 two_prime = this->two_prime_;

    const u64 m = (degree >> 1) / t;
    const u64 root_idx = 1 + degree - (degree / t);
    const u64 *w_ptr = psi_inv_rev_.data() + root_idx;
    const u64 *ws_ptr = psi_inv_rev_shoup_.data() + root_idx;

    switch (t) {
    case 1:
        HEAAN_LOOP_UNROLL_8
        for (u64 i = (degree >> 4); i > 0; --i, op += 16) {
            butterflyInvPrune(op[0], op[1], *w_ptr++, *ws_ptr++, prime, two_prime);
            butterflyInvPrune(op[2], op[3], *w_ptr++, *ws_ptr++, prime, two_prime);
            butterflyInvPrune(op[4], op[5], *w_ptr++, *ws_ptr++, prime, two_prime);
            butterflyInvPrune(op[6], op[7], *w_ptr++, *ws_ptr++, prime, two_prime);

            butterflyInvPrune(op[8], op[9], *w_ptr++, *ws_ptr++, prime, two_prime);
            butterflyInvPrune(op[10], op[11], *w_ptr++, *ws_ptr++, prime, two_prime);
            butterflyInvPrune(op[12], op[13], *w_ptr++, *ws_ptr++, prime, two_prime);
            butterflyInvPrune(op[14], op[15], *w_ptr++, *ws_ptr++, prime, two_prime);
        }
        break;
    case 2:
        HEAAN_LOOP_UNROLL_8
        for (u64 i = (degree >> 4); i > 0; --i, op += 16) {
            butterflyInvPrune(op[1], op[3], *w_ptr++, *ws_ptr++, prime, two_prime);
            butterflyInvPrune(op[5], op[7], *w_ptr++, *ws_ptr++, prime, two_prime);
            butterflyInvPrune(op[9], op[11], *w_ptr++, *ws_ptr++, prime, two_prime);
            butterflyInvPrune(op[13], op[15], *w_ptr++, *ws_ptr++, prime, two_prime);
        }
        break;
    case 4:
        HEAAN_LOOP_UNROLL_8
        for (u64 i = (degree >> 4); i > 0; --i, op += 16) {
            butterflyInvPrune(op[3], op[7], *w_ptr++, *ws_ptr++, prime, two_prime);
            butterflyInvPrune(op[11], op[15], *w_ptr++, *ws_ptr++, prime, two_prime);
        }
        break;
    case 8:
        HEAAN_LOOP_UNROLL_8
        for (u64 i = (degree >> 4); i > 0; --i, op += 16) {
            const u64 w = *w_ptr++;
            const u64 ws = *ws_ptr++;
            butterflyInvPrune(op[7], op[15], w, ws, prime, two_prime);
        }
        break;
    default:
        u64 *x_ptr = op + (fullmod - 1) % t;
        u64 *y_ptr = x_ptr + t;

        for (u64 i = m; i > 0; --i) {
            const u64 w = *w_ptr++;
            const u64 ws = *ws_ptr++;
            butterflyInvPrune(*x_ptr, *y_ptr, w, ws, prime, two_prime);
            x_ptr += 2 * t;
            y_ptr += 2 * t;
        }
    }
}

void NTT::computeBackwardNativeLast(u64 *op) const {
    const u64 degree = this->degree_;
    const u64 prime = this->prime_;
    const u64 two_prime = this->two_prime_;

    const u64 degree_inv = this->degree_inv_;
    const u64 degree_inv_br = this->degree_inv_barrett_;
    const u64 degree_inv_w = this->degree_inv_w_;
    const u64 degree_inv_w_br = this->degree_inv_w_barrett_;

    auto butterfly_inv_degree = [&](u64 &x, u64 &y) {
        u64 tx = x + y;
        u64 ty = x + two_prime - y;
        tx = subIfGE(tx, two_prime);
        x = mulModLazy(tx, degree_inv, degree_inv_br, prime);
        y = mulModLazy(ty, degree_inv_w, degree_inv_w_br, prime);
    };

    u64 *x_ptr = op;
    u64 *y_ptr = op + (degree >> 1);

    HEAAN_LOOP_UNROLL_8
    for (u64 i = (degree >> 4); i > 0; --i) {
        butterfly_inv_degree(*x_ptr++, *y_ptr++);
        butterfly_inv_degree(*x_ptr++, *y_ptr++);
        butterfly_inv_degree(*x_ptr++, *y_ptr++);
        butterfly_inv_degree(*x_ptr++, *y_ptr++);

        butterfly_inv_degree(*x_ptr++, *y_ptr++);
        butterfly_inv_degree(*x_ptr++, *y_ptr++);
        butterfly_inv_degree(*x_ptr++, *y_ptr++);
        butterfly_inv_degree(*x_ptr++, *y_ptr++);
    }
}

void NTT::computeBackwardNativeLast(u64 *op, const u64 fullmod) const {
    const u64 degree = this->degree_;
    const u64 prime = this->prime_;
    const u64 two_prime = this->two_prime_;

    const u64 degree_inv = this->degree_inv_;
    const u64 degree_inv_br = this->degree_inv_barrett_;
    const u64 degree_inv_w = this->degree_inv_w_;
    const u64 degree_inv_w_br = this->degree_inv_w_barrett_;

    auto butterfly_inv_degree = [&](u64 &x, u64 &y) {
        u64 tx = x + y;
        u64 ty = x + two_prime - y;
        tx = subIfGE(tx, two_prime);
        x = mulModLazy(tx, degree_inv, degree_inv_br, prime);
        y = mulModLazy(ty, degree_inv_w, degree_inv_w_br, prime);
    };

    u64 repeat = degree / (2 * fullmod);
    u64 *x_ptr = op + fullmod - 1;
    u64 *y_ptr = op + fullmod + (degree >> 1) - 1;

    HEAAN_LOOP_UNROLL_8
    for (u64 i = repeat; i > 0; --i) {
        butterfly_inv_degree(*x_ptr, *y_ptr);
        x_ptr += fullmod;
        y_ptr += fullmod;
    }
}

template <int OutputModFactor>
void NTT::computeBackward(u64 *op) const {
    static_assert((OutputModFactor == 1) || (OutputModFactor == 2), "OutputModFactor must be 1 or 2");

    const u64 degree = this->degree_;
    const u64 half_degree = degree >> 1;

    for (u64 t = 1; t < half_degree; t <<= 1) {
        computeBackwardNativeSingleStep(op, t);
    }

    computeBackwardNativeLast(op);

    if constexpr (OutputModFactor == 1) {
        const u64 prime = this->prime_;

        for (u64 i = 0; i < degree; i++) {
            op[i] = subIfGE(op[i], prime);
        }
    }
}

template <int OutputModFactor>
void NTT::computeBackward(u64 *op, u64 fullmod) const { // full mode must be the 2 to the power of n.
    static_assert((OutputModFactor == 1) || (OutputModFactor == 2), "OutputModFactor must be 1 or 2");

    const u64 degree = this->degree_;
    const u64 half_degree = degree >> 1;
    const u64 step1_target = fullmod;
    const u64 repeat = degree / fullmod;

    for (u64 t = 1; t < fullmod; t <<= 1) {
        computeBackwardNativeSingleStep1(op, t, fullmod);
    }
    for (u64 t = fullmod; t < half_degree; t <<= 1) {
        computeBackwardNativeSingleStep2(op, t, fullmod);
    }

    computeBackwardNativeLast(op, fullmod);
    if constexpr (OutputModFactor == 1) {
        const u64 prime = this->prime_;

        for (u64 i = fullmod - 1; i < degree; i += fullmod) {
            op[i] = subIfGE(op[i], prime);
        }
    }
}

template void NTT::computeBackward<1>(u64 *op) const;
template void NTT::computeBackward<2>(u64 *op) const;

template void NTT::computeBackward<1>(u64 *op, u64 fullmod) const;
template void NTT::computeBackward<2>(u64 *op, u64 fullmod) const;
} // namespace detail
} // namespace evi
