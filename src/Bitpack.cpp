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

#include "EVI/impl/Bitpack.hpp"
#include "EVI/impl/Type.hpp"

namespace evi {
namespace detail {
namespace bitpack {

bool valid_W(unsigned w) {
    return (w >= 1 && w <= 64);
}

uint64_t mask_u64(unsigned w) {
    // Caller should ensure w in [1,64]
    return (w == 64) ? ~0ULL : ((1ULL << w) - 1ULL);
}

size_t words_for(size_t n, unsigned w) {
    // Caller should ensure w in [1,64]
    u128 bits = (u128)n * (u128)w;
    return (size_t)((bits + 63) >> 6); // ceil(bits/64)
}

size_t pack_fixedW(const uint64_t *in, size_t n, uint64_t *out_words, size_t out_cap_words, unsigned w) {
    if (n == 0) {
        return 0;
    }
    if (!valid_W(w) || !in || !out_words) {
        return 0;
    }

    const size_t need = words_for(n, w);
    if (out_cap_words < need) {
        return 0;
    }

    if (w == 64) {
        // Direct copy
        std::memcpy(out_words, in, n * sizeof(uint64_t));
        return n;
    }

    const uint64_t m = mask_u64(w);

    u128 acc = 0;      // low bits = earliest stream bits
    unsigned bits = 0; // 0..63 after each iteration
    size_t out_i = 0;

    for (size_t i = 0; i < n; ++i) {
        const uint64_t v = in[i] & m;

        acc |= (u128)v << bits;
        bits += w;

        // For W<=63 and bits previously in 0..63, flush happens at most once/iter.
        if (bits >= 64) {
            out_words[out_i++] = (uint64_t)acc; // full-word store (no RMW)
            acc >>= 64;
            bits -= 64;
        }
    }

    // Tail word (partial). Padding bits are zeros.
    if (bits != 0) {
        out_words[out_i++] = (uint64_t)acc;
    }

    // out_i should equal need
    return out_i;
}

bool unpack_fixedW(const uint64_t *in_words, size_t in_nwords, uint64_t *out, size_t n, unsigned w) {
    if (n == 0) {
        return true;
    }
    if (!valid_W(w) || !in_words || !out) {
        return false;
    }

    const size_t need = words_for(n, w);
    if (in_nwords < need) {
        return false;
    }

    if (w == 64) {
        std::memcpy(out, in_words, n * sizeof(uint64_t));
        return true;
    }

    const uint64_t m = mask_u64(w);

    u128 acc = 0;
    unsigned bits = 0;
    size_t in_i = 0;

    for (size_t i = 0; i < n; ++i) {
        // Ensure at least W bits available.
        if (bits < w) {
            acc |= (u128)in_words[in_i++] << bits;
            bits += 64;
        }

        out[i] = (uint64_t)(acc & m);
        acc >>= w;
        bits -= w;
    }

    return true;
}

uint64_t get_i_fixedW(const uint64_t *in_words, size_t nwords, size_t i, unsigned w) {
    if (!valid_W(w) || !in_words) {
        return 0;
    }
    if (w == 64) {
        return (i < nwords) ? in_words[i] : 0ULL;
    }

    const uint64_t m = mask_u64(w);
    const u128 bitpos = (u128)i * (u128)w;

    const size_t word_index = (size_t)(bitpos >> 6);
    const unsigned s = static_cast<unsigned>(static_cast<u64>(bitpos & 63));

    const uint64_t lo = (word_index < nwords) ? in_words[word_index] : 0ULL;
    const uint64_t hi = (word_index + 1 < nwords) ? in_words[word_index + 1] : 0ULL;

    const u128 x = (u128)lo | ((u128)hi << 64);
    return (uint64_t)((x >> s) & m);
}

} // namespace bitpack
} // namespace detail
} // namespace evi
