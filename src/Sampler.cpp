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

#include "utils/Sampler.hpp"
#include "EVI/Const.hpp"
#include "alea/algorithms.h"
#include <algorithm>
#include <cstdint>
#include <cstring>

namespace evi {
namespace detail {
RandomSampler::RandomSampler(const Context &context) : context_(context) {
    std::random_device rd;
    std::vector<u8> nseed(SEED_MIN_SIZE);
    for (int i = 0; i < SEED_MIN_SIZE / 4; i++) {
        u32 val = rd();
        memcpy(nseed.data() + i * 4, &val, sizeof(val));
    }
    as_ = std::shared_ptr<void>(alea_init(nseed.data(), ALEA_ALGORITHM_SHAKE256), [](void *p) {
        alea_free(static_cast<alea_state *>(p));
    });
}

RandomSampler::RandomSampler(const Context &context, std::optional<std::vector<u8>> seed) : context_(context) {
    if (!seed) {
        std::random_device rd;
        std::vector<u8> nseed(SEED_MIN_SIZE);
        for (int i = 0; i < SEED_MIN_SIZE / 4; i++) {
            u32 val = rd();
            memcpy(nseed.data() + i * 4, &val, sizeof(val));
        }
        seed = std::move(nseed);
    }
    as_ = std::shared_ptr<void>(alea_init(seed->data(), ALEA_ALGORITHM_SHAKE256), [](void *p) {
        alea_free(static_cast<alea_state *>(p));
    });
}

void RandomSampler::embedding(span<i64> coeff, span<u64> poly, u64 mod) {
    for (u64 i = 0; i < DEGREE; ++i) {
        poly[i] = addIfLTZeroU64(coeff[i], mod);
    }
}

i64 RandomSampler::getCenteredBinomialError() {
    i64 ret = 0;
    alea_sample_cbd_int64_array(as_.get(), &ret, 1, CBD_COIN_SIZE);
    return ret;
}

void RandomSampler::sampleZO(span<u64> res_q, std::optional<span<u64>> res_p) {
    u64 b1, b2;
    for (u32 i = 0; i < DEGREE; i++) {
        b1 = getRandomBits(1);
        b2 = getRandomBits(1);
        res_q[i] = sampleTernaryModU64(b1, b2, context_->getParam()->getPrimeQ());
        if (res_p) {
            res_p.value()[i] = sampleTernaryModU64(b1, b2, context_->getParam()->getPrimeP());
        }
    }
}

void RandomSampler::rejSamplingMod(span<i32> si) {
    int n = DEGREE;
    int tow_to_l = 1ULL << HW_REJ_BIT_SIZE;
    u32 rnd, m, l, t, s;
    for (int i = 0; i < n - 1; i++) {
        s = n - 1 - i;
        t = tow_to_l % s;
        do {
            rnd = getRandomBits(HW_REJ_BIT_SIZE);
            m = rnd * s;
            l = m & (tow_to_l - 1);
        } while (l < t);
        si[i] = (i32)m >> HW_REJ_BIT_SIZE;
    }
}

void RandomSampler::sampleHWT(span<i64> res) {
    alea_sample_hwt_int64_array(as_.get(), res.data(), DEGREE, HAMMING_WEIGHT);
}

void RandomSampler::noSampleHWT(span<i64> res) {
    std::fill(res.begin(), res.end(), 0L);
    for (u64 count = 0; count < context_->getParam()->getHW(); count++) {
        const u64 pos = (7 * count) % DEGREE;
        res[pos] = (count % 2) * 2 - 1;
    }
}

void RandomSampler::sampleGaussian(span<u64> res_q, std::optional<span<u64>> res_p) {
    for (u64 i = 0; i < DEGREE; i++) {
        i64 rnd = getCenteredBinomialError();
        res_q[i] = addIfLTZeroU64(rnd, context_->getParam()->getPrimeQ());
        if (res_p) {
            res_p.value()[i] = addIfLTZeroU64(rnd, context_->getParam()->getPrimeP());
        }
    }
}

void RandomSampler::sampleUniformModQ(span<u64> res) {
    for (int i = 0; i < DEGREE; i++) {
        u64 bw = bitWidth(context_->getParam()->getPrimeQ());
        res[i] = getRandomBits(bw);
        if (res[i] >= context_->getParam()->getPrimeQ()) {
            i--;
        }
    }
}

void RandomSampler::sampleUniformModP(span<u64> res) {
    for (int i = 0; i < DEGREE; i++) {
        u64 bw = bitWidth(context_->getParam()->getPrimeP());
        res[i] = getRandomBits(bw);
        if (res[i] >= context_->getParam()->getPrimeP()) {
            i--;
        }
    }
}

u64 RandomSampler::getRandomBits(u64 out_len) {
    u64 result;
    if (out_len == sizeof(u64) * 8) {
        return alea_get_random_uint64(as_.get());
    } else if (buffer_size_ >= out_len) {
        result = buffer & ((1ULL << out_len) - 1);
        buffer >>= out_len;
        buffer_size_ -= out_len;
    } else {
        u64 remaining_bits = out_len - buffer_size_;
        u64 low_bits = alea_get_random_uint64(as_.get());
        result = (buffer << remaining_bits) | (low_bits & (1UL << remaining_bits) - 1);
        buffer = low_bits >> remaining_bits;
        buffer_size_ = sizeof(u64) * 8 - remaining_bits;
    }
    return result;
}
} // namespace detail
} // namespace evi
