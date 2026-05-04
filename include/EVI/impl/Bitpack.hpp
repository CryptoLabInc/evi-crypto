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

#include <cstddef>
#include <cstdint>
#include <cstring>

namespace evi {
namespace detail {
namespace bitpack {

bool valid_W(unsigned w);
uint64_t mask_u64(unsigned w);
size_t words_for(size_t n, unsigned w);

// Pack n values from in[] into out_words[] (capacity out_cap_words).
// Returns number of u64 words written, or 0 on error.
// Requirements:
// - W in [1,64]
// - out_cap_words >= words_for(n,W)
// - in/out non-null unless n==0
size_t pack_fixedW(const uint64_t *in, size_t n, uint64_t *out_words, size_t out_cap_words, unsigned w);

// Unpack n values from in_words[] (length in_nwords) into out[].
// reminder: in_nwords must be >= words_for(n,W).
// Returns true on success, false on error.
bool unpack_fixedW(const uint64_t *in_words, size_t in_nwords, uint64_t *out, size_t n, unsigned w);

// Random access (best-effort):
// - If words are missing (near tail), treats them as 0 (padding).
// - Returns 0 if W invalid.
uint64_t get_i_fixedW(const uint64_t *in_words, size_t nwords, size_t i, unsigned w);

} // namespace bitpack
} // namespace detail
} // namespace evi
