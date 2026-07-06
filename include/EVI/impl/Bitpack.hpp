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
uint32_t words_for(uint32_t n, unsigned w);

// Single canonical wire-format authority, templated on the value element
// type T; the packed stream stays u64-word-framed regardless of T.
// Byte-identical guarantee: for T=uint64_t the value cast is the identity;
// for narrow T it is mask-equivalent to the legacy widen-then-pack path.
// Non-inline + explicitly instantiated (below) for ABI stability and zero
// call-site churn (~150 u64 callers use the default T via implicit narrow).
template <class T = uint64_t>
uint32_t pack_fixedW(const T *in, uint32_t n, uint64_t *out_words, uint32_t out_cap_words, unsigned w);

template <class T = uint64_t>
bool unpack_fixedW(const uint64_t *in_words, uint32_t in_nwords, T *out, uint32_t n, unsigned w);

extern template uint32_t pack_fixedW<uint64_t>(const uint64_t *, uint32_t, uint64_t *, uint32_t, unsigned);
extern template uint32_t pack_fixedW<uint32_t>(const uint32_t *, uint32_t, uint64_t *, uint32_t, unsigned);
extern template bool unpack_fixedW<uint64_t>(const uint64_t *, uint32_t, uint64_t *, uint32_t, unsigned);
extern template bool unpack_fixedW<uint32_t>(const uint64_t *, uint32_t, uint32_t *, uint32_t, unsigned);

// Random access (best-effort): missing tail words read as 0, returns 0 if W invalid.
uint64_t get_i_fixedW(const uint64_t *in_words, uint32_t nwords, uint32_t i, unsigned w);

} // namespace bitpack
} // namespace detail
} // namespace evi
