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

#include "EVI/impl/CKKSTypes.hpp"
#include "EVI/impl/ContextImpl.hpp"

#include <deb/CKKSTypes.hpp>
#include <deb/Preset.hpp>

// Backward-compat aliases for deb types templated in deb-private #59
namespace deb {
using PolyUnit = PolyUnitT<u64>;
using Polynomial = PolynomialT<u64>;
using Ciphertext = CiphertextT<u64>;
using SecretKey = SecretKeyT<u64>;
using SwitchKey = SwitchKeyT<u64>;
} // namespace deb

namespace evi {
namespace detail {
namespace utils {

deb::Preset getDebPreset(const detail::Context &context);

// Single source of truth for the IP3 u32-native gate: the context runs the
// u32-native deb path (keygen/encrypt/keyswitch in deb::*32) iff its preset is
// IP3 and it is on CPU. Mirrors the isU32Matrix() <=> preset==IP3 invariant,
// plus the CPU restriction of the u32 deb backend. (Distinct from
// Encode.hpp's isU32Preset(ParameterPreset), which is an IP2 storage-width
// check with different semantics.)
bool isU32NativePreset(const detail::Context &context);

// Single source of truth for the backward-L0-key u32/u64 storage variant,
// shared by the writer (KeyGeneratorImpl) and the reader (KeyPackImpl) so the
// two sides decide identically. Same preset==IP3 condition as isU32NativePreset
// but WITHOUT the CPU/device check: key storage is device-agnostic.
bool isU32BackwardKey(const detail::Context &context);

deb::Preset getDebPreset(const std::string &preset);

deb::Size getDebNumP(const detail::Context &context);

deb::Size getDebGadgetRank(const detail::Context &context);

const deb::u64 *getDebPrimes(const detail::Context &context);

std::optional<deb::RNGSeed> convertDebSeed(const std::optional<std::vector<u8>> &seed);

bool syncFixedKeyToDebSwkKey(const detail::Context &context, const detail::FixedKeyType &fixed, deb::SwitchKey &swk);

bool syncVarKeyToDebSwkKey(const detail::Context &context, const detail::VariadicKeyType &variadic,
                           deb::SwitchKey &swk);

// Wrap caller-owned limb buffers in a deb::CiphertextT<U> (zero-copy via
// PolyUnitT<U>::setData) so deb's Encryptor writes the ciphertext in-place.
// a_p/b_p == nullptr => level 0. Instantiated for u64 and the IP3 u32-native
// path (IP3 primes < 2^32). Element type U is deduced from the buffer pointers;
// pass it explicitly (e.g. convertPointerToDebCipher<u64>(...)) when a_p/b_p
// are a bare nullptr so deduction has a width to use.
template <typename U>
deb::CiphertextT<U> convertPointerToDebCipher(const detail::Context &context, U *a_q, U *b_q, U *a_p = nullptr,
                                              U *b_p = nullptr, bool is_ntt = true);

template <typename U>
deb::SecretKeyT<U> makeDebSecretKey(deb::Preset preset, const deb::SecretKey &src);

template <typename U>
deb::SecretKeyT<U> makeDirectRootDebSecretKey(deb::Preset preset, const deb::SecretKey &src);

deb::Ciphertext convertSingleCipherToDebCipher(const detail::Context &context,
                                               detail::SingleBlock<DataType::CIPHER> &cipher, bool is_ntt = true);

deb::Preset getDebPreset(evi::ParameterPreset preset);

deb::Ciphertext convertPointerToDebCipherWithPreset(evi::ParameterPreset preset, detail::u64 *a_q, detail::u64 *b_q,
                                                    bool is_ntt = true);

} // namespace utils
} // namespace detail
} // namespace evi
