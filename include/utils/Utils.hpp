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
#include "EVI/impl/KeyGeneratorImpl.hpp"
#include "nlohmann/json_fwd.hpp"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <functional>
#include <map>
#include <optional>
#include <sstream>
#include <string>

#include <openssl/buffer.h>
#include <openssl/evp.h>

// Inner (per-ciphertext-block) rank for RMP/RMS packing: the floor-power-of-two
// square root of the dimension, padded up to the next power of two FIRST.
//
// Why pad first: a message/dim of size D is laid out in a power-of-two-sized
// container (nextPow2(D)), so the inner rank must be derived from that padded
// size, not the raw D. Computing it on the raw D floors log2(D) one step too low
// for D in the upper half between two even powers (e.g. D in (2048, 4096) gave
// 32 instead of 64), which made the encrypt inner rank, the context padRank, and
// the eval-key file naming disagree for non-power-of-two dimensions. Padding
// first makes all three agree. For power-of-two D this is identical to the old
// raw form, so power-of-two ranks (every previously-working config) are
// unaffected; only non-power-of-two dims (which were already broken) change.
//
// Implemented with integer ops (no std::log2/std::pow rounding hazards) and kept
// as a function-like macro so the call sites that sit inside ContextImpl methods
// expand to a qualified call and are not shadowed by the 0-arg
// ContextImpl::getInnerRank() member.
namespace evi {
namespace detail {
namespace utils {
inline uint64_t innerRankFromDim(uint64_t dim) {
    uint64_t padded = 1; // nextPow2(dim): smallest power of two >= dim
    unsigned k = 0;      // log2(padded)
    while (padded < dim) {
        padded <<= 1;
        ++k;
    }
    uint64_t inner = uint64_t(1) << (k / 2); // 2^floor(log2(padded)/2)
    return inner < 32 ? uint64_t(32) : inner;
}
} // namespace utils
} // namespace detail
} // namespace evi
#define getInnerRank(rank) (evi::detail::utils::innerRankFromDim(static_cast<uint64_t>(rank)))

namespace evi {
namespace detail {
namespace utils {
namespace fs = std::filesystem;

void serializeQueryTo(const Query &query, std::ostream &os);
// TRUNC truncates each CIPHER block's b-part to its populated count `n` (V3).
void serializeQueryTo(const Query &query, std::ostream &os, evi::BTruncMode mode);
Query deserializeQueryFrom(std::istream &is);

void serializeResultTo(const SearchResult &res, std::ostream &os);
SearchResult deserializeResultFrom(std::istream &is);

std::string encodeToBase64(const std::vector<uint8_t> &data);
std::string encodeToBase64(const std::string &str);
std::vector<uint8_t> decodeBase64(const std::string &encoded);
std::string timePointToIso8601UtcString(std::chrono::system_clock::time_point tp);
std::chrono::system_clock::time_point iso8601UtcStringToTimePoint(const std::string &ts);
std::string currentIso8601UtcString();
bool isEnvelopeJson(const nlohmann::json &parsed);
std::string encryptMetadata(const std::string &metadata, const std::vector<uint8_t> &key,
                            const std::vector<uint8_t> &aad = {});
std::string decryptMetadata(const std::string &encrypted, const std::vector<uint8_t> &key,
                            const std::vector<uint8_t> &aad = {});

evi::ParameterPreset stringToPreset(const std::string &str);
evi::SealMode stringToSealMode(const std::string &str);
evi::EvalMode stringToEvalMode(const std::string &str);

std::string assignParameterString(evi::ParameterPreset preset);
std::string assignEvalModeString(evi::EvalMode mode);
std::string assignSealModeString(evi::SealMode s_mode);

void serializeString(const std::string &str, std::ostream &out);
void serializeEvalKey(const std::string &dir_path, const std::string &out_path);

void deserializeString(std::istream &in, std::string &str);
void deserializeEvalKey(const std::string &key_path, const std::string &output_dir, bool delete_after = true);

void serializeKeyFiles(const std::string &key_dir, std::ostream &out);
void deserializeKeyFiles(std::istream &in, SecretKey &sec_key, KeyPack &keypack);

std::vector<std::pair<int, int>> adjustRankList(std::vector<int> &rank_list);

} // namespace utils
} // namespace detail
} // namespace evi
