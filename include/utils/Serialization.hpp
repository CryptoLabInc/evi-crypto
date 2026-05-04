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

#include "EVI/impl/Bitpack.hpp"
#include "utils/Exceptions.hpp"
#include <cstdint>
#include <cstring>
#include <istream>
#include <ostream>
#include <vector>

namespace evi {
namespace detail {

using u64 = uint64_t;

namespace serialization {

constexpr char kMagic[4] = {'E', 'V', 'I', 'S'};
constexpr uint8_t kVersionV1 = 1;
// V2 adds: IData::preset (u8) after prime_p_bits in Matrix<T>::serializeTo.
// Everything else in the payload is unchanged. V1 readers treat preset
// as ParameterPreset::RUNTIME (same as context, no base conversion).
constexpr uint8_t kVersionV2 = 2;

struct HeaderInfo {
    bool has_header = false;
    uint8_t version = 0;
};

inline void writeHeader(std::ostream &os, uint8_t version = kVersionV1) {
    os.write(kMagic, sizeof(kMagic));
    os.write(reinterpret_cast<const char *>(&version), sizeof(version));
}

inline HeaderInfo readHeader(std::istream &is) {
    HeaderInfo info{};
    char magic[sizeof(kMagic)]{};

    std::streampos pos = is.tellg();
    is.read(magic, sizeof(magic));
    if (!is) {
        is.clear();
        if (pos != std::streampos(-1)) {
            is.seekg(pos);
        }
        return info;
    }

    if (std::memcmp(magic, kMagic, sizeof(magic)) != 0) {
        if (pos != std::streampos(-1)) {
            is.clear();
            is.seekg(pos);
        } else {
            for (int i = static_cast<int>(sizeof(magic)) - 1; i >= 0; --i) {
                is.unget();
            }
        }
        return info;
    }

    uint8_t version = 0;
    is.read(reinterpret_cast<char *>(&version), sizeof(version));
    if (!is) {
        is.clear();
        if (pos != std::streampos(-1)) {
            is.seekg(pos);
        }
        return info;
    }

    info.has_header = true;
    info.version = version;
    return info;
}

inline uint8_t bitLengthU64(uint64_t v) {
    uint8_t bits = 0;
    while (v) {
        ++bits;
        v >>= 1;
    }
    return bits;
}

inline void writePackedU64(std::ostream &stream, const u64 *data, std::size_t count, unsigned w) {
    if (!bitpack::valid_W(w)) {
        throw evi::InvalidInputError("Invalid bit width for packed serialization");
    }
    const std::size_t words = bitpack::words_for(count, w);
    std::vector<u64> packed(words);
    const std::size_t wrote = bitpack::pack_fixedW(data, count, packed.data(), words, w);
    if (wrote != words) {
        throw evi::InvalidInputError("Failed to pack data for serialization");
    }
    stream.write(reinterpret_cast<const char *>(packed.data()), words * sizeof(u64));
}

inline void readPackedU64(std::istream &stream, u64 *data, std::size_t count, unsigned w) {
    if (!bitpack::valid_W(w)) {
        throw evi::InvalidInputError("Invalid bit width for packed deserialization");
    }
    const std::size_t words = bitpack::words_for(count, w);
    std::vector<u64> packed(words);
    stream.read(reinterpret_cast<char *>(packed.data()), words * sizeof(u64));
    if (!bitpack::unpack_fixedW(packed.data(), words, data, count, w)) {
        throw evi::InvalidInputError("Failed to unpack data for deserialization");
    }
}

// Skip packed u64 data without allocating or unpacking. Advances stream past the payload.
inline void skipPackedU64(std::istream &stream, std::size_t count, unsigned w) {
    if (!bitpack::valid_W(w)) {
        throw evi::InvalidInputError("Invalid bit width for packed skip");
    }
    const std::size_t words = bitpack::words_for(count, w);
    stream.seekg(static_cast<std::streamoff>(words * sizeof(u64)), std::ios::cur);
    if (!stream) {
        throw evi::InvalidInputError("skipPackedU64: seekg failed (non-seekable or truncated stream)");
    }
}

} // namespace serialization
} // namespace detail
} // namespace evi
