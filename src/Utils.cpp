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

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iomanip>
#include <limits>
#include <random>
#include <set>
#include <sstream>
#include <stdexcept>
#include <vector>

#include "EVI/Const.hpp"
#include "EVI/Utils.hpp"
#include "alea/alea.h"
#include "alea/algorithms.h"
#include "nlohmann/json.hpp"
#include "utils/Utils.hpp"

#include "EVI/Enums.hpp"
#include "utils/Exceptions.hpp"
#include "utils/Serialization.hpp"
#include "utils/crypto/AES.hpp"
#include <filesystem>
#include <memory>
#include <stdexcept>

namespace evi {
namespace detail {
namespace fs = std::filesystem;

namespace {
constexpr char K_BASE64_ALPHABET[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::array<uint8_t, 256> buildBase64DecodeTable() {
    std::array<uint8_t, 256> table{};
    table.fill(0xFF);
    for (uint8_t i = 0; i < 64; ++i) {
        table[static_cast<uint8_t>(K_BASE64_ALPHABET[i])] = i;
    }
    return table;
}

const std::array<uint8_t, 256> K_BASE64_DECODE_TABLE = buildBase64DecodeTable();

inline bool isBase64Whitespace(unsigned char c) {
    return c == '\n' || c == '\r' || c == '\t' || c == ' ';
}

nlohmann::ordered_json canonicalizeJson(const nlohmann::ordered_json &node) {
    std::function<nlohmann::ordered_json(const nlohmann::ordered_json &)> normalize =
        [&](const nlohmann::ordered_json &n) -> nlohmann::ordered_json {
        if (n.is_object()) {
            nlohmann::ordered_json canonical = nlohmann::ordered_json::object();
            std::vector<std::string> keys;
            keys.reserve(n.size());
            for (auto it = n.cbegin(); it != n.cend(); ++it) {
                keys.push_back(it.key());
            }
            std::sort(keys.begin(), keys.end());
            for (const auto &key : keys) {
                canonical[key] = normalize(n.at(key));
            }
            return canonical;
        }
        if (n.is_array()) {
            nlohmann::ordered_json canonical = nlohmann::ordered_json::array();
            for (const auto &element : n) {
                canonical.push_back(normalize(element));
            }
            return canonical;
        }
        if (n.is_number_float()) {
            const double val = n.get<double>();
            if (val == 0.0 && std::signbit(val)) {
                return nlohmann::ordered_json(0);
            }
            double int_part = 0.0;
            if (std::modf(val, &int_part) == 0.0 && std::fabs(val) < static_cast<double>(1LL << 53)) {
                return nlohmann::ordered_json(static_cast<int64_t>(val));
            }
        }
        return n;
    };
    return normalize(node);
}
} // namespace

std::string utils::encodeToBase64(const std::vector<uint8_t> &data) {
    if (data.empty()) {
        return {};
    }

    const std::size_t encoded_len = ((data.size() + 2) / 3) * 4;
    std::string encoded;
    encoded.reserve(encoded_len);

    std::size_t i = 0;
    while (i + 2 < data.size()) {
        const uint32_t triple = (static_cast<uint32_t>(data[i]) << 16) | (static_cast<uint32_t>(data[i + 1]) << 8) |
                                static_cast<uint32_t>(data[i + 2]);
        encoded.push_back(K_BASE64_ALPHABET[(triple >> 18) & 0x3F]);
        encoded.push_back(K_BASE64_ALPHABET[(triple >> 12) & 0x3F]);
        encoded.push_back(K_BASE64_ALPHABET[(triple >> 6) & 0x3F]);
        encoded.push_back(K_BASE64_ALPHABET[triple & 0x3F]);
        i += 3;
    }

    const std::size_t remaining = data.size() - i;
    if (remaining == 1) {
        const uint32_t triple = static_cast<uint32_t>(data[i]) << 16;
        encoded.push_back(K_BASE64_ALPHABET[(triple >> 18) & 0x3F]);
        encoded.push_back(K_BASE64_ALPHABET[(triple >> 12) & 0x3F]);
        encoded.push_back('=');
        encoded.push_back('=');
    } else if (remaining == 2) {
        const uint32_t triple = (static_cast<uint32_t>(data[i]) << 16) | (static_cast<uint32_t>(data[i + 1]) << 8);
        encoded.push_back(K_BASE64_ALPHABET[(triple >> 18) & 0x3F]);
        encoded.push_back(K_BASE64_ALPHABET[(triple >> 12) & 0x3F]);
        encoded.push_back(K_BASE64_ALPHABET[(triple >> 6) & 0x3F]);
        encoded.push_back('=');
    }

    return encoded;
}

std::string utils::encodeToBase64(const std::string &str) {
    std::vector<uint8_t> data(str.begin(), str.end());
    return encodeToBase64(data);
}

std::vector<uint8_t> utils::decodeBase64(const std::string &encoded) {
    if (encoded.empty()) {
        return {};
    }

    std::vector<uint8_t> decoded;
    decoded.reserve((encoded.size() / 4) * 3);

    uint8_t block[4];
    std::size_t block_len = 0;

    auto decode_block = [&](const uint8_t *b) {
        const bool pad2 = b[2] == '=';
        const bool pad3 = b[3] == '=';
        const uint32_t v0 = K_BASE64_DECODE_TABLE[b[0]];
        const uint32_t v1 = K_BASE64_DECODE_TABLE[b[1]];
        if (v0 == 0xFF || v1 == 0xFF) {
            throw std::runtime_error("Base64 decoding failed");
        }

        uint32_t v2 = 0;
        uint32_t v3 = 0;
        if (!pad2) {
            v2 = K_BASE64_DECODE_TABLE[b[2]];
            if (v2 == 0xFF) {
                throw std::runtime_error("Base64 decoding failed");
            }
        }
        if (!pad3) {
            v3 = K_BASE64_DECODE_TABLE[b[3]];
            if (v3 == 0xFF) {
                throw std::runtime_error("Base64 decoding failed");
            }
        }

        const uint32_t triple = (v0 << 18) | (v1 << 12) | (v2 << 6) | v3;
        decoded.push_back(static_cast<uint8_t>((triple >> 16) & 0xFF));
        if (!pad2) {
            decoded.push_back(static_cast<uint8_t>((triple >> 8) & 0xFF));
        }
        if (!pad3) {
            decoded.push_back(static_cast<uint8_t>(triple & 0xFF));
        }
    };

    for (unsigned char c : encoded) {
        if (isBase64Whitespace(c)) {
            continue;
        }
        block[block_len++] = c;
        if (block_len == 4) {
            decode_block(block);
            block_len = 0;
        }
    }

    if (block_len != 0) {
        throw std::runtime_error("Base64 decoding failed");
    }

    return decoded;
}

std::string utils::timePointToIso8601UtcString(std::chrono::system_clock::time_point tp) {
    const std::time_t raw = std::chrono::system_clock::to_time_t(tp);
    std::tm tm{};
#ifdef _WIN32
    gmtime_s(&tm, &raw);
#else
    gmtime_r(&raw, &tm);
#endif
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    return oss.str();
}

std::chrono::system_clock::time_point utils::iso8601UtcStringToTimePoint(const std::string &ts) {
    std::tm tm{};
    std::istringstream iss(ts);
    iss >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    if (iss.fail() || iss.peek() != std::char_traits<char>::eof()) {
        throw evi::InvalidInputError("Invalid timestamp format: '" + ts + "'");
    }
#ifdef _WIN32
    const std::time_t raw = _mkgmtime(&tm);
#else
    const std::time_t raw = timegm(&tm);
#endif
    if (raw == static_cast<std::time_t>(-1)) {
        throw evi::InvalidInputError("Failed to parse timestamp: '" + ts + "'");
    }
    return std::chrono::system_clock::from_time_t(raw);
}

std::string utils::currentIso8601UtcString() {
    return timePointToIso8601UtcString(std::chrono::system_clock::now());
}

bool utils::isEnvelopeJson(const nlohmann::json &parsed) {
    if (!parsed.is_object()) {
        return false;
    }
    const auto entries_it = parsed.find("entries");
    if (entries_it == parsed.end() || !entries_it->is_array() || entries_it->empty()) {
        return false;
    }
    const auto kid_it = parsed.find("kid");
    return kid_it != parsed.end() && kid_it->is_string();
}

std::string utils::encryptMetadata(const std::string &metadata, const std::vector<uint8_t> &key,
                                   const std::vector<uint8_t> &aad) {
    if (key.size() != static_cast<std::size_t>(evi::detail::AES256_KEY_SIZE)) {
        throw InvalidInputError("metadata key must be 32 bytes (AES-256)");
    }
    const std::vector<uint8_t> plaintext(metadata.begin(), metadata.end());

    std::vector<uint8_t> iv;
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> tag;
    if (!AES::encryptAESGCM(plaintext, key, iv, ciphertext, tag, aad)) {
        throw EncryptionError("failed to encrypt metadata with AES-256-GCM");
    }

    return nlohmann::json{
        {"iv", encodeToBase64(iv)}, {"tag", encodeToBase64(tag)}, {"encrypted_data", encodeToBase64(ciphertext)}}
        .dump();
}

std::string utils::decryptMetadata(const std::string &encrypted, const std::vector<uint8_t> &key,
                                   const std::vector<uint8_t> &aad) {
    if (key.size() != static_cast<std::size_t>(evi::detail::AES256_KEY_SIZE)) {
        throw InvalidInputError("metadata decryption key must be 32 bytes (AES-256)");
    }
    const nlohmann::json encrypted_json = nlohmann::json::parse(encrypted);
    if (!encrypted_json.is_object()) {
        throw InvalidInputError("encrypted metadata must be a JSON object");
    }
    if (!encrypted_json.contains("iv") || !encrypted_json.contains("tag") ||
        !encrypted_json.contains("encrypted_data")) {
        throw InvalidInputError("encrypted metadata must contain iv, tag, and encrypted_data");
    }

    const std::string iv_b64 = encrypted_json.at("iv").get<std::string>();
    const std::string tag_b64 = encrypted_json.at("tag").get<std::string>();
    const std::string data_b64 = encrypted_json.at("encrypted_data").get<std::string>();

    const std::vector<uint8_t> iv = decodeBase64(iv_b64);
    const std::vector<uint8_t> tag = decodeBase64(tag_b64);
    const std::vector<uint8_t> ciphertext = decodeBase64(data_b64);

    std::vector<uint8_t> plaintext;
    if (!AES::decryptAESGCM(ciphertext, key, iv, plaintext, tag, aad)) {
        throw EncryptionError("failed to decrypt metadata with AES-256-GCM");
    }
    return std::string(plaintext.begin(), plaintext.end());
}

void utils::serializeQueryTo(const Query &query, std::ostream &os) {
    serializeQueryTo(query, os, evi::BTruncMode::NONE);
}

void utils::serializeQueryTo(const Query &query, std::ostream &os, evi::BTruncMode mode) {
    serialization::writeHeader(os, serialization::kVersionV1);
    QueryType query_type = QueryType::SINGLE;
    uint8_t query_type_raw = static_cast<uint8_t>(query_type);
    os.write(reinterpret_cast<const char *>(&query_type_raw), sizeof(query_type_raw));
    if (query_type_raw != static_cast<uint8_t>(QueryType::SINGLE)) {
        throw NotSupportedError("Matrix-based Query serialization requires BUILD_WITH_HEM");
    }

    if (query.empty()) {
        throw InvalidInputError("Cannot serialize empty single-query container");
    }
    auto t = query[0]->getDataType(); // check plain or cipher
    os.write(reinterpret_cast<char *>(&t), 1);
    u32 size = query.size();
    os.write(reinterpret_cast<char *>(&size), sizeof(u32));
    const bool b_trunc = (mode == evi::BTruncMode::TRUNC);
    const auto &typed_state = query.getTypedDataState();
    if (typed_state && typed_state->preset == ParameterPreset::IP3 && t == DataType::CIPHER) {
        // u32-native (#703): pack each typed Matrix<CIPHER,u32> row straight to
        // the stream — no u32->u64 widen, no temporary SingleBlock. With
        // BTruncMode::NONE this is byte-identical to SingleBlock::serializeTo(os)
        // (V1, full width). When the caller requests TRUNC, emit a V3 row
        // truncating b to the populated item count `meta.n` (NOT meta.dim) — the
        // same b_trunc_len the non-typed SingleBlock path below uses
        // (blk->serializeTo(os, TRUNC, blk->n)). meta.dim is the matrix row dim,
        // so a dim-truncated V2 row would ship a wrong-length b-part whenever
        // dim != n. The reader (readCipherBlockRowMeta) auto-detects V1/V2/V3
        // from the header, so the IP3 V3 stream and a non-typed V3 SingleBlock
        // stream round-trip identically. The typed path holds polys in
        // Matrix<u32> with only query[0] as metadata, so it cannot use the
        // per-block SingleBlock loop below (query[i>0] would be out of range).
        // Metadata comes from query[0].
        const auto *typed = asU32Data(typed_state.get());
        const auto &meta = query[0];
        const int level = typed->getLevel();
        const u8 q_bits = typed_state->prime_q_bits;
        const u8 p_bits = typed_state->prime_p_bits;
        const BTruncMode row_mode = b_trunc ? BTruncMode::TRUNC : BTruncMode::NONE;
        if (b_trunc && meta->n > static_cast<u64>(DEGREE)) {
            throw InvalidInputError("populated count n exceeds DEGREE; cannot truncate b-part");
        }
        const std::uint32_t b_trunc_len = static_cast<std::uint32_t>(meta->n);
        for (u32 i = 0; i < size; ++i) {
            const std::size_t offset = static_cast<std::size_t>(i) * DEGREE;
            serializeCipherBlockRow<u32>(
                os, *meta, typed->getPolyData(1, 0) + offset, typed->getPolyData(0, 0) + offset,
                level ? typed->getPolyData(1, 1) + offset : nullptr,
                level ? typed->getPolyData(0, 1) + offset : nullptr, row_mode, q_bits, p_bits, b_trunc_len);
        }
        return;
    }
    for (u32 i = 0; i < size; i++) {
        if (b_trunc) {
            auto blk = std::dynamic_pointer_cast<SingleBlock<DataType::CIPHER>>(query[i]);
            if (!blk) {
                throw InvalidInputError("b-part truncation requires CIPHER SingleBlock query");
            }
            if (blk->n > static_cast<u64>(DEGREE)) {
                throw InvalidInputError("populated count n exceeds DEGREE; cannot truncate b-part");
            }
            blk->serializeTo(os, evi::BTruncMode::TRUNC, static_cast<std::uint32_t>(blk->n));
        } else {
            query[i]->serializeTo(os);
        }
    }
}

Query utils::deserializeQueryFrom(std::istream &is) {
    auto header = serialization::readHeader(is);
    if (header.has_header && header.version != serialization::kVersionV1) {
        throw NotSupportedError("Unsupported query serialization version");
    }

    uint8_t query_type_raw = 0;
    is.read(reinterpret_cast<char *>(&query_type_raw), sizeof(query_type_raw));

    if (query_type_raw != static_cast<uint8_t>(QueryType::SINGLE)) {
        throw NotSupportedError("Matrix-based Query deserialization is not supported current mode");
    }

    DataType t;
    is.read(reinterpret_cast<char *>(&t), 1);
    u32 size;
    is.read(reinterpret_cast<char *>(&size), sizeof(u32));
    Query res;
    switch (t) {
    case DataType::CIPHER:
        for (u32 i = 0; i < size; i++) {
            res.emplace_back(std::make_shared<SingleBlock<DataType::CIPHER>>(is));
        }
        break;
    case DataType::PLAIN:
        for (u32 i = 0; i < size; i++) {
            res.emplace_back(std::make_shared<SingleBlock<DataType::PLAIN>>(is));
        }
        break;
    case DataType::SERIALIZED_PLAIN:
        throw NotSupportedError("To be updated after shared-a feature done");
    default:
        throw NotSupportedError("Invalid type for query deserialization");
    }
    return res;
}

void utils::serializeResultTo(const SearchResult &res, std::ostream &os) {
    serialization::writeHeader(os, serialization::kVersionV2);
    uint8_t tag = 0;
    os.write(reinterpret_cast<const char *>(&tag), sizeof(tag));

    u32 total_count = res.getTotalItemCount();
    if (!total_count && res->ip_data != nullptr && res->ip_data->n != 0) {
        total_count = static_cast<u32>(res->ip_data->n);
    }
    os.write(reinterpret_cast<const char *>(&total_count), sizeof(total_count));

    if (res->ip_data != nullptr) {
        if (res->ip_data->isU32() && res->ip_data->preset != ParameterPreset::IP3) {
            throw InvalidInputError("u32 search results are only supported for IP3");
        }
        const uint8_t coeff_width = res->ip_data->isU32() ? sizeof(u32) : sizeof(u64);
        os.write(reinterpret_cast<const char *>(&coeff_width), sizeof(coeff_width));
        res->ip_data->serializeTo(os);
    } else {
        throw NotSupportedError("Invalid type for result serialization");
    }
}

SearchResult utils::deserializeResultFrom(std::istream &is) {
    auto header = serialization::readHeader(is);
    if (header.has_header && header.version != serialization::kVersionV1 &&
        header.version != serialization::kVersionV2) {
        throw NotSupportedError("Unsupported result serialization version");
    }

    uint8_t tag = 0;
    is.read(reinterpret_cast<char *>(&tag), sizeof(tag));

    u32 total_count = 0;
    is.read(reinterpret_cast<char *>(&total_count), sizeof(total_count));

    SearchResult res;

    if (tag == 0) {
        res = SearchResult(std::make_shared<IPSearchResult>());
        uint8_t coeff_width = sizeof(u64);
        if (header.has_header && header.version >= serialization::kVersionV2) {
            is.read(reinterpret_cast<char *>(&coeff_width), sizeof(coeff_width));
        }
        if (coeff_width == sizeof(u32)) {
            res->ip_data = std::make_shared<Matrix<DataType::CIPHER, u32>>(0);
        } else if (coeff_width == sizeof(u64)) {
            res->ip_data = std::make_shared<Matrix<DataType::CIPHER>>(0);
        } else {
            throw InvalidInputError("Unsupported result coefficient width");
        }
        res->ip_data->deserializeFrom(is);
        if (res->ip_data->isU32() && res->ip_data->preset != ParameterPreset::IP3) {
            throw InvalidInputError("u32 search results are only supported for IP3");
        }
        if (!total_count && res->ip_data != nullptr) {
            total_count = static_cast<u32>(res->ip_data->n);
        }
    } else {
        throw std::runtime_error("Unknown result type tag");
    }
    res.total_item_count = total_count;
    return res;
}

SealMode utils::stringToSealMode(const std::string &str) {
    if (str == "NONE") {
        return SealMode::NONE;
    }
    if (str == "AES-KEK") {
        return SealMode::AES_KEK;
    }
    return SealMode::NONE;
}

EvalMode utils::stringToEvalMode(const std::string &str) {
    if (str == "RMP") {
        return EvalMode::RMP;
    } else if (str == "RMS") {
        return EvalMode::RMS;
    } else if (str == "MS") {
        return EvalMode::MS;
    } else if (str == "FLAT") {
        return EvalMode::FLAT;
    } else if (str == "MM") {
        return EvalMode::MM;
    } else if (str == "MMS") {
        return EvalMode::MMS;
    } else if (str == "MM32") {
        return EvalMode::MM32;
    } else if (str == "MMS32") {
        return EvalMode::MMS32;
    } else if (str == "SINGLE") {
        return EvalMode::SINGLE;
    } else {
        throw InvalidInputError("Invalid eval mode name : " + str);
    }
}

ParameterPreset utils::stringToPreset(const std::string &str) {
    if (str == "IP0") {
        return ParameterPreset::IP0;
    } else if (str == "IP1") {
        return ParameterPreset::IP1;
    } else if (str == "IP2") {
        return ParameterPreset::IP2;
    } else if (str == "IP3") {
        return ParameterPreset::IP3;
    } else if (str == "QF0") {
        return ParameterPreset::QF0;
    } else if (str == "QF1") {
        return ParameterPreset::QF1;
    } else {
        throw InvalidInputError("Invalid preset name : " + str);
    }
}

std::string utils::assignParameterString(evi::ParameterPreset preset) {
    switch (preset) {
    case evi::ParameterPreset::IP0: {
        return "IP0";
    }
    case evi::ParameterPreset::IP1: {
        return "IP1";
    }
    case evi::ParameterPreset::IP2: {
        return "IP2";
    }
    case evi::ParameterPreset::IP3: {
        return "IP3";
    }
    case evi::ParameterPreset::QF1: {
        return "QF1";
    }
    case evi::ParameterPreset::QF0: {
        return "QF0";
    }
    default:
        return "NULL";
    }
}

std::string utils::assignEvalModeString(evi::EvalMode mode) {
    switch (mode) {
    case evi::EvalMode::RMP: {
        return "RMP";
    }
    case evi::EvalMode::RMS: {
        return "RMS";
    }
    case evi::EvalMode::MS: {
        return "MS";
    }
    case evi::EvalMode::FLAT: {
        return "FLAT";
    }
    case evi::EvalMode::MM: {
        return "MM";
    }
    case evi::EvalMode::MMS: {
        return "MMS";
    }
    case evi::EvalMode::MM32: {
        return "MM32";
    }
    case evi::EvalMode::MMS32: {
        return "MMS32";
    }
    default:
        return "NULL";
    }
}

std::string utils::assignSealModeString(evi::SealMode s_mode) {
    switch (s_mode) {
    case evi::SealMode::AES_KEK: {
        return "AES-KEK";
    }
    case evi::SealMode::NONE: {
        return "NONE";
    }
    default:
        return "NULL";
    }
}

// Serialize a string to the ostringstream
void utils::serializeString(const std::string &str, std::ostream &out) {
    uint64_t size = str.size();
    out.write(reinterpret_cast<const char *>(&size), sizeof(size)); // Write string size
    out.write(str.data(), size);                                    // Write string content
}

// Serialize the directory structure into an ostringstream
void utils::serializeEvalKey(const std::string &key_dir_path, const std::string &out_file_path) {
    std::ofstream out(out_file_path, std::ios::binary);
    serialization::writeHeader(out, serialization::kVersionV1);
    std::vector<fs::path> serialized_files;
    for (const auto &entry : fs::recursive_directory_iterator(key_dir_path)) {
        std::string relative_path = fs::relative(entry.path(), key_dir_path).string();

        if (fs::is_directory(entry.status())) {
            // Serialize directory
            char type = 'D';
            out.write(&type, sizeof(type));      // Write type 'D'
            serializeString(relative_path, out); // Write relative path
        } else if (fs::is_regular_file(entry.status())) {

            if (entry.path().filename().string().find("EncKey") != std::string::npos ||
                entry.path().filename().string().find("EvalKey") != std::string::npos ||
                entry.path().filename().string().find("SecKey") != std::string::npos) {
                continue;
            }

            // Serialize file
            char type = 'F';
            out.write(&type, sizeof(type));      // Write type 'F'
            serializeString(relative_path, out); // Write relative path

            // Read and serialize file contents
            std::ifstream in_file(entry.path(), std::ios::binary | std::ios::ate);
            if (!in_file.is_open()) {
                throw FileNotFoundError("Failed to open file: " + entry.path().string());
            }

            std::streamsize file_size = in_file.tellg();
            in_file.seekg(0, std::ios::beg);

            out.write(reinterpret_cast<const char *>(&file_size), sizeof(file_size)); // Write file size

            std::vector<char> content(file_size);
            in_file.read(content.data(), file_size);   // Read file contents
            out.write(content.data(), content.size()); // Write file contents

            in_file.close();
            serialized_files.push_back(entry.path());
        }
    }
    for (const auto &file : serialized_files) {
        fs::remove(file);
    }
    for (auto it = fs::recursive_directory_iterator(key_dir_path, fs::directory_options::skip_permission_denied),
              end = fs::recursive_directory_iterator();
         it != end;) {
        if (fs::is_directory(it->path()) && fs::is_empty(it->path())) {
            fs::remove(it->path());                              // Remove empty directory
            it = fs::recursive_directory_iterator(key_dir_path); // Restart iterator due to potential structure change
        } else {
            ++it;
        }
    }
    out.close();
}

// Deserialize a string from the istringstream
void utils::deserializeString(std::istream &in, std::string &str) {
    uint64_t size;
    in.read(reinterpret_cast<char *>(&size), sizeof(size)); // Read string size

    str.resize(size);
    in.read(&str[0], size); // Read string content
}

// Deserialize the directory structure from an istringstream
void utils::deserializeEvalKey(const std::string &key_file_path, const std::string &out_dir_path, bool delete_after) {
    const fs::path output_dir(out_dir_path);
    if (!fs::exists(output_dir)) {
        fs::create_directory(output_dir);
    }

    std::ifstream in(key_file_path, std::ios::binary);
    auto header = serialization::readHeader(in);
    if (header.has_header && header.version != serialization::kVersionV1) {
        throw NotSupportedError("Unsupported eval key serialization version");
    }
    while (in.peek() != EOF) {
        char type;
        in.read(&type, sizeof(type)); // Read type ('D' or 'F')

        std::string relative_path;
        deserializeString(in, relative_path); // Read relative path

        fs::path full_path = output_dir / relative_path;

        if (type == 'D') {
            // Create directory
            fs::create_directories(full_path);
        } else if (type == 'F') {
            // Create file
            std::streamsize file_size;
            in.read(reinterpret_cast<char *>(&file_size), sizeof(file_size)); // Read file size

            std::vector<char> content(file_size);
            in.read(content.data(), file_size); // Read file contents

            std::ofstream out_file(full_path, std::ios::binary);
            if (!out_file.is_open()) {
                throw std::runtime_error("Failed to create file: " + full_path.string());
            }

            out_file.write(content.data(), content.size()); // Write file contents
        }
    }

    in.close();
    if (delete_after) {
        fs::remove(fs::path(key_file_path));
    }
}

void utils::serializeKeyFiles(const std::string &key_dir, std::ostream &out) {
    static constexpr std::array<const char *, 3> ORDER = {"SecKey.bin", "EncKey.bin", "EvalKey.bin"};
    fs::path dir(key_dir);
    for (const auto *name : ORDER) {
        fs::path file = dir / name;
        if (!fs::exists(file)) {
            throw FileNotFoundError("Key file not found: " + file.string());
        }
        std::ifstream in(file, std::ios::binary | std::ios::ate);
        if (!in.is_open()) {
            throw FileNotFoundError("Failed to open key file: " + file.string());
        }
        std::streamsize size = in.tellg();
        in.seekg(0, std::ios::beg);
        std::vector<char> buffer(size);
        in.read(buffer.data(), size);

        uint32_t name_len = static_cast<uint32_t>(std::strlen(name));
        out.write(reinterpret_cast<const char *>(&name_len), sizeof(name_len));
        out.write(name, name_len);
        uint64_t blob_size = static_cast<uint64_t>(size);
        out.write(reinterpret_cast<const char *>(&blob_size), sizeof(blob_size));
        out.write(buffer.data(), blob_size);
    }
    uint32_t sentinel = 0;
    out.write(reinterpret_cast<const char *>(&sentinel), sizeof(sentinel));
}

void utils::deserializeKeyFiles(std::istream &in, SecretKey &sec_key, KeyPack &keypack) {
    while (true) {
        uint32_t name_len = 0;
        in.read(reinterpret_cast<char *>(&name_len), sizeof(name_len));
        if (!in) {
            throw InvalidInputError("Failed to read key file name length");
        }
        if (name_len == 0) {
            break;
        }
        std::string name(name_len, '\0');
        in.read(name.data(), name_len);
        uint64_t size = 0;
        in.read(reinterpret_cast<char *>(&size), sizeof(size));
        std::string buffer(size, '\0');
        in.read(buffer.data(), size);
        std::istringstream data_stream(buffer, std::ios::binary);
        if (name == "SecKey.bin") {
            sec_key->loadSecKey(data_stream);
        } else if (name == "EncKey.bin") {
            keypack->loadEncKeyBuffer(data_stream);
        } else if (name == "EvalKey.bin") {
            keypack->loadEvalKeyBuffer(data_stream);
        }
    }
    if (!sec_key) {
        throw InvalidInputError("Secret key blob missing in key bundle");
    }
}

std::vector<std::pair<int, int>> utils::adjustRankList(std::vector<int> &rank_list) {
    std::map<int, int> inner_ranks;
    if (!rank_list.empty()) {
        std::sort(rank_list.begin(), rank_list.end());
        std::set<int> unique_ranks;
        for (int d : rank_list) {
            if (d < evi::MIN_CONTEXT_SIZE || d > evi::MAX_CONTEXT_SIZE) {
                throw InvalidInputError("Dimension must be over than " + (std::to_string(evi::MIN_CONTEXT_SIZE >> 1)) +
                                        " and less than or equal to " + std::to_string(evi::MAX_CONTEXT_SIZE) + ".");
            }
            int power = evi::MIN_CONTEXT_SIZE;
            while (power < d) {
                power *= 2;
            }
            unique_ranks.insert(power);
        }
        rank_list.assign(unique_ranks.begin(), unique_ranks.end());
    } else {
        for (int d = evi::MIN_CONTEXT_SIZE; d <= evi::MAX_CONTEXT_SIZE; d *= 2) {
            rank_list.push_back(d);
        }
    }
    for (int i = 0; i < rank_list.size(); i++) {
        int inner_rank = getInnerRank(rank_list[i]);
        if (inner_ranks.find(inner_rank) == inner_ranks.end()) {
            inner_ranks[inner_rank] = i;
        }
    }

    return std::vector<std::pair<int, int>>(inner_ranks.begin(), inner_ranks.end());
}

} // namespace detail

void Utils::serializeEvalKey(const std::string &dir_path, const std::string &out_key_path) {
    detail::utils::serializeEvalKey(dir_path, out_key_path);
}

void Utils::deserializeEvalKey(const std::string &key_path, const std::string &output_dir, bool delete_after) {
    detail::utils::deserializeEvalKey(key_path, output_dir, delete_after);
}

void Utils::serializeKeyFiles(const std::string &dir_path, std::ostream &out) {
    detail::utils::serializeKeyFiles(dir_path, out);
}

void Utils::deserializeKeyFiles(std::istream &in, SecretKey &seckey, KeyPack &keypack) {
    auto &sec_impl = getImpl(seckey);
    if (!sec_impl) {
        throw std::runtime_error("SecretKey implementation is null");
    }
    auto &kp_impl = getImpl(keypack);
    if (!kp_impl) {
        throw std::runtime_error("KeyPack implementation is null");
    }
    detail::utils::deserializeKeyFiles(in, *sec_impl, kp_impl);
}

std::string Utils::encryptMetadata(const std::string &metadata, const std::vector<uint8_t> &key,
                                   const std::vector<uint8_t> &aad) {
    return detail::utils::encryptMetadata(metadata, key, aad);
}

std::string Utils::decryptMetadata(const std::string &encrypted, const std::vector<uint8_t> &key,
                                   const std::vector<uint8_t> &aad) {
    return detail::utils::decryptMetadata(encrypted, key, aad);
}

SealMode Utils::stringToSealMode(const std::string &s) {
    return detail::utils::stringToSealMode(s);
}

ParameterPreset Utils::stringToPreset(const std::string &s) {
    return detail::utils::stringToPreset(s);
}

EvalMode Utils::stringToEvalMode(const std::string &s) {
    return detail::utils::stringToEvalMode(s);
}

std::vector<uint8_t> Utils::generateRandomBytes(std::size_t size, const std::optional<std::vector<uint8_t>> &seed) {
    if (size == 0) {
        return {};
    }

    std::vector<uint8_t> alea_seed;
    if (seed.has_value()) {
        if (seed->size() < static_cast<std::size_t>(SEED_MIN_SIZE)) {
            throw std::invalid_argument("seed size must be at least SEED_MIN_SIZE bytes");
        }
        alea_seed = *seed;
    } else {
        alea_seed.resize(SEED_MIN_SIZE);
        std::random_device rd;
        for (std::size_t i = 0; i < alea_seed.size(); i += sizeof(uint32_t)) {
            const uint32_t val = rd();
            const std::size_t copy_size = std::min(sizeof(uint32_t), alea_seed.size() - i);
            std::memcpy(alea_seed.data() + i, &val, copy_size);
        }
    }

    std::shared_ptr<alea_state> as(alea_init(alea_seed.data(), ALEA_ALGORITHM_SHAKE256), [](alea_state *p) {
        if (p != nullptr) {
            alea_free(p);
        }
    });
    if (as == nullptr) {
        throw std::runtime_error("failed to initialize alea state");
    }

    std::vector<uint8_t> out(size, 0);
    alea_get_random_bytes(as.get(), out.data(), out.size());
    return out;
}
} // namespace evi
