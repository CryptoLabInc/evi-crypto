#include "KeyProviderCommon.hpp"

#include "EVI/impl/Parameter.hpp"
#include "nlohmann/json.hpp"
#include "utils/Exceptions.hpp"
#include "utils/Serialization.hpp"
#include "utils/Utils.hpp"
#include "utils/crypto/AES.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iterator>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

#include <openssl/evp.h>
#include <openssl/sha.h>

using json = nlohmann::json;
using ordered_json = nlohmann::ordered_json;

namespace {

constexpr char K_STREAM_BASE64_ALPHABET[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
namespace fs = std::filesystem;

struct StreamDigest {
    std::string hash_base64;
    uint64_t byte_count{0};
};

struct EnvelopeDecodeInfo {
    std::string kid;
    std::string expected_hash;
};

struct TempSpoolFile {
    fs::path path;

    explicit TempSpoolFile(const char *prefix) {
        const auto seed = std::chrono::high_resolution_clock::now().time_since_epoch().count();
        for (int i = 0; i < 100; ++i) {
            fs::path candidate =
                fs::temp_directory_path() / (std::string(prefix) + std::to_string(seed) + "-" + std::to_string(i));
            if (fs::exists(candidate)) {
                continue;
            }
            std::ofstream create(candidate, std::ios::binary | std::ios::trunc);
            if (!create) {
                continue;
            }
            path = std::move(candidate);
            return;
        }
        throw evi::InvalidInputError("Failed to create temporary key spool file");
    }

    TempSpoolFile(const TempSpoolFile &) = delete;
    TempSpoolFile &operator=(const TempSpoolFile &) = delete;

    TempSpoolFile(TempSpoolFile &&other) noexcept : path(std::move(other.path)) {
        other.path.clear();
    }

    ~TempSpoolFile() {
        if (!path.empty()) {
            std::error_code ec;
            fs::remove(path, ec);
        }
    }
};

TempSpoolFile spoolStreamToTemp(std::istream &stream, const char *prefix) {
    TempSpoolFile spool(prefix);
    std::ofstream out(spool.path, std::ios::binary | std::ios::trunc);
    if (!out) {
        throw evi::InvalidInputError("Failed to open temporary key spool file");
    }
    std::vector<char> buffer(1024 * 1024);
    while (stream) {
        stream.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        const std::streamsize count = stream.gcount();
        if (count > 0) {
            out.write(buffer.data(), count);
            if (!out) {
                throw evi::InvalidInputError("Failed to write temporary key spool file");
            }
        }
    }
    if (stream.bad()) {
        throw evi::InvalidInputError("Failed to read stream into temporary key spool file");
    }
    return spool;
}

void copyTempSpoolToStream(const TempSpoolFile &spool, std::ostream &out_stream) {
    std::ifstream in(spool.path, std::ios::binary);
    if (!in) {
        throw evi::InvalidInputError("Failed to reopen decoded key spool file");
    }
    out_stream << in.rdbuf();
    if (!in.eof() && in.fail()) {
        throw evi::InvalidInputError("Failed to read decoded key spool file");
    }
    if (!out_stream.good()) {
        throw evi::InvalidInputError("Failed to write decoded key bytes");
    }
}

json parseJsonFromEvalPayload(const std::vector<uint8_t> &payload) {
    if (payload.empty()) {
        throw evi::InvalidInputError("Evaluation key payload is empty");
    }

    const uint8_t *cursor = payload.data();
    const uint8_t *end = cursor + payload.size();
    if (payload.size() >= sizeof(evi::detail::serialization::kMagic) + sizeof(evi::detail::serialization::kVersionV1) &&
        std::memcmp(cursor, evi::detail::serialization::kMagic, sizeof(evi::detail::serialization::kMagic)) == 0) {
        cursor += sizeof(evi::detail::serialization::kMagic) + sizeof(evi::detail::serialization::kVersionV1);
    }

    auto require_bytes = [&](std::size_t count) {
        if (static_cast<std::size_t>(end - cursor) < count) {
            throw evi::InvalidInputError("Evaluation key payload is truncated");
        }
    };

    auto read_integral = [&](auto &value) {
        using T = std::decay_t<decltype(value)>;
        require_bytes(sizeof(T));
        std::memcpy(&value, cursor, sizeof(T));
        cursor += sizeof(T);
    };

    auto read_string = [&]() -> std::string {
        uint64_t size = 0;
        read_integral(size);
        require_bytes(static_cast<std::size_t>(size));
        std::string str(reinterpret_cast<const char *>(cursor), reinterpret_cast<const char *>(cursor + size));
        cursor += size;
        return str;
    };

    std::string k_metadata_file = "metadata-eval.json";
    while (cursor < end) {
        uint8_t type_byte = 0;
        read_integral(type_byte);
        std::string relative_path = read_string();

        if (type_byte == 'D') {
            continue;
        }
        if (type_byte != 'F') {
            throw evi::InvalidInputError("Evaluation key payload contains unknown entry type");
        }

        std::streamsize raw_size = 0;
        read_integral(raw_size);
        if (raw_size < 0) {
            throw evi::InvalidInputError("Evaluation key payload reports negative file size");
        }
        const auto file_size = static_cast<uint64_t>(raw_size);
        require_bytes(static_cast<std::size_t>(file_size));

        const bool is_metadata =
            relative_path == k_metadata_file || relative_path.find(k_metadata_file) != std::string::npos;
        if (is_metadata) {
            const char *json_begin = reinterpret_cast<const char *>(cursor);
            std::string json_text(json_begin, json_begin + file_size);
            return json::parse(json_text);
        }
        cursor += file_size;
    }

    throw evi::InvalidInputError("Evaluation key metadata file was not found in payload");
}

template <typename T>
void readIntegralFromStream(std::istream &stream, T &value, const char *field_name) {
    stream.read(reinterpret_cast<char *>(&value), static_cast<std::streamsize>(sizeof(T)));
    if (!stream) {
        throw evi::InvalidInputError(std::string("Evaluation key payload is truncated while reading ") + field_name);
    }
}

std::string readStringFromStream(std::istream &stream) {
    uint64_t size = 0;
    readIntegralFromStream(stream, size, "entry path size");
    std::string value(size, '\0');
    if (size > 0) {
        stream.read(value.data(), static_cast<std::streamsize>(size));
        if (!stream) {
            throw evi::InvalidInputError("Evaluation key payload is truncated while reading entry path");
        }
    }
    return value;
}

json parseJsonFromEvalPayloadStream(std::istream &stream) {
    const std::streampos start_pos = stream.tellg();
    if (start_pos == std::streampos(-1)) {
        throw evi::InvalidInputError("Evaluation key stream is not seekable");
    }

    std::array<uint8_t, sizeof(evi::detail::serialization::kMagic) + sizeof(evi::detail::serialization::kVersionV1)>
        header{};
    stream.read(reinterpret_cast<char *>(header.data()), static_cast<std::streamsize>(header.size()));
    const bool has_header =
        stream.gcount() == static_cast<std::streamsize>(header.size()) &&
        std::memcmp(header.data(), evi::detail::serialization::kMagic, sizeof(evi::detail::serialization::kMagic)) == 0;
    if (!has_header) {
        stream.clear();
        stream.seekg(start_pos);
    }

    const std::string k_metadata_file = "metadata-eval.json";
    while (true) {
        uint8_t type_byte = 0;
        stream.read(reinterpret_cast<char *>(&type_byte), sizeof(type_byte));
        if (stream.eof()) {
            break;
        }
        if (!stream) {
            throw evi::InvalidInputError("Evaluation key payload is truncated while reading entry type");
        }

        std::string relative_path = readStringFromStream(stream);
        if (type_byte == 'D') {
            continue;
        }
        if (type_byte != 'F') {
            throw evi::InvalidInputError("Evaluation key payload contains unknown entry type");
        }

        std::streamsize raw_size = 0;
        readIntegralFromStream(stream, raw_size, "file size");
        if (raw_size < 0) {
            throw evi::InvalidInputError("Evaluation key payload reports negative file size");
        }

        const bool is_metadata =
            relative_path == k_metadata_file || relative_path.find(k_metadata_file) != std::string::npos;
        if (is_metadata) {
            std::string json_text(static_cast<std::size_t>(raw_size), '\0');
            if (raw_size > 0) {
                stream.read(json_text.data(), raw_size);
                if (!stream) {
                    throw evi::InvalidInputError("Evaluation key metadata file is truncated");
                }
            }
            return json::parse(json_text);
        }

        stream.seekg(raw_size, std::ios::cur);
        if (!stream) {
            throw evi::InvalidInputError("Evaluation key payload is truncated while skipping file content");
        }
    }

    throw evi::InvalidInputError("Evaluation key metadata file was not found in payload");
}

// RFC 8785 (JCS) JSON canonicalization.
//
// Compliance coverage:
//   §3.2.2.1  Key sorting          — recursive lexicographic key sort
//   §3.2.2.2  String escaping      — nlohmann::json::dump() (shorthand for
//             \b\f\n\r\t, \uXXXX for other C0 controls, UTF-8 pass-through)
//   §3.2.2.3  Number serialization — -0 and integer-valued doubles converted
//             to int; nlohmann uses std::to_chars (C++17) for shortest
//             round-trip representation of remaining floats
//   §3.2.1    Compact form         — dump(-1) (no whitespace)
//
// Current envelope fields are ASCII strings and integers; the float and
// Unicode paths are defensive for forward compatibility.
ordered_json canonicalizeJson(const ordered_json &node) {
    std::function<ordered_json(const ordered_json &)> normalize = [&](const ordered_json &n) -> ordered_json {
        if (n.is_object()) {
            ordered_json canonical = ordered_json::object();
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
            ordered_json canonical = ordered_json::array();
            for (const auto &element : n) {
                canonical.push_back(normalize(element));
            }
            return canonical;
        }
        // RFC 8785 §3.2.2.3: normalize floating-point values.
        if (n.is_number_float()) {
            double val = n.get<double>();
            // -0 must serialize as "0" (positive zero).
            if (val == 0.0 && std::signbit(val)) {
                return ordered_json(0);
            }
            // Integer-valued doubles within the safe-integer range serialize
            // without a decimal point (prevents nlohmann from appending ".0").
            double int_part;
            if (std::modf(val, &int_part) == 0.0 && std::fabs(val) < static_cast<double>(1LL << 53)) {
                return ordered_json(static_cast<int64_t>(val));
            }
        }
        return n;
    };
    return normalize(node);
}

std::string computeAadHash(const std::string &payload) {
    std::array<unsigned char, SHA256_DIGEST_LENGTH> digest{};
    if (SHA256(reinterpret_cast<const unsigned char *>(payload.data()), payload.size(), digest.data()) == nullptr) {
        throw evi::EncryptionError("Failed to compute SHA-256 digest for envelope payload");
    }
    std::vector<uint8_t> digest_bytes(digest.begin(), digest.end());
    return evi::detail::utils::encodeToBase64(digest_bytes);
}

bool hasMetadata(const evi::KeyEntryMetadata &metadata) {
    return metadata.parameter.P != 0 || metadata.parameter.Q != 0 || !metadata.parameter.preset.empty() ||
           !metadata.eval_mode.empty() || (metadata.dim && !metadata.dim->empty());
}

ordered_json makeMetadataJson(const evi::KeyEntryMetadata &metadata) {
    ordered_json metadata_json = {{"parameter",
                                   {{"P", metadata.parameter.P},
                                    {"Q", metadata.parameter.Q},
                                    {"DB_SCALE_FACTOR", metadata.parameter.DB_SCALE_FACTOR},
                                    {"QUERY_SCALE_FACTOR", metadata.parameter.QUERY_SCALE_FACTOR},
                                    {"preset", metadata.parameter.preset}}},
                                  {"eval_mode", metadata.eval_mode}};
    if (metadata.dim && !metadata.dim->empty()) {
        metadata_json["dim"] = *metadata.dim;
    }
    return metadata_json;
}

ordered_json providerEntryToJson(const evi::ProviderEntry &entry) {
    ordered_json node = {{"name", entry.name}, {"role", entry.role}};
    if (entry.alg.has_value()) {
        node["alg"] = *entry.alg;
    }
    node["key_data"] = entry.key_data;
    if (entry.iv.has_value()) {
        node["iv"] = *entry.iv;
    }
    if (entry.tag.has_value()) {
        node["tag"] = *entry.tag;
    }
    if (!entry.hash.empty()) {
        node["hash"] = {{"type", "SHA256"}, {"value", entry.hash}};
    }
    if (hasMetadata(entry.metadata)) {
        node["metadata"] = makeMetadataJson(entry.metadata);
    }
    return node;
}

std::string loadEnvOrDefault(const char *key, const char *fallback) {
    const char *value = std::getenv(key);
    if (value && *value != '\0') {
        return std::string(value);
    }
    return std::string(fallback);
}

ordered_json makeRequesterJson() {
    return {
        {"entity", loadEnvOrDefault("EVI_REQUESTER_ENTITY", "user@tenantA")},
        {"type", loadEnvOrDefault("EVI_REQUESTER_TYPE", "service/automated")},
        {"method", loadEnvOrDefault("EVI_REQUESTER_METHOD", "api/system/cli")},
    };
}

std::string canonicalDump(const ordered_json &node) {
    return canonicalizeJson(node).dump(-1, ' ', false, ordered_json::error_handler_t::strict);
}

std::string encodeDigestToBase64(const std::array<unsigned char, SHA256_DIGEST_LENGTH> &digest) {
    return evi::detail::utils::encodeToBase64(std::vector<uint8_t>(digest.begin(), digest.end()));
}

StreamDigest computeSha256Base64FromStream(std::istream &stream) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == nullptr) {
        throw evi::EncryptionError("Failed to allocate SHA-256 context for evaluation key");
    }
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        throw evi::EncryptionError("Failed to initialize SHA-256 for evaluation key");
    }

    std::vector<char> buffer(1024 * 1024);
    uint64_t byte_count = 0;
    while (stream) {
        stream.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        const std::streamsize count = stream.gcount();
        byte_count += static_cast<uint64_t>(count);
        if (count > 0 && EVP_DigestUpdate(ctx, buffer.data(), static_cast<std::size_t>(count)) != 1) {
            EVP_MD_CTX_free(ctx);
            throw evi::EncryptionError("Failed to update SHA-256 for evaluation key");
        }
    }
    if (stream.bad()) {
        EVP_MD_CTX_free(ctx);
        throw evi::InvalidInputError("Failed to read evaluation key payload for SHA-256");
    }

    std::array<unsigned char, SHA256_DIGEST_LENGTH> digest{};
    unsigned int digest_len = 0;
    if (EVP_DigestFinal_ex(ctx, digest.data(), &digest_len) != 1 || digest_len != SHA256_DIGEST_LENGTH) {
        EVP_MD_CTX_free(ctx);
        throw evi::EncryptionError("Failed to finalize SHA-256 for evaluation key");
    }
    EVP_MD_CTX_free(ctx);
    return {encodeDigestToBase64(digest), byte_count};
}

void writeBase64FromStream(std::istream &in_stream, std::ostream &out_stream) {
    std::array<uint8_t, 3> pending{};
    std::size_t pending_size = 0;
    std::vector<uint8_t> buffer(1024 * 1024);

    auto emit_triple = [&](uint8_t a, uint8_t b, uint8_t c) {
        const uint32_t triple =
            (static_cast<uint32_t>(a) << 16) | (static_cast<uint32_t>(b) << 8) | static_cast<uint32_t>(c);
        out_stream.put(K_STREAM_BASE64_ALPHABET[(triple >> 18) & 0x3F]);
        out_stream.put(K_STREAM_BASE64_ALPHABET[(triple >> 12) & 0x3F]);
        out_stream.put(K_STREAM_BASE64_ALPHABET[(triple >> 6) & 0x3F]);
        out_stream.put(K_STREAM_BASE64_ALPHABET[triple & 0x3F]);
    };

    while (in_stream) {
        in_stream.read(reinterpret_cast<char *>(buffer.data()), static_cast<std::streamsize>(buffer.size()));
        std::size_t count = static_cast<std::size_t>(in_stream.gcount());
        std::size_t pos = 0;

        if (pending_size > 0 && count > 0) {
            while (pending_size < 3 && pos < count) {
                pending[pending_size++] = buffer[pos++];
            }
            if (pending_size == 3) {
                emit_triple(pending[0], pending[1], pending[2]);
                pending_size = 0;
            }
        }

        while (pos + 2 < count) {
            emit_triple(buffer[pos], buffer[pos + 1], buffer[pos + 2]);
            pos += 3;
        }

        pending_size = count - pos;
        for (std::size_t i = 0; i < pending_size; ++i) {
            pending[i] = buffer[pos + i];
        }
    }
    if (in_stream.bad()) {
        throw evi::InvalidInputError("Failed to read evaluation key payload for base64 encoding");
    }

    if (pending_size == 1) {
        const uint32_t triple = static_cast<uint32_t>(pending[0]) << 16;
        out_stream.put(K_STREAM_BASE64_ALPHABET[(triple >> 18) & 0x3F]);
        out_stream.put(K_STREAM_BASE64_ALPHABET[(triple >> 12) & 0x3F]);
        out_stream.put('=');
        out_stream.put('=');
    } else if (pending_size == 2) {
        const uint32_t triple = (static_cast<uint32_t>(pending[0]) << 16) | (static_cast<uint32_t>(pending[1]) << 8);
        out_stream.put(K_STREAM_BASE64_ALPHABET[(triple >> 18) & 0x3F]);
        out_stream.put(K_STREAM_BASE64_ALPHABET[(triple >> 12) & 0x3F]);
        out_stream.put(K_STREAM_BASE64_ALPHABET[(triple >> 6) & 0x3F]);
        out_stream.put('=');
    }
}

evi::KeyEntryMetadata makeEvalKeyMetadataFromPayloadJson(const json &payload_json) {
    evi::KeyEntryMetadata metadata;
    const std::string preset_str = payload_json.value("ParameterPreset", "");
    metadata.eval_mode = payload_json.value("EvalMode", "");

    try {
        auto preset = evi::detail::utils::stringToPreset(preset_str);
        auto param = evi::detail::setPreset(preset);
        metadata.parameter = {evi::detail::deb_prime_at(param.get(), 0), evi::detail::deb_prime_at(param.get(), 1),
                              param->getDBScaleFactor(), param->getQueryScaleFactor(), preset_str};
    } catch (const evi::InvalidInputError &) {
    }
    return metadata;
}

bool assignParameterMetadata(evi::KeyEntryMetadata &metadata, const std::string &preset_str) {
    try {
        auto preset = evi::detail::utils::stringToPreset(preset_str);
        auto param = evi::detail::setPreset(preset);
        metadata.parameter = {evi::detail::deb_prime_at(param.get(), 0), evi::detail::deb_prime_at(param.get(), 1),
                              param->getDBScaleFactor(), param->getQueryScaleFactor(), preset_str};
        return true;
    } catch (const evi::InvalidInputError &) {
        return false;
    }
}

evi::KeyEntryMetadata makeBinaryKeyMetadataFromStreamPrefix(std::istream &stream) {
    evi::KeyEntryMetadata metadata;
    std::array<char, 5> prefix{};
    stream.read(prefix.data(), static_cast<std::streamsize>(prefix.size()));
    const std::streamsize count = stream.gcount();
    if (count >= static_cast<std::streamsize>(prefix.size())) {
        std::string preset_str(prefix.data() + 1, prefix.data() + 5);
        preset_str.erase(std::remove(preset_str.begin(), preset_str.end(), '\0'), preset_str.end());
        assignParameterMetadata(metadata, preset_str);
    }
    if (stream.bad()) {
        throw evi::InvalidInputError("Failed to read key payload metadata prefix");
    }
    return metadata;
}

void writeSealedEnvelopeJsonWithStreamingKeyData(const std::string &key_id, std::istream &key_stream,
                                                 std::ostream &out_stream, const evi::KeyType &entry_type,
                                                 const evi::KeyEntryMetadata &metadata,
                                                 const std::string &integrity_context, const std::string &key_version) {
    const std::streampos start_pos = key_stream.tellg();
    if (start_pos == std::streampos(-1)) {
        key_stream.clear();
        throw evi::InvalidInputError("Key stream must be seekable after spooling");
    }

    auto rewind = [&]() {
        key_stream.clear();
        key_stream.seekg(start_pos);
        if (!key_stream) {
            throw evi::InvalidInputError("Failed to rewind key stream");
        }
    };

    rewind();
    const StreamDigest entry_digest = computeSha256Base64FromStream(key_stream);
    if (entry_digest.byte_count == 0) {
        throw evi::InvalidInputError("Cannot encap empty payload for entry '" + entry_type.name + "'");
    }

    const auto now = std::chrono::system_clock::now();
    const std::string created_at = evi::detail::utils::timePointToIso8601UtcString(now);
    const std::string expires_at =
        evi::detail::utils::timePointToIso8601UtcString(now + std::chrono::hours(24 * 365 * 5));
    const ordered_json requester_json = makeRequesterJson();
    const ordered_json aad_payload = {{"kid", key_id},
                                      {"usage", "vector_search"},
                                      {"requester", requester_json},
                                      {"created_at", created_at},
                                      {"expires_at", expires_at}};
    const std::string aad_context = canonicalDump(aad_payload);
    const std::string aad_hash = computeAadHash(aad_context);
    const std::string integrity_hash = computeAadHash(integrity_context);

    out_stream << "{\"aad\":" << canonicalDump({{"type", "SHA256"}, {"value", aad_hash}})
               << ",\"created_at\":" << ordered_json(created_at).dump()
               << ",\"entries\":[{\"hash\":" << canonicalDump({{"type", "SHA256"}, {"value", entry_digest.hash_base64}})
               << ",\"key_data\":\"";

    rewind();
    writeBase64FromStream(key_stream, out_stream);

    out_stream << "\"";
    if (hasMetadata(metadata)) {
        out_stream << ",\"metadata\":" << canonicalDump(makeMetadataJson(metadata));
    }
    out_stream << ",\"name\":" << ordered_json(entry_type.name).dump()
               << ",\"role\":" << ordered_json(entry_type.role).dump() << "}]"
               << ",\"expires_at\":" << ordered_json(expires_at).dump() << ",\"format_version\":1"
               << ",\"integrity\":" << canonicalDump({{"type", "SHA256"}, {"value", integrity_hash}})
               << ",\"key_version\":" << ordered_json(key_version).dump() << ",\"kid\":" << ordered_json(key_id).dump()
               << ",\"requester\":" << canonicalDump(requester_json) << ",\"state\":"
               << canonicalDump(evi::KeyState{evi::KeyLifecycleState::Active, std::nullopt, created_at}.toJson())
               << ",\"usage\":\"vector_search\"}";

    if (!out_stream.good()) {
        throw evi::InvalidInputError("Failed to write key envelope");
    }
}

std::string requireNonEmptyStringField(const ordered_json &node, const char *field_name, const char *owner_name) {
    auto it = node.find(field_name);
    if (it == node.end() || !it->is_string()) {
        throw evi::InvalidInputError(std::string(owner_name) + " is missing '" + field_name + "'");
    }
    std::string value = it->get<std::string>();
    if (value.empty()) {
        throw evi::InvalidInputError(std::string(owner_name) + " has empty '" + field_name + "'");
    }
    return value;
}

EnvelopeDecodeInfo validateEnvelopeMetadataForDecode(const ordered_json &envelope,
                                                     const std::optional<std::string> &expected_usage) {
    if (!envelope.is_object()) {
        throw evi::InvalidInputError("Key envelope must be a JSON object");
    }

    auto format_version_it = envelope.find("format_version");
    if (format_version_it == envelope.end() ||
        !(format_version_it->is_number_integer() || format_version_it->is_number_unsigned())) {
        throw evi::InvalidInputError("Key envelope is missing integer 'format_version'");
    }

    const std::string kid = requireNonEmptyStringField(envelope, "kid", "Key envelope");
    const std::string usage = requireNonEmptyStringField(envelope, "usage", "Key envelope");
    if (expected_usage.has_value() && usage != *expected_usage) {
        throw evi::AuditCodedError("USAGE_MISMATCH", "Key envelope usage mismatch: expected '" + *expected_usage +
                                                         "', got '" + usage + "'");
    }
    const std::string created_at = requireNonEmptyStringField(envelope, "created_at", "Key envelope");
    const std::string expires_at = requireNonEmptyStringField(envelope, "expires_at", "Key envelope");

    auto requester_it = envelope.find("requester");
    if (requester_it == envelope.end() || !requester_it->is_object()) {
        throw evi::InvalidInputError("Key envelope is missing 'requester' object");
    }
    auto aad_it = envelope.find("aad");
    if (aad_it == envelope.end() || !aad_it->is_object()) {
        throw evi::InvalidInputError("Key envelope is missing 'aad' object");
    }
    const std::string aad_type = requireNonEmptyStringField(*aad_it, "type", "Key envelope aad");
    if (aad_type != "SHA256") {
        throw evi::InvalidInputError("Key envelope aad type is not supported: '" + aad_type + "'");
    }
    const std::string aad_value = requireNonEmptyStringField(*aad_it, "value", "Key envelope aad");

    auto state_it = envelope.find("state");
    if (state_it == envelope.end()) {
        throw evi::InvalidInputError("Key envelope is missing 'state' object");
    }
    const evi::KeyState state = evi::KeyState::fromJson(*state_it, "Key envelope");
    if (state.value != evi::KeyLifecycleState::Active) {
        throw evi::AuditCodedError("KEY_NOT_ACTIVE", "Key '" + kid + "' is in state '" + evi::toString(state.value) +
                                                         "'; unwrap is not allowed");
    }

    const auto now = std::chrono::system_clock::now();
    const auto expires_tp = evi::detail::utils::iso8601UtcStringToTimePoint(expires_at);
    if (now > expires_tp) {
        throw evi::AuditCodedError("KEY_EXPIRED", "Key envelope state is 'expired' (expires_at='" + expires_at + "')");
    }

    ordered_json aad_payload = {{"kid", kid},
                                {"usage", usage},
                                {"requester", *requester_it},
                                {"created_at", created_at},
                                {"expires_at", expires_at}};
    const std::string aad_context = canonicalDump(aad_payload);
    const std::string computed_aad_hash = computeAadHash(aad_context);
    if (computed_aad_hash != aad_value) {
        throw evi::AuditCodedError("AAD_VERIFICATION_FAILED", "Key envelope aad verification failed");
    }

    auto entries_it = envelope.find("entries");
    if (entries_it == envelope.end() || !entries_it->is_array() || entries_it->empty()) {
        throw evi::InvalidInputError("Key envelope is missing non-empty 'entries' array");
    }
    const auto &entry = entries_it->front();
    if (!entry.is_object()) {
        throw evi::InvalidInputError("Key envelope entries[0] must be an object");
    }
    auto hash_it = entry.find("hash");
    if (hash_it == entry.end() || !hash_it->is_object()) {
        throw evi::InvalidInputError("Key entry is missing 'hash' object");
    }
    const std::string hash_type = requireNonEmptyStringField(*hash_it, "type", "Key entry hash");
    if (hash_type != "SHA256") {
        throw evi::InvalidInputError("Key entry hash type is not supported: '" + hash_type + "'");
    }
    return {kid, requireNonEmptyStringField(*hash_it, "value", "Key entry hash")};
}

bool findKeyDataValueStart(std::istream &stream, std::string *prefix_copy) {
    char ch = '\0';
    while (stream.get(ch)) {
        if (prefix_copy != nullptr) {
            prefix_copy->push_back(ch);
        }
        if (ch != '"') {
            continue;
        }

        std::string token;
        bool escaped = false;
        bool closed = false;
        while (stream.get(ch)) {
            if (prefix_copy != nullptr) {
                prefix_copy->push_back(ch);
            }
            if (escaped) {
                token.push_back(ch);
                escaped = false;
                continue;
            }
            if (ch == '\\') {
                escaped = true;
                continue;
            }
            if (ch == '"') {
                closed = true;
                break;
            }
            token.push_back(ch);
        }
        if (!closed) {
            throw evi::InvalidInputError("Key envelope has unterminated JSON string");
        }

        if (token != "key_data") {
            continue;
        }

        while (stream.get(ch)) {
            if (prefix_copy != nullptr) {
                prefix_copy->push_back(ch);
            }
            if (!std::isspace(static_cast<unsigned char>(ch))) {
                break;
            }
        }
        if (!stream) {
            throw evi::InvalidInputError("Key entry is missing 'key_data' value");
        }
        if (ch != ':') {
            continue;
        }

        while (stream.get(ch)) {
            if (prefix_copy != nullptr) {
                prefix_copy->push_back(ch);
            }
            if (!std::isspace(static_cast<unsigned char>(ch))) {
                break;
            }
        }
        if (!stream) {
            throw evi::InvalidInputError("Key entry is missing 'key_data' value");
        }
        if (ch != '"') {
            throw evi::InvalidInputError("Key entry 'key_data' must be a string");
        }
        return true;
    }
    if (stream.bad()) {
        throw evi::InvalidInputError("Failed to read key envelope while searching key_data");
    }
    return false;
}

bool copyEnvelopeWithEmptyKeyData(std::istream &stream, std::string &sanitized_envelope) {
    if (!findKeyDataValueStart(stream, &sanitized_envelope)) {
        return false;
    }

    char ch = '\0';
    bool escaped = false;
    while (stream.get(ch)) {
        if (escaped) {
            escaped = false;
            continue;
        }
        if (ch == '\\') {
            escaped = true;
            continue;
        }
        if (ch == '"') {
            sanitized_envelope.push_back(ch);
            break;
        }
    }
    if (!stream) {
        throw evi::InvalidInputError("Key envelope has unterminated 'key_data'");
    }

    sanitized_envelope.append(std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>());
    if (stream.bad()) {
        throw evi::InvalidInputError("Failed to read key envelope after key_data");
    }
    return true;
}

int base64Value(char ch) {
    if (ch >= 'A' && ch <= 'Z') {
        return ch - 'A';
    }
    if (ch >= 'a' && ch <= 'z') {
        return ch - 'a' + 26;
    }
    if (ch >= '0' && ch <= '9') {
        return ch - '0' + 52;
    }
    if (ch == '+') {
        return 62;
    }
    if (ch == '/') {
        return 63;
    }
    if (ch == '=') {
        return -2;
    }
    return -1;
}

void decodeBase64Quad(const std::array<char, 4> &quad, EVP_MD_CTX *ctx, std::ostream &out_stream,
                      uint64_t &decoded_count) {
    const int v0 = base64Value(quad[0]);
    const int v1 = base64Value(quad[1]);
    const int v2 = base64Value(quad[2]);
    const int v3 = base64Value(quad[3]);
    if (v0 < 0 || v1 < 0 || v2 == -1 || v3 == -1 || v0 == -2 || v1 == -2) {
        throw evi::InvalidInputError("Key entry has invalid base64 'key_data'");
    }
    if (v2 == -2 && v3 != -2) {
        throw evi::InvalidInputError("Key entry has invalid base64 padding");
    }

    const uint8_t b0 = static_cast<uint8_t>((v0 << 2) | (v1 >> 4));
    out_stream.put(static_cast<char>(b0));
    if (EVP_DigestUpdate(ctx, &b0, 1) != 1) {
        throw evi::EncryptionError("Failed to update SHA-256 while decoding key_data");
    }
    ++decoded_count;

    if (v2 != -2) {
        const uint8_t b1 = static_cast<uint8_t>(((v1 & 0x0F) << 4) | (v2 >> 2));
        out_stream.put(static_cast<char>(b1));
        if (EVP_DigestUpdate(ctx, &b1, 1) != 1) {
            throw evi::EncryptionError("Failed to update SHA-256 while decoding key_data");
        }
        ++decoded_count;
    }
    if (v3 != -2) {
        const uint8_t b2 = static_cast<uint8_t>(((v2 & 0x03) << 6) | v3);
        out_stream.put(static_cast<char>(b2));
        if (EVP_DigestUpdate(ctx, &b2, 1) != 1) {
            throw evi::EncryptionError("Failed to update SHA-256 while decoding key_data");
        }
        ++decoded_count;
    }
}

std::string decodeKeyDataStreaming(std::istream &stream, std::ostream &out_stream) {
    if (!findKeyDataValueStart(stream, nullptr)) {
        throw evi::InvalidInputError("Key entry is missing 'key_data'");
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == nullptr) {
        throw evi::EncryptionError("Failed to allocate SHA-256 context for key_data");
    }
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        throw evi::EncryptionError("Failed to initialize SHA-256 for key_data");
    }

    std::array<char, 4> quad{};
    std::size_t quad_size = 0;
    uint64_t decoded_count = 0;
    bool closed = false;
    char ch = '\0';
    while (stream.get(ch)) {
        if (ch == '"') {
            closed = true;
            break;
        }
        if (ch == '\\') {
            EVP_MD_CTX_free(ctx);
            throw evi::InvalidInputError("Key entry has escaped data inside base64 'key_data'");
        }
        quad[quad_size++] = ch;
        if (quad_size == quad.size()) {
            decodeBase64Quad(quad, ctx, out_stream, decoded_count);
            quad_size = 0;
        }
    }
    if (!closed) {
        EVP_MD_CTX_free(ctx);
        throw evi::InvalidInputError("Key envelope has unterminated 'key_data'");
    }
    if (quad_size != 0) {
        EVP_MD_CTX_free(ctx);
        throw evi::InvalidInputError("Key entry has invalid base64 length");
    }
    if (decoded_count == 0) {
        EVP_MD_CTX_free(ctx);
        throw evi::InvalidInputError("Key entry has empty 'key_data'");
    }

    std::array<unsigned char, SHA256_DIGEST_LENGTH> digest{};
    unsigned int digest_len = 0;
    if (EVP_DigestFinal_ex(ctx, digest.data(), &digest_len) != 1 || digest_len != SHA256_DIGEST_LENGTH) {
        EVP_MD_CTX_free(ctx);
        throw evi::EncryptionError("Failed to finalize SHA-256 for key_data");
    }
    EVP_MD_CTX_free(ctx);
    if (!out_stream.good()) {
        throw evi::InvalidInputError("Failed to write decoded key bytes");
    }
    return encodeDigestToBase64(digest);
}

} // namespace

namespace evi::detail::provider_common {

std::vector<uint8_t> readBinaryStream(std::istream &stream) {
    std::vector<uint8_t> buffer((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());
    return buffer;
}

std::vector<uint8_t> computeSha256(const std::vector<uint8_t> &data) {
    std::array<unsigned char, SHA256_DIGEST_LENGTH> digest{};
    if (SHA256(data.data(), data.size(), digest.data()) == nullptr) {
        throw evi::EncryptionError("Failed to compute SHA-256 digest for encryption key");
    }
    return std::vector<uint8_t>(digest.begin(), digest.end());
}

ProviderEntry makeProviderEntryFromPayload(const std::string &name, const std::string &role,
                                           const std::vector<uint8_t> &payload) {
    if (payload.empty()) {
        throw evi::InvalidInputError("Cannot encap empty payload for entry '" + name + "'");
    }
    ProviderEntry entry;
    entry.name = name;
    entry.format_version = 1;
    entry.role = role;

    std::string preset_str = "";
    std::string eval_mode = "";
    if (!payload.empty()) {
        if (name == evi::KeyType::EvalKey.name) {
            auto payload_json = parseJsonFromEvalPayload(payload);
            preset_str = payload_json.value("ParameterPreset", "");
            eval_mode = payload_json.value("EvalMode", "");

        } else if (name == evi::KeyType::SecKeySealed.name || name == evi::KeyType::MetadataKeySealed.name) {
            entry.alg = "AES-256-GCM";
            const std::string payload_string(reinterpret_cast<const char *>(payload.data()), payload.size());
            std::istringstream payload_stream(payload_string);
            nlohmann::json payload_json;
            try {
                payload_stream >> payload_json;
            } catch (const nlohmann::json::parse_error &err) {
                throw evi::InvalidInputError("Failed to parse sealed key metadata: " + std::string(err.what()));
            }

            preset_str = payload_json.value("ParameterPreset", "");
            const std::string seal_type = payload_json.value("SealType", "");
            if (!seal_type.empty()) {
                entry.alg = seal_type;
            }

            payload_stream.ignore(4);
            std::vector<uint8_t> iv_buf(evi::detail::AES256_IV_SIZE);
            std::vector<uint8_t> tag_buf(evi::detail::AES256_TAG_SIZE);
            payload_stream.read(reinterpret_cast<char *>(iv_buf.data()), iv_buf.size());
            payload_stream.read(reinterpret_cast<char *>(tag_buf.data()), tag_buf.size());
            entry.iv = evi::detail::utils::encodeToBase64(iv_buf);
            entry.tag = evi::detail::utils::encodeToBase64(tag_buf);
        } else if (name == evi::KeyType::EncKey.name || name == evi::KeyType::SecKey.name) {
            preset_str = std::string(payload.begin() + 1, payload.begin() + 5);
            preset_str.erase(std::remove(preset_str.begin(), preset_str.end(), '\0'), preset_str.end());
        }
    }

    auto assign_parameter = [&](const std::string &candidate) -> bool {
        try {
            auto preset = evi::detail::utils::stringToPreset(candidate);
            auto param = evi::detail::setPreset(preset);
            entry.metadata.parameter = {param->getQ(0), deb_prime_at(param, 1), param->getDBScaleFactor(),
                                        param->getQueryScaleFactor(), candidate};
            return true;
        } catch (const evi::InvalidInputError &) {
            return false;
        }
    };

    assign_parameter(preset_str);
    entry.metadata.eval_mode = eval_mode;

    std::vector<uint8_t> digest = computeSha256(payload);
    entry.hash = evi::detail::utils::encodeToBase64(digest);
    entry.key_data = evi::detail::utils::encodeToBase64(payload);
    return entry;
}

nlohmann::ordered_json makeSealedEnvelopeJson(const ProviderEnvelope &encap, const std::string &key_id,
                                              const std::string &usage, const std::string &integrity_context,
                                              bool is_secret, const std::string &key_version) {
    const auto now = std::chrono::system_clock::now();
    const std::string created_at = evi::detail::utils::timePointToIso8601UtcString(now);
    const std::string expires_at =
        evi::detail::utils::timePointToIso8601UtcString(now + std::chrono::hours(24 * 365 * 5));

    ordered_json requester_json = makeRequesterJson();
    ordered_json aad_payload = {{"kid", key_id},
                                {"usage", usage},
                                {"requester", requester_json},
                                {"created_at", created_at},
                                {"expires_at", expires_at}};
    const std::string aad_context =
        canonicalizeJson(aad_payload).dump(-1, ' ', false, ordered_json::error_handler_t::strict);

    ordered_json envelope = {{"format_version", 1},
                             {"key_version", key_version},
                             {"kid", key_id},
                             {"usage", usage},
                             {"requester", requester_json},
                             {"created_at", created_at},
                             {"expires_at", expires_at},
                             {"aad", {{"type", "SHA256"}, {"value", computeAadHash(aad_context)}}},
                             {"integrity", {{"type", "SHA256"}, {"value", computeAadHash(integrity_context)}}}};

    ordered_json entries = ordered_json::array();
    for (const auto &entry : encap.entries) {
        entries.push_back(providerEntryToJson(entry));
    }
    envelope["entries"] = std::move(entries);

    envelope["state"] = evi::KeyState{evi::KeyLifecycleState::Active, std::nullopt, created_at}.toJson();
    return canonicalizeJson(envelope);
}

void writeEncKeyEnvelopeJsonFromStream(const std::string &key_id, std::istream &key_stream, std::ostream &out_stream,
                                       const std::string &key_version) {
    const std::streampos start_pos = key_stream.tellg();
    if (start_pos == std::streampos(-1)) {
        key_stream.clear();
        // Spool a non-seekable stream to a seekable temporary file, then reuse the same wrapping logic.
        TempSpoolFile spool = spoolStreamToTemp(key_stream, "evi-enckey-wrap-");
        std::ifstream spooled_in(spool.path, std::ios::binary);
        if (!spooled_in) {
            throw evi::InvalidInputError("Failed to reopen temporary encryption key spool file");
        }
        writeEncKeyEnvelopeJsonFromStream(key_id, spooled_in, out_stream, key_version);
        return;
    }
    const evi::KeyEntryMetadata metadata = makeBinaryKeyMetadataFromStreamPrefix(key_stream);
    key_stream.clear();
    key_stream.seekg(start_pos);
    if (!key_stream) {
        throw evi::InvalidInputError("Failed to rewind encryption key stream");
    }
    writeSealedEnvelopeJsonWithStreamingKeyData(key_id, key_stream, out_stream, evi::KeyType::EncKey, metadata,
                                                key_id + ":enc:integrity", key_version);
}

void writeEvalKeyEnvelopeJsonFromStream(const std::string &key_id, std::istream &key_stream, std::ostream &out_stream,
                                        const std::string &key_version) {
    const std::streampos start_pos = key_stream.tellg();
    if (start_pos == std::streampos(-1)) {
        key_stream.clear();
        // Spool a non-seekable stream to a seekable temporary file, then reuse the same wrapping logic.
        TempSpoolFile spool = spoolStreamToTemp(key_stream, "evi-evalkey-wrap-");
        std::ifstream spooled_in(spool.path, std::ios::binary);
        if (!spooled_in) {
            throw evi::InvalidInputError("Failed to reopen temporary evaluation key spool file");
        }
        writeEvalKeyEnvelopeJsonFromStream(key_id, spooled_in, out_stream, key_version);
        return;
    }
    const json payload_json = parseJsonFromEvalPayloadStream(key_stream);
    const evi::KeyEntryMetadata metadata = makeEvalKeyMetadataFromPayloadJson(payload_json);
    key_stream.clear();
    key_stream.seekg(start_pos);
    if (!key_stream) {
        throw evi::InvalidInputError("Failed to rewind evaluation key stream");
    }
    writeSealedEnvelopeJsonWithStreamingKeyData(key_id, key_stream, out_stream, evi::KeyType::EvalKey, metadata,
                                                key_id + ":eval:integrity", key_version);
}

void writeBinaryStream(std::ostream &stream, const std::vector<uint8_t> &data) {
    if (!stream.good()) {
        throw evi::InvalidInputError("Failed to write key bytes ");
    }
    stream.write(reinterpret_cast<const char *>(data.data()), static_cast<std::streamsize>(data.size()));
    if (!stream.good()) {
        throw evi::InvalidInputError("Failed to flush key bytes");
    }
}

std::vector<uint8_t> decodeEnvelopeKeyDataToVector(std::istream &stream,
                                                   const std::optional<std::string> &expected_usage) {
    ordered_json envelope;
    try {
        stream >> envelope;
    } catch (const json::parse_error &err) {
        throw evi::InvalidInputError("Failed to parse key envelope from " + std::string(err.what()));
    }

    if (!envelope.is_object()) {
        throw evi::InvalidInputError("Key envelope must be a JSON object");
    }

    auto format_version_it = envelope.find("format_version");
    if (format_version_it == envelope.end() ||
        !(format_version_it->is_number_integer() || format_version_it->is_number_unsigned())) {
        throw evi::InvalidInputError("Key envelope is missing integer 'format_version'");
    }
    // read each field
    const std::string kid = requireNonEmptyStringField(envelope, "kid", "Key envelope");
    const std::string usage = requireNonEmptyStringField(envelope, "usage", "Key envelope");
    if (expected_usage.has_value() && usage != *expected_usage) {
        throw evi::AuditCodedError("USAGE_MISMATCH", "Key envelope usage mismatch: expected '" + *expected_usage +
                                                         "', got '" + usage + "'");
    }
    const std::string created_at = requireNonEmptyStringField(envelope, "created_at", "Key envelope");
    const std::string expires_at = requireNonEmptyStringField(envelope, "expires_at", "Key envelope");
    auto requester_it = envelope.find("requester");
    if (requester_it == envelope.end() || !requester_it->is_object()) {
        throw evi::InvalidInputError("Key envelope is missing 'requester' object");
    }
    auto aad_it = envelope.find("aad");
    if (aad_it == envelope.end() || !aad_it->is_object()) {
        throw evi::InvalidInputError("Key envelope is missing 'aad' object");
    }
    const std::string aad_type = requireNonEmptyStringField(*aad_it, "type", "Key envelope aad");
    if (aad_type != "SHA256") {
        throw evi::InvalidInputError("Key envelope aad type is not supported: '" + aad_type + "'");
    }
    const std::string aad_value = requireNonEmptyStringField(*aad_it, "value", "Key envelope aad");

    // check key envelope state
    auto state_it = envelope.find("state");
    if (state_it == envelope.end()) {
        throw evi::InvalidInputError("Key envelope is missing 'state' object");
    }
    const evi::KeyState state = evi::KeyState::fromJson(*state_it, "Key envelope");
    if (state.value != evi::KeyLifecycleState::Active) {
        throw evi::AuditCodedError("KEY_NOT_ACTIVE", "Key '" + kid + "' is in state '" + evi::toString(state.value) +
                                                         "'; unwrap is not allowed");
    }

    // check key envelope expiration
    const auto now = std::chrono::system_clock::now();
    const auto expires_tp = evi::detail::utils::iso8601UtcStringToTimePoint(expires_at);
    if (now > expires_tp) {
        throw evi::AuditCodedError("KEY_EXPIRED", "Key envelope state is 'expired' (expires_at='" + expires_at + "')");
    }

    // check key metadata integrity using aad
    ordered_json aad_payload = {{"kid", kid},
                                {"usage", usage},
                                {"requester", *requester_it},
                                {"created_at", created_at},
                                {"expires_at", expires_at}};
    const std::string aad_context =
        canonicalizeJson(aad_payload).dump(-1, ' ', false, ordered_json::error_handler_t::strict);
    const std::string computed_aad_hash = computeAadHash(aad_context);
    if (computed_aad_hash != aad_value) {
        throw evi::AuditCodedError("AAD_VERIFICATION_FAILED", "Key envelope aad verification failed");
    }

    // decode key data
    auto entries_it = envelope.find("entries");
    if (entries_it == envelope.end() || !entries_it->is_array() || entries_it->empty()) {
        throw evi::InvalidInputError("Key envelope is missing non-empty 'entries' array");
    }
    const auto &entry = entries_it->front();
    if (!entry.is_object()) {
        throw evi::InvalidInputError("Key envelope entries[0] must be an object");
    }
    auto key_it = entry.find("key_data");
    if (key_it == entry.end() || !key_it->is_string()) {
        throw evi::InvalidInputError("Key entry is missing 'key_data'");
    }
    const std::string encoded_key = key_it->get<std::string>();
    if (encoded_key.empty()) {
        throw evi::InvalidInputError("Key entry has empty 'key_data'");
    }

    std::vector<uint8_t> decoded_key;
    try {
        decoded_key = evi::detail::utils::decodeBase64(encoded_key);
    } catch (const std::runtime_error &) {
        throw evi::InvalidInputError("Key entry has invalid base64 'key_data'");
    }

    // check key data integrity using entry hash
    auto hash_it = entry.find("hash");
    if (hash_it == entry.end() || !hash_it->is_object()) {
        throw evi::InvalidInputError("Key entry is missing 'hash' object");
    }
    const std::string hash_type = requireNonEmptyStringField(*hash_it, "type", "Key entry hash");
    if (hash_type != "SHA256") {
        throw evi::InvalidInputError("Key entry hash type is not supported: '" + hash_type + "'");
    }
    const std::string expected_hash = requireNonEmptyStringField(*hash_it, "value", "Key entry hash");
    const std::string computed_hash = evi::detail::utils::encodeToBase64(computeSha256(decoded_key));
    if (computed_hash != expected_hash) {
        throw evi::AuditCodedError("INTEGRITY_CHECK_FAILED", "Key entry hash verification failed");
    }

    return decoded_key;
}

static bool decodeEnvelopeKeyDataToStreamSeekable(std::istream &stream, std::ostream &out_stream,
                                                  const std::optional<std::string> &expected_usage,
                                                  std::string *key_id) {
    const std::streampos start_pos = stream.tellg();
    if (start_pos == std::streampos(-1)) {
        stream.clear();
        return false;
    }

    auto rewind = [&]() {
        stream.clear();
        stream.seekg(start_pos);
        if (!stream) {
            throw evi::InvalidInputError("Failed to rewind key envelope stream");
        }
    };

    rewind();
    std::string sanitized_envelope;
    sanitized_envelope.reserve(4096);
    if (!copyEnvelopeWithEmptyKeyData(stream, sanitized_envelope)) {
        rewind();
        return false;
    }

    ordered_json envelope;
    try {
        envelope = ordered_json::parse(sanitized_envelope);
    } catch (const json::parse_error &err) {
        throw evi::InvalidInputError("Failed to parse key envelope from " + std::string(err.what()));
    }

    const EnvelopeDecodeInfo info = validateEnvelopeMetadataForDecode(envelope, expected_usage);
    if (key_id != nullptr) {
        *key_id = info.kid;
    }

    rewind();
    TempSpoolFile decoded_spool("evi-envelope-decoded-");
    {
        std::ofstream decoded_out(decoded_spool.path, std::ios::binary | std::ios::trunc);
        if (!decoded_out) {
            throw evi::InvalidInputError("Failed to open decoded key spool file");
        }
        const std::string computed_hash = decodeKeyDataStreaming(stream, decoded_out);
        decoded_out.close();
        if (!decoded_out) {
            throw evi::InvalidInputError("Failed to write decoded key spool file");
        }
        if (computed_hash != info.expected_hash) {
            throw evi::AuditCodedError("INTEGRITY_CHECK_FAILED", "Key entry hash verification failed");
        }
    }
    copyTempSpoolToStream(decoded_spool, out_stream);
    return true;
}

void decodeEnvelopeKeyDataToStream(std::istream &stream, std::ostream &out_stream,
                                   const std::optional<std::string> &expected_usage, std::string *key_id) {
    const std::streampos start_pos = stream.tellg();
    if (start_pos == std::streampos(-1)) {
        stream.clear();
        TempSpoolFile spool = spoolStreamToTemp(stream, "evi-envelope-unwrap-");
        std::ifstream spooled_in(spool.path, std::ios::binary);
        if (!spooled_in) {
            throw evi::InvalidInputError("Failed to reopen temporary envelope spool file");
        }
        if (!decodeEnvelopeKeyDataToStreamSeekable(spooled_in, out_stream, expected_usage, key_id)) {
            throw evi::InvalidInputError("Key entry is missing 'key_data'");
        }
        return;
    }

    if (!decodeEnvelopeKeyDataToStreamSeekable(stream, out_stream, expected_usage, key_id)) {
        throw evi::InvalidInputError("Key entry is missing 'key_data'");
    }
}

} // namespace evi::detail::provider_common
