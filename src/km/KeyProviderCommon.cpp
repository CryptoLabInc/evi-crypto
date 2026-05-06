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
#include <functional>
#include <iomanip>
#include <iterator>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <vector>

#include <openssl/sha.h>

using json = nlohmann::json;
using ordered_json = nlohmann::ordered_json;

namespace {

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

ProviderEntry makeEncapEntry(const std::string &name, const std::string &role, const std::vector<uint8_t> &payload) {
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
            entry.metadata.parameter = {param->getPrimeQ(), param->getPrimeP(), param->getDBScaleFactor(),
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

void writeBinaryStream(std::ostream &stream, const std::vector<uint8_t> &data) {
    if (!stream.good()) {
        throw evi::InvalidInputError("Failed to write key bytes ");
    }
    stream.write(reinterpret_cast<const char *>(data.data()), static_cast<std::streamsize>(data.size()));
    if (!stream.good()) {
        throw evi::InvalidInputError("Failed to flush key bytes");
    }
}

std::vector<uint8_t> decodeEnvelopeKeyData(std::istream &stream, const std::optional<std::string> &expected_usage) {
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

} // namespace evi::detail::provider_common
