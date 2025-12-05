#include "km/impl/KeyManagerImpl.hpp"
#include "km/KeyManagerInterface.hpp"
#include "km/KeyProviderInterface.hpp"

#include "km/KeyEnvelope.hpp"
#include "km/ProviderMeta.hpp"
#include "nlohmann/json.hpp"
#include "utils/Exceptions.hpp"
#include "utils/Utils.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <optional>
#include <sstream>
#include <utility>
#include <vector>

#include <openssl/sha.h>

namespace {

using evi::LocalProviderMeta;
using evi::ProviderEntry;
using evi::ProviderEnvelope;
using evi::ProviderMeta;
using evi::ProviderType;
using evi::detail::KeyProvider;
using evi::detail::KeyV1Requester;
using evi::detail::LocalKeyProvider;
using ordered_json = nlohmann::ordered_json;

constexpr const char *K_DEFAULT_KEY_VERSION = "1";

ordered_json canonicalizeJson(const ordered_json &node) {
    if (node.is_object()) {
        ordered_json canonical = ordered_json::object();
        std::vector<std::string> keys;
        keys.reserve(node.size());
        for (auto it = node.cbegin(); it != node.cend(); ++it) {
            keys.push_back(it.key());
        }
        std::sort(keys.begin(), keys.end());
        for (const auto &key : keys) {
            canonical[key] = canonicalizeJson(node.at(key));
        }
        return canonical;
    }
    if (node.is_array()) {
        ordered_json canonical = ordered_json::array();
        for (const auto &element : node) {
            canonical.push_back(canonicalizeJson(element));
        }
        return canonical;
    }
    return node;
}

std::string computeAadHash(const std::string &payload) {
    std::array<unsigned char, SHA256_DIGEST_LENGTH> digest{};
    if (SHA256(reinterpret_cast<const unsigned char *>(payload.data()), payload.size(), digest.data()) == nullptr) {
        throw evi::EncryptionError("Failed to compute SHA-256 digest for envelope payload");
    }
    std::vector<uint8_t> digest_bytes(digest.begin(), digest.end());
    return evi::detail::utils::encodeToBase64(digest_bytes);
}

std::string loadEnvOrDefault(const char *key, const char *fallback) {
    const char *value = std::getenv(key);
    if (value && *value != '\0') {
        return std::string(value);
    }
    return std::string(fallback);
}

KeyV1Requester makeRequester() {
    return {loadEnvOrDefault("EVI_REQUESTER_ENTITY", "user@tenantA"),
            loadEnvOrDefault("EVI_REQUESTER_TYPE", "service/automated"),
            loadEnvOrDefault("EVI_REQUESTER_METHOD", "api/system/cli")};
}

// Format given time_point to an ISO8601 string in UTC, e.g., 2025-11-17T08:21:23Z.
std::string makeIso8601(std::chrono::system_clock::time_point tp) {
    std::time_t t_c = std::chrono::system_clock::to_time_t(tp);
    std::tm tm{};
    gmtime_r(&t_c, &tm);
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    return oss.str();
}

template <typename JsonType>
// TODO : canclration check
void writeEnvelopeTo(const JsonType &envelope, const std::string &output_path) {
    std::ofstream out(output_path);
    if (!out) {
        throw evi::FileNotFoundError("Failed to open output file: " + output_path);
    }
    out << canonicalizeJson(envelope).dump();
}

std::string joinEntryNames(const std::vector<ProviderEntry> &entries) {
    std::ostringstream oss;
    for (std::size_t idx = 0; idx < entries.size(); ++idx) {
        if (idx != 0) {
            oss << ';';
        }
        oss << entries[idx].name;
    }
    return oss.str();
}

bool hasMetadata(const evi::detail::KeyEntryMetadata &metadata) {
    return metadata.parameter.P != 0 || metadata.parameter.Q != 0 || !metadata.parameter.preset.empty() ||
           !metadata.eval_mode.empty() || (metadata.dim && !metadata.dim->empty());
}

ordered_json makeMetadataJson(const evi::detail::KeyEntryMetadata &metadata) {
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

ordered_json providerEntryToJson(const ProviderEntry &entry) {
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
        node["hash"] = entry.hash;
    }
    if (hasMetadata(entry.metadata)) {
        node["metadata"] = makeMetadataJson(entry.metadata);
    }
    return node;
}

ordered_json makeSealedEnvelopeJson(const ProviderEnvelope &encap, const std::string &key_id, const std::string &usage,
                                    const KeyV1Requester &requester, const std::string &created_at,
                                    const std::string &expires_at, const std::string &integrity_context,
                                    const std::string &key_version, const bool is_secret) {
    ordered_json requester_json = {
        {"entity", requester.entity},
        {"type", requester.type},
        {"method", requester.method},
    };
    ordered_json provider_meta_json = encap.provider_meta.toJson(is_secret);
    ordered_json aad_payload = {{"format_version", 1},
                                {"kid", key_id},
                                {"usage", usage},
                                {"requester", requester_json},
                                {"created_at", created_at},
                                {"expires_at", expires_at},
                                {"provider_meta", provider_meta_json}};
    const std::string aad_context = canonicalizeJson(aad_payload).dump();

    ordered_json envelope = {{"format", joinEntryNames(encap.entries)},
                             {"format_version", 1},
                             {"key_version", key_version},
                             {"kid", key_id},
                             {"usage", usage},
                             {"requester", requester_json},
                             {"created_at", created_at},
                             {"expires_at", expires_at},
                             {"provider_meta", provider_meta_json},
                             {"aad", {{"type", "SHA256"}, {"value", computeAadHash(aad_context)}}},
                             {"integrity", {{"type", "SHA256"}, {"value", computeAadHash(integrity_context)}}}};

    ordered_json entries = ordered_json::array();
    for (const auto &entry : encap.entries) {
        entries.push_back(providerEntryToJson(entry));
    }
    envelope["entries"] = std::move(entries);

    ordered_json reason = nullptr;
    envelope["state"] = {{"value", "active"}, {"reason", reason}, {"updated_at", created_at}};

    return envelope;
}

KeyProvider makeProviderFromMeta(const ProviderMeta &provider_meta) {
    if (provider_meta.type == ProviderType::Local) {
        const LocalProviderMeta *local_meta = provider_meta.asLocal();
        if (!local_meta) {
            throw evi::InvalidInputError("Local provider metadata is missing");
        }
        return KeyProvider(std::make_shared<LocalKeyProvider>(*local_meta));
    }
    throw evi::NotSupportedError("Unsupported provider type");
}

} // namespace

namespace evi {
namespace detail {

KeyManagerV1::KeyManagerV1(KeyProvider provider) : provider_(std::move(provider)) {
    if (!provider_) {
        throw InvalidInputError("Key provider is not initialized");
    }
}

/**
 * enckey
 */
void KeyManagerV1::wrapEncKey(const std::string &key_id, std::istream &key_stream, std::ostream &out_stream) {
    if (key_id.empty()) {
        throw InvalidInputError("key_id must not be empty");
    }
    const auto now = std::chrono::system_clock::now();
    const std::string created_at = makeIso8601(now);
    const std::string expires_at = makeIso8601(now + std::chrono::hours(24 * 365 * 5));

    ProviderEnvelope provider_data = provider_->encapEncKey(key_stream);
    ordered_json json_envelope =
        makeSealedEnvelopeJson(provider_data, key_id, "vector_search", makeRequester(), created_at, expires_at,
                               key_id + ":enc:integrity", K_DEFAULT_KEY_VERSION, false);
    out_stream << canonicalizeJson(json_envelope).dump();
}

void KeyManagerV1::wrapEncKey(const std::string &key_id, const std::string key_file_path,
                              const std::string &out_file_path) {
    std::ifstream in(key_file_path, std::ios::binary);
    std::ofstream out(out_file_path);
    wrapEncKey(key_id, in, out);
    in.close();
    out.close();
}

void KeyManagerV1::wrapEncKey(const std::string &key_id, const IKeyPack &keypack, std::ostream &out_stream) {
    std::stringstream ss;
    keypack.getEncKeyBuffer(ss);
    ss.seekg(0);
    wrapEncKey(key_id, ss, out_stream);
}

void KeyManagerV1::unwrapEncKey(std::istream &in_stream, std::ostream &out_stream) {
    provider_->decapEncKey(in_stream, out_stream);
}

void KeyManagerV1::unwrapEncKey(const std::string &file_path, const std::string &out_path) {
    provider_->decapEncKey(file_path, out_path);
}

void KeyManagerV1::unwrapEncKey(std::istream &key_stream, IKeyPack &keypack) {
    std::stringstream ss;
    provider_->decapSecKey(key_stream, ss);
    ss.seekg(0);
    keypack.loadEncKeyBuffer(ss);
}

/**
 * seckey
 */
void KeyManagerV1::wrapSecKey(const std::string &key_id, const std::string key_file_path,
                              const std::string &out_file_path) {
    std::ifstream in(key_file_path, std::ios::binary);
    std::ofstream out(out_file_path, std::ios::binary);
    wrapSecKey(key_id, in, out);
    in.close();
    out.close();
}

void KeyManagerV1::wrapSecKey(const std::string &key_id, std::istream &key_stream, std::ostream &out_stream) {
    if (key_id.empty()) {
        throw InvalidInputError("key_id must not be empty");
    }
    const auto now = std::chrono::system_clock::now();
    const std::string created_at = makeIso8601(now);
    const std::string expires_at = makeIso8601(now + std::chrono::hours(24 * 365 * 5));

    ProviderEnvelope provider_data = provider_->encapSecKey(key_stream);
    ordered_json json_envelope =
        makeSealedEnvelopeJson(provider_data, key_id, "vector_search", makeRequester(), created_at, expires_at,
                               key_id + ":sec:integrity", K_DEFAULT_KEY_VERSION, /* is_seckey */ true);
    out_stream << canonicalizeJson(json_envelope).dump();
}

void KeyManagerV1::wrapSecKey(const std::string &key_id, const SecretKey &seckey, std::ostream &out_stream) {
    const auto now = std::chrono::system_clock::now();
    const std::string created_at = makeIso8601(now);
    const std::string expires_at = makeIso8601(now + std::chrono::hours(24 * 365 * 5));

    std::stringstream ss;
    seckey->saveSecKey(ss);
    ss.seekg(0);
    wrapSecKey(key_id, seckey, out_stream);
}

void KeyManagerV1::unwrapSecKey(const std::string &file_path, const std::string &out_path, const SealInfo &s_info) {
    provider_->decapSecKey(file_path, out_path);
}

void KeyManagerV1::unwrapSecKey(std::istream &in_stream, std::ostream &out_stream, const SealInfo &s_info) {
    provider_->decapSecKey(in_stream, out_stream);
}

void KeyManagerV1::unwrapSecKey(std::istream &in_stream, SecretKey &seckey, const SealInfo &s_info) {
    std::stringstream ss;
    provider_->decapSecKey(in_stream, ss);
    ss.seekg(0);
    if (s_info.s_mode == SealMode::NONE) {
        seckey->loadSecKey(ss);
    } else {
        //
    }
}

/**
 * eval key
 */
void KeyManagerV1::wrapEvalKey(const std::string &key_id, const std::string key_file_path,
                               const std::string &out_file_path) {
    std::ifstream in(key_file_path, std::ios::binary);
    std::ofstream out(out_file_path, std::ios::binary);
    wrapEvalKey(key_id, in, out);
    in.close();
    out.close();
}

void KeyManagerV1::wrapEvalKey(const std::string &key_id, std::istream &key_stream, std::ostream &out_stream) {
    if (key_id.empty()) {
        throw InvalidInputError("key_id must not be empty");
    }
    const auto now = std::chrono::system_clock::now();
    const std::string created_at = makeIso8601(now);
    const std::string expires_at = makeIso8601(now + std::chrono::hours(24 * 365 * 5));

    ProviderEnvelope provider_data = provider_->encapEvalKey(key_stream);
    ordered_json json_envelope =
        makeSealedEnvelopeJson(provider_data, key_id, "evaluation", makeRequester(), created_at, expires_at,
                               key_id + ":eval:integrity", K_DEFAULT_KEY_VERSION, false);
    out_stream << canonicalizeJson(json_envelope).dump();
}

void KeyManagerV1::unwrapEvalKey(const std::string &file_path, const std::string &out_path) {
    provider_->decapEvalKey(file_path, out_path);
}

void KeyManagerV1::unwrapEvalKey(std::istream &in_stream, std::ostream &out_stream) {
    provider_->decapEvalKey(in_stream, out_stream);
}

void KeyManagerV1::wrapKeys(const std::string &key_id, const std::string &key_path) {
    wrapEncKey(key_id, key_path + "/EncKey.bin", key_path + "/EncKey.json");
    wrapEvalKey(key_id, key_path + "/EvalKey.bin", key_path + "/EvalKey.json");
    wrapSecKey(key_id, key_path + "/SecKey.bin", key_path + "/SecKey.json");
}

void KeyManagerV1::wrapKeys(const std::string &key_id, std::istream &file_stream) {
    throw NotSupportedError("Stream-based wrapKeys is not implemented yet");
}

void KeyManagerV1::unwrapKeys(const std::string &file_dir_path, const std::string &out_dir_path) {
    fs::create_directories(out_dir_path);
    unwrapEncKey(file_dir_path + "/EncKey.json", out_dir_path + "/EncKey.bin");
    unwrapEvalKey(file_dir_path + "/EvalKey.json", out_dir_path + "/EvalKey.bin");
    unwrapSecKey(file_dir_path + "/SecKey.json", out_dir_path + "/SecKey.bin", SealInfo(SealMode::NONE));
}

void KeyManagerV1::unwrapKeys(std::istream &key_stream, std::ostream &out_stream) {
    throw NotSupportedError("Stream-based unwrapKeys is not implemented yet");
}

KeyManager makeKeyManager(const ProviderMeta &provider_meta, const KeyFormatVersion version) {
    KeyProvider provider = makeProviderFromMeta(provider_meta);
    if (version == KeyFormatVersion::V1) {
        return KeyManager(std::make_shared<KeyManagerV1>(provider));
    }
    throw NotSupportedError("Unsupported KeyManager version");
}

KeyManager makeKeyManager(const ProviderMeta &provider_meta) {
    return makeKeyManager(provider_meta, KeyFormatVersion::Latest);
}

KeyManager makeKeyManager() {
    ProviderMeta provider_meta = ProviderMeta::makeLocal(LocalProviderMeta{});
    return makeKeyManager(provider_meta);
}

} // namespace detail
} // namespace evi
