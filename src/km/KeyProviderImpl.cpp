#include "km/impl/KeyProviderImpl.hpp"

#include "EVI/impl/Parameter.hpp"
#include "EVI/impl/SecretKeyImpl.hpp"
#include "km/KeyEnvelope.hpp"
#include "nlohmann/json.hpp"
#include "utils/Exceptions.hpp"
#include "utils/SealInfo.hpp"
#include "utils/Utils.hpp"
#include "utils/crypto/AES.hpp"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iterator>
#include <limits>
#include <optional>
#include <random>
#include <sstream>
#include <type_traits>
#include <utility>
#include <vector>

#include <openssl/sha.h>

using json = nlohmann::json;

namespace {

std::vector<uint8_t> makeRandomBytes(std::size_t size) {
    std::vector<uint8_t> buffer(size);
    std::random_device rd;
    std::uniform_int_distribution<int> dist(0, 255);
    for (auto &b : buffer) {
        b = static_cast<uint8_t>(dist(rd));
    }
    return buffer;
}

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

json parseJsonFromEvalPayload(const std::vector<uint8_t> &payload) {
    if (payload.empty()) {
        throw evi::InvalidInputError("Evaluation key payload is empty");
    }

    const uint8_t *cursor = payload.data();
    const uint8_t *end = cursor + payload.size();

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

evi::ProviderEntry makeEncapEntry(const std::string &name, const std::string &role,
                                  const std::vector<uint8_t> &payload) {
    if (payload.empty()) {
        throw evi::InvalidInputError("Cannot encap empty payload for entry '" + name + "'");
    }
    evi::ProviderEntry entry;
    entry.name = name;
    entry.format_version = 1;
    entry.role = role;

    std::string preset_str = "";
    std::string eval_mode = "";
    if (!payload.empty()) {
        if (payload[0] == 'F' || payload[0] == 'D') {
            auto payload_json = parseJsonFromEvalPayload(payload);
            preset_str = payload_json.value("ParameterPreset", "");
            eval_mode = payload_json.value("EvalMode", "");

        } else if (payload[0] == '{') { // sealed secret key
            entry.alg = "AES-256-GCM";
            const std::string payload_string(reinterpret_cast<const char *>(payload.data()), payload.size());
            std::istringstream payload_stream(payload_string);
            json payload_json;
            try {
                payload_stream >> payload_json;
            } catch (const json::parse_error &err) {
                throw evi::InvalidInputError("Failed to parse sealed key metadata: " + std::string(err.what()));
            }
            preset_str = payload_json.value("ParameterPreset", "");
            std::string seal_type = payload_json.value("SealType", "");
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

        } else if (payload[0] == 0x01 || payload[0] == 0x02) {
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

void writeBinaryStream(std::ostream &stream, const std::vector<uint8_t> &data) {
    if (!stream.good()) {
        throw evi::InvalidInputError("Failed to write key bytes ");
    }
    stream.write(reinterpret_cast<const char *>(data.data()), static_cast<std::streamsize>(data.size()));
    if (!stream.good()) {
        throw evi::InvalidInputError("Failed to flush key bytes");
    }
}

std::vector<uint8_t> decodeEnvelopeKeyData(std::istream &stream) {
    json envelope;
    try {
        stream >> envelope;
    } catch (const json::parse_error &err) {
        throw evi::InvalidInputError("Failed to parse key envelope from " + std::string(err.what()));
    }
    auto entries_it = envelope.find("entries");
    if (entries_it == envelope.end() || !entries_it->is_array() || entries_it->empty()) {
        throw evi::InvalidInputError("Key envelope has no entries");
    }
    const auto &entry = entries_it->front();
    auto key_it = entry.find("key_data");
    if (key_it == entry.end()) {
        throw evi::InvalidInputError("Key entry is missing 'key_data'");
    }
    const std::string encoded_key = key_it->get<std::string>();
    return evi::detail::utils::decodeBase64(encoded_key);
}

} // namespace

namespace evi {
namespace detail {

LocalKeyProvider::LocalKeyProvider(LocalProviderMeta provider_meta) : provider_meta_(std::move(provider_meta)) {}

evi::ProviderEnvelope LocalKeyProvider::encapSecKey(const std::string &key_file_path) {
    std::ifstream in(key_file_path);
    return encapSecKey(in);
}
evi::ProviderEnvelope LocalKeyProvider::encapEncKey(const std::string &key_file_path) {
    std::ifstream in(key_file_path);
    return encapEncKey(in);
}
evi::ProviderEnvelope LocalKeyProvider::encapEvalKey(const std::string &key_file_path) {
    std::ifstream in(key_file_path);
    return encapEvalKey(in);
}

evi::ProviderEnvelope LocalKeyProvider::encapSecKey(std::istream &key_stream) {
    std::vector<uint8_t> key_blob = readBinaryStream(key_stream);
    evi::ProviderEntry entry = makeEncapEntry("seckey", "decryption key", key_blob);
    entry.key_data = evi::detail::utils::encodeToBase64(key_blob);
    entry.hash = evi::detail::utils::encodeToBase64(computeSha256(key_blob));
    evi::ProviderEnvelope envelope;
    envelope.provider_meta = provider_meta_;
    envelope.entries.push_back(std::move(entry));
    return envelope;
}
evi::ProviderEnvelope LocalKeyProvider::encapEncKey(std::istream &key_stream) {
    std::vector<uint8_t> key_blob = readBinaryStream(key_stream);
    evi::ProviderEntry entry = makeEncapEntry("enckey", "encryption key", key_blob);
    entry.key_data = evi::detail::utils::encodeToBase64(key_blob);
    entry.hash = evi::detail::utils::encodeToBase64(computeSha256(key_blob));
    evi::ProviderEnvelope envelope;
    envelope.provider_meta = provider_meta_;
    envelope.entries.push_back(std::move(entry));
    return envelope;
}
evi::ProviderEnvelope LocalKeyProvider::encapEvalKey(std::istream &key_stream) {
    std::vector<uint8_t> key_blob = readBinaryStream(key_stream);
    evi::ProviderEntry entry = makeEncapEntry("evalkey", "evaluation key", key_blob);
    entry.key_data = evi::detail::utils::encodeToBase64(key_blob);
    entry.hash = evi::detail::utils::encodeToBase64(computeSha256(key_blob));
    evi::ProviderEnvelope envelope;
    envelope.provider_meta = provider_meta_;
    envelope.entries.push_back(std::move(entry));
    return envelope;
}

void LocalKeyProvider::decapSecKey(const std::string &file_path, const std::string &out_path) {
    std::ifstream in(file_path, std::ios::binary);
    std::ofstream out(out_path, std::ios::binary);
    decapSecKey(in, out);
    in.close();
    out.close();
}
void LocalKeyProvider::decapEncKey(const std::string &file_path, const std::string &out_path) {
    std::ifstream in(file_path, std::ios::binary);
    std::ofstream out(out_path, std::ios::binary);
    decapEncKey(in, out);
    in.close();
    out.close();
}
void LocalKeyProvider::decapEvalKey(const std::string &file_path, const std::string &out_path) {
    std::ifstream in(file_path, std::ios::binary);
    std::ofstream out(out_path, std::ios::binary);
    decapEvalKey(in, out);
    in.close();
    out.close();
}

void LocalKeyProvider::decapSecKey(std::istream &key_stream, std::ostream &out_stream) {
    std::vector<uint8_t> decoded_key = decodeEnvelopeKeyData(key_stream);
    writeBinaryStream(out_stream, decoded_key);
}
void LocalKeyProvider::decapEncKey(std::istream &key_stream, std::ostream &out_stream) {
    std::vector<uint8_t> decoded_key = decodeEnvelopeKeyData(key_stream);
    writeBinaryStream(out_stream, decoded_key);
}
void LocalKeyProvider::decapEvalKey(std::istream &key_stream, std::ostream &out_stream) {
    std::vector<uint8_t> decoded_key = decodeEnvelopeKeyData(key_stream);
    writeBinaryStream(out_stream, decoded_key);
}

} // namespace detail
} // namespace evi
