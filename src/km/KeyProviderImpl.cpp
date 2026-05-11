#include "km/impl/KeyProviderImpl.hpp"

#include "KeyProviderCommon.hpp"
#include "utils/Exceptions.hpp"
#include "utils/SealInfo.hpp"
#include "utils/Serialization.hpp"
#include "utils/Utils.hpp"
#include "utils/crypto/AES.hpp"
#include "utils/security/Security.hpp"

#include <cstdint>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <utility>
#include <vector>

namespace evi {
namespace detail {

nlohmann::ordered_json KeyProvider::encapEncKey(const std::string &key_id, const std::string &key_file_path) {
    std::ifstream in(key_file_path, std::ios::binary);
    return encapEncKey(key_id, in);
}
nlohmann::ordered_json KeyProvider::encapEvalKey(const std::string &key_id, const std::string &key_file_path) {
    std::ifstream in(key_file_path, std::ios::binary);
    return encapEvalKey(key_id, in);
}
nlohmann::ordered_json KeyProvider::encapSecKey(const std::string &key_id, std::istream &key_stream,
                                                const SealInfo &s_info) {
    std::vector<uint8_t> key_blob = evi::detail::provider_common::readBinaryStream(key_stream);
    evi::security::SensitiveDataGuard guard(key_blob);
    const auto &entry_type = s_info.s_mode == SealMode::AES_KEK ? evi::KeyType::SecKeySealed : evi::KeyType::SecKey;
    evi::ProviderEntry entry =
        evi::detail::provider_common::makeProviderEntryFromPayload(entry_type.name, entry_type.role, key_blob);
    evi::ProviderEnvelope envelope;
    envelope.entries.push_back(std::move(entry));
    return evi::detail::provider_common::makeSealedEnvelopeJson(envelope, key_id, "vector_search",
                                                                key_id + ":sec:integrity", true);
}
nlohmann::ordered_json KeyProvider::encapEncKey(const std::string &key_id, std::istream &key_stream) {
    std::vector<uint8_t> key_blob = evi::detail::provider_common::readBinaryStream(key_stream);
    const auto &entry_type = evi::KeyType::EncKey;
    evi::ProviderEntry entry =
        evi::detail::provider_common::makeProviderEntryFromPayload(entry_type.name, entry_type.role, key_blob);
    evi::ProviderEnvelope envelope;
    envelope.entries.push_back(std::move(entry));
    return evi::detail::provider_common::makeSealedEnvelopeJson(envelope, key_id, "vector_search",
                                                                key_id + ":enc:integrity", false);
}
nlohmann::ordered_json KeyProvider::encapEvalKey(const std::string &key_id, std::istream &key_stream) {
    std::vector<uint8_t> key_blob = evi::detail::provider_common::readBinaryStream(key_stream);
    const auto &entry_type = evi::KeyType::EvalKey;
    evi::ProviderEntry entry =
        evi::detail::provider_common::makeProviderEntryFromPayload(entry_type.name, entry_type.role, key_blob);
    evi::ProviderEnvelope envelope;
    envelope.entries.push_back(std::move(entry));
    return evi::detail::provider_common::makeSealedEnvelopeJson(envelope, key_id, "vector_search",
                                                                key_id + ":eval:integrity", false);
}

nlohmann::ordered_json KeyProvider::encapMetadataKey(const std::string &key_id, std::istream &key_stream,
                                                     const SealInfo &s_info) {
    const SealMode mode = s_info.s_mode;
    if (mode != SealMode::NONE && mode != SealMode::AES_KEK) {
        throw evi::NotSupportedError("SealMode::" + evi::detail::utils::assignSealModeString(mode) +
                                     " is not yet supported for metadata key wrap");
    }

    std::vector<uint8_t> key_blob = evi::detail::provider_common::readBinaryStream(key_stream);
    evi::security::SensitiveDataGuard guard(key_blob);
    std::optional<std::vector<uint8_t>> iv;
    std::optional<std::vector<uint8_t>> tag;
    if (mode == SealMode::AES_KEK) {
        if (s_info.kek.size() != evi::AES256_KEY_SIZE) {
            throw evi::InvalidInputError("metadata key AES-KEK requires 32-byte kek");
        }

        std::vector<uint8_t> local_iv;
        std::vector<uint8_t> ciphertext;
        std::vector<uint8_t> local_tag;
        if (!AES::encryptAESGCM(key_blob, s_info.kek, local_iv, ciphertext, local_tag)) {
            throw evi::EncryptionError("Failed to seal metadata key with AES-256-GCM");
        }
        std::ostringstream out(std::ios::binary);
        evi::detail::serialization::writeHeader(out, evi::detail::serialization::kVersionV1);
        const uint32_t ciphertext_size = static_cast<uint32_t>(ciphertext.size());

        out.write(reinterpret_cast<const char *>(local_iv.data()), static_cast<std::streamsize>(local_iv.size()));
        out.write(reinterpret_cast<const char *>(local_tag.data()), static_cast<std::streamsize>(local_tag.size()));
        out.write(reinterpret_cast<const char *>(&ciphertext_size), sizeof(ciphertext_size));
        if (!ciphertext.empty()) {
            out.write(reinterpret_cast<const char *>(ciphertext.data()),
                      static_cast<std::streamsize>(ciphertext.size()));
        }

        std::string sealed_payload = out.str();
        evi::security::SensitiveDataGuard sealed_payload_guard(sealed_payload);
        key_blob = std::vector<uint8_t>(sealed_payload.begin(), sealed_payload.end());
        iv = std::move(local_iv);
        tag = std::move(local_tag);
    }

    const auto &entry_type = evi::KeyType::MetadataKey;
    evi::ProviderEntry entry =
        evi::detail::provider_common::makeProviderEntryFromPayload(entry_type.name, entry_type.role, key_blob);
    if (mode == SealMode::AES_KEK && iv.has_value() && tag.has_value()) {
        entry.alg = "AES-256-GCM";
        entry.iv = evi::detail::utils::encodeToBase64(*iv);
        entry.tag = evi::detail::utils::encodeToBase64(*tag);
    }
    entry.key_data = evi::detail::utils::encodeToBase64(key_blob);
    entry.hash = evi::detail::utils::encodeToBase64(evi::detail::provider_common::computeSha256(key_blob));
    evi::ProviderEnvelope envelope;
    envelope.entries.push_back(std::move(entry));
    return evi::detail::provider_common::makeSealedEnvelopeJson(envelope, key_id, "vector_search",
                                                                key_id + ":metadata:integrity", true);
}

void KeyProvider::decapSecKey(const std::string &file_path, const std::string &out_path, const SealInfo &s_info) {
    std::ifstream in(file_path, std::ios::binary);
    std::ofstream out(out_path, std::ios::binary);
    decapSecKey(in, out, s_info);
    in.close();
    out.close();
}
void KeyProvider::decapEncKey(const std::string &file_path, const std::string &out_path) {
    std::ifstream in(file_path, std::ios::binary);
    std::ofstream out(out_path, std::ios::binary);
    decapEncKey(in, out);
    in.close();
    out.close();
}
void KeyProvider::decapEvalKey(const std::string &file_path, const std::string &out_path) {
    std::ifstream in(file_path, std::ios::binary);
    std::ofstream out(out_path, std::ios::binary);
    decapEvalKey(in, out);
    in.close();
    out.close();
}
void KeyProvider::decapMetadataKey(const std::string &file_path, const std::string &out_path) {
    decapMetadataKey(file_path, out_path, SealInfo(SealMode::NONE));
}

void KeyProvider::decapMetadataKey(const std::string &file_path, const std::string &out_path, const SealInfo &s_info) {
    std::ifstream in(file_path, std::ios::binary);
    std::ofstream out(out_path, std::ios::binary);
    decapMetadataKey(in, out, s_info);
    in.close();
    out.close();
}

void KeyProvider::decapSecKey(std::istream &key_stream, std::ostream &out_stream, const SealInfo &s_info) {
    const SealMode mode = s_info.s_mode;
    if (mode != SealMode::NONE && mode != SealMode::AES_KEK) {
        throw evi::NotSupportedError("SealMode::" + evi::detail::utils::assignSealModeString(mode) +
                                     " is not yet supported for secret key unwrap");
    }
    std::vector<uint8_t> decoded_key =
        evi::detail::provider_common::decodeEnvelopeKeyDataToVector(key_stream, "vector_search");
    evi::security::SensitiveDataGuard guard(decoded_key);
    evi::detail::provider_common::writeBinaryStream(out_stream, decoded_key);
}
void KeyProvider::decapEncKey(std::istream &key_stream, std::ostream &out_stream) {
    evi::detail::provider_common::decodeEnvelopeKeyDataToStream(key_stream, out_stream, "vector_search");
}
void KeyProvider::decapEvalKey(std::istream &key_stream, std::ostream &out_stream) {
    evi::detail::provider_common::decodeEnvelopeKeyDataToStream(key_stream, out_stream, "vector_search");
}
void KeyProvider::decapMetadataKey(std::istream &key_stream, std::ostream &out_stream) {
    decapMetadataKey(key_stream, out_stream, SealInfo(SealMode::NONE));
}

void KeyProvider::decapMetadataKey(std::istream &key_stream, std::ostream &out_stream, const SealInfo &s_info) {
    const SealMode mode = s_info.s_mode;
    if (mode != SealMode::NONE && mode != SealMode::AES_KEK) {
        throw evi::NotSupportedError("SealMode::" + evi::detail::utils::assignSealModeString(mode) +
                                     " is not yet supported for metadata key unwrap");
    }

    std::vector<uint8_t> decoded_key =
        evi::detail::provider_common::decodeEnvelopeKeyDataToVector(key_stream, "vector_search");
    evi::security::SensitiveDataGuard guard(decoded_key);
    if (mode == SealMode::AES_KEK) {
        if (s_info.kek.size() != evi::AES256_KEY_SIZE) {
            throw evi::InvalidInputError("metadata key AES-KEK requires 32-byte kek");
        }
        std::vector<uint8_t> iv_buf(evi::detail::AES256_IV_SIZE, 0);
        std::vector<uint8_t> tag_buf(evi::detail::AES256_TAG_SIZE, 0);
        std::vector<uint8_t> ciphertext;

        std::istringstream in(std::string(decoded_key.begin(), decoded_key.end()), std::ios::binary);
        const auto header = evi::detail::serialization::readHeader(in);
        if (!header.has_header) {
            throw evi::InvalidInputError("Sealed metadata key payload must start with EVIS header");
        }
        uint32_t ciphertext_size = 0;
        in.read(reinterpret_cast<char *>(iv_buf.data()), static_cast<std::streamsize>(iv_buf.size()));
        in.read(reinterpret_cast<char *>(tag_buf.data()), static_cast<std::streamsize>(tag_buf.size()));
        in.read(reinterpret_cast<char *>(&ciphertext_size), sizeof(ciphertext_size));
        if (!in.good()) {
            throw evi::InvalidInputError("Sealed metadata key payload is malformed");
        }
        ciphertext.assign(ciphertext_size, 0);
        if (ciphertext_size > 0) {
            in.read(reinterpret_cast<char *>(ciphertext.data()), static_cast<std::streamsize>(ciphertext_size));
            if (!in.good()) {
                throw evi::InvalidInputError("Sealed metadata key ciphertext is truncated");
            }
        }

        std::vector<uint8_t> plaintext;
        evi::security::SensitiveDataGuard plaintext_guard(plaintext);
        if (!AES::decryptAESGCM(ciphertext, s_info.kek, iv_buf, plaintext, tag_buf)) {
            throw evi::InvalidInputError("Failed to decrypt sealed metadata key with provided KEK");
        }
        decoded_key = std::move(plaintext);
    }
    evi::detail::provider_common::writeBinaryStream(out_stream, decoded_key);
}

} // namespace detail
} // namespace evi
