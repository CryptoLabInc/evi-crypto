#include "km/KeyManagerInterface.hpp"

#include "KeyProviderCommon.hpp"
#include "km/impl/KeyManagerCommon.hpp"
#include "km/impl/KeyProviderImpl.hpp"

#include "km/KeyStorageConfig.hpp"
#include "nlohmann/json.hpp"
#include "utils/Exceptions.hpp"
#include "utils/Utils.hpp"
#include "utils/security/Security.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <functional>
#include <optional>
#include <sstream>
#include <string_view>
#include <utility>

namespace {

using evi::KeyStorageConfig;
using evi::detail::KeyProvider;
using evi::security::SensitiveDataGuard;
namespace fs = std::filesystem;

struct AuditFailure {
    std::string code;
    std::string message;
};

std::string joinKeyRef(const std::string &key_id, const std::string &suffix) {
    if (key_id.empty()) {
        return suffix;
    }
    if (!key_id.empty() && key_id.back() == '/') {
        return key_id + suffix;
    }
    return key_id + "/" + suffix;
}

std::string makeAuditFileTimestamp(std::chrono::system_clock::time_point now) {
    std::string ts = evi::detail::utils::timePointToIso8601UtcString(now);
    ts.erase(std::remove(ts.begin(), ts.end(), ':'), ts.end());
    ts.erase(std::remove(ts.begin(), ts.end(), '-'), ts.end());
    return ts;
}

AuditFailure toAuditFailure(const std::exception &error, const std::string &default_code) {
    if (const auto *evi_error = dynamic_cast<const evi::EviError *>(&error)) {
        const std::string code = evi_error->auditCode();
        if (!code.empty()) {
            return {code, error.what()};
        }
    }
    return {default_code, error.what()};
}

void withAuditedFailure(evi::detail::AuditStore &auditor, const std::string &success_event_type,
                        const std::string &failure_event_type, const std::string &operation, const std::string &key_id,
                        const std::string &key_type, const std::string &default_code,
                        const std::function<void()> &func) {
    try {
        func();
        auditor.emitSuccess(success_event_type, operation, key_id, key_type);
    } catch (const std::exception &e) {
        const AuditFailure failure = toAuditFailure(e, default_code);
        const std::string event_type =
            (failure.code == "AAD_VERIFICATION_FAILED") ? "key.aad.fail" : failure_event_type;
        auditor.emitFailure(event_type, operation, key_id, key_type, failure.code, failure.message);
        throw;
    }
}

std::string extractKeyIdFromEnvelopeText(const std::string &envelope_text) {
    nlohmann::ordered_json envelope;
    try {
        envelope = nlohmann::ordered_json::parse(envelope_text);
    } catch (const nlohmann::json::parse_error &err) {
        throw evi::InvalidInputError("Failed to parse key envelope (parse error at byte " + std::to_string(err.byte) +
                                     ")");
    }

    std::string key_id = envelope.value("kid", std::string{});
    if (key_id.empty()) {
        throw evi::InvalidInputError("Key envelope is missing 'kid'");
    }
    return key_id;
}

void updateEnvelopeEntryAndState(nlohmann::ordered_json &envelope, const nlohmann::ordered_json &new_entry) {
    auto entries_it = envelope.find("entries");
    if (entries_it == envelope.end() || !entries_it->is_array() || entries_it->empty()) {
        throw evi::InvalidInputError("Key envelope is missing non-empty 'entries' array");
    }
    entries_it->front() = new_entry;

    const auto key_version_it = envelope.find("key_version");
    if (key_version_it == envelope.end()) {
        throw evi::InvalidInputError("Key envelope is missing 'key_version'");
    }
    if (key_version_it->is_number_integer()) {
        const auto key_version = key_version_it->get<long long>();
        if (key_version <= 0) {
            throw evi::InvalidInputError("Key envelope has invalid 'key_version'");
        }
        envelope["key_version"] = std::to_string(key_version + 1);
    } else if (key_version_it->is_string()) {
        const std::string key_version = key_version_it->get<std::string>();
        if (key_version.empty()) {
            throw evi::InvalidInputError("Key envelope has empty 'key_version'");
        }
        std::size_t parsed_len = 0;
        unsigned long parsed_value = 0UL;
        try {
            parsed_value = std::stoul(key_version, &parsed_len);
        } catch (const std::exception &) {
            throw evi::InvalidInputError("Key envelope has invalid 'key_version'");
        }
        if (parsed_len != key_version.size() || parsed_value == 0UL) {
            throw evi::InvalidInputError("Key envelope has invalid 'key_version'");
        }
        envelope["key_version"] = std::to_string(parsed_value + 1UL);
    } else {
        throw evi::InvalidInputError("Key envelope has non-string/non-integer 'key_version'");
    }

    auto state_it = envelope.find("state");
    if (state_it == envelope.end() || !state_it->is_object()) {
        throw evi::InvalidInputError("Key envelope is missing 'state' object");
    }
    evi::KeyState state = evi::KeyState::fromJson(*state_it, "Key envelope");
    state.updated_at = evi::detail::utils::currentIso8601UtcString();
    envelope["state"] = state.toJson();
}

int parseEnvelopeVersionId(const nlohmann::ordered_json &envelope) {
    const auto version_it = envelope.find("key_version");
    if (version_it == envelope.end()) {
        return 1;
    }
    if (version_it->is_number_integer()) {
        return version_it->get<int>();
    }
    if (!version_it->is_string()) {
        throw evi::InvalidInputError("Key envelope has invalid 'key_version'");
    }
    try {
        return std::stoi(version_it->get<std::string>());
    } catch (...) {
        throw evi::InvalidInputError("Key envelope has non-integer 'key_version'");
    }
}

nlohmann::ordered_json buildMetadataSummary(const nlohmann::ordered_json &envelope) {
    nlohmann::ordered_json metadata = nlohmann::ordered_json::object();
    metadata["entries"] = nlohmann::ordered_json::array();

    const auto entries_it = envelope.find("entries");
    if (entries_it == envelope.end() || !entries_it->is_array()) {
        return metadata;
    }

    for (const auto &entry : *entries_it) {
        if (!entry.is_object()) {
            continue;
        }
        nlohmann::ordered_json projected = nlohmann::ordered_json::object();
        const auto name_it = entry.find("name");
        if (name_it != entry.end() && name_it->is_string()) {
            projected["name"] = name_it->get<std::string>();
        }
        const auto role_it = entry.find("role");
        if (role_it != entry.end() && role_it->is_string()) {
            projected["role"] = role_it->get<std::string>();
        }
        const auto metadata_it = entry.find("metadata");
        if (metadata_it != entry.end()) {
            projected["metadata"] = *metadata_it;
        } else {
            projected["metadata"] = nlohmann::ordered_json::object();
        }
        metadata["entries"].push_back(std::move(projected));
    }
    return metadata;
}

nlohmann::ordered_json makeVersionRecordFromEnvelope(const nlohmann::ordered_json &envelope, bool is_current) {
    const auto state_it = envelope.find("state");
    if (state_it == envelope.end()) {
        throw evi::InvalidInputError("Key envelope is missing 'state' object");
    }
    const evi::KeyState state = evi::KeyState::fromJson(*state_it, "Key envelope");
    const auto kid_it = envelope.find("kid");
    if (kid_it == envelope.end() || !kid_it->is_string()) {
        throw evi::InvalidInputError("Key envelope is missing 'kid'");
    }
    const auto created_at_it = envelope.find("created_at");
    if (created_at_it == envelope.end() || !created_at_it->is_string()) {
        throw evi::InvalidInputError("Key envelope is missing 'created_at'");
    }

    nlohmann::ordered_json record = {
        {"kid", kid_it->get<std::string>()},
        {"version_id", std::to_string(parseEnvelopeVersionId(envelope))},
        {"state", evi::toString(state.value)},
        {"created_at", created_at_it->get<std::string>()},
        {"updated_at", state.updated_at},
        {"metadata", buildMetadataSummary(envelope)},
        {"state_reason", state.reason.has_value() ? nlohmann::ordered_json(*state.reason) : nlohmann::ordered_json()},
        {"is_current", is_current},
    };
    return record;
}
void storeEnvelopeState(nlohmann::ordered_json &envelope, evi::KeyLifecycleState target_state,
                        const std::string &reason) {
    envelope["state"] = evi::KeyState{target_state, evi::KeyState::sanitizeReason(reason),
                                      evi::detail::utils::currentIso8601UtcString()}
                            .toJson();
}

void transitionEnvelopeState(evi::detail::IKeyManagerImpl &impl, const std::string &storage_key_path,
                             evi::KeyLifecycleState target_state, const std::string &reason, bool is_secret_key) {
    const std::string trimmed_reason = evi::KeyState::sanitizeReason(reason);
    if (trimmed_reason.empty()) {
        throw evi::InvalidInputError("State transition reason must not be empty");
    }

    std::ostringstream envelope_stream(std::ios::binary);
    if (is_secret_key) {
        impl.getSecKey(storage_key_path, envelope_stream);
    } else {
        impl.getPubKey(storage_key_path, envelope_stream);
    }

    std::string envelope_text = envelope_stream.str();
    std::optional<evi::security::SensitiveDataGuard> envelope_guard;
    if (is_secret_key) {
        envelope_guard.emplace(envelope_text);
    }
    nlohmann::ordered_json envelope;
    try {
        envelope = nlohmann::ordered_json::parse(envelope_text);
    } catch (const nlohmann::json::parse_error &err) {
        throw evi::InvalidInputError("Failed to parse key envelope for '" + storage_key_path + "': " + err.what());
    }

    const auto state_it = envelope.find("state");
    if (state_it == envelope.end()) {
        throw evi::InvalidInputError("Key envelope '" + storage_key_path + "' is missing 'state' object");
    }
    const evi::KeyState current_state = evi::KeyState::fromJson(*state_it, "Key envelope '" + storage_key_path + "'");
    std::string allowed_next_state = "none";
    bool valid_transition = false;

    switch (current_state.value) {
    case evi::KeyLifecycleState::Preparing:
        allowed_next_state = "'active'";
        valid_transition = target_state == evi::KeyLifecycleState::Active;
        break;
    case evi::KeyLifecycleState::Active:
        allowed_next_state = "'deactivated'";
        valid_transition = target_state == evi::KeyLifecycleState::Deactivated;
        break;
    case evi::KeyLifecycleState::Deactivated:
        allowed_next_state = "'destroyed'";
        valid_transition = target_state == evi::KeyLifecycleState::Destroyed;
        break;
    case evi::KeyLifecycleState::Destroyed:
        break;
    }

    if (!valid_transition) {
        throw evi::InvalidInputError("Cannot transition key '" + storage_key_path + "' from '" +
                                     evi::toString(current_state.value) + "' to '" + evi::toString(target_state) +
                                     "'; allowed next state is " + allowed_next_state);
    }

    storeEnvelopeState(envelope, target_state, trimmed_reason);
    if (is_secret_key && target_state == evi::KeyLifecycleState::Destroyed) {
        auto entries_it = envelope.find("entries");
        if (entries_it != envelope.end() && entries_it->is_array()) {
            for (auto &entry : *entries_it) {
                if (!entry.is_object()) {
                    continue;
                }
                entry.erase("key_data");
                entry.erase("iv");
                entry.erase("tag");
                entry.erase("hash");
            }
        }
    }
    if (is_secret_key) {
        std::string updated_envelope_text = envelope.dump();
        evi::security::SensitiveDataGuard updated_envelope_guard(updated_envelope_text);
        impl.updateSecKey(storage_key_path, updated_envelope_text);
    } else {
        impl.updatePubKey(storage_key_path, envelope.dump());
    }
}
class LocalKeyManagerImpl : public evi::detail::IKeyManagerImpl {
public:
    explicit LocalKeyManagerImpl(const KeyStorageConfig &storage_config) : IKeyManagerImpl(storage_config) {}

    std::vector<std::string> listKeys(const std::string &prefix = "") override {
        (void)prefix;
        return {};
    }

    void getSecKey(const std::string &storage_key_path, std::ostream &out_stream) override {
        std::ifstream in(storage_key_path, std::ios::binary);
        if (!in) {
            throw evi::FileNotFoundError("Failed to open local key file: " + storage_key_path);
        }
        out_stream << in.rdbuf();
        if (!out_stream.good()) {
            throw evi::InvalidInputError("Failed to read local key file: " + storage_key_path);
        }
    }

    void getPubKey(const std::string &storage_key_path, std::ostream &out_stream) override {
        std::ifstream in(storage_key_path, std::ios::binary);
        if (!in) {
            throw evi::FileNotFoundError("Failed to open local key file: " + storage_key_path);
        }
        out_stream << in.rdbuf();
        if (!out_stream.good()) {
            throw evi::InvalidInputError("Failed to read local key file: " + storage_key_path);
        }
    }

    void deleteSecKey(const std::string &storage_key_path) override {
        std::error_code ec;
        const bool removed = std::filesystem::remove(storage_key_path, ec);
        if (ec) {
            throw evi::InvalidInputError("Failed to delete local key file: " + storage_key_path + ": " + ec.message());
        }
        if (!removed) {
            throw evi::FileNotFoundError("Local key file not found: " + storage_key_path);
        }
    }

    void deletePubKey(const std::string &storage_key_path) override {
        std::error_code ec;
        const bool removed = std::filesystem::remove(storage_key_path, ec);
        if (ec) {
            throw evi::InvalidInputError("Failed to delete local key file: " + storage_key_path + ": " + ec.message());
        }
        if (!removed) {
            throw evi::FileNotFoundError("Local key file not found: " + storage_key_path);
        }
    }

    void putSecKey(const std::string &storage_key_path, std::istream &key_stream) override {
        std::ofstream out(storage_key_path, std::ios::binary | std::ios::trunc);
        if (!out) {
            throw evi::InvalidInputError("Failed to open local key file for write: " + storage_key_path);
        }
        out << key_stream.rdbuf();
        if (!out.good()) {
            throw evi::InvalidInputError("Failed to write local key file: " + storage_key_path);
        }
    }

    void putPubKey(const std::string &storage_key_path, std::istream &key_stream) override {
        std::ofstream out(storage_key_path, std::ios::binary | std::ios::trunc);
        if (!out) {
            throw evi::InvalidInputError("Failed to open local key file for write: " + storage_key_path);
        }
        out << key_stream.rdbuf();
        if (!out.good()) {
            throw evi::InvalidInputError("Failed to write local key file: " + storage_key_path);
        }
    }

    void updateSecKey(const std::string &storage_key_path, const std::string &envelope_text) override {
        std::ofstream out(storage_key_path, std::ios::binary | std::ios::trunc);
        if (!out) {
            throw evi::InvalidInputError("Failed to open local key file for write: " + storage_key_path);
        }
        out << envelope_text;
        if (!out.good()) {
            throw evi::InvalidInputError("Failed to update local key file: " + storage_key_path);
        }
    }

    void updatePubKey(const std::string &storage_key_path, const std::string &envelope_text) override {
        std::ofstream out(storage_key_path, std::ios::binary | std::ios::trunc);
        if (!out) {
            throw evi::InvalidInputError("Failed to open local key file for write: " + storage_key_path);
        }
        out << envelope_text;
        if (!out.good()) {
            throw evi::InvalidInputError("Failed to update local key file: " + storage_key_path);
        }
    }
};

} // namespace

namespace evi::detail {

IKeyManagerImpl::IKeyManagerImpl(const KeyStorageConfig &storage_config)
    : provider_(std::make_shared<KeyProvider>()), storage_config_(storage_config) {
    if (!provider_) {
        throw InvalidInputError("Key provider is not initialized");
    }
}

void IKeyManagerImpl::setAuditStore(const std::string &path) {
    audit_store_ = makeAuditStore(path);
}

void IKeyManagerImpl::setAuditStore() {
    std::string ts = makeAuditFileTimestamp(std::chrono::system_clock::now());
    audit_store_ = makeAuditStore("kms_audit-" + ts + ".jsonl");
}

AuditStore &IKeyManagerImpl::auditor() const {
    return audit_store_ ? *audit_store_ : AuditStore::noop();
}

// ---------------------------------------------------------------------------
// wrapSecKey
// ---------------------------------------------------------------------------

void IKeyManagerImpl::wrapSecKey(const std::string &key_id, const std::string &key_file_path,
                                 const std::string &out_file_path, const SealInfo &s_info) {
    std::ifstream in(key_file_path, std::ios::binary);
    std::ofstream out(out_file_path, std::ios::binary);
    wrapSecKey(key_id, in, out, s_info);
    in.close();
    out.close();
}

void IKeyManagerImpl::wrapSecKey(const std::string &key_id, std::istream &key_stream, std::ostream &out_stream,
                                 const SealInfo &s_info) {
    withAuditedFailure(
        auditor(), "key.wrap", "key.wrap.fail", "wrap", key_id, evi::KeyType::SecKey.name, "WRAP_FAILED", [&] {
            const SealMode mode = s_info.s_mode;
            if (mode != SealMode::NONE && mode != SealMode::AES_KEK) {
                throw evi::NotSupportedError("SealMode::" + evi::detail::utils::assignSealModeString(mode) +
                                             " is not yet supported for SecretKey wrap");
            }
            if (key_id.empty()) {
                throw InvalidInputError("key_id must not be empty");
            }
            std::stringstream payload_stream;
            if (mode == SealMode::NONE) {
                payload_stream << key_stream.rdbuf();
            } else {
                std::stringstream plain_stream;
                plain_stream << key_stream.rdbuf();
                plain_stream.seekg(0);

                SecretKey seckey = makeSecKey(plain_stream, std::nullopt);
                seckey->s_info_ = s_info;
                seckey->teew_.emplace(seckey->s_info_.value());
                seckey->saveSealedSecKey(payload_stream);
            }
            payload_stream.seekg(0);

            nlohmann::ordered_json json_envelope = provider_->encapSecKey(key_id, payload_stream, s_info);
            std::string envelope_text = json_envelope.dump();
            evi::security::SensitiveDataGuard envelope_guard(envelope_text);
            out_stream << envelope_text;
        });
}

void IKeyManagerImpl::wrapSecKey(const std::string &key_id, const SecretKey &seckey, std::ostream &out_stream,
                                 const SealInfo &s_info) {
    const SealMode mode = s_info.s_mode;
    if (mode != SealMode::NONE && mode != SealMode::AES_KEK) {
        throw evi::NotSupportedError("SealMode::" + evi::detail::utils::assignSealModeString(mode) +
                                     " is not yet supported for SecretKey wrap");
    }
    std::stringstream ss;
    seckey->saveSecKey(ss);
    ss.seekg(0);
    wrapSecKey(key_id, ss, out_stream, s_info);
}

// ---------------------------------------------------------------------------
// unwrapSecKey
// ---------------------------------------------------------------------------

void IKeyManagerImpl::unwrapSecKey(const std::string &file_path, const std::string &out_path, const SealInfo &s_info) {
    std::ifstream in(file_path, std::ios::binary);
    std::ofstream out(out_path, std::ios::binary);
    unwrapSecKey(in, out, s_info);
    in.close();
    out.close();
}

void IKeyManagerImpl::unwrapSecKey(std::istream &in_stream, std::ostream &out_stream, const SealInfo &s_info) {
    const std::string key_type = evi::KeyType::SecKey.name;
    std::string envelope_text = evi::detail::common::readStreamToString(in_stream, "key envelope");
    SensitiveDataGuard envelope_guard(envelope_text);
    const std::string key_id = extractKeyIdFromEnvelopeText(envelope_text);
    withAuditedFailure(auditor(), "key.unwrap", "key.unwrap.fail", "unwrap", key_id, key_type, "UNWRAP_FAILED", [&] {
        const SealMode mode = s_info.s_mode;
        if (mode != SealMode::NONE && mode != SealMode::AES_KEK) {
            throw evi::NotSupportedError("SealMode::" + evi::detail::utils::assignSealModeString(mode) +
                                         " is not yet supported for SecretKey wrap");
        }

        std::istringstream envelope_stream(envelope_text, std::ios::binary);
        if (mode == SealMode::NONE) {
            provider_->decapSecKey(envelope_stream, out_stream, s_info);
        } else {
            std::stringstream sealed_stream;
            provider_->decapSecKey(envelope_stream, sealed_stream, s_info);
            sealed_stream.seekg(0);
            SecretKey seckey = makeSecKey(sealed_stream, std::optional<SealInfo>(s_info));

            std::stringstream plain_stream;
            seckey->saveSecKey(plain_stream);
            plain_stream.seekg(0);
            out_stream << plain_stream.rdbuf();
        }
    });
}

void IKeyManagerImpl::unwrapSecKey(std::istream &in_stream, SecretKey &seckey, const SealInfo &s_info) {
    const std::string key_type = evi::KeyType::SecKey.name;
    std::string envelope_text = evi::detail::common::readStreamToString(in_stream, "key envelope");
    SensitiveDataGuard envelope_guard(envelope_text);
    const std::string key_id = extractKeyIdFromEnvelopeText(envelope_text);
    withAuditedFailure(auditor(), "key.unwrap", "key.unwrap.fail", "unwrap", key_id, key_type, "UNWRAP_FAILED", [&] {
        const SealMode mode = s_info.s_mode;
        if (mode != SealMode::NONE && mode != SealMode::AES_KEK) {
            throw evi::NotSupportedError("SealMode::" + evi::detail::utils::assignSealModeString(mode) +
                                         " is not yet supported for SecretKey wrap");
        }
        std::istringstream envelope_stream(envelope_text, std::ios::binary);
        std::stringstream ss;
        provider_->decapSecKey(envelope_stream, ss, s_info);
        ss.seekg(0);
        if (mode == SealMode::NONE) {
            seckey->loadSecKey(ss);
        } else {
            SecretKey unsealed = makeSecKey(ss, std::optional<SealInfo>(s_info));
            std::stringstream plain_stream;
            unsealed->saveSecKey(plain_stream);
            plain_stream.seekg(0);
            seckey->loadSecKey(plain_stream);
        }
    });
}

void IKeyManagerImpl::rotateSecKey(const std::string &storage_key_path, const SealInfo &old_s_info,
                                   const SealInfo &new_s_info) {
    withAuditedFailure(
        auditor(), "key.rotate", "key.rotate.fail", "rotate", storage_key_path, evi::KeyType::SecKey.name,
        "ROTATE_FAILED", [&] {
            if (old_s_info.s_mode != evi::SealMode::NONE && old_s_info.s_mode != evi::SealMode::AES_KEK) {
                throw evi::NotSupportedError("old_s_info supports only NONE or AES_KEK");
            }
            if (new_s_info.s_mode != evi::SealMode::NONE && new_s_info.s_mode != evi::SealMode::AES_KEK) {
                throw evi::NotSupportedError("new_s_info supports only NONE or AES_KEK");
            }

            std::ostringstream envelope_stream(std::ios::binary);
            getSecKey(storage_key_path, envelope_stream);
            std::string envelope_text = envelope_stream.str();
            SensitiveDataGuard envelope_text_guard(envelope_text);

            nlohmann::ordered_json envelope;
            try {
                envelope = nlohmann::ordered_json::parse(envelope_text);
            } catch (const nlohmann::json::parse_error &err) {
                throw evi::InvalidInputError("Failed to parse key envelope for '" + storage_key_path +
                                             "': " + err.what());
            }
            const auto state_it = envelope.find("state");
            if (state_it == envelope.end() || !state_it->is_object()) {
                throw evi::InvalidInputError("Key envelope '" + storage_key_path + "' is missing 'state' object");
            }
            const evi::KeyState state = evi::KeyState::fromJson(*state_it, "Key envelope '" + storage_key_path + "'");
            if (state.value != evi::KeyLifecycleState::Active) {
                throw evi::InvalidInputError("Cannot rotate key '" + storage_key_path + "' from lifecycle state '" +
                                             evi::toString(state.value) + "'; only 'active' keys can be rotated");
            }

            const std::string key_id = envelope.at("kid").get<std::string>();
            const std::string entry_name = envelope.at("entries").front().at("name").get<std::string>();

            if (entry_name == evi::KeyType::SecKey.name || entry_name == evi::KeyType::SecKeySealed.name) {
                std::stringstream plaintext_stream(std::ios::in | std::ios::out | std::ios::binary);
                {
                    std::istringstream in_stream(envelope_text, std::ios::binary);
                    unwrapSecKey(in_stream, plaintext_stream, old_s_info);
                }
                std::string plaintext = plaintext_stream.str();
                SensitiveDataGuard plaintext_guard(plaintext);
                std::istringstream plaintext_input(plaintext, std::ios::binary);

                std::stringstream payload_stream(std::ios::in | std::ios::out | std::ios::binary);
                if (new_s_info.s_mode == SealMode::NONE) {
                    payload_stream << plaintext_input.rdbuf();
                } else {
                    SecretKey seckey = makeSecKey(plaintext_input, std::nullopt);
                    seckey->s_info_ = new_s_info;
                    seckey->teew_.emplace(seckey->s_info_.value());
                    seckey->saveSealedSecKey(payload_stream);
                }
                payload_stream.seekg(0);

                nlohmann::ordered_json rotated_envelope = provider_->encapSecKey(key_id, payload_stream, new_s_info);
                updateEnvelopeEntryAndState(envelope, rotated_envelope.at("entries").front());
                updateSecKey(storage_key_path, envelope.dump());
                return;
            }

            if (entry_name == evi::KeyType::MetadataKey.name || entry_name == evi::KeyType::MetadataKeySealed.name) {
                std::stringstream plaintext_stream(std::ios::in | std::ios::out | std::ios::binary);
                {
                    std::istringstream in_stream(envelope_text, std::ios::binary);
                    unwrapMetadataKey(in_stream, plaintext_stream, old_s_info);
                }
                std::string plaintext = plaintext_stream.str();
                SensitiveDataGuard plaintext_guard(plaintext);
                std::istringstream plaintext_input(plaintext, std::ios::binary);

                nlohmann::ordered_json rotated_envelope =
                    provider_->encapMetadataKey(key_id, plaintext_input, new_s_info);
                updateEnvelopeEntryAndState(envelope, rotated_envelope.at("entries").front());
                updateSecKey(storage_key_path, envelope.dump());
                return;
            }

            throw evi::InvalidInputError("rotateSecKey supports only 'seckey' or 'metadatakey' envelopes");
        });
}

void IKeyManagerImpl::wrapEncKey(const std::string &key_id, const std::string &key_file_path,
                                 const std::string &out_file_path) {
    std::ifstream in(key_file_path, std::ios::binary);
    std::ofstream out(out_file_path);
    wrapEncKey(key_id, in, out);
    in.close();
    out.close();
}

void IKeyManagerImpl::wrapEncKey(const std::string &key_id, std::istream &key_stream, std::ostream &out_stream) {
    withAuditedFailure(auditor(), "key.wrap", "key.wrap.fail", "wrap", key_id, evi::KeyType::EncKey.name, "WRAP_FAILED",
                       [&] {
                           if (key_id.empty()) {
                               throw InvalidInputError("key_id must not be empty");
                           }
                           nlohmann::ordered_json json_envelope = provider_->encapEncKey(key_id, key_stream);
                           const std::string envelope_text = json_envelope.dump();
                           out_stream << envelope_text;
                       });
}

void IKeyManagerImpl::wrapEncKey(const std::string &key_id, const IKeyPack &keypack, std::ostream &out_stream) {
    std::stringstream ss;
    keypack.getEncKeyBuffer(ss);
    ss.seekg(0);
    wrapEncKey(key_id, ss, out_stream);
}

// ---------------------------------------------------------------------------
// unwrapEncKey
// ---------------------------------------------------------------------------

void IKeyManagerImpl::unwrapEncKey(std::istream &in_stream, std::ostream &out_stream) {
    const std::string key_type = evi::KeyType::EncKey.name;
    std::string envelope_text = evi::detail::common::readStreamToString(in_stream, "key envelope");
    SensitiveDataGuard envelope_guard(envelope_text);
    const std::string key_id = extractKeyIdFromEnvelopeText(envelope_text);
    withAuditedFailure(auditor(), "key.unwrap", "key.unwrap.fail", "unwrap", key_id, key_type, "UNWRAP_FAILED", [&] {
        std::istringstream envelope_stream(envelope_text, std::ios::binary);
        provider_->decapEncKey(envelope_stream, out_stream);
    });
}

void IKeyManagerImpl::unwrapEncKey(const std::string &file_path, const std::string &out_path) {
    std::ifstream in(file_path, std::ios::binary);
    std::ofstream out(out_path, std::ios::binary);
    unwrapEncKey(in, out);
}

void IKeyManagerImpl::unwrapEncKey(std::istream &key_stream, IKeyPack &keypack) {
    const std::string key_type = evi::KeyType::EncKey.name;
    std::string envelope_text = evi::detail::common::readStreamToString(key_stream, "key envelope");
    SensitiveDataGuard envelope_guard(envelope_text);
    const std::string key_id = extractKeyIdFromEnvelopeText(envelope_text);
    withAuditedFailure(auditor(), "key.unwrap", "key.unwrap.fail", "unwrap", key_id, key_type, "UNWRAP_FAILED", [&] {
        std::istringstream envelope_stream(envelope_text, std::ios::binary);
        std::stringstream ss;
        provider_->decapEncKey(envelope_stream, ss);
        ss.seekg(0);
        keypack.loadEncKeyBuffer(ss);
    });
}

// ---------------------------------------------------------------------------
// wrapEvalKey
// ---------------------------------------------------------------------------

void IKeyManagerImpl::wrapEvalKey(const std::string &key_id, const std::string &key_file_path,
                                  const std::string &out_file_path) {
    std::ifstream in(key_file_path, std::ios::binary);
    std::ofstream out(out_file_path, std::ios::binary);
    wrapEvalKey(key_id, in, out);
    in.close();
    out.close();
}

void IKeyManagerImpl::wrapEvalKey(const std::string &key_id, std::istream &key_stream, std::ostream &out_stream) {
    withAuditedFailure(auditor(), "key.wrap", "key.wrap.fail", "wrap", key_id, evi::KeyType::EvalKey.name,
                       "WRAP_FAILED", [&] {
                           if (key_id.empty()) {
                               throw InvalidInputError("key_id must not be empty");
                           }
                           nlohmann::ordered_json json_envelope = provider_->encapEvalKey(key_id, key_stream);
                           const std::string envelope_text = json_envelope.dump();
                           out_stream << envelope_text;
                       });
}

// ---------------------------------------------------------------------------
// unwrapEvalKey
// ---------------------------------------------------------------------------

void IKeyManagerImpl::unwrapEvalKey(const std::string &file_path, const std::string &out_path) {
    std::ifstream in(file_path, std::ios::binary);
    std::ofstream out(out_path, std::ios::binary);
    unwrapEvalKey(in, out);
}

void IKeyManagerImpl::unwrapEvalKey(std::istream &in_stream, std::ostream &out_stream) {
    const std::string key_type = evi::KeyType::EvalKey.name;
    std::string envelope_text = evi::detail::common::readStreamToString(in_stream, "key envelope");
    SensitiveDataGuard envelope_guard(envelope_text);
    const std::string key_id = extractKeyIdFromEnvelopeText(envelope_text);
    withAuditedFailure(auditor(), "key.unwrap", "key.unwrap.fail", "unwrap", key_id, key_type, "UNWRAP_FAILED", [&] {
        std::istringstream envelope_stream(envelope_text, std::ios::binary);
        provider_->decapEvalKey(envelope_stream, out_stream);
    });
}

// ---------------------------------------------------------------------------
// wrapMetadataKey
// ---------------------------------------------------------------------------

void IKeyManagerImpl::wrapMetadataKey(const std::string &key_id, const std::string &key_file_path,
                                      const std::string &out_file_path, const SealInfo &s_info) {
    std::ifstream in(key_file_path, std::ios::binary);
    std::ofstream out(out_file_path, std::ios::binary);
    wrapMetadataKey(key_id, in, out, s_info);
    in.close();
    out.close();
}

void IKeyManagerImpl::wrapMetadataKey(const std::string &key_id, std::istream &key_stream, std::ostream &out_stream,
                                      const SealInfo &s_info) {
    withAuditedFailure(
        auditor(), "key.wrap", "key.wrap.fail", "wrap", key_id, evi::KeyType::MetadataKey.name, "WRAP_FAILED", [&] {
            if (key_id.empty()) {
                throw InvalidInputError("key_id must not be empty");
            }
            nlohmann::ordered_json json_envelope = provider_->encapMetadataKey(key_id, key_stream, s_info);
            const std::string envelope_text = json_envelope.dump();
            out_stream << envelope_text;
        });
}

// ---------------------------------------------------------------------------
// unwrapMetadataKey
// ---------------------------------------------------------------------------

void IKeyManagerImpl::unwrapMetadataKey(const std::string &file_path, const std::string &out_path,
                                        const SealInfo &s_info) {
    std::ifstream in(file_path, std::ios::binary);
    std::ofstream out(out_path, std::ios::binary);
    unwrapMetadataKey(in, out, s_info);
}

void IKeyManagerImpl::unwrapMetadataKey(std::istream &in_stream, std::ostream &out_stream, const SealInfo &s_info) {
    const std::string key_type = evi::KeyType::MetadataKey.name;
    std::string envelope_text = evi::detail::common::readStreamToString(in_stream, "key envelope");
    SensitiveDataGuard envelope_guard(envelope_text);
    const std::string key_id = extractKeyIdFromEnvelopeText(envelope_text);
    withAuditedFailure(auditor(), "key.unwrap", "key.unwrap.fail", "unwrap", key_id, key_type, "UNWRAP_FAILED", [&] {
        std::istringstream envelope_stream(envelope_text, std::ios::binary);
        provider_->decapMetadataKey(envelope_stream, out_stream, s_info);
    });
}

// ---------------------------------------------------------------------------
// wrapKeys / unwrapKeys
// ---------------------------------------------------------------------------

void IKeyManagerImpl::wrapKeys(const std::string &key_id, const std::string &key_path, const SealInfo &s_info) {
    wrapEncKey(key_id, key_path + "/EncKey.bin", key_path + "/EncKey.json");
    wrapEvalKey(key_id, key_path + "/EvalKey.bin", key_path + "/EvalKey.json");
    wrapSecKey(key_id, key_path + "/SecKey.bin", key_path + "/SecKey.json", s_info);
}

void IKeyManagerImpl::wrapKeys(const std::string &key_id, std::istream &file_stream, const SealInfo &s_info) {
    (void)key_id;
    (void)file_stream;
    (void)s_info;
    throw NotSupportedError("Stream-based wrapKeys is not implemented yet");
}

void IKeyManagerImpl::unwrapKeys(const std::string &file_dir_path, const std::string &out_dir_path,
                                 const SealInfo &s_info) {
    fs::create_directories(out_dir_path);
    unwrapEncKey(file_dir_path + "/EncKey.json", out_dir_path + "/EncKey.bin");
    unwrapEvalKey(file_dir_path + "/EvalKey.json", out_dir_path + "/EvalKey.bin");
    unwrapSecKey(file_dir_path + "/SecKey.json", out_dir_path + "/SecKey.bin", s_info);
}

void IKeyManagerImpl::unwrapKeys(std::istream &key_stream, std::ostream &out_stream, const SealInfo &s_info) {
    (void)key_stream;
    (void)out_stream;
    (void)s_info;
    throw NotSupportedError("Stream-based unwrapKeys is not implemented yet");
}

// ---------------------------------------------------------------------------
// Default storage operation stubs
// ---------------------------------------------------------------------------

void IKeyManagerImpl::deactivateSecKey(const std::string &storage_key_path, const std::string &reason) {
    transitionEnvelopeState(*this, storage_key_path, evi::KeyLifecycleState::Deactivated, reason, true);
}

void IKeyManagerImpl::deactivatePubKey(const std::string &storage_key_path, const std::string &reason) {
    transitionEnvelopeState(*this, storage_key_path, evi::KeyLifecycleState::Deactivated, reason, false);
}

void IKeyManagerImpl::destroySecKey(const std::string &storage_key_path, const std::string &reason) {
    transitionEnvelopeState(*this, storage_key_path, evi::KeyLifecycleState::Destroyed, reason, true);
}

void IKeyManagerImpl::destroyPubKey(const std::string &storage_key_path, const std::string &reason) {
    transitionEnvelopeState(*this, storage_key_path, evi::KeyLifecycleState::Destroyed, reason, false);
}

void IKeyManagerImpl::getSecKey(const std::string &storage_key_path, std::ostream &out_stream) {
    (void)storage_key_path;
    (void)out_stream;
    throw NotSupportedError("getSecKey is not implemented for this provider");
}

void IKeyManagerImpl::getPubKey(const std::string &storage_key_path, std::ostream &out_stream) {
    (void)storage_key_path;
    (void)out_stream;
    throw NotSupportedError("getPubKey is not implemented for this provider");
}

std::vector<std::string> IKeyManagerImpl::listVersions(const std::string &storage_key_path) {
    std::string envelope_text;
    evi::security::SensitiveDataGuard envelope_guard(envelope_text);
    try {
        std::ostringstream envelope_stream(std::ios::binary);
        getSecKey(storage_key_path, envelope_stream);
        envelope_text = envelope_stream.str();
    } catch (const std::exception &sec_err) {
        try {
            std::ostringstream envelope_stream(std::ios::binary);
            getPubKey(storage_key_path, envelope_stream);
            envelope_text = envelope_stream.str();
        } catch (const std::exception &pub_err) {
            throw evi::InvalidInputError("Failed to read key envelope for '" + storage_key_path +
                                         "' via both getSecKey and getPubKey: sec=" + sec_err.what() +
                                         ", pub=" + pub_err.what());
        }
    }
    nlohmann::ordered_json envelope;
    try {
        envelope = nlohmann::ordered_json::parse(envelope_text);
    } catch (const nlohmann::json::parse_error &err) {
        throw evi::InvalidInputError("Failed to parse key envelope for '" + storage_key_path + "': " + err.what());
    }

    std::vector<std::string> rows;

    nlohmann::ordered_json current_row = makeVersionRecordFromEnvelope(envelope, true);
    current_row["storage_key_path"] = storage_key_path;
    rows.push_back(current_row.dump());
    return rows;
}

const std::shared_ptr<KeyProvider> &IKeyManagerImpl::provider() const {
    return provider_;
}

const KeyStorageConfig &IKeyManagerImpl::storageConfig() const {
    return storage_config_;
}

std::shared_ptr<IKeyManagerImpl> makeLocalKeyManager(const KeyStorageConfig &storage_config) {
    return std::make_shared<LocalKeyManagerImpl>(storage_config);
}

std::shared_ptr<IKeyManagerImpl> makeKeyManager(const KeyStorageConfig &storage_config,
                                                const KeyFormatVersion version) {
    if (version != KeyFormatVersion::V1) {
        throw NotSupportedError("Unsupported KeyManager version");
    }

    switch (storage_config.type) {
    case ProviderType::Local:
        return makeLocalKeyManager(storage_config);
    case ProviderType::Vault:
        if (storage_config.asVault() == nullptr) {
            throw InvalidInputError("Vault provider metadata is missing");
        }
        return makeVaultKeyManager(storage_config);
    case ProviderType::Aws:
        if (storage_config.asAws() == nullptr) {
            throw InvalidInputError("AWS provider metadata is missing");
        }
        return makeAwsKeyManager(storage_config);
    case ProviderType::Gcp:
        if (storage_config.asGcp() == nullptr) {
            throw InvalidInputError("GCP provider metadata is missing");
        }
        return makeGcpKeyManager(storage_config);
    }

    throw NotSupportedError("Unsupported provider type");
}

std::shared_ptr<IKeyManagerImpl> makeKeyManager(const KeyStorageConfig &storage_config) {
    return makeKeyManager(storage_config, KeyFormatVersion::Latest);
}

std::shared_ptr<IKeyManagerImpl> makeKeyManager() {
    KeyStorageConfig storage_config = KeyStorageConfig::makeLocal(LocalConfig{});
    return makeKeyManager(storage_config, KeyFormatVersion::Latest);
}

} // namespace evi::detail
