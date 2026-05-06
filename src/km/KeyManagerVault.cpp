#include "km/KeyManagerInterface.hpp"
#include "km/impl/KeyManagerCommon.hpp"
#include "km/impl/KeyProviderImpl.hpp"

#include "HttpClient.hpp"
#include "KeyProviderCommon.hpp"

#include "nlohmann/json.hpp"
#include "utils/Exceptions.hpp"
#include "utils/Utils.hpp"
#include "utils/security/Security.hpp"

#include <algorithm>
#include <cstdlib>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

using json = nlohmann::json;

namespace {

std::string trimLeadingSlash(std::string value) {
    while (!value.empty() && value.front() == '/') {
        value.erase(value.begin());
    }
    return value;
}

std::string trimTrailingSlash(std::string value) {
    while (!value.empty() && value.back() == '/') {
        value.pop_back();
    }
    return value;
}

std::string joinPath(const std::string &lhs, const std::string &rhs) {
    if (lhs.empty()) {
        return trimLeadingSlash(rhs);
    }
    if (rhs.empty()) {
        return lhs;
    }
    if (lhs.back() == '/') {
        return lhs + trimLeadingSlash(rhs);
    }
    return lhs + "/" + trimLeadingSlash(rhs);
}

std::string requireVaultToken(const evi::VaultConfig &meta) {
    const char *token = std::getenv(meta.token_env.c_str());
    if (!token || token[0] == '\0') {
        throw evi::InvalidInputError("Vault token env '" + meta.token_env + "' is not set");
    }
    return std::string(token);
}

evi::detail::http::Response callVaultApi(const evi::VaultConfig &meta, const std::string &method,
                                         const std::string &path, const std::optional<std::string> &body) {
    const std::string token = requireVaultToken(meta);
    const std::string base = trimTrailingSlash(meta.address);
    const std::string url = base + "/v1/" + trimLeadingSlash(path);
    const auto parsed = evi::detail::http::parseUrl(url);
    if (parsed.https) {
        throw evi::NotSupportedError("Vault address must use http:// in this build");
    }

    std::vector<std::pair<std::string, std::string>> headers;
    headers.emplace_back("X-Vault-Token", token);
    if (!meta.name_space.empty()) {
        headers.emplace_back("X-Vault-Namespace", meta.name_space);
    }
    if (method != "GET" && method != "LIST") {
        headers.emplace_back("Content-Type", "application/json");
    }

    return evi::detail::http::call(method, url, headers, body, meta.tls_skip_verify);
}

} // namespace

namespace evi::detail {

void writeEnvelopeTextToVault(const VaultConfig &meta, const std::string &storage_key_path,
                              const std::string &envelope_text) {
    json body;
    body["data"] = json::object();
    body["data"]["envelope"] = envelope_text;
    (void)callVaultApi(meta, "POST", joinPath(joinPath(meta.kv_mount, "data"), storage_key_path), body.dump());
}

std::vector<std::string> listVaultKeys(const VaultConfig &meta, const std::string &prefix) {
    const std::string metadata_path = joinPath(joinPath(meta.kv_mount, "metadata"), prefix);
    const auto resp = callVaultApi(meta, "LIST", metadata_path, std::nullopt);
    if (resp.status_code == 404) {
        return {};
    }
    if (resp.status_code >= 300) {
        throw std::runtime_error("Vault list failed with HTTP " + std::to_string(resp.status_code));
    }

    const json body = json::parse(resp.body.empty() ? "{}" : resp.body);
    const auto keys_it = body.find("data");
    if (keys_it == body.end() || !keys_it->is_object()) {
        return {};
    }
    const auto list_it = keys_it->find("keys");
    if (list_it == keys_it->end() || !list_it->is_array()) {
        return {};
    }

    std::vector<std::string> out;
    out.reserve(list_it->size());
    for (const auto &node : *list_it) {
        if (!node.is_string()) {
            continue;
        }
        std::string child = node.get<std::string>();
        if (!child.empty() && child.back() == '/') {
            child.pop_back();
        }
        out.push_back(joinPath(prefix, child));
    }
    return out;
}

std::optional<int> getVaultCurrentVersion(const evi::VaultConfig &meta, const std::string &storage_key_path) {
    const auto resp =
        callVaultApi(meta, "GET", joinPath(joinPath(meta.kv_mount, "metadata"), storage_key_path), std::nullopt);
    if (resp.status_code == 404) {
        return std::nullopt;
    }
    if (resp.status_code >= 300) {
        throw std::runtime_error("Vault metadata read failed with HTTP " + std::to_string(resp.status_code));
    }

    const json body = json::parse(resp.body.empty() ? "{}" : resp.body);
    const auto data_it = body.find("data");
    if (data_it == body.end() || !data_it->is_object()) {
        throw evi::InvalidInputError("Vault metadata response is missing 'data' object");
    }
    const auto version_it = data_it->find("current_version");
    if (version_it == data_it->end() || !version_it->is_number_integer()) {
        throw evi::InvalidInputError("Vault metadata response is missing integer 'current_version'");
    }

    const int version = version_it->get<int>();
    if (version <= 0) {
        return std::nullopt;
    }
    return version;
}

VaultKeyManagerImpl::VaultKeyManagerImpl(const KeyStorageConfig &storage_config)
    : IKeyManagerImpl(storage_config), meta_(*storage_config.asVault()) {}

std::vector<std::string> VaultKeyManagerImpl::listKeys(const std::string &prefix) {
    std::vector<std::string> out;
    std::vector<std::string> stack = listVaultKeys(meta_, prefix);
    while (!stack.empty()) {
        std::string current = std::move(stack.back());
        stack.pop_back();

        std::vector<std::string> children;
        try {
            children = listVaultKeys(meta_, current);
        } catch (const std::exception &) {
            children.clear();
        }

        if (children.empty()) {
            out.push_back(std::move(current));
        } else {
            for (auto &child : children) {
                stack.push_back(std::move(child));
            }
        }
    }
    std::sort(out.begin(), out.end());
    out.erase(std::unique(out.begin(), out.end()), out.end());
    return out;
}

void VaultKeyManagerImpl::getSecKey(const std::string &storage_key_path, std::ostream &out_stream) {
    const auto resp =
        callVaultApi(meta_, "GET", joinPath(joinPath(meta_.kv_mount, "data"), storage_key_path), std::nullopt);
    if (resp.status_code >= 300) {
        throw std::runtime_error("Vault read failed with HTTP " + std::to_string(resp.status_code));
    }
    const json body = json::parse(resp.body);
    std::string envelope_text = body.at("data").at("data").at("envelope").get<std::string>();
    evi::security::SensitiveDataGuard envelope_guard(envelope_text);
    out_stream << envelope_text;
}

void VaultKeyManagerImpl::getPubKey(const std::string &storage_key_path, std::ostream &out_stream) {
    (void)storage_key_path;
    (void)out_stream;
    throw NotSupportedError("Vault provider stores only SecKey.json in remote CRUD path");
}

void VaultKeyManagerImpl::destroySecKey(const std::string &storage_key_path, const std::string &reason) {
    (void)reason; // The reason is consumed above for lifecycle/audit intent before purge.
    IKeyManagerImpl::destroySecKey(storage_key_path, reason);

    const auto current_version = getVaultCurrentVersion(meta_, storage_key_path);
    if (!current_version.has_value()) {
        return;
    }

    json body;
    body["versions"] = json::array();
    for (int version = 1; version <= *current_version; ++version) {
        body["versions"].push_back(version);
    }
    const auto resp =
        callVaultApi(meta_, "PUT", joinPath(joinPath(meta_.kv_mount, "destroy"), storage_key_path), body.dump());
    if (resp.status_code >= 300) {
        throw std::runtime_error("Vault destroy failed with HTTP " + std::to_string(resp.status_code));
    }
}

void VaultKeyManagerImpl::destroyPubKey(const std::string &storage_key_path, const std::string &reason) {
    (void)storage_key_path;
    (void)reason;
    throw NotSupportedError("Vault provider does not support destroyPubKey");
}

void VaultKeyManagerImpl::deleteSecKey(const std::string &storage_key_path) {
    const auto resp =
        callVaultApi(meta_, "DELETE", joinPath(joinPath(meta_.kv_mount, "metadata"), storage_key_path), std::nullopt);
    if (resp.status_code >= 300) {
        throw std::runtime_error("Vault delete failed with HTTP " + std::to_string(resp.status_code));
    }
}

void VaultKeyManagerImpl::deletePubKey(const std::string &storage_key_path) {
    (void)storage_key_path;
    throw NotSupportedError("Vault provider does not support deletePubKey");
}

void VaultKeyManagerImpl::putSecKey(const std::string &storage_key_path, std::istream &key_stream) {
    std::stringstream payload_stream;
    payload_stream << key_stream.rdbuf();
    std::string envelope_text = payload_stream.str();
    evi::security::SensitiveDataGuard envelope_guard(envelope_text);
    bool envelope = false;
    try {
        envelope = evi::detail::utils::isEnvelopeJson(nlohmann::json::parse(envelope_text));
    } catch (const std::exception &) {
        envelope = false;
    }
    if (!envelope) {
        if (evi::detail::common::isVersionRecordPath(storage_key_path)) {
            writeEnvelopeTextToVault(meta_, storage_key_path, envelope_text);
            return;
        }
        const std::size_t last_slash = storage_key_path.rfind('/');
        if (last_slash == std::string::npos || last_slash == 0) {
            throw InvalidInputError("Non-envelope payload requires storage_key_path in '<key_id>/<name>.json' form");
        }
        const std::string key_id = storage_key_path.substr(0, last_slash);
        const std::string name = storage_key_path.substr(last_slash + 1);
        if (name != "SecKey.json") {
            throw InvalidInputError("putSecKey requires storage_key_path ending with SecKey.json");
        }
        payload_stream.clear();
        payload_stream.seekg(0, std::ios::beg);
        envelope_text = provider()->encapSecKey(key_id, payload_stream).dump();
    }
    writeEnvelopeTextToVault(meta_, storage_key_path, envelope_text);
}

void VaultKeyManagerImpl::putPubKey(const std::string &storage_key_path, std::istream &key_stream) {
    (void)storage_key_path;
    (void)key_stream;
    throw NotSupportedError("Vault provider does not support putPubKey");
}

void VaultKeyManagerImpl::updateSecKey(const std::string &storage_key_path, const std::string &envelope_text) {
    writeEnvelopeTextToVault(meta_, storage_key_path, envelope_text);
}

void VaultKeyManagerImpl::updatePubKey(const std::string &storage_key_path, const std::string &envelope_text) {
    (void)storage_key_path;
    (void)envelope_text;
    throw NotSupportedError("Vault provider does not support updatePubKey");
}

std::shared_ptr<IKeyManagerImpl> makeVaultKeyManager(const KeyStorageConfig &storage_config) {
    return std::make_shared<VaultKeyManagerImpl>(storage_config);
}

} // namespace evi::detail
