#include "km/KeyStorageConfig.hpp"

#include <algorithm>
#include <cctype>
#include <stdexcept>

namespace evi {
namespace {

std::string normalizeProviderName(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

std::optional<std::string> getConfigValue(const KeyStorageConfig::ConfigMap &config, const std::string &key) {
    const auto it = config.find(key);
    if (it == config.end()) {
        return std::nullopt;
    }
    return it->second;
}

bool parseBool(const std::string &value) {
    std::string normalized = value;
    std::transform(normalized.begin(), normalized.end(), normalized.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return normalized == "1" || normalized == "true" || normalized == "yes" || normalized == "on";
}

} // namespace

KeyStorageConfig KeyStorageConfig::fromConfig(const std::string &provider_name, const ConfigMap &config) {
    const std::string normalized = normalizeProviderName(provider_name);

    if (normalized == "local") {
        LocalConfig meta;
        if (auto v = getConfigValue(config, "provider_version")) {
            meta.provider_version = *v;
        }
        if (auto v = getConfigValue(config, "version_id")) {
            meta.version_id = *v;
        }
        if (auto v = getConfigValue(config, "wrap_alg")) {
            meta.wrap_alg = *v;
        }
        return makeLocal(std::move(meta));
    }

    if (normalized == "vault") {
        VaultConfig meta;
        if (auto v = getConfigValue(config, "provider_version")) {
            meta.provider_version = *v;
        }
        if (auto v = getConfigValue(config, "version_id")) {
            meta.version_id = *v;
        }
        if (auto v = getConfigValue(config, "address")) {
            meta.address = *v;
        }
        if (auto v = getConfigValue(config, "token_env")) {
            meta.token_env = *v;
        }
        if (auto v = getConfigValue(config, "kv_mount")) {
            meta.kv_mount = *v;
        }
        if (auto v = getConfigValue(config, "namespace")) {
            meta.name_space = *v;
        }
        if (auto v = getConfigValue(config, "tls_skip_verify")) {
            meta.tls_skip_verify = parseBool(*v);
        }
        return makeVault(std::move(meta));
    }

    if (normalized == "aws") {
        AwsConfig meta;
        if (auto v = getConfigValue(config, "provider_version")) {
            meta.provider_version = *v;
        }
        if (auto v = getConfigValue(config, "version_id")) {
            meta.version_id = *v;
        }
        if (auto v = getConfigValue(config, "region")) {
            meta.region = *v;
        }
        if (auto v = getConfigValue(config, "bucket_name")) {
            meta.bucket_name = *v;
        }
        if (auto v = getConfigValue(config, "access_key_env")) {
            meta.access_key_env = *v;
        }
        if (auto v = getConfigValue(config, "secret_key_env")) {
            meta.secret_key_env = *v;
        }
        if (auto v = getConfigValue(config, "session_token_env")) {
            meta.session_token_env = *v;
        }
        if (auto v = getConfigValue(config, "endpoint")) {
            meta.endpoint = *v;
        }
        if (auto v = getConfigValue(config, "force_path_style")) {
            meta.force_path_style = parseBool(*v);
        }
        if (auto v = getConfigValue(config, "tls_skip_verify")) {
            meta.tls_skip_verify = parseBool(*v);
        }
        return makeAws(std::move(meta));
    }

    if (normalized == "gcp") {
        GcpConfig meta;
        if (auto v = getConfigValue(config, "provider_version")) {
            meta.provider_version = *v;
        }
        if (auto v = getConfigValue(config, "version_id")) {
            meta.version_id = *v;
        }
        if (auto v = getConfigValue(config, "bucket_name")) {
            meta.bucket_name = *v;
        }
        if (auto v = getConfigValue(config, "oauth_token_env")) {
            meta.oauth_token_env = *v;
        }
        if (auto v = getConfigValue(config, "endpoint")) {
            meta.endpoint = *v;
        }
        if (auto v = getConfigValue(config, "tls_skip_verify")) {
            meta.tls_skip_verify = parseBool(*v);
        }
        return makeGcp(std::move(meta));
    }

    throw std::invalid_argument("Unsupported provider for fromConfig: " + provider_name);
}

KeyStorageConfig KeyStorageConfig::fromConfig(const std::string &provider_name,
                                              std::initializer_list<std::pair<std::string, std::string>> config) {
    ConfigMap parsed;
    for (const auto &item : config) {
        parsed[item.first] = item.second;
    }
    return fromConfig(provider_name, parsed);
}

} // namespace evi
