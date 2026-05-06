
#pragma once

#include <initializer_list>
#include <map>
#include <optional>
#include <string>
#include <variant>
#include <vector>

#include "EVI/Export.hpp"
#include <nlohmann/json.hpp>

namespace evi {

struct LocalConfig {
    std::string type = "LOCAL";
    std::string provider_version = "1";
    std::string version_id;
    std::string wrap_alg;

    nlohmann::ordered_json toJson(bool is_secret = false) const {
        return nlohmann::ordered_json{
            {"type", type},
            {"provider_version", provider_version},
            {"version_id", version_id},
            {"wrap_alg", wrap_alg},
        };
    }
};

struct VaultConfig {
    std::string type = "VAULT";
    std::string provider_version = "1";
    std::string version_id;

    std::string address = "http://127.0.0.1:8200";
    std::string token_env = "VAULT_TOKEN";
    std::string kv_mount = "secret";
    std::string name_space;
    bool tls_skip_verify = false;

    nlohmann::ordered_json toJson(bool is_secret = false) const {
        (void)is_secret;
        return nlohmann::ordered_json{
            {"type", type},
            {"provider_version", provider_version},
            {"version_id", version_id},
            {"address", address},
            {"token_env", token_env},
            {"kv_mount", kv_mount},
            {"namespace", name_space},
            {"tls_skip_verify", tls_skip_verify},
        };
    }
};

struct AwsConfig {
    std::string type = "AWS";
    std::string provider_version = "1";
    std::string version_id;

    std::string region;
    std::string bucket_name;

    // Credentials are read from env at runtime. Values here are env var names only.
    std::string access_key_env = "AWS_ACCESS_KEY_ID";
    std::string secret_key_env = "AWS_SECRET_ACCESS_KEY";
    std::string session_token_env = "AWS_SESSION_TOKEN";

    // Optional: for minio/localstack/testing. If empty, default AWS S3 endpoint is used.
    std::string endpoint;
    bool force_path_style = false;
    bool tls_skip_verify = false;

    nlohmann::ordered_json toJson(bool is_secret = false) const {
        (void)is_secret;
        return nlohmann::ordered_json{
            {"type", type},
            {"provider_version", provider_version},
            {"version_id", version_id},
            {"region", region},
            {"bucket_name", bucket_name},
            {"access_key_env", access_key_env},
            {"secret_key_env", secret_key_env},
            {"session_token_env", session_token_env},
            {"endpoint", endpoint},
            {"force_path_style", force_path_style},
            {"tls_skip_verify", tls_skip_verify},
        };
    }
};

struct GcpConfig {
    std::string type = "GCP";
    std::string provider_version = "1";
    std::string version_id;

    std::string bucket_name;

    // Auth is runtime-injected. Values here are env var names only.
    std::string oauth_token_env = "GCP_OAUTH_TOKEN";
    std::string endpoint = "https://storage.googleapis.com";
    bool tls_skip_verify = false;

    nlohmann::ordered_json toJson(bool is_secret = false) const {
        (void)is_secret;
        return nlohmann::ordered_json{
            {"type", type},
            {"provider_version", provider_version},
            {"version_id", version_id},
            {"bucket_name", bucket_name},
            {"oauth_token_env", oauth_token_env},
            {"endpoint", endpoint},
            {"tls_skip_verify", tls_skip_verify},
        };
    }
};

enum class ProviderType {
    Local,
    Vault,
    Aws,
    Gcp,
};

// Wrapper describing where key envelopes are stored (local file, Vault KV, S3, GCS).
// Canonical name: `KeyStorageConfig`.
struct EVI_API KeyStorageConfig {
    using ConfigMap = std::map<std::string, std::string>;

    ProviderType type{ProviderType::Local};
    std::variant<LocalConfig, VaultConfig, AwsConfig, GcpConfig> value{LocalConfig{}};

    KeyStorageConfig() = default;

    KeyStorageConfig(const LocalConfig &cfg) : type(ProviderType::Local), value(cfg) {}
    KeyStorageConfig(LocalConfig &&cfg) : type(ProviderType::Local), value(std::move(cfg)) {}
    KeyStorageConfig(const VaultConfig &cfg) : type(ProviderType::Vault), value(cfg) {}
    KeyStorageConfig(VaultConfig &&cfg) : type(ProviderType::Vault), value(std::move(cfg)) {}
    KeyStorageConfig(const AwsConfig &cfg) : type(ProviderType::Aws), value(cfg) {}
    KeyStorageConfig(AwsConfig &&cfg) : type(ProviderType::Aws), value(std::move(cfg)) {}
    KeyStorageConfig(const GcpConfig &cfg) : type(ProviderType::Gcp), value(cfg) {}
    KeyStorageConfig(GcpConfig &&cfg) : type(ProviderType::Gcp), value(std::move(cfg)) {}

    static KeyStorageConfig makeLocal(LocalConfig cfg) {
        return KeyStorageConfig(std::move(cfg));
    }
    static KeyStorageConfig makeVault(VaultConfig cfg) {
        return KeyStorageConfig(std::move(cfg));
    }
    static KeyStorageConfig makeAws(AwsConfig cfg) {
        return KeyStorageConfig(std::move(cfg));
    }
    static KeyStorageConfig makeGcp(GcpConfig cfg) {
        return KeyStorageConfig(std::move(cfg));
    }
    static KeyStorageConfig fromConfig(const std::string &provider_name, const ConfigMap &config);
    static KeyStorageConfig fromConfig(const std::string &provider_name,
                                       std::initializer_list<std::pair<std::string, std::string>> config);

    LocalConfig *asLocal() {
        return std::get_if<LocalConfig>(&value);
    }
    const LocalConfig *asLocal() const {
        return std::get_if<LocalConfig>(&value);
    }
    VaultConfig *asVault() {
        return std::get_if<VaultConfig>(&value);
    }
    const VaultConfig *asVault() const {
        return std::get_if<VaultConfig>(&value);
    }
    AwsConfig *asAws() {
        return std::get_if<AwsConfig>(&value);
    }
    const AwsConfig *asAws() const {
        return std::get_if<AwsConfig>(&value);
    }
    GcpConfig *asGcp() {
        return std::get_if<GcpConfig>(&value);
    }
    const GcpConfig *asGcp() const {
        return std::get_if<GcpConfig>(&value);
    }

    nlohmann::ordered_json toJson(bool is_secret = false) const {
        return std::visit(
            [is_secret](auto const &meta) {
                return meta.toJson(is_secret);
            },
            value);
    }
};

} // namespace evi
