#include "km/KeyManagerInterface.hpp"
#include "km/impl/KeyProviderImpl.hpp"

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

#if defined(EVI_KM_USE_GCP_SDK)
#include <google/cloud/secretmanager/v1/secret_manager_connection.h>
#include <google/cloud/storage/client.h>
#endif

using json = nlohmann::json;

#if defined(EVI_KM_USE_GCP_SDK)
namespace gcs = google::cloud::storage;
#endif

namespace evi::detail {

GcpKeyManagerImpl::GcpKeyManagerImpl(const KeyStorageConfig &storage_config)
    : IKeyManagerImpl(storage_config), meta_(*storage_config.asGcp()) {
#if defined(EVI_KM_USE_GCP_SDK)
    initializeGcpState();
#endif
}

void GcpKeyManagerImpl::initializeGcpState() {
#if defined(EVI_KM_USE_GCP_SDK)
    const char *project_env_names[] = {"GOOGLE_CLOUD_PROJECT", "GCLOUD_PROJECT", "GCP_PROJECT", "GOOGLE_PROJECT_ID"};
    for (const char *name : project_env_names) {
        const char *v = std::getenv(name);
        if (v && v[0] != '\0') {
            project_id_ = v;
            break;
        }
    }
    if (project_id_.empty()) {
        throw evi::InvalidInputError(
            "GCP project ID is not set (set GOOGLE_CLOUD_PROJECT or GCLOUD_PROJECT or GCP_PROJECT)");
    }
    gcs_client_.emplace();
    secret_manager_client_.emplace(google::cloud::secretmanager_v1::MakeSecretManagerServiceConnection());
#endif
}

std::vector<std::string> GcpKeyManagerImpl::listKeys(const std::string &prefix) {
#if defined(EVI_KM_USE_GCP_SDK)
    std::vector<std::string> out;
    auto &client = *gcs_client_;
    for (auto &&item : client.ListObjects(meta_.bucket_name, gcs::Prefix(prefix))) {
        if (!item) {
            throw std::runtime_error("GCS LIST failed: " + item.status().message());
        }
        out.push_back(item->name());
    }

    auto &sm = *secret_manager_client_;
    google::cloud::secretmanager::v1::ListSecretsRequest req;
    req.set_parent("projects/" + project_id_);
    if (!prefix.empty()) {
        // Secret Manager filter narrows the result set server-side, then we preserve exact prefix semantics locally.
        req.set_filter("name:" + prefix);
    }
    for (auto secret : sm.ListSecrets(req)) {
        if (!secret) {
            throw std::runtime_error("GCP Secret Manager LIST failed: " + secret.status().message());
        }
        const std::string resource_name = secret->name();
        const std::size_t slash = resource_name.rfind('/');
        if (slash == std::string::npos || slash + 1 >= resource_name.size()) {
            continue;
        }
        const std::string name = resource_name.substr(slash + 1);
        if (prefix.empty() || name.rfind(prefix, 0) == 0) {
            out.push_back(name);
        }
    }

    std::sort(out.begin(), out.end());
    out.erase(std::unique(out.begin(), out.end()), out.end());
    return out;
#else
    throw evi::NotSupportedError("GCP provider requires google-cloud-cpp (enable EVI_KM_USE_GCP_SDK)");
#endif
}

void GcpKeyManagerImpl::getSecKey(const std::string &storage_key_path, std::ostream &out_stream) {
#if defined(EVI_KM_USE_GCP_SDK)
    auto &sm = *secret_manager_client_;
    auto outcome =
        sm.AccessSecretVersion("projects/" + project_id_ + "/secrets/" + storage_key_path + "/versions/latest");
    if (!outcome) {
        throw std::runtime_error("GCP Secret Manager ACCESS failed: " + outcome.status().message());
    }
    std::string payload = outcome->payload().data();
    evi::security::SensitiveDataGuard payload_guard(payload);
    out_stream << payload;
#else
    throw evi::NotSupportedError("GCP provider requires google-cloud-cpp (enable EVI_KM_USE_GCP_SDK)");
#endif
}

void GcpKeyManagerImpl::getPubKey(const std::string &storage_key_path, std::ostream &out_stream) {
#if defined(EVI_KM_USE_GCP_SDK)
    auto &client = *gcs_client_;
    auto stream = client.ReadObject(meta_.bucket_name, storage_key_path);
    out_stream << stream.rdbuf();
    if (!stream.status().ok()) {
        throw std::runtime_error("GCS GET failed: " + stream.status().message());
    }
#else
    throw evi::NotSupportedError("GCP provider requires google-cloud-cpp (enable EVI_KM_USE_GCP_SDK)");
#endif
}

void GcpKeyManagerImpl::deleteSecKey(const std::string &storage_key_path) {
#if defined(EVI_KM_USE_GCP_SDK)
    auto &sm = *secret_manager_client_;
    auto status = sm.DeleteSecret("projects/" + project_id_ + "/secrets/" + storage_key_path);
    if (!status.ok() && status.code() != google::cloud::StatusCode::kNotFound) {
        throw std::runtime_error("GCP Secret Manager DELETE failed: " + status.message());
    }
#else
    throw evi::NotSupportedError("GCP provider requires google-cloud-cpp (enable EVI_KM_USE_GCP_SDK)");
#endif
}

void GcpKeyManagerImpl::deletePubKey(const std::string &storage_key_path) {
#if defined(EVI_KM_USE_GCP_SDK)
    auto &client = *gcs_client_;
    auto status = client.DeleteObject(meta_.bucket_name, storage_key_path);
    if (!status.ok()) {
        throw std::runtime_error("GCS DELETE failed: " + status.message());
    }
#else
    throw evi::NotSupportedError("GCP provider requires google-cloud-cpp (enable EVI_KM_USE_GCP_SDK)");
#endif
}

void GcpKeyManagerImpl::putSecKey(const std::string &storage_key_path, std::istream &key_stream) {
#if defined(EVI_KM_USE_GCP_SDK)
    std::ostringstream key_text_stream;
    key_text_stream << key_stream.rdbuf();
    std::string key_text = key_text_stream.str();
    evi::security::SensitiveDataGuard key_text_guard(key_text);
    bool envelope = false;
    try {
        envelope = evi::detail::utils::isEnvelopeJson(json::parse(key_text));
    } catch (const std::exception &) {
        envelope = false;
    }
    if (!envelope) {
        throw InvalidInputError("putSecKey requires envelope JSON payload");
    }
    if (key_text.size() > 65536) {
        throw evi::InvalidInputError("GCP Secret Manager payload exceeds 65536 bytes for storage_key_path '" +
                                     storage_key_path + "' (size=" + std::to_string(key_text.size()) + ")");
    }
    auto &sm = *secret_manager_client_;
    google::cloud::secretmanager::v1::Secret secret;
    secret.mutable_replication()->mutable_automatic();
    auto create_outcome = sm.CreateSecret("projects/" + project_id_, storage_key_path, secret);
    if (!create_outcome) {
        if (create_outcome.status().code() == google::cloud::StatusCode::kAlreadyExists) {
            throw evi::InvalidInputError("GCP secret already exists: " + storage_key_path);
        }
        throw std::runtime_error("GCP Secret Manager CREATE failed: " + create_outcome.status().message());
    }

    google::cloud::secretmanager::v1::SecretPayload payload;
    payload.set_data(key_text);
    auto add_outcome = sm.AddSecretVersion("projects/" + project_id_ + "/secrets/" + storage_key_path, payload);
    if (!add_outcome) {
        throw std::runtime_error("GCP Secret Manager addVersion failed: " + add_outcome.status().message());
    }
#else
    throw evi::NotSupportedError("GCP provider requires google-cloud-cpp (enable EVI_KM_USE_GCP_SDK)");
#endif
}

void GcpKeyManagerImpl::putPubKey(const std::string &storage_key_path, std::istream &key_stream) {
#if defined(EVI_KM_USE_GCP_SDK)
    std::ostringstream key_text_stream;
    key_text_stream << key_stream.rdbuf();
    std::string key_text = key_text_stream.str();
    evi::security::SensitiveDataGuard key_text_guard(key_text);
    bool envelope = false;
    try {
        envelope = evi::detail::utils::isEnvelopeJson(json::parse(key_text));
    } catch (const std::exception &) {
        envelope = false;
    }
    if (!envelope) {
        throw InvalidInputError("putPubKey requires envelope JSON payload");
    }
    auto &client = *gcs_client_;
    auto result = client.InsertObject(meta_.bucket_name, storage_key_path, key_text,
                                      gcs::ContentType("application/json"), gcs::IfGenerationMatch(0));
    if (!result) {
        if (result.status().code() == google::cloud::StatusCode::kFailedPrecondition) {
            throw evi::InvalidInputError("GCS object already exists: " + storage_key_path);
        }
        throw std::runtime_error("GCS PUT failed: " + result.status().message());
    }
#else
    throw evi::NotSupportedError("GCP provider requires google-cloud-cpp (enable EVI_KM_USE_GCP_SDK)");
#endif
}

void GcpKeyManagerImpl::updateSecKey(const std::string &storage_key_path, const std::string &envelope_text) {
#if defined(EVI_KM_USE_GCP_SDK)
    std::string mutable_envelope_text = envelope_text;
    evi::security::SensitiveDataGuard envelope_guard(mutable_envelope_text);
    auto &sm = *secret_manager_client_;
    google::cloud::secretmanager::v1::SecretPayload payload;
    payload.set_data(mutable_envelope_text);
    auto secret_outcome = sm.AddSecretVersion("projects/" + project_id_ + "/secrets/" + storage_key_path, payload);
    if (secret_outcome) {
        return;
    }

    throw std::runtime_error("GCP Secret Manager addVersion failed: " + secret_outcome.status().message());
#else
    (void)storage_key_path;
    (void)envelope_text;
    throw evi::NotSupportedError("GCP provider requires google-cloud-cpp (enable EVI_KM_USE_GCP_SDK)");
#endif
}

void GcpKeyManagerImpl::updatePubKey(const std::string &storage_key_path, const std::string &envelope_text) {
#if defined(EVI_KM_USE_GCP_SDK)

    auto &client = *gcs_client_;
    auto stream = client.WriteObject(meta_.bucket_name, storage_key_path, gcs::ContentType("application/json"));
    stream << envelope_text;
    stream.Close();
    if (stream.metadata()) {
        return;
    }

    throw std::runtime_error("GCS PUT failed: " + stream.metadata().status().message());
#else
    (void)storage_key_path;
    (void)envelope_text;
    throw evi::NotSupportedError("GCP provider requires google-cloud-cpp (enable EVI_KM_USE_GCP_SDK)");
#endif
}

std::shared_ptr<IKeyManagerImpl> makeGcpKeyManager(const KeyStorageConfig &storage_config) {
    return std::make_shared<GcpKeyManagerImpl>(storage_config);
}

} // namespace evi::detail
