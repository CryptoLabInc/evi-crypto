#include "km/KeyManagerInterface.hpp"
#include "km/impl/KeyProviderImpl.hpp"

#include "KeyProviderCommon.hpp"

#include "nlohmann/json.hpp"
#include "utils/Exceptions.hpp"
#include "utils/Utils.hpp"
#include "utils/security/Security.hpp"

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <iterator>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#if defined(EVI_KM_USE_AWS_SDK)
#include "HttpClient.hpp"

#include <aws/core/Aws.h>
#include <aws/core/auth/AWSCredentials.h>
#include <aws/core/auth/AWSCredentialsProvider.h>
#include <aws/core/auth/AWSCredentialsProviderChain.h>
#include <aws/core/client/ClientConfiguration.h>
#include <aws/core/http/Scheme.h>
#include <aws/s3/S3Client.h>
#include <aws/s3/model/DeleteObjectRequest.h>
#include <aws/s3/model/GetObjectRequest.h>
#include <aws/s3/model/ListObjectsV2Request.h>
#include <aws/s3/model/PutObjectRequest.h>
#include <aws/secretsmanager/SecretsManagerClient.h>
#include <aws/secretsmanager/model/CreateSecretRequest.h>
#include <aws/secretsmanager/model/DeleteSecretRequest.h>
#include <aws/secretsmanager/model/Filter.h>
#include <aws/secretsmanager/model/GetSecretValueRequest.h>
#include <aws/secretsmanager/model/ListSecretsRequest.h>
#include <aws/secretsmanager/model/UpdateSecretRequest.h>
#include <memory>
#endif

namespace evi::detail {

#if defined(EVI_KM_USE_AWS_SDK)
#endif

AwsKeyManagerImpl::AwsKeyManagerImpl(const KeyStorageConfig &storage_config)
    : IKeyManagerImpl(storage_config), meta_(*storage_config.asAws()) {
#if defined(EVI_KM_USE_AWS_SDK)
    initializeAwsClients();
#endif
}

void AwsKeyManagerImpl::initializeAwsClients() {
#if defined(EVI_KM_USE_AWS_SDK)
    static std::once_flag once;
    std::call_once(once, [] {
        static Aws::SDKOptions options;
        Aws::InitAPI(options);
        std::atexit([] {
            Aws::ShutdownAPI(options);
        });
    });

    const bool use_standard_env = (meta_.access_key_env == "AWS_ACCESS_KEY_ID") &&
                                  (meta_.secret_key_env == "AWS_SECRET_ACCESS_KEY") &&
                                  (meta_.session_token_env == "AWS_SESSION_TOKEN");
    if (use_standard_env) {
        credentials_provider_ = std::make_shared<Aws::Auth::DefaultAWSCredentialsProviderChain>();
    } else {
        const char *access_key_raw = std::getenv(meta_.access_key_env.c_str());
        if (!access_key_raw || access_key_raw[0] == '\0') {
            throw evi::InvalidInputError("Env '" + meta_.access_key_env + "' is not set");
        }
        const char *secret_key_raw = std::getenv(meta_.secret_key_env.c_str());
        if (!secret_key_raw || secret_key_raw[0] == '\0') {
            throw evi::InvalidInputError("Env '" + meta_.secret_key_env + "' is not set");
        }
        const char *session_token_raw = std::getenv(meta_.session_token_env.c_str());
        Aws::Auth::AWSCredentials creds(access_key_raw, secret_key_raw,
                                        (session_token_raw && session_token_raw[0] != '\0') ? session_token_raw : "");
        credentials_provider_ = std::make_shared<Aws::Auth::SimpleAWSCredentialsProvider>(creds);
    }

    Aws::Client::ClientConfiguration cfg;
    if (!meta_.region.empty()) {
        cfg.region = meta_.region.c_str();
    }
    if (!meta_.endpoint.empty()) {
        const auto parsed = evi::detail::http::parseUrl(meta_.endpoint);
        cfg.scheme = parsed.https ? Aws::Http::Scheme::HTTPS : Aws::Http::Scheme::HTTP;

        std::string endpoint_override = parsed.host;
        const bool default_port = (parsed.https && parsed.port == "443") || (!parsed.https && parsed.port == "80");
        if (!default_port) {
            try {
                const unsigned long port = std::stoul(parsed.port);
                if (port == 0 || port > 65535UL) {
                    throw evi::InvalidInputError("Invalid AWS endpoint port: " + parsed.port);
                }
            } catch (const evi::InvalidInputError &) {
                throw;
            } catch (...) {
                throw evi::InvalidInputError("Invalid AWS endpoint port: " + parsed.port);
            }
            endpoint_override += ":" + parsed.port;
        }
        cfg.endpointOverride = endpoint_override.c_str();
    }
    if (meta_.tls_skip_verify) {
        cfg.verifySSL = false;
    }
    client_config_ = std::move(cfg);

    s3_client_.emplace(credentials_provider_, *client_config_,
                       Aws::Client::AWSAuthV4Signer::PayloadSigningPolicy::Never, !meta_.force_path_style);
    secrets_manager_client_.emplace(credentials_provider_, *client_config_);
#endif
}

std::vector<std::string> AwsKeyManagerImpl::listKeys(const std::string &prefix) {
#if defined(EVI_KM_USE_AWS_SDK)
    auto &s3 = *s3_client_;
    auto &sm = *secrets_manager_client_;
    std::vector<std::string> out;

    Aws::String continuation;
    while (true) {
        Aws::S3::Model::ListObjectsV2Request req;
        req.SetBucket(meta_.bucket_name.c_str());
        if (!prefix.empty()) {
            req.SetPrefix(prefix.c_str());
        }
        if (!continuation.empty()) {
            req.SetContinuationToken(continuation);
        }
        auto outcome = s3.ListObjectsV2(req);
        if (!outcome.IsSuccess()) {
            throw std::runtime_error("S3 LIST failed: " + outcome.GetError().GetMessage());
        }
        const auto &result = outcome.GetResult();
        const auto &objects = result.GetContents();
        out.reserve(out.size() + objects.size());
        for (const auto &obj : objects) {
            out.push_back(obj.GetKey().c_str());
        }
        if (!result.GetIsTruncated()) {
            break;
        }
        continuation = result.GetNextContinuationToken();
        if (continuation.empty()) {
            break;
        }
    }

    Aws::String next_token;
    while (true) {
        Aws::SecretsManager::Model::ListSecretsRequest req;
        if (!prefix.empty()) {
            Aws::SecretsManager::Model::Filter filter;
            filter.SetKey(Aws::SecretsManager::Model::FilterNameStringType::name);
            filter.AddValues(prefix.c_str());
            req.AddFilters(std::move(filter));
        }
        if (!next_token.empty()) {
            req.SetNextToken(next_token);
        }
        auto outcome = sm.ListSecrets(req);
        if (!outcome.IsSuccess()) {
            throw std::runtime_error("Secrets Manager LIST failed: " + outcome.GetError().GetMessage());
        }
        const auto &result = outcome.GetResult();
        const auto &secret_list = result.GetSecretList();
        out.reserve(out.size() + secret_list.size());
        for (const auto &secret : secret_list) {
            out.push_back(secret.GetName().c_str());
        }
        next_token = result.GetNextToken();
        if (next_token.empty()) {
            break;
        }
    }

    std::sort(out.begin(), out.end());
    out.erase(std::unique(out.begin(), out.end()), out.end());
    return out;
#else
    throw evi::NotSupportedError("AWS provider requires AWS SDK for C++ (enable EVI_KM_USE_AWS_SDK)");
#endif
}

void AwsKeyManagerImpl::getSecKey(const std::string &storage_key_path, std::ostream &out_stream) {
#if defined(EVI_KM_USE_AWS_SDK)
    auto &sm = *secrets_manager_client_;
    Aws::SecretsManager::Model::GetSecretValueRequest req;
    req.SetSecretId(storage_key_path.c_str());
    auto outcome = sm.GetSecretValue(req);
    if (!outcome.IsSuccess()) {
        throw std::runtime_error("Secrets Manager GET failed: " + outcome.GetError().GetMessage());
    }
    std::string envelope_text = outcome.GetResult().GetSecretString().c_str();
    evi::security::SensitiveDataGuard envelope_guard(envelope_text);
    out_stream << envelope_text;
#else
    throw evi::NotSupportedError("AWS provider requires AWS SDK for C++ (enable EVI_KM_USE_AWS_SDK)");
#endif
}

void AwsKeyManagerImpl::getPubKey(const std::string &storage_key_path, std::ostream &out_stream) {
#if defined(EVI_KM_USE_AWS_SDK)
    auto &s3 = *s3_client_;
    Aws::S3::Model::GetObjectRequest req;
    req.SetBucket(meta_.bucket_name.c_str());
    req.SetKey(storage_key_path.c_str());
    auto outcome = s3.GetObject(req);
    if (!outcome.IsSuccess()) {
        throw std::runtime_error("S3 GET failed: " + outcome.GetError().GetMessage());
    }
    auto &stream = outcome.GetResultWithOwnership().GetBody();
    std::ostringstream oss;
    oss << stream.rdbuf();
    out_stream << oss.str();
#else
    throw evi::NotSupportedError("AWS provider requires AWS SDK for C++ (enable EVI_KM_USE_AWS_SDK)");
#endif
}

void AwsKeyManagerImpl::deleteSecKey(const std::string &storage_key_path) {
#if defined(EVI_KM_USE_AWS_SDK)
    auto &sm = *secrets_manager_client_;
    Aws::SecretsManager::Model::DeleteSecretRequest req;
    req.SetSecretId(storage_key_path.c_str());
    req.SetForceDeleteWithoutRecovery(true);
    auto outcome = sm.DeleteSecret(req);
    if (!outcome.IsSuccess()) {
        throw std::runtime_error("Secrets Manager DELETE failed: " + outcome.GetError().GetMessage());
    }
#else
    throw evi::NotSupportedError("AWS provider requires AWS SDK for C++ (enable EVI_KM_USE_AWS_SDK)");
#endif
}

void AwsKeyManagerImpl::deletePubKey(const std::string &storage_key_path) {
#if defined(EVI_KM_USE_AWS_SDK)
    auto &s3 = *s3_client_;
    Aws::S3::Model::DeleteObjectRequest req;
    req.SetBucket(meta_.bucket_name.c_str());
    req.SetKey(storage_key_path.c_str());
    auto outcome = s3.DeleteObject(req);
    if (!outcome.IsSuccess()) {
        throw std::runtime_error("S3 DELETE failed: " + outcome.GetError().GetMessage());
    }
#else
    throw evi::NotSupportedError("AWS provider requires AWS SDK for C++ (enable EVI_KM_USE_AWS_SDK)");
#endif
}

void AwsKeyManagerImpl::putSecKey(const std::string &storage_key_path, std::istream &key_stream) {
#if defined(EVI_KM_USE_AWS_SDK)
    key_stream.clear();
    key_stream.seekg(0, std::ios::beg);
    bool envelope = false;
    try {
        envelope = evi::detail::utils::isEnvelopeJson(nlohmann::json::parse(key_stream));
    } catch (const std::exception &) {
        envelope = false;
    }
    if (!envelope) {
        throw InvalidInputError("putSecKey requires envelope JSON payload");
    }
    key_stream.clear();
    key_stream.seekg(0, std::ios::beg);
    std::string envelope_text((std::istreambuf_iterator<char>(key_stream)), std::istreambuf_iterator<char>());
    evi::security::SensitiveDataGuard envelope_guard(envelope_text);
    auto &sm = *secrets_manager_client_;
    Aws::SecretsManager::Model::CreateSecretRequest create_req;
    create_req.SetName(storage_key_path.c_str());
    create_req.SetSecretString(envelope_text.c_str());
    auto create_outcome = sm.CreateSecret(create_req);
    if (create_outcome.IsSuccess()) {
        return;
    }
    const auto &err = create_outcome.GetError();
    if (err.GetExceptionName() == "ResourceExistsException") {
        throw evi::InvalidInputError("Secret already exists: " + storage_key_path);
    }
    throw std::runtime_error("Secrets Manager CREATE failed: " + err.GetMessage());
#else
    throw evi::NotSupportedError("AWS provider requires AWS SDK for C++ (enable EVI_KM_USE_AWS_SDK)");
#endif
}

void AwsKeyManagerImpl::putPubKey(const std::string &storage_key_path, std::istream &key_stream) {
#if defined(EVI_KM_USE_AWS_SDK)
    key_stream.clear();
    key_stream.seekg(0, std::ios::beg);
    bool envelope = false;
    try {
        envelope = evi::detail::utils::isEnvelopeJson(nlohmann::json::parse(key_stream));
    } catch (const std::exception &) {
        envelope = false;
    }
    if (!envelope) {
        throw InvalidInputError("putPubKey requires envelope JSON payload");
    }
    key_stream.clear();
    key_stream.seekg(0, std::ios::beg);
    const std::string envelope_text((std::istreambuf_iterator<char>(key_stream)), std::istreambuf_iterator<char>());
    auto &s3 = *s3_client_;
    Aws::S3::Model::PutObjectRequest req;
    req.SetBucket(meta_.bucket_name.c_str());
    req.SetKey(storage_key_path.c_str());
    req.SetContentType("application/json");
    req.SetIfNoneMatch("*");
    auto body = Aws::MakeShared<Aws::StringStream>("evi-km-s3-put");
    (*body) << envelope_text;
    req.SetBody(body);
    auto outcome = s3.PutObject(req);
    if (!outcome.IsSuccess()) {
        if (outcome.GetError().GetExceptionName() == "PreconditionFailed") {
            throw evi::InvalidInputError("S3 object already exists: " + storage_key_path);
        }
        throw std::runtime_error("S3 PUT failed: " + outcome.GetError().GetMessage());
    }
#else
    throw evi::NotSupportedError("AWS provider requires AWS SDK for C++ (enable EVI_KM_USE_AWS_SDK)");
#endif
}

void AwsKeyManagerImpl::updateSecKey(const std::string &storage_key_path, const std::string &envelope_text) {
#if defined(EVI_KM_USE_AWS_SDK)
    std::string mutable_envelope_text = envelope_text;
    evi::security::SensitiveDataGuard envelope_guard(mutable_envelope_text);
    auto &sm = *secrets_manager_client_;
    Aws::SecretsManager::Model::UpdateSecretRequest secret_req;
    secret_req.SetSecretId(storage_key_path.c_str());
    secret_req.SetSecretString(mutable_envelope_text.c_str());
    auto secret_outcome = sm.UpdateSecret(secret_req);
    if (secret_outcome.IsSuccess()) {
        return;
    }

    throw std::runtime_error("Secrets Manager UPDATE failed: " + secret_outcome.GetError().GetMessage());
#else
    (void)storage_key_path;
    (void)envelope_text;
    throw evi::NotSupportedError("AWS provider requires AWS SDK for C++ (enable EVI_KM_USE_AWS_SDK)");
#endif
}

void AwsKeyManagerImpl::updatePubKey(const std::string &storage_key_path, const std::string &envelope_text) {
#if defined(EVI_KM_USE_AWS_SDK)

    auto &s3 = *s3_client_;
    Aws::S3::Model::PutObjectRequest object_req;
    object_req.SetBucket(meta_.bucket_name.c_str());
    object_req.SetKey(storage_key_path.c_str());
    object_req.SetContentType("application/json");
    auto body = Aws::MakeShared<Aws::StringStream>("evi-km-s3-update");
    (*body) << envelope_text;
    object_req.SetBody(body);
    auto object_outcome = s3.PutObject(object_req);
    if (object_outcome.IsSuccess()) {
        return;
    }

    throw std::runtime_error("S3 PUT failed: " + object_outcome.GetError().GetMessage());
#else
    (void)storage_key_path;
    (void)envelope_text;
    throw evi::NotSupportedError("AWS provider requires AWS SDK for C++ (enable EVI_KM_USE_AWS_SDK)");
#endif
}

std::shared_ptr<IKeyManagerImpl> makeAwsKeyManager(const KeyStorageConfig &storage_config) {
    return std::make_shared<AwsKeyManagerImpl>(storage_config);
}

} // namespace evi::detail
