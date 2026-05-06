////////////////////////////////////////////////////////////////////////////////
//                                                                            //
// Copyright (C) 2021-2024, CryptoLab Inc. All rights reserved.               //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#pragma once

#include "EVI/SealInfo.hpp"
#include "EVI/impl/KeyPackImpl.hpp"
#include "EVI/impl/SecretKeyImpl.hpp"
#include "km/KeyEnvelope.hpp"
#include "km/KeyStorageConfig.hpp"
#include "km/audit/AuditStore.hpp"

#include <istream>
#include <memory>
#include <ostream>
#include <string>
#include <vector>

#if defined(EVI_KM_USE_AWS_SDK)
#include <aws/core/auth/AWSCredentialsProvider.h>
#include <aws/core/client/ClientConfiguration.h>
#include <aws/s3/S3Client.h>
#include <aws/secretsmanager/SecretsManagerClient.h>
#endif

#if defined(EVI_KM_USE_GCP_SDK)
#include <google/cloud/secretmanager/v1/secret_manager_client.h>
#include <google/cloud/storage/client.h>
#endif

namespace evi {

namespace detail {
class KeyProvider;

class IKeyManagerImpl {
public:
    explicit IKeyManagerImpl(const KeyStorageConfig &storage_config);
    virtual ~IKeyManagerImpl() = default;

    // sec key
    virtual void wrapSecKey(const std::string &key_id, const std::string &key_path, const std::string &output_path,
                            const SealInfo &s_info = SealInfo(SealMode::NONE));
    virtual void wrapSecKey(const std::string &key_id, std::istream &key_stream, std::ostream &out_stream,
                            const SealInfo &s_info = SealInfo(SealMode::NONE));
    virtual void wrapSecKey(const std::string &key_id, const SecretKey &seckey, std::ostream &out_stream,
                            const SealInfo &s_info = SealInfo(SealMode::NONE));

    virtual void unwrapSecKey(const std::string &file_path, const std::string &output_path,
                              const SealInfo &sInfo = SealInfo(SealMode::NONE));
    virtual void unwrapSecKey(std::istream &key_stream, std::ostream &out_stream,
                              const SealInfo &sInfo = SealInfo(SealMode::NONE));
    virtual void unwrapSecKey(std::istream &key_stream, SecretKey &seckey,
                              const SealInfo &s_info = SealInfo(SealMode::NONE));

    // enc key
    virtual void wrapEncKey(const std::string &key_id, const std::string &key_path, const std::string &output_path);
    virtual void wrapEncKey(const std::string &key_id, std::istream &key_stream, std::ostream &out_stream);
    virtual void wrapEncKey(const std::string &key_id, const IKeyPack &keypack, std::ostream &out_stream);

    virtual void unwrapEncKey(const std::string &file_path, const std::string &output_path);
    virtual void unwrapEncKey(std::istream &key_stream, std::ostream &out_stream);
    virtual void unwrapEncKey(std::istream &key_stream, IKeyPack &keypack);

    // eval key
    virtual void wrapEvalKey(const std::string &key_id, const std::string &key_path, const std::string &output_path);
    virtual void wrapEvalKey(const std::string &key_id, std::istream &key_stream, std::ostream &out_stream);

    virtual void unwrapEvalKey(const std::string &file_path, const std::string &output_path);
    virtual void unwrapEvalKey(std::istream &key_stream, std::ostream &out_stream);

    // metadata key (AES-256-GCM key material)
    virtual void wrapMetadataKey(const std::string &key_id, const std::string &key_path, const std::string &output_path,
                                 const SealInfo &s_info = SealInfo(SealMode::NONE));
    virtual void wrapMetadataKey(const std::string &key_id, std::istream &key_stream, std::ostream &out_stream,
                                 const SealInfo &s_info = SealInfo(SealMode::NONE));

    virtual void unwrapMetadataKey(const std::string &file_path, const std::string &output_path,
                                   const SealInfo &s_info = SealInfo(SealMode::NONE));
    virtual void unwrapMetadataKey(std::istream &key_stream, std::ostream &out_stream,
                                   const SealInfo &s_info = SealInfo(SealMode::NONE));

    // all keys
    virtual void wrapKeys(const std::string &key_id, const std::string &file_dir_path,
                          const SealInfo &s_info = SealInfo(SealMode::NONE));
    virtual void wrapKeys(const std::string &key_id, std::istream &key_stream,
                          const SealInfo &s_info = SealInfo(SealMode::NONE));

    virtual void unwrapKeys(const std::string &key_dir_path, const std::string &output_dir_path,
                            const SealInfo &s_info = SealInfo(SealMode::NONE));
    virtual void unwrapKeys(std::istream &key_stream, std::ostream &out_stream,
                            const SealInfo &s_info = SealInfo(SealMode::NONE));
    virtual void rotateSecKey(const std::string &storage_key_path, const SealInfo &old_s_info,
                              const SealInfo &new_s_info);
    virtual void deactivateSecKey(const std::string &storage_key_path, const std::string &reason);
    virtual void deactivatePubKey(const std::string &storage_key_path, const std::string &reason);
    virtual void destroySecKey(const std::string &storage_key_path, const std::string &reason);
    virtual void destroyPubKey(const std::string &storage_key_path, const std::string &reason);
    virtual void getSecKey(const std::string &storage_key_path, std::ostream &out_stream) = 0;
    virtual void getPubKey(const std::string &storage_key_path, std::ostream &out_stream) = 0;
    virtual void deleteSecKey(const std::string &storage_key_path) = 0;
    virtual void deletePubKey(const std::string &storage_key_path) = 0;
    virtual void putSecKey(const std::string &storage_key_path, std::istream &key_stream) = 0;
    virtual void putPubKey(const std::string &storage_key_path, std::istream &key_stream) = 0;
    virtual void updateSecKey(const std::string &storage_key_path, const std::string &envelope_text) = 0;
    virtual void updatePubKey(const std::string &storage_key_path, const std::string &envelope_text) = 0;
    virtual std::vector<std::string> listKeys(const std::string &prefix = "") = 0;
    virtual std::vector<std::string> listVersions(const std::string &storage_key_path);

    void setAuditStore(const std::string &path);
    void setAuditStore();

protected:
    const std::shared_ptr<KeyProvider> &provider() const;
    const KeyStorageConfig &storageConfig() const;
    AuditStore &auditor() const;

private:
    std::shared_ptr<KeyProvider> provider_;
    KeyStorageConfig storage_config_;
    std::shared_ptr<AuditStore> audit_store_;
};

std::shared_ptr<IKeyManagerImpl> makeLocalKeyManager(const KeyStorageConfig &storage_config);
std::shared_ptr<IKeyManagerImpl> makeVaultKeyManager(const KeyStorageConfig &storage_config);
std::shared_ptr<IKeyManagerImpl> makeAwsKeyManager(const KeyStorageConfig &storage_config);
std::shared_ptr<IKeyManagerImpl> makeGcpKeyManager(const KeyStorageConfig &storage_config);

class AwsKeyManagerImpl : public IKeyManagerImpl {
public:
    explicit AwsKeyManagerImpl(const KeyStorageConfig &storage_config);

    std::vector<std::string> listKeys(const std::string &prefix = "") override;
    void getSecKey(const std::string &storage_key_path, std::ostream &out_stream) override;
    void getPubKey(const std::string &storage_key_path, std::ostream &out_stream) override;
    void deleteSecKey(const std::string &storage_key_path) override;
    void deletePubKey(const std::string &storage_key_path) override;
    void updateSecKey(const std::string &storage_key_path, const std::string &envelope_text) override;
    void updatePubKey(const std::string &storage_key_path, const std::string &envelope_text) override;

protected:
    void putSecKey(const std::string &storage_key_path, std::istream &key_stream) override;
    void putPubKey(const std::string &storage_key_path, std::istream &key_stream) override;

private:
    void initializeAwsClients();

    AwsConfig meta_;
#if defined(EVI_KM_USE_AWS_SDK)
    std::shared_ptr<Aws::Auth::AWSCredentialsProvider> credentials_provider_;
    std::optional<Aws::Client::ClientConfiguration> client_config_;
    std::optional<Aws::S3::S3Client> s3_client_;
    std::optional<Aws::SecretsManager::SecretsManagerClient> secrets_manager_client_;
#endif
};

class VaultKeyManagerImpl : public IKeyManagerImpl {
public:
    explicit VaultKeyManagerImpl(const KeyStorageConfig &storage_config);

    std::vector<std::string> listKeys(const std::string &prefix = "") override;
    void getSecKey(const std::string &storage_key_path, std::ostream &out_stream) override;
    void getPubKey(const std::string &storage_key_path, std::ostream &out_stream) override;
    void destroySecKey(const std::string &storage_key_path, const std::string &reason) override;
    void destroyPubKey(const std::string &storage_key_path, const std::string &reason) override;
    void deleteSecKey(const std::string &storage_key_path) override;
    void deletePubKey(const std::string &storage_key_path) override;
    void updateSecKey(const std::string &storage_key_path, const std::string &envelope_text) override;
    void updatePubKey(const std::string &storage_key_path, const std::string &envelope_text) override;

protected:
    void putSecKey(const std::string &storage_key_path, std::istream &key_stream) override;
    void putPubKey(const std::string &storage_key_path, std::istream &key_stream) override;

private:
    VaultConfig meta_;
};

class GcpKeyManagerImpl : public IKeyManagerImpl {
public:
    explicit GcpKeyManagerImpl(const KeyStorageConfig &storage_config);

    std::vector<std::string> listKeys(const std::string &prefix = "") override;
    void getSecKey(const std::string &storage_key_path, std::ostream &out_stream) override;
    void getPubKey(const std::string &storage_key_path, std::ostream &out_stream) override;
    void deleteSecKey(const std::string &storage_key_path) override;
    void deletePubKey(const std::string &storage_key_path) override;
    void updateSecKey(const std::string &storage_key_path, const std::string &envelope_text) override;
    void updatePubKey(const std::string &storage_key_path, const std::string &envelope_text) override;

protected:
    void putSecKey(const std::string &storage_key_path, std::istream &key_stream) override;
    void putPubKey(const std::string &storage_key_path, std::istream &key_stream) override;

private:
    void initializeGcpState();
    GcpConfig meta_;
    std::string project_id_;
#if defined(EVI_KM_USE_GCP_SDK)
    std::optional<google::cloud::storage::Client> gcs_client_;
    std::optional<google::cloud::secretmanager_v1::SecretManagerServiceClient> secret_manager_client_;
#endif
};

std::shared_ptr<IKeyManagerImpl> makeKeyManager(const KeyStorageConfig &storage_config, const KeyFormatVersion version);
std::shared_ptr<IKeyManagerImpl> makeKeyManager(const KeyStorageConfig &storage_config);
std::shared_ptr<IKeyManagerImpl> makeKeyManager();

} // namespace detail
} // namespace evi
