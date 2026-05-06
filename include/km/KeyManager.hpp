////////////////////////////////////////////////////////////////////////////////
//                                                                            //
// Copyright (C) 2021-2024, CryptoLab Inc. All rights reserved.               //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#pragma once

#include "EVI/Export.hpp"
#include "EVI/KeyPack.hpp"
#include "EVI/SealInfo.hpp"
#include "EVI/SecretKey.hpp"
#include "km/KeyStorageConfig.hpp"

#include <istream>
#include <memory>
#include <optional>
#include <ostream>
#include <string>
#include <vector>

namespace evi {

namespace detail {
class IKeyManagerImpl;
}

class EVI_API KeyManager {
public:
    KeyManager() = delete;

    explicit KeyManager(std::shared_ptr<detail::IKeyManagerImpl> impl) noexcept;

    // seckey
    void wrapSecKey(const std::string &key_id, const std::string &key_path, const std::string &output_path,
                    const SealInfo &s_info = SealInfo(SealMode::NONE));
    void wrapSecKey(const std::string &key_id, std::istream &key_stream, std::ostream &out_stream,
                    const SealInfo &s_info = SealInfo(SealMode::NONE));
    void wrapSecKey(const std::string &key_id, const evi::SecretKey &seckey, std::ostream &out_stream,
                    const SealInfo &s_info = SealInfo(SealMode::NONE));

    void unwrapSecKey(const std::string &file_path, const std::string &output_path,
                      const SealInfo &s_info = SealInfo(SealMode::NONE));
    void unwrapSecKey(std::istream &key_stream, std::ostream &out_stream,
                      const SealInfo &s_info = SealInfo(SealMode::NONE));
    void unwrapSecKey(std::istream &key_stream, evi::SecretKey &seckey,
                      const SealInfo &s_info = SealInfo(SealMode::NONE));

    // enckey
    void wrapEncKey(const std::string &key_id, const std::string &key_path, const std::string &output_path);
    void wrapEncKey(const std::string &key_id, std::istream &key_stream, std::ostream &out_stream);
    void wrapEncKey(const std::string &key_id, const evi::KeyPack &keypack, std::ostream &out_stream);

    void unwrapEncKey(const std::string &file_path, const std::string &output_path);
    void unwrapEncKey(std::istream &key_stream, std::ostream &out_stream);
    void unwrapEncKey(std::istream &key_stream, evi::KeyPack &keypack);

    // evalkey
    void wrapEvalKey(const std::string &key_id, const std::string &key_path, const std::string &output_path);
    void wrapEvalKey(const std::string &key_id, std::istream &key_stream, std::ostream &out_stream);

    void unwrapEvalKey(const std::string &file_path, const std::string &output_path);
    void unwrapEvalKey(std::istream &key_stream, std::ostream &out_stream);

    // metadata key (AES-256-GCM key material)
    void wrapMetadataKey(const std::string &key_id, const std::string &key_path, const std::string &output_path,
                         const SealInfo &s_info = SealInfo(SealMode::NONE));
    void wrapMetadataKey(const std::string &key_id, std::istream &key_stream, std::ostream &out_stream,
                         const SealInfo &s_info = SealInfo(SealMode::NONE));

    void unwrapMetadataKey(const std::string &file_path, const std::string &output_path,
                           const SealInfo &s_info = SealInfo(SealMode::NONE));
    void unwrapMetadataKey(std::istream &key_stream, std::ostream &out_stream,
                           const SealInfo &s_info = SealInfo(SealMode::NONE));

    // all keys
    void wrapKeys(const std::string &key_id, const std::string &file_dir_path,
                  const SealInfo &s_info = SealInfo(SealMode::NONE));
    void wrapKeys(const std::string &key_id, std::istream &file_stream,
                  const SealInfo &s_info = SealInfo(SealMode::NONE));
    void unwrapKeys(const std::string &file_dir_path, const std::string &output_dir_path,
                    const SealInfo &s_info = SealInfo(SealMode::NONE));
    void unwrapKeys(std::istream &key_stream, std::ostream &out_stream,
                    const SealInfo &s_info = SealInfo(SealMode::NONE));

    void rotateSecKey(const std::string &storage_key_path, const SealInfo &old_s_info, const SealInfo &new_s_info);
    void deactivateSecKey(const std::string &storage_key_path, const std::string &reason);
    void deactivatePubKey(const std::string &storage_key_path, const std::string &reason);
    void destroySecKey(const std::string &storage_key_path, const std::string &reason);
    void destroyPubKey(const std::string &storage_key_path, const std::string &reason);

    // storage operations
    void getSecKey(const std::string &storage_key_path, std::ostream &out_stream);
    void getPubKey(const std::string &storage_key_path, std::ostream &out_stream);
    void deleteSecKey(const std::string &storage_key_path);
    void deletePubKey(const std::string &storage_key_path);
    void putSecKey(const std::string &storage_key_path, std::istream &key_stream);
    void putPubKey(const std::string &storage_key_path, std::istream &key_stream);
    std::vector<std::string> listKeys(const std::string &prefix = "");
    std::vector<std::string> listVersions(const std::string &storage_key_path);

    void setAuditStore(const std::string &path);
    void setAuditStore();

private:
    std::shared_ptr<detail::IKeyManagerImpl> impl_;
};

EVI_API KeyManager makeKeyManager();
EVI_API KeyManager makeKeyManager(const KeyStorageConfig &storage_config);

} // namespace evi
