
#include "EVI/impl/KeyPackImpl.hpp"

#include "km/KeyManager.hpp"
#include "km/KeyManagerInterface.hpp"

#include "utils/Exceptions.hpp"
#include "utils/SealInfo.hpp"
#include "utils/security/Security.hpp"

#include <iostream>
#include <utility>

namespace evi {

KeyManager::KeyManager(std::shared_ptr<detail::IKeyManagerImpl> impl) noexcept : impl_(std::move(impl)) {}

KeyManager makeKeyManager() {
    evi::security::ensureCoreDumpGuard();
    return KeyManager(detail::makeKeyManager());
}

KeyManager makeKeyManager(const KeyStorageConfig &storage_config) {
    evi::security::ensureCoreDumpGuard();
    return KeyManager(detail::makeKeyManager(storage_config));
}

/**
 * seckey
 */
void KeyManager::wrapSecKey(const std::string &key_id, const std::string &key_file_path,
                            const std::string &output_file_path, const SealInfo &s_info) {
    impl_->wrapSecKey(key_id, key_file_path, output_file_path, *getImpl(s_info));
}
void KeyManager::wrapSecKey(const std::string &key_id, std::istream &key_stream, std::ostream &out_stream,
                            const SealInfo &s_info) {
    impl_->wrapSecKey(key_id, key_stream, out_stream, *getImpl(s_info));
}
void KeyManager::wrapSecKey(const std::string &key_id, const evi::SecretKey &seckey, std::ostream &out_stream,
                            const SealInfo &s_info) {
    impl_->wrapSecKey(key_id, *getImpl(seckey), out_stream, *getImpl(s_info));
}
void KeyManager::unwrapSecKey(const std::string &file_path, const std::string &output_file_path,
                              const SealInfo &s_info) {
    impl_->unwrapSecKey(file_path, output_file_path, *getImpl(s_info));
}
void KeyManager::unwrapSecKey(std::istream &key_stream, std::ostream &out_stream, const SealInfo &s_info) {
    impl_->unwrapSecKey(key_stream, out_stream, *getImpl(s_info));
}
void KeyManager::unwrapSecKey(std::istream &key_stream, evi::SecretKey &seckey, const SealInfo &s_info) {
    impl_->unwrapSecKey(key_stream, *getImpl(seckey), *getImpl(s_info));
}

/**
 * enckey
 */
void KeyManager::wrapEncKey(const std::string &key_id, const std::string &key_file_path,
                            const std::string &output_file_path) {
    impl_->wrapEncKey(key_id, key_file_path, output_file_path);
}
void KeyManager::wrapEncKey(const std::string &key_id, std::istream &key_stream, std::ostream &out_stream) {
    impl_->wrapEncKey(key_id, key_stream, out_stream);
}
void KeyManager::wrapEncKey(const std::string &key_id, const evi::KeyPack &keypack, std::ostream &out_stream) {
    impl_->wrapEncKey(key_id, *getImpl(keypack), out_stream);
}
void KeyManager::unwrapEncKey(const std::string &key_file_path, const std::string &output_file_path) {
    impl_->unwrapEncKey(key_file_path, output_file_path);
}
void KeyManager::unwrapEncKey(std::istream &key_stream, std::ostream &out_stream) {
    impl_->unwrapEncKey(key_stream, out_stream);
}
void KeyManager::unwrapEncKey(std::istream &key_stream, evi::KeyPack &keypack) {
    impl_->unwrapEncKey(key_stream, *getImpl(keypack));
}

/**
 * evalkey
 */
void KeyManager::wrapEvalKey(const std::string &key_id, const std::string &key_file_path,
                             const std::string &output_file_path) {
    impl_->wrapEvalKey(key_id, key_file_path, output_file_path);
}
void KeyManager::wrapEvalKey(const std::string &key_id, std::istream &key_stream, std::ostream &out_stream) {
    impl_->wrapEvalKey(key_id, key_stream, out_stream);
}
void KeyManager::unwrapEvalKey(const std::string &key_file_path, const std::string &output_file_path) {
    impl_->unwrapEvalKey(key_file_path, output_file_path);
}
void KeyManager::unwrapEvalKey(std::istream &key_stream, std::ostream &out_stream) {
    impl_->unwrapEvalKey(key_stream, out_stream);
}

/**
 * metadata key
 */
void KeyManager::wrapMetadataKey(const std::string &key_id, const std::string &key_file_path,
                                 const std::string &output_file_path, const SealInfo &s_info) {
    impl_->wrapMetadataKey(key_id, key_file_path, output_file_path, *getImpl(s_info));
}
void KeyManager::wrapMetadataKey(const std::string &key_id, std::istream &key_stream, std::ostream &out_stream,
                                 const SealInfo &s_info) {
    impl_->wrapMetadataKey(key_id, key_stream, out_stream, *getImpl(s_info));
}
void KeyManager::unwrapMetadataKey(const std::string &key_file_path, const std::string &output_file_path,
                                   const SealInfo &s_info) {
    impl_->unwrapMetadataKey(key_file_path, output_file_path, *getImpl(s_info));
}
void KeyManager::unwrapMetadataKey(std::istream &key_stream, std::ostream &out_stream, const SealInfo &s_info) {
    impl_->unwrapMetadataKey(key_stream, out_stream, *getImpl(s_info));
}

/**
 * all keys
 */
void KeyManager::wrapKeys(const std::string &key_id, const std::string &file_dir_path, const SealInfo &s_info) {
    impl_->wrapKeys(key_id, file_dir_path, *getImpl(s_info));
}
void KeyManager::wrapKeys(const std::string &key_id, std::istream &key_stream, const SealInfo &s_info) {
    impl_->wrapKeys(key_id, key_stream, *getImpl(s_info));
}
void KeyManager::unwrapKeys(const std::string &file_path, const std::string &output_file_path, const SealInfo &s_info) {
    impl_->unwrapKeys(file_path, output_file_path, *getImpl(s_info));
}
void KeyManager::unwrapKeys(std::istream &key_stream, std::ostream &out_stream, const SealInfo &s_info) {
    impl_->unwrapKeys(key_stream, out_stream, *getImpl(s_info));
}

void KeyManager::rotateSecKey(const std::string &storage_key_path, const SealInfo &old_s_info,
                              const SealInfo &new_s_info) {
    impl_->rotateSecKey(storage_key_path, *getImpl(old_s_info), *getImpl(new_s_info));
}

void KeyManager::deactivateSecKey(const std::string &storage_key_path, const std::string &reason) {
    impl_->deactivateSecKey(storage_key_path, reason);
}

void KeyManager::deactivatePubKey(const std::string &storage_key_path, const std::string &reason) {
    impl_->deactivatePubKey(storage_key_path, reason);
}

void KeyManager::destroySecKey(const std::string &storage_key_path, const std::string &reason) {
    impl_->destroySecKey(storage_key_path, reason);
}

void KeyManager::destroyPubKey(const std::string &storage_key_path, const std::string &reason) {
    impl_->destroyPubKey(storage_key_path, reason);
}

std::vector<std::string> KeyManager::listKeys(const std::string &prefix) {
    return impl_->listKeys(prefix);
}

void KeyManager::getSecKey(const std::string &storage_key_path, std::ostream &out_stream) {
    impl_->getSecKey(storage_key_path, out_stream);
}

void KeyManager::getPubKey(const std::string &storage_key_path, std::ostream &out_stream) {
    impl_->getPubKey(storage_key_path, out_stream);
}

void KeyManager::deleteSecKey(const std::string &storage_key_path) {
    std::clog << "Warning: deleteSecKey permanently removes key material and metadata. "
                 "Use destroySecKey for lifecycle destruction.\n";
    impl_->deleteSecKey(storage_key_path);
}

void KeyManager::deletePubKey(const std::string &storage_key_path) {
    std::clog << "Warning: deletePubKey permanently removes key material and metadata. "
                 "Use destroyPubKey for lifecycle destruction.\n";
    impl_->deletePubKey(storage_key_path);
}

void KeyManager::putSecKey(const std::string &storage_key_path, std::istream &key_stream) {
    impl_->putSecKey(storage_key_path, key_stream);
}

void KeyManager::putPubKey(const std::string &storage_key_path, std::istream &key_stream) {
    impl_->putPubKey(storage_key_path, key_stream);
}

void KeyManager::setAuditStore(const std::string &path) {
    impl_->setAuditStore(path);
}

void KeyManager::setAuditStore() {
    impl_->setAuditStore();
}

std::vector<std::string> KeyManager::listVersions(const std::string &storage_key_path) {
    return impl_->listVersions(storage_key_path);
}

} // namespace evi
