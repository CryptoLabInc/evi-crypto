
#include "EVI/impl/KeyPackImpl.hpp"

#include "km/KeyManager.hpp"
#include "km/KeyManagerInterface.hpp"

#include "utils/Exceptions.hpp"
#include "utils/SealInfo.hpp"

#include <iostream>
#include <utility>

namespace evi {

KeyManager::KeyManager(std::shared_ptr<detail::KeyManager> impl) noexcept : impl_(std::move(impl)) {}

KeyManager makeKeyManager() {
    return KeyManager(std::make_shared<detail::KeyManager>(detail::makeKeyManager()));
}

KeyManager makeKeyManager(const ProviderMeta &provider_meta) {
    return KeyManager(std::make_shared<detail::KeyManager>(detail::makeKeyManager(provider_meta)));
}

/**
 * seckey
 */
void KeyManager::wrapSecKey(const std::string &key_id, const std::string &key_file_path,
                            const std::string &output_file_path) {
    (*impl_)->wrapSecKey(key_id, key_file_path, output_file_path);
}
void KeyManager::wrapSecKey(const std::string &key_id, std::istream &key_stream, std::ostream &out_stream) {
    (*impl_)->wrapSecKey(key_id, key_stream, out_stream);
}
void KeyManager::wrapSecKey(const std::string &key_id, const evi::SecretKey &seckey, std::ostream &out_stream) {
    (*impl_)->wrapSecKey(key_id, *getImpl(seckey), out_stream);
}
void KeyManager::unwrapSecKey(const std::string &file_path, const std::string &output_file_path,
                              const std::optional<SealInfo> &s_info) {
    if (s_info) {
        (*impl_)->unwrapSecKey(file_path, output_file_path, *getImpl(*s_info));
    } else {
        detail::SealInfo default_info(SealMode::NONE);
        (*impl_)->unwrapSecKey(file_path, output_file_path, default_info);
    }
}
void KeyManager::unwrapSecKey(std::istream &key_stream, std::ostream &out_stream,
                              const std::optional<SealInfo> &s_info) {
    if (s_info) {
        (*impl_)->unwrapSecKey(key_stream, out_stream, *getImpl(*s_info));
    } else {
        detail::SealInfo default_info(SealMode::NONE);
        (*impl_)->unwrapSecKey(key_stream, out_stream, default_info);
    }
}
void KeyManager::unwrapSecKey(std::istream &key_stream, evi::SecretKey &seckey, const std::optional<SealInfo> &s_info) {
    if (s_info) {
        (*impl_)->unwrapSecKey(key_stream, *getImpl(seckey), *getImpl(*s_info));
    } else {
        detail::SealInfo default_info(SealMode::NONE);
        (*impl_)->unwrapSecKey(key_stream, *getImpl(seckey), default_info);
    }
}

/**
 * enckey
 */
void KeyManager::wrapEncKey(const std::string &key_id, const std::string &key_file_path,
                            const std::string &output_file_path) {
    (*impl_)->wrapEncKey(key_id, key_file_path, output_file_path);
}
void KeyManager::wrapEncKey(const std::string &key_id, std::istream &key_stream, std::ostream &out_stream) {
    (*impl_)->wrapEncKey(key_id, key_stream, out_stream);
}
void KeyManager::wrapEncKey(const std::string &key_id, const evi::KeyPack &keypack, std::ostream &out_stream) {
    (*impl_)->wrapEncKey(key_id, *getImpl(keypack), out_stream);
}
void KeyManager::unwrapEncKey(const std::string &key_file_path, const std::string &output_file_path) {
    (*impl_)->unwrapEncKey(key_file_path, output_file_path);
}
void KeyManager::unwrapEncKey(std::istream &key_stream, std::ostream &out_stream) {
    (*impl_)->unwrapEncKey(key_stream, out_stream);
}
void KeyManager::unwrapEncKey(std::istream &key_stream, evi::KeyPack &keypack) {
    (*impl_)->unwrapEncKey(key_stream, *getImpl(keypack));
}

/**
 * evalkey
 */
void KeyManager::wrapEvalKey(const std::string &key_id, const std::string &key_file_path,
                             const std::string &output_file_path) {
    (*impl_)->wrapEvalKey(key_id, key_file_path, output_file_path);
}
void KeyManager::wrapEvalKey(const std::string &key_id, std::istream &key_stream, std::ostream &out_stream) {
    (*impl_)->wrapEvalKey(key_id, key_stream, out_stream);
}
void KeyManager::unwrapEvalKey(const std::string &key_file_path, const std::string &output_file_path) {
    (*impl_)->unwrapEvalKey(key_file_path, output_file_path);
}
void KeyManager::unwrapEvalKey(std::istream &key_stream, std::ostream &out_stream) {
    (*impl_)->unwrapEvalKey(key_stream, out_stream);
}

/**
 * all keys
 */
void KeyManager::wrapKeys(const std::string &key_id, const std::string &file_dir_path) {
    (*impl_)->wrapKeys(key_id, file_dir_path);
}
void KeyManager::wrapKeys(const std::string &key_id, std::istream &key_stream) {
    (*impl_)->wrapKeys(key_id, key_stream);
}
void KeyManager::unwrapKeys(const std::string &file_path, const std::string &output_file_path) {
    (*impl_)->unwrapKeys(file_path, output_file_path);
}
void KeyManager::unwrapKeys(std::istream &key_stream, std::ostream &out_stream) {
    (*impl_)->unwrapKeys(key_stream, out_stream);
}

} // namespace evi
