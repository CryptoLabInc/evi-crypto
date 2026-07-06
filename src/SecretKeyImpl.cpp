////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//  Copyright (C) 2025, CryptoLab, Inc.                                       //
//                                                                            //
//  Licensed under the Apache License, Version 2.0 (the "License");           //
//  you may not use this file except in compliance with the License.          //
//  You may obtain a copy of the License at                                   //
//                                                                            //
//     http://www.apache.org/licenses/LICENSE-2.0                             //
//                                                                            //
//  Unless required by applicable law or agreed to in writing, software       //
//  distributed under the License is distributed on an "AS IS" BASIS,         //
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  //
//  See the License for the specific language governing permissions and       //
//  limitations under the License.                                            //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

#include "EVI/impl/SecretKeyImpl.hpp"
#include "utils/DebUtils.hpp"
#include "utils/Exceptions.hpp"
#include "utils/Utils.hpp"
#include "utils/security/Security.hpp"

#include <algorithm>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <new>
#include <sstream>
#include <stdexcept>
#include <utility>

#if defined(__linux__) || defined(__APPLE__)
#include <sys/mman.h>
#include <unistd.h>
#define EVI_SECRET_PAGE_PROTECT 1
#else
#define EVI_SECRET_PAGE_PROTECT 0
#endif

namespace evi {
namespace detail {

#if EVI_SECRET_PAGE_PROTECT
class SecretMemoryPages {
public:
    explicit SecretMemoryPages(const Context &context) : SecretMemoryPages(utils::getDebPreset(context)) {}

    explicit SecretMemoryPages(const deb::Preset preset) {
        coeff_ = allocate(sizeof(s_poly));
        key_q_ = allocate(sizeof(poly));
        key_p_ = allocate(sizeof(poly));
        deb_sk_ = allocate(sizeof(deb::SecretKey));
        new (deb_sk_.ptr) deb::SecretKey(preset);
    }

    ~SecretMemoryPages() {
        evi::security::setMemoryProtection(deb_sk_.ptr, sizeof(deb::SecretKey), PROT_READ | PROT_WRITE);
        reinterpret_cast<deb::SecretKey *>(deb_sk_.ptr)->~SecretKeyT();
        release(deb_sk_, sizeof(deb::SecretKey));
        release(coeff_, sizeof(s_poly));
        release(key_q_, sizeof(poly));
        release(key_p_, sizeof(poly));
    }

    s_poly &coeff() noexcept {
        return *reinterpret_cast<s_poly *>(coeff_.ptr);
    }

    poly &keyQ() noexcept {
        return *reinterpret_cast<poly *>(key_q_.ptr);
    }

    poly &keyP() noexcept {
        return *reinterpret_cast<poly *>(key_p_.ptr);
    }

    deb::SecretKey &debSk() noexcept {
        return *reinterpret_cast<deb::SecretKey *>(deb_sk_.ptr);
    }

    void protect() {
        evi::security::setMemoryProtection(coeff_.ptr, sizeof(s_poly), PROT_NONE);
        evi::security::setMemoryProtection(key_q_.ptr, sizeof(poly), PROT_NONE);
        evi::security::setMemoryProtection(key_p_.ptr, sizeof(poly), PROT_NONE);
        evi::security::setMemoryProtection(deb_sk_.ptr, sizeof(deb::SecretKey), PROT_NONE);
    }

    void unprotect() {
        evi::security::setMemoryProtection(coeff_.ptr, sizeof(s_poly), PROT_READ | PROT_WRITE);
        evi::security::setMemoryProtection(key_q_.ptr, sizeof(poly), PROT_READ | PROT_WRITE);
        evi::security::setMemoryProtection(key_p_.ptr, sizeof(poly), PROT_READ | PROT_WRITE);
        evi::security::setMemoryProtection(deb_sk_.ptr, sizeof(deb::SecretKey), PROT_READ | PROT_WRITE);
    }

private:
    struct Mapping {
        void *ptr = nullptr;
        std::size_t alloc_size = 0;
    };

    static Mapping allocate(std::size_t size) {
        const std::size_t ps = evi::security::pageSize();
        const std::size_t alloc_size = ((size + ps - 1) / ps) * ps;
        void *mem = ::mmap(nullptr, alloc_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (mem == MAP_FAILED) {
            throw std::runtime_error("mmap failed for SecretKey protected memory");
        }
        evi::security::secureZeroMemory(mem, size);
        return Mapping{mem, alloc_size};
    }

    static void release(Mapping &mapping, std::size_t logical_size) noexcept {
        if (mapping.ptr == nullptr) {
            return;
        }
        (void)::mprotect(mapping.ptr, mapping.alloc_size, PROT_READ | PROT_WRITE);
        evi::security::secureZeroMemory(mapping.ptr, logical_size);
        (void)::mprotect(mapping.ptr, mapping.alloc_size, PROT_NONE);
        (void)::munmap(mapping.ptr, mapping.alloc_size);
        mapping.ptr = nullptr;
        mapping.alloc_size = 0;
    }

    Mapping coeff_{};
    Mapping key_q_{};
    Mapping key_p_{};
    Mapping deb_sk_{};
};
#else
class SecretMemoryPages {
public:
    explicit SecretMemoryPages(const Context &context) : SecretMemoryPages(utils::getDebPreset(context)) {}

    explicit SecretMemoryPages(const deb::Preset preset) {
        coeff_ = std::make_unique<s_poly>();
        key_q_ = std::make_unique<poly>();
        key_p_ = std::make_unique<poly>();
        deb_sk_ = std::make_unique<deb::SecretKey>(preset);
    }

    ~SecretMemoryPages() {
        if (coeff_) {
            evi::security::secureZeroMemory(coeff_->data(), sizeof(s_poly));
        }
        if (key_q_) {
            evi::security::secureZeroMemory(key_q_->data(), sizeof(poly));
        }
        if (key_p_) {
            evi::security::secureZeroMemory(key_p_->data(), sizeof(poly));
        }
        if (deb_sk_) {
            evi::security::secureZeroMemory(deb_sk_->coeffs(), DEGREE * sizeof(int8_t));
        }
    }

    s_poly &coeff() noexcept {
        return *coeff_;
    }

    poly &keyQ() noexcept {
        return *key_q_;
    }

    poly &keyP() noexcept {
        return *key_p_;
    }

    deb::SecretKey &debSk() noexcept {
        return *deb_sk_;
    }

    void protect() {}
    void unprotect() {}

private:
    std::unique_ptr<s_poly> coeff_;
    std::unique_ptr<poly> key_q_;
    std::unique_ptr<poly> key_p_;
    std::unique_ptr<deb::SecretKey> deb_sk_;
};
#endif

SecretKeyData::SecretKeyData(const Context &context)
    : secret_mem_(std::make_unique<SecretMemoryPages>(context)), sec_coeff_(secret_mem_->coeff()),
      sec_key_q_(secret_mem_->keyQ()), sec_key_p_(secret_mem_->keyP()), deb_sk_(secret_mem_->debSk()) {
    preset_ = context->getParam()->getPreset();
    s_info_ = SealInfo(SealMode::NONE);
    sec_loaded_ = false;
    secret_mem_->protect();
}

SecretKeyData::SecretKeyData(const std::string &path, const std::optional<SealInfo> &s_info)
    : secret_mem_(std::make_unique<SecretMemoryPages>(deb::PRESET_EVI_IP0)), sec_coeff_(secret_mem_->coeff()),
      sec_key_q_(secret_mem_->keyQ()), sec_key_p_(secret_mem_->keyP()), deb_sk_(secret_mem_->debSk()) {

    s_info_ = s_info;
    sec_loaded_ = false;
    secret_mem_->unprotect();
    if (s_info_.has_value() && s_info_.value().s_mode != SealMode::NONE) {
        teew_.emplace(s_info_.value());
    }
    if (!s_info.has_value() || s_info->s_mode == SealMode::NONE) {
        loadSecKey(path);
    } else {
        loadSealedSecKey(path);
    }
    secret_mem_->protect();
}

SecretKeyData::SecretKeyData(std::istream &stream, const std::optional<SealInfo> &s_info)
    : secret_mem_(std::make_unique<SecretMemoryPages>(deb::PRESET_EVI_IP0)), sec_coeff_(secret_mem_->coeff()),
      sec_key_q_(secret_mem_->keyQ()), sec_key_p_(secret_mem_->keyP()), deb_sk_(secret_mem_->debSk()) {
    s_info_ = s_info;
    sec_loaded_ = false;
    secret_mem_->unprotect();
    if (s_info_.has_value() && s_info_.value().s_mode != SealMode::NONE) {
        teew_.emplace(s_info_.value());
    }
    if (!s_info_.has_value() || s_info_.value().s_mode == SealMode::NONE) {
        loadSecKey(stream);
    } else {
        loadSealedSecKey(stream);
    }
    secret_mem_->protect();
}

SecretKeyData::~SecretKeyData() {
    reset();
}

void SecretKeyData::openAccess() {
    std::lock_guard<std::mutex> lock(access_mtx_);
    if (open_count_ == 0) {
        secret_mem_->unprotect();
    }
    ++open_count_;
}

void SecretKeyData::closeAccess() noexcept {
    std::lock_guard<std::mutex> lock(access_mtx_);
    if (open_count_ <= 0) {
        return;
    }

    if (--open_count_ == 0) {
        try {
            secret_mem_->protect();
        } catch (...) {
        }
    }
}

void SecretKeyData::reset() noexcept {
    std::lock_guard<std::mutex> lock(access_mtx_);
    try {
        secret_mem_->unprotect();
    } catch (...) {
    }
    evi::security::secureZeroMemory(sec_coeff_.data(), sizeof(sec_coeff_));
    evi::security::secureZeroMemory(sec_key_q_.data(), sizeof(sec_key_q_));
    evi::security::secureZeroMemory(sec_key_p_.data(), sizeof(sec_key_p_));
    evi::security::secureZeroMemory(deb_sk_.coeffs(), DEGREE * sizeof(int8_t));
    sec_loaded_ = false;
    clearDerivedDebSecKeyCache();
    try {
        secret_mem_->protect();
    } catch (...) {
    }
}

bool hasBinExtension(const std::string &path) {
    static constexpr const char *K_EXT = ".bin";
    const std::size_t ext_len = 4;
    return path.size() >= ext_len && path.compare(path.size() - ext_len, ext_len, K_EXT) == 0;
}

void SecretKeyData::clearDerivedDebSecKeyCache() const noexcept {
    direct_root_deb_sk_.clear();
    deb_sk32_.clear();
    direct_root_deb_sk32_.clear();
}

const deb::SecretKey32 &SecretKeyData::getDirectRootDebSecKey32(deb::Preset preset) const {
    std::lock_guard<std::mutex> lock(access_mtx_);
    return direct_root_deb_sk32_.getOrBuild(preset, [this](deb::Preset p) {
        return utils::makeDirectRootDebSecretKey<deb::u32>(p, deb_sk_);
    });
}

const deb::SecretKey32 &SecretKeyData::getDebSecKey32(deb::Preset preset) const {
    std::lock_guard<std::mutex> lock(access_mtx_);
    // Default root, like genSecKey — same secret's u32 embedding for Encryptor/KeyGenerator.
    return deb_sk32_.getOrBuild(preset, [this](deb::Preset p) {
        return utils::makeDebSecretKey<deb::u32>(p, deb_sk_);
    });
}

const deb::SecretKey &SecretKeyData::getDirectRootDebSecKey(deb::Preset preset) const {
    std::lock_guard<std::mutex> lock(access_mtx_);
    return direct_root_deb_sk_.getOrBuild(preset, [this](deb::Preset p) {
        return utils::makeDirectRootDebSecretKey<deb::u64>(p, deb_sk_);
    });
}

void SecretKeyData::loadSecKey(const std::string &dir_path) {
    if (hasBinExtension(dir_path)) {
        std::ifstream in(dir_path, std::ios::in | std::ios_base::binary);
        if (!in.is_open()) {
            throw evi::FileNotFoundError("Failed to load secret key");
        }
        loadSecKey(in);
        in.close();
    } else {
        std::istringstream key_stream(dir_path, std::ios::binary);
        loadSecKey(key_stream);
    }
}

void SecretKeyData::loadSecKey(std::istream &in) {
    SecretKeyAccessScope scoped_access(*this);
    clearDerivedDebSecKeyCache();
    in.read(reinterpret_cast<char *>(&sec_loaded_), sizeof(bool));
    if (sec_loaded_) {
        char preset_buf[4];
        in.read(preset_buf, sizeof(preset_buf));
        preset_ = utils::stringToPreset(preset_buf);

        std::vector<u8> bytes_2bit(DEGREE / 4);
        in.read(reinterpret_cast<char *>(bytes_2bit.data()), bytes_2bit.size());
        for (int i = 0; i < DEGREE / 4; ++i) {
            int d_idx = i * 4;
            u8 b = bytes_2bit[i];
            u8 c0 = (b >> 6) & 0x03;
            u8 c1 = (b >> 4) & 0x03;
            u8 c2 = (b >> 2) & 0x03;
            u8 c3 = (b >> 0) & 0x03;
            sec_coeff_[d_idx + 0] = c0 | (-(c0 >> 1));
            sec_coeff_[d_idx + 1] = c1 | (-(c1 >> 1));
            sec_coeff_[d_idx + 2] = c2 | (-(c2 >> 1));
            sec_coeff_[d_idx + 3] = c3 | (-(c3 >> 1));
        }
        for (u64 i = 0; i < DEGREE; ++i) {
            deb_sk_.coeffs()[i] = static_cast<int8_t>(sec_coeff_[i]);
        }
        auto deb_preset = utils::getDebPreset(preset_buf);
        deb_sk_ = utils::makeDebSecretKey<deb::u64>(deb_preset, deb_sk_);
        std::memcpy(sec_key_q_.data(), deb_sk_[0][0].data(), detail::U64_DEGREE);
        std::memcpy(sec_key_p_.data(), deb_sk_[0][1].data(), detail::U64_DEGREE);
    } else {
        throw evi::KeyNotLoadedError("Failed to load to secret key from buffer");
    }
}

void SecretKeyData::deserialize(std::istream &in) {
    loadSecKey(in);
}

void SecretKeyData::saveSecKey(const std::string &dir_path) const {
    std::ofstream out(dir_path, std::ios::out | std::ios_base::binary);
    if (!out.is_open()) {
        throw evi::FileNotFoundError("Failed to save secret key");
    }
    saveSecKey(out);
    out.close();
}

void SecretKeyData::saveSecKey(std::ostream &out) const {
    SecretKeyAccessScope scoped_access(*const_cast<SecretKeyData *>(this));
    if (!sec_loaded_) {
        throw evi::KeyNotLoadedError("Secret key is not loaded to be saved");
    }
    std::string preset_str = utils::assignParameterString(preset_);
    preset_str.resize(4, '\0');
    char byte = 0x01;
    out.write(&byte, sizeof(byte));
    out.write(preset_str.data(), preset_str.size());

    std::vector<u8> bytes_2bit(DEGREE / 4, 0);
    for (int i = 0; i < DEGREE / 4; i++) {
        int d_idx = i * 4;
        u8 c0 = static_cast<u8>(sec_coeff_.data()[d_idx + 0]) & 0x03;
        u8 c1 = static_cast<u8>(sec_coeff_.data()[d_idx + 1]) & 0x03;
        u8 c2 = static_cast<u8>(sec_coeff_.data()[d_idx + 2]) & 0x03;
        u8 c3 = static_cast<u8>(sec_coeff_.data()[d_idx + 3]) & 0x03;
        bytes_2bit[i] = static_cast<u8>((c0 << 6) | (c1 << 4) | (c2 << 2) | (c3 << 0));
    }
    out.write(reinterpret_cast<const char *>(bytes_2bit.data()), bytes_2bit.size());
}

void SecretKeyData::serialize(std::ostream &out) const {
    saveSecKey(out);
}

void SecretKeyData::loadSealedSecKey(const std::string &dir_path) {
    std::ifstream sealed_sec_key(dir_path, std::ios::in | std::ios_base::binary);
    if (!sealed_sec_key.is_open()) {
        throw evi::FileNotFoundError("Failed to load secret key");
    }
    loadSealedSecKey(sealed_sec_key);
    sealed_sec_key.close();
}

void SecretKeyData::loadSealedSecKey(std::istream &is) {
    std::stringstream unsealed_seckey;
    switch (s_info_.value().s_mode) {
    case SealMode::AES_KEK: {
        teew_->getUnsealedSecKey(is, preset_, unsealed_seckey, s_info_.value().kek);
        break;
    }
    case SealMode::HSM_PORT:
    case SealMode::HSM_SERIAL:
#ifdef BUILD_YUBIHSM
        teew_->getUnsealedSecKeyHSM(is, preset, unsealed_seckey);
        break;
#else
        throw evi::EviError("YubiHSM support is not enabled");
#endif
    default:
        throw evi::EviError("Invalid seal mode");
    }
    loadSecKey(unsealed_seckey);
    return;
}

void SecretKeyData::saveSealedSecKey(const std::string &dir_path) {
    std::ofstream sealed_sec_key(dir_path, std::ios::out | std::ios_base::binary);
    if (!sealed_sec_key.is_open()) {
        throw evi::FileNotFoundError("Failed to save secret key");
    }
    if (!sec_loaded_) {
        throw evi::KeyNotLoadedError("Secret key is not loaded to be saved");
    }

    std::stringstream serialized_sec_key;
    saveSecKey(serialized_sec_key);
    switch (s_info_.value().s_mode) {
    case SealMode::AES_KEK: {
        teew_->saveSealedSecKey(sealed_sec_key, preset_, serialized_sec_key, s_info_.value().kek);
        break;
    }
    case SealMode::HSM_PORT:
    case SealMode::HSM_SERIAL:
#ifdef BUILD_YUBIHSM
        teew_->saveSealedSecKeyHSM(sealed_sec_key, &presetType, serialized_sec_key);
        break;
#else
        throw evi::EviError("YubiHSM support is not enabled");
#endif
    default:
        throw evi::EviError("Invalid Seal Mode");
    }
    sealed_sec_key.close();

    fs::permissions(dir_path, fs::perms::owner_read | fs::perms::owner_write, fs::perm_options::replace);
}

void SecretKeyData::saveSealedSecKey(std::ostream &os) {
    if (!s_info_.has_value()) {
        throw evi::KeyNotLoadedError("Seal info missing for sealed secret key");
    }
    if (!sec_loaded_) {
        throw evi::KeyNotLoadedError("Secret key is not loaded to be saved");
    }

    std::stringstream serialized_sec_key;
    saveSecKey(serialized_sec_key);
    switch (s_info_.value().s_mode) {
    case SealMode::AES_KEK:
        teew_->saveSealedSecKey(os, preset_, serialized_sec_key, s_info_.value().kek);
        break;
    case SealMode::HSM_PORT:
    case SealMode::HSM_SERIAL:
#ifdef BUILD_YUBIHSM
        teew_->saveSealedSecKeyHSM(os, &presetType, serialized_sec_key);
        break;
#else
        throw evi::EviError("YubiHSM support is not enabled");
#endif
    default:
        throw evi::EviError("Invalid Seal Mode");
    }
}

SecretKey makeSecKey(const Context &context) {
    return std::make_shared<SecretKeyData>(context);
}

SecretKey makeSecKey(const std::string &path, const std::optional<SealInfo> &s_info) {
    return std::make_shared<SecretKeyData>(path, s_info);
}

SecretKey makeSecKey(std::istream &stream, const std::optional<SealInfo> &s_info) {
    return std::make_shared<SecretKeyData>(stream, s_info);
}

SecretKeyAccessScope::SecretKeyAccessScope(SecretKeyData &secret_key)
    : SecretKeyAccessScope(std::shared_ptr<SecretKeyData>(&secret_key, [](SecretKeyData *) {})) {}

SecretKeyAccessScope::SecretKeyAccessScope(const SecretKey &key)
    : SecretKeyAccessScope(std::shared_ptr<SecretKeyData>(key)) {}

SecretKeyAccessScope::SecretKeyAccessScope(const std::shared_ptr<SecretKeyData> &key) : key_(key) {
    if (key_ != nullptr) {
        key_->openAccess();
    }
}

SecretKeyAccessScope::~SecretKeyAccessScope() {
    if (key_ != nullptr) {
        key_->closeAccess();
    }
}

SecretKeyAccessScope::SecretKeyAccessScope(SecretKeyAccessScope &&other) noexcept : key_(std::move(other.key_)) {}

SecretKeyAccessScope &SecretKeyAccessScope::operator=(SecretKeyAccessScope &&other) noexcept {
    if (this != &other) {
        if (key_ != nullptr) {
            key_->closeAccess();
        }
        key_ = std::exchange(other.key_, nullptr);
    }
    return *this;
}

} // namespace detail
} // namespace evi
