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

#pragma once

#include "EVI/impl/CKKSTypes.hpp"
#include "EVI/impl/Const.hpp"
#include "EVI/impl/ContextImpl.hpp"
#include "EVI/impl/NTT.hpp"
#include "EVI/impl/Type.hpp"
#include "utils/SealInfo.hpp"
#include "utils/crypto/TEEWrapper.hpp"

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <istream>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <utility>
#include <vector>

// deb header
#include <deb/CKKSTypes.hpp>
#include <deb/Serialize.hpp>

namespace evi {

namespace fs = std::filesystem;

namespace detail {

class SecretMemoryPages;
class SecretKey;

struct SecretKeyData {
    SecretKeyData(const evi::detail::Context &context);
    SecretKeyData(const std::string &path, const std::optional<SealInfo> &s_info = std::nullopt);
    SecretKeyData(std::istream &stream, const std::optional<SealInfo> &s_info = std::nullopt);
    ~SecretKeyData();

    void openAccess();
    void closeAccess() noexcept;

    void loadSecKey(const std::string &dir_path);
    void loadSecKey(std::istream &is);
    void saveSecKey(const std::string &dir_path) const;
    void saveSecKey(std::ostream &os) const;

    void loadSealedSecKey(const std::string &dir_path);
    void loadSealedSecKey(std::istream &is);
    void saveSealedSecKey(const std::string &dir_path);
    void saveSealedSecKey(std::ostream &os);

    void serialize(std::ostream &os) const;
    void deserialize(std::istream &is);

    s_poly &getCoeff() {
        return sec_coeff_;
    }
    const s_poly &getCoeff() const {
        return sec_coeff_;
    }
    poly &getKeyQ() {
        return sec_key_q_;
    }
    const poly &getKeyQ() const {
        return sec_key_q_;
    }
    poly &getKeyP() {
        return sec_key_p_;
    }
    const poly &getKeyP() const {
        return sec_key_p_;
    }
    deb::SecretKey &getDebSecKey() {
        return deb_sk_;
    }
    const deb::SecretKey &getDebSecKey() const {
        return deb_sk_;
    }
    const deb::SecretKey &getDirectRootDebSecKey(deb::Preset preset) const;

    // u32 embedding of the same secret, default root (IP3 keygen/encrypt).
    const deb::SecretKey32 &getDebSecKey32(deb::Preset preset) const;

    // u32 embedding, DIRECT root (IP3 evi-ntt decrypt path).
    const deb::SecretKey32 &getDirectRootDebSecKey32(deb::Preset preset) const;

    evi::ParameterPreset preset_;
    bool sec_loaded_;

    std::optional<SealInfo> s_info_;
    std::optional<TEEWrapper> teew_;

private:
    void reset() noexcept;
    void clearDerivedDebSecKeyCache() const noexcept;

    // Per-preset cache of a deb key derived from deb_sk_; zeroized on clear/rebuild.
    template <typename U>
    struct DerivedKeyCache {
        std::optional<deb::SecretKeyT<U>> key;
        deb::Preset preset = deb::PRESET_EMPTY;

        void clear() noexcept {
            static_assert(noexcept(std::declval<deb::SecretKeyT<U> &>().zeroize()),
                          "deb::SecretKeyT::zeroize must be noexcept");
            if (key) {
                key->zeroize();
                key.reset();
            }
            preset = deb::PRESET_EMPTY;
        }

        // Rebuilds via make(want) when empty or built for a different preset.
        template <typename Factory>
        const deb::SecretKeyT<U> &getOrBuild(deb::Preset want, Factory &&make) {
            if (!key || preset != want) {
                clear();
                key = std::forward<Factory>(make)(want);
                preset = want;
            }
            return *key;
        }
    };

    std::unique_ptr<SecretMemoryPages> secret_mem_;
    s_poly &sec_coeff_;
    poly &sec_key_q_;
    poly &sec_key_p_;
    mutable std::mutex access_mtx_;
    int open_count_{0};
    deb::SecretKey &deb_sk_;
    mutable DerivedKeyCache<deb::u64> direct_root_deb_sk_;
    mutable DerivedKeyCache<deb::u32> deb_sk32_;
    mutable DerivedKeyCache<deb::u32> direct_root_deb_sk32_;
};

class SecretKeyAccessScope {
public:
    explicit SecretKeyAccessScope(SecretKeyData &secret_key);
    explicit SecretKeyAccessScope(const SecretKey &key);
    explicit SecretKeyAccessScope(const std::shared_ptr<SecretKeyData> &key);
    ~SecretKeyAccessScope();

    SecretKeyAccessScope(const SecretKeyAccessScope &) = delete;
    SecretKeyAccessScope &operator=(const SecretKeyAccessScope &) = delete;
    SecretKeyAccessScope(SecretKeyAccessScope &&other) noexcept;
    SecretKeyAccessScope &operator=(SecretKeyAccessScope &&other) noexcept;

private:
    std::shared_ptr<SecretKeyData> key_;
};

class SecretKey : public std::shared_ptr<SecretKeyData> {
public:
    SecretKey() : std::shared_ptr<SecretKeyData>(NULL) {}
    SecretKey(std::shared_ptr<SecretKeyData> data) : std::shared_ptr<SecretKeyData>(data) {}
};

SecretKey makeSecKey(const evi::detail::Context &context);
SecretKey makeSecKey(const std::string &path, const std::optional<SealInfo> &s_info = std::nullopt);
SecretKey makeSecKey(std::istream &stream, const std::optional<SealInfo> &s_info = std::nullopt);

using MultiSecretKey = std::vector<std::shared_ptr<SecretKeyData>>;

} // namespace detail
} // namespace evi
