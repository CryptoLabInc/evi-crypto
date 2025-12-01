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
#include <nlohmann/json.hpp>

#include <algorithm>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <utility>

using json = nlohmann::json;

namespace evi {
namespace detail {

SecretKeyData::SecretKeyData(const Context &context) : deb_sk_(utils::getDebPreset(context)) {
    preset_ = context->getParam()->getPreset();
    s_info_ = SealInfo(SealMode::NONE);
}

SecretKeyData::SecretKeyData(const std::string &path, std::optional<SealInfo> s_info) : deb_sk_(deb::PRESET_EVI_IP0) {

    s_info_ = s_info;
    if (!s_info.has_value() || s_info->s_mode == SealMode::NONE) {
        loadSecKey(path);
    } else {
        loadSealedSecKey(path);
    }
}

SecretKeyData::SecretKeyData(std::istream &stream, std::optional<SealInfo> s_info) : deb_sk_(deb::PRESET_EVI_IP0) {
    s_info_ = std::move(s_info);
    if (!s_info_.has_value() || s_info_.value().s_mode == SealMode::NONE) {
        loadSecKey(stream);
    } else {
        loadSealedSecKey(stream);
    }
}

namespace {
bool hasBinExtension(const std::string &path) {
    static constexpr const char *K_EXT = ".bin";
    const std::size_t ext_len = 4;
    return path.size() >= ext_len && path.compare(path.size() - ext_len, ext_len, K_EXT) == 0;
}
} // namespace

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
    in.read(reinterpret_cast<char *>(&sec_loaded_), sizeof(bool));
    if (sec_loaded_) {
        json j;
        in >> j;
        preset_ = utils::stringToPreset(j["ParameterPreset"].get<std::string>());
        SealInfo s(utils::stringToSealMode(j["SealType"].get<std::string>()));
        s_info_ = s;

        // TODO : replace below with the following deb deserialize function
        // deb::deserializeFromStream(in, deb_sk_);
        // std::memcpy(sec_key_q_.data(), deb_sk_[0][0].data(), DEGREE * sizeof(u64));
        // std::memcpy(sec_key_p_.data(), deb_sk_[0][1].data(), DEGREE * sizeof(u64));
        // for (u64 i = 0; i < DEGREE; ++i) {
        //     sec_coeff_[i] = static_cast<i64>(deb_sk_.coeffs()[i]);
        // }
        deb_sk_[0][0].setData(sec_key_q_.data(), DEGREE);
        deb_sk_[0][1].setData(sec_key_p_.data(), DEGREE);
        in.read(reinterpret_cast<char *>(sec_key_q_.data()), U64_DEGREE);
        in.read(reinterpret_cast<char *>(sec_key_p_.data()), U64_DEGREE);
        in.read(reinterpret_cast<char *>(sec_coeff_.data()), DEGREE * sizeof(i64));
        for (u64 i = 0; i < DEGREE; ++i) {
            deb_sk_.coeffs()[i] = static_cast<int8_t>(sec_coeff_[i]);
        }
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
    if (!sec_loaded_) {
        throw evi::KeyNotLoadedError("Secret key is not loaded to be saved");
    }

    out.write(reinterpret_cast<const char *>(&sec_loaded_), sizeof(bool));
    json j;
    j["ParameterPreset"] = utils::assignParameterString(preset_);
    j["SealType"] = utils::assignSealModeString(s_info_.value().s_mode);
    out << std::setw(4) << j;

    // TODO : replace below with the following deb serialize function
    // deb::serializeToStream(deb_sk_, out);
    out.write(reinterpret_cast<const char *>(sec_key_q_.data()), U64_DEGREE);
    out.write(reinterpret_cast<const char *>(sec_key_p_.data()), U64_DEGREE);
    out.write(reinterpret_cast<const char *>(sec_coeff_.data()), DEGREE * sizeof(i64));
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

SecretKey makeSecKey(std::istream &stream, std::optional<SealInfo> s_info) {
    return std::make_shared<SecretKeyData>(stream, std::move(s_info));
}

} // namespace detail
} // namespace evi
