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

#include "utils/crypto/TEEWrapper.hpp"

#include "utils/Utils.hpp"
#include <nlohmann/json.hpp>

using json = nlohmann::json;

TEEWrapper::TEEWrapper(evi::detail::SealInfo &s_info) : s_info_(s_info) {
    if (s_info.s_mode == evi::SealMode::AES_KEK) {
        if (s_info.kek.size() != 32) {
            std::cout << "Check your key file format\n";
        }
    } else {
#ifdef BUILD_YUBIHSM
        hsmw_.emplace(s_info);
#else
        std::cout << "Invalid seal mode \n";
        exit(1);
#endif
    }
}

void TEEWrapper::saveSealedSecKey(std::ostream &os, evi::ParameterPreset preset, std::stringstream &seckey,
                                  std::vector<uint8_t> &kek) {
    std::vector<uint8_t> iv(evi::detail::AES256_IV_SIZE, 0);
    std::vector<uint8_t> tag(evi::detail::AES256_TAG_SIZE, 0);
    uint16_t obj_id = 0;
    char zero_bytes[2] = {0x00, 0x00};
    std::string sec_str = seckey.str();
    std::vector<uint8_t> sec_key_vec(sec_str.begin(), sec_str.end());
    std::vector<uint8_t> sealed_seckey(sec_str.size(), 0);

    AES::encryptAESGCM(sec_key_vec, kek, iv, sealed_seckey, tag);
    uint32_t sealed_size = static_cast<uint32_t>(sealed_seckey.size());

    json j;
    j["ParameterPreset"] = evi::detail::utils::assignParameterString(preset);
    j["SealType"] = "AES-KEK";
    os << std::setw(4) << j;
    os.write(reinterpret_cast<const char *>(&obj_id), 2);
    os.write(zero_bytes, 2);
    os.write(reinterpret_cast<const char *>(iv.data()), iv.size());
    os.write(reinterpret_cast<const char *>(tag.data()), tag.size());
    os.write(reinterpret_cast<const char *>(&sealed_size), sizeof(sealed_size));
    os.write(reinterpret_cast<const char *>(sealed_seckey.data()), sealed_seckey.size());
}

void TEEWrapper::getUnsealedSecKey(std::istream &is, evi::ParameterPreset preset, std::stringstream &seckey,
                                   std::vector<uint8_t> &kek) {
    uint16_t obj_id;
    std::vector<uint8_t> iv(evi::detail::AES256_IV_SIZE, 0);
    std::vector<uint8_t> tag(evi::detail::AES256_TAG_SIZE, 0);
    std::vector<uint8_t> tmp(4, 0);
    uint32_t seckey_size;
    std::vector<uint8_t> sealed_seckey;
    std::vector<uint8_t> tmp_seckey;
    char zero_bytes[2];
    json j;
    std::string parm, seal;

    try {
        is >> j;
        parm = j["ParameterPreset"].get<std::string>();
        preset = evi::detail::utils::stringToPreset(parm);
        seal = j["SealType"].get<std::string>();
    } catch (const std::exception &e) {
        throw evi::KeyNotLoadedError("Seal mode mismatch: Check your key file and evi::SealInfo.");
    }
    is.read(reinterpret_cast<char *>(&obj_id), 2);
    is.read(zero_bytes, 2);
    is.read(reinterpret_cast<char *>(iv.data()), iv.size());
    is.read(reinterpret_cast<char *>(tag.data()), tag.size());
    is.read(reinterpret_cast<char *>(&seckey_size), sizeof(seckey_size));
    sealed_seckey.resize(seckey_size);
    tmp_seckey.resize(seckey_size);
    is.read(reinterpret_cast<char *>(sealed_seckey.data()), seckey_size);

    AES::decryptAESGCM(sealed_seckey, kek, iv, tmp_seckey, tag);
    seckey.write(reinterpret_cast<const char *>(tmp_seckey.data()), tmp_seckey.size());
}

#ifdef BUILD_YUBIHSM
void TEEWrapper::saveSealedSecKeyHSM(std::ostream &os, int32_t *preset, std::stringstream &seckey) {
    std::vector<uint8_t> kek(AES256_KEY_SIZE, 0);
    std::vector<uint8_t> iv(AES256_IV_SIZE, 0);
    std::vector<uint8_t> tag(AES256_TAG_SIZE, 0);
    std::vector<uint8_t> wrapKek(1024, 0);
    size_t wrapKekLen = 1024;
    uint16_t obj_id = 0;
    char zero_bytes[2] = {0x00, 0x00};
    std::string sec_str = seckey.str();
    std::vector<uint8_t> sec_key_vec(sec_str.begin(), sec_str.end());
    std::vector<uint8_t> sealed_seckey;

    hsmw_->GetWrapKek(&obj_id, kek.data(), kek.size(), &wrapKek[0], &wrapKekLen);
    wrapKek.resize(wrapKekLen);
    AES::encryptAESGCM(sec_key_vec, kek, iv, sealed_seckey, tag);
    uint32_t sealed_size = static_cast<uint32_t>(sealed_seckey.size());

    os.write(reinterpret_cast<const char *>(&obj_id), 2);
    os.write(zero_bytes, 2);
    os.write(reinterpret_cast<const char *>(iv.data()), iv.size());
    os.write(reinterpret_cast<const char *>(tag.data()), tag.size());
    os.write(reinterpret_cast<const char *>(wrapKek.data()), wrapKek.size());
    os.write(zero_bytes, 2);
    os.write(reinterpret_cast<const char *>(&sealed_size), sizeof(sealed_size));
    if (preset != nullptr) {
        const uint8_t *bytes = reinterpret_cast<const uint8_t *>(preset);
        os.write(reinterpret_cast<const char *>(bytes), sizeof(int32_t));
    }
    os.write(reinterpret_cast<const char *>(sealed_seckey.data()), sealed_seckey.size());
}

void TEEWrapper::getUnsealedSecKeyHSM(std::istream &is, int32_t *preset_, std::stringstream &seckey) {
    uint16_t obj_id;
    uint32_t sealed_size = 0;
    std::vector<uint8_t> wrappedKek(AES256_GCM_OUT_SIZE, 0);
    std::vector<uint8_t> kek(1024, 0);
    std::vector<uint8_t> iv(AES256_IV_SIZE);
    std::vector<uint8_t> tag(AES256_TAG_SIZE);
    std::vector<uint8_t> sealedkey;
    std::vector<uint8_t> key;
    size_t kekLen = kek.size();
    char zero_bytes[2], preset[4];

    is.read(reinterpret_cast<char *>(&obj_id), 2);
    is.read(zero_bytes, 2);
    is.read(reinterpret_cast<char *>(iv.data()), iv.size());
    is.read(reinterpret_cast<char *>(tag.data()), tag.size());
    is.read(reinterpret_cast<char *>(wrappedKek.data()), wrappedKek.size());
    is.read(zero_bytes, 2);
    is.read(reinterpret_cast<char *>(&sealed_size), sizeof(sealed_size));
    if (preset_ != nullptr) {
        is.read(reinterpret_cast<char *>(&preset), sizeof(preset));
        std::memcpy(preset_, preset, sizeof(preset));
    }
    sealedkey.resize(sealed_size);
    key.resize(sealed_size);
    is.read(reinterpret_cast<char *>(sealedkey.data()), sealed_size);

    hsmw_->GetUnwrapKek(obj_id, wrappedKek.data(), wrappedKek.size(), kek.data(), &kekLen);
    AES::decryptAESGCM(sealedkey, kek, iv, key, tag);
    seckey.write(reinterpret_cast<const char *>(key.data()), key.size());
}
#endif
