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

#include "utils/crypto/AES.hpp"

bool AES::encryptAESGCM(const std::vector<uint8_t> &plaintext, const std::vector<uint8_t> &key,
                        std::vector<uint8_t> &iv, std::vector<uint8_t> &ciphertext, std::vector<uint8_t> &tag) {
    if (key.size() != evi::detail::AES256_KEY_SIZE) {
        std::cerr << "Key size must be 256 bits (32 bytes)\n";
        return false;
    }
    iv.resize(evi::detail::AES256_IV_SIZE);
    if (!RAND_bytes(iv.data(), evi::detail::AES256_IV_SIZE)) {
        std::cerr << "IV generation failed\n";
        return false;
    }
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "EVP_CIPHER_CTX_new failed\n";
        return false;
    }
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        std::cerr << "EncryptInit failed\n";
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1) {
        std::cerr << "Set key/iv failed\n";
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    int len = 0;
    ciphertext.resize(plaintext.size());
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size()) != 1) {
        std::cerr << "EncryptUpdate failed\n";
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    int final_len = 0;
    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &final_len) != 1) {
        std::cerr << "EncryptFinal failed\n";
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    ciphertext.resize(len + final_len);
    tag.resize(evi::detail::AES256_TAG_SIZE);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, evi::detail::AES256_TAG_SIZE, tag.data()) != 1) {
        std::cerr << "GetTag failed\n";
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

bool AES::decryptAESGCM(const std::vector<uint8_t> &ciphertext, const std::vector<uint8_t> &key,
                        const std::vector<uint8_t> &iv, std::vector<uint8_t> &plaintext,
                        const std::vector<uint8_t> &tag) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "EVP_CIPHER_CTX_new failed\n";
        return false;
    }
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        std::cerr << "DecryptInit failed\n";
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1) {
        std::cerr << "Set key/iv failed\n";
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    int len = 0;
    plaintext.resize(ciphertext.size());
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size()) != 1) {
        std::cerr << "DecryptUpdate failed\n";
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, evi::detail::AES256_TAG_SIZE, (void *)tag.data()) != 1) {
        std::cerr << "SetTag failed\n";
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    int final_len = 0;
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &final_len) != 1) {
        std::cerr << "DecryptFinal failed!! \n";
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    plaintext.resize(len + final_len);
    EVP_CIPHER_CTX_free(ctx);
    return true;
}
