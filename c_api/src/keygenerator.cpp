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

#include "evi_c/keygenerator.h"

#include "evi_c/internal/common_internal.hpp"

#include <string>
#include <vector>

using namespace evi::c_api::detail;

namespace {

evi_status_t translate_seal_mode(evi_seal_mode_t mode, evi::SealMode &out_mode) {
    switch (mode) {
    case EVI_SEAL_MODE_AES_KEK:
        out_mode = evi::SealMode::AES_KEK;
        return EVI_STATUS_SUCCESS;
    case EVI_SEAL_MODE_NONE:
        out_mode = evi::SealMode::NONE;
        return EVI_STATUS_SUCCESS;
    case EVI_SEAL_MODE_HSM_PORT:
    case EVI_SEAL_MODE_HSM_SERIAL:
        return set_error(EVI_STATUS_NOT_IMPLEMENTED, "seal mode not supported in C API");
    default:
        return set_error(EVI_STATUS_INVALID_ARGUMENT, "unknown seal mode");
    }
}

} // namespace

extern "C" {

evi_status_t evi_seal_info_create(evi_seal_mode_t mode, const uint8_t *key_data, size_t key_length,
                                  evi_seal_info_t **out_info) {
    if (!out_info) {
        return set_error(EVI_STATUS_INVALID_ARGUMENT, "out_info is null");
    }
    evi::SealMode cpp_mode{};
    evi_status_t status = translate_seal_mode(mode, cpp_mode);
    if (status != EVI_STATUS_SUCCESS) {
        return status;
    }

    return invoke_and_catch([&]() {
        switch (cpp_mode) {
        case evi::SealMode::AES_KEK: {
            if (!key_data || key_length != static_cast<size_t>(evi::AES256_KEY_SIZE)) {
                throw evi::InvalidInputError("AES-KEK requires a 32-byte key");
            }
            std::vector<uint8_t> key(key_data, key_data + key_length);
            *out_info = new evi_seal_info(evi::SealInfo(evi::SealMode::AES_KEK, std::move(key)));
            break;
        }
        case evi::SealMode::NONE: {
            if (key_data || key_length != 0) {
                throw evi::InvalidInputError("seal mode NONE must not provide key material");
            }
            *out_info = new evi_seal_info(evi::SealInfo(evi::SealMode::NONE));
            break;
        }
        default:
            throw evi::NotSupportedError("seal mode not handled");
        }
    });
}

evi_status_t evi_keygenerator_create_with_seed(const evi_context_t *context, evi_keypack_t *pack, const uint8_t *seed,
                                               size_t seed_length, evi_keygenerator_t **out_keygen) {
    if (!context || !pack || !out_keygen || !seed) {
        return set_error(EVI_STATUS_INVALID_ARGUMENT, "null argument");
    }
    constexpr size_t seed_min_size = evi::SEED_MIN_SIZE;
    if (seed_length < seed_min_size) {
        return set_error(EVI_STATUS_INVALID_ARGUMENT, "seed_length is too small");
    }
    return invoke_and_catch([&]() {
        std::vector<uint8_t> seed_vec(seed, seed + seed_min_size);
        evi::KeyGenerator keygen = evi::makeKeyGenerator(context->impl, pack->impl, seed_vec);
        *out_keygen = new evi_keygenerator(std::move(keygen));
    });
}

void evi_seal_info_destroy(evi_seal_info_t *info) {
    delete info;
}

// =========================================================
// KeyGenerator
// =========================================================

evi_status_t evi_keygenerator_create(const evi_context_t *context, evi_keypack_t *pack,
                                     evi_keygenerator_t **out_keygen) {
    if (!context || !pack || !out_keygen) {
        return set_error(EVI_STATUS_INVALID_ARGUMENT, "null argument");
    }
    return invoke_and_catch([&]() {
        evi::KeyGenerator keygen = evi::makeKeyGenerator(context->impl, pack->impl);
        *out_keygen = new evi_keygenerator(std::move(keygen));
    });
}

void evi_keygenerator_destroy(evi_keygenerator_t *keygen) {
    delete keygen;
}

evi_status_t evi_keygenerator_generate_secret_key(evi_keygenerator_t *keygen, evi_secret_key_t **out_key) {
    if (!keygen || !out_key) {
        return set_error(EVI_STATUS_INVALID_ARGUMENT, "null argument");
    }
    return invoke_and_catch([&]() {
        evi::SecretKey key = keygen->impl.genSecKey();
        *out_key = new evi_secret_key(std::move(key));
    });
}

evi_status_t evi_keygenerator_generate_public_keys(evi_keygenerator_t *keygen, evi_secret_key_t *seckey) {
    if (!keygen || !seckey) {
        return set_error(EVI_STATUS_INVALID_ARGUMENT, "null argument");
    }
    return invoke_and_catch([&]() {
        keygen->impl.genPubKeys(seckey->impl);
    });
}

// =========================================================
// MultiKeyGenerator
// =========================================================

evi_status_t evi_multikeygenerator_create(const evi_context_t *const *contexts, size_t count, const char *directory,
                                          const evi_seal_info_t *seal_info, evi_multikeygenerator_t **out_keygen) {
    if (!contexts || count == 0) {
        return set_error(EVI_STATUS_INVALID_ARGUMENT, "contexts array is invalid");
    }
    if (!directory) {
        return set_error(EVI_STATUS_INVALID_ARGUMENT, "directory is null");
    }
    if (!seal_info) {
        return set_error(EVI_STATUS_INVALID_ARGUMENT, "seal_info is null");
    }
    if (!out_keygen) {
        return set_error(EVI_STATUS_INVALID_ARGUMENT, "out_keygen is null");
    }

    return invoke_and_catch([&]() {
        std::vector<evi::Context> ctxs;
        ctxs.reserve(count);
        for (size_t i = 0; i < count; ++i) {
            if (!contexts[i]) {
                throw evi::InvalidInputError("context handle is null");
            }
            ctxs.push_back(contexts[i]->impl);
        }

        std::string dir(directory);
        evi::SealInfo seal = seal_info->impl;
        evi::MultiKeyGenerator keygen(ctxs, dir, seal);
        *out_keygen = new evi_multikeygenerator(std::move(keygen));
    });
}

void evi_multikeygenerator_destroy(evi_multikeygenerator_t *keygen) {
    delete keygen;
}

evi_status_t evi_multikeygenerator_check_file_exist(evi_multikeygenerator_t *keygen, int *out_exists) {
    if (!keygen || !out_exists) {
        return set_error(EVI_STATUS_INVALID_ARGUMENT, "null argument");
    }
    return invoke_and_catch([&]() {
        bool exists = keygen->impl.checkFileExist();
        *out_exists = exists ? 1 : 0;
    });
}

evi_status_t evi_multikeygenerator_generate_keys(evi_multikeygenerator_t *keygen, evi_secret_key_t **out_key) {
    if (!keygen || !out_key) {
        return set_error(EVI_STATUS_INVALID_ARGUMENT, "null argument");
    }
    return invoke_and_catch([&]() {
        evi::SecretKey key = keygen->impl.generateKeys();
        *out_key = new evi_secret_key(std::move(key));
    });
}

} // extern "C"
