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

#include "evi_c/secret_key.h"

#include "evi_c/internal/common_internal.hpp"

using namespace evi::c_api::detail;

extern "C" {

void evi_secret_key_destroy(evi_secret_key_t *seckey) {
    delete seckey;
}

evi_status_t evi_secret_key_create(const evi_context_t *context, evi_secret_key_t **out_key) {
    if (!context || !out_key) {
        return set_error(EVI_STATUS_INVALID_ARGUMENT, "null argument");
    }
    return invoke_and_catch([&]() {
        evi::SecretKey key = evi::makeSecKey(context->impl);
        *out_key = new evi_secret_key(std::move(key));
    });
}

evi_status_t evi_secret_key_create_from_path(const char *path, evi_secret_key_t **out_key) {
    if (!path || !out_key) {
        return set_error(EVI_STATUS_INVALID_ARGUMENT, "null argument");
    }
    return invoke_and_catch([&]() {
        evi::SecretKey key = evi::makeSecKey(std::string(path));
        *out_key = new evi_secret_key(std::move(key));
    });
}

evi_status_t evi_secret_key_create_from_path_with_seal_info(const char *path, const evi_seal_info_t *seal_info,
                                                            evi_secret_key_t **out_key) {
    if (!path || !out_key) {
        return set_error(EVI_STATUS_INVALID_ARGUMENT, "null argument");
    }
    return invoke_and_catch([&]() {
        std::optional<evi::SealInfo> info = std::nullopt;
        if (seal_info) {
            info = seal_info->impl;
        }
        evi::SecretKey key = evi::makeSecKey(std::string(path), info);
        *out_key = new evi_secret_key(std::move(key));
    });
}

} // extern "C"
