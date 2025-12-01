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

#include "evi_c/encryptor.h"

#include "evi_c/internal/common_internal.hpp"

#include <algorithm>
#include <optional>
#include <string>
#include <vector>

using namespace evi::c_api::detail;

extern "C" {

evi_status_t evi_encryptor_create(const evi_context_t *context, evi_encryptor_t **out_encryptor) {
    if (!context || !out_encryptor) {
        return set_error(EVI_STATUS_INVALID_ARGUMENT, "null argument");
    }
    return invoke_and_catch([&]() {
        evi::Encryptor enc = evi::makeEncryptor(context->impl);
        *out_encryptor = new evi_encryptor(std::move(enc));
    });
}

evi_status_t evi_encryptor_create_with_seed(const evi_context_t *context, const uint8_t *seed, size_t seed_length,
                                            evi_encryptor_t **out_encryptor) {
    if (!context || !out_encryptor || !seed) {
        return set_error(EVI_STATUS_INVALID_ARGUMENT, "null argument");
    }
    constexpr size_t seed_min_size = evi::SEED_MIN_SIZE;
    if (seed_length < seed_min_size) {
        return set_error(EVI_STATUS_INVALID_ARGUMENT, "seed_length is too small");
    }
    return invoke_and_catch([&]() {
        std::vector<uint8_t> seed_vec(seed, seed + seed_min_size);
        evi::Encryptor enc = evi::makeEncryptor(context->impl, seed_vec);
        *out_encryptor = new evi_encryptor(std::move(enc));
    });
}

void evi_encryptor_destroy(evi_encryptor_t *encryptor) {
    delete encryptor;
}

evi_status_t evi_encryptor_encode_vector(const evi_encryptor_t *encryptor, const float *data, size_t length,
                                         evi_encode_type_t encode_type, int level, const float *scale,
                                         evi_query_t **out_query) {
    if (!encryptor || !data || !out_query) {
        return set_error(EVI_STATUS_INVALID_ARGUMENT, "null argument");
    }

    return invoke_and_catch([&]() {
        std::vector<float> buffer(data, data + length);
        evi::Query q =
            encryptor->impl.encode(buffer, static_cast<evi::EncodeType>(encode_type), level, to_optional(scale));
        *out_query = new evi_query(std::move(q));
    });
}

evi_status_t evi_encryptor_encode_batch(const evi_encryptor_t *encryptor, const float *const *data, const size_t dim,
                                        size_t data_count, evi_encode_type_t encode_type, int level, const float *scale,
                                        evi_query_t ***out_queries, size_t *out_count) {
    if (!encryptor || !out_queries || !out_count) {
        return set_error(EVI_STATUS_INVALID_ARGUMENT, "null argument");
    }
    if (data_count == 0) {
        *out_queries = nullptr;
        *out_count = 0;
        return set_error(EVI_STATUS_SUCCESS, "");
    }
    if (!data || !dim) {
        return set_error(EVI_STATUS_INVALID_ARGUMENT, "data or dimensions null");
    }

    return invoke_and_catch([&]() {
        std::vector<std::vector<float>> inputs;
        inputs.reserve(data_count);
        for (size_t i = 0; i < data_count; ++i) {
            if (!data[i]) {
                throw evi::InvalidInputError("data row is null");
            }
            inputs.emplace_back(data[i], data[i] + dim);
        }

        std::vector<evi::Query> queries =
            encryptor->impl.encode(inputs, static_cast<evi::EncodeType>(encode_type), level);

        auto **result = new evi_query_t *[queries.size()];
        size_t idx = 0;
        try {
            for (auto &q : queries) {
                result[idx++] = new evi_query(std::move(q));
            }
        } catch (...) {
            for (size_t j = 0; j < idx; ++j) {
                delete result[j];
            }
            delete[] result;
            throw;
        }

        *out_queries = result;
        *out_count = queries.size();
    });
}

evi_status_t evi_encryptor_encode_vectors(const evi_encryptor_t *encryptor, const float *const *data, const size_t dim,
                                          size_t data_count, evi_encode_type_t encode_type, int level,
                                          const float *scale, evi_query_t **out_query) {
    if (!encryptor || !out_query) {
        return set_error(EVI_STATUS_INVALID_ARGUMENT, "null argument");
    }
    if (data_count == 0 || !data || dim == 0) {
        return set_error(EVI_STATUS_INVALID_ARGUMENT, "data inputs invalid");
    }

    return invoke_and_catch([&]() {
        std::vector<std::vector<float>> inputs;
        inputs.reserve(data_count);
        for (size_t i = 0; i < data_count; ++i) {
            if (!data[i]) {
                throw evi::InvalidInputError("data row is null");
            }
            inputs.emplace_back(data[i], data[i] + dim);
        }

        auto &enc = const_cast<evi::Encryptor &>(encryptor->impl);
        evi::Query q = enc.encode(inputs, static_cast<evi::EncodeType>(encode_type), level, to_optional(scale));
        *out_query = new evi_query(std::move(q));
    });
}

evi_status_t evi_encryptor_encrypt_vector_with_path(const evi_encryptor_t *encryptor, const char *enckey_path,
                                                    const float *data, size_t length, evi_encode_type_t encode_type,
                                                    int level, const float *scale, evi_query_t **out_query) {
    if (!encryptor || !enckey_path || !data || !out_query) {
        return set_error(EVI_STATUS_INVALID_ARGUMENT, "null argument");
    }

    return invoke_and_catch([&]() {
        std::vector<float> buffer(data, data + length);
        evi::Query q = encryptor->impl.encrypt(buffer, std::string(enckey_path),
                                               static_cast<evi::EncodeType>(encode_type), level, to_optional(scale));
        *out_query = new evi_query(std::move(q));
    });
}

evi_status_t evi_encryptor_encrypt_vector_with_pack(const evi_encryptor_t *encryptor, const evi_keypack_t *pack,
                                                    const float *data, size_t length, evi_encode_type_t encode_type,
                                                    int level, const float *scale, evi_query_t **out_query) {
    if (!encryptor || !pack || !data || !out_query) {
        return set_error(EVI_STATUS_INVALID_ARGUMENT, "null argument");
    }

    return invoke_and_catch([&]() {
        std::vector<float> buffer(data, data + length);
        evi::Query q = encryptor->impl.encrypt(buffer, pack->impl, static_cast<evi::EncodeType>(encode_type), level,
                                               to_optional(scale));
        *out_query = new evi_query(std::move(q));
    });
}

evi_status_t evi_encryptor_encrypt_batch_with_path(const evi_encryptor_t *encryptor, const char *enckey_path,
                                                   const float *const *data, const size_t dim, size_t data_count,
                                                   evi_encode_type_t encode_type, int level, const float *scale,
                                                   evi_query_t ***out_queries, size_t *out_count) {
    if (!encryptor || !out_queries || !out_count || !enckey_path) {
        return set_error(EVI_STATUS_INVALID_ARGUMENT, "null argument");
    }
    if (data_count == 0) {
        *out_queries = nullptr;
        *out_count = 0;
        return set_error(EVI_STATUS_SUCCESS, "");
    }
    if (!data || !dim) {
        return set_error(EVI_STATUS_INVALID_ARGUMENT, "data or dim null");
    }

    return invoke_and_catch([&]() {
        std::vector<std::vector<float>> inputs;
        inputs.reserve(data_count);
        for (size_t i = 0; i < data_count; ++i) {
            if (!data[i]) {
                throw evi::InvalidInputError("data row is null");
            }
            inputs.emplace_back(data[i], data[i] + dim);
        }

        std::vector<evi::Query> queries = encryptor->impl.encrypt(
            inputs, std::string(enckey_path), static_cast<evi::EncodeType>(encode_type), level, to_optional(scale));

        auto **result = new evi_query_t *[queries.size()];
        size_t idx = 0;
        try {
            for (auto &q : queries) {
                result[idx++] = new evi_query(std::move(q));
            }
        } catch (...) {
            for (size_t j = 0; j < idx; ++j) {
                delete result[j];
            }
            delete[] result;
            throw;
        }
        *out_queries = result;
        *out_count = queries.size();
        set_error(EVI_STATUS_SUCCESS, "");
    });
}

evi_status_t evi_encryptor_encrypt_batch_with_pack(const evi_encryptor_t *encryptor, const evi_keypack_t *pack,
                                                   const float *const *data, const size_t dim, size_t data_count,
                                                   evi_encode_type_t encode_type, int level, const float *scale,
                                                   evi_query_t ***out_queries, size_t *out_count) {
    if (!encryptor || !pack || !out_queries || !out_count) {
        return set_error(EVI_STATUS_INVALID_ARGUMENT, "null argument");
    }
    if (data_count == 0) {
        *out_queries = nullptr;
        *out_count = 0;
        return set_error(EVI_STATUS_SUCCESS, "");
    }
    if (!data || !dim) {
        return set_error(EVI_STATUS_INVALID_ARGUMENT, "data or dim null");
    }

    return invoke_and_catch([&]() {
        std::vector<std::vector<float>> inputs;
        inputs.reserve(data_count);
        for (size_t i = 0; i < data_count; ++i) {
            if (!data[i]) {
                throw evi::InvalidInputError("data row is null");
            }
            inputs.emplace_back(data[i], data[i] + dim);
        }

        std::vector<evi::Query> queries = encryptor->impl.encrypt(
            inputs, pack->impl, static_cast<evi::EncodeType>(encode_type), level, to_optional(scale));

        auto **result = new evi_query_t *[queries.size()];
        size_t idx = 0;
        try {
            for (auto &q : queries) {
                result[idx++] = new evi_query(std::move(q));
            }
        } catch (...) {
            for (size_t j = 0; j < idx; ++j) {
                delete result[j];
            }
            delete[] result;
            throw;
        }

        *out_queries = result;
        *out_count = queries.size();
    });
}

} // extern "C"
