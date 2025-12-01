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

#include "evi_c/search_result.h"

#include "evi_c/internal/common_internal.hpp"
#include "evi_c/internal/stream_utils.hpp"

#include <cstdlib>
#include <cstring>
#include <fstream>
#include <new>
#include <sstream>
#include <string>

using namespace evi::c_api::detail;

extern "C" {

void evi_search_result_destroy(evi_search_result_t *result) {
    delete result;
}

evi_status_t evi_search_result_get_item_count(const evi_search_result_t *result, uint32_t *out_count) {
    if (!result || !out_count) {
        return set_error(EVI_STATUS_INVALID_ARGUMENT, "null argument");
    }
    return invoke_and_catch([&]() {
        auto &res = const_cast<evi::SearchResult &>(result->impl);
        *out_count = res.getItemCount();
    });
}

evi_status_t evi_search_result_serialize_to_path(const evi_search_result_t *result, const char *path) {
    if (!result || !path) {
        return set_error(EVI_STATUS_INVALID_ARGUMENT, "null argument");
    }
    return invoke_and_catch([&]() {
        std::ofstream out(path, std::ios::binary);
        if (!out.is_open()) {
            throw evi::FileNotFoundError("failed to open file for writing search result");
        }
        evi::SearchResult::serializeTo(result->impl, out);
    });
}

evi_status_t evi_search_result_deserialize_from_path(const char *path, evi_search_result_t **out_result) {
    if (!path || !out_result) {
        return set_error(EVI_STATUS_INVALID_ARGUMENT, "null argument");
    }
    return invoke_and_catch([&]() {
        std::ifstream in(path, std::ios::binary);
        if (!in.is_open()) {
            throw evi::FileNotFoundError("failed to open file for reading search result");
        }
        evi::SearchResult res = evi::SearchResult::deserializeFrom(in);
        *out_result = new evi_search_result(std::move(res));
    });
}

evi_status_t evi_search_result_serialize_to_stream(const evi_search_result_t *result, evi_stream_write_fn write_fn,
                                                   void *handle) {
    if (!result || !write_fn) {
        return set_error(EVI_STATUS_INVALID_ARGUMENT, "null argument");
    }
    return invoke_and_catch([&]() {
        WriteCallbackStreambuf buf(write_fn, handle);
        std::ostream out(&buf);
        out.exceptions(std::ios::badbit | std::ios::failbit);
        evi::SearchResult::serializeTo(result->impl, out);
        out.flush();
    });
}

evi_status_t evi_search_result_deserialize_from_stream(evi_stream_read_fn read_fn, void *handle,
                                                       evi_search_result_t **out_result) {
    if (!read_fn || !out_result) {
        return set_error(EVI_STATUS_INVALID_ARGUMENT, "null argument");
    }
    return invoke_and_catch([&]() {
        ReadCallbackStreambuf buf(read_fn, handle);
        std::istream in(&buf);
        in.exceptions(std::ios::badbit);
        evi::SearchResult res = evi::SearchResult::deserializeFrom(in);
        *out_result = new evi_search_result(std::move(res));
    });
}

evi_status_t evi_search_result_serialize_to_string(const evi_search_result_t *result, char **out_data,
                                                   size_t *out_size) {
    if (!result || !out_data || !out_size) {
        return set_error(EVI_STATUS_INVALID_ARGUMENT, "null argument");
    }
    return invoke_and_catch([&]() {
        std::ostringstream out(std::ios::binary);
        evi::SearchResult::serializeTo(result->impl, out);
        std::string data = out.str();
        *out_size = data.size();
        if (*out_size == 0) {
            *out_data = nullptr;
            return;
        }
        auto *buffer = static_cast<char *>(std::malloc(*out_size));
        if (!buffer) {
            throw std::bad_alloc();
        }
        std::memcpy(buffer, data.data(), *out_size);
        *out_data = buffer;
    });
}

evi_status_t evi_search_result_deserialize_from_string(const char *data, size_t size,
                                                       evi_search_result_t **out_result) {
    if (!data || !out_result) {
        return set_error(EVI_STATUS_INVALID_ARGUMENT, "null argument");
    }
    return invoke_and_catch([&]() {
        std::string buffer(data, size);
        std::istringstream in(buffer, std::ios::binary);
        in.exceptions(std::ios::badbit);
        evi::SearchResult res = evi::SearchResult::deserializeFrom(in);
        *out_result = new evi_search_result(std::move(res));
    });
}

} // extern "C"
