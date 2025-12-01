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

#include "evi_c/query.h"

#include "evi_c/internal/common_internal.hpp"
#include "evi_c/internal/stream_utils.hpp"

#include <cstdlib>
#include <fstream>
#include <new>
#include <sstream>
#include <string>
#include <vector>

using namespace evi::c_api::detail;

extern "C" {

void evi_query_destroy(evi_query_t *query) {
    delete query;
}

void evi_query_array_destroy(evi_query_t **queries, size_t count) {
    if (!queries)
        return;
    for (size_t i = 0; i < count; ++i) {
        delete queries[i];
    }
    delete[] queries;
}

evi_status_t evi_query_get_level(const evi_query_t *query, uint32_t *out_level) {
    if (!query || !out_level) {
        return set_error(EVI_STATUS_INVALID_ARGUMENT, "null argument");
    }
    return invoke_and_catch([&]() {
        *out_level = query->impl.getLevel();
    });
}

evi_status_t evi_query_get_show_dim(const evi_query_t *query, uint32_t *out_show_dim) {
    if (!query || !out_show_dim) {
        return set_error(EVI_STATUS_INVALID_ARGUMENT, "null argument");
    }
    return invoke_and_catch([&]() {
        *out_show_dim = query->impl.getShowDim();
    });
}

evi_status_t evi_query_get_inner_item_count(const evi_query_t *query, uint32_t *out_count) {
    if (!query || !out_count) {
        return set_error(EVI_STATUS_INVALID_ARGUMENT, "null argument");
    }
    return invoke_and_catch([&]() {
        *out_count = query->impl.getInnerItemCount();
    });
}

evi_status_t evi_query_get_block_count(const evi_query_t *query, size_t *out_count) {
    if (!query || !out_count) {
        return set_error(EVI_STATUS_INVALID_ARGUMENT, "null argument");
    }
    return invoke_and_catch([&]() {
        *out_count = query->impl.size();
    });
}

evi_status_t evi_query_serialize_to_path(const evi_query_t *query, const char *path) {
    if (!query || !path) {
        return set_error(EVI_STATUS_INVALID_ARGUMENT, "null argument");
    }
    return invoke_and_catch([&]() {
        std::ofstream out(path, std::ios::binary);
        if (!out.is_open()) {
            throw evi::FileNotFoundError("failed to open file for writing query");
        }
        evi::Query::serializeTo(query->impl, out);
    });
}

evi_status_t evi_query_deserialize_from_path(const char *path, evi_query_t **out_query) {
    if (!path || !out_query) {
        return set_error(EVI_STATUS_INVALID_ARGUMENT, "null argument");
    }
    return invoke_and_catch([&]() {
        std::ifstream in(path, std::ios::binary);
        if (!in.is_open()) {
            throw evi::FileNotFoundError("failed to open file for reading query");
        }
        evi::Query q = evi::Query::deserializeFrom(in);
        *out_query = new evi_query(std::move(q));
    });
}

evi_status_t evi_query_serialize_to_stream(const evi_query_t *query, evi_stream_write_fn write_fn, void *handle) {
    if (!query || !write_fn) {
        return set_error(EVI_STATUS_INVALID_ARGUMENT, "null argument");
    }
    return invoke_and_catch([&]() {
        WriteCallbackStreambuf buf(write_fn, handle);
        std::ostream out(&buf);
        out.exceptions(std::ios::badbit | std::ios::failbit);
        evi::Query::serializeTo(query->impl, out);
        out.flush();
    });
}

evi_status_t evi_query_deserialize_from_stream(evi_stream_read_fn read_fn, void *handle, evi_query_t **out_query) {
    if (!read_fn || !out_query) {
        return set_error(EVI_STATUS_INVALID_ARGUMENT, "null argument");
    }
    return invoke_and_catch([&]() {
        ReadCallbackStreambuf buf(read_fn, handle);
        std::istream in(&buf);
        in.exceptions(std::ios::badbit);
        evi::Query q = evi::Query::deserializeFrom(in);
        *out_query = new evi_query(std::move(q));
    });
}

evi_status_t evi_query_serialize_to_string(const evi_query_t *query, char **out_data, size_t *out_size) {
    if (!query || !out_data || !out_size) {
        return set_error(EVI_STATUS_INVALID_ARGUMENT, "null argument");
    }
    return invoke_and_catch([&]() {
        std::string data;
        evi::Query::serializeToString(query->impl, data);
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

evi_status_t evi_query_deserialize_from_string(const char *data, size_t size, evi_query_t **out_query) {
    if (!data || !out_query) {
        return set_error(EVI_STATUS_INVALID_ARGUMENT, "null argument");
    }
    return invoke_and_catch([&]() {
        std::string str(data, size);
        evi::Query q = evi::Query::deserializeFromString(str);
        *out_query = new evi_query(std::move(q));
    });
}

evi_status_t evi_query_vector_serialize_to_path(evi_query_t *const *queries, size_t count, const char *path) {
    if (!path) {
        return set_error(EVI_STATUS_INVALID_ARGUMENT, "path is null");
    }
    if (count > 0 && !queries) {
        return set_error(EVI_STATUS_INVALID_ARGUMENT, "queries array is null");
    }
    return invoke_and_catch([&]() {
        std::ofstream out(path, std::ios::binary);
        if (!out.is_open()) {
            throw evi::FileNotFoundError("failed to open file for writing queries");
        }
        std::vector<evi::Query> vec;
        vec.reserve(count);
        for (size_t i = 0; i < count; ++i) {
            if (!queries[i]) {
                throw evi::InvalidInputError("query handle is null");
            }
            vec.push_back(queries[i]->impl);
        }
        evi::Query::serializeVectorTo(vec, out);
    });
}

evi_status_t evi_query_vector_serialize_to_stream(evi_query_t *const *queries, size_t count,
                                                  evi_stream_write_fn write_fn, void *handle) {
    if (!write_fn) {
        return set_error(EVI_STATUS_INVALID_ARGUMENT, "write_fn is null");
    }
    if (count > 0 && !queries) {
        return set_error(EVI_STATUS_INVALID_ARGUMENT, "queries array is null");
    }
    return invoke_and_catch([&]() {
        std::vector<evi::Query> vec;
        vec.reserve(count);
        for (size_t i = 0; i < count; ++i) {
            if (!queries[i]) {
                throw evi::InvalidInputError("query handle is null");
            }
            vec.push_back(queries[i]->impl);
        }
        WriteCallbackStreambuf buf(write_fn, handle);
        std::ostream out(&buf);
        out.exceptions(std::ios::badbit | std::ios::failbit);
        evi::Query::serializeVectorTo(vec, out);
        out.flush();
    });
}

evi_status_t evi_query_vector_deserialize_from_path(const char *path, evi_query_t ***out_queries, size_t *out_count) {
    if (!path || !out_queries || !out_count) {
        return set_error(EVI_STATUS_INVALID_ARGUMENT, "null argument");
    }
    return invoke_and_catch([&]() {
        std::ifstream in(path, std::ios::binary);
        if (!in.is_open()) {
            throw evi::FileNotFoundError("failed to open file for reading queries");
        }
        std::vector<evi::Query> vec = evi::Query::deserializeVectorFrom(in);
        if (vec.empty()) {
            *out_queries = nullptr;
            *out_count = 0;
            return;
        }
        auto **array = new evi_query_t *[vec.size()];
        size_t idx = 0;
        try {
            for (auto &q : vec) {
                array[idx++] = new evi_query(std::move(q));
            }
        } catch (...) {
            for (size_t i = 0; i < idx; ++i) {
                delete array[i];
            }
            delete[] array;
            throw;
        }
        *out_queries = array;
        *out_count = vec.size();
    });
}

evi_status_t evi_query_vector_deserialize_from_stream(evi_stream_read_fn read_fn, void *handle,
                                                      evi_query_t ***out_queries, size_t *out_count) {
    if (!read_fn || !out_queries || !out_count) {
        return set_error(EVI_STATUS_INVALID_ARGUMENT, "null argument");
    }
    return invoke_and_catch([&]() {
        ReadCallbackStreambuf buf(read_fn, handle);
        std::istream in(&buf);
        in.exceptions(std::ios::badbit);
        std::vector<evi::Query> vec = evi::Query::deserializeVectorFrom(in);
        if (vec.empty()) {
            *out_queries = nullptr;
            *out_count = 0;
            return;
        }
        auto **array = new evi_query_t *[vec.size()];
        size_t idx = 0;
        try {
            for (auto &q : vec) {
                array[idx++] = new evi_query(std::move(q));
            }
        } catch (...) {
            for (size_t i = 0; i < idx; ++i) {
                delete array[i];
            }
            delete[] array;
            throw;
        }
        *out_queries = array;
        *out_count = vec.size();
    });
}

evi_status_t evi_query_vector_serialize_to_string(evi_query_t *const *queries, size_t count, char **out_data,
                                                  size_t *out_size) {
    if (!out_data || !out_size) {
        return set_error(EVI_STATUS_INVALID_ARGUMENT, "output pointers are null");
    }
    if (count > 0 && !queries) {
        return set_error(EVI_STATUS_INVALID_ARGUMENT, "queries array is null");
    }
    return invoke_and_catch([&]() {
        std::vector<evi::Query> vec;
        vec.reserve(count);
        for (size_t i = 0; i < count; ++i) {
            if (!queries[i]) {
                throw evi::InvalidInputError("query handle is null");
            }
            vec.push_back(queries[i]->impl);
        }
        std::string data;
        evi::Query::serializeVectorToString(vec, data);
        *out_size = data.size();
        *out_data = new char[*out_size];
        std::memcpy(*out_data, data.data(), *out_size);
    });
}

evi_status_t evi_query_vector_deserialize_from_string(const char *data, size_t size, evi_query_t ***out_queries,
                                                      size_t *out_count) {
    if (!data || !out_queries || !out_count) {
        return set_error(EVI_STATUS_INVALID_ARGUMENT, "null argument");
    }
    return invoke_and_catch([&]() {
        std::string str(data, size);
        std::vector<evi::Query> vec = evi::Query::deserializeVectorFromString(str);
        if (vec.empty()) {
            *out_queries = nullptr;
            *out_count = 0;
            return;
        }
        auto **array = new evi_query_t *[vec.size()];
        size_t idx = 0;
        try {
            for (auto &q : vec) {
                array[idx++] = new evi_query(std::move(q));
            }
        } catch (...) {
            for (size_t i = 0; i < idx; ++i) {
                delete array[i];
            }
            delete[] array;
            throw;
        }
        *out_queries = array;
        *out_count = vec.size();
    });
}
} // extern "C"
