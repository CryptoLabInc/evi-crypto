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

#include "evi_c/common.h"
#include "unity.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 256
#endif

#define ASSERT_OK(step)                                                                                                \
    do {                                                                                                               \
        evi_status_t status__ = (step);                                                                                \
        if (status__ != EVI_STATUS_SUCCESS) {                                                                          \
            const char *msg__ = evi_last_error_message();                                                              \
            UNITY_TEST_FAIL(__LINE__, msg__ ? msg__ : "(no additional details)");                                      \
        }                                                                                                              \
    } while (0)

#define ASSERT_STATUS_OK(step) ASSERT_OK(step)
#define TEST_BUFFER_STREAM_CAPACITY 1024

static void make_directory(const char *path) {
    mkdir(path, 0777);
}

static void remove_directory(const char *dir_path) {
    char path_buf[PATH_MAX];
    const char *files[] = {"EvalKey.bin", "EncKey.bin", "SecKey.bin", "SecKey_sealed.bin"};
    for (size_t i = 0; i < sizeof(files) / sizeof(files[0]); ++i) {
        snprintf(path_buf, sizeof(path_buf), "%s/%s", dir_path, files[i]);
        unlink(path_buf);
    }
    rmdir(dir_path);
}

static inline double max_error(const float *expected, const float *actual, size_t length) {
    double max_error = 0.0;
    for (size_t i = 0; i < length; ++i) {
        double diff = (double)expected[i] - (double)actual[i];
        if (fabs(diff) > max_error) {
            max_error = fabs(diff);
        }
    }
    return max_error;
}

typedef struct test_buffer_stream {
    uint8_t *data;
    size_t size;
    size_t capacity;
    size_t offset;
} test_buffer_stream_t;

static inline void test_buffer_stream_init(test_buffer_stream_t *stream) {
    stream->data = NULL;
    stream->size = 0;
    stream->capacity = 0;
    stream->offset = 0;
}

static inline void test_buffer_stream_reset_read(test_buffer_stream_t *stream) {
    stream->offset = 0;
}

static inline void test_buffer_stream_destroy(test_buffer_stream_t *stream) {
    free(stream->data);
    stream->data = NULL;
    stream->size = 0;
    stream->capacity = 0;
    stream->offset = 0;
}

static inline size_t test_buffer_stream_write(void *handle, const uint8_t *data, size_t size) {
    test_buffer_stream_t *stream = (test_buffer_stream_t *)handle;
    if (size == 0) {
        return 0;
    }
    if (stream->size + size > stream->capacity) {
        size_t new_capacity = stream->capacity ? stream->capacity : TEST_BUFFER_STREAM_CAPACITY;
        while (new_capacity < stream->size + size) {
            new_capacity *= 2;
        }
        uint8_t *new_data = (uint8_t *)realloc(stream->data, new_capacity);
        if (!new_data) {
            return 0;
        }
        stream->data = new_data;
        stream->capacity = new_capacity;
    }
    memcpy(stream->data + stream->size, data, size);
    stream->size += size;
    return size;
}

static inline size_t test_buffer_stream_read(void *handle, uint8_t *buffer, size_t size) {
    test_buffer_stream_t *stream = (test_buffer_stream_t *)handle;
    if (size == 0) {
        return 0;
    }
    if (stream->offset >= stream->size) {
        return 0;
    }
    size_t remaining = stream->size - stream->offset;
    size_t to_copy = remaining < size ? remaining : size;
    memcpy(buffer, stream->data + stream->offset, to_copy);
    stream->offset += to_copy;
    return to_copy;
}
