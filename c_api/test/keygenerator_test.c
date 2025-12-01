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

#include "test_utils.h"
#include "unity.h"

#include "evi_c/context.h"
#include "evi_c/keygenerator.h"
#include "evi_c/keypack.h"
#include "evi_c/secret_key.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static const char *kKeypackDir = "./tmp_keypack_test";
static const char *kEncKeyFile = "EncKey.bin";
static const char *kEvalKeyFile = "EvalKey.bin";

void test_keygenerator_basic(void) {
    make_directory(kKeypackDir);
    evi_context_t *context = NULL;
    evi_keypack_t *pack = NULL;
    evi_keygenerator_t *keygen = NULL;
    evi_secret_key_t *secret = NULL;

    TEST_ASSERT_EQUAL(EVI_STATUS_SUCCESS, evi_context_create(EVI_PARAMETER_PRESET_IP0, EVI_DEVICE_TYPE_CPU, 128,
                                                             EVI_EVAL_MODE_FLAT, NULL, &context));
    TEST_ASSERT_NOT_NULL(context);

    TEST_ASSERT_EQUAL(EVI_STATUS_SUCCESS, evi_keypack_create(context, &pack));
    TEST_ASSERT_NOT_NULL(pack);

    TEST_ASSERT_EQUAL(EVI_STATUS_SUCCESS, evi_keygenerator_create(context, pack, &keygen));
    TEST_ASSERT_NOT_NULL(keygen);

    TEST_ASSERT_EQUAL(EVI_STATUS_SUCCESS, evi_keygenerator_generate_secret_key(keygen, &secret));
    TEST_ASSERT_NOT_NULL(secret);

    TEST_ASSERT_EQUAL(EVI_STATUS_SUCCESS, evi_keygenerator_generate_public_keys(keygen, secret));

    char enc_key_path[256];
    snprintf(enc_key_path, sizeof(enc_key_path), "%s/%s", kKeypackDir, kEncKeyFile);
    char eval_key_path[256];
    snprintf(eval_key_path, sizeof(eval_key_path), "%s/%s", kKeypackDir, kEvalKeyFile);
    TEST_ASSERT_EQUAL(EVI_STATUS_SUCCESS, evi_keypack_save_enc_key(pack, enc_key_path));
    TEST_ASSERT_EQUAL(EVI_STATUS_SUCCESS, evi_keypack_save_eval_key(pack, eval_key_path));

    evi_secret_key_destroy(secret);
    evi_keygenerator_destroy(keygen);
    evi_keypack_destroy(pack);
    evi_context_destroy(context);
}

void test_multikeygenerator_with_seal_info(void) {
    const char *dir = "./tmp_multikey_test";
    make_directory(dir);

    evi_context_t *context = NULL;
    TEST_ASSERT_EQUAL(EVI_STATUS_SUCCESS, evi_context_create(EVI_PARAMETER_PRESET_IP0, EVI_DEVICE_TYPE_CPU, 256,
                                                             EVI_EVAL_MODE_FLAT, NULL, &context));
    TEST_ASSERT_NOT_NULL(context);

    const char seal_key_str[] = "0123456789ABCDEF0123456789ABCDEF";
    TEST_ASSERT_EQUAL_UINT(32, strlen(seal_key_str));
    evi_seal_info_t *seal_info = NULL;
    TEST_ASSERT_EQUAL(EVI_STATUS_SUCCESS, evi_seal_info_create(EVI_SEAL_MODE_AES_KEK, (const uint8_t *)seal_key_str,
                                                               strlen(seal_key_str), &seal_info));
    TEST_ASSERT_NOT_NULL(seal_info);

    const evi_context_t *ctx_array[1] = {context};
    evi_multikeygenerator_t *multi = NULL;
    TEST_ASSERT_EQUAL(EVI_STATUS_SUCCESS, evi_multikeygenerator_create(ctx_array, 1, dir, seal_info, &multi));
    TEST_ASSERT_NOT_NULL(multi);

    int exists = -1;
    TEST_ASSERT_EQUAL(EVI_STATUS_SUCCESS, evi_multikeygenerator_check_file_exist(multi, &exists));
    TEST_ASSERT_TRUE(exists == 0 || exists == 1);

    evi_secret_key_t *secret = NULL;
    TEST_ASSERT_EQUAL(EVI_STATUS_SUCCESS, evi_multikeygenerator_generate_keys(multi, &secret));
    TEST_ASSERT_NOT_NULL(secret);

    evi_secret_key_destroy(secret);
    evi_multikeygenerator_destroy(multi);
    evi_seal_info_destroy(seal_info);
    evi_context_destroy(context);

    remove_directory(dir);
}
