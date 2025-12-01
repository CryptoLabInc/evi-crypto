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

#include "unity.h"

#include "c_api.h"
#include "test_utils.h"

#include <math.h>

void test_encrypt_decrypt(void) {
    const size_t dim = 512;
    float data[dim];
    for (size_t i = 0; i < dim; ++i) {
        data[i] = (float)(0.05 * (double)i);
    }

    evi_context_t *context = NULL;
    evi_keypack_t *pack = NULL;
    evi_keygenerator_t *keygen = NULL;
    evi_secret_key_t *secret = NULL;
    evi_encryptor_t *encryptor = NULL;
    evi_decryptor_t *decryptor = NULL;
    evi_query_t *cipher = NULL;
    evi_message_t *message = NULL;

    ASSERT_OK(
        evi_context_create(EVI_PARAMETER_PRESET_IP0, EVI_DEVICE_TYPE_CPU, 1024, EVI_EVAL_MODE_RMP, NULL, &context));
    ASSERT_OK(evi_keypack_create(context, &pack));
    ASSERT_OK(evi_keygenerator_create(context, pack, &keygen));
    ASSERT_OK(evi_keygenerator_generate_secret_key(keygen, &secret));
    ASSERT_OK(evi_keygenerator_generate_public_keys(keygen, secret));
    ASSERT_OK(evi_encryptor_create(context, &encryptor));
    ASSERT_OK(evi_decryptor_create(context, &decryptor));

    ASSERT_OK(
        evi_encryptor_encrypt_vector_with_pack(encryptor, pack, data, dim, EVI_ENCODE_TYPE_ITEM, 0, NULL, &cipher));
    TEST_ASSERT_NOT_NULL(cipher);

    ASSERT_OK(evi_decryptor_decrypt_query_with_seckey(decryptor, cipher, secret, NULL, &message));
    TEST_ASSERT_NOT_NULL(message);

    const float *decoded = evi_message_data(message);
    size_t decoded_len = evi_message_size(message);
    TEST_ASSERT_TRUE(decoded_len >= dim);

    double err = max_error(data, decoded, dim);
    TEST_ASSERT_TRUE(err < 1e-4);

    evi_message_destroy(message);
    evi_query_destroy(cipher);
    evi_decryptor_destroy(decryptor);
    evi_encryptor_destroy(encryptor);
    evi_secret_key_destroy(secret);
    evi_keygenerator_destroy(keygen);
    evi_keypack_destroy(pack);
    evi_context_destroy(context);
}
