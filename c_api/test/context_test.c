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

#include "evi_c/context.h"
#include "test_utils.h"

static evi_context_t *g_context = NULL;

void setUp(void) {
    g_context = NULL;
}

void tearDown(void) {
    if (g_context) {
        evi_context_destroy(g_context);
        g_context = NULL;
    }
}

void test_context_ip0_flat(void) {
    ASSERT_STATUS_OK(
        evi_context_create(EVI_PARAMETER_PRESET_IP0, EVI_DEVICE_TYPE_CPU, 512, EVI_EVAL_MODE_FLAT, NULL, &g_context));
    TEST_ASSERT_NOT_NULL(g_context);

    TEST_ASSERT_EQUAL_INT(EVI_DEVICE_TYPE_CPU, evi_context_get_device_type(g_context));
    TEST_ASSERT_EQUAL_INT(EVI_EVAL_MODE_FLAT, evi_context_get_eval_mode(g_context));
    TEST_ASSERT_EQUAL_UINT32(512, evi_context_get_show_dim(g_context));
    TEST_ASSERT_EQUAL_UINT32(512, evi_context_get_pad_rank(g_context));
}

void test_context_ip0_rmp(void) {
    ASSERT_STATUS_OK(
        evi_context_create(EVI_PARAMETER_PRESET_IP0, EVI_DEVICE_TYPE_CPU, 512, EVI_EVAL_MODE_RMP, NULL, &g_context));
    TEST_ASSERT_NOT_NULL(g_context);

    TEST_ASSERT_EQUAL_INT(EVI_DEVICE_TYPE_CPU, evi_context_get_device_type(g_context));
    TEST_ASSERT_EQUAL_INT(EVI_EVAL_MODE_RMP, evi_context_get_eval_mode(g_context));
    TEST_ASSERT_EQUAL_UINT32(512, evi_context_get_show_dim(g_context));
    TEST_ASSERT_EQUAL_UINT32(32, evi_context_get_pad_rank(g_context));
}

void test_context_ip0_mm(void) {
    ASSERT_STATUS_OK(
        evi_context_create(EVI_PARAMETER_PRESET_IP0, EVI_DEVICE_TYPE_CPU, 512, EVI_EVAL_MODE_MM, NULL, &g_context));
    TEST_ASSERT_NOT_NULL(g_context);

    TEST_ASSERT_EQUAL_INT(EVI_DEVICE_TYPE_CPU, evi_context_get_device_type(g_context));
    TEST_ASSERT_EQUAL_INT(EVI_EVAL_MODE_MM, evi_context_get_eval_mode(g_context));
    TEST_ASSERT_EQUAL_UINT32(512, evi_context_get_show_dim(g_context));
    TEST_ASSERT_EQUAL_UINT32(512, evi_context_get_pad_rank(g_context));
}
