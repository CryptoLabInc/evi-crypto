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

void test_context_ip0_flat(void);
void test_context_ip0_rmp(void);
void test_context_ip0_mm(void);
void test_keygenerator_basic(void);
void test_keypack_create_from_path(void);
void test_multikeygenerator_with_seal_info(void);
void test_encrypt_decrypt(void);

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_context_ip0_flat);
    RUN_TEST(test_context_ip0_rmp);
    RUN_TEST(test_context_ip0_mm);
    RUN_TEST(test_keygenerator_basic);
    RUN_TEST(test_keypack_create_from_path);
    RUN_TEST(test_multikeygenerator_with_seal_info);
    RUN_TEST(test_encrypt_decrypt);
    return UNITY_END();
}
