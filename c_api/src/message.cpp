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

#include "evi_c/message.h"

#include "evi_c/internal/common_internal.hpp"

using namespace evi::c_api::detail;

extern "C" {

void evi_message_destroy(evi_message_t *message) {
    delete message;
}

size_t evi_message_size(const evi_message_t *message) {
    if (!message) {
        return 0;
    }
    return message->impl.size();
}

const float *evi_message_data(const evi_message_t *message) {
    if (!message) {
        return nullptr;
    }
    return message->impl.data();
}

} // extern "C"
